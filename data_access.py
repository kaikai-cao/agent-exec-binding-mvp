"""Plan-bound authorization for privacy-sensitive, read-only data workflows.

This module is a signed (Ed25519) baseline, not a zero-knowledge implementation.
It deliberately reuses the existing SHA-256 Merkle-tree implementation so the
new data-access scenario can be tested without changing the frozen payment demo.
"""
from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from plan_batch import (
    AuthorizationError,
    MerkleInclusionProof,
    MerkleTree,
    PlanGrant,
    ToolReceipt,
    action_digest,
    canonical_json,
    digest_hex,
    grant_digest,
    object_digest,
    plan_context_hash,
    step_nullifier,
)

TOOL_ID = "data.query.v1"
TOOL_OPERATION = "read"
MAX_ACTION_ROWS = 2**16 - 1
MAX_AGGREGATE_ROWS = 2**32 - 1
MAX_PLAN_ACTIONS = 16

RESOURCE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

# The schema hash binds the tool name, operation, parameters, filter semantics,
# and response shape. A production MCP adapter should hash the exact canonical
# tool schema advertised by the server.
DATA_QUERY_TOOL_SCHEMA: dict[str, Any] = {
    "tool_id": TOOL_ID,
    "operation": TOOL_OPERATION,
    "parameters": {
        "resource": "resource-id",
        "filters": "map<string,string>; equality only",
        "selected_fields": "non-empty unique field-name array",
        "max_rows": f"integer[1,{MAX_ACTION_ROWS}]",
    },
    "result": {
        "rows": "array<object>",
        "returned_rows": "integer",
        "truncated": "boolean",
    },
    "version": 1,
}
DATA_QUERY_SCHEMA_HASH = object_digest(DATA_QUERY_TOOL_SCHEMA)


@dataclass(frozen=True)
class DataQueryAction:
    """One finite, read-only query reserved in a plan.

    Filters are equality predicates only. The action contains a reserved upper
    bound (`max_rows`), not an SQL string, so callers cannot inject SQL syntax.
    """

    step: int
    resource: str
    filters: tuple[tuple[str, str], ...]
    selected_fields: tuple[str, ...]
    max_rows: int

    def __post_init__(self) -> None:
        if isinstance(self.step, bool) or not isinstance(self.step, int) or self.step < 0:
            raise AuthorizationError("step must be a non-negative integer")
        if not isinstance(self.resource, str) or not RESOURCE_NAME.fullmatch(self.resource):
            raise AuthorizationError("invalid resource identifier")
        if isinstance(self.max_rows, bool) or not isinstance(self.max_rows, int):
            raise AuthorizationError("max_rows must be an integer")
        if not 1 <= self.max_rows <= MAX_ACTION_ROWS:
            raise AuthorizationError("max_rows is outside the supported 16-bit range")

        fields = tuple(self.selected_fields)
        if not fields:
            raise AuthorizationError("selected_fields must not be empty")
        if any(not isinstance(name, str) or not FIELD_NAME.fullmatch(name) for name in fields):
            raise AuthorizationError("invalid selected field name")
        if len(set(fields)) != len(fields):
            raise AuthorizationError("selected_fields must not contain duplicates")
        object.__setattr__(self, "selected_fields", tuple(sorted(fields)))

        normalized_filters: list[tuple[str, str]] = []
        seen_filter_fields: set[str] = set()
        for item in self.filters:
            if not isinstance(item, tuple) or len(item) != 2:
                raise AuthorizationError("each filter must be a (field, value) pair")
            key, value = item
            if not isinstance(key, str) or not FIELD_NAME.fullmatch(key):
                raise AuthorizationError("invalid filter field name")
            if key in seen_filter_fields:
                raise AuthorizationError("duplicate filter field")
            if not isinstance(value, str) or not value or len(value) > 128:
                raise AuthorizationError("filter values must be non-empty strings up to 128 chars")
            seen_filter_fields.add(key)
            normalized_filters.append((key, value))
        if not normalized_filters:
            raise AuthorizationError("at least one equality filter is required")
        object.__setattr__(self, "filters", tuple(sorted(normalized_filters)))

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_id": TOOL_ID,
            "operation": TOOL_OPERATION,
            "resource": self.resource,
            "filters": {key: value for key, value in self.filters},
            "selected_fields": list(self.selected_fields),
            "max_rows": self.max_rows,
        }

    def committed_dict(self) -> dict[str, Any]:
        return {"step": self.step, **self.as_dict()}


@dataclass(frozen=True)
class DataAccessPolicy:
    """Authority-held data policy; its detailed attributes are not in the grant."""

    policy_id: str
    version: int
    tenant_id: str
    allowed_fields_by_resource: tuple[tuple[str, tuple[str, ...]], ...]
    allowed_filter_fields_by_resource: tuple[tuple[str, tuple[str, ...]], ...]
    allowed_filter_values_by_field: tuple[tuple[str, tuple[str, ...]], ...]
    max_rows_per_action: int
    aggregate_row_budget: int
    max_plan_actions: int = 16

    def __post_init__(self) -> None:
        if not self.policy_id or not self.tenant_id:
            raise AuthorizationError("policy_id and tenant_id are required")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version <= 0:
            raise AuthorizationError("policy version must be a positive integer")
        if not 1 <= self.max_rows_per_action <= MAX_ACTION_ROWS:
            raise AuthorizationError("per-action row limit is outside the 16-bit range")
        if not 1 <= self.aggregate_row_budget <= MAX_AGGREGATE_ROWS:
            raise AuthorizationError("aggregate row budget is outside the 32-bit range")
        if not 1 <= self.max_plan_actions <= MAX_PLAN_ACTIONS:
            raise AuthorizationError(f"max_plan_actions must be between 1 and {MAX_PLAN_ACTIONS}")

        field_resources = {resource for resource, _ in self.allowed_fields_by_resource}
        filter_resources = {resource for resource, _ in self.allowed_filter_fields_by_resource}
        if len(field_resources) != len(self.allowed_fields_by_resource):
            raise AuthorizationError("duplicate resource in field allowlist")
        if len(filter_resources) != len(self.allowed_filter_fields_by_resource):
            raise AuthorizationError("duplicate resource in filter allowlist")
        if field_resources != filter_resources:
            raise AuthorizationError("field and filter allowlists must cover the same resources")
        for resource, fields in self.allowed_fields_by_resource:
            if not RESOURCE_NAME.fullmatch(resource) or not fields:
                raise AuthorizationError("invalid or empty resource field allowlist")
            if len(set(fields)) != len(fields) or any(not FIELD_NAME.fullmatch(x) for x in fields):
                raise AuthorizationError("invalid or duplicate field in allowlist")
        for resource, fields in self.allowed_filter_fields_by_resource:
            if not RESOURCE_NAME.fullmatch(resource) or not fields:
                raise AuthorizationError("invalid or empty resource filter allowlist")
            if len(set(fields)) != len(fields) or any(not FIELD_NAME.fullmatch(x) for x in fields):
                raise AuthorizationError("invalid or duplicate filter field in allowlist")
        value_fields = [field_name for field_name, _ in self.allowed_filter_values_by_field]
        if len(set(value_fields)) != len(value_fields):
            raise AuthorizationError("duplicate filter field value allowlist")
        allowed_filter_value_fields = set(value_fields)
        for resource, fields in self.allowed_filter_fields_by_resource:
            if not set(fields).issubset(allowed_filter_value_fields):
                raise AuthorizationError("every allowed filter field needs an explicit value allowlist")
        for field_name, values in self.allowed_filter_values_by_field:
            if (
                not FIELD_NAME.fullmatch(field_name)
                or not values
                or len(set(values)) != len(values)
                or any(not isinstance(value, str) or not value or len(value) > 128 for value in values)
            ):
                raise AuthorizationError("invalid filter value allowlist")

    def fields_for(self, resource: str) -> frozenset[str]:
        return frozenset(dict(self.allowed_fields_by_resource).get(resource, ()))

    def filter_fields_for(self, resource: str) -> frozenset[str]:
        return frozenset(dict(self.allowed_filter_fields_by_resource).get(resource, ()))

    def filter_values_for(self, field_name: str) -> frozenset[str]:
        return frozenset(dict(self.allowed_filter_values_by_field).get(field_name, ()))

    def private_policy_dict(self) -> dict[str, Any]:
        """Canonical policy witness to be opened to a future ZK prover only."""
        return {
            "allowed_fields_by_resource": {
                k: sorted(v) for k, v in sorted(self.allowed_fields_by_resource)
            },
            "allowed_filter_fields_by_resource": {
                k: sorted(v) for k, v in sorted(self.allowed_filter_fields_by_resource)
            },
            "allowed_filter_values_by_field": {
                k: sorted(v) for k, v in sorted(self.allowed_filter_values_by_field)
            },
            "max_rows_per_action": self.max_rows_per_action,
            "aggregate_row_budget": self.aggregate_row_budget,
            "max_plan_actions": self.max_plan_actions,
        }


@dataclass(frozen=True)
class DataAccessAuthorization:
    grant: PlanGrant
    tree: MerkleTree
    # Issuer/prover-side opening material. Never send this field to the agent or
    # execution gateway. It is retained here only to support the future Halo2
    # witness-generation stage of the local prototype.
    issuer_policy: DataAccessPolicy = field(repr=False)
    issuer_policy_salt: bytes = field(repr=False)


@dataclass(frozen=True)
class DataStepExecution:
    action: DataQueryAction
    result: dict[str, Any]
    receipt: ToolReceipt
    nullifier: str


def policy_commitment(policy: DataAccessPolicy, salt: bytes) -> str:
    if len(salt) != 32:
        raise AuthorizationError("policy commitment salt must be 32 bytes")
    return digest_hex(b"data-access-policy:v1\x00" + salt + canonical_json(policy.private_policy_dict()))


class DataAccessAuthority:
    """Trusted baseline issuer that evaluates the complete plan before signing."""

    def __init__(self, signing_key: Ed25519PrivateKey):
        self._key = signing_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    @staticmethod
    def _validate_action(action: DataQueryAction, policy: DataAccessPolicy) -> None:
        if not isinstance(action, DataQueryAction):
            raise AuthorizationError("plan contains an unsupported action type")
        allowed_fields = policy.fields_for(action.resource)
        if not allowed_fields:
            raise AuthorizationError("resource is not allowed by policy")
        if not set(action.selected_fields).issubset(allowed_fields):
            raise AuthorizationError("selected field is not allowed by policy")
        allowed_filters = policy.filter_fields_for(action.resource)
        if not {key for key, _ in action.filters}.issubset(allowed_filters):
            raise AuthorizationError("filter field is not allowed by policy")
        for key, value in action.filters:
            if value not in policy.filter_values_for(key):
                raise AuthorizationError("filter value is not allowed by policy")
        if action.max_rows > policy.max_rows_per_action:
            raise AuthorizationError("per-action row limit exceeded")

    def authorize(
        self,
        actions: Iterable[DataQueryAction],
        *,
        principal: str,
        tenant_id: str,
        session_id: str,
        tool_schema_hash: str,
        policy: DataAccessPolicy,
        now: int | None = None,
        ttl_seconds: int = 300,
    ) -> DataAccessAuthorization:
        if ttl_seconds <= 0:
            raise AuthorizationError("grant lifetime must be positive")
        if not principal or not session_id:
            raise AuthorizationError("principal and session are required")
        if tenant_id != policy.tenant_id:
            raise AuthorizationError("tenant is not authorized by policy")

        action_list = tuple(actions)
        if not action_list:
            raise AuthorizationError("plan must contain at least one action")
        if len(action_list) > policy.max_plan_actions:
            raise AuthorizationError("plan exceeds maximum action count")
        if len(action_list) > MAX_PLAN_ACTIONS:
            raise AuthorizationError("plan exceeds circuit design maximum")

        tree = MerkleTree(action_list)
        reserved_rows = 0
        for action in action_list:
            self._validate_action(action, policy)
            reserved_rows += action.max_rows
            if reserved_rows > MAX_AGGREGATE_ROWS:
                raise AuthorizationError("aggregate row reservation overflows 32-bit range")
        if reserved_rows > policy.aggregate_row_budget:
            raise AuthorizationError("aggregate reserved-row budget exceeded")

        salt = secrets.token_bytes(32)
        commitment = policy_commitment(policy, salt)
        issued_at = int(time.time()) if now is None else int(now)
        claims = {
            "grant_version": 1,
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "policy_commitment": commitment,
            "principal": principal,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "tool_schema_hash": tool_schema_hash,
            "plan_root": tree.root,
            "action_count": len(action_list),
            "plan_nonce": secrets.token_hex(16),
            "issued_at": issued_at,
            "expires_at": issued_at + ttl_seconds,
        }
        signature = self._key.sign(canonical_json(claims)).hex()
        return DataAccessAuthorization(
            PlanGrant(claims, signature), tree, policy, salt
        )


# Synthetic rows only. Sensitive columns are present in the backing fixture to
# exercise the field policy, but the read-only tool schema intentionally exposes
# only the approved columns listed below.
MOCK_DATASETS: dict[str, tuple[dict[str, Any], ...]] = {
    "sales_records": (
        {"quarter": "2026-Q3", "region": "north", "revenue_cents": 125000, "customer_id": "cust-001", "customer_email": "alice@example.test"},
        {"quarter": "2026-Q3", "region": "south", "revenue_cents": 90000, "customer_id": "cust-002", "customer_email": "bob@example.test"},
        {"quarter": "2026-Q3", "region": "east", "revenue_cents": 112000, "customer_id": "cust-003", "customer_email": "carol@example.test"},
        {"quarter": "2026-Q4", "region": "north", "revenue_cents": 130000, "customer_id": "cust-004", "customer_email": "dave@example.test"},
    ),
    "support_metrics": (
        {"quarter": "2026-Q3", "category": "billing", "ticket_count": 17, "account_id": "acct-001"},
        {"quarter": "2026-Q3", "category": "technical", "ticket_count": 11, "account_id": "acct-002"},
        {"quarter": "2026-Q3", "category": "account", "ticket_count": 4, "account_id": "acct-003"},
        {"quarter": "2026-Q4", "category": "billing", "ticket_count": 19, "account_id": "acct-004"},
    ),
}

QUERYABLE_FIELDS: dict[str, frozenset[str]] = {
    "sales_records": frozenset({"quarter", "region", "revenue_cents"}),
    "support_metrics": frozenset({"quarter", "category", "ticket_count"}),
}
QUERYABLE_FILTERS: dict[str, frozenset[str]] = {
    "sales_records": frozenset({"quarter", "region"}),
    "support_metrics": frozenset({"quarter", "category"}),
}


class MockReadOnlyDataTool:
    """Deterministic in-memory read-only tool that signs execution receipts."""

    def __init__(self, signing_key: Ed25519PrivateKey):
        self._key = signing_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def execute(
        self,
        *,
        action: DataQueryAction,
        grant: PlanGrant,
        nullifier: str,
        schema_hash: str,
        executed_at: int,
    ) -> tuple[dict[str, Any], ToolReceipt]:
        if action.resource not in MOCK_DATASETS:
            raise AuthorizationError("unknown data resource")
        if not set(action.selected_fields).issubset(QUERYABLE_FIELDS[action.resource]):
            raise AuthorizationError("tool schema does not expose one or more selected fields")
        if not {key for key, _ in action.filters}.issubset(QUERYABLE_FILTERS[action.resource]):
            raise AuthorizationError("tool schema does not expose one or more filter fields")

        filters = dict(action.filters)
        matches = [
            row for row in MOCK_DATASETS[action.resource]
            if all(str(row.get(key)) == value for key, value in filters.items())
        ]
        selected = matches[:action.max_rows]
        output_rows = [
            {field_name: row[field_name] for field_name in action.selected_fields}
            for row in selected
        ]
        result = {
            "rows": output_rows,
            "returned_rows": len(output_rows),
            "truncated": len(matches) > action.max_rows,
        }
        receipt_claims = {
            "receipt_version": 1,
            "grant_digest": grant_digest(grant),
            "plan_root": grant.claims["plan_root"],
            "step": action.step,
            "nullifier": nullifier,
            "action_hash": action_digest(action),
            "result_hash": object_digest(result),
            "returned_rows": len(output_rows),
            "reserved_max_rows": action.max_rows,
            "context_hash": plan_context_hash(grant.claims),
            "tool_schema_hash": schema_hash,
            "executed_at": executed_at,
        }
        signature = self._key.sign(canonical_json(receipt_claims)).hex()
        return result, ToolReceipt(receipt_claims, signature)


class DataAccessGateway:
    """Execution gateway enforcing plan membership, order and one-use steps."""

    def __init__(
        self,
        *,
        issuer_public_key: Ed25519PublicKey,
        tool: MockReadOnlyDataTool,
        expected_tool_schema_hash: str = DATA_QUERY_SCHEMA_HASH,
    ):
        self._issuer_key = issuer_public_key
        self._tool = tool
        self._tool_key = tool.public_key
        self._schema_hash = expected_tool_schema_hash
        self._consumed_nullifiers: set[str] = set()
        self._next_step: dict[str, int] = {}
        self._lock = threading.Lock()

    def execute_step(
        self,
        *,
        grant: PlanGrant,
        action: DataQueryAction,
        inclusion_proof: MerkleInclusionProof,
        principal: str,
        tenant_id: str,
        session_id: str,
        tool_schema_hash: str,
        now: int | None = None,
    ) -> DataStepExecution:
        claims = grant.claims
        current_time = int(time.time()) if now is None else int(now)
        try:
            self._issuer_key.verify(bytes.fromhex(grant.signature_hex), canonical_json(claims))
        except (InvalidSignature, ValueError, TypeError):
            raise AuthorizationError("invalid data-access grant signature") from None

        if claims.get("grant_version") != 1:
            raise AuthorizationError("unsupported grant version")
        if claims.get("principal") != principal:
            raise AuthorizationError("principal mismatch")
        if claims.get("tenant_id") != tenant_id:
            raise AuthorizationError("tenant mismatch")
        if claims.get("session_id") != session_id:
            raise AuthorizationError("session mismatch")
        if claims.get("tool_schema_hash") != tool_schema_hash:
            raise AuthorizationError("schema mismatch")
        if tool_schema_hash != self._schema_hash:
            raise AuthorizationError("gateway schema is not the authorized schema")
        if current_time < int(claims.get("issued_at", 0)):
            raise AuthorizationError("grant is not yet valid")
        if current_time >= int(claims.get("expires_at", 0)):
            raise AuthorizationError("grant has expired")
        if inclusion_proof.leaf_count != int(claims.get("action_count", -1)):
            raise AuthorizationError("action count mismatch")
        if not MerkleTree.verify(action, inclusion_proof, str(claims.get("plan_root", ""))):
            raise AuthorizationError("action is not included in the authorized plan")

        nonce = str(claims["plan_nonce"])
        nullifier = step_nullifier(nonce, action.step)
        with self._lock:
            if nullifier in self._consumed_nullifiers:
                raise AuthorizationError("plan step has already been consumed")
            expected_step = self._next_step.get(nonce, 0)
            if action.step != expected_step:
                raise AuthorizationError("plan step is out of order or has a missing predecessor")
            # Consume before execution. This gives at-most-once behavior; a tool
            # failure burns this step and requires a new plan in this MVP.
            self._consumed_nullifiers.add(nullifier)
            self._next_step[nonce] = expected_step + 1

            result, receipt = self._tool.execute(
                action=action,
                grant=grant,
                nullifier=nullifier,
                schema_hash=tool_schema_hash,
                executed_at=current_time,
            )
            try:
                self._tool_key.verify(bytes.fromhex(receipt.signature_hex), canonical_json(receipt.claims))
            except (InvalidSignature, ValueError, TypeError):
                raise AuthorizationError("invalid tool receipt signature") from None

            expected = {
                "grant_digest": grant_digest(grant),
                "plan_root": claims["plan_root"],
                "step": action.step,
                "nullifier": nullifier,
                "action_hash": action_digest(action),
                "result_hash": object_digest(result),
                "returned_rows": result.get("returned_rows"),
                "reserved_max_rows": action.max_rows,
                "context_hash": plan_context_hash(claims),
                "tool_schema_hash": tool_schema_hash,
                "executed_at": current_time,
            }
            for key, expected_value in expected.items():
                if receipt.claims.get(key) != expected_value:
                    raise AuthorizationError(f"tool receipt binding mismatch: {key}")
            if not isinstance(result.get("rows"), list):
                raise AuthorizationError("tool result rows must be a list")
            if result.get("returned_rows") != len(result["rows"]):
                raise AuthorizationError("tool returned_rows does not match result payload")
            if len(result["rows"]) > action.max_rows:
                raise AuthorizationError("tool returned more rows than authorized")
            allowed_result_fields = set(action.selected_fields)
            if any(not set(row).issubset(allowed_result_fields) for row in result["rows"]):
                raise AuthorizationError("tool result contains an unrequested field")

        return DataStepExecution(action, result, receipt, nullifier)


def build_demo_policy() -> DataAccessPolicy:
    """Small fixed policy for the synthetic sales/support workflow."""
    return DataAccessPolicy(
        policy_id="internal-analytics-read-v1",
        version=1,
        tenant_id="demo-tenant",
        allowed_fields_by_resource=(
            ("sales_records", ("quarter", "region", "revenue_cents")),
            ("support_metrics", ("quarter", "category", "ticket_count")),
        ),
        allowed_filter_fields_by_resource=(
            ("sales_records", ("quarter", "region")),
            ("support_metrics", ("quarter", "category")),
        ),
        allowed_filter_values_by_field=(
            ("quarter", ("2026-Q3", "2026-Q4")),
            ("region", ("north", "south", "east", "west")),
            ("category", ("billing", "technical", "account")),
        ),
        max_rows_per_action=3,
        aggregate_row_budget=5,
        max_plan_actions=8,
    )


def build_demo_plan() -> tuple[DataQueryAction, ...]:
    return (
        DataQueryAction(
            step=0,
            resource="sales_records",
            filters=(("quarter", "2026-Q3"),),
            selected_fields=("region", "revenue_cents"),
            max_rows=2,
        ),
        DataQueryAction(
            step=1,
            resource="support_metrics",
            filters=(("quarter", "2026-Q3"),),
            selected_fields=("category", "ticket_count"),
            max_rows=2,
        ),
        DataQueryAction(
            step=2,
            resource="sales_records",
            filters=(("quarter", "2026-Q3"), ("region", "north")),
            selected_fields=("region", "revenue_cents"),
            max_rows=1,
        ),
    )
