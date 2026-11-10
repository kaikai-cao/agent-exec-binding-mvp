"""Plan-level signed authorization baseline for multi-step agent workflows.

This is deliberately a non-ZK baseline. A trusted policy authority checks a
private aggregate budget and signs one grant over an ordered plan Merkle root.
At execution time, the gateway verifies a per-step Merkle inclusion proof and
consumes a one-time nullifier before invoking a mock tool. The tool signs a
receipt bound to the exact step and result digest.

The code is a research prototype, not production authorization middleware.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class AuthorizationError(Exception):
    """Raised when a plan or step is not authorized."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def digest_hex(data: bytes) -> str:
    return sha256(data).hex()


def object_digest(value: Any) -> str:
    return digest_hex(canonical_json(value))


def action_hash(index: int, action_dict: dict[str, Any]) -> bytes:
    if index < 0 or index >= 2**32:
        raise AuthorizationError("step index is out of supported range")
    # Domain 0x00 separates leaves from internal nodes. The index is committed
    # independently so moving an action to another position changes the leaf.
    return sha256(b"\x00" + index.to_bytes(4, "big") + canonical_json(action_dict))


def parent_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise AuthorizationError("invalid Merkle node length")
    return sha256(b"\x01" + left + right)


@dataclass(frozen=True)
class PlannedAction:
    step: int
    tool_id: str
    operation: str
    recipient: str
    amount_cents: int
    currency: str = "USD"
    memo: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "operation": self.operation,
            "recipient": self.recipient,
            "amount_cents": self.amount_cents,
            "currency": self.currency,
            "memo": self.memo,
        }

    def committed_dict(self) -> dict[str, Any]:
        return {"step": self.step, **self.as_dict()}


@dataclass(frozen=True)
class MerkleSibling:
    digest_hex: str
    is_left: bool


@dataclass(frozen=True)
class MerkleInclusionProof:
    index: int
    leaf_count: int
    siblings: tuple[MerkleSibling, ...]


class MerkleTree:
    """Binary Merkle tree with duplicate-last handling for odd-width levels."""

    def __init__(self, actions: Iterable[PlannedAction]):
        self.actions = tuple(actions)
        if not self.actions:
            raise AuthorizationError("plan must contain at least one action")
        if len(self.actions) > 2**32 - 1:
            raise AuthorizationError("plan contains too many actions")
        expected_steps = tuple(range(len(self.actions)))
        actual_steps = tuple(action.step for action in self.actions)
        if actual_steps != expected_steps:
            raise AuthorizationError("steps must be contiguous and ordered from zero")

        leaves = [
            action_hash(action.step, action.as_dict()) for action in self.actions
        ]
        self._levels: list[list[bytes]] = [leaves]
        while len(self._levels[-1]) > 1:
            current = self._levels[-1]
            next_level: list[bytes] = []
            for offset in range(0, len(current), 2):
                left = current[offset]
                right = current[offset + 1] if offset + 1 < len(current) else left
                next_level.append(parent_hash(left, right))
            self._levels.append(next_level)

    @property
    def root(self) -> str:
        return self._levels[-1][0].hex()

    def proof(self, index: int) -> MerkleInclusionProof:
        if index < 0 or index >= len(self.actions):
            raise AuthorizationError("step index does not exist in plan")
        cursor = index
        siblings: list[MerkleSibling] = []
        for level in self._levels[:-1]:
            if cursor % 2:
                sibling_index = cursor - 1
                siblings.append(MerkleSibling(level[sibling_index].hex(), True))
            else:
                sibling_index = cursor + 1
                if sibling_index >= len(level):
                    sibling_index = cursor  # duplicate-last node
                siblings.append(MerkleSibling(level[sibling_index].hex(), False))
            cursor //= 2
        return MerkleInclusionProof(index, len(self.actions), tuple(siblings))

    @staticmethod
    def verify(
        action: PlannedAction,
        proof: MerkleInclusionProof,
        expected_root_hex: str,
    ) -> bool:
        if proof.index != action.step or proof.leaf_count < 1:
            return False
        if proof.index < 0 or proof.index >= proof.leaf_count:
            return False
        current = action_hash(action.step, action.as_dict())
        cursor = proof.index
        width = proof.leaf_count
        sibling_depth = 0
        while width > 1:
            if sibling_depth >= len(proof.siblings):
                return False
            sibling = proof.siblings[sibling_depth]
            try:
                sibling_digest = bytes.fromhex(sibling.digest_hex)
            except ValueError:
                return False
            if len(sibling_digest) != 32:
                return False
            expected_is_left = bool(cursor % 2)
            if sibling.is_left != expected_is_left:
                return False
            current = (
                parent_hash(sibling_digest, current)
                if sibling.is_left
                else parent_hash(current, sibling_digest)
            )
            cursor //= 2
            width = (width + 1) // 2
            sibling_depth += 1
        if sibling_depth != len(proof.siblings):
            return False
        return current.hex() == expected_root_hex


@dataclass(frozen=True)
class PlanPolicy:
    policy_id: str
    version: int
    allowed_tool_id: str
    allowed_operation: str
    allowed_recipients: tuple[str, ...]
    allowed_currency: str
    max_per_action_cents: int
    # Private policy witness in this signed-baseline prototype. It is checked
    # by the authority but is deliberately not included in the grant payload.
    aggregate_budget_cents: int
    tenant_id: str
    max_plan_actions: int


@dataclass(frozen=True)
class PlanGrant:
    claims: dict[str, Any]
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {"claims": self.claims, "signature_hex": self.signature_hex}


@dataclass(frozen=True)
class PlanAuthorization:
    grant: PlanGrant
    tree: MerkleTree


@dataclass(frozen=True)
class ToolReceipt:
    claims: dict[str, Any]
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {"claims": self.claims, "signature_hex": self.signature_hex}


@dataclass(frozen=True)
class StepExecution:
    action: PlannedAction
    result: dict[str, Any]
    receipt: ToolReceipt
    nullifier: str


class PlanAuthority:
    """Trusted issuer that checks policy and signs one grant per full plan."""

    def __init__(self, signing_key: Ed25519PrivateKey):
        self._key = signing_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def authorize(
        self,
        actions: Iterable[PlannedAction],
        *,
        principal: str,
        tenant_id: str,
        session_id: str,
        tool_schema_hash: str,
        policy: PlanPolicy,
        now: int | None = None,
        ttl_seconds: int = 300,
    ) -> PlanAuthorization:
        if ttl_seconds <= 0:
            raise AuthorizationError("grant lifetime must be positive")
        action_list = tuple(actions)
        tree = MerkleTree(action_list)
        if len(action_list) > policy.max_plan_actions:
            raise AuthorizationError("plan exceeds maximum action count")
        if tenant_id != policy.tenant_id:
            raise AuthorizationError("tenant is not authorized by policy")

        total = 0
        for action in action_list:
            if action.tool_id != policy.allowed_tool_id:
                raise AuthorizationError("tool is not allowed")
            if action.operation != policy.allowed_operation:
                raise AuthorizationError("operation is not allowed")
            if action.recipient not in policy.allowed_recipients:
                raise AuthorizationError("recipient is not allowed")
            if action.currency != policy.allowed_currency:
                raise AuthorizationError("currency is not allowed")
            if not isinstance(action.amount_cents, int) or isinstance(action.amount_cents, bool):
                raise AuthorizationError("amount must be an integer number of cents")
            if action.amount_cents <= 0:
                raise AuthorizationError("amount must be positive")
            if action.amount_cents > policy.max_per_action_cents:
                raise AuthorizationError("per-action limit exceeded")
            total += action.amount_cents
        if total > policy.aggregate_budget_cents:
            raise AuthorizationError("aggregate budget exceeded")

        issued_at = int(time.time()) if now is None else int(now)
        policy_public_fields = {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "allowed_tool_id": policy.allowed_tool_id,
            "allowed_operation": policy.allowed_operation,
            "allowed_recipients": list(policy.allowed_recipients),
            "allowed_currency": policy.allowed_currency,
            "max_per_action_cents": policy.max_per_action_cents,
            "tenant_id": policy.tenant_id,
            "max_plan_actions": policy.max_plan_actions,
        }
        claims = {
            "grant_version": 1,
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "policy_hash": object_digest(policy_public_fields),
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
        return PlanAuthorization(PlanGrant(claims, signature), tree)


def plan_context_hash(claims: dict[str, Any]) -> str:
    context = {
        "principal": claims["principal"],
        "tenant_id": claims["tenant_id"],
        "session_id": claims["session_id"],
    }
    return object_digest(context)


def grant_digest(grant: PlanGrant) -> str:
    return object_digest(grant.as_dict())


def step_nullifier(plan_nonce: str, index: int) -> str:
    return digest_hex(b"nullifier:v1:" + plan_nonce.encode("utf-8") + b":" + str(index).encode("ascii"))


def action_digest(action: PlannedAction) -> str:
    return object_digest(action.committed_dict())


class MockProcurementTool:
    """A deterministic mock tool; no real purchase or transfer is performed."""

    def __init__(self, signing_key: Ed25519PrivateKey):
        self._key = signing_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def execute(
        self,
        *,
        action: PlannedAction,
        grant: PlanGrant,
        nullifier: str,
        schema_hash: str,
        executed_at: int,
    ) -> tuple[dict[str, Any], ToolReceipt]:
        action_hash_hex = action_digest(action)
        result = {
            "status": "accepted",
            "mock_reference": f"mock-{action.step}-{action_hash_hex[:12]}",
            "amount_cents": action.amount_cents,
            "currency": action.currency,
        }
        receipt_claims = {
            "receipt_version": 1,
            "grant_digest": grant_digest(grant),
            "plan_root": grant.claims["plan_root"],
            "step": action.step,
            "nullifier": nullifier,
            "action_hash": action_hash_hex,
            "result_hash": object_digest(result),
            "context_hash": plan_context_hash(grant.claims),
            "tool_schema_hash": schema_hash,
            "executed_at": executed_at,
        }
        signature = self._key.sign(canonical_json(receipt_claims)).hex()
        return result, ToolReceipt(receipt_claims, signature)


class PlanExecutionGateway:
    """Verifies plan grants and admits each committed step at most once."""

    def __init__(
        self,
        *,
        issuer_public_key: Ed25519PublicKey,
        tool: MockProcurementTool,
        expected_tool_schema_hash: str,
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
        action: PlannedAction,
        inclusion_proof: MerkleInclusionProof,
        principal: str,
        tenant_id: str,
        session_id: str,
        tool_schema_hash: str,
        now: int | None = None,
    ) -> StepExecution:
        claims = grant.claims
        current_time = int(time.time()) if now is None else int(now)
        try:
            self._issuer_key.verify(bytes.fromhex(grant.signature_hex), canonical_json(claims))
        except (InvalidSignature, ValueError, TypeError):
            raise AuthorizationError("invalid plan grant signature") from None

        if claims.get("grant_version") != 1:
            raise AuthorizationError("unsupported grant version")
        if claims.get("principal") != principal:
            raise AuthorizationError("principal mismatch")
        if claims.get("tenant_id") != tenant_id:
            raise AuthorizationError("tenant mismatch")
        if claims.get("session_id") != session_id:
            raise AuthorizationError("session mismatch")
        if claims.get("tool_schema_hash") != tool_schema_hash:
            raise AuthorizationError("tool schema mismatch")
        if tool_schema_hash != self._schema_hash:
            raise AuthorizationError("gateway tool schema is not the authorized schema")
        if current_time < int(claims.get("issued_at", 0)):
            raise AuthorizationError("grant is not yet valid")
        if current_time >= int(claims.get("expires_at", 0)):
            raise AuthorizationError("grant has expired")
        if inclusion_proof.leaf_count != int(claims.get("action_count", -1)):
            raise AuthorizationError("action count mismatch")
        if not MerkleTree.verify(action, inclusion_proof, str(claims.get("plan_root", ""))):
            raise AuthorizationError("action is not included in the authorized plan")

        nullifier = step_nullifier(str(claims["plan_nonce"]), action.step)
        root = str(claims["plan_root"])
        plan_nonce = str(claims["plan_nonce"])

        # The lock models an atomic consume-before-execute operation. A real
        # deployment needs durable transactional state shared by all gateways.
        with self._lock:
            if nullifier in self._consumed_nullifiers:
                raise AuthorizationError("plan step has already been consumed")
            expected_step = self._next_step.get(plan_nonce, 0)
            if action.step != expected_step:
                raise AuthorizationError("plan step is out of order or has a missing predecessor")
            self._consumed_nullifiers.add(nullifier)
            self._next_step[plan_nonce] = expected_step + 1

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
            expected_receipt = {
                "grant_digest": grant_digest(grant),
                "plan_root": root,
                "step": action.step,
                "nullifier": nullifier,
                "action_hash": action_digest(action),
                "result_hash": object_digest(result),
                "context_hash": plan_context_hash(claims),
                "tool_schema_hash": tool_schema_hash,
                "executed_at": current_time,
            }
            for key, expected_value in expected_receipt.items():
                if receipt.claims.get(key) != expected_value:
                    raise AuthorizationError(f"tool receipt binding mismatch: {key}")

        return StepExecution(action, result, receipt, nullifier)
