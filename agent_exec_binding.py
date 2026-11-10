"""Minimal request-bound authorization and execution receipt prototype.

This is a research MVP, not production authorization middleware.  The LLM is
modeled as an untrusted producer of ToolCall objects.  A trusted issuer checks
an explicit policy and signs a one-use grant over the exact request, context,
policy version, and tool-schema digest.  The gateway verifies that grant and
executes exactly the bound request.  The mock tool signs a receipt over the
request and response digests; an audit log links events with a signed hash chain.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


class AuthorizationError(Exception):
    """Raised when a request cannot be safely authorized or executed."""


def canonical_json(value: Any) -> bytes:
    """Stable JSON encoding used for all cryptographic commitments."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_object(value: Any) -> str:
    return sha256_hex(canonical_json(value))


def public_key_bytes(key: Ed25519PublicKey) -> str:
    return base64.b64encode(
        key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


def private_key_bytes(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode("ascii")


@dataclass(frozen=True)
class ToolCall:
    agent_id: str
    tool_id: str
    resource: str
    operation: str
    args: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "tool_id": self.tool_id,
            "resource": self.resource,
            "operation": self.operation,
            "args": self.args,
        }


@dataclass(frozen=True)
class ExecutionContext:
    session_id: str
    task_id: str
    tenant_id: str

    def as_dict(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
        }


@dataclass(frozen=True)
class Policy:
    policy_id: str
    version: int
    agent_id: str
    tool_id: str
    resource: str
    allowed_operations: tuple[str, ...]
    allowed_fields: tuple[str, ...]
    required_filters: dict[str, Any]
    allowed_filter_values: dict[str, tuple[Any, ...]]
    max_rows: int
    tenant_id: str
    expires_at: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "agent_id": self.agent_id,
            "tool_id": self.tool_id,
            "resource": self.resource,
            "allowed_operations": list(self.allowed_operations),
            "allowed_fields": list(self.allowed_fields),
            "required_filters": self.required_filters,
            "allowed_filter_values": {
                k: list(v) for k, v in self.allowed_filter_values.items()
            },
            "max_rows": self.max_rows,
            "tenant_id": self.tenant_id,
            "expires_at": self.expires_at,
        }

    @property
    def policy_hash(self) -> str:
        return digest_object(self.as_dict())

    def check(self, call: ToolCall, context: ExecutionContext) -> None:
        """Fail-closed authorization check over the actual tool-call object."""
        if call.agent_id != self.agent_id:
            raise AuthorizationError("agent principal is not authorized")
        if call.tool_id != self.tool_id:
            raise AuthorizationError("tool is not authorized by this policy")
        if call.resource != self.resource:
            raise AuthorizationError("resource is outside policy scope")
        if call.operation not in self.allowed_operations:
            raise AuthorizationError("operation is not allowed")
        if context.tenant_id != self.tenant_id:
            raise AuthorizationError("tenant context does not match policy")

        args = call.args
        if set(args) != {"fields", "where", "limit"}:
            raise AuthorizationError("tool arguments do not match the closed schema")
        fields, where, limit = args["fields"], args["where"], args["limit"]
        if not isinstance(fields, list) or not fields:
            raise AuthorizationError("fields must be a non-empty list")
        if len(fields) != len(set(fields)):
            raise AuthorizationError("duplicate fields are not allowed")
        if not set(fields).issubset(set(self.allowed_fields)):
            raise AuthorizationError("requested field is outside policy scope")
        if not isinstance(where, dict):
            raise AuthorizationError("where must be an object")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise AuthorizationError("limit must be a positive integer")
        if limit > self.max_rows:
            raise AuthorizationError("requested row limit exceeds policy")

        # Required predicates must be present exactly; callers cannot remove or
        # weaken them. Additional predicates must be drawn from allowlisted values.
        for key, required_value in self.required_filters.items():
            if where.get(key) != required_value:
                raise AuthorizationError(f"required filter missing or changed: {key}")
        for key, value in where.items():
            if key in self.required_filters:
                continue
            allowed = self.allowed_filter_values.get(key)
            if allowed is None or value not in allowed:
                raise AuthorizationError(f"filter is not allowed: {key}")


@dataclass(frozen=True)
class SignedGrant:
    payload: dict[str, Any]
    signature: str

    def as_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": self.signature}

    @property
    def grant_hash(self) -> str:
        return digest_object(self.as_dict())


@dataclass(frozen=True)
class SignedReceipt:
    payload: dict[str, Any]
    signature: str

    def as_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": self.signature}

    @property
    def receipt_hash(self) -> str:
        return digest_object(self.as_dict())


class GrantIssuer:
    """Trusted policy enforcement point that mints one-use request grants."""

    def __init__(self, private_key: Ed25519PrivateKey, issuer_id: str = "issuer-1"):
        self.private_key = private_key
        self.issuer_id = issuer_id

    def issue(
        self,
        policy: Policy,
        call: ToolCall,
        context: ExecutionContext,
        tool_schema_hash: str,
        now: int | None = None,
        ttl_seconds: int = 30,
    ) -> SignedGrant:
        now = int(time.time()) if now is None else int(now)
        policy.check(call, context)
        if now >= policy.expires_at:
            raise AuthorizationError("policy has expired")
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        expires_at = min(now + ttl_seconds, policy.expires_at)
        payload = {
            "issuer_id": self.issuer_id,
            "agent_id": call.agent_id,
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "policy_hash": policy.policy_hash,
            "request_hash": digest_object(call.as_dict()),
            "context_hash": digest_object(context.as_dict()),
            "tool_id": call.tool_id,
            "tool_schema_hash": tool_schema_hash,
            "nonce": secrets.token_hex(24),
            "issued_at": now,
            "expires_at": expires_at,
        }
        signature = base64.b64encode(
            self.private_key.sign(canonical_json(payload))
        ).decode("ascii")
        return SignedGrant(payload, signature)


class AuditChain:
    """Signed append-only hash chain; edits/deletions are detected offline."""

    def __init__(self, signing_key: Ed25519PrivateKey):
        self.signing_key = signing_key
        self.entries: list[dict[str, Any]] = []

    def append(self, event: dict[str, Any]) -> None:
        previous = self.entries[-1]["entry_hash"] if self.entries else "0" * 64
        body = {"seq": len(self.entries), "previous_hash": previous, "event": event}
        entry_hash = sha256_hex(canonical_json(body))
        signature = base64.b64encode(
            self.signing_key.sign(bytes.fromhex(entry_hash))
        ).decode("ascii")
        self.entries.append({**body, "entry_hash": entry_hash, "signature": signature})

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        previous = "0" * 64
        for index, entry in enumerate(self.entries):
            body = {
                "seq": entry.get("seq"),
                "previous_hash": entry.get("previous_hash"),
                "event": entry.get("event"),
            }
            if body["seq"] != index or body["previous_hash"] != previous:
                return False
            expected_hash = sha256_hex(canonical_json(body))
            if entry.get("entry_hash") != expected_hash:
                return False
            try:
                signature = base64.b64decode(entry["signature"], validate=True)
                public_key.verify(signature, bytes.fromhex(expected_hash))
            except (InvalidSignature, ValueError, KeyError):
                return False
            previous = expected_hash
        return True


class MockFinanceTool:
    TOOL_ID = "finance.query.v1"
    SCHEMA = {
        "tool_id": TOOL_ID,
        "input": {
            "fields": "non-empty list[str]",
            "where": "dict[str, scalar]",
            "limit": "integer >= 1",
        },
        "output": "list[object]",
    }
    SCHEMA_HASH = digest_object(SCHEMA)

    def __init__(self, private_key: Ed25519PrivateKey, records: Iterable[dict[str, Any]]):
        self.private_key = private_key
        self.records = list(records)

    def execute(
        self,
        call: ToolCall,
        grant: SignedGrant,
        context: ExecutionContext,
        now: int,
    ) -> tuple[list[dict[str, Any]], SignedReceipt]:
        where = call.args["where"]
        selected = [
            row for row in self.records
            if all(row.get(key) == value for key, value in where.items())
        ][: call.args["limit"]]
        fields = call.args["fields"]
        output = [{key: row[key] for key in fields} for row in selected]
        payload = {
            "status": "EXECUTED",
            "tool_id": self.TOOL_ID,
            "tool_schema_hash": self.SCHEMA_HASH,
            "request_hash": digest_object(call.as_dict()),
            "policy_hash": grant.payload["policy_hash"],
            "context_hash": digest_object(context.as_dict()),
            "nonce": grant.payload["nonce"],
            "output_hash": digest_object(output),
            "executed_at": now,
        }
        signature = base64.b64encode(
            self.private_key.sign(canonical_json(payload))
        ).decode("ascii")
        return output, SignedReceipt(payload, signature)


class ToolGateway:
    """Verifies the grant and binds it to the exact request actually executed."""

    def __init__(
        self,
        issuer_public_key: Ed25519PublicKey,
        tool: MockFinanceTool,
        tool_public_key: Ed25519PublicKey,
        policy: Policy,
        audit: AuditChain,
    ):
        self.issuer_public_key = issuer_public_key
        self.tool = tool
        self.tool_public_key = tool_public_key
        self.policy = policy
        self.audit = audit
        self.used_nonces: set[str] = set()

    def _deny(self, reason: str, call: ToolCall | None = None) -> None:
        self.audit.append({
            "decision": "DENY",
            "reason": reason,
            "request_hash": digest_object(call.as_dict()) if call else None,
            "timestamp": int(time.time()),
        })
        raise AuthorizationError(reason)

    def execute(
        self,
        call: ToolCall,
        context: ExecutionContext,
        grant: SignedGrant,
        now: int | None = None,
        current_tool_schema_hash: str | None = None,
    ) -> tuple[list[dict[str, Any]], SignedReceipt]:
        now = int(time.time()) if now is None else int(now)
        p = grant.payload
        try:
            signature = base64.b64decode(grant.signature, validate=True)
            self.issuer_public_key.verify(signature, canonical_json(p))
        except (InvalidSignature, ValueError):
            self._deny("invalid grant signature", call)

        if p.get("issuer_id") != "issuer-1":
            self._deny("unexpected grant issuer", call)
        if p.get("agent_id") != call.agent_id:
            self._deny("grant principal does not match request", call)
        if p.get("policy_id") != self.policy.policy_id or p.get("policy_version") != self.policy.version:
            self._deny("policy identity/version mismatch", call)
        if p.get("policy_hash") != self.policy.policy_hash:
            self._deny("policy content mismatch", call)
        if p.get("request_hash") != digest_object(call.as_dict()):
            self._deny("request differs from the authorized request", call)
        if p.get("context_hash") != digest_object(context.as_dict()):
            self._deny("execution context differs from authorized context", call)
        actual_schema_hash = current_tool_schema_hash or self.tool.SCHEMA_HASH
        if p.get("tool_id") != call.tool_id or p.get("tool_schema_hash") != actual_schema_hash:
            self._deny("tool identity/schema changed after authorization", call)
        if not isinstance(p.get("issued_at"), int) or not isinstance(p.get("expires_at"), int):
            self._deny("invalid grant validity interval", call)
        if now < p["issued_at"] or now >= p["expires_at"]:
            self._deny("grant is not currently valid", call)
        if p.get("nonce") in self.used_nonces:
            self._deny("grant replay detected", call)
        try:
            self.policy.check(call, context)
        except AuthorizationError as exc:
            self._deny(str(exc), call)

        # Consume before invoking the tool: a crash may require a new grant, but
        # the same grant can never be replayed after an uncertain outcome.
        self.used_nonces.add(p["nonce"])
        output, receipt = self.tool.execute(call, grant, context, now)
        # The gateway verifies the tool server's signed receipt and checks that
        # it refers to the same request/context/policy/nonce that was authorized.
        if not verify_receipt(receipt, self.tool_public_key):
            self._deny("invalid tool execution receipt", call)
        receipt_payload = receipt.payload
        expected_receipt_bindings = {
            "status": "EXECUTED",
            "tool_id": call.tool_id,
            "tool_schema_hash": actual_schema_hash,
            "request_hash": digest_object(call.as_dict()),
            "policy_hash": self.policy.policy_hash,
            "context_hash": digest_object(context.as_dict()),
            "nonce": p["nonce"],
            "output_hash": digest_object(output),
        }
        if any(receipt_payload.get(k) != v for k, v in expected_receipt_bindings.items()):
            self._deny("tool receipt is not bound to this execution", call)
        self.audit.append({
            "decision": "ALLOW_EXECUTED",
            "policy_hash": self.policy.policy_hash,
            "request_hash": digest_object(call.as_dict()),
            "grant_hash": grant.grant_hash,
            "receipt_hash": receipt.receipt_hash,
            "output_hash": receipt.payload["output_hash"],
            "nonce": p["nonce"],
            "timestamp": now,
        })
        return output, receipt


def verify_receipt(receipt: SignedReceipt, public_key: Ed25519PublicKey) -> bool:
    try:
        signature = base64.b64decode(receipt.signature, validate=True)
        public_key.verify(signature, canonical_json(receipt.payload))
        return True
    except (InvalidSignature, ValueError):
        return False


def make_demo_environment() -> dict[str, Any]:
    issuer_sk = Ed25519PrivateKey.generate()
    tool_sk = Ed25519PrivateKey.generate()
    audit_sk = Ed25519PrivateKey.generate()
    policy = Policy(
        policy_id="finance-read-sales-2026",
        version=1,
        agent_id="agent:finance-assistant",
        tool_id=MockFinanceTool.TOOL_ID,
        resource="finance_records",
        allowed_operations=("read",),
        allowed_fields=("year", "department", "amount"),
        required_filters={"year": 2026},
        allowed_filter_values={"department": ("Sales", "Finance")},
        max_rows=10,
        tenant_id="tenant:example",
        expires_at=2_000_000_000,
    )
    records = [
        {"year": 2026, "department": "Sales", "amount": 1200, "id_number": "SENSITIVE-001"},
        {"year": 2026, "department": "Finance", "amount": 3400, "id_number": "SENSITIVE-002"},
        {"year": 2025, "department": "Sales", "amount": 900, "id_number": "SENSITIVE-003"},
    ]
    tool = MockFinanceTool(tool_sk, records)
    audit = AuditChain(audit_sk)
    issuer = GrantIssuer(issuer_sk)
    gateway = ToolGateway(
        issuer_sk.public_key(), tool, tool_sk.public_key(), policy, audit
    )
    context = ExecutionContext("session-001", "task-001", "tenant:example")
    return {
        "issuer_sk": issuer_sk,
        "tool_sk": tool_sk,
        "audit_sk": audit_sk,
        "policy": policy,
        "tool": tool,
        "audit": audit,
        "issuer": issuer,
        "gateway": gateway,
        "context": context,
    }


if __name__ == "__main__":
    env = make_demo_environment()
    call = ToolCall(
        agent_id="agent:finance-assistant",
        tool_id=MockFinanceTool.TOOL_ID,
        resource="finance_records",
        operation="read",
        args={
            "fields": ["year", "department", "amount"],
            "where": {"year": 2026, "department": "Sales"},
            "limit": 5,
        },
    )
    grant = env["issuer"].issue(
        env["policy"], call, env["context"], env["tool"].SCHEMA_HASH, now=1_800_000_000
    )
    rows, receipt = env["gateway"].execute(
        call, env["context"], grant, now=1_800_000_001
    )
    print("ALLOW: exact authorized request executed")
    print("Rows:", json.dumps(rows, ensure_ascii=False))
    print("Receipt valid:", verify_receipt(receipt, env["tool_sk"].public_key()))
    print("Audit chain valid:", env["audit"].verify(env["audit_sk"].public_key()))
    print("Sensitive id_number disclosed:", any("id_number" in row for row in rows))
