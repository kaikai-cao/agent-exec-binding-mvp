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
import threading
import time
from dataclasses import dataclass
from pathlib import Path
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

# R2.8-P2 engineering primitives. Imported at module load so that both the
# baseline (opt-out) and hardened (opt-in) paths share ONE implementation of
# nonce consumption and execution state; no behaviour changes unless a caller
# explicitly injects these objects.
from execution_ledger import (  # noqa: E402
    COMPLETED,
    EXECUTING,
    INTENT,
    OUTCOME_UNKNOWN,
    RECONCILED,
    LedgerError,
    NonceConflict,
    NonceRegistry,
    TOOL_FINISHED,
    TOOL_STARTED,
    ExecutionLedger,
    ToolResultStore,
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


def json_snapshot(value: Any) -> Any:
    """Deep, JSON-only copy sharing no mutable state with the caller's value.

    Serialising first also pins the exact bytes used for signature
    verification, so a caller-supplied mapping cannot return different values
    on later reads of the same field.
    """
    return json.loads(canonical_json(value))


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
        self._lock = threading.Lock()

    def append(self, event: dict[str, Any]) -> None:
        with self._lock:
            previous = self.entries[-1]["entry_hash"] if self.entries else "0" * 64
            body = {"seq": len(self.entries), "previous_hash": previous, "event": event}
            entry_hash = sha256_hex(canonical_json(body))
            signature = base64.b64encode(
                self.signing_key.sign(bytes.fromhex(entry_hash))
            ).decode("ascii")
            self.entries.append({
                **body,
                "entry_hash": entry_hash,
                "signature": signature,
            })

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        with self._lock:
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


# --- E2: external audit checkpoint ---------------------------------------

# Verification outcomes. INCOMPLETE and UNKNOWN are deliberately distinct
# from a hard failure: neither may be reported as COMPLETE.
CHECKPOINT_COMPLETE = "COMPLETE"
CHECKPOINT_INCOMPLETE = "INCOMPLETE"
CHECKPOINT_DIVERGED = "DIVERGED"
CHECKPOINT_UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class CheckpointRecord:
    """External anchor of the latest *confirmed* audit head."""

    log_id: str
    last_seq: int          # -1 means "empty log confirmed"
    last_entry_hash: str   # "0"*64 for empty log
    version: int
    anchored_at: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "log_id": self.log_id,
            "last_seq": self.last_seq,
            "last_entry_hash": self.last_entry_hash,
            "version": self.version,
            "anchored_at": self.anchored_at,
        }


class CheckpointError(Exception):
    """Raised when a checkpoint update would violate monotonicity."""


class CheckpointWitness:
    """Abstract external anchor for an append-only log head.

    The anchor is *not* stored in the AuditChain.entries list; a real
    deployment would keep it in an independently controlled store (another
    service, a transparency log, or a signed statement).  This in-process
    reference implementation exists to test the protocol logic only -- it is
    NOT a real independently deployed witness.
    """

    def __init__(self, version: int = 1):
        if version < 1:
            raise ValueError("checkpoint version must be >= 1")
        self.version = version
        self._latest: dict[str, CheckpointRecord] = {}
        self._lock = threading.Lock()

    def anchor(
        self,
        log_id: str,
        last_seq: int,
        last_entry_hash: str,
        *,
        now: int | None = None,
    ) -> CheckpointRecord:
        """Anchor a head.  Sequence may not regress; a given seq has one hash."""
        if not isinstance(log_id, str) or not log_id:
            raise ValueError("log_id must be a non-empty string")
        if not isinstance(last_seq, int) or last_seq < -1:
            raise ValueError("last_seq must be an integer >= -1")
        if not isinstance(last_entry_hash, str) or len(last_entry_hash) != 64:
            raise ValueError("last_entry_hash must be a 64-char hex digest")
        with self._lock:
            current = self._latest.get(log_id)
            if current is not None:
                if last_seq < current.last_seq:
                    raise CheckpointError(
                        f"checkpoint rollback refused: {last_seq} < {current.last_seq}"
                    )
                if last_seq == current.last_seq and last_entry_hash != current.last_entry_hash:
                    raise CheckpointError(
                        f"conflicting head hash for seq {last_seq}"
                    )
            record = CheckpointRecord(
                log_id=log_id,
                last_seq=last_seq,
                last_entry_hash=last_entry_hash,
                version=self.version,
                anchored_at=int(time.time()) if now is None else int(now),
            )
            self._latest[log_id] = record
            return record

    def latest(self, log_id: str) -> CheckpointRecord | None:
        with self._lock:
            return self._latest.get(log_id)

    def available(self) -> bool:
        """A real witness may be unreachable; in-process reference is always up."""
        return True


class UnavailableCheckpointWitness(CheckpointWitness):
    """Test double: models a witness service that cannot be reached."""

    def available(self) -> bool:
        return False


def verify_audit_with_checkpoint(
    chain: AuditChain,
    witness: CheckpointWitness,
    public_key: Ed25519PublicKey,
    log_id: str,
) -> str:
    """Verify chain continuity AND compare its tail to the external checkpoint.

    Returns one of ``COMPLETE`` / ``INCOMPLETE`` / ``DIVERGED`` /
    ``UNVERIFIED``.  It NEVER returns COMPLETE when the witness is unavailable,
    when the anchored terminal record is missing, or when extra unanchored
    records follow the checkpoint.
    """
    if not witness.available():
        return CHECKPOINT_UNVERIFIED
    checkpoint = witness.latest(log_id)
    if checkpoint is None:
        return CHECKPOINT_UNVERIFIED
    if not chain.verify(public_key):
        return CHECKPOINT_DIVERGED
    with chain._lock:
        entries = list(chain.entries)
    anchored_seq = checkpoint.last_seq
    if anchored_seq == -1:
        return CHECKPOINT_COMPLETE if not entries else CHECKPOINT_INCOMPLETE
    if len(entries) < anchored_seq + 1:
        # Missing a record that the checkpoint says was confirmed -> tail cut.
        return CHECKPOINT_DIVERGED
    anchored = entries[anchored_seq]
    if anchored.get("entry_hash") != checkpoint.last_entry_hash:
        return CHECKPOINT_DIVERGED
    if len(entries) > anchored_seq + 1:
        # Chain has records beyond the last confirmed head: not yet complete.
        return CHECKPOINT_INCOMPLETE
    return CHECKPOINT_COMPLETE


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


class VerifyingTool(MockFinanceTool):
    """E1: tool adapter that *independently* verifies the grant before acting.

    Hardening is opt-in: the baseline ``MockFinanceTool`` is deliberately left
    unchanged so the frozen P0/P1 defect-reproduction tests still pass. This
    subclass is the fix path used by R2.8-P2.

    Trust rule: the verification public key and the expected issuer id are held
    by the TOOL, supplied at construction. No caller-supplied key or policy is
    ever consulted. Nine independent checks are performed (signature, issuer,
    principal, tool id, schema hash, request hash, context hash, validity
    window, nonce format + persistent single-use state).

    This closes the *direct adapter call with a forged grant* path. It is NOT a
    proof against every possible execution bypass: an attacker who can replace
    the tool object or its trusted key, or call a lower layer than the adapter,
    is out of scope.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        records: Iterable[dict[str, Any]],
        issuer_public_key: Ed25519PublicKey,
        expected_issuer_id: str,
        expected_policy_hash: str,
        *,
        nonce_registry: NonceRegistry | None = None,
        result_store: ToolResultStore | None = None,
        expected_schema_hash: str | None = None,
    ):
        super().__init__(private_key, records)
        self._issuer_public_key = issuer_public_key
        self._expected_issuer_id = expected_issuer_id
        self._expected_policy_hash = expected_policy_hash
        self._nonce_registry = nonce_registry
        self._result_store = result_store
        self._expected_schema_hash = expected_schema_hash or self.SCHEMA_HASH
        self.verify_log: list[dict[str, Any]] = []
        self.execute_count = 0

    def _log(self, verdict: str, reason: str, **bindings: Any) -> None:
        self.verify_log.append(
            {"verdict": verdict, "reason": reason, **bindings}
        )

    def verify_grant(
        self,
        call: ToolCall,
        grant: SignedGrant,
        context: ExecutionContext,
        now: int,
    ) -> None:
        """Fail-closed independent verification. Raises AuthorizationError."""
        try:
            payload = json_snapshot(grant.payload)
            if not isinstance(payload, dict):
                raise AuthorizationError("grant payload is not an object")
        except (TypeError, ValueError, AttributeError):
            raise AuthorizationError("grant payload is not valid JSON data")

        def reject(reason: str) -> None:
            self._log("REJECT", reason, nonce=payload.get("nonce"))
            raise AuthorizationError(f"tool-side verification failed: {reason}")

        # (1) Ed25519 signature under the tool's OWN trusted issuer key.
        try:
            signature = base64.b64decode(grant.signature, validate=True)
            self._issuer_public_key.verify(signature, canonical_json(payload))
        except (InvalidSignature, ValueError, TypeError):
            reject("invalid grant signature")

        # (2) issuer identity
        if payload.get("issuer_id") != self._expected_issuer_id:
            reject("unexpected issuer")
        # (3) principal
        if payload.get("agent_id") != call.agent_id or not call.agent_id:
            reject("principal does not match request")
        # (4) tool id
        if payload.get("tool_id") != self.TOOL_ID or call.tool_id != self.TOOL_ID:
            reject("tool id mismatch")
        # (5) tool schema hash -- taken from the tool, never from the caller
        if payload.get("tool_schema_hash") != self._expected_schema_hash:
            reject("tool schema hash mismatch")
        if self.SCHEMA_HASH != self._expected_schema_hash:
            reject("trusted schema hash does not match tool schema")
        # (6) request hash
        if payload.get("request_hash") != digest_object(call.as_dict()):
            reject("request hash mismatch")
        # (7) context hash
        if payload.get("context_hash") != digest_object(context.as_dict()):
            reject("context hash mismatch")
        # (8) validity window
        issued_at, expires_at = payload.get("issued_at"), payload.get("expires_at")
        if not isinstance(issued_at, int) or not isinstance(expires_at, int):
            reject("invalid validity interval")
        if now < issued_at or now >= expires_at:
            reject("grant not currently valid")
        # (9a) policy binding
        if payload.get("policy_hash") != self._expected_policy_hash:
            reject("policy hash mismatch")
        # (9b) nonce format + persistent single-use state, UNIFIED with E5.
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            reject("invalid grant nonce")
        if self._nonce_registry is not None:
            grant_hash = SignedGrant(payload, grant.signature).grant_hash
            try:
                result = self._nonce_registry.consume(
                    nonce, grant_hash, digest_object(call.as_dict()), call.agent_id
                )
            except NonceConflict:
                reject("nonce already bound to a different request")
            except LedgerError:
                reject("nonce ledger unavailable")
            if not (result.consumed or result.identical_duplicate):
                reject("nonce consumption failed")
        else:
            # No shared registry supplied: the tool cannot claim one-time
            # enforcement. Record that explicitly rather than silently pass.
            self._log(
                "WARN", "no persistent nonce registry; one-time state not enforced"
            )
        self._log("ACCEPT", "all independent checks passed", nonce=nonce)

    def execute(
        self,
        call: ToolCall,
        grant: SignedGrant,
        context: ExecutionContext,
        now: int,
    ) -> tuple[list[dict[str, Any]], SignedReceipt]:
        self.verify_grant(call, grant, context, now)

        # E6: persist intent-at-tool before the effect, so an external
        # reconciler can later tell "started but no receipt" apart from
        # "never reached the tool".
        nonce = grant.payload["nonce"]
        if self._result_store is not None:
            self._result_store.mark_started(nonce)

        self.execute_count += 1
        output, receipt = super().execute(call, grant, context, now)

        # Persist the executed result + receipt so recovery can CONFIRM the
        # effect without re-executing it.
        if self._result_store is not None:
            self._result_store.store_result(
                nonce,
                receipt.as_dict(),
                receipt.payload["output_hash"],
                output,
            )
        return output, receipt

    def query_execution(self, nonce: str) -> dict[str, Any] | None:
        """External status query surface used by the reconciler (E6).

        Returns the full result (including the signed receipt) when a durable
        store exists, or None when this tool cannot report execution state.
        The None case is what forces OUTCOME_UNKNOWN for tools without a query
        capability -- it is never reported as a successful execution.
        """
        if self._result_store is None:
            return None
        record = self._result_store.query(nonce)
        if record is None:
            return None
        return {
            "nonce": nonce,
            "status": record.status,
            "receipt": record.receipt,
            "output_hash": record.output_hash,
            "output": record.output,
            "updated_at": record.updated_at,
        }


class ToolGateway:
    """Verifies the grant and binds it to the exact request actually executed."""

    def __init__(
        self,
        issuer_public_key: Ed25519PublicKey,
        tool: MockFinanceTool,
        tool_public_key: Ed25519PublicKey,
        policy: Policy,
        audit: AuditChain,
        expected_issuer_id: str = "issuer-1",
    ):
        self.issuer_public_key = issuer_public_key
        self.tool = tool
        self.tool_public_key = tool_public_key
        self.policy = policy
        self.audit = audit
        if not isinstance(expected_issuer_id, str) or not expected_issuer_id.strip():
            raise ValueError("expected_issuer_id must be a non-empty string")
        self.expected_issuer_id = expected_issuer_id
        self.used_nonces: set[str] = set()
        self._nonce_lock = threading.Lock()

    def _record(self, decision: str, reason: str, **bindings: Any) -> None:
        self.audit.append({
            "decision": decision,
            "reason": reason,
            "timestamp": int(time.time()),
            **bindings,
        })

    def _deny(self, reason: str, call: ToolCall | None = None) -> None:
        self._record(
            "DENY", reason,
            request_hash=digest_object(call.as_dict()) if call else None,
        )
        raise AuthorizationError(reason)

    def execute(
        self,
        call: ToolCall,
        context: ExecutionContext,
        grant: SignedGrant,
        now: int | None = None,
    ) -> tuple[list[dict[str, Any]], SignedReceipt]:
        now = int(time.time()) if now is None else int(now)
        # N1: take independent JSON snapshots of every caller-owned object
        # before any check. Signature verification, policy checks, the tool
        # adapter, receipt bindings and auditing use these snapshots only.
        try:
            canonical_payload = canonical_json(grant.payload)
            authorized_signature = grant.signature
            call_data = json_snapshot(call.as_dict())
            context_data = json_snapshot(context.as_dict())
        except (TypeError, ValueError, AttributeError):
            self._deny("grant payload or request is not valid JSON data")

        p = json.loads(canonical_payload)
        if (
            not isinstance(p, dict)
            or not isinstance(call_data, dict)
            or not isinstance(context_data, dict)
            or not isinstance(call_data.get("args"), dict)
            or not all(
                key in call_data
                for key in ("agent_id", "tool_id", "resource", "operation")
            )
        ):
            self._deny("invalid grant payload or request shape")
        authorized_call = ToolCall(
            agent_id=call_data["agent_id"],
            tool_id=call_data["tool_id"],
            resource=call_data["resource"],
            operation=call_data["operation"],
            args=call_data["args"],
        )
        # The context is rebuilt from its snapshot as a fresh object: policy
        # checks and the tool adapter must never see the caller's context.
        try:
            authorized_context = ExecutionContext(**context_data)
        except (TypeError, ValueError):
            self._deny("invalid execution context shape", authorized_call)
        authorized_grant = SignedGrant(p, authorized_signature)
        # Pin the grant hash before the adapter receives any grant copy. The
        # audit entry must describe the payload that was signature-verified.
        authorized_grant_hash = authorized_grant.grant_hash
        authorized_request_hash = digest_object(authorized_call.as_dict())
        context_hash = digest_object(authorized_context.as_dict())

        try:
            signature = base64.b64decode(authorized_signature, validate=True)
            self.issuer_public_key.verify(signature, canonical_payload)
        except (InvalidSignature, ValueError, TypeError):
            self._deny("invalid grant signature", authorized_call)

        if p.get("issuer_id") != self.expected_issuer_id:
            self._deny("unexpected grant issuer", authorized_call)
        if p.get("agent_id") != authorized_call.agent_id:
            self._deny("grant principal does not match request", authorized_call)
        if p.get("policy_id") != self.policy.policy_id or p.get("policy_version") != self.policy.version:
            self._deny("policy identity/version mismatch", authorized_call)
        if p.get("policy_hash") != self.policy.policy_hash:
            self._deny("policy content mismatch", authorized_call)
        if p.get("request_hash") != authorized_request_hash:
            self._deny("request differs from the authorized request", authorized_call)
        if p.get("context_hash") != context_hash:
            self._deny("execution context differs from authorized context", authorized_call)
        # Schema Hash is obtained from the trusted tool adapter, never from the caller.
        actual_schema_hash = self.tool.SCHEMA_HASH
        if p.get("tool_id") != authorized_call.tool_id or p.get("tool_schema_hash") != actual_schema_hash:
            self._deny("tool identity/schema changed after authorization", authorized_call)
        if not isinstance(p.get("issued_at"), int) or not isinstance(p.get("expires_at"), int):
            self._deny("invalid grant validity interval", authorized_call)
        if now < p["issued_at"] or now >= p["expires_at"]:
            self._deny("grant is not currently valid", authorized_call)
        try:
            self.policy.check(authorized_call, authorized_context)
        except AuthorizationError as exc:
            self._deny(str(exc), authorized_call)
        except (TypeError, ValueError, KeyError, AttributeError):
            self._deny("request could not be evaluated against policy", authorized_call)

        # N3: read the nonce once from the verified snapshot; receipt bindings
        # and every audit entry use only this local value from here on.
        nonce = p.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            self._deny("invalid grant nonce", authorized_call)
        with self._nonce_lock:
            if nonce in self.used_nonces:
                self._deny("grant replay detected", authorized_call)
            # 检查与消费必须是一个原子操作
            self.used_nonces.add(nonce)
        # Consume before invoking the tool: a crash may require a new grant, but
        # the same grant can never be replayed after an uncertain outcome.

        # Every adapter input is an independent object built from the same
        # snapshots; the gateway never reads any of them back. A changed
        # adapter input shifts its signed receipt away from the pinned hashes
        # and is reported below. This is detection after execution: it cannot
        # prevent side effects of a compromised or faulty tool adapter.
        tool_call = ToolCall(
            agent_id=call_data["agent_id"],
            tool_id=call_data["tool_id"],
            resource=call_data["resource"],
            operation=call_data["operation"],
            args=json_snapshot(call_data["args"]),
        )
        tool_grant = SignedGrant(json_snapshot(p), authorized_signature)

        # N2: a tool failure means the outcome is unknown; side effects may
        # already have happened. Record that explicitly, keep the nonce, and
        # never put tool output or exception text into the audit entry.
        try:
            output, receipt = self.tool.execute(
                tool_call, tool_grant, authorized_context, now
            )
        except Exception:
            self._record(
                "OUTCOME_UNKNOWN",
                "tool execution failed; outcome unknown and nonce retained",
                request_hash=authorized_request_hash,
                nonce=nonce,
            )
            raise

        # N2: the tool has run, so a bad receipt is not an authorization DENY.
        # P1: verify and inspect one immutable receipt snapshot. Reading the
        # adapter's receipt object twice would allow its payload to change
        # between signature verification and the bindings/audit below.
        try:
            receipt_payload = json_snapshot(receipt.payload)
            if not isinstance(receipt_payload, dict):
                raise TypeError("receipt payload is not a JSON object")
            receipt_snapshot = SignedReceipt(receipt_payload, receipt.signature)
            receipt_valid = verify_receipt(receipt_snapshot, self.tool_public_key)
            expected_receipt_bindings = {
                "status": "EXECUTED",
                "tool_id": authorized_call.tool_id,
                "tool_schema_hash": actual_schema_hash,
                "request_hash": authorized_request_hash,
                "policy_hash": self.policy.policy_hash,
                "context_hash": context_hash,
                "nonce": nonce,
                "output_hash": digest_object(output),
            }
            bindings_ok = receipt_valid and all(
                receipt_payload.get(k) == v
                for k, v in expected_receipt_bindings.items()
            )
            receipt_hash = receipt_snapshot.receipt_hash
        except Exception:
            bindings_ok = False
            receipt_payload = {}
            receipt_snapshot = None
            receipt_hash = None
        if not bindings_ok:
            self._record(
                "RECEIPT_INVALID",
                "tool executed but its receipt is invalid or not bound to the authorized request",
                request_hash=authorized_request_hash,
                nonce=nonce,
            )
            raise AuthorizationError("tool receipt is invalid or not bound to this execution")

        self.audit.append({
            "decision": "ALLOW_EXECUTED",
            "policy_hash": self.policy.policy_hash,
            "request_hash": authorized_request_hash,
            "grant_hash": authorized_grant_hash,
            "receipt_hash": receipt_hash,
            "output_hash": receipt_payload["output_hash"],
            "nonce": nonce,
            "timestamp": now,
        })
        # Return the same snapshot that was verified, not the adapter's object.
        return output, receipt_snapshot


class HardenedToolGateway(ToolGateway):
    """E5/E6 opt-in gateway using the persistent ledger instead of RAM state.

    Construction is identical to :class:`ToolGateway` with two extra required
    positional arguments: ``nonce_registry`` and ``execution_ledger``. The
    frozen baseline keeps using the RAM ``used_nonces`` set and is untouched.
    """

    def __init__(
        self,
        issuer_public_key: Ed25519PublicKey,
        tool: MockFinanceTool,
        tool_public_key: Ed25519PublicKey,
        policy: Policy,
        audit: AuditChain,
        nonce_registry: NonceRegistry,
        execution_ledger: ExecutionLedger,
        expected_issuer_id: str = "issuer-1",
    ):
        super().__init__(
            issuer_public_key, tool, tool_public_key, policy, audit,
            expected_issuer_id=expected_issuer_id,
        )
        self.nonce_registry = nonce_registry
        self.execution_ledger = execution_ledger
        # Optional fault injection points for deterministic crash tests.
        # Keys: "after_intent", "before_tool", "after_tool_before_audit".
        self.fault_hooks: dict[str, Any] = {}

    def _fire(self, point: str) -> None:
        hook = self.fault_hooks.get(point)
        if hook is not None:
            hook()

    def execute(
        self,
        call: ToolCall,
        context: ExecutionContext,
        grant: SignedGrant,
        now: int | None = None,
    ) -> tuple[list[dict[str, Any]], SignedReceipt]:
        now = int(time.time()) if now is None else int(now)
        # E6 step: persist EXECUTION_INTENT BEFORE any side effect.
        try:
            intent_call = json_snapshot(call.as_dict())
            intent_ctx = json_snapshot(context.as_dict())
            nonce = grant.payload.get("nonce")
            if not isinstance(nonce, str) or not nonce:
                raise AuthorizationError("invalid grant nonce")
            request_hash = digest_object(intent_call)
            context_hash = digest_object(intent_ctx)
            self.execution_ledger.write_intent(
                nonce=nonce,
                request_hash=request_hash,
                grant_hash=grant.grant_hash,
                principal=intent_call.get("agent_id", ""),
                idempotency_key=nonce,
                context_hash=context_hash,
            )
            self.execution_ledger.transition(nonce, EXECUTING)
        except (LedgerError, ValueError, TypeError, AttributeError) as exc:
            raise AuthorizationError(f"could not persist execution intent: {exc}")

        self._fire("after_intent")

        # E5: persistent atomic nonce consumption replaces the in-memory set.
        # The tool (if VerifyingTool) shares the SAME registry, so identical
        # duplicates are accepted there while the gateway blocks replay.
        try:
            consume = self.nonce_registry.consume(
                nonce, grant.grant_hash, request_hash, intent_call.get("agent_id", "")
            )
        except NonceConflict:
            self._record("DENY", "nonce bound to a different request", request_hash=request_hash)
            raise AuthorizationError("nonce already bound to a different request")
        except LedgerError as exc:
            raise AuthorizationError(f"nonce ledger unavailable: {exc}")
        if not consume.consumed:
            self._record("DENY", "grant replay detected (persistent)", request_hash=request_hash)
            raise AuthorizationError("grant replay detected")

        self._fire("before_tool")

        # Delegate full grant verification + tool execution to the parent,
        # which binds receipt and audit. Then finalise E6 state.
        try:
            output, receipt = super().execute(call, context, grant, now)
        except Exception:
            self._safe_transition(nonce, OUTCOME_UNKNOWN, "execution failed; outcome unknown")
            raise

        try:
            self.execution_ledger.transition(
                nonce, COMPLETED,
                receipt_hash=receipt.receipt_hash,
                output_hash=receipt.payload["output_hash"],
            )
        except LedgerError as exc:
            # Effect and final audit already happened; only local state update
            # failed. Do not silently claim success.
            raise AuthorizationError(
                f"execution completed but state not finalized: {exc}"
            )
        return output, receipt

    def _safe_transition(self, nonce: str, status: str, detail: str) -> None:
        try:
            self.execution_ledger.transition(nonce, status, detail=detail)
        except LedgerError:
            pass


def verify_receipt(receipt: SignedReceipt, public_key: Ed25519PublicKey) -> bool:
    try:
        signature = base64.b64decode(receipt.signature, validate=True)
        public_key.verify(signature, canonical_json(receipt.payload))
        return True
    except (InvalidSignature, ValueError):
        return False


# --- E6: execution effect / audit recovery -------------------------------

RECONCILE_OK = "RECONCILED"
RECONCILE_UNKNOWN = "OUTCOME_UNKNOWN"
RECONCILE_NOTHING = "NOTHING_TO_RECONCILE"
RECONCILE_ALREADY = "ALREADY_FINAL"


class ExecutionReconciler:
    """Reconcile effects that lack a final confirmation record.

    The reconciler NEVER re-executes a tool operation. It queries the tool's
    durable result store by nonce/idempotency key, verifies the returned
    receipt under the tool key AND against the persisted intent bindings, and
    only then writes a compensation audit record and moves the state to
    RECONCILED. If the tool cannot confirm an execution, the state stays
    OUTCOME_UNKNOWN for manual/后续对账 -- UNKNOWN is never reported as safe.

    This is a best-effort recovery protocol, NOT exactly-once. It requires the
    external tool to (a) persist results keyed by idempotency key and (b)
    expose a status query. Tools without both capabilities return UNKNOWN.
    """

    def __init__(
        self,
        ledger: ExecutionLedger,
        tool: VerifyingTool,
        public_key: Ed25519PublicKey,
        audit: AuditChain,
        expected_policy_hash: str,
    ):
        self.ledger = ledger
        self.tool = tool
        self.public_key = public_key
        self.audit = audit
        self.expected_policy_hash = expected_policy_hash
        self.actions: list[dict[str, Any]] = []

    def pending(self) -> list[ExecutionRecord]:
        return self.ledger.list_pending()

    def reconcile(self, nonce: str, *, now: int | None = None) -> str:
        record = self.ledger.get(nonce)
        if record is None:
            return RECONCILE_NOTHING
        if record.status in (COMPLETED, RECONCILED):
            return RECONCILE_ALREADY

        outcome = self.tool.query_execution(nonce)
        if outcome is None:
            # Tool has no persisted state for this nonce: cannot confirm an
            # effect, cannot safely retry (idempotency unknown). Stay UNKNOWN.
            self.ledger.transition(nonce, OUTCOME_UNKNOWN, detail="tool returned no state")
            self._action(nonce, RECONCILE_UNKNOWN, "tool has no execution state")
            return RECONCILE_UNKNOWN

        if outcome["status"] != TOOL_FINISHED or not outcome.get("receipt"):
            self.ledger.transition(
                nonce, OUTCOME_UNKNOWN, detail="tool started but no receipt"
            )
            self._action(
                nonce, RECONCILE_UNKNOWN,
                "tool reports STARTED without a signed receipt; effect undecidable",
            )
            return RECONCILE_UNKNOWN

        # Verify the tool-returned receipt and bind it to the persisted intent.
        try:
            payload = json_snapshot(outcome["receipt"]["payload"])
            receipt = SignedReceipt(payload, outcome["receipt"]["signature"])
        except (KeyError, TypeError, ValueError):
            self.ledger.transition(nonce, OUTCOME_UNKNOWN, detail="malformed receipt")
            self._action(nonce, RECONCILE_UNKNOWN, "malformed receipt")
            return RECONCILE_UNKNOWN

        if not verify_receipt(receipt, self.public_key):
            self.ledger.transition(nonce, OUTCOME_UNKNOWN, detail="invalid receipt signature")
            self._action(nonce, RECONCILE_UNKNOWN, "invalid receipt signature")
            return RECONCILE_UNKNOWN

        # The intent row has no output_hash yet (the final audit never landed),
        # so the authoritative output hash is the one the TOOL reports via its
        # status query. Require three-way agreement: tool output digest,
        # tool-reported hash, and the signed receipt hash.
        tool_output_hash = outcome.get("output_hash")
        tool_output_digest = digest_object(outcome.get("output"))
        expected = {
            "status": "EXECUTED",
            "tool_id": self.tool.TOOL_ID,
            "tool_schema_hash": self.tool.SCHEMA_HASH,
            "nonce": nonce,
            "request_hash": record.request_hash,
            "context_hash": record.context_hash,
            "output_hash": tool_output_hash,
            "policy_hash": self.expected_policy_hash,
        }
        bindings_ok = (
            all(payload.get(k) == v for k, v in expected.items())
            and tool_output_hash == tool_output_digest
            and tool_output_hash is not None
        )
        if not bindings_ok:
            self.ledger.transition(nonce, OUTCOME_UNKNOWN, detail="receipt binding mismatch")
            self._action(nonce, RECONCILE_UNKNOWN, "receipt not bound to persisted intent")
            return RECONCILE_UNKNOWN

        # Effect is confirmed. Append a compensation record (NOT a re-execution
        # and NOT a forged replay of the original ALLOW_EXECUTED event).
        try:
            self.audit.append({
                "decision": "ALLOW_EXECUTED_RECONCILED",
                "reason": "effect confirmed by tool receipt after missing final audit",
                "request_hash": record.request_hash,
                "grant_hash": record.grant_hash,
                "receipt_hash": receipt.receipt_hash,
                "output_hash": tool_output_hash,
                "nonce": nonce,
                "timestamp": int(time.time()) if now is None else int(now),
            })
        except Exception as exc:
            # Recovery audit itself failed: do NOT declare success.
            self.ledger.transition(nonce, OUTCOME_UNKNOWN, detail="recovery audit failed")
            self._action(nonce, RECONCILE_UNKNOWN, f"recovery audit failed: {exc}")
            return RECONCILE_UNKNOWN

        self.ledger.transition(
            nonce, RECONCILED,
            receipt_hash=receipt.receipt_hash,
            output_hash=tool_output_hash,
        )
        self._action(nonce, RECONCILE_OK, "effect confirmed; compensation record written")
        return RECONCILE_OK

    def _action(self, nonce: str, status: str, detail: str) -> None:
        self.actions.append({"nonce": nonce, "status": status, "detail": detail})


def make_hardened_environment(
    db_dir: str | Path,
    version: int = 1,
) -> dict[str, Any]:
    """Build an opt-in hardened environment backed by a temporary directory.

    Use a throwaway ``db_dir`` (``tempfile.mkdtemp``) in tests so the user's
    repository/data are never touched. No business default is changed.
    """
    base = make_demo_environment()
    policy = base["policy"]
    registry = NonceRegistry(str(Path(db_dir) / "nonce.db"))
    ledger = ExecutionLedger(str(Path(db_dir) / "execution.db"))
    results = ToolResultStore(str(Path(db_dir) / "tool_results.db"))
    tool = VerifyingTool(
        base["tool_sk"],
        base["tool"].records,
        base["issuer_sk"].public_key(),
        "issuer-1",
        policy.policy_hash,
        nonce_registry=registry,
        result_store=results,
    )
    witness = CheckpointWitness(version=version)
    audit = AuditChain(base["audit_sk"])
    gateway = HardenedToolGateway(
        base["issuer_sk"].public_key(),
        tool,
        base["tool_sk"].public_key(),
        policy,
        audit,
        registry,
        ledger,
    )
    reconciler = ExecutionReconciler(
        ledger, tool, base["tool_sk"].public_key(), audit, policy.policy_hash
    )
    def close_all() -> None:
        """Close all SQLite connections (needed on Windows before temp cleanup)."""
        for resource in (registry, ledger, results):
            try:
                resource.close()
            except Exception:
                pass

    return {
        **base,
        "nonce_registry": registry,
        "execution_ledger": ledger,
        "result_store": results,
        "tool": tool,
        "audit": audit,
        "gateway": gateway,
        "witness": witness,
        "reconciler": reconciler,
        "db_dir": db_dir,
        "close_all": close_all,
    }


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
