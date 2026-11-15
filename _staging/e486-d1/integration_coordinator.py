"""Coordinator joining MVP parent authorization to the E4.8.3 durable gateway."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any

from agent_exec_binding import (
    AuthorizationError,
    MockFinanceTool,
    SignedReceipt,
    ToolCall,
    ExecutionContext,
    verify_receipt,
    digest_object,
)
from e483_adapter import E483MockFinanceAdapter
from src.execution_binding import (
    ToolPermission,
    ToolRequest,
    context_hash,
    issue_lease_grant,
    verify_execution_receipt,
)


@dataclass(frozen=True)
class IntegratedExecution:
    output: list[dict[str, Any]]
    tool_receipt: SignedReceipt
    gateway_receipt: dict[str, Any]
    replayed: bool


class IntegrationCoordinator:
    """Trusted bridge: verifies the MVP grant, mints a bound E4.8.3 lease."""

    def __init__(
        self,
        *,
        parent_gateway: Any,
        parent_tool: MockFinanceTool,
        parent_tool_public_key: Any,
        e483_issuer_private_key: Any,
        e483_issuer_id: str,
        e483_gateway: Any,
        adapter: E483MockFinanceAdapter,
        lease_id: str,
        quota_limit: int,
        clock=time.time,
    ):
        if quota_limit < 1:
            raise ValueError("quota_limit must be positive")
        if e483_gateway.broker.lease_id != lease_id:
            raise ValueError("configured lease_id differs from E4.8.3 broker")
        if e483_gateway.broker.quota_limit != quota_limit:
            raise ValueError("configured quota_limit differs from E4.8.3 broker")
        if adapter.tool_name != parent_tool.TOOL_ID:
            raise ValueError("adapter tool name differs from trusted MVP tool")
        if adapter.schema_hash != __import__(
            "src.execution_binding", fromlist=["schema_hash"]
        ).schema_hash(parent_tool.SCHEMA):
            raise ValueError("adapter schema hash differs from MVP tool schema")
        self.parent_gateway = parent_gateway
        self.parent_tool = parent_tool
        self.parent_tool_public_key = parent_tool_public_key
        self.e483_issuer_private_key = e483_issuer_private_key
        self.e483_issuer_id = e483_issuer_id
        self.e483_gateway = e483_gateway
        self.adapter = adapter
        self.lease_id = lease_id
        self.quota_limit = quota_limit
        self.clock = clock

    def execute(self, call: ToolCall, context: ExecutionContext, parent_grant: Any) -> IntegratedExecution:
        now = int(self.clock())
        verified = self.parent_gateway.verify_authorization(
            call, context, parent_grant, now=now
        )
        call_data = json.loads(verified.call_json)
        context_data = json.loads(verified.context_json)
        parent_payload = json.loads(verified.grant_payload_json)

        operation_id = call_data.get("operation_id")
        if not isinstance(operation_id, str) or not operation_id.strip():
            raise AuthorizationError("integrated execution requires a non-empty operation_id")
        if call_data["tool_id"] != self.parent_tool.TOOL_ID:
            raise AuthorizationError("unsupported MVP tool for this integration")
        if verified.tool_schema_hash != self.parent_tool.SCHEMA_HASH:
            raise AuthorizationError("MVP tool schema hash changed after parent authorization")

        child_context_digest = context_hash(context_data)
        child_grant = issue_lease_grant(
            self.e483_issuer_private_key,
            issuer_id=self.e483_issuer_id,
            # Stable child-grant fields make a retry of the same verified
            # parent authorization reproduce the same E4.8.3 journal binding.
            grant_id="e486-" + verified.grant_hash,
            lease_id=self.lease_id,
            subject_id=call_data["agent_id"],
            audience=self.e483_gateway.gateway_id,
            context_digest=child_context_digest,
            issued_at=int(parent_payload["issued_at"]),
            expires_at=int(parent_payload["expires_at"]),
            quota_limit=self.quota_limit,
            nonce=hashlib.sha256(
                ("e486-child-nonce:" + verified.grant_hash).encode("utf-8")
            ).hexdigest()[:48],
            allowed_tools=[ToolPermission(self.adapter.tool_name, self.adapter.schema_hash)],
            parent_authorization_digest=verified.grant_hash,
            parent_authorization_nonce=verified.nonce,
            operation_id=operation_id,
        )

        self.adapter.bind_authorization(
            operation_id=operation_id,
            call_data=call_data,
            context_data=context_data,
            grant_payload=parent_payload,
            grant_signature=verified.grant_signature,
        )
        request = ToolRequest(
            operation_id=operation_id,
            subject_id=call_data["agent_id"],
            tool_name=call_data["tool_id"],
            arguments=call_data["args"],
            context=context_data,
        )
        outcome = self.e483_gateway.execute(child_grant, request)
        if not verify_execution_receipt(outcome.receipt, self.e483_gateway.gateway_public_key):
            raise AuthorizationError("E4.8.3 gateway receipt signature or result digest is invalid")

        gateway_payload = outcome.receipt["payload"]
        expected_gateway = {
            "status": "SUCCEEDED",
            "gateway_id": self.e483_gateway.gateway_id,
            "parent_authorization_digest": verified.grant_hash,
            "parent_authorization_nonce": verified.nonce,
            "operation_id": operation_id,
            "tool_name": call_data["tool_id"],
            "schema_hash": self.adapter.schema_hash,
            "context_digest": child_context_digest,
        }
        if any(gateway_payload.get(k) != v for k, v in expected_gateway.items()):
            raise AuthorizationError("E4.8.3 gateway receipt is not bound to this parent authorization")

        result = gateway_payload["result"]
        output = result.get("output")
        raw_tool_receipt = result.get("tool_receipt")
        if not isinstance(output, list) or not isinstance(raw_tool_receipt, dict):
            raise AuthorizationError("persisted adapter result is malformed")
        tool_receipt = SignedReceipt(
            payload=raw_tool_receipt.get("payload"),
            signature=raw_tool_receipt.get("signature"),
        )
        if not isinstance(tool_receipt.payload, dict):
            raise AuthorizationError("tool receipt payload is malformed")
        if not verify_receipt(tool_receipt, self.parent_tool_public_key):
            raise AuthorizationError("original MVP tool receipt signature is invalid")

        expected_tool = {
            "status": "EXECUTED",
            "tool_id": call_data["tool_id"],
            "tool_schema_hash": verified.tool_schema_hash,
            "request_hash": verified.request_hash,
            "policy_hash": parent_payload["policy_hash"],
            "context_hash": verified.context_hash,
            "nonce": verified.nonce,
            "output_hash": digest_object(output),
        }
        if any(tool_receipt.payload.get(k) != v for k, v in expected_tool.items()):
            raise AuthorizationError("original MVP tool receipt is not bound to the verified parent request")

        self.parent_gateway.audit.append({
            "decision": "ALLOW_EXECUTED",
            "reason": "both tool and durable gateway receipts verified",
            "policy_hash": parent_payload["policy_hash"],
            "request_hash": verified.request_hash,
            "grant_hash": verified.grant_hash,
            "receipt_hash": tool_receipt.receipt_hash,
            "gateway_receipt_hash": digest_object(outcome.receipt),
            "output_hash": tool_receipt.payload["output_hash"],
            "nonce": verified.nonce,
            "operation_id": operation_id,
            "replayed": bool(outcome.replayed),
            "timestamp": now,
        })

        return IntegratedExecution(
            output=output,
            tool_receipt=tool_receipt,
            gateway_receipt=dict(outcome.receipt),
            replayed=outcome.replayed,
        )
