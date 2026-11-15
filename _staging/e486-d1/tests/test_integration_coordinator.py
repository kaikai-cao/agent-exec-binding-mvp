"""Focused D1 integration tests; run with the command in README_D1.md."""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_exec_binding import (
    AuditChain, GrantIssuer, ToolGateway, MockFinanceTool,
    ToolCall, ExecutionContext, make_demo_environment, digest_object,
)
from e483_adapter import E483MockFinanceAdapter
from integration_coordinator import IntegrationCoordinator
from src.durable_broker import DurableCounterBroker
from src.execution_binding import ExecutionBindingGateway, InjectedCrash


class D1IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        env = make_demo_environment()
        self.parent_issuer = env["issuer"]
        self.parent_tool = env["tool"]
        self.parent_gateway = env["gateway"]
        self.policy = env["policy"]
        self.context = env["context"]

        self.e483_issuer_sk = Ed25519PrivateKey.generate()
        self.e483_gateway_sk = Ed25519PrivateKey.generate()
        self.adapter = E483MockFinanceAdapter(
            tool=self.parent_tool, database_path=self.root / "adapter.sqlite"
        )
        self.broker = DurableCounterBroker(
            journal_path=self.root / "broker.sqlite",
            counter_state_path=self.root / "counter.json",
            broker_lock_path=self.root / "broker.lock",
            lease_id="d1-lease",
            quota_limit=3,
        )
        self.gateway = ExecutionBindingGateway(
            issuer_public_key=self.e483_issuer_sk.public_key(),
            gateway_private_key=self.e483_gateway_sk,
            gateway_id="d1-gateway",
            broker=self.broker,
            journal_path=self.root / "gateway.sqlite",
            lock_path=self.root / "gateway.lock",
            tools={self.adapter.tool_name: self.adapter},
        )
        self.coordinator = IntegrationCoordinator(
            parent_gateway=self.parent_gateway,
            parent_tool=self.parent_tool,
            parent_tool_public_key=self.parent_tool.private_key.public_key(),
            e483_issuer_private_key=self.e483_issuer_sk,
            e483_issuer_id="d1-issuer",
            e483_gateway=self.gateway,
            adapter=self.adapter,
            lease_id="d1-lease",
            quota_limit=3,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _authorized(self, operation_id="op-d1-1"):
        call = ToolCall(
            agent_id=self.policy.agent_id,
            tool_id=self.parent_tool.TOOL_ID,
            resource=self.policy.resource,
            operation="read",
            args={"fields": ["year", "department", "amount"],
                  "where": {"year": 2026, "department": "Sales"}, "limit": 5},
            operation_id=operation_id,
        )
        grant = self.parent_issuer.issue(
            self.policy, call, self.context, self.parent_tool.SCHEMA_HASH, now=int(time.time())
        )
        return call, grant

    def test_normal_execution_and_both_receipts(self):
        call, grant = self._authorized()
        result = self.coordinator.execute(call, self.context, grant)
        self.assertTrue(result.output)
        self.assertTrue(result.tool_receipt.signature)
        self.assertEqual(result.gateway_receipt["payload"]["status"], "SUCCEEDED")
        self.assertFalse(result.replayed)

    def test_successful_execution_appends_signed_audit_event(self):
        call, grant = self._authorized("op-d1-audit")
        result = self.coordinator.execute(call, self.context, grant)

        audit = self.parent_gateway.audit
        self.assertEqual(len(audit.entries), 1)

        event = audit.entries[-1]["event"]
        self.assertEqual(event["decision"], "ALLOW_EXECUTED")
        self.assertEqual(event["operation_id"], call.operation_id)
        self.assertEqual(event["policy_hash"], self.policy.policy_hash)
        self.assertEqual(event["request_hash"], result.tool_receipt.payload["request_hash"])
        self.assertEqual(event["grant_hash"], result.gateway_receipt["payload"]["parent_authorization_digest"])
        self.assertEqual(event["receipt_hash"], result.tool_receipt.receipt_hash)
        self.assertEqual(event["gateway_receipt_hash"], digest_object(result.gateway_receipt))
        self.assertEqual(event["output_hash"], digest_object(result.output))
        self.assertEqual(event["nonce"], result.tool_receipt.payload["nonce"])
        self.assertFalse(event["replayed"])

        self.assertTrue(audit.verify(audit.signing_key.public_key()))

    def test_replay_returns_persisted_result(self):
        call, grant = self._authorized()
        first = self.coordinator.execute(call, self.context, grant)
        second = self.coordinator.execute(call, self.context, grant)
        self.assertEqual(first.output, second.output)
        self.assertTrue(second.replayed)
        self.assertEqual(self.adapter.effect_count(), 1)

    def test_operation_id_substitution_is_rejected(self):
        call, grant = self._authorized()
        altered = ToolCall(**{**call.__dict__, "operation_id": "op-d1-other"})
        with self.assertRaises(Exception):
            self.coordinator.execute(altered, self.context, grant)

    def test_parent_context_substitution_is_rejected(self):
        call, grant = self._authorized()
        changed = ExecutionContext(self.context.session_id, "changed-task", self.context.tenant_id)
        with self.assertRaises(Exception):
            self.coordinator.execute(call, changed, grant)

    def test_parent_nonce_cannot_be_rebound_to_another_operation(self):
        call, grant = self._authorized("op-d1-a")
        self.coordinator.execute(call, self.context, grant)
        other = ToolCall(**{**call.__dict__, "operation_id": "op-d1-b"})
        with self.assertRaises(Exception):
            self.coordinator.execute(other, self.context, grant)

    def test_budget_exhaustion_does_not_call_adapter(self):
        for index in range(3):
            call, grant = self._authorized(f"op-budget-{index}")
            self.coordinator.execute(call, self.context, grant)
        before = self.adapter.effect_count()
        call, grant = self._authorized("op-budget-over")
        with self.assertRaises(Exception):
            self.coordinator.execute(call, self.context, grant)
        self.assertEqual(self.adapter.effect_count(), before)


    def _restart_d1_stack(self):
        """Reconstruct D1 runtime objects while preserving durable files and keys."""
        audit = AuditChain(self.parent_gateway.audit.signing_key)

        self.parent_gateway = ToolGateway(
            self.parent_issuer.private_key.public_key(),
            self.parent_tool,
            self.parent_tool.private_key.public_key(),
            self.policy,
            audit,
        )

        self.adapter = E483MockFinanceAdapter(
            tool=self.parent_tool,
            database_path=self.root / "adapter.sqlite",
        )

        self.broker = DurableCounterBroker(
            journal_path=self.root / "broker.sqlite",
            counter_state_path=self.root / "counter.json",
            broker_lock_path=self.root / "broker.lock",
            lease_id="d1-lease",
            quota_limit=3,
        )

        self.gateway = ExecutionBindingGateway(
            issuer_public_key=self.e483_issuer_sk.public_key(),
            gateway_private_key=self.e483_gateway_sk,
            gateway_id="d1-gateway",
            broker=self.broker,
            journal_path=self.root / "gateway.sqlite",
            lock_path=self.root / "gateway.lock",
            tools={self.adapter.tool_name: self.adapter},
        )

        self.coordinator = IntegrationCoordinator(
            parent_gateway=self.parent_gateway,
            parent_tool=self.parent_tool,
            parent_tool_public_key=self.parent_tool.private_key.public_key(),
            e483_issuer_private_key=self.e483_issuer_sk,
            e483_issuer_id="d1-issuer",
            e483_gateway=self.gateway,
            adapter=self.adapter,
            lease_id="d1-lease",
            quota_limit=3,
        )

    def test_process_restart_recovers_after_tool_effect_before_receipt(self):
        call, grant = self._authorized("op-restart-after-tool-effect")

        original_execute = self.gateway.execute

        def crash_after_tool_effect(child_grant, request):
            return original_execute(
                child_grant, request, crash_at="after_tool_effect"
            )

        self.gateway.execute = crash_after_tool_effect

        with self.assertRaises(InjectedCrash):
            self.coordinator.execute(call, self.context, grant)

        # Tool result is durable, but Gateway Receipt has not been committed.
        self.assertEqual(self.adapter.effect_count(), 1)
        self.assertEqual(self.broker.counter.read(), 1)

        # Reconstruct the complete D1 runtime stack.
        self._restart_d1_stack()

        recovered = self.coordinator.execute(call, self.context, grant)

        self.assertTrue(recovered.output)
        self.assertFalse(recovered.replayed)
        self.assertEqual(self.adapter.effect_count(), 1)
        self.assertEqual(self.broker.counter.read(), 1)
        self.assertEqual(
            self.gateway.journal.get(call.operation_id)["status"],
            "COMMITTED",
        )
        self.assertEqual(len(self.parent_gateway.audit.entries), 1)

    def test_process_restart_recovers_after_gateway_receipt_commit(self):
        call, grant = self._authorized("op-restart-after-receipt-commit")

        original_execute = self.gateway.execute

        def crash_after_receipt_commit(child_grant, request):
            return original_execute(
                child_grant, request, crash_at="after_receipt_commit"
            )

        self.gateway.execute = crash_after_receipt_commit

        with self.assertRaises(InjectedCrash):
            self.coordinator.execute(call, self.context, grant)

        # Gateway Receipt is durable, but Parent AuditChain has not been updated.
        journal_row = self.gateway.journal.get(call.operation_id)
        self.assertEqual(journal_row["status"], "COMMITTED")
        persisted_receipt = json.loads(journal_row["receipt_json"])
        self.assertEqual(self.adapter.effect_count(), 1)
        self.assertEqual(self.broker.counter.read(), 1)

        # Reconstruct the complete D1 runtime stack.
        self._restart_d1_stack()

        recovered = self.coordinator.execute(call, self.context, grant)

        self.assertTrue(recovered.replayed)
        self.assertEqual(recovered.gateway_receipt, persisted_receipt)
        self.assertEqual(self.adapter.effect_count(), 1)
        self.assertEqual(self.broker.counter.read(), 1)
        self.assertEqual(len(self.parent_gateway.audit.entries), 1)
        self.assertTrue(
            self.parent_gateway.audit.verify(
                self.parent_gateway.audit.signing_key.public_key()
            )
        )



if __name__ == "__main__":
    unittest.main()
