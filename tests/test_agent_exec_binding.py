import base64
import copy
import unittest

from agent_exec_binding import (
    AuthorizationError,
    ExecutionContext,
    MockFinanceTool,
    SignedGrant,
    ToolCall,
    make_demo_environment,
    verify_receipt,
)

NOW = 1_800_000_000


def good_call():
    return ToolCall(
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


class AgentExecutionBindingTests(unittest.TestCase):
    def setUp(self):
        self.env = make_demo_environment()
        self.call = good_call()
        self.grant = self.env["issuer"].issue(
            self.env["policy"], self.call, self.env["context"],
            self.env["tool"].SCHEMA_HASH, now=NOW
        )

    def test_valid_request_executes_and_receipt_verifies(self):
        rows, receipt = self.env["gateway"].execute(
            self.call, self.env["context"], self.grant, now=NOW + 1
        )
        self.assertEqual(len(rows), 1)
        self.assertNotIn("id_number", rows[0])
        self.assertTrue(verify_receipt(receipt, self.env["tool_sk"].public_key()))
        self.assertTrue(self.env["audit"].verify(self.env["audit_sk"].public_key()))

    def test_write_operation_denied_before_grant(self):
        call = copy.deepcopy(self.call)
        call = ToolCall(call.agent_id, call.tool_id, call.resource, "delete", call.args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(
                self.env["policy"], call, self.env["context"],
                self.env["tool"].SCHEMA_HASH, now=NOW
            )

    def test_sensitive_field_denied_before_grant(self):
        args = dict(self.call.args)
        args["fields"] = ["year", "id_number"]
        call = ToolCall(self.call.agent_id, self.call.tool_id, self.call.resource,
                        self.call.operation, args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(self.env["policy"], call, self.env["context"],
                                     self.env["tool"].SCHEMA_HASH, now=NOW)

    def test_required_filter_cannot_be_removed_or_changed(self):
        args = dict(self.call.args)
        args["where"] = {"department": "Sales"}
        call = ToolCall(self.call.agent_id, self.call.tool_id, self.call.resource,
                        self.call.operation, args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(self.env["policy"], call, self.env["context"],
                                     self.env["tool"].SCHEMA_HASH, now=NOW)

    def test_request_tampering_after_authorization_denied(self):
        args = dict(self.call.args)
        args["where"] = {"year": 2026, "department": "Finance"}
        tampered = ToolCall(self.call.agent_id, self.call.tool_id, self.call.resource,
                            self.call.operation, args)
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(tampered, self.env["context"], self.grant,
                                         now=NOW + 1)

    def test_context_substitution_denied(self):
        other_context = ExecutionContext("other-session", "task-001", "tenant:example")
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(self.call, other_context, self.grant, now=NOW + 1)

    def test_replay_denied(self):
        self.env["gateway"].execute(self.call, self.env["context"], self.grant, now=NOW + 1)
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(self.call, self.env["context"], self.grant, now=NOW + 2)

    def test_expired_grant_denied(self):
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(self.call, self.env["context"], self.grant,
                                         now=NOW + 31)

    def test_tool_schema_drift_denied(self):
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(
                self.call, self.env["context"], self.grant,
                now=NOW + 1, current_tool_schema_hash="f" * 64
            )


    def test_filter_widening_denied_before_grant(self):
        args = dict(self.call.args)
        args["where"] = {"year": 2026, "department": "Legal"}
        call = ToolCall(self.call.agent_id, self.call.tool_id, self.call.resource,
                        self.call.operation, args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(self.env["policy"], call, self.env["context"],
                                     self.env["tool"].SCHEMA_HASH, now=NOW)

    def test_row_limit_escalation_denied_before_grant(self):
        args = dict(self.call.args)
        args["limit"] = 11
        call = ToolCall(self.call.agent_id, self.call.tool_id, self.call.resource,
                        self.call.operation, args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(self.env["policy"], call, self.env["context"],
                                     self.env["tool"].SCHEMA_HASH, now=NOW)

    def test_forged_grant_signature_denied(self):
        forged = SignedGrant(self.grant.payload, base64.b64encode(b"not-a-valid-signature").decode())
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(self.call, self.env["context"], forged, now=NOW + 1)

    def test_audit_tampering_detected(self):
        self.env["gateway"].execute(self.call, self.env["context"], self.grant, now=NOW + 1)
        self.assertTrue(self.env["audit"].verify(self.env["audit_sk"].public_key()))
        self.env["audit"].entries[0]["event"]["decision"] = "DENY"
        self.assertFalse(self.env["audit"].verify(self.env["audit_sk"].public_key()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
