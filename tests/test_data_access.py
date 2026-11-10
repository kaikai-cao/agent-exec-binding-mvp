import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from data_access import (
    DATA_QUERY_SCHEMA_HASH,
    DataAccessAuthority,
    DataAccessGateway,
    DataQueryAction,
    MockReadOnlyDataTool,
    build_demo_plan,
    build_demo_policy,
)
from plan_batch import AuthorizationError, ToolReceipt, action_digest, canonical_json, grant_digest, object_digest, plan_context_hash


class DataAccessTests(unittest.TestCase):
    def setUp(self):
        self.issuer_key = Ed25519PrivateKey.generate()
        self.tool_key = Ed25519PrivateKey.generate()
        self.authority = DataAccessAuthority(self.issuer_key)
        self.tool = MockReadOnlyDataTool(self.tool_key)
        self.policy = build_demo_policy()
        self.actions = build_demo_plan()
        self.now = 1_800_000_000
        self.authorization = self.authority.authorize(
            self.actions,
            principal="analytics-agent",
            tenant_id="demo-tenant",
            session_id="analytics-session-01",
            tool_schema_hash=DATA_QUERY_SCHEMA_HASH,
            policy=self.policy,
            now=self.now,
            ttl_seconds=300,
        )
        self.gateway = DataAccessGateway(
            issuer_public_key=self.authority.public_key,
            tool=self.tool,
        )

    def execute(self, index, **overrides):
        values = {
            "grant": self.authorization.grant,
            "action": self.actions[index],
            "inclusion_proof": self.authorization.tree.proof(index),
            "principal": "analytics-agent",
            "tenant_id": "demo-tenant",
            "session_id": "analytics-session-01",
            "tool_schema_hash": DATA_QUERY_SCHEMA_HASH,
            "now": self.now + index + 1,
        }
        values.update(overrides)
        return self.gateway.execute_step(**values)

    def issue(self, actions, **overrides):
        values = {
            "principal": "analytics-agent",
            "tenant_id": "demo-tenant",
            "session_id": "analytics-session-01",
            "tool_schema_hash": DATA_QUERY_SCHEMA_HASH,
            "policy": self.policy,
            "now": self.now,
            "ttl_seconds": 300,
        }
        values.update(overrides)
        return self.authority.authorize(actions, **values)

    def test_valid_three_step_data_plan_executes_and_receipts_bind_results(self):
        executions = [self.execute(i) for i in range(3)]
        self.assertEqual([x.action.step for x in executions], [0, 1, 2])
        self.assertEqual([x.result["returned_rows"] for x in executions], [2, 2, 1])
        self.assertEqual(sum(x.result["returned_rows"] for x in executions), 5)
        self.assertTrue(all(len(x.receipt.signature_hex) == 128 for x in executions))

    def test_policy_budget_and_allowlists_are_not_disclosed_in_grant(self):
        claims = self.authorization.grant.claims
        self.assertNotIn("aggregate_row_budget", claims)
        self.assertNotIn("allowed_fields_by_resource", claims)
        self.assertIn("policy_commitment", claims)
        self.assertEqual(len(claims["policy_commitment"]), 64)

    def test_private_policy_opening_matches_signed_commitment(self):
        from data_access import policy_commitment
        self.assertEqual(
            policy_commitment(
                self.authorization.issuer_policy,
                self.authorization.issuer_policy_salt,
            ),
            self.authorization.grant.claims["policy_commitment"],
        )

    def test_aggregate_reserved_row_quota_is_enforced(self):
        actions = (
            self.actions[0],
            self.actions[1],
            DataQueryAction(2, "sales_records", (("quarter", "2026-Q3"),), ("region", "revenue_cents"), 2),
        )
        with self.assertRaisesRegex(AuthorizationError, "aggregate reserved-row budget"):
            self.issue(actions)

    def test_per_action_row_limit_is_enforced(self):
        too_large = (
            DataQueryAction(0, "sales_records", (("quarter", "2026-Q3"),), ("region",), 4),
        )
        with self.assertRaisesRegex(AuthorizationError, "per-action row limit"):
            self.issue(too_large)

    def test_unauthorized_resource_is_denied(self):
        bad = (DataQueryAction(0, "employee_records", (("quarter", "2026-Q3"),), ("region",), 1),)
        with self.assertRaisesRegex(AuthorizationError, "resource is not allowed"):
            self.issue(bad)

    def test_sensitive_field_read_is_denied(self):
        bad = (DataQueryAction(0, "sales_records", (("quarter", "2026-Q3"),), ("customer_email",), 1),)
        with self.assertRaisesRegex(AuthorizationError, "selected field is not allowed"):
            self.issue(bad)

    def test_unauthorized_filter_field_is_denied(self):
        bad = (DataQueryAction(0, "sales_records", (("customer_id", "cust-001"),), ("region",), 1),)
        with self.assertRaisesRegex(AuthorizationError, "filter field is not allowed"):
            self.issue(bad)

    def test_unapproved_filter_value_is_denied(self):
        bad = (DataQueryAction(0, "sales_records", (("quarter", "2026-Q3' OR 1=1 --"),), ("region",), 1),)
        with self.assertRaisesRegex(AuthorizationError, "filter value is not allowed"):
            self.issue(bad)

    def test_action_parameter_tampering_is_denied(self):
        altered = DataQueryAction(0, "sales_records", (("quarter", "2026-Q3"),), ("region", "revenue_cents"), 3)
        with self.assertRaisesRegex(AuthorizationError, "not included"):
            self.execute(0, action=altered)

    def test_reordering_is_denied(self):
        with self.assertRaisesRegex(AuthorizationError, "not included"):
            self.execute(0, action=self.actions[1])

    def test_step_cannot_be_skipped(self):
        with self.assertRaisesRegex(AuthorizationError, "out of order"):
            self.execute(1)

    def test_step_replay_is_denied(self):
        self.execute(0)
        with self.assertRaisesRegex(AuthorizationError, "already been consumed"):
            self.execute(0)

    def test_cross_session_or_tenant_substitution_is_denied(self):
        with self.assertRaisesRegex(AuthorizationError, "session mismatch"):
            self.execute(0, session_id="different-session")
        with self.assertRaisesRegex(AuthorizationError, "tenant mismatch"):
            self.execute(0, tenant_id="different-tenant")

    def test_tool_schema_drift_is_denied(self):
        with self.assertRaisesRegex(AuthorizationError, "schema mismatch"):
            self.execute(0, tool_schema_hash="different-schema")

    def test_expired_plan_is_denied(self):
        with self.assertRaisesRegex(AuthorizationError, "expired"):
            self.execute(0, now=self.now + 300)

    def test_max_rows_boolean_is_rejected_as_non_integer(self):
        with self.assertRaisesRegex(AuthorizationError, "max_rows must be an integer"):
            DataQueryAction(0, "sales_records", (("quarter", "2026-Q3"),), ("region",), True)

    def test_duplicate_selected_fields_are_rejected(self):
        with self.assertRaisesRegex(AuthorizationError, "must not contain duplicates"):
            DataQueryAction(0, "sales_records", (("quarter", "2026-Q3"),), ("region", "region"), 1)

    def test_duplicate_filter_fields_are_rejected(self):
        with self.assertRaisesRegex(AuthorizationError, "duplicate filter field"):
            DataQueryAction(0, "sales_records", (("quarter", "2026-Q3"), ("quarter", "2026-Q4")), ("region",), 1)

    def test_result_contains_only_requested_fields(self):
        execution = self.execute(0)
        for row in execution.result["rows"]:
            self.assertEqual(set(row), {"region", "revenue_cents"})
            self.assertNotIn("customer_email", row)
            self.assertNotIn("customer_id", row)

    def test_gateway_rejects_tool_receipt_with_excessive_returned_rows(self):
        class OverReturningTool(MockReadOnlyDataTool):
            def execute(inner_self, *, action, grant, nullifier, schema_hash, executed_at):
                rows = [
                    {"region": "north", "revenue_cents": 1},
                    {"region": "south", "revenue_cents": 2},
                    {"region": "east", "revenue_cents": 3},
                ]
                result = {"rows": rows, "returned_rows": 3, "truncated": False}
                claims = {
                    "receipt_version": 1,
                    "grant_digest": grant_digest(grant),
                    "plan_root": grant.claims["plan_root"],
                    "step": action.step,
                    "nullifier": nullifier,
                    "action_hash": action_digest(action),
                    "result_hash": object_digest(result),
                    "returned_rows": 3,
                    "reserved_max_rows": action.max_rows,
                    "context_hash": plan_context_hash(grant.claims),
                    "tool_schema_hash": schema_hash,
                    "executed_at": executed_at,
                }
                signature = inner_self._key.sign(canonical_json(claims)).hex()
                return result, ToolReceipt(claims, signature)

        bad_tool = OverReturningTool(self.tool_key)
        bad_gateway = DataAccessGateway(
            issuer_public_key=self.authority.public_key,
            tool=bad_tool,
        )
        with self.assertRaisesRegex(AuthorizationError, "more rows than authorized"):
            bad_gateway.execute_step(
                grant=self.authorization.grant,
                action=self.actions[0],
                inclusion_proof=self.authorization.tree.proof(0),
                principal="analytics-agent",
                tenant_id="demo-tenant",
                session_id="analytics-session-01",
                tool_schema_hash=DATA_QUERY_SCHEMA_HASH,
                now=self.now + 1,
            )


if __name__ == "__main__":
    unittest.main()
