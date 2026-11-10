import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plan_batch import (
    AuthorizationError,
    MerkleTree,
    MockProcurementTool,
    PlanAuthority,
    PlanExecutionGateway,
    PlanPolicy,
    PlannedAction,
    MerkleInclusionProof,
    MerkleSibling,
)


class PlanBatchTests(unittest.TestCase):
    def setUp(self):
        self.issuer_key = Ed25519PrivateKey.generate()
        self.tool_key = Ed25519PrivateKey.generate()
        self.authority = PlanAuthority(self.issuer_key)
        self.tool = MockProcurementTool(self.tool_key)
        self.schema_hash = "schema-v1-sha256-demo"
        self.policy = PlanPolicy(
            policy_id="procurement-policy",
            version=3,
            allowed_tool_id="payments.transfer",
            allowed_operation="transfer",
            allowed_recipients=("vendor-A", "vendor-B", "vendor-C"),
            allowed_currency="USD",
            max_per_action_cents=500_000,
            aggregate_budget_cents=900_000,
            tenant_id="tenant-1",
            max_plan_actions=16,
        )
        self.actions = (
            PlannedAction(0, "payments.transfer", "transfer", "vendor-A", 230_000),
            PlannedAction(1, "payments.transfer", "transfer", "vendor-B", 170_000),
            PlannedAction(2, "payments.transfer", "transfer", "vendor-C", 410_000),
        )
        self.authorization = self.authority.authorize(
            self.actions,
            principal="agent-1",
            tenant_id="tenant-1",
            session_id="session-7",
            tool_schema_hash=self.schema_hash,
            policy=self.policy,
            now=1_800_000_000,
            ttl_seconds=300,
        )
        self.gateway = PlanExecutionGateway(
            issuer_public_key=self.authority.public_key,
            tool=self.tool,
            expected_tool_schema_hash=self.schema_hash,
        )

    def execute(self, action_index, **overrides):
        action = overrides.pop("action", self.actions[action_index])
        proof = overrides.pop("proof", self.authorization.tree.proof(action_index))
        values = {
            "grant": self.authorization.grant,
            "action": action,
            "inclusion_proof": proof,
            "principal": "agent-1",
            "tenant_id": "tenant-1",
            "session_id": "session-7",
            "tool_schema_hash": self.schema_hash,
            "now": 1_800_000_001,
        }
        values.update(overrides)
        return self.gateway.execute_step(**values)

    def test_valid_plan_executes_in_order_and_receipts_verify(self):
        results = [self.execute(i) for i in range(3)]
        self.assertEqual([r.action.step for r in results], [0, 1, 2])
        self.assertTrue(all(r.result["status"] == "accepted" for r in results))
        self.assertTrue(all(len(r.receipt.signature_hex) == 128 for r in results))

    def test_plan_with_aggregate_budget_over_limit_is_denied(self):
        too_expensive = (
            PlannedAction(0, "payments.transfer", "transfer", "vendor-A", 500_000),
            PlannedAction(1, "payments.transfer", "transfer", "vendor-B", 450_001),
        )
        with self.assertRaisesRegex(AuthorizationError, "aggregate budget"):
            self.authority.authorize(
                too_expensive,
                principal="agent-1",
                tenant_id="tenant-1",
                session_id="session-7",
                tool_schema_hash=self.schema_hash,
                policy=self.policy,
                now=1_800_000_000,
            )

    def test_per_action_limit_is_enforced(self):
        too_large = (PlannedAction(0, "payments.transfer", "transfer", "vendor-A", 500_001),)
        with self.assertRaisesRegex(AuthorizationError, "per-action"):
            self.authority.authorize(
                too_large,
                principal="agent-1",
                tenant_id="tenant-1",
                session_id="session-7",
                tool_schema_hash=self.schema_hash,
                policy=self.policy,
                now=1_800_000_000,
            )

    def test_action_tampering_is_denied(self):
        altered = PlannedAction(0, "payments.transfer", "transfer", "vendor-A", 230_001)
        with self.assertRaisesRegex(AuthorizationError, "not included"):
            self.execute(0, action=altered)

    def test_action_reordering_is_denied(self):
        # A different action at index zero cannot be presented as step zero.
        swapped = self.actions[1]
        with self.assertRaisesRegex(AuthorizationError, "not included"):
            self.execute(0, action=swapped)

    def test_wrong_inclusion_path_is_denied(self):
        proof = self.authorization.tree.proof(1)
        with self.assertRaisesRegex(AuthorizationError, "not included"):
            self.execute(0, proof=proof)

    def test_step_cannot_be_skipped(self):
        with self.assertRaisesRegex(AuthorizationError, "out of order"):
            self.execute(1)

    def test_step_replay_is_denied(self):
        self.execute(0)
        with self.assertRaisesRegex(AuthorizationError, "already been consumed"):
            self.execute(0)

    def test_cross_session_substitution_is_denied(self):
        with self.assertRaisesRegex(AuthorizationError, "session mismatch"):
            self.execute(0, session_id="session-other")

    def test_schema_drift_is_denied(self):
        with self.assertRaisesRegex(AuthorizationError, "schema mismatch"):
            self.execute(0, tool_schema_hash="schema-v2")

    def test_expired_plan_is_denied(self):
        with self.assertRaisesRegex(AuthorizationError, "expired"):
            self.execute(0, now=1_800_000_301)

    def test_tampered_grant_is_denied(self):
        original = self.authorization.grant
        claims = dict(original.claims)
        claims["plan_root"] = "00" * 32
        from plan_batch import PlanGrant
        tampered = PlanGrant(claims, original.signature_hex)
        with self.assertRaisesRegex(AuthorizationError, "signature"):
            self.gateway.execute_step(
                grant=tampered,
                action=self.actions[0],
                inclusion_proof=self.authorization.tree.proof(0),
                principal="agent-1",
                tenant_id="tenant-1",
                session_id="session-7",
                tool_schema_hash=self.schema_hash,
                now=1_800_000_001,
            )

    def test_invalid_plan_step_sequence_rejected_at_tree_creation(self):
        unordered = (
            PlannedAction(1, "payments.transfer", "transfer", "vendor-A", 100),
            PlannedAction(0, "payments.transfer", "transfer", "vendor-B", 100),
        )
        with self.assertRaisesRegex(AuthorizationError, "contiguous and ordered"):
            MerkleTree(unordered)

    def test_odd_leaf_count_merkle_proofs_verify(self):
        actions = (
            PlannedAction(0, "payments.transfer", "transfer", "vendor-A", 100),
            PlannedAction(1, "payments.transfer", "transfer", "vendor-B", 200),
            PlannedAction(2, "payments.transfer", "transfer", "vendor-C", 300),
        )
        tree = MerkleTree(actions)
        for index, action in enumerate(actions):
            self.assertTrue(MerkleTree.verify(action, tree.proof(index), tree.root))


if __name__ == "__main__":
    unittest.main()
