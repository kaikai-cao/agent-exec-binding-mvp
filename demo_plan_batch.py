"""Run a harmless three-step plan authorization and mock execution demo."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plan_batch import (
    MockProcurementTool,
    PlanAuthority,
    PlanExecutionGateway,
    PlanPolicy,
    PlannedAction,
)


def main() -> None:
    issuer = PlanAuthority(Ed25519PrivateKey.generate())
    tool = MockProcurementTool(Ed25519PrivateKey.generate())
    schema_hash = "payments.transfer.schema.v1"
    policy = PlanPolicy(
        policy_id="demo-procurement",
        version=1,
        allowed_tool_id="payments.transfer",
        allowed_operation="transfer",
        allowed_recipients=("vendor-A", "vendor-B", "vendor-C"),
        allowed_currency="USD",
        max_per_action_cents=500_000,
        aggregate_budget_cents=900_000,
        tenant_id="demo-tenant",
        max_plan_actions=16,
    )
    actions = (
        PlannedAction(0, "payments.transfer", "transfer", "vendor-A", 230_000),
        PlannedAction(1, "payments.transfer", "transfer", "vendor-B", 170_000),
        PlannedAction(2, "payments.transfer", "transfer", "vendor-C", 410_000),
    )
    now = 1_800_000_000
    authorization = issuer.authorize(
        actions,
        principal="demo-agent",
        tenant_id="demo-tenant",
        session_id="demo-session",
        tool_schema_hash=schema_hash,
        policy=policy,
        now=now,
        ttl_seconds=300,
    )
    gateway = PlanExecutionGateway(
        issuer_public_key=issuer.public_key,
        tool=tool,
        expected_tool_schema_hash=schema_hash,
    )

    print("Plan root:", authorization.grant.claims["plan_root"])
    print("Action count:", authorization.grant.claims["action_count"])
    print("Budget value included in grant:", "aggregate_budget_cents" in authorization.grant.claims)
    for index, action in enumerate(actions):
        execution = gateway.execute_step(
            grant=authorization.grant,
            action=action,
            inclusion_proof=authorization.tree.proof(index),
            principal="demo-agent",
            tenant_id="demo-tenant",
            session_id="demo-session",
            tool_schema_hash=schema_hash,
            now=now + 1 + index,
        )
        print(
            f"Step {index}: {execution.result['status']}; "
            f"receipt={execution.receipt.signature_hex[:16]}…; "
            f"nullifier={execution.nullifier[:16]}…"
        )


if __name__ == "__main__":
    main()
