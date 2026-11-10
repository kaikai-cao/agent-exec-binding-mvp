"""Run the harmless three-step, read-only data-access plan demo."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from data_access import (
    DATA_QUERY_SCHEMA_HASH,
    DataAccessAuthority,
    DataAccessGateway,
    MockReadOnlyDataTool,
    build_demo_plan,
    build_demo_policy,
    policy_commitment,
)


def main() -> None:
    issuer = DataAccessAuthority(Ed25519PrivateKey.generate())
    tool = MockReadOnlyDataTool(Ed25519PrivateKey.generate())
    policy = build_demo_policy()
    actions = build_demo_plan()
    now = 1_800_000_000

    authorization = issuer.authorize(
        actions,
        principal="analytics-agent",
        tenant_id="demo-tenant",
        session_id="analytics-session-01",
        tool_schema_hash=DATA_QUERY_SCHEMA_HASH,
        policy=policy,
        now=now,
        ttl_seconds=300,
    )
    gateway = DataAccessGateway(
        issuer_public_key=issuer.public_key,
        tool=tool,
    )

    claims = authorization.grant.claims
    print("Plan root:", claims["plan_root"])
    print("Action count:", claims["action_count"])
    print("Policy commitment:", claims["policy_commitment"])
    print("Aggregate row budget exposed in grant:", "aggregate_row_budget" in claims)
    print("Policy opening matches commitment:", policy_commitment(authorization.issuer_policy, authorization.issuer_policy_salt) == claims["policy_commitment"])

    total_rows = 0
    for index, action in enumerate(actions):
        execution = gateway.execute_step(
            grant=authorization.grant,
            action=action,
            inclusion_proof=authorization.tree.proof(index),
            principal="analytics-agent",
            tenant_id="demo-tenant",
            session_id="analytics-session-01",
            tool_schema_hash=DATA_QUERY_SCHEMA_HASH,
            now=now + 1 + index,
        )
        total_rows += execution.result["returned_rows"]
        print(
            f"Step {index}: accepted; resource={action.resource}; "
            f"returned_rows={execution.result['returned_rows']}; "
            f"receipt={execution.receipt.signature_hex[:16]}…; "
            f"nullifier={execution.nullifier[:16]}…"
        )
        for row in execution.result["rows"]:
            print("  ", row)

    print("Total returned rows:", total_rows)
    print("Reserved row budget:", policy.aggregate_row_budget, "(issuer-held; not in grant)")


if __name__ == "__main__":
    main()
