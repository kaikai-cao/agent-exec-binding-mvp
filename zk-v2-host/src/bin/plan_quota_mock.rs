//! Step 3.2B mock-prover runner for the 16-leaf plan-root circuit.
//!
//! Prints the eight public inputs, the in-circuit R_plan / C_quota /
//! C_statement values, and the MockProver result. No proof is generated and
//! no real authorization data is consumed.

use agent_exec_binding_host_v2::{
    demo_plan,
    plan_quota_circuit::{PlanQuotaCircuit, PUBLIC_INSTANCE_COUNT},
    quota_commitment, statement_commitment, validate_quota_plan, Fp, PoseidonPlanTree,
};
use ff::PrimeField;
use halo2_proofs::dev::MockProver;

const K: u32 = 13;
const BUDGET: u64 = 5;
const LIMIT: u64 = 3;

fn main() -> Result<(), String> {
    let actions = demo_plan();
    let reserved = validate_quota_plan(&actions, BUDGET, LIMIT)?;
    let blinding = Fp::from(123_456_789u64); // deterministic fixture only
    let (circuit, public) =
        PlanQuotaCircuit::from_plan(&actions, BUDGET, LIMIT, blinding, [0x11; 32], [0x22; 32])?;

    let prover = MockProver::run(K, &circuit, vec![public.to_vec()])
        .map_err(|error| format!("MockProver synthesis failed: {error:?}"))?;
    prover
        .verify()
        .map_err(|failures| format!("MockProver rejected the valid witness: {failures:?}"))?;

    let tree = PoseidonPlanTree::new(&actions)?;
    let c_quota = quota_commitment(BUDGET, LIMIT, blinding)?;
    let c_statement = statement_commitment(&agent_exec_binding_host_v2::PublicStatement {
        quota_commitment: c_quota,
        plan_root: tree.root(),
        action_count: actions.len() as u64,
        context_digest: [0x11; 32],
        schema_digest: [0x22; 32],
    })?;

    println!("circuit=plan-quota-16-leaf-statement-binding-v1");
    println!("mock_prover=accepted");
    println!("circuit_k={K}");
    println!("instance_column_count={PUBLIC_INSTANCE_COUNT}");
    println!(
        "public_input_order=C_quota,R_plan,n,H_ctx_hi,H_ctx_lo,H_schema_hi,H_schema_lo,C_statement"
    );
    println!("action_count={}", actions.len());
    println!("blinding=DEMO_ONLY");
    println!("aggregate_reserved_rows={reserved}");
    println!("c_quota_matches_host={}", public[0] == c_quota);
    println!("r_plan_matches_host={}", public[1] == tree.root());
    println!("c_statement_matches_host={}", public[7] == c_statement);
    println!("C_quota={}", hex::encode(public[0].to_repr()));
    println!("R_plan={}", hex::encode(public[1].to_repr()));
    println!("n={}", actions.len());
    println!("C_statement={}", hex::encode(public[7].to_repr()));
    for (index, value) in public.iter().enumerate() {
        println!("public_inputs[{index}]={}", hex::encode(value.to_repr()));
    }
    println!("proof_generated=false");
    println!("ed25519_signature_checked=false");
    println!("private_allowlist_proven=false");
    Ok(())
}
