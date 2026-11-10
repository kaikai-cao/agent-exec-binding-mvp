use agent_exec_binding_host_v2::{quota_circuit::QuotaCircuit, quota_commitment, Fp};
use ff::PrimeField;
use halo2_proofs::dev::MockProver;

fn main() -> Result<(), String> {
    let blinding = Fp::from(123_456_789);
    let budget = 5;
    let per_action_limit = 3;
    let max_rows = [2, 2, 1];
    let public_commitment = quota_commitment(budget, per_action_limit, blinding)?;
    let circuit = QuotaCircuit::new(budget, per_action_limit, blinding, max_rows);

    let prover = MockProver::run(9, &circuit, vec![vec![public_commitment]])
        .map_err(|error| format!("MockProver synthesis failed: {error:?}"))?;
    prover
        .verify()
        .map_err(|failures| format!("MockProver rejected the valid demo witness: {failures:?}"))?;

    println!("circuit=quota-commitment-three-action-v1");
    println!("mock_prover=accepted");
    println!("public_instance_count=1");
    println!(
        "quota_commitment={}",
        hex::encode(public_commitment.to_repr())
    );
    println!("budget_and_per_action_limit_are_private=true");
    println!("rows=[2,2,1]");
    println!("aggregate_reserved_rows=5");
    Ok(())
}
