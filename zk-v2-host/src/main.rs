use agent_exec_binding_host_v2::{
    demo_plan, demo_statement, field_to_hex, quota_commitment, validate_quota_plan,
    verify_inclusion, PoseidonPlanTree,
};
use pasta_curves::pallas;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let actions = demo_plan();
    let total = validate_quota_plan(&actions, 5, 3)?;

    let tree = PoseidonPlanTree::new(&actions)?;
    // Deterministic fixture blinding for test-vector generation only. Never use
    // this value in an actual authorization grant.
    let blinding = pallas::Base::from(123_456_789u64);
    let c_quota = quota_commitment(5, 3, blinding)?;
    let statement = demo_statement(tree.root(), c_quota, actions.len());
    let public_inputs = agent_exec_binding_host_v2::public_input_fields(&statement)?;

    println!("protocol=data-query-v2-poseidon");
    println!("action_count={}", actions.len());
    println!("reserved_rows={total}");
    println!("blinding=DEMO_ONLY");
    println!("C_quota={}", field_to_hex(c_quota));
    println!("R_plan={}", field_to_hex(tree.root()));
    println!("C_statement={}", field_to_hex(public_inputs[7]));
    println!("public_inputs:");
    for (i, value) in public_inputs.iter().enumerate() {
        println!("  [{i}]={}", field_to_hex(*value));
    }

    for (index, action) in actions.iter().enumerate() {
        let proof = tree.proof(index)?;
        let verified = verify_inclusion(action, actions.len(), &proof, tree.root())?;
        println!("step_{index}_inclusion_verified={verified}");
        for (level, sibling) in proof.siblings.iter().enumerate() {
            println!("  step_{index}_sibling_{level}={}", field_to_hex(*sibling));
        }
    }

    Ok(())
}
