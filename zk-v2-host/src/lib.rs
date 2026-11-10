//! Host-side reference implementation for `data-query-v2-poseidon`.
//!
//! The host implementation defines canonical action encoding, Poseidon hashes,
//! quota and statement commitments, and a fixed-depth 16-leaf Merkle tree. The
//! `quota_circuit` module adds an initial fixed-three-action Halo2 quota circuit;
//! full plan-root and statement binding remain subsequent implementation steps.

use ff::{Field, PrimeField};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::pallas;
use std::collections::HashSet;

pub type Fp = pallas::Base;

pub const MAX_PLAN_ACTIONS: usize = 16;
pub const TREE_DEPTH: usize = 4;
pub const MAX_FILTERS_PER_ACTION: usize = 2;
pub const MAX_SELECTED_FIELDS: usize = 3;
pub const DATA_QUERY_SCHEMA_ID: u64 = 2;

pub const D_QUOTA: u64 = 0x5155_4f54_415f_5632;
const D_ACTION: u64 = 0x4143_544e_5f56_32;
const D_NODE: u64 = 0x4e4f_4445_5f56_325f;
const D_PAD: u64 = 0x5041_445f_5632_5f5f;
const D_STATEMENT: u64 = 0x5354_4154_454d_5432;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataQueryAction {
    pub step: u32,
    pub resource: String,
    pub filters: Vec<(String, String)>,
    pub selected_fields: Vec<String>,
    pub max_rows: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedAction {
    pub fields: [Fp; 14],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleInclusionProof {
    pub index: usize,
    pub siblings: [Fp; TREE_DEPTH],
}

#[derive(Clone, Debug)]
pub struct PoseidonPlanTree {
    levels: Vec<Vec<Fp>>,
    action_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicStatement {
    pub quota_commitment: Fp,
    pub plan_root: Fp,
    pub action_count: u64,
    pub context_digest: [u8; 32],
    pub schema_digest: [u8; 32],
}

/// Hash a fixed-length message using the same P128Pow5T3 / ConstantLength
/// construction intended for the Halo2 gadget.
pub fn poseidon_hash<const L: usize>(message: [Fp; L]) -> Fp {
    Hash::<Fp, P128Pow5T3, ConstantLength<L>, 3, 2>::init().hash(message)
}

fn f(value: u64) -> Fp {
    Fp::from(value)
}

pub fn field_to_hex(value: Fp) -> String {
    hex::encode(value.to_repr())
}

pub fn field_from_u64(value: u64) -> Fp {
    f(value)
}

pub fn field_from_u128(value: u128) -> Fp {
    Fp::from_u128(value)
}

/// Split a 32-byte digest into two 128-bit big-endian limbs. Neither limb is
/// reduced modulo the field; each is strictly smaller than 2^128.
pub fn digest_to_limbs(digest: [u8; 32]) -> [Fp; 2] {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&digest[..16]);
    lo.copy_from_slice(&digest[16..]);
    [
        field_from_u128(u128::from_be_bytes(hi)),
        field_from_u128(u128::from_be_bytes(lo)),
    ]
}

fn resource_id(resource: &str) -> Result<u64, String> {
    match resource {
        "sales_records" => Ok(1),
        "support_metrics" => Ok(2),
        _ => Err(format!("unsupported resource: {resource}")),
    }
}

fn selected_field_id(name: &str) -> Result<u64, String> {
    match name {
        "category" => Ok(1),
        "quarter" => Ok(2),
        "region" => Ok(3),
        "revenue_cents" => Ok(4),
        "ticket_count" => Ok(5),
        _ => Err(format!("unsupported selected field: {name}")),
    }
}

fn filter_field_id(name: &str) -> Result<u64, String> {
    match name {
        "category" => Ok(1),
        "quarter" => Ok(2),
        "region" => Ok(3),
        _ => Err(format!("unsupported filter field: {name}")),
    }
}

fn filter_value_id(field: &str, value: &str) -> Result<u64, String> {
    match (field, value) {
        ("category", "account") => Ok(1),
        ("category", "billing") => Ok(2),
        ("category", "technical") => Ok(3),
        ("quarter", "2026-Q3") => Ok(4),
        ("quarter", "2026-Q4") => Ok(5),
        ("region", "east") => Ok(6),
        ("region", "north") => Ok(7),
        ("region", "south") => Ok(8),
        ("region", "west") => Ok(9),
        _ => Err(format!("unsupported filter value {field}={value}")),
    }
}

fn selected_field_allowed(resource: u64, field: u64) -> bool {
    match resource {
        1 => matches!(field, 2 | 3 | 4),
        2 => matches!(field, 1 | 2 | 5),
        _ => false,
    }
}

fn filter_field_allowed(resource: u64, field: u64) -> bool {
    match resource {
        1 => matches!(field, 2 | 3),
        2 => matches!(field, 1 | 2),
        _ => false,
    }
}

/// Convert an action to its unique 14-field-element representation.
///
/// The function sorts filters and selected fields by their numeric IDs, rejects
/// duplicates and incompatible resource/field combinations, and applies zero
/// padding to unused slots.
pub fn encode_action(action: &DataQueryAction) -> Result<EncodedAction, String> {
    if action.step as usize >= MAX_PLAN_ACTIONS {
        return Err("step must be in 0..16".to_string());
    }

    let resource = resource_id(&action.resource)?;
    if !(1..=u16::MAX as u64).contains(&action.max_rows) {
        return Err("max_rows must be in 1..=65535".to_string());
    }

    if action.filters.is_empty() || action.filters.len() > MAX_FILTERS_PER_ACTION {
        return Err("filters count must be in 1..=2".to_string());
    }
    if action.selected_fields.is_empty() || action.selected_fields.len() > MAX_SELECTED_FIELDS {
        return Err("selected_fields count must be in 1..=3".to_string());
    }

    let mut filters = Vec::<(u64, u64)>::with_capacity(action.filters.len());
    let mut seen_filter_fields = HashSet::<u64>::new();
    for (field_name, value) in &action.filters {
        let field = filter_field_id(field_name)?;
        let value_id = filter_value_id(field_name, value)?;
        if !filter_field_allowed(resource, field) {
            return Err(format!(
                "filter field {field_name} is incompatible with resource {}",
                action.resource
            ));
        }
        if !seen_filter_fields.insert(field) {
            return Err(format!("duplicate filter field: {field_name}"));
        }
        filters.push((field, value_id));
    }
    filters.sort_unstable_by_key(|(field, _)| *field);

    let mut selected = Vec::<u64>::with_capacity(action.selected_fields.len());
    for name in &action.selected_fields {
        let id = selected_field_id(name)?;
        if !selected_field_allowed(resource, id) {
            return Err(format!(
                "selected field {name} is incompatible with resource {}",
                action.resource
            ));
        }
        selected.push(id);
    }
    selected.sort_unstable();
    if selected.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate selected field".to_string());
    }

    let mut words = [Fp::ZERO; 14];
    words[0] = f(D_ACTION);
    words[1] = f(DATA_QUERY_SCHEMA_ID);
    words[2] = f(action.step as u64);
    words[3] = f(resource);
    words[4] = f(filters.len() as u64);

    for (slot, (field, value)) in filters.iter().enumerate() {
        let offset = 5 + slot * 2;
        words[offset] = f(*field);
        words[offset + 1] = f(*value);
    }

    words[9] = f(selected.len() as u64);
    for (slot, field) in selected.iter().enumerate() {
        words[10 + slot] = f(*field);
    }
    words[13] = f(action.max_rows);

    Ok(EncodedAction { fields: words })
}

pub fn action_leaf(action: &DataQueryAction) -> Result<Fp, String> {
    Ok(poseidon_hash(encode_action(action)?.fields))
}

pub fn padding_leaf(index: usize) -> Result<Fp, String> {
    if index >= MAX_PLAN_ACTIONS {
        return Err("padding index must be in 0..16".to_string());
    }
    Ok(poseidon_hash([f(D_PAD), f(index as u64)]))
}

pub fn parent_hash(left: Fp, right: Fp) -> Fp {
    poseidon_hash([f(D_NODE), left, right])
}

impl PoseidonPlanTree {
    pub fn new(actions: &[DataQueryAction]) -> Result<Self, String> {
        if actions.is_empty() || actions.len() > MAX_PLAN_ACTIONS {
            return Err("plan action count must be in 1..=16".to_string());
        }

        let mut leaves = Vec::with_capacity(MAX_PLAN_ACTIONS);
        for index in 0..MAX_PLAN_ACTIONS {
            if index < actions.len() {
                if actions[index].step as usize != index {
                    return Err(format!("action at slot {index} must have step={index}"));
                }
                leaves.push(action_leaf(&actions[index])?);
            } else {
                leaves.push(padding_leaf(index)?);
            }
        }

        let mut levels = vec![leaves];
        while levels.last().expect("initial level exists").len() > 1 {
            let previous = levels.last().expect("previous level exists");
            let next = previous
                .chunks_exact(2)
                .map(|pair| parent_hash(pair[0], pair[1]))
                .collect::<Vec<_>>();
            levels.push(next);
        }

        debug_assert_eq!(levels.len(), TREE_DEPTH + 1);
        Ok(Self {
            levels,
            action_count: actions.len(),
        })
    }

    pub fn action_count(&self) -> usize {
        self.action_count
    }

    pub fn root(&self) -> Fp {
        self.levels[TREE_DEPTH][0]
    }

    pub fn proof(&self, index: usize) -> Result<MerkleInclusionProof, String> {
        if index >= self.action_count {
            return Err("cannot create inclusion proof for an inactive slot".to_string());
        }
        let mut cursor = index;
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        for level in 0..TREE_DEPTH {
            siblings.push(self.levels[level][cursor ^ 1]);
            cursor >>= 1;
        }
        let siblings: [Fp; TREE_DEPTH] = siblings
            .try_into()
            .map_err(|_| "internal Merkle proof depth error".to_string())?;
        Ok(MerkleInclusionProof { index, siblings })
    }
}

pub fn verify_inclusion(
    action: &DataQueryAction,
    action_count: usize,
    proof: &MerkleInclusionProof,
    expected_root: Fp,
) -> Result<bool, String> {
    if action_count == 0 || action_count > MAX_PLAN_ACTIONS {
        return Err("action_count must be in 1..=16".to_string());
    }
    if proof.index >= action_count || proof.index != action.step as usize {
        return Ok(false);
    }

    let mut current = action_leaf(action)?;
    let mut cursor = proof.index;
    for sibling in proof.siblings {
        current = if cursor & 1 == 0 {
            parent_hash(current, sibling)
        } else {
            parent_hash(sibling, current)
        };
        cursor >>= 1;
    }
    Ok(current == expected_root)
}

pub fn quota_commitment(budget: u64, per_action_limit: u64, blinding: Fp) -> Result<Fp, String> {
    if !(1..=u32::MAX as u64).contains(&budget) {
        return Err("aggregate budget must be in 1..=2^32-1".to_string());
    }
    if !(1..=u16::MAX as u64).contains(&per_action_limit) {
        return Err("per-action limit must be in 1..=65535".to_string());
    }
    Ok(poseidon_hash([
        f(D_QUOTA),
        f(budget),
        f(per_action_limit),
        blinding,
    ]))
}

/// Host-side pre-check. The Halo2 circuit must independently enforce the same
/// bounds; this function is not a substitute for constraints.
pub fn validate_quota_plan(
    actions: &[DataQueryAction],
    budget: u64,
    per_action_limit: u64,
) -> Result<u64, String> {
    if !(1..=u32::MAX as u64).contains(&budget) {
        return Err("aggregate budget must be in 1..=2^32-1".to_string());
    }
    if !(1..=u16::MAX as u64).contains(&per_action_limit) {
        return Err("per-action limit must be in 1..=65535".to_string());
    }
    if actions.is_empty() || actions.len() > MAX_PLAN_ACTIONS {
        return Err("plan action count must be in 1..=16".to_string());
    }
    let mut total = 0u64;
    for (index, action) in actions.iter().enumerate() {
        if action.step as usize != index {
            return Err(format!("action at slot {index} must have step={index}"));
        }
        if !(1..=per_action_limit).contains(&action.max_rows) {
            return Err(format!("action {index} exceeds the per-action limit"));
        }
        total = total
            .checked_add(action.max_rows)
            .ok_or_else(|| "aggregate row sum overflow".to_string())?;
    }
    if total > budget {
        return Err("plan exceeds aggregate row budget".to_string());
    }
    Ok(total)
}

pub fn statement_commitment(statement: &PublicStatement) -> Result<Fp, String> {
    if !(1..=MAX_PLAN_ACTIONS as u64).contains(&statement.action_count) {
        return Err("action_count must be in 1..=16".to_string());
    }
    let [ctx_hi, ctx_lo] = digest_to_limbs(statement.context_digest);
    let [schema_hi, schema_lo] = digest_to_limbs(statement.schema_digest);
    Ok(poseidon_hash([
        f(D_STATEMENT),
        statement.quota_commitment,
        statement.plan_root,
        f(statement.action_count),
        ctx_hi,
        ctx_lo,
        schema_hi,
        schema_lo,
    ]))
}

/// Public-input order specified by relation-spec v0.2:
/// C_quota, R_plan, n, H_ctx_hi, H_ctx_lo, H_schema_hi, H_schema_lo, C_statement.
pub fn public_input_fields(statement: &PublicStatement) -> Result<[Fp; 8], String> {
    let [ctx_hi, ctx_lo] = digest_to_limbs(statement.context_digest);
    let [schema_hi, schema_lo] = digest_to_limbs(statement.schema_digest);
    let c_statement = statement_commitment(statement)?;
    Ok([
        statement.quota_commitment,
        statement.plan_root,
        f(statement.action_count),
        ctx_hi,
        ctx_lo,
        schema_hi,
        schema_lo,
        c_statement,
    ])
}

pub fn demo_plan() -> Vec<DataQueryAction> {
    vec![
        DataQueryAction {
            step: 0,
            resource: "sales_records".into(),
            filters: vec![("quarter".into(), "2026-Q3".into())],
            selected_fields: vec!["region".into(), "revenue_cents".into()],
            max_rows: 2,
        },
        DataQueryAction {
            step: 1,
            resource: "support_metrics".into(),
            filters: vec![("quarter".into(), "2026-Q3".into())],
            selected_fields: vec!["category".into(), "ticket_count".into()],
            max_rows: 2,
        },
        DataQueryAction {
            step: 2,
            resource: "sales_records".into(),
            filters: vec![
                ("quarter".into(), "2026-Q3".into()),
                ("region".into(), "north".into()),
            ],
            selected_fields: vec!["region".into(), "revenue_cents".into()],
            max_rows: 1,
        },
    ]
}

pub fn demo_statement(plan_root: Fp, quota_commitment: Fp, action_count: usize) -> PublicStatement {
    // Fixture digests only. Replace these with the exact SHA-256 context and v2
    // tool-schema digests before integrating the real authorization envelope.
    PublicStatement {
        quota_commitment,
        plan_root,
        action_count: action_count as u64,
        context_digest: [0x11; 32],
        schema_digest: [0x22; 32],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_actions_match_the_specified_fixed_encoding() {
        let actions = demo_plan();
        let encoded0 = encode_action(&actions[0]).unwrap().fields;
        assert_eq!(encoded0.len(), 14);
        assert_eq!(encoded0[1], f(2));
        assert_eq!(encoded0[2], f(0));
        assert_eq!(encoded0[3], f(1));
        assert_eq!(encoded0[4], f(1));
        assert_eq!(encoded0[5], f(2));
        assert_eq!(encoded0[6], f(4));
        assert_eq!(encoded0[9], f(2));
        assert_eq!(encoded0[10], f(3));
        assert_eq!(encoded0[11], f(4));
        assert_eq!(encoded0[12], Fp::ZERO);
        assert_eq!(encoded0[13], f(2));
    }

    #[test]
    fn filters_and_selected_fields_are_canonicalized_by_numeric_id() {
        let action = DataQueryAction {
            step: 2,
            resource: "sales_records".into(),
            filters: vec![
                ("region".into(), "north".into()),
                ("quarter".into(), "2026-Q3".into()),
            ],
            selected_fields: vec!["revenue_cents".into(), "region".into()],
            max_rows: 1,
        };
        let words = encode_action(&action).unwrap().fields;
        assert_eq!((words[5], words[6]), (f(2), f(4)));
        assert_eq!((words[7], words[8]), (f(3), f(7)));
        assert_eq!((words[10], words[11]), (f(3), f(4)));
    }

    #[test]
    fn demo_plan_builds_a_fixed_16_leaf_tree_and_all_paths_verify() {
        let actions = demo_plan();
        let tree = PoseidonPlanTree::new(&actions).unwrap();
        assert_eq!(tree.action_count(), 3);
        for (index, action) in actions.iter().enumerate() {
            let proof = tree.proof(index).unwrap();
            assert!(verify_inclusion(action, actions.len(), &proof, tree.root()).unwrap());
            assert_eq!(proof.siblings.len(), TREE_DEPTH);
        }
    }

    #[test]
    fn modified_action_does_not_verify_under_original_root() {
        let actions = demo_plan();
        let tree = PoseidonPlanTree::new(&actions).unwrap();
        let mut changed = actions[0].clone();
        changed.max_rows = 3;
        let proof = tree.proof(0).unwrap();
        assert!(!verify_inclusion(&changed, actions.len(), &proof, tree.root()).unwrap());
    }

    #[test]
    fn plan_order_is_bound_into_root() {
        let actions = demo_plan();
        let root = PoseidonPlanTree::new(&actions).unwrap().root();
        let mut invalid_reordering = actions.clone();
        invalid_reordering.swap(0, 1);
        assert!(PoseidonPlanTree::new(&invalid_reordering).is_err());

        let mut reordered_plan = invalid_reordering;
        reordered_plan[0].step = 0;
        reordered_plan[1].step = 1;
        let reordered_root = PoseidonPlanTree::new(&reordered_plan).unwrap().root();
        assert_ne!(root, reordered_root);
    }

    #[test]
    fn malformed_actions_are_rejected() {
        let mut action = demo_plan()[0].clone();
        action.max_rows = 65_536;
        assert!(encode_action(&action).is_err());

        let mut action = demo_plan()[0].clone();
        action.selected_fields.push("ticket_count".into());
        assert!(encode_action(&action).is_err());

        let mut action = demo_plan()[0].clone();
        action.filters.push(("quarter".into(), "2026-Q4".into()));
        assert!(encode_action(&action).is_err());

        let mut action = demo_plan()[0].clone();
        action.selected_fields = vec!["category".into()];
        assert!(encode_action(&action).is_err());

        let mut action = demo_plan()[0].clone();
        action.filters = vec![("category".into(), "technical".into())];
        assert!(encode_action(&action).is_err());
    }

    #[test]
    fn plan_padding_is_position_bound() {
        assert_ne!(padding_leaf(3).unwrap(), padding_leaf(4).unwrap());
    }

    #[test]
    fn quota_bounds_are_checked_and_demo_plan_is_valid() {
        let actions = demo_plan();
        assert_eq!(validate_quota_plan(&actions, 5, 3).unwrap(), 5);
        assert!(validate_quota_plan(&actions, 4, 3).is_err());
        assert!(validate_quota_plan(&actions, 5, 1).is_err());
        assert!(quota_commitment(0, 3, f(9)).is_err());
        assert!(quota_commitment(5, 0, f(9)).is_err());
        assert!(quota_commitment(u32::MAX as u64 + 1, 3, f(9)).is_err());
        assert!(quota_commitment(5, u16::MAX as u64 + 1, f(9)).is_err());
    }

    #[test]
    fn quota_commitment_binds_budget_limit_and_blinding() {
        let c = quota_commitment(5, 3, f(123456789)).unwrap();
        assert_ne!(c, quota_commitment(6, 3, f(123456789)).unwrap());
        assert_ne!(c, quota_commitment(5, 4, f(123456789)).unwrap());
        assert_ne!(c, quota_commitment(5, 3, f(123456790)).unwrap());
    }

    #[test]
    fn digest_limbs_are_big_endian_and_statement_binds_context_and_schema() {
        let mut digest = [0u8; 32];
        digest[15] = 1;
        digest[31] = 2;
        let limbs = digest_to_limbs(digest);
        assert_eq!(limbs[0], f(1));
        assert_eq!(limbs[1], f(2));

        let actions = demo_plan();
        let root = PoseidonPlanTree::new(&actions).unwrap().root();
        let commitment = quota_commitment(5, 3, f(123456789)).unwrap();
        let statement = demo_statement(root, commitment, actions.len());
        let c_statement = statement_commitment(&statement).unwrap();
        let mut changed_context = statement;
        changed_context.context_digest[0] ^= 1;
        assert_ne!(c_statement, statement_commitment(&changed_context).unwrap());
        let mut changed_schema = statement;
        changed_schema.schema_digest[31] ^= 1;
        assert_ne!(c_statement, statement_commitment(&changed_schema).unwrap());
        assert_eq!(public_input_fields(&statement).unwrap()[7], c_statement);
    }

    #[test]
    fn host_hashes_are_deterministic() {
        let message = [f(D_PAD), f(7)];
        assert_eq!(poseidon_hash(message), poseidon_hash(message));
    }
}

/// First Halo2 quota-circuit increment (fixed three-action shape).
pub mod quota_circuit;
