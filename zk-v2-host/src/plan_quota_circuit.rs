//! Step 3.2B: 16-leaf plan-root and statement-binding Halo2 circuit.
//!
//! Implements the full `data-query-v2-poseidon` arithmetic relation from
//! `docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md` on top of the
//! fixed-three-action quota prototype:
//!
//! - hidden B (32-bit, nonzero) and L (16-bit, nonzero) with integer range
//!   constraints and difference witnesses (no finite-field size comparison);
//! - 16 fixed action slots with canonical 14-element encoding, enforced in the
//!   circuit (including public tool-schema structural compatibility);
//! - active-prefix enforcement (active[0]=1, contiguous prefix, n=sum active);
//! - canonical position-bound padding leaves for inactive slots;
//! - a four-level Poseidon Merkle tree with R_plan computed **inside** the
//!   circuit and bound to public instance 1;
//! - a Poseidon statement commitment computed inside the circuit and bound to
//!   public instance 7, with 128-bit range checks on both context limbs and
//!   both schema limbs.
//!
//! Trust boundary: this circuit does NOT prove Ed25519 signatures, private
//! resource/field/filter allowlists, plan nonce/expiry, nullifier atomicity,
//! database execution, or query completeness. The structural compatibility
//! rules enforced below are public tool-schema checks, not private-policy
//! allowlist proofs.

use crate::{
    digest_to_limbs, encode_action, poseidon_hash, DataQueryAction, Fp, D_ACTION, D_NODE, D_PAD,
    D_QUOTA, D_STATEMENT, MAX_PLAN_ACTIONS,
};
use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

/// Number of public inputs required by relation-spec v0.2 section 7.1.
pub const PUBLIC_INSTANCE_COUNT: usize = 8;

// ---------------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PlanQuotaCircuit {
    budget: Option<u64>,
    limit: Option<u64>,
    blinding: Option<Fp>,
    /// 16 slots x 14 field elements. Inactive slots are required to be zero.
    words: Option<[[Fp; 14]; MAX_PLAN_ACTIONS]>,
    /// 16 active flags (0/1); required to form a contiguous prefix from 0.
    active: Option<[u64; MAX_PLAN_ACTIONS]>,
    /// Two 128-bit big-endian limbs of the 32-byte context digest.
    ctx_limbs: Option<[Fp; 2]>,
    /// Two 128-bit big-endian limbs of the 32-byte v2 tool-schema digest.
    schema_limbs: Option<[Fp; 2]>,
}

impl PlanQuotaCircuit {
    fn blank() -> Self {
        Self {
            budget: None,
            limit: None,
            blinding: None,
            words: None,
            active: None,
            ctx_limbs: None,
            schema_limbs: None,
        }
    }

    /// Raw constructor for honest witnesses and negative tests alike. No
    /// host-side validation is applied, so a MockProver rejection is always a
    /// circuit constraint failure rather than an encoder pre-check.
    #[allow(clippy::too_many_arguments)]
    pub fn new_raw(
        budget: u64,
        limit: u64,
        blinding: Fp,
        words: [[Fp; 14]; MAX_PLAN_ACTIONS],
        active: [u64; MAX_PLAN_ACTIONS],
        ctx_limbs: [Fp; 2],
        schema_limbs: [Fp; 2],
    ) -> Self {
        Self {
            budget: Some(budget),
            limit: Some(limit),
            blinding: Some(blinding),
            words: Some(words),
            active: Some(active),
            ctx_limbs: Some(ctx_limbs),
            schema_limbs: Some(schema_limbs),
        }
    }

    /// Build a witness from host-encoded actions and compute the matching
    /// eight public inputs with the host Poseidon primitives.
    pub fn from_plan(
        actions: &[DataQueryAction],
        budget: u64,
        limit: u64,
        blinding: Fp,
        context_digest: [u8; 32],
        schema_digest: [u8; 32],
    ) -> Result<(Self, [Fp; PUBLIC_INSTANCE_COUNT]), String> {
        if actions.is_empty() || actions.len() > MAX_PLAN_ACTIONS {
            return Err("plan action count must be in 1..=16".to_string());
        }
        let mut words = [[Fp::ZERO; 14]; MAX_PLAN_ACTIONS];
        let mut active = [0u64; MAX_PLAN_ACTIONS];
        for (index, action) in actions.iter().enumerate() {
            if action.step as usize != index {
                return Err(format!("action at slot {index} must have step={index}"));
            }
            words[index] = encode_action(action)?.fields;
            active[index] = 1;
        }
        let [ctx_hi, ctx_lo] = digest_to_limbs(context_digest);
        let [schema_hi, schema_lo] = digest_to_limbs(schema_digest);
        let circuit = Self::new_raw(
            budget,
            limit,
            blinding,
            words,
            active,
            [ctx_hi, ctx_lo],
            [schema_hi, schema_lo],
        );
        let public = raw_public_inputs(
            Fp::from(budget),
            Fp::from(limit),
            blinding,
            &words,
            &active,
            ctx_hi,
            ctx_lo,
            schema_hi,
            schema_lo,
        );
        Ok((circuit, public))
    }
}

/// Compute all eight public inputs directly from raw field values, bypassing
/// host-side validators. Used for honest vectors and to isolate failures in
/// negative tests (so the circuit, not the encoder, is what rejects them).
#[allow(clippy::too_many_arguments)]
pub fn raw_public_inputs(
    budget: Fp,
    limit: Fp,
    blinding: Fp,
    words: &[[Fp; 14]; MAX_PLAN_ACTIONS],
    active: &[u64; MAX_PLAN_ACTIONS],
    ctx_hi: Fp,
    ctx_lo: Fp,
    schema_hi: Fp,
    schema_lo: Fp,
) -> [Fp; PUBLIC_INSTANCE_COUNT] {
    let c_quota = poseidon_hash([Fp::from(D_QUOTA), budget, limit, blinding]);

    let mut leaves = Vec::with_capacity(MAX_PLAN_ACTIONS);
    for index in 0..MAX_PLAN_ACTIONS {
        let leaf = if active[index] == 1 {
            poseidon_hash(words[index])
        } else {
            poseidon_hash([Fp::from(D_PAD), Fp::from(index as u64)])
        };
        leaves.push(leaf);
    }
    while leaves.len() > 1 {
        leaves = leaves
            .chunks_exact(2)
            .map(|pair| poseidon_hash([Fp::from(D_NODE), pair[0], pair[1]]))
            .collect();
    }
    let r_plan = leaves[0];
    let n = active.iter().copied().sum::<u64>();
    let c_statement = poseidon_hash([
        Fp::from(D_STATEMENT),
        c_quota,
        r_plan,
        Fp::from(n),
        ctx_hi,
        ctx_lo,
        schema_hi,
        schema_lo,
    ]);
    [
        c_quota,
        r_plan,
        Fp::from(n),
        ctx_hi,
        ctx_lo,
        schema_hi,
        schema_lo,
        c_statement,
    ]
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PlanQuotaConfig {
    poseidon: Pow5Config<Fp, 3, 2>,
    instance: Column<Instance>,

    range_value: Column<Advice>,
    range_inverse: Column<Advice>,
    range_bits: [Column<Advice>; 32],
    nz_flag: Column<Advice>,
    q_range5: Selector,
    q_range16: Selector,
    q_range20: Selector,
    q_range32: Selector,
    q_nz: Selector,

    words: [Column<Advice>; 14],
    active: Column<Advice>,
    slot_index: Column<Advice>,
    limit_diff: Column<Advice>,
    limit_col: Column<Advice>,
    n_col: Column<Advice>,
    sum_col: Column<Advice>,
    budget_col: Column<Advice>,
    budget_diff: Column<Advice>,
    q_slot: Selector,
    q_first: Selector,
    q_prefix: Selector,
    q_nsum: Selector,
    q_sum: Selector,
    q_budget: Selector,

    sel_active: Column<Advice>,
    sel_action: Column<Advice>,
    sel_pad: Column<Advice>,
    sel_leaf: Column<Advice>,
    q_leaf: Selector,

    limb_value: Column<Advice>,
    chunk: Column<Advice>,
    q_limb128: Selector,

    tag: Column<Advice>,
}

#[derive(Clone, Copy)]
enum RangeKind {
    Bits5,
    Bits16,
    Bits20,
    Bits32,
}

fn value_fp(value: Option<Fp>) -> Value<Fp> {
    value.map(Value::known).unwrap_or_else(Value::unknown)
}

fn value_u64(value: Option<u64>) -> Value<Fp> {
    value
        .map(|value| Value::known(Fp::from(value)))
        .unwrap_or_else(Value::unknown)
}

fn bit_from(value: Fp, bit: usize) -> Fp {
    let repr = value.to_repr();
    Fp::from(u64::from((repr.as_ref()[bit / 8] >> (bit % 8)) & 1))
}

/// Assign one generic range-check row. `nz` is an advice-assigned witness that
/// must itself be constrained to the intended flag (1 or a copy of active).
fn assign_range_row(
    region: &mut Region<'_, Fp>,
    config: &PlanQuotaConfig,
    row: usize,
    value: Fp,
    kind: RangeKind,
    nz: Fp,
) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
    match kind {
        RangeKind::Bits5 => config.q_range5.enable(region, row)?,
        RangeKind::Bits16 => config.q_range16.enable(region, row)?,
        RangeKind::Bits20 => config.q_range20.enable(region, row)?,
        RangeKind::Bits32 => config.q_range32.enable(region, row)?,
    }
    config.q_nz.enable(region, row)?;
    let value_cell = region.assign_advice(
        || "range-checked value",
        config.range_value,
        row,
        || Value::known(value),
    )?;
    let inverse = if value == Fp::ZERO {
        Fp::ZERO
    } else {
        value.invert().unwrap_or(Fp::ZERO)
    };
    region.assign_advice(
        || "nonzero inverse witness",
        config.range_inverse,
        row,
        || Value::known(inverse),
    )?;
    for bit in 0..32 {
        region.assign_advice(
            || format!("range bit {bit}"),
            config.range_bits[bit],
            row,
            || Value::known(bit_from(value, bit)),
        )?;
    }
    let nz_cell =
        region.assign_advice(|| "nonzero flag", config.nz_flag, row, || Value::known(nz))?;
    Ok((value_cell, nz_cell))
}

impl Circuit<Fp> for PlanQuotaCircuit {
    type Config = PlanQuotaConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::blank()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let range_value = meta.advice_column();
        let range_inverse = meta.advice_column();
        let range_bits: [Column<Advice>; 32] = std::array::from_fn(|_| meta.advice_column());
        let nz_flag = meta.advice_column();

        let words: [Column<Advice>; 14] = std::array::from_fn(|_| meta.advice_column());
        let active = meta.advice_column();
        let slot_index = meta.advice_column();
        let limit_diff = meta.advice_column();
        let limit_col = meta.advice_column();
        let n_col = meta.advice_column();
        let sum_col = meta.advice_column();
        let budget_col = meta.advice_column();
        let budget_diff = meta.advice_column();

        let sel_active = meta.advice_column();
        let sel_action = meta.advice_column();
        let sel_pad = meta.advice_column();
        let sel_leaf = meta.advice_column();

        let limb_value = meta.advice_column();
        let chunk = meta.advice_column();
        let tag = meta.advice_column();

        for column in [
            range_value,
            words[0],
            words[1],
            words[2],
            words[3],
            words[4],
            words[5],
            words[6],
            words[7],
            words[8],
            words[9],
            words[10],
            words[11],
            words[12],
            words[13],
            active,
            limit_diff,
            limit_col,
            n_col,
            sum_col,
            budget_col,
            budget_diff,
            sel_active,
            sel_action,
            sel_pad,
            sel_leaf,
            limb_value,
            chunk,
            nz_flag,
            tag,
            slot_index,
        ] {
            meta.enable_equality(column);
        }

        let q_range5 = meta.selector();
        let q_range16 = meta.selector();
        let q_range20 = meta.selector();
        let q_range32 = meta.selector();
        let q_nz = meta.selector();
        let q_slot = meta.selector();
        let q_first = meta.selector();
        let q_prefix = meta.selector();
        let q_nsum = meta.selector();
        let q_sum = meta.selector();
        let q_budget = meta.selector();
        let q_leaf = meta.selector();
        let q_limb128 = meta.selector();

        let one = Expression::Constant(Fp::ONE);
        let two = Expression::Constant(Fp::from(2));
        let three = Expression::Constant(Fp::from(3));
        let four = Expression::Constant(Fp::from(4));
        let five = Expression::Constant(Fp::from(5));
        let half = Expression::Constant(Fp::from(2).invert().unwrap());

        let bool_expr = |x: Expression<Fp>| x.clone() * (x - one.clone());

        // Range checks: bits below `bits` are boolean and packed into value;
        // bits at or above `bits` must be zero.
        for (selector, bits, name) in [
            (q_range5, 5usize, "5-bit integer range check"),
            (q_range16, 16, "16-bit integer range check"),
            (q_range20, 20, "20-bit integer range check"),
            (q_range32, 32, "32-bit integer range check"),
        ] {
            meta.create_gate(name, |meta| {
                let q = meta.query_selector(selector);
                let value = meta.query_advice(range_value, Rotation::cur());
                let mut constraints = Vec::with_capacity(34);
                let mut packed = Expression::Constant(Fp::ZERO);
                for bit_index in 0..bits {
                    let bit = meta.query_advice(range_bits[bit_index], Rotation::cur());
                    constraints.push(q.clone() * bool_expr(bit.clone()));
                    packed = packed + bit * Expression::Constant(Fp::from(1u64 << bit_index));
                }
                constraints.push(q.clone() * (value - packed));
                for bit_index in bits..32 {
                    constraints.push(
                        q.clone() * meta.query_advice(range_bits[bit_index], Rotation::cur()),
                    );
                }
                constraints
            });
        }

        meta.create_gate("conditional nonzero via inverse witness", |meta| {
            let q = meta.query_selector(q_nz);
            let flag = meta.query_advice(nz_flag, Rotation::cur());
            let value = meta.query_advice(range_value, Rotation::cur());
            let inverse = meta.query_advice(range_inverse, Rotation::cur());
            vec![q * flag * (value * inverse - one.clone())]
        });

        // One row per action slot; all constraints are active-gated so that
        // inactive slots only need their 14 witness words to be zero.
        meta.create_gate("canonical action slot", |meta| {
            let q = meta.query_selector(q_slot);
            let active = meta.query_advice(active, Rotation::cur());
            let index = meta.query_advice(slot_index, Rotation::cur());
            let w: Vec<Expression<Fp>> = words
                .iter()
                .map(|column| meta.query_advice(*column, Rotation::cur()))
                .collect();
            let limit = meta.query_advice(limit_col, Rotation::cur());
            let diff = meta.query_advice(limit_diff, Rotation::cur());
            let mut constraints = Vec::new();

            constraints.push(q.clone() * bool_expr(active.clone()));
            for word in &w {
                constraints.push(q.clone() * (one.clone() - active.clone()) * word.clone());
            }
            constraints.push(
                q.clone()
                    * active.clone()
                    * (w[0].clone() - Expression::Constant(Fp::from(D_ACTION))),
            );
            constraints.push(q.clone() * active.clone() * (w[1].clone() - two.clone()));
            constraints.push(q.clone() * active.clone() * (w[2].clone() - index));

            // Resource ID {1,2}, filter count {1,2}, selected count {1,2,3}.
            constraints.push(
                q.clone()
                    * active.clone()
                    * (w[3].clone() - one.clone())
                    * (w[3].clone() - two.clone()),
            );
            constraints.push(
                q.clone()
                    * active.clone()
                    * (w[4].clone() - one.clone())
                    * (w[4].clone() - two.clone()),
            );
            constraints.push(
                q.clone()
                    * active.clone()
                    * (w[9].clone() - one.clone())
                    * (w[9].clone() - two.clone())
                    * (w[9].clone() - three.clone()),
            );

            // m_i <= L via range-checked difference d = L - m_i.
            constraints.push(q.clone() * active.clone() * (limit - w[13].clone() - diff));

            // Filter field/value slots: f0=w5,v0=w6,f1=w7,v1=w8.
            let filter_used = active.clone() * (w[4].clone() - one.clone());
            let filter_membership = |field: Expression<Fp>| {
                (field.clone() - one.clone())
                    * (field.clone() - two.clone())
                    * (field - three.clone())
            };
            constraints.push(q.clone() * active.clone() * filter_membership(w[5].clone()));
            constraints.push(q.clone() * filter_used.clone() * filter_membership(w[7].clone()));
            constraints
                .push(q.clone() * active.clone() * (two.clone() - w[4].clone()) * w[7].clone());
            constraints
                .push(q.clone() * active.clone() * (two.clone() - w[4].clone()) * w[8].clone());
            constraints.push(
                q.clone()
                    * filter_used.clone()
                    * (w[7].clone() - w[5].clone() - one.clone())
                    * (w[7].clone() - w[5].clone() - two.clone()),
            );
            let filter_resource = |field: Expression<Fp>| {
                vec![
                    (two.clone() - w[3].clone())
                        * (field.clone() - two.clone())
                        * (field.clone() - three.clone()),
                    (w[3].clone() - one.clone())
                        * (field.clone() - one.clone())
                        * (field.clone() - two.clone()),
                ]
            };
            for expr in filter_resource(w[5].clone()) {
                constraints.push(q.clone() * active.clone() * expr);
            }
            for expr in filter_resource(w[7].clone()) {
                constraints.push(q.clone() * filter_used.clone() * expr);
            }
            let value_compat = |field: Expression<Fp>, value: Expression<Fp>| {
                let j1 =
                    (field.clone() - two.clone()) * (field.clone() - three.clone()) * half.clone();
                let j2 = -(field.clone() - one.clone()) * (field.clone() - three.clone());
                let j3 =
                    (field.clone() - one.clone()) * (field.clone() - two.clone()) * half.clone();
                let p1 = (value.clone() - one.clone())
                    * (value.clone() - two.clone())
                    * (value.clone() - three.clone());
                let p2 = (value.clone() - four.clone()) * (value.clone() - five.clone());
                let p3 = (value.clone() - Expression::Constant(Fp::from(6)))
                    * (value.clone() - Expression::Constant(Fp::from(7)))
                    * (value.clone() - Expression::Constant(Fp::from(8)))
                    * (value - Expression::Constant(Fp::from(9)));
                j1 * p1 + j2 * p2 + j3 * p3
            };
            constraints.push(q.clone() * active.clone() * value_compat(w[5].clone(), w[6].clone()));
            constraints.push(q.clone() * filter_used * value_compat(w[7].clone(), w[8].clone()));

            // Selected field slots: g0=w10,g1=w11,g2=w12; count nc=w9.
            let i1 = (w[9].clone() - two.clone()) * (w[9].clone() - three.clone()) * half.clone();
            let i2 = -(w[9].clone() - one.clone()) * (w[9].clone() - three.clone());
            let i3 = (w[9].clone() - one.clone()) * (w[9].clone() - two.clone()) * half.clone();
            let g0_used = active.clone();
            let g1_used = active.clone() * (i2 + i3.clone());
            let g2_used = active.clone() * i3.clone();
            // Canonical zero padding of unused selected field slots.
            constraints.push(q.clone() * active.clone() * i1 * w[11].clone());
            constraints.push(q.clone() * active.clone() * (one.clone() - i3) * w[12].clone());
            let field_membership = |field: Expression<Fp>| {
                (field.clone() - one.clone())
                    * (field.clone() - two.clone())
                    * (field.clone() - three.clone())
                    * (field.clone() - four.clone())
                    * (field - five.clone())
            };
            let field_resource = |field: Expression<Fp>| {
                vec![
                    (two.clone() - w[3].clone())
                        * (field.clone() - two.clone())
                        * (field.clone() - three.clone())
                        * (field.clone() - four.clone()),
                    (w[3].clone() - one.clone())
                        * (field.clone() - one.clone())
                        * (field.clone() - two.clone())
                        * (field - five.clone()),
                ]
            };
            for (used, field) in [
                (g0_used, w[10].clone()),
                (g1_used.clone(), w[11].clone()),
                (g2_used.clone(), w[12].clone()),
            ] {
                constraints.push(q.clone() * used.clone() * field_membership(field.clone()));
                for expr in field_resource(field) {
                    constraints.push(q.clone() * used.clone() * expr);
                }
            }
            let ordered = |larger: Expression<Fp>, smaller: Expression<Fp>| {
                let d = larger - smaller;
                (d.clone() - one.clone())
                    * (d.clone() - two.clone())
                    * (d.clone() - three.clone())
                    * (d - four.clone())
            };
            constraints.push(q.clone() * g1_used * ordered(w[11].clone(), w[10].clone()));
            constraints.push(q.clone() * g2_used * ordered(w[12].clone(), w[11].clone()));

            constraints
        });

        meta.create_gate("slot 0 is active", |meta| {
            let q = meta.query_selector(q_first);
            let active = meta.query_advice(active, Rotation::cur());
            vec![q * (active - one.clone())]
        });

        meta.create_gate("active prefix continuity", |meta| {
            let q = meta.query_selector(q_prefix);
            let active_cur = meta.query_advice(active, Rotation::cur());
            let previous = meta.query_advice(active, Rotation::prev());
            vec![q * active_cur * (one.clone() - previous)]
        });

        meta.create_gate("n equals active-bit sum", |meta| {
            let q = meta.query_selector(q_nsum);
            let n = meta.query_advice(n_col, Rotation::cur());
            let sum = (0..MAX_PLAN_ACTIONS).fold(Expression::Constant(Fp::ZERO), |acc, index| {
                acc + meta.query_advice(active, Rotation(index as i32))
            });
            vec![q * (n - sum)]
        });

        meta.create_gate("aggregate reserved-row sum", |meta| {
            let q = meta.query_selector(q_sum);
            let sum = meta.query_advice(sum_col, Rotation::cur());
            let terms = (0..MAX_PLAN_ACTIONS).fold(Expression::Constant(Fp::ZERO), |acc, index| {
                acc + meta.query_advice(active, Rotation(index as i32))
                    * meta.query_advice(words[13], Rotation(index as i32))
            });
            vec![q * (sum - terms)]
        });

        meta.create_gate("aggregate budget comparison", |meta| {
            let q = meta.query_selector(q_budget);
            let budget = meta.query_advice(budget_col, Rotation::cur());
            let sum = meta.query_advice(sum_col, Rotation::cur());
            let difference = meta.query_advice(budget_diff, Rotation::cur());
            vec![q * (budget - sum - difference)]
        });

        meta.create_gate("in-circuit action/padding leaf selection", |meta| {
            let q = meta.query_selector(q_leaf);
            let flag = meta.query_advice(sel_active, Rotation::cur());
            let action = meta.query_advice(sel_action, Rotation::cur());
            let padding = meta.query_advice(sel_pad, Rotation::cur());
            let leaf = meta.query_advice(sel_leaf, Rotation::cur());
            vec![q * (leaf - flag.clone() * action - (one.clone() - flag) * padding)]
        });

        meta.create_gate("128-bit limb reconstruction", |meta| {
            let q = meta.query_selector(q_limb128);
            let limb = meta.query_advice(limb_value, Rotation::cur());
            let rebuilt = (0..4).fold(Expression::Constant(Fp::ZERO), |acc, index| {
                acc + meta.query_advice(chunk, Rotation(index as i32))
                    * Expression::Constant(Fp::from_u128(1u128 << (32 * index)))
            });
            vec![q * (limb - rebuilt)]
        });

        let state: [Column<Advice>; 3] = std::array::from_fn(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let rc_a: [Column<Fixed>; 3] = std::array::from_fn(|_| meta.fixed_column());
        let rc_b: [Column<Fixed>; 3] = std::array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        PlanQuotaConfig {
            poseidon,
            instance,
            range_value,
            range_inverse,
            range_bits,
            nz_flag,
            q_range5,
            q_range16,
            q_range20,
            q_range32,
            q_nz,
            words,
            active,
            slot_index,
            limit_diff,
            limit_col,
            n_col,
            sum_col,
            budget_col,
            budget_diff,
            q_slot,
            q_first,
            q_prefix,
            q_nsum,
            q_sum,
            q_budget,
            sel_active,
            sel_action,
            sel_pad,
            sel_leaf,
            q_leaf,
            limb_value,
            chunk,
            q_limb128,
            tag,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let budget = self.budget.map(Fp::from);
        let limit = self.limit.map(Fp::from);
        let blinding = self.blinding;
        let words = self.words.unwrap_or([[Fp::ZERO; 14]; MAX_PLAN_ACTIONS]);
        let active = self.active.unwrap_or([0; MAX_PLAN_ACTIONS]);
        let ctx_limbs = self.ctx_limbs.unwrap_or([Fp::ZERO; 2]);
        let schema_limbs = self.schema_limbs.unwrap_or([Fp::ZERO; 2]);

        let budget_f = budget.unwrap_or(Fp::ZERO);
        let limit_f = limit.unwrap_or(Fp::ZERO);
        let n_value = active.iter().copied().sum::<u64>();
        let sum_value: Fp = (0..MAX_PLAN_ACTIONS)
            .map(|index| {
                if active[index] == 1 {
                    words[index][13]
                } else {
                    Fp::ZERO
                }
            })
            .fold(Fp::ZERO, |acc, value| acc + value);
        let budget_diff_value = budget_f - sum_value;
        let limit_diff_values: Vec<Fp> = (0..MAX_PLAN_ACTIONS)
            .map(|index| limit_f - words[index][13])
            .collect();

        // ---- Frozen domain tags and blinding witness ----------------------
        let (quota_tag, node_tag, pad_tag, statement_tag, blinding_cell) = layouter.assign_region(
            || "domain tags and blinding",
            |mut region| {
                let assign = |region: &mut Region<'_, Fp>, row: usize, value: Fp| {
                    region.assign_advice_from_constant(|| "domain tag", config.tag, row, value)
                };
                let quota_tag = assign(&mut region, 0, Fp::from(D_QUOTA))?;
                let node_tag = assign(&mut region, 1, Fp::from(D_NODE))?;
                let pad_tag = assign(&mut region, 2, Fp::from(D_PAD))?;
                let statement_tag = assign(&mut region, 3, Fp::from(D_STATEMENT))?;
                let blinding_cell = region.assign_advice(
                    || "quota blinding witness",
                    config.tag,
                    4,
                    || value_fp(blinding),
                )?;
                Ok((quota_tag, node_tag, pad_tag, statement_tag, blinding_cell))
            },
        )?;

        // ---- Action region: one row per slot ------------------------------
        let action = layouter.assign_region(
            || "16 canonical action slots",
            |mut region| {
                let mut word_cells = Vec::with_capacity(MAX_PLAN_ACTIONS);
                let mut active_cells = Vec::with_capacity(MAX_PLAN_ACTIONS);
                let mut index_cells = Vec::with_capacity(MAX_PLAN_ACTIONS);
                let mut limit_diff_cells = Vec::with_capacity(MAX_PLAN_ACTIONS);
                let mut limit_cells = Vec::with_capacity(MAX_PLAN_ACTIONS);

                for index in 0..MAX_PLAN_ACTIONS {
                    config.q_slot.enable(&mut region, index)?;
                    let row_words: Vec<AssignedCell<Fp, Fp>> = (0..14)
                        .map(|column| {
                            region.assign_advice(
                                || format!("action word {column}"),
                                config.words[column],
                                index,
                                || Value::known(words[index][column]),
                            )
                        })
                        .collect::<Result<_, _>>()?;
                    let active_cell = region.assign_advice(
                        || "active flag",
                        config.active,
                        index,
                        || value_u64(Some(active[index])),
                    )?;
                    let index_cell = region.assign_advice_from_constant(
                        || "slot index",
                        config.slot_index,
                        index,
                        Fp::from(index as u64),
                    )?;
                    let diff_cell = region.assign_advice(
                        || "L - m difference",
                        config.limit_diff,
                        index,
                        || Value::known(limit_diff_values[index]),
                    )?;
                    let limit_cell = region.assign_advice(
                        || "L copy",
                        config.limit_col,
                        index,
                        || value_fp(limit),
                    )?;

                    if index == 0 {
                        config.q_first.enable(&mut region, 0)?;
                        config.q_nsum.enable(&mut region, 0)?;
                        config.q_sum.enable(&mut region, 0)?;
                        config.q_budget.enable(&mut region, 0)?;
                    } else {
                        config.q_prefix.enable(&mut region, index)?;
                    }

                    word_cells.push(row_words.try_into().map_err(|_| Error::Synthesis)?);
                    active_cells.push(active_cell);
                    index_cells.push(index_cell);
                    limit_diff_cells.push(diff_cell);
                    limit_cells.push(limit_cell);
                }

                let n_cell = region.assign_advice(
                    || "n witness",
                    config.n_col,
                    0,
                    || value_u64(Some(n_value)),
                )?;
                let sum_cell = region.assign_advice(
                    || "aggregate sum witness",
                    config.sum_col,
                    0,
                    || Value::known(sum_value),
                )?;
                let budget_cell = region.assign_advice(
                    || "B witness",
                    config.budget_col,
                    0,
                    || value_fp(budget),
                )?;
                let budget_diff_cell = region.assign_advice(
                    || "B - S difference",
                    config.budget_diff,
                    0,
                    || Value::known(budget_diff_value),
                )?;

                Ok((
                    word_cells,
                    active_cells,
                    index_cells,
                    limit_diff_cells,
                    limit_cells,
                    n_cell,
                    sum_cell,
                    budget_cell,
                    budget_diff_cell,
                ))
            },
        )?;
        let (
            word_cells,
            active_cells,
            index_cells,
            limit_diff_cells,
            limit_cells,
            n_action_cell,
            sum_action_cell,
            budget_action_cell,
            budget_diff_action_cell,
        ): (
            Vec<[AssignedCell<Fp, Fp>; 14]>,
            Vec<AssignedCell<Fp, Fp>>,
            Vec<AssignedCell<Fp, Fp>>,
            Vec<AssignedCell<Fp, Fp>>,
            Vec<AssignedCell<Fp, Fp>>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
        ) = action;

        // ---- Range region: every integer bound gets a checked witness -----
        let range = layouter.assign_region(
            || "integer range constraints",
            |mut region| {
                let (b_cell, b_nz) = assign_range_row(
                    &mut region,
                    &config,
                    0,
                    budget_f,
                    RangeKind::Bits32,
                    Fp::ONE,
                )?;
                region.constrain_equal(b_cell.cell(), budget_action_cell.cell())?;
                let b_nz_const = region.assign_advice_from_constant(
                    || "B nonzero flag = 1",
                    config.nz_flag,
                    100,
                    Fp::ONE,
                )?;
                region.constrain_equal(b_nz.cell(), b_nz_const.cell())?;

                let (l_cell, l_nz) =
                    assign_range_row(&mut region, &config, 1, limit_f, RangeKind::Bits16, Fp::ONE)?;
                let l_nz_const = region.assign_advice_from_constant(
                    || "L nonzero flag = 1",
                    config.nz_flag,
                    101,
                    Fp::ONE,
                )?;
                region.constrain_equal(l_nz.cell(), l_nz_const.cell())?;
                for limit_cell in &limit_cells {
                    region.constrain_equal(l_cell.cell(), limit_cell.cell())?;
                }

                for index in 0..MAX_PLAN_ACTIONS {
                    let (m_cell, m_nz) = assign_range_row(
                        &mut region,
                        &config,
                        2 + index,
                        words[index][13],
                        RangeKind::Bits16,
                        Fp::from(active[index]),
                    )?;
                    region.constrain_equal(m_cell.cell(), word_cells[index][13].cell())?;
                    region.constrain_equal(m_nz.cell(), active_cells[index].cell())?;

                    let (diff_cell, _) = assign_range_row(
                        &mut region,
                        &config,
                        18 + index,
                        limit_diff_values[index],
                        RangeKind::Bits16,
                        Fp::ZERO,
                    )?;
                    region.constrain_equal(diff_cell.cell(), limit_diff_cells[index].cell())?;
                }

                let (sum_cell, _) = assign_range_row(
                    &mut region,
                    &config,
                    34,
                    sum_value,
                    RangeKind::Bits20,
                    Fp::ZERO,
                )?;
                region.constrain_equal(sum_cell.cell(), sum_action_cell.cell())?;

                let (db_cell, _) = assign_range_row(
                    &mut region,
                    &config,
                    35,
                    budget_diff_value,
                    RangeKind::Bits32,
                    Fp::ZERO,
                )?;
                region.constrain_equal(db_cell.cell(), budget_diff_action_cell.cell())?;

                let mut limb_cells = Vec::with_capacity(4);
                for (limb_index, limb) in
                    [ctx_limbs[0], ctx_limbs[1], schema_limbs[0], schema_limbs[1]]
                        .into_iter()
                        .enumerate()
                {
                    let base = 36 + limb_index * 4;
                    config.q_limb128.enable(&mut region, base)?;
                    let limb_cell = region.assign_advice(
                        || "128-bit limb",
                        config.limb_value,
                        base,
                        || Value::known(limb),
                    )?;
                    let repr = limb.to_repr();
                    for chunk_index in 0..4 {
                        let row = base + chunk_index;
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(&repr.as_ref()[chunk_index * 4..chunk_index * 4 + 4]);
                        let chunk_value = Fp::from(u64::from(u32::from_le_bytes(bytes)));
                        let (checked, _) = assign_range_row(
                            &mut region,
                            &config,
                            row,
                            chunk_value,
                            RangeKind::Bits32,
                            Fp::ZERO,
                        )?;
                        let chunk_cell = region.assign_advice(
                            || "limb chunk",
                            config.chunk,
                            row,
                            || Value::known(chunk_value),
                        )?;
                        region.constrain_equal(checked.cell(), chunk_cell.cell())?;
                    }
                    limb_cells.push(limb_cell);
                }

                let (n_cell, _) = assign_range_row(
                    &mut region,
                    &config,
                    52,
                    Fp::from(n_value),
                    RangeKind::Bits5,
                    Fp::ZERO,
                )?;
                region.constrain_equal(n_cell.cell(), n_action_cell.cell())?;

                Ok((b_cell, l_cell, limb_cells, n_cell))
            },
        )?;
        let (b_cell, l_cell, limb_cells, n_cell): (
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            Vec<AssignedCell<Fp, Fp>>,
            AssignedCell<Fp, Fp>,
        ) = range;

        let make_chip = || Pow5Chip::construct(config.poseidon.clone());

        // ---- Action leaves: Poseidon^14(M_i) -------------------------------
        let mut action_leaves = Vec::with_capacity(MAX_PLAN_ACTIONS);
        for (index, cells) in word_cells.iter().enumerate() {
            let hasher = PoseidonHash::<Fp, _, P128Pow5T3, ConstantLength<14>, 3, 2>::init(
                make_chip(),
                layouter.namespace(|| format!("action init {index}")),
            )?;
            let message: [AssignedCell<Fp, Fp>; 14] =
                cells.clone().try_into().map_err(|_| Error::Synthesis)?;
            action_leaves.push(hasher.hash(
                layouter.namespace(|| format!("action leaf {index}")),
                message,
            )?);
        }

        // ---- Padding leaves: Poseidon^2(D_PAD, i) --------------------------
        let mut padding_leaves = Vec::with_capacity(MAX_PLAN_ACTIONS);
        for (index, index_cell) in index_cells.iter().enumerate() {
            let hasher = PoseidonHash::<Fp, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                make_chip(),
                layouter.namespace(|| format!("padding init {index}")),
            )?;
            padding_leaves.push(hasher.hash(
                layouter.namespace(|| format!("padding leaf {index}")),
                [pad_tag.clone(), index_cell.clone()],
            )?);
        }

        // ---- Selection gate ties both choices to the circuit --------------
        let leaves = layouter.assign_region(
            || "select action leaf or position-bound padding leaf",
            |mut region| {
                let mut selected = Vec::with_capacity(MAX_PLAN_ACTIONS);
                for index in 0..MAX_PLAN_ACTIONS {
                    config.q_leaf.enable(&mut region, index)?;
                    let flag = region.assign_advice(
                        || "selection active copy",
                        config.sel_active,
                        index,
                        || value_u64(Some(active[index])),
                    )?;
                    region.constrain_equal(active_cells[index].cell(), flag.cell())?;

                    let action = region.assign_advice(
                        || "action leaf copy",
                        config.sel_action,
                        index,
                        || Value::known(poseidon_hash(words[index])),
                    )?;
                    region.constrain_equal(action_leaves[index].cell(), action.cell())?;

                    let padding = region.assign_advice(
                        || "padding leaf copy",
                        config.sel_pad,
                        index,
                        || Value::known(poseidon_hash([Fp::from(D_PAD), Fp::from(index as u64)])),
                    )?;
                    region.constrain_equal(padding_leaves[index].cell(), padding.cell())?;

                    let leaf_value = if active[index] == 1 {
                        poseidon_hash(words[index])
                    } else {
                        poseidon_hash([Fp::from(D_PAD), Fp::from(index as u64)])
                    };
                    let leaf = region.assign_advice(
                        || "selected leaf",
                        config.sel_leaf,
                        index,
                        || Value::known(leaf_value),
                    )?;
                    selected.push(leaf);
                }
                Ok(selected)
            },
        )?;

        // ---- Four-level Merkle tree, computed inside the circuit ----------
        let mut level: Vec<AssignedCell<Fp, Fp>> = leaves;
        let mut depth = 0;
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                let hasher = PoseidonHash::<Fp, _, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
                    make_chip(),
                    layouter.namespace(|| format!("parent init {depth}")),
                )?;
                next.push(hasher.hash(
                    layouter.namespace(|| format!("parent hash {depth}")),
                    [node_tag.clone(), pair[0].clone(), pair[1].clone()],
                )?);
            }
            level = next;
            depth += 1;
        }
        let root = level[0].clone();

        // ---- Quota commitment ---------------------------------------------
        let quota_hasher = PoseidonHash::<Fp, _, P128Pow5T3, ConstantLength<4>, 3, 2>::init(
            make_chip(),
            layouter.namespace(|| "quota init"),
        )?;
        let c_quota = quota_hasher.hash(
            layouter.namespace(|| "quota commitment"),
            [quota_tag, b_cell, l_cell, blinding_cell],
        )?;

        // ---- Statement commitment -----------------------------------------
        let statement_hasher = PoseidonHash::<Fp, _, P128Pow5T3, ConstantLength<8>, 3, 2>::init(
            make_chip(),
            layouter.namespace(|| "statement init"),
        )?;
        let c_statement = statement_hasher.hash(
            layouter.namespace(|| "statement commitment"),
            [
                statement_tag,
                c_quota.clone(),
                root.clone(),
                n_cell.clone(),
                limb_cells[0].clone(),
                limb_cells[1].clone(),
                limb_cells[2].clone(),
                limb_cells[3].clone(),
            ],
        )?;

        // ---- All eight public inputs are constrained ----------------------
        layouter.constrain_instance(c_quota.cell(), config.instance, 0)?;
        layouter.constrain_instance(root.cell(), config.instance, 1)?;
        layouter.constrain_instance(n_cell.cell(), config.instance, 2)?;
        for (index, limb_cell) in limb_cells.iter().enumerate() {
            layouter.constrain_instance(limb_cell.cell(), config.instance, 3 + index)?;
        }
        layouter.constrain_instance(c_statement.cell(), config.instance, 7)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action_leaf, demo_plan, padding_leaf, parent_hash, poseidon_hash, quota_commitment,
        statement_commitment, validate_quota_plan, PoseidonPlanTree,
    };
    use ff::Field;
    use halo2_proofs::dev::MockProver;

    /// Circuit k determined empirically: k=12 is too small for 16 x Poseidon^14
    /// action leaves plus 16 padding leaves and 15 Merkle parents; k=13 fits.
    const K: u32 = 13;
    const BLIND: u64 = 123_456_789;

    type Raw = (
        u64,
        u64,
        Fp,
        [[Fp; 14]; MAX_PLAN_ACTIONS],
        [u64; MAX_PLAN_ACTIONS],
        [Fp; 2],
        [Fp; 2],
    );

    fn raw_demo() -> Raw {
        let circuit = PlanQuotaCircuit::from_plan(
            &demo_plan(),
            5,
            3,
            Fp::from(BLIND),
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap()
        .0;
        (
            circuit.budget.unwrap(),
            circuit.limit.unwrap(),
            circuit.blinding.unwrap(),
            circuit.words.unwrap(),
            circuit.active.unwrap(),
            circuit.ctx_limbs.unwrap(),
            circuit.schema_limbs.unwrap(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn public_of(
        b: u64,
        l: u64,
        r: Fp,
        w: &[[Fp; 14]; MAX_PLAN_ACTIONS],
        a: &[u64; MAX_PLAN_ACTIONS],
        ctx: [Fp; 2],
        schema: [Fp; 2],
    ) -> [Fp; PUBLIC_INSTANCE_COUNT] {
        raw_public_inputs(
            Fp::from(b),
            Fp::from(l),
            r,
            w,
            a,
            ctx[0],
            ctx[1],
            schema[0],
            schema[1],
        )
    }

    fn sat(circuit: &PlanQuotaCircuit, public: &[Fp; PUBLIC_INSTANCE_COUNT]) {
        let prover = MockProver::run(K, circuit, vec![public.to_vec()])
            .expect("MockProver synthesis should succeed");
        prover.verify().expect("valid witness must be accepted");
    }

    fn unsat(circuit: &PlanQuotaCircuit, public: &[Fp; PUBLIC_INSTANCE_COUNT]) {
        let prover = MockProver::run(K, circuit, vec![public.to_vec()])
            .expect("MockProver synthesis should succeed");
        assert!(
            prover.verify().is_err(),
            "invalid witness must be rejected by the circuit"
        );
    }

    fn action(
        step: u32,
        resource: &str,
        filters: Vec<(&str, &str)>,
        fields: Vec<&str>,
        rows: u64,
    ) -> DataQueryAction {
        DataQueryAction {
            step,
            resource: resource.into(),
            filters: filters
                .into_iter()
                .map(|(f, v)| (f.into(), v.into()))
                .collect(),
            selected_fields: fields.into_iter().map(str::to_string).collect(),
            max_rows: rows,
        }
    }

    // -----------------------------------------------------------------------
    // Positive tests
    // -----------------------------------------------------------------------

    #[test]
    fn positive_n1_minimal() {
        let actions = vec![action(
            0,
            "sales_records",
            vec![("quarter", "2026-Q3")],
            vec!["region"],
            1,
        )];
        let (circuit, public) =
            PlanQuotaCircuit::from_plan(&actions, 1, 1, Fp::from(BLIND), [0x11; 32], [0x22; 32])
                .unwrap();
        sat(&circuit, &public);
        assert_eq!(validate_quota_plan(&actions, 1, 1).unwrap(), 1);
    }

    #[test]
    fn positive_demo_plan() {
        let actions = demo_plan();
        let (circuit, public) =
            PlanQuotaCircuit::from_plan(&actions, 5, 3, Fp::from(BLIND), [0x11; 32], [0x22; 32])
                .unwrap();
        sat(&circuit, &public);
        let tree = PoseidonPlanTree::new(&actions).unwrap();
        assert_eq!(public[1], tree.root());
    }

    #[test]
    fn positive_n16_u16_boundary() {
        let actions: Vec<DataQueryAction> = (0..16)
            .map(|i| {
                if i % 2 == 0 {
                    action(
                        i as u32,
                        "sales_records",
                        vec![("quarter", "2026-Q3")],
                        vec!["region", "revenue_cents"],
                        u16::MAX as u64,
                    )
                } else {
                    action(
                        i as u32,
                        "support_metrics",
                        vec![("category", "billing")],
                        vec!["category", "ticket_count"],
                        u16::MAX as u64,
                    )
                }
            })
            .collect();
        let budget = 16 * u16::MAX as u64;
        let (circuit, public) = PlanQuotaCircuit::from_plan(
            &actions,
            budget,
            u16::MAX as u64,
            Fp::from(BLIND),
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap();
        assert_eq!(public[2], Fp::from(16u64));
        sat(&circuit, &public);
    }

    #[test]
    fn positive_various_legal_encodings() {
        let actions = vec![
            action(
                0,
                "sales_records",
                vec![("quarter", "2026-Q3"), ("region", "north")],
                vec!["region", "revenue_cents"],
                2,
            ),
            action(
                1,
                "support_metrics",
                vec![("category", "technical")],
                vec!["category"],
                3,
            ),
            action(
                2,
                "sales_records",
                vec![("region", "west")],
                vec!["quarter", "region", "revenue_cents"],
                1,
            ),
        ];
        let (circuit, public) =
            PlanQuotaCircuit::from_plan(&actions, 6, 3, Fp::from(BLIND), [0x11; 32], [0x22; 32])
                .unwrap();
        sat(&circuit, &public);
    }

    #[test]
    fn positive_host_gadget_consistency() {
        let actions = demo_plan();
        let (circuit, public) =
            PlanQuotaCircuit::from_plan(&actions, 5, 3, Fp::from(BLIND), [0x11; 32], [0x22; 32])
                .unwrap();
        sat(&circuit, &public);

        let cq = quota_commitment(5, 3, Fp::from(BLIND)).unwrap();
        let tree = PoseidonPlanTree::new(&actions).unwrap();
        let statement = crate::PublicStatement {
            quota_commitment: cq,
            plan_root: tree.root(),
            action_count: 3,
            context_digest: [0x11; 32],
            schema_digest: [0x22; 32],
        };
        let cs = statement_commitment(&statement).unwrap();
        assert_eq!(public[0], cq, "C_quota host/gadget consistency");
        assert_eq!(public[1], tree.root(), "R_plan host/gadget consistency");
        assert_eq!(public[7], cs, "C_statement host/gadget consistency");

        // Individual primitives from the host are distinct and position-bound.
        assert_ne!(
            action_leaf(&actions[0]).unwrap(),
            action_leaf(&actions[1]).unwrap()
        );
        assert_ne!(padding_leaf(0).unwrap(), padding_leaf(1).unwrap());
        assert_ne!(
            parent_hash(Fp::from(1), Fp::from(2)),
            parent_hash(Fp::from(2), Fp::from(1))
        );
        assert_eq!(
            action_leaf(&actions[0]).unwrap(),
            poseidon_hash(crate::encode_action(&actions[0]).unwrap().fields)
        );
    }

    // -----------------------------------------------------------------------
    // Negative tests: quota relations
    // -----------------------------------------------------------------------

    #[test]
    fn negative_budget_zero() {
        let mut raw = raw_demo();
        raw.0 = 0;
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_limit_zero() {
        let mut raw = raw_demo();
        raw.1 = 0;
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_action_rows_zero() {
        let mut raw = raw_demo();
        raw.3[0][13] = Fp::ZERO;
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_action_rows_65536() {
        let mut raw = raw_demo();
        raw.3[0][13] = Fp::from(65_536u64);
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_budget_2_pow_32() {
        let mut raw = raw_demo();
        raw.0 = 1u64 << 32;
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_per_action_limit_exceeded() {
        let mut raw = raw_demo();
        raw.3[0][13] = Fp::from(4u64); // L = 3
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_aggregate_budget_exceeded() {
        let mut raw = raw_demo();
        raw.0 = 4; // sum of m = 5
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    // -----------------------------------------------------------------------
    // Negative tests: slot structure
    // -----------------------------------------------------------------------

    #[test]
    fn negative_n_zero() {
        let mut raw = raw_demo();
        raw.4 = [0; MAX_PLAN_ACTIONS];
        raw.3 = [[Fp::ZERO; 14]; MAX_PLAN_ACTIONS];
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_n_seventeen() {
        // With only 16 slots, n=17 can only appear as a public instance; an
        // honest witness has n=3, so instance 2 is the sole failing constraint.
        let (_, mut public) = PlanQuotaCircuit::from_plan(
            &demo_plan(),
            5,
            3,
            Fp::from(BLIND),
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap();
        let circuit = PlanQuotaCircuit::from_plan(
            &demo_plan(),
            5,
            3,
            Fp::from(BLIND),
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap()
        .0;
        public[2] = Fp::from(17u64);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_noncontiguous_active() {
        let mut raw = raw_demo();
        raw.4[1] = 0;
        raw.4[2] = 1;
        raw.3[1] = [Fp::ZERO; 14]; // keep inactive slot canonical so prefix is isolated
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_inactive_slot_nonzero() {
        let mut raw = raw_demo();
        raw.3[3][3] = Fp::from(1u64); // inactive slot must be all-zero
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    // -----------------------------------------------------------------------
    // Negative tests: canonical encoding / tool-schema structure
    // -----------------------------------------------------------------------

    #[test]
    fn negative_illegal_resource_id() {
        let mut raw = raw_demo();
        raw.3[0][3] = Fp::from(3u64);
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_resource_selected_field_incompatible() {
        // Change demo[0] resource from sales_records(1) to support_metrics(2):
        // selected fields {region=3, revenue_cents=4} are invalid for resource 2.
        let mut raw = raw_demo();
        raw.3[0][3] = Fp::from(2u64);
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_resource_filter_field_incompatible() {
        let actions = vec![action(
            0,
            "support_metrics",
            vec![("category", "billing")],
            vec!["quarter"],
            2,
        )];
        let mut raw = raw_demo();
        raw.3[0] =
            PlanQuotaCircuit::from_plan(&actions, 2, 2, Fp::from(BLIND), [0x11; 32], [0x22; 32])
                .unwrap()
                .0
                .words
                .unwrap()[0];
        raw.3[0][3] = Fp::from(1u64); // sales_records cannot filter on category
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_filter_field_value_incompatible() {
        let actions = vec![action(
            0,
            "support_metrics",
            vec![("category", "billing")],
            vec!["quarter"],
            2,
        )];
        let mut raw = raw_demo();
        raw.3[0] =
            PlanQuotaCircuit::from_plan(&actions, 2, 2, Fp::from(BLIND), [0x11; 32], [0x22; 32])
                .unwrap()
                .0
                .words
                .unwrap()[0];
        raw.3[0][6] = Fp::from(4u64); // category field with quarter value ID
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_selected_fields_duplicate_or_out_of_order() {
        let mut raw = raw_demo();
        // demo[0] has selected fields [region=3, revenue_cents=4]; swap to [2,3]? No:
        // set first selected field to 4 and second to 3 -> strictly decreasing.
        raw.3[0][10] = Fp::from(4u64);
        raw.3[0][11] = Fp::from(3u64);
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_filter_fields_duplicate_or_out_of_order() {
        let actions = vec![action(
            0,
            "sales_records",
            vec![("quarter", "2026-Q3"), ("region", "north")],
            vec!["region"],
            2,
        )];
        let mut raw = raw_demo();
        raw.3[0] =
            PlanQuotaCircuit::from_plan(&actions, 2, 2, Fp::from(BLIND), [0x11; 32], [0x22; 32])
                .unwrap()
                .0
                .words
                .unwrap()[0];
        raw.3[0][7] = Fp::from(2u64); // duplicate filter field 2 instead of increasing to 3
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    // -----------------------------------------------------------------------
    // Negative tests: commitment and public-input binding
    // -----------------------------------------------------------------------

    #[test]
    fn negative_action_modified_with_original_root() {
        let actions = demo_plan();
        let (original, original_public) =
            PlanQuotaCircuit::from_plan(&actions, 5, 3, Fp::from(BLIND), [0x11; 32], [0x22; 32])
                .unwrap();
        sat(&original, &original_public);
        let mut altered = original.clone();
        let mut words = altered.words.unwrap();
        words[0][13] = Fp::from(1u64); // change an action field; keep original R_plan
        altered.words = Some(words);
        unsat(&altered, &original_public);
    }

    #[test]
    fn negative_action_reordered() {
        let actions = demo_plan();
        let (circuit, public) =
            PlanQuotaCircuit::from_plan(&actions, 5, 3, Fp::from(BLIND), [0x11; 32], [0x22; 32])
                .unwrap();
        let mut altered = circuit.clone();
        let mut words = altered.words.unwrap();
        words.swap(0, 1);
        altered.words = Some(words);
        unsat(&altered, &public); // steps no longer match slots and root changes
    }

    #[test]
    fn negative_step_index_modified() {
        let mut raw = raw_demo();
        raw.3[0][2] = Fp::from(5u64); // step must equal slot index 0
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_wrong_quota_commitment() {
        let (circuit, mut public) = PlanQuotaCircuit::from_plan(
            &demo_plan(),
            5,
            3,
            Fp::from(BLIND),
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap();
        public[0] = public[0] + Fp::ONE;
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_wrong_plan_root() {
        let (circuit, mut public) = PlanQuotaCircuit::from_plan(
            &demo_plan(),
            5,
            3,
            Fp::from(BLIND),
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap();
        public[1] = public[1] + Fp::ONE;
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_wrong_statement_commitment() {
        let (circuit, mut public) = PlanQuotaCircuit::from_plan(
            &demo_plan(),
            5,
            3,
            Fp::from(BLIND),
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap();
        public[7] = public[7] + Fp::ONE;
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_context_modified_old_statement() {
        let mut raw = raw_demo();
        raw.5[0] = raw.5[0] + Fp::ONE;
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let (_, original_public) = PlanQuotaCircuit::from_plan(
            &demo_plan(),
            5,
            3,
            Fp::from(BLIND),
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap();
        let mut public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        public[7] = original_public[7]; // context changed, statement commitment not refreshed
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_schema_modified_old_statement() {
        let mut raw = raw_demo();
        raw.6[1] = raw.6[1] + Fp::ONE;
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let (_, original_public) = PlanQuotaCircuit::from_plan(
            &demo_plan(),
            5,
            3,
            Fp::from(BLIND),
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap();
        let mut public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        public[7] = original_public[7]; // schema changed, statement commitment not refreshed
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_context_limb_above_128_bits() {
        let mut raw = raw_demo();
        raw.5[0] = Fp::from_u128(u128::MAX); // 2^128 - 1 is representable, but > 2^128-1 check boundary
        raw.5[0] = raw.5[0] + Fp::ONE; // 2^128 mod p, not a 128-bit integer
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }

    #[test]
    fn negative_schema_limb_above_128_bits() {
        let mut raw = raw_demo();
        raw.6[0] = Fp::from_u128(u128::MAX) + Fp::ONE;
        let circuit = PlanQuotaCircuit::new_raw(raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6);
        let public = public_of(raw.0, raw.1, raw.2, &raw.3, &raw.4, raw.5, raw.6);
        unsat(&circuit, &public);
    }
}
