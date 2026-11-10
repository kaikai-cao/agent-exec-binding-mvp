//! First Halo2 circuit increment for data-query-v2-poseidon.
//!
//! This circuit intentionally proves only the quota sub-relation for a fixed
//! three-action demo plan. It does not yet prove the 16-leaf Merkle root,
//! statement commitment, action-schema compatibility, grant freshness, or
//! execution receipts. Those are separate subsequent increments.

use crate::{Fp, D_QUOTA};
use ff::Field;
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};

/// Fixed shape for the first circuit increment: exactly three active actions.
#[derive(Clone, Debug)]
pub struct QuotaCircuit {
    budget: Option<u64>,
    per_action_limit: Option<u64>,
    blinding: Option<Fp>,
    max_rows: [Option<u64>; 3],
}

impl QuotaCircuit {
    pub fn new(budget: u64, per_action_limit: u64, blinding: Fp, max_rows: [u64; 3]) -> Self {
        Self {
            budget: Some(budget),
            per_action_limit: Some(per_action_limit),
            blinding: Some(blinding),
            max_rows: max_rows.map(Some),
        }
    }

    fn blank() -> Self {
        Self {
            budget: None,
            per_action_limit: None,
            blinding: None,
            max_rows: [None; 3],
        }
    }

    fn derived_sum(&self) -> Option<u64> {
        let [a, b, c] = self.max_rows;
        Some(a?.saturating_add(b?).saturating_add(c?))
    }

    fn limit_differences(&self) -> [Option<u64>; 3] {
        std::array::from_fn(|i| {
            self.per_action_limit
                .zip(self.max_rows[i])
                .map(|(limit, rows)| limit.saturating_sub(rows))
        })
    }

    fn budget_difference(&self) -> Option<u64> {
        self.budget
            .zip(self.derived_sum())
            .map(|(budget, sum)| budget.saturating_sub(sum))
    }
}

#[derive(Clone, Debug)]
pub struct QuotaConfig {
    poseidon: Pow5Config<Fp, 3, 2>,
    instance: Column<Instance>,

    // Generic range-check row: one value and 32 bit witnesses.
    range_value: Column<Advice>,
    range_inverse: Column<Advice>,
    range_bits: [Column<Advice>; 32],
    q_range16: Selector,
    q_range20: Selector,
    q_range32: Selector,
    q_nonzero: Selector,

    // Copies of already range-checked values used in arithmetic relations.
    rel_a: Column<Advice>,
    rel_b: Column<Advice>,
    rel_c: Column<Advice>,
    rel_d: Column<Advice>,
    q_step_bound: Selector,
    q_sum: Selector,
    q_budget: Selector,

    // Inputs to the Poseidon quota commitment.
    domain_tag: Column<Advice>,
    blinding: Column<Advice>,
}

#[derive(Clone, Copy)]
enum RangeKind {
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

fn value_bit(value: Option<u64>, bit: usize) -> Value<Fp> {
    value
        .map(|value| Value::known(Fp::from((value >> bit) & 1)))
        .unwrap_or_else(Value::unknown)
}

fn assign_range_row(
    region: &mut halo2_proofs::circuit::Region<'_, Fp>,
    config: &QuotaConfig,
    row: usize,
    value: Option<u64>,
    kind: RangeKind,
    require_nonzero: bool,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    match kind {
        RangeKind::Bits16 => config.q_range16.enable(region, row)?,
        RangeKind::Bits20 => config.q_range20.enable(region, row)?,
        RangeKind::Bits32 => config.q_range32.enable(region, row)?,
    }
    if require_nonzero {
        config.q_nonzero.enable(region, row)?;
    }

    let value_cell = region.assign_advice(
        || "range-checked value",
        config.range_value,
        row,
        || value_u64(value),
    )?;

    let inverse = value.map(|v| {
        if v == 0 {
            Fp::ZERO
        } else {
            Fp::from(v).invert().unwrap_or(Fp::ZERO)
        }
    });
    region.assign_advice(
        || "nonzero inverse witness",
        config.range_inverse,
        row,
        || value_fp(inverse),
    )?;

    for bit in 0..32 {
        region.assign_advice(
            || format!("range bit {bit}"),
            config.range_bits[bit],
            row,
            || value_bit(value, bit),
        )?;
    }

    Ok(value_cell)
}

fn assign_copy(
    region: &mut halo2_proofs::circuit::Region<'_, Fp>,
    column: Column<Advice>,
    row: usize,
    value: Option<u64>,
    source: &AssignedCell<Fp, Fp>,
) -> Result<(), Error> {
    let copy = region.assign_advice(
        || "copy range-checked value",
        column,
        row,
        || value_u64(value),
    )?;
    region.constrain_equal(source.cell(), copy.cell())
}

impl Circuit<Fp> for QuotaCircuit {
    type Config = QuotaConfig;
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

        let rel_a = meta.advice_column();
        let rel_b = meta.advice_column();
        let rel_c = meta.advice_column();
        let rel_d = meta.advice_column();
        let domain_tag = meta.advice_column();
        let blinding = meta.advice_column();

        for column in [
            range_value,
            rel_a,
            rel_b,
            rel_c,
            rel_d,
            domain_tag,
            blinding,
        ] {
            meta.enable_equality(column);
        }

        let q_range16 = meta.selector();
        let q_range20 = meta.selector();
        let q_range32 = meta.selector();
        let q_nonzero = meta.selector();
        let q_step_bound = meta.selector();
        let q_sum = meta.selector();
        let q_budget = meta.selector();

        meta.create_gate("16-bit range check", |meta| {
            let q = meta.query_selector(q_range16);
            let value = meta.query_advice(range_value, Rotation::cur());
            let mut constraints = Vec::with_capacity(33);
            let mut packed = Expression::Constant(Fp::ZERO);
            for bit_index in 0..16 {
                let bit = meta.query_advice(range_bits[bit_index], Rotation::cur());
                constraints
                    .push(q.clone() * bit.clone() * (bit.clone() - Expression::Constant(Fp::ONE)));
                packed = packed + bit * Expression::Constant(Fp::from(1u64 << bit_index));
            }
            constraints.push(q.clone() * (value - packed));
            for bit_index in 16..32 {
                let bit = meta.query_advice(range_bits[bit_index], Rotation::cur());
                constraints.push(q.clone() * bit);
            }
            constraints
        });

        meta.create_gate("20-bit range check", |meta| {
            let q = meta.query_selector(q_range20);
            let value = meta.query_advice(range_value, Rotation::cur());
            let mut constraints = Vec::with_capacity(33);
            let mut packed = Expression::Constant(Fp::ZERO);
            for bit_index in 0..20 {
                let bit = meta.query_advice(range_bits[bit_index], Rotation::cur());
                constraints
                    .push(q.clone() * bit.clone() * (bit.clone() - Expression::Constant(Fp::ONE)));
                packed = packed + bit * Expression::Constant(Fp::from(1u64 << bit_index));
            }
            constraints.push(q.clone() * (value - packed));
            for bit_index in 20..32 {
                let bit = meta.query_advice(range_bits[bit_index], Rotation::cur());
                constraints.push(q.clone() * bit);
            }
            constraints
        });

        meta.create_gate("32-bit range check", |meta| {
            let q = meta.query_selector(q_range32);
            let value = meta.query_advice(range_value, Rotation::cur());
            let mut constraints = Vec::with_capacity(33);
            let mut packed = Expression::Constant(Fp::ZERO);
            for bit_index in 0..32 {
                let bit = meta.query_advice(range_bits[bit_index], Rotation::cur());
                constraints
                    .push(q.clone() * bit.clone() * (bit.clone() - Expression::Constant(Fp::ONE)));
                packed = packed + bit * Expression::Constant(Fp::from(1u64 << bit_index));
            }
            constraints.push(q * (value - packed));
            constraints
        });

        meta.create_gate("nonzero range-checked value", |meta| {
            let q = meta.query_selector(q_nonzero);
            let value = meta.query_advice(range_value, Rotation::cur());
            let inverse = meta.query_advice(range_inverse, Rotation::cur());
            vec![q * (value * inverse - Expression::Constant(Fp::ONE))]
        });

        meta.create_gate("per-action limit", |meta| {
            let q = meta.query_selector(q_step_bound);
            let limit = meta.query_advice(rel_a, Rotation::cur());
            let rows = meta.query_advice(rel_b, Rotation::cur());
            let difference = meta.query_advice(rel_c, Rotation::cur());
            vec![q * (limit - rows - difference)]
        });

        meta.create_gate("aggregate sum", |meta| {
            let q = meta.query_selector(q_sum);
            let sum = meta.query_advice(rel_a, Rotation::cur());
            let m0 = meta.query_advice(rel_b, Rotation::cur());
            let m1 = meta.query_advice(rel_c, Rotation::cur());
            let m2 = meta.query_advice(rel_d, Rotation::cur());
            vec![q * (sum - m0 - m1 - m2)]
        });

        meta.create_gate("aggregate budget", |meta| {
            let q = meta.query_selector(q_budget);
            let budget = meta.query_advice(rel_a, Rotation::cur());
            let sum = meta.query_advice(rel_b, Rotation::cur());
            let difference = meta.query_advice(rel_c, Rotation::cur());
            vec![q * (budget - sum - difference)]
        });

        let state: [Column<Advice>; 3] = std::array::from_fn(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let rc_a = std::array::from_fn(|_| meta.fixed_column());
        let rc_b = std::array::from_fn(|_| meta.fixed_column());
        // Matches the upstream halo2_gadgets Poseidon test configuration.
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        QuotaConfig {
            poseidon,
            instance,
            range_value,
            range_inverse,
            range_bits,
            q_range16,
            q_range20,
            q_range32,
            q_nonzero,
            rel_a,
            rel_b,
            rel_c,
            rel_d,
            q_step_bound,
            q_sum,
            q_budget,
            domain_tag,
            blinding,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let differences = self.limit_differences();
        let sum = self.derived_sum();
        let budget_difference = self.budget_difference();
        let values = [
            (self.budget, RangeKind::Bits32, true),
            (self.per_action_limit, RangeKind::Bits16, true),
            (self.max_rows[0], RangeKind::Bits16, true),
            (self.max_rows[1], RangeKind::Bits16, true),
            (self.max_rows[2], RangeKind::Bits16, true),
            (differences[0], RangeKind::Bits16, false),
            (differences[1], RangeKind::Bits16, false),
            (differences[2], RangeKind::Bits16, false),
            (sum, RangeKind::Bits20, false),
            (budget_difference, RangeKind::Bits32, false),
        ];

        let range_cells = layouter.assign_region(
            || "range constraints",
            |mut region| {
                let mut cells = Vec::with_capacity(values.len());
                for (row, (value, kind, nonzero)) in values.iter().enumerate() {
                    cells.push(assign_range_row(
                        &mut region,
                        &config,
                        row,
                        *value,
                        *kind,
                        *nonzero,
                    )?);
                }
                Ok(cells)
            },
        )?;

        // Enforce L = m_i + d_i, S = m_0 + m_1 + m_2,
        // and B = S + d_B. All operands have already been range checked.
        layouter.assign_region(
            || "integer quota relations",
            |mut region| {
                for i in 0..3 {
                    config.q_step_bound.enable(&mut region, i)?;
                    assign_copy(
                        &mut region,
                        config.rel_a,
                        i,
                        self.per_action_limit,
                        &range_cells[1],
                    )?;
                    assign_copy(
                        &mut region,
                        config.rel_b,
                        i,
                        self.max_rows[i],
                        &range_cells[2 + i],
                    )?;
                    assign_copy(
                        &mut region,
                        config.rel_c,
                        i,
                        differences[i],
                        &range_cells[5 + i],
                    )?;
                }

                config.q_sum.enable(&mut region, 3)?;
                assign_copy(&mut region, config.rel_a, 3, sum, &range_cells[8])?;
                assign_copy(
                    &mut region,
                    config.rel_b,
                    3,
                    self.max_rows[0],
                    &range_cells[2],
                )?;
                assign_copy(
                    &mut region,
                    config.rel_c,
                    3,
                    self.max_rows[1],
                    &range_cells[3],
                )?;
                assign_copy(
                    &mut region,
                    config.rel_d,
                    3,
                    self.max_rows[2],
                    &range_cells[4],
                )?;

                config.q_budget.enable(&mut region, 4)?;
                assign_copy(&mut region, config.rel_a, 4, self.budget, &range_cells[0])?;
                assign_copy(&mut region, config.rel_b, 4, sum, &range_cells[8])?;
                assign_copy(
                    &mut region,
                    config.rel_c,
                    4,
                    budget_difference,
                    &range_cells[9],
                )?;
                Ok(())
            },
        )?;

        let (domain_tag, blinding) = layouter.assign_region(
            || "quota commitment inputs",
            |mut region| {
                let tag = region.assign_advice_from_constant(
                    || "quota domain tag",
                    config.domain_tag,
                    0,
                    Fp::from(D_QUOTA),
                )?;
                let blinding = region.assign_advice(
                    || "quota blinding witness",
                    config.blinding,
                    0,
                    || value_fp(self.blinding),
                )?;
                Ok((tag, blinding))
            },
        )?;

        let chip = Pow5Chip::construct(config.poseidon);
        let hasher = PoseidonHash::<Fp, _, P128Pow5T3, ConstantLength<4>, 3, 2>::init(
            chip,
            layouter.namespace(|| "initialize quota Poseidon hasher"),
        )?;
        let commitment = hasher.hash(
            layouter.namespace(|| "hash quota commitment"),
            [
                domain_tag,
                range_cells[0].clone(),
                range_cells[1].clone(),
                blinding,
            ],
        )?;

        layouter.constrain_instance(commitment.cell(), config.instance, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{poseidon_hash, quota_commitment};
    use halo2_proofs::dev::MockProver;

    const DEMO_K: u32 = 9;

    fn raw_commitment(budget: u64, limit: u64, blinding: Fp) -> Fp {
        poseidon_hash([
            Fp::from(D_QUOTA),
            Fp::from(budget),
            Fp::from(limit),
            blinding,
        ])
    }

    fn is_satisfied(circuit: QuotaCircuit, public_commitment: Fp) -> bool {
        let prover = MockProver::run(DEMO_K, &circuit, vec![vec![public_commitment]])
            .expect("MockProver should be able to synthesize the fixed circuit");
        prover.verify().is_ok()
    }

    #[test]
    fn accepts_demo_quota_and_matches_host_commitment() {
        let blind = Fp::from(123_456_789);
        let commitment = quota_commitment(5, 3, blind).unwrap();
        let circuit = QuotaCircuit::new(5, 3, blind, [2, 2, 1]);
        assert!(is_satisfied(circuit, commitment));
    }

    #[test]
    fn rejects_wrong_public_commitment() {
        let blind = Fp::from(123_456_789);
        let commitment = quota_commitment(5, 3, blind).unwrap();
        let circuit = QuotaCircuit::new(5, 3, blind, [2, 2, 1]);
        assert!(!is_satisfied(circuit, commitment + Fp::ONE));
    }

    #[test]
    fn rejects_per_action_limit_violation() {
        let blind = Fp::from(123_456_789);
        let commitment = quota_commitment(8, 3, blind).unwrap();
        let circuit = QuotaCircuit::new(8, 3, blind, [2, 4, 1]);
        assert!(!is_satisfied(circuit, commitment));
    }

    #[test]
    fn rejects_aggregate_budget_violation() {
        let blind = Fp::from(123_456_789);
        let commitment = quota_commitment(5, 3, blind).unwrap();
        let circuit = QuotaCircuit::new(5, 3, blind, [2, 2, 2]);
        assert!(!is_satisfied(circuit, commitment));
    }

    #[test]
    fn rejects_zero_budget() {
        let blind = Fp::from(123_456_789);
        let commitment = raw_commitment(0, 3, blind);
        let circuit = QuotaCircuit::new(0, 3, blind, [1, 1, 1]);
        assert!(!is_satisfied(circuit, commitment));
    }

    #[test]
    fn rejects_zero_per_action_limit() {
        let blind = Fp::from(123_456_789);
        let commitment = raw_commitment(5, 0, blind);
        let circuit = QuotaCircuit::new(5, 0, blind, [1, 1, 1]);
        assert!(!is_satisfied(circuit, commitment));
    }

    #[test]
    fn rejects_zero_action_rows() {
        let blind = Fp::from(123_456_789);
        let commitment = quota_commitment(5, 3, blind).unwrap();
        let circuit = QuotaCircuit::new(5, 3, blind, [2, 0, 1]);
        assert!(!is_satisfied(circuit, commitment));
    }

    #[test]
    fn accepts_three_action_u16_boundary() {
        let blind = Fp::from(987_654_321);
        let budget = 3 * u16::MAX as u64;
        let commitment = quota_commitment(budget, u16::MAX as u64, blind).unwrap();
        let circuit = QuotaCircuit::new(budget, u16::MAX as u64, blind, [u16::MAX as u64; 3]);
        assert!(is_satisfied(circuit, commitment));
    }

    #[test]
    fn rejects_action_rows_outside_u16() {
        let blind = Fp::from(123_456_789);
        let commitment = quota_commitment(200_000, u16::MAX as u64, blind).unwrap();
        let circuit = QuotaCircuit::new(200_000, u16::MAX as u64, blind, [65_536, 1, 1]);
        assert!(!is_satisfied(circuit, commitment));
    }

    #[test]
    fn rejects_budget_outside_u32() {
        let blind = Fp::from(123_456_789);
        let budget = (u32::MAX as u64) + 1;
        let commitment = raw_commitment(budget, 3, blind);
        let circuit = QuotaCircuit::new(budget, 3, blind, [1, 1, 1]);
        assert!(!is_satisfied(circuit, commitment));
    }
}
