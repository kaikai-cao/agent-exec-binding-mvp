# Implementation notes

- Host hash parameters: Pallas Base, `P128Pow5T3`, `ConstantLength<L>`.
- Circuit hash: `halo2_gadgets::poseidon::Pow5Chip` and `Hash`, with `ConstantLength<4>`.
- Range checks: Boolean bit decomposition for 16-, 20-, and 32-bit values.
- Nonzero: inverse witness `x * x^{-1} = 1`.
- Integer comparisons: nonnegative difference witnesses, `L = m_i + d_i` and `B = S + d_B`.
- All compared operands are range bounded; sums remain far below the Pallas modulus, preventing modular wraparound from satisfying the integer relations.
- Fixed shape is exactly three active action slots. This is an incremental circuit, not the full v0.2 specification.
- Generated source has not been compiled in this artifact environment (no Rust toolchain available). Verify using the provided Windows commands before accepting this stage.
