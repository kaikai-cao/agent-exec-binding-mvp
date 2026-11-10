# Step 3.2A implementation notes

1. The circuit uses `halo2_gadgets::poseidon::Pow5Chip` with `P128Pow5T3`, `ConstantLength<4>`, Pallas Base, matching the Host `quota_commitment()` primitive.
2. `MockProver` checks that the Poseidon gadget output equals the public instance commitment.
3. Range checks use 16-, 20-, and 32-bit decompositions. Nonzero checks use inverse witnesses.
4. `L = m_i + d_i`, `S = m_0 + m_1 + m_2`, and `B = S + d_B` are constrained in separate gates. All integer operands are range-bounded, preventing field-wraparound interpretations.
5. The circuit shape is intentionally fixed to three actions. It is a first proving-relation increment, not full v0.2 compliance.
6. No Rust toolchain is available in the artifact-generation environment. This source has been reviewed against the upstream Halo2 0.4 / gadgets 0.6 APIs, but compilation and MockProver results must be confirmed in the user's Windows environment before the increment is accepted.
