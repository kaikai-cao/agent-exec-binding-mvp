# Agent execution binding — Halo2 v2 prototype

This project contains two layers:

- Host-side Poseidon encoding, quota commitment, fixed 16-leaf plan Merkle tree, and statement commitment (`src/lib.rs`).
- A first Halo2 circuit increment for the quota relation with exactly three active actions (`src/quota_circuit.rs`).

## Build and test on Windows

Run from this directory:

```powershell
cargo test
cargo test --locked
cargo run --locked --bin quota_mock
cargo run --locked --bin agent-exec-binding-host-v2
```

The first `cargo test` after adding Halo2 dependencies may update `Cargo.lock`. Review and keep that lockfile; all later reproducible runs should use `--locked`.

## Current proof boundary

The Halo2 circuit proves only:

1. `C_quota = Poseidon(D_QUOTA, B, L, r)` using the fixed `P128Pow5T3 / ConstantLength<4>` gadget;
2. `B` is a nonzero 32-bit integer;
3. `L` and the three `max_rows` values are nonzero 16-bit integers;
4. each `max_rows[i] <= L`;
5. the aggregate is exactly `sum(max_rows[0..3])` and is at most `B`.

It does **not** yet prove the plan Merkle root, the full statement commitment, a variable action count, inactive padding slots, or data-query schema compatibility. The Host implementation is not proof of those properties.

The deterministic blinding value used in test fixtures is for reproducibility only. A production grant must use a fresh OS-CSPRNG-generated field element.
