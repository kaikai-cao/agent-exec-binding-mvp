# Step 3.2A — Halo2 quota circuit (fixed three-action prototype)

This patch adds the first Halo2 circuit to the host-side `data-query-v2-poseidon` crate.

## Scope

The circuit proves the following relation for exactly three active action slots:

- the private `(budget, per_action_limit, blinding)` hashes to the public Poseidon quota commitment;
- `budget` is a nonzero 32-bit integer;
- `per_action_limit` and each of the three `max_rows` values are nonzero 16-bit integers;
- each `max_rows[i] <= per_action_limit`;
- the 20-bit aggregate is exactly the sum of the three rows;
- the aggregate is no larger than `budget`.

The comparisons use nonnegative difference witnesses and bit-decomposition range checks. Because all operands are range bounded far below the Pallas modulus, the field equalities have the intended integer interpretation.

## Explicit non-goals in this increment

This circuit does **not** yet prove:

- the 16-leaf Poseidon plan Merkle root;
- the full eight-element `C_statement` commitment;
- a variable action count `n` or inactive padding slots;
- the action resource/filter/selected-field schema compatibility;
- execution receipts, tool output truth, or nullifier state;
- Ed25519 authorization-envelope validity.

The Host Poseidon tree and statement functions remain reference implementations only. Do not claim that the full v0.2 relation is already proved.

## Windows build

Run from the existing `zk-v2-host` directory:

```powershell
cargo test
cargo test --locked
cargo run --locked --bin quota_mock
cargo run --locked --bin agent-exec-binding-host-v2
```

The first `cargo test` after applying this patch may update `Cargo.lock` to add `halo2_gadgets` and `halo2_proofs`. Review and retain the resulting lockfile. The subsequent `--locked` commands must run without changing it.

## Expected circuit tests

- valid demo `(B=5, L=3, m=[2,2,1])` accepted;
- wrong public quota commitment rejected;
- per-action overflow rejected;
- aggregate budget overflow rejected;
- zero budget, zero limit, and zero `max_rows` rejected;
- 16-bit boundary values accepted for the fixed three-step shape;
- 16-bit action overflow and 32-bit budget overflow rejected.

The deterministic blinding value in the test and demo is for reproducible tests only. Production authorization must sample a fresh field element using an OS-backed cryptographic RNG.
