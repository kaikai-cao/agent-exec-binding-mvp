# Step 3.2B — 16-leaf plan root and statement-binding Halo2 circuit

Task package: `AE-ZK-STEP3.2B` (`16-Leaf Plan Root and Statement Binding Circuit`).

This increment completes the arithmetic relation in
`docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md` inside Halo2. It is
**implementation completion of an existing relation spec**, not a new paper
claim and not a novelty statement. ZKA/Coord v2 remains a close competing work
and must be compared separately.

## Phase 0 baseline record

Recorded before creating the work branch:

| Item | Value |
| --- | --- |
| Repository | `kaikai-cao/agent-exec-binding-mvp` |
| Local path | `D:\Research\agent-exec-binding-mvp` |
| Checkout at start | `experiment/independent-execution-proxy` @ `e327a9444ed8cea17baefbac01587b7fa77e8d39` |
| `main` (local == remote) | `f3048571268642696616d9f38c536d9449106918` |
| Experiment branch (local == remote) | `e327a9444ed8cea17baefbac01587b7fa77e8d39` |
| `git status --short --branch` at start | clean, no untracked changes |
| `zk-v2-host/` diff `main..HEAD` | empty (Halo2 baseline identical on both branches) |
| Python baseline | 80/80 `unittest` tests pass in 4.885s |
| Rust baseline | 21/21 tests pass (11 host + 10 quota circuit) |

Protected E-stage archive (`independent_execution_proxy.py`, `research/`,
`tests/test_independent_execution_proxy.py`, `_staging/e486-d1/`) is tracked on
the experiment branch. Because `main` is two commits behind and lacks these
files, the work branch `feat/step3-2b-plan-root-circuit` was created **from the
current HEAD** rather than from `main`. This preserves every protected file,
keeps all 80 Python tests reproducible, and leaves the Halo2 baseline identical
to `main`. No file under these paths was modified.

No `git reset --hard`, `git clean`, or stash was used. This round is local only:
**no commit, no push, no PR**.

## What the circuit proves

`PlanQuotaCircuit` (`src/plan_quota_circuit.rs`) enforces:

1. `B` is a nonzero 32-bit integer; `L` is a nonzero 16-bit integer.
2. Each active action's `m_i` is a nonzero 16-bit integer and `m_i <= L`,
   via a 16-bit range-checked difference witness `d_i = L - m_i`.
3. `S = Σ active_i * m_i` is a 20-bit integer and `S <= B`, via a 32-bit
   range-checked difference witness `d_B = B - S`. No finite-field comparison
   is used for any of these inequalities.
4. Exactly 16 slots. `active[0] = 1`, `active[i]*(1-active[i-1]) = 0`, and
   `n = Σ active_i` (5-bit range checked). Inactive slots carry all-zero
   action witnesses and use the position-bound padding leaf
   `Pad_i = Poseidon^2(D_PAD, i)`.
5. Each active action uses the canonical 14-element message from v0.2 §4.2,
   including resource ID, filter/field counts, strict numeric ID ordering,
   canonical zero padding, resource↔field/filter compatibility, and
   filter-field↔value compatibility. These are *public tool-schema structural*
   checks, **not** a proof of a private authorization allowlist.
6. `C_quota = Poseidon^4(D_QUOTA, B, L, r)` is computed in-circuit.
7. Each leaf is selected **inside the circuit** by
   `leaf_i = active_i * Poseidon^14(M_i) + (1-active_i) * Pad_i`.
8. `R_plan` is the four-level Poseidon^3 `Node(l,r) = Poseidon^3(D_NODE,l,r)`
   tree root, computed in-circuit, not supplied as an untrusted public input.
9. `C_statement = Poseidon^8(D_STATEMENT, C_quota, R_plan, n, H_ctx_hi,
   H_ctx_lo, H_schema_hi, H_schema_lo)` is computed in-circuit.
10. Each context/schema digest is split into two big-endian 128-bit limbs; all
    four limbs are range checked as four 32-bit chunks and reconstructed in a
    dedicated gate. A limb at or above `2^128` is rejected.
11. All eight public inputs are bound with `constrain_instance` in the exact
    v0.2 order: `C_quota, R_plan, n, H_ctx_hi, H_ctx_lo, H_schema_hi,
    H_schema_lo, C_statement`. None is an unused instance.

## Explicit trust boundary / non-goals

This circuit does **not** prove:

- Ed25519 signature validity;
- private resource/field/filter allowlist compliance (still checked
  deterministically by the trusted authority);
- plan nonce or expiry;
- nullifier cross-gateway atomic state;
- actual database execution, or that query results are real/complete/fresh;
- absence of data-egress bypass.

Do not describe this result as an end-to-end ZK Agent execution system.

## Files added / modified

| Path | Change |
| --- | --- |
| `zk-v2-host/src/plan_quota_circuit.rs` | new: `PlanQuotaCircuit`, config, tests (32 new tests) |
| `zk-v2-host/src/bin/plan_quota_mock.rs` | new: MockProver demo binary |
| `zk-v2-host/src/lib.rs` | 2 module exports + `pub(crate)` visibility on 4 existing frozen domain tags; no value changes |
| `zk-v2-host/README_STEP3_2B.md` | new: this file |
| `zk-v2-host/IMPLEMENTATION_NOTES_STEP3_2B.md` | new: implementation and verification notes |
| `README.md` | Halo2 status and test-count table synchronization only |

Not modified: `agent_exec_binding.py`, `data_access.py`, `plan_batch.py`, any
Python test, `quota_circuit.rs`, Step 3.2A docs, or any archived E-stage file.
No new dependency was introduced; `Cargo.toml` and `Cargo.lock` are untouched.

## Acceptance commands (Windows PowerShell)

```powershell
cd D:\Research\agent-exec-binding-mvp\zk-v2-host
cargo fmt --check
cargo test --locked
cargo run --locked --bin quota_mock
cargo run --locked --bin plan_quota_mock
cargo run --locked --bin agent-exec-binding-host-v2
cd D:\Research\agent-exec-binding-mvp
git diff --check
git status --short --branch
git diff --stat
```

All nine commands returned exit code 0. See `IMPLEMENTATION_NOTES_STEP3_2B.md`
for the complete raw output, test breakdown, structure statistics, host/gadget
results, and v0.2 difference table.

## Status

Step 3.2B is complete locally and awaits independent review. Step 3.2C (ZKP
integration into the Python authorization gateway), Step 3.3 (comparison
experiments), Step 3.4/4 (adversarial prompt-injection experiments), and any
novelty claim remain **not started**.
