# Step 3.2B implementation and verification notes

These notes accompany `README_STEP3_2B.md` and record the evidence for the
completion criteria in task package `AE-ZK-STEP3.2B`.

## 1. Full acceptance-command raw output summary

All commands were run in Windows PowerShell (via Git Bash in this session),
from `D:\Research\agent-exec-binding-mvp\zk-v2-host` unless noted.

| Command | Exit | Key result |
| --- | --- | --- |
| `cargo fmt --check` | 0 | no formatting diff |
| `cargo test --locked` | 0 | 53 passed, 0 failed |
| `cargo run --locked --bin quota_mock` | 0 | `mock_prover=accepted` (Step 3.2A preserved) |
| `cargo run --locked --bin plan_quota_mock` | 0 | `mock_prover=accepted`, all 3 host/gadget equality flags `true` |
| `cargo run --locked --bin agent-exec-binding-host-v2` | 0 | 3/3 inclusion proofs verified, unchanged output |
| `git diff --check` | 0 | no whitespace errors (one CRLF advisory on `lib.rs`, not an error) |
| `git status --short --branch` | 0 | `## feat/step3-2b-plan-root-circuit`, 2 modified + 4 new files |
| `git diff --stat` | 0 | `README.md \| 67 ++++...`, `zk-v2-host/src/lib.rs \| 12 ++++++---`; four new files untracked (no commit by design) |

`cargo test --locked` per-target breakdown:

```text
running 53 tests
test result: ok. 53 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 27.07s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Important baseline correction: the root README previously described 59 Python
+ 11 Rust host + 10 Rust Halo2 = 80 tests. Actual measured counts are **80
Python** (`40 test_agent_exec_binding + 21 test_data_access + 5
test_independent_execution_proxy + 14 test_plan_batch`) and **21 Rust** (11
host + 10 quota circuit) before this round. The README table is corrected in
this round to the actual measured values; no test was added or removed.

`plan_quota_mock` raw output (excerpt):

```text
circuit=plan-quota-16-leaf-statement-binding-v1
mock_prover=accepted
circuit_k=13
instance_column_count=8
public_input_order=C_quota,R_plan,n,H_ctx_hi,H_ctx_lo,H_schema_hi,H_schema_lo,C_statement
action_count=3
blinding=DEMO_ONLY
aggregate_reserved_rows=5
c_quota_matches_host=true
r_plan_matches_host=true
c_statement_matches_host=true
C_quota=c08b09fbb2ded7013971b6bdbe6498c9346f021aa189c32e2c084cfa85f05
R_plan=381dd1e7a757e4cd26dcddd90f75631d9208474c5b2b02b60224eec6e8f69b3d
n=3
C_statement=fa88ffef99369b6e7a421ef87a9b866b50f90eaaecd4662b779cd448aff2641d
proof_generated=false
ed25519_signature_checked=false
private_allowlist_proven=false
```

## 2. Test count and coverage

| Scope | Before | After | Delta |
| --- | ---: | ---: | ---: |
| Python unittest | 80 | 80 | 0 |
| Rust host | 11 | 11 | 0 |
| Rust Step 3.2A quota circuit | 10 | 10 | 0 |
| Rust Step 3.2B plan-root circuit | 0 | 32 | +32 |
| **Total** | **101** | **133** | **+32** |

The 32 Step 3.2B tests are:

- 5 positive: `n=1` minimal, current demo (`n=3`), `n=16` all `m=65535`,
  multiple legal resource/filter/selected-field encodings, host/gadget
  consistency of `C_quota`/`R_plan`/`C_statement` plus distinctness of action
  leaf, padding leaf, and ordered parent hash;
- 26 negative, each driven through `PlanQuotaCircuit::new_raw` with recomputed
  public inputs so the failure comes from a circuit gate, not from the host
  `encode_action()` validator: `B=0`, `L=0`, `m_i=0`, `m_i=65536`, `B=2^32`,
  per-action overflow, aggregate overflow, `n=0`, `n=17`, non-contiguous
  active prefix, nonzero inactive witness, illegal resource ID,
  resource↔selected incompatibility, resource↔filter incompatibility,
  filter-field↔value incompatibility, selected-field duplicate/out-of-order,
  filter-field duplicate/out-of-order, action modified with original `R_plan`,
  action reordered, step index modified, wrong `C_quota`, wrong `R_plan`,
  wrong `C_statement`, context modified with old `C_statement`, schema modified
  with old `C_statement`, and context/schema limb above 128 bits (two tests).

For `n=17`, a 16-slot circuit can only represent it as a public instance value;
the test fixes an honest `n=3` witness and sets `instance[2]=17` so the sole
failing constraint is the instance binding. For context/schema modification
tests, the corresponding limb instance is updated while `C_statement` is not,
isolating the statement-binding constraint.

## 3. Circuit size and structure statistics

The required circuit parameter is **`k = 13`** (`2^13 = 8192` rows). `k=12`
was not attempted as final because 16 × `Poseidon^14` action leaves plus 16
padding leaves and 15 parent hashes exceed it; `k=13` synthesizes and verifies
with `MockProver`.

Halo2 0.4.0 does not expose gate/constraint counts through its public API
(`ConstraintSystem` fields are `pub(crate)` and `MockProver` exposes only
`run`/`verify`). Therefore no constraint-polynomial count is claimed. The
following are **exact structure statistics** obtained by counting constructors
in `PlanQuotaCircuit::configure` (array constructors expanded), not estimates:

| Structure | Exact count |
| --- | ---: |
| Advice columns | 68 |
| Fixed columns | 6 |
| Instance columns | 1 |
| Selectors | 13 |
| Custom gate definitions | 13 |
| Poseidon hashes per proof | 49 (16 action + 16 padding + 15 parent + 1 quota + 1 statement) |
| Generic range-check rows | 53 (B, L, 16×m, 16×d_L, S, d_B, 16×limb chunks, n) |

The 13 gates are: four range widths (5/16/20/32-bit) generated from one
parameterized definition, conditional nonzero, canonical action slot, slot 0
active, active-prefix continuity, n-sum, aggregate sum, aggregate budget,
in-circuit leaf selection, and 128-bit limb reconstruction.

## 4. Host/gadget consistency results

`positive_host_gadget_consistency` and `plan_quota_mock` compare the circuit's
instance-bound outputs with the Host reference functions on the demo plan:

| Primitive | Host function | Result |
| --- | --- | --- |
| Quota commitment | `quota_commitment(5,3,r)` | `public[0]` equal, `c_quota_matches_host=true` |
| 16-leaf plan root | `PoseidonPlanTree::new(...).root()` | `public[1]` equal, `r_plan_matches_host=true` |
| Statement commitment | `statement_commitment(&PublicStatement)` | `public[7]` equal, `c_statement_matches_host=true` |
| Action leaf | `action_leaf(action)` vs `poseidon_hash(encode_action(action).fields)` | equal; distinct across actions |
| Padding leaf | `padding_leaf(i)` | position-bound (leaf 0 != leaf 1) |
| Merkle parent | `parent_hash(l,r)` | order-bound (`parent_hash(1,2) != parent_hash(2,1)`) |

The circuit's action leaves, padding leaves, and parent nodes are computed by
the same `P128Pow5T3` gadget with `ConstantLength<14>`, `<2>`, and `<3>` and
the same frozen domain tags as the Host. The selected leaf is gated in-circuit;
a modified action with the original `R_plan` is rejected by MockProver.

## 5. Actual coverage of the relation

Implemented and constrained:

- `C_quota` relation, integer ranges, `m_i<=L`, `S<=B`, active prefix, `n`,
  14-element canonical action encoding, public tool-schema compatibility,
  position-bound padding, four-level Merkle root, selection gate, statement
  commitment, 128-bit limb range checks, and all eight instance bindings.

Not proven by this circuit (unchanged trust boundary):

- Ed25519 authorization-envelope validity;
- private resource/field/filter allowlist (trusted authority check remains);
- plan nonce / issued_at / expires_at freshness;
- nullifier cross-gateway atomic consumption;
- database execution, tool receipt authenticity, query result truth,
  completeness or freshness;
- absence of data-egress bypass;
- performance or security-effectiveness claims.

No real proof was generated (only `MockProver`); no Python gateway or LLM is
connected. This is not an end-to-end ZK agent execution system.

## 6. v0.2 specification difference table

| v0.2 item | Host/spec | Circuit behavior | Difference |
| --- | --- | --- | --- |
| Instance order (§7.1) | 8 fields in fixed order | identical, all `constrain_instance` | none |
| Domain tags (§5) | five frozen u64 tags | reused via `pub(crate)` constants; values unchanged | none |
| `C_quota` length 4 | `ConstantLength(4)` | identical | none |
| Action message length 14 | §4.2 | identical; constants `D_ACTION`, schema id 2, `step=i` enforced | none |
| Filter/field IDs and value IDs | §4.1 tables | enforced as polynomial membership and compatibility gates | none |
| `n` range | 5-bit | 5-bit range check plus active-bit sum | none |
| Limb width | two 128-bit big-endian limbs each | four 32-bit chunk range checks plus reconstruction gate | none |
| Padding | `Pad_i=Poseidon^2(D_PAD,i)` | computed in-circuit and selected by active gate | none |
| Merkle depth | four levels, no duplicate-last | 16 leaves → 15 parent hashes, fixed four levels | none |
| Host fixture digests | `demo_statement` uses `[0x11;32]`/`[0x22;32]` | tests reuse the same fixtures | none; real v2 schema digest must be supplied at integration |
| Proof system | Halo2 0.4 / Pallas / Poseidon | same; no dependency changes | none |
| Private allowlist | explicitly outside circuit | outside circuit | none |

No v0.2 mathematical or API defect was found; no spec value was changed. No
constraint was lowered to make a failing test pass.

## 7. Completion criteria and Step 3.2C condition

| # | Criterion | Result |
| --- | --- | --- |
| 1 | Full Halo2 relation implemented | yes, per §5 |
| 2 | `R_plan` computed and constrained in-circuit | yes (instance 1) |
| 3 | `C_statement` computed and constrained in-circuit | yes (instance 7) |
| 4 | Host/gadget consistency passes | yes, six primitives per §4 |
| 5 | Core positive and negative MockProver tests pass | yes, 5 positive + 26 negative |
| 6 | Step 3.2A reproducible | yes, 10 circuit tests + `quota_mock` unchanged |
| 7 | Python baseline untouched | yes, 80/80 before and after |
| 8 | Docs match circuit boundary | yes, explicit non-goals in both docs |

Step 3.2C readiness: **technically ready to be scoped**, but not authorized to
start by this task package. Before integration, a separate decision must
define how the real v2 schema digest and the Ed25519 envelope feed the eight
instances, and how the Python gateway obtains/verifies proofs. This round makes
no claim about exceeding ZKA/Coord v2 or zkagent research contributions.

Work stops here for independent review. No commit, push, or PR was created.
