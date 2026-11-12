# Agent Execution Binding MVP

A small, runnable research prototype for **request-bound authorization and execution evidence** in LLM tool-calling agents.

## Research question

Can a gateway ensure that the tool call it authorizes is exactly the operation a tool server later executes, while binding the decision to the principal, policy version, runtime context, tool schema, freshness nonce, and execution receipt?

## Why this scope

Recent work already covers (i) LLM-assisted natural-language policy compilation, (ii) runtime tool-call policy enforcement and information-flow labels, (iii) capability-token provenance for multi-agent state, and (iv) request-bound ZK authorization as a separate cryptographic relation. A recent CVA study explicitly lists context-binding implementation and runtime execution binding as open problems. This MVP isolates the authorization-to-execution binding problem rather than claiming novelty for generic "LLM + ZKP" integration.

## What is implemented

### Single-call baseline (`agent_exec_binding.py`)

1. **Untrusted model boundary:** the agent produces a `ToolCall`; it does not hold the signing key.
2. **Fail-closed policy check:** the issuer checks principal, tool, resource, operation, field allowlist, mandatory filters, optional filter values, row limit, and tenant.
3. **Request-specific Ed25519 grant:** the signed grant binds the policy hash/version, exact canonical request hash, context hash, tool-schema hash, one-time nonce, and validity interval.
4. **Execution gateway:** takes independent JSON snapshots of the grant payload, request, and execution context at entry, verifies the signature over those snapshot bytes, rechecks policy against the snapshot-built context, rejects request/context/schema substitution, expired grants, and nonce replay, then hands a request, an isolated grant copy, and a context all built from those snapshots to the tool adapter. The authorized request hash and grant hash are pinned before the adapter runs. Adapter-side request mutation can be detected through receipt-binding verification. This check does not prevent side effects performed by a compromised or faulty tool adapter.
5. **Tool-signed receipt:** binds the request hash, policy hash, context hash, nonce, tool schema, and output digest.
6. **Signed hash-chain audit:** records `ALLOW_EXECUTED`, `DENY`, `OUTCOME_UNKNOWN` (tool failed with an unknown outcome) and `RECEIPT_INVALID` (tool ran but its receipt failed verification), and detects entry modification.

### Plan-level batch baseline (`plan_batch.py`)

1. A trusted authority checks a finite ordered plan against a private aggregate budget and public per-action policy constraints.
2. The authority signs one Ed25519 grant over the ordered action Merkle root, action count, principal, tenant/session, policy ID/version/hash, tool-schema hash, nonce, and expiry. The aggregate budget value is not included in the grant.
3. Each tool invocation presents its exact action and a Merkle inclusion proof; the gateway rejects substitution, reordering, skipped steps, replay, expiry, context mismatch, and schema drift.
4. A per-step nullifier is consumed once, and the mock tool signs a receipt bound to the grant, action, context, schema, and result digest.
5. `demo_plan_batch.py` runs a harmless three-step mock workflow; it performs no real transfer or purchase.

The plan-level implementation is a **signed authorization baseline, not ZKP**. The budget is hidden from the agent/gateway interface because the trusted authority checks it before signing; this does not let an independent verifier cryptographically verify the hidden budget predicate. The mock transfer schema is used only to test plan-commitment mechanics. A fresh literature review found ZKM already covers privacy-preserving, cap-bounded agent spend authorization, so payment authorization is not the proposed paper domain. The research brief narrows the candidate to non-financial, multi-step data-access workflows; this remains a hypothesis, not a novelty claim.

## Explicit limitations

- This is not a production-ready gateway or complete MCP implementation.
- The policy is a trusted, preconfigured structured envelope. There is no natural-language policy compiler yet.
- Ed25519 signatures are used in this baseline; the Python execution path does not use a zero-knowledge proof.
- The tool server is a mock process and is trusted to sign truthful execution receipts. A signature authenticates the server's assertion; it does not independently prove that external data are true.
- The audit chain and plan-step nullifier store are in-memory, single-process demonstrations. A real deployment needs durable, shared, transactional state across gateway replicas; the prototype consumes a step before calling the mock tool, so a failed tool call requires a new plan rather than an automatic retry.
- The LLM is not yet connected. Tests use fixed plans to isolate the authorization protocol from model variability and prompt-injection behavior.
- No performance or security effectiveness claim should be made from the unit tests alone.

## Run on Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py .\agent_exec_binding.py
py .\demo_plan_batch.py
py -m unittest discover -s tests -v
```

## Run on Linux / WSL

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python agent_exec_binding.py
python demo_plan_batch.py
python -m unittest discover -s tests -v
```

## Tests

The repository currently has 80 passing automated tests:

| Test scope | Count | Status |
| --- | --- | --- |
| Python Agent Execution Binding | 24 | passed |
| Python Data Access | 21 | passed |
| Python Plan Batch | 14 | passed |
| Rust Host | 11 | passed |
| Rust Halo2 quota circuit | 10 | passed |
| **Total** | **80** | **passed** |

- 59 Python unit tests;
- 11 Rust host tests;
- 10 Rust Halo2 quota-circuit tests.

Python tests:

```powershell
python -m unittest discover -s tests -v
```

Rust tests:

```
cd zk-v2-host
cargo test --locked
```

The Halo2 quota circuit is additionally exercised through
the `quota_mock` demo, while the host-side Poseidon plan,
commitment, public-input, and Merkle inclusion functionality
is exercised through `agent-exec-binding-host-v2`.

These tests validate the implemented prototype, not the
complete v0.2 relation or an end-to-end ZK execution system.

The Python suite covers successful execution plus policy violations, request/action substitution, context/session substitution, schema drift, expiry, replay, ordered-step enforcement, Merkle inclusion verification, aggregate-budget denial, forged grant, and audit tampering. It also checks authorized/executed request consistency, exception-path audit outcomes, nonce binding consistency, and includes a no-lock mutation guard for the concurrency test. Passing tests establish expected behavior for this prototype only; they do not establish production security, end-to-end ZK authorization, or security effectiveness against a compromised tool server.

## First experiment matrix (next step)

| Arm | Enforcement | What it tests |
|---|---|---|
| A0 | No gateway | Upper-bound execution of malicious calls in the mock environment |
| A1 | Policy check only | Runtime allow/deny without cryptographic request binding |
| A2 | Signed request-bound grant | Principal/policy/request/context/schema/freshness binding |
| A3 | A2 + signed tool receipt + audit chain | Authorization-to-execution evidence chain |

Attack classes: unauthorized operation, sensitive-field read, required-filter removal, filter widening, row-limit escalation, request substitution after authorization, context substitution, tool-schema drift, expired grant, replay, forged grant, and audit-log tampering.

Primary metrics: attack success rate (ASR), false deny rate on benign calls, authorization latency, execution/receipt latency, proof-or-signature bytes, and audit verification cost. Each attack should be tested under paired seeds and with explicit expected outcomes.

## Current Halo2 prototype

The repository now includes an initial Halo2 quota circuit in
`zk-v2-host`.

The circuit proves a fixed three-action quota sub-relation:

- a private budget, per-action limit, and blinding factor match a public
  Poseidon quota commitment;
- the budget and per-action limits satisfy their integer range constraints;
- each action's reserved row count does not exceed the per-action limit;
- the sum of the three reserved row counts does not exceed the budget.

The prototype is tested with Halo2 `MockProver`.

This is not yet a proof of the complete v0.2 relation. In particular,
the circuit does not yet constrain the 16-leaf plan Merkle root,
the full statement commitment, variable action counts, inactive slots,
or action-schema compatibility. It is also not integrated with the
Python authorization envelope and execution gateway.

The Rust host currently provides Poseidon action encoding, plan-tree
construction, quota and statement commitments, and public-input encoding.
These host-side functions must not be confused with constraints enforced
by the current Halo2 circuit.

See `zk-v2-host/README_STEP3_2.md` for the exact circuit boundary.
