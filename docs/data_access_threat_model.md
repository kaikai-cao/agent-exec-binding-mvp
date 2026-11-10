# Step 2 — Data-access workflow: scope and threat model

**Status:** design + signed Python baseline. This is not a ZK proof and is not a production security claim.

## 1. Research scenario

A read-only analytics Agent proposes a finite, ordered plan over two synthetic data resources:

- `sales_records`: approved fields `quarter`, `region`, `revenue_cents`.
- `support_metrics`: approved fields `quarter`, `category`, `ticket_count`.

Backing fixtures also contain `customer_id`, `customer_email`, and `account_id`; these fields are intentionally not exposed by the tool schema or policy allowlist. All records are synthetic (`example.test`). No real database, personal data, network service, or write operation is used.

Each action specifies:

- `step`: contiguous index in the plan;
- `resource`: fixed resource identifier;
- `filters`: non-empty equality filters only (no SQL text or arbitrary operators);
- `selected_fields`: exact output projection;
- `max_rows`: reserved upper bound for this action's output row count.

## 2. Policy and quantitative semantics

The authority holds a private policy containing:

- allowed output fields per resource;
- allowed filter fields and permitted filter values;
- a per-action maximum row count;
- an aggregate **reserved-row quota** `B`;
- a maximum plan length.

For actions `a_0 ... a_(n-1)`, authorization requires:

1. `selected_fields(a_i)` is a subset of the resource's allowed fields;
2. every filter field/value is allowed for that resource;
3. `1 <= max_rows(a_i) <= L`, where `L` is the per-action cap;
4. `sum_i max_rows(a_i) <= B`;
5. `1 <= n <= 8` in the demo policy (the implementation supports at most 16);
6. all step indices are exactly `0 ... n-1`.

**Important semantic boundary:** `B` limits the sum of reserved maximum output rows across calls, counting repeated/overlapping query results again. It is not a count of unique people or unique records, not differential privacy, and not a guarantee against inference from query combinations. The proof would establish compliance with this explicit row-volume policy only.

The action's `max_rows` is enforced by the mock tool before output. The tool receipt records the actual returned-row count and result digest. The tool signature authenticates the tool's assertion; it does not independently prove the truth or completeness of the database contents.

## 3. Trust assumptions

Trusted in this MVP:

- the policy authority and its Ed25519 signing key;
- the execution gateway implementation and its configured issuer/tool public keys;
- the mock data tool and its receipt-signing key;
- the schema digest distributed to the authority and gateway.

Untrusted:

- LLM Agent and any plan it proposes;
- plan/action payloads supplied at execution time;
- caller attempts to alter, reorder, skip, replay, or substitute steps.

## 4. Security properties tested

- **Policy compliance at issuance:** the authority rejects unauthorized resources, fields, filters, values, per-step row bounds, and aggregate reservations.
- **Plan integrity:** each executed action must prove membership in the signed ordered Merkle root.
- **Context/schema binding:** principal, tenant, session, and tool schema must match the grant.
- **Freshness and one-use:** grants expire; each step has a nullifier and can be consumed once.
- **Order:** the gateway accepts only the next expected step; skipping/reordering is rejected.
- **Output bound and receipt binding:** returned rows cannot exceed `max_rows`; the signed receipt binds plan, step, action, result digest, row count, schema, context, and time.

The in-memory nullifier store is single-process and is not crash-safe or shared across replicas. A consumed step is not automatically retried if tool execution fails.

## 5. Out of scope

- compromised policy authority, gateway, tool server, or signing keys;
- proving that the database contents are truthful, complete, fresh, or correctly sourced;
- differential privacy and inference attacks from query composition;
- arbitrary SQL, joins, dynamic query arguments derived from previous outputs, writes, or external MCP services;
- LLM prompt-injection success rates (the planner is not connected yet);
- transport security, availability, and multi-replica transactional nullifier storage.

## 6. Cryptographic migration notes

This step uses Ed25519 signatures and SHA-256 Merkle commitments as a non-ZK baseline. The issuer salts a SHA-256 commitment to the private policy attributes; the grant exposes only the commitment, not the row quota or field allowlists. The gateway verifies the issuer signature and trusts the authority's check; it does **not** independently verify the hidden policy predicate.

The next Halo2 stage must define public inputs and private witnesses precisely, select a circuit-friendly commitment/hash (likely a Pasta-field Poseidon construction), enforce bounded integer/range constraints for row counts and sums, and bind the exact ordered action commitment. Replacing SHA-256 with Poseidon changes the commitment format and must be treated as a protocol-version change, not a silent implementation detail.

## 7. Current demonstration policy

- per-action `max_rows <= 3`;
- aggregate reserved-row quota `B = 5`;
- three actions with reserved maxima `2 + 2 + 1 = 5`;
- all actions are read-only; no SQL strings or real data stores are involved.
