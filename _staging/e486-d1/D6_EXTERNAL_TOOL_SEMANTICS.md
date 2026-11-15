# D6 — External Tool Execution Semantics

## 1. Research Question

When an Agent invokes an external tool and the Gateway loses
the response due to timeout, process termination, or network
failure, how can the system determine whether the external
effect occurred?

The Gateway cannot roll back arbitrary external side effects.
Exactly-once execution must not be assumed.

## 2. Existing Implementation

The current ToolAdapter exposes:

- idempotent_by_operation_id
- execute(operation_id, request_digest, ...)
- lookup(operation_id, request_digest)

The Gateway first attempts durable lookup. If no result exists,
it retries only when the adapter declares operation_id idempotency
or when the dispatch has just been entered for the first time.
After restart, a non-idempotent adapter without a recoverable
result is marked INDETERMINATE.

This is a conservative baseline, but the capability contract
does not yet describe idempotency scope, retention, or lookup
consistency and status semantics.

## 3. External Tool Capability Classes

### A. Naturally idempotent operations

Repeated identical requests have the same intended business
effect. The adapter must still verify the actual operation
semantics and request binding.

### B. Server-enforced idempotency keys

The external service durably binds an idempotency key to the
request parameters and effect. Retries must preserve the same
key and request. Scope and retention must be documented.

### C. Authoritative status lookup

The service can query an operation by stable identifier and
return an authoritative status, bound to the original request.

A non-authoritative NOT_FOUND response is insufficient evidence
that the operation was never applied.

### D. No idempotency or authoritative lookup

After dispatch ambiguity, automatic retry is unsafe.
The Gateway must fail closed and preserve INDETERMINATE.

## 4. Proposed Capability Contract

The next implementation should replace the single boolean
capability declaration with an explicit capability descriptor:

- naturally_idempotent
- supports_idempotency_key
- supports_authoritative_lookup
- idempotency_scope
- idempotency_retention_seconds

These values are trusted adapter configuration, not Planner input.

## 5. Proposed Lookup States

- NOT_FOUND
- IN_PROGRESS
- SUCCEEDED
- FAILED_NO_EFFECT
- UNKNOWN

Lookup results must bind operation_id and request_digest.
The adapter must define whether NOT_FOUND is authoritative,
eventually consistent, or unavailable.

## 6. Recovery Rules

| Observation | Recovery |
|---|---|
| SUCCEEDED | Verify binding and recover result |
| IN_PROGRESS | Poll or wait; do not redispatch |
| FAILED_NO_EFFECT | Retry only when explicitly safe |
| Authoritative NOT_FOUND | Redispatch may be allowed |
| Non-authoritative NOT_FOUND | Keep uncertain |
| UNKNOWN / lookup failure | INDETERMINATE |
| Valid idempotency key within retention | Retry with same key and same request |

An expired idempotency key must not be treated as a permanent
deduplication guarantee.

## 7. Evidence and Trust Boundaries

The adapter's capability declaration is a trusted configuration
claim. It is not independently proven by the Gateway.

A production adapter must document the provider's semantics,
key scope, retention, parameter mismatch behavior, lookup
consistency, and result authenticity.

A Gateway-signed receipt attests to the Gateway's recorded
execution result. It is not automatically a provider-signed
proof of an external side effect.

## 8. Current Test Boundary

The existing SQLite-backed mock adapter is read-only and
persists its computed result and receipt. Its SQLite transaction
does not establish atomicity with arbitrary external services.

The FileBackedCounter remains a software counter emulator.

No production external tool, real TPM, or hardware-backed
trust boundary is validated by this stage.

## 9. D6 Plan

D6.1: Define external tool capability and recovery semantics.

D6.2: Implement the capability descriptor and structured lookup
results in an isolated experiment branch. Add tests for the four
capability classes, delayed visibility, lookup failure, timeout,
and idempotency retention expiry.

D6.3: Verify fail-closed behavior and preserve budget, journal,
and receipt consistency.

No production protocol claim should be made solely from mock tests.
