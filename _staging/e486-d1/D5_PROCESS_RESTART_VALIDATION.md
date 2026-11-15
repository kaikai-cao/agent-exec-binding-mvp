# D5 Process Restart Validation

## 1. Objective

Validate recovery across actual operating-system process termination,
rather than only reconstructing Python objects within one process.

The test uses a child process to execute the D1 integration flow,
injects a crash at a durable execution boundary, and then reconstructs
the complete D1 stack in the parent process using the same persistent
test directory and cryptographic configuration.

## 2. Crash Scenarios

### Scenario A: After tool effect, before gateway receipt commit

Crash point:
- `after_tool_effect`

Validation:
- Child process terminates at the injected crash boundary.
- Parent process reconstructs the D1 stack.
- The existing persisted tool result is recovered.
- The tool result record count remains 1.
- The durable budget counter remains 1.
- The execution journal reaches COMMITTED.

### Scenario B: After gateway receipt commit

Crash point:
- `after_receipt_commit`

Validation:
- Child process terminates after gateway receipt persistence.
- Parent process reconstructs the D1 stack.
- The previously committed gateway receipt is recovered.
- The tool result record count remains 1.
- The durable budget counter remains 1.
- The execution journal remains COMMITTED.

## 3. Test Results

D5 process restart tests:
- 2 passed, 0 failed.

D1 integration regression:
- 11 passed, 0 failed.

MVP regression:
- 80 passed, 0 failed.

The child process was expected to terminate with exit code 86
at the injected crash boundary. Both process restart scenarios passed.

## 4. Evidence Boundaries

The results establish recovery behavior for the implemented D1
integration and its SQLite-backed mock adapter under the tested
crash windows.

They do NOT establish:

- Exactly-once execution for arbitrary external tools or services.
- Exactly-once external side effects without cooperation from the
  external service.
- Hardware-backed monotonic counter guarantees. The current
  FileBackedCounter is a software implementation.
- Durable persistence of the MVP Parent AuditChain itself.
  The recovery test reconstructs the parent-side audit object and
  records the recovered operation after restart.
- Recovery under every possible crash point, storage failure,
  concurrency schedule, or hardware failure.

The mock adapter's persisted result count is evidence about its
SQLite-backed test behavior, not a measurement of arbitrary
real-world side effects.

## 5. Conclusion

D5 process-level recovery validation is complete for the two
specified crash windows.

Together with D4.3, the project now has:
- Same-process full-stack reconstruction tests.
- Independent OS process termination and restart tests.
- Recovery checks for both pre-receipt and post-receipt crash windows.

No commit or push was performed as part of this validation.
