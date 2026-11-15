# D1: E4.8.3 Execution Binding Integration

## 1. Purpose

D1 integrates the Agent Execution Binding MVP with the E4.8.3 durable execution-binding implementation.

The integration preserves the two projects as separate codebases. The MVP provides parent authorization, while E4.8.3 provides durable budget allocation, execution journaling, and gateway-controlled tool execution.

The Integration Coordinator acts as a trusted bridge and child-grant issuer. It is not an independent authorization authority.

## 2. Directory Structure

This integration package is maintained under the MVP repository:

```text
_staging/
└── e486-d1/
    ├── README_D1.md
    ├── e483_adapter.py
    ├── integration_coordinator.py
    └── tests/
        └── test_integration_coordinator.py
```

The E4.8.3 implementation remains in the separate `offline-agent-budget-lab` project:

```text
e4_8_3_execution_binding/
```

## 3. Execution Flow

1. The MVP ToolGateway verifies the parent SignedGrant.
2. The Integration Coordinator derives a child LeaseGrant bound to the verified parent authorization, request, context, tool, and schema.
3. The E4.8.3 Gateway performs durable budget allocation and execution journaling.
4. The adapter invokes the original MVP mock tool and stores its result and signed receipt for recovery.
5. The Coordinator verifies both the E4.8.3 gateway receipt and the original MVP tool receipt.
6. Only after both receipt checks succeed does the Coordinator append `ALLOW_EXECUTED` to the MVP AuditChain.

## 4. Running Tests

Run the D1 integration tests from PowerShell:

```powershell
$M = "D:\Research\agent-exec-binding-mvp"
$E = "D:\Research\offline-agent-budget-lab\e4_8_3_execution_binding"

$env:PYTHONPATH = "$M;$D;$E"
Set-Location $M

python -m unittest discover -s "$M\_staging\e486-d1\tests" -v
```

Run the MVP test suite:

```powershell
Set-Location $M
python -m unittest discover -s tests -v
```

Run the E4.8.3 test suite from its own project directory:

```powershell
Set-Location $E
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\run-tests.ps1"
```

## 5. Security and Model Limitations

- The MVP `MockFinanceTool` is a read-only in-memory query. The adapter stores its result and signed tool receipt in SQLite for restart recovery.
- This does not establish exactly-once behavior for arbitrary external side effects.
- The E4.8.3 counter is a software file-backed emulator, not TPM-backed monotonic storage.
- The Coordinator is a trusted bridge and child-grant issuer, not an independent authorization authority.
- After restart, the caller must present the same parent authorization again to re-establish the in-process binding.
- The MVP AuditChain is currently in-memory. It is not a durable cross-process audit database.
- Passing the integration tests validates the tested implementation behavior, not a formal security proof or production security guarantee.
