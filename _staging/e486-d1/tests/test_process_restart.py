"""D5: independent OS-process crash and recovery tests."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_exec_binding import (
    ExecutionContext,
    SignedGrant,
    ToolCall,
    make_demo_environment,
    private_key_bytes,
)
from e483_adapter import E483MockFinanceAdapter
from integration_coordinator import IntegrationCoordinator
from src.durable_broker import DurableCounterBroker
from src.execution_binding import ExecutionBindingGateway, InjectedCrash


def _build_stack(root: Path, cfg: dict):
    """Reconstruct the complete D1 object stack from persisted test inputs."""
    from agent_exec_binding import (
        AuditChain,
        GrantIssuer,
        MockFinanceTool,
        Policy,
        ToolGateway,
    )

    issuer_sk = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(cfg["parent_issuer_sk"])
    )
    tool_sk = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(cfg["parent_tool_sk"])
    )
    audit_sk = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(cfg["parent_audit_sk"])
    )
    e483_issuer_sk = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(cfg["e483_issuer_sk"])
    )
    e483_gateway_sk = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(cfg["e483_gateway_sk"])
    )

    policy_data = dict(cfg["policy"])
    policy_data["allowed_operations"] = tuple(policy_data["allowed_operations"])
    policy_data["allowed_filter_values"] = {
        key: tuple(values)
        for key, values in policy_data["allowed_filter_values"].items()
    }
    policy = Policy(**policy_data)

    records = cfg["records"]
    parent_tool = MockFinanceTool(tool_sk, records)
    parent_audit = AuditChain(audit_sk)
    parent_issuer = GrantIssuer(issuer_sk)

    parent_gateway = ToolGateway(
        issuer_sk.public_key(),
        parent_tool,
        tool_sk.public_key(),
        policy,
        parent_audit,
    )

    adapter = E483MockFinanceAdapter(
        tool=parent_tool,
        database_path=root / "adapter.sqlite",
    )
    broker = DurableCounterBroker(
        journal_path=root / "broker.sqlite",
        counter_state_path=root / "counter.json",
        broker_lock_path=root / "broker.lock",
        lease_id="d1-lease",
        quota_limit=3,
    )
    gateway = ExecutionBindingGateway(
        issuer_public_key=e483_issuer_sk.public_key(),
        gateway_private_key=e483_gateway_sk,
        gateway_id="d1-gateway",
        broker=broker,
        journal_path=root / "gateway.sqlite",
        lock_path=root / "gateway.lock",
        tools={adapter.tool_name: adapter},
    )
    coordinator = IntegrationCoordinator(
        parent_gateway=parent_gateway,
        parent_tool=parent_tool,
        parent_tool_public_key=tool_sk.public_key(),
        e483_issuer_private_key=e483_issuer_sk,
        e483_issuer_id="d1-issuer",
        e483_gateway=gateway,
        adapter=adapter,
        lease_id="d1-lease",
        quota_limit=3,
    )

    call = ToolCall(**cfg["call"])
    context = ExecutionContext(**cfg["context"])
    grant = SignedGrant(**cfg["grant"])

    return {
        "parent_gateway": parent_gateway,
        "adapter": adapter,
        "broker": broker,
        "gateway": gateway,
        "coordinator": coordinator,
        "call": call,
        "context": context,
        "grant": grant,
    }


def _child_main(root_string: str, crash_at: str) -> None:
    """Child process: execute until the selected durable boundary, then exit."""
    root = Path(root_string)
    cfg = json.loads((root / "bootstrap.json").read_text(encoding="utf-8"))
    stack = _build_stack(root, cfg)

    original_execute = stack["gateway"].execute

    def crash_execute(grant, request):
        return original_execute(grant, request, crash_at=crash_at)

    stack["gateway"].execute = crash_execute

    try:
        stack["coordinator"].execute(
            stack["call"], stack["context"], stack["grant"]
        )
    except InjectedCrash:
        # Exit the OS process without normal Python shutdown.
        os._exit(86)

    raise RuntimeError(f"expected crash point was not reached: {crash_at}")


class D5ProcessRestartTests(unittest.TestCase):
    def _run_restart_case(self, crash_at: str, expected_replayed: bool):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            # Generate the parent authorization once. The same keys, grant,
            # request and context are reconstructed in the child and parent.
            env = make_demo_environment()
            call = ToolCall(
                agent_id=env["policy"].agent_id,
                tool_id=env["tool"].TOOL_ID,
                resource=env["policy"].resource,
                operation="read",
                args={
                    "fields": ["year", "department", "amount"],
                    "where": {"year": 2026, "department": "Sales"},
                    "limit": 5,
                },
                operation_id=f"d5-{crash_at}",
            )
            context = env["context"]
            grant = env["issuer"].issue(
                env["policy"],
                call,
                context,
                env["tool"].SCHEMA_HASH,
                now=__import__("time").time_ns() // 1_000_000_000,
            )

            e483_issuer_sk = Ed25519PrivateKey.generate()
            e483_gateway_sk = Ed25519PrivateKey.generate()

            cfg = {
                "parent_issuer_sk": private_key_bytes(env["issuer"].private_key),
                "parent_tool_sk": private_key_bytes(env["tool"].private_key),
                "parent_audit_sk": private_key_bytes(env["audit"].signing_key),
                "e483_issuer_sk": private_key_bytes(e483_issuer_sk),
                "e483_gateway_sk": private_key_bytes(e483_gateway_sk),
                "policy": env["policy"].as_dict(),
                "records": env["tool"].records,
                "call": call.as_dict(),
                "context": context.as_dict(),
                "grant": grant.as_dict(),
            }
            (root / "bootstrap.json").write_text(
                json.dumps(cfg, sort_keys=True), encoding="utf-8"
            )

            # A real child OS process performs the execution and terminates
            # at the injected durable boundary.
            tests_dir = str(Path(__file__).resolve().parent)
            d1_dir = str(Path(__file__).resolve().parents[1])
            repo_dir = str(Path(__file__).resolve().parents[3])
            e483_dir = str(Path(repo_dir).parent / "offline-agent-budget-lab"
                           / "e4_8_3_execution_binding")

            env_vars = os.environ.copy()
            env_vars["PYTHONPATH"] = os.pathsep.join(
                [tests_dir, d1_dir, repo_dir, e483_dir]
            )

            child_code = (
                "from test_process_restart import _child_main; "
                f"_child_main({str(root)!r}, {crash_at!r})"
            )
            proc = subprocess.run(
                [sys.executable, "-c", child_code],
                cwd=repo_dir,
                env=env_vars,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                proc.returncode,
                86,
                msg=f"child did not exit at injected crash point\n"
                    f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
            )

            # Parent process reconstructs every object using the same
            # durable files and cryptographic identities.
            stack = _build_stack(root, cfg)
            gateway = stack["gateway"]

            persisted_row = gateway.journal.get(call.operation_id)
            self.assertIsNotNone(persisted_row)

            persisted_receipt = None
            if crash_at == "after_receipt_commit":
                self.assertEqual(persisted_row["status"], "COMMITTED")
                persisted_receipt = json.loads(persisted_row["receipt_json"])

            recovered = stack["coordinator"].execute(
                call, context, grant
            )

            self.assertTrue(recovered.output)
            self.assertEqual(recovered.replayed, expected_replayed)
            self.assertEqual(stack["adapter"].effect_count(), 1)
            self.assertEqual(stack["broker"].counter.read(), 1)

            final_row = gateway.journal.get(call.operation_id)
            self.assertEqual(final_row["status"], "COMMITTED")

            if persisted_receipt is not None:
                self.assertEqual(
                    recovered.gateway_receipt,
                    persisted_receipt,
                )

            audit = stack["parent_gateway"].audit
            self.assertEqual(len(audit.entries), 1)
            self.assertTrue(audit.verify(audit.signing_key.public_key()))

    def test_os_process_restart_after_tool_effect_before_receipt(self):
        self._run_restart_case(
            crash_at="after_tool_effect",
            expected_replayed=False,
        )

    def test_os_process_restart_after_gateway_receipt_commit(self):
        self._run_restart_case(
            crash_at="after_receipt_commit",
            expected_replayed=True,
        )


if __name__ == "__main__":
    unittest.main()
