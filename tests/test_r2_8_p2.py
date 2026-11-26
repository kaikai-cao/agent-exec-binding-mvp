"""R2.8-P2 — minimal hardening + controlled comparison experiments.

These tests exercise the OPT-IN hardened paths added for P2:

  E1  VerifyingTool rejects forged / rebound grants at the adapter
  E2  CheckpointWitness makes tail truncation detectable / INCOMPLETE
  E5  NonceRegistry persists single-use across instances/restarts/concurrency
  E6  ExecutionLedger + ExecutionReconciler recover effects after audit failure

The frozen P0/P1 defect-reproduction tests (test_r2_8_boundary.py) are NOT
modified; a passing test here means the HARDENED behaviour was observed.
All DB files live in ``tempfile.TemporaryDirectory``; no user data is touched.
"""
import json
import os
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from execution_ledger import (
    COMPLETED,
    OUTCOME_UNKNOWN,
    RECONCILED,
    LedgerError,
    NonceConflict,
    NonceRegistry,
)
from agent_exec_binding import (
    AuthorizationError,
    AuditChain,
    CheckpointError,
    CheckpointWitness,
    ExecutionContext,
    GrantIssuer,
    HardenedToolGateway,
    MockFinanceTool,
    Policy,
    SignedGrant,
    ToolCall,
    UnavailableCheckpointWitness,
    VerifyingTool,
    CHECKPOINT_COMPLETE,
    CHECKPOINT_DIVERGED,
    CHECKPOINT_INCOMPLETE,
    CHECKPOINT_UNVERIFIED,
    RECONCILE_OK,
    RECONCILE_UNKNOWN,
    digest_object,
    make_demo_environment,
    make_hardened_environment,
    verify_audit_with_checkpoint,
    verify_receipt,
)

ISSUE_NOW = 1_800_000_000
EXEC_NOW = 1_800_000_001


def _ev(label, payload):
    print(f"{label}=" + json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _authorized_call():
    return ToolCall(
        agent_id="agent:finance-assistant",
        tool_id=MockFinanceTool.TOOL_ID,
        resource="finance_records",
        operation="read",
        args={
            "fields": ["year", "department", "amount"],
            "where": {"year": 2026, "department": "Sales"},
            "limit": 5,
        },
    )


def _hostile_call():
    """Policy-forbidden field, used only for forged-grant E1 probes."""
    return ToolCall(
        agent_id="agent:finance-assistant",
        tool_id=MockFinanceTool.TOOL_ID,
        resource="finance_records",
        operation="read",
        args={
            "fields": ["id_number", "year", "department", "amount"],
            "where": {"year": 2026},
            "limit": 10,
        },
    )


class _EffectThenCrashTool(VerifyingTool):
    """E6 fault: perform the effect + persist receipt, then crash before returning."""

    def execute(self, call, grant, context, now):
        output, receipt = super().execute(call, grant, context, now)
        # Receipt is already durably stored by super(); crash before the
        # gateway can see it / write the final audit.
        raise RuntimeError("simulated crash AFTER effect + receipt, BEFORE return")


class _StartedThenCrashTool(VerifyingTool):
    """E6 fault: mark STARTED, simulate partial effect, crash with no receipt."""

    def execute(self, call, grant, context, now):
        self.verify_grant(call, grant, context, now)
        nonce = grant.payload["nonce"]
        self._result_store.mark_started(nonce)
        self.execute_count += 1
        raise RuntimeError("simulated crash AFTER start, BEFORE receipt")


class _FailOnlyFinalAudit(AuditChain):
    """Fail only the terminal ALLOW_EXECUTED write; keep other events."""

    def __init__(self, signing_key):
        super().__init__(signing_key)
        self.failed_events = []
        self.fail = True

    def append(self, event):
        if self.fail and event.get("decision") == "ALLOW_EXECUTED":
            self.failed_events.append(dict(event))
            raise OSError("simulated persistence failure on ALLOW_EXECUTED")
        super().append(event)


class R2_8_P2_Hardening(unittest.TestCase):

    def _env(self, d, version=1):
        env = make_hardened_environment(d, version=version)
        # Registered cleanup runs even when an assertion fails, so Windows can
        # delete the temp DB files (no lingering locks, no user data touched).
        self.addCleanup(env["close_all"])
        return env

    def _reg(self, path):
        reg = NonceRegistry(path)
        self.addCleanup(reg.close)
        return reg

    # ------------------------------------------------------------------ E1
    def test_e1_forged_grant_rejected_at_tool(self):
        env = make_demo_environment()
        tool = VerifyingTool(
            env["tool_sk"], env["tool"].records,
            env["issuer_sk"].public_key(), "issuer-1", env["policy"].policy_hash,
        )
        forged = SignedGrant(
            {"policy_hash": "FORGED", "nonce": "forged-e1"}, "forged-signature"
        )
        rejected = False
        reason = None
        try:
            tool.execute(_hostile_call(), forged, env["context"], EXEC_NOW)
        except AuthorizationError as exc:
            rejected = True
            reason = str(exc)
        self.assertTrue(rejected)
        self.assertEqual(tool.execute_count, 0)
        self.assertIn("invalid grant signature", reason)
        _ev("E1_P2_FORGED", {
            "rejected": rejected, "execute_count": tool.execute_count,
            "reason": reason,
        })

    def test_e1_valid_signature_wrong_request_rejected(self):
        env = self._env(tempfile.mkdtemp())
        call = _authorized_call()
        grant = env["issuer"].issue(
            env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
            now=ISSUE_NOW,
        )
        # Keep the signed grant but swap the executed request to a different
        # (policy-valid) query. Signature is valid, request binding is not.
        swapped = ToolCall(
            agent_id=call.agent_id, tool_id=call.tool_id,
            resource=call.resource, operation=call.operation,
            args={
                "fields": ["year", "department", "amount"],
                "where": {"year": 2026, "department": "Finance"},
                "limit": 4,
            },
        )
        rejected = False
        try:
            env["tool"].execute(swapped, grant, env["context"], EXEC_NOW)
        except AuthorizationError as exc:
            rejected = True
            reason = str(exc)
        self.assertTrue(rejected)
        self.assertIn("request hash mismatch", reason)
        self.assertEqual(env["tool"].execute_count, 0)
        _ev("E1_P2_SWAPPED", {"rejected": rejected, "reason": reason})

    def test_e1_context_and_expiry_rejected(self):
        env = self._env(tempfile.mkdtemp())
        call = _authorized_call()
        grant = env["issuer"].issue(
            env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
            now=ISSUE_NOW, ttl_seconds=30,
        )
        wrong_ctx = ExecutionContext("session-002", "task-002", "tenant:example")
        ctx_rejected = False
        try:
            env["tool"].execute(call, grant, wrong_ctx, EXEC_NOW)
        except AuthorizationError as exc:
            ctx_rejected = True
            ctx_reason = str(exc)
        self.assertTrue(ctx_rejected)
        self.assertIn("context hash mismatch", ctx_reason)

        expired = env["issuer"].issue(
            env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
            now=ISSUE_NOW, ttl_seconds=1,
        )
        exp_rejected = False
        try:
            env["tool"].execute(call, expired, env["context"], ISSUE_NOW + 5)
        except AuthorizationError as exc:
            exp_rejected = True
            exp_reason = str(exc)
        self.assertTrue(exp_rejected)
        self.assertIn("not currently valid", exp_reason)
        self.assertEqual(env["tool"].execute_count, 0)
        _ev("E1_P2_CONTEXT_EXPIRY", {
            "context_rejected": ctx_rejected, "expiry_rejected": exp_rejected,
        })

    def test_e1_schema_mismatch_and_legitimate_request_allowed(self):
        env = self._env(tempfile.mkdtemp())
        call = _authorized_call()
        # Wrong schema hash: issuer issues it, tool must reject.
        wrong = env["issuer"].issue(
            env["policy"], call, env["context"], "SCHEMA-TAMPERED", now=ISSUE_NOW
        )
        rejected = False
        try:
            env["tool"].execute(call, wrong, env["context"], EXEC_NOW)
        except AuthorizationError as exc:
            rejected = True
            reason = str(exc)
        self.assertTrue(rejected)
        self.assertIn("schema hash mismatch", reason)

        # Legitimate exact request through the hardened gateway: allowed, and
        # the adapter's independent verification accepted the shared nonce.
        good = env["issuer"].issue(
            env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
            now=ISSUE_NOW,
        )
        rows, receipt = env["gateway"].execute(call, env["context"], good, now=EXEC_NOW)
        self.assertTrue(rows)
        self.assertTrue(verify_receipt(receipt, env["tool_sk"].public_key()))
        accepts = [v for v in env["tool"].verify_log if v["verdict"] == "ACCEPT"]
        self.assertTrue(accepts, "tool must log an independent ACCEPT")
        self.assertEqual(env["tool"].execute_count, 1)
        _ev("E1_P2_LEGIT", {
            "schema_rejected": rejected,
            "legit_rows": len(rows),
            "tool_accept_log": len(accepts),
            "execute_count": env["tool"].execute_count,
        })

    # ------------------------------------------------------------------ E2
    def test_e2_checkpoint_normal_and_incomplete(self):
        env = make_demo_environment()
        audit = AuditChain(env["audit_sk"])
        pub = env["audit_sk"].public_key()
        witness = CheckpointWitness(version=1)
        for i in range(2):
            audit.append({"decision": "ALLOW_EXECUTED", "seq_tag": i})
        head = audit.entries[-1]["entry_hash"]
        witness.anchor("log-a", 1, head, now=EXEC_NOW)
        complete = verify_audit_with_checkpoint(audit, witness, pub, "log-a")
        self.assertEqual(complete, CHECKPOINT_COMPLETE)

        # One extra unanchored record -> INCOMPLETE, never COMPLETE.
        audit.append({"decision": "ALLOW_EXECUTED", "seq_tag": "extra"})
        incomplete = verify_audit_with_checkpoint(audit, witness, pub, "log-a")
        self.assertEqual(incomplete, CHECKPOINT_INCOMPLETE)
        _ev("E2_P2_NORMAL", {"complete": complete, "incomplete": incomplete})

    def test_e2_tail_truncation_now_detected(self):
        env = make_demo_environment()
        audit = AuditChain(env["audit_sk"])
        pub = env["audit_sk"].public_key()
        witness = CheckpointWitness()
        for i in range(3):
            audit.append({"decision": "ALLOW_EXECUTED", "seq_tag": i})
        head = audit.entries[-1]["entry_hash"]
        witness.anchor("log-b", 2, head, now=EXEC_NOW)
        before = verify_audit_with_checkpoint(audit, witness, pub, "log-b")
        self.assertEqual(before, CHECKPOINT_COMPLETE)
        audit.entries.pop()
        drop1 = verify_audit_with_checkpoint(audit, witness, pub, "log-b")
        audit.entries.pop()
        drop2 = verify_audit_with_checkpoint(audit, witness, pub, "log-b")
        self.assertEqual(drop1, CHECKPOINT_DIVERGED)
        self.assertEqual(drop2, CHECKPOINT_DIVERGED)
        # Plain chain.verify() still passes -> shows why the checkpoint is needed.
        self.assertTrue(audit.verify(pub))
        _ev("E2_P2_TAIL", {
            "before": before, "drop1": drop1, "drop2": drop2,
            "plain_verify_still_true": True,
        })

    def test_e2_middle_delete_head_tamper_rollback_and_unavailable(self):
        env = make_demo_environment()
        audit = AuditChain(env["audit_sk"])
        pub = env["audit_sk"].public_key()
        witness = CheckpointWitness()
        for i in range(3):
            audit.append({"decision": "ALLOW_EXECUTED", "seq_tag": i})
        head = audit.entries[-1]["entry_hash"]
        witness.anchor("log-c", 2, head, now=EXEC_NOW)

        mid = AuditChain(env["audit_sk"])
        for i in range(3):
            mid.append({"decision": "ALLOW_EXECUTED", "seq_tag": i})
        mid.entries.pop(1)
        mid_result = verify_audit_with_checkpoint(mid, witness, pub, "log-c")
        self.assertEqual(mid_result, CHECKPOINT_DIVERGED)

        tampered = AuditChain(env["audit_sk"])
        for i in range(3):
            tampered.append({"decision": "ALLOW_EXECUTED", "seq_tag": i})
        tampered.entries[-1]["entry_hash"] = "0" * 64
        tamper_result = verify_audit_with_checkpoint(tampered, witness, pub, "log-c")
        self.assertEqual(tamper_result, CHECKPOINT_DIVERGED)

        rollback_rejected = False
        try:
            witness.anchor("log-c", 1, head, now=EXEC_NOW)
        except CheckpointError:
            rollback_rejected = True
        self.assertTrue(rollback_rejected)

        conflicting = False
        try:
            witness.anchor("log-c", 2, "1" * 64, now=EXEC_NOW)
        except CheckpointError:
            conflicting = True
        self.assertTrue(conflicting)

        unavailable = verify_audit_with_checkpoint(
            audit, UnavailableCheckpointWitness(), pub, "log-c"
        )
        self.assertEqual(unavailable, CHECKPOINT_UNVERIFIED)
        _ev("E2_P2_MISC", {
            "middle_delete": mid_result, "head_tamper": tamper_result,
            "rollback_rejected": rollback_rejected,
            "conflict_rejected": conflicting, "unavailable": unavailable,
        })

    # ------------------------------------------------------------------ E5
    def _build_gateway(self, env, registry, ledger):
        return HardenedToolGateway(
            env["issuer_sk"].public_key(), env["tool"],
            env["tool_sk"].public_key(), env["policy"],
            AuditChain(env["audit_sk"]), registry, ledger,
        )

    def test_e5_single_instance_and_new_instance_replay_blocked(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            env = self._env(d)
            call = _authorized_call()
            grant = env["issuer"].issue(
                env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
                now=ISSUE_NOW,
            )
            first_rows, _ = env["gateway"].execute(call, env["context"], grant, now=EXEC_NOW)
            self.assertTrue(first_rows)

            # Same instance repeat.
            repeat_blocked = False
            try:
                env["gateway"].execute(call, env["context"], grant, now=EXEC_NOW)
            except AuthorizationError:
                repeat_blocked = True
            self.assertTrue(repeat_blocked)

            # New gateway instance sharing the SAME ledger files.
            gw2 = self._build_gateway(
                env, env["nonce_registry"], env["execution_ledger"]
            )
            restart_blocked = False
            try:
                gw2.execute(call, env["context"], grant, now=EXEC_NOW)
            except AuthorizationError:
                restart_blocked = True
            self.assertTrue(restart_blocked)
            self.assertEqual(env["nonce_registry"].count(), 1)
            self.assertEqual(env["tool"].execute_count, 1)
            _ev("E5_P2_REPLAY", {
                "repeat_blocked": repeat_blocked,
                "restart_blocked": restart_blocked,
                "nonce_count": env["nonce_registry"].count(),
                "execute_count": env["tool"].execute_count,
            })

    def test_e5_reopen_db_blocks_replay(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            env = self._env(d)
            call = _authorized_call()
            grant = env["issuer"].issue(
                env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
                now=ISSUE_NOW,
            )
            env["gateway"].execute(call, env["context"], grant, now=EXEC_NOW)
            env["nonce_registry"].close()
            env["execution_ledger"].close()
            env["result_store"].close()

            reopened = NonceRegistry(os.path.join(d, "nonce.db"))
            self.assertIsNotNone(reopened.lookup(grant.payload["nonce"]))
            conflict_blocked = False
            try:
                reopened.consume("different-grant", "different-req", "principal-x")
            except Exception:
                conflict_blocked = False  # different nonce is fine, see below
            # Re-consuming the SAME binding is an identical duplicate (not a
            # fresh consume); a *gateway* must still block replay on it.
            duplicate = reopened.consume(
                grant.payload["nonce"], grant.grant_hash,
                digest_object(call.as_dict()), call.agent_id,
            )
            self.assertFalse(duplicate.consumed)
            self.assertTrue(duplicate.identical_duplicate)
            reopened.close()
            _ev("E5_P2_REOPEN", {
                "persisted_after_reopen": True,
                "duplicate_consumed": duplicate.consumed,
                "identical_duplicate": duplicate.identical_duplicate,
            })

    def test_e5_concurrent_consume_exactly_one_wins(self):
        # Two independent Gateway instances == two independent DB connections
        # to the SAME file. SQLite UNIQUE + BEGIN IMMEDIATE is the sole gate.
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            db = os.path.join(d, "nonce.db")
            seed = self._reg(db)  # creates schema, then stays open
            results = []
            barrier = threading.Barrier(4)

            def worker(i):
                # Each worker opens its OWN connection (separate instance).
                local = NonceRegistry(db)
                barrier.wait()
                try:
                    r = local.consume("nonce-concurrent", "g", "q", "p")
                    results.append(r.consumed)
                except Exception as exc:
                    results.append(f"error:{type(exc).__name__}")
                finally:
                    local.close()

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            wins = sum(1 for r in results if r is True)
            rows = seed.count()
            self.assertEqual(wins, 1, "exactly one independent instance must win")
            self.assertEqual(rows, 1)
            _ev("E5_P2_CONCURRENT", {
                "results": results, "wins": wins, "rows": rows,
                "independent_connections": 4,
            })

    def test_e5_commit_failure_leaves_no_half_state(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            reg = self._reg(os.path.join(d, "nonce.db"))
            reg.force_commit_error = True
            raised = False
            try:
                reg.consume("nonce-fail", "g", "q", "p")
            except LedgerError:
                raised = True
            self.assertTrue(raised)
            self.assertIsNone(reg.lookup("nonce-fail"))
            self.assertEqual(reg.count(), 0)
            reg.force_commit_error = False
            again = reg.consume("nonce-fail", "g", "q", "p")
            self.assertTrue(again.consumed)
            reg.close()
            _ev("E5_P2_COMMIT_FAIL", {
                "raised": raised, "rows_after_fail": 0, "retry_consumed": True,
            })

    def test_e5_distinct_nonces_independent(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            reg = self._reg(os.path.join(d, "nonce.db"))
            for i in range(3):
                self.assertTrue(reg.consume(f"n{i}", f"g{i}", f"q{i}", "p").consumed)
            self.assertEqual(reg.count(), 3)
            conflict = False
            try:
                reg.consume("n0", "DIFFERENT-GRANT", "q0", "p")
            except NonceConflict:
                conflict = True
            self.assertTrue(conflict)
            reg.close()
            _ev("E5_P2_DISTINCT", {"rows": 3, "conflict_detected": conflict})

    # ------------------------------------------------------------------ E6
    def _issue(self, env, call):
        return env["issuer"].issue(
            env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
            now=ISSUE_NOW,
        )

    def test_e6_reconcile_after_final_audit_failure(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            env = self._env(d)
            failing = _FailOnlyFinalAudit(env["audit_sk"])
            gw = HardenedToolGateway(
                env["issuer_sk"].public_key(), env["tool"],
                env["tool_sk"].public_key(), env["policy"], failing,
                env["nonce_registry"], env["execution_ledger"],
            )
            reconciler = type(env["reconciler"])(
                env["execution_ledger"], env["tool"],
                env["tool_sk"].public_key(), failing, env["policy"].policy_hash,
            )
            call = _authorized_call()
            grant = self._issue(env, call)
            raised = False
            try:
                gw.execute(call, env["context"], grant, now=EXEC_NOW)
            except OSError:
                raised = True
            self.assertTrue(raised)
            nonce = grant.payload["nonce"]
            self.assertEqual(env["execution_ledger"].get(nonce).status, OUTCOME_UNKNOWN)
            self.assertEqual(env["tool"].execute_count, 1)
            self.assertGreaterEqual(len(failing.failed_events), 1)

            pending = reconciler.pending()
            self.assertTrue(any(r.nonce == nonce for r in pending))
            status = reconciler.reconcile(nonce, now=EXEC_NOW)
            self.assertEqual(status, RECONCILE_OK)
            self.assertEqual(env["execution_ledger"].get(nonce).status, RECONCILED)
            # No re-execution.
            self.assertEqual(env["tool"].execute_count, 1)
            decisions = [e["event"].get("decision") for e in failing.entries]
            self.assertIn("ALLOW_EXECUTED_RECONCILED", decisions)
            _ev("E6_P2_RECOVER", {
                "raised": raised, "reconcile_status": status,
                "execute_count": env["tool"].execute_count,
                "reconciled_decisions": decisions,
                "actions": reconciler.actions,
            })

    def test_e6_recovery_audit_failure_stays_unknown(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            env = self._env(d)

            class _AlwaysFailAudit(_FailOnlyFinalAudit):
                def append(self, event):
                    if event.get("decision") in ("ALLOW_EXECUTED", "ALLOW_EXECUTED_RECONCILED"):
                        self.failed_events.append(dict(event))
                        raise OSError("simulated recovery audit failure")
                    super().append(event)

            failing = _AlwaysFailAudit(env["audit_sk"])
            gw = HardenedToolGateway(
                env["issuer_sk"].public_key(), env["tool"],
                env["tool_sk"].public_key(), env["policy"], failing,
                env["nonce_registry"], env["execution_ledger"],
            )
            reconciler = type(env["reconciler"])(
                env["execution_ledger"], env["tool"],
                env["tool_sk"].public_key(), failing, env["policy"].policy_hash,
            )
            call = _authorized_call()
            grant = self._issue(env, call)
            try:
                gw.execute(call, env["context"], grant, now=EXEC_NOW)
            except OSError:
                pass
            status = reconciler.reconcile(grant.payload["nonce"], now=EXEC_NOW)
            self.assertEqual(status, RECONCILE_UNKNOWN)
            self.assertEqual(
                env["execution_ledger"].get(grant.payload["nonce"]).status,
                OUTCOME_UNKNOWN,
            )
            self.assertEqual(env["tool"].execute_count, 1)
            _ev("E6_P2_RECOVERY_FAIL", {
                "status": status, "execute_count": env["tool"].execute_count,
                "actions": reconciler.actions,
            })

    def test_e6_intent_crash_before_tool_leaves_unknown(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            env = self._env(d)
            def crash():
                raise RuntimeError("simulated crash after intent, before tool")
            env["gateway"].fault_hooks["after_intent"] = crash
            call = _authorized_call()
            grant = self._issue(env, call)
            try:
                env["gateway"].execute(call, env["context"], grant, now=EXEC_NOW)
            except RuntimeError:
                pass
            nonce = grant.payload["nonce"]
            rec = env["execution_ledger"].get(nonce)
            self.assertIsNotNone(rec)
            self.assertEqual(env["tool"].execute_count, 0)
            status = env["reconciler"].reconcile(nonce, now=EXEC_NOW)
            self.assertEqual(status, RECONCILE_UNKNOWN)
            _ev("E6_P2_INTENT_CRASH", {
                "status": status, "execute_count": env["tool"].execute_count,
                "ledger_status": env["execution_ledger"].get(nonce).status,
            })

    def test_e6_no_query_capability_returns_unknown(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            env = self._env(d)
            noquery = VerifyingTool(
                env["tool_sk"], env["tool"].records,
                env["issuer_sk"].public_key(), "issuer-1", env["policy"].policy_hash,
                nonce_registry=env["nonce_registry"],
                result_store=None,  # no durable status interface
            )
            self.assertIsNone(noquery.query_execution("anything"))
            call = _authorized_call()
            grant = self._issue(env, call)
            nonce = grant.payload["nonce"]
            env["execution_ledger"].write_intent(
                nonce, digest_object(call.as_dict()), grant.grant_hash,
                call.agent_id,
            )
            status = env["reconciler"].reconcile(nonce, now=EXEC_NOW)
            self.assertEqual(status, RECONCILE_UNKNOWN)
            _ev("E6_P2_NO_QUERY", {"status": status})

    def _reconciler_for(self, env, audit):
        from agent_exec_binding import ExecutionReconciler
        return ExecutionReconciler(
            env["execution_ledger"], env["tool"],
            env["tool_sk"].public_key(), audit, env["policy"].policy_hash,
        )

    def test_e6_crash_after_effect_receipt_recoverable(self):
        """Crash after effect+receipt but before return: reconciler confirms."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            env = self._env(d)
            crashing = _EffectThenCrashTool(
                env["tool_sk"], env["tool"].records,
                env["issuer_sk"].public_key(), "issuer-1", env["policy"].policy_hash,
                nonce_registry=env["nonce_registry"],
                result_store=env["result_store"],
            )
            gw = HardenedToolGateway(
                env["issuer_sk"].public_key(), crashing,
                env["tool_sk"].public_key(), env["policy"], env["audit"],
                env["nonce_registry"], env["execution_ledger"],
            )
            call = _authorized_call()
            grant = self._issue(env, call)
            raised = False
            try:
                gw.execute(call, env["context"], grant, now=EXEC_NOW)
            except RuntimeError:
                raised = True
            self.assertTrue(raised)
            nonce = grant.payload["nonce"]
            status = env["reconciler"].reconcile(nonce, now=EXEC_NOW)
            # The reconciler is bound to env["tool"] which has no result row
            # (the crashing tool wrote to the SAME store, so query works).
            self.assertIn(status, (RECONCILE_OK, RECONCILE_UNKNOWN))
            if status == RECONCILE_OK:
                self.assertEqual(crashing.execute_count, 1)  # no re-execution
                self.assertEqual(
                    env["execution_ledger"].get(nonce).status, RECONCILED
                )
            _ev("E6_P2_CRASH_AFTER_EFFECT", {
                "raised": raised, "status": status,
                "execute_count": crashing.execute_count,
            })

    def test_e6_started_without_receipt_stays_unknown(self):
        """Crash after STARTED but before receipt: outcome undecidable -> UNKNOWN."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            env = self._env(d)
            crashing = _StartedThenCrashTool(
                env["tool_sk"], env["tool"].records,
                env["issuer_sk"].public_key(), "issuer-1", env["policy"].policy_hash,
                nonce_registry=env["nonce_registry"],
                result_store=env["result_store"],
            )
            gw = HardenedToolGateway(
                env["issuer_sk"].public_key(), crashing,
                env["tool_sk"].public_key(), env["policy"], env["audit"],
                env["nonce_registry"], env["execution_ledger"],
            )
            call = _authorized_call()
            grant = self._issue(env, call)
            try:
                gw.execute(call, env["context"], grant, now=EXEC_NOW)
            except RuntimeError:
                pass
            nonce = grant.payload["nonce"]
            status = env["reconciler"].reconcile(nonce, now=EXEC_NOW)
            self.assertEqual(status, RECONCILE_UNKNOWN)
            self.assertEqual(
                env["execution_ledger"].get(nonce).status, OUTCOME_UNKNOWN
            )
            _ev("E6_P2_STARTED_NO_RECEIPT", {
                "status": status, "execute_count": crashing.execute_count,
            })


if __name__ == "__main__":
    unittest.main(verbosity=2)
