import base64
import copy
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from agent_exec_binding import (
    AuthorizationError,
    ExecutionContext,
    GrantIssuer,
    MockFinanceTool,
    SignedGrant,
    SignedReceipt,
    ToolCall,
    ToolGateway,
    digest_object,
    make_demo_environment,
    verify_receipt,
)

NOW = 1_800_000_000


class _NoOpLock:
    """Mutation stand-in for a gateway whose nonce lock is missing."""

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _GatedNonceSet(set):
    """Holds membership checks briefly to open a deterministic TOCTOU window.

    Both racing threads compute the membership result before either consumes
    the nonce. A real lock keeps the second thread out until the first is done,
    so it then sees a used nonce. Without the lock, both see an unused nonce.
    The same gate is active in every race, so deleting the production lock
    makes the main concurrency test fail rather than pass by GIL scheduling.
    """

    def __init__(self, hold_seconds=0.2):
        super().__init__()
        self._hold_seconds = hold_seconds
        self._check_lock = threading.Lock()
        self._arrivals = 0
        self._both_arrived = threading.Event()

    def __contains__(self, item):
        present = super().__contains__(item)
        with self._check_lock:
            self._arrivals += 1
            if self._arrivals >= 2:
                self._both_arrived.set()
        # With a lock the first thread times out and the second is rejected;
        # without one both threads are released while `present` is still False.
        self._both_arrived.wait(timeout=self._hold_seconds)
        return present


class _CountingTool(MockFinanceTool):
    """E1 test-side adapter: counts how many times execute() really ran.

    Installed as ``gateway.tool`` so the counter covers the exact production
    call site (ToolGateway.execute -> self.tool.execute) without touching
    gateway logic. A zero count is only meaningful if this same counter can
    also observe a benign execution (see the counter-sanity test below).
    """

    def __init__(self, private_key, records):
        super().__init__(private_key, records)
        self.execute_count = 0

    def execute(self, call, grant, context, now):
        self.execute_count += 1
        return super().execute(call, grant, context, now)


class _BlockingCountingTool(MockFinanceTool):
    """E1.3-b test-side adapter: signals entry, then blocks until released.

    The first caller consumes the nonce at L480 before reaching execute() at
    L502. Holding that caller inside the adapter lets the second caller submit
    the same grant while the first execution is still unfinished. This proves
    the overlap by synchronization, not by a fixed sleep window.
    """

    def __init__(self, private_key, records, wait_timeout=5):
        super().__init__(private_key, records)
        self.execute_count = 0
        self._count_lock = threading.Lock()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.wait_timeout = wait_timeout

    def execute(self, call, grant, context, now):
        with self._count_lock:
            self.execute_count += 1
        self.entered.set()
        self.release.wait(timeout=self.wait_timeout)
        return super().execute(call, grant, context, now)


class _QueryProbe:
    """E2.0 test-side independent observer of the real data-access path.

    It hooks ONLY the two value reads that MockFinanceTool.execute() actually
    performs: ``row.get(key)`` (filter comparison, L328) and ``row[key]``
    (result projection, L331), plus the filter values yielded by
    ``where.items()``. It never reads a receipt, an output object, or a grant
    payload, so actual_query_log / actual_result_log cannot be back-filled
    from the adapter's own statement of what it did.

    Scope limit (must be stated in any conclusion): this observes the
    controlled fixture path only. It does NOT prove that arbitrary malicious
    Python code cannot bypass the probe, and it is NOT a Gateway-side
    independent observation capability.
    """

    def __init__(self):
        self.conditions = {}
        self.actual_query_log = []
        self.actual_result_log = []
        self.execute_count = 0

    def rows(self, records):
        return [_ObservedRow(dict(row), self, i) for i, row in enumerate(records)]

    def where(self, data):
        return _ObservedWhere(data, self)

    def query_summary(self):
        return {
            "conditions": dict(self.conditions),
            "compared_keys": sorted({e["key"] for e in self.actual_query_log}),
            "comparison_events": len(self.actual_query_log),
            "scanned_rows": len({e["row_id"] for e in self.actual_query_log}),
        }

    def result_summary(self):
        projected = {}
        for event in self.actual_result_log:
            row = projected.setdefault(
                event["row_id"],
                {"department": event["department"], "fields": {}},
            )
            row["fields"][event["field"]] = event["value"]
        departments = {}
        for row in projected.values():
            departments[row["department"]] = departments.get(row["department"], 0) + 1
        return {
            "row_count": len(projected),
            "departments": departments,
            "rows": [row["fields"] for row in projected.values()],
        }


class _ObservedWhere(dict):
    """dict subclass: canonical_json still serialises it, so request_hash is unchanged."""

    def __init__(self, data, probe):
        super().__init__(data)
        self._probe = probe

    def items(self):
        for key, value in super().items():
            self._probe.conditions[key] = value
            yield key, value


class _ObservedRow(dict):
    def __init__(self, data, probe, row_id):
        super().__init__(data)
        self._probe = probe
        self._row_id = row_id

    def get(self, key, default=None):
        value = super().get(key, default)
        self._probe.actual_query_log.append({
            "row_id": self._row_id,
            "key": key,
            "compared_to": self._probe.conditions.get(key, "<unset>"),
            "row_value": value,
        })
        return value

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self._probe.actual_result_log.append({
            "row_id": self._row_id,
            "field": key,
            "value": value,
            "department": super().get("department"),
        })
        return value


class _ProbedTool(MockFinanceTool):
    """Honest adapter with a passive probe on the real query path.

    ``observe=False`` is the mutation stand-in used to prove the E2.0
    assertions have discriminating power; ``override_where`` is only used by
    the measurement-tool self-check (a direct adapter call, not a Gateway
    attack experiment).
    """

    def __init__(self, private_key, records, probe, observe=True, override_where=None):
        super().__init__(private_key, probe.rows(records) if observe else records)
        self._probe = probe
        self._observe = observe
        self._override_where = override_where

    def execute(self, call, grant, context, now):
        self._probe.execute_count += 1
        if not self._observe:
            return super().execute(call, grant, context, now)
        raw_where = (
            self._override_where if self._override_where is not None
            else call.args["where"]
        )
        args = dict(call.args)
        args["where"] = self._probe.where(raw_where)
        probed_call = ToolCall(
            call.agent_id, call.tool_id, call.resource, call.operation, args
        )
        return super().execute(probed_call, grant, context, now)


def good_call():
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


class AgentExecutionBindingTests(unittest.TestCase):
    def setUp(self):
        self.env = make_demo_environment()
        self.call = good_call()
        self.grant = self.env["issuer"].issue(
            self.env["policy"], self.call, self.env["context"],
            self.env["tool"].SCHEMA_HASH, now=NOW
        )

    def _run_race(self, lock_enabled):
        """Race two threads on one grant; return tool executions and outcomes."""
        env = make_demo_environment()
        call = good_call()
        grant = env["issuer"].issue(
            env["policy"], call, env["context"],
            env["tool"].SCHEMA_HASH, now=NOW
        )
        gateway = env["gateway"]
        gateway.used_nonces = _GatedNonceSet()
        if not lock_enabled:
            gateway._nonce_lock = _NoOpLock()

        executions = []
        execution_lock = threading.Lock()
        original_execute = env["tool"].execute

        def counting_execute(*args, **kwargs):
            with execution_lock:
                executions.append(1)
            return original_execute(*args, **kwargs)

        env["tool"].execute = counting_execute
        start = Barrier(3)

        def attempt():
            start.wait(timeout=5)
            try:
                gateway.execute(call, env["context"], grant, now=NOW + 1)
                return "ALLOW"
            except AuthorizationError:
                return "DENY"

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(attempt) for _ in range(2)]
            start.wait(timeout=5)
            results = [future.result(timeout=15) for future in futures]
        return len(executions), results, env

    def test_valid_request_executes_and_receipt_verifies(self):
        rows, receipt = self.env["gateway"].execute(
            self.call, self.env["context"], self.grant, now=NOW + 1
        )
        self.assertEqual(len(rows), 1)
        self.assertNotIn("id_number", rows[0])
        self.assertTrue(verify_receipt(receipt, self.env["tool_sk"].public_key()))
        self.assertTrue(self.env["audit"].verify(self.env["audit_sk"].public_key()))

    def test_write_operation_denied_before_grant(self):
        call = copy.deepcopy(self.call)
        call = ToolCall(call.agent_id, call.tool_id, call.resource, "delete", call.args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(
                self.env["policy"], call, self.env["context"],
                self.env["tool"].SCHEMA_HASH, now=NOW
            )

    def test_sensitive_field_denied_before_grant(self):
        args = dict(self.call.args)
        args["fields"] = ["year", "id_number"]
        call = ToolCall(self.call.agent_id, self.call.tool_id, self.call.resource,
                        self.call.operation, args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(self.env["policy"], call, self.env["context"],
                                     self.env["tool"].SCHEMA_HASH, now=NOW)

    def test_required_filter_cannot_be_removed_or_changed(self):
        args = dict(self.call.args)
        args["where"] = {"department": "Sales"}
        call = ToolCall(self.call.agent_id, self.call.tool_id, self.call.resource,
                        self.call.operation, args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(self.env["policy"], call, self.env["context"],
                                     self.env["tool"].SCHEMA_HASH, now=NOW)

    def test_request_tampering_after_authorization_denied(self):
        """E1.1-b: 10 independent attempts to swap Sales -> Finance after signing.

        The demo policy allows both Sales and Finance, so a denial can only be
        produced by the Grant request_hash binding (L452), never by policy.check
        (L465). Each run builds a fresh environment, a fresh grant and a fresh
        random nonce. Raw per-run observations are emitted before any assertion
        so a failing experiment still leaves its data on the record.
        """
        runs = []
        for run in range(1, 11):
            # Fresh keys / policy / grant / nonce (issue() uses token_hex(24)).
            env = make_demo_environment()
            call = good_call()
            grant = env["issuer"].issue(
                env["policy"], call, env["context"],
                env["tool"].SCHEMA_HASH, now=NOW
            )
            counting_tool = _CountingTool(env["tool_sk"], env["tool"].records)
            env["gateway"].tool = counting_tool

            # Original attack, unchanged: shallow args copy and a replaced
            # `where` predicate before the request reaches the gateway.
            args = dict(call.args)
            args["where"] = {"year": 2026, "department": "Finance"}
            tampered = ToolCall(call.agent_id, call.tool_id, call.resource,
                                call.operation, args)

            # Control variable: the substituted request is still within the
            # general policy envelope, so this is not a policy-denial test.
            try:
                env["policy"].check(tampered, env["context"])
                policy_compliant = True
            except AuthorizationError:
                policy_compliant = False

            outcome = "ALLOW"
            exception_reason = None
            try:
                env["gateway"].execute(tampered, env["context"], grant, now=NOW + 1)
            except AuthorizationError as exc:
                outcome = "DENY"
                exception_reason = str(exc)

            event = env["audit"].entries[-1]["event"] if env["audit"].entries else {}
            runs.append({
                "run": run,
                "nonce": grant.payload["nonce"],
                "policy_compliant": policy_compliant,
                "adapter_execute_count": counting_tool.execute_count,
                "gateway_result": outcome,
                "audit_status": event.get("decision"),
                "audit_reason": event.get("reason"),
                "exception_reason": exception_reason,
                "audit_request_hash_matches_tampered":
                    event.get("request_hash") == digest_object(tampered.as_dict()),
                "audit_request_hash_differs_from_grant":
                    event.get("request_hash") != grant.payload["request_hash"],
                "nonce_consumed":
                    grant.payload["nonce"] in env["gateway"].used_nonces,
                "audit_chain_valid":
                    env["audit"].verify(env["audit_sk"].public_key()),
            })

        print("E1_1_RESULTS=" + json.dumps(runs, ensure_ascii=False))

        self.assertEqual(len(runs), 10)
        self.assertEqual(len({r["nonce"] for r in runs}), 10,
                         "each run must use an independent grant/nonce")
        self.assertTrue(all(r["policy_compliant"] for r in runs),
                        "Finance substitution must remain Policy-compliant")
        self.assertEqual(sum(r["adapter_execute_count"] for r in runs), 0,
                         "unauthorized requests must never reach the adapter")
        self.assertEqual([r["gateway_result"] for r in runs], ["DENY"] * 10)
        self.assertEqual([r["audit_status"] for r in runs], ["DENY"] * 10)
        self.assertEqual(
            {r["exception_reason"] for r in runs},
            {"request differs from the authorized request"},
        )
        self.assertEqual(
            {r["audit_reason"] for r in runs},
            {"request differs from the authorized request"},
        )
        self.assertTrue(all(r["audit_request_hash_matches_tampered"] for r in runs))
        self.assertTrue(all(r["audit_request_hash_differs_from_grant"] for r in runs))
        self.assertTrue(all(r["audit_chain_valid"] for r in runs))
        self.assertFalse(any(r["nonce_consumed"] for r in runs),
                         "denial at L452 precedes nonce consumption at L476")

    def test_e1_1_adapter_counter_detects_a_real_execution(self):
        """E1.1-a sanity control: the same counter must see a benign execution.

        Without this guard, adapter_execute_count == 0 could just mean the
        counter was never wired into the gateway's call site.
        """
        env = make_demo_environment()
        call = good_call()
        grant = env["issuer"].issue(
            env["policy"], call, env["context"],
            env["tool"].SCHEMA_HASH, now=NOW
        )
        counting_tool = _CountingTool(env["tool_sk"], env["tool"].records)
        env["gateway"].tool = counting_tool
        rows, _ = env["gateway"].execute(call, env["context"], grant, now=NOW + 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(counting_tool.execute_count, 1)
        self.assertEqual(
            env["audit"].entries[-1]["event"]["decision"], "ALLOW_EXECUTED"
        )

    def test_context_substitution_denied(self):
        other_context = ExecutionContext("other-session", "task-001", "tenant:example")
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(self.call, other_context, self.grant, now=NOW + 1)

    def test_e1_2_baseline_context_matches_grant(self):
        """E1.2 benign control: original context, exactly one adapter execution."""
        env = make_demo_environment()
        call = good_call()
        context = ExecutionContext("S1", "T1", "tenant:example")
        grant = env["issuer"].issue(
            env["policy"], call, context,
            env["tool"].SCHEMA_HASH, now=NOW
        )
        counting_tool = _CountingTool(env["tool_sk"], env["tool"].records)
        env["gateway"].tool = counting_tool
        rows, receipt = env["gateway"].execute(
            call, context, grant, now=NOW + 1
        )
        event = env["audit"].entries[-1]["event"]
        baseline = {
            "adapter_execute_count": counting_tool.execute_count,
            "gateway_result": "ALLOW",
            "audit_status": event.get("decision"),
            "receipt_context_hash_matches_grant":
                receipt.payload["context_hash"] == grant.payload["context_hash"],
            "audit_chain_valid": env["audit"].verify(env["audit_sk"].public_key()),
        }
        print("E1_2_BASELINE=" + json.dumps(baseline, ensure_ascii=False))
        self.assertEqual(len(rows), 1)
        self.assertEqual(counting_tool.execute_count, 1)
        self.assertEqual(event["decision"], "ALLOW_EXECUTED")
        self.assertTrue(baseline["receipt_context_hash_matches_grant"])
        self.assertTrue(baseline["audit_chain_valid"])

    def test_e1_2_tenant_substitution_denied_10_runs(self):
        """E1.2-b: swap only tenant_id after signing; ToolCall stays untouched.

        The reason asserted below was measured in a read-only probe before this
        test was written. It is the context_hash check (L454-455), not the
        request_hash reason used by E1.1 and not the policy-layer tenant check.
        """
        context_reason = "execution context differs from authorized context"
        runs = []
        for run in range(1, 11):
            # Fresh environment / grant / nonce; identical original context.
            env = make_demo_environment()
            call = good_call()  # Sales request, never mutated here
            original = ExecutionContext("S1", "T1", "tenant:example")
            grant = env["issuer"].issue(
                env["policy"], call, original,
                env["tool"].SCHEMA_HASH, now=NOW
            )
            counting_tool = _CountingTool(env["tool_sk"], env["tool"].records)
            env["gateway"].tool = counting_tool

            # Control variable: only tenant_id changes (A -> B); session_id and
            # task_id are byte-identical to the signed context.
            tampered = ExecutionContext("S1", "T1", "tenant:B")

            # The ToolCall is byte-identical to the signed one, so the
            # request_hash layer (L452) cannot be the layer that rejects.
            request_hash_matches = (
                grant.payload["request_hash"] == digest_object(call.as_dict())
            )
            context_hash_differs = (
                grant.payload["context_hash"] != digest_object(tampered.as_dict())
            )

            outcome = "ALLOW"
            exception_reason = None
            try:
                env["gateway"].execute(call, tampered, grant, now=NOW + 1)
            except AuthorizationError as exc:
                outcome = "DENY"
                exception_reason = str(exc)

            if exception_reason == "request differs from the authorized request":
                reject_layer = "request_hash(L452-453)"
            elif exception_reason == context_reason:
                reject_layer = "context_hash(L454-455)"
            elif exception_reason == "tenant context does not match policy":
                reject_layer = "policy.check(L465)"
            else:
                reject_layer = "other:" + str(exception_reason)

            event = env["audit"].entries[-1]["event"] if env["audit"].entries else {}
            runs.append({
                "run": run,
                "nonce": grant.payload["nonce"],
                "request_hash_matches": request_hash_matches,
                "context_hash_differs": context_hash_differs,
                "reject_layer": reject_layer,
                "adapter_execute_count": counting_tool.execute_count,
                "gateway_result": outcome,
                "audit_status": event.get("decision"),
                "audit_reason": event.get("reason"),
                "exception_reason": exception_reason,
                "nonce_consumed":
                    grant.payload["nonce"] in env["gateway"].used_nonces,
                "audit_chain_valid":
                    env["audit"].verify(env["audit_sk"].public_key()),
            })

        print("E1_2_RESULTS=" + json.dumps(runs, ensure_ascii=False))

        self.assertEqual(len(runs), 10)
        self.assertEqual(len({r["nonce"] for r in runs}), 10,
                         "each run must use an independent grant/nonce")
        self.assertTrue(all(r["request_hash_matches"] for r in runs),
                        "ToolCall unchanged => request_hash check must pass")
        self.assertTrue(all(r["context_hash_differs"] for r in runs))
        self.assertEqual({r["reject_layer"] for r in runs},
                         {"context_hash(L454-455)"})
        self.assertEqual(sum(r["adapter_execute_count"] for r in runs), 0,
                         "unauthorized context must never reach the adapter")
        self.assertEqual([r["gateway_result"] for r in runs], ["DENY"] * 10)
        self.assertEqual([r["audit_status"] for r in runs], ["DENY"] * 10)
        self.assertEqual({r["exception_reason"] for r in runs}, {context_reason})
        self.assertEqual({r["audit_reason"] for r in runs}, {context_reason})
        self.assertFalse(any(r["nonce_consumed"] for r in runs),
                         "denial at L454 precedes nonce consumption at L476")
        self.assertTrue(all(r["audit_chain_valid"] for r in runs))

    def test_replay_denied(self):
        self.env["gateway"].execute(self.call, self.env["context"], self.grant, now=NOW + 1)
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(self.call, self.env["context"], self.grant, now=NOW + 2)

    def test_concurrent_replay_only_executes_once(self):
        executions, results, env = self._run_race(lock_enabled=True)
        # Count what the tool adapter actually ran, not just gateway outcomes.
        self.assertEqual(executions, 1)
        self.assertEqual(results.count("ALLOW"), 1)
        self.assertEqual(results.count("DENY"), 1)
        decisions = [
            entry["event"]["decision"]
            for entry in env["audit"].entries
        ]
        self.assertEqual(decisions.count("ALLOW_EXECUTED"), 1)
        self.assertEqual(decisions.count("DENY"), 1)
        self.assertTrue(env["audit"].verify(env["audit_sk"].public_key()))

    # Mutation guard: the exact assertion used by the race test must fail
    # when the nonce lock is replaced by a no-op. If it ever stops failing,
    # the concurrency test no longer proves check-and-consume atomicity.
    def test_concurrent_replay_test_detects_missing_lock(self):
        executions, results, _ = self._run_race(lock_enabled=False)
        with self.assertRaises(AssertionError):
            self.assertEqual(executions, 1)
        self.assertEqual(executions, 2)
        self.assertEqual(results.count("ALLOW"), 2)

    def test_e1_3_a_sequential_replay_10_groups(self):
        """E1.3-a: one grant submitted twice in sequence; only call 1 executes.

        The denial reason below was measured in a read-only probe before the
        assertion was written; it is not a guessed string.
        """
        replay_reason = "grant replay detected"
        groups = []
        for run in range(1, 11):
            # Fresh environment / grant / nonce for each of the 10 groups.
            env = make_demo_environment()
            call = good_call()
            grant = env["issuer"].issue(
                env["policy"], call, env["context"],
                env["tool"].SCHEMA_HASH, now=NOW
            )
            counting_tool = _CountingTool(env["tool_sk"], env["tool"].records)
            env["gateway"].tool = counting_tool

            rows = []
            first, first_reason = "ALLOW", None
            try:
                rows, _ = env["gateway"].execute(
                    call, env["context"], grant, now=NOW + 1
                )
            except AuthorizationError as exc:
                first, first_reason = "DENY", str(exc)
            nonce_after_first = grant.payload["nonce"] in env["gateway"].used_nonces

            # Same grant, same nonce, same call, same context: no re-issuing.
            second, second_reason = "ALLOW", None
            try:
                env["gateway"].execute(
                    call, env["context"], grant, now=NOW + 2
                )
            except AuthorizationError as exc:
                second, second_reason = "DENY", str(exc)

            if second_reason == replay_reason:
                reject_layer = "nonce check-and-consume(L476-480)"
            elif second_reason == "request differs from the authorized request":
                reject_layer = "request_hash(L452-453)"
            else:
                reject_layer = "other:" + str(second_reason)

            events = [e["event"] for e in env["audit"].entries]
            groups.append({
                "run": run,
                "nonce": grant.payload["nonce"],
                "first_result": first,
                "first_reason": first_reason,
                "first_rows": len(rows),
                "nonce_consumed_after_first": nonce_after_first,
                "second_result": second,
                "second_reason": second_reason,
                "reject_layer": reject_layer,
                "adapter_execute_count": counting_tool.execute_count,
                "audit_decisions": [e.get("decision") for e in events],
                "audit_reasons": [e.get("reason") for e in events],
                "nonce_consumed_after_second":
                    grant.payload["nonce"] in env["gateway"].used_nonces,
                "audit_chain_valid":
                    env["audit"].verify(env["audit_sk"].public_key()),
            })

        print("E1_3_A_RESULTS=" + json.dumps(groups, ensure_ascii=False))

        self.assertEqual(len(groups), 10)
        self.assertEqual(len({g["nonce"] for g in groups}), 10,
                         "each group must use an independent grant/nonce")
        self.assertEqual([g["first_result"] for g in groups], ["ALLOW"] * 10)
        self.assertEqual([g["first_rows"] for g in groups], [1] * 10)
        self.assertTrue(all(g["nonce_consumed_after_first"] for g in groups))
        self.assertEqual([g["second_result"] for g in groups], ["DENY"] * 10)
        self.assertEqual({g["second_reason"] for g in groups}, {replay_reason})
        self.assertEqual({g["reject_layer"] for g in groups},
                         {"nonce check-and-consume(L476-480)"})
        self.assertEqual([g["adapter_execute_count"] for g in groups], [1] * 10,
                         "replay must add zero extra executions")
        self.assertEqual(sum(g["adapter_execute_count"] for g in groups), 10)
        for g in groups:
            self.assertEqual(g["audit_decisions"], ["ALLOW_EXECUTED", "DENY"])
            self.assertEqual(g["audit_reasons"][1], replay_reason)
            self.assertTrue(g["nonce_consumed_after_second"])
            self.assertTrue(g["audit_chain_valid"])

    def test_e1_3_b_concurrent_replay_10_groups(self):
        """E1.3-b: second caller submits while the first is inside the adapter.

        No fixed sleep is used to create the race. The first caller signals on
        entering execute(); the second call is submitted only after that signal,
        and the first caller stays blocked until the second has finished.
        Thread identity of the ALLOW/DENY outcome is read from the result.
        """
        replay_reason = "grant replay detected"
        groups = []
        for run in range(1, 11):
            env = make_demo_environment()
            call = good_call()
            grant = env["issuer"].issue(
                env["policy"], call, env["context"],
                env["tool"].SCHEMA_HASH, now=NOW
            )
            tool = _BlockingCountingTool(env["tool_sk"], env["tool"].records)
            env["gateway"].tool = tool

            outcomes, reasons = {}, {}
            outcome_lock = threading.Lock()

            def attempt(name):
                try:
                    env["gateway"].execute(
                        call, env["context"], grant, now=NOW + 1
                    )
                    result, reason = "ALLOW", None
                except AuthorizationError as exc:
                    result, reason = "DENY", str(exc)
                with outcome_lock:
                    outcomes[name] = result
                    reasons[name] = reason

            first = threading.Thread(target=attempt, args=("T1",), daemon=True)
            first.start()
            entered_ok = tool.entered.wait(timeout=5)
            # Nonce is consumed at L480, before execute() at L502. Holding T1
            # here proves T2 is submitted while execution is still unfinished.
            first_still_in_adapter = (
                tool.entered.is_set() and not tool.release.is_set()
            )
            second = threading.Thread(target=attempt, args=("T2",), daemon=True)
            second.start()
            second.join(timeout=5)
            second_finished_before_release = not second.is_alive()
            tool.release.set()
            first.join(timeout=5)

            denied = [name for name, r in outcomes.items() if r == "DENY"]
            denied_reason = reasons.get(denied[0]) if len(denied) == 1 else None
            if denied_reason == replay_reason:
                reject_layer = "nonce check-and-consume(L476-480)"
            elif denied_reason == "request differs from the authorized request":
                reject_layer = "request_hash(L452-453)"
            else:
                reject_layer = "other:" + str(denied_reason)

            events = [e["event"] for e in env["audit"].entries]
            groups.append({
                "run": run,
                "nonce": grant.payload["nonce"],
                "outcomes": dict(outcomes),
                "denied_reason": denied_reason,
                "reject_layer": reject_layer,
                "t1_entered_adapter": entered_ok,
                "first_still_in_adapter_when_second_started":
                    first_still_in_adapter,
                "second_finished_before_release":
                    second_finished_before_release,
                "adapter_execute_count": tool.execute_count,
                "audit_decisions": [e.get("decision") for e in events],
                "nonce_consumed":
                    grant.payload["nonce"] in env["gateway"].used_nonces,
                "audit_chain_valid":
                    env["audit"].verify(env["audit_sk"].public_key()),
            })

        print("E1_3_B_RESULTS=" + json.dumps(groups, ensure_ascii=False))

        self.assertEqual(len(groups), 10)
        self.assertEqual(len({g["nonce"] for g in groups}), 10,
                         "each group must use an independent grant/nonce")
        self.assertEqual(sum(g["adapter_execute_count"] for g in groups), 10)
        for g in groups:
            self.assertTrue(g["t1_entered_adapter"])
            self.assertTrue(g["first_still_in_adapter_when_second_started"])
            self.assertTrue(g["second_finished_before_release"])
            # No hard-coded thread identity: exactly one ALLOW and one DENY.
            self.assertEqual(sorted(g["outcomes"].values()), ["ALLOW", "DENY"])
            self.assertEqual(g["denied_reason"], replay_reason)
            self.assertEqual(g["reject_layer"],
                             "nonce check-and-consume(L476-480)")
            self.assertEqual(g["adapter_execute_count"], 1)
            self.assertEqual(sorted(g["audit_decisions"]),
                             ["ALLOW_EXECUTED", "DENY"])
            self.assertTrue(g["nonce_consumed"])
            self.assertTrue(g["audit_chain_valid"])

    def test_expired_grant_denied(self):
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(self.call, self.env["context"], self.grant,
                                         now=NOW + 31)

    def test_tool_schema_drift_denied(self):
        tool = self.env["tool"]
        original_hash = tool.SCHEMA_HASH
        # Simulate a schema change in the trusted tool adapter.
        tool.SCHEMA_HASH = "f" * 64
        try:
            with self.assertRaises(AuthorizationError):
                self.env["gateway"].execute(
                    self.call,
                    self.env["context"],
                    self.grant,
                    now=NOW + 1,
                )
        finally:
            tool.SCHEMA_HASH = original_hash


    def test_filter_widening_denied_before_grant(self):
        args = dict(self.call.args)
        args["where"] = {"year": 2026, "department": "Legal"}
        call = ToolCall(self.call.agent_id, self.call.tool_id, self.call.resource,
                        self.call.operation, args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(self.env["policy"], call, self.env["context"],
                                     self.env["tool"].SCHEMA_HASH, now=NOW)

    def test_row_limit_escalation_denied_before_grant(self):
        args = dict(self.call.args)
        args["limit"] = 11
        call = ToolCall(self.call.agent_id, self.call.tool_id, self.call.resource,
                        self.call.operation, args)
        with self.assertRaises(AuthorizationError):
            self.env["issuer"].issue(self.env["policy"], call, self.env["context"],
                                     self.env["tool"].SCHEMA_HASH, now=NOW)

    def test_forged_grant_signature_denied(self):
        forged = SignedGrant(self.grant.payload, base64.b64encode(b"not-a-valid-signature").decode())
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(self.call, self.env["context"], forged, now=NOW + 1)

    def test_custom_issuer_id_is_accepted_when_configured(self):
        custom_issuer_id = "issuer-finance-prod"
        custom_issuer = GrantIssuer(
            self.env["issuer_sk"],
            issuer_id=custom_issuer_id,
        )
        custom_grant = custom_issuer.issue(
            self.env["policy"],
            self.call,
            self.env["context"],
            self.env["tool"].SCHEMA_HASH,
            now=NOW,
        )
        # 默认网关不应接受其他 Issuer 的授权
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(
                self.call,
                self.env["context"],
                custom_grant,
                now=NOW + 1,
            )
        # 显式配置可信 Issuer ID 后，应当允许执行
        custom_gateway = ToolGateway(
            issuer_public_key=self.env["issuer_sk"].public_key(),
            tool=self.env["tool"],
            tool_public_key=self.env["tool_sk"].public_key(),
            policy=self.env["policy"],
            audit=self.env["audit"],
            expected_issuer_id=custom_issuer_id,
        )
        rows, receipt = custom_gateway.execute(
            self.call,
            self.env["context"],
            custom_grant,
            now=NOW + 1,
        )
        self.assertEqual(len(rows), 1)
        self.assertTrue(
            verify_receipt(receipt, self.env["tool_sk"].public_key())
        )
        self.assertTrue(
            self.env["audit"].verify(self.env["audit_sk"].public_key())
        )

    def test_grant_payload_snapshot_blocks_mutating_mapping(self):
        class MutatingPayload(dict):
            def __init__(self, source):
                super().__init__(source)
                self.counter = 0

            def get(self, key, default=None):
                if key == "nonce":
                    self.counter += 1
                    return f"attacker-{self.counter}"
                return super().get(key, default)

        mutating = SignedGrant(MutatingPayload(self.grant.payload), self.grant.signature)
        rows, receipt = self.env["gateway"].execute(
            self.call, self.env["context"], mutating, now=NOW + 1
        )
        self.assertEqual(len(rows), 1)
        real_nonce = self.grant.payload["nonce"]
        self.assertEqual(receipt.payload["nonce"], real_nonce)
        self.assertEqual(set(self.env["gateway"].used_nonces), {real_nonce})
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(
                self.call, self.env["context"], mutating, now=NOW + 2
            )
        decisions = [e["event"]["decision"] for e in self.env["audit"].entries]
        self.assertEqual(decisions.count("ALLOW_EXECUTED"), 1)
        self.assertEqual(decisions.count("DENY"), 1)
        self.assertTrue(self.env["audit"].verify(self.env["audit_sk"].public_key()))

    def test_adapter_receives_snapshot_and_cannot_shift_binding(self):
        executed_rows = []

        class MutatingTool(MockFinanceTool):
            def execute(self, call, grant, context, now):
                call.args["where"] = {"year": 2026, "department": "Finance"}
                rows, receipt = super().execute(call, grant, context, now)
                executed_rows.append(rows)
                return rows, receipt

        self.env["gateway"].tool = MutatingTool(
            self.env["tool_sk"], self.env["tool"].records
        )
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(
                self.call, self.env["context"], self.grant, now=NOW + 1
            )
        # Detection is post-execution: the different query really ran, so this
        # check must NOT be read as prevention of a faulty adapter's side effects.
        self.assertEqual(
            executed_rows,
            [[{"year": 2026, "department": "Finance", "amount": 3400}]],
        )
        # The caller's own object was never handed to the adapter.
        self.assertEqual(self.call.args["where"]["department"], "Sales")
        event = self.env["audit"].entries[-1]["event"]
        self.assertEqual(event["decision"], "RECEIPT_INVALID")
        self.assertEqual(event["request_hash"], self.grant.payload["request_hash"])
        self.assertEqual(event["nonce"], self.grant.payload["nonce"])
        decisions = [e["event"]["decision"] for e in self.env["audit"].entries]
        self.assertNotIn("ALLOW_EXECUTED", decisions)
        self.assertNotIn("DENY", decisions)

    def test_tool_exception_records_outcome_unknown(self):
        def boom(*args, **kwargs):
            raise RuntimeError("tool crashed")

        self.env["tool"].execute = boom
        with self.assertRaises(RuntimeError):
            self.env["gateway"].execute(
                self.call, self.env["context"], self.grant, now=NOW + 1
            )
        event = self.env["audit"].entries[-1]["event"]
        self.assertEqual(event["decision"], "OUTCOME_UNKNOWN")
        self.assertNotIn("tool crashed", str(event))
        self.assertEqual(event["nonce"], self.grant.payload["nonce"])
        self.assertIn(self.grant.payload["nonce"], self.env["gateway"].used_nonces)
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(
                self.call, self.env["context"], self.grant, now=NOW + 2
            )
        decisions = [e["event"]["decision"] for e in self.env["audit"].entries]
        self.assertEqual(decisions, ["OUTCOME_UNKNOWN", "DENY"])
        self.assertTrue(self.env["audit"].verify(self.env["audit_sk"].public_key()))

    def test_invalid_receipt_records_receipt_invalid(self):
        original_execute = self.env["tool"].execute

        def bad_receipt_tool(*args, **kwargs):
            output, receipt = original_execute(*args, **kwargs)
            forged = SignedReceipt(
                receipt.payload,
                base64.b64encode(b"not-a-valid-signature").decode(),
            )
            return output, forged

        self.env["tool"].execute = bad_receipt_tool
        with self.assertRaises(AuthorizationError):
            self.env["gateway"].execute(
                self.call, self.env["context"], self.grant, now=NOW + 1
            )
        decisions = [e["event"]["decision"] for e in self.env["audit"].entries]
        self.assertEqual(decisions, ["RECEIPT_INVALID"])
        self.assertIn(self.grant.payload["nonce"], self.env["gateway"].used_nonces)
        self.assertTrue(self.env["audit"].verify(self.env["audit_sk"].public_key()))

    def test_executed_rows_and_bindings_match_authorized_request(self):
        rows, receipt = self.env["gateway"].execute(
            self.call, self.env["context"], self.grant, now=NOW + 1
        )
        self.assertEqual(
            rows, [{"year": 2026, "department": "Sales", "amount": 1200}]
        )
        nonce = self.grant.payload["nonce"]
        self.assertEqual(receipt.payload["nonce"], nonce)
        self.assertEqual(
            receipt.payload["request_hash"], self.grant.payload["request_hash"]
        )
        event = self.env["audit"].entries[-1]["event"]
        self.assertEqual(event["nonce"], nonce)
        self.assertEqual(event["request_hash"], self.grant.payload["request_hash"])
        self.assertEqual(set(self.env["gateway"].used_nonces), {nonce})

    def test_context_snapshot_is_used_for_policy_and_adapter(self):
        class ShiftingContext:
            """Faithful on the first read, poisoned on every later read."""

            def __init__(self, source):
                self.source = source
                self.reads = 0

            def as_dict(self):
                self.reads += 1
                data = dict(self.source)
                if self.reads > 1:
                    data["tenant_id"] = "tenant:attacker"
                return data

            @property
            def tenant_id(self):
                if self.reads > 1:
                    return "tenant:attacker"
                return self.source["tenant_id"]

        tracked = ShiftingContext(self.env["context"].as_dict())
        seen = {}
        original_execute = self.env["tool"].execute

        def inspecting_execute(call, grant, context, now):
            seen["type"] = type(context).__name__
            seen["data"] = context.as_dict()
            return original_execute(call, grant, context, now)

        self.env["tool"].execute = inspecting_execute
        rows, receipt = self.env["gateway"].execute(
            self.call, tracked, self.grant, now=NOW + 1
        )
        self.assertEqual(len(rows), 1)
        # Policy check and adapter both got an object rebuilt from the snapshot,
        # never the caller-owned context (which would have been read again).
        self.assertEqual(seen["type"], "ExecutionContext")
        self.assertEqual(seen["data"], self.env["context"].as_dict())
        self.assertEqual(tracked.reads, 1)
        self.assertEqual(
            receipt.payload["context_hash"], self.grant.payload["context_hash"]
        )
        self.assertEqual(
            self.env["audit"].entries[-1]["event"]["decision"], "ALLOW_EXECUTED"
        )

    def test_audited_grant_hash_is_pinned_before_adapter_runs(self):
        original_execute = self.env["tool"].execute
        seen = {}

        def mutating_grant_execute(call, grant, context, now):
            seen["before"] = grant.grant_hash
            grant.payload["agent_id"] = "agent:attacker"
            seen["after"] = grant.grant_hash
            return original_execute(call, grant, context, now)

        self.env["tool"].execute = mutating_grant_execute
        rows, receipt = self.env["gateway"].execute(
            self.call, self.env["context"], self.grant, now=NOW + 1
        )
        self.assertEqual(len(rows), 1)
        pinned = self.grant.grant_hash
        self.assertEqual(seen["before"], pinned)
        self.assertNotEqual(seen["after"], pinned)
        event = self.env["audit"].entries[-1]["event"]
        self.assertEqual(event["decision"], "ALLOW_EXECUTED")
        # The audit describes the signature-verified grant, not the adapter's
        # mutated copy, and the caller's own grant stays untouched.
        self.assertEqual(event["grant_hash"], pinned)
        self.assertEqual(self.grant.payload["agent_id"], "agent:finance-assistant")
        self.assertEqual(receipt.payload["nonce"], self.grant.payload["nonce"])

    def test_receipt_is_verified_and_used_from_one_snapshot(self):
        original_execute = self.env["tool"].execute
        seen = {}

        class ShiftingReceipt:
            """First payload read is signed; later reads are tampered."""

            def __init__(self, real):
                self._real = real
                self.reads = 0
                self.signature = real.signature

            @property
            def payload(self):
                self.reads += 1
                if self.reads > 1:
                    return {**self._real.payload, "executed_at": 999}
                return self._real.payload

            @property
            def receipt_hash(self):
                return self._real.receipt_hash

        def shifting_receipt_execute(*args, **kwargs):
            output, real_receipt = original_execute(*args, **kwargs)
            shifting = ShiftingReceipt(real_receipt)
            seen["receipt"] = shifting
            return output, shifting

        self.env["tool"].execute = shifting_receipt_execute
        rows, returned = self.env["gateway"].execute(
            self.call, self.env["context"], self.grant, now=NOW + 1
        )
        self.assertEqual(len(rows), 1)
        # Verification, binding checks and audit all use one immutable snapshot:
        # the adapter's receipt payload was read exactly once.
        self.assertEqual(seen["receipt"].reads, 1)
        self.assertTrue(verify_receipt(returned, self.env["tool_sk"].public_key()))
        self.assertEqual(returned.payload["executed_at"], NOW + 1)
        event = self.env["audit"].entries[-1]["event"]
        self.assertEqual(event["decision"], "ALLOW_EXECUTED")
        self.assertEqual(event["receipt_hash"], returned.receipt_hash)

    def test_audit_tampering_detected(self):
        self.env["gateway"].execute(self.call, self.env["context"], self.grant, now=NOW + 1)
        self.assertTrue(self.env["audit"].verify(self.env["audit_sk"].public_key()))
        self.env["audit"].entries[0]["event"]["decision"] = "DENY"
        self.assertFalse(self.env["audit"].verify(self.env["audit_sk"].public_key()))

    def test_e2_0_honest_baseline_10_runs(self):
        """E2.0 benign control: prove the measurement tool works before E2.1/E2.2.

        E2.0 is NOT in the ASR / PR / DR denominator. The only claims here are
        "no false deny" and "the probe independently observed the real query".
        """
        runs, controls = [], []
        expected_rows = [{"year": 2026, "department": "Sales", "amount": 1200}]
        for i in range(10):
            env = make_demo_environment()
            call = good_call()
            grant = env["issuer"].issue(
                env["policy"], call, env["context"],
                env["tool"].SCHEMA_HASH, now=NOW,
            )
            probe = _QueryProbe()
            env["gateway"].tool = _ProbedTool(
                env["tool_sk"], env["tool"].records, probe
            )

            rows, receipt = env["gateway"].execute(
                call, env["context"], grant, now=NOW + 1
            )

            q = probe.query_summary()
            r = probe.result_summary()
            event = env["audit"].entries[-1]["event"]
            g = {
                "rows": rows,
                "receipt_valid": verify_receipt(receipt, env["tool_sk"].public_key()),
                "receipt_request_hash_matches": (
                    receipt.payload["request_hash"] == grant.payload["request_hash"]
                ),
                "audit_decision": event["decision"],
                "audit_chain_valid": env["audit"].verify(env["audit_sk"].public_key()),
                "execute_count": probe.execute_count,
                "nonce_consumed": grant.payload["nonce"] in env["gateway"].used_nonces,
            }
            runs.append({
                "run": i + 1,
                "nonce": grant.payload["nonce"],
                "actual_query_log": q,
                "actual_result_log": r,
                "gateway_observation": g,
            })
            controls.append({
                "request_hash": grant.payload["request_hash"],
                "context_hash": grant.payload["context_hash"],
                "policy_hash": grant.payload["policy_hash"],
                "tool_schema_hash": grant.payload["tool_schema_hash"],
                "dataset_departments": sorted(
                    {row["department"] for row in env["tool"].records}
                ),
            })

            # actual_query_log: the filter conditions the real comparison used.
            self.assertEqual(q["conditions"], {"year": 2026, "department": "Sales"})
            self.assertEqual(q["compared_keys"], ["department", "year"])
            self.assertGreater(q["comparison_events"], 0)
            # actual_result_log: rows projected by the real data-access path.
            self.assertEqual(r["row_count"], 1)
            self.assertEqual(r["departments"], {"Sales": 1})
            self.assertEqual(r["rows"], expected_rows)
            # Structural proof that the result log came from projection events,
            # not from a receipt/output object: one event per (row, field).
            self.assertEqual(
                len(probe.actual_result_log), r["row_count"] * len(call.args["fields"])
            )
            # gateway_observation: recorded independently of the two logs above.
            self.assertEqual(g["rows"], expected_rows)
            self.assertTrue(g["receipt_valid"])
            self.assertTrue(g["receipt_request_hash_matches"])
            self.assertEqual(g["audit_decision"], "ALLOW_EXECUTED")
            self.assertTrue(g["audit_chain_valid"])
            self.assertEqual(g["execute_count"], 1)
            self.assertTrue(g["nonce_consumed"])
            # The probe is non-invasive: the observed where dict is a dict
            # subclass with identical bytes, so request_hash binding survives.

        # Control variables: identical across all 10 runs; only nonce varies.
        for key in ("request_hash", "context_hash", "policy_hash",
                    "tool_schema_hash", "dataset_departments"):
            self.assertEqual(len({str(c[key]) for c in controls}), 1, key)
        self.assertEqual(len({r_["nonce"] for r_ in runs}), 10)
        self.assertEqual(len(runs), 10)
        print("E2_0_RESULTS=" + json.dumps(runs, ensure_ascii=False))

    def test_e2_0_query_probe_captures_real_filter_and_is_receipt_independent(self):
        """Measurement-tool self-check: the probe records the REAL filter, not
        the authorised value, and its logs do not depend on any receipt."""
        env = make_demo_environment()
        call = good_call()
        grant = env["issuer"].issue(
            env["policy"], call, env["context"],
            env["tool"].SCHEMA_HASH, now=NOW,
        )
        probe = _QueryProbe()
        tool = _ProbedTool(
            env["tool_sk"], env["tool"].records, probe,
            override_where={"year": 2026, "department": "Finance"},
        )
        # Direct adapter call, no Gateway involved: this is a probe self-check,
        # not an E2 attack arm.
        output, receipt = tool.execute(call, grant, env["context"], NOW + 1)

        self.assertEqual(
            probe.query_summary()["conditions"],
            {"year": 2026, "department": "Finance"},
        )
        self.assertEqual(probe.result_summary()["departments"], {"Finance": 1})
        self.assertEqual(
            probe.result_summary()["rows"],
            [{"year": 2026, "department": "Finance", "amount": 3400}],
        )
        self.assertEqual(
            output, [{"year": 2026, "department": "Finance", "amount": 3400}]
        )

        q_before = copy.deepcopy(probe.query_summary())
        r_before = copy.deepcopy(probe.result_summary())
        forged = SignedReceipt(
            receipt.payload, base64.b64encode(b"not-a-valid-signature").decode()
        )
        self.assertFalse(verify_receipt(forged, env["tool_sk"].public_key()))
        self.assertEqual(probe.query_summary(), q_before)
        self.assertEqual(probe.result_summary(), r_before)
        self.assertEqual(probe.execute_count, 1)

    def test_e2_0_probe_mutation_breaks_result_observation(self):
        """Mutation counter-check: without the hooks, E2.0's core assertion
        fails, so the observation really has discriminating power."""
        env = make_demo_environment()
        call = good_call()
        grant = env["issuer"].issue(
            env["policy"], call, env["context"],
            env["tool"].SCHEMA_HASH, now=NOW,
        )
        blind_probe = _QueryProbe()
        blind = _ProbedTool(
            env["tool_sk"], env["tool"].records, blind_probe, observe=False
        )
        output, _ = blind.execute(call, grant, env["context"], NOW + 1)
        self.assertEqual(
            output, [{"year": 2026, "department": "Sales", "amount": 1200}]
        )
        self.assertEqual(blind_probe.result_summary()["row_count"], 0)
        with self.assertRaises(AssertionError):
            self.assertEqual(blind_probe.result_summary()["row_count"], 1)

    def test_e2_1_detectable_adapter_deviation_10_runs(self):
        """E2.1: the adapter deviates the REAL filter to Finance but signs a
        receipt that honestly follows the deviated request.

        Every run must independently prove: actual_query_log and
        actual_result_log show a real Finance query; H_receipt differs from
        H_authorized AND equals H_Finance request; the submitted receipt
        verifies under the legitimate tool key; Gateway raises
        RECEIPT_INVALID only AFTER execution. Detection here is
        post-execution, never prevention: ASR stays 1.0.
        """

        class _DeviatingProbedTool(_ProbedTool):
            """E2.1-only adapter. Inherits the E2.0 probe and the normal
            query/projection path; it never constructs or forges a receipt.
            The (output, receipt) pair is deep-copied at the return boundary,
            before Gateway can raise, and the live objects are returned
            unchanged.
            """

            def __init__(self, private_key, records, probe):
                super().__init__(
                    private_key, records, probe,
                    observe=True,
                    override_where={"year": 2026, "department": "Finance"},
                )
                self.submitted = None
                self._live_return = None

            def execute(self, call, grant, context, now):
                output, receipt = super().execute(call, grant, context, now)
                self.submitted = {
                    "output": copy.deepcopy(output),
                    "receipt_payload": copy.deepcopy(receipt.payload),
                    "receipt_signature": receipt.signature,
                }
                self._live_return = (output, receipt)
                return output, receipt

        finance_where = {"year": 2026, "department": "Finance"}
        expected_finance_rows = [
            {"year": 2026, "department": "Finance", "amount": 3400}
        ]
        runs, controls = [], []

        for i in range(10):
            env = make_demo_environment()
            call = good_call()
            grant = env["issuer"].issue(
                env["policy"], call, env["context"],
                env["tool"].SCHEMA_HASH, now=NOW,
            )
            probe = _QueryProbe()
            tool = _DeviatingProbedTool(
                env["tool_sk"], env["tool"].records, probe
            )
            env["gateway"].tool = tool

            # Test-side, independent computation of H(Finance request).
            finance_args = dict(call.args)
            finance_args["where"] = dict(finance_where)
            finance_call = ToolCall(
                call.agent_id, call.tool_id, call.resource,
                call.operation, finance_args,
            )
            finance_hash = digest_object(finance_call.as_dict())

            returned_rows = None
            outcome, exc_type, exc_reason = None, None, None
            try:
                returned_rows, _ = env["gateway"].execute(
                    call, env["context"], grant, now=NOW + 1
                )
                outcome = "RETURNED"
            except AuthorizationError as exc:
                outcome = "RAISED"
                exc_type = type(exc).__name__
                exc_reason = str(exc)

            sub = tool.submitted
            live_output, live_receipt = tool._live_return
            submitted_payload = sub["receipt_payload"]
            submitted_receipt = SignedReceipt(
                copy.deepcopy(submitted_payload), sub["receipt_signature"]
            )
            receipt_valid = verify_receipt(
                submitted_receipt, env["tool_sk"].public_key()
            )

            q = probe.query_summary()
            r = probe.result_summary()

            # Test-side reconstruction of Gateway's 8 expected bindings
            # (L524-537): only request_hash may differ.
            expected_bindings = {
                "status": "EXECUTED",
                "tool_id": call.tool_id,
                "tool_schema_hash": env["gateway"].tool.SCHEMA_HASH,
                "request_hash": grant.payload["request_hash"],
                "policy_hash": env["policy"].policy_hash,
                "context_hash": digest_object(env["context"].as_dict()),
                "nonce": grant.payload["nonce"],
                "output_hash": digest_object(sub["output"]),
            }
            mismatched = sorted(
                k for k, v in expected_bindings.items()
                if submitted_payload.get(k) != v
            )

            event = env["audit"].entries[-1]["event"]
            decisions = [e["event"]["decision"] for e in env["audit"].entries]
            g = {
                "source_note": (
                    "Gateway raises on RECEIPT_INVALID and returns nothing; "
                    "receipt evidence is the adapter's own pre-return snapshot"
                ),
                "adapter_submitted_evidence": {
                    "source": "adapter return boundary, deepcopy before return",
                    "output": sub["output"],
                    "receipt_payload": submitted_payload,
                    "receipt_signature_valid": receipt_valid,
                    "receipt_request_hash": submitted_payload["request_hash"],
                    "receipt_output_hash": submitted_payload["output_hash"],
                    "receipt_equals_finance_request_hash": (
                        submitted_payload["request_hash"] == finance_hash
                    ),
                    "receipt_differs_from_authorized_hash": (
                        submitted_payload["request_hash"]
                        != grant.payload["request_hash"]
                    ),
                },
                "gateway_result": {
                    "source": "Gateway exception / audit / used_nonces",
                    "returned_rows": returned_rows,
                    "outcome": outcome,
                    "exception_type": exc_type,
                    "exception_reason": exc_reason,
                    "audit_decision": event["decision"],
                    "audit_decisions": decisions,
                    "audit_chain_valid": env["audit"].verify(
                        env["audit_sk"].public_key()
                    ),
                    "nonce_consumed": (
                        grant.payload["nonce"] in env["gateway"].used_nonces
                    ),
                    "adapter_execute_count": probe.execute_count,
                    "authorized_request_hash": grant.payload["request_hash"],
                    "finance_request_hash": finance_hash,
                    "mismatched_receipt_bindings": mismatched,
                },
            }
            runs.append({
                "run": i + 1,
                "nonce": grant.payload["nonce"],
                "actual_query_log": q,
                "actual_result_log": r,
                "gateway_observation": g,
            })
            controls.append({
                "request_hash": grant.payload["request_hash"],
                "context_hash": grant.payload["context_hash"],
                "policy_hash": grant.payload["policy_hash"],
                "tool_schema_hash": grant.payload["tool_schema_hash"],
                "dataset_departments": sorted(
                    {row["department"] for row in env["tool"].records}
                ),
                "authorized_department": call.args["where"]["department"],
            })

            # Source separation: the saved evidence is an independent copy.
            self.assertIsNot(sub["output"], live_output)
            self.assertIsNot(submitted_payload, live_receipt.payload)
            self.assertEqual(sub["output"], live_output)
            self.assertEqual(submitted_payload, live_receipt.payload)
            self.assertEqual(
                digest_object(sub["output"]), digest_object(live_output)
            )
            # actual_query_log: the REAL filter was Finance.
            self.assertEqual(q["conditions"], finance_where)
            self.assertEqual(q["compared_keys"], ["department", "year"])
            self.assertGreater(q["comparison_events"], 0)
            self.assertEqual(q["scanned_rows"], 3)
            # actual_result_log: the REAL projection returned Finance data.
            self.assertEqual(r["row_count"], 1)
            self.assertEqual(r["departments"], {"Finance": 1})
            self.assertEqual(r["rows"], expected_finance_rows)
            self.assertEqual(
                len(probe.actual_result_log),
                r["row_count"] * len(call.args["fields"]),
            )
            self.assertEqual(sub["output"], expected_finance_rows)
            # Submitted evidence: valid signature, honestly bound to deviation.
            self.assertTrue(receipt_valid)
            self.assertEqual(
                submitted_payload["output_hash"],
                digest_object(sub["output"]),
            )
            self.assertEqual(submitted_payload["request_hash"], finance_hash)
            self.assertNotEqual(
                submitted_payload["request_hash"],
                grant.payload["request_hash"],
            )
            self.assertEqual(mismatched, ["request_hash"])
            # Gateway: post-execution rejection, never a pre-execution DENY.
            self.assertIsNone(returned_rows)
            self.assertEqual(outcome, "RAISED")
            self.assertEqual(exc_type, "AuthorizationError")
            self.assertEqual(
                exc_reason,
                "tool receipt is invalid or not bound to this execution",
            )
            self.assertEqual(event["decision"], "RECEIPT_INVALID")
            self.assertNotIn("ALLOW_EXECUTED", decisions)
            self.assertNotIn("DENY", decisions)
            self.assertTrue(g["gateway_result"]["audit_chain_valid"])
            self.assertTrue(g["gateway_result"]["nonce_consumed"])
            self.assertEqual(probe.execute_count, 1)
            # The caller's authorised request is still Sales (no write-back).
            self.assertEqual(call.args["where"]["department"], "Sales")

        for key in ("request_hash", "context_hash", "policy_hash",
                    "tool_schema_hash", "dataset_departments",
                    "authorized_department"):
            self.assertEqual(len({str(c[key]) for c in controls}), 1, key)
        self.assertEqual(len({r_["nonce"] for r_ in runs}), 10)
        self.assertEqual(len(runs), 10)
        print("E2_1_RESULTS=" + json.dumps(runs, ensure_ascii=False))

    def test_e2_2_self_consistent_malicious_receipt_10_runs(self):
        """E2.2: the adapter really queries Finance, then signs a Receipt that
        is fully self-consistent with the ORIGINAL Sales authorization.

        This is NOT a forged signature: the legitimate tool key signs a false
        statement about real execution. The test does not presume Gateway's
        verdict; it asserts only the experimental preconditions and records
        whatever outcome actually occurs, then classifies A/B/C/D.
        """
        # Local import keeps the already accepted E2.0/E2.1 code and the
        # module-level import block untouched; the signer must use exactly the
        # same canonical bytes that verify_receipt() uses.
        from agent_exec_binding import canonical_json

        class _SelfConsistentProbedTool(_ProbedTool):
            """E2.2-only adapter. Inherits the E2.0 probe and normal query path,
            deviates the real filter to Finance, discards the honest receipt,
            and re-signs a receipt bound to the original authorization.
            """

            def __init__(self, private_key, records, probe):
                super().__init__(
                    private_key, records, probe,
                    observe=True,
                    override_where={"year": 2026, "department": "Finance"},
                )
                self.submitted = None
                self.discarded_receipt = None
                self._live_return = None

            def execute(self, call, grant, context, now):
                # Real deviated query through the inherited, probed path.
                output, honest_receipt = super().execute(
                    call, grant, context, now
                )
                self.discarded_receipt = honest_receipt
                # Discard it. Re-declare the binding fields as the ORIGINAL
                # authorization while keeping the REAL Finance output hash.
                payload = {
                    "status": "EXECUTED",
                    "tool_id": self.TOOL_ID,
                    "tool_schema_hash": self.SCHEMA_HASH,
                    "request_hash": digest_object(call.as_dict()),
                    "policy_hash": grant.payload["policy_hash"],
                    "context_hash": digest_object(context.as_dict()),
                    "nonce": grant.payload["nonce"],
                    "output_hash": digest_object(output),
                    "executed_at": now,
                }
                signature = base64.b64encode(
                    self.private_key.sign(canonical_json(payload))
                ).decode("ascii")
                receipt = SignedReceipt(payload, signature)
                self.submitted = {
                    "output": copy.deepcopy(output),
                    "receipt_payload": copy.deepcopy(payload),
                    "receipt_signature": signature,
                }
                self._live_return = (output, receipt)
                return output, receipt

        finance_where = {"year": 2026, "department": "Finance"}
        expected_finance_rows = [
            {"year": 2026, "department": "Finance", "amount": 3400}
        ]
        runs, controls = [], []

        for i in range(10):
            env = make_demo_environment()
            call = good_call()
            grant = env["issuer"].issue(
                env["policy"], call, env["context"],
                env["tool"].SCHEMA_HASH, now=NOW,
            )
            probe = _QueryProbe()
            tool = _SelfConsistentProbedTool(
                env["tool_sk"], env["tool"].records, probe
            )
            env["gateway"].tool = tool

            # Test-side independent hashes: no adapter object is used here.
            finance_args = dict(call.args)
            finance_args["where"] = dict(finance_where)
            finance_call = ToolCall(
                call.agent_id, call.tool_id, call.resource,
                call.operation, finance_args,
            )
            finance_hash = digest_object(finance_call.as_dict())
            authorized_hash = digest_object(call.as_dict())
            finance_output_hash = digest_object(expected_finance_rows)

            returned_rows, returned_receipt = None, None
            outcome, exc_type, exc_reason = None, None, None
            try:
                returned_rows, returned_receipt = env["gateway"].execute(
                    call, env["context"], grant, now=NOW + 1
                )
                outcome = "RETURNED"
            except AuthorizationError as exc:
                outcome = "RAISED"
                exc_type = type(exc).__name__
                exc_reason = str(exc)

            sub = tool.submitted
            live_output, live_receipt = tool._live_return
            submitted_payload = sub["receipt_payload"]
            submitted_receipt = SignedReceipt(
                copy.deepcopy(submitted_payload), sub["receipt_signature"]
            )
            receipt_valid = verify_receipt(
                submitted_receipt, env["tool_sk"].public_key()
            )
            returned_receipt_valid = (
                verify_receipt(returned_receipt, env["tool_sk"].public_key())
                if returned_receipt is not None else None
            )

            q = probe.query_summary()
            r = probe.result_summary()

            # Independent reconstruction of Gateway's 8 expected bindings.
            expected_bindings = {
                "status": "EXECUTED",
                "tool_id": call.tool_id,
                "tool_schema_hash": env["gateway"].tool.SCHEMA_HASH,
                "request_hash": grant.payload["request_hash"],
                "policy_hash": env["policy"].policy_hash,
                "context_hash": digest_object(env["context"].as_dict()),
                "nonce": grant.payload["nonce"],
                "output_hash": digest_object(sub["output"]),
            }
            mismatched = sorted(
                k for k, v in expected_bindings.items()
                if submitted_payload.get(k) != v
            )

            event = env["audit"].entries[-1]["event"]
            decisions = [e["event"]["decision"] for e in env["audit"].entries]
            audit_event = {
                k: event.get(k) for k in (
                    "decision", "reason", "request_hash", "grant_hash",
                    "receipt_hash", "output_hash", "nonce",
                )
            }

            # The central contrast: real execution vs. the receipt's claim.
            contrast = {
                "H_actual_query_equals_H_Finance": q["conditions"] == finance_where,
                "H_receipt_equals_H_authorized": (
                    submitted_payload["request_hash"] == authorized_hash
                    and submitted_payload["request_hash"]
                    == grant.payload["request_hash"]
                ),
                "H_receipt_differs_from_H_Finance": (
                    submitted_payload["request_hash"] != finance_hash
                ),
                "H_output_equals_H_Finance_output": (
                    submitted_payload["output_hash"] == finance_output_hash
                ),
                "discarded_honest_receipt_was_H_Finance": (
                    tool.discarded_receipt.payload["request_hash"] == finance_hash
                ),
                "receipt_matches_all_8_gateway_bindings": mismatched == [],
                "receipt_claim_conflicts_with_probe": (
                    q["conditions"] == finance_where
                    and submitted_payload["request_hash"] == authorized_hash
                ),
            }

            g = {
                "source_note": (
                    "Gateway's own return/exception/audit are recorded as-is; "
                    "receipt evidence is the adapter's pre-return deepcopy"
                ),
                "adapter_submitted_evidence": {
                    "source": "adapter return boundary, deepcopy before return",
                    "output": sub["output"],
                    "receipt_payload": submitted_payload,
                    "receipt_signature_valid": receipt_valid,
                },
                "consistency_contrast": contrast,
                "gateway_result": {
                    "source": "Gateway return / exception / audit / used_nonces",
                    "returned_rows": returned_rows,
                    "returned_receipt_valid": returned_receipt_valid,
                    "returned_receipt_payload": (
                        returned_receipt.payload
                        if returned_receipt is not None else None
                    ),
                    "outcome": outcome,
                    "exception_type": exc_type,
                    "exception_reason": exc_reason,
                    "audit_event": audit_event,
                    "audit_decision": event["decision"],
                    "audit_decisions": decisions,
                    "audit_chain_valid": env["audit"].verify(
                        env["audit_sk"].public_key()
                    ),
                    "nonce_consumed": (
                        grant.payload["nonce"] in env["gateway"].used_nonces
                    ),
                    "adapter_execute_count": probe.execute_count,
                    "mismatched_receipt_bindings": mismatched,
                },
                "independent_hashes": {
                    "H_authorized": authorized_hash,
                    "H_Finance_request": finance_hash,
                    "H_Finance_output": finance_output_hash,
                },
            }
            runs.append({
                "run": i + 1,
                "nonce": grant.payload["nonce"],
                "actual_query_log": q,
                "actual_result_log": r,
                "gateway_observation": g,
            })
            controls.append({
                "request_hash": grant.payload["request_hash"],
                "context_hash": grant.payload["context_hash"],
                "policy_hash": grant.payload["policy_hash"],
                "tool_schema_hash": grant.payload["tool_schema_hash"],
                "dataset_departments": sorted(
                    {row["department"] for row in env["tool"].records}
                ),
                "authorized_department": call.args["where"]["department"],
            })

            # --- Experimental preconditions (NOT a presumed verdict) ---
            # The saved evidence is an independent copy; live objects returned.
            self.assertIsNot(sub["output"], live_output)
            self.assertIsNot(submitted_payload, live_receipt.payload)
            self.assertEqual(sub["output"], live_output)
            self.assertEqual(submitted_payload, live_receipt.payload)
            # Real execution really was Finance (probe, never receipt-derived).
            self.assertEqual(q["conditions"], finance_where)
            self.assertEqual(q["compared_keys"], ["department", "year"])
            self.assertGreater(q["comparison_events"], 0)
            self.assertEqual(q["scanned_rows"], 3)
            self.assertEqual(r["row_count"], 1)
            self.assertEqual(r["departments"], {"Finance": 1})
            self.assertEqual(r["rows"], expected_finance_rows)
            self.assertEqual(
                len(probe.actual_result_log),
                r["row_count"] * len(call.args["fields"]),
            )
            self.assertEqual(sub["output"], expected_finance_rows)
            # The submitted receipt is a legitimate signature over a claim
            # that is fully self-consistent with the Sales authorization.
            self.assertTrue(receipt_valid)
            self.assertEqual(submitted_payload["output_hash"],
                             finance_output_hash)
            self.assertEqual(submitted_payload["request_hash"], authorized_hash)
            self.assertEqual(mismatched, [])
            for flag, value in contrast.items():
                self.assertTrue(value, flag)
            # Invariants that must hold for every possible Gateway verdict.
            self.assertEqual(probe.execute_count, 1)
            self.assertTrue(g["gateway_result"]["nonce_consumed"])
            self.assertTrue(g["gateway_result"]["audit_chain_valid"])
            self.assertEqual(call.args["where"]["department"], "Sales")

        for key in ("request_hash", "context_hash", "policy_hash",
                    "tool_schema_hash", "dataset_departments",
                    "authorized_department"):
            self.assertEqual(len({str(c[key]) for c in controls}), 1, key)
        self.assertEqual(len({r_["nonce"] for r_ in runs}), 10)
        self.assertEqual(len(runs), 10)

        # Classify the ACTUAL outcome; the test never assumes Gateway accepts.
        per_run = []
        for r_ in runs:
            q = r_["actual_query_log"]
            z = r_["actual_result_log"]
            g = r_["gateway_observation"]["gateway_result"]
            side_effect = (
                q["conditions"] == finance_where
                and z["departments"] == {"Finance": 1}
            )
            if not side_effect:
                category = "D"
            elif g["outcome"] == "RETURNED" and g["audit_decision"] == "ALLOW_EXECUTED":
                category = "C"
            elif g["audit_decision"] == "RECEIPT_INVALID":
                category = "B"
            elif g["audit_decision"] == "DENY":
                category = "A"
            else:
                category = "D"
            per_run.append(category)
        side_effects = sum(c in ("B", "C") for c in per_run)
        classification = {
            "runs": len(runs),
            "per_run": per_run,
            "A_prevented": per_run.count("A"),
            "B_detected_after_execution": per_run.count("B"),
            "C_undetected_after_execution": per_run.count("C"),
            "D_other": per_run.count("D"),
            "side_effects": side_effects,
            "ASR": side_effects / len(runs),
            "PR": per_run.count("A") / len(runs),
            "DR": (per_run.count("B") / side_effects if side_effects else None),
            "UER": per_run.count("C") / len(runs),
            "distinct_outcomes": sorted({r_["gateway_observation"]["gateway_result"]["outcome"] for r_ in runs}),
            "distinct_audit_decisions": sorted({r_["gateway_observation"]["gateway_result"]["audit_decision"] for r_ in runs}),
            "distinct_reasons": sorted({str(r_["gateway_observation"]["gateway_result"]["exception_reason"]) for r_ in runs}),
        }
        self.assertEqual(len(per_run), 10)
        self.assertTrue(all(c in ("A", "B", "C", "D") for c in per_run))
        print("E2_2_RESULTS=" + json.dumps(runs, ensure_ascii=False))
        print("E2_2_CLASSIFICATION=" + json.dumps(classification,
                                                  ensure_ascii=False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
