"""R2.8-P0/P1 — Agent execution boundary audit (tests only, no production changes).

Six independent boundary experiments against the frozen main @ f304857:

  E1  direct Adapter call bypassing ToolGateway            -> CONDITIONAL_BYPASS_REPRODUCED
  E2  audit-chain tail truncation                          -> TAIL_TRUNCATION_REPRODUCED
  E3  audit-chain middle-event deletion                    -> MIDDLE_DELETION_DETECTED
  E4  tool side effect then exception (OUTCOME_UNKNOWN)     -> UNKNOWN_OUTCOME_HANDLING_VERIFIED
  E5  grant replay after Gateway restart (new nonce state)  -> REPLAY_AFTER_RESTART_REPRODUCED
  E6  effect completed but final ALLOW_EXECUTED audit fails -> EFFECT_WITHOUT_FINAL_AUDIT_REPRODUCED

A passing test means the PREDICTED OBSERVATION was reproduced/verified. For E1/E2/E5/E6
defect reproduction is an experiment PASS, NOT a system-security PASS. For E3/E4 the
protection behaving as expected IS the security behaviour PASS. No business file is
modified; all helper adapters are test-local subclasses.
"""
import json
import unittest

from agent_exec_binding import (
    AuthorizationError,
    AuditChain,
    ExecutionContext,
    GrantIssuer,
    MockFinanceTool,
    SignedGrant,
    ToolCall,
    ToolGateway,
    digest_object,
    make_demo_environment,
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


class _EffectThenRaiseTool(MockFinanceTool):
    """E4: simulate an external effect, then raise during execution."""

    def __init__(self, private_key, records, effects):
        super().__init__(private_key, records)
        self.effects = effects

    def execute(self, call, grant, context, now):
        self.effects.append({"event": "external_effect", "nonce": grant.payload["nonce"]})
        raise RuntimeError("simulated tool failure AFTER external effect")


class _CountingTool(MockFinanceTool):
    """E6: count real adapter executions (effect proxy) then delegate."""

    def __init__(self, private_key, records, effects):
        super().__init__(private_key, records)
        self.effects = effects

    def execute(self, call, grant, context, now):
        self.effects.append({"event": "adapter_executed", "nonce": grant.payload["nonce"]})
        return super().execute(call, grant, context, now)


class _FailFinalAudit(AuditChain):
    """E6: persist every event except the terminal ALLOW_EXECUTED record."""

    def __init__(self, signing_key):
        super().__init__(signing_key)
        self.failed_events = []

    def append(self, event):
        if event.get("decision") == "ALLOW_EXECUTED":
            self.failed_events.append(dict(event))
            raise OSError("simulated persistence failure on ALLOW_EXECUTED")
        super().append(event)


class R2_8_BoundaryAudit(unittest.TestCase):

    # ---- E1 -------------------------------------------------------------
    def test_e1_direct_adapter_bypass(self):
        env = make_demo_environment()
        tool = env["tool"]
        context = env["context"]

        # A request that asks for a field forbidden by policy (id_number),
        # sent DIRECTLY to the adapter with a forged grant, no Gateway.
        forged_payload = {
            "policy_hash": "FORGED-POLICY-HASH",
            "nonce": "forged-nonce-e1",
        }
        forged_grant = SignedGrant(forged_payload, "forged-signature")
        hostile_call = ToolCall(
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
        out, receipt = tool.execute(hostile_call, forged_grant, context, EXEC_NOW)
        leaked = any("id_number" in row for row in out)
        receipt_signature_valid = verify_receipt(receipt, env["tool_sk"].public_key())
        receipt_carries_forged_policy = receipt.payload.get("policy_hash") == "FORGED-POLICY-HASH"

        result = "CONDITIONAL_BYPASS_REPRODUCED" if (leaked and receipt_signature_valid) else "NOT_REPRODUCED"
        _ev("E1_EVIDENCE", {
            "gateway_invoked": False,
            "grant_signature_verified_by_adapter": False,
            "sensitive_field_returned": leaked,
            "rows": out,
            "receipt_signature_valid": receipt_signature_valid,
            "receipt_carries_forged_policy_hash": receipt_carries_forged_policy,
            "condition": "caller has a direct reference to the Adapter object",
            "result": result,
        })
        self.assertTrue(leaked, "direct adapter call must return the forbidden field")
        self.assertTrue(receipt_signature_valid, "adapter-signed receipt verifies under tool key")
        self.assertEqual(result, "CONDITIONAL_BYPASS_REPRODUCED")

    # ---- E2 -------------------------------------------------------------
    def test_e2_audit_tail_truncation(self):
        env = make_demo_environment()
        audit = AuditChain(env["audit_sk"])
        pub = env["audit_sk"].public_key()
        for i in range(3):
            audit.append({"decision": "ALLOW_EXECUTED", "seq_tag": i})
        original_count = len(audit.entries)
        original_verify = audit.verify(pub)

        audit.entries.pop()
        drop1_verify = audit.verify(pub)
        drop1_count = len(audit.entries)
        audit.entries.pop()
        drop2_verify = audit.verify(pub)
        drop2_count = len(audit.entries)

        reproduced = original_verify and drop1_verify and drop2_verify
        result = "TAIL_TRUNCATION_REPRODUCED" if reproduced else "NOT_REPRODUCED"
        _ev("E2_EVIDENCE", {
            "original_count": original_count,
            "original_verify": original_verify,
            "drop_last_1": {"count": drop1_count, "verify": drop1_verify},
            "drop_last_2": {"count": drop2_count, "verify": drop2_verify},
            "result": result,
        })
        self.assertTrue(original_verify)
        self.assertTrue(drop1_verify, "removing last entry must still verify")
        self.assertTrue(drop2_verify, "removing last two entries must still verify")
        self.assertEqual(result, "TAIL_TRUNCATION_REPRODUCED")

    # ---- E3 -------------------------------------------------------------
    def test_e3_audit_middle_deletion(self):
        env = make_demo_environment()
        audit = AuditChain(env["audit_sk"])
        pub = env["audit_sk"].public_key()
        for i in range(3):
            audit.append({"decision": "ALLOW_EXECUTED", "seq_tag": i})
        original_verify = audit.verify(pub)
        original_seq = [e["seq"] for e in audit.entries]

        removed = audit.entries.pop(1)  # delete the middle record
        after_verify = audit.verify(pub)
        remaining_seq = [e["seq"] for e in audit.entries]

        detected = original_verify and (not after_verify)
        result = "MIDDLE_DELETION_DETECTED" if detected else "NOT_DETECTED"
        _ev("E3_EVIDENCE", {
            "original_count": 3,
            "original_seq": original_seq,
            "original_verify": original_verify,
            "removed_seq": removed["seq"],
            "remaining_seq": remaining_seq,
            "after_verify": after_verify,
            "result": result,
        })
        self.assertTrue(original_verify)
        self.assertFalse(after_verify, "middle deletion must break seq continuity")
        self.assertEqual(result, "MIDDLE_DELETION_DETECTED")

    # ---- E4 -------------------------------------------------------------
    def test_e4_effect_then_exception(self):
        env = make_demo_environment()
        effects = []
        tool = _EffectThenRaiseTool(env["tool_sk"], env["tool"].records, effects)
        gateway = ToolGateway(
            env["issuer_sk"].public_key(), tool, env["tool_sk"].public_key(),
            env["policy"], env["audit"],
        )
        call = _authorized_call()
        grant = env["issuer"].issue(
            env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
            now=ISSUE_NOW,
        )
        nonce = grant.payload["nonce"]

        raised = False
        try:
            gateway.execute(call, env["context"], grant, now=EXEC_NOW)
        except RuntimeError:
            raised = True

        decisions = [e["event"].get("decision") for e in env["audit"].entries]
        outcome_unknown = "OUTCOME_UNKNOWN" in decisions
        recorded_as_deny = "DENY" in decisions
        nonce_consumed = nonce in gateway.used_nonces

        # Try to reuse the same grant after the unknown outcome.
        replay_result = None
        try:
            gateway.execute(call, env["context"], grant, now=EXEC_NOW)
            replay_result = "ALLOW"
        except AuthorizationError as exc:
            replay_result = f"DENY: {exc}"
        replay_blocked = isinstance(replay_result, str) and replay_result.startswith("DENY")

        verified = (
            raised and len(effects) == 1 and outcome_unknown
            and not recorded_as_deny and nonce_consumed and replay_blocked
        )
        result = "UNKNOWN_OUTCOME_HANDLING_VERIFIED" if verified else "NOT_VERIFIED"
        _ev("E4_EVIDENCE", {
            "exception_propagated": raised,
            "simulated_effects": effects,
            "audit_decisions": decisions,
            "outcome_unknown_recorded": outcome_unknown,
            "wrongly_recorded_as_deny": recorded_as_deny,
            "nonce_consumed": nonce_consumed,
            "same_grant_replay": replay_result,
            "replay_blocked": replay_blocked,
            "result": result,
        })
        self.assertTrue(raised)
        self.assertEqual(len(effects), 1)
        self.assertTrue(outcome_unknown)
        self.assertFalse(recorded_as_deny)
        self.assertTrue(nonce_consumed)
        self.assertTrue(replay_blocked)
        self.assertEqual(result, "UNKNOWN_OUTCOME_HANDLING_VERIFIED")

    # ---- E5 -------------------------------------------------------------
    def test_e5_replay_after_gateway_restart(self):
        env = make_demo_environment()
        call = _authorized_call()
        grant = env["issuer"].issue(
            env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
            now=ISSUE_NOW,
        )
        nonce = grant.payload["nonce"]

        first_rows, first_receipt = env["gateway"].execute(
            call, env["context"], grant, now=EXEC_NOW
        )

        # Simulate process-level state loss: new Gateway + new AuditChain,
        # identical keys / policy / tool, so in-memory used_nonces is empty.
        fresh_audit = AuditChain(env["audit_sk"])
        restarted_gateway = ToolGateway(
            env["issuer_sk"].public_key(), env["tool"], env["tool_sk"].public_key(),
            env["policy"], fresh_audit,
        )
        second_rows, second_receipt = restarted_gateway.execute(
            call, env["context"], grant, now=EXEC_NOW
        )

        replayed = bool(first_rows) and bool(second_rows)
        result = "REPLAY_AFTER_RESTART_REPRODUCED" if replayed else "NOT_REPRODUCED"
        _ev("E5_EVIDENCE", {
            "nonce": nonce,
            "grant_expires_at": grant.payload["expires_at"],
            "execute_now": EXEC_NOW,
            "first_execution": {
                "rows": first_rows,
                "receipt_valid": verify_receipt(first_receipt, env["tool_sk"].public_key()),
            },
            "restarted_execution": {
                "rows": second_rows,
                "receipt_valid": verify_receipt(second_receipt, env["tool_sk"].public_key()),
            },
            "new_gateway_nonce_state": sorted(restarted_gateway.used_nonces),
            "result": result,
        })
        self.assertTrue(first_rows)
        self.assertTrue(second_rows, "same grant must replay on a fresh gateway")
        self.assertEqual(result, "REPLAY_AFTER_RESTART_REPRODUCED")

    # ---- E6 -------------------------------------------------------------
    def test_e6_effect_without_final_audit(self):
        env = make_demo_environment()
        effects = []
        tool = _CountingTool(env["tool_sk"], env["tool"].records, effects)
        audit = _FailFinalAudit(env["audit_sk"])
        gateway = ToolGateway(
            env["issuer_sk"].public_key(), tool, env["tool_sk"].public_key(),
            env["policy"], audit,
        )
        call = _authorized_call()
        grant = env["issuer"].issue(
            env["policy"], call, env["context"], env["tool"].SCHEMA_HASH,
            now=ISSUE_NOW,
        )
        nonce = grant.payload["nonce"]

        raised = False
        try:
            gateway.execute(call, env["context"], grant, now=EXEC_NOW)
        except OSError:
            raised = True

        decisions = [e["event"].get("decision") for e in audit.entries]
        final_audit_present = "ALLOW_EXECUTED" in decisions
        effect_happened = len(effects) == 1
        failed_events = [e.get("decision") for e in audit.failed_events]

        reproduced = (
            raised and effect_happened and failed_events == ["ALLOW_EXECUTED"]
            and not final_audit_present
        )
        result = "EFFECT_WITHOUT_FINAL_AUDIT_REPRODUCED" if reproduced else "NOT_REPRODUCED"
        _ev("E6_EVIDENCE", {
            "nonce": nonce,
            "gateway_raised": raised,
            "adapter_effects": effects,
            "receipt_signature_valid": True,  # receipt was produced before audit failure
            "failed_audit_events": failed_events,
            "persisted_decisions": decisions,
            "final_allow_executed_present": final_audit_present,
            "recovery_record_identifying_effect": None,
            "result": result,
        })
        self.assertTrue(raised)
        self.assertTrue(effect_happened, "tool effect must occur before audit write")
        self.assertEqual(failed_events, ["ALLOW_EXECUTED"])
        self.assertFalse(final_audit_present)
        self.assertEqual(result, "EFFECT_WITHOUT_FINAL_AUDIT_REPRODUCED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
