"""E4.8.6-D1 adapter for the MVP's read-only MockFinanceTool."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
import threading
from pathlib import Path
from typing import Any, Mapping

from agent_exec_binding import (
    ExecutionContext,
    SignedGrant,
    ToolCall,
    canonical_json,
    digest_object,
)
from src.execution_binding import ToolAdapter, ToolOperationConflict, schema_hash


class E483MockFinanceAdapter(ToolAdapter):
    """Durably caches the read-only mock query result and its tool receipt.

    The wrapped MockFinanceTool is a pure in-memory read-only function. The
    SQLite transaction persists its result/receipt for recovery; this is not
    a generic exactly-once wrapper for external side effects.
    """

    idempotent_by_operation_id = True

    def __init__(self, *, tool: Any, database_path: str | Path):
        self.tool = tool
        self.tool_name = tool.TOOL_ID
        self.schema_hash = schema_hash(tool.SCHEMA)
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._binding_lock = threading.RLock()
        self._bindings: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]] = {}
        with closing(self._connect()) as con:
            con.execute(
                """CREATE TABLE IF NOT EXISTS mock_finance_results (
                    operation_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )"""
            )

    def _connect(self):
        con = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA synchronous=FULL")
        return con

    def effect_count(self) -> int:
        """Return the number of durably persisted execution results.

        This is a test helper for the read-only MockFinanceTool adapter.
        It counts committed SQLite result records, not arbitrary external
        side effects or execution attempts.
        """
        with closing(self._connect()) as con:
            row = con.execute(
                "SELECT COUNT(*) FROM mock_finance_results"
            ).fetchone()
        return int(row[0])
    def bind_authorization(
        self,
        *,
        operation_id: str,
        call_data: Mapping[str, Any],
        context_data: Mapping[str, Any],
        grant_payload: Mapping[str, Any],
        grant_signature: str,
    ) -> None:
        """Install the verified parent snapshots needed to invoke the MVP tool."""
        call_copy = json.loads(canonical_json(dict(call_data)))
        context_copy = json.loads(canonical_json(dict(context_data)))
        grant_copy = json.loads(canonical_json(dict(grant_payload)))
        with self._binding_lock:
            prior = self._bindings.get(operation_id)
            binding = (call_copy, context_copy, grant_copy, grant_signature)
            if prior is not None and prior != binding:
                raise ValueError("operation_id is already bound to another parent authorization")
            self._bindings[operation_id] = binding

    def lookup(self, *, operation_id: str, request_digest: str):
        with closing(self._connect()) as con:
            row = con.execute(
                "SELECT request_digest,result_json FROM mock_finance_results WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        if row is None:
            return None
        if row[0] != request_digest:
            raise ToolOperationConflict("operation_id is bound to another adapter request")
        return json.loads(row[1])

    def execute(
        self,
        *,
        operation_id: str,
        request_digest: str,
        arguments: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        with self._binding_lock:
            binding = self._bindings.get(operation_id)
        if binding is None:
            raise RuntimeError("verified parent authorization is not bound to this operation")
        call_data, context_data, grant_payload, grant_signature = binding

        if dict(arguments) != call_data.get("args"):
            raise ValueError("adapter arguments differ from verified parent ToolCall")
        if dict(context) != context_data:
            raise ValueError("adapter context differs from verified parent context")
        if call_data.get("operation_id") != operation_id:
            raise ValueError("adapter operation_id differs from verified parent ToolCall")

        call = ToolCall(
            agent_id=call_data["agent_id"],
            tool_id=call_data["tool_id"],
            resource=call_data["resource"],
            operation=call_data["operation"],
            args=call_data["args"],
            operation_id=operation_id,
        )
        parent_grant = SignedGrant(grant_payload, grant_signature)
        execution_context = ExecutionContext(**context_data)

        # This adapter wraps a read-only query. The result is computed while
        # holding the SQLite writer transaction and committed with its receipt.
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT request_digest,result_json FROM mock_finance_results WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is not None:
                if row[0] != request_digest:
                    raise ToolOperationConflict("operation_id is bound to another adapter request")
                con.commit()
                return json.loads(row[1])

            output, receipt = self.tool.execute(
                call, parent_grant, execution_context, int(__import__("time").time())
            )
            result = {
                "output": output,
                "tool_receipt": receipt.as_dict(),
            }
            encoded = canonical_json(result).decode("utf-8")
            con.execute(
                "INSERT INTO mock_finance_results(operation_id,request_digest,result_json) VALUES(?,?,?)",
                (operation_id, request_digest, encoded),
            )
            con.commit()
            return result
        except Exception:
            if con.in_transaction:
                con.rollback()
            raise
        finally:
            con.close()
