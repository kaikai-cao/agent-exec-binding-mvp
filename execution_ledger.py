"""Durable execution ledger for R2.8-P2 (stdlib ``sqlite3`` only).

This module provides two narrow, general-purpose engineering primitives:

* :class:`NonceRegistry` -- an atomic, persistent single-use nonce registry
  (E5).  Consumption is a unique-constraint insert inside one transaction, so
  it is safe across Gateway instances and across process restarts that share
  the same database file.
* :class:`ExecutionLedger` -- a persistent execution-state record used for
  intent / executing / completed / unknown / reconciled transitions and for
  recovery of an effect whose final audit write failed (E6).

Trust assumptions (stated explicitly, not implied by this module):
* The SQLite file is an *independent,Durably-written* store from the in-memory
  ``AuditChain`` and from the Gateway process.  If an attacker can edit the
  database file, all guarantees here collapse.
* Atomicity is limited to a single SQLite transaction on a single database
  file.  There is **no** distributed transaction with the external tool and no
  cross-store atomicity is claimed.
* Persisting a nonce prevents *local* replay against this registry.  It does
  not by itself prevent a caller from invoking a tool adapter that does not
  consult the registry.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


# --- Execution status vocabulary (E6) ------------------------------------
INTENT = "INTENT"
EXECUTING = "EXECUTING"
COMPLETED = "COMPLETED"
OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
RECONCILED = "RECONCILED"

EXECUTION_STATUSES = frozenset(
    {INTENT, EXECUTING, COMPLETED, OUTCOME_UNKNOWN, RECONCILED}
)


class LedgerError(Exception):
    """Raised when a ledger operation cannot be completed safely."""


class NonceConflict(LedgerError):
    """Raised when a nonce is already consumed for a different request."""


@dataclass(frozen=True)
class NonceRecord:
    nonce: str
    grant_hash: str
    request_hash: str
    principal: str
    consumed_at: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "nonce": self.nonce,
            "grant_hash": self.grant_hash,
            "request_hash": self.request_hash,
            "principal": self.principal,
            "consumed_at": self.consumed_at,
        }


@dataclass(frozen=True)
class ConsumeResult:
    """Outcome of one atomic consume attempt.

    ``consumed`` is True only for the single call that inserted the row.  When
    False, ``existing`` describes the prior binding so callers can distinguish
    a benign duplicate (same request) from a conflicting replay.
    """

    consumed: bool
    nonce: str
    existing: NonceRecord | None

    @property
    def identical_duplicate(self) -> bool:
        return not self.consumed and self.existing is not None


def _connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # WAL improves concurrent readers; the UNIQUE constraint is the real gate.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


class NonceRegistry:
    """Persistent, atomic, single-use nonce registry.

    One SQLite row per nonce.  Each ``consume`` runs inside one ``BEGIN
    IMMEDIATE`` transaction with a UNIQUE primary key; therefore exactly one
    concurrent caller can observe ``consumed=True``.  ``force_commit_error``
    is a *test-only* hook used to verify that a failed commit leaves no
    half-consumed row.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn = _connect(self.db_path)
        self._lock = threading.RLock()
        self._init_schema()
        # Test-only fault injection. Not part of the security interface.
        self.force_commit_error: bool = False

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nonce_consumptions (
                    nonce        TEXT PRIMARY KEY,
                    grant_hash   TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    principal    TEXT NOT NULL,
                    consumed_at  REAL NOT NULL
                )
                """
            )

    def consume(
        self,
        nonce: str,
        grant_hash: str,
        request_hash: str,
        principal: str,
    ) -> ConsumeResult:
        """Atomically consume ``nonce`` or report the existing binding.

        A different (grant_hash, request_hash, principal) for an already-used
        nonce is a conflict and raises :class:`NonceConflict`; the row is never
        overwritten.  The same binding repeated is an identical duplicate.
        """
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a non-empty string")
        now = time.time()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT INTO nonce_consumptions "
                    "(nonce, grant_hash, request_hash, principal, consumed_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (nonce, grant_hash, request_hash, principal, now),
                )
                if self.force_commit_error:
                    raise LedgerError("simulated commit failure")
                self._conn.execute("COMMIT")
                return ConsumeResult(
                    True,
                    nonce,
                    NonceRecord(nonce, grant_hash, request_hash, principal, now),
                )
            except sqlite3.IntegrityError:
                self._conn.execute("ROLLBACK")
                row = self._conn.execute(
                    "SELECT nonce, grant_hash, request_hash, principal, consumed_at "
                    "FROM nonce_consumptions WHERE nonce = ?",
                    (nonce,),
                ).fetchone()
                existing = NonceRecord(
                    row["nonce"], row["grant_hash"], row["request_hash"],
                    row["principal"], row["consumed_at"],
                )
                if (
                    existing.grant_hash != grant_hash
                    or existing.request_hash != request_hash
                    or existing.principal != principal
                ):
                    raise NonceConflict("nonce already bound to a different request")
                return ConsumeResult(False, nonce, existing)
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def lookup(self, nonce: str) -> NonceRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT nonce, grant_hash, request_hash, principal, consumed_at "
                "FROM nonce_consumptions WHERE nonce = ?",
                (nonce,),
            ).fetchone()
        if row is None:
            return None
        return NonceRecord(
            row["nonce"], row["grant_hash"], row["request_hash"],
            row["principal"], row["consumed_at"],
        )

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute(
                "SELECT COUNT(*) FROM nonce_consumptions"
            ).fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()


@dataclass(frozen=True)
class ExecutionRecord:
    nonce: str
    request_hash: str
    grant_hash: str
    principal: str
    status: str
    idempotency_key: str
    intent_at: float
    updated_at: float
    receipt_hash: str | None
    output_hash: str | None
    detail: str | None
    context_hash: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "nonce": self.nonce,
            "request_hash": self.request_hash,
            "grant_hash": self.grant_hash,
            "principal": self.principal,
            "status": self.status,
            "idempotency_key": self.idempotency_key,
            "intent_at": self.intent_at,
            "updated_at": self.updated_at,
            "receipt_hash": self.receipt_hash,
            "output_hash": self.output_hash,
            "detail": self.detail,
            "context_hash": self.context_hash,
        }


class ExecutionLedger:
    """Persistent execution-intent and state record (E6).

    Statuses move forward through ``INTENT -> EXECUTING -> COMPLETED``; failure
    paths move to ``OUTCOME_UNKNOWN`` and a successful reconciliation moves to
    ``RECONCILED``.  The intent row is written *before* the tool is invoked and
    is never deleted, so a final-audit failure cannot erase evidence that an
    operation was attempted.
    """

    _COLUMNS = (
        "nonce, request_hash, grant_hash, principal, status, idempotency_key, "
        "intent_at, updated_at, receipt_hash, output_hash, detail, context_hash"
    )

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn = _connect(self.db_path)
        self._lock = threading.RLock()
        self._init_schema()
        self.force_commit_error: bool = False

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_records (
                    nonce           TEXT PRIMARY KEY,
                    request_hash    TEXT NOT NULL,
                    grant_hash      TEXT NOT NULL,
                    principal       TEXT NOT NULL,
                    status          TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    intent_at       REAL NOT NULL,
                    updated_at      REAL NOT NULL,
                    receipt_hash    TEXT,
                    output_hash     TEXT,
                    detail          TEXT,
                    context_hash    TEXT
                )
                """
            )
            # Backward-compatible column for DBs created before context_hash
            # was introduced; harmless for fresh databases.
            cols = {
                row["name"]
                for row in self._conn.execute("PRAGMA table_info(execution_records)")
            }
            if "context_hash" not in cols:
                self._conn.execute(
                    "ALTER TABLE execution_records ADD COLUMN context_hash TEXT"
                )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ExecutionRecord:
        return ExecutionRecord(
            nonce=row["nonce"],
            request_hash=row["request_hash"],
            grant_hash=row["grant_hash"],
            principal=row["principal"],
            status=row["status"],
            idempotency_key=row["idempotency_key"],
            intent_at=row["intent_at"],
            updated_at=row["updated_at"],
            receipt_hash=row["receipt_hash"],
            output_hash=row["output_hash"],
            detail=row["detail"],
            context_hash=row["context_hash"],
        )

    def write_intent(
        self,
        nonce: str,
        request_hash: str,
        grant_hash: str,
        principal: str,
        idempotency_key: str | None = None,
        context_hash: str | None = None,
    ) -> ExecutionRecord:
        """Persist an INTENT row before any tool side effect.

        Idempotent on the same nonce: if an intent already exists it is
        returned unchanged.  A conflicting binding raises :class:`LedgerError`.
        """
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a non-empty string")
        if status_is_invalid(INTENT):
            raise LedgerError("invalid status constant")
        now = time.time()
        key = idempotency_key or nonce
        with self._lock:
            existing = self.get(nonce)
            if existing is not None:
                if (
                    existing.request_hash != request_hash
                    or existing.grant_hash != grant_hash
                    or existing.principal != principal
                ):
                    raise LedgerError("intent nonce bound to a different request")
                return existing
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT INTO execution_records "
                    "(nonce, request_hash, grant_hash, principal, status, "
                    " idempotency_key, intent_at, updated_at, receipt_hash, "
                    " output_hash, detail, context_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)",
                    (
                        nonce, request_hash, grant_hash, principal, INTENT,
                        key, now, now, context_hash,
                    ),
                )
                if self.force_commit_error:
                    raise LedgerError("simulated commit failure")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            return self.get(nonce)  # type: ignore[return-value]

    def transition(
        self,
        nonce: str,
        status: str,
        *,
        receipt_hash: str | None = None,
        output_hash: str | None = None,
        detail: str | None = None,
    ) -> ExecutionRecord:
        """Move a record to ``status`` with an explicit forward-only rule.

        A terminal ``COMPLETED``/``RECONCILED`` record is never downgraded to
        ``OUTCOME_UNKNOWN``.  ``OUTCOME_UNKNOWN`` may be superseded by
        ``RECONCILED`` once an external state query confirms the effect.
        """
        if status not in EXECUTION_STATUSES:
            raise ValueError(f"unknown execution status: {status!r}")
        with self._lock:
            current = self.get(nonce)
            if current is None:
                raise LedgerError(f"no execution intent for nonce {nonce!r}")
            if current.status in (COMPLETED, RECONCILED) and status != current.status:
                raise LedgerError(
                    f"cannot move terminal status {current.status} to {status}"
                )
            now = time.time()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "UPDATE execution_records SET status=?, updated_at=?, "
                    "receipt_hash=COALESCE(?, receipt_hash), "
                    "output_hash=COALESCE(?, output_hash), "
                    "detail=COALESCE(?, detail) WHERE nonce=?",
                    (status, now, receipt_hash, output_hash, detail, nonce),
                )
                if self.force_commit_error:
                    raise LedgerError("simulated commit failure")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            return self.get(nonce)  # type: ignore[return-value]

    def get(self, nonce: str) -> ExecutionRecord | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {self._COLUMNS} FROM execution_records WHERE nonce = ?",
                (nonce,),
            ).fetchone()
        return None if row is None else self._row_to_record(row)

    def list_by_status(self, statuses: Iterable[str]) -> list[ExecutionRecord]:
        wanted = tuple(statuses)
        if not wanted:
            return []
        marks = ",".join("?" for _ in wanted)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {self._COLUMNS} FROM execution_records "
                f"WHERE status IN ({marks}) ORDER BY intent_at",
                wanted,
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def list_pending(self) -> list[ExecutionRecord]:
        """Records that may have an effect without a final confirmation."""
        return self.list_by_status((INTENT, EXECUTING, OUTCOME_UNKNOWN))

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute(
                "SELECT COUNT(*) FROM execution_records"
            ).fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def status_is_invalid(status: str) -> bool:
    """Small guard kept as a function so callers can reason about it."""
    return status not in EXECUTION_STATUSES


# --- Tool-side durable result store (E6) ---------------------------------
TOOL_STARTED = "STARTED"
TOOL_FINISHED = "FINISHED"


@dataclass(frozen=True)
class ToolExecutionResult:
    nonce: str
    status: str
    receipt: dict[str, Any] | None
    output_hash: str | None
    output: Any
    updated_at: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "nonce": self.nonce,
            "status": self.status,
            "receipt_present": self.receipt is not None,
            "output_hash": self.output_hash,
            "updated_at": self.updated_at,
        }


class ToolResultStore:
    """Mock tool's durable nonce -> execution-result store.

    This models the *tool server* persisting what it did, keyed by the grant
    nonce / idempotency key, so an external reconciler can query the real
    outcome later.  It is a DB in this MVP, but the reconciler only depends on
    the ``query`` interface -- a real tool would expose an equivalent endpoint.

    A STARTED row without a receipt means the effect may or may not have
    happened; a FINISHED row carries the signed receipt and output hash.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn = _connect(self.db_path)
        self._lock = threading.RLock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_results (
                    nonce       TEXT PRIMARY KEY,
                    status      TEXT NOT NULL,
                    receipt_json TEXT,
                    output_hash TEXT,
                    output_json TEXT,
                    updated_at  REAL NOT NULL
                )
                """
            )

    def mark_started(self, nonce: str) -> None:
        """Record that execution began; never overwrite a FINISHED row."""
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a non-empty string")
        now = time.time()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO tool_results "
                    "(nonce, status, receipt_json, output_hash, output_json, updated_at) "
                    "VALUES (?, ?, NULL, NULL, NULL, ?)",
                    (nonce, TOOL_STARTED, now),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _encode(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def store_result(
        self, nonce: str, receipt: dict[str, Any], output_hash: str, output: Any
    ) -> None:
        """Persist the executed result and signed receipt for later recovery."""
        now = time.time()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT INTO tool_results "
                    "(nonce, status, receipt_json, output_hash, output_json, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(nonce) DO UPDATE SET status=excluded.status, "
                    "receipt_json=excluded.receipt_json, output_hash=excluded.output_hash, "
                    "output_json=excluded.output_json, updated_at=excluded.updated_at",
                    (
                        nonce, TOOL_FINISHED, self._encode(receipt),
                        output_hash, self._encode(output), now,
                    ),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def query(self, nonce: str) -> ToolExecutionResult | None:
        """External state query used by the reconciler. None = no record."""
        with self._lock:
            row = self._conn.execute(
                "SELECT status, receipt_json, output_hash, output_json, updated_at "
                "FROM tool_results WHERE nonce = ?",
                (nonce,),
            ).fetchone()
        if row is None:
            return None
        return ToolExecutionResult(
            nonce=nonce,
            status=row["status"],
            receipt=json.loads(row["receipt_json"]) if row["receipt_json"] else None,
            output_hash=row["output_hash"],
            output=json.loads(row["output_json"]) if row["output_json"] else None,
            updated_at=row["updated_at"],
        )

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute(
                "SELECT COUNT(*) FROM tool_results"
            ).fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
