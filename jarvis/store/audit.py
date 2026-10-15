"""jarvis/store/audit.py — Append-Only SHA-256 Hash-Chained Audit Log with SQLite Triggers."""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from jarvis.contracts import redact_secrets, utc_now

GENESIS_HASH = "GENESIS_" + ("0" * 64)


class AuditLogger:
    def __init__(self, db_path: str | Path = "data/jarvis.db") -> None:
        self.db_path = Path(db_path)

    def init_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                task_id TEXT,
                reason TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                row_hash TEXT NOT NULL
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_task_id ON audit_log(task_id);")
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_audit_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only');
            END;
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only');
            END;
            """
        )

    def append_entry(
        self,
        conn: sqlite3.Connection,
        actor: str,
        action: str,
        reason: str,
        task_id: Optional[str] = None,
    ) -> str:
        clean_actor = redact_secrets(actor)
        clean_action = redact_secrets(action)
        clean_reason = redact_secrets(reason)
        row = conn.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row[0] if row else GENESIS_HASH
        ts = utc_now().isoformat()
        raw = f"{prev_hash}|{ts}|{clean_actor}|{clean_action}|{task_id or ''}|{clean_reason}".encode("utf-8")
        row_hash = hashlib.sha256(raw).hexdigest()
        conn.execute(
            """
            INSERT INTO audit_log (timestamp, actor, action, task_id, reason, prev_hash, row_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, clean_actor, clean_action, task_id, clean_reason, prev_hash, row_hash),
        )
        return row_hash

    def list_entries(self, limit: int = 50) -> List[Dict[str, Any]]:
        if not self.db_path.exists():
            return []
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, timestamp, actor, action, task_id, reason, prev_hash, row_hash FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                {
                    "id": r[0],
                    "timestamp": r[1],
                    "actor": r[2],
                    "action": r[3],
                    "task_id": r[4],
                    "reason": r[5],
                    "prev_hash": r[6],
                    "row_hash": r[7],
                }
                for r in rows
            ]

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        if not self.db_path.exists():
            return True, None
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, timestamp, actor, action, task_id, reason, prev_hash, row_hash FROM audit_log ORDER BY id ASC"
            ).fetchall()
        expected_prev = GENESIS_HASH
        for row_id, ts, actor, action, task_id, reason, prev_hash, row_hash in rows:
            if prev_hash != expected_prev:
                return False, int(row_id)
            raw = f"{expected_prev}|{ts}|{actor}|{action}|{task_id or ''}|{reason}".encode("utf-8")
            computed = hashlib.sha256(raw).hexdigest()
            if row_hash != computed:
                return False, int(row_id)
            expected_prev = row_hash
        return True, None
