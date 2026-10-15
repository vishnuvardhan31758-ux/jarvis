"""jarvis/memory/service.py — Governed SQLite FTS5 Memory with Anti-Poisoning Rules."""
from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import List
from jarvis.contracts import (
    DataClass,
    EpistemicLabel,
    MemoryCategory,
    MemoryItem,
    redact_secrets,
    utc_now,
)


class MemoryService:
    def __init__(self, db_path: str | Path = "data/jarvis_memory.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._fts_enabled = True
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_items (
                    memory_id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    data_class_rank INTEGER NOT NULL,
                    expires_at TEXT,
                    created_at TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags_text TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )
            try:
                conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(memory_id UNINDEXED, content, tags_text);"
                )
            except sqlite3.OperationalError:
                self._fts_enabled = False

    def store_memory(self, item: MemoryItem) -> MemoryItem:
        item.content = redact_secrets(item.content)
        if (
            item.category == MemoryCategory.SEMANTIC
            and item.epistemic_label in {EpistemicLabel.OBSERVED, EpistemicLabel.SOURCE_SUPPORTED}
            and len(item.evidence_ids) == 0
        ):
            item.epistemic_label = EpistemicLabel.UNVERIFIED

        if item.category == MemoryCategory.PREFERENCE and not item.confirmed_by_owner:
            item.epistemic_label = EpistemicLabel.INFERRED
            if item.expires_at is None:
                item.expires_at = utc_now() + timedelta(days=14)

        tags_text = " ".join(item.tags)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO memory_items
                (memory_id, category, data_class_rank, expires_at, created_at, content, tags_text, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.memory_id,
                    item.category.value,
                    item.data_class.rank,
                    item.expires_at.isoformat() if item.expires_at else None,
                    item.created_at.isoformat(),
                    item.content,
                    tags_text,
                    item.model_dump_json(),
                ),
            )
            if self._fts_enabled:
                conn.execute("DELETE FROM memory_fts WHERE memory_id = ?", (item.memory_id,))
                conn.execute(
                    "INSERT INTO memory_fts (memory_id, content, tags_text) VALUES (?, ?, ?)",
                    (item.memory_id, item.content, tags_text),
                )
        return item

    def search_memory(
        self,
        query: str,
        max_data_class: DataClass = DataClass.D2_CONFIDENTIAL,
        limit: int = 5,
    ) -> List[MemoryItem]:
        now_iso = utc_now().isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload_json, content, tags_text
                FROM memory_items
                WHERE data_class_rank <= ?
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
                """,
                (max_data_class.rank, now_iso),
            ).fetchall()

        q_terms = [t.lower() for t in query.split() if t.strip()]
        matched: List[MemoryItem] = []
        for payload_json, content, tags_text in rows:
            hay = f"{content} {tags_text}".lower()
            if not q_terms or any(t in hay for t in q_terms):
                matched.append(MemoryItem.model_validate_json(payload_json))
                if len(matched) >= limit:
                    break
        return matched

    def delete_memory(self, memory_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM memory_items WHERE memory_id = ?", (memory_id,))
            if self._fts_enabled:
                conn.execute("DELETE FROM memory_fts WHERE memory_id = ?", (memory_id,))
            return cur.rowcount > 0
