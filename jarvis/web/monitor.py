"""jarvis/web/monitor.py — Scheduled Page Diff Monitor."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List


class PageMonitor:
    def __init__(self) -> None:
        self._snapshots: Dict[str, Tuple[str, List[str]]] = {}

    def check_diff(self, url: str, new_content: str) -> Dict[str, Any]:
        new_hash = hashlib.sha256(new_content.encode("utf-8")).hexdigest()
        new_lines = [line.strip() for line in new_content.splitlines() if line.strip()]
        if url not in self._snapshots:
            self._snapshots[url] = (new_hash, new_lines)
            return {
                "changed": False,
                "prev_hash": None,
                "new_hash": new_hash,
                "added_lines": new_lines,
                "removed_lines": [],
            }
        prev_hash, prev_lines = self._snapshots[url]
        added = [l for l in new_lines if l not in prev_lines]
        removed = [l for l in prev_lines if l not in new_lines]
        self._snapshots[url] = (new_hash, new_lines)
        return {
            "changed": prev_hash != new_hash,
            "prev_hash": prev_hash,
            "new_hash": new_hash,
            "added_lines": added,
            "removed_lines": removed,
        }
