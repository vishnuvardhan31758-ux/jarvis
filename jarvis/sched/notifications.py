"""jarvis/sched/notifications.py — Notification Attention Budgeter & Daily Briefing Generator."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from jarvis.contracts import ApprovalRecord, TaskRecord, TaskState


class NotificationService:
    def __init__(self, daily_non_urgent_cap: int = 5, quiet_hours: Tuple[int, int] = (22, 7)) -> None:
        self.daily_non_urgent_cap = daily_non_urgent_cap
        self.quiet_hours = quiet_hours
        self.sent_non_urgent_today = 0
        self._seen_keys: set[Tuple[str, str]] = set()

    def _in_quiet_hours(self, hour: int) -> bool:
        start_h, end_h = self.quiet_hours
        if start_h > end_h:
            return hour >= start_h or hour < end_h
        return start_h <= hour < end_h

    def send_notification(
        self,
        title: str,
        message: str,
        priority: str = "info",
        current_hour: int = 12,
    ) -> Dict[str, Any]:
        dedup_key = (title.strip(), message.strip())
        if dedup_key in self._seen_keys and priority not in {"urgent", "security"}:
            return {"delivered": False, "reason": "DEDUPLICATED"}
        self._seen_keys.add(dedup_key)

        if priority in {"urgent", "security"}:
            return {"delivered": True, "priority": priority, "title": title}

        if self._in_quiet_hours(current_hour):
            return {"delivered": False, "reason": "QUIET_HOURS_DEFERRED"}

        if self.sent_non_urgent_today >= self.daily_non_urgent_cap:
            return {"delivered": False, "reason": "DAILY_CAP_REACHED"}

        self.sent_non_urgent_today += 1
        return {"delivered": True, "priority": priority, "title": title}

    def generate_briefing(
        self,
        tasks: List[TaskRecord],
        pending_approvals: List[ApprovalRecord],
        spend_today_usd: float,
    ) -> Dict[str, Any]:
        return {
            "completed_tasks": sum(1 for t in tasks if t.state == TaskState.SUCCEEDED),
            "running_tasks": sum(1 for t in tasks if t.state == TaskState.RUNNING),
            "pending_approvals_count": len(pending_approvals),
            "spend_today_usd": round(spend_today_usd, 2),
        }
