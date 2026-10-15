"""jarvis/ops/proactive.py — Proactive Standing Goal & Trigger Engine."""
from __future__ import annotations

from typing import Any, Dict, List
from jarvis.contracts import (
    GoalSpec,
    SafetyKernelProtocol,
    StoreProtocol,
    TaskRecord,
    new_id,
)


class ProactiveGoalEngine:
    def __init__(self, store: StoreProtocol, kernel: SafetyKernelProtocol) -> None:
        self.store = store
        self.kernel = kernel
        self._standing_goals: Dict[str, Dict[str, Any]] = {}

    def register_standing_goal(
        self,
        title: str,
        domain: str,
        mandate_id: str,
        trigger_key: str,
        sub_objectives: List[str],
    ) -> str:
        sg_id = new_id("sgoal")
        self._standing_goals[sg_id] = {
            "sg_id": sg_id,
            "title": title,
            "domain": domain,
            "mandate_id": mandate_id,
            "trigger_key": trigger_key,
            "sub_objectives": list(sub_objectives),
        }
        return sg_id

    def evaluate_triggers(self, events: List[Dict[str, Any]]) -> List[TaskRecord]:
        if self.kernel.is_stopped():
            return []
        spawned: List[TaskRecord] = []
        event_keys = {str(e.get("trigger_key", "")) for e in events}
        for sg in self._standing_goals.values():
            if sg["trigger_key"] in event_keys:
                mandate = self.store.get_mandate(sg["mandate_id"])
                if mandate is None or not mandate.active:
                    continue
                goal = GoalSpec(
                    raw_input=sg["title"],
                    normalized_objective=sg["title"],
                    risk_tier=mandate.max_risk_tier,
                    mandate_id=mandate.mandate_id,
                )
                self.store.save_goal(goal)
                for obj in sg["sub_objectives"]:
                    t = TaskRecord(
                        goal_id=goal.goal_id,
                        objective=obj,
                        domain=sg["domain"],
                        risk_tier=mandate.max_risk_tier,
                        autonomy_level=mandate.autonomy_level,
                        mandate_id=mandate.mandate_id,
                    )
                    self.store.create_task(t, actor="proactive_engine", reason=f"Triggered by {sg['trigger_key']}")
                    spawned.append(t)
        return spawned
