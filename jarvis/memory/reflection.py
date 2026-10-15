"""jarvis/memory/reflection.py — Post-Mortem Episodic Reflection Engine."""
from __future__ import annotations

from typing import List
from jarvis.contracts import EvidenceRecord, PostMortemReflection, TaskRecord, TaskState


class ReflectionEngine:
    def record_reflection(
        self,
        task: TaskRecord,
        evidence: List[EvidenceRecord],
        error_msg: str = "",
    ) -> PostMortemReflection:
        if task.state == TaskState.SUCCEEDED:
            worked = [f"Verified {len(evidence)} evidence item(s) at {task.required_verification.value}"]
            if task.selected_plan:
                worked.append(f"Strategy '{task.selected_plan.strategy_name}' succeeded")
            return PostMortemReflection(
                task_id=task.task_id,
                domain=task.domain,
                outcome=task.state,
                what_worked=worked,
                what_failed=[],
                root_cause="All acceptance criteria verified deterministically",
                reusable_lesson=f"Use {task.selected_plan.strategy_name if task.selected_plan else 'deterministic'} path for {task.domain}",
                proposed_skill_name=f"auto_{task.domain}_workflow",
            )

        return PostMortemReflection(
            task_id=task.task_id,
            domain=task.domain,
            outcome=task.state,
            what_worked=[f"Collected {len(evidence)} evidence record(s) before halt"],
            what_failed=[error_msg or task.error_message or "Task did not reach SUCCEEDED"],
            root_cause=error_msg or task.error_message or "Verification or policy gate blocked completion",
            reusable_lesson=f"Pre-verify preconditions and step-up approvals in domain '{task.domain}'",
            proposed_skill_name=None,
        )
