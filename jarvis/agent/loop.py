"""jarvis/agent/loop.py — Checkpointed DAG & Non-Blocking Mandate Queue Executor."""
from __future__ import annotations

from typing import Dict, Optional, Tuple
from jarvis.agent.planner import DeliberatePlanner
from jarvis.contracts import (
    ApprovalRecord,
    JarvisError,
    JobRunnerProtocol,
    StoreProtocol,
    TaskRecord,
    TaskState,
    VerificationDisposition,
    VerifierExamProtocol,
    WorldMemoryProtocol,
    canonical_hash,
)


class AgentLoop:
    def __init__(
        self,
        store: StoreProtocol,
        runner: JobRunnerProtocol,
        planner: DeliberatePlanner,
        verifier: VerifierExamProtocol,
        world_model: Optional[WorldMemoryProtocol] = None,
    ) -> None:
        self.store = store
        self.runner = runner
        self.planner = planner
        self.verifier = verifier
        self.world_model = world_model

    def run_task(
        self,
        task_id: str,
        approval_overrides: Optional[Dict[str, Tuple[str, bool]]] = None,
    ) -> TaskRecord:
        task = self.store.get_task(task_id)
        if task is None:
            raise JarvisError(f"Task {task_id} not found")

        if task.state == TaskState.CREATED:
            task = self.store.transition_task(task.task_id, TaskState.PLANNING, "planner", "Entering planning")

        if task.selected_plan is None:
            reflections = self.store.list_reflections(task.domain)
            self.planner.build_plans(task, self.runner.get_registered_tools(), reflections=reflections)
            task = self.store.update_task(task, task.version)

        if task.state == TaskState.PLANNING:
            task = self.store.transition_task(task.task_id, TaskState.READY, "planner", "Plan selected")
        if task.state in {TaskState.READY, TaskState.WAITING_FOR_APPROVAL, TaskState.PAUSED}:
            task = self.store.transition_task(task.task_id, TaskState.RUNNING, "conductor", "Executing DAG steps")

        call_counts: Dict[str, int] = {}
        blocked_step_ids: set[str] = set()
        recovering_unknown = False

        assert task.selected_plan is not None
        for step in task.selected_plan.steps:
            if step.completed:
                continue

            if any(dep in blocked_step_ids for dep in step.depends_on):
                blocked_step_ids.add(step.step_id)
                continue

            sig = f"{step.tool_name}:{canonical_hash(step.tool_args)}"
            call_counts[sig] = call_counts.get(sig, 0) + 1
            if call_counts[sig] >= 3:
                task.error_message = "Loop detected: identical tool and arguments called 3 times"
                self.store.update_task(task, task.version)
                task = self.store.transition_task(task.task_id, TaskState.FAILED, "conductor", task.error_message)
                if self.world_model:
                    refl = self.world_model.record_reflection(task, self.store.list_evidence(task.task_id), task.error_message)
                    self.store.save_reflection(refl)
                return task

            apr_id, step_up = (None, False)
            if approval_overrides and step.step_id in approval_overrides:
                apr_id, step_up = approval_overrides[step.step_id]

            if self.world_model is not None and step.risk_tier.rank >= 2 and apr_id is None:
                pred = self.world_model.predict_consequences(step.tool_name, step.tool_args, task)
                if pred.conflict_detected and not pred.safe_to_proceed:
                    apr = ApprovalRecord(
                        task_id=task.task_id,
                        action=step.tool_name,
                        args_hash=canonical_hash(step.tool_args),
                        resource_scope=str(step.tool_args.get("path", step.tool_args.get("recipient", ""))),
                        risk_tier=step.risk_tier,
                        data_class=task.data_class,
                        consequences_summary=f"WorldModel conflict: {pred.conflict_reason}",
                        requires_step_up=(step.risk_tier.rank >= 3),
                    )
                    self.store.save_approval(apr)
                    blocked_step_ids.add(step.step_id)
                    continue

            res, _ = self.runner.execute_step(task, step, approval_id=apr_id, step_up_verified=step_up)
            status = res.get("status", "OK")
            if status == "WAITING_FOR_APPROVAL":
                blocked_step_ids.add(step.step_id)
            elif status == "RECOVERING_UNKNOWN":
                blocked_step_ids.add(step.step_id)
                recovering_unknown = True

        latest_db = self.store.get_task(task.task_id)
        if latest_db:
            task.version = latest_db.version
            task.state = latest_db.state
        task = self.store.update_task(task, task.version)

        if blocked_step_ids:
            if recovering_unknown and task.state != TaskState.RECOVERING:
                task = self.store.transition_task(task.task_id, TaskState.RECOVERING, "conductor", "Step recovery unknown")
            elif not recovering_unknown and task.state == TaskState.RUNNING:
                task = self.store.transition_task(
                    task.task_id,
                    TaskState.WAITING_FOR_APPROVAL,
                    "conductor",
                    f"{len(blocked_step_ids)} step(s) parked awaiting owner approval while unblocked branches finished",
                )
            return task

        if all(s.completed for s in task.selected_plan.steps):
            task = self.store.transition_task(task.task_id, TaskState.VERIFYING, "conductor", "All steps completed; verifying")
            ev_list = self.store.list_evidence(task.task_id)
            ver = self.verifier.verify_task(task, ev_list)
            self.store.save_verification(ver)
            if ver.disposition == VerificationDisposition.ACCEPT and ver.level_achieved.rank >= task.required_verification.rank:
                task = self.store.transition_task(
                    task.task_id, TaskState.SUCCEEDED, "verifier", "Verification passed", verification=ver
                )
            elif ver.disposition == VerificationDisposition.PARTIAL:
                task = self.store.transition_task(task.task_id, TaskState.PARTIALLY_COMPLETED, "verifier", ver.notes)
            else:
                task.error_message = ver.notes or "Verification rejected"
                task = self.store.update_task(task, task.version)
                task = self.store.transition_task(task.task_id, TaskState.FAILED, "verifier", task.error_message)

            if self.world_model:
                refl = self.world_model.record_reflection(task, ev_list, task.error_message or "")
                self.store.save_reflection(refl)

        return task
