"""jarvis/runner/engine.py — Durable Checkpointed Job Runner with Non-Idempotent Crash Reconciliation."""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple
from jarvis.contracts import (
    ApprovalRecord,
    EmergencyStopActiveError,
    EvidenceRecord,
    JarvisError,
    JobRunnerProtocol,
    PlanStep,
    PolicyDeniedError,
    PolicyEngineProtocol,
    PolicyRequest,
    ReconcileOutcome,
    SafetyKernelProtocol,
    StoreProtocol,
    TaskRecord,
    TaskState,
    ToolProtocol,
    canonical_hash,
)


class JobRunner:
    def __init__(
        self,
        store: StoreProtocol,
        policy: PolicyEngineProtocol,
        kernel: SafetyKernelProtocol,
        worker_id: str = "worker_local_1",
    ) -> None:
        self.store = store
        self.policy = policy
        self.kernel = kernel
        self.worker_id = worker_id
        self._tools: Dict[str, ToolProtocol] = {}

    def register_tool(self, tool: ToolProtocol) -> None:
        self._tools[tool.name] = tool

    def get_registered_tools(self) -> List[str]:
        return list(self._tools.keys())

    def execute_step(
        self,
        task: TaskRecord,
        step: PlanStep,
        approval_id: Optional[str] = None,
        step_up_verified: bool = False,
    ) -> Tuple[Dict[str, Any], Optional[EvidenceRecord]]:
        if self.kernel.is_stopped():
            raise EmergencyStopActiveError("SafetyKernel emergency stop is active")

        if (
            task.depth > task.budget.max_depth
            or task.budget.spent_cost_usd > task.budget.max_cost_usd
            or task.budget.retries_used > task.budget.max_retries
        ):
            raise PolicyDeniedError("Task budget or depth limit exceeded")

        tool = self._tools.get(step.tool_name)
        if tool is None:
            raise JarvisError(f"Unknown tool: {step.tool_name}")

        eff_risk = step.risk_tier if step.risk_tier.rank >= tool.default_risk.rank else tool.default_risk
        scope = str(step.tool_args.get("path", step.tool_args.get("url", step.tool_args.get("recipient", ""))))
        req = PolicyRequest(
            task_id=task.task_id,
            domain=task.domain,
            action=step.tool_name,
            args=step.tool_args,
            resource_scope=scope,
            data_class=task.data_class,
            requested_risk=eff_risk,
            autonomy_level=task.autonomy_level,
            mandate_id=task.mandate_id,
            approval_id=approval_id,
            step_up_verified=step_up_verified,
            estimated_spend_usd=float(step.tool_args.get("amount_usd", 0.0)),
        )
        decision = self.policy.evaluate(req)
        self.store.save_decision(decision, task.task_id)

        if not decision.allowed:
            if decision.requires_approval:
                apr = ApprovalRecord(
                    task_id=task.task_id,
                    action=step.tool_name,
                    args_hash=canonical_hash(step.tool_args),
                    resource_scope=scope,
                    risk_tier=decision.effective_risk,
                    data_class=task.data_class,
                    consequences_summary=decision.explanation,
                    requires_step_up=decision.requires_step_up,
                )
                self.store.save_approval(apr)
                return (
                    {
                        "status": "WAITING_FOR_APPROVAL",
                        "approval_id": apr.approval_id,
                        "requires_step_up": apr.requires_step_up,
                        "reason": decision.explanation,
                    },
                    None,
                )
            raise PolicyDeniedError(decision.explanation)

        if tool.idempotent:
            last_err: Optional[Exception] = None
            for attempt in range(task.budget.max_retries + 1):
                try:
                    out, ev = tool.execute(step.tool_args, task)
                    step.completed = True
                    self.store.save_evidence(ev)
                    return out, ev
                except (TimeoutError, RuntimeError) as exc:
                    last_err = exc
                    task.budget.retries_used += 1
                    if task.budget.retries_used > task.budget.max_retries:
                        break
                    time.sleep(0.01 * (2 ** attempt))
            raise JarvisError(f"Idempotent tool {tool.name} failed after retries: {last_err}")

        # Non-idempotent execution: never auto-retry without reconciliation
        try:
            out, ev = tool.execute(step.tool_args, task)
            step.completed = True
            self.store.save_evidence(ev)
            return out, ev
        except (TimeoutError, RuntimeError):
            db_task = self.store.get_task(task.task_id)
            if db_task and db_task.state == TaskState.RUNNING:
                task_rec = self.store.transition_task(
                    task.task_id,
                    TaskState.RECOVERING,
                    actor=self.worker_id,
                    reason=f"Reconciling non-idempotent tool {tool.name} after timeout/crash",
                )
                task.state = task_rec.state
                task.version = task_rec.version
            outcome = tool.reconcile(step.tool_args, task)
            if outcome == ReconcileOutcome.KNOWN_DONE:
                ev = EvidenceRecord(
                    task_id=task.task_id,
                    source_type="reconciled",
                    content_summary=f"Reconciled {tool.name} as KNOWN_DONE without duplicate execution",
                )
                self.store.save_evidence(ev)
                db_task = self.store.get_task(task.task_id)
                if db_task and db_task.state == TaskState.RECOVERING:
                    t_run = self.store.transition_task(
                        task.task_id, TaskState.RUNNING, actor=self.worker_id, reason="Reconciled KNOWN_DONE"
                    )
                    task.state = t_run.state
                    task.version = t_run.version
                step.completed = True
                return {"status": "RECONCILED_DONE"}, ev
            if outcome == ReconcileOutcome.KNOWN_NOT_DONE:
                task.budget.retries_used += 1
                db_task = self.store.get_task(task.task_id)
                if db_task and db_task.state == TaskState.RECOVERING:
                    t_run = self.store.transition_task(
                        task.task_id, TaskState.RUNNING, actor=self.worker_id, reason="Reconciled KNOWN_NOT_DONE; retrying once"
                    )
                    task.state = t_run.state
                    task.version = t_run.version
                out, ev = tool.execute(step.tool_args, task)
                step.completed = True
                self.store.save_evidence(ev)
                return out, ev
            return {"status": "RECOVERING_UNKNOWN"}, None
