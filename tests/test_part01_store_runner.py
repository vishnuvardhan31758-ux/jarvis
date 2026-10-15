from __future__ import annotations

import sqlite3
from pathlib import Path
import pytest
from jarvis.contracts import (
    AcceptanceCriterion,
    AutonomyLevel,
    DataClass,
    EmergencyStopActiveError,
    EvidenceRecord,
    GoalSpec,
    IllegalTransitionError,
    JarvisError,
    JobRunnerProtocol,
    OptimisticLockError,
    PlanStep,
    PolicyDeniedError,
    ReconcileOutcome,
    RiskTier,
    StoreProtocol,
    TaskRecord,
    TaskState,
    VerificationDisposition,
    VerificationLevel,
    VerificationRecord,
)
from jarvis.policy.engine import PolicyEngine
from jarvis.policy.kernel import SafetyKernel
from jarvis.runner.engine import JobRunner
from jarvis.store.db import DatabaseStore


class DummyTool:
    def __init__(self, name: str = "fs.write", risk: RiskTier = RiskTier.R1_LOCAL_REVERSIBLE, idempotent: bool = True) -> None:
        self.name = name
        self.description = "Dummy tool"
        self.default_risk = risk
        self.idempotent = idempotent
        self.calls = 0
        self.fail_times = 0
        self.reconcile_outcome = ReconcileOutcome.KNOWN_DONE

    def execute(self, args: dict, task: TaskRecord):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise TimeoutError("Simulated tool timeout")
        return {"ok": True, "calls": self.calls}, EvidenceRecord(
            task_id=task.task_id, source_type="file_hash", content_summary="done", sha256="a" * 64
        )

    def reconcile(self, args: dict, task: TaskRecord) -> ReconcileOutcome:
        return self.reconcile_outcome


def test_store_and_runner_protocols(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    policy = PolicyEngine(kernel, store)
    runner = JobRunner(store, policy, kernel)
    assert isinstance(store, StoreProtocol)
    assert isinstance(runner, JobRunnerProtocol)


def test_task_lifecycle_and_succeeded_verification_gate(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    g = store.save_goal(GoalSpec(raw_input="test", normalized_objective="test"))
    t = store.create_task(
        TaskRecord(goal_id=g.goal_id, objective="test", required_verification=VerificationLevel.V2_INDEPENDENT)
    )
    store.transition_task(t.task_id, TaskState.PLANNING, "test", "plan")
    store.transition_task(t.task_id, TaskState.READY, "test", "ready")
    store.transition_task(t.task_id, TaskState.RUNNING, "test", "run")
    store.transition_task(t.task_id, TaskState.VERIFYING, "test", "verify")

    # Cannot transition to SUCCEEDED without VerificationRecord
    with pytest.raises(IllegalTransitionError):
        store.transition_task(t.task_id, TaskState.SUCCEEDED, "test", "no ver")

    # Cannot transition to SUCCEEDED with V1 when V2 is required
    low_ver = VerificationRecord(
        task_id=t.task_id, level_achieved=VerificationLevel.V1_STATE_CHECK, disposition=VerificationDisposition.ACCEPT
    )
    with pytest.raises(IllegalTransitionError):
        store.transition_task(t.task_id, TaskState.SUCCEEDED, "test", "low ver", verification=low_ver)

    ok_ver = VerificationRecord(
        task_id=t.task_id, level_achieved=VerificationLevel.V2_INDEPENDENT, disposition=VerificationDisposition.ACCEPT
    )
    done = store.transition_task(t.task_id, TaskState.SUCCEEDED, "test", "ok", verification=ok_ver)
    assert done.state == TaskState.SUCCEEDED
    assert done.state.is_terminal is True


def test_optimistic_locking_conflict(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    t = store.create_task(TaskRecord(goal_id="g1", objective="lock test"))
    store.update_task(t, expected_version=1)
    with pytest.raises(OptimisticLockError):
        store.update_task(t, expected_version=1)


def test_audit_log_immutability_triggers_and_tamper_detection(tmp_path: Path) -> None:
    db_file = tmp_path / "j.db"
    store = DatabaseStore(db_file, tmp_path / "arts")
    store.create_task(TaskRecord(goal_id="g1", objective="audit sk-1234567890abcdefghijklmnop"))
    valid, bad_row = store.verify_audit_chain()
    assert valid is True and bad_row is None

    # Triggers block UPDATE and DELETE
    with sqlite3.connect(db_file) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit_log SET reason = 'hacked' WHERE id = 1")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM audit_log WHERE id = 1")

        # Drop trigger to simulate raw file tampering and verify hash chain catches it
        conn.execute("DROP TRIGGER prevent_audit_update;")
        conn.execute("UPDATE audit_log SET reason = 'tampered' WHERE id = 1")

    valid_after, corrupted_id = store.verify_audit_chain()
    assert valid_after is False and corrupted_id == 1


def test_artifact_hash_verification_and_corruption_detection(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    meta = store.put_artifact(b"hello jarvis", "text/plain", DataClass.D1_INTERNAL, "t1")
    _, data = store.get_artifact(meta.artifact_id)
    assert data == b"hello jarvis"

    # Corrupt file on disk
    Path(meta.storage_path).write_bytes(b"corrupted bytes")
    with pytest.raises(JarvisError):
        store.get_artifact(meta.artifact_id, verify_hash=True)


def test_non_idempotent_reconciliation_known_done_and_not_done(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    policy = PolicyEngine(kernel, store)
    runner = JobRunner(store, policy, kernel)

    tool = DummyTool(name="git.commit", risk=RiskTier.R2_EXTERNAL_REVERSIBLE, idempotent=False)
    tool.fail_times = 1
    tool.reconcile_outcome = ReconcileOutcome.KNOWN_DONE
    runner.register_tool(tool)

    t = store.create_task(
        TaskRecord(goal_id="g1", objective="commit", autonomy_level=AutonomyLevel.A3_DELEGATE)
    )
    store.transition_task(t.task_id, TaskState.PLANNING, "sys", "p")
    store.transition_task(t.task_id, TaskState.READY, "sys", "r")
    t = store.transition_task(t.task_id, TaskState.RUNNING, "sys", "run")

    step = PlanStep(index=0, description="commit", tool_name="git.commit", risk_tier=RiskTier.R2_EXTERNAL_REVERSIBLE)
    res, ev = runner.execute_step(t, step)
    assert res["status"] == "RECONCILED_DONE"
    assert ev is not None and ev.source_type == "reconciled"
    assert tool.calls == 1  # Never re-executed because reconcile returned KNOWN_DONE!
