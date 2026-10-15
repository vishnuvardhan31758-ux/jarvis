from __future__ import annotations

from pathlib import Path
import pytest
from jarvis.contracts import (
    AcceptanceCriterion,
    CapabilityLevel,
    EvidenceRecord,
    ImmutableTargetError,
    RiskTier,
    TaskRecord,
    VerificationDisposition,
    VerificationLevel,
    VerifierExamProtocol,
)
from jarvis.evals.self_improve import SelfImprovementEngine, VerifierExamService
from jarvis.policy.kernel import SafetyKernel
from jarvis.store.db import DatabaseStore


def test_verifier_canary_exam_and_self_improvement_guards(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    svc = VerifierExamService(store, kernel)
    assert isinstance(svc, VerifierExamProtocol)
    assert svc.run_canary() is True

    # Zero-test pytest claim must be rejected
    t = TaskRecord(
        goal_id="g1",
        objective="run tests",
        risk_tier=RiskTier.R1_LOCAL_REVERSIBLE,
        required_verification=VerificationLevel.V2_INDEPENDENT,
        acceptance_criteria=[AcceptanceCriterion(description="pytest", check_type="pytest_passed")],
    )
    bad_ev = [EvidenceRecord(task_id=t.task_id, source_type="command_output", content_summary="[ACI exit=0]\n0 passed")]
    ver_bad = svc.verify_task(t, bad_ev)
    assert ver_bad.disposition == VerificationDisposition.REJECT

    scorecard = svc.run_capability_exam(quick=True)
    assert scorecard.passed_gate is True
    assert scorecard.assigned_level in {CapabilityLevel.L4_SELF_IMPROVING, CapabilityLevel.L5_EXPERT_GENERALIST}

    improver = SelfImprovementEngine(kernel, svc)
    with pytest.raises(ImmutableTargetError):
        improver.propose_patch({"jarvis/policy/engine.py": "hacked"}, scorecard, scorecard)
