from __future__ import annotations

import hashlib
from pathlib import Path
import pytest
from pydantic import BaseModel
from jarvis.agent.calibration import ConfidenceCalibrator
from jarvis.agent.loop import AgentLoop
from jarvis.agent.planner import DeliberatePlanner
from jarvis.coding.engine import CodePatchTool, NativeCodingAgent
from jarvis.contracts import (
    AuthMode,
    AutonomyLevel,
    DataClass,
    PlanStep,
    PolicyDeniedError,
    RiskTier,
    SpecialistRole,
    TaskRecord,
    TaskState,
    VerificationLevel,
)
from jarvis.evals.self_improve import VerifierExamService
from jarvis.models.gateway import ModelGateway
from jarvis.policy.engine import PolicyEngine
from jarvis.policy.kernel import SafetyKernel
from jarvis.runner.engine import JobRunner
from jarvis.secrets.broker import SecretsBroker
from jarvis.store.db import DatabaseStore


class SampleSchema(BaseModel):
    answer: str
    score: int


def test_model_gateway_d3_routing_oauth_and_schema_repair(tmp_path: Path) -> None:
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    policy = PolicyEngine(kernel)
    secrets = SecretsBroker()
    session = secrets.store_oauth_session(
        "google_gemini", "cid", "ya29.valid_access_token_1234567890", "ref_token", ttl_seconds=3600
    )
    gw = ModelGateway(policy=policy, secrets=secrets)
    gw.configure_oauth_provider(session, "https://generativelanguage.googleapis.com")

    pkce = gw.build_pkce_login_url("https://accounts.google.com/o/oauth2/v2/auth", "cid")
    assert "code_challenge=" in pkce["authorization_url"]

    # D3 restricted data must be blocked when forced to cloud
    with pytest.raises(PolicyDeniedError):
        gw.generate([{"role": "user", "content": "bank csv"}], data_class=DataClass.D3_RESTRICTED_LOCAL, target_provider="cloud")

    # 1-pass JSON schema repair
    gw.queue_scripted_response("NOT VALID JSON")
    gw.queue_scripted_response('{"answer": "repaired", "score": 42}')
    parsed = gw.generate_structured([{"role": "user", "content": "test"}], SampleSchema)
    assert parsed.answer == "repaired" and parsed.score == 42


def test_deliberate_planner_and_nonblocking_dag_loop(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    policy = PolicyEngine(kernel, store)
    runner = JobRunner(store, policy, kernel)
    gw = ModelGateway(policy)
    planner = DeliberatePlanner(gw)
    verifier = VerifierExamService(store, kernel)

    worktree = tmp_path / "worktrees"
    coder = NativeCodingAgent(worktree)
    runner.register_tool(CodePatchTool(coder))

    target_file = worktree / "app.py"
    target_file.write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    pre_sha = hashlib.sha256(target_file.read_bytes()).hexdigest()

    t = store.create_task(
        TaskRecord(
            goal_id="g1",
            objective="Fix bug in app.py and send email",
            risk_tier=RiskTier.R3_CONSEQUENTIAL,
            autonomy_level=AutonomyLevel.A2_COPILOT,
            required_verification=VerificationLevel.V2_INDEPENDENT,
        )
    )
    steps = [
        # Branch A: R3 email step (will park in WAITING_FOR_APPROVAL)
        PlanStep(
            step_id="stp_email",
            index=0,
            description="Send external email",
            tool_name="code.patch",
            tool_args={
                "file_path": str(target_file),
                "expected_sha256": pre_sha,
                "old_text": "return a - b",
                "new_text": "return a + b",
            },
            risk_tier=RiskTier.R3_CONSEQUENTIAL,
            specialist=SpecialistRole.OPERATOR,
        ),
        # Branch B: Independent R1 code patch step (must complete even though Branch A is parked!)
        PlanStep(
            step_id="stp_patch",
            index=1,
            description="Patch app.py",
            tool_name="code.patch",
            tool_args={
                "file_path": str(target_file),
                "expected_sha256": pre_sha,
                "old_text": "return a - b",
                "new_text": "return a + b",
            },
            risk_tier=RiskTier.R1_LOCAL_REVERSIBLE,
            specialist=SpecialistRole.CODER,
        ),
    ]
    plans, selected = planner.build_plans(t, runner.get_registered_tools(), custom_steps=steps)
    assert len(plans) == 3
    assert "[Debate Round 1 -> Round 2 Resolved" in selected.critic_notes
    t = store.update_task(t, t.version)

    loop = AgentLoop(store, runner, planner, verifier)
    parked = loop.run_task(t.task_id)
    assert parked.state == TaskState.WAITING_FOR_APPROVAL
    assert parked.selected_plan.steps[0].completed is False
    assert parked.selected_plan.steps[1].completed is True
    assert "return a + b" in target_file.read_text(encoding="utf-8")
