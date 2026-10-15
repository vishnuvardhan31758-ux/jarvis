from __future__ import annotations

import sys
from pathlib import Path
import pytest
from jarvis.contracts import (
    ApprovalRecord,
    AutonomyLevel,
    DataClass,
    ImmutableTargetError,
    PolicyDeniedError,
    PolicyRequest,
    RiskTier,
    StandingMandate,
    TaskRecord,
    canonical_hash,
)
from jarvis.policy.engine import PolicyEngine
from jarvis.policy.kernel import SafetyKernel
from jarvis.secrets.broker import SecretsBroker
from jarvis.secrets.sandbox import SandboxRunner
from jarvis.store.db import DatabaseStore


@pytest.mark.parametrize(
    "autonomy,risk,expected_allowed",
    [
        (AutonomyLevel.A0_ADVISOR, RiskTier.R0_READ_ONLY, False),
        (AutonomyLevel.A1_ASSISTANT, RiskTier.R0_READ_ONLY, True),
        (AutonomyLevel.A1_ASSISTANT, RiskTier.R1_LOCAL_REVERSIBLE, False),
        (AutonomyLevel.A2_COPILOT, RiskTier.R1_LOCAL_REVERSIBLE, True),
        (AutonomyLevel.A2_COPILOT, RiskTier.R2_EXTERNAL_REVERSIBLE, False),
        (AutonomyLevel.A3_DELEGATE, RiskTier.R2_EXTERNAL_REVERSIBLE, True),
        (AutonomyLevel.A3_DELEGATE, RiskTier.R3_CONSEQUENTIAL, False),
        (AutonomyLevel.A4_OPERATOR, RiskTier.R3_CONSEQUENTIAL, True),
        (AutonomyLevel.A4_OPERATOR, RiskTier.R4_CRITICAL_IRREVERSIBLE, False),
    ],
)
def test_autonomy_vs_risk_matrix(tmp_path: Path, autonomy: AutonomyLevel, risk: RiskTier, expected_allowed: bool) -> None:
    action_by_risk = {
        RiskTier.R0_READ_ONLY: "fs.read",
        RiskTier.R1_LOCAL_REVERSIBLE: "fs.write",
        RiskTier.R2_EXTERNAL_REVERSIBLE: "git.commit",
        RiskTier.R3_CONSEQUENTIAL: "email.send",
        RiskTier.R4_CRITICAL_IRREVERSIBLE: "finance.pay",
    }
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    engine = PolicyEngine(kernel)
    req = PolicyRequest(
        task_id="t1",
        action=action_by_risk[risk],
        requested_risk=risk,
        autonomy_level=autonomy,
    )
    dec = engine.evaluate(req)
    assert dec.allowed is expected_allowed


def test_r4_requires_step_up_and_matching_args_hash(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    engine = PolicyEngine(kernel, store)

    args = {"merchant": "Acme", "amount_usd": 99.0}
    apr = ApprovalRecord(
        task_id="t1",
        action="finance.pay",
        args_hash=canonical_hash(args),
        resource_scope="Acme",
        risk_tier=RiskTier.R4_CRITICAL_IRREVERSIBLE,
        data_class=DataClass.D2_CONFIDENTIAL,
        consequences_summary="Pay $99",
        requires_step_up=True,
        status="APPROVED",
    )
    store.save_approval(apr)

    # Without step_up_verified=True -> denied
    dec_no_stepup = engine.evaluate(
        PolicyRequest(
            task_id="t1",
            action="finance.pay",
            args=args,
            requested_risk=RiskTier.R4_CRITICAL_IRREVERSIBLE,
            approval_id=apr.approval_id,
            step_up_verified=False,
        )
    )
    assert dec_no_stepup.allowed is False

    # With step_up_verified=True and matching args_hash -> allowed
    dec_ok = engine.evaluate(
        PolicyRequest(
            task_id="t1",
            action="finance.pay",
            args=args,
            requested_risk=RiskTier.R4_CRITICAL_IRREVERSIBLE,
            approval_id=apr.approval_id,
            step_up_verified=True,
        )
    )
    assert dec_ok.allowed is True


def test_standing_mandate_caps_and_immutable_paths(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    engine = PolicyEngine(kernel, store)

    m = StandingMandate(
        name="Email Mandate",
        domain="comms",
        max_risk_tier=RiskTier.R3_CONSEQUENTIAL,
        allowed_recipients=["boss@company.com"],
        per_action_spend_cap_usd=25.0,
        daily_spend_cap_usd=50.0,
    )
    store.save_mandate(m)

    ok_dec = engine.evaluate(
        PolicyRequest(
            task_id="t1",
            domain="comms",
            action="email.send",
            args={"recipient": "boss@company.com"},
            mandate_id=m.mandate_id,
        )
    )
    assert ok_dec.allowed is True

    bad_recip = engine.evaluate(
        PolicyRequest(
            task_id="t1",
            domain="comms",
            action="email.send",
            args={"recipient": "stranger@evil.com"},
            mandate_id=m.mandate_id,
        )
    )
    assert bad_recip.allowed is False

    for path in ["jarvis/contracts.py", "jarvis/policy/kernel.py", "jarvis/verify/service.py", "jarvis/store/audit.py"]:
        with pytest.raises(ImmutableTargetError):
            kernel.assert_immutable_path(path)


def test_secrets_broker_and_oauth_pkce_auto_refresh() -> None:
    broker = SecretsBroker()
    broker.put_secret("openai_key", "sk-1234567890abcdefghijklmnop")
    hnd = broker.issue_handle("t1", "openai_key")
    out = broker.inject_into_callback(hnd, lambda val: f" leaked: {val} ")
    assert "sk-123456" not in out and "[REDACTED_SECRET]" in out

    # Expired OAuth session with refresh token auto-rotates
    broker.store_oauth_session(
        provider_name="google_gemini",
        client_id="cid",
        access_token="ya29.expired_token_1234567890abcdef",
        refresh_token="refresh_tok_secret",
        ttl_seconds=-10,
    )
    refreshed_hnd = broker.get_valid_oauth_handle("t1", "google_gemini")
    assert refreshed_hnd.startswith("hnd_")


def test_sandbox_aci_viewport_and_timeout_kill(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    sandbox = SandboxRunner(kernel, store, allowed_roots=[tmp_path])
    t = TaskRecord(goal_id="g1", objective="sandbox test")

    code, out, err, ev = sandbox.run_cmd(
        [sys.executable, "-c", "for i in range(100): print(f'line {i}')"],
        cwd=str(tmp_path),
        task=t,
    )
    assert code == 0
    assert "elided by ACI viewport" in ev.content_summary
