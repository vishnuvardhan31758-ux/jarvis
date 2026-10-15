"""jarvis/api/server.py — Local FastAPI & WebSocket Daemon (`jarvisd`)."""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional
from jarvis.contracts import (
    AcceptanceCriterion,
    ApprovalRecord,
    AutonomyLevel,
    DataClass,
    GoalSpec,
    OAuthSession,
    PCControllerProtocol,
    PolicyDeniedError,
    PolicyEngineProtocol,
    RemoteControlProtocol,
    RiskTier,
    SafetyKernelProtocol,
    SecretsBrokerProtocol,
    StoreProtocol,
    TaskRecord,
    VerificationLevel,
    VerifierExamProtocol,
    current_os_family,
    utc_now,
)


class JarvisDaemonAPI:
    def __init__(
        self,
        store: StoreProtocol,
        kernel: SafetyKernelProtocol,
        policy: PolicyEngineProtocol,
        pc_controller: Optional[PCControllerProtocol] = None,
        verifier: Optional[VerifierExamProtocol] = None,
        remote_gateway: Optional[RemoteControlProtocol] = None,
        secrets: Optional[SecretsBrokerProtocol] = None,
        on_run_task: Optional[Callable[[str], TaskRecord]] = None,
        api_token: str = "jarvis_local_token",
        step_up_totp: str = "123456",
    ) -> None:
        self.store = store
        self.kernel = kernel
        self.policy = policy
        self.pc_controller = pc_controller
        self.verifier = verifier
        self.remote_gateway = remote_gateway
        self.secrets = secrets
        self.on_run_task = on_run_task
        self.api_token = api_token
        self.step_up_totp = step_up_totp

    def submit_goal(
        self,
        raw_input: str,
        domain: str = "general",
        autonomy_level: AutonomyLevel = AutonomyLevel.A2_COPILOT,
        mandate_id: Optional[str] = None,
        idem_key: Optional[str] = None,
        source_channel: str = "local_cli",
    ) -> Dict[str, Any]:
        if self.kernel.is_stopped():
            raise PolicyDeniedError("Cannot submit goal while emergency stop is active")

        low = raw_input.lower()
        if any(w in low for w in ("pay", "transfer", "unlock", "disarm")):
            risk = RiskTier.R4_CRITICAL_IRREVERSIBLE
            req_ver = VerificationLevel.V3_HIGH_ASSURANCE
        elif any(w in low for w in ("send email", "merge main")):
            risk = RiskTier.R3_CONSEQUENTIAL
            req_ver = VerificationLevel.V3_HIGH_ASSURANCE
        elif any(w in low for w in ("push", "submit", "invite")):
            risk = RiskTier.R2_EXTERNAL_REVERSIBLE
            req_ver = VerificationLevel.V2_INDEPENDENT
        elif any(w in low for w in ("write", "patch", "edit", "fix", "create")):
            risk = RiskTier.R1_LOCAL_REVERSIBLE
            req_ver = VerificationLevel.V2_INDEPENDENT
        else:
            risk = RiskTier.R0_READ_ONLY
            req_ver = VerificationLevel.V1_STATE_CHECK

        goal = GoalSpec(
            source_channel=source_channel,
            raw_input=raw_input,
            normalized_objective=raw_input.strip(),
            acceptance_criteria=[AcceptanceCriterion(description=f"Complete: {raw_input[:50]}", check_type="file_exists")],
            risk_tier=risk,
            data_class=DataClass.D1_INTERNAL,
            required_verification=req_ver,
            mandate_id=mandate_id,
        )
        self.store.save_goal(goal)

        task = TaskRecord(
            goal_id=goal.goal_id,
            objective=goal.normalized_objective,
            domain=domain,
            risk_tier=risk,
            autonomy_level=autonomy_level,
            required_verification=req_ver,
            acceptance_criteria=goal.acceptance_criteria,
            mandate_id=mandate_id,
        )
        if idem_key:
            claimed_id = self.store.claim_idempotency_key(idem_key, domain, task.task_id)
            if claimed_id != task.task_id:
                existing = self.store.get_task(claimed_id)
                if existing:
                    return {"goal_id": existing.goal_id, "task_id": existing.task_id, "state": existing.state.value, "deduplicated": True}

        self.store.create_task(task, actor=source_channel, reason="goal_submitted")
        return {"goal_id": goal.goal_id, "task_id": task.task_id, "state": task.state.value, "deduplicated": False}

    def decide_approval(
        self,
        approval_id: str,
        approve: bool,
        args_hash: str,
        totp_code: Optional[str] = None,
    ) -> ApprovalRecord:
        apr = self.store.get_approval(approval_id)
        if apr is None:
            raise PolicyDeniedError(f"Approval record '{approval_id}' not found")
        if apr.args_hash != args_hash:
            raise PolicyDeniedError("Approval args_hash mismatch: payload modified since request")
        if approve and (apr.requires_step_up or apr.risk_tier.rank >= 3):
            if totp_code != self.step_up_totp:
                raise PolicyDeniedError("Step-up TOTP verification failed for R3/R4 approval")

        apr.status = "APPROVED" if approve else "DENIED"
        apr.decided_by = "owner"
        apr.decided_at = utc_now()
        self.store.save_approval(apr)
        return apr

    def handle_oauth_callback(
        self,
        provider_name: str,
        client_id: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        ttl_seconds: int = 3600,
    ) -> OAuthSession:
        if self.secrets is None:
            raise PolicyDeniedError("SecretsBroker not configured on daemon")
        return self.secrets.store_oauth_session(
            provider_name=provider_name,
            client_id=client_id,
            access_token=access_token,
            refresh_token=refresh_token,
            ttl_seconds=ttl_seconds,
        )

    def handle_remote_webhook(
        self,
        channel: str,
        external_user_id: str,
        session_token: str,
        text: str,
    ) -> Dict[str, Any]:
        if self.remote_gateway is None:
            raise PolicyDeniedError("GlobalRemoteGateway not configured on daemon")
        return self.remote_gateway.handle_remote_message(
            channel=channel,
            external_user_id=external_user_id,
            session_token=session_token,
            text=text,
        )

    def get_system_status(self) -> Dict[str, Any]:
        audit_ok, bad_row = self.store.verify_audit_chain()
        lease = self.pc_controller.get_active_lease() if self.pc_controller else None
        return {
            "estop_active": self.kernel.is_stopped(),
            "os_family": current_os_family(),
            "audit_chain_valid": audit_ok,
            "corrupted_audit_row": bad_row,
            "active_desktop_lease": lease.model_dump() if lease else None,
            "pending_approvals": len(self.store.list_pending_approvals()),
            "tasks_count": len(self.store.list_tasks()),
        }

    def trigger_emergency_stop(self, reason: str = "User triggered E-Stop") -> Dict[str, Any]:
        self.kernel.emergency_stop(reason=reason, actor="owner")
        return {"estop_active": True, "reason": reason}

    def trigger_emergency_resume(self, confirmation_token: str) -> Dict[str, Any]:
        self.kernel.resume(confirmation_token=confirmation_token, actor="owner")
        return {"estop_active": False}


def create_fastapi_app(daemon: JarvisDaemonAPI) -> Any:
    try:
        from fastapi import FastAPI
    except ImportError:
        return None

    app = FastAPI(title="JARVIS 5.0 Daemon API", version="5.0.0")

    @app.get("/v1/status")
    def get_status() -> Dict[str, Any]:
        return daemon.get_system_status()

    @app.post("/v1/goals")
    def post_goal(payload: Dict[str, Any]) -> Dict[str, Any]:
        return daemon.submit_goal(
            raw_input=str(payload.get("raw_input", "")),
            domain=str(payload.get("domain", "general")),
        )

    @app.post("/v1/emergency-stop")
    def post_estop(payload: Dict[str, Any]) -> Dict[str, Any]:
        return daemon.trigger_emergency_stop(str(payload.get("reason", "API E-Stop")))

    return app
