"""jarvis/tui/cockpit.py — Interactive Full-Screen Terminal Cockpit (`jarvis tui`)."""
from __future__ import annotations

from typing import Any, Dict, Optional
from jarvis.api.server import JarvisDaemonAPI
from jarvis.contracts import StoreProtocol


class TerminalCockpit:
    def __init__(self, daemon: JarvisDaemonAPI, store: StoreProtocol) -> None:
        self.daemon = daemon
        self.store = store

    def render_dashboard_text(self, active_task_id: Optional[str] = None) -> str:
        st = self.daemon.get_system_status()
        kernel_badge = "🛑 ESTOP" if st["estop_active"] else "🟢 ARMED"
        audit_badge = "OK" if st["audit_chain_valid"] else "TAMPERED"
        lease_badge = "HELD" if st["active_desktop_lease"] else "FREE"

        lines = [
            "================================================================================",
            f" JARVIS 5.0 TERMINAL COCKPIT | Kernel: {kernel_badge} | OS: {st['os_family'].upper()} | Audit: {audit_badge} | Lease: {lease_badge} | Approvals: {st['pending_approvals']}",
            "================================================================================",
        ]

        task = self.store.get_task(active_task_id) if active_task_id else (self.store.list_tasks(limit=1)[0] if self.store.list_tasks(limit=1) else None)
        if task:
            lines.append(f"[ACTIVE TASK] {task.task_id} | State: {task.state.value} | Risk: {task.risk_tier.value} | Confidence: {task.calibrated_confidence:.0%}")
            lines.append(f"  Objective: {task.objective}")
            if task.candidate_plans:
                lines.append("  [DELIBERATE REASONING CANDIDATE PLANS]")
                for p in task.candidate_plans:
                    sel = " *SELECTED*" if (task.selected_plan and task.selected_plan.plan_id == p.plan_id) else ""
                    lines.append(f"    - {p.strategy_name} (Critic: {p.critic_score:.2f}){sel}: {p.summary}")
            ver = self.store.get_latest_verification(task.task_id)
            if ver:
                lines.append(f"  [VERIFICATION RECEIPT] Level: {ver.level_achieved.value} | Disposition: {ver.disposition.value} | Checks Run: {ver.checks_run}")
        else:
            lines.append("[NO ACTIVE TASKS] Type /run <goal> to launch an autonomous task.")

        pending = self.store.list_pending_approvals()
        if pending:
            lines.append("--------------------------------------------------------------------------------")
            lines.append("[NON-BLOCKING APPROVAL QUEUE]")
            for apr in pending:
                step_tag = " [STEP-UP TOTP REQUIRED]" if apr.requires_step_up else ""
                lines.append(f"  * {apr.approval_id} | Action: {apr.action} ({apr.risk_tier.value}){step_tag} | Hash: {apr.args_hash[:12]}")

        lines.append("================================================================================")
        return "\n".join(lines)

    def handle_slash_command(self, cmd_line: str) -> Dict[str, Any]:
        cmd = cmd_line.strip()
        if cmd == "/status":
            return self.daemon.get_system_status()
        if cmd == "/tasks":
            return {"tasks": [t.model_dump() for t in self.store.list_tasks()]}
        if cmd.startswith("/plan "):
            tid = cmd.split(maxsplit=1)[1].strip()
            t = self.store.get_task(tid)
            return {"task_id": tid, "plans": [p.model_dump() for p in (t.candidate_plans if t else [])]}
        if cmd.startswith("/approve "):
            parts = cmd.split()
            apr_id = parts[1]
            args_hash = parts[2]
            totp = parts[3] if len(parts) > 3 else None
            apr = self.daemon.decide_approval(apr_id, True, args_hash, totp_code=totp)
            return {"status": apr.status, "approval_id": apr.approval_id}
        if cmd.startswith("/deny "):
            parts = cmd.split()
            apr_id = parts[1]
            args_hash = parts[2]
            apr = self.daemon.decide_approval(apr_id, False, args_hash)
            return {"status": apr.status, "approval_id": apr.approval_id}
        if cmd == "/pair":
            if self.daemon.remote_gateway is None:
                return {"error": "Remote gateway not configured"}
            code = self.daemon.remote_gateway.generate_pairing_code()
            return {"status": "PAIRING_CODE_GENERATED", "pairing_code": code}
        if cmd.startswith("/kill"):
            reason = cmd[5:].strip() or "TUI /kill command"
            return self.daemon.trigger_emergency_stop(reason)
        if cmd.startswith("/resume "):
            token = cmd.split(maxsplit=1)[1].strip()
            return self.daemon.trigger_emergency_resume(token)
        if cmd.startswith("/run "):
            goal_text = cmd[5:].strip()
            sub = self.daemon.submit_goal(goal_text, source_channel="tui")
            if self.daemon.on_run_task:
                t = self.daemon.on_run_task(sub["task_id"])
                sub["state"] = t.state.value
            return sub
        return {"error": f"Unknown slash command: {cmd}"}
