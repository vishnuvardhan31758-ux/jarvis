"""jarvis/main.py — Unified CLI Entrypoint (`jarvis up/tui/desktop/pair/oauth-login/run/exam/kill/doctor`)."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional
from jarvis.container import JarvisContainer
from jarvis.contracts import ImmutableTargetError


def main(argv: Optional[List[str]] = None, data_dir: str | Path = "data") -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    cmd = args[0] if args else "status"
    container = JarvisContainer(data_dir=data_dir)

    if cmd in {"up", "tui", "status"}:
        print(container.tui.render_dashboard_text())
        return 0

    if cmd == "desktop":
        print("DESKTOP_HUD_STATE:", container.hud.get_hud_state())
        return 0

    if cmd == "pair":
        code = container.remote_gateway.generate_pairing_code()
        print(f"PAIRING_CODE: {code}")
        return 0

    if cmd == "oauth-login":
        provider = args[1] if len(args) > 1 else "google_gemini"
        client_id = args[2] if len(args) > 2 else "jarvis_client"
        access_tok = args[3] if len(args) > 3 else "ya29.default_token_1234567890abcdef"
        refresh_tok = args[4] if len(args) > 4 else "ref_default_token"
        session = container.daemon.handle_oauth_callback(provider, client_id, access_tok, refresh_tok)
        print(f"OAUTH_CONNECTED: {session.provider_name} (expires={session.expires_at.isoformat()})")
        return 0

    if cmd == "run":
        goal_text = " ".join(args[1:]) or "Verify system status"
        sub = container.daemon.submit_goal(goal_text, source_channel="local_cli")
        task = container.agent_loop.run_task(sub["task_id"])
        ver = container.store.get_latest_verification(task.task_id)
        refls = container.store.list_reflections(task.domain, limit=1)
        print(f"TASK_ID: {task.task_id}")
        print(f"FINAL_STATE: {task.state.value}")
        print(f"SELECTED_PLAN: {task.selected_plan.strategy_name if task.selected_plan else 'none'}")
        print(f"VERIFICATION_LEVEL: {ver.level_achieved.value if ver else 'none'}")
        print(f"REFLECTION: {refls[0].reusable_lesson if refls else 'none'}")
        return 0

    if cmd == "exam":
        scorecard = container.verifier.run_capability_exam(quick=("--quick" in args))
        print(f"CAPABILITY_LEVEL: {scorecard.assigned_level.value} ({scorecard.overall_score:.1%})")
        for track, sc in scorecard.track_scores.items():
            print(f"  - {track}: {sc:.1%}")
        return 0

    if cmd == "kill":
        reason = " ".join(args[1:]) or "CLI kill switch"
        container.daemon.trigger_emergency_stop(reason)
        print("EMERGENCY_STOP_ACTIVE")
        return 0

    if cmd == "doctor":
        audit_ok, _ = container.store.verify_audit_chain()
        canary_ok = container.verifier.run_canary()
        immut_ok = False
        try:
            container.kernel.assert_immutable_path("jarvis/contracts.py")
        except ImmutableTargetError:
            immut_ok = True
        assert audit_ok and canary_ok and immut_ok, "Doctor check failed!"
        print("DOCTOR_ALL_CHECKS_PASSED")
        return 0

    if cmd == "telemetry":
        print("SYSTEM_TELEMETRY:", container.builtin_skills.system_telemetry_diagnostics())
        return 0

    if cmd == "audit-repo":
        target = args[1] if len(args) > 1 else "."
        print("REPO_FORENSICS:", container.builtin_skills.git_repository_forensics(target))
        return 0

    if cmd == "hud-window":
        print("HUD_WINDOW:", container.hud_window.launch_gui(headless_check=("--live" not in args)))
        return 0

    print(f"Unknown command: {cmd}")
    return 1


def cli_entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    cli_entrypoint()
