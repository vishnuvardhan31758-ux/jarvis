from __future__ import annotations

from pathlib import Path
from jarvis.api.server import JarvisDaemonAPI
from jarvis.cie.controller import PCController
from jarvis.desktop.hud import DesktopHUDController
from jarvis.policy.engine import PolicyEngine
from jarvis.policy.kernel import SafetyKernel
from jarvis.remote.gateway import GlobalRemoteGateway
from jarvis.secrets.broker import SecretsBroker
from jarvis.store.db import DatabaseStore
from jarvis.tui.cockpit import TerminalCockpit
from jarvis.voice.pipeline import VoicePipeline


def test_daemon_tui_hud_and_voice_pipeline(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    policy = PolicyEngine(kernel, store)
    secrets = SecretsBroker()
    pc = PCController(store, policy, kernel, allowed_roots=[tmp_path])
    remote = GlobalRemoteGateway(store, kernel, pc_controller=pc)
    daemon = JarvisDaemonAPI(store, kernel, policy, pc_controller=pc, remote_gateway=remote, secrets=secrets)
    tui = TerminalCockpit(daemon, store)
    hud_win = DesktopHUDController(daemon, pc, os_override="windows")
    hud_mac = DesktopHUDController(daemon, pc, os_override="macos")
    voice = VoicePipeline(daemon, policy)

    assert hud_win.get_hud_state()["spotlight_shortcut"] == "Alt+Space"
    assert hud_mac.get_hud_state()["spotlight_shortcut"] == "Cmd+Shift+Space"

    lease = pc.acquire_lease("task_live_1")
    assert hud_win.get_hud_state()["live_control_banner_visible"] is True
    pc.release_lease(lease.lease_id)
    assert hud_win.get_hud_state()["live_control_banner_visible"] is False

    pair_out = tui.handle_slash_command("/pair")
    assert len(pair_out["pairing_code"]) == 6

    # Voice R2/R3 read-back confirmation & R4 HUD step-up routing
    r3_voice = voice.process_utterance("Send email to team", audio_bytes=b"sample1")
    assert r3_voice["status"] == "READBACK_CONFIRMATION_REQUIRED"
    # Replay of same audio bytes is rejected
    replay = voice.process_utterance("Send email to team", audio_bytes=b"sample1")
    assert replay["status"] == "REJECTED_AUDIO_REPLAY"
    # Confirming dispatches the pending R3 command
    confirmed = voice.process_utterance("confirm", audio_bytes=b"sample2")
    assert confirmed["status"] == "CONFIRMED_AND_DISPATCHED"

    r4_voice = voice.process_utterance("Pay invoice 500 USD", audio_bytes=b"sample3")
    assert r4_voice["status"] == "ROUTED_TO_STEP_UP_HUD"
