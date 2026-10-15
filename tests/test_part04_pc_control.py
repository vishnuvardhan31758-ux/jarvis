from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import pytest
from jarvis.cie.controller import PCController
from jarvis.contracts import (
    EmergencyStopActiveError,
    JarvisError,
    PCControllerProtocol,
    StaleObservationError,
    TaskRecord,
    UIElementNode,
    utc_now,
)
from jarvis.policy.engine import PolicyEngine
from jarvis.policy.kernel import SafetyKernel
from jarvis.store.db import DatabaseStore


def test_dual_os_commands_and_trash_restore(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    policy = PolicyEngine(kernel, store)

    pc_win = PCController(store, policy, kernel, allowed_roots=[tmp_path], os_override="windows")
    pc_mac = PCController(store, policy, kernel, allowed_roots=[tmp_path], os_override="macos")
    assert isinstance(pc_win, PCControllerProtocol)

    win_cmd = pc_win.native_os.build_os_app_command("Notepad", "focus")
    mac_cmd = pc_mac.native_os.build_os_app_command("Safari", "focus")
    assert win_cmd[0] == "powershell"
    assert mac_cmd[0] == "osascript"

    f_path, sha = pc_win.native_os.write_file(tmp_path / "doc.txt", "important content")
    trashed = pc_win.native_os.soft_delete(f_path)
    assert not Path(f_path).exists()
    restored = pc_win.native_os.restore_from_trash(trashed["trashed_name"])
    assert Path(restored).read_text(encoding="utf-8") == "important content"


def test_uia_ax_password_masking_and_vision_corner_failsafe(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    policy = PolicyEngine(kernel, store)
    pc = PCController(store, policy, kernel, allowed_roots=[tmp_path], os_override="macos")

    pc.accessibility.register_window_elements(
        "LoginWindow",
        [
            UIElementNode(node_id="btn_ok", role="AXButton", name="Sign In", bbox=(100, 100, 80, 30)),
            UIElementNode(node_id="pwd_1", role="AXSecureTextField", name="Password", value="topsecret", bbox=(100, 50, 120, 30)),
        ],
    )
    dumped = pc.dump_accessibility_tree("LoginWindow")
    pwd_node = [n for n in dumped if n.node_id == "pwd_1"][0]
    assert pwd_node.is_password is True
    assert pwd_node.value == "********"

    # Cannot type plaintext into password field without secret_injected=True
    with pytest.raises(JarvisError):
        pc.accessibility.act_on_node("pwd_1", action="set_value", value=" mypass ", secret_injected=False)

    art, mark_map, obs_at = pc.vision.capture_masked_screenshot("t1", "LoginWindow", dumped)
    _, raw_bytes = store.get_artifact(art.artifact_id)
    assert b"REDACTED_BLACK_BOX" in raw_bytes
    assert b"topsecret" not in raw_bytes

    # Stale observation (>2.0s) raises StaleObservationError
    with pytest.raises(StaleObservationError):
        pc.vision.execute_grounded_action(
            1, mark_map, obs_at - timedelta(seconds=5), "LoginWindow", "LoginWindow"
        )

    # Mouse at (0,0) triggers SafetyKernel emergency stop
    with pytest.raises(EmergencyStopActiveError):
        pc.vision.execute_grounded_action(
            1, mark_map, obs_at, "LoginWindow", "LoginWindow", mouse_pos=(0, 0)
        )
    assert kernel.is_stopped() is True
