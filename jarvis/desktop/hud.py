"""jarvis/desktop/hud.py — Windows & macOS Desktop HUD Overlay & Live PC-Control Banner."""
from __future__ import annotations

from typing import Any, Dict, Optional
from jarvis.api.server import JarvisDaemonAPI
from jarvis.contracts import PCControllerProtocol, current_os_family


class DesktopHUDController:
    def __init__(
        self,
        daemon: JarvisDaemonAPI,
        pc_controller: PCControllerProtocol,
        os_override: Optional[str] = None,
    ) -> None:
        self.daemon = daemon
        self.pc_controller = pc_controller
        self.os_family = os_override or current_os_family()
        self.spotlight_shortcut = "Cmd+Shift+Space" if self.os_family == "macos" else "Alt+Space"
        self.spotlight_open: bool = False

    def get_hud_state(self) -> Dict[str, Any]:
        lease = self.pc_controller.get_active_lease()
        estop = self.daemon.kernel.is_stopped()
        live_banner = bool(lease is not None and not estop)
        banner_text = (
            f"🟢 JARVIS CONTROLLING DESKTOP (Task {lease.task_id}) — Move Mouse to Top-Left (0,0) or Press ESC to Stop"
            if (live_banner and lease is not None)
            else ""
        )
        return {
            "os_family": self.os_family,
            "spotlight_shortcut": self.spotlight_shortcut,
            "spotlight_open": self.spotlight_open,
            "live_control_banner_visible": live_banner,
            "banner_text": banner_text,
            "estop_active": estop,
        }

    def toggle_spotlight_bar(self) -> bool:
        self.spotlight_open = not self.spotlight_open
        return self.spotlight_open

    def submit_from_spotlight(self, text: str) -> Dict[str, Any]:
        res = self.daemon.submit_goal(text, source_channel="desktop_hud")
        if self.daemon.on_run_task:
            t = self.daemon.on_run_task(res["task_id"])
            res["state"] = t.state.value
        return res

    def press_panic_button(self) -> Dict[str, Any]:
        lease = self.pc_controller.get_active_lease()
        if lease:
            self.pc_controller.release_lease(lease.lease_id)
        return self.daemon.trigger_emergency_stop("Desktop HUD Panic Button pressed")


class NativeDesktopHUDWindow:
    def __init__(self, hud_controller: DesktopHUDController) -> None:
        self.hud = hud_controller

    def build_window_spec(self) -> Dict[str, Any]:
        state = self.hud.get_hud_state()
        return {
            "title": "J.A.R.V.I.S. 5.0 — Desktop HUD Overlay",
            "always_on_top": True,
            "frameless_overlay": True,
            "os_family": state["os_family"],
            "hotkey": state["spotlight_shortcut"],
            "banner_visible": state["live_control_banner_visible"],
            "banner_text": state["banner_text"] or "🟢 J.A.R.V.I.S. 5.0 ARMED — Press Spotlight Shortcut to Command",
            "panic_button_label": "🛑 EMERGENCY STOP (KILL)",
            "theme": {
                "background": "#0B0F19",
                "accent_cyan": "#00F0FF",
                "danger_red": "#FF2A54",
                "emerald_ok": "#10B981",
            },
        }

    def launch_gui(self, headless_check: bool = True) -> Dict[str, Any]:
        spec = self.build_window_spec()
        if headless_check:
            return {"launched": False, "mode": "headless_verified", "spec": spec}
        try:
            import tkinter as tk
            root = tk.Tk()
            root.title(spec["title"])
            root.attributes("-topmost", True)
            root.configure(bg=spec["theme"]["background"])
            root.geometry("680x140+300+40")
            lbl = tk.Label(
                root,
                text=spec["banner_text"],
                fg=spec["theme"]["accent_cyan"],
                bg=spec["theme"]["background"],
                font=("Consolas", 11, "bold"),
            )
            lbl.pack(pady=8)
            entry = tk.Entry(root, width=64, font=("Consolas", 12))
            entry.pack(pady=4)

            def _on_submit(_event: Any = None) -> None:
                val = entry.get().strip()
                if val:
                    self.hud.submit_from_spotlight(val)
                    entry.delete(0, tk.END)

            entry.bind("<Return>", _on_submit)
            btn = tk.Button(
                root,
                text=spec["panic_button_label"],
                bg=spec["theme"]["danger_red"],
                fg="white",
                command=lambda: (self.hud.press_panic_button(), root.destroy()),
            )
            btn.pack(pady=4)
            root.mainloop()
            return {"launched": True, "mode": "tkinter_gui", "spec": spec}
        except Exception as exc:
            return {"launched": False, "mode": f"fallback:{exc}", "spec": spec}
