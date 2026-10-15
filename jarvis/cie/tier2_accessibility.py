"""jarvis/cie/tier2_accessibility.py — Microsoft UFO Dual-OS Windows UIA + macOS AX Tree Driver."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from jarvis.contracts import JarvisError, UIElementNode, current_os_family

ROLE_MAP = {
    "ButtonControl": "button",
    "AXButton": "button",
    "button": "button",
    "EditControl": "textfield",
    "AXTextField": "textfield",
    "textfield": "textfield",
    "AXSecureTextField": "password_field",
    "password_field": "password_field",
}


class AccessibilityDriver:
    def __init__(self, os_override: Optional[str] = None) -> None:
        self.os_family = os_override or current_os_family()
        self._windows: Dict[str, List[UIElementNode]] = {}

    def register_window_elements(self, window_title: str, elements: List[UIElementNode]) -> None:
        normalized: List[UIElementNode] = []
        backend = "windows_uia" if self.os_family == "windows" else ("macos_ax" if self.os_family == "macos" else "headless_mock")
        for el in elements:
            copy_el = el.model_copy(deep=True)
            if copy_el.role == "AXSecureTextField" or "password" in copy_el.name.lower():
                copy_el.is_password = True
            copy_el.role = ROLE_MAP.get(copy_el.role, copy_el.role)
            copy_el.os_backend = backend
            normalized.append(copy_el)
        self._windows[window_title] = normalized

    def dump_tree(self, window_title: str = "") -> List[UIElementNode]:
        nodes: List[UIElementNode] = []
        targets = [self._windows[window_title]] if window_title in self._windows else list(self._windows.values())
        for group in targets:
            for el in group:
                copied = el.model_copy(deep=True)
                if copied.is_password and copied.value:
                    copied.value = "********"
                nodes.append(copied)
        return nodes

    def act_on_node(
        self,
        node_id: str,
        action: str = "invoke",
        value: str = "",
        secret_injected: bool = False,
    ) -> Tuple[UIElementNode, bool]:
        for group in self._windows.values():
            for el in group:
                if el.node_id == node_id:
                    if not el.enabled:
                        raise JarvisError(f"UI node '{node_id}' is disabled")
                    if el.is_password and action == "set_value" and not secret_injected:
                        raise JarvisError("Password fields can only be populated via SecretsBroker injection")
                    el.focused = True
                    if action == "set_value":
                        el.value = "********" if el.is_password else value
                    elif action == "invoke":
                        el.value = "invoked"
                    returned = el.model_copy(deep=True)
                    if returned.is_password:
                        returned.value = "********"
                    return returned, True
        raise JarvisError(f"Accessibility node '{node_id}' not found")
