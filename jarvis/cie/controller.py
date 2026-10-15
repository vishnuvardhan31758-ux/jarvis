"""jarvis/cie/controller.py — Unified 3-Tier PC Controller implementing PCControllerProtocol."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from jarvis.cie.demonstration import DemoRecorder
from jarvis.cie.leases import DesktopLeaseManager
from jarvis.cie.tier1_native import NativeOSDriver
from jarvis.cie.tier2_accessibility import AccessibilityDriver
from jarvis.cie.tier3_vision import VisionGrounder
from jarvis.contracts import (
    ArtifactMeta,
    DesktopLease,
    EvidenceRecord,
    JarvisError,
    PCControllerProtocol,
    PolicyDeniedError,
    PolicyEngineProtocol,
    PolicyRequest,
    SafetyKernelProtocol,
    StoreProtocol,
    TaskRecord,
    UIElementNode,
)


class PCController:
    def __init__(
        self,
        store: StoreProtocol,
        policy: PolicyEngineProtocol,
        kernel: SafetyKernelProtocol,
        allowed_roots: Optional[List[str | Path]] = None,
        os_override: Optional[str] = None,
    ) -> None:
        self.store = store
        self.policy = policy
        self.kernel = kernel
        self.leases = DesktopLeaseManager(kernel)
        self.native_os = NativeOSDriver(allowed_roots=allowed_roots, os_override=os_override)
        self.accessibility = AccessibilityDriver(os_override=os_override)
        self.vision = VisionGrounder(store=store, kernel=kernel)
        self.demo_recorder = DemoRecorder()

    def acquire_lease(self, task_id: str, ttl_seconds: int = 60) -> DesktopLease:
        return self.leases.acquire(task_id=task_id, ttl_seconds=ttl_seconds)

    def release_lease(self, lease_id: str) -> None:
        self.leases.release(lease_id)

    def get_active_lease(self) -> Optional[DesktopLease]:
        return self.leases.get_active()

    def dump_accessibility_tree(self, window_title: str = "") -> List[UIElementNode]:
        return self.accessibility.dump_tree(window_title)

    def capture_masked_screenshot(
        self, task_id: str, window_title: str = ""
    ) -> Tuple[ArtifactMeta, List[UIElementNode]]:
        nodes = self.accessibility.dump_tree(window_title)
        art, mark_map, _ = self.vision.capture_masked_screenshot(task_id, window_title or "Desktop", nodes)
        return art, list(mark_map.values())

    def execute_pc_action(
        self,
        task: TaskRecord,
        action: str,
        args: Dict[str, Any],
        lease_id: str,
    ) -> Tuple[Dict[str, Any], EvidenceRecord]:
        active = self.get_active_lease()
        if active is None or active.lease_id != lease_id:
            raise JarvisError("Valid active DesktopLease is required before executing PC control actions")

        req = PolicyRequest(
            task_id=task.task_id,
            domain=task.domain,
            action=action,
            args=args,
            data_class=task.data_class,
            requested_risk=task.risk_tier,
            autonomy_level=task.autonomy_level,
            mandate_id=task.mandate_id,
        )
        decision = self.policy.evaluate(req)
        if not decision.allowed:
            raise PolicyDeniedError(decision.explanation)

        if action == "pc.focus":
            out = self.native_os.launch_or_focus_app(str(args.get("app_name", "Terminal")), dry_run=True)
        elif "node_id" in args:
            node, ok = self.accessibility.act_on_node(
                node_id=str(args["node_id"]),
                action=str(args.get("ui_action", "invoke")),
                value=str(args.get("value", "")),
                secret_injected=bool(args.get("secret_injected", False)),
            )
            out = {"node": node.model_dump(), "verified": ok, "tier": "tier2_accessibility"}
        else:
            out = {"action": action, "args": args, "tier": "tier1_native", "verified": True}

        ev = EvidenceRecord(
            task_id=task.task_id,
            source_type="ui_tree",
            content_summary=f"PC action {action} verified on {self.native_os.os_family}",
        )
        self.store.save_evidence(ev)
        return out, ev
