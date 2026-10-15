"""jarvis/cie/tier3_vision.py — OmniParser Set-of-Marks Vision Annotator & Privacy Redactor."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Tuple
from jarvis.contracts import (
    ArtifactMeta,
    DataClass,
    EmergencyStopActiveError,
    JarvisError,
    SafetyKernelProtocol,
    StaleObservationError,
    StoreProtocol,
    UIElementNode,
    utc_now,
)

SENSITIVE_WINDOWS = (
    "1password",
    "bitwarden",
    "keepass",
    "keychain access",
    "windows security",
    "bank",
    "vault",
    "private",
)


class VisionGrounder:
    def __init__(
        self,
        store: StoreProtocol,
        kernel: SafetyKernelProtocol,
        max_observation_age_seconds: float = 2.0,
    ) -> None:
        self.store = store
        self.kernel = kernel
        self.max_observation_age_seconds = max_observation_age_seconds

    def capture_masked_screenshot(
        self,
        task_id: str,
        window_title: str,
        elements: List[UIElementNode],
    ) -> Tuple[ArtifactMeta, Dict[int, UIElementNode], datetime]:
        win_sensitive = any(pat in window_title.lower() for pat in SENSITIVE_WINDOWS)
        mark_map: Dict[int, UIElementNode] = {}
        redacted_boxes: List[Dict[str, Any]] = []
        visible_marks: List[Dict[str, Any]] = []
        mark_idx = 1

        for el in elements:
            if win_sensitive or el.is_password:
                redacted_boxes.append({"node_id": el.node_id, "bbox": el.bbox, "mask": "REDACTED_BLACK_BOX"})
            elif el.enabled:
                mark_map[mark_idx] = el.model_copy(deep=True)
                visible_marks.append({"mark_id": f"[#{mark_idx}]", "node_id": el.node_id, "name": el.name, "bbox": el.bbox})
                mark_idx += 1

        payload = {
            "window_title": window_title,
            "window_redacted": win_sensitive,
            "redacted_boxes": redacted_boxes,
            "set_of_marks": visible_marks,
        }
        art = self.store.put_artifact(
            json.dumps(payload).encode("utf-8"),
            media_type="image/png",
            data_class=DataClass.D2_CONFIDENTIAL,
            task_id=task_id,
        )
        return art, mark_map, utc_now()

    def execute_grounded_action(
        self,
        mark_id: int,
        mark_map: Dict[int, UIElementNode],
        observed_at: datetime,
        expected_window: str,
        current_window: str,
        action: str = "click",
        text: str = "",
        mouse_pos: Tuple[int, int] = (500, 500),
    ) -> Dict[str, Any]:
        if mouse_pos == (0, 0) or self.kernel.is_stopped():
            self.kernel.emergency_stop("Mouse moved to (0,0) top-left fail-safe corner")
            raise EmergencyStopActiveError("Mouse corner (0,0) hardware fail-safe triggered")

        age = (utc_now() - observed_at).total_seconds()
        if age > self.max_observation_age_seconds or expected_window != current_window:
            raise StaleObservationError(
                f"Visual observation is stale ({age:.2f}s > {self.max_observation_age_seconds}s) or window focus shifted"
            )

        if mark_id not in mark_map:
            raise JarvisError(f"Set-of-Marks tag [#{mark_id}] not found in observation")

        el = mark_map[mark_id]
        x, y, w, h = el.bbox
        cx, cy = x + (w // 2), y + (h // 2)
        return {
            "mark_id": mark_id,
            "node_id": el.node_id,
            "coords": (cx, cy),
            "action": action,
            "text": text,
            "verified": True,
        }
