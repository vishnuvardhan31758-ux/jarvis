"""jarvis/cie/demonstration.py — Watch-Me-Once Demonstration Recorder & Skill Compiler."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple
from jarvis.contracts import RiskTier, SkillManifest, SkillStatus


class DemoRecorder:
    def __init__(self) -> None:
        self._active_demo: Optional[str] = None
        self._events: List[Dict[str, Any]] = []

    def start_recording(self, demo_name: str) -> str:
        self._active_demo = demo_name
        self._events = []
        return demo_name

    def record_event(
        self,
        event_type: str,
        window_title: str,
        node_id: Optional[str] = None,
        value: str = "",
        is_password: bool = False,
    ) -> None:
        safe_val = "{{SECRET_INPUT}}" if is_password else value
        self._events.append(
            {
                "event_type": event_type,
                "window_title": window_title,
                "node_id": node_id,
                "value": safe_val,
            }
        )

    def stop_and_compile(self) -> Tuple[SkillManifest, str, str]:
        name = self._active_demo or "recorded_demo_skill"
        steps_repr = repr(self._events)
        code_body = (
            f"def run_demo_skill(inputs=None):\n"
            f"    trace = {steps_repr}\n"
            f"    return {{'skill': '{name}', 'steps_executed': len(trace), 'trace': trace}}\n"
        )
        test_body = (
            f"from skill import run_demo_skill\n\n"
            f"def test_recorded_demo():\n"
            f"    res = run_demo_skill()\n"
            f"    assert res['steps_executed'] == {len(self._events)}\n"
        )
        manifest = SkillManifest(
            name=name,
            description=f"Compiled from {len(self._events)} user demonstration events",
            allowed_tools=["pc.focus", "pc.click", "pc.type"],
            max_risk_tier=RiskTier.R1_LOCAL_REVERSIBLE,
            status=SkillStatus.CANDIDATE,
            sha256=hashlib.sha256(code_body.encode("utf-8")).hexdigest(),
        )
        self._active_demo = None
        return manifest, code_body, test_body
