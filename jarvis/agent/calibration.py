"""jarvis/agent/calibration.py — Epistemic Confidence Calibrator."""
from __future__ import annotations

from typing import List, Optional
from jarvis.contracts import PostMortemReflection, TaskState

AMBIGUOUS_TRIGGERS = (
    "that file",
    "do it to them",
    "send it to him",
    "send it to her",
    "the usual place",
    "fix that thing",
)


class ConfidenceCalibrator:
    def calibrate(
        self,
        raw_input: str,
        available_tools: List[str],
        past_reflections: Optional[List[PostMortemReflection]] = None,
        model_self_score: float = 0.8,
    ) -> float:
        score = 0.50
        if available_tools:
            score += 0.20
        score += min(0.30, max(0.0, float(model_self_score)) * 0.30)

        low = raw_input.lower()
        has_concrete_anchor = ("/" in raw_input) or ("\\" in raw_input) or ("@" in raw_input) or ("http" in low)
        if any(trig in low for trig in AMBIGUOUS_TRIGGERS) and not has_concrete_anchor:
            score -= 0.25

        if past_reflections:
            succ = sum(1 for r in past_reflections if r.outcome == TaskState.SUCCEEDED)
            fail = sum(1 for r in past_reflections if r.outcome == TaskState.FAILED)
            if succ > fail:
                score += 0.10
            elif fail > succ:
                score -= 0.10

        return round(max(0.05, min(0.99, score)), 4)
