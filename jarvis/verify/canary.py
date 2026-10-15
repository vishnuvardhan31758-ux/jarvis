"""jarvis/verify/canary.py — 20-Case Verifier Canary Watchdog."""
from __future__ import annotations

from typing import List, Tuple
from jarvis.contracts import (
    AcceptanceCriterion,
    EvidenceRecord,
    RiskTier,
    TaskRecord,
    VerificationDisposition,
    VerificationLevel,
)
from jarvis.verify.service import VerificationService


class VerifierCanary:
    def _build_fixtures(self) -> Tuple[List[Tuple[TaskRecord, List[EvidenceRecord]]], List[Tuple[TaskRecord, List[EvidenceRecord]]]]:
        known_pass: List[Tuple[TaskRecord, List[EvidenceRecord]]] = []
        known_fail: List[Tuple[TaskRecord, List[EvidenceRecord]]] = []

        for i in range(10):
            t_pass = TaskRecord(
                goal_id=f"g_pass_{i}",
                objective=f"Canary pass case {i}",
                risk_tier=RiskTier.R1_LOCAL_REVERSIBLE,
                required_verification=VerificationLevel.V2_INDEPENDENT,
                acceptance_criteria=[
                    AcceptanceCriterion(description="Tests pass", check_type="pytest_passed")
                ],
            )
            ev_pass = [
                EvidenceRecord(
                    task_id=t_pass.task_id,
                    source_type="command_output",
                    content_summary=f"[ACI exit=0]\n{i + 1} passed in 0.05s",
                )
            ]
            known_pass.append((t_pass, ev_pass))

            t_fail = TaskRecord(
                goal_id=f"g_fail_{i}",
                objective=f"Canary fail case {i}",
                risk_tier=RiskTier.R1_LOCAL_REVERSIBLE,
                required_verification=VerificationLevel.V2_INDEPENDENT,
                acceptance_criteria=[
                    AcceptanceCriterion(description="Tests pass", check_type="pytest_passed")
                ],
            )
            if i % 3 == 0:
                ev_fail: List[EvidenceRecord] = []
            elif i % 3 == 1:
                ev_fail = [
                    EvidenceRecord(
                        task_id=t_fail.task_id,
                        source_type="command_output",
                        content_summary="[ACI exit=0]\n0 passed, 0 collected in 0.01s",
                    )
                ]
            else:
                ev_fail = [
                    EvidenceRecord(
                        task_id=t_fail.task_id,
                        source_type="command_output",
                        content_summary="[ACI exit=1]\n1 failed, 4 passed in 0.12s",
                    )
                ]
            known_fail.append((t_fail, ev_fail))

        return known_pass, known_fail

    def run_canary(self, verifier: VerificationService) -> bool:
        was_degraded = verifier.canary_degraded
        verifier.canary_degraded = False
        known_pass, known_fail = self._build_fixtures()

        for t_p, ev_p in known_pass:
            res = verifier.verify_task(t_p, ev_p)
            if res.disposition != VerificationDisposition.ACCEPT:
                verifier.canary_degraded = True
                return False

        for t_f, ev_f in known_fail:
            res = verifier.verify_task(t_f, ev_f)
            if res.disposition == VerificationDisposition.ACCEPT:
                verifier.canary_degraded = True
                return False

        verifier.canary_degraded = was_degraded and False
        return True
