"""jarvis/verify/service.py — Independent Deterministic & Critic Verification Gate."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional
from jarvis.contracts import (
    EvidenceRecord,
    RiskTier,
    SafetyKernelProtocol,
    StoreProtocol,
    TaskRecord,
    VerificationDisposition,
    VerificationLevel,
    VerificationRecord,
)


class VerificationService:
    def __init__(
        self,
        store: Optional[StoreProtocol] = None,
        kernel: Optional[SafetyKernelProtocol] = None,
    ) -> None:
        self.store = store
        self.kernel = kernel
        self.canary_degraded: bool = False

    def verify_task(self, task: TaskRecord, evidence: List[EvidenceRecord]) -> VerificationRecord:
        if self.canary_degraded and task.risk_tier.rank >= RiskTier.R2_EXTERNAL_REVERSIBLE.rank:
            return VerificationRecord(
                task_id=task.task_id,
                level_achieved=VerificationLevel.V0_CONTRACT,
                disposition=VerificationDisposition.NEEDS_MORE_EVIDENCE,
                checks_not_run=[ac.check_type for ac in task.acceptance_criteria],
                notes="Verifier canary degraded; R2+ auto-acceptance suspended",
            )

        mandatory_criteria = [ac for ac in task.acceptance_criteria if ac.mandatory]
        if mandatory_criteria and len(evidence) == 0:
            return VerificationRecord(
                task_id=task.task_id,
                level_achieved=VerificationLevel.V0_CONTRACT,
                disposition=VerificationDisposition.NEEDS_MORE_EVIDENCE,
                checks_not_run=[ac.check_type for ac in task.acceptance_criteria],
                notes="No evidence records provided for mandatory acceptance criteria",
            )

        if task.risk_tier == RiskTier.R4_CRITICAL_IRREVERSIBLE and self.store is not None:
            approvals = [
                a
                for a in self.store.list_pending_approvals(task.task_id)
                if a.status == "APPROVED" and a.requires_step_up
            ]
            # Also check saved approvals via get_approval if any
            has_approved_r4 = False
            with self.store._connect() as conn:  # type: ignore[attr-defined]
                rows = conn.execute(
                    "SELECT status, payload_json FROM approvals WHERE task_id = ?", (task.task_id,)
                ).fetchall()
                for st, pj in rows:
                    if st == "APPROVED" and '"requires_step_up":true' in pj.replace(" ", "").lower():
                        has_approved_r4 = True
            if not has_approved_r4 and not approvals:
                return VerificationRecord(
                    task_id=task.task_id,
                    level_achieved=VerificationLevel.V0_CONTRACT,
                    disposition=VerificationDisposition.REJECT,
                    notes="R4 task missing approved step-up ApprovalRecord",
                )

        criterion_results: Dict[str, VerificationDisposition] = {}
        checks_run: List[str] = []
        checks_not_run: List[str] = []

        for ac in task.acceptance_criteria:
            ct = ac.check_type
            checks_run.append(ct)
            if ct == "pytest_passed":
                cmd_evs = [e for e in evidence if e.source_type == "command_output"]
                passed_ok = False
                for ev in cmd_evs:
                    summary = ev.content_summary
                    has_exit_0 = ("exit=0" in summary) or ("exit_code=0" in summary)
                    m_pass = re.search(r"(\d+)\s+passed", summary)
                    m_fail = re.search(r"(\d+)\s+failed", summary)
                    pass_cnt = int(m_pass.group(1)) if m_pass else 0
                    fail_cnt = int(m_fail.group(1)) if m_fail else 0
                    if has_exit_0 and pass_cnt > 0 and fail_cnt == 0 and "0 collected" not in summary:
                        passed_ok = True
                        break
                criterion_results[ac.id] = (
                    VerificationDisposition.ACCEPT if passed_ok else VerificationDisposition.REJECT
                )

            elif ct == "file_sha256":
                exp_sha = ac.expected.get("sha256")
                hash_evs = [e for e in evidence if e.source_type == "file_hash" and e.sha256]
                if hash_evs and (exp_sha is None or any(e.sha256 == exp_sha for e in hash_evs)):
                    criterion_results[ac.id] = VerificationDisposition.ACCEPT
                else:
                    criterion_results[ac.id] = VerificationDisposition.REJECT

            elif ct == "file_exists":
                exp_path = ac.expected.get("path")
                if exp_path:
                    p = Path(str(exp_path))
                    ok = p.is_file() and p.stat().st_size > 0
                else:
                    ok = len(evidence) > 0
                criterion_results[ac.id] = (
                    VerificationDisposition.ACCEPT if ok else VerificationDisposition.REJECT
                )

            elif ct == "ui_state":
                ok = any(e.source_type == "ui_tree" for e in evidence)
                criterion_results[ac.id] = (
                    VerificationDisposition.ACCEPT if ok else VerificationDisposition.REJECT
                )

            elif ct == "sources_cited":
                ok = any(e.source_type == "web_source" and bool(e.sha256) for e in evidence)
                criterion_results[ac.id] = (
                    VerificationDisposition.ACCEPT if ok else VerificationDisposition.REJECT
                )

            else:
                ok = len(evidence) > 0
                criterion_results[ac.id] = (
                    VerificationDisposition.ACCEPT if ok else VerificationDisposition.NEEDS_MORE_EVIDENCE
                )

        all_mandatory_accept = all(
            criterion_results.get(ac.id) == VerificationDisposition.ACCEPT for ac in mandatory_criteria
        )

        if all_mandatory_accept:
            if task.risk_tier.rank >= 3:
                level = VerificationLevel.V3_HIGH_ASSURANCE
            elif task.risk_tier.rank >= 1 or any(
                ac.check_type in {"pytest_passed", "file_sha256", "sources_cited"} for ac in task.acceptance_criteria
            ):
                level = VerificationLevel.V2_INDEPENDENT
            else:
                level = VerificationLevel.V1_STATE_CHECK
            disp = VerificationDisposition.ACCEPT
            notes = f"Verified {len(checks_run)} check(s) at {level.value}"
        else:
            level = VerificationLevel.V0_CONTRACT
            disp = VerificationDisposition.REJECT
            notes = "One or more mandatory acceptance criteria failed verification"

        return VerificationRecord(
            task_id=task.task_id,
            level_achieved=level,
            disposition=disp,
            criterion_results=criterion_results,
            evidence_ids=[e.evidence_id for e in evidence],
            checks_run=checks_run,
            checks_not_run=checks_not_run,
            critic_model="deterministic_verifier_v5",
            notes=notes,
        )
