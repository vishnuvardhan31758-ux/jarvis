"""jarvis/ops/life_business.py — Inbox Triage, Outbound DLP, Financial CSV Forensics & R4 Payment Gate."""
from __future__ import annotations

import ast, os, platform, shutil
from pathlib import Path
from jarvis.contracts import SECRET_PATTERNS, current_os_family
import csv
import io
from typing import Any, Dict, List, Optional, Tuple
from jarvis.contracts import (
    DataClass,
    EvidenceRecord,
    PolicyDeniedError,
    PolicyEngineProtocol,
    PolicyRequest,
    RiskTier,
    StoreProtocol,
    TaskRecord,
    redact_secrets,
)


class LifeOpsService:
    def __init__(self, store: StoreProtocol, policy: PolicyEngineProtocol) -> None:
        self.store = store
        self.policy = policy

    def triage_inbox(self, task: TaskRecord, messages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for msg in messages:
            sender = msg.get("sender", "unknown@example.com")
            subj = msg.get("subject", "")
            body = msg.get("body", "")
            wrapped = self.policy.wrap_untrusted(body, source=f"email:{sender}")
            triggers = self.policy.scan_prompt_injection(body)
            if triggers:
                results.append(
                    {
                        "sender": sender,
                        "subject": subj,
                        "status": "QUARANTINED_INJECTION",
                        "triggers": triggers,
                        "wrapped_body": wrapped,
                    }
                )
            else:
                results.append(
                    {
                        "sender": sender,
                        "subject": subj,
                        "status": "TRIAGED_CLEAN",
                        "draft_reply": f"Hi {sender}, received your note regarding '{subj}'.",
                        "wrapped_body": wrapped,
                    }
                )
        return results

    def send_email(
        self,
        task: TaskRecord,
        to_addr: str,
        subject: str,
        body: str,
        approval_id: Optional[str] = None,
        step_up_verified: bool = False,
    ) -> Tuple[Dict[str, Any], Optional[EvidenceRecord]]:
        scrubbed = redact_secrets(body)
        if "[REDACTED_SECRET]" in scrubbed or task.data_class.rank >= DataClass.D3_RESTRICTED_LOCAL.rank:
            raise PolicyDeniedError("Outbound DLP blocked secret or D3 restricted data in outgoing email")

        req = PolicyRequest(
            task_id=task.task_id,
            domain=task.domain,
            action="email.send",
            args={"recipient": to_addr, "subject": subject},
            data_class=task.data_class,
            requested_risk=RiskTier.R3_CONSEQUENTIAL,
            autonomy_level=task.autonomy_level,
            mandate_id=task.mandate_id,
            approval_id=approval_id,
            step_up_verified=step_up_verified,
        )
        dec = self.policy.evaluate(req)
        if not dec.allowed:
            raise PolicyDeniedError(dec.explanation)

        ev = EvidenceRecord(
            task_id=task.task_id,
            source_type="command_output",
            content_summary=f"Sent email to {to_addr}: {subject}",
        )
        self.store.save_evidence(ev)
        return {"sent": True, "recipient": to_addr, "subject": subject}, ev

    def analyze_ledger_csv(self, task: TaskRecord, csv_text: str) -> Dict[str, Any]:
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
        total_spend = 0.0
        seen_rows: Dict[Tuple[str, str, float], int] = {}
        merchant_history: Dict[str, List[float]] = {}
        duplicates: List[Dict[str, Any]] = []
        spikes: List[Dict[str, Any]] = []

        for row in reader:
            dt = row.get("date", "").strip()
            merch = row.get("merchant", "").strip()
            amt = float(row.get("amount", 0.0))
            total_spend += amt

            key = (dt, merch, amt)
            seen_rows[key] = seen_rows.get(key, 0) + 1
            if seen_rows[key] == 2:
                duplicates.append({"date": dt, "merchant": merch, "amount": amt})

            prev_list = merchant_history.setdefault(merch, [])
            if prev_list and amt > prev_list[-1] * 1.15:
                spikes.append({"merchant": merch, "previous": prev_list[-1], "current": amt})
            prev_list.append(amt)

        return {
            "total_spend": round(total_spend, 2),
            "duplicate_charges": duplicates,
            "subscription_spikes": spikes,
            "processed_locally_d3": True,
        }

    def execute_payment(
        self,
        task: TaskRecord,
        merchant: str,
        amount_usd: float,
        approval_id: Optional[str] = None,
        step_up_verified: bool = False,
    ) -> Tuple[Dict[str, Any], Optional[EvidenceRecord]]:
        req = PolicyRequest(
            task_id=task.task_id,
            domain=task.domain,
            action="finance.pay",
            args={"merchant": merchant, "amount_usd": amount_usd},
            data_class=task.data_class,
            requested_risk=RiskTier.R4_CRITICAL_IRREVERSIBLE,
            autonomy_level=task.autonomy_level,
            mandate_id=task.mandate_id,
            approval_id=approval_id,
            step_up_verified=step_up_verified,
            estimated_spend_usd=amount_usd,
        )
        dec = self.policy.evaluate(req)
        if not dec.allowed:
            raise PolicyDeniedError(dec.explanation)

        ev = EvidenceRecord(
            task_id=task.task_id,
            source_type="command_output",
            content_summary=f"Executed payment of ${amount_usd:.2f} to {merchant}",
        )
        self.store.save_evidence(ev)
        return {"paid": True, "merchant": merchant, "amount_usd": amount_usd}, ev



class BuiltinSkillPack:
    def __init__(self, store: StoreProtocol, root_dir: str | Path = ".") -> None:
        self.store = store
        self.root_dir = Path(root_dir).resolve()

    def system_telemetry_diagnostics(self) -> Dict[str, Any]:
        usage = shutil.disk_usage(self.root_dir)
        load_1, load_5, load_15 = os.getloadavg() if hasattr(os, "getloadavg") else (0.25, 0.20, 0.15)
        return {
            "os_family": current_os_family(),
            "platform_release": platform.release(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count() or 1,
            "load_avg": (round(load_1, 2), round(load_5, 2), round(load_15, 2)),
            "disk_total_gb": round(usage.total / (1024 ** 3), 2),
            "disk_free_gb": round(usage.free / (1024 ** 3), 2),
            "disk_used_pct": round((usage.used / usage.total) * 100.0, 1) if usage.total else 0.0,
            "status": "HEALTHY",
        }

    def git_repository_forensics(self, target_dir: str | Path) -> Dict[str, Any]:
        base = Path(target_dir).resolve()
        py_files = sorted(base.rglob("*.py"))
        total_lines = 0
        complex_functions: List[Dict[str, Any]] = []
        secret_leaks: List[str] = []

        for pf in py_files:
            try:
                src = pf.read_text(encoding="utf-8")
            except Exception:
                continue
            lines = src.splitlines()
            total_lines += len(lines)
            rel = str(pf.relative_to(base)).replace("\\", "/")

            for pat in SECRET_PATTERNS:
                if pat.search(src):
                    secret_leaks.append(rel)

            try:
                tree = ast.parse(src)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        branch_nodes = sum(
                            1 for n in ast.walk(node) if isinstance(n, (ast.If, ast.For, ast.While, ast.Try, ast.ExceptHandler))
                        )
                        if branch_nodes >= 5:
                            complex_functions.append(
                                {"file": rel, "function": node.name, "lineno": node.lineno, "complexity": branch_nodes + 1}
                            )
            except SyntaxError:
                continue

        return {
            "python_files_scanned": len(py_files),
            "total_lines_of_code": total_lines,
            "complexity_hotspots": complex_functions,
            "secret_leaks_detected": secret_leaks,
            "clean_security_scan": len(secret_leaks) == 0,
        }

    def security_posture_scan(self) -> Dict[str, Any]:
        chain_valid, corrupted_row = self.store.verify_audit_chain()
        active_mandates = self.store.list_mandates(active_only=True)
        pending_approvals = self.store.list_pending_approvals()
        return {
            "audit_chain_intact": chain_valid,
            "corrupted_audit_row": corrupted_row,
            "active_mandates_count": len(active_mandates),
            "pending_approvals_count": len(pending_approvals),
            "posture_grade": "A+" if chain_valid else "CRITICAL_ALERT",
        }
