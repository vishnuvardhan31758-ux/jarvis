"""jarvis/secrets/sandbox.py — OpenHands/SWE-agent 40-Line ACI Viewport & Process-Group Sandbox."""
from __future__ import annotations

import os
import re
import signal
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple
from jarvis.contracts import (
    DataClass,
    EmergencyStopActiveError,
    EvidenceRecord,
    PolicyDeniedError,
    RiskTier,
    SafetyKernelProtocol,
    SandboxRunnerProtocol,
    StoreProtocol,
    TaskRecord,
    current_os_family,
    redact_secrets,
)

R4_CMD_PATTERNS = [
    re.compile(r"rm\s+-rf\s+/(?:\s|$)"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\s+if="),
    re.compile(r":\(\)\{"),
    re.compile(r"(?:curl|wget)\s+[^|]+\|\s*(?:ba)?sh"),
    re.compile(r"(?i)Format-Volume"),
    re.compile(r"(?i)Remove-Item.*-Recurse.*C:\\"),
]

R3_CMD_PATTERNS = [
    re.compile(r"git\s+push\s+.*--force"),
    re.compile(r"chmod\s+-R\s+777"),
    re.compile(r"\bsudo\s+"),
    re.compile(r"rm\s+-rf\b"),
]

R1_CMD_PATTERNS = [
    re.compile(r"^(?:pytest|python|python3|git\s+status|git\s+diff|ls|dir|echo)\b"),
]


class SandboxRunner:
    def __init__(
        self,
        kernel: SafetyKernelProtocol,
        store: StoreProtocol,
        allowed_roots: Optional[List[str | Path]] = None,
    ) -> None:
        self.kernel = kernel
        self.store = store
        self.allowed_roots = [Path(r).resolve() for r in (allowed_roots or [Path.cwd()])]

    def classify_command(self, cmd: str) -> RiskTier:
        clean = cmd.strip()
        for pat in R4_CMD_PATTERNS:
            if pat.search(clean):
                return RiskTier.R4_CRITICAL_IRREVERSIBLE
        for pat in R3_CMD_PATTERNS:
            if pat.search(clean):
                return RiskTier.R3_CONSEQUENTIAL
        for pat in R1_CMD_PATTERNS:
            if pat.search(clean):
                return RiskTier.R1_LOCAL_REVERSIBLE
        return RiskTier.R2_EXTERNAL_REVERSIBLE

    def format_aci_output(self, exit_code: int, stdout: str, stderr: str, max_lines: int = 40) -> str:
        clean_out = redact_secrets(stdout)
        clean_err = redact_secrets(stderr)
        combined = clean_out + (f"\n[STDERR]\n{clean_err}" if clean_err.strip() else "")
        lines = combined.splitlines()
        if len(lines) > max_lines:
            half = max_lines // 2
            elided = len(lines) - max_lines
            body = "\n".join(
                lines[:half]
                + [f"... [{elided} lines elided by ACI viewport; full log stored in artifact] ..."]
                + lines[-half:]
            )
        else:
            body = "\n".join(lines)
        return f"[ACI exit={exit_code}]\n{body}"

    def _assert_cwd_allowed(self, cwd: str) -> Path:
        resolved = Path(cwd).resolve()
        for root in self.allowed_roots:
            try:
                resolved.relative_to(root)
                return resolved
            except ValueError:
                continue
        raise PolicyDeniedError(f"Working directory '{cwd}' is outside allowed sandbox roots")

    def run_cmd(
        self,
        cmd: List[str],
        cwd: str,
        task: TaskRecord,
        timeout_seconds: int = 60,
        allow_network: bool = False,
    ) -> Tuple[int, str, str, EvidenceRecord]:
        if self.kernel.is_stopped():
            raise EmergencyStopActiveError("Emergency stop active")
        safe_cwd = self._assert_cwd_allowed(cwd)
        joined = " ".join(cmd)
        if self.classify_command(joined) == RiskTier.R4_CRITICAL_IRREVERSIBLE:
            raise PolicyDeniedError(f"Blocked R4 destructive shell command: {joined}")

        os_fam = current_os_family()
        popen_kwargs: dict = {
            "cwd": str(safe_cwd),
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
        }
        if os_fam == "windows":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_kwargs["start_new_session"] = True

        proc = subprocess.Popen(cmd, **popen_kwargs)
        self.kernel.register_pid(proc.pid)
        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            try:
                if os_fam == "windows":
                    proc.kill()
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            proc.communicate()
            raise TimeoutError(f"Command timed out after {timeout_seconds}s: {joined}") from exc
        finally:
            self.kernel.unregister_pid(proc.pid)

        clean_out = redact_secrets(stdout)
        clean_err = redact_secrets(stderr)
        aci_text = self.format_aci_output(proc.returncode, clean_out, clean_err)
        art = self.store.put_artifact(
            (clean_out + "\n" + clean_err).encode("utf-8"),
            media_type="text/plain",
            data_class=DataClass.D1_INTERNAL,
            task_id=task.task_id,
        )
        ev = EvidenceRecord(
            task_id=task.task_id,
            source_type="command_output",
            content_summary=aci_text,
            artifact_id=art.artifact_id,
            sha256=art.sha256,
        )
        self.store.save_evidence(ev)
        return proc.returncode, clean_out, clean_err, ev
