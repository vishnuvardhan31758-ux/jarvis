"""jarvis/policy/kernel.py — Model-Free Safety Kernel (.estop.lock & Immutable Core Path Guard)."""
from __future__ import annotations

import json
import os
import signal
import sys
from pathlib import Path
from jarvis.contracts import (
    ImmutableTargetError,
    PolicyDeniedError,
    SafetyKernelProtocol,
    redact_secrets,
    utc_now,
)

IMMUTABLE_CORE_PATHS = {
    "jarvis/contracts.py",
    "jarvis/policy/kernel.py",
    "jarvis/policy/engine.py",
    "jarvis/verify/service.py",
    "jarvis/store/audit.py",
}


class SafetyKernel:
    def __init__(
        self,
        lockfile_path: str | Path = "data/.estop.lock",
        resume_secret: str = "OWNER_STEP_UP_OK",
    ) -> None:
        self._lockfile = Path(lockfile_path)
        self._resume_secret = resume_secret
        self._pids: set[int] = set()
        self._stopped: bool = self._lockfile.exists()

    def emergency_stop(self, reason: str, actor: str = "owner") -> None:
        self._stopped = True
        self._lockfile.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "stopped": True,
            "reason": redact_secrets(reason),
            "actor": actor,
            "timestamp": utc_now().isoformat(),
        }
        with open(self._lockfile, "w", encoding="utf-8") as f:
            json.dump(payload, f)
            f.flush()
            os.fsync(f.fileno())
        for pid in list(self._pids):
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        self._pids.clear()

    def resume(self, confirmation_token: str, actor: str = "owner") -> None:
        if actor != "owner" or confirmation_token != self._resume_secret:
            raise PolicyDeniedError("Invalid owner step-up token for emergency resume")
        if self._lockfile.exists():
            self._lockfile.unlink()
        self._stopped = False

    def is_stopped(self) -> bool:
        return bool(self._stopped or self._lockfile.exists())

    def assert_immutable_path(self, relative_path: str) -> None:
        norm = relative_path.replace("\\", "/").lstrip("./")
        if (
            norm in IMMUTABLE_CORE_PATHS
            or norm.startswith("jarvis/policy/")
            or norm.startswith("jarvis/verify/")
            or norm.endswith("/contracts.py")
            or norm.endswith("/audit.py")
        ):
            raise ImmutableTargetError(
                f"Modification of protected safety/verification core file '{relative_path}' is forbidden"
            )

    def register_pid(self, pid: int) -> None:
        self._pids.add(int(pid))

    def unregister_pid(self, pid: int) -> None:
        self._pids.discard(int(pid))


if __name__ == "__main__":
    k = SafetyKernel()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "stop":
        k.emergency_stop(" ".join(sys.argv[2:]) or "CLI emergency stop")
        print("ESTOP_ENGAGED")
    elif cmd == "resume":
        token = sys.argv[2] if len(sys.argv) > 2 else ""
        k.resume(token)
        print("ESTOP_RESUMED")
    else:
        print("ESTOP_ACTIVE" if k.is_stopped() else "KERNEL_ARMED")
