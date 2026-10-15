"""jarvis/cie/leases.py — OpenClaw-Style Exclusive Desktop Session Lease Manager."""
from __future__ import annotations

import threading
from datetime import timedelta
from typing import Optional
from jarvis.contracts import (
    DesktopLease,
    EmergencyStopActiveError,
    JarvisError,
    SafetyKernelProtocol,
    SpecialistRole,
    utc_now,
)


class DesktopLeaseManager:
    def __init__(self, kernel: SafetyKernelProtocol) -> None:
        self.kernel = kernel
        self._lock = threading.RLock()
        self._active: Optional[DesktopLease] = None

    def acquire(
        self,
        task_id: str,
        ttl_seconds: int = 60,
        owner_role: SpecialistRole = SpecialistRole.OPERATOR,
        active_window: str = "Desktop",
    ) -> DesktopLease:
        with self._lock:
            if self.kernel.is_stopped():
                raise EmergencyStopActiveError("Cannot acquire desktop lease during emergency stop")
            now = utc_now()
            if self._active is not None and self._active.expires_at > now and self._active.task_id != task_id:
                raise JarvisError(f"Desktop session is already leased by task {self._active.task_id}")
            lease = DesktopLease(
                task_id=task_id,
                owner_role=owner_role,
                active_window=active_window,
                acquired_at=now,
                expires_at=now + timedelta(seconds=ttl_seconds),
            )
            self._active = lease
            return lease

    def renew(self, lease_id: str, ttl_seconds: int = 60) -> DesktopLease:
        with self._lock:
            if self._active is None or self._active.lease_id != lease_id:
                raise JarvisError(f"Cannot renew unknown or inactive lease {lease_id}")
            self._active.expires_at = utc_now() + timedelta(seconds=ttl_seconds)
            return self._active

    def release(self, lease_id: str) -> None:
        with self._lock:
            if self._active is not None and self._active.lease_id == lease_id:
                self._active = None

    def get_active(self) -> Optional[DesktopLease]:
        with self._lock:
            if self.kernel.is_stopped():
                self._active = None
                return None
            if self._active is not None and self._active.expires_at <= utc_now():
                self._active = None
            return self._active
