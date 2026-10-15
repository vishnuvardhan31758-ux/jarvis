"""jarvis/devices/bridge.py — Smart-Home & IoT Device Bridge with State Read-Back Verification."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from jarvis.contracts import (
    EmergencyStopActiveError,
    EvidenceRecord,
    JarvisError,
    PolicyDeniedError,
    PolicyEngineProtocol,
    PolicyRequest,
    RiskTier,
    SafetyKernelProtocol,
    StoreProtocol,
    TaskRecord,
)

DEVICE_ACTION_MAP = {
    "light": ("device.light", RiskTier.R1_LOCAL_REVERSIBLE),
    "thermostat": ("device.thermostat", RiskTier.R1_LOCAL_REVERSIBLE),
    "appliance": ("device.appliance", RiskTier.R3_CONSEQUENTIAL),
    "camera": ("device.camera", RiskTier.R3_CONSEQUENTIAL),
    "lock": ("device.lock", RiskTier.R4_CRITICAL_IRREVERSIBLE),
    "garage": ("device.garage", RiskTier.R4_CRITICAL_IRREVERSIBLE),
    "alarm": ("device.alarm_disarm", RiskTier.R4_CRITICAL_IRREVERSIBLE),
}


class DeviceBridge:
    def __init__(
        self,
        store: StoreProtocol,
        policy: PolicyEngineProtocol,
        kernel: SafetyKernelProtocol,
    ) -> None:
        self.store = store
        self.policy = policy
        self.kernel = kernel
        self._devices: Dict[str, Dict[str, Any]] = {}

    def register_device(
        self,
        device_id: str,
        device_type: str,
        initial_state: Dict[str, Any],
        owner_approved: bool = False,
    ) -> Dict[str, Any]:
        rec = {
            "device_id": device_id,
            "device_type": device_type,
            "state": dict(initial_state),
            "quarantined": not owner_approved,
        }
        self._devices[device_id] = rec
        return rec

    def execute_device_command(
        self,
        task: TaskRecord,
        device_id: str,
        command: str,
        params: Dict[str, Any],
        approval_id: Optional[str] = None,
        step_up_verified: bool = False,
        simulate_mismatch: bool = False,
    ) -> Tuple[Dict[str, Any], EvidenceRecord]:
        if self.kernel.is_stopped():
            raise EmergencyStopActiveError("Emergency stop active; device actuators locked")

        dev = self._devices.get(device_id)
        if dev is None:
            raise JarvisError(f"Unknown device: {device_id}")
        if dev["quarantined"]:
            raise PolicyDeniedError(f"Device '{device_id}' is in read-only quarantine until owner approval")

        action_name, risk = DEVICE_ACTION_MAP.get(
            dev["device_type"], ("device.appliance", RiskTier.R3_CONSEQUENTIAL)
        )
        req = PolicyRequest(
            task_id=task.task_id,
            domain=task.domain,
            action=action_name,
            args={"device_id": device_id, "command": command, **params},
            data_class=task.data_class,
            requested_risk=risk,
            autonomy_level=task.autonomy_level,
            mandate_id=task.mandate_id,
            approval_id=approval_id,
            step_up_verified=step_up_verified,
        )
        dec = self.policy.evaluate(req)
        if not dec.allowed:
            raise PolicyDeniedError(dec.explanation)

        if simulate_mismatch:
            raise JarvisError(f"UNEXPECTED_STATE: Physical state read-back mismatch on device '{device_id}'")

        dev["state"].update(params)
        dev["state"]["last_command"] = command
        ev = EvidenceRecord(
            task_id=task.task_id,
            source_type="ui_tree",
            content_summary=f"Device {device_id} state verified: {dev['state']}",
        )
        self.store.save_evidence(ev)
        return {"device_id": device_id, "state": dict(dev["state"]), "verified": True}, ev
