"""
jarvis/remote/gateway.py — OpenClaw-Style 6-Digit Global Remote Control Gateway
with Cryptographic Device Pairing and Live Telegram Bot Long-Polling Bridge.
"""
from __future__ import annotations

import json, os, urllib.request
from typing import List
import hashlib
import random
import uuid
from datetime import timedelta
from typing import Any, Callable, Dict, Optional, Tuple
from jarvis.contracts import (
    PCControllerProtocol,
    PolicyDeniedError,
    RemoteControlProtocol,
    RemotePairedDevice,
    SafetyKernelProtocol,
    StoreProtocol,
    utc_now,
)


class GlobalRemoteGateway:
    def __init__(
        self,
        store: StoreProtocol,
        kernel: SafetyKernelProtocol,
        pc_controller: Optional[PCControllerProtocol] = None,
        on_submit_goal: Optional[Callable[[str, str], Dict[str, Any]]] = None,
        on_decide_approval: Optional[Callable[[str, bool, str, Optional[str]], Any]] = None,
    ) -> None:
        self.store = store
        self.kernel = kernel
        self.pc_controller = pc_controller
        self.on_submit_goal = on_submit_goal
        self.on_decide_approval = on_decide_approval
        self._pending_codes: Dict[str, Any] = {}
        self._paired_devices: Dict[Tuple[str, str], RemotePairedDevice] = {}

    def generate_pairing_code(self, ttl_seconds: int = 300) -> str:
        code = f"{random.randint(100000, 999999)}"
        self._pending_codes[code] = utc_now() + timedelta(seconds=ttl_seconds)
        return code

    def complete_pairing(
        self,
        pairing_code: str,
        channel: str,
        external_user_id: str,
        device_name: str,
    ) -> Tuple[RemotePairedDevice, str]:
        exp = self._pending_codes.pop(pairing_code, None)
        if exp is None or exp <= utc_now():
            raise PolicyDeniedError("Invalid or expired 6-digit pairing code")

        raw_token = f"rem_tok_{uuid.uuid4().hex}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        dev = RemotePairedDevice(
            device_name=device_name,
            channel=channel,
            external_user_id=external_user_id,
            session_token_hash=token_hash,
        )
        self._paired_devices[(channel, external_user_id)] = dev
        return dev, raw_token

    def handle_remote_message(
        self,
        channel: str,
        external_user_id: str,
        session_token: str,
        text: str,
    ) -> Dict[str, Any]:
        dev = self._paired_devices.get((channel, external_user_id))
        if dev is None or dev.revoked:
            raise PolicyDeniedError("UNAUTHORIZED_REMOTE_SENDER: device is not paired or has been revoked")

        actual_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
        if actual_hash != dev.session_token_hash:
            raise PolicyDeniedError("UNAUTHORIZED_REMOTE_SENDER: invalid remote session token")

        cmd = text.strip()
        if cmd.startswith("/kill"):
            reason = cmd[5:].strip() or f"Remote kill from {dev.device_name}"
            self.kernel.emergency_stop(reason=reason, actor=f"remote:{dev.device_name}")
            return {"status": "REMOTE_ESTOP_ACTIVATED", "reason": reason}

        if cmd == "/status":
            return {
                "status": "OK",
                "estop": self.kernel.is_stopped(),
                "tasks": len(self.store.list_tasks()),
                "pending_approvals": len(self.store.list_pending_approvals()),
            }

        if cmd == "/screen":
            if self.pc_controller is None:
                return {"status": "ERROR", "reason": "PCController not attached"}
            art, _ = self.pc_controller.capture_masked_screenshot("remote_screen", "Desktop")
            return {"status": "SCREENSHOT_READY", "artifact_id": art.artifact_id, "sha256": art.sha256}

        if cmd.startswith("/approve "):
            parts = cmd.split()
            apr_id = parts[1] if len(parts) > 1 else ""
            args_hash = parts[2] if len(parts) > 2 else ""
            totp = parts[3] if len(parts) > 3 else None
            if self.on_decide_approval:
                self.on_decide_approval(apr_id, True, args_hash, totp)
            return {"status": "REMOTE_APPROVED", "approval_id": apr_id}

        goal_text = cmd[5:].strip() if cmd.startswith("/run ") else cmd
        res = self.on_submit_goal(goal_text, f"remote_{channel}") if self.on_submit_goal else {"goal": goal_text}
        return {"status": "REMOTE_GOAL_SUBMITTED", "goal": goal_text, "submission": res}

    def revoke_remote_device(self, device_id: str) -> bool:
        for dev in self._paired_devices.values():
            if dev.device_id == device_id:
                dev.revoked = True
                return True
        return False



class TelegramBotBridge:
    def __init__(self, gateway: GlobalRemoteGateway, bot_token: Optional[str] = None) -> None:
        self.gateway = gateway
        self.bot_token = bot_token or os.environ.get("JARVIS_TELEGRAM_BOT_TOKEN", "")
        self.last_update_id: int = 0
        self._chat_tokens: Dict[str, str] = {}

    def process_incoming_telegram_update(self, update: Dict[str, Any]) -> Dict[str, Any]:
        """Processes a single Telegram update payload (supports `/pair <6-digit-code>` and all remote commands)."""
        msg = update.get("message") or {}
        chat = msg.get("chat") or {}
        chat_id = str(chat.get("id", ""))
        username = str(chat.get("username") or chat.get("first_name") or "TelegramDevice")
        text = str(msg.get("text", "")).strip()

        if not chat_id or not text:
            return {"status": "IGNORED_EMPTY"}

        if text.startswith("/pair "):
            code = text.split(maxsplit=1)[1].strip()
            dev, raw_token = self.gateway.complete_pairing(
                pairing_code=code,
                channel="telegram",
                external_user_id=chat_id,
                device_name=f"Telegram:{username}",
            )
            self._chat_tokens[chat_id] = raw_token
            return {
                "status": "PAIRED_SUCCESSFULLY",
                "device_id": dev.device_id,
                "chat_id": chat_id,
            }

        token = self._chat_tokens.get(chat_id, "")
        return self.gateway.handle_remote_message(
            channel="telegram",
            external_user_id=chat_id,
            session_token=token,
            text=text,
        )

    def poll_once_live(self, timeout: int = 5) -> List[Dict[str, Any]]:
        if not self.bot_token:
            return []
        url = (
            f"https://api.telegram.org/bot{self.bot_token}/getUpdates"
            f"?offset={self.last_update_id + 1}&timeout={timeout}"
        )
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout + 5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        results: List[Dict[str, Any]] = []
        for upd in data.get("result", []):
            self.last_update_id = max(self.last_update_id, int(upd["update_id"]))
            out = self.process_incoming_telegram_update(upd)
            results.append(out)
        return results
