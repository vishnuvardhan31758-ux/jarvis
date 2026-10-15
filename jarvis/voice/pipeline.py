"""jarvis/voice/pipeline.py — Local-First Voice Pipeline with Replay Defense & Read-Back Confirmation."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional
from jarvis.api.server import JarvisDaemonAPI
from jarvis.contracts import PolicyEngineProtocol


class VoicePipeline:
    def __init__(self, daemon: JarvisDaemonAPI, policy: PolicyEngineProtocol) -> None:
        self.daemon = daemon
        self.policy = policy
        self.muted: bool = False
        self.is_speaking: bool = False
        self._seen_audio_hashes: set[str] = set()
        self._pending_readback: Optional[str] = None

    def barge_in(self) -> bool:
        self.is_speaking = False
        return True

    def process_utterance(
        self,
        transcript: str,
        audio_bytes: bytes = b"",
        is_owner_voice: bool = True,
        wake_word_detected: bool = True,
    ) -> Dict[str, Any]:
        if self.muted or not wake_word_detected:
            return {"status": "IGNORED_MUTE_OR_NO_WAKE", "audio_transmitted": False}

        if audio_bytes:
            audio_hash = hashlib.sha256(audio_bytes).hexdigest()
            if audio_hash in self._seen_audio_hashes:
                return {"status": "REJECTED_AUDIO_REPLAY"}
            self._seen_audio_hashes.add(audio_hash)

        clean = transcript.strip()
        low = clean.lower()

        if not is_owner_voice:
            if any(w in low for w in ("send", "write", "patch", "delete", "pay", "transfer", "unlock", "disarm", "yes", "confirm")):
                return {"status": "REJECTED_NON_OWNER_VOICE"}

        if low in {"yes", "confirm", "do it"} and self._pending_readback is not None:
            goal_text = self._pending_readback
            self._pending_readback = None
            sub = self.daemon.submit_goal(goal_text, source_channel="voice")
            return {"status": "CONFIRMED_AND_DISPATCHED", "goal": goal_text, "submission": sub}

        if any(w in low for w in ("pay", "transfer", "unlock", "disarm", "garage")):
            return {
                "status": "ROUTED_TO_STEP_UP_HUD",
                "message": "R4 critical action requires step-up TOTP verification on Desktop HUD or Terminal TUI",
            }

        if any(w in low for w in ("send email", "push", "submit", "merge", "invite", "delete")):
            self._pending_readback = clean
            self.is_speaking = True
            return {
                "status": "READBACK_CONFIRMATION_REQUIRED",
                "readback_prompt": f"Please confirm: '{clean}'? Say 'confirm' or 'yes' to proceed.",
            }

        sub = self.daemon.submit_goal(clean, source_channel="voice")
        return {"status": "DISPATCHED", "submission": sub}
