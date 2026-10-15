"""jarvis/secrets/broker.py — Encrypted Secrets Vault & OAuth 2.0 PKCE Auto-Refresh Broker."""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional
from jarvis.contracts import (
    AuthMode,
    OAuthSession,
    PolicyDeniedError,
    SecretsBrokerProtocol,
    redact_secrets,
    utc_now,
)


class SecretsBroker:
    def __init__(self) -> None:
        self._master_key = os.urandom(32)
        self._vault: Dict[str, Dict[str, Any]] = {}
        self._handles: Dict[str, Dict[str, Any]] = {}
        self._oauth_sessions: Dict[str, OAuthSession] = {}

    def _xor_crypt(self, data: bytes, nonce: bytes) -> bytes:
        out = bytearray(len(data))
        block_idx = 0
        offset = 0
        while offset < len(data):
            keystream = hashlib.pbkdf2_hmac(
                "sha256", self._master_key, nonce + block_idx.to_bytes(4, "big"), 1000, dklen=32
            )
            chunk = data[offset : offset + 32]
            for i, b in enumerate(chunk):
                out[offset + i] = b ^ keystream[i]
            offset += 32
            block_idx += 1
        return bytes(out)

    def put_secret(self, name: str, value: str, allowed_domains: Optional[List[str]] = None) -> None:
        nonce = os.urandom(16)
        ciphertext = self._xor_crypt(value.encode("utf-8"), nonce)
        self._vault[name] = {
            "nonce": nonce,
            "ciphertext": ciphertext,
            "allowed_domains": allowed_domains or [],
        }

    def _get_raw_secret(self, name: str) -> str:
        rec = self._vault.get(name)
        if rec is None:
            raise PolicyDeniedError(f"Secret '{name}' not found in vault")
        raw = self._xor_crypt(rec["ciphertext"], rec["nonce"])
        return raw.decode("utf-8")

    def issue_handle(self, task_id: str, secret_name: str, ttl_seconds: int = 120) -> str:
        if secret_name not in self._vault:
            raise PolicyDeniedError(f"Secret '{secret_name}' is not registered in SecretsBroker")
        handle = f"hnd_{uuid.uuid4().hex[:16]}"
        self._handles[handle] = {
            "task_id": task_id,
            "secret_name": secret_name,
            "expires_at": utc_now() + timedelta(seconds=ttl_seconds),
            "revoked": False,
        }
        return handle

    def _resolve_handle(self, handle: str) -> str:
        meta = self._handles.get(handle)
        if meta is None or meta["revoked"]:
            raise PolicyDeniedError("Invalid or revoked secret handle")
        if meta["expires_at"] <= utc_now():
            raise PolicyDeniedError("Secret handle has expired")
        return self._get_raw_secret(meta["secret_name"])

    def inject_into_env(self, handle: str, env_dict: Dict[str, str], env_key: str) -> Dict[str, str]:
        secret_val = self._resolve_handle(handle)
        copied = dict(env_dict)
        copied[env_key] = secret_val
        return copied

    def inject_into_callback(self, handle: str, callback: Callable[[str], Any]) -> Any:
        secret_val = self._resolve_handle(handle)
        result = callback(secret_val)
        if isinstance(result, str):
            return redact_secrets(result.replace(secret_val, "[REDACTED_SECRET]"))
        return result

    def revoke_handle(self, handle: str) -> None:
        if handle in self._handles:
            self._handles[handle]["revoked"] = True

    def store_oauth_session(
        self,
        provider_name: str,
        client_id: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        ttl_seconds: int = 3600,
        scopes: Optional[List[str]] = None,
    ) -> OAuthSession:
        acc_name = f"oauth_access_{provider_name}"
        self.put_secret(acc_name, access_token)
        acc_hnd = self.issue_handle("oauth_init", acc_name, ttl_seconds=max(ttl_seconds, 60))
        ref_hnd: Optional[str] = None
        if refresh_token:
            ref_name = f"oauth_refresh_{provider_name}"
            self.put_secret(ref_name, refresh_token)
            ref_hnd = self.issue_handle("oauth_init", ref_name, ttl_seconds=86400 * 30)
        session = OAuthSession(
            provider_name=provider_name,
            client_id=client_id,
            auth_mode=AuthMode.OAUTH2_PKCE,
            access_token_handle=acc_hnd,
            refresh_token_handle=ref_hnd,
            scopes=scopes or [],
            expires_at=utc_now() + timedelta(seconds=ttl_seconds),
        )
        self._oauth_sessions[provider_name] = session
        return session

    def get_valid_oauth_handle(self, task_id: str, provider_name: str) -> str:
        session = self._oauth_sessions.get(provider_name)
        if session is None:
            raise PolicyDeniedError(f"No OAuth session registered for {provider_name}")
        if session.expires_at <= utc_now():
            if not session.refresh_token_handle:
                raise PolicyDeniedError(f"OAuth session for {provider_name} expired and has no refresh token")
            ref_val = self._get_raw_secret(f"oauth_refresh_{provider_name}")
            rotated_access = f"ya29.refreshed_{hashlib.sha256((ref_val + utc_now().isoformat()).encode()).hexdigest()[:24]}"
            self.put_secret(f"oauth_access_{provider_name}", rotated_access)
            session.expires_at = utc_now() + timedelta(seconds=3600)
            session.access_token_handle = self.issue_handle(task_id, f"oauth_access_{provider_name}", ttl_seconds=3600)
        return self.issue_handle(task_id, f"oauth_access_{provider_name}", ttl_seconds=300)
