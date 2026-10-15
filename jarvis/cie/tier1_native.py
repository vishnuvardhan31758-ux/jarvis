"""jarvis/cie/tier1_native.py — Dual-OS (Windows PowerShell/Win32 + macOS AppleScript) Driver & Trash."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from jarvis.contracts import JarvisError, PolicyDeniedError, current_os_family


class NativeOSDriver:
    def __init__(
        self,
        allowed_roots: Optional[List[str | Path]] = None,
        trash_dir: str | Path = "data/trash",
        os_override: Optional[str] = None,
    ) -> None:
        self.os_family = os_override or current_os_family()
        self.allowed_roots = [Path(r).resolve() for r in (allowed_roots or [Path.cwd()])]
        self.trash_dir = Path(trash_dir).resolve()
        self.trash_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.trash_dir / "manifest.json"
        if not self.manifest_path.exists():
            self.manifest_path.write_text("{}", encoding="utf-8")

    def build_os_app_command(self, app_name: str, operation: str = "focus") -> List[str]:
        if self.os_family == "windows":
            if operation == "launch":
                return ["powershell", "-NoProfile", "-Command", f"Start-Process '{app_name}'"]
            if operation == "focus":
                return [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(New-Object -ComObject WScript.Shell).AppActivate('{app_name}')",
                ]
            if operation == "close":
                return [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"Stop-Process -Name '{app_name}' -ErrorAction SilentlyContinue",
                ]
        elif self.os_family == "macos":
            if operation == "launch":
                return ["open", "-a", app_name]
            if operation == "focus":
                return ["osascript", "-e", f'tell application "{app_name}" to activate']
            if operation == "close":
                return ["osascript", "-e", f'tell application "{app_name}" to quit']
        else:
            if operation == "launch":
                return ["xdg-open", app_name]
            if operation == "focus":
                return ["wmctrl", "-a", app_name]
            if operation == "close":
                return ["pkill", "-f", app_name]
        raise JarvisError(f"Unsupported OS operation: {operation}")

    def _resolve_safe(self, path: str | Path) -> Path:
        resolved = Path(path).resolve()
        for root in self.allowed_roots:
            try:
                resolved.relative_to(root)
                return resolved
            except ValueError:
                continue
        raise PolicyDeniedError(f"Path '{path}' is outside allowed roots")

    def read_file(self, path: str | Path) -> Tuple[str, str]:
        p = self._resolve_safe(path)
        raw = p.read_bytes()
        return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()

    def write_file(self, path: str | Path, content: str) -> Tuple[str, str]:
        p = self._resolve_safe(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        raw = content.encode("utf-8")
        p.write_bytes(raw)
        return str(p), hashlib.sha256(raw).hexdigest()

    def soft_delete(self, path: str | Path) -> Dict[str, str]:
        p = self._resolve_safe(path)
        if not p.is_file():
            raise JarvisError(f"Cannot soft-delete missing file: {p}")
        raw = p.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        trashed_name = f"{int(time.time() * 1000)}_{p.name}"
        dest = self.trash_dir / trashed_name
        shutil.move(str(p), str(dest))
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        manifest[trashed_name] = {"original_path": str(p), "sha256": sha}
        self.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return {"trashed_name": trashed_name, "original_path": str(p), "sha256": sha}

    def restore_from_trash(self, trashed_name: str) -> str:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        if trashed_name not in manifest:
            raise JarvisError(f"Trashed item '{trashed_name}' not found in manifest")
        entry = manifest[trashed_name]
        src = self.trash_dir / trashed_name
        orig = Path(entry["original_path"])
        orig.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(orig))
        actual_sha = hashlib.sha256(orig.read_bytes()).hexdigest()
        if actual_sha != entry["sha256"]:
            raise JarvisError("Restored file SHA-256 mismatch")
        return str(orig)

    def get_system_metrics(self) -> Dict[str, Any]:
        load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.5
        return {
            "os_family": self.os_family,
            "cpu_load": round(load, 2),
            "on_ac_power": True,
        }

    def launch_or_focus_app(self, app_name: str, dry_run: bool = True) -> Dict[str, Any]:
        cmd = self.build_os_app_command(app_name, operation="focus")
        return {"app_name": app_name, "os_family": self.os_family, "command": cmd, "dry_run": dry_run}
