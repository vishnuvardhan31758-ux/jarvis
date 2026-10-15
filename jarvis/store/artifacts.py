"""jarvis/store/artifacts.py — Content-Addressable SHA-256 Artifact Vault."""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from jarvis.contracts import ArtifactMeta, DataClass, JarvisError


class ArtifactStore:
    def __init__(self, base_dir: str | Path = "data/artifacts") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def put_bytes(
        self,
        data: bytes,
        media_type: str,
        data_class: DataClass,
        task_id: str,
    ) -> ArtifactMeta:
        sha256 = hashlib.sha256(data).hexdigest()
        subdir = self.base_dir / sha256[:2]
        subdir.mkdir(parents=True, exist_ok=True)
        target = subdir / sha256
        if not target.exists():
            tmp_path = subdir / f"{sha256}.tmp_{uuid.uuid4().hex[:8]}"
            with open(tmp_path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target)
        return ArtifactMeta(
            task_id=task_id,
            sha256=sha256,
            media_type=media_type,
            size_bytes=len(data),
            data_class=data_class,
            storage_path=str(target),
        )

    def get_bytes(self, meta: ArtifactMeta, verify_hash: bool = True) -> bytes:
        p = Path(meta.storage_path)
        if not p.is_file():
            raise JarvisError(f"Artifact file missing on disk: {meta.storage_path}")
        raw = p.read_bytes()
        if verify_hash:
            actual = hashlib.sha256(raw).hexdigest()
            if actual != meta.sha256:
                raise JarvisError(
                    f"Artifact SHA-256 mismatch for {meta.artifact_id}: expected {meta.sha256}, got {actual}"
                )
        return raw
