"""
jarvis/coding/engine.py — Claude Code / Aider AST Repo-Map & SHA-256 Search/Replace Patcher.
"""
from __future__ import annotations

import ast
import hashlib
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple
from jarvis.contracts import (
    EvidenceRecord,
    JarvisError,
    PolicyDeniedError,
    ReconcileOutcome,
    RiskTier,
    SECRET_PATTERNS,
    TaskRecord,
    ToolProtocol,
)


class NativeCodingAgent:
    def __init__(self, worktree_root: str | Path = "data/worktrees") -> None:
        self.worktree_root = Path(worktree_root).resolve()
        self.worktree_root.mkdir(parents=True, exist_ok=True)

    def _assert_inside_worktree(self, file_path: str | Path) -> Path:
        resolved = Path(file_path).resolve()
        try:
            resolved.relative_to(self.worktree_root)
            return resolved
        except ValueError as exc:
            raise PolicyDeniedError(f"Path '{file_path}' escapes coding worktree root '{self.worktree_root}'") from exc

    def repo_map(self, root_dir: str | Path) -> Dict[str, List[str]]:
        base = self._assert_inside_worktree(root_dir)
        out: Dict[str, List[str]] = {}
        for py_file in sorted(base.rglob("*.py")):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            symbols: List[str] = []
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                    symbols.append(f"class {node.name} (L{node.lineno}): {', '.join(methods)}")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    symbols.append(f"def {node.name} (L{node.lineno})")
            rel = str(py_file.relative_to(base)).replace("\\", "/")
            out[rel] = symbols
        return out

    def apply_search_replace_blocks(
        self,
        file_path: str | Path,
        expected_sha256: str,
        blocks: List[Tuple[str, str]],
        task: TaskRecord,
    ) -> Tuple[Dict[str, Any], EvidenceRecord]:
        target = self._assert_inside_worktree(file_path)
        if not target.is_file():
            raise JarvisError(f"Target file does not exist: {target}")
        raw = target.read_bytes()
        actual_sha = hashlib.sha256(raw).hexdigest()
        if actual_sha != expected_sha256:
            raise JarvisError(
                f"Precondition failed: file SHA-256 changed since read (expected {expected_sha256}, got {actual_sha})"
            )

        content = raw.decode("utf-8")
        for search_str, replace_str in blocks:
            for pat in SECRET_PATTERNS:
                if pat.search(replace_str):
                    raise PolicyDeniedError("Refusing to write plaintext secret into source code")
            occ = content.count(search_str)
            if occ == 0:
                raise JarvisError(f"Search block not found in {target.name}")
            if occ > 1:
                raise JarvisError(f"Ambiguous search block appears {occ} times in {target.name}")
            content = content.replace(search_str, replace_str, 1)

        new_bytes = content.encode("utf-8")
        tmp_path = target.with_suffix(f".tmp_{uuid.uuid4().hex[:6]}")
        with open(tmp_path, "wb") as f:
            f.write(new_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)

        post_sha = hashlib.sha256(new_bytes).hexdigest()
        ev = EvidenceRecord(
            task_id=task.task_id,
            source_type="file_hash",
            content_summary=f"Patched {target.name}: {expected_sha256[:10]} -> {post_sha[:10]}",
            sha256=post_sha,
        )
        return (
            {"patched_file": str(target), "pre_sha256": expected_sha256, "post_sha256": post_sha},
            ev,
        )

    def apply_patch(
        self,
        file_path: str | Path,
        expected_sha256: str,
        old_text: str,
        new_text: str,
        task: TaskRecord,
    ) -> Tuple[Dict[str, Any], EvidenceRecord]:
        return self.apply_search_replace_blocks(
            file_path=file_path,
            expected_sha256=expected_sha256,
            blocks=[(old_text, new_text)],
            task=task,
        )


class CodePatchTool:
    name = "code.patch"
    description = "Applies SHA-256 verified search/replace patches to source files"
    default_risk = RiskTier.R1_LOCAL_REVERSIBLE
    idempotent = True

    def __init__(self, agent: NativeCodingAgent) -> None:
        self.agent = agent

    def execute(self, args: Dict[str, Any], task: TaskRecord) -> Tuple[Dict[str, Any], EvidenceRecord]:
        return self.agent.apply_patch(
            file_path=args["file_path"],
            expected_sha256=args["expected_sha256"],
            old_text=args["old_text"],
            new_text=args["new_text"],
            task=task,
        )

    def reconcile(self, args: Dict[str, Any], task: TaskRecord) -> ReconcileOutcome:
        return ReconcileOutcome.KNOWN_NOT_DONE
