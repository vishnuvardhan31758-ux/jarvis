"""jarvis/skills/forge.py — Voyager / Hermes AST-Verified SkillForge & Pytest Compiler."""
from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import List, Optional
from jarvis.contracts import (
    JarvisError,
    PolicyDeniedError,
    RiskTier,
    SkillManifest,
    SkillStatus,
    TaskRecord,
)

FORBIDDEN_MODULES = (
    "jarvis.policy",
    "jarvis.verify",
    "jarvis.store.audit",
    "ctypes",
    "winreg",
)
FORBIDDEN_CALLS = {"eval", "exec", "__import__", "compile"}


class SkillForge:
    def __init__(self, skills_dir: str | Path = "data/skills") -> None:
        self.skills_dir = Path(skills_dir)
        self.skills_dir.mkdir(parents=True, exist_ok=True)

    def scan_skill_ast(self, code_body: str) -> List[str]:
        try:
            tree = ast.parse(code_body)
        except SyntaxError as exc:
            return [f"SyntaxError: {exc}"]

        violations: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(alias.name.startswith(mod) for mod in FORBIDDEN_MODULES):
                        violations.append(f"Forbidden import: {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                mod_name = node.module or ""
                if any(mod_name.startswith(mod) for mod in FORBIDDEN_MODULES):
                    violations.append(f"Forbidden import from: {mod_name}")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
                    violations.append(f"Forbidden builtin call: {node.func.id}()")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if ".estop.lock" in node.value:
                    violations.append("Forbidden reference to .estop.lock")
        return violations

    def synthesize_skill(
        self,
        name: str,
        description: str,
        code_body: str,
        test_body: str,
        task: TaskRecord,
        allowed_tools: Optional[List[str]] = None,
        max_risk_tier: RiskTier = RiskTier.R1_LOCAL_REVERSIBLE,
        owner_approved: bool = False,
    ) -> SkillManifest:
        violations = self.scan_skill_ast(code_body) + self.scan_skill_ast(test_body)
        if violations:
            raise PolicyDeniedError(f"SkillForge AST safety scanner blocked skill '{name}': {violations}")

        safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
        skill_dir = self.skills_dir / safe_name
        skill_dir.mkdir(parents=True, exist_ok=True)
        code_path = skill_dir / "skill.py"
        test_path = skill_dir / "test_skill.py"
        code_path.write_text(code_body, encoding="utf-8")
        test_path.write_text(test_body, encoding="utf-8")

        runner_code = (
            "import importlib.util, pathlib, sys\n"
            "sys.path.insert(0, str(pathlib.Path.cwd()))\n"
            "spec = importlib.util.spec_from_file_location('test_skill', 'test_skill.py')\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "ran = 0\n"
            "for name in dir(mod):\n"
            "    if name.startswith('test_') and callable(getattr(mod, name)):\n"
            "        getattr(mod, name)()\n"
            "        ran += 1\n"
            "assert ran > 0, 'No test_ functions found'\n"
            "print(f'{ran} passed')\n"
        )
        res = subprocess.run(
            [sys.executable, "-c", runner_code],
            cwd=str(skill_dir),
            capture_output=True,
            text=True,
            timeout=20,
        )
        if res.returncode != 0:
            raise JarvisError(f"Synthesized skill '{name}' failed unit tests:\n{res.stdout}\n{res.stderr}")

        sha = hashlib.sha256(code_body.encode("utf-8")).hexdigest()
        status = SkillStatus.ACTIVE if (max_risk_tier.rank <= 1 or owner_approved) else SkillStatus.STAGED
        return SkillManifest(
            name=safe_name,
            description=description,
            allowed_tools=allowed_tools or [],
            max_risk_tier=max_risk_tier,
            status=status,
            code_path=str(code_path),
            test_path=str(test_path),
            sha256=sha,
        )
