from __future__ import annotations

from pathlib import Path
import pytest
from jarvis.contracts import (
    EpistemicLabel,
    MemoryCategory,
    MemoryItem,
    PolicyDeniedError,
    SkillStatus,
    TaskRecord,
    WorldMemoryProtocol,
)
from jarvis.policy.kernel import SafetyKernel
from jarvis.skills.practice import WorldMemoryService
from jarvis.store.db import DatabaseStore


def test_memory_anti_poisoning_and_world_model_conflicts(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    wm = WorldMemoryService(store, kernel, tmp_path / "mem.db", tmp_path / "skills")
    assert isinstance(wm, WorldMemoryProtocol)

    # Unverified OBSERVED semantic memory without evidence_ids is downgraded to UNVERIFIED
    m = wm.store_memory(
        MemoryItem(category=MemoryCategory.SEMANTIC, content="Server IP is 1.2.3.4", epistemic_label=EpistemicLabel.OBSERVED)
    )
    assert m.epistemic_label == EpistemicLabel.UNVERIFIED

    wm.world.register_project("/repo", dirty_files=["main.py"])
    t = TaskRecord(goal_id="g1", objective="edit")
    pred = wm.predict_consequences("code.patch", {"file_path": "/repo/main.py"}, t)
    assert pred.conflict_detected is True and pred.safe_to_proceed is False


def test_skill_forge_ast_scanner_and_pytest_execution(tmp_path: Path) -> None:
    store = DatabaseStore(tmp_path / "j.db", tmp_path / "arts")
    kernel = SafetyKernel(tmp_path / ".estop.lock")
    wm = WorldMemoryService(store, kernel, tmp_path / "mem.db", tmp_path / "skills")
    t = TaskRecord(goal_id="g1", objective="forge skill")

    # Poisoned skill importing jarvis.policy is blocked
    with pytest.raises(PolicyDeniedError):
        wm.synthesize_skill(
            "evil_skill",
            "tries to import policy",
            "import jarvis.policy.kernel\ndef run():\n    pass\n",
            "def test_x():\n    assert True\n",
            t,
        )

    # Valid skill passes AST scan and unit test runner
    manifest = wm.synthesize_skill(
        "fib_calculator",
        "Calculates Fibonacci numbers",
        "def fib(n: int) -> int:\n    return n if n <= 1 else fib(n - 1) + fib(n - 2)\n",
        "from skill import fib\ndef test_fib():\n    assert fib(6) == 8\n",
        t,
    )
    assert manifest.status == SkillStatus.ACTIVE

    # Practice runner refuses cloud provider
    res_cloud = wm.practice.run_idle_practice(provider_type="cloud")
    assert res_cloud["ran"] is False
    res_local = wm.practice.run_idle_practice(provider_type="local", cpu_percent=10.0)
    assert res_local["ran"] is True and res_local["cost_usd"] == 0.0
