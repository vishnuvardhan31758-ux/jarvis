"""jarvis/skills/practice.py — Local-Only Idle Practice Mode & WorldMemoryService Facade."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from jarvis.contracts import (
    DataClass,
    EvidenceRecord,
    MemoryItem,
    PostMortemReflection,
    SafetyKernelProtocol,
    SkillManifest,
    StoreProtocol,
    TaskRecord,
    WorldMemoryProtocol,
    WorldStatePrediction,
)
from jarvis.memory.reflection import ReflectionEngine
from jarvis.memory.service import MemoryService
from jarvis.memory.world_model import WorldModel
from jarvis.skills.forge import SkillForge


class PracticeRunner:
    def __init__(self, kernel: SafetyKernelProtocol) -> None:
        self.kernel = kernel

    def run_idle_practice(
        self,
        cpu_percent: float = 10.0,
        on_ac_power: bool = True,
        active_tasks: int = 0,
        provider_type: str = "local",
        weakest_domain: str = "coding",
    ) -> Dict[str, Any]:
        if self.kernel.is_stopped():
            return {"ran": False, "reason": "ESTOP_ACTIVE"}
        if active_tasks > 0:
            return {"ran": False, "reason": "ACTIVE_USER_TASKS"}
        if cpu_percent >= 25.0:
            return {"ran": False, "reason": "CPU_TOO_HIGH"}
        if not on_ac_power:
            return {"ran": False, "reason": "ON_BATTERY_POWER"}
        if provider_type != "local":
            return {"ran": False, "reason": "CLOUD_PROVIDER_FORBIDDEN_FOR_PRACTICE"}

        return {
            "ran": True,
            "cost_usd": 0.0,
            "provider_type": "local",
            "practiced_domain": weakest_domain,
            "synthetic_tasks_completed": 3,
        }


class WorldMemoryService:
    def __init__(
        self,
        store: StoreProtocol,
        kernel: SafetyKernelProtocol,
        memory_db_path: str | Path = "data/jarvis_memory.db",
        skills_dir: str | Path = "data/skills",
    ) -> None:
        self.store = store
        self.kernel = kernel
        self.memory = MemoryService(db_path=memory_db_path)
        self.world = WorldModel()
        self.reflections = ReflectionEngine()
        self.forge = SkillForge(skills_dir=skills_dir)
        self.practice = PracticeRunner(kernel=kernel)

    def store_memory(self, item: MemoryItem) -> MemoryItem:
        return self.memory.store_memory(item)

    def search_memory(
        self,
        query: str,
        max_data_class: DataClass = DataClass.D2_CONFIDENTIAL,
        limit: int = 5,
    ) -> List[MemoryItem]:
        return self.memory.search_memory(query=query, max_data_class=max_data_class, limit=limit)

    def delete_memory(self, memory_id: str) -> bool:
        return self.memory.delete_memory(memory_id)

    def predict_consequences(self, action: str, args: Dict[str, Any], task: TaskRecord) -> WorldStatePrediction:
        mandate = self.store.get_mandate(task.mandate_id) if task.mandate_id else None
        return self.world.predict_consequences(action=action, args=args, task=task, mandate=mandate)

    def record_reflection(
        self,
        task: TaskRecord,
        evidence: List[EvidenceRecord],
        error_msg: str = "",
    ) -> PostMortemReflection:
        return self.reflections.record_reflection(task=task, evidence=evidence, error_msg=error_msg)

    def synthesize_skill(
        self,
        name: str,
        description: str,
        code_body: str,
        test_body: str,
        task: TaskRecord,
    ) -> SkillManifest:
        return self.forge.synthesize_skill(
            name=name,
            description=description,
            code_body=code_body,
            test_body=test_body,
            task=task,
        )
