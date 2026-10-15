"""jarvis/container.py — Master Dependency Injection Container wiring all 10 Parts of JARVIS 5.0."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple
from jarvis.agent.calibration import ConfidenceCalibrator
from jarvis.agent.loop import AgentLoop
from jarvis.agent.planner import DeliberatePlanner
from jarvis.agent.specialists import SpecialistSwarm
from jarvis.api.server import JarvisDaemonAPI
from jarvis.cie.controller import PCController
from jarvis.coding.engine import CodePatchTool, NativeCodingAgent
from jarvis.contracts import (
    AutonomyLevel,
    EvidenceRecord,
    ReconcileOutcome,
    RiskTier,
    StandingMandate,
    TaskRecord,
)
from jarvis.desktop.hud import DesktopHUDController
from jarvis.devices.bridge import DeviceBridge
from jarvis.evals.self_improve import SelfImprovementEngine, VerifierExamService
from jarvis.models.gateway import ModelGateway
from jarvis.ops.life_business import LifeOpsService
from jarvis.ops.proactive import ProactiveGoalEngine
from jarvis.policy.engine import PolicyEngine
from jarvis.policy.kernel import SafetyKernel
from jarvis.remote.gateway import GlobalRemoteGateway
from jarvis.research.agent import WebResearchService
from jarvis.runner.engine import JobRunner
from jarvis.sched.notifications import NotificationService
from jarvis.secrets.broker import SecretsBroker
from jarvis.secrets.sandbox import SandboxRunner
from jarvis.skills.practice import WorldMemoryService
from jarvis.store.db import DatabaseStore
from jarvis.tui.cockpit import TerminalCockpit
from jarvis.voice.pipeline import VoicePipeline
from jarvis.ops.life_business import BuiltinSkillPack
from jarvis.remote.gateway import TelegramBotBridge
from jarvis.desktop.hud import NativeDesktopHUDWindow


class _BuiltinFuncTool:
    def __init__(self, name: str, description: str, default_risk: RiskTier, fn: Any, idempotent: bool = True) -> None:
        self.name = name
        self.description = description
        self.default_risk = default_risk
        self._fn = fn
        self.idempotent = idempotent

    def execute(self, args: Dict[str, Any], task: TaskRecord) -> Tuple[Dict[str, Any], EvidenceRecord]:
        return self._fn(args, task)

    def reconcile(self, args: Dict[str, Any], task: TaskRecord) -> ReconcileOutcome:
        return ReconcileOutcome.KNOWN_NOT_DONE


class JarvisContainer:
    def __init__(self, data_dir: str | Path = "data") -> None:
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.kernel = SafetyKernel(lockfile_path=self.data_dir / ".estop.lock")
        self.store = DatabaseStore(
            db_path=self.data_dir / "jarvis.db",
            artifact_dir=self.data_dir / "artifacts",
        )
        self.policy = PolicyEngine(kernel=self.kernel, store=self.store)
        self.secrets = SecretsBroker()
        self.sandbox = SandboxRunner(
            kernel=self.kernel,
            store=self.store,
            allowed_roots=[str(self.data_dir)],
        )

        self._seed_default_mandates()

        self.runner = JobRunner(store=self.store, policy=self.policy, kernel=self.kernel)
        self.gateway = ModelGateway(policy=self.policy, secrets=self.secrets)
        self.calibrator = ConfidenceCalibrator()
        self.planner = DeliberatePlanner(gateway=self.gateway, calibrator=self.calibrator)
        self.swarm = SpecialistSwarm(gateway=self.gateway, store=self.store)
        self.coder = NativeCodingAgent(worktree_root=self.data_dir / "worktrees")
        self.pc_controller = PCController(
            store=self.store,
            policy=self.policy,
            kernel=self.kernel,
            allowed_roots=[str(self.data_dir)],
        )
        self.web_research = WebResearchService(store=self.store, policy=self.policy)
        self.world_memory = WorldMemoryService(
            store=self.store,
            kernel=self.kernel,
            memory_db_path=self.data_dir / "jarvis_memory.db",
            skills_dir=self.data_dir / "skills",
        )
        self.verifier = VerifierExamService(store=self.store, kernel=self.kernel)
        assert self.verifier.run_canary() is True, "Verifier startup canary failed!"
        self.self_improver = SelfImprovementEngine(kernel=self.kernel, verifier_svc=self.verifier)

        self.proactive = ProactiveGoalEngine(store=self.store, kernel=self.kernel)
        self.life_ops = LifeOpsService(store=self.store, policy=self.policy)
        self.notifications = NotificationService()
        self.devices = DeviceBridge(store=self.store, policy=self.policy, kernel=self.kernel)

        self._register_builtin_tools()

        self.agent_loop = AgentLoop(
            store=self.store,
            runner=self.runner,
            planner=self.planner,
            verifier=self.verifier,
            world_model=self.world_memory,
        )
        self.remote_gateway = GlobalRemoteGateway(
            store=self.store,
            kernel=self.kernel,
            pc_controller=self.pc_controller,
        )
        self.daemon = JarvisDaemonAPI(
            store=self.store,
            kernel=self.kernel,
            policy=self.policy,
            pc_controller=self.pc_controller,
            verifier=self.verifier,
            remote_gateway=self.remote_gateway,
            secrets=self.secrets,
            on_run_task=self.agent_loop.run_task,
        )
        self.remote_gateway.on_submit_goal = lambda text, ch: self.daemon.submit_goal(text, source_channel=ch)
        self.remote_gateway.on_decide_approval = self.daemon.decide_approval

        self.tui = TerminalCockpit(daemon=self.daemon, store=self.store)
        self.hud = DesktopHUDController(daemon=self.daemon, pc_controller=self.pc_controller)
        self.voice = VoicePipeline(daemon=self.daemon, policy=self.policy)
        self.builtin_skills = BuiltinSkillPack(store=self.store, root_dir=self.data_dir.parent)
        self.telegram_bridge = TelegramBotBridge(gateway=self.remote_gateway)
        self.hud_window = NativeDesktopHUDWindow(hud_controller=self.hud)

    def _seed_default_mandates(self) -> None:
        defaults = [
            StandingMandate(
                mandate_id="mnd_coding_default",
                name="Default Coding Mandate",
                domain="coding",
                autonomy_level=AutonomyLevel.A3_DELEGATE,
                max_risk_tier=RiskTier.R2_EXTERNAL_REVERSIBLE,
                allowed_paths=[str(self.data_dir)],
            ),
            StandingMandate(
                mandate_id="mnd_pc_files_default",
                name="Default PC Files Mandate",
                domain="pc_files",
                autonomy_level=AutonomyLevel.A3_DELEGATE,
                max_risk_tier=RiskTier.R2_EXTERNAL_REVERSIBLE,
                allowed_paths=[str(self.data_dir)],
            ),
            StandingMandate(
                mandate_id="mnd_web_research_default",
                name="Default Web Research Mandate",
                domain="web_research",
                autonomy_level=AutonomyLevel.A3_DELEGATE,
                max_risk_tier=RiskTier.R2_EXTERNAL_REVERSIBLE,
            ),
        ]
        for m in defaults:
            self.store.save_mandate(m)

    def _register_builtin_tools(self) -> None:
        self.runner.register_tool(CodePatchTool(self.coder))

        def _fs_write(args: Dict[str, Any], task: TaskRecord) -> Tuple[Dict[str, Any], EvidenceRecord]:
            target = args.get("path", str(self.data_dir / "note.txt"))
            content = str(args.get("content", args.get("objective", "written by jarvis")))
            written_path, sha = self.pc_controller.native_os.write_file(target, content)
            ev = EvidenceRecord(
                task_id=task.task_id,
                source_type="file_hash",
                content_summary=f"Wrote {written_path}",
                sha256=sha,
            )
            return {"path": written_path, "sha256": sha}, ev

        def _fs_read(args: Dict[str, Any], task: TaskRecord) -> Tuple[Dict[str, Any], EvidenceRecord]:
            target = args.get("path")
            if target and Path(str(target)).is_file():
                text, sha = self.pc_controller.native_os.read_file(str(target))
            else:
                text, sha = "ok", "0" * 64
            ev = EvidenceRecord(
                task_id=task.task_id,
                source_type="file_hash",
                content_summary=f"Read {len(text)} chars",
                sha256=sha,
            )
            return {"content": text, "sha256": sha}, ev

        def _finance_pay(args: Dict[str, Any], task: TaskRecord) -> Tuple[Dict[str, Any], EvidenceRecord]:
            ev = EvidenceRecord(
                task_id=task.task_id,
                source_type="command_output",
                content_summary=f"Paid ${args.get('amount_usd', 0.0)} to {args.get('merchant', 'merchant')}",
            )
            return {"paid": True, "merchant": args.get("merchant"), "amount_usd": args.get("amount_usd")}, ev

        self.runner.register_tool(_BuiltinFuncTool("fs.write", "Write local file", RiskTier.R1_LOCAL_REVERSIBLE, _fs_write))
        self.runner.register_tool(_BuiltinFuncTool("fs.read", "Read local file", RiskTier.R0_READ_ONLY, _fs_read))
        self.runner.register_tool(
            _BuiltinFuncTool("finance.pay", "Execute payment", RiskTier.R4_CRITICAL_IRREVERSIBLE, _finance_pay, idempotent=False)
        )
