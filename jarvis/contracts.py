"""
jarvis/contracts.py — Canonical Zero-Drift Interface & Data Contract Layer (v5.0 Production).
Defines all Enums, Exceptions, Pydantic v2 StrictModels, State Machine, Secret Redaction,
and 13 Runtime-Checkable Subsystem Protocols.
"""
from __future__ import annotations

import hashlib
import json
import platform
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, runtime_checkable
from pydantic import BaseModel, Field
try:
    from pydantic import ConfigDict
    _PYDANTIC_V2 = hasattr(BaseModel, "model_dump")
except ImportError:
    ConfigDict = None  # type: ignore
    _PYDANTIC_V2 = False


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    short = uuid.uuid4().hex[:8]
    return f"{prefix}_{ts}_{short}"


def canonical_hash(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def current_os_family() -> str:
    sys_name = platform.system().lower()
    if "windows" in sys_name:
        return "windows"
    if "darwin" in sys_name or "mac" in sys_name:
        return "macos"
    return "linux"


SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ya29\.[0-9A-Za-z_-]{20,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-~+/]+=*"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
]


def redact_secrets(text: str) -> str:
    if not text:
        return text
    out = str(text)
    for pat in SECRET_PATTERNS:
        out = pat.sub("[REDACTED_SECRET]", out)
    return out


# ============================================================================
# 1. CANONICAL ENUMS
# ============================================================================

class CapabilityLevel(str, Enum):
    L1_ASSISTANT = "L1_ASSISTANT"
    L2_AUTONOMOUS_WORKER = "L2_WORKER"
    L3_GENERAL_AGENT = "L3_GENERAL"
    L4_SELF_IMPROVING = "L4_SELF_IMPROVING"
    L5_EXPERT_GENERALIST = "L5_EXPERT"


class TaskState(str, Enum):
    CREATED = "CREATED"
    PLANNING = "PLANNING"
    WAITING_FOR_CLARIFICATION = "WAITING_FOR_CLARIFICATION"
    READY = "READY"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    WAITING_FOR_DEPENDENCY = "WAITING_FOR_DEPENDENCY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    RECOVERING = "RECOVERING"
    VERIFYING = "VERIFYING"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"

    @property
    def is_terminal(self) -> bool:
        return self in {
            TaskState.SUCCEEDED,
            TaskState.FAILED,
            TaskState.CANCELLED,
            TaskState.EXPIRED,
            TaskState.BLOCKED_BY_POLICY,
        }


class RiskTier(str, Enum):
    R0_READ_ONLY = "R0"
    R1_LOCAL_REVERSIBLE = "R1"
    R2_EXTERNAL_REVERSIBLE = "R2"
    R3_CONSEQUENTIAL = "R3"
    R4_CRITICAL_IRREVERSIBLE = "R4"

    @property
    def rank(self) -> int:
        return {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}[self.value]


class DataClass(str, Enum):
    D0_PUBLIC = "D0"
    D1_INTERNAL = "D1"
    D2_CONFIDENTIAL = "D2"
    D3_RESTRICTED_LOCAL = "D3"
    D4_SECRET = "D4"

    @property
    def rank(self) -> int:
        return {"D0": 0, "D1": 1, "D2": 2, "D3": 3, "D4": 4}[self.value]


class AutonomyLevel(str, Enum):
    A0_ADVISOR = "A0"
    A1_ASSISTANT = "A1"
    A2_COPILOT = "A2"
    A3_DELEGATE = "A3"
    A4_OPERATOR = "A4"

    @property
    def max_auto_risk(self) -> int:
        return {"A0": -1, "A1": 0, "A2": 1, "A3": 2, "A4": 3}[self.value]


class VerificationLevel(str, Enum):
    V0_CONTRACT = "V0"
    V1_STATE_CHECK = "V1"
    V2_INDEPENDENT = "V2"
    V3_HIGH_ASSURANCE = "V3"

    @property
    def rank(self) -> int:
        return {"V0": 0, "V1": 1, "V2": 2, "V3": 3}[self.value]


class VerificationDisposition(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EpistemicLabel(str, Enum):
    OBSERVED = "OBSERVED"
    SOURCE_SUPPORTED = "SOURCE_SUPPORTED"
    DETERMINISTICALLY_DERIVED = "DETERMINISTICALLY_DERIVED"
    INFERRED = "INFERRED"
    PREDICTED = "PREDICTED"
    DISPUTED = "DISPUTED"
    UNVERIFIED = "UNVERIFIED"
    UNKNOWN = "UNKNOWN"


class ReconcileOutcome(str, Enum):
    KNOWN_DONE = "KNOWN_DONE"
    KNOWN_NOT_DONE = "KNOWN_NOT_DONE"
    UNKNOWN = "UNKNOWN"


class SpecialistRole(str, Enum):
    CONDUCTOR = "CONDUCTOR"
    PLANNER = "PLANNER"
    RESEARCHER = "RESEARCHER"
    CODER = "CODER"
    CRITIC = "CRITIC"
    OPERATOR = "OPERATOR"
    VERIFIER = "VERIFIER"


class ControlMethod(str, Enum):
    NATIVE_API = "NATIVE_API"
    ACCESSIBILITY_TREE = "ACCESSIBILITY_TREE"
    DOM_AUTOMATION = "DOM_AUTOMATION"
    GROUNDED_VISION = "GROUNDED_VISION"
    RAW_INPUT = "RAW_INPUT"


class AuthMode(str, Enum):
    LOCAL_NONE = "LOCAL_NONE"
    API_KEY = "API_KEY"
    OAUTH2_PKCE = "OAUTH2_PKCE"


class MemoryCategory(str, Enum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"
    WORLD_STATE = "world_state"
    PREFERENCE = "preference"


class SkillStatus(str, Enum):
    DRAFT = "DRAFT"
    CANDIDATE = "CANDIDATE"
    EVALUATED = "EVALUATED"
    STAGED = "STAGED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    QUARANTINED = "QUARANTINED"


# ============================================================================
# 2. EXCEPTIONS
# ============================================================================

class JarvisError(Exception):
    """Base exception across all JARVIS packages."""


class IllegalTransitionError(JarvisError):
    """Raised on invalid task state transition or unverified SUCCEEDED attempt."""


class OptimisticLockError(JarvisError):
    """Raised when saving a TaskRecord whose version is stale."""


class PolicyDeniedError(JarvisError):
    """Raised when PolicyEngine or SafetyKernel blocks an action."""


class EmergencyStopActiveError(PolicyDeniedError):
    """Raised when the model-free SafetyKernel kill switch is engaged."""


class ImmutableTargetError(PolicyDeniedError):
    """Raised when code modification targets protected kernel/policy/verifier files."""


class StaleObservationError(JarvisError):
    """Raised when a visual or UI action references an observation older than 2.0s."""


# ============================================================================
# 3. PYDANTIC DATA MODELS
# ============================================================================

class StrictModel(BaseModel):
    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid", validate_assignment=True)
    else:
        class Config:
            extra = "forbid"
            validate_assignment = True

        def model_dump(self, **kwargs: Any) -> Dict[str, Any]:
            return self.dict(**kwargs)

        def model_dump_json(self, **kwargs: Any) -> str:
            return self.json(**kwargs)

        @classmethod
        def model_validate(cls, obj: Any) -> Any:
            return cls.parse_obj(obj)

        @classmethod
        def model_validate_json(cls, raw: str | bytes) -> Any:
            return cls.parse_raw(raw)

        def model_copy(self, *, deep: bool = False, update: Optional[Dict[str, Any]] = None) -> Any:
            return self.copy(deep=deep, update=update)


class AcceptanceCriterion(StrictModel):
    id: str = Field(default_factory=lambda: new_id("ac"))
    description: str
    check_type: str
    expected: Dict[str, Any] = Field(default_factory=dict)
    mandatory: bool = True


class TaskBudget(StrictModel):
    max_wall_seconds: int = 1800
    max_tokens: int = 500_000
    max_cost_usd: float = 2.00
    max_retries: int = 3
    max_subagents: int = 20
    max_depth: int = 4
    spent_tokens: int = 0
    spent_cost_usd: float = 0.0
    retries_used: int = 0


class StandingMandate(StrictModel):
    mandate_id: str = Field(default_factory=lambda: new_id("mnd"))
    name: str
    domain: str
    autonomy_level: AutonomyLevel = AutonomyLevel.A2_COPILOT
    max_risk_tier: RiskTier = RiskTier.R2_EXTERNAL_REVERSIBLE
    daily_spend_cap_usd: float = 0.0
    per_action_spend_cap_usd: float = 0.0
    spent_today_usd: float = 0.0
    allowed_actions: List[str] = Field(default_factory=list)
    allowed_recipients: List[str] = Field(default_factory=list)
    allowed_paths: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    active: bool = True
    expires_at: Optional[datetime] = None


class PlanStep(StrictModel):
    step_id: str = Field(default_factory=lambda: new_id("stp"))
    index: int
    description: str
    tool_name: str
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    depends_on: List[str] = Field(default_factory=list)
    risk_tier: RiskTier = RiskTier.R1_LOCAL_REVERSIBLE
    specialist: SpecialistRole = SpecialistRole.OPERATOR
    completed: bool = False


class CandidatePlan(StrictModel):
    plan_id: str = Field(default_factory=lambda: new_id("pln"))
    strategy_name: str
    summary: str
    steps: List[PlanStep] = Field(default_factory=list)
    estimated_cost_usd: float = 0.0
    estimated_confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    predicted_side_effects: List[str] = Field(default_factory=list)
    critic_score: float = Field(default=0.0, ge=0.0, le=1.0)
    critic_notes: str = ""


class GoalSpec(StrictModel):
    goal_id: str = Field(default_factory=lambda: new_id("goal"))
    principal: str = "owner"
    source_channel: str = "local_cli"
    raw_input: str
    normalized_objective: str
    assumptions: List[str] = Field(default_factory=list)
    acceptance_criteria: List[AcceptanceCriterion] = Field(default_factory=list)
    risk_tier: RiskTier = RiskTier.R1_LOCAL_REVERSIBLE
    data_class: DataClass = DataClass.D1_INTERNAL
    required_verification: VerificationLevel = VerificationLevel.V1_STATE_CHECK
    mandate_id: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)


class TaskRecord(StrictModel):
    task_id: str = Field(default_factory=lambda: new_id("task"))
    goal_id: str
    parent_task_id: Optional[str] = None
    depth: int = 0
    state: TaskState = TaskState.CREATED
    objective: str
    domain: str = "general"
    risk_tier: RiskTier = RiskTier.R1_LOCAL_REVERSIBLE
    data_class: DataClass = DataClass.D1_INTERNAL
    autonomy_level: AutonomyLevel = AutonomyLevel.A2_COPILOT
    required_verification: VerificationLevel = VerificationLevel.V1_STATE_CHECK
    acceptance_criteria: List[AcceptanceCriterion] = Field(default_factory=list)
    budget: TaskBudget = Field(default_factory=TaskBudget)
    calibrated_confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    candidate_plans: List[CandidatePlan] = Field(default_factory=list)
    selected_plan: Optional[CandidatePlan] = None
    mandate_id: Optional[str] = None
    error_message: Optional[str] = None
    version: int = 1
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ApprovalRecord(StrictModel):
    approval_id: str = Field(default_factory=lambda: new_id("apr"))
    task_id: str
    action: str
    args_hash: str
    resource_scope: str
    risk_tier: RiskTier
    data_class: DataClass
    consequences_summary: str
    requires_step_up: bool = False
    status: str = "PENDING"
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utc_now)


class PolicyRequest(StrictModel):
    task_id: str
    principal: str = "owner"
    domain: str = "general"
    action: str
    args: Dict[str, Any] = Field(default_factory=dict)
    resource_scope: str = ""
    data_class: DataClass = DataClass.D1_INTERNAL
    requested_risk: RiskTier = RiskTier.R1_LOCAL_REVERSIBLE
    autonomy_level: AutonomyLevel = AutonomyLevel.A2_COPILOT
    target_provider: str = "local"
    estimated_spend_usd: float = 0.0
    mandate_id: Optional[str] = None
    approval_id: Optional[str] = None
    step_up_verified: bool = False


class AuthorizationDecision(StrictModel):
    decision_id: str = Field(default_factory=lambda: new_id("dec"))
    allowed: bool
    effective_risk: RiskTier
    requires_approval: bool = False
    requires_step_up: bool = False
    reason_code: str
    explanation: str
    policy_hash: str
    decided_at: datetime = Field(default_factory=utc_now)


class ArtifactMeta(StrictModel):
    artifact_id: str = Field(default_factory=lambda: new_id("art"))
    task_id: str
    sha256: str
    media_type: str
    size_bytes: int
    data_class: DataClass = DataClass.D1_INTERNAL
    storage_path: str
    created_at: datetime = Field(default_factory=utc_now)


class EvidenceRecord(StrictModel):
    evidence_id: str = Field(default_factory=lambda: new_id("evd"))
    task_id: str
    criterion_id: Optional[str] = None
    source_type: str
    content_summary: str
    artifact_id: Optional[str] = None
    sha256: Optional[str] = None
    epistemic_label: EpistemicLabel = EpistemicLabel.OBSERVED
    observed_at: datetime = Field(default_factory=utc_now)


class VerificationRecord(StrictModel):
    verification_id: str = Field(default_factory=lambda: new_id("ver"))
    task_id: str
    level_achieved: VerificationLevel
    disposition: VerificationDisposition
    criterion_results: Dict[str, VerificationDisposition] = Field(default_factory=dict)
    evidence_ids: List[str] = Field(default_factory=list)
    checks_run: List[str] = Field(default_factory=list)
    checks_not_run: List[str] = Field(default_factory=list)
    critic_model: Optional[str] = None
    notes: str = ""
    verified_at: datetime = Field(default_factory=utc_now)


class PostMortemReflection(StrictModel):
    reflection_id: str = Field(default_factory=lambda: new_id("rfl"))
    task_id: str
    domain: str = "general"
    outcome: TaskState
    what_worked: List[str] = Field(default_factory=list)
    what_failed: List[str] = Field(default_factory=list)
    root_cause: str
    reusable_lesson: str
    proposed_skill_name: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)


class WorldStatePrediction(StrictModel):
    dry_run_id: str = Field(default_factory=lambda: new_id("sim"))
    action: str
    args: Dict[str, Any] = Field(default_factory=dict)
    predicted_changes: List[str] = Field(default_factory=list)
    reversible: bool = True
    conflict_detected: bool = False
    conflict_reason: str = ""
    safe_to_proceed: bool = True


class UIElementNode(StrictModel):
    node_id: str
    role: str
    name: str
    value: str = ""
    os_backend: str = "auto"
    enabled: bool = True
    focused: bool = False
    is_password: bool = False
    bbox: Tuple[int, int, int, int] = (0, 0, 0, 0)


class DesktopLease(StrictModel):
    lease_id: str = Field(default_factory=lambda: new_id("lse"))
    task_id: str
    owner_role: SpecialistRole = SpecialistRole.OPERATOR
    active_window: str = ""
    os_family: str = Field(default_factory=current_os_family)
    acquired_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime


class OAuthSession(StrictModel):
    provider_name: str
    client_id: str
    auth_mode: AuthMode = AuthMode.OAUTH2_PKCE
    access_token_handle: str
    refresh_token_handle: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    expires_at: datetime


class RemotePairedDevice(StrictModel):
    device_id: str = Field(default_factory=lambda: new_id("rem"))
    device_name: str
    channel: str
    external_user_id: str
    session_token_hash: str
    paired_at: datetime = Field(default_factory=utc_now)
    revoked: bool = False


class CitedClaim(StrictModel):
    claim_id: str = Field(default_factory=lambda: new_id("clm"))
    statement: str
    epistemic_label: EpistemicLabel
    source_artifact_ids: List[str] = Field(default_factory=list)
    source_urls: List[str] = Field(default_factory=list)
    quote_span: str = ""
    source_date: Optional[str] = None


class MemoryItem(StrictModel):
    memory_id: str = Field(default_factory=lambda: new_id("mem"))
    category: MemoryCategory
    content: str
    source_task_id: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    epistemic_label: EpistemicLabel = EpistemicLabel.OBSERVED
    data_class: DataClass = DataClass.D1_INTERNAL
    tags: List[str] = Field(default_factory=list)
    confirmed_by_owner: bool = False
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utc_now)


class SkillManifest(StrictModel):
    skill_id: str = Field(default_factory=lambda: new_id("skl"))
    name: str
    version: str = "1.0.0"
    description: str
    allowed_tools: List[str] = Field(default_factory=list)
    max_risk_tier: RiskTier = RiskTier.R1_LOCAL_REVERSIBLE
    status: SkillStatus = SkillStatus.DRAFT
    code_path: str = ""
    test_path: str = ""
    sha256: str = ""


class ExamScorecard(StrictModel):
    exam_id: str = Field(default_factory=lambda: new_id("exm"))
    track_scores: Dict[str, float] = Field(default_factory=dict)
    overall_score: float = 0.0
    false_success_rate: float = 0.0
    injection_compromise_rate: float = 0.0
    assigned_level: CapabilityLevel = CapabilityLevel.L1_ASSISTANT
    delta_vs_previous: float = 0.0
    passed_gate: bool = False
    created_at: datetime = Field(default_factory=utc_now)


# ============================================================================
# 4. CANONICAL TASK STATE MACHINE
# ============================================================================

ALLOWED_TRANSITIONS: Dict[TaskState, set[TaskState]] = {
    TaskState.CREATED: {TaskState.PLANNING, TaskState.BLOCKED_BY_POLICY, TaskState.CANCEL_REQUESTED},
    TaskState.PLANNING: {
        TaskState.WAITING_FOR_CLARIFICATION,
        TaskState.READY,
        TaskState.BLOCKED_BY_POLICY,
        TaskState.CANCEL_REQUESTED,
        TaskState.EXPIRED,
    },
    TaskState.WAITING_FOR_CLARIFICATION: {
        TaskState.PLANNING,
        TaskState.EXPIRED,
        TaskState.CANCEL_REQUESTED,
    },
    TaskState.READY: {
        TaskState.RUNNING,
        TaskState.WAITING_FOR_APPROVAL,
        TaskState.BLOCKED_BY_POLICY,
        TaskState.CANCEL_REQUESTED,
        TaskState.EXPIRED,
    },
    TaskState.WAITING_FOR_APPROVAL: {
        TaskState.RUNNING,
        TaskState.BLOCKED_BY_POLICY,
        TaskState.EXPIRED,
        TaskState.CANCEL_REQUESTED,
    },
    TaskState.RUNNING: {
        TaskState.WAITING_FOR_DEPENDENCY,
        TaskState.WAITING_FOR_APPROVAL,
        TaskState.PAUSED,
        TaskState.RECOVERING,
        TaskState.VERIFYING,
        TaskState.CANCEL_REQUESTED,
        TaskState.EXPIRED,
        TaskState.BLOCKED_BY_POLICY,
    },
    TaskState.WAITING_FOR_DEPENDENCY: {
        TaskState.RUNNING,
        TaskState.PAUSED,
        TaskState.EXPIRED,
        TaskState.CANCEL_REQUESTED,
    },
    TaskState.PAUSED: {
        TaskState.RUNNING,
        TaskState.CANCEL_REQUESTED,
        TaskState.EXPIRED,
    },
    TaskState.RECOVERING: {
        TaskState.RUNNING,
        TaskState.FAILED,
        TaskState.PARTIALLY_COMPLETED,
        TaskState.CANCEL_REQUESTED,
    },
    TaskState.VERIFYING: {
        TaskState.SUCCEEDED,
        TaskState.RUNNING,
        TaskState.PARTIALLY_COMPLETED,
        TaskState.FAILED,
        TaskState.CANCEL_REQUESTED,
    },
    TaskState.PARTIALLY_COMPLETED: {
        TaskState.PLANNING,
        TaskState.CANCEL_REQUESTED,
    },
    TaskState.CANCEL_REQUESTED: {TaskState.CANCELLED},
    TaskState.SUCCEEDED: set(),
    TaskState.FAILED: set(),
    TaskState.CANCELLED: set(),
    TaskState.EXPIRED: set(),
    TaskState.BLOCKED_BY_POLICY: set(),
}


def validate_transition(
    task: TaskRecord,
    to_state: TaskState,
    verification: Optional[VerificationRecord] = None,
) -> TaskRecord:
    allowed = ALLOWED_TRANSITIONS.get(task.state, set())
    if to_state not in allowed:
        raise IllegalTransitionError(
            f"Illegal state transition from {task.state.value} to {to_state.value}"
        )
    if to_state == TaskState.SUCCEEDED:
        if verification is None:
            raise IllegalTransitionError("Cannot transition to SUCCEEDED without a VerificationRecord")
        if verification.disposition != VerificationDisposition.ACCEPT:
            raise IllegalTransitionError(
                f"Cannot transition to SUCCEEDED with disposition {verification.disposition.value}"
            )
        if verification.level_achieved.rank < task.required_verification.rank:
            raise IllegalTransitionError(
                f"Verification level {verification.level_achieved.value} is below required "
                f"{task.required_verification.value}"
            )
    task.state = to_state
    task.version += 1
    task.updated_at = utc_now()
    return task


# ============================================================================
# 5. SUBSYSTEM PROTOCOLS
# ============================================================================

@runtime_checkable
class StoreProtocol(Protocol):
    def save_goal(self, goal: GoalSpec) -> GoalSpec: ...
    def get_goal(self, goal_id: str) -> Optional[GoalSpec]: ...
    def create_task(self, task: TaskRecord, actor: str = "system", reason: str = "created") -> TaskRecord: ...
    def get_task(self, task_id: str) -> Optional[TaskRecord]: ...
    def list_tasks(self, state: Optional[TaskState] = None, limit: int = 50) -> List[TaskRecord]: ...
    def update_task(self, task: TaskRecord, expected_version: int) -> TaskRecord: ...
    def transition_task(
        self,
        task_id: str,
        to_state: TaskState,
        actor: str,
        reason: str,
        verification: Optional[VerificationRecord] = None,
    ) -> TaskRecord: ...
    def claim_idempotency_key(self, idem_key: str, scope: str, task_id: str) -> str: ...
    def save_mandate(self, mandate: StandingMandate) -> StandingMandate: ...
    def get_mandate(self, mandate_id: str) -> Optional[StandingMandate]: ...
    def list_mandates(self, domain: Optional[str] = None, active_only: bool = True) -> List[StandingMandate]: ...
    def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord: ...
    def get_approval(self, approval_id: str) -> Optional[ApprovalRecord]: ...
    def list_pending_approvals(self, task_id: Optional[str] = None) -> List[ApprovalRecord]: ...
    def save_decision(self, decision: AuthorizationDecision, task_id: str) -> AuthorizationDecision: ...
    def save_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord: ...
    def list_evidence(self, task_id: str) -> List[EvidenceRecord]: ...
    def save_verification(self, verification: VerificationRecord) -> VerificationRecord: ...
    def get_latest_verification(self, task_id: str) -> Optional[VerificationRecord]: ...
    def save_reflection(self, reflection: PostMortemReflection) -> PostMortemReflection: ...
    def list_reflections(self, domain: Optional[str] = None, limit: int = 10) -> List[PostMortemReflection]: ...
    def verify_audit_chain(self) -> Tuple[bool, Optional[int]]: ...
    def put_artifact(self, data: bytes, media_type: str, data_class: DataClass, task_id: str) -> ArtifactMeta: ...
    def get_artifact(self, artifact_id: str, verify_hash: bool = True) -> Tuple[ArtifactMeta, bytes]: ...


@runtime_checkable
class SafetyKernelProtocol(Protocol):
    def emergency_stop(self, reason: str, actor: str = "owner") -> None: ...
    def resume(self, confirmation_token: str, actor: str = "owner") -> None: ...
    def is_stopped(self) -> bool: ...
    def assert_immutable_path(self, relative_path: str) -> None: ...
    def register_pid(self, pid: int) -> None: ...
    def unregister_pid(self, pid: int) -> None: ...


@runtime_checkable
class PolicyEngineProtocol(Protocol):
    def evaluate(self, request: PolicyRequest) -> AuthorizationDecision: ...
    def wrap_untrusted(self, content: str, source: str) -> str: ...
    def scan_prompt_injection(self, content: str) -> List[str]: ...


@runtime_checkable
class SecretsBrokerProtocol(Protocol):
    def put_secret(self, name: str, value: str, allowed_domains: Optional[List[str]] = None) -> None: ...
    def issue_handle(self, task_id: str, secret_name: str, ttl_seconds: int = 120) -> str: ...
    def inject_into_env(self, handle: str, env_dict: Dict[str, str], env_key: str) -> Dict[str, str]: ...
    def inject_into_callback(self, handle: str, callback: Callable[[str], Any]) -> Any: ...
    def revoke_handle(self, handle: str) -> None: ...
    def store_oauth_session(
        self,
        provider_name: str,
        client_id: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        ttl_seconds: int = 3600,
        scopes: Optional[List[str]] = None,
    ) -> OAuthSession: ...
    def get_valid_oauth_handle(self, task_id: str, provider_name: str) -> str: ...


@runtime_checkable
class SandboxRunnerProtocol(Protocol):
    def classify_command(self, cmd: str) -> RiskTier: ...
    def format_aci_output(self, exit_code: int, stdout: str, stderr: str, max_lines: int = 40) -> str: ...
    def run_cmd(
        self,
        cmd: List[str],
        cwd: str,
        task: TaskRecord,
        timeout_seconds: int = 60,
        allow_network: bool = False,
    ) -> Tuple[int, str, str, EvidenceRecord]: ...


@runtime_checkable
class ToolProtocol(Protocol):
    name: str
    description: str
    default_risk: RiskTier
    idempotent: bool

    def execute(self, args: Dict[str, Any], task: TaskRecord) -> Tuple[Dict[str, Any], EvidenceRecord]: ...
    def reconcile(self, args: Dict[str, Any], task: TaskRecord) -> ReconcileOutcome: ...


@runtime_checkable
class JobRunnerProtocol(Protocol):
    def register_tool(self, tool: ToolProtocol) -> None: ...
    def get_registered_tools(self) -> List[str]: ...
    def execute_step(
        self,
        task: TaskRecord,
        step: PlanStep,
        approval_id: Optional[str] = None,
        step_up_verified: bool = False,
    ) -> Tuple[Dict[str, Any], Optional[EvidenceRecord]]: ...


@runtime_checkable
class ModelGatewayProtocol(Protocol):
    def configure_oauth_provider(self, session: OAuthSession, endpoint_url: str) -> None: ...
    def generate(
        self,
        messages: List[Dict[str, str]],
        data_class: DataClass = DataClass.D1_INTERNAL,
        role: SpecialistRole = SpecialistRole.PLANNER,
        task: Optional[TaskRecord] = None,
        target_provider: Optional[str] = None,
    ) -> Dict[str, Any]: ...
    def generate_structured(
        self,
        messages: List[Dict[str, str]],
        response_schema: type[BaseModel],
        data_class: DataClass = DataClass.D1_INTERNAL,
        role: SpecialistRole = SpecialistRole.PLANNER,
        task: Optional[TaskRecord] = None,
    ) -> BaseModel: ...


@runtime_checkable
class PCControllerProtocol(Protocol):
    def acquire_lease(self, task_id: str, ttl_seconds: int = 60) -> DesktopLease: ...
    def release_lease(self, lease_id: str) -> None: ...
    def get_active_lease(self) -> Optional[DesktopLease]: ...
    def dump_accessibility_tree(self, window_title: str = "") -> List[UIElementNode]: ...
    def capture_masked_screenshot(self, task_id: str, window_title: str = "") -> Tuple[ArtifactMeta, List[UIElementNode]]: ...
    def execute_pc_action(
        self,
        task: TaskRecord,
        action: str,
        args: Dict[str, Any],
        lease_id: str,
    ) -> Tuple[Dict[str, Any], EvidenceRecord]: ...


@runtime_checkable
class WebResearchProtocol(Protocol):
    def validate_url(self, url: str) -> str: ...
    def browse_and_extract(self, task: TaskRecord, url: str, selector: str = "body") -> Tuple[str, EvidenceRecord]: ...
    def conduct_research(self, task: TaskRecord, query: str, sources: List[Dict[str, str]]) -> List[CitedClaim]: ...


@runtime_checkable
class WorldMemoryProtocol(Protocol):
    def store_memory(self, item: MemoryItem) -> MemoryItem: ...
    def search_memory(self, query: str, max_data_class: DataClass = DataClass.D2_CONFIDENTIAL, limit: int = 5) -> List[MemoryItem]: ...
    def delete_memory(self, memory_id: str) -> bool: ...
    def predict_consequences(self, action: str, args: Dict[str, Any], task: TaskRecord) -> WorldStatePrediction: ...
    def record_reflection(self, task: TaskRecord, evidence: List[EvidenceRecord], error_msg: str = "") -> PostMortemReflection: ...
    def synthesize_skill(self, name: str, description: str, code_body: str, test_body: str, task: TaskRecord) -> SkillManifest: ...


@runtime_checkable
class VerifierExamProtocol(Protocol):
    def verify_task(self, task: TaskRecord, evidence: List[EvidenceRecord]) -> VerificationRecord: ...
    def run_canary(self) -> bool: ...
    def run_capability_exam(self, quick: bool = False) -> ExamScorecard: ...


@runtime_checkable
class RemoteControlProtocol(Protocol):
    def generate_pairing_code(self, ttl_seconds: int = 300) -> str: ...
    def complete_pairing(
        self,
        pairing_code: str,
        channel: str,
        external_user_id: str,
        device_name: str,
    ) -> Tuple[RemotePairedDevice, str]: ...
    def handle_remote_message(
        self,
        channel: str,
        external_user_id: str,
        session_token: str,
        text: str,
    ) -> Dict[str, Any]: ...
    def revoke_remote_device(self, device_id: str) -> bool: ...


if __name__ == "__main__":
    g = GoalSpec(
        raw_input="Smoke test contracts",
        normalized_objective="Verify contracts module",
        acceptance_criteria=[AcceptanceCriterion(description="ok", check_type="file_exists")],
    )
    t = TaskRecord(
        goal_id=g.goal_id,
        objective=g.normalized_objective,
        required_verification=VerificationLevel.V2_INDEPENDENT,
        acceptance_criteria=g.acceptance_criteria,
    )
    validate_transition(t, TaskState.PLANNING)
    validate_transition(t, TaskState.READY)
    validate_transition(t, TaskState.RUNNING)
    validate_transition(t, TaskState.VERIFYING)
    ver = VerificationRecord(
        task_id=t.task_id,
        level_achieved=VerificationLevel.V2_INDEPENDENT,
        disposition=VerificationDisposition.ACCEPT,
    )
    validate_transition(t, TaskState.SUCCEEDED, ver)
    print("CONTRACTS_V5_1_SMOKE_TEST_PASSED", t.task_id)
