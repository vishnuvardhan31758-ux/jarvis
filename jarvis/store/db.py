"""jarvis/store/db.py — SQLite WAL Persistence Layer implementing StoreProtocol."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import List, Optional, Tuple
from jarvis.contracts import (
    ApprovalRecord,
    ArtifactMeta,
    AuthorizationDecision,
    DataClass,
    EvidenceRecord,
    GoalSpec,
    JarvisError,
    OptimisticLockError,
    PostMortemReflection,
    StandingMandate,
    StoreProtocol,
    TaskRecord,
    TaskState,
    VerificationRecord,
    utc_now,
    validate_transition,
)
from jarvis.store.artifacts import ArtifactStore
from jarvis.store.audit import AuditLogger


class DatabaseStore:
    def __init__(
        self,
        db_path: str | Path = "data/jarvis.db",
        artifact_dir: str | Path = "data/artifacts",
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.audit = AuditLogger(self.db_path)
        self.artifacts = ArtifactStore(artifact_dir)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            self.audit.init_schema(conn)
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS goals (
                    goal_id TEXT PRIMARY KEY,
                    principal TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    goal_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
                CREATE TABLE IF NOT EXISTS mandates (
                    mandate_id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verifications (
                    verification_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    verified_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reflections (
                    reflection_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    idem_key TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (idem_key, scope)
                );
                """
            )

    def save_goal(self, goal: GoalSpec) -> GoalSpec:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO goals (goal_id, principal, created_at, payload_json) VALUES (?, ?, ?, ?)",
                (goal.goal_id, goal.principal, goal.created_at.isoformat(), goal.model_dump_json()),
            )
            self.audit.append_entry(conn, goal.principal, "goal.save", goal.normalized_objective)
        return goal

    def get_goal(self, goal_id: str) -> Optional[GoalSpec]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT payload_json FROM goals WHERE goal_id = ?", (goal_id,)).fetchone()
            return GoalSpec.model_validate_json(row[0]) if row else None

    def create_task(self, task: TaskRecord, actor: str = "system", reason: str = "created") -> TaskRecord:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tasks (task_id, goal_id, state, domain, version, updated_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.task_id,
                    task.goal_id,
                    task.state.value,
                    task.domain,
                    task.version,
                    task.updated_at.isoformat(),
                    task.model_dump_json(),
                ),
            )
            self.audit.append_entry(conn, actor, f"task.create.{task.state.value}", reason, task.task_id)
        return task

    def get_task(self, task_id: str) -> Optional[TaskRecord]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT payload_json FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            return TaskRecord.model_validate_json(row[0]) if row else None

    def list_tasks(self, state: Optional[TaskState] = None, limit: int = 50) -> List[TaskRecord]:
        with self._lock, self._connect() as conn:
            if state is not None:
                rows = conn.execute(
                    "SELECT payload_json FROM tasks WHERE state = ? ORDER BY updated_at DESC LIMIT ?",
                    (state.value, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload_json FROM tasks ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [TaskRecord.model_validate_json(r[0]) for r in rows]

    def update_task(self, task: TaskRecord, expected_version: int) -> TaskRecord:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT version FROM tasks WHERE task_id = ?", (task.task_id,)).fetchone()
            if row is None:
                raise JarvisError(f"Task {task.task_id} does not exist")
            current_version = int(row[0])
            if current_version != expected_version:
                raise OptimisticLockError(
                    f"Optimistic lock failed for {task.task_id}: expected version {expected_version}, found {current_version}"
                )
            task.version = expected_version + 1
            task.updated_at = utc_now()
            conn.execute(
                """
                UPDATE tasks
                SET state = ?, domain = ?, version = ?, updated_at = ?, payload_json = ?
                WHERE task_id = ? AND version = ?
                """,
                (
                    task.state.value,
                    task.domain,
                    task.version,
                    task.updated_at.isoformat(),
                    task.model_dump_json(),
                    task.task_id,
                    expected_version,
                ),
            )
            self.audit.append_entry(conn, "system", "task.update", f"version={task.version}", task.task_id)
        return task

    def transition_task(
        self,
        task_id: str,
        to_state: TaskState,
        actor: str,
        reason: str,
        verification: Optional[VerificationRecord] = None,
    ) -> TaskRecord:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT payload_json, version FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            if row is None:
                raise JarvisError(f"Task {task_id} not found")
            task = TaskRecord.model_validate_json(row[0])
            expected_version = int(row[1])
            validate_transition(task, to_state, verification)
            conn.execute(
                """
                UPDATE tasks
                SET state = ?, version = ?, updated_at = ?, payload_json = ?
                WHERE task_id = ? AND version = ?
                """,
                (
                    task.state.value,
                    task.version,
                    task.updated_at.isoformat(),
                    task.model_dump_json(),
                    task.task_id,
                    expected_version,
                ),
            )
            self.audit.append_entry(conn, actor, f"task.transition.{to_state.value}", reason, task.task_id)
        return task

    def claim_idempotency_key(self, idem_key: str, scope: str, task_id: str) -> str:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT task_id FROM idempotency_keys WHERE idem_key = ? AND scope = ?",
                (idem_key, scope),
            ).fetchone()
            if row is not None:
                return str(row[0])
            conn.execute(
                "INSERT INTO idempotency_keys (idem_key, scope, task_id, created_at) VALUES (?, ?, ?, ?)",
                (idem_key, scope, task_id, utc_now().isoformat()),
            )
            return task_id

    def save_mandate(self, mandate: StandingMandate) -> StandingMandate:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO mandates (mandate_id, domain, active, payload_json) VALUES (?, ?, ?, ?)",
                (mandate.mandate_id, mandate.domain, 1 if mandate.active else 0, mandate.model_dump_json()),
            )
            self.audit.append_entry(conn, "owner", "mandate.save", mandate.name)
        return mandate

    def get_mandate(self, mandate_id: str) -> Optional[StandingMandate]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT payload_json FROM mandates WHERE mandate_id = ?", (mandate_id,)).fetchone()
            return StandingMandate.model_validate_json(row[0]) if row else None

    def list_mandates(self, domain: Optional[str] = None, active_only: bool = True) -> List[StandingMandate]:
        with self._lock, self._connect() as conn:
            q = "SELECT payload_json FROM mandates WHERE 1=1"
            params: list = []
            if domain:
                q += " AND domain = ?"
                params.append(domain)
            if active_only:
                q += " AND active = 1"
            rows = conn.execute(q, tuple(params)).fetchall()
            return [StandingMandate.model_validate_json(r[0]) for r in rows]

    def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO approvals (approval_id, task_id, status, payload_json) VALUES (?, ?, ?, ?)",
                (approval.approval_id, approval.task_id, approval.status, approval.model_dump_json()),
            )
            self.audit.append_entry(
                conn,
                approval.decided_by or "system",
                f"approval.{approval.status.lower()}",
                approval.action,
                approval.task_id,
            )
        return approval

    def get_approval(self, approval_id: str) -> Optional[ApprovalRecord]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT payload_json FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            return ApprovalRecord.model_validate_json(row[0]) if row else None

    def list_pending_approvals(self, task_id: Optional[str] = None) -> List[ApprovalRecord]:
        with self._lock, self._connect() as conn:
            if task_id:
                rows = conn.execute(
                    "SELECT payload_json FROM approvals WHERE status = 'PENDING' AND task_id = ?",
                    (task_id,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT payload_json FROM approvals WHERE status = 'PENDING'").fetchall()
            return [ApprovalRecord.model_validate_json(r[0]) for r in rows]

    def save_decision(self, decision: AuthorizationDecision, task_id: str) -> AuthorizationDecision:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO decisions (decision_id, task_id, payload_json) VALUES (?, ?, ?)",
                (decision.decision_id, task_id, decision.model_dump_json()),
            )
            self.audit.append_entry(conn, "policy", f"decision.{decision.reason_code}", decision.explanation, task_id)
        return decision

    def save_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO evidence (evidence_id, task_id, observed_at, payload_json) VALUES (?, ?, ?, ?)",
                (evidence.evidence_id, evidence.task_id, evidence.observed_at.isoformat(), evidence.model_dump_json()),
            )
        return evidence

    def list_evidence(self, task_id: str) -> List[EvidenceRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM evidence WHERE task_id = ? ORDER BY observed_at ASC",
                (task_id,),
            ).fetchall()
            return [EvidenceRecord.model_validate_json(r[0]) for r in rows]

    def save_verification(self, verification: VerificationRecord) -> VerificationRecord:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO verifications (verification_id, task_id, verified_at, payload_json) VALUES (?, ?, ?, ?)",
                (
                    verification.verification_id,
                    verification.task_id,
                    verification.verified_at.isoformat(),
                    verification.model_dump_json(),
                ),
            )
            self.audit.append_entry(
                conn,
                "verifier",
                f"verify.{verification.disposition.value}",
                verification.notes or verification.level_achieved.value,
                verification.task_id,
            )
        return verification

    def get_latest_verification(self, task_id: str) -> Optional[VerificationRecord]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM verifications WHERE task_id = ? ORDER BY verified_at DESC LIMIT 1",
                (task_id,),
            ).fetchone()
            return VerificationRecord.model_validate_json(row[0]) if row else None

    def save_reflection(self, reflection: PostMortemReflection) -> PostMortemReflection:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO reflections (reflection_id, task_id, domain, created_at, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    reflection.reflection_id,
                    reflection.task_id,
                    reflection.domain,
                    reflection.created_at.isoformat(),
                    reflection.model_dump_json(),
                ),
            )
        return reflection

    def list_reflections(self, domain: Optional[str] = None, limit: int = 10) -> List[PostMortemReflection]:
        with self._lock, self._connect() as conn:
            if domain:
                rows = conn.execute(
                    "SELECT payload_json FROM reflections WHERE domain = ? ORDER BY created_at DESC LIMIT ?",
                    (domain, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload_json FROM reflections ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [PostMortemReflection.model_validate_json(r[0]) for r in rows]

    def verify_audit_chain(self) -> Tuple[bool, Optional[int]]:
        return self.audit.verify_chain()

    def put_artifact(self, data: bytes, media_type: str, data_class: DataClass, task_id: str) -> ArtifactMeta:
        meta = self.artifacts.put_bytes(data, media_type, data_class, task_id)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO artifacts (artifact_id, task_id, sha256, payload_json) VALUES (?, ?, ?, ?)",
                (meta.artifact_id, task_id, meta.sha256, meta.model_dump_json()),
            )
        return meta

    def get_artifact(self, artifact_id: str, verify_hash: bool = True) -> Tuple[ArtifactMeta, bytes]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT payload_json FROM artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone()
            if row is None:
                raise JarvisError(f"Artifact {artifact_id} not found in store")
            meta = ArtifactMeta.model_validate_json(row[0])
        raw = self.artifacts.get_bytes(meta, verify_hash=verify_hash)
        return meta, raw
