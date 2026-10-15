"""jarvis/memory/world_model.py — Persistent World Model & Consequence Dry-Run Simulator."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from jarvis.contracts import StandingMandate, TaskRecord, WorldStatePrediction


class WorldModel:
    def __init__(self) -> None:
        self._projects: Dict[str, Dict[str, Any]] = {}
        self._calendar_slots: List[Dict[str, str]] = []
        self._contacts: Dict[str, Dict[str, Any]] = {}

    def register_project(
        self,
        path: str,
        dirty_files: Optional[List[str]] = None,
        protected_branches: Optional[List[str]] = None,
    ) -> None:
        self._projects[path] = {
            "dirty_files": set(dirty_files or []),
            "protected_branches": set(protected_branches or ["main", "master"]),
        }

    def register_calendar_slot(self, start_iso: str, end_iso: str, title: str) -> None:
        self._calendar_slots.append({"start_iso": start_iso, "end_iso": end_iso, "title": title})

    def register_known_contact(self, email: str, name: str, trusted: bool = True) -> None:
        self._contacts[email.lower()] = {"name": name, "trusted": trusted}

    def predict_consequences(
        self,
        action: str,
        args: Dict[str, Any],
        task: TaskRecord,
        mandate: Optional[StandingMandate] = None,
    ) -> WorldStatePrediction:
        if action in {"fs.write", "fs.delete_permanent", "code.patch"}:
            target = str(args.get("path", args.get("file_path", "")))
            for proj in self._projects.values():
                if target in proj["dirty_files"] or any(target.endswith(df) for df in proj["dirty_files"]):
                    return WorldStatePrediction(
                        action=action,
                        args=args,
                        predicted_changes=[f"Overwrites uncommitted dirty file '{target}'"],
                        reversible=False,
                        conflict_detected=True,
                        conflict_reason=f"Target file '{target}' has uncommitted local changes",
                        safe_to_proceed=False,
                    )

        if action in {"git.push_branch", "git.merge_main"}:
            branch = str(args.get("branch", "main" if action == "git.merge_main" else ""))
            if branch in {"main", "master"}:
                return WorldStatePrediction(
                    action=action,
                    args=args,
                    predicted_changes=[f"Mutates protected git branch '{branch}'"],
                    reversible=False,
                    conflict_detected=True,
                    conflict_reason=f"Branch '{branch}' is a protected branch",
                    safe_to_proceed=False,
                )

        if action in {"calendar.invite", "calendar.create_local"}:
            s_iso = str(args.get("start_iso", ""))
            e_iso = str(args.get("end_iso", ""))
            if s_iso and e_iso:
                for slot in self._calendar_slots:
                    if s_iso < slot["end_iso"] and e_iso > slot["start_iso"]:
                        return WorldStatePrediction(
                            action=action,
                            args=args,
                            predicted_changes=[f"Creates overlapping calendar event with '{slot['title']}'"],
                            reversible=True,
                            conflict_detected=True,
                            conflict_reason=f"Overlaps existing calendar slot '{slot['title']}'",
                            safe_to_proceed=False,
                        )

        if action == "email.send":
            recip = str(args.get("recipient", args.get("to", ""))).lower()
            allowed_by_mandate = bool(mandate and recip in [r.lower() for r in mandate.allowed_recipients])
            if recip and recip not in self._contacts and not allowed_by_mandate:
                return WorldStatePrediction(
                    action=action,
                    args=args,
                    predicted_changes=[f"Sends external email to unknown recipient '{recip}'"],
                    reversible=False,
                    conflict_detected=True,
                    conflict_reason=f"Recipient '{recip}' is not in known contacts or mandate allowlist",
                    safe_to_proceed=False,
                )

        return WorldStatePrediction(
            action=action,
            args=args,
            predicted_changes=[f"Executes {action}"],
            reversible=(task.risk_tier.rank <= 2),
            conflict_detected=False,
            safe_to_proceed=True,
        )
