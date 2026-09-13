from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable

from keeper.app.git_safety import GitSafetyService
from keeper.app.lifecycle import RunLifecycle, RunStage
from keeper.app.notifications import deliver_local_notification
from keeper.app.reporting import (
    finalize_evidence,
    verify_protected_evidence,
)
from keeper.app.path_safety import contained_path, validate_path_budget
from keeper.app.security import redact_text
from keeper.app.storage import KeeperStore, default_data_directory
from keeper.app.workflow import WorkflowCoordinator
from keeper.authority_service.client import AuthorityServiceClient
from keeper.providers.adapters import (
    ProviderDiscovery,
    validate_provider_registration_contract,
)
from keeper.recovery import atomic_write_json, load_json
from keeper.version import VERSION


authority_client_factory: Callable[[Path], AuthorityServiceClient] = (
    lambda _data_directory: AuthorityServiceClient()
)


def _reject_reparse_components(path: Path) -> None:
    """Reject symlinks and Windows junctions anywhere in an evidence path."""
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if not os.path.lexists(current):
            continue
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise PermissionError(
                "evidence path identity cannot be safely inspected"
            ) from error
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if stat.S_ISLNK(metadata.st_mode) or attributes & 0x400:
            raise PermissionError("evidence path cannot contain a reparse point")


def _same_path(left: Path, right: Path) -> bool:
    """Compare local path spellings without touching an untrusted target."""
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def _validated_evidence_child(root: Path, path: Path, label: str) -> Path:
    """Return one evidence child only when its whole path remains trustworthy."""
    _reject_reparse_components(path)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise PermissionError(f"{label} identity cannot be safely inspected") from error
    if not resolved.is_relative_to(root):
        raise PermissionError(f"{label} escapes the run root")
    return resolved


class KeeperApplication:
    def __init__(self, data_directory: Path | None = None) -> None:
        self.data_directory = (data_directory or default_data_directory()).resolve()
        self.store = KeeperStore(self.data_directory / "keeper.db")
        self.store.migrate()
        self.authority = authority_client_factory(self.data_directory)
        self.git = GitSafetyService()
        self.lifecycle = RunLifecycle(self.store)
        self.workflow = WorkflowCoordinator(
            self.store, self.data_directory, self.notify, self.authority
        )

    def diagnostics(self) -> dict[str, Any]:
        try:
            providers = [
                item.to_dict()
                for item in ProviderDiscovery(
                    self.provider_paths(),
                    self.provider_registrations(),
                    self.qualification_evidence(),
                    self.authority.verify,
                ).discover()
            ]
            provider_diagnostics_error = None
        except (OSError, PermissionError, RuntimeError, TimeoutError) as error:
            providers = []
            provider_diagnostics_error = str(error)
        writable = _writable(self.data_directory)
        try:
            authority_diagnostics: dict[str, Any] = self.authority.diagnostics()
            authority_status = "available"
        except (OSError, PermissionError, RuntimeError, TimeoutError) as error:
            authority_diagnostics = {"error": str(error)}
            authority_status = "unavailable"
        return {
            "keeper_version": VERSION,
            "python": sys.version.split()[0],
            "python_supported": sys.version_info >= (3, 12),
            "git": shutil.which("git"),
            "git_available": shutil.which("git") is not None,
            "data_directory": str(self.data_directory),
            "data_directory_writable": writable,
            "providers": providers,
            "provider_diagnostics_error": provider_diagnostics_error,
            "local_only": True,
            "authority_service_status": authority_status,
            "authority_service": authority_diagnostics,
        }

    def setup_complete(self) -> bool:
        value = self.store.get("settings", "application")
        return bool(value and value.get("setup_complete"))

    def finish_setup(self, evidence_directory: Path | None = None) -> None:
        settings = self.store.get("settings", "application") or {}
        settings.update(
            {
                "setup_complete": True,
                "evidence_directory": str(
                    (evidence_directory or self.data_directory / "evidence").resolve()
                ),
                "theme": settings.get("theme", "dark"),
                "log_retention_days": settings.get("log_retention_days", 90),
                "default_timeout_seconds": settings.get("default_timeout_seconds", 1800),
            }
        )
        self.store.upsert("settings", "application", settings)

    def provider_paths(self) -> dict[str, str]:
        value = self.store.get("settings", "providers") or {}
        return {
            str(key): str(path)
            for key, path in value.items()
            if isinstance(key, str) and isinstance(path, str)
        }

    def save_provider_paths(self, paths: dict[str, str]) -> None:
        self.store.upsert("settings", "providers", paths)

    def provider_registrations(self) -> dict[str, dict[str, Any]]:
        value = self.store.get("settings", "provider_registrations") or {}
        return {
            str(key): dict(registration)
            for key, registration in value.items()
            if isinstance(key, str) and isinstance(registration, dict)
        }

    def qualification_evidence(self) -> dict[str, dict[str, Any]]:
        return {
            str(item["id"]): item
            for item in self.store.list("artifacts")
            if item.get("kind")
            in {"provider_qualification", "provider_qualification_started"}
            and isinstance(item.get("id"), str)
        }

    def sync_qualified_provider(
        self,
        provider_id: str,
        registration_id: str,
        qualification_id: str,
    ) -> dict[str, Any]:
        """Project one exact Authority-qualified provider into local UI state.

        Authority remains the source of truth.  This operation only imports
        signed, terminal records that already exist; it never registers,
        qualifies, launches, or retries a provider.
        """

        if provider_id not in {"codex", "claude", "gemini", "qwen"}:
            raise PermissionError("provider projection identity is unsupported")
        if not registration_id.strip() or not qualification_id.strip():
            raise ValueError(
                "provider projection requires exact registration and qualification IDs"
            )

        registration_result = self.authority.query_state(
            "registrations", registration_id
        )
        registration_value = registration_result.get("record")
        if not registration_result.get("found") or not isinstance(
            registration_value, dict
        ):
            raise PermissionError("Authority provider registration is unavailable")
        registration = dict(registration_value)
        registration_state = registration.pop("service_state", None)
        valid, detail = validate_provider_registration_contract(registration)
        if (
            registration_state != "QUALIFIED"
            or registration.get("registration_lifecycle") != "QUALIFIED"
            or registration.get("logical_provider_id") != provider_id
            or registration.get("trusted_registration_id") != registration_id
            or registration.get("qualification_evidence_id") != qualification_id
            or not valid
        ):
            raise PermissionError(
                f"Authority provider registration is not projectable: {detail}"
            )

        qualification_result = self.authority.query_state(
            "qualifications", qualification_id
        )
        qualification_value = qualification_result.get("record")
        if not qualification_result.get("found") or not isinstance(
            qualification_value, dict
        ):
            raise PermissionError("Authority provider qualification is unavailable")
        qualification = dict(qualification_value)
        qualification_state = qualification.pop("service_state", None)
        start = qualification.get("start")
        evidence = qualification.get("evidence")
        if (
            qualification_state != "QUALIFIED"
            or not isinstance(start, dict)
            or not isinstance(evidence, dict)
            or start.get("kind") != "provider_qualification_started"
            or evidence.get("kind") != "provider_qualification"
            or start.get("id") != f"{qualification_id}:started"
            or evidence.get("id") != qualification_id
            or start.get("registration_id") != registration_id
            or evidence.get("registration_id") != registration_id
            or start.get("provider_id") != provider_id
            or evidence.get("provider_id") != provider_id
            or evidence.get("qualification_result") != "qualified"
            or evidence.get("evidence_digest")
            != registration.get("qualification_evidence_digest")
            or not self.authority.verify("provider-qualification-start", start)
            or not self.authority.verify("provider-qualification", evidence)
        ):
            raise PermissionError(
                "Authority provider qualification is not projectable"
            )

        existing_registrations = self.provider_registrations()
        existing_registration = existing_registrations.get(provider_id)
        if existing_registration is not None and existing_registration != registration:
            existing_registration_id = existing_registration.get(
                "trusted_registration_id"
            )
            existing_authority_result = (
                self.authority.query_state(
                    "registrations", existing_registration_id
                )
                if isinstance(existing_registration_id, str)
                else {}
            )
            existing_authority_value = existing_authority_result.get("record")
            existing_authority_registration = (
                dict(existing_authority_value)
                if existing_authority_result.get("found")
                and isinstance(existing_authority_value, dict)
                else None
            )
            existing_authority_state = (
                existing_authority_registration.pop("service_state", None)
                if existing_authority_registration is not None
                else None
            )
            existing_executable = (
                existing_authority_registration.get("canonical_executable_path")
                if existing_authority_registration is not None
                else None
            )
            if (
                existing_authority_state != "REVOKED"
                or existing_authority_registration is None
                or existing_authority_registration.get("registration_lifecycle")
                != "REVOKED"
                or existing_authority_registration.get("logical_provider_id")
                != provider_id
                or existing_authority_registration.get("trusted_registration_id")
                != existing_registration_id
                or not isinstance(existing_executable, str)
                or Path(existing_executable).resolve()
                != Path(str(registration["canonical_executable_path"])).resolve()
            ):
                raise PermissionError(
                    "local provider projection conflicts with another registration"
                )

        artifacts_to_insert: list[tuple[str, dict[str, Any]]] = []
        for artifact in (start, evidence):
            identifier = artifact.get("id")
            if not isinstance(identifier, str) or not identifier:
                raise PermissionError(
                    "Authority provider qualification identity is malformed"
                )
            existing_artifact = self.store.get("artifacts", identifier)
            if existing_artifact is None:
                artifacts_to_insert.append((identifier, artifact))
            elif existing_artifact != artifact:
                raise PermissionError(
                    "local qualification projection conflicts with Authority evidence"
                )

        canonical_executable = registration.get("canonical_executable_path")
        if not isinstance(canonical_executable, str) or not canonical_executable:
            raise PermissionError(
                "Authority provider executable projection is unavailable"
            )
        paths = self.provider_paths()
        existing_path = paths.get(provider_id)
        if existing_path is not None and Path(existing_path).resolve() != Path(
            canonical_executable
        ).resolve():
            raise PermissionError(
                "local provider path conflicts with the Authority registration"
            )

        for identifier, artifact in artifacts_to_insert:
            self.store.insert_immutable("artifacts", identifier, artifact)
        paths[provider_id] = canonical_executable
        self.save_provider_paths(paths)

        existing_registrations[provider_id] = registration
        self.store.upsert(
            "settings", "provider_registrations", existing_registrations
        )
        return {
            "provider_id": provider_id,
            "registration_id": registration_id,
            "qualification_id": qualification_id,
            "registration_lifecycle": registration["registration_lifecycle"],
            "projected": True,
        }

    def migrate_legacy_authority(self) -> dict[str, Any]:
        existing = list(self.provider_registrations().values())
        result = self.authority.migrate_legacy(existing)
        migrated = result.get("registrations")
        if not isinstance(migrated, list) or any(
            not isinstance(item, dict) for item in migrated
        ):
            raise RuntimeError("Authority Service migration response is malformed")
        registrations = {
            str(item["logical_provider_id"]): dict(item)
            for item in migrated
        }
        self.store.upsert(
            "settings", "provider_registrations", registrations
        )
        self.store.upsert(
            "settings",
            "authority_migration",
            {
                "status": "MIGRATED_UNQUALIFIED",
                "legacy_evidence_status": "UNVERIFIABLE",
                "migrated_at": _now(),
                "migrated_registrations": len(registrations),
            },
        )
        return result

    def register_provider(
        self,
        provider_id: str,
        executable: Path,
        authorizer: str,
        *,
        executive_capabilities: list[str],
        project_types: list[str],
        effort_levels: list[str],
        pricing_authority: dict[str, Any],
        expected_executable_sha256: str | None = None,
        expected_executable_size: int | None = None,
        expected_version: str | None = None,
        model_allowlist: list[str] | None = None,
        model_revalidation_expires_at: str | None = None,
        authentication_policy: dict[str, Any] | None = None,
        usage_policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if (
            provider_id not in {"codex", "claude", "gemini", "qwen"}
            or not authorizer.strip()
        ):
            raise PermissionError(
                "provider registration requires a supported identity and authorizer"
            )
        declarations: dict[str, Any] = {
            "executive_capabilities": executive_capabilities,
            "project_types": project_types,
            "effort_levels": effort_levels,
            "pricing_authority": pricing_authority,
        }
        extended = (
            model_allowlist,
            expected_executable_sha256,
            expected_executable_size,
            expected_version,
            model_revalidation_expires_at,
            authentication_policy,
            usage_policy,
        )
        if any(item is not None for item in extended):
            if any(item is None for item in extended):
                raise ValueError(
                    "Codex subscription registration declaration is incomplete"
                )
            declarations.update(
                {
                    "model_allowlist": model_allowlist,
                    "expected_executable_sha256": expected_executable_sha256,
                    "expected_executable_size": expected_executable_size,
                    "expected_version": expected_version,
                    "model_revalidation_expires_at": (
                        model_revalidation_expires_at
                    ),
                    "authentication_policy": authentication_policy,
                    "usage_policy": usage_policy,
                }
            )
        protected = self.authority.register_provider(
            provider_id, executable, **declarations
        )
        registration = protected.get("registration")
        if not isinstance(registration, dict):
            raise RuntimeError(
                "Authority Service provider registration is malformed"
            )
        registrations = self.provider_registrations()
        registrations[provider_id] = registration
        self.store.upsert(
            "settings", "provider_registrations", registrations
        )
        return registration

    def qualify_provider(
        self, provider_id: str, authorizer: str
    ) -> dict[str, Any]:
        registrations = self.provider_registrations()
        registration = registrations.get(provider_id)
        if not isinstance(registration, dict) or not authorizer.strip():
            raise PermissionError("qualification requires registration and authorization")
        executable: Path | None = None
        if registration.get("registration_schema_version") in {4, 5}:
            canonical = registration.get("canonical_executable_path")
            if not isinstance(canonical, str) or not canonical.strip():
                raise PermissionError(
                    "subscription qualification requires the registered executable"
                )
            executable = Path(canonical)
        registration_id = str(registration["trusted_registration_id"])
        protected = (
            self.authority.qualify_provider(registration_id, executable)
            if executable is not None
            else self.authority.qualify_provider(registration_id)
        )
        updated = protected.get("registration")
        evidence = protected.get("qualification")
        start_record = protected.get("qualification_start")
        if (
            not isinstance(updated, dict)
            or not isinstance(evidence, dict)
            or not isinstance(start_record, dict)
        ):
            raise RuntimeError(
                "Authority Service qualification response is malformed"
            )
        self.store.insert_immutable(
            "artifacts", str(start_record["id"]), start_record
        )
        self.store.insert_immutable(
            "artifacts", str(evidence["id"]), evidence
        )
        registrations[provider_id] = updated
        self.store.upsert("settings", "provider_registrations", registrations)
        if updated.get("registration_lifecycle") != "QUALIFIED":
            raise PermissionError("Authority Service provider qualification failed")
        return updated

    def add_project(self, repository: Path, name: str | None = None) -> dict[str, Any]:
        inspection = self.git.inspect(repository)
        validate_path_budget(
            Path(inspection.root) / ".git" / "objects" / "00" / ("0" * 38),
            purpose="repository Git object path",
        )
        identifier = uuid.uuid5(uuid.NAMESPACE_URL, inspection.root).hex
        project = {
            "id": identifier,
            "name": name or Path(inspection.root).name,
            "repository": inspection.root,
            "protected_original": True,
            "branch": inspection.branch,
            "head": inspection.head,
            "dirty": inspection.dirty,
            "detached": inspection.detached,
            "worktrees": inspection.worktrees,
            "added_at": _now(),
        }
        self.store.upsert("projects", identifier, project)
        self.store.upsert("settings", "active_project", {"project_id": identifier})
        return project

    def projects(self) -> list[dict[str, Any]]:
        return self.store.list("projects")

    def active_project(self) -> dict[str, Any] | None:
        setting = self.store.get("settings", "active_project")
        return (
            self.store.get("projects", str(setting["project_id"]))
            if setting and setting.get("project_id")
            else None
        )

    def create_task(self, values: dict[str, Any]) -> dict[str, Any]:
        required = ("title", "objective", "baseline", "target_branch")
        missing = [field for field in required if not str(values.get(field, "")).strip()]
        if missing:
            raise ValueError(f"task is missing required fields: {missing}")
        task_id = str(values.get("id") or f"task-{uuid.uuid4().hex[:12]}")
        active = self.active_project()
        repository = str(values.get("repository") or (active or {}).get("repository", ""))
        if not repository:
            raise ValueError("task requires an active repository")
        repository_path = Path(repository).resolve()
        included_paths = _validated_task_paths(
            repository_path, values.get("included_paths", ["keeper/"]), "included"
        )
        excluded_paths = _validated_task_paths(
            repository_path, values.get("excluded_paths", []), "excluded"
        )
        routing = self.store.get("settings", "routing") or {}
        selected_policy = str(
            values.get("provider_policy")
            or routing.get("default_provider_policy")
            or "automatic"
        ).strip().lower()
        if selected_policy == "repository/default":
            selected_policy = str(
                routing.get("default_provider_policy") or "automatic"
            ).strip().lower()
        allowed_policies = {
            "automatic",
            "mock",
            "local-only",
            "strongest",
            "codex",
            "claude",
            "gemini",
            "qwen",
        }
        if selected_policy not in allowed_policies:
            raise ValueError(f"unsupported provider policy: {selected_policy}")
        is_demo = bool(values.get("is_demo", False))
        if selected_policy == "mock" and not is_demo:
            raise PermissionError("mock policy is restricted to explicit demonstration tasks")
        if values.get("verification_specs") and not is_demo:
            raise PermissionError(
                "desktop tasks may select only immutable registered validation categories"
            )
        validations = list(values.get("required_validations", ["tests"])) or ["tests"]
        task: dict[str, Any] = {
            "id": task_id,
            "title": str(values["title"]),
            "objective": str(values["objective"]),
            "included_paths": included_paths,
            "excluded_paths": excluded_paths,
            "baseline": str(values["baseline"]),
            "target_branch": str(values["target_branch"]),
            "risk": str(values.get("risk", "low")),
            "allowed_actions": list(values.get("allowed_actions", [])),
            "prohibited_actions": list(values.get("prohibited_actions", [])),
            "required_validations": validations,
            "verification_specs": (
                list(values.get("verification_specs", [])) if is_demo else []
            ),
            "verification_waivers": list(values.get("verification_waivers", [])),
            "required_reviewers": list(values.get("required_reviewers", ["independent"])),
            "completion_criteria": list(values.get("completion_criteria", [])),
            "delegation_mode": bool(values.get("delegation_mode", False)),
            "repository": str(repository_path),
            "keeper_project_id": (
                str(values["keeper_project_id"])
                if values.get("keeper_project_id")
                else None
            ),
            "keeper_charter_id": (
                str(values["keeper_charter_id"])
                if values.get("keeper_charter_id")
                else None
            ),
            "keeper_charter_revision": values.get("keeper_charter_revision"),
            "keeper_founder_approval_record_id": (
                str(values["keeper_founder_approval_record_id"])
                if values.get("keeper_founder_approval_record_id")
                else None
            ),
            "keeper_founder_approval_identity": (
                str(values["keeper_founder_approval_identity"])
                if values.get("keeper_founder_approval_identity")
                else None
            ),
            "provider_policy": selected_policy,
            "is_demo": is_demo,
            "mock_scenario": str(values.get("mock_scenario", "repair")),
            "requires_manual_approval": bool(
                values.get("requires_manual_approval", False)
            ),
            "commit_requested": bool(values.get("commit_requested", False)),
            "push_requested": bool(values.get("push_requested", False)),
            "commit_message": str(values.get("commit_message", values["title"])),
            "push_remote": str(values.get("push_remote", "origin")),
            "push_destination": str(values.get("push_destination", "")),
            "status": "INTAKE",
            "created_at": _now(),
        }
        self.store.upsert("tasks", task_id, task)
        for waiver in task["verification_waivers"]:
            if isinstance(waiver, dict) and waiver.get("waiver_id"):
                stored_waiver = {
                    **waiver,
                    "id": str(waiver["waiver_id"]),
                    "capability": "verification_waiver",
                    "task_id": task_id,
                    "run_id": waiver.get("run_id"),
                    "issued_at": str(waiver.get("issued_at") or _now()),
                    "consumed_at": waiver.get("consumed_at"),
                    "revoked_at": waiver.get("revoked_at"),
                }
                self.store.upsert(
                    "authorizations", str(waiver["waiver_id"]), stored_waiver
                )
        return task

    def tasks(self) -> list[dict[str, Any]]:
        return self.store.list("tasks")

    def pause_run(self, run_id: str) -> None:
        self.workflow.pause(run_id)

    def resume_run(self, run_id: str) -> None:
        self.workflow.resume(run_id)

    def cancel_run(self, run_id: str) -> None:
        self.workflow.cancel(run_id)

    def approve_run(self, run_id: str, authority: str) -> None:
        self.workflow.approve(run_id, authority)

    def reject_run(self, run_id: str, authority: str, reason: str) -> None:
        self.workflow.reject(run_id, authority, reason)

    def run_status(self, run_id: str) -> dict[str, Any]:
        run = self.store.get("runs", run_id)
        if run is None:
            raise LookupError("run not found")
        evidence = run.get("evidence_root")
        latest = ""
        if isinstance(evidence, str):
            root = self._validated_evidence_root(
                run_id, run, require_exists=False
            )
            if os.path.lexists(root):
                root = self._validated_evidence_root(run_id, run)
                logs = sorted(root.glob(".ai-workflow/runs/*/*.log"))
                if logs:
                    try:
                        latest_log = _validated_evidence_child(
                            root, logs[-1], "log evidence"
                        )
                        latest = redact_text(
                            latest_log.read_text(encoding="utf-8"), 20_000
                        )
                    except OSError:
                        latest = ""
        verification = [
            item
            for item in self.store.list("verification_records")
            if item.get("run_id") == run_id
        ]
        waivers = [
            item
            for item in self.store.list("authorizations")
            if item.get("capability") == "verification_waiver"
            and item.get("run_id") in {None, run_id}
            and item.get("task_id") == run.get("task_id")
        ]
        return {
            **run,
            "latest_log": latest,
            "verification_records": verification,
            "verification_waivers": waivers,
        }

    def evidence_details(self, run_id: str, category: str) -> dict[str, Any]:
        run = self.run_status(run_id)
        root = self._validated_evidence_root(run_id, run)
        provider_records: list[dict[str, Any]] = []
        for path in sorted(root.glob(".ai-workflow/runs/*/run.json")):
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                raise PermissionError("provider evidence escapes the run root")
            try:
                value = json.loads(resolved.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                provider_records.append(value)
        authorizations = [
            item
            for item in self.store.list("authorizations")
            if item.get("task_id") == run.get("task_id")
            and item.get("run_id") in {None, run_id}
        ]
        findings = [
            {
                "provider_run_id": item.get("run_id"),
                "role": item.get("role"),
                "findings": item.get("review_findings", []),
                "accepted": item.get("accepted_findings", []),
                "rejected": item.get("rejected_findings", []),
            }
            for item in provider_records
            if item.get("review_findings")
            or item.get("accepted_findings")
            or item.get("rejected_findings")
        ]
        logs: list[dict[str, Any]] = []
        for path in sorted(root.glob(".ai-workflow/runs/*/*.log")):
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                raise PermissionError("log evidence escapes the run root")
            content = resolved.read_bytes()
            logs.append(
                {
                    "path": resolved.relative_to(root).as_posix(),
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "recent_output": redact_text(
                        content.decode("utf-8", errors="replace"), 20_000
                    ),
                }
            )
        index_path = root / "evidence-index.json"
        hashes: list[dict[str, Any]] = []
        if index_path.is_file():
            index = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(index, dict) and isinstance(index.get("files"), list):
                hashes = [
                    item for item in index["files"] if isinstance(item, dict)
                ]
        categories: dict[str, Any] = {
            "routing": {
                "routing_rationale": run.get("routing_decisions", []),
                "provider_identities": run.get("providers", {}),
            },
            "verification": {
                "categories": run.get("verification_records", []),
                "commands": [
                    item
                    for item in provider_records
                    if item.get("verification_result") is not None
                ],
            },
            "waivers": run.get("verification_waivers", []),
            "authorizations": authorizations,
            "findings": findings,
            "logs": logs,
            "hashes": hashes,
            "git": run.get("git_result", {}),
        }
        if category not in categories:
            raise ValueError("unsupported evidence detail category")
        return {
            "run_id": run_id,
            "category": category,
            "details": categories[category],
        }

    def revoke_waiver(self, authorization_id: str) -> None:
        value = self.store.get("authorizations", authorization_id)
        if value is None or value.get("capability") != "verification_waiver":
            raise LookupError("verification waiver not found")
        if value.get("revoked_at") is not None or value.get("consumed_at") is not None:
            raise PermissionError("only an active waiver may be revoked")
        try:
            expires_at = datetime.fromisoformat(str(value["expires_at"]))
        except (KeyError, TypeError, ValueError) as error:
            raise PermissionError("waiver expiration is invalid") from error
        if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
            raise PermissionError("only an active waiver may be revoked")
        self.revoke_authorization(authorization_id)
        revoked = self.store.get("authorizations", authorization_id)
        if revoked is None:
            raise RuntimeError("revoked waiver could not be reloaded")
        task_id = str(revoked.get("task_id", ""))
        task = self.store.get("tasks", task_id)
        if task is not None:
            task["verification_waivers"] = [
                (
                    {**item, "revoked_at": revoked["revoked_at"]}
                    if isinstance(item, dict)
                    and item.get("waiver_id") == authorization_id
                    else item
                )
                for item in task.get("verification_waivers", [])
            ]
            self.store.upsert("tasks", task_id, task)
        for run in self.store.list("runs"):
            if run.get("task_id") != task_id or run.get("status") in {
                "COMPLETED",
                "REJECTED",
            }:
                continue
            evidence = run.get("evidence_root")
            if not isinstance(evidence, str):
                continue
            task_path = Path(evidence) / ".ai-workflow" / "tasks" / f"{task_id}.json"
            if not task_path.is_file():
                continue
            domain_task = load_json(task_path, {})
            if not isinstance(domain_task, dict):
                continue
            domain_task["verification_waivers"] = [
                (
                    {**item, "revoked_at": revoked["revoked_at"]}
                    if isinstance(item, dict)
                    and item.get("waiver_id") == authorization_id
                    else item
                )
                for item in domain_task.get("verification_waivers", [])
            ]
            atomic_write_json(task_path, domain_task)

    def start_task(self, task_id: str) -> dict[str, Any]:
        task = self.store.get("tasks", task_id)
        if task is None:
            raise LookupError("task not found")
        executive_generation = self._validate_task_authority_binding(task)
        if any(item.get("task_id") == task_id for item in self.store.list("runs")):
            raise PermissionError(
                "task was already launched; use its explicit run recovery controls"
            )
        task_digest = self.store.claim_task_launch(
            task_id,
            task,
            executive_generation,
            {
                "kind": "task_launch_claim",
                "task_id": task_id,
                "claimed_at": _now(),
                "keeper_project_id": task.get("keeper_project_id"),
                "keeper_charter_id": task.get("keeper_charter_id"),
                "keeper_charter_revision": task.get("keeper_charter_revision"),
                "keeper_founder_approval_record_id": task.get(
                    "keeper_founder_approval_record_id"
                ),
                "keeper_founder_approval_identity": task.get(
                    "keeper_founder_approval_identity"
                ),
            },
        )
        return self.workflow.start(
            task_id, validated_task=task, task_digest=task_digest
        )

    def _validate_task_authority_binding(
        self, task: dict[str, Any]
    ) -> int | None:
        """Revalidate an exact Pass B charter binding at the execution boundary."""
        project_id = task.get("keeper_project_id")
        bound_fields = (
            "keeper_charter_id",
            "keeper_charter_revision",
            "keeper_founder_approval_record_id",
            "keeper_founder_approval_identity",
        )
        if project_id is None:
            if any(task.get(field) is not None for field in bound_fields):
                raise PermissionError("task has an incomplete Keeper charter binding")
            return None
        if not isinstance(project_id, str) or not project_id:
            raise PermissionError("task Keeper project binding is invalid")
        from keeper.executive.service import KeeperExecutive

        status: dict[str, Any] | None = None
        generation_after: int | None = None
        for _attempt in range(2):
            generation_before = self.store.executive_generation()
            try:
                candidate = KeeperExecutive(self.store.path).status(
                    project_id
                ).to_dict()
            except (KeyError, PermissionError, RuntimeError, ValueError) as error:
                raise PermissionError(
                    "task Keeper project authority is unavailable"
                ) from error
            generation_after = self.store.executive_generation()
            if generation_before == generation_after:
                status = candidate
                break
        if status is None or generation_after is None:
            raise PermissionError(
                "Keeper charter changed while task authority was validated"
            )
        charter = status.get("active_charter")
        if not isinstance(charter, dict):
            raise PermissionError("task Keeper project has no active charter")
        expected = {
            "keeper_charter_id": charter.get("charter_id"),
            "keeper_charter_revision": charter.get("revision"),
            "keeper_founder_approval_record_id": charter.get(
                "founder_approval_record_id"
            ),
            "keeper_founder_approval_identity": charter.get(
                "founder_approval_identity"
            ),
        }
        if (
            not isinstance(expected["keeper_charter_id"], str)
            or not expected["keeper_charter_id"]
            or type(expected["keeper_charter_revision"]) is not int
            or not isinstance(
                expected["keeper_founder_approval_record_id"], str
            )
            or not expected["keeper_founder_approval_record_id"]
            or not isinstance(expected["keeper_founder_approval_identity"], str)
            or not expected["keeper_founder_approval_identity"]
            or any(task.get(field) != value for field, value in expected.items())
        ):
            raise PermissionError(
                "task is not bound to the current approved Keeper charter"
            )
        workspaces = charter.get("workspaces")
        if not isinstance(workspaces, (list, tuple)) or len(workspaces) != 1:
            raise PermissionError(
                "task Keeper charter must authorize exactly one workspace"
            )
        try:
            workspace = Path(str(workspaces[0])).resolve(strict=True)
            repository = Path(str(task.get("repository", ""))).resolve(strict=True)
        except OSError as error:
            raise PermissionError("task Keeper workspace is unavailable") from error
        registered = any(
            item.get("protected_original") is True
            and _same_path(Path(str(item.get("repository", ""))), workspace)
            for item in self.projects()
        )
        if not registered or not _same_path(repository, workspace):
            raise PermissionError(
                "task is not bound to its approved protected repository"
            )
        return generation_after

    def execute_task(self, task_id: str) -> dict[str, Any]:
        run = self.start_task(task_id)
        self.workflow.wait(str(run["id"]), timeout=120)
        completed = self.store.get("runs", str(run["id"]))
        if completed is None:
            raise LookupError("run not found")
        return completed

    def wait_for_run(self, run_id: str, timeout: float | None = None) -> dict[str, Any]:
        self.workflow.wait(run_id, timeout)
        run = self.store.get("runs", run_id)
        if run is None:
            raise LookupError("run not found")
        return run

    def recover_runs(self) -> list[dict[str, Any]]:
        return self.workflow.recover_interrupted_runs()

    def recovery_records(self) -> list[dict[str, Any]]:
        """Read durable recovery state globally, without probing or stopping work."""
        return [
            record
            for record in self.store.list("runs")
            if str(record.get("status", "")).lower() in {"interrupted", "uncertain"}
        ]

    def retry_run(
        self,
        run_id: str,
        reason: str,
        stage: str | None = None,
        authorizer: str = "local-user",
        reroute_authorization_id: str | None = None,
    ) -> dict[str, Any]:
        return self.workflow.retry(
            run_id,
            reason,
            stage,
            authorizer,
            reroute_authorization_id,
        )

    def create_provider_reroute_authorization(
        self,
        run_id: str,
        approving_authority: str,
        minutes: int,
    ) -> dict[str, Any]:
        preview = self.workflow.retry_routing_preview(run_id)
        if preview["from_routing_digest"] == preview["to_routing_digest"]:
            raise ValueError("retry routing is unchanged and needs no authorization")
        run = self.run_status(run_id)
        return self.create_authorization(
            "provider_reroute",
            str(run["task_id"]),
            str(run["repository"]),
            approving_authority,
            minutes,
            reusable=False,
            scope={
                "run_id": run_id,
                "retry_stage": preview["retry_stage"],
                "provider_policy": preview["provider_policy"],
                "from_routing_digest": preview["from_routing_digest"],
                "to_routing_digest": preview["to_routing_digest"],
                "source_attempt_id": preview["source_attempt_id"],
                "destination_attempt_number": preview[
                    "destination_attempt_number"
                ],
                "capability_requirements": preview[
                    "capability_requirements"
                ],
                "independence_requirements": preview[
                    "independence_requirements"
                ],
                "previous_decisions": preview["previous_decisions"],
                "proposed_decisions": preview["proposed_decisions"],
            },
        )

    def filtered_runs(
        self,
        *,
        repository: str = "",
        branch: str = "",
        provider: str = "",
        outcome: str = "",
        task_id: str = "",
        date_from: str = "",
        date_to: str = "",
    ) -> list[dict[str, Any]]:
        values = self.store.list("runs")
        filters = {
            "repository": repository,
            "branch": branch,
            "provider": provider,
            "status": outcome,
            "task_id": task_id,
        }
        return [
            item
            for item in values
            if all(
                not expected or str(item.get(key, "")) == expected
                for key, expected in filters.items()
            )
            and (not date_from or str(item.get("started_at", "")) >= date_from)
            and (not date_to or str(item.get("started_at", "")) <= date_to)
        ]

    def evidence_path(self, run_id: str, kind: str = "folder") -> Path:
        run = self.store.get("runs", run_id)
        if run is None:
            raise LookupError("run not found")
        root = self._validated_evidence_root(run_id, run)
        choices = {
            "folder": root,
            "markdown": root / "final-report.md",
            "json": root / "final-report.json",
        }
        if kind not in choices or not choices[kind].exists():
            raise ValueError("requested evidence target is unavailable")
        return contained_path(root, choices[kind], purpose="evidence target")

    def _validated_evidence_root(
        self,
        requested_run_id: str,
        run: dict[str, Any],
        *,
        require_exists: bool = True,
    ) -> Path:
        """Resolve evidence only from the exact Keeper-owned run location.

        Demonstration runs use the desktop data directory. Production runs use
        the authenticated Authority Service client exchange. A stored run may
        not redirect evidence to another directory, even beneath an otherwise
        trusted parent.
        """
        root_value = run.get("evidence_root")
        if not isinstance(root_value, str):
            raise ValueError("run has no finalized evidence")
        raw_root = Path(root_value)
        run_id = str(run.get("id", ""))
        if not requested_run_id or run_id != requested_run_id:
            raise PermissionError("run evidence identity does not match its durable key")

        execution_value = run.get("authority_execution_root")
        if isinstance(execution_value, str) and execution_value:
            execution_root = Path(execution_value).absolute()
            if not _same_path(execution_root, self.data_directory):
                diagnostics = self.authority.diagnostics()
                exchange_value = diagnostics.get("client_exchange_root")
                if not isinstance(exchange_value, str) or not exchange_value:
                    raise RuntimeError("Authority Service client exchange is unavailable")
                current_exchange = Path(exchange_value).absolute()
                if not _same_path(execution_root, current_exchange):
                    raise PermissionError("run evidence is not bound to the current Authority Service exchange")
            expected = execution_root / "evidence" / run_id
        else:
            expected = self.data_directory.absolute() / "evidence" / run_id

        if not _same_path(raw_root, expected):
            raise PermissionError("evidence path is outside Keeper storage")
        _reject_reparse_components(expected)
        _reject_reparse_components(raw_root.absolute())
        root = raw_root.resolve(strict=require_exists)
        if root != expected.resolve(strict=require_exists):
            raise PermissionError("evidence path is outside Keeper storage")
        return root

    def open_evidence(self, run_id: str, kind: str = "folder") -> Path:
        target = self.evidence_path(run_id, kind)
        subprocess.Popen(
            ["explorer.exe", str(target)],
            cwd=self.data_directory,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return target

    def save_template(self, name: str, task: dict[str, Any]) -> None:
        self.store.upsert("policies", f"template:{name}", {"name": name, "task": task})

    def create_authorization(
        self,
        capability: str,
        task_id: str,
        repository: str,
        approving_authority: str,
        minutes: int,
        reusable: bool = False,
        scope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if minutes < 1 or minutes > 1440:
            raise ValueError("authorization duration must be between 1 and 1440 minutes")
        if capability not in {
            "commit",
            "push",
            "network",
            "verification_waiver",
            "provider_reroute",
        }:
            raise ValueError("authorization capability is unsupported")
        if not approving_authority.strip():
            raise ValueError("approving authority is required")
        identifier = f"authorization-{uuid.uuid4().hex}"
        authorization = {
            "id": identifier,
            "capability": capability,
            "task_id": task_id,
            "repository": str(Path(repository).resolve()),
            "approving_authority": approving_authority,
            "issued_at": _now(),
            "expires_at": (datetime.now(UTC) + timedelta(minutes=minutes)).isoformat(),
            "reusable": reusable,
            "consumed_at": None,
            "revoked_at": None,
            **(scope or {}),
        }
        self.store.upsert("authorizations", identifier, authorization)
        return authorization

    def authorization_preview(
        self, capability: str, run_id: str
    ) -> dict[str, Any]:
        if capability not in {"commit", "push"}:
            raise ValueError("run-aware authorization supports commit or push")
        run = self.run_status(run_id)
        task = self.store.get("tasks", str(run["task_id"]))
        if task is None:
            raise LookupError("authorization task is unavailable")
        worktree_value = run.get("worktree")
        if not isinstance(worktree_value, str):
            raise ValueError("run has no authoritative worktree")
        worktree = Path(worktree_value).resolve()
        inspection = self.git.inspect(worktree)
        if capability == "commit":
            if run.get("status") != "awaiting_approval":
                raise PermissionError("commit authorization requires an approval-ready run")
            if not inspection.staged:
                raise PermissionError("commit authorization requires exact staged paths")
            return {
                "task_id": str(task["id"]),
                "run_id": run_id,
                "repository": str(Path(str(task["repository"])).resolve()),
                "worktree": str(worktree),
                "branch": inspection.branch,
                "head": inspection.head,
                "staged_paths": sorted(inspection.staged),
                "staged_digest": self.git.staged_digest(worktree),
            }
        if run.get("status") != "awaiting_push_authorization":
            raise PermissionError("push authorization requires a committed awaiting-push run")
        remote = str(task.get("push_remote", "origin"))
        remote_url = self.git.remote_url(worktree, remote)
        source_ref = inspection.branch
        destination_ref = str(
            task.get("push_destination") or f"refs/heads/{source_ref}"
        )
        return {
            "task_id": str(task["id"]),
            "run_id": run_id,
            "repository": str(Path(str(task["repository"])).resolve()),
            "worktree": str(worktree),
            "branch": inspection.branch,
            "head": inspection.head,
            "remote": remote,
            "remote_url": remote_url,
            "source_ref": source_ref,
            "destination_ref": destination_ref,
            "expected_commit": inspection.head,
            "force": False,
        }

    def create_run_authorization(
        self,
        capability: str,
        run_id: str,
        approving_authority: str,
        minutes: int,
    ) -> dict[str, Any]:
        scope = self.authorization_preview(capability, run_id)
        return self.create_authorization(
            capability,
            str(scope["task_id"]),
            str(scope["repository"]),
            approving_authority,
            minutes,
            reusable=False,
            scope=scope,
        )

    def revoke_authorization(self, identifier: str) -> None:
        value = self.store.get("authorizations", identifier)
        if value is None:
            raise LookupError("authorization not found")
        value["revoked_at"] = _now()
        self.store.upsert("authorizations", identifier, value)

    def run_mock_demo(self) -> dict[str, Any]:
        repository = self._demo_repository()
        project = self.add_project(repository, "Keeper demonstration")
        task = self.create_task(
            {
                "title": "Keeper deterministic demonstration",
                "objective": "Exercise the unified production orchestration path.",
                "baseline": project["head"],
                "target_branch": "keeper/demo",
                "included_paths": [".keeper-workflow/"],
                "required_validations": ["task"],
                "is_demo": True,
                "provider_policy": "mock",
                "mock_scenario": "repair",
            }
        )
        return self.execute_task(str(task["id"]))

    def notify(self, event: str, title: str, detail: str) -> dict[str, Any]:
        identifier = f"notification-{uuid.uuid4().hex}"
        value: dict[str, Any] = {
            "id": identifier,
            "event": event,
            "title": redact_text(title, 120),
            "detail": redact_text(detail, 1000),
            "created_at": _now(),
            "read_at": None,
        }
        self.store.upsert("notifications", identifier, value)
        settings = self.store.get("settings", "application") or {}
        if bool(settings.get("os_notifications", False)):
            delivery = deliver_local_notification(event, value["title"], value["detail"])
            value["delivery"] = {
                "delivered": delivery.delivered,
                "channel": delivery.channel,
                "detail": delivery.detail,
            }
            self.store.upsert("notifications", identifier, value)
        return value

    def dashboard(self) -> dict[str, Any]:
        runs = self.store.list("runs")
        findings = self.store.list("findings")
        authorizations = self.store.list("authorizations")
        return {
            "status": "ready" if self.setup_complete() else "setup required",
            "active_project": self.active_project(),
            "running_workflow": next(
                (run for run in runs if run.get("status") == "running"), None
            ),
            "recent_runs": runs[:10],
            "pending_approvals": [
                item for item in authorizations
                if item.get("consumed_at") is None and item.get("revoked_at") is None
            ],
            "unresolved_findings": [
                item for item in findings if item.get("status", "open") == "open"
            ],
            "providers": self.diagnostics()["providers"],
        }

    def export_run_report(self, run_id: str, destination: Path) -> Path:
        run = self.store.get("runs", run_id)
        if run is None:
            raise LookupError("run not found")
        finalization_id = run.get("evidence_finalization_id")
        if not isinstance(finalization_id, str):
            raise PermissionError(
                "run has no protected evidence finalization record"
            )
        protected = self.store.get("artifacts", finalization_id)
        if (
            protected is None
            or protected.get("run_id") != run_id
            or protected.get("task_id") != run.get("task_id")
            or protected.get("manifest_digest")
            != run.get("evidence_manifest_digest")
        ):
            raise PermissionError(
                "protected evidence finalization binding is inconsistent"
            )
        root = self.evidence_path(run_id, "folder")
        report = verify_protected_evidence(root, protected)
        if (
            str(report.get("terminal_status", "")).upper()
            != str(protected.get("final_status", "")).upper()
        ):
            raise RuntimeError(
                "final report status conflicts with protected finalization"
            )
        finalize_evidence(destination, report)
        return destination

    def _demo_repository(self) -> Path:
        root = self.data_directory / "demonstrations" / f"demo-{uuid.uuid4().hex}"
        repository = root / "repository"
        validate_path_budget(
            repository / ".git" / "objects" / "00" / ("0" * 38),
            purpose="demonstration repository path",
        )
        repository.mkdir(parents=True)
        commands = (
            ("init",),
            ("config", "user.email", "keeper@example.invalid"),
            ("config", "user.name", "Keeper Demonstration"),
        )
        for command in commands:
            _git(repository, *command)
        (repository / "README.md").write_text(
            "Keeper demonstration\n", encoding="utf-8"
        )
        _git(repository, "add", "README.md")
        _git(repository, "commit", "-m", "demonstration baseline")
        return repository


def _writable(directory: Path) -> bool:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / f".write-probe-{uuid.uuid4().hex}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def _validated_task_paths(
    repository: Path, values: object, label: str
) -> list[str]:
    if not isinstance(values, list):
        raise ValueError(f"{label} paths must be a list")
    normalized: list[str] = []
    for raw in values:
        value = str(raw).replace("\\", "/").strip()
        path = PurePosixPath(value)
        if not value or path.is_absolute() or ".." in path.parts:
            raise PermissionError(f"{label} path contains traversal or is absolute")
        candidate = repository.joinpath(*path.parts)
        if candidate.is_symlink() or (
            candidate.exists() and not candidate.resolve().is_relative_to(repository)
        ):
            raise PermissionError(f"{label} path escapes through a symbolic link")
        normalized.append(path.as_posix().rstrip("/") + ("/" if value.endswith("/") else ""))
    if label == "included" and not normalized:
        raise ValueError("at least one included path is required")
    return normalized


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _git(repository: Path, *arguments: str) -> None:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        shell=False,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "unable to prepare demonstration")
