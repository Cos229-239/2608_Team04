from __future__ import annotations

import ctypes
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from keeper.agent_runner import AgentRunner
from keeper.authority_service.client import AuthorityServiceClient
from keeper.app.git_safety import GitSafetyService
from keeper.app.lifecycle import RunLifecycle, RunStage
from keeper.app.path_safety import validate_path_budget
from keeper.app.reporting import finalize_evidence
from keeper.app.storage import KeeperStore
from keeper.app.verification_policy import trusted_bash_launcher
from keeper.config import KeeperConfig
from keeper.models.task import Task
from keeper.orchestrator import Keeper
from keeper.policies import filtered_environment
from keeper.providers.adapters import (
    ProviderCapabilities,
    ProviderDiagnostic,
    ProviderDiscovery,
    RoutingRequest,
    route_provider,
)
from keeper.providers.authority_service import AuthorityServiceProvider
from keeper.providers.base import AgentProvider
from keeper.providers.codex_cli import CliProvider
from keeper.providers.mock import MockProvider
from keeper.providers.ollama import OllamaProvider
from keeper.providers.routing import ProviderRouter
from keeper.recovery import (
    atomic_write_json,
    load_json,
    ownership_records_match,
    ProcessProbe,
    ProcessState,
    probe_process,
    process_exists,
    process_identity_matches,
    retain_process_handle,
)
from keeper.state_machine import TaskStatus
from keeper.workspace import WorkspaceManager

_ORIGINAL_PROCESS_EXISTS = process_exists


@dataclass(slots=True)
class ActiveRun:
    thread: threading.Thread
    cancel_requested: threading.Event
    pause_requested: threading.Event
    approval_ready: threading.Event
    approval_decision: str | None = None
    cancel_callbacks: list[Callable[[], None]] = field(default_factory=list)


class WorkflowCoordinator:
    """Connect persisted desktop tasks to the production Keeper orchestrator."""

    def __init__(
        self,
        store: KeeperStore,
        data_directory: Path,
        notify: Callable[[str, str, str], dict[str, Any]],
        authority: AuthorityServiceClient,
    ) -> None:
        self.store = store
        self.data_directory = data_directory
        self.lifecycle = RunLifecycle(store)
        self.notify = notify
        self.authority = authority
        self._active: dict[str, ActiveRun] = {}
        self._lock = threading.Lock()
        self.startup_recovery = self.recover_interrupted_runs()

    def start(
        self, task_id: str, metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        task = self._task(task_id)
        run_id = f"run-{uuid.uuid4().hex}"
        if (
            task.get("provider_policy") == "mock"
            and bool(task.get("is_demo", False))
        ):
            execution_root = self.data_directory
        else:
            diagnostics = self.authority.diagnostics()
            exchange = diagnostics.get("client_exchange_root")
            if not isinstance(exchange, str) or not exchange:
                raise RuntimeError(
                    "Authority Service client exchange is unavailable"
                )
            execution_root = Path(exchange).resolve(strict=True)
        validate_path_budget(
            execution_root
            / "evidence"
            / run_id
            / ".ai-workflow"
            / "runs"
            / "pr-p-00000000"
            / "stderr.log",
            purpose="workflow evidence path",
        )
        validate_path_budget(
            execution_root / "worktrees" / run_id / str(task["id"]),
            purpose="workflow worktree path",
        )
        run = self.lifecycle.create(run_id, task_id)
        run.update(
            {
                "repository": task["repository"],
                "branch": task["target_branch"],
                "baseline": task["baseline"],
                "objective": task["objective"],
                "started_at": _now(),
                "provider": None,
                "latest_log": None,
                "evidence_root": str(execution_root / "evidence" / run_id),
                "authority_execution_root": str(execution_root),
                "attempt": 1,
            }
        )
        run.update(metadata or {})
        self.store.upsert("runs", run_id, run)
        cancel = threading.Event()
        pause = threading.Event()
        approval = threading.Event()
        thread = threading.Thread(
            target=self._execute_guarded,
            args=(run_id, task, cancel, pause, approval),
            name=f"keeper-{run_id}",
            daemon=True,
        )
        with self._lock:
            self._active[run_id] = ActiveRun(thread, cancel, pause, approval)
        thread.start()
        return self._run(run_id)

    def recover_interrupted_runs(self) -> list[dict[str, Any]]:
        recovered: list[dict[str, Any]] = []
        terminal = {"COMPLETED", "REJECTED", "blocked", "cancelled"}
        for record in self.store.list("runs"):
            if record.get("status") in terminal:
                continue
            run_id = str(record.get("id", ""))
            if not run_id:
                continue
            stage = str(record.get("stage", ""))
            execution_attempt = _durable_active_execution(record)
            evidence_resolution = _resolve_execution_evidence(
                record, execution_attempt
            )
            provider_record = evidence_resolution.get("record")
            completion_resolution = self._resolve_protected_completion(
                record, execution_attempt, provider_record
            )
            if execution_attempt is None:
                provider_record = _legacy_active_provider_record(record)
            ownership = (
                provider_record.get("process_ownership")
                if isinstance(provider_record, dict)
                else None
            )
            if not isinstance(ownership, dict):
                ownership = None
            authority_records = self._process_ownership_records(
                run_id,
                (
                    str(
                        execution_attempt.get("provider_run_id")
                        if isinstance(execution_attempt, dict)
                        else provider_record.get("run_id")
                        if isinstance(provider_record, dict)
                        else ""
                    )
                    if (
                        isinstance(execution_attempt, dict)
                        or isinstance(provider_record, dict)
                    )
                    else None
                ),
            )
            authority = authority_records[0] if len(authority_records) == 1 else None
            if ownership is None and isinstance(authority, dict):
                ownership = authority
            pid = record.get("process_id")
            if not isinstance(pid, int) and isinstance(ownership, dict):
                pid = ownership.get("pid")
            if not isinstance(pid, int) and isinstance(authority, dict):
                pid = authority.get("pid")
            if not isinstance(pid, int) and execution_attempt is None:
                pid = _active_provider_pid(record)
            if process_exists is not _ORIGINAL_PROCESS_EXISTS:
                probe = ProcessProbe(
                    (
                        ProcessState.CONFIRMED_PRESENT
                        if process_exists(pid if isinstance(pid, int) else None)
                        else ProcessState.CONFIRMED_ABSENT
                    ),
                    "compatibility process predicate",
                )
            else:
                probe = probe_process(pid if isinstance(pid, int) else None)
            running = probe.state is ProcessState.CONFIRMED_PRESENT
            terminated = False
            identity_verified = False
            destructive_revalidation_verified = False
            retained_handle_acquired = False
            termination_uncertain = False
            termination_reason = ""
            binding_verified = ownership_records_match(authority, ownership)
            safe_terminal_finalization = bool(
                execution_attempt
                and evidence_resolution.get("status") == "RESOLVED_TERMINAL"
                and completion_resolution.get("status") == "VERIFIED"
                and isinstance(pid, int)
                and probe.state is ProcessState.CONFIRMED_ABSENT
                and isinstance(authority, dict)
                and binding_verified
            )
            unresolved_execution = bool(execution_attempt) and not (
                safe_terminal_finalization
            )
            if unresolved_execution and not isinstance(pid, int):
                probe = ProcessProbe(
                    ProcessState.INDETERMINATE,
                    "durable execution-started attempt has no authoritative pid",
                )
                running = False
                termination_uncertain = True
                termination_reason = str(evidence_resolution.get("detail", ""))
            process_state = probe.state.value
            descendant_state = "not-inspected"
            if probe.state in {
                ProcessState.CONFIRMED_PRESENT,
                ProcessState.INDETERMINATE,
            } and isinstance(pid, int):
                retained = retain_process_handle(pid)
                retained_handle_acquired = retained is not None
                if retained is None:
                    termination_uncertain = True
                    termination_reason = (
                        probe.diagnostic
                        if probe.state is ProcessState.INDETERMINATE
                        else "authoritative process handle could not be acquired"
                    )
                else:
                    try:
                        current_identity = retained.identity()
                        if current_identity is None and bool(
                            getattr(retained, "is_exited", lambda: False)()
                        ):
                            running = False
                            process_state = "confirmed_exited"
                            termination_reason = "retained process object was already signaled"
                            continue_recovery = False
                        else:
                            continue_recovery = True
                        identity_verified = (
                            retained.pid == pid
                            and binding_verified
                            and process_identity_matches(authority, current_identity)
                        )
                        if not continue_recovery:
                            pass
                        elif not identity_verified:
                            termination_uncertain = True
                            termination_reason = (
                                "retained process identity did not match protected ownership"
                            )
                        else:
                            initial_tree = _windows_process_tree(pid)
                            if initial_tree is None:
                                termination_uncertain = True
                                descendant_state = "enumeration-failed"
                                termination_reason = (
                                    "descendant ownership could not be established"
                                )
                            elif initial_tree != [pid]:
                                termination_uncertain = True
                                descendant_state = "ambiguous"
                                termination_reason = (
                                    "owned root has descendants that cannot be "
                                    "authoritatively rebound after restart"
                                )
                            else:
                                descendant_state = "root-only"
                                if execution_attempt is not None:
                                    fresh_resolution = _resolve_execution_evidence(
                                        self._run(run_id), execution_attempt
                                    )
                                    fresh_provider = fresh_resolution.get("record")
                                else:
                                    fresh_provider = _legacy_active_provider_record(
                                        record
                                    )
                                fresh_ownership = (
                                    fresh_provider.get("process_ownership")
                                    if isinstance(fresh_provider, dict)
                                    else None
                                )
                                fresh_authorities = self._process_ownership_records(
                                    run_id,
                                    (
                                        str(execution_attempt.get("provider_run_id"))
                                        if isinstance(execution_attempt, dict)
                                        and execution_attempt.get("provider_run_id")
                                        else str(fresh_provider.get("run_id"))
                                        if isinstance(fresh_provider, dict)
                                        and fresh_provider.get("run_id")
                                        else None
                                    ),
                                )
                                fresh_authority = (
                                    fresh_authorities[0]
                                    if len(fresh_authorities) == 1
                                    else None
                                )
                                if (
                                    not isinstance(fresh_ownership, dict)
                                    and isinstance(fresh_authority, dict)
                                ):
                                    fresh_ownership = fresh_authority
                                final_identity = retained.identity()
                                final_tree = _windows_process_tree(pid)
                                destructive_revalidation_verified = (
                                    fresh_authority == authority
                                    and fresh_ownership == ownership
                                    and ownership_records_match(
                                        fresh_authority, fresh_ownership
                                    )
                                    and final_identity == current_identity
                                    and process_identity_matches(
                                        fresh_authority, final_identity
                                    )
                                    and final_tree == [pid]
                                )
                                if destructive_revalidation_verified:
                                    terminated = retained.terminate_exact()
                                    running = not terminated
                                    if not terminated:
                                        termination_uncertain = True
                                        termination_reason = (
                                            "exact retained-process termination "
                                            "outcome was uncertain"
                                        )
                                else:
                                    termination_uncertain = True
                                    termination_reason = (
                                        "process or protected ownership changed "
                                        "before termination"
                                    )
                                    running = final_identity is not None
                    finally:
                        retained.close()
            if stage != RunStage.INTERRUPTED.value:
                try:
                    self.lifecycle.transition(run_id, RunStage.INTERRUPTED)
                except (RuntimeError, ValueError):
                    continue
            current = self._run(run_id)
            if safe_terminal_finalization and isinstance(execution_attempt, dict):
                current["provider_execution_attempts"] = [
                    (
                        {
                            **item,
                            "status": "RECOVERED_TERMINAL",
                            "finish_time": _now(),
                            "result": (
                                provider_record.get("status")
                                if isinstance(provider_record, dict)
                                else "terminal"
                            ),
                        }
                        if isinstance(item, dict)
                        and item.get("provider_run_id")
                        == execution_attempt.get("provider_run_id")
                        else item
                    )
                    for item in current.get("provider_execution_attempts", [])
                ]
            current.update(
                {
                    "status": "interrupted",
                    "recovery": {
                        "classification": (
                            "uncertain"
                            if (
                                termination_uncertain
                                or unresolved_execution
                                or (running and not identity_verified)
                                or (
                                    isinstance(provider_record, dict)
                                    and not binding_verified
                                )
                            )
                            else "recoverable"
                        ),
                        "previous_process_running": running,
                        "process_state": process_state,
                        "process_probe_diagnostic": probe.diagnostic,
                        "process_probe_os_error": probe.os_error,
                        "provider_process_id": pid,
                        "attributable_tree_terminated": terminated,
                        "exact_root_process_terminated": terminated,
                        "identity_verified": identity_verified,
                        "retained_handle_acquired": retained_handle_acquired,
                        "destructive_revalidation_verified": (
                            destructive_revalidation_verified
                        ),
                        "descendant_state": descendant_state,
                        "termination_reason": termination_reason,
                        "durable_execution_attempt": execution_attempt,
                        "provider_evidence_status": evidence_resolution.get(
                            "status"
                        ),
                        "provider_evidence_detail": evidence_resolution.get(
                            "detail"
                        ),
                        "protected_completion_status": completion_resolution.get(
                            "status"
                        ),
                        "protected_completion_detail": completion_resolution.get(
                            "detail"
                        ),
                        "protected_completion": completion_resolution.get("record"),
                        "ownership_binding_verified": binding_verified,
                        "authoritative_ownership": authority,
                        "authoritative_ownership_record_count": len(
                            authority_records
                        ),
                        "recorded_ownership": ownership,
                        "retry_safe": (
                            not running
                            and not termination_uncertain
                            and not unresolved_execution
                            and (
                                not isinstance(provider_record, dict)
                                or binding_verified
                            )
                            and stage
                            not in {
                                RunStage.AUTHORIZED_COMMIT.value,
                                RunStage.AUTHORIZED_PUSH.value,
                                RunStage.EVIDENCE_FINALIZATION.value,
                            }
                        ),
                        "detected_at": _now(),
                        "reroute_reservations": (
                            self.store.reroute_reservations_for_run(run_id)
                        ),
                    },
                }
            )
            self.store.upsert("runs", run_id, current)
            recovered.append(current)
        return recovered

    def retry(
        self,
        run_id: str,
        reason: str,
        stage: str | None = None,
        authorizer: str = "local-user",
        reroute_authorization_id: str | None = None,
    ) -> dict[str, Any]:
        previous = self._run(run_id)
        expected = (
            previous.get("interrupted_from")
            if previous.get("stage") == RunStage.INTERRUPTED.value
            else previous.get("stopped_from")
        )
        selected = stage or (str(expected) if expected else "")
        if not selected:
            raise PermissionError("failed stage could not be identified")
        current = self.lifecycle.retry_stage(
            run_id,
            RunStage(selected),
            reason=reason,
            authorizer=authorizer,
        )
        cancel = threading.Event()
        pause = threading.Event()
        approval = threading.Event()
        task = self._task(str(previous["task_id"]))
        thread = threading.Thread(
            target=self._execute_guarded,
            args=(
                run_id,
                task,
                cancel,
                pause,
                approval,
                selected,
                reroute_authorization_id,
            ),
            name=f"keeper-retry-{run_id}-{selected}",
            daemon=True,
        )
        with self._lock:
            if run_id in self._active:
                raise RuntimeError("stage retry is already active")
            self._active[run_id] = ActiveRun(thread, cancel, pause, approval)
        thread.start()
        return current

    def retry_routing_preview(self, run_id: str) -> dict[str, Any]:
        run = self._run(run_id)
        task = self._task(str(run["task_id"]))
        attempts = run.get("routing_attempts")
        if not isinstance(attempts, list) or not attempts:
            raise PermissionError("retry routing state is missing or malformed")
        _, _, proposed = _select_routes(
            task,
            self._provider_settings(),
        )
        previous = attempts[-1]
        decisions = previous.get("decisions")
        if not isinstance(decisions, list):
            raise PermissionError("prior routing decision is malformed")
        source_attempt_id = str(previous.get("attempt_id") or "")
        if not source_attempt_id:
            raise PermissionError("prior routing attempt identity is malformed")
        return {
            "run_id": run_id,
            "task_id": run["task_id"],
            "retry_stage": run.get("stopped_from")
            or run.get("interrupted_from"),
            "provider_policy": previous.get("provider_policy"),
            "from_routing_digest": _routing_digest(decisions),
            "to_routing_digest": _routing_digest(proposed),
            "source_attempt_id": source_attempt_id,
            "destination_attempt_number": len(attempts) + 1,
            "capability_requirements": {
                str(item["role"]): item.get("capability") for item in proposed
            },
            "independence_requirements": {
                str(item["role"]): item.get("independence") for item in proposed
            },
            "previous_decisions": decisions,
            "proposed_decisions": proposed,
        }

    def _bind_retry_routing(
        self,
        run_id: str,
        stored: dict[str, Any],
        retry_stage: str,
        providers: dict[str, AgentProvider],
        proposed: list[dict[str, Any]],
        authorization_id: str | None,
    ) -> tuple[dict[str, AgentProvider], list[dict[str, Any]], str | None]:
        run = self._run(run_id)
        attempts = run.get("routing_attempts")
        if not isinstance(attempts, list) or not attempts:
            raise PermissionError("retry routing state is missing or malformed")
        prior = attempts[-1]
        prior_decisions = prior.get("decisions")
        if (
            not isinstance(prior_decisions, list)
            or prior.get("provider_policy") != stored.get("provider_policy")
        ):
            raise PermissionError("retry provider policy or routing state changed")
        _validate_routing_decisions(
            prior_decisions, str(stored.get("provider_policy", ""))
        )
        _validate_routing_decisions(
            proposed, str(stored.get("provider_policy", ""))
        )
        prior_digest = _routing_digest(prior_decisions)
        proposed_digest = _routing_digest(proposed)
        if prior_digest == proposed_digest:
            prior_instances = {
                str(item["role"]): str(item["provider_instance_id"])
                for item in prior_decisions
            }
            proposed_instances = {
                str(item["role"]): str(item["provider_instance_id"])
                for item in proposed
            }
            if any(
                proposed_instances[role] == prior_instances[role]
                for role in prior_instances
            ):
                raise PermissionError(
                    "retry provider attempt identity was not freshly generated"
                )
            return providers, proposed, None
        if not authorization_id:
            raise PermissionError(
                "original retry provider is unavailable or changed; reroute authorization is required"
            )
        expected = {
            "capability": "provider_reroute",
            "task_id": str(stored["id"]),
            "run_id": run_id,
            "retry_stage": retry_stage,
            "provider_policy": stored.get("provider_policy"),
            "from_routing_digest": prior_digest,
            "to_routing_digest": proposed_digest,
            "source_attempt_id": str(prior.get("attempt_id") or ""),
            "destination_attempt_number": len(attempts) + 1,
            "capability_requirements": {
                str(item["role"]): item.get("capability") for item in proposed
            },
            "independence_requirements": {
                str(item["role"]): item.get("independence") for item in proposed
            },
        }
        self.store.consume_reroute_authorization(authorization_id, expected)
        return providers, proposed, authorization_id

    def execute(self, task_id: str) -> dict[str, Any]:
        run = self.start(task_id)
        self.wait(str(run["id"]), timeout=120)
        return self._run(str(run["id"]))

    def wait(self, run_id: str, timeout: float | None = None) -> None:
        with self._lock:
            active = self._active.get(run_id)
        if active is not None:
            active.thread.join(timeout)

    def cancel(self, run_id: str) -> None:
        with self._lock:
            active = self._active.get(run_id)
        if active is None or not active.thread.is_alive():
            raise ValueError("run is not active")
        active.cancel_requested.set()
        active.approval_ready.set()
        for callback in active.cancel_callbacks:
            callback()
        self.lifecycle.transition(run_id, RunStage.CANCELLED)
        self.notify("run_cancelled", "Run cancelled", f"Run {run_id}")

    def pause(self, run_id: str) -> None:
        active = self._active_run(run_id)
        if not active.pause_requested.is_set():
            active.pause_requested.set()
            self.lifecycle.transition(run_id, RunStage.INTERRUPTED)
            self.notify("workflow_blocked", "Workflow paused", f"Run {run_id}")

    def resume(self, run_id: str) -> None:
        active = self._active_run(run_id)
        record = self._run(run_id)
        interrupted = record.get("interrupted_from")
        if not interrupted:
            raise ValueError("run is not paused")
        self.lifecycle.transition(run_id, RunStage(str(interrupted)))
        active.pause_requested.clear()

    def approve(self, run_id: str, authority: str) -> None:
        self._decide(run_id, authority, "approved", "")

    def reject(self, run_id: str, authority: str, reason: str) -> None:
        self._decide(run_id, authority, "rejected", reason)

    def _decide(
        self, run_id: str, authority: str, decision: str, reason: str
    ) -> None:
        if not authority.strip() or (decision == "rejected" and not reason.strip()):
            raise ValueError("approval identity and rejection reason are required")
        active = self._active_run(run_id)
        record = self._run(run_id)
        if record.get("stage") != RunStage.APPROVAL_DECISION.value:
            raise ValueError("run is not awaiting approval")
        active.approval_decision = decision
        record["approval"] = {
            "decision": decision,
            "approving_authority": authority,
            "reason": reason,
            "timestamp": _now(),
        }
        self.store.upsert("runs", run_id, record)
        active.approval_ready.set()

    def _execute_guarded(
        self,
        run_id: str,
        task: dict[str, Any],
        cancel: threading.Event,
        pause: threading.Event,
        approval: threading.Event,
        retry_stage: str | None = None,
        reroute_authorization_id: str | None = None,
    ) -> None:
        try:
            self._execute(
                run_id,
                task,
                cancel,
                pause,
                approval,
                retry_stage,
                reroute_authorization_id,
            )
        except Exception as error:
            self._complete_routing_attempt(run_id, "blocked")
            record = self._run(run_id)
            if record.get("stage") not in {
                RunStage.CANCELLED.value,
                RunStage.BLOCKED.value,
            }:
                self.lifecycle.transition(run_id, RunStage.BLOCKED)
            record = self._run(run_id)
            record["failure_reason"] = str(error)
            record["ended_at"] = _now()
            self._add_recovery(record)
            self.store.upsert("runs", run_id, record)
            self._finalize_report(
                run_id,
                task,
                None,
                "BLOCKED",
                failure_reason=str(error),
            )
            self.notify("provider_failure", "Workflow blocked", f"Run {run_id}")
        finally:
            with self._lock:
                self._active.pop(run_id, None)

    def _execute(
        self,
        run_id: str,
        stored: dict[str, Any],
        cancel: threading.Event,
        pause: threading.Event,
        approval: threading.Event,
        retry_stage: str | None = None,
        reroute_authorization_id: str | None = None,
    ) -> None:
        repository = Path(str(stored["repository"])).resolve()
        if retry_stage is None:
            self._advance(run_id, RunStage.SCOPE_VALIDATION)
            _validate_task_scope(stored, repository)
            self._advance(run_id, RunStage.RISK_CLASSIFICATION)
            self._advance(run_id, RunStage.AUTHORIZATION_RESOLUTION)
            self._advance(run_id, RunStage.PROVIDER_SELECTION)
        providers, routes, routing = _select_routes(
            stored,
            self._provider_settings(),
        )
        reroute_authorization: str | None = None
        if retry_stage is not None:
            providers, routing, reroute_authorization = self._bind_retry_routing(
                run_id,
                stored,
                retry_stage,
                providers,
                routing,
                reroute_authorization_id,
            )
        with self._lock:
            active = self._active.get(run_id)
            if active is not None:
                unique = {id(provider): provider for provider in providers.values()}
                callbacks: list[Callable[[], None]] = []
                for provider in unique.values():
                    callback = getattr(provider, "cancel", None)
                    if callable(callback):
                        callbacks.append(callback)
                active.cancel_callbacks = callbacks
        self._record_routing_attempt(
            run_id,
            stored,
            providers,
            routing,
            retry_stage,
            reroute_authorization,
        )
        if cancel.is_set():
            self._complete_routing_attempt(run_id, "cancelled")
            return
        if retry_stage is None:
            self._advance(run_id, RunStage.WORKTREE_PREPARATION)
        protected_run = self._run(run_id)
        execution_root = Path(
            str(protected_run.get("authority_execution_root", ""))
        ).resolve(strict=True)
        evidence = Path(str(protected_run["evidence_root"])).resolve()
        evidence.mkdir(parents=True, exist_ok=True)
        state = evidence / ".ai-workflow"
        config = KeeperConfig(
            repository,
            state,
            execution_root / "worktrees" / run_id,
            (),
            provider_routes=tuple(routes.items()),
            process_timeout_seconds=int(stored.get("timeout_seconds", 30)),
        )
        task_path = state / "tasks" / f"{stored['id']}.json"
        domain_task = (
            Task.from_dict(load_json(task_path, {}))
            if retry_stage is not None and task_path.exists()
            else _domain_task(stored, run_id)
        )
        routed_providers: dict[str, AgentProvider] = dict(providers)
        router = ProviderRouter(routed_providers, routes)
        observer = _LifecycleObserver(
            self.lifecycle, run_id, cancel, pause, self.notify
        )
        latest_routing_attempt = self._run(run_id).get("routing_attempts", [])[-1]
        engine = Keeper(
            config,
            AgentRunner(
                providers["builder"],
                state / "runs",
                30,
                keeper_run_id=run_id,
                ownership_sink=self._persist_process_ownership,
                execution_sink=lambda event: self._record_provider_execution(
                    run_id, event
                ),
                execution_authority={
                    "attempt_number": latest_routing_attempt.get("attempt_number"),
                    "retry_parent": latest_routing_attempt.get("retry_of"),
                },
            ),
            WorkspaceManager(repository, config.workspace_root, state / "ownership"),
            router,
            observer,
        )
        try:
            result = engine.run_task(
                domain_task,
                retry_stage=retry_stage,
                stage_attempt_id=(
                    str(self._run(run_id).get("active_stage_attempt_id", ""))
                    if retry_stage is not None
                    else None
                ),
            )
        except Exception:
            if cancel.is_set() and domain_task.status in {
                TaskStatus.BUILDING,
                TaskStatus.SELF_VERIFYING,
                TaskStatus.INDEPENDENT_AUDIT,
                TaskStatus.REPAIRING,
                TaskStatus.FINAL_VERIFY,
            }:
                previous = domain_task.status
                domain_task.status = TaskStatus.FAILED
                domain_task.transition_history.append(
                    {
                        "from": previous.value,
                        "to": TaskStatus.FAILED.value,
                        "timestamp": _now(),
                    }
                )
                engine.save_task(domain_task)
            raise
        self._complete_routing_attempt(run_id, result.status.value)
        if cancel.is_set():
            return
        if result.status.value != "COMPLETED":
            self.lifecycle.transition(run_id, RunStage.BLOCKED)
            blocked = self._run(run_id)
            self._add_recovery(blocked)
            blocked["ended_at"] = _now()
            self.store.upsert("runs", run_id, blocked)
            semantic_records = self._persist_semantic_evidence(
                run_id, str(stored["id"]), state
            )
            self._finalize_report(
                run_id,
                stored,
                result,
                "BLOCKED",
                semantic_records=semantic_records,
            )
            if result.status.value == "FAILED":
                self.notify(
                    "verification_failed",
                    "Verification failed",
                    f"Run {run_id}",
                )
            self.notify("workflow_blocked", "Workflow blocked", f"Run {run_id}")
            return
        observer.finish_validation()
        workspace_path = Path(str(result.workspace_path)).resolve()
        git = GitSafetyService()
        changed_paths = engine.workspace_manager.changed_files(workspace_path)
        record = self._run(run_id)
        record.update(
            {
                "worktree": str(workspace_path),
                "worktree_branch": result.branch_name,
                "worktree_head": git.inspect(workspace_path).head,
                "changed_paths": changed_paths,
            }
        )
        self.store.upsert("runs", run_id, record)

        if bool(stored.get("commit_requested", False)):
            staging_allowed = (
                [".keeper-workflow/"]
                if bool(stored.get("is_demo", False))
                else [str(item) for item in stored.get("included_paths", [])]
            )
            staging_blocked = (
                []
                if bool(stored.get("is_demo", False))
                else [str(item) for item in stored.get("excluded_paths", [])]
            )
            git.stage_allowlisted(
                workspace_path,
                changed_paths,
                staging_allowed,
                staging_blocked,
            )
            record = self._run(run_id)
            record["staged_paths"] = git.inspect(workspace_path).staged
            record["staged_digest"] = git.staged_digest(workspace_path)
            self.store.upsert("runs", run_id, record)
        semantic_records = self._persist_semantic_evidence(
            run_id, str(stored["id"]), state
        )
        if bool(stored.get("requires_manual_approval", False)):
            record = self._run(run_id)
            record["status"] = "awaiting_approval"
            self.store.upsert("runs", run_id, record)
            self.notify("authorization_required", "Approval required", f"Run {run_id}")
            while not approval.wait(0.1):
                if cancel.is_set():
                    return
            if cancel.is_set():
                return
            active = self._active_run(run_id)
            if active.approval_decision != "approved":
                self.lifecycle.transition(run_id, RunStage.BLOCKED)
                record = self._run(run_id)
                record.update(
                    {"status": "REJECTED", "outcome": "rejected", "ended_at": _now()}
                )
                self.store.upsert("runs", run_id, record)
                self._finalize_report(
                    run_id,
                    stored,
                    result,
                    "REJECTED",
                    semantic_records=semantic_records,
                )
                self.notify("run_rejected", "Run rejected", f"Run {run_id}")
                return
            self.notify("run_approved", "Run approved", f"Run {run_id}")
        git_result: dict[str, Any] = {}
        if bool(stored.get("commit_requested", False)):
            self.lifecycle.transition(run_id, RunStage.AUTHORIZED_COMMIT)
            authorization = self._authorization("commit", run_id, str(stored["id"]))
            git.commit(
                repository,
                str(stored.get("commit_message", stored["title"])),
                authorization,
                task_id=str(stored["id"]),
                run_id=run_id,
                worktree=workspace_path,
                branch=str(result.branch_name),
            )
            self.store.upsert(
                "authorizations", str(authorization["id"]), authorization
            )
            commit_hash = git.inspect(workspace_path).head
            git_result["commit_hash"] = commit_hash
            if bool(stored.get("push_requested", False)):
                record = self._run(run_id)
                record.update(
                    {
                        "status": "awaiting_push_authorization",
                        "commit_hash": commit_hash,
                    }
                )
                self.store.upsert("runs", run_id, record)
                authorization = self._wait_for_authorization(
                    "push", run_id, str(stored["id"]), cancel
                )
                self.lifecycle.transition(run_id, RunStage.AUTHORIZED_PUSH)
                remote = str(stored.get("push_remote", "origin"))
                source = str(result.branch_name)
                destination = str(
                    stored.get("push_destination") or f"refs/heads/{source}"
                )
                push_result = git.push(
                    repository,
                    remote,
                    source,
                    destination,
                    authorization,
                    task_id=str(stored["id"]),
                    run_id=run_id,
                    worktree=workspace_path,
                )
                self.store.upsert(
                    "authorizations", str(authorization["id"]), authorization
                )
                git_result.update(
                    {
                        "push_result": {
                            "remote": remote,
                            "source_ref": source,
                            "destination_ref": destination,
                            "expected_commit": commit_hash,
                            "output": push_result,
                            "remote_hash": commit_hash,
                        }
                    }
                )
        record = self._run(run_id)
        record["ended_at"] = _now()
        record["git_result"] = git_result
        self.store.upsert("runs", run_id, record)
        self._advance(run_id, RunStage.EVIDENCE_FINALIZATION)
        self._finalize_report(
            run_id,
            stored,
            result,
            "COMPLETED",
            semantic_records=semantic_records,
            git_result=git_result,
        )
        self._advance(run_id, RunStage.CLOSED)
        record = self._run(run_id)
        record.update(
            {
                "status": "COMPLETED",
                "outcome": "approved",
                "ended_at": record.get("ended_at", _now()),
                "evidence_root": str(evidence),
                "report_markdown": str(evidence / "final-report.md"),
                "report_json": str(evidence / "final-report.json"),
                "git_result": git_result,
            }
        )
        self.store.upsert("runs", run_id, record)
        self.notify("run_completed", "Run completed", f"Run {run_id}")

    def _provider_settings(self) -> dict[str, Any]:
        paths = dict(self.store.get("settings", "providers") or {})
        paths["__registrations__"] = dict(
            self.store.get("settings", "provider_registrations") or {}
        )
        paths["__qualification_evidence__"] = {
            str(item["id"]): item
            for item in self.store.list("artifacts")
            if item.get("kind")
            in {"provider_qualification", "provider_qualification_started"}
            and isinstance(item.get("id"), str)
        }
        paths["__authority_verifier__"] = self.authority.verify
        paths["__authority_client__"] = self.authority
        return paths

    def _finalize_report(
        self,
        run_id: str,
        stored: dict[str, Any],
        result: Task | None,
        terminal_status: str,
        *,
        semantic_records: list[dict[str, Any]] | None = None,
        git_result: dict[str, Any] | None = None,
        failure_reason: str | None = None,
    ) -> dict[str, Any]:
        evidence = Path(str(self._run(run_id)["evidence_root"])).resolve()
        evidence.mkdir(parents=True, exist_ok=True)
        run = self._run(run_id)
        records = _provider_records(evidence)
        reroute_reservations = self.store.reroute_reservations_for_run(run_id)
        executions = run.get("provider_execution_attempts", [])
        if not isinstance(executions, list):
            raise RuntimeError("provider execution attempt state is malformed")
        evidence_by_id = {
            str(item.get("run_id")): item
            for item in records
            if item.get("run_id")
        }
        execution_ids = [str(item.get("provider_run_id") or "") for item in executions]
        if len(execution_ids) != len(set(execution_ids)) or any(
            not value for value in execution_ids
        ):
            raise RuntimeError("provider execution attempts are duplicated or malformed")
        unresolved_execution_ids = {
            str(item.get("provider_run_id"))
            for item in executions
            if item.get("status") == "EXECUTION_STARTED"
            and str(item.get("provider_run_id")) not in evidence_by_id
        }
        if set(execution_ids) != set(evidence_by_id) and not (
            terminal_status == "BLOCKED"
            and set(execution_ids) - set(evidence_by_id)
            == unresolved_execution_ids
            and set(evidence_by_id).issubset(set(execution_ids))
        ):
            raise RuntimeError(
                "provider execution attempts do not reconcile with provider run evidence"
            )
        for attempt in executions:
            evidence_record = evidence_by_id.get(str(attempt["provider_run_id"]))
            if evidence_record is None and attempt.get("status") == "EXECUTION_STARTED":
                continue
            if evidence_record is None:
                raise RuntimeError("provider execution evidence is missing")
            if (
                evidence_record.get("task_id") != attempt.get("task_id")
                or evidence_record.get("role") != attempt.get("role")
                or evidence_record.get("provider_instance_id")
                != attempt.get("provider_instance_id")
            ):
                raise RuntimeError("provider execution evidence binding is inconsistent")
        authorizations = [
            item
            for item in self.store.list("authorizations")
            if item.get("task_id") == stored.get("id")
            and item.get("run_id") in {None, run_id}
        ]
        waivers = [
            item
            for item in authorizations
            if item.get("capability") == "verification_waiver"
        ]
        verifications = semantic_records
        if verifications is None:
            verifications = [
                item
                for item in self.store.list("verification_records")
                if item.get("run_id") == run_id
            ]
        initial_reviews = [
            item for item in records if item.get("role") == "reviewer"
        ]
        post_reviews = [
            item
            for item in records
            if item.get("role") == "post_repair_reviewer"
        ]
        repairs = [
            {
                "provider_run_id": item.get("run_id"),
                "provider_name": item.get("provider_name"),
                "files_changed": item.get("files_changed", []),
                "status": item.get("status"),
                "start_time": item.get("start_time"),
                "end_time": item.get("end_time"),
            }
            for item in records
            if item.get("role") == "repairer"
        ]
        git_snapshot = dict(git_result or run.get("git_result") or {})
        findings_snapshot = {
            "findings": [
                finding
                for item in initial_reviews
                for finding in item.get("review_findings", [])
            ],
            "dispositions": [
                disposition
                for item in post_reviews
                for disposition in item.get("accepted_findings", [])
            ],
            "post_repair_findings": [
                finding
                for item in post_reviews
                for finding in item.get("review_findings", [])
            ],
            "repairs": repairs,
        }
        atomic_write_json(evidence / "task-definition.json", stored)
        atomic_write_json(
            evidence / "verification-records.json",
            {"records": verifications},
        )
        atomic_write_json(
            evidence / "review-records.json", findings_snapshot
        )
        atomic_write_json(
            evidence / "authorization-records.json",
            {"records": authorizations},
        )
        atomic_write_json(evidence / "git-result.json", git_snapshot)
        atomic_write_json(
            evidence / "routing-records.json",
            {"attempts": list(run.get("routing_attempts", []))},
        )
        artifacts = _evidence_artifacts(evidence)
        provider_identities = run.get("providers", {})
        if not isinstance(provider_identities, dict):
            provider_identities = {}
        git_values = dict(git_snapshot)
        push_result = git_values.pop("push_result", {})
        approval = run.get("approval")
        if not isinstance(approval, dict):
            approving_records = [
                item for item in records if item.get("final_approval_authority")
            ]
            approval = (
                {
                    "decision": "approved",
                    "authority": approving_records[-1]["final_approval_authority"],
                }
                if approving_records
                else {}
            )
        report: dict[str, Any] = {
            "schema_version": 1,
            "run_id": run_id,
            "task_id": stored.get("id"),
            "objective": stored.get("objective", ""),
            "repository": stored.get("repository", ""),
            "worktree": (
                result.workspace_path
                if result is not None and result.workspace_path
                else run.get("worktree", run.get("workspace", ""))
            ),
            "branch": (
                result.branch_name
                if result is not None and result.branch_name
                else run.get("worktree_branch", run.get("branch", ""))
            ),
            "baseline": stored.get("baseline", ""),
            "scope": {
                "included_paths": list(stored.get("included_paths", [])),
                "excluded_paths": list(stored.get("excluded_paths", [])),
                "completion_criteria": list(
                    stored.get("completion_criteria", [])
                ),
                "required_validations": list(
                    stored.get("required_validations", [])
                ),
                "risk": stored.get("risk", "low"),
                "prohibited_actions": list(
                    stored.get("prohibited_actions", [])
                ),
            },
            "provider_policy": stored.get("provider_policy", "repository-default"),
            "provider_identities": provider_identities,
            "routing_rationale": list(run.get("routing_decisions", [])),
            "routing_attempts": list(run.get("routing_attempts", [])),
            "provider_execution_attempts": executions,
            "reroute_reservations": reroute_reservations,
            "recovery": run.get("recovery", {}),
            "lifecycle_stages": list(run.get("history", [])),
            "authorizations": authorizations,
            "waivers": waivers,
            "commands": verifications,
            "verification_results": verifications,
            "findings": findings_snapshot["findings"],
            "dispositions": findings_snapshot["dispositions"],
            "repairs": repairs,
            "post_repair_findings": findings_snapshot[
                "post_repair_findings"
            ],
            "approval_result": approval,
            "commit_result": git_values,
            "push_result": push_result,
            "logs": [
                item
                for item in artifacts
                if str(item["path"]).endswith((".log", "prompt.md"))
            ],
            "artifacts": artifacts,
            "evidence_paths": [
                str(evidence.resolve()),
                str((evidence / "final-report.json").resolve()),
                str((evidence / "final-report.md").resolve()),
                str((evidence / "evidence-index.json").resolve()),
            ],
            "evidence_hashes": [
                {"path": item["path"], "sha256": item["sha256"]}
                for item in artifacts
            ],
            "unresolved_observations": [
                finding
                for item in records
                for finding in item.get("rejected_findings", [])
            ],
            "start_time": run.get("started_at", ""),
            "end_time": run.get("ended_at", _now()),
            "terminal_status": terminal_status,
            "failure_reason": failure_reason or run.get("failure_reason", ""),
        }
        index = finalize_evidence(evidence, report)
        self._persist_evidence_finalization(
            run_id, stored, report, evidence, index
        )
        return report

    def _persist_evidence_finalization(
        self,
        run_id: str,
        stored: dict[str, Any],
        report: dict[str, Any],
        evidence: Path,
        index: dict[str, Any],
    ) -> None:
        root = evidence.resolve()
        files: list[dict[str, Any]] = []
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            if path.is_symlink():
                raise PermissionError(
                    "protected evidence cannot contain symbolic links"
                )
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root):
                raise PermissionError("protected evidence escapes the run root")
            content = resolved.read_bytes()
            files.append(
                {
                    "path": resolved.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                }
            )
        paths = {str(item["path"]) for item in files}
        mandatory = {
            "final-report.json",
            "final-report.md",
            "evidence-index.json",
            "task-definition.json",
            "verification-records.json",
            "review-records.json",
            "authorization-records.json",
            "git-result.json",
            "routing-records.json",
        }
        provider_attempts = _provider_records(root)
        provider_paths = {
            path.resolve(strict=True).relative_to(root).as_posix()
            for path in root.glob(".ai-workflow/runs/*/run.json")
        }
        mandatory.update(provider_paths)
        if not mandatory.issubset(paths):
            raise RuntimeError("mandatory finalized evidence is incomplete")
        index_paths = {
            str(item.get("path"))
            for item in index.get("files", [])
            if isinstance(item, dict)
        }
        if index_paths != paths - {"evidence-index.json"}:
            raise RuntimeError("finalized evidence manifest is incomplete")
        critical_keys = (
            "schema_version",
            "run_id",
            "task_id",
            "terminal_status",
            "provider_policy",
            "provider_identities",
            "routing_attempts",
            "authorizations",
            "approval_result",
            "commit_result",
            "push_result",
        )
        finalization_id = f"evidence-finalization:{run_id}:{uuid.uuid4().hex}"
        protected: dict[str, Any] = {
            "id": finalization_id,
            "kind": "evidence_finalization",
            "run_id": run_id,
            "task_id": str(stored["id"]),
            "final_status": report["terminal_status"],
            "report_schema_version": report["schema_version"],
            "files": files,
            "mandatory_paths": sorted(mandatory),
            "manifest_digest": hashlib.sha256(
                (root / "evidence-index.json").read_bytes()
            ).hexdigest(),
            "provider_attempt_identities": [
                {
                    "run_id": item.get("run_id"),
                    "task_id": item.get("task_id"),
                    "role": item.get("role"),
                    "provider_name": item.get("provider_name"),
                    "provider_instance_id": item.get("provider_instance_id"),
                }
                for item in provider_attempts
            ],
            "authorization_outcomes": report["authorizations"],
            "git_outcomes": {
                "commit_result": report["commit_result"],
                "push_result": report["push_result"],
            },
            "critical_report_fields": {
                key: report.get(key) for key in critical_keys
            },
            "finalized_at": _now(),
        }
        self.store.insert_immutable(
            "artifacts", finalization_id, protected
        )
        run = self._run(run_id)
        run["evidence_finalization_id"] = finalization_id
        run["evidence_manifest_digest"] = protected["manifest_digest"]
        self.store.upsert("runs", run_id, run)

    def _record_routing_attempt(
        self,
        run_id: str,
        stored: dict[str, Any],
        providers: dict[str, AgentProvider],
        routing: list[dict[str, Any]],
        retry_stage: str | None,
        reroute_authorization: str | None,
    ) -> None:
        _validate_routing_decisions(
            routing, str(stored.get("provider_policy", ""))
        )
        record = self._run(run_id)
        routing_by_role = {
            str(item["role"]): item for item in routing
        }
        record["providers"] = {
            role: {
                "provider_name": provider.provider_name,
                "provider_instance_id": provider.instance_id,
                "stable_registration_digest": routing_by_role[
                    "post_repair_reviewer" if role == "post-reviewer" else role
                ]["stable_registration_digest"],
                "executable": routing_by_role[
                    "post_repair_reviewer" if role == "post-reviewer" else role
                ]["executable"],
                "executable_sha256": routing_by_role[
                    "post_repair_reviewer" if role == "post-reviewer" else role
                ]["executable_sha256"],
            }
            for role, provider in providers.items()
        }
        record["routing_decisions"] = routing
        attempts = list(record.get("routing_attempts", []))
        recorded_at = _now()
        attempt_number = len(attempts) + 1
        retry_parent = attempts[-1]["attempt_id"] if attempts else None
        attempt_id = str(
            record.get("active_stage_attempt_id") or f"{run_id}:initial"
        )
        attempt_decisions = [
            {
                **item,
                "run_id": run_id,
                "task_id": str(stored["id"]),
                "stage_id": retry_stage or "initial-routing",
                "attempt_number": attempt_number,
                "retry_parent_attempt": retry_parent,
                "reroute_authorization_id": reroute_authorization,
                "outcome": "selected",
            }
            for item in routing
        ]
        attempts.append(
            {
                "attempt_id": attempt_id,
                "attempt_number": attempt_number,
                "retry_of": retry_parent,
                "run_id": run_id,
                "task_id": str(stored["id"]),
                "stage_id": retry_stage or "initial-routing",
                "retry_stage": retry_stage,
                "provider_policy": stored.get("provider_policy"),
                "decisions": attempt_decisions,
                "reroute_authorization_id": reroute_authorization,
                "outcome": "selected",
                "recorded_at": recorded_at,
            }
        )
        record["routing_attempts"] = attempts
        self.store.upsert("runs", run_id, record)

    def _complete_routing_attempt(self, run_id: str, outcome: str) -> None:
        record = self._run(run_id)
        attempts = list(record.get("routing_attempts", []))
        if not attempts or attempts[-1].get("outcome") != "selected":
            return
        latest = dict(attempts[-1])
        latest["outcome"] = outcome
        decisions = latest.get("decisions")
        if isinstance(decisions, list):
            latest["decisions"] = [
                {
                    **item,
                    "disposition": outcome,
                }
                for item in decisions
                if isinstance(item, dict)
            ]
        attempts[-1] = latest
        record["routing_attempts"] = attempts
        self.store.upsert("runs", run_id, record)

    def _record_provider_execution(
        self, run_id: str, event: dict[str, Any]
    ) -> dict[str, Any] | None:
        record = self._run(run_id)
        executions = list(record.get("provider_execution_attempts", []))
        provider_run_id = str(event.get("provider_run_id") or "")
        if not provider_run_id:
            raise PermissionError("provider execution identity is missing")
        matches = [
            index
            for index, item in enumerate(executions)
            if item.get("provider_run_id") == provider_run_id
        ]
        if event.get("event") == "started":
            if matches:
                raise PermissionError("duplicate provider execution attempt")
            if event.get("authority_required") is False:
                executions.append(
                    {
                        **event,
                        "status": "MOCK_EXECUTION",
                        "authority_status": "NOT_APPLICABLE_DEMO",
                    }
                )
                record["provider_execution_attempts"] = executions
                self.store.upsert("runs", run_id, record)
                return None
            route_attempts = record.get("routing_attempts", [])
            latest_route = (
                route_attempts[-1]
                if isinstance(route_attempts, list) and route_attempts
                else {}
            )
            decisions = (
                latest_route.get("decisions", [])
                if isinstance(latest_route, dict)
                else []
            )
            matching_routes = [
                item
                for item in decisions
                if isinstance(item, dict)
                and item.get("role") == event.get("role")
                and item.get("provider_instance_id")
                == event.get("provider_instance_id")
            ]
            if len(matching_routes) != 1:
                raise PermissionError(
                    "provider execution has no unique selected routing identity"
                )
            route = matching_routes[0]
            reroute_authorization_id = latest_route.get(
                "reroute_authorization_id"
            )
            registration = route.get("stable_registration")
            if not isinstance(registration, dict):
                raise PermissionError(
                    "provider execution registration is unavailable"
                )
            provider_environment = filtered_environment(dict(os.environ))
            provider_environment["KEEPER_PROVIDER_ROLE"] = str(
                event["role"]
            )
            launcher_parent = str(
                Path(str(registration["launcher_path"])).resolve().parent
            )
            provider_environment["PATH"] = (
                launcher_parent
                + os.pathsep
                + provider_environment.get("PATH", "")
            )
            authority_role = {
                "reviewer": "executive_reviewer",
                "post_repair_reviewer": "executive_post_repair_reviewer",
            }.get(str(event["role"]), str(event["role"]))
            reservation = self.authority.reserve_attempt(
                registration_id=str(registration["trusted_registration_id"]),
                keeper_run_id=run_id,
                task_id=str(event["task_id"]),
                stage_id=str(event["stage_id"]),
                role=authority_role,
                attempt_number=int(latest_route["attempt_number"]),
                provider_run_id=provider_run_id,
                provider_instance_id=str(event["provider_instance_id"]),
                evidence_path=str(event["evidence_path"]),
                prompt_path=str(event["prompt_path"]),
                stdout_path=str(event["stdout_path"]),
                stderr_path=str(event["stderr_path"]),
                workspace=str(event["workspace"]),
                timeout_seconds=int(event["timeout_seconds"]),
                reasoning_level=str(event["reasoning_level"]),
                environment=provider_environment,
                provider_input_required=False,
            )
            authority_attempt = reservation.get("attempt")
            authority_attempt_id = reservation.get("attempt_id")
            if not isinstance(authority_attempt, dict) or not isinstance(
                authority_attempt_id, str
            ):
                raise RuntimeError(
                    "Authority Service attempt reservation is malformed"
                )
            executions.append(
                {
                    **event,
                    "attempt_number": latest_route.get("attempt_number"),
                    "retry_parent": latest_route.get("retry_of"),
                    "reroute_authorization_id": reroute_authorization_id,
                    "stable_registration_digest": route.get(
                        "stable_registration_digest"
                    ),
                    "stable_registration": route.get("stable_registration"),
                    "executable": route.get("executable"),
                    "executable_sha256": route.get("executable_sha256"),
                    "completion_challenge": None,
                    "authority_attempt_id": authority_attempt_id,
                    "authority_launch_challenge": authority_attempt.get(
                        "launch_challenge"
                    ),
                    "authority_role": authority_role,
                    "status": "EXECUTION_RESERVED",
                }
            )
            if reroute_authorization_id:
                self.store.transition_reroute_reservation(
                    str(reroute_authorization_id),
                    "RESERVED",
                    "EXECUTION_STARTED",
                )
            record["provider_execution_attempts"] = executions
            self.store.upsert("runs", run_id, record)
            return {"attempt_id": authority_attempt_id}
        elif event.get("event") == "finished":
            if len(matches) != 1:
                raise PermissionError("provider completion has no unique start record")
            current = dict(executions[matches[0]])
            if current.get("status") == "MOCK_EXECUTION":
                current.update(event)
                current["status"] = str(event.get("result", "failed")).upper()
                executions[matches[0]] = current
                record["provider_execution_attempts"] = executions
                self.store.upsert("runs", run_id, record)
                return None
            if current.get("status") != "EXECUTION_STARTED":
                raise PermissionError("provider execution was already finalized")
            authority_attempt_id = current.get("authority_attempt_id")
            if not isinstance(authority_attempt_id, str):
                raise PermissionError(
                    "Authority Service attempt identity is unavailable"
                )
            authority_state = self.authority.query_state(
                "attempts", authority_attempt_id
            ).get("record")
            if (
                isinstance(authority_state, dict)
                and authority_state.get("service_state") == "CANCELLED"
            ):
                current.update(event)
                current["status"] = "CANCELLED"
                executions[matches[0]] = current
                record["provider_execution_attempts"] = executions
                self.store.upsert("runs", run_id, record)
                return None
            protected = self.authority.finalize_completion(authority_attempt_id)
            completion = protected.get("completion")
            if not isinstance(completion, dict):
                raise RuntimeError(
                    "Authority Service completion response is malformed"
                )
            self.store.insert_immutable(
                "artifacts", str(completion["id"]), completion
            )
            current.update(event)
            current["status"] = str(event.get("result", "failed")).upper()
            current["completion_record_id"] = completion["id"]
            current["completion_integrity_digest"] = completion.get(
                "authenticated_writer_proof"
            )
            current["completion_challenge"] = completion.get(
                "completion_challenge"
            )
            executions[matches[0]] = current
        else:
            raise PermissionError("unknown provider execution lifecycle event")
        record["provider_execution_attempts"] = executions
        self.store.upsert("runs", run_id, record)
        return None

    def _persist_process_ownership(self, ownership: dict[str, Any]) -> None:
        keeper_run_id = str(ownership.get("keeper_run_id") or "")
        provider_run_id = str(ownership.get("provider_run_id") or "")
        task_id = str(ownership.get("task_id") or "")
        if not keeper_run_id or not provider_run_id or not task_id:
            raise PermissionError("process ownership binding is incomplete")
        run = self._run(keeper_run_id)
        if run.get("task_id") != task_id:
            raise PermissionError("process ownership task binding is inconsistent")
        evidence_root = Path(str(run.get("evidence_root", ""))).resolve()
        evidence_path = Path(str(ownership.get("evidence_path", ""))).resolve()
        if not evidence_path.is_relative_to(evidence_root):
            raise PermissionError("process ownership evidence path escapes the run")
        value = {
            **ownership,
            "id": f"process-ownership:{keeper_run_id}:{provider_run_id}",
            "kind": "process_ownership",
            "recorded_at": _now(),
        }
        self.store.insert_immutable("artifacts", str(value["id"]), value)
        run["provider_execution_attempts"] = [
            (
                {
                    **item,
                    "process_id": ownership.get("pid"),
                    "process_ownership": value,
                    "launch_nonce": ownership.get("launch_nonce"),
                    "ownership_token": ownership.get("ownership_token"),
                    "process_creation_identity": ownership.get("creation_time"),
                    "parent_or_job_identity": ownership.get(
                        "job_or_group_identity"
                    ),
                    "completion_challenge": ownership.get(
                        "completion_challenge"
                    ),
                    "status": "EXECUTION_STARTED",
                }
                if isinstance(item, dict)
                and item.get("provider_run_id") == provider_run_id
                and item.get("status") == "EXECUTION_RESERVED"
                else item
            )
            for item in run.get("provider_execution_attempts", [])
        ]
        self.store.upsert("runs", keeper_run_id, run)

    def _process_ownership_records(
        self, keeper_run_id: str, provider_run_id: str | None
    ) -> list[dict[str, Any]]:
        if not provider_run_id:
            return []
        return [
            item
            for item in self.store.list("artifacts")
            if item.get("kind") == "process_ownership"
            and item.get("keeper_run_id") == keeper_run_id
            and item.get("provider_run_id") == provider_run_id
        ]

    def _resolve_protected_completion(
        self,
        run: dict[str, Any],
        attempt: dict[str, Any] | None,
        evidence: object,
    ) -> dict[str, Any]:
        if not isinstance(attempt, dict):
            return {"status": "NOT_REQUIRED", "detail": ""}
        if (
            attempt.get("authority_required") is False
            or attempt.get("authority_status") == "NOT_APPLICABLE_DEMO"
        ):
            return {
                "status": "NOT_REQUIRED_DEMO",
                "detail": "mock/demo executions do not carry protected authority",
            }
        matches = [
            item
            for item in self.store.list("artifacts")
            if item.get("kind") == "provider_completion"
            and item.get("keeper_run_id") == run.get("id")
            and item.get("provider_run_id") == attempt.get("provider_run_id")
        ]
        if not matches:
            authority_attempt_id = attempt.get("authority_attempt_id")
            if isinstance(authority_attempt_id, str):
                try:
                    protected = self.authority.query_state(
                        "attempts", authority_attempt_id
                    ).get("record")
                except (
                    OSError,
                    PermissionError,
                    RuntimeError,
                    TimeoutError,
                ) as error:
                    return {
                        "status": "SERVICE_UNAVAILABLE",
                        "detail": str(error),
                    }
                if (
                    isinstance(protected, dict)
                    and protected.get("service_state")
                    in {"COMPLETED", "FAILED"}
                    and protected.get("kind") == "provider_completion"
                ):
                    completion = dict(protected)
                    completion.pop("service_state", None)
                    self.store.insert_immutable(
                        "artifacts",
                        str(completion["id"]),
                        completion,
                    )
                    matches = [completion]
        if len(matches) != 1:
            return {
                "status": "MISSING" if not matches else "INDETERMINATE",
                "detail": "protected completion record is missing or duplicated",
            }
        completion = matches[0]
        if completion.get("schema_version") != 2:
            return {
                "status": "LEGACY_UNVERIFIABLE",
                "detail": (
                    "in-process authority completion is legacy and must not "
                    "authorize recovery"
                ),
                "record": completion,
            }
        registration = attempt.get("stable_registration")
        expected = {
            "attempt_id": attempt.get("authority_attempt_id"),
            "keeper_run_id": run.get("id"),
            "task_id": attempt.get("task_id"),
            "stage_id": attempt.get("stage_id"),
            "role": attempt.get("authority_role", attempt.get("role")),
            "attempt_number": attempt.get("attempt_number"),
            "provider_run_id": attempt.get("provider_run_id"),
            "provider_instance_id": attempt.get("provider_instance_id"),
            "registration_id": (
                registration.get("trusted_registration_id")
                if isinstance(registration, dict)
                else None
            ),
            "registration_digest": (
                registration.get("configuration_digest")
                if isinstance(registration, dict)
                else None
            ),
            "completion_challenge": (
                attempt.get("completion_challenge")
                or completion.get("completion_challenge")
            ),
            "process_id": (
                attempt.get("process_id") or completion.get("process_id")
            ),
            "process_creation_time": (
                attempt.get("process_creation_identity")
                or completion.get("process_creation_time")
            ),
        }
        if any(
            value is None or completion.get(key) != value
            for key, value in expected.items()
        ):
            return {
                "status": "IDENTITY_MISMATCH",
                "detail": "protected completion identity differs from attempt",
                "record": completion,
            }
        if not self.authority.verify("provider-completion", completion):
            return {
                "status": "AUTHENTICATION_FAILED",
                "detail": "protected completion writer authentication is invalid",
                "record": completion,
            }
        challenge = completion.get("completion_challenge")
        challenge_uses = [
            item
            for item in self.store.list("artifacts")
            if item.get("kind") == "provider_completion"
            and item.get("completion_challenge") == challenge
        ]
        if not isinstance(challenge, str) or not challenge or len(challenge_uses) != 1:
            return {
                "status": "CHALLENGE_REPLAY",
                "detail": "completion challenge is missing or reused",
                "record": completion,
            }
        if not isinstance(evidence, dict):
            return {
                "status": "INDETERMINATE",
                "detail": "provider evidence is unavailable for completion reconciliation",
                "record": completion,
            }
        try:
            content = Path(str(attempt["evidence_path"])).read_bytes()
        except OSError:
            return {
                "status": "INDETERMINATE",
                "detail": "provider evidence digest cannot be reconciled",
                "record": completion,
            }
        if (
            completion.get("provider_evidence_digest")
            != hashlib.sha256(content).hexdigest()
            or completion.get("terminal_disposition")
            != str(evidence.get("status", "")).upper()
        ):
            return {
                "status": "INTEGRITY_MISMATCH",
                "detail": "provider evidence differs from protected completion",
                "record": completion,
            }
        return {
            "status": "VERIFIED",
            "detail": "protected completion record verified",
            "record": completion,
        }

    @staticmethod
    def _add_recovery(record: dict[str, Any]) -> None:
        stopped = str(record.get("stopped_from") or "")
        record["recovery"] = {
            "classification": "recoverable",
            "previous_process_running": False,
            "retry_safe": stopped
            not in {
                RunStage.AUTHORIZED_COMMIT.value,
                RunStage.AUTHORIZED_PUSH.value,
                RunStage.EVIDENCE_FINALIZATION.value,
            },
            "detected_at": _now(),
        }

    def _persist_semantic_evidence(
        self, run_id: str, task_id: str, state: Path
    ) -> list[dict[str, Any]]:
        persisted: list[dict[str, Any]] = []
        for path in sorted(state.glob("runs/*/run.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            verification = payload.get("verification_result")
            if not isinstance(verification, dict):
                continue
            commands = verification.get("semantic_commands", [])
            if not isinstance(commands, list):
                continue
            for item in commands:
                if not isinstance(item, dict) or not item.get("command_id"):
                    continue
                record = {
                    **item,
                    "run_id": run_id,
                    "task_id": task_id,
                    "provider_run_id": payload.get("run_id"),
                    "stage": verification.get("stage"),
                }
                identifier = str(item["command_id"])
                self.store.upsert("verification_records", identifier, record)
                self.store.upsert("commands", identifier, record)
                persisted.append(record)
        return persisted

    def _authorization(
        self, capability: str, run_id: str, task_id: str
    ) -> dict[str, Any]:
        matches = [
            item
            for item in self.store.list("authorizations")
            if item.get("capability") == capability
            and item.get("run_id") == run_id
            and item.get("task_id") == task_id
            and item.get("consumed_at") is None
            and item.get("revoked_at") is None
        ]
        if len(matches) != 1:
            raise PermissionError(
                f"exactly one scoped {capability} authorization is required"
            )
        return matches[0]

    def _wait_for_authorization(
        self,
        capability: str,
        run_id: str,
        task_id: str,
        cancel: threading.Event,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + 60
        self.notify(
            "authorization_required",
            f"{capability.title()} authorization required",
            f"Run {run_id}",
        )
        while time.monotonic() < deadline:
            if cancel.is_set():
                raise RuntimeError("run cancellation requested")
            try:
                return self._authorization(capability, run_id, task_id)
            except PermissionError:
                time.sleep(0.1)
        raise PermissionError(f"{capability} authorization was not provided")

    def _advance(self, run_id: str, stage: RunStage) -> None:
        self.lifecycle.transition(run_id, stage)

    def _task(self, task_id: str) -> dict[str, Any]:
        task = self.store.get("tasks", task_id)
        if task is None:
            raise LookupError("task not found")
        return task

    def _run(self, run_id: str) -> dict[str, Any]:
        run = self.store.get("runs", run_id)
        if run is None:
            raise LookupError("run not found")
        return run

    def _active_run(self, run_id: str) -> ActiveRun:
        with self._lock:
            active = self._active.get(run_id)
        if active is None:
            raise ValueError("run is not active")
        return active


class _LifecycleObserver:
    def __init__(
        self,
        lifecycle: RunLifecycle,
        run_id: str,
        cancel: threading.Event,
        pause: threading.Event,
        notify: Callable[[str, str, str], dict[str, Any]],
    ) -> None:
        self.lifecycle = lifecycle
        self.run_id = run_id
        self.cancel = cancel
        self.pause = pause
        self.notify = notify

    def __call__(self, value: str) -> None:
        if self.cancel.is_set():
            raise RuntimeError("run cancellation requested")
        while self.pause.is_set():
            if self.cancel.is_set():
                raise RuntimeError("run cancellation requested")
            time.sleep(0.05)
        mapping = {
            "BUILDING": RunStage.AUTHOR_EXECUTION,
            "SELF_VERIFYING": RunStage.AUTHOR_SELF_VERIFICATION,
            "INDEPENDENT_AUDIT": RunStage.INDEPENDENT_AUDIT,
            "REPAIRING": RunStage.REPAIR_EXECUTION,
            "POST_REPAIR_REVIEWING": RunStage.POST_REPAIR_VERIFICATION,
            "FINAL_VERIFY": RunStage.FINAL_VALIDATION,
        }
        target = mapping.get(value)
        if target is None:
            return
        if target == RunStage.REPAIR_EXECUTION:
            self.notify(
                "blocking_finding", "Critical/High finding", f"Run {self.run_id}"
            )
        if target == RunStage.POST_REPAIR_VERIFICATION:
            self.notify("repair_completed", "Repair completed", f"Run {self.run_id}")
        current = RunStage(str(self.lifecycle.store.get("runs", self.run_id)["stage"]))  # type: ignore[index]
        if target == RunStage.FINAL_VALIDATION and current == RunStage.POST_REPAIR_VERIFICATION:
            self.lifecycle.transition(self.run_id, RunStage.INDEPENDENT_AUDIT)
        self.lifecycle.transition(self.run_id, target)

    def finish_validation(self) -> None:
        record = self.lifecycle.store.get("runs", self.run_id)
        if record is None:
            raise LookupError("run not found")
        current = RunStage(str(record["stage"]))
        if current != RunStage.FINAL_VALIDATION:
            raise RuntimeError("orchestrator completed without final validation")
        self.lifecycle.transition(self.run_id, RunStage.APPROVAL_DECISION)


def _validate_task_scope(task: dict[str, Any], repository: Path) -> None:
    if not (repository / ".git").exists():
        # Worktrees use a .git file.
        if not (repository / ".git").is_file():
            raise ValueError("task repository is not a Git repository")
    included = task.get("included_paths")
    if not isinstance(included, list) or not included:
        raise ValueError("task requires included paths")
    if any(".." in Path(str(value)).parts for value in included):
        raise PermissionError("task scope contains traversal")


def _domain_task(stored: dict[str, Any], run_id: str) -> Task:
    is_demo = bool(stored.get("is_demo", False))
    scenario = str(stored.get("mock_scenario", "repair"))
    final = "repaired\n" if scenario == "repair" else "built\n"
    waivers = [
        item
        for item in stored.get("verification_waivers", [])
        if isinstance(item, dict)
    ]
    waiver_id = str(waivers[0]["waiver_id"]) if waivers else None
    if is_demo:
        commands = [["keeper:file-equals", ".keeper-workflow/result.txt", "built\n"]]
        final_commands = [["keeper:file-equals", ".keeper-workflow/result.txt", final]]
        specs = [
            {
                "category": "task",
                "arguments": commands[0],
                "validator": "file-equals",
                "registration_id": "keeper:demo-file-equals",
                "required": True,
                "waiver_id": waiver_id,
            }
        ]
        final_specs = [
            {
                "category": "task",
                "arguments": final_commands[0],
                "validator": "file-equals",
                "registration_id": "keeper:demo-file-equals",
                "required": True,
                "waiver_id": waiver_id,
            }
        ]
        categories = ["task"]
        allowed_paths = [".keeper-workflow/"]
        blocked_paths: list[str] = []
    else:
        specs = _registered_verification_specs(stored)
        final_specs = [dict(item) for item in specs]
        commands = []
        for item in specs:
            arguments = item.get("arguments")
            if not isinstance(arguments, list) or not arguments:
                raise ValueError("registered verification arguments must be a non-empty list")
            commands.append([str(value) for value in arguments])
        final_commands = [list(item) for item in commands]
        categories = [str(value) for value in stored.get("required_validations", [])]
        allowed_paths = [str(value) for value in stored.get("included_paths", [])]
        blocked_paths = [str(value) for value in stored.get("excluded_paths", [])]
    return Task(
        str(stored["id"]),
        str(stored["title"]),
        str(stored["objective"]),
        "desktop",
        1,
        risk=str(stored.get("risk", "low")),
        acceptance_criteria=[
            str(value) for value in stored.get("completion_criteria", [])
        ],
        verification_commands=commands,
        final_verification_commands=final_commands,
        verification_specs=specs,
        final_verification_specs=final_specs,
        required_verification_categories=categories,
        allowed_paths=allowed_paths,
        blocked_paths=blocked_paths,
        capabilities=["repository_write", "run_verification"],
        provider=str(stored.get("provider_policy", "automatic")),
        verification_waivers=waivers,
    )


def _select_routes(
    stored: dict[str, Any], configured_paths: dict[str, Any]
) -> tuple[dict[str, AgentProvider], dict[str, str], list[dict[str, Any]]]:
    policy = str(stored.get("provider_policy", "mock"))
    if policy == "mock":
        if not bool(stored.get("is_demo", False)):
            raise PermissionError("mock routing is restricted to explicit demonstrations")
        return _mock_routes(str(stored.get("mock_scenario", "repair")))
    registrations = configured_paths.get("__registrations__", {})
    qualification_evidence = configured_paths.get("__qualification_evidence__", {})
    authority_verifier = configured_paths.get("__authority_verifier__")
    authority_client = configured_paths.get("__authority_client__")
    paths = {
        str(key): str(value)
        for key, value in configured_paths.items()
        if key
        not in {
            "__registrations__",
            "__qualification_evidence__",
            "__authority_verifier__",
            "__authority_client__",
        }
    }
    diagnostics = ProviderDiscovery(
        paths,
        (
            {
                str(key): dict(value)
                for key, value in registrations.items()
                if isinstance(value, dict)
            }
            if isinstance(registrations, dict)
            else {}
        ),
        (
            {
                str(key): dict(value)
                for key, value in qualification_evidence.items()
                if isinstance(value, dict)
            }
            if isinstance(qualification_evidence, dict)
            else {}
        ),
        authority_verifier if callable(authority_verifier) else None,
    ).discover()
    real_diagnostics = [
        item
        for item in diagnostics
        if item.provider_id != "mock"
        and item.discovery_state == "qualified"
    ]
    if policy == "local-only":
        author_pool = [
            item for item in real_diagnostics if item.capabilities.local_only
        ]
    elif policy in {"automatic", "strongest"}:
        author_pool = real_diagnostics
    else:
        author_pool = [
            item for item in real_diagnostics if item.provider_id == policy
        ]
    author = route_provider(
        RoutingRequest("builder", str(stored.get("risk", "low")), "keeper"),
        author_pool,
    )
    reviewer = route_provider(
        RoutingRequest(
            "reviewer",
            str(stored.get("risk", "low")),
            "keeper",
            frozenset({author.provider_id}),
            author.provider_id == "ollama",
        ),
        real_diagnostics,
    )
    repairer = route_provider(
        RoutingRequest("repairer", str(stored.get("risk", "low")), "keeper"),
        real_diagnostics,
    )
    selected = {author.provider_id, reviewer.provider_id, repairer.provider_id}
    instances = {
        provider_id: _adapter(
            next(item for item in real_diagnostics if item.provider_id == provider_id),
            authority_client,
        )
        for provider_id in selected
    }
    providers: dict[str, AgentProvider] = {
        "builder": instances[author.provider_id],
        "reviewer": instances[reviewer.provider_id],
        "repairer": instances[repairer.provider_id],
        "post-reviewer": instances[reviewer.provider_id],
    }
    routes = {
        "builder": "builder",
        "reviewer": "reviewer",
        "repairer": "repairer",
        "post_repair_reviewer": "post-reviewer",
    }
    selected_provider_ids = {
        "builder": author.provider_id,
        "reviewer": reviewer.provider_id,
        "repairer": repairer.provider_id,
        "post_repair_reviewer": reviewer.provider_id,
    }
    diagnostics_by_id = {item.provider_id: item for item in real_diagnostics}
    decisions = [
        _routing_decision(
            role=role,
            provider_id=selected_provider_ids[role],
            provider=providers[target],
            diagnostic=diagnostics_by_id[selected_provider_ids[role]],
            capability=role,
            independence=(
                "independent-review"
                if role in {"reviewer", "post_repair_reviewer"}
                else "authoring"
            ),
            reasons=(
                author.reasons
                if role == "builder"
                else reviewer.reasons
                if role in {"reviewer", "post_repair_reviewer"}
                else repairer.reasons
            ),
            policy=policy,
            configured_paths=configured_paths,
        )
        for role, target in routes.items()
    ]
    return providers, routes, decisions


def _registered_verification_specs(stored: dict[str, Any]) -> list[dict[str, Any]]:
    supplied = stored.get("verification_specs", [])
    if supplied:
        raise PermissionError(
            "normal tasks cannot supply caller-controlled verification specifications"
        )
    repository = Path(str(stored["repository"])).resolve()
    specifications: list[dict[str, Any]] = []
    for category_value in stored.get("required_validations", []):
        category = str(category_value).strip().lower()
        if category == "tests":
            arguments = ["{python}", "-m", "pytest", "-q"]
            validator = "pytest"
        elif category == "typing":
            arguments = [
                "{python}",
                "-m",
                "mypy",
                "--strict",
                "keeper",
                "tests/keeper",
            ]
            validator = "mypy"
        elif category == "compilation":
            arguments = [
                "{python}",
                "-m",
                "compileall",
                "-q",
                "keeper",
                "tests/keeper",
            ]
            validator = "compileall"
        elif category == "foundation":
            script = (repository / "scripts" / "verify-foundation.sh").resolve()
            if (
                not script.is_relative_to(repository)
                or script.is_symlink()
                or not script.is_file()
            ):
                raise PermissionError("foundation validator script is unavailable or unsafe")
            bash = trusted_bash_launcher()
            if bash is None:
                raise RuntimeError("foundation validator requires Git Bash")
            arguments = [str(bash), str(script)]
            validator = "foundation-script"
        else:
            raise ValueError(
                f"validation category requires an explicit registered specification: {category}"
            )
        specification: dict[str, Any] = {
            "category": category,
            "arguments": arguments,
            "validator": validator,
            "registration_id": f"keeper:{category}:v1",
            "required": True,
            "expected_executable_sha256": hashlib.sha256(
                (
                    Path(sys.executable).resolve()
                    if validator in {"pytest", "mypy", "compileall"}
                    else Path(arguments[0]).resolve()
                ).read_bytes()
            ).hexdigest(),
        }
        if validator == "foundation-script":
            specification["expected_sha256"] = hashlib.sha256(
                Path(arguments[-1]).read_bytes()
            ).hexdigest()
        specifications.append(specification)
    if not specifications:
        raise ValueError("normal tasks require registered validation categories")
    return specifications


def _adapter(
    diagnostic: ProviderDiagnostic, authority_client: object
) -> AgentProvider:
    if (
        diagnostic.provider_id == "codex"
        and diagnostic.executable
        and diagnostic.registration
    ):
        if not isinstance(authority_client, AuthorityServiceClient):
            raise RuntimeError("Authority Service client is unavailable")
        return AuthorityServiceProvider(authority_client, diagnostic.registration)
    if (
        diagnostic.provider_id == "claude"
        and diagnostic.executable
        and diagnostic.registration
    ):
        if not isinstance(authority_client, AuthorityServiceClient):
            raise RuntimeError("Authority Service client is unavailable")
        return AuthorityServiceProvider(authority_client, diagnostic.registration)
    if diagnostic.provider_id == "ollama":
        return OllamaProvider()
    if diagnostic.provider_id == "mock":
        return MockProvider(provider_name="mock")
    raise RuntimeError(f"provider adapter is unavailable: {diagnostic.provider_id}")


def _routing_decision(
    *,
    role: str,
    provider_id: str,
    provider: AgentProvider,
    diagnostic: ProviderDiagnostic,
    capability: str,
    independence: str,
    reasons: object,
    policy: str,
    configured_paths: dict[str, Any],
) -> dict[str, Any]:
    if diagnostic.registration is not None:
        registration = dict(diagnostic.registration)
        executable = str(registration["canonical_executable_path"])
        executable_sha256 = str(registration["executable_sha256"])
        registration_digest = _stable_registration_digest(registration)
        return {
            "role": role,
            "provider_id": provider_id,
            "provider": provider.provider_name,
            "provider_instance_id": provider.instance_id,
            "executable": executable,
            "executable_sha256": executable_sha256,
            "capability": capability,
            "independence": independence,
            "reasons": reasons,
            "policy": policy,
            "stable_registration": registration,
            "stable_registration_digest": registration_digest,
        }
    executable = ""
    executable_sha256 = ""
    executable_size = 0
    endpoint_identity = (
        "http://127.0.0.1:11434"
        if diagnostic.provider_id == "ollama"
        else "local-process"
    )
    authentication_mode = (
        "external-cli-session"
        if diagnostic.provider_id in {"codex", "claude"}
        else "local-none"
    )
    capabilities = diagnostic.capabilities.to_dict() if hasattr(
        diagnostic.capabilities, "to_dict"
    ) else {
        key: value
        for key, value in diagnostic.to_dict()["capabilities"].items()
    }
    generated_registration: dict[str, Any] = {
        "trusted_registration_id": f"keeper-provider:{provider_id}:v1",
        "logical_provider_id": provider_id,
        "provider_name": provider.provider_name,
        "canonical_executable_path": executable,
        "executable_sha256": executable_sha256,
        "executable_size": executable_size,
        "endpoint_identity": endpoint_identity,
        "capability_set": capabilities,
        "selected_capability": capability,
        "independence_classification": (
            "independent-capable"
            if role in {"reviewer", "post_repair_reviewer"}
            else "authoring-only"
        ),
        "role_eligibility": [role],
        "provider_policy": policy,
        "authentication_mode": authentication_mode,
        "registration_version": 1,
        "configured_path": str(configured_paths.get(provider_id, "")),
    }
    generated_registration["configuration_digest"] = hashlib.sha256(
        json.dumps(
            {
                "diagnostic": diagnostic.to_dict(),
                "registration": generated_registration,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    setattr(provider, "registration", dict(generated_registration))
    registration_digest = hashlib.sha256(
        json.dumps(
            generated_registration, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return {
        "role": role,
        "provider_id": provider_id,
        "provider": provider.provider_name,
        "provider_instance_id": provider.instance_id,
        "executable": executable,
        "executable_sha256": executable_sha256,
        "capability": capability,
        "independence": independence,
        "reasons": reasons,
        "policy": policy,
        "stable_registration": generated_registration,
        "stable_registration_digest": registration_digest,
    }


def _mock_routes(
    scenario: str,
) -> tuple[dict[str, AgentProvider], dict[str, str], list[dict[str, Any]]]:
    finding: list[dict[str, object]] = []
    if scenario == "repair":
        finding = [
            {
                "finding_id": "MOCK-H-1",
                "severity": "High",
                "title": "Deterministic repair",
                "description": "The acceptance scenario requires repair.",
            }
        ]
    providers: dict[str, AgentProvider] = {
        "builder": MockProvider(
            provider_name="mock-author",
            output={"status": "completed", "files_changed": [".keeper-workflow/result.txt"]},
            file_writes={".keeper-workflow/result.txt": "built\n"},
        ),
        "reviewer": MockProvider(
            provider_name="mock-reviewer",
            output={"status": "completed", "files_changed": [], "findings": finding},
        ),
        "repairer": MockProvider(
            provider_name="mock-repairer",
            output={"status": "completed", "files_changed": [".keeper-workflow/result.txt"]},
            file_writes={".keeper-workflow/result.txt": "repaired\n"},
        ),
        "post-reviewer": MockProvider(
            provider_name="mock-post-reviewer",
            output={
                "status": "completed",
                "files_changed": [],
                "findings": [],
                "dispositions": (
                    [
                        {
                            "finding_id": "MOCK-H-1",
                            "status": "resolved",
                            "justification": "Deterministic repair verified.",
                        }
                    ]
                    if finding
                    else []
                ),
            },
        ),
    }
    if scenario == "blocked-reviewer":
        providers["reviewer"] = providers["builder"]
    routes = {
        "builder": "builder",
        "reviewer": "reviewer",
        "repairer": "repairer",
        "post_repair_reviewer": "post-reviewer",
    }
    rationale: list[dict[str, Any]] = []
    for role, provider_id in routes.items():
        provider = providers[provider_id]
        diagnostic = ProviderDiagnostic(
            provider.provider_name,
            provider.provider_name,
            True,
            None,
            "built-in",
            "verified",
            ProviderCapabilities(local_only=True, streaming=False),
            "Deterministic built-in provider.",
        )
        rationale.append(
            _routing_decision(
                role=role,
                provider_id=provider.provider_name,
                provider=provider,
                diagnostic=diagnostic,
                capability=role,
                independence=(
                    "independent-review"
                    if role in {"reviewer", "post_repair_reviewer"}
                    else "authoring"
                ),
                reasons=["deterministic capability match with independent identity"],
                policy="mock",
                configured_paths={},
            )
        )
    return providers, routes, rationale


def _provider_records(evidence: Path) -> list[dict[str, Any]]:
    root = evidence.resolve()
    records: list[dict[str, Any]] = []
    for path in sorted(root.glob(".ai-workflow/runs/*/run.json")):
        if path.is_symlink():
            raise PermissionError("provider evidence cannot be a symbolic link")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise PermissionError("provider evidence escapes the run root")
        try:
            value = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def _routing_digest(decisions: list[dict[str, Any]]) -> str:
    fields = (
        "role",
        "policy",
        "capability",
        "independence",
        "stable_registration_digest",
    )
    normalized = [
        {key: item.get(key) for key in fields}
        for item in sorted(decisions, key=lambda value: str(value.get("role", "")))
    ]
    return hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _validate_routing_decisions(
    decisions: list[dict[str, Any]], policy: str
) -> None:
    required_roles = {
        "builder",
        "reviewer",
        "repairer",
        "post_repair_reviewer",
    }
    by_role = {
        str(item.get("role")): item
        for item in decisions
        if isinstance(item, dict) and item.get("role")
    }
    if set(by_role) != required_roles or len(decisions) != len(required_roles):
        raise PermissionError("routing decisions are incomplete or duplicated")
    for role, item in by_role.items():
        if policy != "mock" and (
            str(item.get("provider_id", "")).startswith("mock")
            or str(item.get("provider", "")).startswith("mock")
        ):
            raise PermissionError("retry cannot downgrade routing to mock")
        registration = item.get("stable_registration")
        registration_digest = item.get("stable_registration_digest")
        registration_required = (
            "trusted_registration_id",
            "logical_provider_id",
            "provider_name",
            "canonical_executable_path",
            "executable_sha256",
            "executable_size",
            "configuration_digest",
            "endpoint_identity",
            "capability_set",
            "provider_policy",
            "independence_classification",
            "authentication_mode",
            "registration_version",
        )
        if (
            item.get("policy") != policy
            or item.get("capability") != role
            or not item.get("provider_id")
            or not item.get("provider")
            or not item.get("provider_instance_id")
            or not isinstance(registration, dict)
            or any(
                key not in registration
                or registration.get(key) is None
                or (
                    key not in {
                        "canonical_executable_path",
                        "executable_sha256",
                    }
                    and registration.get(key) == ""
                )
                for key in registration_required
            )
            or registration_digest != _stable_registration_digest(registration)
            or item.get("executable")
            != registration.get("canonical_executable_path")
            or item.get("executable_sha256")
            != registration.get("executable_sha256")
            or item.get("provider_id")
            != registration.get("logical_provider_id")
            or item.get("provider") != registration.get("provider_name")
            or registration.get("registration_status", "active") != "active"
            or registration.get("revoked_at") is not None
            or (
                policy != "mock"
                and (
                    role not in registration.get("role_eligibility", [])
                    or not isinstance(registration.get("capability_set"), dict)
                    or registration["capability_set"].get(
                        "author"
                        if role == "builder"
                        else "repairer"
                        if role == "repairer"
                        else "reviewer"
                    )
                    is not True
                    or (
                        role in {"reviewer", "post_repair_reviewer"}
                        and registration.get("independence_classification")
                        != "independent-capable"
                    )
                )
            )
        ):
            raise PermissionError("routing decision identity is malformed")
    if (
        by_role["reviewer"]["provider_id"]
        == by_role["builder"]["provider_id"]
        or by_role["post_repair_reviewer"]["provider_id"]
        == by_role["builder"]["provider_id"]
    ):
        raise PermissionError("retry routing weakens reviewer independence")


def _stable_registration_digest(registration: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(registration, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _evidence_artifacts(evidence: Path) -> list[dict[str, Any]]:
    root = evidence.resolve()
    artifacts: list[dict[str, Any]] = []
    excluded = {"evidence-index.json", "final-report.json", "final-report.md"}
    for path in sorted(root.rglob("*")):
        if path.name in excluded or not path.is_file():
            continue
        if path.is_symlink():
            raise PermissionError("evidence artifact cannot be a symbolic link")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise PermissionError("evidence artifact escapes the run root")
        content = resolved.read_bytes()
        artifacts.append(
            {
                "path": resolved.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    return artifacts


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _active_provider_pid(record: dict[str, Any]) -> int | None:
    root = record.get("evidence_root")
    if not isinstance(root, str):
        return None
    for path in sorted(
        Path(root).glob(".ai-workflow/runs/*/run.json"),
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
        reverse=True,
    ):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        pid = value.get("process_id")
        if value.get("status") == "running" and isinstance(pid, int):
            return pid
    return None


def _active_provider_record(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    resolution = _resolve_execution_evidence(
        record, _durable_active_execution(record)
    )
    return (
        resolution.get("record")
        if resolution.get("status") == "RESOLVED_ACTIVE"
        and isinstance(resolution.get("record"), dict)
        else None
    )


def _legacy_active_provider_record(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    root = record.get("evidence_root")
    if not isinstance(root, str):
        return None
    for path in sorted(
        Path(root).glob(".ai-workflow/runs/*/run.json"),
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
        reverse=True,
    ):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("status") == "running":
            return value
    return None


def _durable_active_execution(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    attempts = record.get("provider_execution_attempts")
    if not isinstance(attempts, list):
        return None
    active = [
        item
        for item in attempts
        if isinstance(item, dict)
        and item.get("status")
        in {"EXECUTION_RESERVED", "EXECUTION_STARTED"}
    ]
    if len(active) != 1:
        return (
            {
                "status": "INDETERMINATE",
                "detail": "duplicate durable execution-started attempts",
            }
            if active
            else None
        )
    return active[0]


def _resolve_execution_evidence(
    record: dict[str, Any],
    attempt: dict[str, Any] | None,
) -> dict[str, Any]:
    if attempt is None:
        return {"status": "NO_ACTIVE_ATTEMPT", "detail": ""}
    provider_run_id = attempt.get("provider_run_id")
    if not isinstance(provider_run_id, str) or not provider_run_id:
        return {
            "status": "INDETERMINATE",
            "detail": "durable execution attempt has no provider run id",
        }
    root_value = record.get("evidence_root")
    evidence_value = attempt.get("evidence_path")
    if not isinstance(root_value, str) or not isinstance(evidence_value, str):
        return {
            "status": "MISSING_EVIDENCE",
            "detail": "protected evidence root or canonical evidence path is missing",
        }
    try:
        root = Path(root_value).resolve(strict=True)
        declared = Path(evidence_value)
        path = declared.resolve(strict=True)
    except FileNotFoundError:
        return {
            "status": "MISSING_EVIDENCE",
            "detail": "exact protected provider evidence path does not exist",
        }
    except OSError:
        return {
            "status": "INACCESSIBLE_EVIDENCE",
            "detail": "exact protected provider evidence path is inaccessible",
        }
    expected_parent = root / ".ai-workflow" / "runs" / provider_run_id
    if (
        not path.is_relative_to(root)
        or path != expected_parent / "run.json"
        or str(path) != evidence_value
        or path.is_symlink()
        or any(parent.is_symlink() for parent in path.parents if parent != root.parent)
    ):
        return {
            "status": "IDENTITY_MISMATCH",
            "detail": "protected provider evidence path is noncanonical or escapes its run",
        }
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {
            "status": "MALFORMED_EVIDENCE",
            "detail": "exact protected provider evidence is malformed",
        }
    except OSError:
        return {
            "status": "INACCESSIBLE_EVIDENCE",
            "detail": "exact protected provider evidence is inaccessible",
        }
    if not isinstance(value, dict):
        return {
            "status": "MALFORMED_EVIDENCE",
            "detail": "exact protected provider evidence is not an object",
        }
    registration = attempt.get("stable_registration")
    if not isinstance(registration, dict):
        return {
            "status": "INDETERMINATE",
            "detail": "durable attempt has no complete stable registration",
            "record": value,
        }
    expected = {
        "run_id": provider_run_id,
        "keeper_run_id": record.get("id"),
        "task_id": attempt.get("task_id"),
        "stage_id": attempt.get("stage_id"),
        "role": attempt.get("role"),
        "attempt_number": attempt.get("attempt_number"),
        "retry_parent": attempt.get("retry_parent"),
        "provider_name": attempt.get("provider_name"),
        "provider_logical_id": registration.get("logical_provider_id"),
        "provider_instance_id": attempt.get("provider_instance_id"),
        "stable_registration_digest": attempt.get("stable_registration_digest"),
        "executable_path": attempt.get("executable"),
        "executable_sha256": attempt.get("executable_sha256"),
        "configuration_digest": registration.get("configuration_digest"),
        "endpoint_identity": registration.get("endpoint_identity"),
        "authentication_mode": registration.get("authentication_mode"),
        "capability_set": registration.get("capability_set"),
        "provider_policy": registration.get("provider_policy"),
        "independence_classification": registration.get(
            "independence_classification"
        ),
        "evidence_path": evidence_value,
        "launch_nonce": attempt.get("launch_nonce"),
        "ownership_token": attempt.get("ownership_token"),
    }
    mismatches = [
        key
        for key, expected_value in expected.items()
        if expected_value is None or value.get(key) != expected_value
    ]
    if mismatches:
        return {
            "status": "IDENTITY_MISMATCH",
            "detail": (
                "provider evidence differs from protected execution fields: "
                + ", ".join(mismatches)
            ),
            "record": value,
        }
    status_value = value.get("status")
    if not isinstance(status_value, str):
        return {
            "status": "INDETERMINATE",
            "detail": "provider evidence status is missing or malformed",
            "record": value,
        }
    canonical_status = status_value.upper()
    nonterminal = {"CREATED", "STARTING", "RUNNING", "EXECUTION_STARTED"}
    terminal = {
        "COMPLETED",
        "FAILED",
        "REJECTED",
        "BLOCKED",
        "CANCELLED",
        "TERMINATED",
    }
    if canonical_status not in nonterminal | terminal:
        return {
            "status": "INDETERMINATE",
            "detail": "provider evidence status is not a supported state",
            "record": value,
        }
    if canonical_status in terminal and not _terminal_evidence_complete(
        value, canonical_status
    ):
        return {
            "status": "INDETERMINATE",
            "detail": "terminal provider evidence disposition is incomplete",
            "record": value,
        }
    return {
        "status": (
            "RESOLVED_ACTIVE" if canonical_status in nonterminal else "RESOLVED_TERMINAL"
        ),
        "detail": "provider evidence resolved against protected execution state",
        "record": value,
    }


def _terminal_evidence_complete(value: dict[str, Any], status: str) -> bool:
    if not isinstance(value.get("end_time"), str) or not value["end_time"]:
        return False
    exit_code = value.get("process_exit_code")
    if not isinstance(exit_code, int):
        return False
    if status == "COMPLETED":
        return exit_code == 0 and value.get("failure_reason") is None
    return exit_code != 0 and isinstance(value.get("failure_reason"), str) and bool(
        value["failure_reason"]
    )


def _protected_record_digest(value: dict[str, Any]) -> str:
    protected = {
        key: item
        for key, item in value.items()
        if key
        not in {
            "integrity_digest",
            "authority_schema_version",
            "authority_key_id",
            "authenticated_writer_proof",
        }
    }
    return hashlib.sha256(
        json.dumps(protected, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _windows_process_tree(root_process_id: int) -> list[int] | None:
    class ProcessEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_uint32),
            ("cntUsage", ctypes.c_uint32),
            ("th32ProcessID", ctypes.c_uint32),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_uint32),
            ("cntThreads", ctypes.c_uint32),
            ("th32ParentProcessID", ctypes.c_uint32),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_uint32),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = (ctypes.c_uint32, ctypes.c_uint32)
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32FirstW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ProcessEntry),
    )
    kernel32.Process32FirstW.restype = ctypes.c_int
    kernel32.Process32NextW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ProcessEntry),
    )
    kernel32.Process32NextW.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        return None
    children: dict[int, list[int]] = {}
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        available = bool(kernel32.Process32FirstW(snapshot, ctypes.byref(entry)))
        while available:
            children.setdefault(int(entry.th32ParentProcessID), []).append(
                int(entry.th32ProcessID)
            )
            available = bool(kernel32.Process32NextW(snapshot, ctypes.byref(entry)))
    finally:
        kernel32.CloseHandle(snapshot)

    ordered: list[int] = []

    def visit(pid: int) -> None:
        for child in children.get(pid, []):
            visit(child)
        ordered.append(pid)

    visit(root_process_id)
    return ordered
