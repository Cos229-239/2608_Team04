from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable, NoReturn, SupportsIndex
from weakref import WeakKeyDictionary

from keeper.executive.authority import (
    AuthorityEvaluator,
    TrustedActionClassifier,
)
from keeper.executive.authority_gateway import (
    AuthorityBackedSpecialistGateway,
    AuthorityExecutionPlan,
    ProductionAuthorityBackedSpecialistGateway,
    SemanticAuthorityTestGateway,
    artifact_digest_from_files,
)
from keeper.executive.enums import ExecutiveState, TaskStatus
from keeper.executive.models import (
    ApprovalRecord,
    ExecutiveTask,
    MemoryRecord,
    ProjectCharter,
    ProjectRecord,
    SpecialistProfile,
    utc_now,
)
from keeper.executive.planning import TaskReadiness, WorkflowPlanner
from keeper.executive.repository import (
    ExecutiveRepository,
    ProductionExecutiveRepository,
    TestExecutiveRepository,
    new_id,
)
from keeper.executive.specialists import SpecialistSelector
from keeper.executive.state import transition_project


IN_FLIGHT = frozenset(
    {
        TaskStatus.LAUNCH_CLAIMED,
        TaskStatus.EXECUTION_STARTED,
        TaskStatus.RUNNING,
        TaskStatus.COMPLETION_PENDING,
        TaskStatus.UNCERTAIN,
    }
)


@dataclass(frozen=True, slots=True)
class _RuntimeComposition:
    production: bool
    repository: ExecutiveRepository
    gateway: AuthorityBackedSpecialistGateway
    repository_identity: object | None
    gateway_identity: object | None


def _composition_registry() -> tuple[
    Callable[[ExecutiveRuntime, _RuntimeComposition], None],
    Callable[[ExecutiveRuntime], _RuntimeComposition | None],
]:
    registry: WeakKeyDictionary[ExecutiveRuntime, _RuntimeComposition] = (
        WeakKeyDictionary()
    )

    def register(
        runtime: ExecutiveRuntime,
        composition: _RuntimeComposition,
    ) -> None:
        if runtime in registry:
            raise AttributeError("Executive runtime is already initialized")
        registry[runtime] = composition

    def registered(runtime: ExecutiveRuntime) -> _RuntimeComposition | None:
        return registry.get(runtime)

    return register, registered


_register_composition, _registered_composition = _composition_registry()
del _composition_registry

_IMMUTABLE_RUNTIME_NAMES = frozenset(
    {
        "repository",
        "gateway",
        "_repository",
        "_gateway",
        "sealed",
        "_sealed",
        "__sealed",
        "_ExecutiveRuntime__repository",
        "_ExecutiveRuntime__gateway",
        "_ExecutiveRuntime__sealed",
        "_ExecutiveRuntime__repository_id",
        "_ExecutiveRuntime__gateway_id",
        "_ExecutiveRuntime__repository_identity",
        "_ExecutiveRuntime__gateway_identity",
        "_ExecutiveRuntime__production_composition",
        "__dict__",
        "__weakref__",
    }
)


class ExecutiveRuntime:
    """Production runtime: every provider boundary is KeeperAuthority-owned.

    Public composition is immutable for supported application use. Provider
    output is data and is never imported into this interpreter. Deliberate
    private-field mutation or monkey-patching after arbitrary code is already
    executing here is post-compromise behavior outside the Keeper 1.0
    personal-use threat model.
    """

    __repository: ExecutiveRepository
    __gateway: AuthorityBackedSpecialistGateway
    __slots__ = (
        "__repository",
        "__gateway",
        "evaluator",
        "selector",
        "__weakref__",
    )

    def __init__(
        self,
        repository: ExecutiveRepository,
        gateway: SemanticAuthorityTestGateway,
    ) -> None:
        if _registered_composition(self) is not None:
            raise AttributeError("Executive runtime is already initialized")
        if type(self) is not ExecutiveRuntime:
            raise TypeError("Executive runtime subclasses are not supported")
        if type(repository) is not TestExecutiveRepository:
            raise RuntimeError("test runtime requires the exact test repository")
        if type(gateway) is not SemanticAuthorityTestGateway:
            raise RuntimeError(
                "test runtime requires the explicit semantic Authority test gateway"
            )
        object.__setattr__(self, "_ExecutiveRuntime__repository", repository)
        object.__setattr__(self, "_ExecutiveRuntime__gateway", gateway)
        self.evaluator = AuthorityEvaluator()
        self.selector = SpecialistSelector()
        _register_composition(
            self,
            _RuntimeComposition(
                production=False,
                repository=repository,
                gateway=gateway,
                repository_identity=None,
                gateway_identity=None,
            ),
        )

    @classmethod
    def production(
        cls,
        repository: ProductionExecutiveRepository,
        gateway: ProductionAuthorityBackedSpecialistGateway,
    ) -> ExecutiveRuntime:
        if cls is not ExecutiveRuntime:
            raise TypeError("Executive runtime subclasses are not supported")
        if type(repository) is not ProductionExecutiveRepository:
            raise RuntimeError(
                "production runtime requires the exact production repository"
            )
        if type(gateway) is not ProductionAuthorityBackedSpecialistGateway:
            raise RuntimeError(
                "production runtime requires the sealed production gateway"
            )
        repository_identity = repository._production_runtime_identity()
        gateway_identity = gateway._production_runtime_identity()
        runtime = object.__new__(cls)
        object.__setattr__(runtime, "_ExecutiveRuntime__repository", repository)
        object.__setattr__(runtime, "_ExecutiveRuntime__gateway", gateway)
        runtime.evaluator = AuthorityEvaluator()
        runtime.selector = SpecialistSelector()
        _register_composition(
            runtime,
            _RuntimeComposition(
                production=True,
                repository=repository,
                gateway=gateway,
                repository_identity=repository_identity,
                gateway_identity=gateway_identity,
            ),
        )
        return runtime

    def __setattr__(self, name: str, value: object) -> None:
        if name in _IMMUTABLE_RUNTIME_NAMES:
            raise AttributeError("Executive runtime composition is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if name in _IMMUTABLE_RUNTIME_NAMES:
            raise AttributeError("Executive runtime composition is immutable")
        object.__delattr__(self, name)

    def __copy__(self) -> NoReturn:
        raise TypeError("Executive runtime cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        del memo
        raise TypeError("Executive runtime cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Executive runtime cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("Executive runtime cannot be serialized")

    def progress(self, project_id: str) -> ProjectRecord:
        self._validate_composition()
        project = self.__repository.project(project_id)
        if project.state in {
            ExecutiveState.PAUSED,
            ExecutiveState.CANCELED,
            ExecutiveState.COMPLETED,
            ExecutiveState.FAILED,
            ExecutiveState.WAITING_FOR_FOUNDER,
            ExecutiveState.WAITING_FOR_PROVIDER,
            ExecutiveState.WAITING_FOR_CREDENTIAL,
            ExecutiveState.WAITING_FOR_EXTERNAL_SYSTEM,
            ExecutiveState.WAITING_FOR_USAGE_RESET,
        }:
            return project
        charter = self._active_charter(project)
        workflows = self.__repository.workflows(project_id)
        if not workflows:
            if project.state == ExecutiveState.ACTIVE:
                prior = project
                project = transition_project(project, ExecutiveState.PLANNING)
                self.__repository.save_project(project, expected=prior)
            WorkflowPlanner(self.__repository).generate(project, charter)
            prior = project
            project = transition_project(project, ExecutiveState.EXECUTING)
            self.__repository.save_project(project, expected=prior)
            return project
        tasks = tuple(self.__repository.tasks(project_id))
        in_flight = next(
            (task for task in tasks if TaskStatus(task.status) in IN_FLIGHT),
            None,
        )
        if in_flight is not None:
            return self._reconcile_author(project, charter, in_flight)
        review_pending = next(
            (
                task
                for task in tasks
                if task.status == TaskStatus.REVIEW_REQUIRED
                and task.review_attempt_id is not None
            ),
            None,
        )
        if review_pending is not None:
            return self._reconcile_review(project, charter, review_pending)
        unclaimed_review = next(
            (
                task
                for task in tasks
                if task.status == TaskStatus.REVIEW_REQUIRED
                and task.review_attempt_id is None
            ),
            None,
        )
        if unclaimed_review is not None:
            profiles = self.__gateway.specialists(charter)
            author = next(
                (
                    item
                    for item in profiles
                    if item.provider_id == unclaimed_review.provider_id
                    and item.model_id == unclaimed_review.model_id
                    and item.session_id == unclaimed_review.session_id
                ),
                None,
            )
            if author is None:
                return self._pause(
                    project,
                    ExecutiveState.BLOCKED,
                    "Author Authority identity is unavailable for review binding.",
                )
            return self._review(
                project, charter, unclaimed_review, author
            )
        if tasks and all(
            task.status in {TaskStatus.COMPLETED, TaskStatus.SKIPPED}
            for task in tasks
        ):
            prior = project
            if project.state == ExecutiveState.EXECUTING:
                project = transition_project(project, ExecutiveState.REVIEWING)
            project = transition_project(project, ExecutiveState.COMPLETED)
            self.__repository.save_project(project, expected=prior)
            return project
        candidate = self._next_candidate(tasks)
        if candidate is None:
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                "No task can progress from durable state.",
            )
        profiles = self.__gateway.specialists(charter)
        author = self.selector.select(candidate, charter, profiles)
        if author is None:
            return self._pause(
                project,
                ExecutiveState.WAITING_FOR_PROVIDER,
                "No Authority-qualified provider can accept the task.",
            )
        available_inputs = frozenset(
            output
            for task in tasks
            if task.status == TaskStatus.COMPLETED
            for output in task.expected_outputs
        )
        if candidate.status in {
            TaskStatus.PROPOSED,
            TaskStatus.BLOCKED,
            TaskStatus.WAITING,
        }:
            readiness = TaskReadiness(self.evaluator).evaluate(
                candidate,
                all_tasks=tasks,
                project=project,
                charter=charter,
                specialist=author,
                available_inputs=available_inputs,
                approvals=tuple(
                    self.__repository.approvals(
                        project.project_id, charter.revision
                    )
                ),
            )
            if not readiness.ready:
                return self._pause(
                    project,
                    ExecutiveState.BLOCKED,
                    "; ".join(readiness.reasons),
                )
            ready = TaskReadiness.mark_ready(candidate, readiness)
            try:
                self.__repository.save_task(ready, expected=candidate)
            except PermissionError:
                return self.__repository.project(project_id)
            candidate = ready
        action = TrustedActionClassifier().classify(
            candidate, charter, author
        )
        decision = self.evaluator.evaluate(
            project,
            charter,
            action,
            tuple(
                self.__repository.approvals(
                    project.project_id, charter.revision
                )
            ),
        )
        if decision.outcome not in {"ALLOWED", "ALLOWED_WITHIN_LIMIT"}:
            return self._pause(
                project,
                ExecutiveState.WAITING_FOR_FOUNDER,
                f"Authority denied launch: {decision.outcome}.",
            )
        plan = self.__gateway.prepare(candidate, charter, author)
        try:
            claimed = self.__repository.claim_execution(
                candidate.task_id,
                expected_revision=candidate.revision,
                plan=asdict(plan),
                action=action,
                approval_id=decision.approval_id,
            )
        except PermissionError:
            return self.__repository.project(project_id)
        owned = claimed
        try:
            self.__gateway.reserve(plan)
            claimed = self.__repository.transition_execution(
                claimed.task_id,
                expected_revision=claimed.revision,
                expected_status=TaskStatus.LAUNCH_CLAIMED,
                target_status=TaskStatus.EXECUTION_STARTED,
                attempt_state="RESERVED",
            )
            owned = claimed
            self._recheck_launch(claimed, charter, author)
            running = self.__repository.transition_execution(
                claimed.task_id,
                expected_revision=claimed.revision,
                expected_status=TaskStatus.EXECUTION_STARTED,
                target_status=TaskStatus.RUNNING,
                attempt_state="EXECUTION_STARTED",
            )
            owned = running
            self._cross_budget_boundary(running)
            result = self.__gateway.execute(plan)
        except BaseException as error:
            current = self.__repository.task(candidate.task_id)
            if (
                current.authority_attempt_id is not None
                and self.__gateway.attempt_state(
                    current.authority_attempt_id
                )
                == "WAITING_FOR_USAGE_RESET"
                and current.revision == owned.revision
                and current.status
                in {TaskStatus.EXECUTION_STARTED, TaskStatus.RUNNING}
            ):
                try:
                    self.__repository.mark_execution_waiting_for_usage(
                        current.task_id,
                        expected_revision=current.revision,
                        reason=str(error),
                    )
                except PermissionError:
                    pass
                return self._pause(
                    self.__repository.project(project_id),
                    ExecutiveState.WAITING_FOR_USAGE_RESET,
                    "Provider usage is exhausted; automatic retry and fallback are disabled.",
                )
            if (
                current.revision == owned.revision
                and current.status == TaskStatus.LAUNCH_CLAIMED
                and current.authority_attempt_id is not None
                and self.__gateway.attempt_state(
                    current.authority_attempt_id
                )
                is None
            ):
                try:
                    self.__repository.release_prelaunch_execution_claim(
                        current.task_id,
                        expected_revision=current.revision,
                    )
                except PermissionError:
                    pass
                return self._pause(
                    self.__repository.project(project_id),
                    ExecutiveState.WAITING_FOR_PROVIDER,
                    "Authority reservation failed before launch; local holds were released.",
                )
            if (
                current.revision != owned.revision
                or current.status != owned.status
            ):
                return self.__repository.project(project_id)
            if current.status != TaskStatus.CANCELED:
                try:
                    self.__repository.mark_execution_uncertain(
                        current.task_id,
                        expected_revision=current.revision,
                        reason=f"Authority reconciliation required: {type(error).__name__}",
                    )
                except PermissionError:
                    pass
            return self._pause(
                self.__repository.project(project_id),
                ExecutiveState.BLOCKED,
                "Provider execution is uncertain and is not retry-safe.",
            )
        try:
            imported = self.__repository.accept_author_completion(
                running.task_id,
                expected_revision=running.revision,
                result=asdict(result),
            )
        except PermissionError:
            current = self.__repository.task(running.task_id)
            if (
                current.authority_attempt_id
                == running.authority_attempt_id
                and current.revision != running.revision
            ):
                return self.__repository.project(project_id)
            raise
        self._record_author_evidence(imported, result.evidence_digest)
        if imported.status == TaskStatus.WAITING:
            return self._pause(
                self.__repository.project(project_id),
                ExecutiveState.WAITING_FOR_USAGE_RESET,
                "Provider usage is exhausted; automatic retry and fallback are disabled.",
            )
        if imported.status != TaskStatus.REVIEW_REQUIRED:
            return self._pause(
                self.__repository.project(project_id),
                ExecutiveState.BLOCKED,
                imported.result_disposition or "Provider execution failed.",
            )
        if imported.status == TaskStatus.CANCELED:
            return self.__repository.project(project_id)
        return self._review(project, charter, imported, author)

    def _validate_composition(self) -> None:
        try:
            composition = _registered_composition(self)
            if composition is None:
                raise PermissionError("Executive runtime has no trusted composition")
            repository = self.__repository
            gateway = self.__gateway
            if (
                repository is not composition.repository
                or gateway is not composition.gateway
            ):
                raise PermissionError(
                    "Executive runtime dependency identity changed"
                )
            if composition.production:
                if (
                    type(repository) is not ProductionExecutiveRepository
                    or type(gateway)
                    is not ProductionAuthorityBackedSpecialistGateway
                    or repository._production_runtime_identity()
                    != composition.repository_identity
                    or gateway._production_runtime_identity()
                    != composition.gateway_identity
                ):
                    raise PermissionError(
                        "production Executive composition is invalid"
                    )
            elif (
                type(repository) is not TestExecutiveRepository
                or type(gateway) is not SemanticAuthorityTestGateway
            ):
                raise PermissionError(
                    "test Executive composition is invalid"
                )
        except Exception as error:
            raise RuntimeError(
                "Executive runtime composition is invalid"
            ) from error

    def pause(self, project_id: str, reason: str) -> ProjectRecord:
        self._validate_composition()
        project = self.__repository.project(project_id)
        paused = transition_project(project, ExecutiveState.PAUSED, reason)
        self.__repository.save_project(paused, expected=project)
        return paused

    def resume(self, project_id: str) -> ProjectRecord:
        self._validate_composition()
        project = self.__repository.project(project_id)
        if project.state not in {
            ExecutiveState.PAUSED,
            ExecutiveState.BLOCKED,
            ExecutiveState.WAITING_FOR_PROVIDER,
            ExecutiveState.WAITING_FOR_CREDENTIAL,
            ExecutiveState.WAITING_FOR_EXTERNAL_SYSTEM,
            ExecutiveState.WAITING_FOR_USAGE_RESET,
        }:
            raise PermissionError("project is not resumable")
        charter = self._active_charter(project)
        approval = self._active_charter_approval(charter)
        if approval.revoked_at is not None:
            raise PermissionError(
                "delegation was revoked; new Founder approval is required"
            )
        resumed = replace(
            project,
            state=ExecutiveState.EXECUTING.value,
            pause_reason=None,
            updated_at=utc_now(),
        )
        self.__repository.save_project(resumed, expected=project)
        return resumed

    def revoke_delegation(self, project_id: str) -> ProjectRecord:
        self._validate_composition()
        project, attempt_ids = (
            self.__repository.revoke_project_launch_authority(project_id)
        )
        failures: list[str] = []
        try:
            authoritative_canceled = self.__gateway.revoke_project_launch(
                project_id, int(project.active_charter_revision or 0)
            )
        except (KeyError, PermissionError, RuntimeError, ValueError):
            authoritative_canceled = ()
            failures.append("project-launch-authorization")
        attempt_ids = tuple(
            dict.fromkeys((*attempt_ids, *authoritative_canceled))
        )
        for attempt_id in attempt_ids:
            try:
                self.__gateway.cancel(attempt_id)
            except (KeyError, PermissionError, RuntimeError):
                state = self.__gateway.attempt_state(attempt_id)
                if state not in {
                    "CANCELLED", "CANCELED", "COMPLETED", "FAILED"
                }:
                    failures.append(attempt_id)
        if failures:
            current = self.__repository.project(project_id)
            blocked = replace(
                current,
                pause_reason=(
                    "Founder revoked delegation; Authority cancellation "
                    "requires reconciliation."
                ),
                updated_at=utc_now(),
            )
            self.__repository.save_project(blocked, expected=current)
            return blocked
        return project

    def cancel(self, project_id: str) -> ProjectRecord:
        self._validate_composition()
        canceled, attempt_ids = self.__repository.cancel_project_execution(
            project_id
        )
        for attempt_id in attempt_ids:
            try:
                self.__gateway.cancel(attempt_id)
            except PermissionError:
                # A terminal Authority attempt is reconciled as late evidence;
                # local cancellation remains authoritative.
                continue
        return canceled

    def _review(
        self,
        project: ProjectRecord,
        charter: ProjectCharter,
        task: ExecutiveTask,
        author: SpecialistProfile,
    ) -> ProjectRecord:
        requires_independent = any(
            "independent" in item.casefold()
            for item in task.review_requirements
        )
        if not requires_independent:
            try:
                self.__repository.complete_automated_review(
                    task.task_id, expected_revision=task.revision
                )
            except PermissionError:
                return self.__repository.project(project.project_id)
            return project
        profiles = self.__gateway.specialists(charter)
        reviewer = self.selector.select(
            task,
            charter,
            profiles,
            author=author,
            independent=True,
        )
        if reviewer is None:
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                "A distinct Authority-qualified reviewer is unavailable.",
            )
        artifact_digest = task.artifact_digest
        if artifact_digest is None:
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                "Author artifact evidence is missing.",
            )
        try:
            self._recheck_artifact(task)
        except PermissionError:
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                "Author artifact changed after authenticated completion.",
            )
        review_task_id = (
            f"{task.task_id}:review:r{task.revision}:"
            f"{artifact_digest[:16]}"
        )
        plan = self.__gateway.prepare(
            task,
            charter,
            reviewer,
            task_id=review_task_id,
            role="reviewer",
            artifact_revision_digest=artifact_digest,
            review_instructions=(
                "Review the exact bound artifact and evidence revision.",
                "Return a structured semantic review disposition.",
                "Do not approve your own session or attempt.",
            ),
        )
        try:
            claimed = self.__repository.claim_review(
                task.task_id,
                expected_revision=task.revision,
                plan=asdict(plan),
            )
        except PermissionError:
            return self.__repository.project(project.project_id)
        try:
            self.__gateway.reserve(plan)
            self.__repository.transition_review(
                plan.authority_attempt_id,
                expected_state="LAUNCH_CLAIMED",
                target_state="EXECUTION_STARTED",
            )
            self._recheck_review(claimed, artifact_digest)
            result = self.__gateway.execute(plan)
            self._recheck_artifact(claimed)
        except BaseException as error:
            try:
                self.__repository.transition_review(
                    plan.authority_attempt_id,
                    expected_state="EXECUTION_STARTED",
                    target_state="UNCERTAIN",
                )
            except PermissionError:
                pass
            return self._pause(
                self.__repository.project(project.project_id),
                ExecutiveState.BLOCKED,
                f"Independent review is uncertain: {type(error).__name__}.",
            )
        disposition = self.__repository.accept_review_completion(
            task.task_id,
            expected_revision=claimed.revision,
            result=asdict(result),
        )
        if disposition.status == TaskStatus.CANCELED:
            return self.__repository.project(project.project_id)
        self.__repository.insert_memory(
            MemoryRecord(
                new_id("memory"),
                task.project_id,
                task.charter_revision,
                task.task_id,
                task.stage_id,
                "OUTCOME",
                "VERIFIED",
                "authenticated independent review",
                disposition.result_disposition or "",
                True,
                (
                    result.authority_attempt_id,
                    result.completion_digest,
                    result.structured_review_digest or "",
                ),
                None,
                utc_now(),
            )
        )
        if disposition.status in {
            TaskStatus.REPAIR_REQUIRED,
            TaskStatus.FAILED,
        }:
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                disposition.result_disposition
                or "Independent review requires repair.",
            )
        return project

    def _reconcile_author(
        self,
        project: ProjectRecord,
        charter: ProjectCharter,
        task: ExecutiveTask,
    ) -> ProjectRecord:
        if task.authority_attempt_id is None:
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                "In-flight task has no Authority attempt binding.",
            )
        record = self.__repository.execution_attempt(
            task.authority_attempt_id
        )
        plan = self.__gateway.plan_from_record(record)
        completion = self.__gateway.reconcile(plan)
        if completion is None:
            state = self.__gateway.attempt_state(plan.authority_attempt_id)
            if (
                state == "WAITING_FOR_USAGE_RESET"
                and task.status
                in {
                    TaskStatus.EXECUTION_STARTED,
                    TaskStatus.RUNNING,
                    TaskStatus.UNCERTAIN,
                }
            ):
                try:
                    self.__repository.mark_execution_waiting_for_usage(
                        task.task_id,
                        expected_revision=task.revision,
                        reason="Authority preserved a pre-provider usage pause.",
                    )
                except PermissionError:
                    pass
                return self._pause(
                    project,
                    ExecutiveState.WAITING_FOR_USAGE_RESET,
                    "Provider usage is exhausted; automatic retry and fallback are disabled.",
                )
            if (
                state == "RESERVED"
                and task.status
                in {
                    TaskStatus.LAUNCH_CLAIMED,
                    TaskStatus.EXECUTION_STARTED,
                    TaskStatus.UNCERTAIN,
                }
            ):
                current = task
                if current.status in {
                    TaskStatus.LAUNCH_CLAIMED,
                    TaskStatus.UNCERTAIN,
                }:
                    try:
                        current = self.__repository.transition_execution(
                            current.task_id,
                            expected_revision=current.revision,
                            expected_status=TaskStatus(current.status),
                            target_status=TaskStatus.EXECUTION_STARTED,
                            attempt_state="RESERVED",
                        )
                    except PermissionError:
                        return self.__repository.project(
                            project.project_id
                        )
                profiles = self.__gateway.specialists(charter)
                author = next(
                    (
                        item
                        for item in profiles
                        if item.provider_id == current.provider_id
                        and item.model_id == current.model_id
                        and item.session_id == current.session_id
                    ),
                    None,
                )
                if author is None:
                    return self._pause(
                        project,
                        ExecutiveState.BLOCKED,
                        "The claimed Authority provider is no longer qualified.",
                    )
                try:
                    self._recheck_launch(
                        current,
                        charter,
                        author,
                        allow_blocked_reconciliation=True,
                    )
                except PermissionError:
                    return self.__repository.project(project.project_id)
                try:
                    running = self.__repository.transition_execution(
                        current.task_id,
                        expected_revision=current.revision,
                        expected_status=TaskStatus.EXECUTION_STARTED,
                        target_status=TaskStatus.RUNNING,
                        attempt_state="EXECUTION_STARTED",
                    )
                except PermissionError:
                    return self.__repository.project(project.project_id)
                self._cross_budget_boundary(running)
                try:
                    completion = self.__gateway.execute(plan)
                except BaseException:
                    self.__repository.mark_execution_uncertain(
                        running.task_id,
                        expected_revision=running.revision,
                        reason="Authority reconciliation required after launch",
                    )
                    return self._pause(
                        project,
                        ExecutiveState.BLOCKED,
                        "Provider execution is uncertain and not retry-safe.",
                    )
                task = running
            else:
                if task.status != TaskStatus.UNCERTAIN:
                    try:
                        self.__repository.mark_execution_uncertain(
                            task.task_id,
                            expected_revision=task.revision,
                            reason="Authority completion is not yet authenticated",
                        )
                    except PermissionError:
                        pass
                return self._pause(
                    project,
                    ExecutiveState.BLOCKED,
                    "Claimed execution awaits Authority reconciliation; no retry was created.",
                )
        try:
            imported = self.__repository.accept_author_completion(
                task.task_id,
                expected_revision=task.revision,
                result=asdict(completion),
            )
        except PermissionError:
            current = self.__repository.task(task.task_id)
            if (
                current.authority_attempt_id == task.authority_attempt_id
                and current.revision != task.revision
            ):
                return self.__repository.project(project.project_id)
            raise
        if imported.status == TaskStatus.CANCELED:
            self._record_author_evidence(
                imported, completion.evidence_digest
            )
            return self.__repository.project(project.project_id)
        if imported.status != TaskStatus.REVIEW_REQUIRED:
            self._record_author_evidence(
                imported, completion.evidence_digest
            )
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                imported.result_disposition or "Provider execution failed.",
            )
        profiles = self.__gateway.specialists(charter)
        author = next(
            (
                item
                for item in profiles
                if item.provider_id == imported.provider_id
                and item.model_id == imported.model_id
                and item.session_id == imported.session_id
            ),
            None,
        )
        if author is None:
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                "Completed provider identity is no longer Authority-qualified.",
            )
        self._record_author_evidence(
            imported, completion.evidence_digest
        )
        return self._review(project, charter, imported, author)

    def _reconcile_review(
        self,
        project: ProjectRecord,
        charter: ProjectCharter,
        task: ExecutiveTask,
    ) -> ProjectRecord:
        if task.review_attempt_id is None:
            return project
        review = self.__repository.review(task.review_attempt_id)
        plan = self.__gateway.plan_from_record(review["plan"])
        completion = self.__gateway.reconcile(plan)
        if completion is None:
            state = self.__gateway.attempt_state(plan.authority_attempt_id)
            if state == "RESERVED" and review.get("state") in {
                "LAUNCH_CLAIMED",
                "UNCERTAIN",
            }:
                self.__repository.transition_review(
                    plan.authority_attempt_id,
                    expected_state=str(review["state"]),
                    target_state="EXECUTION_STARTED",
                )
                self._recheck_artifact(task)
                try:
                    completion = self.__gateway.execute(plan)
                except BaseException:
                    try:
                        self.__repository.transition_review(
                            plan.authority_attempt_id,
                            expected_state="EXECUTION_STARTED",
                            target_state="UNCERTAIN",
                        )
                    except PermissionError:
                        pass
                    return self._pause(
                        project,
                        ExecutiveState.BLOCKED,
                        "Independent review launch is uncertain and not retry-safe.",
                    )
            else:
                if review.get("state") != "UNCERTAIN":
                    try:
                        self.__repository.transition_review(
                            plan.authority_attempt_id,
                            expected_state=str(review["state"]),
                            target_state="UNCERTAIN",
                        )
                    except PermissionError:
                        pass
                return self._pause(
                    project,
                    ExecutiveState.BLOCKED,
                    "Independent review awaits Authority reconciliation.",
                )
        if completion is None:
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                "Independent review awaits Authority reconciliation.",
            )
        self._recheck_artifact(task)
        disposition = self.__repository.accept_review_completion(
            task.task_id,
            expected_revision=task.revision,
            result=asdict(completion),
        )
        if disposition.status != TaskStatus.COMPLETED:
            return self._pause(
                project,
                ExecutiveState.BLOCKED,
                disposition.result_disposition
                or "Independent review requires repair.",
            )
        return project

    def _recheck_artifact(self, task: ExecutiveTask) -> None:
        if task.authority_attempt_id is None or task.artifact_digest is None:
            raise PermissionError("task has no author artifact binding")
        attempt = self.__repository.execution_attempt(task.authority_attempt_id)
        identity = attempt.get("artifact_identity")
        files = attempt.get("artifact_files")
        if (
            not isinstance(identity, str)
            or not isinstance(files, list)
            or not all(isinstance(item, str) for item in files)
            or not isinstance(attempt.get("workspace"), str)
        ):
            raise PermissionError("author artifact manifest is unavailable")
        current = artifact_digest_from_files(
            identity,
            Path(str(attempt["workspace"])),
            tuple(files),
        )
        if current != task.artifact_digest:
            raise PermissionError("author artifact digest changed")

    def _recheck_launch(
        self,
        task: ExecutiveTask,
        charter: ProjectCharter,
        specialist: SpecialistProfile,
        *,
        allow_blocked_reconciliation: bool = False,
    ) -> None:
        project = self.__repository.project(task.project_id)
        durable_task = self.__repository.task(task.task_id)
        durable_charter = self._active_charter(project)
        approval = self._active_charter_approval(durable_charter)
        if (
            durable_task.revision != task.revision
            or durable_task.status != task.status
            or approval.revoked_at is not None
            or durable_charter.charter_id != charter.charter_id
        ):
            raise PermissionError("launch authority changed before execution")
        action = TrustedActionClassifier().classify(
            durable_task, durable_charter, specialist
        )
        authority_project = (
            replace(
                project,
                state=ExecutiveState.EXECUTING.value,
                pause_reason=None,
            )
            if allow_blocked_reconciliation
            and project.state == ExecutiveState.BLOCKED
            else project
        )
        decision = self.evaluator.evaluate(
            authority_project,
            durable_charter,
            action,
            tuple(
                self.__repository.approvals(
                    project.project_id, durable_charter.revision
                )
            ),
        )
        if decision.outcome not in {"ALLOWED", "ALLOWED_WITHIN_LIMIT"}:
            raise PermissionError("launch authority was revoked or changed")

    def _recheck_review(
        self,
        task: ExecutiveTask,
        artifact_digest: str,
    ) -> None:
        project = self.__repository.project(task.project_id)
        current = self.__repository.task(task.task_id)
        charter = self._active_charter(project)
        approval = self._active_charter_approval(charter)
        if (
            project.state == ExecutiveState.CANCELED
            or current.status != TaskStatus.REVIEW_REQUIRED
            or current.artifact_digest != artifact_digest
            or approval.revoked_at is not None
        ):
            raise PermissionError("review authority changed before execution")

    def _active_charter(self, project: ProjectRecord) -> ProjectCharter:
        if project.active_charter_id is None:
            raise PermissionError("project has no active charter")
        charter = self.__repository.charter(project.active_charter_id)
        if (
            charter.status != "ACTIVE"
            or charter.revision != project.active_charter_revision
        ):
            raise PermissionError("active charter binding is invalid")
        return charter

    def _active_charter_approval(
        self, charter: ProjectCharter
    ) -> ApprovalRecord:
        approval_id = charter.founder_approval_record_id
        if approval_id is None:
            raise PermissionError("active charter approval is missing")
        approvals = self.__repository.approvals(
            charter.project_id, charter.revision
        )
        approval = next(
            (
                item
                for item in approvals
                if item.approval_id == approval_id
            ),
            None,
        )
        if approval is None:
            raise PermissionError("active charter approval is unavailable")
        return approval

    def _record_author_evidence(
        self,
        task: ExecutiveTask,
        completion_digest: str,
    ) -> None:
        memory_id = (
            "memory:authority-completion:"
            f"{task.authority_attempt_id or task.task_id}"
        )
        if self.__repository.memory(memory_id) is not None:
            return
        record = MemoryRecord(
                memory_id,
                task.project_id,
                task.charter_revision,
                task.task_id,
                task.stage_id,
                "EVIDENCE",
                "VERIFIED",
                "authenticated Authority completion",
                "KeeperAuthority completed the bound provider attempt.",
                True,
                (
                    task.authority_attempt_id or "",
                    completion_digest,
                    task.artifact_digest or "",
                ),
                None,
                utc_now(),
            )
        try:
            self.__repository.insert_memory(record)
        except PermissionError:
            if (
                self.__repository.memory(memory_id)
                is None
            ):
                raise

    def _cross_budget_boundary(self, task: ExecutiveTask) -> None:
        if task.authority_attempt_id is None:
            raise PermissionError("execution attempt binding is missing")
        attempt = self.__repository.execution_attempt(
            task.authority_attempt_id
        )
        reservation_id = attempt.get("budget_reservation_id")
        if isinstance(reservation_id, str):
            self.__repository.mark_budget_boundary(reservation_id)

    @staticmethod
    def _next_candidate(
        tasks: tuple[ExecutiveTask, ...],
    ) -> ExecutiveTask | None:
        completed = {
            item.task_id
            for item in tasks
            if item.status == TaskStatus.COMPLETED
        }
        for task in tasks:
            if task.status in {
                TaskStatus.PROPOSED,
                TaskStatus.READY,
                TaskStatus.REPAIR_REQUIRED,
                TaskStatus.BLOCKED,
                TaskStatus.WAITING,
            } and set(task.dependencies).issubset(completed):
                return task
        return None

    def _pause(
        self,
        project: ProjectRecord,
        state: ExecutiveState,
        reason: str,
    ) -> ProjectRecord:
        if project.state == ExecutiveState.CANCELED:
            return project
        try:
            paused = transition_project(project, state, reason)
        except PermissionError:
            paused = replace(
                project,
                state=state.value,
                pause_reason=reason,
                updated_at=utc_now(),
            )
        try:
            self.__repository.save_project(paused, expected=project)
        except PermissionError:
            return self.__repository.project(project.project_id)
        return paused
