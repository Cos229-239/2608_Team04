from __future__ import annotations

import builtins
import hashlib
import json
import math
import os
import sqlite3
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar, cast

from keeper.app.storage import KeeperStore
from keeper.evidence_input import validate_review_input_declaration
from keeper.pass_b.enums import (
    AssignmentRole,
    AssignmentState,
    AttemptState,
    CostMode,
    EvidenceReferenceState,
    EvidenceState,
    HealthState,
    ProviderSessionState,
    ReservationMode,
    ReservationState,
    ReviewState,
    WorkItemState,
    WorkflowState,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    AuthorityReservationReconciliationRecord,
    DeliveredInputRecord,
    EvidenceBundleRecord,
    EvidenceReferenceRecord,
    ExecutionProfileRecord,
    PassBRecord,
    PauseReasonRecord,
    PrelaunchAbandonmentRecord,
    ProviderAccountRecord,
    ProviderRecord,
    ProviderSelectionRecord,
    ProviderSessionRecord,
    ResumeCheckpointRecord,
    ReviewRecord,
    RepositorySnapshotRecord,
    UncertaintyReconciliationRecord,
    UsagePoolRecord,
    WorkflowRecord,
    WorkItemRecord,
    WorkspaceReservationRecord,
    WriteReservationRecord,
)
from keeper.pass_b.providers import (
    ProviderSelectionPolicy,
    provider_selection_policy_digest,
    validate_provider_execution_declarations,
)

R = TypeVar("R", bound=PassBRecord)
PASS_B_SCHEMA_VERSION = 6


class PassBRepository:
    """Transactional Pass B records stored inside the existing Keeper database."""

    def __init__(self, store: KeeperStore) -> None:
        self.store = store
        self.migrate()

    def migrate(self) -> None:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS pass_b_schema_migrations ("
                "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            current = int(
                connection.execute(
                    "SELECT COALESCE(MAX(version),0) FROM pass_b_schema_migrations"
                ).fetchone()[0]
            )
            if current > PASS_B_SCHEMA_VERSION:
                raise RuntimeError("Pass B schema is newer than this application")
            if current < 1:
                connection.execute(
                    "CREATE TABLE pass_b_records ("
                    "kind TEXT NOT NULL, id TEXT NOT NULL, project_id TEXT, "
                    "state TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), "
                    "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
                    "payload TEXT NOT NULL, payload_hash TEXT NOT NULL, "
                    "PRIMARY KEY(kind,id))"
                )
                connection.execute(
                    "CREATE INDEX ix_pass_b_records_project "
                    "ON pass_b_records(project_id,kind,updated_at)"
                )
                connection.execute(
                    "CREATE TABLE pass_b_workspace_claims ("
                    "reservation_id TEXT PRIMARY KEY, canonical_path TEXT NOT NULL, "
                    "assignment_id TEXT NOT NULL, "
                    "mode TEXT NOT NULL CHECK(mode IN ('READ_ONLY','WRITE')), "
                    "state TEXT NOT NULL CHECK(state IN "
                    "('ACTIVE','RELEASED','STALE','UNCERTAIN')), "
                    "lease_expires_at TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE INDEX ix_pass_b_workspace_claim_path "
                    "ON pass_b_workspace_claims(canonical_path,state)"
                )
                connection.execute(
                    "CREATE TABLE pass_b_write_claims ("
                    "scope_key TEXT PRIMARY KEY, reservation_id TEXT NOT NULL, "
                    "assignment_id TEXT NOT NULL, "
                    "state TEXT NOT NULL CHECK(state IN "
                    "('ACTIVE','RELEASED','STALE','UNCERTAIN')), "
                    "lease_expires_at TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE pass_b_usage_reservations ("
                    "reservation_id TEXT PRIMARY KEY, pool_id TEXT NOT NULL, "
                    "assignment_id TEXT NOT NULL, amount REAL NOT NULL CHECK(amount>=0), "
                    "state TEXT NOT NULL CHECK(state IN "
                    "('ACTIVE','CONSUMED','RELEASED')), "
                    "reserved_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE UNIQUE INDEX ux_pass_b_usage_assignment_active "
                    "ON pass_b_usage_reservations(assignment_id) "
                    "WHERE state='ACTIVE'"
                )
                connection.execute(
                    "CREATE TABLE pass_b_launch_claims ("
                    "attempt_id TEXT PRIMARY KEY, assignment_id TEXT NOT NULL, "
                    "launch_token TEXT NOT NULL UNIQUE, "
                    "state TEXT NOT NULL CHECK(state IN "
                    "('RESERVED','LAUNCH_CLAIMED','RUNNING','COMPLETED',"
                    "'CANCELED','FAILED','UNCERTAIN')), "
                    "updated_at TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE UNIQUE INDEX ux_pass_b_assignment_active_launch "
                    "ON pass_b_launch_claims(assignment_id) "
                    "WHERE state IN "
                    "('RESERVED','LAUNCH_CLAIMED','RUNNING','COMPLETED','UNCERTAIN')"
                )
                connection.execute(
                    "INSERT INTO pass_b_schema_migrations(version,applied_at) "
                    "VALUES(1,?)",
                    (_now(),),
                )
            if current < 2:
                connection.execute(
                    "ALTER TABLE pass_b_usage_reservations "
                    "ADD COLUMN observation_generation INTEGER NOT NULL DEFAULT 1"
                )
                connection.execute(
                    "ALTER TABLE pass_b_launch_claims "
                    "ADD COLUMN authority_attempt_id TEXT NOT NULL DEFAULT ''"
                )
                connection.execute(
                    "UPDATE pass_b_launch_claims "
                    "SET authority_attempt_id='legacy:' || attempt_id "
                    "WHERE authority_attempt_id=''"
                )
                connection.execute(
                    "CREATE UNIQUE INDEX ux_pass_b_authority_attempt "
                    "ON pass_b_launch_claims(authority_attempt_id)"
                )
                connection.execute(
                    "INSERT INTO pass_b_schema_migrations(version,applied_at) "
                    "VALUES(2,?)",
                    (_now(),),
                )
            if current < 3:
                connection.execute(
                    "CREATE TABLE pass_b_usage_reset_observations ("
                    "observation_id TEXT PRIMARY KEY, "
                    "pool_id TEXT NOT NULL, "
                    "observation_generation INTEGER NOT NULL, "
                    "observation_digest TEXT NOT NULL, "
                    "observed_at TEXT NOT NULL, "
                    "UNIQUE(pool_id,observation_generation))"
                )
                connection.execute(
                    "INSERT INTO pass_b_schema_migrations(version,applied_at) "
                    "VALUES(3,?)",
                    (_now(),),
                )

            if current < 4:
                connection.execute(
                    "INSERT INTO pass_b_schema_migrations(version,applied_at) "
                    "VALUES(4,?)",
                    (_now(),),
                )
            if current < 5:
                connection.execute(
                    "INSERT INTO pass_b_schema_migrations(version,applied_at) "
                    "VALUES(5,?)",
                    (_now(),),
                )
            if current < 6:
                connection.execute(
                    "INSERT INTO pass_b_schema_migrations(version,applied_at) "
                    "VALUES(6,?)",
                    (_now(),),
                )

    def insert(self, record: PassBRecord) -> None:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._insert(connection, record)

    def insert_review_with_reference(
        self,
        review: ReviewRecord,
        reference: EvidenceReferenceRecord,
        *,
        consumed_at: str,
    ) -> EvidenceReferenceRecord:
        return self.insert_review_with_references(
            review,
            (reference,),
            consumed_at=consumed_at,
        )[0]

    def insert_review_with_references(
        self,
        review: ReviewRecord,
        references: tuple[EvidenceReferenceRecord, ...],
        *,
        consumed_at: str,
    ) -> tuple[EvidenceReferenceRecord, ...]:
        if not references:
            raise PermissionError("review requires its delivered evidence set")
        consumed_records: list[EvidenceReferenceRecord] = []
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if (
                tuple(item.evidence_reference_id for item in references)
                != review.consumed_evidence_reference_ids
                or tuple(item.revision + 1 for item in references)
                != review.consumed_evidence_reference_revisions
            ):
                raise PermissionError("review consumed-reference set is not exact")
            for reference in references:
                current = self._get(
                    connection,
                    EvidenceReferenceRecord,
                    reference.evidence_reference_id,
                )
                if (
                    current.revision != reference.revision
                    or current.state != EvidenceReferenceState.VALIDATED
                    or current.consumed_by_review_id is not None
                    or current.assignment_id != review.reviewer_assignment_id
                    or current.source_evidence_bundle_id
                    != review.producer_evidence_bundle_id
                ):
                    raise PermissionError(
                        "evidence reference cannot be consumed for review"
                    )
                consumed = replace(
                    current,
                    consumed_by_review_id=review.review_id,
                    consumed_at=consumed_at,
                    updated_at=consumed_at,
                    revision=current.revision + 1,
                )
                self._replace(connection, consumed, current.revision)
                consumed_records.append(consumed)
            self._insert(connection, review)
        return tuple(consumed_records)

    def replace(self, record: R, *, expected_revision: int) -> R:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._replace(connection, record, expected_revision)
        return record

    def get(self, record_type: type[R], record_id: str) -> R:
        with self.store.connect() as connection:
            return self._get(connection, record_type, record_id)

    def optional(self, record_type: type[R], record_id: str) -> R | None:
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND id=?",
                (record_type.KIND, record_id),
            ).fetchone()
            if row is None:
                return None
            return self._decode(record_type, row)

    def list(
        self, record_type: type[R], *, project_id: str | None = None
    ) -> list[R]:
        query = (
            "SELECT payload,payload_hash FROM pass_b_records WHERE kind=?"
        )
        parameters: tuple[object, ...] = (record_type.KIND,)
        if project_id is not None:
            query += " AND project_id=?"
            parameters += (project_id,)
        query += " ORDER BY created_at,id"
        with self.store.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._decode(record_type, row) for row in rows]

    def insert_workflow(self, record: WorkflowRecord) -> None:
        if record.state != WorkflowState.ACTIVE:
            raise ValueError("new workflows must begin active")
        self.insert(record)

    def insert_workflow_plan(
        self,
        workflow: WorkflowRecord,
        work_items: tuple[WorkItemRecord, ...],
    ) -> bool:
        """Commit one charter-derived workflow and all of its work atomically."""

        if workflow.state != WorkflowState.ACTIVE or not work_items:
            raise ValueError("workflow plan must begin active with work items")
        by_id = {item.work_item_id: item for item in work_items}
        if len(by_id) != len(work_items):
            raise ValueError("workflow plan work-item identities must be unique")
        positions = {
            item.work_item_id: index
            for index, item in enumerate(work_items)
        }
        for index, item in enumerate(work_items):
            _validate_workflow_work_item(workflow, item)
            if item.state != WorkItemState.READY:
                raise ValueError("workflow plan work items must begin ready")
            if any(
                dependency_id not in by_id
                or by_id[dependency_id].workflow_id != workflow.workflow_id
                or positions[dependency_id] >= index
                for dependency_id in item.dependencies
            ):
                raise PermissionError(
                    "workflow plan dependency is missing, cyclic, or cross-plan"
                )
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND project_id=?",
                (WorkflowRecord.KIND, workflow.project_id),
            ).fetchall()
            if any(
                current.charter_id == workflow.charter_id
                and current.charter_revision == workflow.charter_revision
                for current in (
                    self._decode(WorkflowRecord, row) for row in rows
                )
            ):
                return False
            self._insert(connection, workflow)
            for item in work_items:
                self._insert(connection, item)
        return True

    def insert_work_item_bound(self, record: WorkItemRecord) -> None:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            workflow = self._get(
                connection, WorkflowRecord, record.workflow_id
            )
            _validate_workflow_work_item(workflow, record)
            for dependency_id in record.dependencies:
                dependency = self._get(
                    connection, WorkItemRecord, dependency_id
                )
                if (
                    dependency.workflow_id != workflow.workflow_id
                    or dependency.project_id != workflow.project_id
                    or dependency.charter_id != workflow.charter_id
                    or dependency.charter_revision != workflow.charter_revision
                ):
                    raise PermissionError(
                        "work item dependency crosses its durable workflow"
                    )
            self._insert(connection, record)

    def insert_assignment_bound(
        self,
        record: AssignmentRecord,
        supplied_work_item: WorkItemRecord,
    ) -> None:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            work_item = self._get(
                connection, WorkItemRecord, record.work_item_id
            )
            if work_item != supplied_work_item:
                raise PermissionError(
                    "assignment work item differs from durable state"
                )
            workflow = self._get(
                connection, WorkflowRecord, record.workflow_id
            )
            _validate_assignment_binding(workflow, work_item, record)
            self._insert(connection, record)

    def insert_execution_profile_bound(
        self,
        record: ExecutionProfileRecord,
        supplied_work_item: WorkItemRecord,
    ) -> bool:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            work_item = self._get(
                connection, WorkItemRecord, record.work_item_id
            )
            if work_item != supplied_work_item:
                raise PermissionError(
                    "execution profile work item differs from durable state"
                )
            workflow = self._get(
                connection, WorkflowRecord, record.workflow_id
            )
            _validate_execution_profile(workflow, work_item, record)
            rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND project_id=?",
                (ExecutionProfileRecord.KIND, record.project_id),
            ).fetchall()
            existing = [
                self._decode(ExecutionProfileRecord, row)
                for row in rows
                if self._decode(
                    ExecutionProfileRecord, row
                ).work_item_id
                == record.work_item_id
            ]
            if existing:
                return False
            self._insert(connection, record)
        return True

    def claim_prepared_assignment(
        self,
        *,
        profile: ExecutionProfileRecord,
        selection: ProviderSelectionRecord,
        assignment: AssignmentRecord,
        supplied_work_item: WorkItemRecord,
    ) -> bool:
        """Atomically claim one dependency-ready work item without launching."""

        if assignment.state != AssignmentState.READY:
            raise ValueError("prepared assignment must begin ready")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            durable_profile = self._get(
                connection,
                ExecutionProfileRecord,
                profile.execution_profile_id,
            )
            work_item = self._get(
                connection, WorkItemRecord, profile.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, profile.workflow_id
            )
            if durable_profile != profile:
                raise PermissionError(
                    "prepared assignment differs from durable profile"
                )
            if work_item != supplied_work_item:
                rows = connection.execute(
                    "SELECT payload,payload_hash FROM pass_b_records "
                    "WHERE kind=? AND project_id=?",
                    (AssignmentRecord.KIND, assignment.project_id),
                ).fetchall()
                if any(
                    (current := self._decode(AssignmentRecord, row)).work_item_id
                    == work_item.work_item_id
                    and current.state != AssignmentState.CANCELED
                    for row in rows
                ):
                    return False
                raise PermissionError(
                    "prepared assignment work item changed without a winner"
                )
            _validate_execution_profile(workflow, work_item, profile)
            _validate_assignment_binding(workflow, work_item, assignment)
            if (
                work_item.state != WorkItemState.READY
                or selection.execution_profile_id
                != profile.execution_profile_id
                or selection.assignment_id != assignment.assignment_id
                or selection.project_id != profile.project_id
                or selection.charter_id != profile.charter_id
                or selection.charter_revision != profile.charter_revision
                or selection.workflow_id != profile.workflow_id
                or selection.work_item_id != profile.work_item_id
                or selection.role != profile.role
                or selection.provider_id != assignment.provider_id
                or selection.account_id != assignment.account_id
                or selection.session_id != assignment.session_id
                or selection.model_id != assignment.model_id
                or selection.effort_level != profile.effort_level
                or selection.privacy_classification
                != profile.privacy_classification
                or assignment.workspace_id != profile.workspace_id
                or assignment.expected_evidence != profile.expected_evidence
                or assignment.authority_envelope_digest
                != profile.authority_envelope_digest
            ):
                raise PermissionError("prepared assignment binding is not exact")
            for dependency_id in work_item.dependencies:
                dependency = self._get(
                    connection, WorkItemRecord, dependency_id
                )
                if (
                    dependency.workflow_id != workflow.workflow_id
                    or dependency.project_id != workflow.project_id
                    or dependency.charter_id != workflow.charter_id
                    or dependency.charter_revision
                    != workflow.charter_revision
                    or dependency.state != WorkItemState.COMPLETED
                ):
                    raise PermissionError(
                        "work item dependencies are not durably complete"
                    )
            rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND project_id=?",
                (AssignmentRecord.KIND, assignment.project_id),
            ).fetchall()
            if any(
                (current := self._decode(AssignmentRecord, row)).work_item_id
                == work_item.work_item_id
                and current.state != AssignmentState.CANCELED
                for row in rows
            ):
                return False
            provider = self._get(
                connection, ProviderRecord, selection.provider_id
            )
            account = self._get(
                connection, ProviderAccountRecord, selection.account_id
            )
            session = self._get(
                connection, ProviderSessionRecord, selection.session_id
            )
            capabilities = {
                item.casefold() for item in provider.capabilities
            }
            expected_exclusions: set[str] = set()
            if profile.review_of_assignment_id:
                producer = self._get(
                    connection,
                    AssignmentRecord,
                    profile.review_of_assignment_id,
                )
                expected_exclusions.update(
                    {
                        producer.independence_key,
                        producer.provider_id,
                        f"provider:{producer.provider_id}",
                        producer.account_id,
                        f"account:{producer.account_id}",
                        producer.session_id,
                        f"session:{producer.session_id}",
                    }
                )
            expected_policy_digest = provider_selection_policy_digest(
                profile.role,
                ProviderSelectionPolicy(
                    allowed_provider_ids=frozenset(
                        selection.allowed_provider_ids
                    ),
                    required_capabilities=frozenset(
                        selection.required_capabilities
                    ),
                    allow_substitution=profile.allow_substitution,
                    allow_paid=False,
                    privacy_classification=profile.privacy_classification,
                    excluded_independence_keys=frozenset(
                        selection.excluded_independence_keys
                    ),
                    preferred_provider_id=profile.preferred_provider_id,
                    project_type=profile.project_type,
                    effort_level=profile.effort_level,
                ),
            )
            validate_provider_execution_declarations(
                provider,
                project_type=profile.project_type,
                effort_level=profile.effort_level,
                checked_at=assignment.created_at,
            )
            if (
                account.provider_id != provider.provider_id
                or selection.provider_id
                not in selection.allowed_provider_ids
                or set(selection.required_capabilities)
                != set(profile.required_capabilities)
                or set(selection.excluded_independence_keys)
                != expected_exclusions
                or selection.policy_digest != expected_policy_digest
                or session.provider_id != provider.provider_id
                or session.account_id != account.account_id
                or session.model_id != selection.model_id
                or account.usage_pool_id != selection.usage_pool_id
                or account.cost_mode != selection.cost_mode
                or account.privacy_classification
                != selection.privacy_classification
                or provider.cost_mode == CostMode.PAID
                or account.cost_mode == CostMode.PAID
                or profile.allow_paid
                or not provider.authentication_ready
                or not account.authentication_ready
                or not account.enabled
                or provider.health != HealthState.READY
                or session.state != ProviderSessionState.READY
                or session.active_assignments >= session.concurrency_limit
                or (
                    profile.role.casefold() not in capabilities
                    and "all-roles" not in capabilities
                )
                or not {
                    item.casefold()
                    for item in profile.required_capabilities
                }.issubset(capabilities)
            ):
                raise PermissionError(
                    "selected provider session no longer satisfies policy"
                )
            self._insert(connection, assignment)
            self._insert(connection, selection)
            self._replace(
                connection,
                replace(
                    work_item,
                    state=WorkItemState.ASSIGNED,
                    updated_at=assignment.created_at,
                    revision=work_item.revision + 1,
                ),
                work_item.revision,
            )
        return True

    def claim_repair_assignment(
        self,
        *,
        review: ReviewRecord,
        original: AssignmentRecord,
        work_item: WorkItemRecord,
        profile: ExecutionProfileRecord,
        selection: ProviderSelectionRecord,
        repair: AssignmentRecord,
    ) -> bool:
        """Atomically bind one fresh production-runnable repair assignment."""

        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            durable_review = self._get(connection, ReviewRecord, review.review_id)
            durable_original = self._get(
                connection, AssignmentRecord, original.assignment_id
            )
            durable_item = self._get(
                connection, WorkItemRecord, work_item.work_item_id
            )
            durable_profile = self._get(
                connection, ExecutionProfileRecord, profile.execution_profile_id
            )
            if any(
                current != supplied
                for current, supplied in (
                    (durable_review, review),
                    (durable_original, original),
                    (durable_item, work_item),
                    (durable_profile, profile),
                )
            ):
                raise PermissionError("repair claim differs from durable state")
            rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND project_id=?",
                (AssignmentRecord.KIND, original.project_id),
            ).fetchall()
            existing = [
                self._decode(AssignmentRecord, row)
                for row in rows
                if self._decode(AssignmentRecord, row).usage_policy.get(
                    "repair_review_id"
                )
                == review.review_id
            ]
            if existing:
                return False
            workflow = self._get(
                connection, WorkflowRecord, original.workflow_id
            )
            _validate_execution_profile(workflow, work_item, profile)
            _validate_assignment_binding(workflow, work_item, repair)
            provider = self._get(connection, ProviderRecord, repair.provider_id)
            account = self._get(
                connection, ProviderAccountRecord, repair.account_id
            )
            session = self._get(
                connection, ProviderSessionRecord, repair.session_id
            )
            if (
                review.state != ReviewState.REPAIR_REQUIRED
                or review.assignment_id != original.assignment_id
                or original.state != AssignmentState.REPAIR_REQUIRED
                or work_item.state != WorkItemState.REPAIR_REQUIRED
                or repair.state != AssignmentState.READY
                or repair.assignment_id == original.assignment_id
                or repair.usage_policy.get("repair_of_assignment_id")
                != original.assignment_id
                or repair.usage_policy.get("repair_review_id") != review.review_id
                or repair.usage_policy.get("execution_profile_id")
                != profile.execution_profile_id
                or repair.usage_policy.get("provider_selection_id")
                != selection.provider_selection_id
                or selection.assignment_id != repair.assignment_id
                or selection.execution_profile_id != profile.execution_profile_id
                or selection.provider_id != repair.provider_id
                or selection.account_id != repair.account_id
                or selection.session_id != repair.session_id
                or selection.model_id != repair.model_id
                or provider.health != HealthState.READY
                or provider.cost_mode == CostMode.PAID
                or not provider.authentication_ready
                or account.provider_id != provider.provider_id
                or account.cost_mode == CostMode.PAID
                or not account.authentication_ready
                or not account.enabled
                or session.provider_id != provider.provider_id
                or session.account_id != account.account_id
                or session.model_id != repair.model_id
                or session.state != ProviderSessionState.READY
                or session.active_assignments >= session.concurrency_limit
            ):
                raise PermissionError("repair assignment binding is invalid")
            self._insert(connection, repair)
            self._insert(connection, selection)
        return True

    def assignment_launch_binding(
        self, assignment_id: str
    ) -> tuple[WorkflowRecord, WorkItemRecord, AssignmentRecord]:
        with self.store.connect() as connection:
            assignment = self._get(
                connection, AssignmentRecord, assignment_id
            )
            work_item = self._get(
                connection, WorkItemRecord, assignment.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, assignment.workflow_id
            )
            _validate_assignment_binding(workflow, work_item, assignment)
            return workflow, work_item, assignment

    def reconcile_workflow_completion(
        self,
        workflow_id: str,
        *,
        completed_at: str,
    ) -> WorkflowRecord:
        """Atomically terminalize an active workflow whose work is complete."""

        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            workflow = self._get(
                connection, WorkflowRecord, workflow_id
            )
            work_items = self._workflow_items(connection, workflow)
            all_completed = all(
                item.state == WorkItemState.COMPLETED
                for item in work_items
            )
            if workflow.state == WorkflowState.COMPLETED:
                if not all_completed:
                    raise RuntimeError(
                        "completed workflow contains incomplete durable work"
                    )
                return workflow
            if (
                workflow.state != WorkflowState.ACTIVE
                or not all_completed
            ):
                raise PermissionError(
                    "workflow cannot complete before all durable work"
                )
            updated = replace(
                workflow,
                state=WorkflowState.COMPLETED,
                updated_at=completed_at,
                revision=workflow.revision + 1,
            )
            self._replace(connection, updated, workflow.revision)
        return updated

    def reserve_workspace(self, record: WorkspaceReservationRecord) -> None:
        if record.state != ReservationState.ACTIVE:
            raise ValueError("new workspace reservations must be active")
        canonical_path = canonical_workspace_path(Path(record.canonical_path))
        if canonical_path != record.canonical_path:
            raise PermissionError("workspace reservation path is not canonical")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            assignment = self._get(
                connection, AssignmentRecord, record.assignment_id
            )
            if assignment.workspace_id != record.workspace_id:
                raise PermissionError("workspace identity differs from assignment")
            profile_id = assignment.usage_policy.get(
                "execution_profile_id"
            )
            if isinstance(profile_id, str):
                profile = self._get(
                    connection, ExecutionProfileRecord, profile_id
                )
                if (
                    profile.project_id != assignment.project_id
                    or profile.charter_id != assignment.charter_id
                    or profile.charter_revision
                    != assignment.charter_revision
                    or profile.workflow_id != assignment.workflow_id
                    or profile.work_item_id != assignment.work_item_id
                    or profile.workspace_id != assignment.workspace_id
                    or profile.canonical_workspace_path
                    != record.canonical_path
                    or profile.expected_evidence
                    != assignment.expected_evidence
                ):
                    raise PermissionError(
                        "workspace differs from durable execution profile"
                    )
            if assignment.read_only and record.mode != ReservationMode.READ_ONLY:
                raise PermissionError("read-only assignment cannot reserve a writer")
            claims = connection.execute(
                "SELECT canonical_path,mode,state "
                "FROM pass_b_workspace_claims "
                "WHERE state IN ('ACTIVE','UNCERTAIN')"
            ).fetchall()
            if any(
                _path_overlap(
                    record.canonical_path, str(item["canonical_path"])
                )
                and (
                    record.mode == ReservationMode.WRITE
                    or str(item["mode"]) == ReservationMode.WRITE
                )
                for item in claims
            ):
                raise PermissionError("workspace already has an incompatible owner")
            self._insert(connection, record)
            connection.execute(
                "INSERT INTO pass_b_workspace_claims VALUES(?,?,?,?,?,?)",
                (
                    record.workspace_reservation_id,
                    record.canonical_path,
                    record.assignment_id,
                    record.mode,
                    record.state,
                    record.lease_expires_at,
                ),
            )

    def reserve_write(self, record: WriteReservationRecord) -> None:
        if record.state != ReservationState.ACTIVE:
            raise ValueError("new write reservations must be active")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            assignment = self._get(
                connection, AssignmentRecord, record.assignment_id
            )
            workspace = self._get(
                connection,
                WorkspaceReservationRecord,
                record.workspace_reservation_id,
            )
            if (
                canonical_workspace_path(Path(workspace.canonical_path))
                != workspace.canonical_path
            ):
                raise PermissionError("writer workspace path is not canonical")
            if tuple(
                canonical_scope(workspace.canonical_path, scope)
                for scope in record.scope
            ) != record.scope_keys:
                raise PermissionError("write reservation scope is not canonical")
            profile_id = assignment.usage_policy.get(
                "execution_profile_id"
            )
            if isinstance(profile_id, str):
                profile = self._get(
                    connection, ExecutionProfileRecord, profile_id
                )
                if (
                    profile.workspace_id != workspace.workspace_id
                    or profile.canonical_workspace_path
                    != workspace.canonical_path
                    or profile.write_scopes != record.scope
                    or profile.write_scope_keys != record.scope_keys
                ):
                    raise PermissionError(
                        "write scope differs from durable execution profile"
                    )
            if (
                assignment.read_only
                or workspace.mode != ReservationMode.WRITE
                or workspace.state != ReservationState.ACTIVE
                or workspace.assignment_id != assignment.assignment_id
            ):
                raise PermissionError("assignment has no active writer workspace")
            active = connection.execute(
                "SELECT scope_key FROM pass_b_write_claims "
                "WHERE state IN ('ACTIVE','UNCERTAIN')"
            ).fetchall()
            existing = [str(row["scope_key"]) for row in active]
            if any(
                _scope_overlap(candidate, current)
                for candidate in record.scope_keys
                for current in existing
            ):
                raise PermissionError("protected write scope is already reserved")
            self._insert(connection, record)
            connection.executemany(
                "INSERT OR REPLACE INTO pass_b_write_claims "
                "VALUES(?,?,?,?,?)",
                [
                    (
                        key,
                        record.workspace_reservation_id,
                        record.assignment_id,
                        record.state,
                        record.lease_expires_at,
                    )
                    for key in record.scope_keys
                ],
            )

    def renew_workspace(
        self,
        reservation_id: str,
        owner_token: str,
        lease_expires_at: str,
        updated_at: str,
    ) -> WorkspaceReservationRecord:
        _parse_time(lease_expires_at)
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get(
                connection, WorkspaceReservationRecord, reservation_id
            )
            if (
                canonical_workspace_path(Path(current.canonical_path))
                != current.canonical_path
            ):
                raise PermissionError("workspace lease path is no longer safe")
            if (
                current.owner_token != owner_token
                or current.state != ReservationState.ACTIVE
            ):
                raise PermissionError("workspace lease owner or state changed")
            updated = replace(
                current,
                lease_expires_at=lease_expires_at,
                updated_at=updated_at,
                revision=current.revision + 1,
            )
            self._replace(connection, updated, current.revision)
            for write in self._active_writes(connection, reservation_id):
                self._replace(
                    connection,
                    replace(
                        write,
                        lease_expires_at=lease_expires_at,
                        updated_at=updated_at,
                        revision=write.revision + 1,
                    ),
                    write.revision,
                )
            connection.execute(
                "UPDATE pass_b_write_claims SET lease_expires_at=? "
                "WHERE reservation_id=? AND state='ACTIVE'",
                (lease_expires_at, reservation_id),
            )
            connection.execute(
                "UPDATE pass_b_workspace_claims SET lease_expires_at=? "
                "WHERE reservation_id=? AND state='ACTIVE'",
                (lease_expires_at, reservation_id),
            )
        return updated

    def release_workspace(
        self, reservation_id: str, owner_token: str, updated_at: str
    ) -> WorkspaceReservationRecord:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get(
                connection, WorkspaceReservationRecord, reservation_id
            )
            if (
                canonical_workspace_path(Path(current.canonical_path))
                != current.canonical_path
            ):
                raise PermissionError("workspace release path is no longer safe")
            assignment = self._get(
                connection, AssignmentRecord, current.assignment_id
            )
            if current.owner_token != owner_token:
                raise PermissionError("workspace lease owner changed")
            live_launch = connection.execute(
                "SELECT 1 FROM pass_b_launch_claims "
                "WHERE assignment_id=? AND state IN "
                "('RESERVED','LAUNCH_CLAIMED','RUNNING','UNCERTAIN')",
                (assignment.assignment_id,),
            ).fetchone()
            if assignment.state in {
                AssignmentState.LAUNCH_CLAIMED,
                AssignmentState.RUNNING,
                AssignmentState.UNCERTAIN,
            } or live_launch is not None:
                raise PermissionError("active or uncertain workspace cannot be released")
            updated = replace(
                current,
                state=ReservationState.RELEASED,
                updated_at=updated_at,
                revision=current.revision + 1,
            )
            self._replace(connection, updated, current.revision)
            for write in self._active_writes(connection, reservation_id):
                self._replace(
                    connection,
                    replace(
                        write,
                        state=ReservationState.RELEASED,
                        updated_at=updated_at,
                        revision=write.revision + 1,
                    ),
                    write.revision,
                )
            connection.execute(
                "UPDATE pass_b_workspace_claims SET state='RELEASED' "
                "WHERE reservation_id=? AND state='ACTIVE'",
                (reservation_id,),
            )
            connection.execute(
                "UPDATE pass_b_write_claims SET state='RELEASED' "
                "WHERE reservation_id=? AND state='ACTIVE'",
                (reservation_id,),
            )
        return updated

    def abandon_prelaunch_assignment(
        self, assignment_id: str, abandoned_at: str
    ) -> PrelaunchAbandonmentRecord:
        """Cancel one never-launched assignment and return local reservations."""

        abandonment_id = f"prelaunch-abandonment:{assignment_id}"
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_row = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND id=?",
                (PrelaunchAbandonmentRecord.KIND, abandonment_id),
            ).fetchone()
            if existing_row is not None:
                existing = self._decode(PrelaunchAbandonmentRecord, existing_row)
                assignment = self._get(
                    connection, AssignmentRecord, existing.assignment_id
                )
                if (
                    existing.assignment_id != assignment_id
                    or assignment.state != AssignmentState.CANCELED
                    or self._get(
                        connection, WorkItemRecord, assignment.work_item_id
                    ).state
                    != WorkItemState.READY
                    or connection.execute(
                        "SELECT 1 FROM pass_b_usage_reservations "
                        "WHERE assignment_id=? AND state='ACTIVE'",
                        (assignment_id,),
                    ).fetchone()
                    is not None
                    or connection.execute(
                        "SELECT 1 FROM pass_b_workspace_claims "
                        "WHERE assignment_id=? AND state='ACTIVE'",
                        (assignment_id,),
                    ).fetchone()
                    is not None
                    or connection.execute(
                        "SELECT 1 FROM pass_b_write_claims "
                        "WHERE assignment_id=? AND state='ACTIVE'",
                        (assignment_id,),
                    ).fetchone()
                    is not None
                ):
                    raise PermissionError(
                        "prelaunch abandonment replay differs from durable state"
                    )
                return existing

            assignment = self._get(connection, AssignmentRecord, assignment_id)
            work_item = self._get(
                connection, WorkItemRecord, assignment.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, assignment.workflow_id
            )
            _validate_assignment_binding(workflow, work_item, assignment)
            attempts = [
                self._decode(AttemptRecord, row)
                for row in connection.execute(
                    "SELECT payload,payload_hash FROM pass_b_records WHERE kind=?",
                    (AttemptRecord.KIND,),
                ).fetchall()
            ]
            if (
                assignment.state != AssignmentState.READY
                or work_item.state != WorkItemState.ASSIGNED
                or any(item.assignment_id == assignment_id for item in attempts)
                or connection.execute(
                    "SELECT 1 FROM pass_b_launch_claims WHERE assignment_id=?",
                    (assignment_id,),
                ).fetchone()
                is not None
            ):
                raise PermissionError(
                    "only a never-launched READY assignment can be abandoned"
                )

            workspace_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records WHERE kind=?",
                (WorkspaceReservationRecord.KIND,),
            ).fetchall()
            workspaces = tuple(
                workspace_item
                for row in workspace_rows
                if (
                    workspace_item := self._decode(
                        WorkspaceReservationRecord, row
                    )
                ).assignment_id
                == assignment_id
            )
            if any(
                item.state not in {ReservationState.ACTIVE, ReservationState.RELEASED}
                for item in workspaces
            ):
                raise PermissionError(
                    "prelaunch workspace is uncertain or not safely releasable"
                )
            write_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records WHERE kind=?",
                (WriteReservationRecord.KIND,),
            ).fetchall()
            writes = tuple(
                write_item
                for row in write_rows
                if (
                    write_item := self._decode(WriteReservationRecord, row)
                ).assignment_id
                == assignment_id
            )
            if any(
                item.state not in {ReservationState.ACTIVE, ReservationState.RELEASED}
                for item in writes
            ):
                raise PermissionError(
                    "prelaunch write reservation is not safely releasable"
                )

            usage_rows = connection.execute(
                "SELECT * FROM pass_b_usage_reservations "
                "WHERE assignment_id=? AND state='ACTIVE'",
                (assignment_id,),
            ).fetchall()
            if len(usage_rows) > 1:
                raise PermissionError(
                    "prelaunch assignment has multiple active usage reservations"
                )
            usage = usage_rows[0] if usage_rows else None
            usage_id: str | None = None
            pool_id: str | None = None
            amount = 0.0
            if usage is not None:
                usage_id = str(usage["reservation_id"])
                pool_id = str(usage["pool_id"])
                amount = float(usage["amount"])
                pool = self._get(connection, UsagePoolRecord, pool_id)
                if (
                    not math.isfinite(amount)
                    or amount < 0
                    or pool.reserved < amount
                ):
                    raise PermissionError(
                        "prelaunch usage pool cannot return the exact reservation"
                    )
                restored_remaining = (
                    None
                    if pool.remaining is None
                    else pool.remaining + amount
                )
                if (
                    restored_remaining is not None
                    and pool.capacity is not None
                ):
                    restored_remaining = min(
                        restored_remaining, pool.capacity
                    )
                self._replace(
                    connection,
                    replace(
                        pool,
                        reserved=pool.reserved - amount,
                        remaining=restored_remaining,
                        exhausted=(
                            False
                            if restored_remaining is None
                            or restored_remaining > 0
                            else pool.exhausted
                        ),
                        updated_at=abandoned_at,
                        last_observed_at=abandoned_at,
                        revision=pool.revision + 1,
                    ),
                    pool.revision,
                )
                cursor = connection.execute(
                    "UPDATE pass_b_usage_reservations "
                    "SET state='RELEASED',updated_at=? "
                    "WHERE reservation_id=? AND state='ACTIVE'",
                    (abandoned_at, usage_id),
                )
                if cursor.rowcount != 1:
                    raise PermissionError(
                        "prelaunch usage reservation changed concurrently"
                    )

            for workspace in workspaces:
                if workspace.state == ReservationState.ACTIVE:
                    self._replace(
                        connection,
                        replace(
                            workspace,
                            state=ReservationState.RELEASED,
                            updated_at=abandoned_at,
                            revision=workspace.revision + 1,
                        ),
                        workspace.revision,
                    )
            for write in writes:
                if write.state == ReservationState.ACTIVE:
                    self._replace(
                        connection,
                        replace(
                            write,
                            state=ReservationState.RELEASED,
                            updated_at=abandoned_at,
                            revision=write.revision + 1,
                        ),
                        write.revision,
                    )
            connection.execute(
                "UPDATE pass_b_workspace_claims SET state='RELEASED' "
                "WHERE assignment_id=? AND state='ACTIVE'",
                (assignment_id,),
            )
            connection.execute(
                "UPDATE pass_b_write_claims SET state='RELEASED' "
                "WHERE assignment_id=? AND state='ACTIVE'",
                (assignment_id,),
            )
            self._replace(
                connection,
                replace(
                    assignment,
                    state=AssignmentState.CANCELED,
                    updated_at=abandoned_at,
                    revision=assignment.revision + 1,
                ),
                assignment.revision,
            )
            self._replace(
                connection,
                replace(
                    work_item,
                    state=WorkItemState.READY,
                    updated_at=abandoned_at,
                    revision=work_item.revision + 1,
                ),
                work_item.revision,
            )
            record = PrelaunchAbandonmentRecord(
                abandonment_id=abandonment_id,
                project_id=assignment.project_id,
                charter_id=assignment.charter_id,
                charter_revision=assignment.charter_revision,
                workflow_id=assignment.workflow_id,
                work_item_id=assignment.work_item_id,
                assignment_id=assignment.assignment_id,
                released_workspace_reservation_ids=tuple(
                    sorted(item.workspace_reservation_id for item in workspaces)
                ),
                released_write_reservation_ids=tuple(
                    sorted(item.write_reservation_id for item in writes)
                ),
                released_usage_reservation_id=usage_id,
                released_usage_pool_id=pool_id,
                released_usage_amount=amount,
                state="APPLIED",
                abandoned_at=abandoned_at,
                created_at=abandoned_at,
                updated_at=abandoned_at,
                revision=1,
            )
            self._insert(connection, record)
        return record

    def reconcile_absent_authority_reservation(
        self,
        assignment_id: str,
        *,
        attempt_id: str,
        authority_attempt_id: str,
        observation_digest: str,
        service_key_id: str,
        service_key_version: int,
        client_sid: str,
        reconciled_at: str,
    ) -> AuthorityReservationReconciliationRecord:
        """Release a prelaunch uncertainty after exact Authority absence proof."""

        reconciliation_id = (
            f"authority-reservation-reconciliation:{attempt_id}"
        )
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_row = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND id=?",
                (
                    AuthorityReservationReconciliationRecord.KIND,
                    reconciliation_id,
                ),
            ).fetchone()
            if existing_row is not None:
                existing = self._decode(
                    AuthorityReservationReconciliationRecord, existing_row
                )
                assignment = self._get(
                    connection, AssignmentRecord, existing.assignment_id
                )
                attempt = self._get(
                    connection, AttemptRecord, existing.attempt_id
                )
                work_item = self._get(
                    connection, WorkItemRecord, existing.work_item_id
                )
                launch_claim = connection.execute(
                    "SELECT state FROM pass_b_launch_claims "
                    "WHERE attempt_id=? AND assignment_id=? "
                    "AND authority_attempt_id=?",
                    (
                        existing.attempt_id,
                        existing.assignment_id,
                        existing.authority_attempt_id,
                    ),
                ).fetchone()
                unresolved_local_claim = connection.execute(
                    "SELECT 1 FROM pass_b_workspace_claims "
                    "WHERE assignment_id=? AND state IN ('ACTIVE','UNCERTAIN') "
                    "UNION ALL SELECT 1 FROM pass_b_write_claims "
                    "WHERE assignment_id=? AND state IN ('ACTIVE','UNCERTAIN') "
                    "UNION ALL SELECT 1 FROM pass_b_usage_reservations "
                    "WHERE assignment_id=? AND state='ACTIVE' LIMIT 1",
                    (assignment_id, assignment_id, assignment_id),
                ).fetchone()
                if (
                    existing.assignment_id != assignment_id
                    or existing.attempt_id != attempt_id
                    or existing.authority_attempt_id != authority_attempt_id
                    or existing.observation_digest != observation_digest
                    or existing.service_key_id != service_key_id
                    or existing.service_key_version != service_key_version
                    or existing.client_sid != client_sid
                    or assignment.state != AssignmentState.CANCELED
                    or attempt.state != AttemptState.FAILED
                    or attempt.uncertainty_kind is not None
                    or attempt.session_slot_claimed
                    or work_item.state != WorkItemState.READY
                    or launch_claim is None
                    or str(launch_claim["state"]) != AttemptState.FAILED
                    or unresolved_local_claim is not None
                ):
                    raise PermissionError(
                        "Authority absence reconciliation replay differs"
                    )
                return existing

            assignment = self._get(
                connection, AssignmentRecord, assignment_id
            )
            attempt = self._get(connection, AttemptRecord, attempt_id)
            work_item = self._get(
                connection, WorkItemRecord, assignment.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, assignment.workflow_id
            )
            session = self._get(
                connection, ProviderSessionRecord, assignment.session_id
            )
            _validate_assignment_binding(workflow, work_item, assignment)
            launch_claim = connection.execute(
                "SELECT authority_attempt_id,state FROM pass_b_launch_claims "
                "WHERE attempt_id=? AND assignment_id=?",
                (attempt_id, assignment_id),
            ).fetchone()
            if (
                attempt.assignment_id != assignment_id
                or attempt.authority_attempt_id != authority_attempt_id
                or attempt.state != AttemptState.UNCERTAIN
                or attempt.uncertainty_kind
                != "AUTHORITY_RESERVATION_OUTCOME_AMBIGUOUS"
                or attempt.external_execution_id is not None
                or attempt.authority_reservation_state
                not in {"RESERVATION_IN_FLIGHT", "AUTHORITY_RESERVED"}
                or attempt.launch_token
                != "pending:" + attempt.authority_reservation_plan_digest
                or not attempt.session_slot_claimed
                or assignment.state != AssignmentState.UNCERTAIN
                or work_item.state != WorkItemState.ASSIGNED
                or session.active_assignments < 1
                or launch_claim is None
                or str(launch_claim["authority_attempt_id"])
                != authority_attempt_id
                or str(launch_claim["state"]) != AttemptState.UNCERTAIN
            ):
                raise PermissionError(
                    "Authority absence reconciliation binding is invalid"
                )

            workspace_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND state='UNCERTAIN'",
                (WorkspaceReservationRecord.KIND,),
            ).fetchall()
            workspaces = tuple(
                item
                for row in workspace_rows
                if (
                    item := self._decode(WorkspaceReservationRecord, row)
                ).assignment_id
                == assignment_id
            )
            write_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND state='UNCERTAIN'",
                (WriteReservationRecord.KIND,),
            ).fetchall()
            writes = tuple(
                item
                for row in write_rows
                if (
                    item := self._decode(WriteReservationRecord, row)
                ).assignment_id
                == assignment_id
            )
            if len(workspaces) != 1:
                raise PermissionError(
                    "Authority absence requires one uncertain workspace"
                )
            workspace_claims = connection.execute(
                "SELECT reservation_id FROM pass_b_workspace_claims "
                "WHERE assignment_id=? AND state='UNCERTAIN'",
                (assignment_id,),
            ).fetchall()
            write_claims = connection.execute(
                "SELECT scope_key FROM pass_b_write_claims "
                "WHERE assignment_id=? AND state='UNCERTAIN'",
                (assignment_id,),
            ).fetchall()
            if (
                {str(row["reservation_id"]) for row in workspace_claims}
                != {item.workspace_reservation_id for item in workspaces}
                or {str(row["scope_key"]) for row in write_claims}
                != {
                    scope_key
                    for item in writes
                    for scope_key in item.scope_keys
                }
            ):
                raise PermissionError(
                    "Authority absence reservation claims are incomplete"
                )

            usage_rows = connection.execute(
                "SELECT * FROM pass_b_usage_reservations "
                "WHERE assignment_id=? AND state='ACTIVE'",
                (assignment_id,),
            ).fetchall()
            if len(usage_rows) > 1:
                raise PermissionError(
                    "Authority absence has multiple active usage reservations"
                )
            usage = usage_rows[0] if usage_rows else None
            usage_id: str | None = None
            pool_id: str | None = None
            amount = 0.0
            if usage is not None:
                usage_id = str(usage["reservation_id"])
                pool_id = str(usage["pool_id"])
                amount = float(usage["amount"])
                pool = self._get(connection, UsagePoolRecord, pool_id)
                if (
                    not math.isfinite(amount)
                    or amount < 0
                    or pool.reserved < amount
                ):
                    raise PermissionError(
                        "Authority absence usage reservation cannot be returned"
                    )
                restored_remaining = (
                    None
                    if pool.remaining is None
                    else pool.remaining + amount
                )
                if (
                    restored_remaining is not None
                    and pool.capacity is not None
                ):
                    restored_remaining = min(
                        restored_remaining, pool.capacity
                    )
                self._replace(
                    connection,
                    replace(
                        pool,
                        reserved=pool.reserved - amount,
                        remaining=restored_remaining,
                        exhausted=(
                            False
                            if restored_remaining is None
                            or restored_remaining > 0
                            else pool.exhausted
                        ),
                        updated_at=reconciled_at,
                        last_observed_at=reconciled_at,
                        revision=pool.revision + 1,
                    ),
                    pool.revision,
                )
                cursor = connection.execute(
                    "UPDATE pass_b_usage_reservations "
                    "SET state='RELEASED',updated_at=? "
                    "WHERE reservation_id=? AND state='ACTIVE'",
                    (reconciled_at, usage_id),
                )
                if cursor.rowcount != 1:
                    raise PermissionError(
                        "Authority absence usage reservation changed"
                    )

            for workspace in workspaces:
                self._replace(
                    connection,
                    replace(
                        workspace,
                        state=ReservationState.RELEASED,
                        updated_at=reconciled_at,
                        revision=workspace.revision + 1,
                    ),
                    workspace.revision,
                )
            for write in writes:
                self._replace(
                    connection,
                    replace(
                        write,
                        state=ReservationState.RELEASED,
                        updated_at=reconciled_at,
                        revision=write.revision + 1,
                    ),
                    write.revision,
                )
            connection.execute(
                "UPDATE pass_b_workspace_claims SET state='RELEASED' "
                "WHERE assignment_id=? AND state='UNCERTAIN'",
                (assignment_id,),
            )
            connection.execute(
                "UPDATE pass_b_write_claims SET state='RELEASED' "
                "WHERE assignment_id=? AND state='UNCERTAIN'",
                (assignment_id,),
            )
            self._replace(
                connection,
                replace(
                    attempt,
                    state=AttemptState.FAILED,
                    finished_at=reconciled_at,
                    last_error=(
                        "Authority authenticated state confirmed the reservation "
                        "was never created"
                    ),
                    uncertainty_kind=None,
                    session_slot_claimed=False,
                    updated_at=reconciled_at,
                    revision=attempt.revision + 1,
                ),
                attempt.revision,
            )
            self._replace(
                connection,
                replace(
                    assignment,
                    state=AssignmentState.CANCELED,
                    updated_at=reconciled_at,
                    revision=assignment.revision + 1,
                ),
                assignment.revision,
            )
            self._replace(
                connection,
                replace(
                    work_item,
                    state=WorkItemState.READY,
                    updated_at=reconciled_at,
                    revision=work_item.revision + 1,
                ),
                work_item.revision,
            )
            remaining = max(0, session.active_assignments - 1)
            self._replace(
                connection,
                replace(
                    session,
                    active_assignments=remaining,
                    state=(
                        "BUSY"
                        if remaining >= session.concurrency_limit
                        else "READY"
                    ),
                    last_seen_at=reconciled_at,
                    updated_at=reconciled_at,
                    revision=session.revision + 1,
                ),
                session.revision,
            )
            cursor = connection.execute(
                "UPDATE pass_b_launch_claims SET state='FAILED',updated_at=? "
                "WHERE attempt_id=? AND assignment_id=? "
                "AND authority_attempt_id=? AND state='UNCERTAIN'",
                (
                    reconciled_at,
                    attempt_id,
                    assignment_id,
                    authority_attempt_id,
                ),
            )
            if cursor.rowcount != 1:
                raise PermissionError(
                    "Authority absence launch claim changed concurrently"
                )
            record = AuthorityReservationReconciliationRecord(
                reconciliation_id=reconciliation_id,
                project_id=assignment.project_id,
                charter_id=assignment.charter_id,
                charter_revision=assignment.charter_revision,
                workflow_id=assignment.workflow_id,
                work_item_id=assignment.work_item_id,
                assignment_id=assignment.assignment_id,
                attempt_id=attempt.attempt_id,
                authority_attempt_id=attempt.authority_attempt_id,
                observation_digest=observation_digest,
                service_key_id=service_key_id,
                service_key_version=service_key_version,
                client_sid=client_sid,
                released_workspace_reservation_ids=tuple(
                    sorted(item.workspace_reservation_id for item in workspaces)
                ),
                released_write_reservation_ids=tuple(
                    sorted(item.write_reservation_id for item in writes)
                ),
                released_usage_reservation_id=usage_id,
                released_usage_pool_id=pool_id,
                released_usage_amount=amount,
                state="APPLIED",
                reconciled_at=reconciled_at,
                created_at=reconciled_at,
                updated_at=reconciled_at,
                revision=1,
            )
            self._insert(connection, record)
        return record

    def insert_repository_snapshot_evidence(
        self,
        *,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        attempt: AttemptRecord,
        evidence: EvidenceBundleRecord,
        snapshot: RepositorySnapshotRecord,
    ) -> RepositorySnapshotRecord:
        """Atomically publish deterministic Git evidence without a provider effect."""

        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            durable_workflow = self._get(
                connection, WorkflowRecord, workflow.workflow_id
            )
            existing_row = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND id=?",
                (RepositorySnapshotRecord.KIND, snapshot.snapshot_id),
            ).fetchone()
            if existing_row is not None:
                existing = self._decode(RepositorySnapshotRecord, existing_row)
                if existing != snapshot:
                    stable_existing = existing.to_dict()
                    stable_candidate = snapshot.to_dict()
                    for key in ("created_at", "updated_at"):
                        stable_existing.pop(key)
                        stable_candidate.pop(key)
                    if stable_existing != stable_candidate:
                        raise PermissionError(
                            "repository snapshot replay differs from durable evidence"
                        )
                return existing
            if durable_workflow != workflow or workflow.state != WorkflowState.ACTIVE:
                raise PermissionError("repository snapshot workflow changed")
            _validate_workflow_work_item(workflow, work_item)
            _validate_assignment_binding(workflow, work_item, assignment)
            artifact = evidence.artifacts[0] if len(evidence.artifacts) == 1 else None
            manifest_entries = (
                artifact.get("entries") if isinstance(artifact, dict) else None
            )
            manifest_digest = (
                hashlib.sha256(
                    json.dumps(
                        manifest_entries,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                if isinstance(manifest_entries, list)
                else None
            )
            manifest_total = (
                sum(
                    int(item.get("size_bytes", -1))
                    for item in manifest_entries
                    if isinstance(item, dict)
                )
                if isinstance(manifest_entries, list)
                and all(isinstance(item, dict) for item in manifest_entries)
                else -1
            )
            if (
                work_item.state != WorkItemState.REVIEW_REQUIRED
                or work_item.required_roles != (AssignmentRole.RESEARCHER,)
                or assignment.state != AssignmentState.REVIEW_REQUIRED
                or assignment.provider_id != "keeper-repository-snapshot"
                or assignment.role != AssignmentRole.RESEARCHER
                or not assignment.read_only
                or attempt.assignment_id != assignment.assignment_id
                or attempt.state != AttemptState.COMPLETED
                or attempt.external_execution_id is not None
                or attempt.side_effect_class != "READ_ONLY_REPOSITORY_SNAPSHOT"
                or evidence.assignment_id != assignment.assignment_id
                or evidence.attempt_id != attempt.attempt_id
                or evidence.state != EvidenceState.VALIDATED
                or evidence.producer_provider_id != "keeper-repository-snapshot"
                or not isinstance(artifact, dict)
                or artifact.get("kind") != "repository_snapshot"
                or artifact.get("snapshot_id") != snapshot.snapshot_id
                or artifact.get("canonical_repository_path")
                != snapshot.canonical_repository_path
                or artifact.get("commit_hash") != snapshot.commit_hash
                or artifact.get("tree_hash") != snapshot.tree_hash
                or artifact.get("manifest_digest") != snapshot.manifest_digest
                or artifact.get("file_count") != snapshot.file_count
                or artifact.get("total_size_bytes") != snapshot.total_size_bytes
                or manifest_digest != snapshot.manifest_digest
                or len(manifest_entries or ()) != snapshot.file_count
                or manifest_total != snapshot.total_size_bytes
                or snapshot.assignment_id != assignment.assignment_id
                or snapshot.attempt_id != attempt.attempt_id
                or snapshot.evidence_bundle_id != evidence.evidence_bundle_id
            ):
                raise PermissionError(
                    "repository snapshot evidence binding is invalid"
                )
            expected_evidence_digest = hashlib.sha256(
                json.dumps(
                    {
                        "project_id": evidence.project_id,
                        "assignment_id": evidence.assignment_id,
                        "attempt_id": evidence.attempt_id,
                        "producer_provider_id": evidence.producer_provider_id,
                        "producer_session_id": evidence.producer_session_id,
                        "schema_version": evidence.schema_version,
                        "artifacts": evidence.artifacts,
                        "summary": evidence.summary,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            if evidence.content_digest != expected_evidence_digest:
                raise PermissionError("repository snapshot evidence digest is invalid")
            for record in (work_item, assignment, attempt, evidence, snapshot):
                self._insert(connection, record)
        return snapshot

    def recover_stale_workspace(
        self, reservation_id: str, observed_at: str
    ) -> WorkspaceReservationRecord:
        observed = _parse_time(observed_at)
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get(
                connection, WorkspaceReservationRecord, reservation_id
            )
            if (
                canonical_workspace_path(Path(current.canonical_path))
                != current.canonical_path
            ):
                raise PermissionError("workspace release path is no longer safe")
            assignment = self._get(
                connection, AssignmentRecord, current.assignment_id
            )
            live_launch = connection.execute(
                "SELECT 1 FROM pass_b_launch_claims "
                "WHERE assignment_id=? AND state IN "
                "('RESERVED','LAUNCH_CLAIMED','RUNNING','UNCERTAIN')",
                (assignment.assignment_id,),
            ).fetchone()
            if _parse_time(current.lease_expires_at) > observed:
                raise PermissionError("workspace lease has not expired")
            if assignment.state in {
                AssignmentState.LAUNCH_CLAIMED,
                AssignmentState.RUNNING,
                AssignmentState.UNCERTAIN,
            } or live_launch is not None:
                raise PermissionError("stale active work requires Founder review")
            updated = replace(
                current,
                state=ReservationState.STALE,
                updated_at=observed_at,
                revision=current.revision + 1,
            )
            self._replace(connection, updated, current.revision)
            for write in self._active_writes(connection, reservation_id):
                self._replace(
                    connection,
                    replace(
                        write,
                        state=ReservationState.STALE,
                        updated_at=observed_at,
                        revision=write.revision + 1,
                    ),
                    write.revision,
                )
            connection.execute(
                "UPDATE pass_b_workspace_claims SET state='STALE' "
                "WHERE reservation_id=? AND state='ACTIVE'",
                (reservation_id,),
            )
            connection.execute(
                "UPDATE pass_b_write_claims SET state='STALE' "
                "WHERE reservation_id=? AND state='ACTIVE'",
                (reservation_id,),
            )
        return updated

    def reserve_usage_or_pause(
        self,
        *,
        reservation_id: str,
        pool_id: str,
        assignment_id: str,
        amount: float,
        pause: PauseReasonRecord,
        checkpoint: ResumeCheckpointRecord,
        observed_at: str,
    ) -> bool:
        if not math.isfinite(amount) or amount < 0:
            raise ValueError("usage reservation must be finite and nonnegative")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            pool = self._get(connection, UsagePoolRecord, pool_id)
            assignment = self._get(
                connection, AssignmentRecord, assignment_id
            )
            account = self._get(
                connection, ProviderAccountRecord, assignment.account_id
            )
            if account.usage_pool_id != pool_id:
                raise PermissionError("assignment account uses another usage pool")
            remaining = pool.remaining
            exhausted = pool.exhausted or (
                remaining is not None and remaining < amount
            )
            if exhausted:
                paused_assignment = replace(
                    assignment,
                    state=AssignmentState.WAITING_FOR_USAGE_RESET,
                    updated_at=observed_at,
                    revision=assignment.revision + 1,
                )
                exhausted_pool = replace(
                    pool,
                    exhausted=True,
                    updated_at=observed_at,
                    last_observed_at=observed_at,
                    revision=pool.revision + 1,
                )
                self._replace(connection, paused_assignment, assignment.revision)
                self._replace(connection, exhausted_pool, pool.revision)
                self._insert(connection, pause)
                self._insert(connection, checkpoint)
                return False
            updated_remaining = (
                None if remaining is None else max(0.0, remaining - amount)
            )
            updated_pool = replace(
                pool,
                reserved=pool.reserved + amount,
                remaining=updated_remaining,
                last_observed_at=observed_at,
                updated_at=observed_at,
                revision=pool.revision + 1,
            )
            self._replace(connection, updated_pool, pool.revision)
            connection.execute(
                "INSERT INTO pass_b_usage_reservations("
                "reservation_id,pool_id,assignment_id,amount,state,"
                "reserved_at,updated_at,observation_generation"
                ") VALUES(?,?,?,?,?,?,?,?)",
                (
                    reservation_id,
                    pool_id,
                    assignment_id,
                    amount,
                    "ACTIVE",
                    observed_at,
                    observed_at,
                    pool.observation_generation,
                ),
            )
            return True

    def observe_usage_reset(
        self,
        *,
        pool_id: str,
        observation_id: str,
        observation_digest: str,
        observed_reset_at: str,
        observation_source: str,
        observation_generation: int,
        observed_capacity: float | None,
        observed_consumed: float,
        observed_remaining: float | None,
        confidence: str,
        observed_at: str,
    ) -> UsagePoolRecord:
        reset = _parse_time(observed_reset_at)
        observation = _parse_time(observed_at)
        if reset > observation:
            raise PermissionError("usage reset observation is in the future")
        if (
            not observation_id
            or len(observation_digest) != 64
            or not observation_source
            or confidence not in {"HIGH", "MEDIUM"}
        ):
            raise PermissionError("usage reset observation is not trustworthy")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            pool = self._get(connection, UsagePoolRecord, pool_id)
            if (
                pool.reset_at is None
                or reset < _parse_time(pool.reset_at)
                or observation <= _parse_time(pool.last_observed_at)
                or observation_generation != pool.observation_generation + 1
                or observed_capacity != pool.capacity
            ):
                raise PermissionError("usage reset observation is stale")
            active = connection.execute(
                "SELECT COALESCE(SUM(amount),0) "
                "FROM pass_b_usage_reservations "
                "WHERE pool_id=? AND state='ACTIVE'",
                (pool_id,),
            ).fetchone()
            reserved = float(active[0])
            if (
                observed_remaining is not None
                and observed_remaining < reserved
            ):
                raise PermissionError(
                    "usage reset cannot cover active durable reservations"
                )
            remaining = (
                None
                if observed_remaining is None
                else observed_remaining - reserved
            )
            updated = replace(
                pool,
                consumed=observed_consumed,
                reserved=reserved,
                remaining=remaining,
                reset_at=None,
                observation_source=observation_source,
                confidence=confidence,
                exhausted=(
                    remaining is not None and remaining <= 0
                ),
                last_observed_at=observed_at,
                updated_at=observed_at,
                revision=pool.revision + 1,
                observation_generation=pool.observation_generation + 1,
            )
            self._replace(connection, updated, pool.revision)
            try:
                connection.execute(
                    "INSERT INTO pass_b_usage_reset_observations "
                    "VALUES(?,?,?,?,?)",
                    (
                        observation_id,
                        pool_id,
                        updated.observation_generation,
                        observation_digest,
                        observed_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "usage reset observation was replayed"
                ) from error
        return updated

    def resume_after_usage_reset(
        self,
        *,
        pool_id: str,
        assignment_id: str,
        checkpoint_id: str,
        resumed_at: str,
    ) -> AssignmentRecord:
        resumed = _parse_time(resumed_at)
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            pool = self._get(connection, UsagePoolRecord, pool_id)
            assignment = self._get(
                connection, AssignmentRecord, assignment_id
            )
            checkpoint = self._get(
                connection, ResumeCheckpointRecord, checkpoint_id
            )
            if (
                assignment.state != AssignmentState.WAITING_FOR_USAGE_RESET
                or checkpoint.assignment_id != assignment_id
                or checkpoint.project_id != assignment.project_id
                or checkpoint.charter_id != assignment.charter_id
                or checkpoint.charter_revision != assignment.charter_revision
                or checkpoint.authority_envelope_digest
                != assignment.authority_envelope_digest
                or checkpoint.usage_pool_id != pool_id
                or checkpoint.resumed_at is not None
                or checkpoint.checkpoint_state.get(
                    "usage_observation_generation"
                )
                != pool.observation_generation - 1
                or checkpoint.checkpoint_state.get("provider_id")
                != assignment.provider_id
                or checkpoint.checkpoint_state.get("account_id")
                != assignment.account_id
                or checkpoint.checkpoint_state.get("session_id")
                != assignment.session_id
                or checkpoint.checkpoint_state.get("model_id")
                != assignment.model_id
                or checkpoint.checkpoint_state.get(
                    "assignment_revision"
                )
                != assignment.revision - 1
            ):
                raise PermissionError("resume checkpoint no longer matches assignment")
            if (
                pool.observation_generation < 2
                or _parse_time(pool.last_observed_at) > resumed
                or pool.exhausted
            ):
                raise PermissionError("validated usage reset has not occurred")
            workspace = self._get(
                connection,
                WorkspaceReservationRecord,
                checkpoint.workspace_reservation_id,
            )
            if (
                workspace.assignment_id != assignment_id
                or workspace.state != ReservationState.ACTIVE
                or workspace.workspace_id != assignment.workspace_id
                or (
                    "workspace_id" in checkpoint.checkpoint_state
                    and checkpoint.checkpoint_state["workspace_id"]
                    != workspace.workspace_id
                )
                or (
                    "workspace_canonical_path"
                    in checkpoint.checkpoint_state
                    and checkpoint.checkpoint_state[
                        "workspace_canonical_path"
                    ]
                    != workspace.canonical_path
                )
                or checkpoint.checkpoint_state.get(
                    "workspace_revision"
                )
                != workspace.revision
            ):
                raise PermissionError("resume workspace is unavailable")
            uncertain = connection.execute(
                "SELECT 1 FROM pass_b_launch_claims "
                "WHERE assignment_id=? AND state='UNCERTAIN'",
                (assignment_id,),
            ).fetchone()
            if uncertain is not None:
                raise PermissionError("uncertain attempt cannot resume automatically")
            reset_observation = connection.execute(
                "SELECT 1 FROM pass_b_usage_reset_observations "
                "WHERE pool_id=? AND observation_generation=?",
                (pool_id, pool.observation_generation),
            ).fetchone()
            if reset_observation is None:
                raise PermissionError(
                    "durable usage reset observation is missing"
                )
            updated_assignment = replace(
                assignment,
                state=AssignmentState.READY,
                updated_at=resumed_at,
                revision=assignment.revision + 1,
            )
            updated_checkpoint = replace(
                checkpoint,
                resumed_at=resumed_at,
                revision=checkpoint.revision + 1,
            )
            self._replace(connection, updated_assignment, assignment.revision)
            self._replace(connection, updated_checkpoint, checkpoint.revision)
            pauses = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND state='' ORDER BY created_at",
                (PauseReasonRecord.KIND,),
            ).fetchall()
            for row in pauses:
                pause = self._decode(PauseReasonRecord, row)
                if pause.assignment_id == assignment_id and pause.resolved_at is None:
                    self._replace(
                        connection,
                        replace(
                            pause,
                            resolved_at=resumed_at,
                            revision=pause.revision + 1,
                        ),
                        pause.revision,
                    )
        return updated_assignment

    def reserve_attempt(
        self,
        attempt: AttemptRecord,
        *,
        delivered_input: DeliveredInputRecord | None = None,
        expected_workflow: WorkflowRecord | None = None,
        expected_work_item: WorkItemRecord | None = None,
        expected_assignment: AssignmentRecord | None = None,
        expected_profile: ExecutionProfileRecord | None = None,
        expected_selection: ProviderSelectionRecord | None = None,
        expected_provider: ProviderRecord | None = None,
    ) -> None:
        if attempt.state != AttemptState.RESERVED:
            raise ValueError("new attempts must begin reserved")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            work_item = self._get(
                connection, WorkItemRecord, assignment.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, assignment.workflow_id
            )
            _validate_assignment_binding(workflow, work_item, assignment)
            expected = (
                expected_workflow,
                expected_work_item,
                expected_assignment,
            )
            if any(item is not None for item in expected) and (
                expected_workflow != workflow
                or expected_work_item != work_item
                or expected_assignment != assignment
            ):
                raise PermissionError(
                    "launch binding changed before the transactional claim"
                )
            provider = self._get(
                connection, ProviderRecord, assignment.provider_id
            )
            account = self._get(
                connection, ProviderAccountRecord, assignment.account_id
            )
            session = self._get(
                connection, ProviderSessionRecord, assignment.session_id
            )
            prepared = (
                expected_profile,
                expected_selection,
                expected_provider,
            )
            expected_usage_amount: float | None = None
            if any(item is not None for item in prepared):
                if any(item is None for item in prepared):
                    raise PermissionError(
                        "launch requires an exact profile, selection, and provider"
                    )
                assert expected_profile is not None
                assert expected_selection is not None
                assert expected_provider is not None
                profile_id = assignment.usage_policy.get(
                    "execution_profile_id"
                )
                selection_id = assignment.usage_policy.get(
                    "provider_selection_id"
                )
                if (
                    profile_id != expected_profile.execution_profile_id
                    or selection_id
                    != expected_selection.provider_selection_id
                    or self._get(
                        connection,
                        ExecutionProfileRecord,
                        expected_profile.execution_profile_id,
                    )
                    != expected_profile
                    or self._get(
                        connection,
                        ProviderSelectionRecord,
                        expected_selection.provider_selection_id,
                    )
                    != expected_selection
                    or provider != expected_provider
                ):
                    raise PermissionError(
                        "durable profile, provider selection, or provider changed "
                        "before the transactional claim"
                    )
                _validate_execution_profile(
                    workflow, work_item, expected_profile
                )
                if (
                    expected_selection.execution_profile_id
                    != expected_profile.execution_profile_id
                    or expected_selection.assignment_id
                    != assignment.assignment_id
                    or expected_selection.project_id
                    != assignment.project_id
                    or expected_selection.charter_id
                    != assignment.charter_id
                    or expected_selection.charter_revision
                    != assignment.charter_revision
                    or expected_selection.workflow_id
                    != assignment.workflow_id
                    or expected_selection.work_item_id
                    != assignment.work_item_id
                    or expected_selection.provider_id
                    != assignment.provider_id
                    or expected_selection.account_id
                    != assignment.account_id
                    or expected_selection.session_id
                    != assignment.session_id
                    or expected_selection.model_id != assignment.model_id
                    or assignment.usage_policy.get("requested_amount")
                    != expected_profile.usage_amount
                    or account.provider_id != provider.provider_id
                    or account.account_id != assignment.account_id
                    or account.usage_pool_id
                    != expected_selection.usage_pool_id
                    or account.cost_mode != expected_selection.cost_mode
                    or account.privacy_classification
                    != expected_selection.privacy_classification
                    or not account.authentication_ready
                    or not account.enabled
                    or provider.health != HealthState.READY
                    or not provider.authentication_ready
                    or provider.cost_mode == CostMode.PAID
                    or account.cost_mode == CostMode.PAID
                    or session.provider_id != provider.provider_id
                    or session.account_id != account.account_id
                    or session.model_id != expected_selection.model_id
                    or session.state
                    not in {
                        ProviderSessionState.READY,
                        ProviderSessionState.BUSY,
                    }
                    or (
                        expected_profile.role.casefold()
                        not in {
                            item.casefold()
                            for item in provider.capabilities
                        }
                        and "all-roles"
                        not in {
                            item.casefold()
                            for item in provider.capabilities
                        }
                    )
                    or not {
                        item.casefold()
                        for item in expected_profile.required_capabilities
                    }.issubset(
                        {
                            item.casefold()
                            for item in provider.capabilities
                        }
                    )
                ):
                    raise PermissionError(
                        "provider selection no longer satisfies launch policy"
                    )
            workspace = self._active_workspace(connection, assignment.assignment_id)
            usage_row = connection.execute(
                "SELECT reservation_id,pool_id,amount,observation_generation "
                "FROM pass_b_usage_reservations "
                "WHERE assignment_id=? AND state='ACTIVE'",
                (assignment.assignment_id,),
            ).fetchone()
            expected_usage_amount = expected_profile.usage_amount if expected_profile else None
            if (
                assignment.state != AssignmentState.READY
                or session.provider_id != assignment.provider_id
                or session.account_id != assignment.account_id
                or session.active_assignments >= session.concurrency_limit
                or workspace.workspace_id != assignment.workspace_id
                or workspace.workspace_reservation_id
                != attempt.workspace_reservation_id
                or workspace.state != ReservationState.ACTIVE
                or _parse_time(workspace.lease_expires_at)
                <= _parse_time(attempt.created_at)
            ):
                raise PermissionError("assignment is not launch-ready")
            if bool(assignment.usage_policy.get("reservation_required", True)):
                if (
                    usage_row is None
                    or usage_row["reservation_id"]
                    != attempt.usage_reservation_id
                ):
                    raise PermissionError("assignment has no usage reservation")
                if (
                    expected_usage_amount is not None
                    and float(usage_row["amount"]) != expected_usage_amount
                ):
                    raise PermissionError("usage reservation amount is not exact")
                pool = self._get(
                    connection,
                    UsagePoolRecord,
                    str(usage_row["pool_id"]),
                )
                if pool.exhausted:
                    raise PermissionError(
                        "usage pool exhausted before provider launch"
                    )
            elif attempt.usage_reservation_id is not None:
                raise PermissionError("unexpected usage reservation binding")
            if not assignment.read_only:
                write = connection.execute(
                    "SELECT 1 FROM pass_b_write_claims "
                    "WHERE reservation_id=? AND assignment_id=? "
                    "AND state='ACTIVE'",
                    (
                        workspace.workspace_reservation_id,
                        assignment.assignment_id,
                    ),
                ).fetchone()
                if write is None:
                    raise PermissionError(
                        "write-capable launch requires a protected write scope"
                    )
            if delivered_input is not None:
                if (
                    assignment.role != AssignmentRole.REVIEWER
                    or delivered_input.reviewer_attempt_id != attempt.attempt_id
                    or delivered_input.reviewer_assignment_id
                    != assignment.assignment_id
                    or attempt.delivered_input_id
                    != delivered_input.delivered_input_id
                    or attempt.delivered_input_digest
                    != delivered_input.delivered_input_digest
                    or attempt.provider_input_digest
                    != delivered_input.provider_input_digest
                    or delivered_input.project_id != assignment.project_id
                    or delivered_input.charter_id != assignment.charter_id
                    or delivered_input.charter_revision
                    != assignment.charter_revision
                    or delivered_input.workflow_id != assignment.workflow_id
                    or delivered_input.work_item_id != assignment.work_item_id
                ):
                    raise PermissionError(
                        "attempt delivered-input binding is invalid"
                    )
            elif attempt.delivered_input_id is not None:
                raise PermissionError("attempt delivered input was not persisted")
            updated_session = replace(
                session,
                active_assignments=session.active_assignments + 1,
                state=(
                    "BUSY"
                    if session.active_assignments + 1
                    >= session.concurrency_limit
                    else session.state
                ),
                last_seen_at=attempt.created_at,
                updated_at=attempt.created_at,
                revision=session.revision + 1,
            )
            if delivered_input is not None:
                self._insert(connection, delivered_input)
            self._insert(connection, attempt)
            self._replace(connection, updated_session, session.revision)
            try:
                connection.execute(
                    "INSERT INTO pass_b_launch_claims("
                    "attempt_id,assignment_id,launch_token,state,updated_at,"
                    "authority_attempt_id) VALUES(?,?,?,?,?,?)",
                    (
                        attempt.attempt_id,
                        attempt.assignment_id,
                        attempt.launch_token,
                        attempt.state,
                        attempt.updated_at,
                        attempt.authority_attempt_id,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "assignment already has an active or completed launch"
                ) from error

    def decide_review(
        self,
        review_id: str,
        *,
        decided_at: str,
    ) -> tuple[ReviewRecord, AssignmentRecord, WorkItemRecord]:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            review = self._get(connection, ReviewRecord, review_id)
            assignment = self._get(
                connection, AssignmentRecord, review.assignment_id
            )
            work_item = self._get(
                connection, WorkItemRecord, assignment.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, assignment.workflow_id
            )
            _validate_assignment_binding(workflow, work_item, assignment)
            producer_evidence = self._get(
                connection,
                EvidenceBundleRecord,
                review.producer_evidence_bundle_id,
            )
            reviewer_assignment = self._get(
                connection,
                AssignmentRecord,
                review.reviewer_assignment_id,
            )
            reviewer_work_item = self._get(
                connection,
                WorkItemRecord,
                reviewer_assignment.work_item_id,
            )
            _validate_assignment_binding(
                workflow, reviewer_work_item, reviewer_assignment
            )
            reviewer_attempt = self._get(
                connection, AttemptRecord, review.reviewer_attempt_id
            )
            reviewer_evidence = self._get(
                connection,
                EvidenceBundleRecord,
                review.reviewer_evidence_bundle_id,
            )
            delivered_input = (
                self._get(
                    connection,
                    DeliveredInputRecord,
                    review.delivered_input_id,
                )
                if review.delivered_input_id is not None
                else None
            )
            references = tuple(
                self._get(connection, EvidenceReferenceRecord, reference_id)
                for reference_id in review.consumed_evidence_reference_ids
            )
            declarations = [
                artifact.get("review_input_declaration")
                for artifact in reviewer_evidence.artifacts
                if isinstance(artifact, dict)
                and "review_input_declaration" in artifact
            ]
            declaration_valid = False
            if delivered_input is not None and len(declarations) == 1:
                try:
                    validate_review_input_declaration(
                        declarations[0],
                        delivered_input.provider_input,
                        provider_input_digest=delivered_input.provider_input_digest,
                        review_disposition=cast(str, review.disposition),
                    )
                    declaration_valid = True
                except ValueError:
                    declaration_valid = False
            if (
                review.state != ReviewState.PENDING
                or review.disposition
                not in {
                    ReviewState.ACCEPTED,
                    ReviewState.REPAIR_REQUIRED,
                }
                or assignment.state != AssignmentState.REVIEW_REQUIRED
                or producer_evidence.state != EvidenceState.VALIDATED
                or producer_evidence.assignment_id
                != assignment.assignment_id
                or producer_evidence.attempt_id != review.attempt_id
                or reviewer_assignment.role != AssignmentRole.REVIEWER
                or not reviewer_assignment.read_only
                or reviewer_assignment.state
                != AssignmentState.REVIEW_REQUIRED
                or reviewer_attempt.assignment_id
                != reviewer_assignment.assignment_id
                or reviewer_attempt.state != AttemptState.COMPLETED
                or reviewer_evidence.assignment_id
                != reviewer_assignment.assignment_id
                or reviewer_evidence.attempt_id
                != reviewer_attempt.attempt_id
                or reviewer_evidence.state != EvidenceState.VALIDATED
                or reviewer_assignment.project_id != assignment.project_id
                or reviewer_assignment.charter_id != assignment.charter_id
                or reviewer_assignment.charter_revision
                != assignment.charter_revision
                or reviewer_assignment.usage_policy.get(
                    "review_of_assignment_id"
                )
                != assignment.assignment_id
                or reviewer_assignment.independence_key
                == assignment.independence_key
                or work_item.project_id != assignment.project_id
                or work_item.charter_id != assignment.charter_id
                or work_item.charter_revision != assignment.charter_revision
                or delivered_input is None
                or review.delivered_input_digest
                != delivered_input.delivered_input_digest
                or delivered_input.project_id != assignment.project_id
                or delivered_input.charter_id != assignment.charter_id
                or delivered_input.charter_revision
                != assignment.charter_revision
                or delivered_input.workflow_id
                != reviewer_assignment.workflow_id
                or delivered_input.work_item_id
                != reviewer_assignment.work_item_id
                or delivered_input.producer_assignment_id
                != assignment.assignment_id
                or delivered_input.producer_attempt_id
                != producer_evidence.attempt_id
                or delivered_input.reviewer_assignment_id
                != reviewer_assignment.assignment_id
                or reviewer_attempt.delivered_input_id
                != delivered_input.delivered_input_id
                or reviewer_attempt.delivered_input_digest
                != delivered_input.delivered_input_digest
                or reviewer_attempt.provider_input_digest
                != delivered_input.provider_input_digest
                or reviewer_evidence.delivered_input_id
                != delivered_input.delivered_input_id
                or reviewer_evidence.delivered_input_digest
                != delivered_input.delivered_input_digest
                or reviewer_evidence.provider_input_digest
                != delivered_input.provider_input_digest
                or not declaration_valid
                or tuple(
                    item["reference_id"]
                    for item in delivered_input.references
                )
                != review.consumed_evidence_reference_ids
                or tuple(item.revision for item in references)
                != review.consumed_evidence_reference_revisions
                or any(
                    reference.consumed_by_review_id != review.review_id
                    or reference.assignment_id
                    != reviewer_assignment.assignment_id
                    or reference.review_target_assignment_id
                    != assignment.assignment_id
                    or reference.producer_assignment_id
                    != assignment.assignment_id
                    or reference.producer_attempt_id
                    != producer_evidence.attempt_id
                    or reference.source_evidence_bundle_id
                    != producer_evidence.evidence_bundle_id
                    or reference.source_project_id != assignment.project_id
                    or reference.source_workflow_id != assignment.workflow_id
                    or reference.source_work_item_id != assignment.work_item_id
                    or reference.source_charter_id != assignment.charter_id
                    or reference.source_charter_revision
                    != assignment.charter_revision
                    or reference.sha256
                    != delivered_input.references[index]["sha256"]
                    or reference.revision
                    != delivered_input.references[index]["reference_revision"]
                    + 1
                    for index, reference in enumerate(references)
                )
            ):
                raise PermissionError("review decision binding changed")
            review_state = ReviewState(review.disposition)
            accepted = review_state == ReviewState.ACCEPTED
            assignment_state = (
                AssignmentState.COMPLETED
                if accepted
                else AssignmentState.REPAIR_REQUIRED
            )
            work_item_state = (
                WorkItemState.COMPLETED
                if accepted
                else WorkItemState.REPAIR_REQUIRED
            )
            updated_review = replace(
                review,
                state=review_state,
                updated_at=decided_at,
                revision=review.revision + 1,
            )
            updated_assignment = replace(
                assignment,
                state=assignment_state,
                updated_at=decided_at,
                revision=assignment.revision + 1,
            )
            updated_work_item = replace(
                work_item,
                state=work_item_state,
                updated_at=decided_at,
                revision=work_item.revision + 1,
            )
            updated_reviewer = replace(
                reviewer_assignment,
                state=AssignmentState.COMPLETED,
                updated_at=decided_at,
                revision=reviewer_assignment.revision + 1,
            )
            updated_reviewer_work_item = (
                updated_work_item
                if reviewer_work_item.work_item_id
                == updated_work_item.work_item_id
                else replace(
                    reviewer_work_item,
                    state=WorkItemState.COMPLETED,
                    updated_at=decided_at,
                    revision=reviewer_work_item.revision + 1,
                )
            )
            updated_workflow = None
            if accepted:
                work_items = self._workflow_items(connection, workflow)
                completed_items = {
                    updated_work_item.work_item_id: updated_work_item,
                    updated_reviewer_work_item.work_item_id: (
                        updated_reviewer_work_item
                    ),
                }
                if all(
                    completed_items.get(
                        item.work_item_id, item
                    ).state == WorkItemState.COMPLETED
                    for item in work_items
                ):
                    updated_workflow = replace(
                        workflow,
                        state=WorkflowState.COMPLETED,
                        updated_at=decided_at,
                        revision=workflow.revision + 1,
                    )
            self._replace(connection, updated_review, review.revision)
            self._replace(
                connection, updated_assignment, assignment.revision
            )
            self._replace(
                connection, updated_work_item, work_item.revision
            )
            self._replace(
                connection,
                updated_reviewer,
                reviewer_assignment.revision,
            )
            if (
                updated_reviewer_work_item.work_item_id
                != updated_work_item.work_item_id
            ):
                self._replace(
                    connection, updated_reviewer_work_item,
                    reviewer_work_item.revision,
                )
            if updated_workflow is not None:
                self._replace(
                    connection,
                    updated_workflow,
                    workflow.revision,
                )
        return updated_review, updated_assignment, updated_work_item

    def mark_authority_reservation_in_flight(
        self,
        attempt_id: str,
        reservation_plan_digest: str,
        updated_at: str,
    ) -> AttemptRecord:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            if (
                attempt.state != AttemptState.RESERVED
                or assignment.state != AssignmentState.READY
                or attempt.authority_reservation_state != "LOCAL_PREPARED"
                or attempt.authority_reservation_plan_digest
                != reservation_plan_digest
                or not attempt.session_slot_claimed
            ):
                raise PermissionError(
                    "Authority reservation preparation changed"
                )
            updated = replace(
                attempt,
                authority_reservation_state="RESERVATION_IN_FLIGHT",
                updated_at=updated_at,
                revision=attempt.revision + 1,
            )
            self._replace(connection, updated, attempt.revision)
        return updated

    def mark_authority_reserved(
        self,
        attempt_id: str,
        reservation_plan_digest: str,
        updated_at: str,
    ) -> AttemptRecord:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            if (
                attempt.state != AttemptState.RESERVED
                or assignment.state != AssignmentState.READY
                or attempt.authority_reservation_state
                != "RESERVATION_IN_FLIGHT"
                or attempt.authority_reservation_plan_digest
                != reservation_plan_digest
            ):
                raise PermissionError(
                    "Authority reservation completion changed"
                )
            updated = replace(
                attempt,
                authority_reservation_state="AUTHORITY_RESERVED",
                updated_at=updated_at,
                revision=attempt.revision + 1,
            )
            self._replace(connection, updated, attempt.revision)
        return updated

    def bind_authority_authorization(
        self,
        attempt_id: str,
        *,
        launch_token: str,
        launch_plan_digest: str,
        delivered_input: DeliveredInputRecord | None,
        updated_at: str,
    ) -> AttemptRecord:
        if not launch_token or len(launch_plan_digest) != 64:
            raise ValueError("Authority launch authorization is invalid")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            if (
                attempt.state != AttemptState.RESERVED
                or assignment.state != AssignmentState.READY
                or attempt.authority_reservation_state
                != "AUTHORITY_RESERVED"
                or not attempt.session_slot_claimed
            ):
                raise PermissionError(
                    "Authority launch authorization cannot be bound"
                )
            delivered_input_id: str | None = None
            delivered_input_digest: str | None = None
            provider_input_digest: str | None = None
            if delivered_input is not None:
                if (
                    assignment.role != AssignmentRole.REVIEWER
                    or delivered_input.reviewer_attempt_id
                    != attempt.attempt_id
                    or delivered_input.reviewer_assignment_id
                    != assignment.assignment_id
                    or delivered_input.project_id != assignment.project_id
                    or delivered_input.charter_id != assignment.charter_id
                    or delivered_input.charter_revision
                    != assignment.charter_revision
                    or delivered_input.workflow_id
                    != assignment.workflow_id
                    or delivered_input.work_item_id
                    != assignment.work_item_id
                ):
                    raise PermissionError(
                        "attempt delivered-input binding is invalid"
                    )
                delivered_input_id = delivered_input.delivered_input_id
                delivered_input_digest = (
                    delivered_input.delivered_input_digest
                )
                provider_input_digest = delivered_input.provider_input_digest
            updated = replace(
                attempt,
                launch_token=launch_token,
                launch_plan_digest=launch_plan_digest,
                authority_reservation_state="AUTHORIZED",
                updated_at=updated_at,
                revision=attempt.revision + 1,
                delivered_input_id=delivered_input_id,
                delivered_input_digest=delivered_input_digest,
                provider_input_digest=provider_input_digest,
            )
            if delivered_input is not None:
                self._insert(connection, delivered_input)
            self._replace(connection, updated, attempt.revision)
            try:
                cursor = connection.execute(
                    "UPDATE pass_b_launch_claims SET launch_token=?,"
                    "updated_at=? WHERE attempt_id=? AND assignment_id=? "
                    "AND authority_attempt_id=? AND state='RESERVED'",
                    (
                        launch_token,
                        updated_at,
                        attempt.attempt_id,
                        attempt.assignment_id,
                        attempt.authority_attempt_id,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "Authority launch token was already consumed"
                ) from error
            if cursor.rowcount != 1:
                raise PermissionError(
                    "durable launch claim changed before authorization"
                )
        return updated

    def mark_authority_reservation_uncertain(
        self,
        attempt_id: str,
        *,
        detail: str,
        updated_at: str,
    ) -> AttemptRecord:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            if (
                attempt.state != AttemptState.RESERVED
                or assignment.state != AssignmentState.READY
                or attempt.authority_reservation_state
                not in {"RESERVATION_IN_FLIGHT", "AUTHORITY_RESERVED"}
            ):
                raise PermissionError(
                    "Authority reservation uncertainty claim changed"
                )
            uncertain_attempt = replace(
                attempt,
                state=AttemptState.UNCERTAIN,
                last_error=detail,
                uncertainty_kind="AUTHORITY_RESERVATION_OUTCOME_AMBIGUOUS",
                updated_at=updated_at,
                revision=attempt.revision + 1,
            )
            uncertain_assignment = replace(
                assignment,
                state=AssignmentState.UNCERTAIN,
                updated_at=updated_at,
                revision=assignment.revision + 1,
            )
            self._replace(
                connection, uncertain_attempt, attempt.revision
            )
            self._replace(
                connection, uncertain_assignment, assignment.revision
            )
            workspace_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND state='ACTIVE'",
                (WorkspaceReservationRecord.KIND,),
            ).fetchall()
            for row in workspace_rows:
                workspace = self._decode(WorkspaceReservationRecord, row)
                if workspace.assignment_id != assignment.assignment_id:
                    continue
                self._replace(
                    connection,
                    replace(
                        workspace,
                        state=ReservationState.UNCERTAIN,
                        updated_at=updated_at,
                        revision=workspace.revision + 1,
                    ),
                    workspace.revision,
                )
                connection.execute(
                    "UPDATE pass_b_workspace_claims SET state='UNCERTAIN' "
                    "WHERE reservation_id=? AND state='ACTIVE'",
                    (workspace.workspace_reservation_id,),
                )
            write_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND state='ACTIVE'",
                (WriteReservationRecord.KIND,),
            ).fetchall()
            for row in write_rows:
                write = self._decode(WriteReservationRecord, row)
                if write.assignment_id != assignment.assignment_id:
                    continue
                self._replace(
                    connection,
                    replace(
                        write,
                        state=ReservationState.UNCERTAIN,
                        updated_at=updated_at,
                        revision=write.revision + 1,
                    ),
                    write.revision,
                )
                connection.execute(
                    "UPDATE pass_b_write_claims SET state='UNCERTAIN' "
                    "WHERE reservation_id=? AND state='ACTIVE'",
                    (write.workspace_reservation_id,),
                )
            cursor = connection.execute(
                "UPDATE pass_b_launch_claims SET state='UNCERTAIN',"
                "updated_at=? WHERE attempt_id=? AND state='RESERVED'",
                (updated_at, attempt.attempt_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError(
                    "Authority reservation launch claim changed"
                )
        return uncertain_attempt

    def require_active_launch_ownership(
        self,
        attempt_id: str,
        *,
        expected_claim_state: str,
        checked_at: str,
    ) -> None:
        if expected_claim_state not in {
            AttemptState.RESERVED,
            AttemptState.LAUNCH_CLAIMED,
        }:
            raise ValueError("unsupported launch ownership state")
        checked = _parse_time(checked_at)
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            workspace = self._active_workspace(
                connection, assignment.assignment_id
            )
            claim = connection.execute(
                "SELECT state,authority_attempt_id FROM pass_b_launch_claims "
                "WHERE attempt_id=? AND assignment_id=?",
                (attempt.attempt_id, assignment.assignment_id),
            ).fetchone()
            expected_assignment_state = (
                AssignmentState.READY
                if expected_claim_state == AttemptState.RESERVED
                else AssignmentState.LAUNCH_CLAIMED
            )
            expected_authority_state = (
                "RESERVATION_IN_FLIGHT"
                if expected_claim_state == AttemptState.RESERVED
                else "AUTHORIZED"
            )
            if (
                attempt.state != expected_claim_state
                or assignment.state != expected_assignment_state
                or attempt.authority_reservation_state
                != expected_authority_state
                or not attempt.session_slot_claimed
                or workspace.workspace_reservation_id
                != attempt.workspace_reservation_id
                or workspace.workspace_id != assignment.workspace_id
                or workspace.state != ReservationState.ACTIVE
                or _parse_time(workspace.lease_expires_at) <= checked
                or claim is None
                or str(claim["state"]) != expected_claim_state
                or str(claim["authority_attempt_id"])
                != attempt.authority_attempt_id
            ):
                raise PermissionError(
                    "durable launch ownership is no longer active"
                )
            if not assignment.read_only:
                write = connection.execute(
                    "SELECT lease_expires_at FROM pass_b_write_claims "
                    "WHERE reservation_id=? AND assignment_id=? "
                    "AND state='ACTIVE'",
                    (
                        workspace.workspace_reservation_id,
                        assignment.assignment_id,
                    ),
                ).fetchone()
                if (
                    write is None
                    or _parse_time(str(write["lease_expires_at"])) <= checked
                ):
                    raise PermissionError(
                        "durable write ownership is no longer active"
                    )
            if bool(
                assignment.usage_policy.get("reservation_required", True)
            ):
                usage = connection.execute(
                    "SELECT reservation_id,amount "
                    "FROM pass_b_usage_reservations "
                    "WHERE assignment_id=? AND state='ACTIVE'",
                    (assignment.assignment_id,),
                ).fetchone()
                requested = assignment.usage_policy.get("requested_amount")
                if (
                    usage is None
                    or str(usage["reservation_id"])
                    != attempt.usage_reservation_id
                    or (
                        isinstance(requested, (int, float))
                        and (
                            not math.isfinite(float(requested))
                            or float(usage["amount"])
                            != float(requested)
                        )
                    )
                ):
                    raise PermissionError(
                        "durable usage ownership is no longer exact"
                    )

    def claim_launch(self, attempt_id: str, claimed_at: str) -> AttemptRecord:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            if (
                attempt.state != AttemptState.RESERVED
                or assignment.state != AssignmentState.READY
            ):
                raise PermissionError("attempt launch claim was already consumed")
            updated_attempt = replace(
                attempt,
                state=AttemptState.LAUNCH_CLAIMED,
                updated_at=claimed_at,
                revision=attempt.revision + 1,
            )
            updated_assignment = replace(
                assignment,
                state=AssignmentState.LAUNCH_CLAIMED,
                updated_at=claimed_at,
                revision=assignment.revision + 1,
            )
            self._replace(connection, updated_attempt, attempt.revision)
            self._replace(connection, updated_assignment, assignment.revision)
            cursor = connection.execute(
                "UPDATE pass_b_launch_claims SET state='LAUNCH_CLAIMED',updated_at=? "
                "WHERE attempt_id=? AND state='RESERVED'",
                (claimed_at, attempt_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError("durable launch claim changed concurrently")
        return updated_attempt

    def mark_running(
        self, attempt_id: str, external_execution_id: str, started_at: str
    ) -> AttemptRecord:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            work_item = self._get(
                connection, WorkItemRecord, assignment.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, assignment.workflow_id
            )
            _validate_assignment_binding(workflow, work_item, assignment)
            session = self._get(
                connection, ProviderSessionRecord, assignment.session_id
            )
            if (
                attempt.state != AttemptState.LAUNCH_CLAIMED
                or assignment.state != AssignmentState.LAUNCH_CLAIMED
                or not attempt.session_slot_claimed
                or session.active_assignments < 1
            ):
                raise PermissionError("attempt cannot cross the launch boundary")
            updated_attempt = replace(
                attempt,
                state=AttemptState.RUNNING,
                external_execution_id=external_execution_id,
                started_at=started_at,
                updated_at=started_at,
                revision=attempt.revision + 1,
            )
            updated_assignment = replace(
                assignment,
                state=AssignmentState.RUNNING,
                updated_at=started_at,
                revision=assignment.revision + 1,
            )
            self._replace(connection, updated_attempt, attempt.revision)
            self._replace(connection, updated_assignment, assignment.revision)
            cursor = connection.execute(
                "UPDATE pass_b_launch_claims SET state='RUNNING',updated_at=? "
                "WHERE attempt_id=? AND state='LAUNCH_CLAIMED'",
                (started_at, attempt_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError("launch boundary changed concurrently")
        return updated_attempt

    def claim_cancellation(
        self, assignment_id: str, claimed_at: str
    ) -> AttemptRecord:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT attempt_id FROM pass_b_launch_claims "
                "WHERE assignment_id=? AND state='RUNNING'",
                (assignment_id,),
            ).fetchone()
            if row is None:
                raise PermissionError("assignment has no cancelable running attempt")
            attempt = self._get(
                connection, AttemptRecord, str(row["attempt_id"])
            )
            assignment = self._get(
                connection, AssignmentRecord, assignment_id
            )
            if (
                attempt.state != AttemptState.RUNNING
                or assignment.state != AssignmentState.RUNNING
                or not attempt.external_execution_id
            ):
                raise PermissionError("running attempt cancellation claim changed")
            updated_attempt = replace(
                attempt,
                state=AttemptState.CANCELLATION_CLAIMED,
                cancellation_requested_at=claimed_at,
                updated_at=claimed_at,
                revision=attempt.revision + 1,
            )
            updated_assignment = replace(
                assignment,
                state=AssignmentState.CANCELLATION_CLAIMED,
                updated_at=claimed_at,
                revision=assignment.revision + 1,
            )
            self._replace(connection, updated_attempt, attempt.revision)
            self._replace(connection, updated_assignment, assignment.revision)
        return updated_attempt

    def mark_cancellation_uncertain(
        self,
        attempt_id: str,
        *,
        detail: str,
        updated_at: str,
    ) -> AttemptRecord:
        """Preserve every claimed resource after an ambiguous cancel effect."""

        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            if (
                attempt.state != AttemptState.CANCELLATION_CLAIMED
                or assignment.state
                != AssignmentState.CANCELLATION_CLAIMED
            ):
                raise PermissionError(
                    "cancellation uncertainty claim changed concurrently"
                )
            uncertain_attempt = replace(
                attempt,
                state=AttemptState.UNCERTAIN,
                last_error=detail,
                uncertainty_kind="CANCELLATION_OUTCOME_AMBIGUOUS",
                updated_at=updated_at,
                revision=attempt.revision + 1,
            )
            uncertain_assignment = replace(
                assignment,
                state=AssignmentState.UNCERTAIN,
                updated_at=updated_at,
                revision=assignment.revision + 1,
            )
            self._replace(connection, uncertain_attempt, attempt.revision)
            self._replace(
                connection, uncertain_assignment, assignment.revision
            )
            workspace_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND state='ACTIVE'",
                (WorkspaceReservationRecord.KIND,),
            ).fetchall()
            for row in workspace_rows:
                workspace = self._decode(
                    WorkspaceReservationRecord, row
                )
                if workspace.assignment_id != assignment.assignment_id:
                    continue
                self._replace(
                    connection,
                    replace(
                        workspace,
                        state=ReservationState.UNCERTAIN,
                        updated_at=updated_at,
                        revision=workspace.revision + 1,
                    ),
                    workspace.revision,
                )
            write_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND state='ACTIVE'",
                (WriteReservationRecord.KIND,),
            ).fetchall()
            for row in write_rows:
                write = self._decode(WriteReservationRecord, row)
                if write.assignment_id != assignment.assignment_id:
                    continue
                self._replace(
                    connection,
                    replace(
                        write,
                        state=ReservationState.UNCERTAIN,
                        updated_at=updated_at,
                        revision=write.revision + 1,
                    ),
                    write.revision,
                )
            cursor = connection.execute(
                "UPDATE pass_b_launch_claims "
                "SET state='UNCERTAIN',updated_at=? "
                "WHERE attempt_id=? AND state='RUNNING'",
                (updated_at, attempt.attempt_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError(
                    "cancellation launch claim changed concurrently"
                )
            connection.execute(
                "UPDATE pass_b_workspace_claims SET state='UNCERTAIN' "
                "WHERE assignment_id=? AND state='ACTIVE'",
                (assignment.assignment_id,),
            )
            connection.execute(
                "UPDATE pass_b_write_claims SET state='UNCERTAIN' "
                "WHERE assignment_id=? AND state='ACTIVE'",
                (assignment.assignment_id,),
            )
        return uncertain_attempt

    def reconcile_uncertain_cancellation(
        self,
        record: UncertaintyReconciliationRecord,
    ) -> AttemptRecord:
        """Apply one exact Founder-approved confirmed-cancel decision."""

        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(
                connection, AttemptRecord, record.attempt_id
            )
            assignment = self._get(
                connection, AssignmentRecord, record.assignment_id
            )
            work_item = self._get(
                connection, WorkItemRecord, record.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, record.workflow_id
            )
            _validate_assignment_binding(workflow, work_item, assignment)
            session = self._get(
                connection, ProviderSessionRecord, assignment.session_id
            )
            workspace_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND state='UNCERTAIN'",
                (WorkspaceReservationRecord.KIND,),
            ).fetchall()
            workspaces: list[WorkspaceReservationRecord] = []
            for row in workspace_rows:
                workspace = self._decode(WorkspaceReservationRecord, row)
                if workspace.assignment_id == assignment.assignment_id:
                    workspaces.append(workspace)
            reconciliation_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=?",
                (UncertaintyReconciliationRecord.KIND,),
            ).fetchall()
            existing: list[UncertaintyReconciliationRecord] = []
            for row in reconciliation_rows:
                reconciliation = self._decode(
                    UncertaintyReconciliationRecord, row
                )
                if reconciliation.attempt_id == attempt.attempt_id:
                    existing.append(reconciliation)
            if (
                attempt.assignment_id != assignment.assignment_id
                or attempt.state != AttemptState.UNCERTAIN
                or assignment.state != AssignmentState.UNCERTAIN
                or attempt.uncertainty_kind
                != "CANCELLATION_OUTCOME_AMBIGUOUS"
                or attempt.external_execution_id
                != record.external_execution_id
                or len(workspaces) != 1
                or workspaces[0].workspace_reservation_id
                != record.workspace_reservation_id
                or workspaces[0].canonical_path
                != record.canonical_workspace_path
                or record.project_id != assignment.project_id
                or record.charter_id != assignment.charter_id
                or record.charter_revision != assignment.charter_revision
                or record.workflow_id != assignment.workflow_id
                or record.work_item_id != assignment.work_item_id
                or record.provider_id != assignment.provider_id
                or record.account_id != assignment.account_id
                or record.session_id != assignment.session_id
                or record.model_id != assignment.model_id
                or record.authority_attempt_id
                != attempt.authority_attempt_id
                or record.launch_token != attempt.launch_token
                or not attempt.session_slot_claimed
                or session.active_assignments < 1
                or existing
            ):
                raise PermissionError(
                    "uncertain cancellation reconciliation binding is invalid"
                )
            remaining = max(0, session.active_assignments - 1)
            updated_attempt = replace(
                attempt,
                state=AttemptState.CANCELED,
                finished_at=record.reconciled_at,
                last_error=None,
                updated_at=record.reconciled_at,
                revision=attempt.revision + 1,
            )
            updated_assignment = replace(
                assignment,
                state=AssignmentState.CANCELED,
                updated_at=record.reconciled_at,
                revision=assignment.revision + 1,
            )
            updated_session = replace(
                session,
                active_assignments=remaining,
                state=(
                    "BUSY"
                    if remaining >= session.concurrency_limit
                    else "READY"
                ),
                last_seen_at=record.reconciled_at,
                updated_at=record.reconciled_at,
                revision=session.revision + 1,
            )
            self._insert(connection, record)
            self._replace(connection, updated_attempt, attempt.revision)
            self._replace(
                connection, updated_assignment, assignment.revision
            )
            self._replace(connection, updated_session, session.revision)
            for workspace in workspaces:
                self._replace(
                    connection,
                    replace(
                        workspace,
                        state=ReservationState.ACTIVE,
                        updated_at=record.reconciled_at,
                        revision=workspace.revision + 1,
                    ),
                    workspace.revision,
                )
            write_rows = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind=? AND state='UNCERTAIN'",
                (WriteReservationRecord.KIND,),
            ).fetchall()
            for row in write_rows:
                write = self._decode(WriteReservationRecord, row)
                if write.assignment_id != assignment.assignment_id:
                    continue
                self._replace(
                    connection,
                    replace(
                        write,
                        state=ReservationState.ACTIVE,
                        updated_at=record.reconciled_at,
                        revision=write.revision + 1,
                    ),
                    write.revision,
                )
            cursor = connection.execute(
                "UPDATE pass_b_launch_claims "
                "SET state='CANCELED',updated_at=? "
                "WHERE attempt_id=? AND state='UNCERTAIN'",
                (record.reconciled_at, attempt.attempt_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError(
                    "uncertain cancellation launch claim changed"
                )
            connection.execute(
                "UPDATE pass_b_workspace_claims SET state='ACTIVE' "
                "WHERE assignment_id=? AND state='UNCERTAIN'",
                (assignment.assignment_id,),
            )
            connection.execute(
                "UPDATE pass_b_write_claims SET state='ACTIVE' "
                "WHERE assignment_id=? AND state='UNCERTAIN'",
                (assignment.assignment_id,),
            )
            self._consume_usage(
                connection,
                assignment.assignment_id,
                record.reconciled_at,
            )
        return updated_attempt

    def complete_cancellation(
        self, attempt_id: str, canceled_at: str
    ) -> AttemptRecord:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            work_item = self._get(
                connection, WorkItemRecord, assignment.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, assignment.workflow_id
            )
            _validate_assignment_binding(workflow, work_item, assignment)
            session = self._get(
                connection, ProviderSessionRecord, assignment.session_id
            )
            if (
                attempt.state != AttemptState.CANCELLATION_CLAIMED
                or assignment.state != AssignmentState.CANCELLATION_CLAIMED
            ):
                raise PermissionError("cancellation claim changed concurrently")
            remaining = max(0, session.active_assignments - 1)
            updated_attempt = replace(
                attempt,
                state=AttemptState.CANCELED,
                finished_at=canceled_at,
                updated_at=canceled_at,
                revision=attempt.revision + 1,
            )
            updated_assignment = replace(
                assignment,
                state=AssignmentState.CANCELED,
                updated_at=canceled_at,
                revision=assignment.revision + 1,
            )
            updated_session = replace(
                session,
                active_assignments=remaining,
                state="BUSY"
                if remaining >= session.concurrency_limit
                else "READY",
                last_seen_at=canceled_at,
                updated_at=canceled_at,
                revision=session.revision + 1,
            )
            self._replace(connection, updated_attempt, attempt.revision)
            self._replace(connection, updated_assignment, assignment.revision)
            self._replace(connection, updated_session, session.revision)
            cursor = connection.execute(
                "UPDATE pass_b_launch_claims SET state='CANCELED',updated_at=? "
                "WHERE attempt_id=? AND state='RUNNING'",
                (canceled_at, attempt_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError("durable cancellation claim changed")
            self._consume_usage(
                connection, assignment.assignment_id, canceled_at
            )
        return updated_attempt

    def complete_attempt(
        self,
        attempt_id: str,
        evidence: EvidenceBundleRecord,
        completed_at: str,
    ) -> AttemptRecord:
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._get(connection, AttemptRecord, attempt_id)
            assignment = self._get(
                connection, AssignmentRecord, attempt.assignment_id
            )
            work_item = self._get(
                connection, WorkItemRecord, assignment.work_item_id
            )
            workflow = self._get(
                connection, WorkflowRecord, assignment.workflow_id
            )
            _validate_assignment_binding(workflow, work_item, assignment)
            session = self._get(
                connection, ProviderSessionRecord, assignment.session_id
            )
            if (
                attempt.state != AttemptState.RUNNING
                or assignment.state != AssignmentState.RUNNING
                or evidence.attempt_id != attempt_id
                or evidence.assignment_id != assignment.assignment_id
                or evidence.state != EvidenceState.UNTRUSTED
            ):
                raise PermissionError("attempt completion binding is invalid")
            self._insert(connection, evidence)
            updated_attempt = replace(
                attempt,
                state=AttemptState.COMPLETED,
                finished_at=completed_at,
                updated_at=completed_at,
                revision=attempt.revision + 1,
            )
            updated_assignment = replace(
                assignment,
                state=AssignmentState.REVIEW_REQUIRED,
                updated_at=completed_at,
                revision=assignment.revision + 1,
            )
            updated_session = replace(
                session,
                active_assignments=max(0, session.active_assignments - 1),
                state="READY",
                last_seen_at=completed_at,
                updated_at=completed_at,
                revision=session.revision + 1,
            )
            self._replace(connection, updated_attempt, attempt.revision)
            self._replace(connection, updated_assignment, assignment.revision)
            self._replace(connection, updated_session, session.revision)
            connection.execute(
                "UPDATE pass_b_launch_claims SET state='COMPLETED',updated_at=? "
                "WHERE attempt_id=? AND state='RUNNING'",
                (completed_at, attempt_id),
            )
            self._consume_usage(connection, assignment.assignment_id, completed_at)
        return updated_attempt

    def recover_interrupted_attempts(self, recovered_at: str) -> dict[str, int]:
        result = {"prelaunch_released": 0, "uncertain": 0}
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            claims = connection.execute(
                "SELECT attempt_id,state FROM pass_b_launch_claims "
                "WHERE state IN "
                "('RESERVED','LAUNCH_CLAIMED','RUNNING')"
            ).fetchall()
            for claim in claims:
                attempt = self._get(
                    connection, AttemptRecord, str(claim["attempt_id"])
                )
                assignment = self._get(
                    connection, AssignmentRecord, attempt.assignment_id
                )
                state = str(claim["state"])
                if (
                    state == AttemptState.RESERVED
                    and attempt.authority_reservation_state
                    == "LOCAL_PREPARED"
                ):
                    session = self._get(
                        connection,
                        ProviderSessionRecord,
                        assignment.session_id,
                    )
                    self._replace(
                        connection,
                        replace(
                            attempt,
                            state=AttemptState.FAILED,
                            finished_at=recovered_at,
                            last_error="recovered before external launch",
                            updated_at=recovered_at,
                            revision=attempt.revision + 1,
                        ),
                        attempt.revision,
                    )
                    if attempt.session_slot_claimed:
                        remaining = max(
                            0, session.active_assignments - 1
                        )
                        self._replace(
                            connection,
                            replace(
                                session,
                                active_assignments=remaining,
                                state=(
                                    "BUSY"
                                    if remaining
                                    >= session.concurrency_limit
                                    else "READY"
                                ),
                                last_seen_at=recovered_at,
                                updated_at=recovered_at,
                                revision=session.revision + 1,
                            ),
                            session.revision,
                        )
                    connection.execute(
                        "UPDATE pass_b_launch_claims "
                        "SET state='FAILED',updated_at=? WHERE attempt_id=?",
                        (recovered_at, attempt.attempt_id),
                    )
                    result["prelaunch_released"] += 1
                    continue
                uncertain_attempt = replace(
                    attempt,
                    state=AttemptState.UNCERTAIN,
                    last_error=(
                        "cancellation outcome is uncertain after restart"
                        if attempt.state
                        == AttemptState.CANCELLATION_CLAIMED
                        else "external execution outcome is uncertain after restart"
                    ),
                    uncertainty_kind=(
                        "CANCELLATION_OUTCOME_AMBIGUOUS"
                        if attempt.state
                        == AttemptState.CANCELLATION_CLAIMED
                        else "EXTERNAL_EXECUTION_OUTCOME_AMBIGUOUS"
                    ),
                    updated_at=recovered_at,
                    revision=attempt.revision + 1,
                    session_slot_claimed=(
                        attempt.session_slot_claimed
                        or state == AttemptState.LAUNCH_CLAIMED
                    ),
                )
                uncertain_assignment = replace(
                    assignment,
                    state=AssignmentState.UNCERTAIN,
                    updated_at=recovered_at,
                    revision=assignment.revision + 1,
                )
                self._replace(connection, uncertain_attempt, attempt.revision)
                self._replace(connection, uncertain_assignment, assignment.revision)
                if (
                    state == AttemptState.LAUNCH_CLAIMED
                    and not attempt.session_slot_claimed
                ):
                    session = self._get(
                        connection,
                        ProviderSessionRecord,
                        assignment.session_id,
                    )
                    if session.active_assignments >= session.concurrency_limit:
                        raise RuntimeError(
                            "legacy uncertain launch exceeds session capacity"
                        )
                    self._replace(
                        connection,
                        replace(
                            session,
                            active_assignments=session.active_assignments + 1,
                            state="BUSY",
                            last_seen_at=recovered_at,
                            updated_at=recovered_at,
                            revision=session.revision + 1,
                        ),
                        session.revision,
                    )
                workspace_rows = connection.execute(
                    "SELECT payload,payload_hash FROM pass_b_records "
                    "WHERE kind=? AND state='ACTIVE'",
                    (WorkspaceReservationRecord.KIND,),
                ).fetchall()
                for row in workspace_rows:
                    workspace = self._decode(WorkspaceReservationRecord, row)
                    if workspace.assignment_id == assignment.assignment_id:
                        self._replace(
                            connection,
                            replace(
                                workspace,
                                state=ReservationState.UNCERTAIN,
                                updated_at=recovered_at,
                                revision=workspace.revision + 1,
                            ),
                            workspace.revision,
                        )
                write_rows = connection.execute(
                    "SELECT payload,payload_hash FROM pass_b_records "
                    "WHERE kind=? AND state='ACTIVE'",
                    (WriteReservationRecord.KIND,),
                ).fetchall()
                for row in write_rows:
                    write = self._decode(WriteReservationRecord, row)
                    if write.assignment_id == assignment.assignment_id:
                        self._replace(
                            connection,
                            replace(
                                write,
                                state=ReservationState.UNCERTAIN,
                                updated_at=recovered_at,
                                revision=write.revision + 1,
                            ),
                            write.revision,
                        )
                connection.execute(
                    "UPDATE pass_b_launch_claims "
                    "SET state='UNCERTAIN',updated_at=? WHERE attempt_id=?",
                    (recovered_at, attempt.attempt_id),
                )
                connection.execute(
                    "UPDATE pass_b_workspace_claims SET state='UNCERTAIN' "
                    "WHERE assignment_id=? AND state='ACTIVE'",
                    (assignment.assignment_id,),
                )
                connection.execute(
                    "UPDATE pass_b_write_claims SET state='UNCERTAIN' "
                    "WHERE assignment_id=? AND state='ACTIVE'",
                    (assignment.assignment_id,),
                )
                result["uncertain"] += 1
        return result

    def usage_reservations(
        self, assignment_id: str
    ) -> builtins.list[dict[str, Any]]:
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM pass_b_usage_reservations "
                "WHERE assignment_id=? ORDER BY reserved_at",
                (assignment_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def launch_claim(self, attempt_id: str) -> dict[str, Any]:
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT * FROM pass_b_launch_claims WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"launch claim not found: {attempt_id}")
        return dict(row)

    def _active_workspace(
        self, connection: sqlite3.Connection, assignment_id: str
    ) -> WorkspaceReservationRecord:
        rows = connection.execute(
            "SELECT r.payload,r.payload_hash FROM pass_b_workspace_claims AS c "
            "JOIN pass_b_records AS r "
            "ON r.kind=? AND r.id=c.reservation_id "
            "WHERE c.assignment_id=? AND c.state='ACTIVE'",
            (WorkspaceReservationRecord.KIND, assignment_id),
        ).fetchall()
        if len(rows) != 1:
            raise PermissionError("assignment needs one active workspace")
        return self._decode(WorkspaceReservationRecord, rows[0])

    def _consume_usage(
        self,
        connection: sqlite3.Connection,
        assignment_id: str,
        completed_at: str,
    ) -> None:
        row = connection.execute(
            "SELECT reservation_id,pool_id,amount FROM pass_b_usage_reservations "
            "WHERE assignment_id=? AND state='ACTIVE'",
            (assignment_id,),
        ).fetchone()
        if row is None:
            return
        pool = self._get(connection, UsagePoolRecord, str(row["pool_id"]))
        amount = float(row["amount"])
        updated = replace(
            pool,
            reserved=max(0.0, pool.reserved - amount),
            consumed=pool.consumed + amount,
            updated_at=completed_at,
            last_observed_at=completed_at,
            revision=pool.revision + 1,
        )
        self._replace(connection, updated, pool.revision)
        connection.execute(
            "UPDATE pass_b_usage_reservations "
            "SET state='CONSUMED',updated_at=? WHERE reservation_id=?",
            (completed_at, str(row["reservation_id"])),
        )

    def _insert(
        self, connection: sqlite3.Connection, record: PassBRecord
    ) -> None:
        payload = record.to_dict()
        serialized, digest = _serialize(payload)
        created_at = str(payload.get("created_at") or payload["updated_at"])
        updated_at = str(payload.get("updated_at") or created_at)
        project_id = payload.get("project_id")
        state = str(payload.get("state") or "")
        revision = int(payload["revision"])
        try:
            connection.execute(
                "INSERT INTO pass_b_records("
                "kind,id,project_id,state,revision,created_at,updated_at,"
                "payload,payload_hash) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    record.KIND,
                    record.record_id,
                    project_id,
                    state,
                    revision,
                    created_at,
                    updated_at,
                    serialized,
                    digest,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise PermissionError(
                f"durable {record.KIND} identity already exists"
            ) from error

    def _replace(
        self,
        connection: sqlite3.Connection,
        record: PassBRecord,
        expected_revision: int,
    ) -> None:
        if record.to_dict()["revision"] != expected_revision + 1:
            raise ValueError("replacement revision must advance exactly once")
        current = connection.execute(
            "SELECT payload_hash,revision FROM pass_b_records "
            "WHERE kind=? AND id=?",
            (record.KIND, record.record_id),
        ).fetchone()
        if current is None:
            raise KeyError(f"{record.KIND} not found: {record.record_id}")
        if int(current["revision"]) != expected_revision:
            raise PermissionError("durable record changed concurrently")
        payload = record.to_dict()
        serialized, digest = _serialize(payload)
        state = str(payload.get("state") or "")
        updated_at = str(
            payload.get("updated_at")
            or payload.get("resumed_at")
            or payload.get("resolved_at")
            or payload.get("created_at")
        )
        cursor = connection.execute(
            "UPDATE pass_b_records SET state=?,revision=?,updated_at=?,"
            "payload=?,payload_hash=? "
            "WHERE kind=? AND id=? AND revision=? AND payload_hash=?",
            (
                state,
                expected_revision + 1,
                updated_at,
                serialized,
                digest,
                record.KIND,
                record.record_id,
                expected_revision,
                str(current["payload_hash"]),
            ),
        )
        if cursor.rowcount != 1:
            raise PermissionError("durable record CAS was rejected")

    def _get(
        self, connection: sqlite3.Connection, record_type: type[R], record_id: str
    ) -> R:
        row = connection.execute(
            "SELECT payload,payload_hash FROM pass_b_records "
            "WHERE kind=? AND id=?",
            (record_type.KIND, record_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"{record_type.KIND} not found: {record_id}")
        return self._decode(record_type, row)

    def _active_writes(
        self,
        connection: sqlite3.Connection,
        workspace_reservation_id: str,
    ) -> builtins.list[WriteReservationRecord]:
        rows = connection.execute(
            "SELECT payload,payload_hash FROM pass_b_records "
            "WHERE kind=? AND state='ACTIVE'",
            (WriteReservationRecord.KIND,),
        ).fetchall()
        return [
            record
            for row in rows
            if (
                record := self._decode(WriteReservationRecord, row)
            ).workspace_reservation_id
            == workspace_reservation_id
        ]

    @staticmethod
    def _workflow_items(
        connection: sqlite3.Connection,
        workflow: WorkflowRecord,
    ) -> tuple[WorkItemRecord, ...]:
        rows = connection.execute(
            "SELECT payload,payload_hash FROM pass_b_records "
            "WHERE kind=? AND project_id=? ORDER BY created_at,id",
            (WorkItemRecord.KIND, workflow.project_id),
        ).fetchall()
        decoded = tuple(
            PassBRepository._decode(WorkItemRecord, row) for row in rows
        )
        items = tuple(
            item
            for item in decoded
            if item.workflow_id == workflow.workflow_id
        )
        if not items:
            raise RuntimeError("durable workflow has no work items")
        if any(
            item.project_id != workflow.project_id
            or item.charter_id != workflow.charter_id
            or item.charter_revision != workflow.charter_revision
            for item in items
        ):
            raise PermissionError(
                "workflow contains cross-project or cross-charter work"
            )
        return items

    @staticmethod
    def _decode(record_type: type[R], row: sqlite3.Row) -> R:
        serialized = str(row["payload"])
        if hashlib.sha256(serialized.encode("utf-8")).hexdigest() != str(
            row["payload_hash"]
        ):
            raise RuntimeError("Pass B durable record failed integrity validation")
        value = json.loads(serialized)
        if not isinstance(value, dict):
            raise RuntimeError("Pass B durable record is not an object")
        return record_type.from_dict(cast(dict[str, Any], value))


_PROTECTED_TREE_FRAGMENTS = (
    (".ai-workflow", "pilot-invocations"),
    (".ai-workflow", "pw"),
)


def validate_protected_workspace_tree(
    path: Path, *, require_exists: bool = True
) -> Path:
    """Return one safe canonical workspace tree or fail conservatively."""
    try:
        resolved = path.resolve(strict=require_exists)
    except (OSError, RuntimeError) as error:
        raise PermissionError(
            "workspace path identity cannot be safely resolved"
        ) from error
    if require_exists and not resolved.is_dir():
        raise ValueError("workspace path must be an existing directory")
    if _is_protected_tree_path(resolved):
        raise PermissionError(
            "workspace overlaps protected Keeper pilot evidence "
            "or workflow state"
        )
    _reject_primary_repository(resolved)
    if not require_exists and not os.path.lexists(resolved):
        return resolved
    if not resolved.is_dir():
        raise ValueError("workspace path must be a directory")

    visited: set[str] = set()
    pending = [resolved]
    while pending:
        current = pending.pop()
        try:
            canonical_current = current.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise PermissionError(
                "workspace tree contains an unresolved path identity"
            ) from error
        key = _path_key(canonical_current)
        if key in visited:
            continue
        visited.add(key)
        if _is_protected_tree_path(canonical_current):
            raise PermissionError(
                "workspace contains protected Keeper pilot evidence "
                "or workflow state"
            )
        try:
            with os.scandir(canonical_current) as entries:
                for entry in entries:
                    candidate = Path(entry.path)
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                        is_reparse = bool(
                            getattr(entry_stat, "st_file_attributes", 0)
                            & getattr(os, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                        )
                        is_alias = entry.is_symlink() or is_reparse
                        is_directory = entry.is_dir(follow_symlinks=False)
                        if not is_directory and not is_alias:
                            continue
                        canonical_candidate = candidate.resolve(strict=True)
                    except (OSError, RuntimeError) as error:
                        raise PermissionError(
                            "workspace tree contains an unresolved alias"
                        ) from error
                    if _is_protected_tree_path(canonical_candidate):
                        raise PermissionError(
                            "workspace contains protected Keeper pilot evidence "
                            "or workflow state"
                        )
                    if (
                        entry.name.casefold() == ".git"
                        and canonical_candidate.is_dir()
                    ):
                        raise PermissionError(
                            "primary repository cannot be a Keeper workspace"
                        )
                    if is_alias:
                        try:
                            canonical_candidate.relative_to(resolved)
                        except ValueError as error:
                            raise PermissionError(
                                "workspace alias escapes its canonical tree"
                            ) from error
                    if canonical_candidate.is_dir():
                        pending.append(canonical_candidate)
        except PermissionError:
            raise
        except OSError as error:
            raise PermissionError(
                "workspace tree cannot be safely inspected"
            ) from error
    return resolved


def canonical_workspace_path(path: Path) -> str:
    return _path_key(validate_protected_workspace_tree(path))


def canonical_evidence_reference_path(path: Path) -> str:
    resolved = path.resolve(strict=True)
    parts = tuple(item.casefold() for item in resolved.parts)
    if _contains_parts(parts, (".ai-workflow", "pw")):
        raise PermissionError("Keeper browser evidence reference is protected")
    if not _contains_parts(
        parts, (".ai-workflow", "pilot-invocations")
    ):
        raise PermissionError(
            "only explicit pilot evidence uses this read-only reference path"
        )
    return _path_key(resolved)


def canonical_scope(workspace_path: str, scope: str) -> str:
    normalized = scope.replace("\\", "/").strip("/")
    if not normalized or normalized == "." or ".." in normalized.split("/"):
        raise ValueError("write scope must be a contained relative path")
    root = validate_protected_workspace_tree(Path(workspace_path))
    candidate = (root / normalized).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise PermissionError(
            "write scope resolves outside the assigned workspace"
        ) from error
    if _is_protected_tree_path(candidate):
        raise PermissionError("write scope overlaps protected Keeper state")
    return _path_key(candidate)


def _path_key(path: Path) -> str:
    return str(path).replace("\\", "/").casefold()


def _contains_parts(
    parts: tuple[str, ...], fragment: tuple[str, ...]
) -> bool:
    return any(
        parts[index : index + len(fragment)] == fragment
        for index in range(max(0, len(parts) - len(fragment) + 1))
    )


def is_pilot_evidence_path(path: Path) -> bool:
    resolved = path.resolve(strict=False)
    parts = tuple(item.casefold() for item in resolved.parts)
    return _contains_parts(
        parts, (".ai-workflow", "pilot-invocations")
    )


def contains_pilot_evidence(path: Path) -> bool:
    resolved = path.resolve(strict=False)
    direct = resolved / ".ai-workflow" / "pilot-invocations"
    if direct.exists():
        return True
    if not resolved.is_dir():
        return False
    try:
        return any(
            candidate.exists()
            for candidate in resolved.glob(
                "**/.ai-workflow/pilot-invocations"
            )
        )
    except OSError:
        return True


def _is_protected_tree_path(path: Path) -> bool:
    parts = tuple(item.casefold() for item in path.parts)
    return any(
        _contains_parts(parts, fragment)
        for fragment in _PROTECTED_TREE_FRAGMENTS
    )


def _reject_primary_repository(path: Path) -> None:
    for ancestor in (path, *path.parents):
        marker = ancestor / ".git"
        try:
            if marker.is_dir():
                raise PermissionError(
                    "primary repository cannot be a Keeper workspace"
                )
            if marker.is_file():
                return
        except OSError as error:
            raise PermissionError(
                "repository identity cannot be safely inspected"
            ) from error


def _validate_workflow_work_item(
    workflow: WorkflowRecord, work_item: WorkItemRecord
) -> None:
    if (
        workflow.state != WorkflowState.ACTIVE
        or work_item.state not in {
            WorkItemState.PROPOSED,
            WorkItemState.READY,
            WorkItemState.ASSIGNED,
            WorkItemState.ACTIVE,
            WorkItemState.REVIEW_REQUIRED,
            WorkItemState.REPAIR_REQUIRED,
        }
        or work_item.workflow_id != workflow.workflow_id
        or work_item.project_id != workflow.project_id
        or work_item.charter_id != workflow.charter_id
        or work_item.charter_revision != workflow.charter_revision
    ):
        raise PermissionError(
            "work item is not bound to an active durable workflow"
        )


def _validate_execution_profile(
    workflow: WorkflowRecord,
    work_item: WorkItemRecord,
    profile: ExecutionProfileRecord,
) -> None:
    _validate_workflow_work_item(workflow, work_item)
    if (
        profile.workflow_id != workflow.workflow_id
        or profile.work_item_id != work_item.work_item_id
        or profile.project_id != workflow.project_id
        or profile.charter_id != workflow.charter_id
        or profile.charter_revision != workflow.charter_revision
        or profile.authority_envelope_digest
        != workflow.authority_envelope_digest
        or (
            work_item.required_roles
            and profile.role not in work_item.required_roles
        )
        or canonical_workspace_path(
            Path(profile.canonical_workspace_path)
        )
        != profile.canonical_workspace_path
        or tuple(
            canonical_scope(
                profile.canonical_workspace_path, item
            )
            for item in profile.write_scopes
        )
        != profile.write_scope_keys
    ):
        raise PermissionError(
            "execution profile is not bound to its durable work item"
        )


def _validate_assignment_binding(
    workflow: WorkflowRecord,
    work_item: WorkItemRecord,
    assignment: AssignmentRecord,
) -> None:
    _validate_workflow_work_item(workflow, work_item)
    if (
        assignment.workflow_id != workflow.workflow_id
        or assignment.work_item_id != work_item.work_item_id
        or assignment.project_id != workflow.project_id
        or assignment.charter_id != workflow.charter_id
        or assignment.charter_revision != workflow.charter_revision
        or assignment.authority_envelope_digest
        != workflow.authority_envelope_digest
        or (
            work_item.required_roles
            and assignment.role not in work_item.required_roles
            and not (
                assignment.role == AssignmentRole.REVIEWER
                and assignment.read_only
                and bool(
                    assignment.usage_policy.get("review_of_assignment_id")
                )
            )
        )
    ):
        raise PermissionError(
            "assignment binding mismatch: durable workflow or work item"
        )

def _path_overlap(left: str, right: str) -> bool:
    return (
        left == right
        or left.startswith(right.rstrip("/") + "/")
        or right.startswith(left.rstrip("/") + "/")
    )


def _scope_overlap(left: str, right: str) -> bool:
    return (
        left == right
        or left.startswith(right.rstrip("/") + "/")
        or right.startswith(left.rstrip("/") + "/")
    )


def _serialize(payload: dict[str, Any]) -> tuple[str, str]:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return serialized, hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone aware")
    return parsed


def _now() -> str:
    from datetime import UTC

    return datetime.now(UTC).isoformat()
