from __future__ import annotations

import copy
import pickle
from pathlib import Path
from typing import Any

import pytest

import keeper.authority_service.client as authority_client_module
from keeper.app.storage import KeeperStore
from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.executive.authority_gateway import (
    AuthorityProviderBinding,
    ProductionAuthorityBackedSpecialistGateway,
)
from keeper.executive.founder_auth import (
    ProductionFounderAuthenticator,
    TestFounderAuthenticator,
)
from keeper.executive.repository import (
    ExecutiveRepository,
    ProductionExecutiveRepository,
    TestExecutiveRepository,
)
from keeper.executive.runtime import ExecutiveRuntime
from keeper.executive.service import KeeperExecutive
from tests.keeper.executive.authority_semantics import semantic_gateway
from tests.keeper.executive.test_intake_charters import approved_project


class _ProductionRepositorySubclass(ProductionExecutiveRepository):
    __slots__ = ()


class _ProductionGatewaySubclass(
    ProductionAuthorityBackedSpecialistGateway
):
    __slots__ = ()


class _RepositoryDuck:
    pass


class _ExecutiveRuntimeSubclass(ExecutiveRuntime):
    __slots__ = ()


def _production_repository(
    root: Path, name: str
) -> tuple[ProductionExecutiveRepository, KeeperStore]:
    store = KeeperStore(root / f"{name}.db")
    store.migrate()
    repository = ProductionExecutiveRepository(
        store,
        ProductionFounderAuthenticator(root / f"{name}.dpapi"),
    )
    return repository, store


def _test_repository(root: Path, name: str) -> TestExecutiveRepository:
    store = KeeperStore(root / f"{name}.db")
    store.migrate()
    return TestExecutiveRepository(store, TestFounderAuthenticator())


def _production_gateway(
    root: Path, name: str
) -> tuple[
    ProductionAuthorityBackedSpecialistGateway,
    ProductionAuthorityServiceClient,
]:
    client = ProductionAuthorityServiceClient(timeout_seconds=0.01)
    gateway = ProductionAuthorityBackedSpecialistGateway(
        client,
        (
            AuthorityProviderBinding(
                f"registration-{name}", f"qualification-{name}"
            ),
        ),
        root / f"exchange-{name}",
    )
    return gateway, client


def _production_runtime(root: Path, name: str) -> ExecutiveRuntime:
    repository, _ = _production_repository(root, f"repository-{name}")
    gateway, _ = _production_gateway(root, f"gateway-{name}")
    return ExecutiveRuntime.production(repository, gateway)


def test_production_runtime_requires_exact_repository_and_gateway_types(
    tmp_path: Path,
) -> None:
    repository, store = _production_repository(tmp_path, "exact")
    gateway, _ = _production_gateway(tmp_path, "exact")
    test_repository = _test_repository(tmp_path, "test")

    with pytest.raises(RuntimeError, match="exact production repository"):
        ExecutiveRuntime.production(
            test_repository, gateway  # type: ignore[arg-type]
        )
    with pytest.raises(RuntimeError, match="exact production repository"):
        ExecutiveRuntime.production(
            object.__new__(ExecutiveRepository),  # type: ignore[arg-type]
            gateway
        )
    with pytest.raises(RuntimeError, match="exact production repository"):
        ExecutiveRuntime.production(
            _RepositoryDuck(), gateway  # type: ignore[arg-type]
        )

    derived_repository = _ProductionRepositorySubclass(
        store,
        ProductionFounderAuthenticator(tmp_path / "derived.dpapi"),
    )
    with pytest.raises(RuntimeError, match="exact production repository"):
        ExecutiveRuntime.production(derived_repository, gateway)

    derived_gateway = _ProductionGatewaySubclass(
        ProductionAuthorityServiceClient(timeout_seconds=0.01),
        (AuthorityProviderBinding("registration-derived", "qualification-derived"),),
        tmp_path / "exchange-derived",
    )
    with pytest.raises(RuntimeError, match="sealed production gateway"):
        ExecutiveRuntime.production(repository, derived_gateway)


def test_test_runtime_rejects_production_repository(tmp_path: Path) -> None:
    repository, _ = _production_repository(tmp_path, "production")
    gateway, _ = semantic_gateway(tmp_path)
    with pytest.raises(RuntimeError, match="exact test repository"):
        ExecutiveRuntime(repository, gateway)


def test_approved_test_repository_cannot_become_production_input(
    tmp_path: Path,
) -> None:
    test_service, project, charter = approved_project(tmp_path / "approved")
    assert test_service.repository.approvals(
        project.project_id, charter.revision
    )
    gateway, _ = _production_gateway(tmp_path, "approved-constructor")
    with pytest.raises(RuntimeError, match="exact production repository"):
        ExecutiveRuntime.production(
            test_service.repository,  # type: ignore[arg-type]
            gateway,
        )

    runtime = _production_runtime(tmp_path, "approved-substitution")
    object.__setattr__(
        runtime,
        "_ExecutiveRuntime__repository",
        test_service.repository,
    )
    with pytest.raises(RuntimeError, match="composition is invalid"):
        runtime.progress(project.project_id)


def test_production_runtime_exposes_no_dependency_surface_and_is_immutable(
    tmp_path: Path,
) -> None:
    runtime = _production_runtime(tmp_path, "sealed")
    gateway, _ = _production_gateway(tmp_path, "replacement")
    repository, _ = _production_repository(tmp_path, "replacement")

    assert not hasattr(runtime, "repository")
    assert not hasattr(runtime, "gateway")
    for name, value in (
        ("repository", repository),
        ("gateway", gateway),
        ("_repository", repository),
        ("_gateway", gateway),
        ("_ExecutiveRuntime__repository", repository),
        ("_ExecutiveRuntime__gateway", gateway),
    ):
        with pytest.raises(AttributeError, match="immutable"):
            setattr(runtime, name, value)


def test_production_gateway_dependencies_are_immutable(tmp_path: Path) -> None:
    gateway, client = _production_gateway(tmp_path, "sealed-gateway")
    for name, value in (
        ("_production_client", ProductionAuthorityServiceClient()),
        ("_authority", object()),
        ("_bindings", ()),
        ("_exchange_root", tmp_path / "other"),
        ("_ProductionAuthorityBackedSpecialistGateway__sealed", False),
    ):
        with pytest.raises(AttributeError, match="immutable"):
            setattr(gateway, name, value)
        with pytest.raises(AttributeError, match="immutable"):
            delattr(gateway, name)
    assert gateway._production_runtime_identity().client_identity == id(client)


@pytest.mark.parametrize(
    ("method_name", "arguments"),
    [
        ("progress", ("missing",)),
        ("pause", ("missing", "reason")),
        ("resume", ("missing",)),
        ("revoke_delegation", ("missing",)),
        ("cancel", ("missing",)),
    ],
)
def test_every_public_operation_revalidates_composition_before_state_access(
    tmp_path: Path,
    method_name: str,
    arguments: tuple[str, ...],
) -> None:
    runtime = _production_runtime(tmp_path, method_name)
    replacement = _test_repository(tmp_path, f"test-{method_name}")
    object.__setattr__(
        runtime, "_ExecutiveRuntime__repository", replacement
    )

    operation: Any = getattr(runtime, method_name)
    with pytest.raises(RuntimeError, match="composition is invalid"):
        operation(*arguments)


def test_forced_exact_repository_or_gateway_replacement_fails_closed(
    tmp_path: Path,
) -> None:
    runtime = _production_runtime(tmp_path, "forced")
    replacement_repository, _ = _production_repository(
        tmp_path, "forced-repository"
    )
    object.__setattr__(
        runtime,
        "_ExecutiveRuntime__repository",
        replacement_repository,
    )
    with pytest.raises(RuntimeError, match="composition is invalid"):
        runtime._validate_composition()

    runtime = _production_runtime(tmp_path, "forced-gateway-runtime")
    replacement_gateway, _ = _production_gateway(
        tmp_path, "forced-gateway"
    )
    object.__setattr__(
        runtime, "_ExecutiveRuntime__gateway", replacement_gateway
    )
    with pytest.raises(RuntimeError, match="composition is invalid"):
        runtime._validate_composition()


def test_repository_authenticator_and_database_tampering_fail_closed(
    tmp_path: Path,
) -> None:
    repository, _ = _production_repository(tmp_path, "repository-tamper")
    gateway, _ = _production_gateway(tmp_path, "repository-tamper")
    runtime = ExecutiveRuntime.production(repository, gateway)
    object.__setattr__(
        repository,
        "_ExecutiveRepository__founder_authenticator",
        TestFounderAuthenticator(),
    )
    with pytest.raises(RuntimeError, match="composition is invalid"):
        runtime._validate_composition()

    repository, _ = _production_repository(tmp_path, "database-tamper")
    other_repository, other_store = _production_repository(
        tmp_path, "other-database"
    )
    del other_repository
    runtime = ExecutiveRuntime.production(
        repository,
        _production_gateway(tmp_path, "database-tamper")[0],
    )
    object.__setattr__(
        repository, "_ExecutiveRepository__store", other_store
    )
    with pytest.raises(RuntimeError, match="composition is invalid"):
        runtime._validate_composition()


def test_injected_or_replaced_production_transport_fails_closed(
    tmp_path: Path,
) -> None:
    repository, _ = _production_repository(tmp_path, "transport")
    gateway, client = _production_gateway(tmp_path, "transport")
    runtime = ExecutiveRuntime.production(repository, gateway)

    client._test_transport = lambda _request: {}
    with pytest.raises(RuntimeError, match="composition is invalid"):
        runtime._validate_composition()

    repository, _ = _production_repository(tmp_path, "send")
    gateway, client = _production_gateway(tmp_path, "send")
    runtime = ExecutiveRuntime.production(repository, gateway)
    client._send = lambda _request: {}  # type: ignore[assignment]
    with pytest.raises(RuntimeError, match="composition is invalid"):
        runtime._validate_composition()


def test_runtime_reinitialization_copy_and_serialization_are_rejected(
    tmp_path: Path,
) -> None:
    runtime = _production_runtime(tmp_path, "lifecycle")
    test_repository = _test_repository(tmp_path, "lifecycle-test")
    test_gateway, _ = semantic_gateway(tmp_path)

    with pytest.raises(AttributeError, match="already initialized"):
        runtime.__init__(test_repository, test_gateway)  # type: ignore[misc]
    with pytest.raises(TypeError, match="copied"):
        copy.copy(runtime)
    with pytest.raises(TypeError, match="copied"):
        copy.deepcopy(runtime)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(runtime)


def test_production_facade_returns_a_validated_sealed_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ProductionAuthorityServiceClient,
        "require_live_identity",
        lambda _self: {
            "protocol_version": "2.0.0",
            "observer_available": True,
        },
    )
    executive = KeeperExecutive(tmp_path / "facade.db")
    client = ProductionAuthorityServiceClient(timeout_seconds=0.01)
    runtime = executive.production_runtime(
        client,
        provider_bindings=(
            AuthorityProviderBinding(
                "registration-facade", "qualification-facade"
            ),
        ),
        exchange_root=tmp_path / "exchange-facade",
    )

    runtime._validate_composition()
    assert not hasattr(runtime, "repository")
    with pytest.raises(AttributeError, match="immutable"):
        runtime.gateway = object()


def test_name_mangled_seal_attack_and_reinitialization_fail_closed(
    tmp_path: Path,
) -> None:
    runtime = _production_runtime(tmp_path, "seal-regression")
    test_service, project, _ = approved_project(tmp_path / "seal-test-state")
    test_gateway, _ = semantic_gateway(tmp_path)
    original_state = test_service.repository.project(project.project_id).state

    for name in ("__sealed", "_ExecutiveRuntime__sealed"):
        with pytest.raises(AttributeError, match="immutable"):
            setattr(runtime, name, False)
        with pytest.raises(AttributeError, match="immutable"):
            delattr(runtime, name)
        with pytest.raises(AttributeError):
            object.__setattr__(runtime, name, False)

    with pytest.raises(AttributeError, match="already initialized"):
        runtime.__init__(  # type: ignore[misc]
            test_service.repository, test_gateway
        )
    with pytest.raises(AttributeError, match="already initialized"):
        type(runtime).__init__(
            runtime, test_service.repository, test_gateway
        )

    runtime._validate_composition()
    assert test_service.repository.project(project.project_id).state == original_state


def test_class_level_production_transport_replacement_fails_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = _production_repository(tmp_path, "class-send")
    gateway, _ = _production_gateway(tmp_path, "class-send")
    runtime = ExecutiveRuntime.production(repository, gateway)
    original_send = ProductionAuthorityServiceClient.__dict__["_send"]
    replacement_executed = False

    def replacement_send(_self: object, _request: object) -> dict[str, Any]:
        nonlocal replacement_executed
        replacement_executed = True
        return {"impersonated": True}

    monkeypatch.setattr(
        ProductionAuthorityServiceClient, "_send", replacement_send
    )
    with pytest.raises(RuntimeError, match="composition is invalid"):
        runtime._validate_composition()
    with pytest.raises(PermissionError, match="transport implementation"):
        gateway._authority.diagnostics()
    assert replacement_executed is False

    monkeypatch.setattr(
        ProductionAuthorityServiceClient, "_send", original_send
    )
    runtime._validate_composition()


def test_supported_writes_do_not_require_an_external_lineage_commit(
    tmp_path: Path,
) -> None:
    repository, store = _production_repository(tmp_path, "sqlite-only")
    gateway, _ = _production_gateway(tmp_path, "sqlite-only")
    runtime = ExecutiveRuntime.production(repository, gateway)

    store.upsert("settings", "transaction-marker", {"generation": 2})
    assert store.get("settings", "transaction-marker") == {"generation": 2}
    runtime._validate_composition()

    assert not (tmp_path / ".keeper-lineage").exists()
    assert store.executive_repository_binding()[4] == 0


def test_runtime_subclasses_cannot_construct_trusted_composition(
    tmp_path: Path,
) -> None:
    test_repository = _test_repository(tmp_path, "subclass-test")
    test_gateway, _ = semantic_gateway(tmp_path)
    with pytest.raises(TypeError, match="subclasses"):
        _ExecutiveRuntimeSubclass(test_repository, test_gateway)

    repository, _ = _production_repository(tmp_path, "subclass-production")
    gateway, _ = _production_gateway(tmp_path, "subclass-production")
    with pytest.raises(TypeError, match="subclasses"):
        _ExecutiveRuntimeSubclass.production(repository, gateway)


def test_module_level_transport_helper_replacement_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = _production_repository(tmp_path, "module-connect")
    gateway, _ = _production_gateway(tmp_path, "module-connect")
    runtime = ExecutiveRuntime.production(repository, gateway)
    original_connect = authority_client_module._connect
    replacement_executed = False

    def replacement_connect(_pipe: str, _timeout: float) -> int:
        nonlocal replacement_executed
        replacement_executed = True
        return 0

    monkeypatch.setattr(authority_client_module, "_connect", replacement_connect)
    with pytest.raises(RuntimeError, match="composition is invalid"):
        runtime._validate_composition()
    assert replacement_executed is False

    monkeypatch.setattr(authority_client_module, "_connect", original_connect)
    runtime._validate_composition()


def test_copied_production_database_cannot_silently_change_paths(
    tmp_path: Path,
) -> None:
    _, source = _production_repository(tmp_path, "source-copy")
    copied_path = tmp_path / "copied-production.db"
    source.backup(copied_path)
    copied = KeeperStore(copied_path)
    copied.migrate()

    with pytest.raises(PermissionError, match="path.*recovery identity"):
        copied.executive_repository_binding()
