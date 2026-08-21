from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from keeper.app.storage import KeeperStore
from keeper.executive.authority import AuthorityEvaluator, NON_DELEGABLE
from keeper.executive.enums import ActionCategory, ActionEffect, AuthorityOutcome
from keeper.executive.founder_auth import (
    ProductionFounderAuthenticator,
    TestFounderAuthenticator,
)
from keeper.executive.models import ProposedAction
from keeper.executive.repository import (
    ProductionExecutiveRepository,
    TestExecutiveRepository,
)
from keeper.executive.service import KeeperExecutive
from tests.keeper.executive.test_intake_charters import approved_project


LEGACY_ACTION_ALIASES = {
    "PUBLISH_EXTERNAL": ActionCategory.PUBLISH_PUBLIC,
    "SPEND": ActionCategory.SPENDING,
    "PAID_PROVIDER_USE": ActionCategory.SPENDING,
    "ACCESS_CREDENTIAL": ActionCategory.CREDENTIAL_ACCESS,
    "CHANGE_SECURITY_BOUNDARY": ActionCategory.SECURITY_BOUNDARY_CHANGE,
    "REWRITE_HISTORY": ActionCategory.HISTORY_REWRITE,
    "ENABLE_LIVE_TRADING": ActionCategory.LIVE_TRADING,
    "CHANGE_FINANCIAL_AUTHORITY": ActionCategory.FINANCIAL_AUTHORITY_CHANGE,
    "DELETE_PROTECTED": ActionCategory.IRREVERSIBLE_DELETE,
    "IRREVERSIBLE_DESTRUCTIVE": ActionCategory.IRREVERSIBLE_DELETE,
}


@pytest.mark.parametrize(("legacy", "canonical"), LEGACY_ACTION_ALIASES.items())
def test_legacy_action_aliases_serialize_canonically(
    legacy: str, canonical: ActionCategory
) -> None:
    assert ActionCategory(legacy) is canonical
    assert ActionCategory(legacy).value == canonical.value


@pytest.mark.parametrize(
    ("legacy", "effect"),
    [
        ("ACCESS_CREDENTIAL", ActionEffect.CREDENTIAL_ACCESS),
        ("CHANGE_SECURITY_BOUNDARY", ActionEffect.SECURITY_BOUNDARY_CHANGE),
        ("REWRITE_HISTORY", ActionEffect.HISTORY_REWRITE),
        ("ENABLE_LIVE_TRADING", ActionEffect.LIVE_TRADING),
        ("CHANGE_FINANCIAL_AUTHORITY", ActionEffect.FINANCIAL_AUTHORITY_CHANGE),
        ("DELETE_PROTECTED", ActionEffect.IRREVERSIBLE_DELETE),
        ("IRREVERSIBLE_DESTRUCTIVE", ActionEffect.IRREVERSIBLE_DELETE),
    ],
)
def test_legacy_aliases_cannot_bypass_non_delegable_policy(
    tmp_path: Path, legacy: str, effect: ActionEffect
) -> None:
    service, project, charter = approved_project(tmp_path)
    category = ActionCategory(legacy)
    assert category in NON_DELEGABLE
    action = ProposedAction(
        action_id=f"alias:{legacy}",
        project_id=project.project_id,
        charter_revision=charter.revision,
        category=legacy,
        target_resource="protected-resource",
        scope=("workspace",),
        provider=None,
        tool=None,
        workspace=None,
        cost=None,
        reversible=False,
        risk="HIGH",
        currency=None,
        data_classification="INTERNAL",
        external_side_effect=True,
        objective=f"attempt protected action through {legacy}",
        trusted_source="TRUSTED_TEST",
        effect_classes=(effect.value,),
    )
    decision = AuthorityEvaluator().evaluate(project, charter, action)
    assert decision.outcome == AuthorityOutcome.DENIED
    assert decision.rule == "non-delegable-action"


def test_unknown_action_category_fails_closed() -> None:
    with pytest.raises(ValueError):
        ActionCategory("CREDENTIAL_READISH")


def test_production_repository_and_facade_are_sealed(tmp_path: Path) -> None:
    production_database = tmp_path / "production.db"
    store = KeeperStore(production_database)
    store.migrate()
    production_authenticator = ProductionFounderAuthenticator(
        tmp_path / "unused-compatibility-key.dpapi"
    )
    repository = ProductionExecutiveRepository(
        store, production_authenticator
    )
    with pytest.raises(AttributeError, match="does not expose"):
        _ = repository.store
    with pytest.raises(AttributeError, match="immutable"):
        repository._ExecutiveRepository__founder_authenticator = (
            TestFounderAuthenticator()
        )
    with pytest.raises(AttributeError, match="already initialized"):
        repository._initialize(
            store, TestFounderAuthenticator(), "PRODUCTION"
        )

    executive = KeeperExecutive(tmp_path / "facade.db")
    assert not hasattr(executive, "repository")
    assert not hasattr(executive, "charters")
    with pytest.raises(AttributeError, match="immutable"):
        executive._KeeperExecutive__repository = repository


def test_repository_database_modes_cannot_cross(tmp_path: Path) -> None:
    production_path = tmp_path / "production.db"
    production_store = KeeperStore(production_path)
    production_store.migrate()
    production_authenticator = ProductionFounderAuthenticator(
        tmp_path / "unused-production-key.dpapi"
    )
    ProductionExecutiveRepository(production_store, production_authenticator)
    reopened_production = KeeperStore(production_path)
    reopened_production.migrate()
    with pytest.raises(PermissionError, match="mode"):
        TestExecutiveRepository(
            reopened_production, TestFounderAuthenticator()
        )

    test_path = tmp_path / "test.db"
    test_store = KeeperStore(test_path)
    test_store.migrate()
    TestExecutiveRepository(test_store, TestFounderAuthenticator())
    reopened_test = KeeperStore(test_path)
    reopened_test.migrate()
    with pytest.raises(PermissionError, match="mode"):
        ProductionExecutiveRepository(
            reopened_test, production_authenticator
        )


def test_production_rejects_unbound_fixture_state(tmp_path: Path) -> None:
    store = KeeperStore(tmp_path / "unbound-fixture.db")
    store.migrate()
    with store.connect() as connection:
        connection.execute(
            'INSERT INTO "executive_projects" '
            "(id,schema_version,created_at,updated_at,payload,payload_hash) "
            "VALUES('fixture',6,'now','now','{}','invalid-fixture-hash')"
        )
    production_authenticator = ProductionFounderAuthenticator(
        tmp_path / "unused-unbound-key.dpapi"
    )
    with pytest.raises(PermissionError, match="no trusted repository mode"):
        ProductionExecutiveRepository(store, production_authenticator)


class _FakeFunction:
    def __init__(self, callback: Any) -> None:
        self.callback = callback
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *args: Any) -> Any:
        return self.callback(*args)


def _credential_api(
    *,
    prompt_result: int = 0,
    unpack_result: bool = True,
    logon_result: bool = True,
) -> tuple[SimpleNamespace, list[str]]:
    calls: list[str] = []

    def prompt(*args: Any) -> int:
        calls.append("prompt")
        if prompt_result == 0:
            ctypes.cast(
                args[5], ctypes.POINTER(ctypes.c_void_p)
            )[0] = ctypes.c_void_p(0x1234)
            ctypes.cast(
                args[6], ctypes.POINTER(ctypes.c_ulong)
            )[0] = ctypes.c_ulong(73)
        return prompt_result

    def unpack(*args: Any) -> bool:
        calls.append("unpack")
        if unpack_result:
            args[3].value = "founder"
            args[5].value = "DARKSAGE"
            args[7].value = "secret"
        return unpack_result

    def logon(*args: Any) -> bool:
        calls.append("logon")
        if logon_result:
            ctypes.cast(
                args[5], ctypes.POINTER(ctypes.c_void_p)
            )[0] = ctypes.c_void_p(0x777)
        return logon_result

    def close(*_args: Any) -> bool:
        calls.append("close")
        return True

    api = SimpleNamespace(
        credui=SimpleNamespace(
            CredUIPromptForWindowsCredentialsW=_FakeFunction(prompt),
            CredUnPackAuthenticationBufferW=_FakeFunction(unpack),
        ),
        advapi32=SimpleNamespace(LogonUserW=_FakeFunction(logon)),
        kernel32=SimpleNamespace(CloseHandle=_FakeFunction(close)),
        ole32=SimpleNamespace(CoTaskMemFree=_FakeFunction(lambda *_: None)),
    )
    return api, calls


@pytest.mark.parametrize(
    ("prompt_result", "unpack_result", "logon_result", "expected_exception"),
    [
        (0, True, True, None),
        (0, True, False, PermissionError),
        (1223, True, True, PermissionError),
        (0, False, True, OSError),
    ],
)
def test_credential_ui_cleanup_runs_on_every_exit(
    monkeypatch: pytest.MonkeyPatch,
    prompt_result: int,
    unpack_result: bool,
    logon_result: bool,
    expected_exception: type[BaseException] | None,
) -> None:
    from keeper.executive import founder_auth

    api, calls = _credential_api(
        prompt_result=prompt_result,
        unpack_result=unpack_result,
        logon_result=logon_result,
    )
    zero_calls: list[tuple[int, int]] = []
    freed: list[tuple[int, int]] = []
    monkeypatch.setattr(ctypes, "windll", api)
    monkeypatch.setattr(
        founder_auth,
        "_secure_zero",
        lambda address, length: zero_calls.append((address, length)),
    )
    monkeypatch.setattr(
        founder_auth,
        "_zero_and_free_authentication_buffer",
        lambda buffer, length: freed.append(
            (int(buffer.value or 0), length)
        )
        if buffer
        else None,
    )
    monkeypatch.setattr(
        founder_auth,
        "_token_identity",
        lambda _token: ("S-1-5-21-1000", "0x123"),
    )

    if expected_exception is None:
        assert founder_auth._credential_ui_logon() == (
            "S-1-5-21-1000",
            "DARKSAGE\\founder",
            "0x123",
        )
    else:
        with pytest.raises(expected_exception):
            founder_auth._credential_ui_logon()

    assert len(zero_calls) == 3
    if prompt_result == 0:
        assert freed == [(0x1234, 73)]
    else:
        assert freed == []
    assert calls.count("close") == (1 if logon_result and prompt_result == 0 and unpack_result else 0)


def test_authentication_buffer_is_zeroed_before_single_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from keeper.executive import founder_auth

    order: list[tuple[str, int]] = []
    fake_windll = SimpleNamespace(
        ole32=SimpleNamespace(
            CoTaskMemFree=_FakeFunction(
                lambda buffer: order.append(
                    ("free", int(buffer.value or 0))
                )
            )
        )
    )
    monkeypatch.setattr(ctypes, "windll", fake_windll)
    monkeypatch.setattr(
        founder_auth,
        "_secure_zero",
        lambda address, length: order.append(("zero", length)),
    )
    founder_auth._zero_and_free_authentication_buffer(
        ctypes.c_void_p(0x1234), 73
    )
    assert order == [("zero", 73), ("free", 0x1234)]
