from types import SimpleNamespace

import pytest

from keeper.app.service import KeeperApplication
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.authority_reservation import UnavailableAuthorityAttemptReservation
from keeper.pass_b.launch_authority import UnavailableLaunchAuthority
from keeper.ui_qml import composition


class Health:
    def diagnostics(self):
        return {}

    def require_live_identity(self):
        return {"protocol_version": 7, "observer_available": True}


def configure(monkeypatch, tmp_path):
    client = Health()
    monkeypatch.setattr(composition, "ProductionAuthorityServiceClient", lambda **kw: client)
    monkeypatch.setattr(composition, "configured_authority_bindings", lambda app: ("first", "second"))
    monkeypatch.setattr(composition, "authority_exchange_root_from_diagnostics", lambda value: tmp_path / "exchange")
    return client


@pytest.mark.parametrize("failure", [PermissionError, TimeoutError, ConnectionError])
def test_bridge_rejection_rebuilds_without_execution_authority(tmp_path, monkeypatch, failure):
    configure(monkeypatch, tmp_path)
    app = KeeperApplication(tmp_path)
    partial = SimpleNamespace(orchestration=object())
    monkeypatch.setattr(composition, "PassBApplication", lambda *a, **kw: partial if kw.get("authority_client") else PassBApplication(*a, **kw))
    seen = []

    def bridge(*args):
        seen.append(args[-1])
        if args[-1] == "second":
            raise failure("private-provider-diagnostic")

    monkeypatch.setattr("keeper.pass_b.provider_bridge.bridge_qualified_provider", bridge)
    for _ in range(2):  # Restart never resurrects partially constructed authority.
        result = composition.desktop_pass_b_application(app)
        assert result is not partial
        assert result.authority_client is None
        assert isinstance(result.orchestration.launch_authority, UnavailableLaunchAuthority)
        assert isinstance(result.orchestration.authority_reservation, UnavailableAuthorityAttemptReservation)
        with pytest.raises(PermissionError):
            result.orchestration.launch_authority.launch(None, None, None)
        assert result.diagnostics()["authority"]["state"] == "UNAVAILABLE"
        assert result.diagnostics()["launch_authority_configured"] is False
        assert "private-provider-diagnostic" not in str(result.diagnostics())
        assert result.startup_provider_block
    assert seen == ["first", "second", "first", "second"]


def test_service_offline_does_not_construct_launch_authority(tmp_path, monkeypatch):
    client = configure(monkeypatch, tmp_path)
    monkeypatch.setattr(client, "diagnostics", lambda: (_ for _ in ()).throw(TimeoutError("private")))
    result = composition.desktop_pass_b_application(KeeperApplication(tmp_path))
    assert result.authority_client is None
    assert result.startup_provider_block


def test_database_identity_failure_is_not_swallowed(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    monkeypatch.setattr(composition, "PassBApplication", lambda *a, **kw: (_ for _ in ()).throw(PermissionError("database recovery identity")))
    with pytest.raises(PermissionError, match="database recovery identity"):
        composition.desktop_pass_b_application(KeeperApplication(tmp_path))


def test_successful_bridge_retains_production_composition(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    result = SimpleNamespace(orchestration=object())
    monkeypatch.setattr(composition, "PassBApplication", lambda *a, **kw: result)
    monkeypatch.setattr("keeper.pass_b.provider_bridge.bridge_qualified_provider", lambda *a: None)
    assert composition.desktop_pass_b_application(KeeperApplication(tmp_path)) is result


def test_blocked_controller_banner_survives_refresh(tmp_path):
    pytest.importorskip("PySide6")
    from keeper.ui_qml.controller import KeeperDesktopController

    app = KeeperApplication(tmp_path)
    blocked = composition._blocked_desktop(tmp_path, Health())
    controller = KeeperDesktopController(app, pass_b_application=blocked)
    for _ in range(2):
        controller.refresh()
        assert controller.state_snapshot()["startupProviderBlock"] == composition._PROVIDER_STARTUP_BLOCK
        assert controller.state_snapshot()["diagnostics"]["authorityStatus"] == "UNAVAILABLE"


def test_blocked_restart_preserves_uncertain_work(tmp_path):
    pytest.importorskip("PySide6")
    from keeper.ui_qml.controller import KeeperDesktopController

    app = KeeperApplication(tmp_path)
    record = {"id": "uncertain-run", "task_id": "other-task", "status": "interrupted",
              "recovery": {"classification": "uncertain"}}
    app.store.upsert("runs", record["id"], record)
    for _ in range(2):
        reopened = KeeperApplication(tmp_path)
        blocked = composition._blocked_desktop(tmp_path, Health())
        controller = KeeperDesktopController(reopened, pass_b_application=blocked)
        controller.refresh()
        state = controller.state_snapshot()
        assert state["counts"]["uncertain"] == 1
        recovery = next(row for row in state["recoveries"] if row["run_id"] == record["id"])
        assert recovery["status"] == "UNCERTAIN"
        assert recovery["recovery_action"] == ""
        assert state["startupProviderBlock"] == composition._PROVIDER_STARTUP_BLOCK
