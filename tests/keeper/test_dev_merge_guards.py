from pathlib import Path

from keeper.executive.founder_auth import ProductionFounderAuthenticator
from keeper.executive.charters import CharterService
from keeper.executive.service import KeeperExecutive


def test_unreviewed_password_account_replacement_is_not_exposed():
    assert not hasattr(ProductionFounderAuthenticator, "configure_keeper_account")
    assert not hasattr(CharterService, "configure_keeper_account")
    assert not hasattr(KeeperExecutive, "configure_founder_account")


def test_desktop_does_not_collect_passwords_or_launch_overlapping_instances():
    root = Path(__file__).parents[2]
    qml = (root / "keeper/ui_qml/qml/Main.qml").read_text(encoding="utf-8")
    app = (root / "keeper/ui_qml/app.py").read_text(encoding="utf-8")
    assert "approvalPassword" not in qml
    assert "founderAccountDialog" not in qml
    assert "keeper.approveCurrentCharter()" in qml
    assert "rebootDialog" not in qml
    assert "startDetached" not in app


def test_qml_production_composition_reaches_exchange_root_validation(monkeypatch, tmp_path):
    import pytest
    pytest.importorskip("PySide6")
    from types import SimpleNamespace
    from keeper.ui_qml import composition

    class ValidationStopped(Exception):
        pass

    seen = []
    def validate(value):
        seen.append(value)
        raise ValidationStopped

    monkeypatch.setattr(composition, "ProductionAuthorityServiceClient", lambda **kwargs: SimpleNamespace(diagnostics=lambda: {"identity": "test"}))
    monkeypatch.setattr(composition, "configured_authority_bindings", lambda app: (object(),))
    monkeypatch.setattr(composition, "authority_exchange_root_from_diagnostics", validate)
    with pytest.raises(ValidationStopped):
        composition.desktop_pass_b_application(SimpleNamespace(data_directory=tmp_path))
    assert seen == [{"identity": "test"}]
