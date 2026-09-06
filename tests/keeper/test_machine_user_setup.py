from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("machine_user_setup", ROOT / "scripts/keeper-machine-user-setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
VERIFY_ENROLLMENT = setup.verify_enrollment


@pytest.fixture
def case(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    root = profile / "AppData/Local/Programs/DarkSage/KeeperProviderHost"
    state = root / "state"
    state.mkdir(parents=True)
    startup = profile / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    payload = tmp_path / "payload"
    (payload / "provider-host").mkdir(parents=True)
    (payload / "provider-host/keeper-provider-host-package-manifest.json").write_text('{"version":"1.7.52"}')
    current = {"version": "1.7.52", "package_sha256": "a" * 64, "artifact_sha256": "b" * 64}
    installer = SimpleNamespace(
        root=root, state=state, transaction_path=root / "lifecycle-transaction.json",
        status=Mock(return_value={"current": current}), install=Mock(),
        attest_protected_tree=Mock(), _installed_package=Mock(),
    )
    authority = SimpleNamespace(
        require_live_identity=Mock(return_value={"client_sid": "S-1-test", "service_key_id": "key"}),
        provider_host_enrollment_status=Mock(return_value={"state": "NOT_INSTALLED", "installed": False}),
    )
    enroll = Mock()
    verify = Mock()
    monkeypatch.setattr(setup, "ProductionAuthorityServiceClient", lambda: authority)
    monkeypatch.setattr(setup, "ProviderHostInstaller", lambda *a, **k: installer)
    monkeypatch.setattr(setup.cli, "_validate_authority_compatibility", lambda _: None)
    monkeypatch.setattr(setup.cli, "_authority_service_sid", lambda: "S-1-service")
    monkeypatch.setattr(setup.cli, "current_user_binding", lambda: SimpleNamespace(user_sid="S-1-test", profile_path=str(profile), session_id=1))
    monkeypatch.setattr(setup.cli, "_production_enrollment_client", lambda: SimpleNamespace(enroll=enroll))
    monkeypatch.setattr(setup, "_verify_package", Mock(return_value=SimpleNamespace(
        manifest_sha256="a" * 64, executable_sha256="b" * 64, executable=payload / "provider-host/KeeperProviderHost.exe"
    )))
    monkeypatch.setattr(setup, "verify_enrollment", verify)
    return SimpleNamespace(**locals())


def run(c, **kwargs):
    return setup.ensure_host(c.payload, c.root, c.startup, **kwargs)


def test_reinstall_retains_enrolled_earlier_build_and_file_identity(case):
    c = case
    receipt = c.state / "provider-host-enrollment.json"
    receipt.write_bytes(b"existing signed receipt fixture")
    c.current["package_sha256"] = "c" * 64  # enrolled earlier build, same version
    before = (receipt.read_bytes(), receipt.stat())
    assert "retained" in run(c)
    assert "retained" in run(c, check_only=True)
    assert (receipt.read_bytes(), receipt.stat()) == before
    c.installer.install.assert_not_called()
    c.enroll.assert_not_called()
    assert c.verify.call_count == 2
    c.installer._installed_package.assert_called_with("1.7.52", "c" * 64, require_defender=True)


@pytest.mark.parametrize("failure", ["Defender failure", "Package corrupt", "ACL mismatch"])
def test_existing_host_verification_failure_blocks_changes(case, failure):
    c = case
    (c.state / "provider-host-enrollment.json").touch()
    target = c.installer.attest_protected_tree if failure == "ACL mismatch" else c.installer._installed_package
    target.side_effect = PermissionError(failure)
    with pytest.raises(PermissionError, match=failure):
        run(c)
    c.installer.install.assert_not_called()
    c.enroll.assert_not_called()


@pytest.mark.parametrize("state", ["REVOKED", "ENROLLMENT_PENDING", "ENROLLED_OFFLINE", "UNCERTAIN"])
def test_missing_receipt_does_not_reset_authority_enrollment(case, state):
    case.authority.provider_host_enrollment_status.return_value = {"state": state, "installed": True}
    with pytest.raises(PermissionError, match="must be recovered"):
        run(case)
    case.enroll.assert_not_called()
    case.installer.install.assert_not_called()


@pytest.mark.parametrize("name", ["provider-host-enrollment-pending.json", "provider-host-enrollment-revoked.json", "provider-host-enrollment-superseded-old.json", "provider-host.db"])
def test_local_history_prevents_generation_one(case, name):
    (case.state / name).touch()
    with pytest.raises(PermissionError, match="must be recovered"):
        run(case)
    case.enroll.assert_not_called()


def test_pending_lifecycle_stops_before_verification_or_enrollment(case):
    case.installer.transaction_path.touch()
    with pytest.raises(PermissionError, match="transaction is pending"):
        run(case)
    case.installer.install.assert_not_called()
    case.enroll.assert_not_called()


def test_unenrolled_existing_exact_package_enrolls_once_with_founder_flow(case):
    assert "Founder-approved" in run(case)
    case.enroll.assert_called_once_with(generation=1)
    case.verify.assert_called_once()
    case.installer.install.assert_not_called()


def test_check_only_never_installs_or_enrolls(case):
    assert "no changes" in run(case, check_only=True)
    case.installer.install.assert_not_called()
    case.enroll.assert_not_called()


def test_unenrolled_different_build_cannot_be_adopted(case):
    case.current["package_sha256"] = "d" * 64
    with pytest.raises(PermissionError, match="Unenrolled Host package differs"):
        run(case)
    with pytest.raises(PermissionError, match="Unenrolled Host package differs"):
        run(case, check_only=True)
    case.enroll.assert_not_called()


def test_fresh_install_then_founder_enrollment_and_verification(case, monkeypatch):
    # An absent root, not a partially installed directory with lost selection.
    monkeypatch.setattr(Path, "exists", lambda self: False)
    case.installer.status.side_effect = [{"current": None}, {"current": case.current}]
    assert "Founder-approved" in run(case)
    case.installer.install.assert_called_once()
    case.enroll.assert_called_once_with(generation=1)
    case.verify.assert_called_once()


def test_failed_install_never_enrolls(case, monkeypatch):
    monkeypatch.setattr(Path, "exists", lambda self: False)
    case.installer.status.return_value = {"current": None}
    case.installer.install.side_effect = RuntimeError("copy failed")
    with pytest.raises(RuntimeError, match="copy failed"):
        run(case)
    case.enroll.assert_not_called()


def test_founder_cancel_is_not_retried(case):
    case.enroll.side_effect = PermissionError("Founder cancelled")
    with pytest.raises(PermissionError, match="Founder cancelled"):
        run(case)
    case.enroll.assert_called_once()
    case.verify.assert_not_called()


@pytest.mark.parametrize("change", [None, "file_id", "generation", "enrollment_id", "service_key", "session", "revoked", "pending", "signature"])
def test_retained_enrollment_exact_binding_validation(tmp_path, monkeypatch, change):
    import hashlib

    state = tmp_path / "state"
    state.mkdir()
    executable = tmp_path / "KeeperProviderHost.exe"
    executable.write_bytes(b"inert fixture")
    stat = executable.stat()
    proposal = {"payload": {"host_id": "host"}, "signature": "test-envelope"}
    enrollment_id = "provider-host-enrollment:" + hashlib.sha256(
        ("host:" + setup.structured_digest(proposal)).encode()
    ).hexdigest()
    binding = SimpleNamespace(user_sid="user", session_id=1, profile_path=str(tmp_path))
    runtime = {"host_id": "host", "enrollment_id": enrollment_id, "user_binding": {
        "user_sid": "user", "session_id": 1, "profile_path": str(tmp_path),
    }}
    receipt = {"payload": {"enrollment_generation": 33, "service_key_id": "service-key"}}
    (state / "provider-host-enrollment.json").write_text(json.dumps(receipt))
    (state / "provider-host-enrollment-pending.json").write_text(json.dumps({"proposal": proposal}))
    current = {"artifact_path": str(executable), "artifact_sha256": "b" * 64, "package_sha256": "a" * 64, "version": "1.7.52"}
    installation = {
        "authenticode_binding": {"status": "NotSigned"},
        "executable_file_identity": {"schema_version": 1, "device_id": stat.st_dev, "file_id": stat.st_ino, "modified_ns": stat.st_mtime_ns, "size": stat.st_size},
        "executable_path": str(executable.resolve()), "executable_sha256": "b" * 64,
        "executable_size": stat.st_size, "install_root": str(tmp_path.resolve()),
        "manifest_sha256": "a" * 64, "package_version": "1.7.52",
    }
    status = {"state": "ENROLLED_OFFLINE", "enrollment_id": enrollment_id, "enrollment_generation": 33}
    diagnostics = {"service_key_id": "service-key"}
    installer = SimpleNamespace(state=state, root=tmp_path, attest_protected_tree=Mock())
    authority = SimpleNamespace(provider_host_enrollment_status=lambda: status)
    parser = Mock(return_value=(runtime, installation))
    # Signed receipt/checkpoint parser has its own cryptographic regression
    # suite; isolate the installer's additional live binding checks here.
    monkeypatch.setattr(setup.cli, "_startup_configuration", parser)
    monkeypatch.setattr(setup.cli, "_revoked_status", lambda _: {} if change == "revoked" else None)
    monkeypatch.setattr(setup, "authenticode_enrollment_binding", lambda _: {"status": "NotSigned"})
    if change == "file_id":
        installation["executable_file_identity"]["file_id"] += 1
    elif change == "generation":
        status["enrollment_generation"] += 1
    elif change == "enrollment_id":
        status["enrollment_id"] = "other"
    elif change == "service_key":
        diagnostics["service_key_id"] = "other"
    elif change == "session":
        binding.session_id = 2
    elif change == "pending":
        status["state"] = "ENROLLMENT_PENDING"
    elif change == "signature":
        parser.side_effect = PermissionError("bad signature")
    before = {p.name: (p.read_bytes(), p.stat()) for p in state.iterdir()}
    if change is None:
        VERIFY_ENROLLMENT(installer, current, authority, diagnostics, binding)
        installer.attest_protected_tree.assert_called_once()
    else:
        with pytest.raises(PermissionError):
            VERIFY_ENROLLMENT(installer, current, authority, diagnostics, binding)
    assert before == {p.name: (p.read_bytes(), p.stat()) for p in state.iterdir()}
