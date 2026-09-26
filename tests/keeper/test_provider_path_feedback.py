from pathlib import Path

import pytest

from tests.keeper.test_qml_desktop import controller


@pytest.mark.parametrize("value", ["", "   ", "https://example.com/provider.exe", "file://server/share/provider.exe", r"\\server\share\provider.exe", "bad\x00path", "file:////server/share/provider.exe", "file:///%2Fserver/share/provider.exe", "file://localhost/C:/ok.exe", r"/\server\share\provider.exe"])
def test_invalid_address_never_resolves_or_changes_settings(controller, monkeypatch, value):
    monkeypatch.setattr(controller, "_local_path", lambda value: pytest.fail("invalid address must not be probed"))
    controller.setProviderPath("codex", value)
    assert controller.error
    assert controller.application.provider_paths() == {}
    assert controller.application.provider_registrations() == {}


@pytest.mark.parametrize("name", ["../codex", "a/b", "<b>codex</b>", "x" * 65])
def test_invalid_provider_name_is_not_persisted(controller, name, tmp_path):
    controller.setProviderPath(name, str(tmp_path))
    assert "provider name" in controller.error
    assert controller.application.provider_paths() == {}


@pytest.mark.parametrize("failure", [OSError, ValueError])
def test_resolution_failure_has_safe_actionable_feedback(controller, monkeypatch, failure):
    def fail(value):
        raise failure(r"C:\private\secret.exe")
    monkeypatch.setattr(controller, "_local_path", fail)
    controller.setProviderPath("codex", "valid.exe")
    assert "could not be checked" in controller.error
    assert "private" not in controller.error
    assert controller.application.provider_paths() == {}


@pytest.mark.parametrize("as_url", [False, True])
def test_picker_url_and_path_save_without_registration(controller, tmp_path, as_url):
    executable = tmp_path / "folder with spaces" / "provider.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"fixture, never executed")
    value = executable.as_uri() if as_url else str(executable)
    controller.setProviderPath("  CODEX  ", value)
    assert controller.application.provider_paths() == {"codex": str(executable.resolve())}
    assert controller.application.provider_registrations() == {}
    assert "qualification" in controller.status
    assert str(executable) not in repr(controller.state_snapshot())


def test_directory_rejected_and_previous_path_preserved(controller, tmp_path):
    controller.application.save_provider_paths({"codex": "previous.exe"})
    controller.setProviderPath("codex", str(tmp_path))
    assert "not found" in controller.error
    assert controller.application.provider_paths() == {"codex": "previous.exe"}
