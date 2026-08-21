from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

import keeper.ui_qml.__main__ as desktop_main
from keeper.ui_qml.__main__ import _QA_MARKER, main


def test_qa_modes_require_explicit_isolated_profile(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--mock-demo"])

    existing = tmp_path / "founder-profile"
    existing.mkdir()
    sentinel = existing / "founder-state.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["--data-dir", str(existing), "--mock-demo"])
    with pytest.raises(SystemExit):
        main(["--data-dir", str(existing), "--ui-smoke"])

    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert not (existing / "keeper.db").exists()
    assert not (existing / _QA_MARKER).exists()


def test_qa_profile_marker_is_explicit_and_malformed_marker_rejects(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / _QA_MARKER).write_text("wrong", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["--data-dir", str(malformed), "--mock-demo"])
    assert not (malformed / "keeper.db").exists()


def test_test_fixture_flag_cannot_label_normal_desktop_as_test(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--data-dir", str(tmp_path / "qa"), "--test-ui-fixture"])

def test_packaged_diagnostics_contract_is_pathless(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = tmp_path / "diagnostic-profile"
    assert main(["--data-dir", str(data), "--diagnostics"]) == 0
    output = capsys.readouterr().out
    payload = json.loads(output)

    assert payload["keeper_version"]
    assert "data_directory" not in payload
    assert str(tmp_path) not in output
    assert '"executable":' not in output
    assert "service_root" not in output
    assert "client_exchange_root" not in output
    assert "allowed_evidence_root" not in output

def test_ui_smoke_is_always_labeled_as_test_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_desktop(application: object, **options: object) -> int:
        captured.update(options)
        return 0

    monkeypatch.setattr(desktop_main, "run_desktop", fake_run_desktop)
    assert main(["--data-dir", str(tmp_path / "smoke"), "--ui-smoke"]) == 0
    assert captured["smoke"] is True
    assert captured["test_fixture"] is True