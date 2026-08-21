from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

from keeper.app.verification_policy import (
    VerificationSpec,
    trusted_bash_launcher,
    validate_semantic_bindings,
)
from keeper.verifier import VerificationCommand, Verifier


def _trusted_pytest(workspace: Path) -> tuple[bool, dict[str, object] | None]:
    spec = VerificationSpec(
        "tests",
        ["{python}", "-m", "pytest", "-q"],
        "pytest",
        registration_id="keeper:tests:v1",
        expected_executable_sha256=hashlib.sha256(
            Path(sys.executable).resolve().read_bytes()
        ).hexdigest(),
    )
    validate_semantic_bindings([spec], ["tests"])
    result = Verifier().run(
        workspace,
        [
            VerificationCommand(
                spec.arguments,
                validator=spec.validator,
                registration_id=spec.registration_id,
                expected_executable_sha256=spec.expected_executable_sha256,
            )
        ],
    )[0]
    return result.passed, result.validator_identity


@pytest.mark.parametrize("shadow_kind", ["module", "package"])
def test_workspace_pytest_shadowing_is_ignored(
    tmp_path: Path, shadow_kind: str
) -> None:
    if shadow_kind == "module":
        (tmp_path / "pytest.py").write_text(
            "raise SystemExit('workspace pytest executed')\n", encoding="utf-8"
        )
    else:
        package = tmp_path / "pytest"
        package.mkdir()
        (package / "__main__.py").write_text(
            "raise SystemExit('workspace pytest package executed')\n", encoding="utf-8"
        )
    (tmp_path / "test_real.py").write_text(
        "def test_real():\n    assert True\n", encoding="utf-8"
    )
    passed, identity = _trusted_pytest(tmp_path)
    assert passed
    assert identity is not None
    assert not Path(str(identity["module_origin"])).is_relative_to(tmp_path)


def test_import_environment_is_sanitized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    malicious = tmp_path / "malicious"
    malicious.mkdir()
    (malicious / "pytest.py").write_text(
        "raise SystemExit('PYTHONPATH shadow executed')\n", encoding="utf-8"
    )
    monkeypatch.setenv("PYTHONPATH", str(malicious))
    monkeypatch.setenv("PYTHONHOME", str(malicious))
    monkeypatch.setenv("PYTHONUSERBASE", str(malicious))
    (tmp_path / "test_real.py").write_text(
        "def test_real():\n    assert True\n", encoding="utf-8"
    )
    assert _trusted_pytest(tmp_path)[0]


def test_executable_substitution_is_rejected() -> None:
    with pytest.raises(PermissionError, match="immutable registration"):
        validate_semantic_bindings(
            [
                VerificationSpec(
                    "tests",
                    [os.fspath(Path("fake-python.exe")), "-m", "pytest"],
                    "pytest",
                )
            ],
            ["tests"],
        )


def test_zero_exit_fake_stdout_cannot_satisfy_pytest(tmp_path: Path) -> None:
    fake = tmp_path / "fake.cmd"
    fake.write_text("@echo fabricated success\r\n@exit /b 0\r\n", encoding="ascii")
    with pytest.raises(PermissionError):
        validate_semantic_bindings(
            [VerificationSpec("tests", [str(fake), "-m", "pytest"], "pytest")],
            ["tests"],
        )


def test_foundation_script_is_pinned_and_must_not_be_symlink(
    tmp_path: Path,
) -> None:
    script = tmp_path / "scripts" / "verify-foundation.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher = trusted_bash_launcher()
    if launcher is None:
        pytest.skip("trusted Bash launcher is unavailable")
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    spec = VerificationSpec(
        "foundation",
        [str(launcher), str(script)],
        "foundation-script",
        registration_id="keeper:foundation:v1",
        expected_sha256=digest,
        expected_executable_sha256=hashlib.sha256(
            launcher.read_bytes()
        ).hexdigest(),
    )
    validate_semantic_bindings([spec], ["foundation"], trusted_root=tmp_path)
    script.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="digest"):
        validate_semantic_bindings([spec], ["foundation"], trusted_root=tmp_path)
    link = tmp_path / "linked" / "scripts" / "verify-foundation.sh"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(script)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    linked = VerificationSpec(
        "foundation",
        [str(launcher), str(link)],
        "foundation-script",
        registration_id="keeper:foundation:v1",
        expected_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        expected_executable_sha256=hashlib.sha256(
            launcher.read_bytes()
        ).hexdigest(),
    )
    with pytest.raises(PermissionError, match="immutable registration"):
        validate_semantic_bindings(
            [linked], ["foundation"], trusted_root=tmp_path / "linked"
        )


def test_genuine_trusted_validator_records_identity(tmp_path: Path) -> None:
    (tmp_path / "test_real.py").write_text(
        "def test_real():\n    assert 2 + 2 == 4\n", encoding="utf-8"
    )
    passed, identity = _trusted_pytest(tmp_path)
    assert passed
    assert identity is not None
    assert identity["registration_id"] == "keeper:tests:v1"
    assert identity["environment_policy"] == "isolated-no-user-site-no-pythonpath"


def test_foundation_rejects_wrapper_unused_script_and_argument_changes(
    tmp_path: Path,
) -> None:
    launcher = trusted_bash_launcher()
    if launcher is None:
        pytest.skip("trusted Bash launcher is unavailable")
    script = tmp_path / "scripts" / "verify-foundation.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper = tmp_path / "wrapper.cmd"
    wrapper.write_text("@exit /b 0\r\n", encoding="ascii")
    launcher_digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
    script_digest = hashlib.sha256(script.read_bytes()).hexdigest()
    for arguments in (
        [str(wrapper), str(script)],
        [str(wrapper), "unused", str(script)],
        [str(script), str(launcher)],
        [str(launcher), str(script), "--extra"],
    ):
        with pytest.raises(PermissionError):
            validate_semantic_bindings(
                [
                    VerificationSpec(
                        "foundation",
                        arguments,
                        "foundation-script",
                        registration_id="keeper:foundation:v1",
                        expected_sha256=script_digest,
                        expected_executable_sha256=launcher_digest,
                    )
                ],
                ["foundation"],
                trusted_root=tmp_path,
            )


def test_unknown_and_stale_registrations_are_rejected(tmp_path: Path) -> None:
    fake = tmp_path / "zero.cmd"
    fake.write_text("@exit /b 0\r\n", encoding="ascii")
    with pytest.raises(ValueError, match="cannot satisfy"):
        validate_semantic_bindings(
            [
                VerificationSpec(
                    "task",
                    [str(fake)],
                    "registered-command",
                    registration_id="unknown",
                )
            ],
            ["task"],
        )
    with pytest.raises(PermissionError, match="immutable registration"):
        validate_semantic_bindings(
            [
                VerificationSpec(
                    "tests",
                    ["{python}", "-m", "pytest", "-q"],
                    "pytest",
                    registration_id="keeper:tests:v1",
                    expected_executable_sha256="0" * 64,
                )
            ],
            ["tests"],
        )
