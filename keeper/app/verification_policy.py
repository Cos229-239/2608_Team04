from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import os
from pathlib import Path
import sys
from typing import Iterable


@dataclass(frozen=True, slots=True)
class VerificationSpec:
    category: str
    arguments: list[str]
    validator: str
    required: bool = True
    waiver_id: str | None = None
    registration_id: str | None = None
    expected_sha256: str | None = None
    expected_executable_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class VerificationWaiver:
    waiver_id: str
    category: str
    task_id: str
    approving_authority: str
    reason: str
    expires_at: str
    revoked_at: str | None = None


REGISTERED_CATEGORIES: dict[str, frozenset[str]] = {
    "tests": frozenset({"pytest"}),
    "typing": frozenset({"mypy"}),
    "compilation": frozenset({"compileall"}),
    "foundation": frozenset({"foundation-script"}),
    "task": frozenset({"file-equals"}),
    "security": frozenset({"security-scan"}),
    "packaging": frozenset({"package-smoke"}),
}


def validate_semantic_bindings(
    specs: Iterable[VerificationSpec],
    required_categories: Iterable[str],
    waivers: Iterable[VerificationWaiver] = (),
    task_id: str | None = None,
    now: datetime | None = None,
    trusted_root: Path | None = None,
) -> None:
    values = list(specs)
    if not values:
        raise ValueError("verification specification cannot be empty")
    seen_commands: set[tuple[str, ...]] = set()
    covered: set[str] = set()
    waiver_map = {item.waiver_id: item for item in waivers}
    for spec in values:
        if not spec.arguments:
            raise ValueError("verification command cannot be empty")
        accepted = REGISTERED_CATEGORIES.get(spec.category)
        if accepted is None or spec.validator not in accepted:
            raise ValueError(
                f"validator {spec.validator!r} cannot satisfy category {spec.category!r}"
            )
        _validate_command_pattern(spec, trusted_root)
        fingerprint = tuple(spec.arguments)
        if fingerprint in seen_commands:
            raise ValueError("the same command cannot be counted more than once")
        seen_commands.add(fingerprint)
        if spec.required:
            if spec.waiver_id is None:
                covered.add(spec.category)
            else:
                waiver = waiver_map.get(spec.waiver_id)
                if waiver is None:
                    raise PermissionError("verification waiver is missing or malformed")
                validate_waiver(
                    waiver,
                    task_id=task_id or "",
                    category=spec.category,
                    now=now or datetime.now(UTC),
                )
                covered.add(spec.category)
    missing = set(required_categories) - covered
    if missing:
        raise ValueError(f"mandatory verification categories are unsatisfied: {sorted(missing)}")


def validate_waiver(
    waiver: VerificationWaiver, *, task_id: str, category: str, now: datetime
) -> None:
    try:
        expires = datetime.fromisoformat(waiver.expires_at)
    except ValueError as error:
        raise PermissionError("verification waiver expiration is malformed") from error
    if expires.tzinfo is None or expires.utcoffset() is None:
        raise PermissionError("verification waiver expiration must be timezone-aware")
    if (
        waiver.task_id != task_id
        or waiver.category != category
        or not waiver.approving_authority.strip()
        or not waiver.reason.strip()
        or waiver.revoked_at is not None
        or expires <= now
    ):
        raise PermissionError("verification waiver is invalid for this task and category")


def environment_summary(environment: dict[str, str]) -> dict[str, object]:
    safe_keys = sorted(
        key
        for key in environment
        if not any(
            marker in key.upper()
            for marker in ("TOKEN", "SECRET", "PASSWORD", "KEY", "COOKIE", "CREDENTIAL")
        )
    )
    return {"available_keys": safe_keys, "secret_values_included": False}


def trusted_bash_launcher() -> Path | None:
    candidates = (
        (
            Path("C:/Program Files/Git/bin/bash.exe"),
            Path("C:/Program Files/Git/usr/bin/bash.exe"),
        )
        if os.name == "nt"
        else (Path("/bin/bash"), Path("/usr/bin/bash"))
    )
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate.resolve()
    return None


def _validate_command_pattern(
    spec: VerificationSpec, trusted_root: Path | None
) -> None:
    args = [item.lower().replace("\\", "/") for item in spec.arguments]
    python_registrations = {
        "pytest": (
            "keeper:tests:v1",
            ["{python}", "-m", "pytest", "-q"],
        ),
        "mypy": (
            "keeper:typing:v1",
            ["{python}", "-m", "mypy", "--strict", "keeper", "tests/keeper"],
        ),
        "compileall": (
            "keeper:compilation:v1",
            [
                "{python}",
                "-m",
                "compileall",
                "-q",
                "keeper",
                "tests/keeper",
            ],
        ),
    }
    if spec.validator in python_registrations:
        registration_id, registered_arguments = python_registrations[spec.validator]
        if (
            spec.registration_id != registration_id
            or spec.arguments != registered_arguments
            or spec.expected_executable_sha256
            != hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()
        ):
            raise PermissionError(
                f"{spec.validator} command does not match its immutable registration"
            )
    if spec.validator == "foundation-script":
        if (
            spec.registration_id != "keeper:foundation:v1"
            or len(spec.arguments) != 2
            or trusted_root is None
        ):
            raise PermissionError("foundation registration is missing or malformed")
        launcher = Path(spec.arguments[0])
        script = Path(spec.arguments[1])
        registered_launcher = trusted_bash_launcher()
        expected_script = (
            trusted_root.resolve() / "scripts" / "verify-foundation.sh"
        )
        if (
            spec.expected_sha256 is None
            or spec.expected_executable_sha256 is None
            or not launcher.is_absolute()
            or launcher.is_symlink()
            or not launcher.is_file()
            or registered_launcher is None
            or launcher.resolve() != registered_launcher
            or not script.is_absolute()
            or script.is_symlink()
            or not script.is_file()
            or script.resolve() != expected_script.resolve()
        ):
            raise PermissionError(
                "foundation launcher and script must match the immutable registration"
            )
        launcher_digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
        script_digest = hashlib.sha256(script.read_bytes()).hexdigest()
        if (
            launcher_digest != spec.expected_executable_sha256
            or script_digest != spec.expected_sha256
        ):
            raise PermissionError("foundation launcher or script digest is stale")
    if spec.validator == "file-equals" and args[0] != "keeper:file-equals":
        raise ValueError("file-equals validator requires the Keeper registered command")
    if spec.validator == "registered-command":
        raise PermissionError("unknown registered commands are not trusted")
