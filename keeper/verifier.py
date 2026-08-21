from __future__ import annotations

import os
import json
import hashlib
import importlib.metadata
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from keeper.models.task import now_iso
from keeper.app.verification_policy import trusted_bash_launcher

from keeper.policies import filtered_environment
from keeper.policies import resolve_within


@dataclass(frozen=True, slots=True)
class VerificationCommand:
    arguments: list[str]
    required: bool = True
    timeout_seconds: int = 600
    validator: str | None = None
    registration_id: str | None = None
    expected_sha256: str | None = None
    expected_executable_sha256: str | None = None
    trusted_root: Path | None = None


@dataclass(frozen=True, slots=True)
class VerificationResult:
    arguments: list[str]
    required: bool
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    started_at: str | None = None
    ended_at: str | None = None
    validator_identity: dict[str, object] | None = None

    @property
    def passed(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class Verifier:
    def run(self, workspace: Path, commands: list[VerificationCommand]) -> list[VerificationResult]:
        if not commands:
            raise ValueError("at least one mandatory verification command is required")
        results: list[VerificationResult] = []
        for command in commands:
            if not command.arguments:
                raise ValueError("verification command cannot be empty")
            if command.arguments[0] == "keeper:file-equals":
                if len(command.arguments) != 3:
                    raise ValueError("keeper:file-equals requires a path and expected content")
                target = resolve_within(workspace, command.arguments[1])
                actual = target.read_text(encoding="utf-8") if target.is_file() else ""
                expected = command.arguments[2]
                result = VerificationResult(
                    command.arguments,
                    command.required,
                    0 if actual == expected else 1,
                    "file content matched\n" if actual == expected else "",
                    "" if actual == expected else f"unexpected content in {command.arguments[1]}\n",
                    started_at=now_iso(),
                    ended_at=now_iso(),
                    validator_identity={
                        "registration_id": command.registration_id or "keeper:file-equals",
                        "validator": "file-equals",
                        "implementation": str(Path(__file__).resolve()),
                    },
                )
                results.append(result)
                if result.required and not result.passed:
                    break
                continue
            started_at = now_iso()
            arguments, identity, environment = self._prepare_trusted_command(
                workspace, command
            )
            try:
                completed = subprocess.run(
                    arguments,
                    cwd=workspace,
                    env=environment,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=command.timeout_seconds,
                    check=False,
                )
                result = VerificationResult(
                    arguments,
                    command.required,
                    completed.returncode,
                    completed.stdout,
                    completed.stderr,
                    started_at=started_at,
                    ended_at=now_iso(),
                    validator_identity=identity,
                )
            except subprocess.TimeoutExpired as error:
                timeout_stdout = error.stdout.decode() if isinstance(error.stdout, bytes) else (error.stdout or "")
                timeout_stderr = error.stderr.decode() if isinstance(error.stderr, bytes) else (error.stderr or "")
                result = VerificationResult(
                    arguments,
                    command.required,
                    124,
                    timeout_stdout,
                    timeout_stderr,
                    True,
                    started_at,
                    now_iso(),
                    identity,
                )
            except FileNotFoundError as error:
                result = VerificationResult(
                    arguments,
                    command.required,
                    127,
                    "",
                    str(error),
                    started_at=started_at,
                    ended_at=now_iso(),
                    validator_identity=identity,
                )
            results.append(result)
            if result.required and not result.passed:
                break
        return results

    @staticmethod
    def _prepare_trusted_command(
        workspace: Path, command: VerificationCommand
    ) -> tuple[list[str], dict[str, object], dict[str, str]]:
        environment = filtered_environment(dict(os.environ))
        for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE"):
            environment.pop(key, None)
        environment.update(
            {
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        validator = command.validator
        if (
            validator is None
            and len(command.arguments) >= 3
            and command.arguments[0] == "{python}"
            and command.arguments[1] == "-m"
            and command.arguments[2] in {"pytest", "mypy", "compileall"}
        ):
            validator = command.arguments[2]
        if validator in {"pytest", "mypy", "compileall"}:
            registered_arguments = {
                "pytest": ["{python}", "-m", "pytest", "-q"],
                "mypy": [
                    "{python}",
                    "-m",
                    "mypy",
                    "--strict",
                    "keeper",
                    "tests/keeper",
                ],
                "compileall": [
                    "{python}",
                    "-m",
                    "compileall",
                    "-q",
                    "keeper",
                    "tests/keeper",
                ],
            }[validator]
            registered_id = {
                "pytest": "keeper:tests:v1",
                "mypy": "keeper:typing:v1",
                "compileall": "keeper:compilation:v1",
            }[validator]
            executable = Path(sys.executable).resolve()
            executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            if (
                command.arguments != registered_arguments
                or command.registration_id != registered_id
                or command.expected_executable_sha256 != executable_digest
            ):
                raise PermissionError("trusted Python validator command is not registered")
            module_identity = Verifier._resolve_module_identity(
                executable, validator, environment
            )
            origin = Path(str(module_identity["origin"])).resolve()
            trusted_roots = {
                Path(sys.base_prefix).resolve(),
                Path(sys.prefix).resolve(),
            }
            if origin.is_relative_to(workspace.resolve()) or not any(
                origin.is_relative_to(root) for root in trusted_roots
            ):
                raise PermissionError("validator module is outside the trusted environment")
            try:
                package_version = importlib.metadata.version(validator)
            except importlib.metadata.PackageNotFoundError:
                package_version = None
            identity: dict[str, object] = {
                "registration_id": command.registration_id or f"python-module:{validator}",
                "validator": validator,
                "canonical_executable": str(executable),
                "executable_sha256": executable_digest,
                "interpreter_version": sys.version,
                "module": validator,
                "module_origin": str(origin),
                "trusted_roots": sorted(str(root) for root in trusted_roots),
                "package_version": package_version,
                "environment_policy": "isolated-no-user-site-no-pythonpath",
            }
            return (
                [str(executable), "-I", *command.arguments[1:]],
                identity,
                environment,
            )
        if validator == "foundation-script":
            if (
                len(command.arguments) != 2
                or command.registration_id != "keeper:foundation:v1"
                or command.expected_sha256 is None
                or command.expected_executable_sha256 is None
                or command.trusted_root is None
            ):
                raise PermissionError("foundation validator registration is incomplete")
            launcher = Path(command.arguments[0])
            script = Path(command.arguments[1])
            if (
                not launcher.is_absolute()
                or launcher.is_symlink()
                or not launcher.is_file()
                or not script.is_absolute()
                or script.is_symlink()
            ):
                raise PermissionError(
                    "foundation launcher and validator must be absolute regular files"
                )
            resolved_launcher = launcher.resolve(strict=True)
            registered_launcher = trusted_bash_launcher()
            if (
                registered_launcher is None
                or resolved_launcher != registered_launcher
            ):
                raise PermissionError(
                    "foundation launcher does not match its immutable registration"
                )
            resolved = script.resolve(strict=True)
            expected_script = (
                command.trusted_root.resolve()
                / "scripts"
                / "verify-foundation.sh"
            ).resolve(strict=True)
            if resolved != expected_script:
                raise PermissionError("foundation script is outside its trusted root")
            digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
            launcher_digest = hashlib.sha256(
                resolved_launcher.read_bytes()
            ).hexdigest()
            if (
                digest != command.expected_sha256
                or launcher_digest != command.expected_executable_sha256
            ):
                raise PermissionError(
                    "foundation launcher or validator changed after registration"
                )
            arguments = [str(resolved_launcher), str(resolved)]
            return (
                arguments,
                {
                    "registration_id": command.registration_id
                    or "repository-script:foundation",
                    "validator": validator,
                    "resolved_script": str(resolved),
                    "script_sha256": digest,
                    "canonical_executable": str(resolved_launcher),
                    "executable_sha256": launcher_digest,
                    "environment_policy": "filtered",
                },
                environment,
            )
        raise PermissionError("verification command has no immutable registration")

    @staticmethod
    def _resolve_module_identity(
        executable: Path, module: str, environment: dict[str, str]
    ) -> dict[str, object]:
        probe = (
            "import importlib.util,json;"
            f"s=importlib.util.find_spec({module!r});"
            "print(json.dumps({'origin': s.origin if s else None}))"
        )
        completed = subprocess.run(
            [str(executable), "-I", "-c", probe],
            cwd=executable.parent,
            env=environment,
            capture_output=True,
            text=True,
            shell=False,
            timeout=15,
            check=False,
        )
        if completed.returncode:
            raise PermissionError("trusted validator identity could not be resolved")
        try:
            identity = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise PermissionError("trusted validator identity is malformed") from error
        if not isinstance(identity, dict) or not identity.get("origin"):
            raise PermissionError("trusted validator module is unavailable")
        return identity

    @staticmethod
    def required_passed(results: list[VerificationResult]) -> bool:
        return bool(results) and any(result.required for result in results) and all(
            result.passed for result in results if result.required
        )


def verification_evidence(
    *,
    task_id: str,
    attempt_id: str,
    run_id: str,
    stage: str,
    workspace: Path,
    branch: str,
    head: str,
    tree_identity: str,
    results: list[VerificationResult],
) -> dict[str, object]:
    return {
        "task_id": task_id,
        "attempt_id": attempt_id,
        "run_id": run_id,
        "stage": stage,
        "workspace": str(workspace.resolve()),
        "branch": branch,
        "head": head,
        "tree_identity": tree_identity,
        "timestamp": now_iso(),
        "passed": Verifier.required_passed(results),
        "commands": [result.to_dict() for result in results],
    }
