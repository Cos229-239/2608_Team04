from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

from keeper.authority_service.core import SERVICE_VERSION
from keeper.authority_service.protocol import PROTOCOL_VERSION
from keeper.authority_service.store import SERVICE_SCHEMA_VERSION
from keeper.provider_host.protocol import HOST_PROTOCOL


PACKAGE_MANIFEST = "keeper-authority-package.json"
PACKAGE_SCHEMA_VERSION = 1
ENTRYPOINT = "keeper.authority_service.service_main:main"
ROOT_MODULE = "keeper.authority_service.service_main"
_ENTRY_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_ENTRY_MODE = (0o100644 & 0xFFFF) << 16
_FORBIDDEN_PARTS = {
    ".ai-workflow",
    "__pycache__",
    "tests",
    "test",
    "assets",
    "ui",
    "ui_qml",
    "app",
}
_REQUIRED_RUNTIME_ENTRIES = {
    "keeper/authority_service/core.py",
    "keeper/authority_service/protocol.py",
    "keeper/authority_service/provider_host_enrollment.py",
    "keeper/authority_service/service_main.py",
    "keeper/authority_service/store.py",
    "keeper/authority_service/codex_registration.py",
    "keeper/provider_host/enrollment.py",
    "keeper/provider_host/protocol.py",
}


@dataclass(frozen=True)
class VerifiedServicePackage:
    path: Path
    package_sha256: str
    package_size: int
    manifest: dict[str, Any]


@dataclass(frozen=True)
class VerifiedRollbackPackage:
    path: Path
    package_sha256: str
    package_size: int


def build_service_package(source_root: Path, destination: Path) -> VerifiedServicePackage:
    source = source_root.resolve(strict=True)
    target = destination.resolve(strict=False)
    if target.exists():
        raise PermissionError("Authority package destination already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    modules = _service_module_closure(source)
    main_content = (
        b"from keeper.authority_service.service_main import main\n"
        b"raise SystemExit(main())\n"
    )
    payload: list[tuple[str, bytes]] = [("__main__.py", main_content)]
    payload.extend(
        (archive_name, path.read_bytes())
        for archive_name, path in sorted(modules.items())
    )
    entries = [_entry_record(name, content) for name, content in payload]
    manifest = {
        "entrypoint": ENTRYPOINT,
        "entries": entries,
        "package_schema_version": PACKAGE_SCHEMA_VERSION,
        "provider_host_protocol": HOST_PROTOCOL,
        "protocol_version": PROTOCOL_VERSION,
        "service_schema_version": SERVICE_SCHEMA_VERSION,
        "service_version": SERVICE_VERSION,
        "source_tree_sha256": _source_tree_digest(entries),
    }
    manifest_content = _canonical_json(manifest)
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in payload:
            _write_entry(archive, name, content)
        _write_entry(archive, PACKAGE_MANIFEST, manifest_content)
    return verify_service_package(target)


def verify_service_package(
    package: Path, expected_sha256: str | None = None
) -> VerifiedServicePackage:
    path = package.resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise PermissionError("Authority package must be a regular canonical file")
    package_digest = _digest_file(path)
    if expected_sha256 is not None:
        normalized = expected_sha256.upper()
        if len(normalized) != 64 or any(value not in "0123456789ABCDEF" for value in normalized):
            raise ValueError("expected Authority package SHA-256 is invalid")
        if package_digest != normalized:
            raise PermissionError("Authority package SHA-256 differs from authorization")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(names) != len(set(names)) or not names or names[-1] != PACKAGE_MANIFEST:
                raise PermissionError("Authority package entry order or uniqueness is invalid")
            if any(not _safe_archive_name(name) for name in names):
                raise PermissionError("Authority package contains an unsafe entry")
            for info in infos:
                if (
                    info.date_time != _ENTRY_TIMESTAMP
                    or info.compress_type != zipfile.ZIP_DEFLATED
                    or info.create_system != 3
                    or info.external_attr != _ENTRY_MODE
                    or info.flag_bits & 0x1
                ):
                    raise PermissionError("Authority package metadata is not deterministic")
            manifest_value = json.loads(archive.read(PACKAGE_MANIFEST))
            manifest = _validate_manifest(manifest_value)
            entries = manifest["entries"]
            expected_names = [str(item["path"]) for item in entries] + [PACKAGE_MANIFEST]
            if names != expected_names:
                raise PermissionError("Authority package manifest coverage differs")
            for entry in entries:
                content = archive.read(str(entry["path"]))
                if len(content) != entry["size"] or _digest_bytes(content) != entry["sha256"]:
                    raise PermissionError("Authority package entry digest differs")
            if _source_tree_digest(entries) != manifest["source_tree_sha256"]:
                raise PermissionError("Authority package source-tree digest differs")
    except (KeyError, TypeError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        raise PermissionError("Authority package is invalid") from error
    return VerifiedServicePackage(path, package_digest, path.stat().st_size, manifest)


def verify_rollback_package(
    package: Path, expected_sha256: str
) -> VerifiedRollbackPackage:
    path = package.resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise PermissionError("Authority rollback package must be a regular canonical file")
    normalized = expected_sha256.upper()
    if len(normalized) != 64 or any(value not in "0123456789ABCDEF" for value in normalized):
        raise ValueError("expected Authority rollback SHA-256 is invalid")
    digest = _digest_file(path)
    if digest != normalized:
        raise PermissionError("Authority rollback package SHA-256 differs")
    try:
        with zipfile.ZipFile(path) as archive:
            names = [item.filename for item in archive.infolist()]
            if (
                len(names) != len(set(names))
                or "__main__.py" not in names
                or any(not _safe_legacy_archive_name(name) for name in names)
            ):
                raise PermissionError("Authority rollback archive is invalid")
    except zipfile.BadZipFile as error:
        raise PermissionError("Authority rollback archive is invalid") from error
    return VerifiedRollbackPackage(path, digest, path.stat().st_size)


def write_external_manifest(
    verified: VerifiedServicePackage, destination: Path, *, source_root: Path
) -> Path:
    target = destination.resolve(strict=False)
    if target.exists():
        raise PermissionError("Authority package manifest destination already exists")
    source_commit, source_tree = _verify_packaged_git_source(
        verified, source_root.resolve(strict=True)
    )
    value = {
        "archive_manifest": verified.manifest,
        "packaged_entries_match_source_commit": True,
        "package_path": str(verified.path),
        "package_sha256": verified.package_sha256,
        "package_size": verified.package_size,
        "source_commit": source_commit,
        "source_tree": source_tree,
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_canonical_json(value))
    return target


def verify_external_manifest(
    verified: VerifiedServicePackage,
    manifest_path: Path,
    expected_sha256: str,
    *,
    source_root: Path,
) -> dict[str, Any]:
    """Bind exact candidate bytes to their committed Git source identity."""
    path = manifest_path.resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise PermissionError("Authority external manifest must be a canonical file")
    normalized = expected_sha256.upper()
    if (
        len(normalized) != 64
        or any(value not in "0123456789ABCDEF" for value in normalized)
    ):
        raise ValueError("expected Authority external-manifest SHA-256 is invalid")
    content = path.read_bytes()
    if _digest_bytes(content) != normalized:
        raise PermissionError("Authority external-manifest SHA-256 differs")
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PermissionError("Authority external manifest is invalid") from error
    expected_fields = {
        "archive_manifest",
        "packaged_entries_match_source_commit",
        "package_path",
        "package_sha256",
        "package_size",
        "source_commit",
        "source_tree",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or content != _canonical_json(value)
        or value.get("archive_manifest") != verified.manifest
        or value.get("packaged_entries_match_source_commit") is not True
        or value.get("package_path") != str(verified.path)
        or value.get("package_sha256") != verified.package_sha256
        or value.get("package_size") != verified.package_size
    ):
        raise PermissionError("Authority external manifest binding differs")
    commit, tree = _verify_packaged_git_source(
        verified, source_root.resolve(strict=True)
    )
    if value.get("source_commit") != commit or value.get("source_tree") != tree:
        raise PermissionError("Authority external manifest source identity differs")
    return dict(value)


def _verify_packaged_git_source(
    verified: VerifiedServicePackage, source_root: Path
) -> tuple[str, str]:
    commit = _git_value(source_root, "HEAD")
    tree = _git_value(source_root, "HEAD^{tree}")
    for entry in verified.manifest["entries"]:
        name = str(entry["path"])
        if name == "__main__.py":
            continue
        completed = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={source_root.as_posix()}",
                "-C",
                str(source_root),
                "show",
                f"{commit}:{name}",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        if (
            completed.returncode != 0
            or _digest_bytes(completed.stdout) != entry["sha256"]
        ):
            raise PermissionError(
                f"Authority package entry differs from recorded source commit: {name}"
            )
    return commit, tree


def _service_module_closure(source_root: Path) -> dict[str, Path]:
    pending = [ROOT_MODULE]
    visited: set[str] = set()
    result: dict[str, Path] = {}
    while pending:
        module = pending.pop()
        if module in visited or not module.startswith("keeper"):
            continue
        visited.add(module)
        path = _module_path(source_root, module)
        if path is None:
            raise PermissionError(
                f"Authority service dependency is missing from source: {module}"
            )
        archive_name = path.relative_to(source_root).as_posix()
        if _forbidden_archive_name(archive_name):
            raise PermissionError(f"Authority service dependency is outside the service closure: {module}")
        result[archive_name] = path
        pending.extend(_parent_packages(module))
        pending.extend(_keeper_imports(source_root, module, path))
    missing = _REQUIRED_RUNTIME_ENTRIES.difference(result)
    if missing:
        raise PermissionError(f"Authority package required runtime closure is missing: {sorted(missing)}")
    return result


def _keeper_imports(source_root: Path, module: str, path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    found: set[str] = set()

    class ImportVisitor(ast.NodeVisitor):
        _ignore_nested_imports = path.name == "__init__.py"

        def visit_Import(self, node: ast.Import) -> None:
            found.update(alias.name for alias in node.names if alias.name.startswith("keeper"))

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            imported = node.module or ""
            if node.level:
                try:
                    imported = importlib.util.resolve_name("." * node.level + imported, package)
                except (ImportError, ValueError):
                    return
            if imported.startswith("keeper"):
                found.add(imported)
                for alias in node.names:
                    candidate = f"{imported}.{alias.name}"
                    if _module_path(source_root, candidate) is not None:
                        found.add(candidate)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if not self._ignore_nested_imports:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if not self._ignore_nested_imports:
                self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            if not self._ignore_nested_imports:
                self.generic_visit(node)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            if not self._ignore_nested_imports:
                self.generic_visit(node)

    ImportVisitor().visit(tree)
    return found


def _module_path(source_root: Path, module: str) -> Path | None:
    relative = Path(*module.split("."))
    module_file = source_root / relative.with_suffix(".py")
    if module_file.is_file():
        return module_file.resolve(strict=True)
    package_file = source_root / relative / "__init__.py"
    if package_file.is_file():
        return package_file.resolve(strict=True)
    return None


def _parent_packages(module: str) -> Iterable[str]:
    parts = module.split(".")[:-1]
    for index in range(1, len(parts) + 1):
        yield ".".join(parts[:index])


def _validate_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "entrypoint",
        "entries",
        "package_schema_version",
        "provider_host_protocol",
        "protocol_version",
        "service_schema_version",
        "service_version",
        "source_tree_sha256",
    }:
        raise PermissionError("Authority package manifest shape is invalid")
    if (
        value.get("entrypoint") != ENTRYPOINT
        or value.get("package_schema_version") != PACKAGE_SCHEMA_VERSION
        or value.get("provider_host_protocol") != HOST_PROTOCOL
        or value.get("protocol_version") != PROTOCOL_VERSION
        or value.get("service_schema_version") != SERVICE_SCHEMA_VERSION
        or value.get("service_version") != SERVICE_VERSION
    ):
        raise PermissionError("Authority package contract identity differs")
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries:
        raise PermissionError("Authority package entry manifest is invalid")
    previous = ""
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise PermissionError("Authority package entry is invalid")
        name = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size")
        if (
            not isinstance(name, str)
            or not _safe_archive_name(name)
            or (index > 0 and name <= previous)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789ABCDEF" for character in digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise PermissionError("Authority package entry identity is invalid")
        previous = name
    if not _REQUIRED_RUNTIME_ENTRIES.issubset({str(item["path"]) for item in entries}):
        raise PermissionError("Authority package runtime closure is incomplete")
    source_digest = value.get("source_tree_sha256")
    if not isinstance(source_digest, str) or len(source_digest) != 64:
        raise PermissionError("Authority package source-tree identity is invalid")
    return dict(value)


def _entry_record(name: str, content: bytes) -> dict[str, object]:
    return {"path": name, "sha256": _digest_bytes(content), "size": len(content)}


def _source_tree_digest(entries: list[dict[str, Any]]) -> str:
    return _digest_bytes(_canonical_json(entries))


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _write_entry(archive: zipfile.ZipFile, name: str, content: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=_ENTRY_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = _ENTRY_MODE
    archive.writestr(info, content)


def _safe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and "\\" not in name
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
        and not _forbidden_archive_name(name)
        and not name.endswith((".pyc", ".pyo"))
    )


def _safe_legacy_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and "\\" not in name
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _forbidden_archive_name(name: str) -> bool:
    return any(part.lower() in _FORBIDDEN_PARTS for part in PurePosixPath(name).parts)


def _digest_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest().upper()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _git_value(source_root: Path, revision: str) -> str:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={source_root.as_posix()}", "-C", str(source_root), "rev-parse", revision],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    return completed.stdout.strip()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="keeper-authority-package")
    commands = result.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--manifest-output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--package", type=Path, required=True)
    verify.add_argument("--expected-sha256", required=True)
    rollback = commands.add_parser("verify-rollback")
    rollback.add_argument("--package", type=Path, required=True)
    rollback.add_argument("--expected-sha256", required=True)
    return result


def main(arguments: Sequence[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "build":
            verified = build_service_package(options.source_root, options.output)
            write_external_manifest(verified, options.manifest_output, source_root=options.source_root)
        elif options.command == "verify":
            verified = verify_service_package(options.package, options.expected_sha256)
        else:
            rollback = verify_rollback_package(options.package, options.expected_sha256)
            print(json.dumps({
                "package": str(rollback.path),
                "package_sha256": rollback.package_sha256,
                "package_size": rollback.package_size,
                "rollback": True,
            }, indent=2, sort_keys=True))
            return 0
        print(json.dumps({
            "manifest": verified.manifest,
            "package": str(verified.path),
            "package_sha256": verified.package_sha256,
            "package_size": verified.package_size,
        }, indent=2, sort_keys=True))
        return 0
    except (FileNotFoundError, OSError, PermissionError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
