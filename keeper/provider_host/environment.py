from __future__ import annotations

import hashlib
import hmac
import json
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


_BASE_ALLOWED = {
    "APPDATA",
    "COMPUTERNAME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE",
    "WINDIR",
}
_FORBIDDEN_EXACT = {
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "CODEX_API_KEY",
    "CODEX_CONFIG",
    "CODEX_HOME",
    "OPENAI_API_KEY",
    "OPENAI_ORG_ID",
    "OPENAI_PROJECT_ID",
    "CODEX_CA_CERTIFICATE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
}
_FORBIDDEN_FRAGMENTS = (
    "API_KEY",
    "ACCESS_TOKEN",
    "AUTH_TOKEN",
    "BEARER_TOKEN",
    "CLIENT_SECRET",
    "COOKIE",
    "PASSWORD",
    "PAID_FALLBACK",
    "PROXY",
    "REFRESH_TOKEN",
)


@dataclass(frozen=True, slots=True)
class EnvironmentSnapshot:
    values: dict[str, str]
    allowlist: tuple[str, ...]
    scrubbed_names: tuple[str, ...]
    digest: str
    preparation_nonce: str
    tls_root_bundle: dict[str, object]

    def public_attestation(self) -> dict[str, object]:
        return {
            "allowlist": list(self.allowlist),
            "digest": self.digest,
            "preparation_nonce": self.preparation_nonce,
            "scrubbed_names": list(self.scrubbed_names),
            "tls_root_bundle": dict(self.tls_root_bundle),
        }


def build_sanitized_environment(
    source: Mapping[str, str],
    *,
    profile_path: Path,
    provider_bin: Path,
    preparation_nonce: str,
    attestation_key: bytes,
    exchange_root: Path,
) -> EnvironmentSnapshot:
    profile = profile_path.resolve(strict=True)
    provider = provider_bin.resolve(strict=True)
    if not preparation_nonce or "\x00" in preparation_nonce or not attestation_key:
        raise ValueError("Provider Host environment attestation inputs are required")
    folded: dict[str, tuple[str, str]] = {}
    for raw_name, raw_value in source.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise PermissionError("Provider Host environment entries must be strings")
        if "\x00" in raw_name or "=" in raw_name or "\x00" in raw_value:
            raise PermissionError("Provider Host environment entry shape is invalid")
        upper = raw_name.upper()
        if upper in folded and folded[upper][0] != raw_name:
            raise PermissionError("Provider Host environment has case aliases")
        folded[upper] = (raw_name, raw_value)
    scrubbed = sorted(
        name
        for name in folded
        if name in _FORBIDDEN_EXACT
        or any(fragment in name for fragment in _FORBIDDEN_FRAGMENTS)
        or name.startswith("HTTP_")
        or name.startswith("HTTPS_")
        or name in {"ALL_PROXY", "NO_PROXY"}
    )
    values: dict[str, str] = {}
    for name in sorted(_BASE_ALLOWED):
        item = folded.get(name)
        if item is not None:
            values[name] = item[1]
    system_root = Path(os.environ["SYSTEMROOT"]).resolve(strict=True)
    values["PATH"] = os.pathsep.join((str(provider), str(system_root / "System32")))
    values["USERPROFILE"] = str(profile)
    tls_root_bundle = _materialize_windows_root_bundle(exchange_root)
    values["SSL_CERT_FILE"] = str(tls_root_bundle["canonical_path"])
    _validate_profile_paths(values, profile, system_root)
    canonical = json.dumps(
        {"tls_root_bundle": tls_root_bundle, "values": values},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    digest = hmac.new(
        attestation_key,
        preparation_nonce.encode("utf-8") + b"\0" + canonical,
        hashlib.sha256,
    ).hexdigest()
    return EnvironmentSnapshot(
        values=values,
        allowlist=tuple(sorted(values, key=str.upper)),
        scrubbed_names=tuple(scrubbed),
        digest=digest,
        preparation_nonce=preparation_nonce,
        tls_root_bundle=tls_root_bundle,
    )


def assert_attestation_matches(
    snapshot: EnvironmentSnapshot, declared: Mapping[str, object]
) -> None:
    if declared != snapshot.public_attestation():
        raise PermissionError("Provider Host environment attestation differs")


def _validate_profile_paths(
    values: Mapping[str, str], profile: Path, system_root: Path
) -> None:
    for name in ("APPDATA", "LOCALAPPDATA", "TEMP", "TMP"):
        raw = values.get(name)
        if raw is None:
            continue
        candidate = Path(raw).resolve(strict=True)
        if candidate != profile and profile not in candidate.parents:
            raise PermissionError(f"Provider Host {name} escapes the profile")
    for name in ("SYSTEMROOT", "WINDIR"):
        raw = values.get(name)
        if raw is not None and Path(raw).resolve(strict=True) != system_root:
            raise PermissionError(f"Provider Host {name} differs from Windows")


def _materialize_windows_root_bundle(exchange_root: Path) -> dict[str, object]:
    if os.name != "nt" or not hasattr(ssl, "enum_certificates"):
        raise RuntimeError("Provider Host Windows trust export requires Windows")
    exchange = Path(os.path.abspath(exchange_root))
    if not exchange.is_absolute() or not exchange.is_dir() or exchange.is_symlink():
        raise PermissionError("Provider Host exchange root is invalid")
    canonical_exchange = exchange.resolve(strict=True)
    if canonical_exchange != exchange:
        raise PermissionError("Provider Host exchange root is not canonical")
    trust_root = exchange / "trust"
    trust_root.mkdir(exist_ok=True)
    if trust_root.is_symlink() or trust_root.resolve(strict=True) != trust_root:
        raise PermissionError("Provider Host trust root is invalid")

    server_auth_oid = "1.3.6.1.5.5.7.3.1"
    try:
        disallowed_entries = ssl.enum_certificates("Disallowed")
    except (OSError, ssl.SSLError) as error:
        raise PermissionError(
            "Provider Host Windows disallowed certificate store is unavailable"
        ) from error
    disallowed: set[str] = set()
    for entry in disallowed_entries:
        if (
            not isinstance(entry, tuple)
            or len(entry) != 3
            or not isinstance(entry[0], bytes)
            or entry[1] != "x509_asn"
        ):
            raise PermissionError(
                "Provider Host Windows disallowed certificate store is invalid"
            )
        disallowed.add(hashlib.sha256(entry[0]).hexdigest())
    roots: dict[str, bytes] = {}
    for certificate, encoding, trust in ssl.enum_certificates("ROOT"):
        if encoding != "x509_asn" or not isinstance(certificate, bytes):
            continue
        if trust is not True and (
            not isinstance(trust, (set, frozenset)) or server_auth_oid not in trust
        ):
            continue
        digest = hashlib.sha256(certificate).hexdigest()
        if digest in disallowed:
            continue
        roots[digest] = certificate
    if not roots or len(roots) > 4096:
        raise PermissionError("Provider Host Windows trust root count is invalid")
    content = "".join(
        ssl.DER_cert_to_PEM_cert(roots[digest]) for digest in sorted(roots)
    ).encode("ascii")
    if not content or len(content) > 4 * 1024 * 1024:
        raise PermissionError("Provider Host Windows trust bundle size is invalid")
    digest = hashlib.sha256(content).hexdigest()
    target = trust_root / f"windows-roots-{digest}.pem"
    try:
        with target.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        pass
    if target.is_symlink() or target.resolve(strict=True) != target:
        raise PermissionError("Provider Host Windows trust bundle is invalid")
    observed = target.read_bytes()
    if observed != content:
        raise PermissionError("Provider Host Windows trust bundle differs")
    stat = target.stat()
    return {
        "canonical_path": str(target),
        "certificate_count": len(roots),
        "file_identity": {
            "device_id": int(stat.st_dev),
            "file_id": int(stat.st_ino),
            "modified_ns": int(stat.st_mtime_ns),
            "schema_version": 1,
            "size": int(stat.st_size),
        },
        "sha256": digest,
        "size": len(content),
        "source": "windows-root-store",
    }
