from __future__ import annotations

import hashlib
import os
import ssl
from pathlib import Path

import pytest

from keeper.provider_host import environment as host_environment
from keeper.provider_host.environment import build_sanitized_environment
from keeper.provider_host.windows_process import locked_tls_root_bundle


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows trust store required")


def _profile_paths(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    profile = tmp_path / "profile"
    system_root = tmp_path / "Windows"
    provider_bin = profile / "Programs" / "Codex"
    exchange = profile / "AppData" / "Local" / "DarkSage" / "KeeperProviderExchange"
    for path in (
        profile / "AppData" / "Local" / "Temp",
        profile / "AppData" / "Roaming",
        system_root / "System32",
        provider_bin,
        exchange,
    ):
        path.mkdir(parents=True)
    return profile, system_root, provider_bin, exchange


def _source(profile: Path, system_root: Path) -> dict[str, str]:
    return {
        "APPDATA": str(profile / "AppData" / "Roaming"),
        "CODEX_CA_CERTIFICATE": r"C:\untrusted\codex.pem",
        "CURL_CA_BUNDLE": r"C:\untrusted\curl.pem",
        "LOCALAPPDATA": str(profile / "AppData" / "Local"),
        "REQUESTS_CA_BUNDLE": r"C:\untrusted\requests.pem",
        "SSL_CERT_FILE": r"C:\untrusted\ssl.pem",
        "SYSTEMROOT": str(system_root),
        "TEMP": str(profile / "AppData" / "Local" / "Temp"),
        "TMP": str(profile / "AppData" / "Local" / "Temp"),
        "USERPROFILE": str(profile),
        "WINDIR": str(system_root),
    }


def test_windows_root_bundle_is_deterministic_filtered_and_attested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, system_root, provider_bin, exchange = _profile_paths(tmp_path)
    monkeypatch.setenv("SYSTEMROOT", str(system_root))
    server_auth = "1.3.6.1.5.5.7.3.1"
    roots = [
        (b"root-b", "x509_asn", True),
        (b"root-a", "x509_asn", {server_auth}),
        (b"root-a", "x509_asn", {server_auth}),
        (b"client-only", "x509_asn", {"1.3.6.1.5.5.7.3.2"}),
        (b"ignored", "pkcs_7_asn", True),
    ]
    monkeypatch.setattr(
        ssl,
        "enum_certificates",
        lambda store: [] if store == "Disallowed" else list(roots),
    )

    first = build_sanitized_environment(
        _source(profile, system_root),
        profile_path=profile,
        provider_bin=provider_bin,
        preparation_nonce="nonce-one",
        attestation_key=b"environment-key",
        exchange_root=exchange,
    )
    roots.reverse()
    second = build_sanitized_environment(
        _source(profile, system_root),
        profile_path=profile,
        provider_bin=provider_bin,
        preparation_nonce="nonce-two",
        attestation_key=b"environment-key",
        exchange_root=exchange,
    )

    assert first.tls_root_bundle == second.tls_root_bundle
    bundle = first.tls_root_bundle
    assert bundle["certificate_count"] == 2
    assert first.values["SSL_CERT_FILE"] == bundle["canonical_path"]
    assert "SSL_CERT_FILE" in first.allowlist
    assert {
        "CODEX_CA_CERTIFICATE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
    }.issubset(first.scrubbed_names)
    content = Path(str(bundle["canonical_path"])).read_bytes()
    assert hashlib.sha256(content).hexdigest() == bundle["sha256"]
    assert content.count(b"-----BEGIN CERTIFICATE-----") == 2
    assert first.digest != second.digest
    assert first.public_attestation()["tls_root_bundle"] == bundle


@pytest.mark.parametrize(
    "roots",
    [[], [(b"client-only", "x509_asn", {"1.3.6.1.5.5.7.3.2"})]],
)
def test_windows_root_bundle_fails_closed_without_server_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    roots: list[tuple[bytes, str, object]],
) -> None:
    profile, system_root, provider_bin, exchange = _profile_paths(tmp_path)
    monkeypatch.setenv("SYSTEMROOT", str(system_root))
    monkeypatch.setattr(
        ssl,
        "enum_certificates",
        lambda store: [] if store == "Disallowed" else roots,
    )
    with pytest.raises(PermissionError, match="root count"):
        build_sanitized_environment(
            _source(profile, system_root),
            profile_path=profile,
            provider_bin=provider_bin,
            preparation_nonce="no-roots",
            attestation_key=b"environment-key",
            exchange_root=exchange,
        )


def test_tls_root_bundle_lock_denies_mutation_and_revalidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, system_root, provider_bin, exchange = _profile_paths(tmp_path)
    monkeypatch.setenv("SYSTEMROOT", str(system_root))
    monkeypatch.setattr(
        ssl,
        "enum_certificates",
        lambda store: (
            [] if store == "Disallowed" else [(b"root-a", "x509_asn", True)]
        ),
    )
    snapshot = build_sanitized_environment(
        _source(profile, system_root),
        profile_path=profile,
        provider_bin=provider_bin,
        preparation_nonce="locked-root",
        attestation_key=b"environment-key",
        exchange_root=exchange,
    )
    path = Path(str(snapshot.tls_root_bundle["canonical_path"]))
    with locked_tls_root_bundle(snapshot.values, snapshot.tls_root_bundle):
        with pytest.raises(PermissionError):
            path.write_bytes(b"replacement")
        with pytest.raises(PermissionError):
            path.unlink()
    changed = dict(snapshot.tls_root_bundle)
    changed["sha256"] = "0" * 64
    with pytest.raises(PermissionError, match="identity changed"):
        with locked_tls_root_bundle(snapshot.values, changed):
            pass


def test_windows_root_bundle_rejects_noncanonical_exchange(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not hasattr(os, "symlink"):
        pytest.fail("Windows symlink API is unavailable")
    profile, system_root, provider_bin, exchange = _profile_paths(tmp_path)
    monkeypatch.setenv("SYSTEMROOT", str(system_root))
    monkeypatch.setattr(
        ssl,
        "enum_certificates",
        lambda store: (
            [] if store == "Disallowed" else [(b"root-a", "x509_asn", True)]
        ),
    )
    alias = tmp_path / "exchange-alias"
    try:
        alias.symlink_to(exchange, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Windows symlink privilege unavailable: {error}")
    with pytest.raises(PermissionError, match="exchange root"):
        host_environment._materialize_windows_root_bundle(alias)


def test_windows_disallowed_store_excludes_overlapping_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, _, exchange = _profile_paths(tmp_path)

    def certificates(store: str) -> list[tuple[bytes, str, object]]:
        if store == "Disallowed":
            return [(b"blocked-root", "x509_asn", True)]
        return [
            (b"allowed-root", "x509_asn", True),
            (b"blocked-root", "x509_asn", True),
        ]

    monkeypatch.setattr(ssl, "enum_certificates", certificates)
    bundle = host_environment._materialize_windows_root_bundle(exchange)
    content = Path(str(bundle["canonical_path"])).read_bytes()
    assert bundle["certificate_count"] == 1
    assert ssl.DER_cert_to_PEM_cert(b"allowed-root").encode("ascii") in content
    assert ssl.DER_cert_to_PEM_cert(b"blocked-root").encode("ascii") not in content


@pytest.mark.parametrize(
    "failure",
    [OSError("store unavailable"), [(b"opaque", "pkcs_7_asn", True)]],
)
def test_windows_disallowed_store_fails_closed_when_not_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: object,
) -> None:
    _, _, _, exchange = _profile_paths(tmp_path)

    def certificates(store: str) -> list[tuple[bytes, str, object]]:
        if store != "Disallowed":
            return [(b"allowed-root", "x509_asn", True)]
        if isinstance(failure, BaseException):
            raise failure
        return failure  # type: ignore[return-value]

    monkeypatch.setattr(ssl, "enum_certificates", certificates)
    with pytest.raises(PermissionError, match="disallowed certificate store"):
        host_environment._materialize_windows_root_bundle(exchange)
