"""Installer-only Host preflight. Never replace an enrolled Host on reinstall."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.authority_service.windows_signature import authenticode_enrollment_binding
from keeper.provider_host import cli
from keeper.provider_host.install import ProviderHostInstaller, _verify_package
from keeper.provider_host.protocol import structured_digest


def verify_enrollment(installer, current, authority, diagnostics, binding):
    """Read only: retain the receipt, checkpoint, keys, and executable file IDs."""
    receipt_path = installer.state / "provider-host-enrollment.json"
    if cli._revoked_status(receipt_path) is not None:
        raise PermissionError("Host enrollment is revoked; use the supported recovery flow")
    runtime, installation = cli._startup_configuration(receipt_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))["payload"]
    checkpoint = json.loads(
        (installer.state / "provider-host-enrollment-pending.json").read_text(encoding="utf-8")
    )
    expected_id = "provider-host-enrollment:" + hashlib.sha256(
        (runtime["host_id"] + ":" + structured_digest(checkpoint["proposal"])).encode("utf-8")
    ).hexdigest()
    status = authority.provider_host_enrollment_status()
    if (
        status.get("state") != "ENROLLED_OFFLINE"
        or status.get("enrollment_id") != expected_id
        or status.get("enrollment_id") != runtime["enrollment_id"]
        or status.get("enrollment_generation") != receipt["enrollment_generation"]
        or receipt["service_key_id"] != diagnostics["service_key_id"]
        or runtime["user_binding"] != {
            "user_sid": binding.user_sid,
            "session_id": binding.session_id,
            "profile_path": binding.profile_path,
        }
    ):
        raise PermissionError("Host enrollment differs from live Authority or this session; use recovery")
    executable = Path(current["artifact_path"]).resolve(strict=True)
    stat = executable.stat()
    expected = {
        "authenticode_binding": authenticode_enrollment_binding(executable),
        "executable_file_identity": {
            "schema_version": 1, "device_id": stat.st_dev, "file_id": stat.st_ino,
            "modified_ns": stat.st_mtime_ns, "size": stat.st_size,
        },
        "executable_path": str(executable),
        "executable_sha256": current["artifact_sha256"],
        "executable_size": stat.st_size,
        "install_root": str(installer.root.resolve(strict=True)),
        "manifest_sha256": current["package_sha256"],
        "package_version": current["version"],
    }
    if installation != expected:
        raise PermissionError("Host enrolled installation identity differs; use recovery, not reinstall")
    installer.attest_protected_tree()


def ensure_host(payload: Path, install_root: Path, startup_root: Path, *, check_only=False):
    authority = ProductionAuthorityServiceClient()
    diagnostics = authority.require_live_identity()
    cli._validate_authority_compatibility(diagnostics)
    binding = cli.current_user_binding()
    if diagnostics["client_sid"].casefold() != binding.user_sid.casefold():
        raise PermissionError("Installer account differs from Authority client")
    expected_root = Path(binding.profile_path) / "AppData/Local/Programs/DarkSage/KeeperProviderHost"
    if os.path.normcase(str(install_root.absolute())) != os.path.normcase(str(expected_root.absolute())):
        raise PermissionError("Host installer path differs from production enrollment")
    expected_startup = Path(binding.profile_path) / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    if os.path.normcase(str(startup_root.absolute())) != os.path.normcase(str(expected_startup.absolute())):
        raise PermissionError("Host startup path differs from production enrollment")
    installer = ProviderHostInstaller(
        install_root, startup_root, owner_sid=binding.user_sid,
        authority_service_sid=cli._authority_service_sid(),
    )
    if installer.transaction_path.exists():
        raise PermissionError("Host lifecycle transaction is pending; resolve it before setup")
    manifest_path = payload / "provider-host/keeper-provider-host-package-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    package = _verify_package(
        payload / "provider-host/KeeperProviderHost.exe", version=manifest["version"],
        expected_manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        require_defender=True,
    )
    current = installer.status()["current"]
    if current is not None:
        if current["version"] != manifest["version"]:
            raise PermissionError("Existing Host version differs; use the approved Host upgrade flow")
        # No install/update/repair call here: replacing identical bytes changes
        # the file identity bound into the protected enrollment.
        installer._installed_package(
            current["version"], current["package_sha256"], require_defender=True
        )
        installer.attest_protected_tree()
    elif installer.root.exists() and any(installer.root.iterdir()):
        raise PermissionError("Partial Host installation exists; use recovery before setup")

    status = authority.provider_host_enrollment_status()
    receipt_path = installer.state / "provider-host-enrollment.json"
    if receipt_path.exists():
        if current is None:
            raise PermissionError("Enrollment exists without its installed Host")
        verify_enrollment(installer, current, authority, diagnostics, binding)
        return "Existing enrolled Host verified and retained (not replaced by bundled Host); desktop may now update"
    if (
        status.get("state") != "NOT_INSTALLED"
        or status.get("installed") is not False
        or any(installer.state.glob("provider-host-enrollment*.json"))
        or (installer.state / "provider-host.db").exists()
    ):
        raise PermissionError("Existing enrollment/state must be recovered; setup will not reset it")
    if current is not None and (
        current["package_sha256"].lower() != package.manifest_sha256.lower()
        or current["artifact_sha256"].lower() != package.executable_sha256.lower()
    ):
        raise PermissionError("Unenrolled Host package differs from setup; use the approved upgrade flow")
    if check_only:
        return "Initial Host installation/enrollment required; no changes made"
    if current is None:
        installer.install(
            package.executable, version=manifest["version"],
            expected_package_sha256=package.manifest_sha256,
        )
    # Only a genuinely unenrolled installation reaches initial generation 1.
    # This uses the existing interactive Founder confirmation, never a bypass.
    cli._production_enrollment_client().enroll(generation=1)
    verify_enrollment(installer, installer.status()["current"], authority, diagnostics, binding)
    return "Initial Host installation and Founder-approved enrollment verified"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--startup-root", type=Path, required=True)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    try:
        print(ensure_host(args.payload, args.install_root, args.startup_root, check_only=args.check_only))
    except Exception as error:
        print(f"Keeper Host setup stopped: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
