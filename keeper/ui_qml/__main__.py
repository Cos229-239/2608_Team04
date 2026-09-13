from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from keeper.app.service import KeeperApplication
from keeper.app.storage import default_data_directory
from keeper.ui_qml import run_desktop


_QA_MARKER = ".keeper-qa-profile"


def _public_diagnostics(application: KeeperApplication) -> dict[str, Any]:
    """Return a pathless, primitive diagnostics contract for packaged support."""
    source = application.diagnostics()
    authority = source.get("authority_service")
    safe_authority: dict[str, Any] = {}
    if isinstance(authority, dict):
        for key in (
            "service_version",
            "protocol_version",
            "schema_version",
            "service_key_id",
            "service_key_version",
            "observer_available",
        ):
            value = authority.get(key)
            if value is None or isinstance(value, (str, int, float, bool)):
                safe_authority[key] = value
    safe_providers: list[dict[str, Any]] = []
    providers = source.get("providers")
    if isinstance(providers, list):
        for provider in providers:
            if not isinstance(provider, dict):
                continue
            safe_providers.append(
                {
                    key: provider.get(key)
                    for key in (
                        "provider_id",
                        "display_name",
                        "available",
                        "version",
                        "verification_status",
                        "discovery_state",
                        "role_eligibility",
                        "independence_classification",
                        "provider_policy",
                    )
                }
            )
    return {
        "keeper_version": source.get("keeper_version"),
        "python": source.get("python"),
        "python_supported": source.get("python_supported"),
        "git_available": source.get("git_available"),
        "data_directory_writable": source.get("data_directory_writable"),
        "local_only": source.get("local_only"),
        "providers": safe_providers,
        "provider_diagnostics_available": source.get("provider_diagnostics_error")
        is None,
        "authority_service_status": source.get("authority_service_status"),
        "authority_service": safe_authority,
    }


def _require_isolated_qa_directory(
    parser: argparse.ArgumentParser, data_directory: Path | None
) -> Path:
    if data_directory is None:
        parser.error("QA modes require an explicit isolated --data-dir")
    resolved = data_directory.resolve()
    if resolved == default_data_directory().resolve():
        parser.error("QA modes refuse the normal Keeper profile")
    if any(part.lower() == ".ai-workflow" for part in resolved.parts):
        parser.error("QA modes refuse protected workflow paths")
    marker = resolved / _QA_MARKER
    if resolved.exists():
        existing = list(resolved.iterdir())
        if existing and not marker.is_file():
            parser.error("QA data directory is not an initialized isolated profile")
    else:
        resolved.mkdir(parents=True)
    if marker.exists():
        if marker.read_text(encoding="utf-8") != "KEEPER_QA_PROFILE_V1\n":
            parser.error("QA profile marker is malformed")
    else:
        with marker.open("x", encoding="utf-8") as stream:
            stream.write("KEEPER_QA_PROFILE_V1\n")
    return resolved


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Keeper Qt Quick desktop")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--diagnostics", action="store_true")
    parser.add_argument("--mock-demo", action="store_true")
    parser.add_argument("--ui-smoke", action="store_true")
    parser.add_argument("--screenshot-dir", type=Path)
    parser.add_argument("--test-ui-fixture", action="store_true")
    options = parser.parse_args(arguments)
    qa_mode = options.mock_demo or options.ui_smoke or options.test_ui_fixture
    if options.test_ui_fixture and not options.ui_smoke:
        parser.error("--test-ui-fixture is valid only with --ui-smoke")
    data_directory = (
        _require_isolated_qa_directory(parser, options.data_dir)
        if qa_mode
        else options.data_dir
    )
    application = KeeperApplication(data_directory)
    if options.diagnostics:
        print(json.dumps(_public_diagnostics(application), indent=2))
        return 0
    if options.mock_demo:
        print(json.dumps(application.run_mock_demo(), indent=2))
        return 0
    if options.ui_smoke:
        application.finish_setup()
    return run_desktop(
        application,
        smoke=options.ui_smoke,
        screenshot_directory=options.screenshot_dir,
        test_fixture=options.test_ui_fixture or options.ui_smoke,
    )


if __name__ == "__main__":
    raise SystemExit(main())
