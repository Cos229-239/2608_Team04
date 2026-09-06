from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from keeper.agent_runner import AgentRunner
from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service import service_install
from keeper.config import KeeperConfig
from keeper.orchestrator import Keeper
from keeper.policies import filtered_environment
from keeper.providers.authority_service import AuthorityServiceProvider
from keeper.providers.mock import MockProvider
from keeper.providers.ollama import OllamaProvider
from keeper.providers.routing import ProviderRouter
from keeper.task_queue import TaskQueue
from keeper.verifier import VerificationCommand, Verifier
from keeper.workspace import WorkspaceManager


authority_client_factory: Callable[[Path], AuthorityServiceClient] = (
    lambda _root: AuthorityServiceClient()
)


def build_keeper(root: Path, mock: bool = False) -> Keeper:
    config = KeeperConfig.load(root)
    registration = config.provider_registration or {}
    authority = authority_client_factory(root)

    def command_provider() -> AuthorityServiceProvider:
        if not config.provider_command:
            raise PermissionError("provider command is missing")
        executable = config.provider_command[0]
        provider_id = str(registration.get("logical_provider_id") or "")
        registration_id = registration.get("trusted_registration_id")
        if not provider_id or not isinstance(registration_id, str):
            raise PermissionError(
                "standalone provider service registration is missing"
            )
        protected = authority.query_state("registrations", registration_id)
        authoritative = protected.get("record")
        if not isinstance(authoritative, dict):
            raise PermissionError(
                "standalone provider is not registered with the Authority Service"
            )
        state = authoritative.pop("service_state", None)
        if (
            state != "QUALIFIED"
            or authoritative.get("configuration_digest")
            != registration.get("configuration_digest")
            or authoritative.get("logical_provider_id") != provider_id
        ):
            raise PermissionError(
                "standalone provider service qualification is inconsistent"
            )
        expected_invocation = registration.get("invocation_shape")
        actual_invocation = list(config.provider_command)
        if registration.get("script_path") is not None:
            actual_invocation = [
                str(registration.get("launcher_path")),
                "/d",
                "/c",
                str(registration.get("script_path")),
                *actual_invocation[1:],
            ]
        if actual_invocation != expected_invocation:
            raise PermissionError(
                "provider command differs from canonical registration invocation"
            )
        provider = AuthorityServiceProvider(authority, authoritative)
        provider.validate()
        return provider
    provider = (
        MockProvider(output={"status": "completed", "files_changed": [], "findings": []})
        if mock
        else command_provider()
    )
    reviewer_provider = (
        MockProvider(output={"status": "completed", "files_changed": [], "findings": []})
        if mock
        else command_provider()
    )
    repairer_provider = (
        MockProvider(output={"status": "completed", "files_changed": [], "findings": []})
        if mock
        else command_provider()
    )
    post_repair_reviewer = (
        MockProvider(output={"status": "completed", "files_changed": [], "findings": [], "dispositions": []})
        if mock
        else command_provider()
    )
    qwen = (
        MockProvider(
            output={"status": "completed", "files_changed": [], "findings": []},
            provider_name=config.ollama_model,
        )
        if mock
        else OllamaProvider(config.ollama_model, config.ollama_endpoint)
    )
    router = ProviderRouter(
        {
            "primary_builder": provider,
            "primary_reviewer": reviewer_provider,
            "primary_repairer": repairer_provider,
            "primary_post_repair_reviewer": post_repair_reviewer,
            "qwen": qwen,
        },
        dict(config.provider_routes),
    )
    if mock:
        runtime_config = config
        runs_root = config.state_root / "runs"
        keeper_run_id = None
        execution_sink = None
    else:
        diagnostics = authority.diagnostics()
        exchange_value = diagnostics.get("client_exchange_root")
        if not isinstance(exchange_value, str) or not exchange_value:
            raise RuntimeError("Authority Service client exchange is unavailable")
        exchange = Path(exchange_value).resolve(strict=True)
        repository_id = hashlib.sha256(
            str(root.resolve()).encode("utf-8")
        ).hexdigest()[:16]
        runtime_config = replace(
            config,
            workspace_root=exchange / "worktrees" / f"standalone-{repository_id}",
        )
        runs_root = (
            exchange / "evidence" / f"standalone-{repository_id}" / "runs"
        )
        keeper_run_id = f"standalone:{repository_id}"

        def execution_sink(event: dict[str, Any]) -> dict[str, Any] | None:
            if event.get("event") == "started":
                environment = filtered_environment(dict(os.environ))
                environment["KEEPER_PROVIDER_ROLE"] = str(event["role"])
                reserved = authority.reserve_attempt(
                    registration_id=str(
                        registration["trusted_registration_id"]
                    ),
                    keeper_run_id=keeper_run_id,
                    task_id=str(event["task_id"]),
                    stage_id=str(event["stage_id"]),
                    role=str(event["role"]),
                    attempt_number=int(event["retry_count"]) + 1,
                    provider_run_id=str(event["provider_run_id"]),
                    provider_instance_id=str(event["provider_instance_id"]),
                    evidence_path=str(event["evidence_path"]),
                    prompt_path=str(event["prompt_path"]),
                    stdout_path=str(event["stdout_path"]),
                    stderr_path=str(event["stderr_path"]),
                    workspace=str(event["workspace"]),
                    timeout_seconds=int(event["timeout_seconds"]),
                    reasoning_level=str(event["reasoning_level"]),
                    environment=environment,
                )
                return {"attempt_id": reserved["attempt_id"]}
            if event.get("event") == "finished":
                record_path = Path(str(event["evidence_path"]))
                record = json.loads(record_path.read_text(encoding="utf-8"))
                attempt_id = record.get("authority_attempt_id")
                if not isinstance(attempt_id, str):
                    raise PermissionError(
                        "standalone Authority Service attempt is missing"
                    )
                completed = authority.finalize_completion(attempt_id)
                (record_path.parent / "authority-completion.json").write_text(
                    json.dumps(completed, sort_keys=True),
                    encoding="utf-8",
                )
            return None

    runner = AgentRunner(
        provider,
        runs_root,
        runtime_config.process_timeout_seconds,
        keeper_run_id=keeper_run_id,
        execution_sink=execution_sink,
    )
    return Keeper(
        runtime_config,
        runner,
        WorkspaceManager(
            runtime_config.repository_root,
            runtime_config.workspace_root,
            config.state_root / "workspace-ownership",
        ),
        router,
        runs_root=runs_root,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="python -m keeper", description="Run the local Keeper workflow.")
    result.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    result.add_argument("--mock", action="store_true", help="use the deterministic test provider")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("start", help="recover and process tasks until the queue is empty")
    commands.add_parser("run-next", help="run the next eligible task")
    commands.add_parser("resume", help="clear pause state, recover, and run the next task")
    commands.add_parser("pause", help="stop progression after the current process")
    commands.add_parser("status", help="show queue and pause state")
    commands.add_parser("list-tasks", help="list task IDs and statuses")
    show = commands.add_parser("show-task", help="print one task")
    show.add_argument("task_id")
    commands.add_parser("verify", help="run Keeper's self-verification")
    commands.add_parser("recover", help="record decisions for interrupted runs")
    cleanup = commands.add_parser("cleanup-worktrees", help="remove a clean task worktree")
    cleanup.add_argument("path", type=Path)
    commands.add_parser(
        "authority-install", help="install the KeeperAuthority Windows service"
    )
    commands.add_parser("authority-start", help="start KeeperAuthority")
    commands.add_parser("authority-stop", help="stop KeeperAuthority")
    commands.add_parser("authority-restart", help="restart KeeperAuthority")
    commands.add_parser("authority-status", help="show KeeperAuthority SCM status")
    commands.add_parser(
        "authority-diagnostics", help="query KeeperAuthority diagnostics"
    )
    authority_backup = commands.add_parser(
        "authority-backup", help="backup protected authority metadata"
    )
    authority_backup.add_argument("destination", type=Path)
    provider_sync = commands.add_parser(
        "sync-qualified-provider",
        help=(
            "project an existing Authority-qualified provider into Keeper Desktop"
        ),
    )
    provider_sync.add_argument(
        "provider_id", choices=("codex", "claude", "gemini", "qwen")
    )
    provider_sync.add_argument("registration_id")
    provider_sync.add_argument("qualification_id")
    provider_sync.add_argument(
        "--data-directory",
        type=Path,
        default=None,
        help="Keeper Desktop data directory (defaults to the installed user profile)",
    )
    provider_host = commands.add_parser(
        "provider-host", help="run or manage the per-user Keeper Provider Host"
    )
    provider_host.add_argument("provider_host_arguments", nargs=argparse.REMAINDER)
    return result


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    root = options.root.resolve()
    try:
        if options.command == "provider-host":
            from keeper.provider_host.cli import main as provider_host_main

            return provider_host_main(options.provider_host_arguments)
        if options.command == "authority-install":
            value = service_install.AuthorityServiceInstaller(root).install()
            print(json.dumps(value, indent=2, sort_keys=True))
            return 0
        if options.command == "authority-start":
            service_install.start()
            print("KeeperAuthority started.")
            return 0
        if options.command == "authority-stop":
            service_install.stop()
            print("KeeperAuthority stopped.")
            return 0
        if options.command == "authority-restart":
            service_install.restart()
            print("KeeperAuthority restarted.")
            return 0
        if options.command == "authority-status":
            print(json.dumps(service_install.status(), indent=2, sort_keys=True))
            return 0
        if options.command == "authority-diagnostics":
            print(
                json.dumps(
                    service_install.diagnostics(), indent=2, sort_keys=True
                )
            )
            return 0
        if options.command == "authority-backup":
            print(
                json.dumps(
                    {
                        "backup": str(
                            service_install.backup(
                                options.destination.resolve()
                            )
                        )
                    },
                    indent=2,
                )
            )
            return 0
        if options.command == "sync-qualified-provider":
            from keeper.app.service import KeeperApplication

            application = KeeperApplication(options.data_directory)
            result = application.sync_qualified_provider(
                options.provider_id,
                options.registration_id,
                options.qualification_id,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        keeper = build_keeper(root, options.mock)
        if options.command == "pause":
            keeper.pause()
            print("Keeper is paused.")
        elif options.command == "status":
            print(json.dumps(keeper.status(), indent=2))
        elif options.command == "list-tasks":
            for task in keeper.queue.load():
                print(f"{task.id}\t{task.status.value}\t{task.title}")
        elif options.command == "show-task":
            shown_task = next((item for item in keeper.queue.load() if item.id == options.task_id), None)
            if shown_task is None:
                raise LookupError(f"task not found: {options.task_id}")
            print(json.dumps(shown_task.to_dict(), indent=2))
        elif options.command == "verify":
            commands = [
                VerificationCommand([sys.executable, "-m", "mypy", "keeper"]),
                VerificationCommand([sys.executable, "-m", "pytest", "-q", "tests/keeper"]),
            ]
            results = Verifier().run(root, commands)
            for result in results:
                print(f"{'PASS' if result.passed else 'FAIL'}: {' '.join(result.arguments)}")
                if result.stdout:
                    print(result.stdout, end="")
                if result.stderr:
                    print(result.stderr, file=sys.stderr, end="")
            return 0 if Verifier.required_passed(results) else 1
        elif options.command == "recover":
            print(json.dumps(keeper.recover(), indent=2))
        elif options.command == "cleanup-worktrees":
            keeper.workspace_manager.cleanup(options.path.resolve())
        elif options.command == "resume":
            resumed_task = keeper.resume()
            print(resumed_task.id if resumed_task else "No eligible tasks.")
        elif options.command == "run-next":
            next_task = keeper.run_next()
            print(next_task.id if next_task else "No eligible tasks.")
        elif options.command == "start":
            keeper.recover()
            while started_task := keeper.run_next():
                print(f"{started_task.id}: {started_task.status.value}")
                if started_task.status.value in {"BLOCKED", "FAILED"}:
                    break
        return 0
    except (FileNotFoundError, LookupError, PermissionError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
