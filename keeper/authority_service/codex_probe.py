from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Sequence

from keeper.providers.codex_contract import parse_codex_app_server_probe


def probe(executable: Path, model_allowlist: list[str]) -> dict[str, object]:
    process = subprocess.Popen(
        [str(executable.resolve(strict=True)), "app-server", "--listen", "stdio://"],
        text=True,
        encoding="utf-8",
        errors="strict",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if process.stdin is None or process.stdout is None:
        process.kill()
        raise RuntimeError("Codex app-server pipes are unavailable")
    stdin = process.stdin
    stdout = process.stdout
    responses: list[str] = []

    def send(value: dict[str, object]) -> None:
        stdin.write(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        stdin.flush()

    def receive(identifier: int) -> None:
        while True:
            line = stdout.readline()
            if not line:
                raise PermissionError("Codex app-server ended before responding")
            value = json.loads(line)
            if isinstance(value, dict) and value.get("id") == identifier:
                responses.append(line)
                return

    try:
        send(
            {
                "method": "initialize",
                "id": 1,
                "params": {
                    "clientInfo": {
                        "name": "keeper-authority",
                        "version": "1",
                    }
                },
            }
        )
        receive(1)
        send({"method": "initialized", "params": {}})
        for identifier, method in (
            (2, "account/read"),
            (3, "model/list"),
            (4, "account/rateLimits/read"),
            (5, "account/usage/read"),
        ):
            send({"method": method, "id": identifier, "params": {}})
            receive(identifier)
    finally:
        stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    if process.returncode != 0:
        raise PermissionError("Codex app-server account probe failed")
    return parse_codex_app_server_probe(
        responses, model_allowlist=model_allowlist
    )


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="keeper-authority codex-probe")
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--model", action="append", required=True)
    options = parser.parse_args(arguments)
    value = probe(options.executable, list(options.model))
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
