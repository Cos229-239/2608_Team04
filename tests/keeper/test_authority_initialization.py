from __future__ import annotations

import multiprocessing
import os
from pathlib import Path
from typing import Any

import pytest

from keeper.authority import AuthorityKey


def _initialize_authority(
    data_directory: str,
    start: Any,
    results: Any,
) -> None:
    start.wait(10)
    try:
        results.put(("ok", AuthorityKey(Path(data_directory)).key_id))
    except BaseException as error:
        results.put(("error", type(error).__name__, str(error)))


def test_concurrent_first_initialization_uses_one_published_key(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    workers = [
        context.Process(
            target=_initialize_authority,
            args=(str(tmp_path / "data"), start, results),
        )
        for _ in range(4)
    ]
    for worker in workers:
        worker.start()
    start.set()
    outcomes = [results.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(20)

    assert all(worker.exitcode == 0 for worker in workers)
    assert {outcome[0] for outcome in outcomes} == {"ok"}
    assert len({outcome[1] for outcome in outcomes}) == 1
    authority_directory = tmp_path / "data" / "authority"
    assert [path.name for path in authority_directory.glob("*.bin")] == [
        "authority-key-v1.bin"
    ]
    assert list(authority_directory.glob("*.tmp")) == []


def test_interrupted_temporary_write_never_publishes_partial_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_link = os.link

    def fail_publish(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated interrupted publication")

    monkeypatch.setattr(os, "link", fail_publish)
    with pytest.raises(PermissionError, match="atomic publication"):
        AuthorityKey(tmp_path / "data")

    authority_directory = tmp_path / "data" / "authority"
    assert (authority_directory / "authority-key-v1.bin").exists() is False
    assert list(authority_directory.glob("*.tmp")) == []

    monkeypatch.setattr(os, "link", original_link)
    authority = AuthorityKey(tmp_path / "data")
    assert authority.path.is_file()


def test_corrupt_published_key_fails_closed(tmp_path: Path) -> None:
    authority_directory = tmp_path / "data" / "authority"
    authority_directory.mkdir(parents=True)
    key_path = authority_directory / "authority-key-v1.bin"
    key_path.write_bytes(b"partial")
    if os.name != "nt":
        key_path.chmod(0o600)

    with pytest.raises(PermissionError, match="key"):
        AuthorityKey(tmp_path / "data")
