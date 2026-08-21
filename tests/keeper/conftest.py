from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _isolate_provider_host_defender_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Unit tests inject Defender; explicit boundary tests exercise its contract."""
    from keeper.provider_host import install

    monkeypatch.setattr(
        install,
        "_verify_provider_host_with_defender",
        lambda _artifact, _digest: None,
    )
    yield
