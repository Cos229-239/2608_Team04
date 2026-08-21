"""Shared Keeper pytest fixtures."""

from __future__ import annotations

import pytest

from tests.keeper.authority_testkit import TestAuthorityClient


@pytest.fixture(autouse=True)
def _inject_keeper_test_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep tests explicit while production has no signer fallback."""
    monkeypatch.setattr(
        "keeper.app.service.authority_client_factory",
        TestAuthorityClient,
    )
    monkeypatch.setattr(
        "keeper.cli.authority_client_factory",
        TestAuthorityClient,
    )
