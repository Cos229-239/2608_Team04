from pathlib import Path

import pytest

from keeper.pass_b.application import authority_exchange_root_from_diagnostics


def test_authority_exchange_root_uses_authenticated_evidence_tree(
    tmp_path: Path,
) -> None:
    client_root = tmp_path / "client-exchange"
    evidence_root = client_root / "evidence"
    evidence_root.mkdir(parents=True)

    result = authority_exchange_root_from_diagnostics(
        {
            "client_exchange_root": str(client_root),
            "allowed_evidence_root": str(evidence_root),
        }
    )

    assert result == evidence_root.resolve() / "pass-b"


def test_authority_exchange_root_rejects_misbound_evidence_tree(
    tmp_path: Path,
) -> None:
    client_root = tmp_path / "client-exchange"
    evidence_root = tmp_path / "other" / "evidence"
    client_root.mkdir()
    evidence_root.mkdir(parents=True)

    with pytest.raises(PermissionError, match="outside the client exchange"):
        authority_exchange_root_from_diagnostics(
            {
                "client_exchange_root": str(client_root),
                "allowed_evidence_root": str(evidence_root),
            }
        )


@pytest.mark.parametrize(
    "diagnostics",
    [
        {},
        {"client_exchange_root": "missing"},
        {"allowed_evidence_root": "missing"},
    ],
)
def test_authority_exchange_root_requires_both_authority_paths(
    diagnostics: dict[str, str],
) -> None:
    with pytest.raises(RuntimeError, match="client exchange is unavailable"):
        authority_exchange_root_from_diagnostics(diagnostics)
