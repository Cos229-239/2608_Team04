from pathlib import Path

from keeper.models.finding import Finding, Severity
from keeper.providers.base import AgentRequest
from keeper.providers.codex_cli import CliProvider
from keeper.providers.mock import MockProvider
from keeper.reviewer import blocking_findings, parse_review_output, record_cleanup
from keeper.verifier import VerificationCommand, Verifier


def request(tmp_path: Path) -> AgentRequest:
    prompt = tmp_path / "prompt.md"
    prompt.write_text("task", encoding="utf-8")
    return AgentRequest("builder", prompt, tmp_path, 5, tmp_path / "out.log", tmp_path / "err.log")


def test_provider_command_construction(tmp_path: Path) -> None:
    provider = CliProvider(("runner", "--prompt", "{prompt}", "--cwd", "{workspace}", "--role", "{role}"))
    command = provider.build_command(request(tmp_path))
    assert command[-1] == "builder"
    assert str(tmp_path / "prompt.md") in command


def test_mock_agent_execution(tmp_path: Path) -> None:
    provider = MockProvider(output={"status": "completed", "files_changed": ["keeper/cli.py"]})
    result = provider.run(request(tmp_path))
    assert result.exit_code == 0
    assert provider.requests[0].role == "builder"


def test_verification_failure_stops_required_sequence(tmp_path: Path) -> None:
    (tmp_path / "actual.txt").write_text("actual\n", encoding="utf-8")
    commands = [
        VerificationCommand(
            ["keeper:file-equals", "actual.txt", "expected\n"],
            registration_id="keeper:file-equals",
        ),
        VerificationCommand(
            ["keeper:file-equals", "actual.txt", "actual\n"],
            registration_id="keeper:file-equals",
        ),
    ]
    results = Verifier().run(tmp_path, commands)
    assert len(results) == 1
    assert not Verifier.required_passed(results)


def test_review_severity_and_cleanup(tmp_path: Path) -> None:
    findings = parse_review_output(
        {"findings": [
            {"finding_id": "H-1", "severity": "High", "title": "block", "description": "fix"},
            {"finding_id": "M-1", "severity": "Minor", "title": "later", "description": "tidy"},
        ]}
    )
    assert [item.title for item in blocking_findings(findings)] == ["block"]
    register = tmp_path / "cleanup.json"
    record_cleanup(findings, register, "task-1")
    assert '"later"' in register.read_text(encoding="utf-8")
