# Keeper Setup

Keeper uses the repository Python environment and adds no runtime dependency.
Install the existing development requirements so tests, linting, and type checks
are available.

From the repository root:

```bash
python -m keeper --help
python -m keeper status
python -m keeper verify
```

## Provider configuration

Production subscription providers are imported from KeeperAuthority into
Keeper Desktop by exact registration and qualification ID. The import verifies
the terminal registration contract and both signed qualification records; it
does not register, qualify, or execute the provider:

```powershell
python -m keeper sync-qualified-provider codex <registration-id> <qualification-id>
```

Production execution then uses Keeper Desktop's Executive workflow, which
creates a cryptographically authenticated Founder project-launch capability.
The legacy standalone task runner does not synthesize or bypass that
authorization.

The configuration below is retained for deterministic local/mock workflow
development. It is not a substitute for the production Authority projection
and Founder-authorized Executive path.

Set `provider_command` in `.ai-workflow/config.json` to the verified local
development-agent command. Keeper does not guess a machine-specific invocation.
The command must be an argument array and must include `{prompt}`. Optional
placeholders are `{workspace}` and `{role}`.

Example shape:

```json
{
  "provider_command": [
    "configured-agent-executable",
    "run",
    "--prompt-file",
    "{prompt}",
    "--working-directory",
    "{workspace}"
  ]
}
```

Replace the example with the command confirmed by `--help` for the installed
tool. Startup fails clearly when the executable, command, or prompt placeholder
is missing. Use `--mock` for deterministic local workflow tests that make no
external calls.

Secrets are removed from the child environment using credential-oriented variable
name markers. Provider prompts and logs must never contain credentials.

## Ollama

The local provider defaults to `http://127.0.0.1:11434` and
`qwen3-coder:30b`. Change `ollama_endpoint` or `ollama_model` in
`.ai-workflow/config.json`. Startup queries `/api/tags` and fails clearly when the
service or configured model is unavailable. Generation uses `/api/generate`,
disables streaming, requests JSON, applies the role timeout, and validates the
structured object before Keeper uses it.

`provider_routes` assigns each role explicitly. Missing or unavailable routes
block work; Keeper never falls back silently.
