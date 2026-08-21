# Provider Setup

Keeper discovers configured full paths and the system path for the Codex command,
Claude Code command, and Ollama. The deterministic mock provider is built in.
Executable paths are ordinary settings; authentication remains owned by each
provider's CLI or operating-system credential mechanism and is never copied into
Keeper records.

A configured path is not authority. Before desktop diagnostics, routing, or the
standalone `start` and `run-next` commands can use a command provider, an
authorized registration must be created and stored. The schema-versioned record
binds component identities, canonical paths, hashes and sizes, exact invocation,
endpoint, authentication profile reference, capabilities, role eligibility,
policy, independence, qualification, authorization, revocation, and expiration.
Its canonical digest covers every field other than the digest itself. Missing,
extra, mistyped, expired, revoked, or mutated fields fail closed.

Registration does not execute the provider or accept a caller-supplied version.
It begins as `REGISTERED_UNQUALIFIED`. A separate explicitly authorized
qualification retains the registered launcher and script through process creation,
runs the approved version command, and stores immutable start and completion
evidence containing the actual normalized output and component identities.
Discovery reports `qualified` only when the registration references that exact
protected evidence and digest. Both the start event and final evidence are bound
to an unpredictable pre-launch challenge and authenticated by Keeper's
installation authority key. A caller-computed public digest cannot qualify a
provider.

Capabilities and eligible workflow roles are registration authority. Diagnostics
copy them exactly; routing requires the provider to be qualified, the required
capability enabled, the role explicitly eligible, and independent-review
classification for reviewer roles. Empty eligibility means no workflow routing.

Standalone configuration contains only the protected qualification evidence
reference, never raw authoritative evidence. Startup resolves the signed record
and its signed authorization event from Keeper-controlled storage and validates
them with the installation authority key. Its exact `provider_command` array must
match the registered invocation.
For batch providers, Keeper canonicalizes the standalone script command to the
registered `cmd.exe` launcher plus script component before comparison.

On Windows, Keeper creates both standard executable and registered launcher/script
providers suspended. It configures a kill-on-close Job Object first, inherits only
the explicit standard I/O handles, assigns and confirms the suspended process,
then resumes the retained primary thread. Descendants remain in the same Job and
are terminated before executable, script, Job, process, thread, or authority
protections are released. Systems that reject nested Job assignment or any other
confinement step fail closed.

The Codex adapter uses non-interactive execution, ephemeral session state,
workspace-write sandboxing, and an output schema. Its command contract was checked
against current official documentation; authenticated task execution was not
performed during productization. The Claude adapter uses print mode with JSON and a
JSON schema; it was not locally exercised. Unavailable providers block required
roles rather than causing approval. Arguments are passed as arrays, never shell text.

## Retry identity

Routing records separate stable registration identity from execution-attempt
identity. Stable identity binds the logical registration, canonical executable
path, executable SHA-256 and size, configuration digest, endpoint, capabilities,
policy, independence classification, authentication mode, and registration
version and qualification metadata. The canonical registration digest is checked
during discovery, and executable components are checked again immediately before
execution.

Every retry creates fresh provider objects with truthful new instance IDs. Keeper
never rewrites a new instance to resemble an earlier attempt. An unchanged stable
registration may retry without rerouting; any material registration change
requires an exact, unexpired, one-use reroute authorization. Attempt records and
final reports retain the actual instance, stable registration digest, executable
digest, retry parent, timestamps, outcome, and authorization reference.
