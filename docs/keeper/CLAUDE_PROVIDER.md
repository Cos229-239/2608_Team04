# Claude subscription reviewer provider

Keeper 1.7.52 supports Claude Code as an opt-in, reviewer-only provider through
the same KeeperAuthority and restricted Provider Host boundary used by the
qualified Codex subscription provider. It does not use an Anthropic API key,
API billing, paid fallback, account switching, or provider switching.

Release 1.7.52 also binds the exact `claude` provider identity into the
provisional Host setup envelope. A pre-dispatch failure remains a single
durable registration claim and resumes with the same registration, setup, and
challenge identities after an Authority restart; recovery cannot create a
second registration or qualification request.

The release contains one narrowly bounded migration for the exact historical
1.7.47 Claude pre-dispatch defect. It accepts only the original generation-1
Claude claim, exact 1.7.47 Authority and Host artifacts, the active generation-27
enrollment, Founder-signed retained-process termination evidence, and explicit
zero-effect accounting. Before that transaction, Keeper verifies the original
Host-signed proposal and Authority-signed grant and receipt in their production
envelope schemas and requires their proposal, grant, receipt, runtime, Host,
user, enrollment, generation, and Authority bindings to agree exactly. One
transaction permanently records the signed
migration, creates the dormant generation-2 retry, and revokes the offline old
Host enrollment. It does not fabricate a Host result, contact the incompatible
old Host, register a provider, qualify a subscription, or execute a model.
The already-offline continuation accepts historical termination evidence only
when its complete canonical digest equals the protected record preserved by the
failed 1.7.49 action; every other record retains the normal freshness limit.
Replay returns the same signed result; mismatched releases, identities, effects,
process evidence, providers, or generations fail closed.

## Qualified contract

- Provider ID: `claude`
- Registration schema: 5
- Authentication: an existing `claude.ai` subscription session for the exact
  authenticated Windows client profile
- Accepted plans: Pro or Max, bound to the account digest observed during the
  Host registration probe
- Model: exact pinned `claude-sonnet-4-6-20251114`
- Efforts: medium and high
- Roles: reviewer and post-repair reviewer only
- Independence: independent-capable; author and repairer capabilities are false
- Billing: included subscription only, with Keeper's local launch budget and no
  automatic retry

The executable is opened and locked by the authenticated client, duplicated
through the exact retained client-process identity, and checked for canonical
path, file identity, size, SHA-256, and Anthropic Authenticode identity before
registration or qualification can persist.

## Host execution

The Provider Host runs Claude with a restricted medium-integrity token, Job
containment, the exact enrolled Windows profile/session, a sanitized environment,
and a locked Windows-root trust bundle. User settings and MCP configuration are
disabled for the bounded operation. Only `Read`, `Grep`, and `Glob` tools are
available; Bash, Edit, Write, browser, API-key, fallback-model, and provider-switch
paths are absent.

Qualification makes exactly one schema-constrained Medium request after a stable
durable Authority claim. Registration and qualification terminal results are
signed and recoverable across restart or lost response. Any uncertain Host work
or pending Authority claim blocks additional provider work.

## Coexistence with Codex

Provider Host store schema 5 retains the existing Codex binding and permits one
distinct immutable binding per provider ID. Adding Claude does not replace or
weaken Codex. A conflicting second binding for either provider fails closed.

The supported one-shot command is:

```text
keeper-authority claude-register-once --executable <exact-path> \
  --expected-sha256 <sha256> --expected-size <bytes> \
  --expected-version <version> --subscription-plan <pro|max> \
  --output-directory <fresh-protected-directory> --apply
```

The command persists the complete registration response before reading its ID,
then persists the complete qualification response before returning. It never
retries automatically.
