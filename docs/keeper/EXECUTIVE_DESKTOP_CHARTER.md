# Keeper Executive Desktop Charter

## Status

Bounded completion pass for the Keeper 1.0 desktop product shell. This charter
changes presentation and information architecture only. Durable Executive,
Pass B, Founder-authentication, review, provider, workspace, recovery, and
KeeperAuthority services remain authoritative.

## Visual direction

The desktop follows the Founder-supplied second Keeper mockup as its primary
visual reference:

- black and charcoal surfaces with metallic-gold structure and white text;
- a premium executive command-center composition;
- persistent left navigation and a right system-integrity rail;
- dense, readable cards, tables, status colors, and receipt summaries;
- visible Founder, authority, provider, audit, and local-first boundaries.

Example names, dates, percentages, providers, slogans, and project content in
the reference are not product requirements. Repository terminology and durable
state always win when the reference conflicts with implemented behavior.

## Information architecture

The supported product entry point renders nine pages:

1. **Dashboard** - active project, workflow, approval, provider, evidence, and
   system-integrity summary.
2. **Conversation** - non-authoritative Founder intake that prepares a durable
   charter proposal.
3. **Projects & Charters** - project status and the exact current charter
   projection.
4. **Workflows** - durable work stages, roles, provider assignments, usage waits,
   and uncertainty status.
5. **Approvals** - current approval requests and exact-charter review entry.
6. **Providers** - provider composition, health, capacity, usage pools, privacy,
   cost, and capability boundaries.
7. **Audit & Receipts** - validated evidence, independent reviews, and typed
   evidence-reference identities without raw protected paths.
8. **Recovery** - durable pause, conflict, cancellation, and uncertain-state
   projection. The UI never retries uncertain external effects.
9. **Settings** - product composition, security, read-only Authority health,
   provider policy, protected paths, and redacted diagnostics.

Legacy internal page names map to the new pages so existing supported service
callbacks remain compatible.

## Authority and security invariants

- The desktop is a projection and supported service client, never an authority
  source.
- Founder approval continues through the existing Windows authentication and
  exact current-charter service path. The approval dialog renders the exact
  pending charter identity, and the service revalidates that displayed ID and
  revision before authentication.
- Developer diagnostics use a fixed safe-field allowlist. Raw snapshots,
  workspace paths, reservation owner tokens, and provider or Authority failure
  details are not rendered.
- Dashboard health styling is derived from durable uncertainty and read-only
  Authority health; unavailable or uncertain state cannot appear healthy.
- The UI cannot directly approve review evidence, launch a provider, mutate
  KeeperAuthority, force-push, rewrite history, deploy, spend, access credentials,
  change services, or trade live.
- Test, mock, health-only, and production composition labels remain explicit.
- Provider output and evidence remain untrusted structured data.
- Typed evidence cards do not expose raw protected filesystem paths.
- Sage remains optional presentation with authority effect `NONE`; `HIDDEN` mode
  removes its labels and presentation area.
- Failure, uncertainty, usage waits, and unavailable Authority state remain
  visually distinct and are never hidden by decorative polish.

## Design tokens

The application uses a central Tk theme with:

- background `#07080A`;
- sidebar `#0A0B0D`;
- primary surface `#101216`;
- raised surface `#171A1F`;
- metallic gold `#E0AD36`;
- primary text `#F7F7F5`;
- green, amber, red, and blue reserved for state semantics.

Gold identifies navigation, hierarchy, borders, and Founder-facing emphasis. It
must not imply approval unless the durable state is actually approved.

## Acceptance criteria

- Product entry point uses the executive desktop projection.
- All nine pages construct under real Tcl/Tk and the Workflows page can be
  selected by the packaged smoke path.
- Refresh invokes the existing durable snapshot path and updates the status band.
- Active navigation is visually obvious.
- Dense provider, workflow, evidence, and project tables remain readable at the
  supported minimum window size.
- The first-run wizard and Founder approval dialog retain their existing safe
  service behavior.
- Headless tests cover navigation, entry-point wiring, state colors, theme tokens,
  legacy aliases, exact pending-charter identity, redacted diagnostics, dynamic
  failure status, and absence of direct authority bypass methods.
- Rendered visual inspection confirms the reference-aligned dashboard and a dense
  management page.

## Exclusions

This pass does not add a new UI framework, provider, cloud service, paid
dependency, deployment path, live trading, Sage animation, voice, lip sync,
avatar generation, KeeperAuthority mutation, or direct filesystem authority.
