# Pass B Desktop and Sage Presentation

The Pass B desktop is one coherent Tk shell backed by application services and
durable state.

Its black, gold, gray, and white interface contains:

- Conversation: Founder and Keeper messages, charter proposal state, approval
  requirements, blockers, evidence summaries, and recovery prompts.
- Control Room: assignments, workflows, provider sessions, usage reset state,
  reservations, evidence, reviews, and uncertainty.
- Project: charter revision, work graph, assignments, attempts, workspaces,
  evidence, and review decisions.
- Providers: provider, account, session, model, capability, concurrency, health,
  and usage-pool state.
- Safety: Authority health, delegated-mode grants, open pauses, checkpoints,
  workspace conflicts, uncertainty, and prohibited actions.

The UI reads `ControlRoomService` snapshots. It does not contain hard-coded
project screenshots or its own lifecycle truth.

## Sage presentation boundary

`PresentationStateRecord` stores form, mode, expression, intensity, background,
and ambient effect. The interface supports compact, conversation, and analyst
modes as a foundation for later avatar, voice, lip-sync, expression,
interruption, and environmental work.

Presentation state is never input to planning, scoring, evidence validation,
risk, permissions, provider selection, launch, or Authority calls. Diagnostics
and the pilot report expose `presentation_authority_effect` as `NONE`.

## Environment note

Tk rendering requires an interactive desktop. Service/view-model tests run
headlessly. Packaged rendered smoke may report unavailable when no interactive
display is present; that is an environmental limitation rather than an
authority bypass.
