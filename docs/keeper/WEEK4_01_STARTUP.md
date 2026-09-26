# Update 1 - blocked startup and honest readiness

Integrated the previously published startup fix `0eeb5ec` into this review branch.
This is integration of prior work, not a claim that the startup repair was first
written this week. Provider diagnostic/bridge failures reopen a health-only
desktop without launch or reservation authority. Database identity failures
remain fatal, and recovery records remain visible.

New follow-up: the header now reports observed Authority health instead of a
static READY claim. Saved provider sessions display BLOCKED during startup
failure and are omitted from the chat-provider chooser. Their durable recorded
qualification is not modified. Health remains separate from execution approval.

Verification: startup failure/restart tests plus blocked-session projection
regression. No live credentials, provider execution, install, or service changes.
