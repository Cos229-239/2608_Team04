# Keeper Overview

Keeper is a small, local development-workflow orchestrator for supported Git repositories. It reads
structured tasks, creates one isolated worktree per task, runs separate builder
and reviewer processes, verifies results, records decisions, and preserves state
for recovery.

Keeper is not part of the trading product. It is not a cloud service, deployment
system, broker controller, or general-purpose agent marketplace. It does not alter
the canonical trading-validation pipeline.

## Architecture

- `models/` contains task, run, finding, and decision records.
- `state_machine.py` rejects invalid task transitions.
- `task_queue.py` selects dependency-complete work.
- `workspace.py` creates deterministic branches and isolated worktrees.
- `providers/` isolates process-provider command construction.
- `verifier.py` runs trusted argument arrays in order.
- `reviewer.py` separates blocking findings from deferred cleanup.
- `recovery.py` provides atomic JSON writes and interrupted-run checks.
- `orchestrator.py` implements the workflow.
- `cli.py` exposes operator commands.

State and logs live under `.ai-workflow/` in the managed repository. Task
worktrees default to a sibling `<repository-name>.keeper-worktrees` directory.

## Current limitations

The MVP supports one builder and one reviewer at a time. It performs one repair
pass, does not merge or push, and leaves completed or failed task worktrees in
place for inspection. Automatic commits are intentionally disabled.
