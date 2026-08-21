# Keeper Workflow

Keeper enforces this progression:

```text
BACKLOG -> READY -> BUILDING -> SELF_VERIFYING -> INDEPENDENT_AUDIT
        -> REPAIRING (only for Critical or High findings)
        -> FINAL_VERIFY -> APPROVED -> COMPLETED
```

`BLOCKED`, `FAILED`, `PAUSED`, and `CANCELLED` are explicit exceptional states.
Invalid transitions raise an error.

Task selection is deterministic. Dependencies must be `COMPLETED`; remaining
tasks are ordered by phase, sequence, priority, and ID. Attempt limits prevent
infinite retries. Failed workspaces and logs are preserved.

The builder receives requirements, acceptance criteria, allowed scope, repository
rules, verification commands, and a structured-report requirement. The reviewer
receives the original task and patch, but not the builder's persuasive summary.
Critical and High findings receive one repair pass. Other severities are written
to `.ai-workflow/cleanup-register.json`.

Useful commands:

```bash
python -m keeper run-next
python -m keeper start
python -m keeper pause
python -m keeper resume
python -m keeper status
python -m keeper list-tasks
python -m keeper show-task TASK_ID
```

Keeper never merges, rebases, resets, stashes, cleans, force-pushes, or deploys
work. Commit and normal push are optional lifecycle stages. Each requires a
separate, run-scoped, one-time authorization bound to current repository,
worktree, branch, HEAD, and Git scope. A commit authorization does not grant push
authority.

On Windows, Keeper validates generated evidence and worktree paths against a
240 UTF-16 code-unit safety budget before provider launch. This matches the unit
used by Windows path APIs, including supplementary characters that consume two
code units. Use a shorter Keeper data directory or repository path when the
diagnostic reports an over-budget path.

## Reasoning tiers

Primary-provider runs use `medium` reasoning by default. Keeper selects `high`
when more than five important files are affected, architecture or workflow state
changes, tests fail twice, important Qwen work needs review, or security,
authentication, database integrity, or financial behavior is involved.
`extra-high` is reserved for live trading or brokerage, unresolved Critical
findings, or changes crossing several major system boundaries. The chosen tier is
recorded in `run.json` and may be inserted into a configured command with the
`{reasoning}` placeholder.
