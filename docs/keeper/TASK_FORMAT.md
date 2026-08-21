# Keeper Task Format

Tasks are JSON files in `.ai-workflow/tasks/`. The storage adapter is isolated so
another task source can be added later without rewriting orchestration.

Required fields:

- `id`, `title`, `description`
- `phase`, `sequence`, `status`, `priority`, `risk`, `component`
- `dependencies`
- `acceptance_criteria`
- `verification_commands`
- `allowed_paths`, `blocked_paths`
- `maximum_attempts`
- `provider` and `size`
- `created_timestamp`, `updated_timestamp`

Verification commands are arrays of arguments, never shell strings:

```json
{
  "id": "keeper-example",
  "title": "Example task",
  "description": "Make one scoped improvement.",
  "phase": "pilot",
  "sequence": 1,
  "status": "BACKLOG",
  "priority": 10,
  "risk": "low",
  "component": "keeper",
  "dependencies": [],
  "acceptance_criteria": ["The improvement has a unit test."],
  "verification_commands": [
    ["python", "-m", "pytest", "-q", "tests/keeper"]
  ],
  "allowed_paths": ["keeper/", "tests/keeper/"],
  "blocked_paths": ["backend/", "shared/", "apps/"],
  "maximum_attempts": 2,
  "provider": "primary",
  "size": "small",
  "created_timestamp": "2026-07-26T00:00:00+00:00",
  "updated_timestamp": "2026-07-26T00:00:00+00:00"
}
```

IDs must be unique and should use lowercase words separated by hyphens. Branch
names are derived deterministically as `keeper/<task-id>`.
