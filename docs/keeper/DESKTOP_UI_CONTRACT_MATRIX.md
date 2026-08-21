# Keeper Desktop UI Contract Matrix

This matrix is the source-grounded contract for the PySide6/Qt Quick desktop.
QML owns presentation only. Python controllers validate UI input and call the
existing application layer. Domain services and KeeperAuthority remain the
only business and authority truth.

| Screen | Control | Expected action | Backend/service | Authority | Candidate test |
|---|---|---|---|---|---|
| Overview | Project selector | Persist active project and refresh projections | `PassBApplication.select_project`, `product_snapshot` | None; selection grants nothing | controller project selection |
| Overview | Refresh | Reload durable state and Authority health | `product_snapshot`, `diagnostics` | Read-only | refresh signal/state test |
| Overview | New project | Begin validated conversation intake | `PassBApplication.begin_conversation` | Non-authoritative intake | conversation creation test |
| Overview | New task | Create a supported legacy task for the selected repository | `KeeperApplication.create_task` | Existing task validation | task validation test |
| Overview | Status cards | Navigate to source detail screen | controller routing | None | every card route test |
| Overview | Keeper Assistant | Submit Founder text to begin/continue conversation | `begin_conversation`, `continue_conversation` | Conversation is non-authoritative | empty/provider-unavailable/continuation tests |
| Projects | Search/filter | Filter durable project catalog locally | `project_catalog` projection | None | model filter tests |
| Projects | New project | Open intake dialog; create only after validation | `begin_conversation` | Non-authoritative intake | dialog/controller test |
| Projects | Select/open | Persist project selection and open detail | `select_project`, `product_snapshot` | None | selection binding test |
| Projects | Prepare/revise charter | Continue durable conversation | `continue_conversation` | Non-authoritative | revision test |
| Projects | Approve charter | Authenticate and approve exact displayed revision | `approve_and_plan_current_charter` | Production Founder authentication | exact identity/cancel tests |
| Repositories | Add repository | Validate and persist a local Git repository | `KeeperApplication.add_project` | Filesystem/path validation | valid/invalid/protected path tests |
| Repositories | Refresh | Reload branch, HEAD, status and readiness | `KeeperApplication.dashboard` | Read-only | projection refresh test |
| Workflows | Stage selection | Display exact durable WorkItem/Assignment details | `product_snapshot` | None | selected-stage test |
| Workflows | Start/resume | Run bounded coordinator only for approved charter | `advance_delegated_completion`, `run_delegated_completion` | Existing charter/delegation/Authority gates | blocked/provider-unavailable/duplicate tests |
| Tasks | Search/filter/sort/page | Operate on durable projected tasks | `KeeperApplication.tasks`, Pass B work items | None | table-state tests |
| Tasks | New task | Validate task fields and paths | `KeeperApplication.create_task` | Existing policy and repository binding | controller validation test |
| Tasks | Start | Start through application workflow service | `KeeperApplication.start_task` | Existing authorization gates | start/error test |
| Findings | Filter/view | Project validated review findings and evidence | `product_snapshot` reviews/evidence | None | severity/filter/detail tests |
| Findings | Repair | Create only a bounded repair for `REPAIR_REQUIRED` review | `OrchestrationService.create_repair_assignment` | Existing review/delegation gates | invalid/valid repair test |
| Findings | Export | Export a supported run report | `KeeperApplication.export_run_report` | Safe destination validation | export test |
| Authorizations | View/filter | Project durable grants, approvals and controls | `product_snapshot`, legacy dashboard | None | state projection test |
| Authorizations | Revoke | Revoke only supported legacy authorization | `KeeperApplication.revoke_authorization` | Existing service validation | replay/revoke test |
| Authorizations | Create/renew | Disabled with explanation; available through charter flow only | None | Must not create UI authority | disabled-contract test |
| Evidence | Search/filter/open | Display redacted durable bundle/reference metadata | `product_snapshot` | Read-only | redaction/detail tests |
| Evidence | Preview | Preview allowlisted redacted text only through the validated run-evidence service; typed references expose metadata only | `evidence_details`/validated reference metadata | No workspace/write authority | traversal/binary/redaction tests |
| Evidence | Export | Export only through validated application destination | `export_run_report` where applicable | Existing path policy | path test |
| Reviews | View/filter | Display exact producer/reviewer/evidence binding | `product_snapshot` | Read-only | lineage projection test |
| Reviews | Decide | No direct UI decision; completion/review service remains authoritative | None | Intentionally unavailable | absent/dead-control test |
| Reports | Export | Export a selected supported run report | `export_run_report` | Existing path policy | export test |
| Providers | Refresh | Read actual discovery, registration, qualification and pricing declarations | `diagnostics`, Pass B provider snapshot | Read-only | truthful unavailable test |
| Providers | Configure path | Persist executable path only | `save_provider_paths` | Does not register or qualify | no-registration test |
| Providers | Register/qualify | Disabled pending separate Founder authorization | None | Explicit Founder action required | disabled-contract test |
| Recovery | Refresh | List interrupted/recoverable runs and durable blockers | `recover_runs`, Pass B safety projection | Read-only | recovery projection test |
| Recovery | Resume | Resume through supported service only | `resume_run` or coordinator | Existing recovery/Authority fences | unsafe-state rejection test |
| Settings | Browse/validate path | Validate canonical directory/repository path | application path policies | No authority | protected/alias/invalid tests |
| Settings | Save/reset/cancel | Persist UI/provider-path settings atomically; never credentials | settings store and `save_provider_paths` | None | persistence/cancel tests |
| Setup | Back/next/retry/finish | Move through seven validated steps; commit only on finish | setup controller/application settings | Founder auth only where existing backend requires | complete/invalid/cancel/scaling tests |

## Intentionally unavailable controls

- Real provider registration or qualification requires separate Founder authorization and is not performed by this frontend phase.
- Paid fallback, spending, deployment, publication, service mutation, security boundary changes, live trading, force push, and history rewrite are prohibited.
- Direct review acceptance remains an orchestration/domain transition backed by completed independent execution and evidence.
- Automatic coordinator resume on process relaunch is presented as unavailable until a supported recovery service proves it is safe.

## Superseded legacy-shell findings

The Qt product shell resolves the recorded Tk limitations: it supplies the canonical 13-screen information architecture, validated settings and setup flows, no Sage presentation surface, the Founder-approved lighthouse/helmet identity, and a manifest-bound per-user lifecycle. The legacy Tk implementation remains source-compatible for older tests and headless recovery use but is not the product shell and is excluded from the Qt package.
