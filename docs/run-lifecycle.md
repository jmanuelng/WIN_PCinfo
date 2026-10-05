# Assessment Run lifecycle

The current generated application can run the approved Comprehensive Local Assessment and produce a Protected Evidence Package. The production Status desk owns preparation, collection, cancellation and completion through a separate PowerShell runspace. See the [Guided Runway](guided-runway.md) for current operator behavior and the [production Status desk implementation checkpoint](validation/issue-137-status-desk.md) for its implemented boundary. Implementation and controlled regression evidence do not establish signed delivery, Windows-client acceptance, or a Preview/Supported claim.

The sections below preserve the original synthetic lifecycle slice from issues #42–#44. Their synthetic collector, injected finalizer, five-second operation budget and absence of a persistent journal describe that slice; they are not limits or implementation claims for the later comprehensive collector. Issue #46 subsequently implemented [Protected Evidence Packages](protected-evidence-package.md), and resource-owning runs use the [Evidence Workspace and recovery journal](evidence-workspace-recovery.md). Historical validation reports remain unchanged.

The seven terminal outcomes and the rule that cleanup uncertainty closes further scheduling remain relevant across these paths. The synthetic privilege and SYSTEM fixture seams demonstrate confined authority and cleanup behavior; real administrator/SYSTEM cleanup and delivered GUI acceptance still require their own evidence. See [Privileged Collection Plan](privileged-collection-plan.md) and [SYSTEM Collection Sub-plan](system-collection-sub-plan.md).

## Original synthetic lifecycle slice

## What an operator can rely on

Every accepted run ends with one of these stable outcomes and its matching process exit code:

| Outcome | Exit code | Meaning in this slice |
| --- | ---: | --- |
| `Completed` | 0 | Validated complete evidence, verified protected package, and verified cleanup. Available only through the exported test-finalizer seam for now. |
| `CompletedWithGaps` | 10 | Validated partial evidence with explicit gap coverage, a verified protected package, and verified cleanup. Available only through the exported test-finalizer seam for now. |
| `NotStarted` | 20 | Collection did not begin, including a live Active Run Lock or cleanup-only stale-owner recovery. |
| `Cancelled` | 30 | One cancellation stopped scheduling, the owned process ended, and cleanup ran. |
| `TimedOut` | 40 | A release-owned deadline expired independently of operator cancellation. |
| `IntegrityFailed` | 50 | Evidence or package integrity could not be proved. Useful collection never overrides this result. |
| `CleanupIncomplete` | 60 | Exact owned-resource absence could not be proved. Useful collection and a package never override this result. |

The exit-code map, lock identity, deadline budgets, retry ceiling, progress budgets, and allowed synthetic scenarios are frozen in the schema-validated [release lifecycle policy](spec/releases/2.0.0-preview.1-run-lifecycle.json). The deterministic build embeds its exact bytes and digest.

## Run sequence

The orchestrator follows one finite path:

1. Emit structured `run.accepted` progress immediately.
2. Try the device-wide Active Run Lock without waiting.
3. Run the one approved synthetic collection operation at most once.
4. Validate any resulting Assessment Record against the embedded release Contract Set.
5. Verify cleanup and incorporate cleanup failure into the final Assessment Record.
6. Ask the injected finalizer to protect that final record.
7. Emit exactly one terminal record and return its mapped exit code.

Progress records contain stable IDs, phase/state values, timestamps, and bounded completion counts. They contain no raw process output, exception text, device identifier, path, or evidence value. The first event budget is five seconds, active heartbeat gaps are at most ten seconds, and cancellation acknowledgement is at most two seconds. The current collector process is itself capped at five seconds, so its completion-seam heartbeat closes the active interval before the heartbeat ceiling.

## Active Run Lock and interruption

The release uses the Windows named mutex `Global\WINPCInfo-AssessmentRun-v1`. `Global` gives the object device-wide scope across interactive sessions, while the kernel owns synchronization and supplies no writable lock-file path. A second launch performs a zero-millisecond acquisition attempt. If another run owns the mutex, the second launch returns `NotStarted`; it does not join, signal, cancel, terminate, or otherwise disturb the owner.

An abandoned mutex proves only that the prior owning thread ended. It does not prove which lifecycle phase finished or whether side effects are reusable. WIN-PCInfo therefore enters cleanup-only recovery, never restarts collection, verifies registered synthetic residue absent, returns `NotStarted`, and releases the recovered ownership. Failure to prove cleanup becomes `CleanupIncomplete`.

This tracer bullet has no persistent recovery journal because its approved collector creates no file, task, service, workspace, or package. Later resource-owning slices must register exact targets before creation and preserve their restricted journal until absence is proved.

## Cancellation and deadlines

One cancellation token crosses the orchestrator/collector seam. The Process Supervisor signals the collector's run-unique Windows event, waits only through the release grace, and then escalates to bounded Job Object termination when necessary. The lifecycle emits one `Acknowledged` progress event, closes further scheduling, retains matching `Cancelled` coverage, and proceeds directly to cleanup without another prompt. The operator token is scoped to collection; cleanup and permitted recoverable finalization use a fresh token governed only by the remaining run and phase deadlines, so cancellation cannot kill the work required to leave an honest state.

Run Control, Collection, Packaging, Cleanup, the synthetic operation, and its process each have a positive finite deadline. The operation has `maximumAttempts: 1`; there is no automatic retry. The orchestrator supplies linked deadline cancellation to the collector. Package and cleanup adapters run in a suspended child assigned to a kill-on-close Windows Job Object before its first instruction; each receives a deadline token, and the parent reserves time inside the phase/run maximum for hard termination and kernel accounting. An exception, invalid result, timeout, or unverified tree absence becomes `IntegrityFailed` for packaging or `CleanupIncomplete` for cleanup without copying private exception text.

## Package and terminal honesty

The orchestrator validates an Assessment Record before finalization. Cleanup happens before the test finalizer receives the final record, so `CleanupIncomplete` cannot be hidden inside a provisional `Completed` package. If package verification fails, the unprotected provisional record is not emitted as completed evidence.

Until the real finalizer exists, the generated application deliberately maps a successful synthetic collection to `IntegrityFailed` with package state `IntegrityFailed`. Only module-level lifecycle tests inject a synthetic finalizer and may observe `Completed` or `CompletedWithGaps`.

For the complete synthetic fixture matrix, timing evidence, and validation commands, see [Issue #42 lifecycle validation](validation/issue-42-run-lifecycle.md).
