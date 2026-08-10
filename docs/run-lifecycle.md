# Assessment Run lifecycle

WIN-PCInfo now has one orchestrator for a narrow, synthetic Assessment Run. It owns the run state machine from accepted preparation through collection, package gating, cleanup, and exactly one terminal outcome. This proves lifecycle behavior; it does not collect real computer information, deliver a Product Capability, or create a Preview/Supported claim.

Ordinary generated execution still stops safely after preparation because the real Protected Evidence Package finalizer is delivered by issue #46. Hidden validation fixtures may run only the release-owned synthetic collector. They cannot select an executable, command, script, argument, working path, real evidence source, or package implementation.

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
