# GUI failure precedence and owned recovery (#192)

Status: focused repair checks pass; final integrated candidate qualification
and independent whole-branch review remain pending. This is controlled-source
engineering evidence. It grants no live assessment or release acceptance.

## Fault timing and terminal precedence

Pre-start plan-integrity rejection is a distinct fault case. It proves that
execution never started, no collection or privileged operations occurred,
NotStarted/20 is authoritative, and no usable package is claimed.

The post-start Integrity case corrupts final canonical bytes only after collection
started and validated sources were accepted. Its final contract rejection proves
IntegrityFailed/50, collection-start evidence, consistent completion, no usable
package and verified cleanup. The original pre-start fixture failure remains Fail;
its old expectation is not relabeled into a post-start success.

Six separate real STA WPF control tests exercise Cancel and active-window Close
during administrator, SYSTEM and native-worker waits. Three separate failure
tests exercise pre-start Integrity, post-start Integrity and Cleanup precedence.
Functional and owned-cleanup assertions pass. Retained resource-limit failures
belong to #191 and remain separate from functional results.

## Exact lifetime admission

The recovery test now persists its scoped observation before admission. A worker
writes a fixed test-only witness after creating its nested child. Admission
requires the actual recorded worker and nested PowerShell child, independently
approved full executable images, matching held-process and CIM creation times,
a live held parent with a valid earlier start, and the exact observed parent
relationship. The fixed Windows console helper is observed for absence only.

Metadata negatives reject wrong process, parent, creation time and image, missing
image and exited lifetimes. Failure cleanup terminates only the already held
application process. It never uses recursive termination to bypass admission.
A controlled regression proves that a separately held nested child survives
failed parent admission and is stopped separately through its own admitted handle.

Successful application interruption exercises the product's job-bound worker
cleanup. Held descendants become absent; unauthorized stale recovery refuses;
redirecting recovery to a foreign matching directory refuses and preserves its
sentinel bytes. Authenticated authorized recovery removes the registered stale
workspace and journal. A second launch creates no resumed collection, and still
preserves the foreign directory. Output inspection and every cleanup action stay
bounded and independent. Incomplete observations preserve a cleanup blocker.

## Original failed recovery disposition

The first revised interruption attempt failed descendant admission before saving
its complete observation. Its original failure, journal, scoped reconstruction
and cleanup blocker are retained privately. Existing process-creation audit
records reconstructed the exact owned tree without changing audit policy or
starting host-wide tracing. Exact tree absence was verified before the final
audit cutoff, and independent safety advisory found no remaining material gap.
Authenticated registered stale cleanup then verified owned artifact absence.
The original blocker was archived only after that verified cleanup.

This resolves the unsafe residue, not the failed invocation. No unrelated
process, package, key or workspace was adopted or removed. Observer completeness,
actual delivered-app acceptance and eligible-client live validation remain pending
in #160/#161. Scope and release gates are unchanged.

## Focused checks

- StatusDeskActiveActions.Tests.ps1: six WPF actions plus three failure cases pass.
- StatusDeskRecovery.Tests.ps1: actual nested-worker interruption, unauthorized
  and foreign recovery, authorized cleanup and second launch pass.
- RecoveryProcessOwnership.Tests.ps1: metadata negatives and actual parent-only
  failed-admission cleanup pass.
- QualificationCleanup.Tests.ps1 and StatusDesk.Tests.ps1: independent cleanup,
  retained primary errors, disposal faults and safe retry pass.

Final source/candidate identities, full-gate outcomes and independent Standards
and Spec findings must be recorded before engineering closure.
