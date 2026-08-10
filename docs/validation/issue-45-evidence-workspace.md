# Issue #45 validation evidence

This is public-safe synthetic evidence. It contains no real workspace path, journal, process identity, user SID, evidence, package, credential, Recipient Profile, device identifier, or recovery target.

## Contract and privacy boundary

- `docs/spec/releases/2.0.0-preview.1-evidence-workspace.json` freezes local-volume eligibility, the protected ACL, per-run naming, safe alternative, temporary-evidence bounds, journal privacy, cleanup-only recovery, preservation, deadlines, retry, and nine scenarios.
- `schemas/evidence-workspace.schema.json` closes the release policy.
- `schemas/run-recovery-journal.schema.json` closes the private journal to run ownership, plan, phase, exact artifacts, and cleanup state.
- The deterministic build embeds and integrity-binds both the policy and journal schema. The digest detects mutation but does not authenticate an unsigned developer build. No runtime download or dependency is used.

ACL tests create a real Windows directory with a security descriptor supplied atomically to `CreateDirectoryW`. They verify the initiating user owns it, DACL inheritance is disabled, and the only access-rule SIDs are the initiating user and LocalSystem. File and directory registrations use volume serial and file ID obtained from a non-following Windows handle.

The journal test writes a synthetic private marker only to bounded Temporary Evidence. The marker does not appear in the journal or generated record. The ingestion consumer receives the exact bytes only under the same process/start/SID owner, the file is removed, and its registration disappears. A mismatched live process is rejected before byte access, and a 1,048,577-byte artifact is rejected before creation.

The interruption test starts a real child process, lets it create the workspace and journal and register an empty Temporary Evidence file, then terminates the child before the first evidence write. Cleanup observes that exact owner as stale and proves the registered file, workspace, and journal absent in order.

Separate interrupted-journal fixtures leave the fixed atomic-update sibling both beside a valid stale journal and as the only file after an interrupted initial write. Recovery returns `CleanupIncomplete` with actionable guidance and leaves every available journal version and registered evidence untouched. The preserved-package fixture also moves the protected package deliberately and proves a retry removes only the empty workspace and journal while the moved package survives.

## Synthetic matrix

| Scenario | Observable result | Safety proof |
| --- | --- | --- |
| EligibleDestination | `Validated` / `WORKSPACE.CREATED` | new protected workspace; verified cleanup |
| UnsafeDestination | `Rejected` / `WORKSPACE.DESTINATION_NETWORK` | no workspace; safe local alternative offered |
| InterruptedTemporaryEvidence | `Recovered` / `RECOVERY.STALE_RESIDUE_REMOVED` | registered interrupted bytes and workspace absent before journal removal |
| StaleOwner | `Recovered` / `RECOVERY.STALE_RESIDUE_REMOVED` | exited exact owner permits cleanup only |
| LiveOwner | `Deferred` / `RECOVERY.LIVE_OWNER` | live owner's file and journal remain untouched during recovery |
| AmbiguousTarget | `CleanupIncomplete` / `RECOVERY.OWNERSHIP_UNVERIFIED` | same path is replaced with a different file ID and remains untouched |
| PreservedPackage | `Deferred` / `RECOVERY.FINALIZED_PACKAGE_PRESERVED` | finalized package and protected workspace remain; journal remains and cleanup is not falsely verified |
| WindowsFeatureObservation | `ObservedOnly` / `RECOVERY.WINDOWS_FEATURE_OBSERVED` | `ObserveOnly`; no feature change API is invoked |
| CleanupFailure | `CleanupIncomplete` / `RECOVERY.CLEANUP_FAILED` | a real exclusive file handle defeats both bounded attempts; file and journal remain |

The generated application repeats all nine scenarios after request validation, an explicit `allowStaleRecovery: true` choice, and Preparation approval. Each emits one sanitized workspace-validation record with actionable guidance and one matching terminal outcome. Expected ambiguity, preserved-package deferral, and cleanup failure return `CleanupIncomplete` / exit `60`; other expected safety paths remain `NotStarted` / exit `20`. Collection never starts. The harness then removes its exact fresh validation-only boundary and proves its directory listing is unchanged after every scenario.

A separate negative generated case uses `allowStaleRecovery: false` and proves the hidden fixture cannot grant authority: it stops with `WORKSPACE.RECOVERY_NOT_AUTHORIZED` before workspace creation. Duplicate fixture properties stop with `WORKSPACE.FIXTURE_INVALID`.

## Commands

```powershell
pwsh -NoLogo -NoProfile -File ./tests/EvidenceWorkspacePolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/EvidenceWorkspace.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/EvidenceWorkspaceRecovery.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/EvidenceWorkspaceApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/RequestValidation.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/BuildDeterminism.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

## Claim boundary

No controlled client or real restricted assessment evidence was used. The generated matrix is `SyntheticUnelevated`, creates no capability claim, and publishes no private recovery material. Ordinary execution still stops before collection because Protected Evidence Package finalization is a later slice. No release is published by issue #45.
