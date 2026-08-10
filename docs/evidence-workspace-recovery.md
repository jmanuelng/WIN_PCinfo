# Evidence Workspace and Stale-run Recovery

An Evidence Workspace is a new directory used by one Assessment Run. It confines unprotected Restricted Diagnostic Evidence while WIN-PCInfo is working. A Run Recovery Journal is a small, separate ownership record that tells a later launch which exact product-created objects may need cleanup after a crash or power loss.

This implementation is a tracer bullet. The generated application can exercise the complete safety contract through visibly synthetic fixtures, but an ordinary assessment still stops before collection because the real Protected Evidence Package finalizer is not available. Nothing in this slice creates a Preview or Supported capability claim.

## What an operator needs to know

Before approval, WIN-PCInfo evaluates the requested destination without creating the workspace. The destination must be an existing, non-root directory on a ready local fixed NTFS or ReFS volume. Network paths, unavailable or unsupported volumes, existing run targets, and any path whose existing ancestors include a junction, mount point, or symbolic link are rejected with a specific reason. The safe alternative is the initiating user's local application-data area under `WIN-PCInfo\Runs`.

A workspace is never silently redirected. If the requested location is unsafe, preparation stops and presents the restriction and alternative so the operator can submit a new request deliberately.

When creation is authorized, the directory name contains a fresh run-scoped UUID. Windows creates the directory and its security descriptor in one native operation. Its owner is the initiating Windows user, inheritance is disabled, and full access is granted only to that user and LocalSystem, the one trusted process identity already fixed by the SYSTEM Collection Sub-plan. Failure to create or verify that boundary stops before evidence is written.

## Why the ACL is applied atomically

Creating a normal directory and tightening its permissions afterward would leave a short race in which inherited users could enter. WIN-PCInfo instead passes a protected Windows security descriptor to `CreateDirectoryW`. The mechanism trusts the Windows object manager and the local filesystem's ACL enforcement. It does not claim to protect a compromised operating-system kernel or an initiating user who intentionally copies their own evidence elsewhere.

The implementation opens each registered filesystem object without following a reparse point and records its volume serial plus file identifier. A path alone is not ownership proof: another object can later appear at the same spelling. Recovery compares the current object identity with the registered identity before deletion. A mismatch remains untouched and becomes `CleanupIncomplete`.

## What the journal contains

The journal has a closed schema and a 32 KiB UTF-8 ceiling. It records only:

- the per-run UUID and approved-plan digest;
- the lifecycle phase;
- the owner's process ID, exact process start time, and initiating-user SID;
- exact run-owned workspace, Temporary Evidence, and finalized-package registrations with filesystem identities and cleanup actions; and
- cleanup state, attempt count, and a stable reason code.

It has no free-form metadata or evidence field. It cannot contain an Assessment Observation, Assessment Record, Assessment Subject, credential, secret, Recipient Profile, or product-generated cross-run tracking identity. Journal writes use a create-new sibling, a durable flush, and a same-directory atomic rename. An interrupted write is preserved for deliberate inspection; it is never guessed into validity.

## Temporary Evidence

An approved collector should return its normal Collector Result Envelope in memory. Temporary Evidence exists only for a collector that cannot do that. This release contract permits at most 16 temporary artifacts and 1 MiB per artifact. Each file receives a generated name inside the workspace, is registered before content is written, and is read only after its path and filesystem identity are reverified.

The ingestion consumer must accept the exact bounded bytes before WIN-PCInfo deletes the temporary file and removes its registration. If ingestion or deletion fails, the file remains registered and cleanup takes precedence over useful partial work.

Deletion here means that the product-owned directory entry is removed and its absence is checked. Windows and the storage device may retain recoverable blocks. WIN-PCInfo makes no forensic secure-erasure claim.

## Deliberate Stale-run Recovery

Automation sets `automationChoices.allowStaleRecovery` to `true`; guided operation will expose the equivalent deliberate choice in a later user-interface slice. The Preparation Summary states `CleanupOnly` and `collectionResumeAllowed: false`. A hidden validation fixture cannot grant that authority.

Recovery follows this order:

1. Parse the bounded journal with strict UTF-8, duplicate-property, depth, number, and closed-schema checks.
2. Verify the journal directory owner and protected ACL and confirm the current initiating user matches it.
3. Compare the recorded process ID and exact start time with the live process table.
4. If that exact owner is live, do nothing and return `NotStarted` with `RECOVERY.LIVE_OWNER`.
5. If the owner is stale, verify the workspace name, ACL, reparse state, and filesystem identity, then verify every registered artifact is inside it and still has its registered identity.
6. Remove only artifacts marked `Remove`, then the fixed empty temporary-evidence directory, then an empty workspace. Cleanup has two attempts total—one initial attempt and one idempotent retry—inside a two-second deadline.
7. Preserve a registered finalized Protected Evidence Package and its access-restricted workspace. Windows Feature state remains observation-only; recovery never enables or disables a feature.
8. Remove the journal last, only after every cleanup target is absent and every preserved object is still the exact registered object.

Recovery never resumes collection, adopts an unknown directory, recursively deletes a guessed path, removes a finalized package, or changes an existing Windows Feature.

## Outcomes and troubleshooting

`RECOVERY.STALE_RESIDUE_REMOVED` means exact stale residue was handled and the journal was removed. The run remains `NotStarted`; start a new Assessment Run deliberately.

`RECOVERY.LIVE_OWNER` means the exact recorded process is still active. Let it finish, then retry. Do not terminate it merely because another launch found the journal.

`RECOVERY.OWNER_UNVERIFIED`, `RECOVERY.JOURNAL_OWNERSHIP_UNVERIFIED`, or `RECOVERY.OWNERSHIP_UNVERIFIED` means identity or access could not be proven. The target and journal remain. Close software only when appropriate, inspect the protected journal locally, and retry; do not manually delete a path whose ownership is uncertain.

`RECOVERY.CLEANUP_FAILED` means a verified owned object remained after both attempts, often because another program still holds it open. Close that program and retry deliberate recovery. The outcome is `CleanupIncomplete`, exit code `60`.

## Reproduce the public-safe checks

```powershell
pwsh -NoLogo -NoProfile -File ./tests/EvidenceWorkspacePolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/EvidenceWorkspace.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/EvidenceWorkspaceRecovery.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/EvidenceWorkspaceApplication.Tests.ps1
```

The fixtures contain only release-owned scenario names. They cannot provide a path, journal object, process identity, command, script, evidence value, package, or Windows Feature name.
