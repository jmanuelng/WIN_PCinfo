# #152 recipient opening, viewing and restricted export checkpoint

Implementation source: `6cae8c4ad08b45c021b7a7bd73c65917dd459f0a`.
Starting revision and CodeReview fixed point:
`4013e82fd4ad966425e2d12f4bac1ecde44a3a52`.
Specification: [#152](https://github.com/jmanuelng/WIN_PCinfo/issues/152), with
the applicable [#134](https://github.com/jmanuelng/WIN_PCinfo/issues/134) and
[#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37) protection contracts.

Automated checkpoint: **Pass**. Independent Standards: **Pending**. Independent
Spec: **Pending**. Root dispatches fresh reviewers after the implementation turn;
neither axis is waived or represented as passed. Live acceptance: **Pending #161**.
This checkpoint is not application acceptance, public qualification or publication.

## Behavior and regression evidence

- The Status desk selects zero or one fingerprint-confirmed public profile before
  approval and recreates the complete preparation plan. Separate explicit setup
  retains the existing provider, non-exportability and synthetic round-trip rules.
  GUI setup and existing-package workflows require eligible runtime and artifact
  trust; validation fixtures cannot grant those persistent/live operations.
- Local and recipient viewing independently enter the complete package reader.
  Recipient selection never falls back to local DPAPI. Only requested HTML enters
  the protected viewing boundary. The report has an explicit close control; window
  closure also disposes the browser and verifies owned plaintext removal.
- Reopening and warned export are deliberate Status desk actions. The separate
  generated `OpenReport -Mode Gui` and `RestrictedReportExport` workflows accept
  an explicit `PackageProtectionRoute`. Expired historical recipient access does
  not require the old profile or bypass package admission.
- Export rejects broad ACLs, repository paths, public/known OneDrive roots,
  network/redirected or otherwise unsafe destinations before temporary or final
  writes. It accepts only an existing private local directory and never rewrites
  the selected directory's permissions. Saved HTML retains its Restricted banner.
- Actual controlled child-process interruption exposed a stale-recovery defect:
  the registered HTML was removed but its fixed empty viewing directory remained.
  Recovery now applies the same nonrecursive, no-reparse, empty-directory checks
  to that directory. The regression kills only its exact test child, invokes the
  ordinary recovery gate, verifies plaintext removal and preserves the package.

RED observations retained: missing recipient viewing parameter; unsafe export
incorrectly returned `Exported`; absent standalone explicit-close view; missing
recipient selection dialog; and incomplete interrupted-view cleanup. Each now
passes through generated modules, production WPF controls or the package boundary.
One WPF regression driver still expected the browser to be the window's direct
content after the close toolbar was added. Its exact stalled synthetic child was
stopped, its journal-owned test root was verified and removed, and the driver was
repaired to use the named report and close controls. The corrected check passed.

## Executed checks

Command for each row: installed PowerShell 7.6.5 X64,
`pwsh -NoLogo -NoProfile -File tests/<name>.Tests.ps1`. WPF wrappers launch their
own STA test child. Generated assessments use the established controlled OS-source
adapters; no fixture grants live collection authority. Checks ran serially.

| Check | Result | Seconds |
| --- | --- | ---: |
| RecipientViewingApplication | Pass | 9.48 |
| StatusDeskRecipientSelection | Pass | 6.42 |
| StatusDeskViewing | Pass | 6.75 |
| RecipientSharingApplication, including unsigned opening/export rejection | Pass | 56.38 |
| RecipientSelection | Pass | 20.28 |
| RestrictedReportExport | Pass | 1.78 |
| ProtectedPackageViewing | Pass | 1.91 |
| ProtectedPackageContracts | Pass | 1.42 |
| EvidenceWorkspaceRecovery | Pass | 3.19 |
| StatusDeskWpf, controlled comprehensive GUI-to-HTML | Pass | 24.59 |
| BuildDeterminism | Pass | 51.32 |
| ProtectedPackageNegative | Pass | 3.12 |

The final two new GUI drivers also received bounded 20-second watchdogs and passed
again (selection 6.65 seconds, viewing 6.77 seconds). These test-only changes do not
change candidate bytes. Changed PowerShell source/tests parsed without errors;
`git diff --check` passed. The full `tests/Run-Tests.ps1` suite was intentionally
not run under the user's focused-ticket cadence; #158 owns integrated regression.

Generated unsigned script SHA-256:
`e1f4ebb7041fbd11e9a9b37659830efe545c0d83dfeafa2fc15e400449151b1e`
(3,253,190 bytes).

Generated unsigned portable ZIP SHA-256:
`c95cc5e2aa8673883115d7e93feb9861c9dae0b34a4fa3ab6dd073636eef4cf1`
(4,786,647 bytes).

The deterministic gate produced identical script bytes from two build locations.
Synthetic keys were in-memory handles and were disposed; test-owned packages,
profiles, plaintext exports, views and recovery records were removed. The stopped
WPF attempt's exact owned residue was separately verified absent. Generated build
outputs remain in ignored build directories. No real certificate, trust store,
signature, retained private package or frozen personal-evaluation artifact changed.

## Required #161 live acceptance handoff

All cases below remain **Pending** on the exact final personally admitted candidate.
Record candidate hashes, preparation decisions, observed terminal/cleanup states,
timings and restricted evidence privately. Publish only sanitized outcomes.

1. From the delivered Status desk, perform the separately authorized dedicated
   recipient setup. Observe provider/protection level, non-exportable Current User
   key and successful synthetic round trip. Preserve keys needed by retained
   packages. Confirm the fingerprint independently and select it before collection;
   verify the rebuilt frozen summary. Also exercise zero-recipient preparation.
2. Complete the real approved assessment, including a legitimate partial-result
   case. Verify Open report is available appropriately and completion produces no
   permanent unencrypted HTML export. Confirm adding/changing recipients is no
   longer possible after approval or collection.
3. Reopen the same encrypted results independently through local and recipient
   protection. Verify unrelated/missing protector and corrupt-package refusal,
   including no temporary plaintext exposure. A same-device test key is an
   additional opening route, **not independent off-device recovery evidence**.
4. Close viewing explicitly, close the report window, and exit the application in
   separate cases. Verify owned plaintext and recovery-state disposition. Exercise
   deliberate interruption, then the folder-scoped recovery action; preserve
   protected results and refuse ambiguous/foreign objects. Browser tab closure is
   not accepted as cleanup evidence.
5. Decline Save HTML's complete warning and reject unsuitable/private-destination
   choices, proving zero writes. Deliberately save to an eligible private directory,
   reopen the file offline, verify the persistent Restricted designation and
   partial coverage, then remove the authorized test export and verify disposition.
   Confirm the original protected package still reopens afterward.
6. Validate actual keyboard/focus, screen/scaling, HTML usefulness, interaction
   timing and private transfer guidance across these actions. Retain the inherited
   full-app quality budgets and all #134/#37 gates. Do not infer acceptance from
   this synthetic checkpoint or renew old exact-candidate signing evidence.

## Review handoff

Use `git diff 4013e82fd4ad966425e2d12f4bac1ecde44a3a52...HEAD` and
`git log 4013e82fd4ad966425e2d12f4bac1ecde44a3a52..HEAD --oneline`.
The fixed point resolves and the implementation diff/commit list is nonempty.
Standards sources are the original checkout's `AGENTS.md`, `CONTEXT.md`,
`docs/agents/issue-tracker.md`, `triage-labels.md`, `domain.md`, plus integration
`CONTRIBUTING.md` and `.sandcastle/CODING_STANDARDS.md`. No ADR directory exists.
Apply the CodeReview skill's complete smell baseline independently from Spec.
The orchestrator owns the shared #134 register update, review aggregation and
transactional GitHub delivery. No issue was closed or requirement waived here.
