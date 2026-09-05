# Issue #138 cancellation, active close and recovery

Scope: [#138](https://github.com/jmanuelng/WIN_PCinfo/issues/138), under
[#134](https://github.com/jmanuelng/WIN_PCinfo/issues/134) and
[#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37). Exact implementation and
review starting point: `1a55d448780c948db566787ff91a834455d7e7f9`.

Status: implementation complete; final focused validation and independent review
are in progress. Actual delivered-app acceptance remains **Pending** in
[#161](https://github.com/jmanuelng/WIN_PCinfo/issues/161). September 6 remains
the private handoff target, with timing and complete-scope acceptance at risk.
No live assessment, actual SYSTEM task creation, elevation, signing, trust change,
installation, cloud operation or publication belongs to this evidence.

## Delivered behavior

- Actual Cancel and active-window close signal the ordinary engine's cancellation
  token. The GUI waits for supervised completion and cleanup while remaining
  responsive. A bounded controller heartbeat describes waiting for the worker;
  it does not claim a blocked source has produced new evidence. Progress and
  cancellation acknowledgment use serialized, bounded structured transport.
- The existing native, privileged and SYSTEM supervisors retain cooperative
  cancellation, bounded hard termination and independent tree/channel/task
  absence checks. Access denied while probing Task Scheduler is uncertainty,
  never task absence. No runspace-only stop substitutes for owned-work cleanup.
- Ordinary collection registers its protected workspace and recovery journal
  before its first source. Verified packages move to the approved retained
  destination before transient workspace/journal retirement. Cleanup uncertainty
  retains recovery state and disables report actions; integrity failure also
  disables opening. GUI, Completion Summary, terminal record and exit agree.
- New journals use contract 1.1.0 and carry at most one fixed-name SYSTEM task
  registration with its exact ownership digest, durably written before persistent
  task creation. Recovery validates task definition and restricted access before
  stopping/deleting it, then checks registration, captured instances and engine
  processes. Legacy 1.0.0 filesystem-only journals remain readable.
- A subsequent launch holds the device-wide Active Run Lock while inspecting
  residue. Recovery requires a deliberate action and preparation approval. The
  Status desk exposes Recover owned residue; automation retains the existing
  `allowStaleRecovery` choice. Recovery ends without collection, even when no
  residue exists. It refuses live owners, redirected workspaces, replacement
  objects, foreign tasks, ambiguous journals and unproved absence.

## Automated method and status

The primary seam is the generated application with its ordinary comprehensive
scheduler, actual WPF controls, canonical record/rule/report pipeline, encryption
and protected reopening. Only OS source/Task Scheduler boundaries use synthetic
adapters. Tests do not change shipped trust admission or grant fixture authority
to live collection.

`StatusDeskActiveActions.Tests.ps1` drives separate Cancel and Close controls
against actual controlled privileged and SYSTEM workers, plus cooperative and
uncooperative native workers. A controlled source waits over eleven seconds so a
missing heartbeat is observable. It verifies cancellation acknowledgments,
continued dispatcher activity, bounded worker cleanup, retained partial evidence,
actual protected HTML viewing and no later collection. Integrity and locked
residue cases verify disabled report actions and failure precedence.

`StatusDeskRecovery.Tests.ps1` kills only its owned generated application after a
real controlled privileged worker and nested child execute. Kept process handles
verify the product's Job ownership stops both children. The surviving journal is
then exercised through the ordinary generated launch: no authority, foreign path,
successful cleanup and recovery with no residue. No collection resumes.
`SystemTaskRecovery.Tests.ps1` uses generated journal/recovery code with a
controlled Task Scheduler boundary to prove foreign replacement refusal and
owned task absence before journal retirement. Actual Task Scheduler operation
remains a #161 live gate.

Red evidence retained in the work record: missing sustained progress metrics;
ordinary collection without a journal; Task Scheduler access denial falsely
reported absent (after correcting an empty-collection binding failure); and a
live cleanup failure still enabling report opening. Each was followed by its
focused passing check. An interrupted-test launch initially lacked UTF-8 console
setup; its test host now uses the established UTF-8 harness contract. The scoped
owned-child observer required the authorized test sandbox escalation after a
sandbox access denial; that was not a product pass or a flaky retry waiver.

The final focused batch runs these twelve files in fresh installed PowerShell
processes: StatusDeskActiveActions, StatusDeskRecovery, SystemTaskRecovery,
SystemTaskAbsence, SystemCollectionPlan, EvidenceWorkspaceRecovery,
EvidenceWorkspacePolicy, EvidenceWorkspaceApplication, ProtectedPackageWriteFailure,
DeviceReadinessApplication, StatusDeskLock and StatusDesk. Final results, measured
timings, exact candidate identities and separate review reports follow when the
batch completes. No whole-suite run is claimed: the user's September 5 cadence
reserves the next integrated gate for #158/final acceptance unless an observed
regression justifies expanding it. #137's preceding full pass is historical for
the bytes changed here.

## Requirement register contribution and next owners

| Requirement | Automated contribution | Remaining owner |
| --- | --- | --- |
| #37 stories 14–18,57,63,68,74; #134 stories 9–14,16 | Ordinary cancel/close, serialized activity, cleanup-only recovery, honest terminals and protected partial/no-result paths | #158 aggregates final regression; #161 observes every delivered workflow |
| CAP-0015 / CAP-0017; CMP-0031,0032,0045,0046 | Device-wide exclusion, cancellation through actual supervised workers, absence proofs and truthful cleanup/integrity precedence | #139 deepens actual privilege ownership/activation; #161 real Cancel and Close separately |
| CAP-0018 / CAP-0020; CMP-0024,0026,0027,0047,0052,0055 | Durable ownership, protected partial packages, restricted recovery and retained uncertainty | #152 completes reopening/export; #154 finalizes evidence/package boundary failures; #161 actual local/recipient/recovery acceptance |
| First progress ≤5 seconds; heartbeat gaps ≤10 seconds; acknowledgment ≤2 seconds | Measured through generated WPF integration; final matrix pending below | #161 actual delivered-candidate timing; #158 overall regression |
| Provisional cleanup/resource budgets | Synthetic test-host sampling only; no live budget acceptance | #158/#161 measure final candidate; keep any over-budget value explicit |

These rows contribute to the published #158 allocation; they do not close shared
components, parent specs, release qualification or all-product acceptance.
CMP-0061 remains deferred. The separately frozen #160 private candidate and its
real-certificate state are outside this source/build/test boundary.

## Prepared #161 live cases — all Pending

Use the exact later delivered, authorized candidate and approved private evidence
area. Record its signed application/helper/portable digests, source revision,
installed runtime, request/plan identity, expected/observed results and disposition
privately. Do not copy device, user, process, task, path, certificate or evidence
identities into public source or issue comments.

1. Independently exercise Cancel and active-window close during standard, native,
   administrator and SYSTEM collection as applicable. Record which selected
   source actually executed, first progress, every active heartbeat gap,
   acknowledgment and cancellation-to-cleanup duration. Keep interacting during
   finalization. Observe zero new work and exact process/task/channel absence;
   a collector that never executed is a coverage gap, not a pass.
2. For each action, confirm truthful GUI, structured terminal, exit and Completion
   Summary. Reopen trustworthy protected partial evidence and inspect explicit
   Cancelled coverage; otherwise require disabled report actions and the no-usable-
   result explanation. Exercise IntegrityFailed and CleanupIncomplete precedence.
3. Attempt a concurrent launch during active collection and cleanup. Verify it
   neither joins nor disrupts the live owner. Interrupt the owning app during a
   controlled approved operation, then launch deliberately with the original
   destination. Verify the recovery journal survives until all owned residue is
   proved absent and recovery never resumes collection.
4. Exercise recovery with a retained package, locked artifact, unknown/replaced
   object and ambiguous ownership. Preserve foreign state and the journal on
   failure. After deliberate operator resolution, retry cleanup and then approve
   a separate new Assessment Run. For SYSTEM interruption, verify real task
   definition/access ownership, captured instance/process absence and no surviving
   registration. A protected package is retained, never discarded by recovery.
5. Measure the actual candidate's private memory, working set, workspace/package/
   report sizes and cleanup time independently from build/test-host overhead.
   Compare with provisional 768 MiB private memory, 512 MiB working set, 256 MiB
   workspace, 100 MiB package, 25 MiB report and two-minute cancellation cleanup.
   Record Pass, Fail, Blocked or justified NotApplicable per case. An over-budget
   observation remains a finding until deliberately confirmed or versioned.
6. Open and explicitly close the protected report view; prove owned plaintext
   removal, retained package reopening and no automatic plaintext export. Carry
   actual recipient/provider and deliberate export cases to #152/#161.

Implementation-only closure establishes neither a real assessment milestone nor
application, private-handoff or public-release acceptance.
