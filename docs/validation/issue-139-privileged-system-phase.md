# Issue #139 — one administrator and SYSTEM collection phase

This is synthetic implementation evidence for [#139](https://github.com/jmanuelng/WIN_PCinfo/issues/139),
not live elevation, real collection, personal acceptance or release qualification.
The implementation starts at `d9dc6fd58f4b4eff6a82770f70394a76b55585e4` on the
integration branch. #137 and #138 are merged dependencies. The separately frozen
#160 candidate and its certificate/trust state were not inspected or changed.

## Implemented behavior

The common generated engine now performs its one possible UAC interaction before
any collection. An already-elevated coordinator reuses its authority. The three
release-owned administrator operations finish inside one worker; that worker
then brokers only the frozen SYSTEM operation before it exits. Standard-user
collection and package finalization remain in the initiating process.

The SYSTEM broker receives a closed typed configuration bound to the approved
sub-plan digest. It assembles the existing release-owned worker internally;
script text, commands, executable paths, journal paths, package protectors and
recipient data are not activation parameters. The generated artifact embeds the
reviewed broker source and compressed SYSTEM template, preserving deterministic
builds and the Windows in-memory launch bound.

The initiating coordinator still creates the one-use SYSTEM pipe and owned Job
Object, verifies the actual worker PID and protocol, validates evidence, records
durable task intent before registration, and independently checks current task
instances before recording an absence witness. The administrator grants task
access only to the initiating user, its own selected administrator identity and
SYSTEM; it never gains package access from this channel. Process image checks
use limited query rights while retaining the exact executable digest check.

Denied UAC skips SYSTEM activation and preserves unrelated standard-user evidence
through the canonical record, encryption and protected HTML opening. Source-scoped
SYSTEM denial/loss/timeout remains a gap. Protocol or cleanup uncertainty closes
scheduling. A pre-activation envelope describes the coordinator's failed attempt
using a schema-valid context while activation remains explicitly `NotStarted`;
it fabricates no SYSTEM observation. Early cancellation can truthfully have no
usable report. Cancellation checks SYSTEM cleanup even when no later source may
start.

## Red/green evidence and focused gates

Tests used the explicitly selected installed PowerShell Core 7.6.5 X64 host,
`-NoLogo -NoProfile`, and `-STA` for WPF cases. No dependency acquisition, real
elevation, Task Scheduler registration, live collector, certificate/trust change,
signing, cloud action or publication was performed.

Observed failures before their corrections:

- The combined phase test could not bind the missing SYSTEM-plan parameter.
- The generated request-to-record check detected collection before privilege.
- Duplicate framed properties were accepted by the coordinator reader.
- Denied UAC reached an invalid canonical SYSTEM context and could not package.
- The broker's pre-activation refusal tried to clean up an empty task identity.
- Old early-cancel assertions incorrectly required a report after collection was
  moved behind the front-loaded privileged phase; they now require honest
  `VerifiedAbsent`, no report action and verified worker cleanup at that point.

Passing focused checks recorded before independent review:

| Boundary | Observed result |
| --- | --- |
| `PrivilegedSystemPhase.Tests.ps1` | Real controlled administrator/SYSTEM workers: accepted, reused and alternate authority; SYSTEM denial, worker loss and timeout; no second UAC; preserved protector; re-digested ownership-transfer parameters rejected; actual host signer mismatch rejected before dispatch |
| `SystemBrokerAdmission.Tests.ps1` | Actual activation/framing boundary refuses arbitrary operation, extra protector, untyped deadline, changed plan and expired input before activation-ready; no activation resources |
| `CollectionChannelFraming.Tests.ps1` | Duplicate root/nested fields, zero/negative/oversized lengths, truncated frames and invalid UTF-8 rejected |
| `PrivilegedCollectionPlanPolicy.Tests.ps1` and `PrivilegedCollectionPlan.Tests.ps1` | Closed policy plus nine existing peer, plan, denial, worker-loss, timeout, cancellation and owned-tree checks |
| `SystemCollectionPlanPolicy.Tests.ps1` and `SystemCollectionPlan.Tests.ps1` | Closed policy plus twenty existing catalog, typed parameter, provenance, result, source-failure and cleanup cases |
| `SystemTaskAbsence.Tests.ps1` and `SystemTaskRecovery.Tests.ps1` | Missing/failed observation never proves absence; foreign task preserved; exact owned task and independent instance checks retain recovery uncertainty |
| `StatusDeskEngine.Tests.ps1 -RequireFrontLoadedPrivilege` | Generated ordinary approved flow reaches encrypted package and protected report |
| Same test with `-PrivilegeOutcome ElevationDenied`, `AlreadyElevated`, `AlternateAdministrator` | Generated scope/ownership outcomes reach encrypted report; denied scopes remain explicit and standard evidence survives |
| `StatusDeskCancellation.Tests.ps1` | Cancellation after identity/resource preserves usable partial evidence; active privileged cancellation safely permits no report |
| Four WPF `StatusDeskEngine` cases: Cancel/Close × Privilege/System, with `-RequireRecoveryJournal` | Actual controls cancel controlled workers; journal precedes sources; owned trees/channels absent; no invented report |

WPF timing observations, in milliseconds; memory is sampled test-host MiB:

| Action/worker | First progress | Maximum observed gap | Acknowledgment | Cancel to terminal | Private / working set |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cancel/Administrator | 1269 | 1774 | 15 | 1777 | 345 / 488 |
| Close/Administrator | 525 | 1798 | 8 | 1800 | 331 / 472 |
| Cancel/SYSTEM | 544 | 2584 | 4 | 1827 | 352 / 499 |
| Close/SYSTEM | 1262 | 2519 | 5 | 1843 | 353 / 500 |

These are short controlled cancellation runs, not live performance acceptance.
The earlier #138 full test-host working-set samples of 662–755 MiB exceeded the
provisional 512 MiB budget and remain an explicit #158/#161 measurement obligation.
No budget or live gate is waived by the lower early-cancel samples here.

Build/automation regression, exact final candidate digests and separate review
results are recorded in the completion addendum below. The complete 132-plus-file
repository suite was deliberately not repeated for this ticket, per the current
testing cadence. #158/final owns the next integrated full gate.

## Requirement register contribution and next owners

| Requirement | Automated contribution | Remaining owner |
| --- | --- | --- |
| #37 stories 8–12,15–16,29–30,58,71–72; #134 stories 7,10,12,25 | Common engine's frozen administrator/SYSTEM phase, front-loaded authority, initiating-user ownership, typed IPC, denial continuation and bounded stop | #158 integrated regression; #161 actual privilege and ownership matrix |
| CAP-0007,0015,0016,0017,0020; CMP-0007,0019,0024,0026,0027,0031,0032,0033,0045,0046,0047,0052,0055 | Existing collectors and protection reused across the actual broker/supervisor seams | Relevant remaining collection/evidence tickets close their portions; #158 reconciles shared components |
| Cleanup/recovery and provisional budgets | Controlled tree/channel absence and retained uncertain-task semantics | #161 live task/worker absence, interruption and final resource measurement; #158 final candidate gate |

These rows contribute to the published #158 requirement allocation. Parent #134,
parent #37 and shared capability completion are not claimed. CMP-0061 stays deferred.

## Prepared #161 live cases — all Pending

Use the authorized exact signed acceptance candidate in the intended private
session. Record sanitized outcomes and retain detailed observations privately:

1. Standard launch: UAC approval once before collection; administrator and actual
   predefined SYSTEM evidence reach the same initiating-user protected report.
2. Already-elevated launch: no UAC; report actual source/Assessment User Context
   constraints rather than relabeling administrator identity as a standard user.
3. Denied UAC and denied source access: no retry/prompt, unrelated standard work
   and honest coverage/report survive.
4. Alternate-administrator UAC: initiating user still owns the workspace,
   recovery records and local package protector; alternate administrator/SYSTEM
   receive no package access merely from activation.
5. Cancel and active-window close during administrator and SYSTEM work as
   separate cases: measure acknowledgment/cleanup and independently verify exact
   worker trees, scheduled registration, running instances and temporary plaintext
   absent. Verify subsequent-run behavior and cleanup-only interrupted recovery.
6. Measure final complete-run responsiveness and resource budgets. Re-test exact
   changed candidate bytes; synthetic success establishes no live acceptance.

## Completion addendum

Implementation candidate is awaiting its independent Standards/Spec reviews and
the final focused build/automation results. No implementation closure is claimed
by this initial evidence commit.
