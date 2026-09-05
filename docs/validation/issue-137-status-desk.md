# Issue #137 production Status desk evidence

Scope: [#137](https://github.com/jmanuelng/WIN_PCinfo/issues/137), under
[#134](https://github.com/jmanuelng/WIN_PCinfo/issues/134) and
[#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37). Fixed review/start revision:
`56f40ab7fb9e3ab4262c8799e019e4c4b80ad3a1`.

Status: implementation, focused synthetic validation, independent reviews and the
combined **132-file integrated regression gate pass** on the final governed inputs.
Real signing, trust, device collection and signed GUI-to-HTML acceptance remain
**Pending #160**. September 6 remains the private handoff target; this automated
slice does not establish that handoff or reset its deadline.

## Implemented path

The portable GUI entry loads the production white/light-grey and blue WPF Status
desk. Four persistent facts show assessment, authority, network and protected
results. The same preparation gate and ordinary comprehensive collector chain
used by guided/automation run in one separate PowerShell runspace. Request values
cross into that worker as a serialized snapshot. Preparation, definition,
recipient and plan remain there; the UI gets JSON copies and returns only the
displayed digest and its decision. Decline starts no collection. `AcceptPreparation`
does not bypass the GUI control.

The transport holds at most 128 immutable event strings, with independent frozen
preparation, completion and terminal slots so activity overflow cannot lose them.
The STA dispatcher owns every control update, elapsed activity and a 64-entry
timeline. No PowerShell UI callbacks run on arbitrary worker threads. Completion
shows the unchanged seven-outcome vocabulary and enables Open report only for an
actually verified available package. The exact package path stays in process,
outside public progress and terminal records.

Collection scheduling checks cancellation between source families. Existing
standard-user native workers, the approved device process and privileged/SYSTEM
plans receive the same cancellation token. Rule evaluation and encrypted
finalization remain independent of collection cancellation. Controlled cancellation
after identity and after resources preserves earlier normalized evidence in a
validated, encrypted partial package, with Cancelled coverage for stopped
prerequisites and no fabricated empty-device observations. The ordinary scheduler
also takes the existing device-wide Active Run Lock. Unknown worker failure after
collection is CleanupIncomplete; loss of package integrity never becomes usable
report access.

Open report reuses protected-package verification and the registered temporary
viewing boundary. Its owned WPF browser rejects navigation outside the local
report; the existing renderer remains self-contained. Closing disposes the view
and verifies owned plaintext removal. Package-integrity failure and viewing-cleanup
failure remain distinct. No automatic permanent plaintext export is introduced.

## TDD and focused checks

The confirmed seam is generated WPF preparation/approval through ordinary
comprehensive scheduling, controlled OS collector adapters, canonical records,
rules, report generation, actual local package encryption and protected viewing.
The synthetic adapter substitutions exist only in the test-owned in-memory copy
of generated module regions, never as a shipped trust or live-collection switch.
No lifecycle-only fixture substitutes for the ordinary engine test.

Recorded red cases:

- The generated modules initially lacked the bounded Status desk transport.
- The worker initially could not enter GUI preparation; after adding the shared
  approval adapter, decline returned PREPARATION.DECLINED without collection.
- The complete ordinary controlled chain initially had no private package handoff
  for Open report; the finalizer now exposes only its verified surviving package.
- Cancellation exposed absent stopped-firmware/SYSTEM composition and collection
  cancellation incorrectly reaching a rule worker. Stopped-source coverage and
  independent interpretation/finalization now produce reopenable partial evidence.
- The first modal WPF test driver could not close its own report from the same
  timer callback. A separate STA closing driver resolved the harness defect. The
  exact owned synthetic process was stopped, its registered viewing plaintext was
  removed through recovery, and its verified owned test root was removed. No live
  evidence, key or unrelated process/resource was involved.
- The lock test first overlapped another focused engine test, which correctly held
  the shared lock; its test cleanup now releases only a lock actually acquired.
  The isolated test proves a held lock refuses collection.
- An additional unchanged generated-entry test found that dynamic closure modules
  hid script-scoped callback helpers. STA callbacks now retain the active dialog
  scope. The exact generated `-Mode Gui` entry displays preparation and declines
  successfully; the approval-to-report WPF test also passes after this correction.
  The failed fixture-only test child was verified and stopped without collection.

All 13 initial focused files passed in **172.69 seconds** in fresh installed PowerShell Core 7.6.5 x64
processes using `-NoLogo -NoProfile -File tests/<name>.Tests.ps1`:
StatusDesk, StatusDeskWpf, StatusDeskCancellation, PreparationSummary,
DeviceReadinessApplication, FirmwareReadinessContract,
AdministratorExposureContract, EffectivePolicy, ProcessSupervisor,
ComprehensiveReportApplication, NetworkTopologyNativeSource,
SoftwareInventoryNativeSource and CertificateTrustNativeSource.
StatusDeskLock separately passed. WPF uses the same installed executable with STA.
The affected StatusDesk/WPF checks are refreshed after final adapter corrections.
All 24 changed PowerShell files pass the parser, and `git diff --check` passes.

The first independent reviews examined `56f40ab7...e56642e`. Standards found no
hard violations and one low-priority naming judgment: the scheduling predicate
also entered a stage. It is now named `Enter-AssessmentCollectionStageIfActive`.
Spec found one actionable gap: cancellation inside the active privileged worker
threw before protecting earlier source envelopes. A new controlled native
privileged-worker cancellation test reproduced Cancelled with no package. The
verified stopped worker now contributes Cancelled prerequisite coverage and
continues safe partial finalization. Its wider partial record exposed a null
cross-domain policy evidence-reference list; the renderer's canonical finding
constructor now preserves an empty array. No evidence or successful negative is
invented. The strengthened WPF check requires the actual HTML DOM/headline to load,
then closes the owned report and verifies plaintext cleanup.

## Independent review

Standards: zero remaining hard violations or actionable judgments. The initial
naming judgment is resolved. Spec: zero remaining actionable findings; the active
privileged-worker cancellation gap is resolved. Both independent reviewers
rechecked the affected cancellation, exact generated-entry callback, first-run
documentation and explicit build-source expectation corrections. No duplicate
review layer or tests were run by the reviewers.

## Integrated checkpoint and candidate

Final implementation/test revision:
`ce05fbda65a1701c7d0eab433493d905ab997c4e`. The local DCO commits are
`e56642e` (production path), `ab1460c` (active privileged cancellation), `59accb5`
(generated callback scope), `53a9e49` (first-run documentation) and `ce05fbd`
(exact source-provenance expectation). A later evidence-only commit records the
completed gate without changing governed candidate inputs.

The initial full-suite command was installed `pwsh -NoLogo -NoProfile -File
tests/Run-Tests.ps1`. It stopped after **211.64 seconds**, exit 1, at
`BuildDeterminism.Tests.ps1`: the explicit expected source set omitted the new
Status desk module. Adding that source retained the exact source-set equality and
all per-resource hash assertions. Its focused rerun passed, including LF/CRLF
mirror builds and relocated generated-app checks.

Two governed first-run pages still said the GUI was unavailable and were corrected
during the early initial run. Their final write times were **21:48:36.5408122 UTC**
and **21:48:37.5683804 UTC** on September 5. The immediate log observation and
subsequent observations through 21:49 showed only `AdministratorExposure.Tests`
completed and `AdministratorExposureApplication.Tests` running. Those two files
are refreshed on the frozen final inputs. Fourteen later files completed after
the freeze before the build-test failure. A separate run covers the two refreshed
files and all 115 previously unrun files. This is an explicitly combined gate,
not a claim that the interrupted initial run validated one unchanged candidate.
The resumed **117-file segment passed**, exit **0**, in **3044.43 seconds**
(50 minutes 44.43 seconds). Its final-input file set, the fourteen retained
post-freeze files and the corrected focused build check were compared with the
repository's test-file inventory: their union is exactly **132 of 132 files**.
The initial failed segment's 211.64 seconds is separate, and the focused build
check's duration was not captured. No unchanged full-suite restart was performed.

The resumed method used the same installed host, UTF-8 console setup and sequential
file invocation as `tests/Run-Tests.ps1`, selecting the two named prefix files plus
test filenames sorting after `BuildDeterminism.Tests.ps1`. Local ignored logs are
`.test-output/issue137-full.log`, `.test-output/issue137-resumed.log` and matching
JSON timing/exit records. The suffix includes final-input documentation and
portable determinism/application tests, all six Status desk files, the three
cancellation variants, actual WPF HTML DOM loading and all SYSTEM application
paths. The final Status desk synthetic test-root inventory is empty; owned report
viewing plaintext was verified removed. Standard harness/build outputs remain
ignored synthetic artifacts.

The final canonical build reproduced these unsigned precursor identities from the
focused deterministic build after the governed documentation freeze:

- Generated application SHA-256:
  `efecf42cf6d1d102e9e828878b88c742c9cb65182425c796a5910f509d1a4900`.
- Portable ZIP SHA-256:
  `2d9e0deed8713a2dd0f17ea9955e9894e24934e241d540b46ddd29237140d59d`.

Candidate paths are `artifacts/WIN-PCInfo.ps1` and
`artifacts/WIN-PCInfo-2.0.0-preview.1-portable.zip`, with the expanded portable
folder beside them. Final build evidence is the ignored
`.test-output/issue137-final-build.json`. These are unsigned precursor artifacts;
no real certificate, trust, signing, assessment or publication action occurred.

Validation documentation is explicitly excluded from packaged documents by
`build/PortableDistribution.ps1`; final evidence updates do not change these
candidate bytes. The earlier pre-#136 full pass remains historical and is not
validation of these changed bytes.

## Requirement contribution and next owners

| #134 / #37 obligation | This slice's evidence | Remaining owner / gate |
| --- | --- | --- |
| One engine, accepted Status desk and frozen preparation/consent; #134 stories 1,4–9,13,15,19–24,29 | Actual generated WPF controls reach the ordinary comprehensive engine; bounded progress, immutable worker request/plan, decline, terminal and protected opening are automated | Real signed GUI-to-HTML #160; complete control/help/scaling polish #153; full delivered workflow acceptance #161 |
| CAP-0015 / CAP-0017; real scheduling, cancellation and seven honest terminals | Native token propagation, controlled cancellation with protected partial evidence, lossless terminal slot and ordinary Active Run Lock | Active-close/interruption/stale recovery and full timing depth #138; administrator/SYSTEM ownership/elevation depth #139; real acceptance #160/#161 |
| CAP-0018 / CAP-0020; protected canonical evidence and ownership | Existing local protection, canonical validation, encryption, surviving package handoff and owned temporary viewing cleanup execute in controlled generated integration | Complete reopening/export/recipient UX #152; boundary failures #154; actual intended-user and alternate-admin/provider evidence #160/#161 |
| CAP-0019; useful advisory offline report | Real record/rule/report pipeline carries controlled observations, evidence-linked findings, recommendations and honest coverage through encrypted reopening | Evidence-family breadth #140–#150; full cross-domain report #151; live usefulness #160/#161 |
| Local Only sends zero assessment requests | Frozen plannedRequests is empty; controlled ordinary network/connectivity adapters reject any expanded behavior; existing native-source offline and report checks retained | Complete local topology #148; enabled-network breadth #150; measured real Local Only egress #160/#161 |
| CAP-0023 / CAP-0024; language-neutral portable GUI path | Actual STA WPF controls and generated entry preserve shared contracts and installed runtime | Beginner guidance/help/scaling #153; final reproducible candidate/provenance #155; exact acceptance #158/#160/#161 |
| #37 stories 6–8,13–16,18,21,23,50–58,65,70–75; sub-objectives 1,2,8,9 | The listed rows contribute the minimum GUI spine, not blanket closure of shared stories/components | #158 aggregates the published #134/#37 requirement allocation and all remaining owners |

Shared CMP-0024, CMP-0025, CMP-0026, CMP-0027, CMP-0031, CMP-0032,
CMP-0035, CMP-0040, CMP-0045, CMP-0046, CMP-0047, CMP-0048,
CMP-0052, CMP-0054 and CMP-0055 retain their other owning slices.
CMP-0061 remains deferred; no fallback profile is added or authorized.

## Prepared #160 cases

Use the private certificate/candidate procedure in
[personal-evaluation-certificates.md](../personal-evaluation-certificates.md).
Keep instantiated identities, paths, signatures, device data and screenshots in
the approved private session area. The unsigned build is a candidate precursor,
not authority to collect.

1. Sign and verify the exact generated helper/application and all governed package
   resources; record exact signed candidate digests privately. Launch through the
   portable double-click entry with the installed eligible runtime.
2. Inspect all preparation facts/details, confirmed recipient and Local Only.
   Decline and prove no collector, privileged worker, evidence workspace or package
   started. Repeat from a clean new run and approve the displayed plan once.
3. Observe responsive controls, activity and elapsed time during the real complete
   Local Only chain. Privilege denial, inaccessible evidence and limitations must
   remain honest gaps. Record actual source/coverage execution; fixture passes
   cannot stand in for a selected live collector that never ran.
4. Require a truthful terminal and Completion Summary. Open the actual encrypted
   report, inspect at least one source-backed advisory finding, evidence reference,
   coverage limitation and useful follow-up. Verify no assessment or report-opening
   network requests and no unintended permanent plaintext export.
5. Close the report and verify owned viewing plaintext removal. Reopen the retained
   protected package; separately exercise cancellation, competing launch and active
   close with their exact terminal/package/cleanup dispositions. Record all timing
   and any interruption/elevation/feature defect under its named owner.

No fixture, disclosed gap or private test certificate closes #160, #161, public
qualification, or final release approval. A verified #160 blocker is required
before considering the separately governed historical interim fallback.
