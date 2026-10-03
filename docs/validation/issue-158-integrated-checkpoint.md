# #158 integrated automated preparation checkpoint

**Automated preparation completed; source qualification blocked.** This record
does not close #154 or #158. Both independent Code Review axes are Pending for
root's fresh CLI contexts. Actual #160/#161 acceptance and public #162–#164 gates
remain pending, as do both parent specifications. The September 7 05:00 UTC
(00:00 CDT) deadline was missed: qualifying source and private/live handoff were
not achieved. No deadline or acceptance threshold was changed.

## Identities and evidence entry points

Exact start / Code Review fixed point:
`e742e92daccd87b04e1572fe0b9926199996864f`.
Branch: `codex/spec134-afk-batch`. HEAD matched before edits; the worktree was
clean. No checkout switch, pull, rebase, reset or inherited implementation
conversation was used.

Historical failed full-suite product/test checkpoint:
`c5d7e9ad1dbdc3857c9eb55ae51e414bbe6aa6f7`.
The corrected test checkpoint is
`621f95f3fa65004a62252e4f4edb350dcb505d45`; its separate affected qualification is
recorded in [the harness correction evidence](issue-158-harness-correction.json).
No complete gate ran at these corrected inputs. The original full run remains
historical even though product bytes are unchanged.
The last product correction remains
`447c73041f3f5e9ce249856555694447c3519e53`; #158 changes only test evidence retention
and documentation. The unsigned generated primary is 3,319,490 bytes, SHA-256
`262f069f9d228c1636f84165846b9996bf257993f0900f423e9154166467a86e`.
The final documentation commit will be reported in the delivery handoff; it cannot
be substituted for the actual frozen test-source identity.

| Artifact | Purpose |
| --- | --- |
| [Operational requirement register](issue-158-requirement-register.json) | One register: 90 original stories, 12 sub-objectives, 39 implementation and 26 testing decisions, 29 capabilities, 58 required components, 33 GUI stories, six GUI implementation sections and both eight-row gate sets. |
| [Integrated results](issue-158-integrated-results.json) | Actual command/result/timing, file inventory, source/input/environment identities, candidate resources and independently evaluated quality measurements. |
| [Frozen gate scope witnesses](issue-158-scope-results.json) | Actual c5d7 case/state/reason evidence, expected source-owned witnesses and justified inapplicable combinations; old #154 observations are not reused. |
| [Corrected affected checks](issue-158-harness-correction.json) | Exact corrected test-source/input identities, sampler RED/GREEN, all 15 readiness cases, cleanup and disclosed sampling losses. |
| [Complete #161 session packet](issue-161-session-packet.md) | Beginner launch path, every control/family, eight actual live checks, private bindings, comparisons, both protectors/network behaviors, recovery/cleanup/retest and sanitized summary. |
| [Bounded observer preparation](issue-158-observer-boundary.md) | Supported read-only facts, finite conditional method and precise unresolved save/metadata/ownership/loss/attribution blockers. No activation or calibration. |

Implementation state, automated validation, live execution, private handoff,
release qualification and publication are independent. A scoped synthetic Pass
does not complete a requirement needing live evidence. Story 90 and CMP-0061
remain Deferred with a justified Preview.1 NotApplicable implementation action.
Missing required behavior is not an environmental gap. Shared component closure
requires every applicable owning-slice obligation.

The supplied refreshed dependency evidence reports #138–#153 Closed. #154 is
implemented in this batch, not merged; its native Open/blocking relationship is
preserved. Its 25 passing affected checks and two fresh zero-finding correction
reviews are recorded in [the root review record](issue-154-correction-review.md).
Full current qualification was explicitly pending this joint gate. The old
343-case/676-pair result retains its historical candidate and inputs.

## Small #158 harness change and RED/GREEN

The existing `Run-Tests.ps1` still discovers every `*.Tests.ps1` and executes
serially. It now records each file's result/timing/hash, continues to subsequent
files after a thrown failure and fails the overall gate if any file failed.
`RegressionHarness.Tests.ps1` copies that runner into an owned synthetic tree:
the first file throws, the second emits its independent execution witness.
RED: the original runner never reached the second file. GREEN: it reached the
second file, retained Fail/Pass separately and returned a failed overall result.
Its owned synthetic directory is verified and removed.

The existing safety wrapper copies only its minimized mode summaries before its
ordinary owned cleanup. The existing official-validator wrapper likewise retains
its result inventory. Generated Status desk tests use the existing qualification
projection for the eleven source-application entry files when the suite supplies
its owned evidence destination. Each projection includes exact bounded arguments,
scope states/reasons, terminal/exit, body-assertion result, separate test-cleanup
disposition and measurements. No observation values, packages, profiles, plaintext
reports or secret-like marker payloads enter this retained projection. Summary
success requires completed case assertions and verified cleanup. Scope pairing
compares those completed case witnesses; full qualification additionally requires
the owning files and entire gate to pass. An early projection alone cannot qualify
a case, and a passing case does not erase a failure elsewhere in its owning file.

The Workers selection adds the retained `PrivilegePostStartLoss` regression.
The gate therefore expects the original 195 source cases plus 18 Safety,
24 Workers, 52 Sources and 55 Cultures: **344**, not a forced 343. Other established
generated cases and semantic-format regressions execute through their normal
files. There is no separate duplicate 343-case matrix or replacement runner.

Focused generated post-start loss and Readiness/Complete checks passed before
freeze. The former observed IntegrityFailed/50 after actual controlled execution,
zero admitted envelopes, no SYSTEM/package and verified cleanup. The latter
retained all selected scope rows through the protected report. Changed script
parsing and the final harness regression passed before the DCO checkpoint.

## Single integrated gate

The authorized command is:

```text
C:/Program Files/PowerShell/7/pwsh.exe -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

It executed **184/184 files: 175 Pass, 9 Fail**, exit 1, from
`2026-09-07T01:30:16.6038861Z` to `2026-09-07T04:44:11.2991085Z`:
**11,634.677 seconds (3h 13m 54.677s)**. Installed host: PowerShell Core
7.6.5 X64, .NET 10.0.11. No runtime, software or dependency was acquired. Generated
tests and candidate builds were serialized. New #158 documentation under
`docs/validation` is outside portable build inputs; product/tests/definitions stay
frozen while the gate ran. The evidence includes 643 primary source/test/schema/
definition/infra inputs plus a continuity inventory of all 787 tracked inputs at
the frozen checkpoint. Actual execution and continuity checks are distinguished.
All 787 tracked input identities were rechecked unchanged at
`2026-09-07T05:06:18.1191575Z`, after original-input supplemental cases and before
the sampler correction.

Safety 18, Workers 24, Sources 52 and Cultures 55 all passed. The 195 source-case
inventory contains 194 Pass and the retained Virtual sampler failure after six
initially unreached readiness cases were executed separately. Thus the frozen
qualification inventory has **344 cases, 343 Pass, one Fail**. The existing
allocation's 676 applicable scope/state pairs have passing current-run witnesses,
with 611 justified NotApplicable pairs; that pair coverage does not erase the
failed case or qualify a failed full gate. Current official-schema execution
retained 573 Pass, zero Fail and 177 NotApplicable outcomes with no external fetches.
All 470 semantic-format regressions passed across five cultures.

After the full gate, the remaining 37 Effective Policy cases, six readiness cases
and GUI Cleanup-precedence case all passed on unchanged c5d7 inputs. Their separate
commands, elapsed times and log hashes are retained in
[policy](issue-158-policy-case-completion.json),
[readiness](issue-158-readiness-case-completion.json) and
[GUI Cleanup](issue-158-active-case-completion.json) evidence. No initial passing
case was replayed for those completion steps. Assertions still unreachable in the
other failing files remain explicitly unqualified below.

Full-suite stdout/stderr remains an ignored local synthetic test log, with its
digest retained in sanitized evidence. It is not a public log upload. Only
allowlisted outcomes, filenames, stable codes, counters and hashes are delivered.
Existing historical failures remain intact. No test file is excluded, no failing
suite is silently accepted, and no identical full run is repeated.

## Frozen quality workload and hard limits

The existing SoftwareReportApplication entry executes the already-defined
Maximum, Distinct and EscapedOverflow scenarios. Maximum retains all 128 bounded
software registrations in the comprehensive report; Distinct exercises maximum
distinct Unicode/escaped evidence; EscapedOverflow must refuse the oversized
rendering with IntegrityFailed/50, no final package and verified cleanup. Exact
source and fixture hashes bind each measurement; no reduced workload is invented.
The existing FullReportApplication maximum and six WPF active-action scenarios
provide further report and real-control synthetic witnesses.

Every budget in release-gates policy 1.0.0 remains governing: first progress
5 seconds, heartbeat 10 seconds, acknowledgment 2 seconds; normal run 30 minutes,
absolute ceiling 60 minutes, cancellation cleanup 2 minutes; private memory
768 MiB, working set 512 MiB, workspace 256 MiB, package 100 MiB, HTML 25 MiB.
Stricter package-policy bounds remain 2,621,440-byte plaintext/archive,
2,097,152-byte record and 262,144-byte HTML. Maximum/distinct byte results and
overflow-safe refusal are independent checks, not averaged.

Samples measure the generated test host, including build/module compilation/WPF
overhead, and the owned test directory. Package/HTML final lengths are exact.
Samples are lower bounds on peaks and do not establish aggregate child-process or
live delivered-app acceptance. Historical #138 working-set excess (662–755 MiB)
is retained; current overruns remain Fail without an environmental label or a
threshold waiver. #161/#162 still require actual-device evidence and three clean
qualifying full-profile measurements.

## Retained owning-slice failure

**F158-1 — contract-set declaration exceeds its schema.** The full gate's
`AssessmentContractSet.Tests.ps1` failed in 46 ms at its first Test-Json check.
Expected: the release Contract Set satisfies its Draft 2020-12 schema.
Observed: `/fieldDefinitions` has **264** entries, while
`schemas/assessment-contract-set.schema.json` permits at most **262**; the test's
later explicit count also still expects 262. The exact schema error was
`Value should have at most 262 items at '/fieldDefinitions'`.

The two added definitions are `field:resource.printer-driver.environment` and
`field:resource.printer-driver.driver-model`, introduced by the #147 correction
`c613fed3cccea8c0055a6bd9c84f616f5d149f59`. This is a source/schema/test consistency
failure, not an environment issue. Root should dispatch a fresh bounded owning
correction for #147's additive contract integration, coordinating #154's contract
qualification seam. Preserve both fields and their delivered behavior; this record
does not propose deleting evidence or waiving a bound. The owning worker must
determine the correct versioned contract change, refresh affected tests and
candidate identities, and obtain the required independent reviews.

#158 did not repair this other-product defect. The full run gathered all applicable
file evidence while independent register/session preparation continued.
Any source/harness repair invalidates affected current evidence; retain
this failed full run and let root determine the justified final qualification
refresh after the fresh correction. #154 and #158 stay Open.

## Measured quality failure

**F158-2 — measured memory and timing budget failures.** Across 364 retained
generated-case measurements, 349 working-set and two private-memory observations
exceeded their limits. Global sampled maxima were **1,413,914,624 bytes working
set** and **1,216,479,232 bytes private memory** in the direct engine case running
inside the accumulated suite host. That host includes previous test state; it is
not a product-only measurement. The separately invoked FullReport maximum case
still reached 865,660,928 bytes working set, above the 536,870,912-byte hard limit.
There were also **22 timing violations**: three first-progress and 19 heartbeat-gap
observations. The largest were 10,861 ms first progress (5,000 ms limit) and
21,951 ms heartbeat gap (10,000 ms limit). Every exact case/metric/limit remains in
the integrated results; behavioral Pass never overrides an independent quality Fail.

| Frozen workload | HTML bytes | Package bytes | Sampled private bytes | Sampled working-set bytes | Behavioral result |
| --- | ---: | ---: | ---: | ---: | --- |
| Software Maximum | 236,813 | 1,802,705 | 614,854,656 | 753,139,712 | Pass |
| Software Distinct | 246,333 | 1,812,617 | 691,003,392 | 831,737,856 | Pass |
| EscapedOverflow | 0 | 0 | 724,258,816 | 865,067,008 | Pass: IntegrityFailed/50, no package, cleanup verified |
| FullReport Maximum | 236,813 | 1,802,705 | 727,429,120 | 865,660,928 | Pass |

The maximum sampled owned workspace was 1,813,898 bytes. Exact internal record,
plaintext and archive lengths were not separately exported; the existing
assertions exercised their stricter bounds. They are not invented measurements.
The six WPF Cancel/Close cases passed their control/timing assertions; these do
not replace missing actual-device responsiveness, keyboard, focus or scaling checks.
Their largest acknowledgment was 14 ms and actual cancellation-to-terminal time
8,120 ms. Only the six nonnegative recorded cancellation-request timestamps enter
that calculation; a -1 sentinel is not a request. The 363 recorded nonnegative
coordinator-terminal clocks peaked at 27,891 ms and stayed below both the normal
30-minute and absolute 60-minute ceilings. An unrecorded terminal clock cannot
pass by subtraction or default zero. These are controlled scenario clocks, not
live full-profile/owned-tree cleanup qualification; final test disposal is timed
separately by each owning invocation. The evidence records the draft calculation
correction without altering any raw observation or rerunning cases.

The sampled process includes deterministic build/module compilation and the test
driver. It does not measure an aggregate delivered-app child tree or establish
three clean full-profile/live runs. This measurement boundary is explicit; it is
not an environmental explanation or a budget waiver. Root owns a fresh bounded
memory/timing correction and qualification task at the #138 generated-app seam, with
#158/#161 retaining the exact workload, failed measurements and unresolved live
measurement boundary. No broad memory repair was attempted here.

## Synthetic filesystem-negative check

**F158-3 — unchanged affected retry passed.** `AzureValidationAdmission.Tests.ps1` failed in
454 ms while creating its synthetic directory under the Windows Public directory,
before the product's public-path rejection could execute. The source test creates
only a synthetic privacy marker there and later verifies that admission rejects
the destination without rendering anything. The managed sandbox denied that
directory creation. This failed full-run entry remains retained. After the full
suite, the explicitly authorized bounded filesystem-negative escalation executed
this unchanged test with resolved-target and owned-cleanup checks.

The unchanged affected retry subsequently **passed** under the explicitly
authorized filesystem-negative escalation, with pre-existing-target refusal and
verified absence of every new owned public/temp fixture. See
[separate retry evidence](issue-158-filesystem-retry.json). This resolves that
fixture execution boundary without relabeling the failed full-run entry.

## Device Readiness owning-slice failure

**F158-4 — Device Readiness public-output marker assertion.**
`DeviceReadinessApplication.Tests.ps1` failed in 10,425 ms with
`Restricted synthetic device-identifying values entered public progress or validation output.`
All preceding assertions in that unchanged test passed: Complete/0, canonical
admission, report/package verification, Completion Summary consistency and owned
validation-root absence. Its final regex rejects manufacturer/model/processor
markers and the words matching product-key, entitlement or purchase patterns.
The full-run log retained the failure without the matching property. The separate
minimized reproduction below establishes the precise public guidance match.
Neither the failed assertion nor required privacy validation is waived.

The [minimized affected reproduction](issue-158-readiness-failure.json) also failed
the same assertion after application exit 0, no stderr and verified cleanup.
Its only matches were the entitlement word in
`/plan/softwareInventory/recommendations/0/caution` and `/1/caution`, the released
public guidance cautions. No manufacturer/model/processor marker matched. This
narrows the owner to #151 guidance integration with the #140 privacy assertion;
it does not establish a device-identifier disclosure. Preserve meaningful privacy
checks when root corrects the assertion integration.

## Effective Policy owning-slice failure

**F158-5 — Effective Policy DeniedSystem finding mismatch.**
`EffectivePolicyApplication.Tests.ps1` failed in 88,815 ms at the seventh of 44
declared cases. Its `DeniedSystem` case expected `securityControlFinding` to be
Informational, but the generated sanitized projection reported Indeterminate.
The first six cases completed all their assertions; this seventh case passed
its earlier terminal/coverage assertions before the mismatch. No correct finding
is invented by this record. Root must reconcile the approved missing-SYSTEM
semantics and owning expected/projection/rule behavior in a fresh bounded #142/
#143 correction, coordinating #154 qualification. No product or expectation edit
was made here. The remaining 37 cases subsequently passed serially through the
existing Scenario parameter, with separate exact evidence and all failures
preserved; no earlier pass or failed full-gate entry was overwritten.

## Microsoft Connectivity owning-slice failure

**F158-6 — native HTTP certificate-rejection state mismatch.**
`MicrosoftConnectivityNative.Tests.ps1` failed in 4,405 ms. At the existing owned
synthetic TLS loopback server, the production HTTP phase returned
TlsAuthenticationFailed; the unchanged test expected Failed. The preceding TLS
phase rejection assertions completed. The HTTP server's finally disposal executed,
but later transport/proxy assertions and subsequent static-proxy, local DNS and
local TCP blocks were not reached in this file. They are unqualified here, not
silently passed. Root owns a fresh bounded #150 HTTP typed-state/test correction,
coordinating #154 source qualification. This source/expectation mismatch is not
classified as environment and no owning test assertion is removed or bypassed.

## #158 sampler correction boundary

**F158-7 — #158 disk-sampling race.** `ReadinessSourceApplication.Tests.ps1`
failed in 207,265 ms at Virtual, the ninth of 15 declared cases. The new
`Measure-QualificationWorkload` in `StatusDeskEngine.Tests.ps1` called recursive
Get-ChildItem while the application removed its owned run workspace. Enumeration
threw DirectoryNotFound (`Could not find a part of the path`), aborting the test.
The preceding eight source cases passed; the six following cases were initially
unreached and subsequently passed on the same inputs.
This is an instrumentation defect owned by #158, not a readiness product failure
or an environmental exception. After sealing the failed full-run evidence, the
sampler regression reproduced the directory-removal failure. The narrow correction
catches only directory/file/item-not-found exceptions, preserves the prior maximum
and increments `workspaceSamplingLosses`. Deterministic regression checks all three
loss types and verifies that access denial still propagates. GREEN passed.
The correction checkpoint and complete affected results are recorded separately
in [the correction evidence](issue-158-harness-correction.json). Changed harness
inputs prevent reuse of the original full gate as current qualification. Root
still needs a justified final gate after the other owning fixes.

At `621f95f`, the harness regression passed in **1.649 seconds** and the complete
15-case readiness source file passed in **346.138 seconds**, finishing at
`2026-09-07T05:17:26.4717847Z`. All case assertions and owned cleanup passed.
The readiness run recorded zero sampling losses; the deterministic regression
separately exercised all three loss types. All 643 tested input identities, four
environment binaries and the entire candidate inventory remained unchanged during
this affected execution. All 15 readiness cases still exceeded the working-set
limit, independently recorded as quality Fail. F158-7 is corrected with passing
affected behavior; current full qualification remains Blocked / NotStarted.

## Preparation-plan owning-slice failure

**F158-8 — generated preparation plan disagrees with its frozen policy const.**
`SchemaContracts.Tests.ps1` failed in 6,931 ms while validating the generated plan
against `schemas/preparation-plan.schema.json`, at `/microsoftConnectivity`.
The schema's const has only findingKind/definitionId on each recommendation; the
current release policy adds authoritativeReferences, caution, prerequisites,
purpose, responsibleRole and verification to both recommendations. These twelve
property-presence differences were confirmed by a read-only structural comparison.
The policy metadata was introduced by #151 commit
`3055d2ddc8bf725fe3fc1ed9b5491fcfc963f909`.
This is the actual generated plan, not merely a hand-authored fixture. Later
immutable-plan mutations and the other network-behavior iteration were not reached.
Root owns a fresh bounded #151 guidance-metadata integration correction across the
#150 policy and #136 preparation-plan schema seam. Preserve the guidance fields
and immutable authority; do not remove metadata or loosen the plan as a waiver.
No source/schema repair is made in #158 for this owning-slice failure.

## GUI precedence owning-slice failure

**F158-9 — GUI Integrity-precedence expectation mismatch.**
`StatusDeskActiveActions.Tests.ps1` failed in 132,245 ms after all six actual
synthetic WPF Cancel/Close cases completed their assertions. The subsequent
`-Wpf -FailureKind Integrity` case expected IntegrityFailed but the GUI reported
NotStarted (`GUI displays the authoritative failure precedence`). The later
Cleanup-precedence case was initially unreached and subsequently passed separately
through its existing generated-case command. Root owns a fresh bounded #138 GUI fault-stage/
terminal-precedence correction, coordinated with #154's pre-start/post-start
failure semantics. The fault's actual execution stage must be established; this
record neither relabels NotStarted nor changes the expected terminal. No product
or owning assertion was changed by #158.

## Recovery qualification boundary

**F158-10 — recovery process observation unavailable.**
`StatusDeskRecovery.Tests.ps1` failed in 8,197 ms with Access denied. The owning
test observes only descendants of its exact controlled child through Win32_Process
before opening process handles and interrupting the app. The full log did not retain
the exact failing statement. A bounded read-only query for only the worker tool's
own PID in the same managed sandbox independently failed with CimException,
`HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand`.
That is evidence of unavailable CIM observation in this execution context, not
proof that product recovery succeeds or proof of the full failure's exact stage.
Recovery assertions remain unqualified. Root owns a fresh bounded #138 recovery
qualification context that can establish exact child ownership, interruption,
absence and cleanup. No broad process query, elevation, trace or private operation
was used to bypass the boundary. The original failed full-run entry remains Fail.

## Review and delivery boundary

Implement, TDD and Code Review skills were invoked. The supplied exact fixed point
resolves; root will receive the verified nonempty three-dot diff and complete DCO
commit inventory at the final documentation checkpoint:

```text
git diff e742e92daccd87b04e1572fe0b9926199996864f...HEAD
git log e742e92daccd87b04e1572fe0b9926199996864f..HEAD --format=full
```

Assigned spec: complete supplied #158 body/comments, with normative #134/#37 and
current #160/#161 snapshots. Standards: original-checkout AGENTS.md, CONTEXT.md,
docs/agents/{issue-tracker,triage-labels,domain}.md; integration CONTRIBUTING.md and
.sandcastle/CODING_STANDARDS.md; Code Review's twelve smell heuristics. No relevant
ADR exists. Existing GUI/certificate/seam decisions were retained.

**Standards: Pending. Spec: Pending.** Root launches two fresh independent CLI
contexts on the same frozen final HEAD. No nested reviewer, exploratory agent,
parallel implementation lane or model change was used. Local DCO Git metadata
writes used the explicitly authorized bounded sandbox escalation. Root owns all
GitHub changes, push, PR, merge, closure, signing/private preparation and delivery.
No private #160 artifact/key/profile/trust access or mutation occurred.

Root's remaining bounded work is F158-1 (#147 contract integration), F158-2
(#138 memory/timing and measurement qualification), F158-4 (#151/#140 public
guidance/privacy assertion), F158-5 (#142/#143 DeniedSystem semantics), F158-6
(#150 HTTP typed state), F158-8 (#151/#150/#136 plan-schema agreement), F158-9
(#138/#154 GUI fault stage) and F158-10 (#138 recovery observation/qualification).
F158-3 has a passing unchanged affected retry; F158-7 has the committed correction
and passing affected checks above. The observer's OBS-158-1/2 and all unperformed
live/public requirements remain pending. These are concrete correction and
qualification boundaries, not authorization to close #154/#158 or the parents.
