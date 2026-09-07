# Spec #134 paused checkpoint

The user requested finishing the active work, saving it, and stopping until next weekend. No new ticket, product repair, signing or live session was started after that instruction. The active #158 work completed its original full run, bounded diagnostics and a same-ticket sampler correction.

Implementation checkpoint: `5b22b1112955fe0a5e5087633f056438cbc3b07e`.
Review fixed point: `e742e92daccd87b04e1572fe0b9926199996864f`.

- Full suite at `c5d7e9ad1dbdc3857c9eb55ae51e414bbe6aa6f7`: 184 files executed, 175 passed, 9 failed; 11,634.677 seconds. This remains a failed historical gate.
- Corrected sampler at `621f95f3fa65004a62252e4f4edb350dcb505d45`: regression and all 15 readiness cases passed, with independent quality failures retained. No whole-suite pass is claimed for corrected inputs.
- [The integrated checkpoint](issue-158-integrated-checkpoint.md) contains exact failed gates, separate follow-up evidence, measurement boundaries and remaining corrections. The [requirement register](issue-158-requirement-register.json) has 309 rows; the [session packet](issue-161-session-packet.md) preserves all unperformed live checks.
- The generated unsigned primary remains 3,319,490 bytes, SHA-256 `262f069f9d228c1636f84165846b9996bf257993f0900f423e9154166467a86e`.

## Independent Code Review

Both axes used genuinely fresh, read-only conversations against the same frozen implementation checkpoint. The previously reviewed unchanged #154 baseline was not reviewed again. This final review status supersedes the Pending statuses in the implementation handoff. Reports below are lightly normalized to repository-relative paths; no findings are removed or combined.

## Standards

**STANDARDS: 1 documented violation; 0 judgment-call smells.**

Verified branch `codex/spec134-afk-batch`, clean tree, and unchanged frozen HEAD through review completion:

- Fixed point: `e742e92daccd87b04e1572fe0b9926199996864f`
- HEAD: `5b22b1112955fe0a5e5087633f056438cbc3b07e`
- Nonempty three-dot diff: **19 files, +298240/−6**
- Exactly **3 commits**, matching inventory: `c5d7e9a`, `621f95f`, `5b22b11`; all contain DCO sign-offs.

**[P2] Evidence collection can bypass mandatory test cleanup.** In [StatusDeskEngine.Tests.ps1:788](tests/StatusDeskEngine.Tests.ps1:788), the added `Measure-QualificationWorkload` and subsequent evidence write execute inside `finally`, before cancellation, lock release, disposal and workspace cleanup. A persistent access-denied sampling error or failed evidence write exits that block before cleanup. The new regression explicitly verifies access denial propagates, but does not exercise cleanup afterward. The added copies in [AssessmentSafetyQualification.Tests.ps1:18](tests/AssessmentSafetyQualification.Tests.ps1:18) and [OfficialSchemaQualification.Tests.ps1:21](tests/OfficialSchemaQualification.Tests.ps1:21) have the same ordering.

Rule: the supplied worker authority and workflow (line 15): “Do not weaken original scope, trust, privacy, ownership, cleanup or honest coverage.” #158 additionally requires failure handling to “remove only verified owned transient resources.” A future correction should guarantee cleanup independently of evidence-retention failures while preserving the failed result.

Evidence projections reconcile: **309 unique requirement rows**, **344 cases: 343 Pass/1 Fail**, **676 passing scope witnesses**, and **611 justified NotApplicable pairs**. All **643 corrected input hashes** match current files; inspected evidence references resolve.

This remains a truthful saved checkpoint, **not qualification or closure**. The full gate is **184 files / 175 Pass / 9 Fail**; later sampler/readiness passes retain quality failures. No full gate ran on corrected inputs. The deadline was missed; merge, #154/#158 closure, independent gates and unperformed human/live acceptance remain blocked or pending. Root owns delivery. No edits, tests, private-artifact access or external operations were performed; no repairs were started.

## Spec

**SPEC: 1 new checkpoint defect; 0 scope-creep findings.**

**[P2] Evidence retention can bypass owned cleanup.** In [StatusDeskEngine.Tests.ps1:788](tests/StatusDeskEngine.Tests.ps1:788), the new `finally` block samples resources and writes evidence before releasing locks, cancelling unfinished work, and removing the owned workspace. A sampler access-denial or evidence-write failure exits that block before cleanup; the suite then catches the failure and continues. The regression explicitly preserves access-denial propagation but does not verify cleanup afterward. #158 requires: “On failure, stop new scheduling … and remove only verified owned transient resources.” Cleanup needs an unconditional enclosing `finally`, while retaining the original failure. This is a #158 harness defect, separate from the historical owning-ticket blockers.

Verified branch `codex/spec134-afk-batch`, clean tree, unchanged final HEAD, and fixed point equal to merge-base:

```text
Base: e742e92daccd87b04e1572fe0b9926199996864f
HEAD: 5b22b1112955fe0a5e5087633f056438cbc3b07e
```

The supplied inventory matches exactly: **3 DCO commits**, **19 files**, **+298240/−6**, nonempty three-dot diff:

```text
5b22b1112955fe0a5e5087633f056438cbc3b07e
621f95f3fa65004a62252e4f4edb350dcb505d45
c5d7e9ad1dbdc3857c9eb55ae51e414bbe6aa6f7
```

Evidence consistently retains **184 files executed / 175 Pass / 9 Fail**, overall exit 1; **344 cases / 343 Pass / 1 Fail**; 676 passing scope witnesses and 611 justified inapplicable pairs. All 643 corrected input hashes match. The 309-row register separates historical, current automated, and live statuses. Fifteen corrected readiness cases passed separately; quality remains Fail. The session packet covers eight live checks, controls, families, comparisons, protection and cleanup. Observer blockers remain explicit.

**Suitable for saving as an incomplete checkpoint with this finding recorded; merge does not qualify.** #154/#158 acceptance remains pending: contract/schema inconsistencies, other owning assertion failures, memory/timing overruns, incomplete recovery qualification, and no complete gate at corrected inputs. Signing, observer calibration, actual human acceptance and public gates remain pending. The September 6 handoff was missed.

No tests, mutations, private-artifact access, or nested agents. Root owns delivery and the other independent review axis. No further implementation starts before the user resumes.

Standards: 1 documented violation, 0 smell judgments; worst finding P2. Spec: 1 defect, 0 scope-creep findings; worst finding P2. Both axes independently identified the same cleanup path; they remain separate reports.

## Delivery and resume boundary

This is a saved checkpoint. Unresolved acceptance failures prevent merge and closure of #154 and #158. F158-3 has a passing unchanged filesystem retry; F158-7 has a passing bounded correction. The new review finding is F158-11: evidence failure can bypass mandatory owned cleanup. Remaining F158-1/2/4/5/6/8/9/10/11, OBS-158-1/2 and all unperformed live/public gates remain open. Historical closed-ticket status does not qualify those newly discovered integration failures.

Before this checkpoint, 21 tickets were closed (#135–#153, #165 and #179), through 20 merged PRs (#166–#178 and #180–#186). This paused checkpoint adds no PR or merge. Parent specifications #134 and #37 and native blocking relationships are preserved.

The September 6 EOD cutoff passed without a qualified private handoff: target missed. No acceptance threshold changed. Previously staged private artifacts and their signing approvals remain bound to their exact bytes and held status; no approval transfers to future corrected artifacts. No live assessment, observer trace, cloud validation or publication is claimed.

On explicit user resumption, verify the saved branch/commit and current issues, then use fresh bounded owning contexts for the documented failures. First correct F158-11 in a fresh #158 context before running more generated tests: owned cleanup must execute despite sampling or evidence-retention errors, while the test still fails and unrelated resources remain untouched. Then address contract/catalog and immutable-plan schema coherence, preserving intended fields and guidance. Include directly affected schema/admission checks when versioned definitions change. Diagnose quality and lifecycle boundaries using the retained measurements; refresh affected evidence and required independent/final gates on actual corrected inputs. Keep #154/#158 open until merged changes and closure evidence qualify. Continue the remaining backlog only after resumption. No automatic continuation is scheduled.


