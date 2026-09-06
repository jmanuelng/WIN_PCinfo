# #154 package admission checkpoint — partial implementation

Specification: [#154](https://github.com/jmanuelng/WIN_PCinfo/issues/154), inheriting
[#134](https://github.com/jmanuelng/WIN_PCinfo/issues/134) and
[#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37).
This is a bounded repair and acceptance audit checkpoint. **#154 remains open.**
It does not qualify the entire evidence-contract and package-safety requirement.

Starting revision / Code Review fixed point:
`82f3990dcf309695b954dcfe0837857b3864537c`.
Implementation and regression source:
`0d8aed50f57b9aad9b31195a7781b8d46781180e` (DCO signed).

## Confirmed defect and correction

An authenticated ZIP with an `ASSESSMENT-REPORT.HTML` entry was accepted as the
release-declared `assessment-report.html` artifact. The regression first failed
with expected `IntegrityFailed`, actual `Verified`. Windows filesystem name
comparison must not silently normalize the closed archive graph.

`ProtectedPackage.ps1` now checks artifact names and locates ZIP entries using
case-sensitive comparisons. Unknown casing fails before final naming or viewing;
the cryptographic implementation and frozen package bounds are unchanged.
The new exported-boundary regression proves canonical finalization still works,
case-aliased input creates no provisional or final package, and aliases of all
three ZIP entries expose no artifacts or viewing workspace. Authenticated
duplicate manifest properties were also checked and already failed closed;
they required no production repair. Failed admission preserves the existing
canonical package. The regression uses only synthetic record/report bytes.

## Exact candidate and affected validation

Validation date: September 6, 2026. Installed runtime: PowerShell Core 7.6.5 X64.
Generated unsigned application: 3,305,322 bytes, SHA-256
`03b56dd606dd443e200f24c1504598274f2e54f5619022eaf0c2ac13a94a0956`.
The two independent deterministic builds produced that same digest. Build
provenance verification passed against the committed implementation bytes.

Commands: `pwsh -NoLogo -NoProfile -File tests/<name>.Tests.ps1`, using the
installed PowerShell 7 executable and shared test harness. The focused checks
ran sequentially; no source edits occurred during these checks.

| Check | Observed result | Seconds |
| --- | --- | ---: |
| ProtectedPackageAdmission | Pass: canonical positive, pre-final-name alias rejection, three authenticated entry aliases and duplicate manifest refused before viewing | 1.29 |
| ProtectedPackageContracts | Pass: emitted envelope/manifest schema contracts | 0.11 |
| ProtectedPackage | Pass: known answer, fresh keys, DPAPI reopen, deterministic inner bytes and ciphertext-only persistence | 0.36 |
| ProtectedPackageNegative | Pass: maximum bounds, unique nonces, wrong contexts, corruption/truncation, archive/manifest/digest failures | 2.46 |
| ProtectedPackageViewing | Pass: restricted view, verified close/recovery ownership and refusal before content exposure | 0.59 |
| ProtectedPackageWriteFailure | Pass: owned incomplete-write rollback and preservation of verified packages | 0.58 |
| ProtectedPackageApplication | Pass: all ten generated application scenarios, matching terminal/exit, sanitized output and verified absence of scenario residue | 39.48 |
| BuildDeterminism | Pass: exact reproducible candidate and source provenance | 48.50 |

The new unique test directory was removed after validating its resolved parent.
Package/view/write-failure checks cleaned their owned resources; generated
application fixtures verified no added validation residue. Ignored generated
application and deterministic-build files remain local. No real assessment,
UAC, signing, trust change, installed key change, external publication, dependency
acquisition, cloud operation or private #160 artifact modification occurred.

## Remaining #154 acceptance work

This is an incomplete audit, not evidence that every unreviewed behavior is
defective. Existing tests and historical validation retain their actual value;
their results are not promoted to exact-current full application qualification.

| Requirement | Existing evidence / remaining work |
| --- | --- |
| Exact structural validator and semantic contracts | `AssessmentContractSet.Tests.ps1` has two `prefixItems` dialect probes; `ContractValidator.Tests.ps1` and `ContractSemanticMatrix.Tests.ps1` cover wire and semantic negatives. #37 requires: “Qualify the exact structural validator against applicable official Draft 2020-12 tests.” Applicability and sufficient coverage of the actual release schema keywords still need an explicit qualification audit. A whole upstream corpus or new acquisition is not prescribed by this checkpoint. These unchanged matrices were not rerun here. |
| Each applicable closed state for every selected Evidence Scope | Existing collector/scenario and lifecycle tests provide substantial state coverage. The scope-by-scope applicability/outcome inventory remains unfinished. Record justified NotApplicable cases rather than requiring an artificial full Cartesian product, and preserve observation value, finding outcome, diagnostic and terminal distinctions. |
| Crypto and protector boundaries | The checks above refresh known answer, fresh keys, nonce uniqueness, DPAPI and existing negative evidence. Explicit associated-data mutation and chunk-order/finalization coverage still need a focused audit; no claim is made that they are absent or faulty in production. Recipient RSA/software/hardware contracts are covered by existing recipient tests but were not rerun in this checkpoint. |
| Invalid/incompatible/bounded/interrupted packages before final naming or viewing | Confirmed alias defect repaired and affected checks passed. Existing version, record, corruption, bound and recovery cases must still be mapped to the complete #154 acceptance requirement; this narrow fix is not that complete mapping. |
| Marker-only exclusion, public safety, cleanup and five cultures | Current generated package checks verify sanitized output and cleanup. Existing contract/collector marker tests and `ReportContractAssertions.ps1` contain relevant exclusion and all-five-culture evidence. The complete applicable input/output and retention audit remains pending; those unchanged matrices were not duplicated here. |

The exact-candidate integrated suite is **NotRun**, reserved for #158/final by
the user's testing-cadence override. Real wrong-user/device, recipient hardware
and software, non-English Windows and delivered-GUI acceptance remain named
#161/#162 session work; fixture passes cannot satisfy those live requirements.
Inherited #138 memory-budget and #152 sticky cleanup requirements remain intact.

## Independent reviews and next owner

Code Review invoked. Fixed point resolves; the three-dot diff is nonempty and
the implementation commit is traceable to #154. **Standards: Pending. Spec:
Pending.** Root dispatches both fresh axes sequentially under the established
review-slot handoff; prior-ticket review results are not reused.

Review command:
`git diff 82f3990dcf309695b954dcfe0837857b3864537c...HEAD`.
Commit inventory:
`git log 82f3990dcf309695b954dcfe0837857b3864537c..HEAD --oneline`.
Standards sources are the original checkout's `AGENTS.md`, `CONTEXT.md` and
`docs/agents/` instructions, plus this integration checkout's `CONTRIBUTING.md`
and `.sandcastle/CODING_STANDARDS.md`, and the Code Review skill's smell baseline.

Next: root obtains both required reviews of this bounded repair, records the
partial delivery disposition without closing #154, and retains the unfinished
acceptance audit as the #154/#158 gate. No requirement-register, issue, push,
pull-request, merge or closure operation was performed by this worker.

## Independent bounded review outcome

Fresh Standards and Spec reviewed82f3990dcf309695b954dcfe0837857b3864537c throughca03cf01e244c7bfea5d53eec19c036497146eab:3files+198/-6,both DCO commits. Standards:0hardfindings/0actionablesmelljudgments. Spec:0actionablefindings for the bounded repair; exact-case admission and retained regression correctly reject invalid packages before final naming/viewing. Both axes reviewed recorded evidence read-only without rerunning tests.

Full #154 remains incomplete for the qualification/applicability and acceptance mappings above. The repair is reviewed/tested/committed in batch, not yet merged. Do not close #154, unblock #158 by closure, or infer live acceptance. Root owns delivery and fresh-context continuation of the unfinished qualification.
