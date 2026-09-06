# #179 report composability checkpoint

The retained maximum inventory and the controlled generated **Comprehensive**
assessment now deliver verified protected reports within the unchanged **262,144
byte** report bound. This is an implementation checkpoint awaiting both fresh
independent review axes, not issue closure or live acceptance.

## Exact source and candidate

- Starting/review revision: `1aa9d3882be07c354c21b1ffe1fbacef69098ad6`.
- DCO implementation: `8f7cbe6250418586f4f946b190debf03b35db545`.
- Generated `WIN-PCInfo.ps1`: **3,221,099 bytes**; SHA-256
  `b42309abb78df5fe2bddbecc4832d372d2889bc1d24e9a52b5ef0073dbe3ba09`.
- Controller: installed PowerShell **7.6.5 x64**. The existing declared isolated
  Windows PowerShell 5.1 software worker remains unchanged.
- Native blocker #137 is closed. No issue, dependency, PR, parent specification,
  private #160 artifact, signing/trust setting or remote resource was changed.

## Repair and retained evidence

Software tables share only explicit source/context/view/type metadata. Every
registration remains a separate row; identity, name, publisher and arbitrary
provider version values are never coalesced. Column namespaces and captions
preserve field meaning and state. An identical Unrecognized/catalog annotation
can be explicitly inherited by every row in its table; other recognition outcomes
retain their individual explanation and provenance. The canonical record retains
every annotation. The pre-existing projection boundary is unchanged: MSIX full
package names remain in the canonical record, with family identities in HTML.

Security evidence uses a compact table with exact observation/field references
and links to shared source/context tuples. Subject, source, execution context,
collection time and locale remain resolvable without scripting. Migration-detail
links replace duplicated overview prose; equal title/purpose text appears once.
Only optional HTML end tags are omitted at allowed following elements. Text and
attribute escaping remain distinct, and no scripts or external assets were added.
Collection authority, canonical evidence, rules, cryptography, archive/schema/
digest admission and report/export limits are unchanged.

The existing RED evidence in
[the #146 checkpoint](issue-146-software-source-flow.md) remains historical:
305,581-byte HTML and generated exit 50 / `DEVICE_READINESS.REPORT_FAILED`.
The relevant renderer, source fixture and contract test are identical between
that checkpoint's source `37b8608` and this ticket's starting revision, verified
by an empty fixed-revision diff. Unchanged baseline execution was not duplicated.
Intermediate larger Comprehensive renders also failed safely during this repair;
only the final successful outputs below qualify the positive cases.

## Focused validation

Commands use the installed `pwsh -NoLogo -NoProfile -File` and these test paths.
The new application test drives the ordinary generated Status desk with controlled
sources, including the retained AggregateMaximum software fixture. Production
canonical validation, interpretation, rendering, protection, reopening, deliberate
export and viewing cleanup remain in the path. The distinct variant changes all
admitted names, versions and publishers to distinct maximum-byte-length strings
containing Unicode and HTML-sensitive characters; it does not reduce field bounds.

| Check | Outcome |
| --- | --- |
| `SoftwareReportApplication.Tests.ps1`: Maximum | **Pass**; full Comprehensive HTML **259,499 bytes**, 128 rows, eight Complete software scopes, 128 Unrecognized annotations; protected reopening, named-field comparison, source/context links, deliberate export and viewing cleanup pass |
| Same test: Distinct | **Pass**; full Comprehensive HTML **261,963 bytes**; exact Unicode, quote, ampersand, angle-bracket and arbitrary version values survive their named columns and source metadata through reopening/export |
| Same test: EscapedOverflow | **Pass as refusal**, not delivery; record-valid evidence exceeds the separate rendered-output bound; exit 50 / IntegrityFailed / `DEVICE_READINESS.REPORT_FAILED`, no exposed package, owned cleanup verified |
| `SoftwareInventoryContract.Tests.ps1` | **Pass**, including the unchanged retained maximum contract assertion |
| `SoftwareInventory.Tests.ps1` | **Pass**, source identities, contexts, payload bounds and privacy |
| `StatusDeskEngine.Tests.ps1` with Software Complete + Security Active | **Pass**, generated controlled native sources, duplicate registrations, MSI contexts, package types, recognition, protected report and viewing cleanup |
| Same test with Software DeniedUser + Security Denied | **Pass**, explicit denied coverage and unrelated useful evidence survive |
| `SoftwareRecognitionApplication.Tests.ps1` | **Pass**, known/unknown recognition, logical failure isolation and tampered-catalog refusal |
| `ComprehensiveReportApplication.Tests.ps1` | **Pass**, four generated report-contract scenarios |
| `ComprehensiveReport.Tests.ps1` | **Pass**, deterministic output, five culture/Unicode fixtures and report stress bound |
| `CrossDomainGuidance.Tests.ps1` | **Pass**, advisory findings, recommendations, discovery tasks and relationships |
| `ProtectedPackageNegative.Tests.ps1` | **Pass**, frozen bounds, historical admission and corruption/schema/digest failures |
| `RestrictedReportExport.Tests.ps1` | **Pass**, deliberate warning, restricted designation and failure cleanup |
| `ProtectedPackageViewing.Tests.ps1` | **Pass**, requested-artifact isolation, close and recovery ownership |
| Changed PowerShell parser checks; `git diff --check` | **Pass** |

The maximum positives do not promise that every record-valid combination fits the
independent rendered-output bound. The distinct case has only 181 bytes of report
headroom; larger escaped combinations must still refuse rather than truncate.

Browser visual inspection was **blocked by the browser's local-file URL policy**.
No alternate URL, server, browser or other workaround was used. The test-owned
synthetic preview was removed and absence checked. The browser tab was closed.
Real HTML/GUI usability, printing and full live acceptance remain #161 obligations.
No synthetic report, package or source identifiers were committed.

## Review and next owners

CodeReview was invoked with the supplied fixed point. Both axes are **pending**,
not passed, under the documented root-dispatch recovery for retained nested slots.

- Diff: `git diff 1aa9d3882be07c354c21b1ffe1fbacef69098ad6...HEAD`.
- Commits: `git log 1aa9d3882be07c354c21b1ffe1fbacef69098ad6..HEAD --oneline`.
- Spec: current #179 with #134/#37/#158 context.
- Standards: original-checkout `AGENTS.md`, agent/domain instructions and
  `CONTEXT.md`; integration `CONTRIBUTING.md`, `.sandcastle/CODING_STANDARDS.md`,
  plus the CodeReview skill's complete smell baseline. No relevant ADR exists.

Root dispatches fresh Standards and Spec reviews separately, then records the
affected #146 maximum acceptance refresh on this candidate before any closure.
The source-flow outcomes from #146 remain revision-scoped historical evidence;
they are not silently upgraded into live validation. Full integrated regression
is reserved for #158/final under the explicit testing-cadence override. #145's
incomplete WinRM fields and #138's historical working-set excess remain unwaived.
#160 stays frozen and untouched; #161 owns the actual private acceptance session.
