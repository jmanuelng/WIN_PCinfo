# Issue 151: full report evidence and consulting next steps

September 6, 2026. Automated implementation evidence only. Original issue:
<https://github.com/jmanuelng/WIN_PCinfo/issues/151>, with inherited #134/#37
requirements and #158 allocation. Implementation used the existing report,
canonical record, generated worker and protected-package seams.

## Source and candidate

- Dispatch / Code Review fixed point: `4c312346e2ecdba18d0853ea1f867a8a40d10e88`.
- DCO implementation commit: `3055d2ddc8bf725fe3fc1ed9b5491fcfc963f909`.
- Unsigned generated `artifacts/WIN-PCInfo.ps1`: **3,283,991 bytes**,
  SHA-256 `1adeaee5bac8a1c037bcf5628469bec81bf40b9c3e807de633592442e079ac78`.
- Two consecutive `build/Build.ps1` runs produced that identical script digest.
- Build-reported portable ZIP identity:
  `25ba2c60458da9142e03d6cbea405adc403db74925e7d161043e406ec263c3e7`.
- Build-reported source-input identity:
  `64af446777216a2d16a8dd364745786b729a252d78d0ee6bacd48e12a6563aaa`.

Candidate identities are unsigned build identities, not signing, trust, release
qualification or renewed private #160 evidence. The historical #145 candidate
does not identify these changed bytes.

## Change and red/green evidence

The report identifies the selected canonical evidence profile and every admitted
scope's state/reason. Outcome, completeness, limitations and priorities precede
detail. Source-reported unknown, observed absence and uncollected device fields
retain different presentation. The white/light-gray/blue palette follows the
existing Status desk constants.

Complete portable recommendation metadata is required by the resource, network,
software, certificate and connectivity definition schemas. Existing cross-domain
definitions already supplied that contract. Reports retain prerequisites,
cautions, owner, verification and authoritative Microsoft references. Repeated
definitions and references share display text without losing recommendation
instances. Cross-domain sources and typed From/To relationships have internal
destinations. Tenant tasks remain separate from observed local facts.

Canonical-order `fN` / `rN` anchors link findings to their family evidence and
recommendations to their full guidance. The zero-based mapping is disclosed in
the report. Security tables disclose shared field/observation prefixes and the
exact run suffix; tests reconstruct full canonical IDs and compare every field,
value, source, subject, execution context, timestamp and locale. The compact
representation does not truncate mandatory evidence or raise a bound.

Original reports identify their renderer, language and SHA-256 input fingerprint
(record plus exact definitions). Explicit ReRendered / ReEvaluated rendering
requires the source-report digest. Original-with-source and derived-without-source
combinations refuse. Rendering leaves the protected original and input record
unchanged; downstream export/re-evaluation workflows retain their existing owners.

Observed RED cases included the unresolved Next steps destination, absent
prerequisite metadata, unresolved generated recommendation destinations, missing
explicit derivation inputs, unnamed incomplete scopes, a denied-profile tenant
task destination, and SourceReportedUnknown collapsed into generic unavailability.
The retained tests now pass. Intermediate full report sizes of 273,766 through
263,743 bytes were actual failures: the generated application refused delivery
with `IntegrityFailed`, exit 50 and `DEVICE_READINESS.REPORT_FAILED`. They are
historical failed compositions, not final bound results.

## Focused validation

Commands used the installed PowerShell 7.6.5 x64 executable with
`-NoLogo -NoProfile -File`. Generated assessment tests ran serially, with controlled
synthetic sources and protected reopening. Each listed test exited 0.

| Command under `tests/` | Result and evidence |
| --- | --- |
| `FullReportApplication.Tests.ps1` | PASS, AcceptedElevation and ElevationDenied; actual Comprehensive reopened recommendation metadata, all admitted scopes, every canonical finding/recommendation destination, and source-report provenance. |
| `ComprehensiveReportApplication.Tests.ps1` | PASS, existing outbound, Local Only, Unicode and redirected-storage workflows through the generated application. |
| `SoftwareReportApplication.Tests.ps1` | PASS, Maximum **258,910 B**; Distinct **261,374 B**, **770 B** below unchanged **262,144 B** cap; EscapedOverflow safely refused with verified owned cleanup. Both positive cases preserve all **128** software registrations and security source/context values through protected reopening and deliberate export. |
| `RemoteSourceApplication.Tests.ps1 -Scenario Configured` | PASS, affected update/remote/auth evidence references; generated run elapsed **22.4 s**. |
| `SoftwareInventoryContract.Tests.ps1` | PASS, resource/network/software canonical evidence and source identities. |
| `RecommendationDefinitions.Tests.ps1` | PASS, exact definitions validate; deleting each required consulting metadata field fails the schema. |
| `ComprehensiveReport.Tests.ps1` | PASS, six terminal outcomes, UTF-8/Unicode fixtures, repeated bytes, bounded stress, admitted scopes, source-reported unknown and invalid derivation combinations. |
| `CrossDomainGuidance.Tests.ps1` | PASS, existing cross-domain rule and recommendation relationships. |
| Changed PowerShell file parsing; `git diff --check` | PASS. |
| `build/Build.ps1`, twice | PASS, identical unsigned script bytes and digest above. |

The reopened Comprehensive check changes both CurrentCulture and CurrentUICulture
to en-US, es-MX, tr-TR, ja-JP and ar-SA and compares identical bytes for identical
canonical inputs. It also checks scripting-free internal navigation, keyboard
structure, print rules and UTF-8. This is actual renderer culture execution,
not a claim of collection on five real localized Windows installations.

The final fallback-only text correction makes an absent priority's confidence
Unspecified. Pure renderer negatives and the Configured generated case ran after
that correction; the final maximum case was refreshed against the committed
source. It does not change output for the populated priority cases above.

## Artifact disposition and pending owners

Generated test workers complete before cleanup. The existing harness validates
each resolved synthetic root is below this worktree's `.test-output` directory,
closes viewing and export boundaries, and removes only its owned root. Overflow
asserts verified terminal cleanup. Temporary byte-measurement helpers were removed
after checking their literal paths inside the assigned worktree. Generated script,
build evidence and portable ZIP remain ignored local build artifacts; no real
device record, HTML, key, certificate identity or operational screenshot was added
to source. No live assessment, UAC, signing/trust mutation, cloud operation or new
dependency acquisition was performed.

Final inspection found no `.test-output/status-desk-*` directory. Other existing
test-output directories were preserved. The final maximum refresh retained the
exact candidate digest above.

**#158 pending:** the integrated full repository gate and exact private acceptance
candidate. Focused ticket cadence follows the user's explicit override; this
note does not claim the complete suite ran. Historical #138 working-set pressure
(662–755 MiB against the provisional 512 MiB bound) remains an inherited
measurement/diagnosis gate, not an accepted exception.

**#161 pending:** real generated-report usefulness and complete private acceptance,
including actual Edge offline operation, no-script keyboard interaction, visible
white/light-gray/blue consistency, opening details and evidence links, printing
all relevant detail without clipped tables, and consulting usefulness. Static
structure and fixture passes establish none of those human judgments. #160 and
#162–164 retain their existing live authority/signing/publication boundaries.

## Code Review handoff

Implement, TDD and Code Review skills were invoked. The fixed point resolves and
`git diff 4c312346e2ecdba18d0853ea1f867a8a40d10e88...HEAD` is nonempty.
`git log 4c312346e2ecdba18d0853ea1f867a8a40d10e88..HEAD --oneline`
identifies the DCO implementation and this evidence commit.

- **Standards: pending** fresh independent root dispatch.
- **Spec: pending** fresh independent root dispatch.

Root dispatches the two fresh axes sequentially after this worker returns, per the
documented retained-slot recovery instruction. No prior review is reused and no
independent review success is claimed here. Standards sources: original checkout
`AGENTS.md`, `CONTEXT.md`, `docs/agents/issue-tracker.md`,
`docs/agents/triage-labels.md`, `docs/agents/domain.md`; integration
`.sandcastle/CODING_STANDARDS.md` and `CONTRIBUTING.md`; Code Review's complete smell
baseline. No `docs/adr` directory was present. Spec source is the current full
#151 issue snapshot supplied at dispatch, plus relevant #134/#37/#158 snapshots
in the orchestration worktree. Root owns review aggregation, shared requirement
register updates, GitHub delivery and closure.
