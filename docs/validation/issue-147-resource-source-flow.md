# #147 resource source and report checkpoint

## Focused review corrections

The latest checkpoint corrects the two P2 findings from the fresh #147 Spec
review. The earlier implementation and its evidence below remain historical.
Fresh review of these affected corrections is still pending on both axes.

- Correction starting/review fixed point:
  `9b5deeaff21eeb4759298f8661e4ee1382d6c350`, clean on entry.
- DCO correction: `c613fed3cccea8c0055a6bd9c84f616f5d149f59`.
- Exact generated `WIN-PCInfo.ps1`: **3,236,027 bytes**, SHA-256
  `3d533dd9a4f620a0b8767116db7255d39e8ec794f59991a6e8fb379c4a80b254`.
- Runtime: installed PowerShell **7.6.5 x64**. Generated assessments are
  serialized and use controlled Windows boundaries throughout.

Printer-driver identity now retains the actual local registry name, environment
and driver model through the worker payload, normalization, package-local
subjects, typed observations, canonical validation and HTML. Distinct versions
and INF basenames stay attached to their corresponding registration. Printer
bindings retain the exact reported driver name; a shared name is not treated as
proof of a binding to one specific environment/model registration. The tuple
used by the source is encoded without delimiter ambiguity.

The two added field definitions admit at most 128 UTF-8 bytes for environment
and 32 for the registry driver-model key. Their source properties and frozen
preparation scope are declared explicitly. The eight-registration ceiling,
131,072-byte worker ceiling and 262,144-byte report ceiling are unchanged.
Rule input counts account for the two additional fields per eight registrations:
peripheral inputs change from 88 to 104, and all resource inputs from 192 to 208.
These counts do not admit additional registrations or output bytes.

Mapped-drive correlation now preserves an already-read provider only when the
canonical drive matches and the endpoint is exactly equal using ordinal
comparison. A different endpoint or unavailable provider remains
`SourceReportedUnknown`; the session table still reports its actual endpoint
and makes no reachability claim. No new source, remote query, content read or
device mutation was introduced.

### Test-first and affected checks

The approved seam is the generated Comprehensive assessment with actual resource
source code under controlled identity, registry, native enumeration and CIM
boundaries. Production normalization, canonical validation, interpretation,
HTML, package protection/reopening and owned cleanup execute normally.

- **Driver RED:** three same-name registrations became one subject after
  protected reopening. **GREEN:** all three survive, including x64 Version-3,
  x64 Version-4 with different version/INF, and ARM64 Version-3 sharing the first
  registration's version/INF. Assertions check distinct subjects, exact attached
  values, each HTML observation anchor and Complete driver coverage.
- **Provider RED:** an exact remembered mapping/session match lost its provider,
  yielding `SourceReportedUnknown` instead of `ObservedValue`. **GREEN:** the
  provider survives protected reopening; differing-endpoint and unavailable-
  provider negatives remain unknown and retain the actual session endpoint.
- `ResourceDependencies.Tests.ps1`: Pass for bounded typed payloads, same-
  registration deduplication, Unicode, privacy and source failure isolation.
- `ResourceDependenciesPolicy.Tests.ps1`,
  `ResourceDependenciesNativeSource.Tests.ps1`,
  `ResourceSourceExecution.Tests.ps1`: Pass for closed authority, finite bounds,
  controlled actual-source construction and prohibited-call/context checks.
- `ResourceDependenciesContract.Tests.ps1`: Pass for source/subject/reference/
  coverage/rule/recommendation composition, including the 26-field empty scope
  and maximum partial resource evidence.
- `ContractValidator.Tests.ps1`: Pass for canonical and malformed/Unicode/byte/
  depth/numeric/secret/reference/coverage/graph negatives.
- `ResourceDependenciesApplication.Tests.ps1 -Scenario
  Printers,PortsAndDrivers,Partial,Duplicates,LongUnicode,NonEnglish,Empty`:
  Pass for all seven affected fixture cases plus invalid-fixture refusal.
  The optional test selector preserves the default complete matrix.

`ResourceSourceApplication.Tests.ps1 -Scenario
DriverRegistrations,Complete,ProviderMismatch,ProviderUnavailable` passed on the
exact candidate above; elapsed times were respectively 23.1, 22.6, 22.7 and
23.2 seconds. Earlier RED failures and the initial implementation's broader
matrix are not represented as final-candidate passes. Unchanged unrelated cases
and the full repository suite are not rerun here; full integrated regression
remains #158/final under the user override.

`SoftwareReportApplication.Tests.ps1 -Scenario Maximum,Distinct,EscapedOverflow`
also passed on that exact candidate: **259,400 bytes** for Maximum,
**261,864 bytes** for Distinct (280 bytes below the unchanged ceiling), and safe
refusal with cleanup for EscapedOverflow. All 128 software registrations remain
represented; no shared renderer code, required value or report cap changed.
Changed PowerShell syntax and `git diff --check` passed. These focused checks
refresh the affected evidence without repeating the unchanged full source or
fixture matrices.

### Affected Code Review handoff

Implement, TDD and Code Review were invoked. The fixed point resolves and the
committed correction diff is nonempty:

- `git diff 9b5deeaff21eeb4759298f8661e4ee1382d6c350...HEAD`
- `git log 9b5deeaff21eeb4759298f8661e4ee1382d6c350..HEAD --oneline`
- Spec: full current #147 body/comments, relevant #134/#37 and #158 allocation,
  and the two assigned P2 findings. No unchanged full-diff review is requested.
- Standards: original `AGENTS.md`, agent issue/triage/domain instructions and
  `CONTEXT.md`; integration `CONTRIBUTING.md`, `.sandcastle/CODING_STANDARDS.md`,
  and Code Review's full smell baseline. No relevant ADR directory exists.
- **Standards: pending fresh affected review by root.**
- **Spec: pending fresh affected review by root.**

No nested reviewers were spawned under the documented retained-slot procedure.
The initial fresh Standards result (zero hard violations, one nonblocking unused
test-branch judgment) is not substituted for either pending affected review.
Root owns review dispatch, delivery, GitHub and the requirement register.

Only synthetic inputs and sanitized outcomes are retained. The existing harness
verifies cleanup of its owned test packages/workspaces/viewing artifacts; ignored
generated build outputs stay local. No private #160 artifact, live assessment,
signing key, certificate trust, UAC or cloud state was touched. The private #161
comparisons below remain pending, now including same-name registrations across
environments/models and matching/stale remembered mapping providers. #145 gaps,
#138 memory evidence, full #158 regression and all live acceptance/signing/trust/
release gates remain unwaived. This is a review checkpoint, not ticket closure
or application acceptance.

## Historical initial implementation checkpoint

This checkpoint implements the controlled source-to-report path for locally
observable user resources and peripherals. Both independent review axes remain
pending root dispatch. It establishes no live assessment, packet-capture,
peripheral compatibility or release-acceptance result.

## Revision and candidate

- Starting/review fixed point: `3a0cebca469dcc569302b1a75292fb79f95ab790`;
  the integration worktree was clean at that HEAD.
- DCO implementation: `cea675b4f9977f6dda235abf33c931a7d2766d56` on
  `codex/spec134-afk-batch`.
- Generated `WIN-PCInfo.ps1`: **3,231,996 bytes**, SHA-256
  `e2321bbdb4682b21f3cceb87bd8243d61b3ed512828d9fac0e59941e1e58b8b5`.
- Installed test/controller runtime: PowerShell **7.6.5 x64**. No new runtime,
  dependency, certificate or tool was installed.
- #137 is closed. Root delivered the starting revision through PR #180,
  closing #146/#179 during this implementation. #145 remains independently
  incomplete; its missing WinRM fields were neither repaired nor waived here.

## Repairs and test-first evidence

Executing the original resource source with controlled Windows boundaries
returned **one scope instead of five**. Each scope is now constructed as a
separate command. Existing prepared-payload fixtures had hidden this failure.

The printer source now uses `EnumPrintersW(NULL, LOCAL | CONNECTIONS, level 4)`
and fixed local registry reads. It retains cached network-printer names when
remote details are unavailable, and reads locally configured port/driver binding,
Work Offline configuration, default-printer name and installed driver metadata.
Null fields survive projection as `SourceReportedUnknown`, including in HTML.
Denied default/configuration keys no longer erase successfully enumerated names.
The controlled cached-printer test failed with one/zero names before these
repairs and passes with both expected names afterward.

The resource source uses `NetUseEnum(NULL, level 0)` for SMB session names and
correlates them with read-only initiating-user `Network` definitions. Level zero
excludes credential-bearing structures. Names do not establish connection health;
connection state remains unavailable. DFS/WebDAV session coverage is explicitly
unobserved, and a remembered mapping is not called connected or disconnected.
Peripheral metadata uses the exact native Core CIM module and declared
`Win32_PnPSignedDriver` properties, without a compatibility-host fallback.

The fixed worker uses the existing inline gzip packing pattern to stay within
Windows' command-line limit, rather than staging a mutable script. Time, output,
owned-process cleanup and eight-entry category limits remain in force. The child
receives startup telemetry/update opt-outs. Native libraries are restricted to
System32. No share browsing, UNC probe, print job, device-content or arbitrary
file access was added.

The first generated Comprehensive run then failed at software recognition:
printer-driver subjects legitimately have kind `Application`, but recognition
and canonical annotation validation incorrectly selected *every* such subject.
Both now select only software inventory's `subject:software:<index>` subjects.
The regression keeps actual printer-driver subjects, canonical validation,
recognition, reporting and protection in the same generated assessment.

Resource HTML previously omitted unknown fields and source/subject provenance.
It now retains those fields, observation anchors and the subject/source/context/
time/locale tuple. Exact printer-to-driver names remain typed observations,
scoped findings remain advisory, and migration recommendations survive partial
coverage. No report-size bound was raised or required value truncated.

## Focused checks

Commands use installed `pwsh -NoLogo -NoProfile -File` with these test paths.
Generated assessments ran sequentially. The controlled source matrix substitutes
only identity, registry, native enumeration and CIM boundaries; the actual worker
supervisor, reducers, canonical validation, recommendations, HTML, package
protection/reopening and viewing cleanup execute normally.

| Check | Outcome |
| --- | --- |
| `ResourceSourceExecution.Tests.ps1` | Pass; actual source constructs five scopes, preserves mapped/UNC identities and unknown remote printer metadata; default and printer-metadata denial corrections also pass |
| `ResourceSourceApplication.Tests.ps1` | Pass for all 11 cases: Complete, RegistryDenied, ConnectionDenied, PrinterDenied, DefaultDenied, PrinterMetadataDenied, PeripheralUnavailable, Maximum, Oversize, AlternateAdministrator, LocalSystem; generated cases took about 21.7–23.7 seconds each |
| `ResourceDependencies.Tests.ps1` | Pass; typed bounds, Unicode, duplicates, privacy and failure isolation |
| `ResourceDependenciesPolicy.Tests.ps1` | Pass; finite source and authority declarations |
| `ResourceDependenciesNativeSource.Tests.ps1` | Pass; initiating-context denial and allowed/prohibited call surface |
| `ResourceDependenciesContract.Tests.ps1` | Pass; canonical scope/subject/finding/recommendation composition |
| `ResourceDependenciesApplication.Tests.ps1` | Pass; 14 existing fixture cases plus invalid-fixture refusal, protected package and cleanup |
| `SoftwareRecognition.Tests.ps1`, `SoftwareRecognitionCatalog.Tests.ps1` | Pass; recognition remains conservative and catalog admission remains closed |
| `SoftwareReportApplication.Tests.ps1`: Maximum | Pass; **259,400 bytes**, all 128 registrations retained |
| `SoftwareReportApplication.Tests.ps1`: Distinct | Pass; **261,864 bytes**, distinct maximum Unicode/escaped values retained, **280 bytes** below the unchanged cap |
| `SoftwareReportApplication.Tests.ps1`: EscapedOverflow | Pass; safe refusal and cleanup, no truncation or cap increase |
| `SoftwareInventoryContract.Tests.ps1`, `ContractValidator.Tests.ps1` | Pass; inherited resource/network contract composition, all 128 software registrations, exact references, annotation ownership, malformed/Unicode/byte/depth/numeric/secret/coverage/graph negatives |
| Affected PowerShell syntax and `git diff --check` | Pass |

Only synthetic inputs and sanitized outcomes appear here. Test-owned protected
packages, plaintext viewing artifacts and workspaces are removed by the existing
verified harness cleanup. Generated ignored build outputs remain local; no real
assessment, package, certificate, key or private #160 candidate was touched.

## Private #161 comparison handoff

After the separately authorized exact-candidate signing/admission and live session:

1. Confirm initiating-user context and compare known remembered/disconnected
   mappings and SMB UNC connections against authorized local metadata. Include
   DFS/WebDAV cases to confirm the documented coverage limit; do not browse a
   share or probe availability as part of Local Only collection.
2. Compare a local/USB or locally installed TCP/IP printer's exact name, configured
   port/driver binding, installed driver metadata, default and Work Offline
   setting. Include a disconnected remote queue. Distinguish metadata returned
   by the selected cache from information not exposed by that source; do not
   fetch remote properties to fill a gap.
3. Compare representative USB/HID/Bluetooth/imaging/audio dependencies and
   unavailable devices. Confirm driver-registration evidence is not presented
   as present-device health or future compatibility. Include unavailable or
   policy-denied providers and source/buffer limits where authorized.
4. Confirm alternate-administrator and SYSTEM execution never supplies another
   user's mappings/default printer. Check exact Unicode names and source/context
   provenance in the reopened private package and HTML, with useful migration
   follow-up for incomplete coverage.
5. Capture the candidate's actual Local Only network behavior with attribution
   to its process tree and relevant Windows provider/broker activity. Separate
   pre-existing background traffic from assessment-triggered requests. Static
   API selection and fixture successes do **not** establish live zero egress.
   Record actual failures/unknowns and preserve the existing live hold until its
   governing conditions are satisfied.

Primary API rationale: Microsoft's [EnumPrinters documentation](https://learn.microsoft.com/en-us/windows/win32/printdocs/enumprinters)
distinguishes the local level-four cache from remote opens at level two;
[NetUseEnum](https://learn.microsoft.com/en-us/windows/win32/api/lmuse/nf-lmuse-netuseenum)
defines the null local server, level-zero names and SMB/DFS/provider limits.
These source contracts do not replace the private comparison and egress evidence.

## Review and remaining gates

Code Review was invoked with a resolved fixed point, nonempty committed diff and
the current #147 issue/spec. Under the documented retained-slot recovery,
**Standards: pending** and **Spec: pending** are separate obligations. Root must
dispatch fresh reviewers after this implementation turn; neither axis is waived
or represented by a previous-ticket review.

- Diff: `git diff 3a0cebca469dcc569302b1a75292fb79f95ab790...HEAD`.
- Commits: `git log 3a0cebca469dcc569302b1a75292fb79f95ab790..HEAD --oneline`.
- Standards sources: original-checkout `AGENTS.md`, `docs/agents/issue-tracker.md`,
  `triage-labels.md`, `domain.md`, `CONTEXT.md`; integration `CONTRIBUTING.md`,
  `.sandcastle/CODING_STANDARDS.md`, and Code Review's full smell baseline.
  No relevant ADR directory is present.
- Spec source: full current #147 body/comments, inherited #134/#37 requirements
  and #158 allocation, with supplied frontier/dependency evidence.

The full integrated suite remains #158/final under the explicit testing-cadence
override. #145's missing WinRM fields, #138's historical memory excess, actual
#161 GUI/HTML/physical/provider comparisons and all signing/trust/release gates
remain unwaived. Deadline remains end of September 6 in America/Chicago, before
September 7 00:00 CDT / 05:00 UTC. Root owns review, delivery, issues and the
requirement register.

## Orchestrator final independent review and delivery readiness

The initial clean checkpoint9b5deeaff21eeb4759298f8661e4ee1382d6c350 received fresh independent reviews against3a0cebca469dcc569302b1a75292fb79f95ab790. Standards reported zero documented violations and one nonblocking possible Speculative Generality judgment for unused printer CIM fixture branches. Spec identified two P2 implementation blockers: distinct same-name driver registrations collapsed, and exact matching connections discarded locally collected provider metadata. Those earlier pending-review statements are historical.

A new implementation worker with no inherited conversation history corrected only those findings in c613fed3cccea8c0055a6bd9c84f616f5d149f59, with focused evidence at1afbb5e57da4e4114bb560f83029b9f8f330bf08. Root dispatched fresh affected-only Standards and Spec reviewers for9b5deeaff21eeb4759298f8661e4ee1382d6c350...1afbb5e57da4e4114bb560f83029b9f8f330bf08. Neither reran tests or reviewed the unchanged original diff again.

**Standards correction result:** zero documented violations; zero new smell judgments. The original nonblocking maintenance judgment does not prevent delivery.

**Spec correction result:** zero findings. Both original P2 findings are resolved. Driver name/environment/model and associated version/INF metadata survive source capture, normalization, canonical observations and HTML. Frozen fields and rule bounds cover the additions. Provider metadata survives only exact drive/endpoint correlation; mismatched or unavailable providers remain unknown and the active endpoint retains precedence. No correction scope creep or new incorrect behavior was identified.

**Disposition:** the automated #147 implementation slice qualifies for delivery and closure after merge. Full #158/final regression and actual #161 provider/GUI/zero-egress acceptance remain pending; no live result, parent completion or release acceptance is claimed. #145's open WinRM source gaps and the old #160 candidate's collection hold remain unchanged. This review record changes documentation only; the final source/candidate identities and actual test results above are retained without duplicate runs.
