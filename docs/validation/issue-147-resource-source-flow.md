# #147 resource source and report checkpoint

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
