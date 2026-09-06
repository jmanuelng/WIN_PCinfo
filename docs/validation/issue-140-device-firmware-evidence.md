# Issue #140 — generated device, Windows and firmware evidence

This is synthetic implementation evidence for
[#140](https://github.com/jmanuelng/WIN_PCinfo/issues/140). Starting revision and
Code Review fixed point: `5e7c5fe0567c37fd774a029f1c4cba012fe26f29`.
It establishes no live assessment, physical support, private handoff acceptance,
signing, qualification or publication result. The frozen #160 candidate and
private keys/trust were not inspected or changed.

## Source audit and repair

| Capability / required component | Approved source and generated path | Audit result / next owner |
| --- | --- | --- |
| CAP-0001 / CMP-0001 | Process Supervisor's `ContextActual`: exact ComputerSystem, Processor, OperatingSystem projections and OSArchitecture; Device Readiness normalizes 15 source fields before two derived fields | Existing collector reused. Numeric edition/build/architecture and Unicode inventory verified through the Comprehensive record, rules, encrypted package and HTML. #161 compares real sources. |
| CAP-0002 / CMP-0002 | Windows ApplicationID-filtered SoftwareLicensingProduct, LicenseStatus only | Repaired denial classification, null-status coercion and silent 16-row truncation; no product/key identity properties added. #161 verifies real row count and state; legal entitlement remains unestablished. |
| CAP-0003 / CMP-0003 | Frozen `observe-firmware-tpm` worker: GetFirmwareType, narrow Win32_BIOS, built-in Confirm-SecureBootUEFI, narrow Win32_Tpm | Existing source/worker reused. Eight firmware fields, three scopes, UTF-8 bounds, denial/unsupported/malformed and observed absence exercised through the actual source statements and protected report. #161 owns live comparison and representative physical hardware. |
| CAP-0004 / CMP-0004 | ComputerSystem PCSystemType/HypervisorPresent; SystemEnclosure ChassisTypes; Battery status/charge/runtime | Repaired silent enclosure/chassis/battery truncation and malformed chassis omission. Bounds now declared in the release policy/schema. Multiple batteries produce an explicit constraint, not a first-battery summary advertised as complete. #161 verifies actual device fit. |
| CAP-0001, CAP-0004 / CMP-0015 | Validated-record readiness, VM/form classification, platform and power rules | Repaired Microsoft physical OEM false VM classification; a running hypervisor alone is not VM evidence. Missing source input cannot produce “no virtual signal” report wording. #161 verifies physical/VM interpretation without attestation or performance claims. |
| CAP-0002 / CMP-0016 | Versioned activation rule reads admitted normalized activation observation | Unknown/inaccessible activation stays Indeterminate; legal entitlement and purchasing advice remain excluded. #161 compares the real point-in-time state. |
| CAP-0003 / CMP-0017 | Firmware, Secure Boot and TPM rules read validated source observations and VM context | Missing/denied/unsupported/malformed evidence remains Indeterminate; observed absence and legacy BIOS retain their distinct semantics. Guest evidence cannot establish physical TPM attestation. #161 owns live acceptance. |

The ordinary Comprehensive engine now retains earlier normalized evidence when
the device source times out or returns malformed/over-bound output, provided
the collector started and its owned worker/tree/artifacts were verified absent.
Its device scope becomes TimedOut, Malformed or Constrained with no fabricated
device observations. Integrity/admission and unverified-cleanup failures retain
their existing fail-closed behavior. Cancellation retains its Cancelled terminal
and explicit coverage, while already collected protected evidence remains usable.

All actual device/firmware reads remain offline and observational. No setting,
feature, service, power plan, Secure Boot state, TPM state or trust store is
changed. No new tool, dependency, installation, raw licensing dump, credential,
key, serial-number projection or live WinGet capability was added. CMP-0061
remains deferred.

## Reproduction and evidence

Tests use the already-installed PowerShell Core 7.6.5 X64 host with
`-NoLogo -NoProfile`. `ReadinessSourceApplication.Tests.ps1` invokes the generated
Status desk Comprehensive scheduler with controlled OS adapters. It executes the
generated actual device-source statements and actual firmware worker routine;
the record validator, rules, crypto, package reopening, offline HTML and viewing
cleanup remain the product implementations.

Test-only source doubles are admitted against their own recomputed source
digests inside that controlled harness. They cannot be selected from the product
CLI or authorize live collection. Unrelated collector families retain the
existing controlled adapters. Their unreachable live worker functions are
omitted only from the test worker to keep source doubles within the unchanged
Windows launch bound; production source is not removed. Native/API values and
all test artifacts are synthetic. Exact generated unmodified candidate checks
and the existing narrow application scenarios complement this source seam.

Observed red cases before repairs:

- Actual source denial lost the three ACCESS_DENIED diagnostics.
- Null licensing status became NotActivated; bounded enumerations looked complete.
- Unsupported providers became generic unavailable sources; an invalid chassis
  code was silently dropped.
- A Microsoft physical model was classified Virtual.
- Device timeout discarded earlier evidence; malformed and oversized output
  ended the assessment instead of preserving a scoped gap and useful report.
- HTML denied source constraints and described missing VM evidence as no signal.

Final focused commands, results, timing, source commits and candidate digests are
recorded below after the final-input checks. Integrated full regression is
deliberately reserved for #158 under the latest testing-cadence instruction.
Historical #137 full-suite evidence predates these changed bytes; #138/#139
evidence remains historical for the same reason.

## Requirement allocation and acceptance handoff

| Requirement | This slice | Remaining gate / next owner |
| --- | --- | --- |
| #37 stories 27–28; CAP-0001–0004 and required CMP-0001–0004, CMP-0015–0017 | Approved source wiring, typed record/provenance, coverage, seven rules, protected report; automated gates below | Private read-only source comparison and complete delivered-app acceptance: #161 |
| #37 stories 19–20, 66–67 | Narrow read projections, existing source bounds/supervision and secret exclusion preserved; focused safety checks below | Exact-candidate live observation and artifact/cleanup checks: #161 |
| #37 stories 50–54, 69; sub-objectives 3, 8, 9 | Scoped failure states, evidence-linked rules, advisory limits and culture/Unicode coverage for these capabilities | Other capability owners retain their allocations; full integrated regression and exact candidate: #158; live locale/hardware evidence: #161 |
| #134 GUI stories 19–21, 24 | Generated Comprehensive worker through protected Open report, including retained partial evidence | Complete GUI interaction/scaling/keyboard/close/export and human report usefulness: #153, #158, #161 |
| Physical TPM/OEM/battery/performance or broad support claim | Not established by controlled sources | Representative real evidence: #161; support/qualification/publication: #162–#164 |
| Resource budget | No new claim or waiver | Prior test-host working set exceeded provisional 512 MiB. #158/#161 must measure final candidate and resolve the budget obligation. |

The concrete [private source-comparison procedure](issue-140-readonly-comparison.md)
lists expected field/scope checks, read-only sources, dispositions and artifact
handling. It is unexecuted and assigned to #161. Shared parent specifications
remain untouched; the orchestrator may use this allocation table to update the
shared requirement register during delivery. September 6 remains the private
handoff target, with unmet live gates explicitly pending.
