# Device, Windows, activation, form, virtualization, and power context

This is a narrow real-assessment slice of WIN-PCInfo. After the operator reviews and accepts the Preparation Summary, the generated application collects a fixed 17-field device-context scope, validates the canonical Assessment Record twice, derives an English HTML report, and places the record and report in a locally protected package.

The result is advisory. It is not a compatibility guarantee, compliance score, proof of license entitlement, battery-health test, hardware attestation, or statement that the full WIN-PCInfo capability set is delivered.

## What Windows is asked for

The collector runs as the standard user, offline, with no elevation or device change. Every query names its properties explicitly:

- `Win32_ComputerSystem`: `Manufacturer`, `Model`, `TotalPhysicalMemory`, numeric `PCSystemType`, and `HypervisorPresent`;
- the first `Win32_Processor`: `Name`;
- `Win32_OperatingSystem`: numeric `OperatingSystemSKU` and `BuildNumber`;
- `SoftwareLicensingProduct`: `LicenseStatus` only, filtered to the public Windows application identity and limited to 16 rows;
- the first `Win32_SystemEnclosure`: `ChassisTypes`, normalized to at most eight numeric codes;
- the first `Win32_Battery`: `BatteryStatus`, `EstimatedChargeRemaining`, and `EstimatedRunTime`; and
- .NET `RuntimeInformation.OSArchitecture`.

There is no broad CIM serialization, localized-caption identity, network request, download, installation, prompt, self-elevation, `powercfg`, activation repair, battery calibration, or Windows Feature change. Source failure is recorded as unavailable or inaccessible evidence; WIN-PCInfo does not retry with broader authority.

## Activation: what the state does and does not mean

The collector deliberately excludes every product-key, partial-key, product-identifier, and free-form licensing property before output exists. Only the numeric `LicenseStatus` projection crosses the Windows source boundary. WIN-PCInfo normalizes it to `Activated`, `NotActivated`, or an explicit unknown value.

That is a point-in-time Windows-reported state. It cannot prove legal entitlement, license ownership, transfer rights, genuine-purchase history, or whether anyone should buy a license. The report gives no purchasing guidance. A denied or unavailable source remains a coverage limitation and an `Indeterminate` interpretation; it never becomes `NotActivated` by guesswork.

## Form and virtualization

The form rule reads only contract-validated `PCSystemType` and chassis codes and emits `Desktop`, `Laptop`, `Tablet`, `Virtual`, `Other`, or unknown. The virtualization rule uses validated manufacturer and model signals. `HypervisorPresent` is retained as context but is not enough by itself to label a physical Hyper-V host as a virtual machine.

A virtual result is labeled **Virtual**. Its battery observations describe only what the guest can see. They cannot support claims about a host's physical battery, firmware, TPM attestation, OEM identity, or performance. Conversely, “not detected” does not prove that a device is physical. This preview therefore sets `physicalClaimsAllowed` to false in every public validation result.

## Battery and bounded power observations

When Windows exposes no battery instance after a successful query, battery presence is `Absent` and the status, charge, and runtime fields are `ObservedAbsent`. When a battery is present, the first bounded instance may supply a normalized status, a 0–100 charge percentage, and an estimate of at most seven days. Provider sentinel values, malformed values, denial, and inaccessible sources become explicit unknown or partial coverage.

These observations do not measure wear, design capacity, calibration, charging policy, thermal behavior, or performance. WIN-PCInfo never runs a battery report and never changes the active power configuration.

## How interpretation stays evidence-aware

The readiness rule executes only after the Assessment Contract validator accepts the source observations. It checks the same preview thresholds as the earlier slice: at least 8 GiB of physical memory, Windows build 19045 or later, and `X64` or `Arm64` architecture. A second contract pass validates every derived reference and the final coverage state.

Activation, form, virtualization, and power sections show the actual observation state, an evidence-referenced advisory finding, and the scope limitation. The rule emits four independently referenced findings: core readiness, activation, platform, and power. A virtual signal produces an informational platform finding; a non-match stays `Indeterminate` because it does not prove a physical device. Missing or inaccessible evidence cannot become a successful or negative claim. Per-source activation, chassis, and battery access denial is retained with a distinct stable diagnostic instead of being collapsed into ordinary unavailability. `Complete`, `Partial`, `Unavailable`, `Denied`, `Malformed`, and `ProhibitedMaterialBlocked` remain distinct from observation and finding outcomes.

## Reading the protected report

The report starts with outcome, scope coverage, Windows version, and architecture. It then explains activation, form/virtualization, and battery/power context in plain language. Identifying values and detailed provenance remain inside the encrypted package under **Device details and where they came from**.

`assessment-record.json` is canonical. `assessment-report.html` is a derived view. Package reopening authenticates the envelope and validates the archive, manifest, exact-byte digests, schemas, and semantic references before either artifact is returned.

## Frozen bounds and safe failure

The approved collector operation is `op:device.windows-context.collect`. Its release policy freezes the Microsoft-signed active PowerShell host, exact compact source digest, standard-user context, offline behavior, built-in dependencies, one attempt, five-second deadline, 16 KiB stdout, 4 KiB stderr, and verified Windows Job Object cleanup. The compact encoded source itself is bounded below the Windows command-line limit and never crosses a writable script path.

Four separate in-process rule operations evaluate readiness, activation, platform, and power context. Each reads only its declared subset of the 17 validated observations, emits exactly one advisory finding, runs once with its own 100 ms deadline, performs no network or file operation, and creates no artifact. The collector and all four rule identities and bounds are embedded in the immutable Preparation Plan before approval.

The first contract pass contains only the 15 observations actually examined at the Windows source boundary and no findings. After that pass succeeds, two separately bounded release-owned classifier operations append virtualization and form observations. Each has its own actual timing, classifier provenance, and one-observation result envelope; the completed Windows collector envelope remains unchanged. The four Rule Evaluations then read completed observations and append one finding apiece before the final contract pass. This prevents a pending classifier from masquerading as `SourceReportedUnknown`, prevents a finding from manufacturing its own input evidence, and avoids attributing post-collection work to the Windows collector.

An approved malformed, over-limit, or prohibited-material fixture can produce a typed recoverable gap package. A failure before process launch is `NotStarted`/`20`, cancellation is `Cancelled`/`30`, timeout is `TimedOut`/`40`, integrity failure is `50`, and unverified cleanup takes precedence with `60`. A lifecycle failure without evidence creates no report or package.

## Reproduce the synthetic matrix

The closed fixture names cover complete, partial, unavailable, malformed, oversize, explicitly activated/unactivated/unknown, explicitly physical/virtual, desktop/laptop, battery-present/absent/unavailable, Unicode, non-English, denied, and prohibited-material behavior. Fixture files carry only a scenario name; synthetic values live in release source and are never printed as public validation evidence.

Run:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessScenarios.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessPolicy.Tests.ps1
```

For the identifier-free closure record, see [Issue #49 validation evidence](validation/issue-49-activation-form-power.md).
