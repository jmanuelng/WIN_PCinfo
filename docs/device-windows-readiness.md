# Device and Windows readiness

This is WIN-PCInfo's first narrow, real assessment slice. After the operator reviews and approves the Preparation Summary, the generated application collects eight facts, validates one closed Evidence Scope, explains the result in an HTML report, and places both the report and canonical Assessment Record in a locally protected package.

It is an advisory check, not a compatibility guarantee, compliance score, or statement that the full WIN-PCInfo capability set is delivered.

## What it reads

The collector runs as the standard user, offline, with no elevation or device change. It asks Windows for named properties only:

- `Win32_ComputerSystem`: `Manufacturer`, `Model`, and `TotalPhysicalMemory`;
- the first `Win32_Processor`: `Name`;
- `Win32_OperatingSystem`: numeric `OperatingSystemSKU` and `BuildNumber`; and
- .NET `RuntimeInformation.OSArchitecture`.

There is no `SELECT *`, broad object serialization, inventory sweep, network request, download, installation, prompt, or self-elevation. The numeric SKU is mapped by the release to a short edition name. WIN-PCInfo never uses the localized Windows `Caption` as a stable identifier, so changing the display language does not change the edition identity.

Manufacturer, model, processor name, and the other device values are **Restricted Diagnostic Evidence**. They may appear in the local encrypted report and canonical record. They do not appear in progress, terminal output, public validation records, fixture files, or CI evidence.

## How the readiness result works

The rule evaluates only after the Assessment Contract validator accepts the typed record and the scope has `Complete` coverage. This preview check expects:

- at least 8 GiB of physical memory;
- Windows build 19045 or later; and
- an `X64` or `Arm64` operating-system architecture.

Meeting those conditions produces `ExpectedCondition`; an observed value below a threshold produces `NeedsAttention`. If any required fact is missing, malformed, unavailable, or rejected by a bound, the result is `Indeterminate`. Missing evidence never becomes either a successful or negative claim.

Virtualization is a separate advisory fact derived from the already validated manufacturer and model. A virtual machine is not automatically treated as unready.

## Reading the report and package

The report begins with the outcome in plain language and explains that the result is advisory. Windows edition, build, architecture, and coverage appear first. Identifying device details and their provenance are inside a collapsed **Device details and where they came from** section.

`assessment-record.json` remains the canonical typed evidence. `assessment-report.html` is derived from that record. Both are authenticated inside the Protected Evidence Package; reopening validates the encryption, archive, manifest, digests, schema, and semantic references before either artifact is returned.

## Bounds and safe failure

The approved collection operation is `op:device.windows-readiness.collect`. The release policy freezes the signed PowerShell executable, exact embedded source digest, standard-user context, offline behavior, dependencies, five-second deadline, one attempt, 8 KiB stdout, 4 KiB stderr, and Job Object cleanup. The separate `op:rule.device-windows-readiness.evaluate` operation is in-process and offline, reads at most eight already validated observations, emits at most one finding, has one attempt and a 100 ms deadline, and creates no artifact. The complete contract is approved in the Preparation Summary before collection begins.

An approved unavailable-source fixture or an attempted collection whose malformed or over-limit output is retained only as a typed gap completes with exit code `10`; it fabricates no field observations. A failure before process launch is `NotStarted`/`20`, cancellation is `Cancelled`/`30`, timeout is `TimedOut`/`40`, other integrity failure uses `50`, and unverified cleanup takes precedence with `60`. Those lifecycle failures create no report or package when there is no evidence. WIN-PCInfo does not retry with a broader query, ask for elevation, install a provider, or switch to a localized command.

Repository tests use eight closed synthetic scenarios: complete, partial, unavailable, malformed, oversize, virtual, Unicode, and non-English. Those files contain scenario names only; the synthetic device values live in release source and never enter public application output.

For public-safe test results and commands, see [Issue #48 validation evidence](validation/issue-48-device-readiness.md).
