# Issue #41 process-supervision validation

This public evidence is synthetic and identifier-free. It contains no assessment evidence, machine paths, environment values, raw collector output, credentials, Azure facts, or private operational diagnostics.

## Observable seam

The current generated application stops after its Preparation gate and has no collection invocation path. Issue #41 therefore uses the explicitly permitted exported security-contract seam, `Invoke-ApprovedCollectorProcess`. The deterministic build includes that module and its embedded release catalog so the next dependent collection slice can call the same interface without introducing a second launch path.

The interface accepts one closed operation ID plus an optional cancellation token. Tests observe only the returned Collector Result Envelope, normalized synthetic record parts, sanitized supervision accounting, and verified cleanup.

## Required fixture matrix

| Fixture | Expected terminal process state | Safety evidence |
| --- | --- | --- |
| success | `Completed` | Microsoft-signed literal host, exact staged payload, normalized multilingual observation, separate bounded pipes, Job tree absent |
| wrong-executable | `NotStarted` / `PROCESS.EXECUTABLE_IDENTITY_INVALID` | no process launch and no path disclosure |
| invalid-argument | `NotStarted` / `PROCESS.ARGUMENT_INVALID` | secret-shaped argument rejected before native launch |
| excess-output | `Failed` / `PROCESS.OUTPUT_LIMIT_EXCEEDED` | stdout and stderr independently exceed 4 KiB, raw text absent, Job terminated |
| timeout | `TimedOut` / `PROCESS.DEADLINE_EXCEEDED` | 200 ms synthetic deadline and complete tree termination |
| cooperative-cancel | `Cancelled` / `PROCESS.CANCELLED_COOPERATIVELY` | fixed marker protocol, bounded grace, no hard-termination claim |
| hard-cancel | `Cancelled` / `PROCESS.CANCELLED_HARD` | ignored marker escalates to Job termination within two seconds |
| child-process | `Completed` | kernel accounting observes at least two Job members and removes the surviving child |
| incompatible-child | `NotStarted` / `PROCESS.JOB_INCOMPATIBLE` | suspended candidate never executes; explicit `IncompatibleNoLaunch` fallback |

Every row also asserts the complete owned tree and run-owned temporary boundary absent before return. The fixed synthetic script creates no task, service, persistent lock, or other process artifact.

## Validation commands

Run the focused contract tests:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/ApprovedCollectorCatalog.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ProcessSupervisor.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/BuildDeterminism.Tests.ps1
```

Run the repository suite:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

These tests require Windows because they exercise real Windows Job Objects, suspended `CreateProcessW`, Authenticode verification, and process-tree accounting. They use only the already-installed stable PowerShell host and acquire no dependency.

## Threat-boundary summary

- Caller-controlled paths, commands, scripts, arguments, environment maps, working directories, output limits, and deadlines do not cross the interface.
- The release catalog and payload have exact SHA-256 identities; the executable has literal active-host resolution plus valid Microsoft Authenticode identity.
- Parent environment inheritance is disabled, preventing ambient credentials, tokens, proxy settings, or module paths from crossing into the collector.
- Raw untrusted output is bounded, privately normalized only for the approved success shape, never returned or hashed, and cleared after use.
- Job incompatibility fails before execution. No root-only fallback can claim complete tree control.
- Cleanup targets only a freshly generated GUID child of the fixed supervisor temporary root and is verified before the result returns.
