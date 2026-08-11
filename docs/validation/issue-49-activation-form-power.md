# Issue #49 activation, form, virtualization, and power validation evidence

This page is the public-safe validation record for the expanded device-context slice. It contains no real Assessment Record, package, device value, activation identifier, user or machine path, environment fact, or raw diagnostic output.

## Generated-application evidence

`tests/DeviceReadinessApplication.Tests.ps1` runs the complete physical-desktop/battery-absent tracer bullet through the generated public application. `tests/DeviceReadinessScenarios.Tests.ps1` runs the remaining closed synthetic matrix: activation unknown and unactivated; virtual; laptop; battery present and unavailable; source unavailable; malformed; oversized; denied; Unicode; non-English; and prohibited material.

Every case asserts:

- one sanitized scenario result and one matching stable terminal outcome/exit code;
- a 15-observation/no-finding source pass followed by two separately timed, one-output classifier envelopes and four independently declared Rule Evaluations;
- distinct virtual informational and physical-not-established finding fixtures;
- per-source activation, chassis, and battery access-denied diagnostics;
- `physicalClaimsAllowed: false`, including the virtual case;
- two-pass Assessment Contract acceptance where a recoverable record is permitted;
- beginner report verification and Protected Evidence Package reopen;
- absence of identifying and secret-shaped synthetic markers from stdout/stderr; and
- verified removal of the exact run-owned workspace and package boundary.

The prohibited-material case makes the child return a synthetic key-shaped field. The supervisor rejects it before `PrivatePayload` admission. The canonical record contains zero field observations and only the approved marker `encountered: true`, `retained: false`, `hashed: false`; no field name or value enters progress, diagnostics, a report, a hash, or public evidence.

## Focused contract evidence

- `tests/DeviceReadinessContract.Tests.ps1` proves exact 17-field closure, normalized activation, four closed finding reference sets, virtual-versus-physical advisory semantics, per-source denied diagnostics, `ObservedAbsent` battery detail, source-wide zero-observation failure, prohibited-material omission, and both contract passes.
- `tests/DeviceReadinessPolicy.Tests.ps1` proves the explicit CIM projections, absence of mutation commands and licensing-key projections, compact payload bound, closed authority, and negative schema mutations.
- `tests/ApprovedCollectorCatalog.Tests.ps1` proves the distinct collector/operation identity and process bounds.
- `tests/AssessmentContractSet.Tests.ps1` proves that the old eight-field scope remains versioned separately from the new 17-field scope.
- `tests/BuildDeterminism.Tests.ps1` executes a relocated generated artifact, proving the embedded policy has no repository-sidecar dependency.

## Commands

Run with stable PowerShell 7.6 or later 7.x:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessScenarios.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AssessmentContractSet.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ApprovedCollectorCatalog.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/BuildDeterminism.Tests.ps1
```

Synthetic packages and reports exist only inside an ignored, run-owned validation boundary and are removed before the generated application reports cleanup success. No release publication or real-device support claim is authorized by this ticket.
