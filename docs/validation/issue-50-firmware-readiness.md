# Issue #50 firmware-readiness validation

This public-safe projection records release-owned contracts and synthetic generated-application validation. It contains no device observation, account identity, path, provider error, certificate, secret, hardware identifier, or protected package content.

## Closed scenario matrix

The generated artifact exercised all ten release-declared states through Preparation, the one immutable privileged phase, standard-user device collection, canonical validation, three bounded rules, beginner report generation, encrypted packaging, immediate reopening, and verified fixture cleanup.

| Scenario | Firmware coverage | Secure Boot coverage | TPM coverage | Terminal |
| --- | --- | --- | --- | --- |
| Supported | Complete | Complete | Complete | Completed |
| Disabled | Complete | Complete | Complete | Completed |
| Absent | Complete | Complete | Complete | Completed |
| Virtual | Complete | Complete | Complete | Completed |
| NonUefi | Complete | Unsupported | Complete | CompletedWithGaps |
| AccessDenied | Denied | Denied | Denied | CompletedWithGaps |
| Unsupported | Complete | Unsupported | Unsupported | CompletedWithGaps |
| Malformed | Malformed | Malformed | Malformed | CompletedWithGaps |
| Timeout | TimedOut | TimedOut | TimedOut | CompletedWithGaps |
| CollectorFailure | Failed | Failed | Failed | CompletedWithGaps |

Every case produced exactly one terminal result and its stable exit code. The fixtures cover both the direct already-elevated branch and the synthetic single-UAC coordinator branch without claiming that CI displayed a real UAC prompt. Every result explicitly reported `physicalTpmAttestationEstablished=false` and `platformSecurityStateChanged=false`. Virtual evidence created the physical-attestation follow-up instead of upgrading the claim.

The package/report assertions proved that the accepted combined Assessment Record and beginner report were present after authenticated reopening. Validation then removed the synthetic package, worker, channel, and staging boundary and verified absence.

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/FirmwareReadinessPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/FirmwareReadinessContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/FirmwarePrivilegedCollector.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/FirmwareReadinessApplication.Tests.ps1
```

The fixtures are closed by the release policy and cannot supply scripts, commands, executable paths, provider error text, arbitrary fields, identifiers, secrets, network authority, or device-write authority.
