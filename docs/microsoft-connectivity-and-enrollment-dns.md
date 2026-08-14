# Microsoft service connectivity and enrollment discovery

WIN-PCInfo can run a small, read-only set of unauthenticated connectivity probes after the operator approves `MicrosoftConnectivityEnabled`. The release freezes the targets, ports, HTTP method, deadlines, redirect behavior, evidence limits, and privacy rules before collection. `LocalOnly` returns before any endpoint is materialized and performs zero outbound requests.

## Exact Preview.1 catalog

Catalog version `2026-08-14` contains three generic Microsoft targets:

| Purpose | Target | Port | Request |
| --- | --- | ---: | --- |
| Intune enrollment discovery | `enterpriseenrollment-s.manage.microsoft.com/EnrollmentServer/Discovery.svc` | 443 | `HEAD`, no body, no redirects |
| Microsoft Entra device registration | `enterpriseregistration.windows.net/` | 443 | `HEAD`, no body, no redirects |
| Shared identity and Defender security-management prerequisite | `login.microsoftonline.com/` | 443 | `HEAD`, no body, no redirects |

The catalog comes from Microsoft's published [Intune endpoint requirements](https://learn.microsoft.com/en-us/intune/fundamentals/endpoints), [Windows enrollment CNAME guidance](https://learn.microsoft.com/en-us/intune/device-enrollment/windows/create-cname-autodiscovery), and [Defender for Endpoint connectivity guidance](https://learn.microsoft.com/en-us/defender-endpoint/standard-device-connectivity-urls-commercial). A catalog entry is a bounded diagnostic target, not authorization to contact related wildcard, tenant, regional, telemetry, update, or control-plane endpoints.

## What is observed

The protected Assessment Record keeps DNS, TCP, TLS handshake, offline certificate-chain evaluation, negotiated protocol/cipher, Windows proxy behavior, HTTP response metadata, and enrollment-discovery DNS as separate Evidence Scopes. This separation matters: a DNS failure does not claim a TCP failure was attempted, a TCP block does not become a certificate verdict, and an HTTP redirect is recorded without following it.

Per-endpoint values, addresses, certificate fingerprints and chain status, negotiated cipher, proxy outcomes, and HTTP metadata are Restricted Diagnostic Evidence. Public output contains only bounded counts, catalog/network mode, one aggregate TLS-inspection state, privacy booleans, and validation/package/cleanup proof.

TLS inspection has four deliberately narrow outcomes:

- `Confirmed` requires independent proxy-policy and certificate-path corroboration.
- `Suspected` can record a direct/proxy certificate-path difference, but that difference alone is not confirmation.
- `NotObservedWithinCompletedTests` applies only when completed paths agree.
- `Indeterminate` preserves insufficient or incomplete evidence.

## Privacy and safety boundary

The collector uses in-process .NET APIs and the Windows system proxy without default credentials. It sends no credential, tenant identifier, cookie, collected evidence, or request body; follows no redirect; downloads no certificate-chain material; performs no packet capture; and changes no adapter, resolver, route, proxy, firewall, certificate store, trust setting, enrollment state, or other device configuration. Each release-owned phase and rule has a finite operation ID, input/output bound, and deadline.

Failed, blocked, redirected, or timed-out endpoint attempts are evidence gaps, not a reason to discard other successful scopes. The app still validates the canonical record, creates the beginner report, protects and reopens the package, and returns `CompletedWithGaps` where appropriate. Cleanup uncertainty takes precedence over a normal diagnostic result.

## Limits and troubleshooting

These probes do not authenticate, enroll or register the device, prove Intune/Defender onboarding or compliance, verify service health, validate tenant intent, or cover every regional Microsoft endpoint. They intentionally do not test the organization's tenant-specific `EnterpriseEnrollment` or `EnterpriseRegistration` CNAME because doing so would require a tenant/domain identifier that this release is forbidden to transmit. Confirm those values through the responsible tenant administrator's approved workflow.

Read the per-protocol coverage and diagnostic reason codes before changing anything. A DNS gap points to name resolution; a TCP gap points to the bounded port path; a TLS/chain gap points to negotiation or offline trust evidence; a proxy or HTTP gap remains separate. Do not disable a firewall, proxy, TLS inspection product, or certificate control merely to obtain Complete coverage.

Repository maintainers can reproduce the closed validation matrix with:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/MicrosoftConnectivityPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/MicrosoftConnectivity.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/MicrosoftConnectivityContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/MicrosoftConnectivityApplication.Tests.ps1
```

The fixtures are synthetic; they never claim facts about the test computer.
