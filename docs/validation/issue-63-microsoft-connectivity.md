# Issue 63 public-safe validation evidence

This evidence is synthetic and contains no real IP address, resolver, proxy value, route, certificate chain, endpoint result, tenant identifier, credential, Assessment Record, report, or protected package.

Validated behavior:

- the immutable Preparation Plan embeds catalog version `2026-08-14`, three exact generic Microsoft endpoints, port 443, `HEAD`, zero response-body bytes, zero redirects, finite deadlines, one attempt, and all operation/rule safety fields;
- the generated application will run the collector only after `MicrosoftConnectivityEnabled` approval; Local Only returns before endpoint materialization and reports zero outbound operations;
- collector output keeps DNS, TCP, TLS, offline chain, negotiated protocol/cipher, Windows proxy, bounded HTTP metadata, and enrollment DNS in eight separate typed Evidence Scopes;
- credentials, tenant identifiers, collected evidence, arbitrary payloads, cookies, redirect following, packet capture, settings changes, downloads, installation, and self-elevation are prohibited by the closed policy and payload contracts;
- TLS inspection has only Confirmed, Suspected, NotObservedWithinCompletedTests, and Indeterminate outcomes, and a certificate difference without independent corroboration is rejected;
- both TLS transports receive an offline chain policy before validation, provider status text is mapped before packaging, and failed proxy sends retain their selected transport mode;
- bounded local static proxy and bypass settings choose an explicit route; PAC and WPAD fail closed without lookup, download, or an HTTP attempt;
- direct, proxy, blocked, partially reachable, DNS failure, redirect, timeout, confirmed/suspected inspection, invalid chain, HTTP metadata bound, Local Only, retired endpoint, and non-English fixtures cross the generated application seam;
- every scenario composes prerequisite evidence, validates the canonical Assessment Record, derives the beginner report, creates and reopens the Protected Evidence Package, verifies cleanup, emits one identifier-free projection, and reaches one honest terminal outcome;
- failed remote scopes remain recoverable gaps while local evidence and protected packaging continue;
- exact per-endpoint observations and certificate/proxy/transport details remain only inside the synthetic protected evidence path and never enter public output.

Reproduction commands:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
pwsh -NoLogo -NoProfile -File ./tests/MicrosoftConnectivityPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/MicrosoftConnectivity.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/MicrosoftConnectivityNative.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/MicrosoftConnectivityContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/MicrosoftConnectivityApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AssessmentContractSet.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

Final validation completed all 89 test files. The deterministic generated artifact SHA-256 is `b0abca92d496e98a862d008e8c2d6cd0c3efb743d58007bda7b155642071aae8`. This is repository and synthetic-fixture evidence only. It is not live device, tenant, proxy, firewall, Microsoft-service-health, enrollment, registration, Defender-onboarding, compliance, or regional-endpoint validation.
