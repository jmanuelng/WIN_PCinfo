# Issue 62 public-safe validation evidence

This evidence is synthetic and contains no real certificate identity, fingerprint, account, private key, PFX, store content, or recipient data.

Validated behavior:

- the release policy freezes standard-user, offline, read-only collection and four bounded post-validation rules;
- all twelve release-owned scenario fixtures satisfy an exact payload contract;
- presence, store source, date validity, chain completeness, local trust, and key-protection state remain distinct;
- leaf date errors remain separate from trust while issuer date errors remain material to trust;
- inaccessible, malformed, alternate-user, and incomplete cases retain explicit per-purpose coverage and findings;
- live store and chain work runs inside a hard-deadline Job Object worker whose complete process tree must be proved absent;
- the worker launches only from the active host after a valid Microsoft Corporation Authenticode signature check;
- multi-store partial access retains successful evidence as `Partial`, and live absence uses an honest purpose subject;
- the virtual-device fixture drives the canonical device evidence and report as well as the sanitized certificate projection;
- public output contains counts and states but no certificate identifier or fingerprint;
- unexpected private-key- or PFX-shaped fields are rejected;
- native-source inspection confirms read-only existing-store access, disabled certificate downloads, no remote revocation claim, and no key-export or store-mutation API;
- the generated application validates the Assessment Record, beginner report, protected package, and cleanup proof for every scenario.

Reproduction commands:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
pwsh -NoLogo -NoProfile -File ./tests/CertificateTrustPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/CertificateTrust.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/CertificateTrustNativeSource.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/CertificateTrustApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AssessmentContractSet.Tests.ps1
```

Final local result on 2026-08-14:

- `PASS: 81 test files completed.`
- deterministic generated artifact SHA-256: `e3ab2427ec171aad952b661c8e317806f7fbd40b5dd8213cd691ea321ff9d488`

This is repository and synthetic-fixture evidence only. It is not live physical-device, virtual-device, tenant, remote-service, revocation, or recipient-environment validation.
