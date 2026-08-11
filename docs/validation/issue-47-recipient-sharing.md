# Issue 47 public-safe validation evidence

This projection describes release-owned contracts, synthetic validation, and sanitized live certificate-store validation. It contains no real Recipient Profile, fingerprint, certificate, private key, PFX, password, credential, recovery phrase, package, report, Assessment Record, user/device/organization identity, local path, or provider diagnostic.

## Automated evidence

- `RecipientSharingPolicy.Tests.ps1` validates the exact Recipient Sharing policy and Recipient Profile schemas.
- `RecipientProfile.Tests.ps1` exercises synthetic TPM-backed and software-protected setup, public-only profile export, RSA 3072 default, OAEP-SHA-256 round-trip, profile admission, wrong fingerprint, and expired admission with verified cleanup.
- `RecipientSelection.Tests.ps1` drives a synthetic profile through the generated application's request, Preparation Summary, and normal Device Readiness completion. It proves the fingerprint-confirmed zero-or-one selection, proves the profile path is not emitted, proves approval cannot override a mismatch, and proves Preparation carries the exact admitted public certificate into RSA-OAEP-SHA-256 packaging rather than accepting a late arbitrary certificate. Its Completion Summary records successful package verification but correctly marks recipient access and transfer unavailable after validation cleanup removes that synthetic package. The generated `OneRecipient` case receives that same private execution fact from Preparation.
- `ProtectedPackageRecipient.Tests.ps1` proves zero-recipient local access, one-approved-recipient RSA-OAEP-SHA-256 wrapping alongside DPAPI, identity-free envelope metadata, expired historical opening from the matching key alone, and missing-key rejection after the matching synthetic key handle is actually disposed, without plaintext.
- `RestrictedReportExport.Tests.ps1` proves the public application emits a prominent structured warning before the export call, warning refusal, interrupted-write cleanup, HTML-only output, the permanent Restricted banner, non-public classification, and cleanup-aware Result-sharing Guidance, including the fail-safe `Uncertain` residue state.
- `RecipientSharingApplication.Tests.ps1` invokes all twelve closed scenarios through the generated application and verifies one sanitized result, one post-cleanup Completion Summary that claims no retained access or transfer, one matching terminal record, and zero validation residue.
- `DeviceReadinessApplication.Tests.ps1` proves a normal zero-recipient validation records successful package verification without claiming local access or recipient transfer after its synthetic package is removed.
- `DeviceReadinessContract.Tests.ps1` proves a typed package `CleanupIncomplete`, failed fixture-boundary cleanup, and retained package that fails final reopening all map to non-transferable `Uncertain` availability with the correct cleanup or integrity terminal instead of false verified absence.
- Existing Protected Package, Preparation, request, deterministic-build, schema, and Windows PowerShell host suites guard integration and regression behavior.

The generated scenarios are `TpmBackedSetup`, `SoftwareFallbackSetup`, `ProfileValidation`, `WrongFingerprint`, `ExpiredAdmission`, `HistoricalOpening`, `MissingKey`, `ZeroRecipient`, `OneRecipient`, `InterruptedExport`, `WarningDeclined`, and `RestrictedExport`. They use ephemeral in-memory RSA keys and test-owned local files only. They do not create a real certificate-store identity or exercise a real recipient. The focused provider-contract seam separately verifies the production CNG/store facts that the TPM and software paths must prove, without mutating a developer certificate store.

## Live certificate-store boundary

The actual consultant setup implementation uses the Current User certificate store and prefers the Microsoft Platform Crypto Provider before the explicitly labeled Microsoft Software Key Storage Provider fallback. Live validation completed under an approved dedicated disposable standard-user profile. The bounded worker used the production setup and rollback functions and proved all of these public-safe facts:

- the profile was loaded and the worker was not an administrator;
- the selected provider was release-approved and reported `WindowsUserBound` protection;
- the key was RSA 3072, non-exportable, present in the Current User store and provider during the test, and usable for an RSA-OAEP-SHA-256 round trip;
- production rollback removed the exact certificate and provider key and verified both absent;
- the worker terminated and the protected staging boundary, recovery descriptor, and transient execution artifact were absent after validation.

The dedicated account password was rotated to an undisclosed random value after the worker exited. No fingerprint, key name, certificate, private key, password, user/device identifier, local path, or provider diagnostic is retained in this public evidence.

Passing these tests proves this tracer-bullet contract only. It does not mark a Product Capability delivered, publish a release, identify a real recipient, or create a Preview/Supported claim.
