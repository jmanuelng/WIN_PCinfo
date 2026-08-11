# Issue 47 public-safe validation evidence

This projection describes only release-owned contracts and synthetic validation. It contains no real Recipient Profile, fingerprint, certificate, private key, PFX, password, credential, recovery phrase, package, report, Assessment Record, user/device/organization identity, local path, or provider diagnostic.

## Automated evidence

- `RecipientSharingPolicy.Tests.ps1` validates the exact Recipient Sharing policy and Recipient Profile schemas.
- `RecipientProfile.Tests.ps1` exercises synthetic TPM-backed and software-protected setup, public-only profile export, RSA 3072 default, OAEP-SHA-256 round-trip, profile admission, wrong fingerprint, and expired admission with verified cleanup.
- `RecipientSelection.Tests.ps1` drives a synthetic profile through the generated application's request and Preparation Summary, proves the fingerprint-confirmed zero-or-one selection, proves the profile path is not emitted, proves approval cannot override a mismatch, and proves Preparation carries the exact admitted public certificate into packaging rather than accepting a late arbitrary certificate. The generated `OneRecipient` case receives that same private execution fact from Preparation.
- `ProtectedPackageRecipient.Tests.ps1` proves zero-recipient local access, one-approved-recipient RSA-OAEP-SHA-256 wrapping alongside DPAPI, identity-free envelope metadata, expired historical opening from the matching key alone, and missing-key rejection after the matching synthetic key handle is actually disposed, without plaintext.
- `RestrictedReportExport.Tests.ps1` proves the public application emits a prominent structured warning before the export call, warning refusal, interrupted-write cleanup, HTML-only output, the permanent Restricted banner, non-public classification, and actual Result-sharing Guidance topics.
- `RecipientSharingApplication.Tests.ps1` invokes all twelve closed scenarios through the generated application and verifies one sanitized result, one actual Completion Summary, one matching terminal record, and zero validation residue.
- Existing Protected Package, Preparation, request, deterministic-build, schema, and Windows PowerShell host suites guard integration and regression behavior.

The generated scenarios are `TpmBackedSetup`, `SoftwareFallbackSetup`, `ProfileValidation`, `WrongFingerprint`, `ExpiredAdmission`, `HistoricalOpening`, `MissingKey`, `ZeroRecipient`, `OneRecipient`, `InterruptedExport`, `WarningDeclined`, and `RestrictedExport`. They use ephemeral in-memory RSA keys and test-owned local files only. They do not create a real certificate-store identity or exercise a real recipient. The focused provider-contract seam separately verifies the production CNG/store facts that the TPM and software paths must prove, without mutating a developer certificate store.

## Live certificate-store boundary

The actual consultant setup implementation uses the Current User certificate store and prefers the Microsoft Platform Crypto Provider before the explicitly labeled Microsoft Software Key Storage Provider fallback. This repository run does not invoke that persistent human-only workflow. A future approved disposable Windows client or dedicated disposable user-profile validation may create a test-owned provider key, but must resolve and remove the exact certificate, private key, Recipient Profile, and temporary artifact and verify absence before the round ends.

Passing these tests proves this tracer-bullet contract only. It does not mark a Product Capability delivered, publish a release, identify a real recipient, or create a Preview/Supported claim.
