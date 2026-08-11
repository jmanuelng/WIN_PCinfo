# Recipient Profiles, private package transfer, and restricted report export

This tracer bullet proves three separate safety paths: a consultant can create a portable public Recipient Profile, an assessment operator can fix zero or one confirmed Package Recipient before collection, and an authorized user can deliberately export only the HTML report after accepting a prominent warning. It does not make a Preview or Supported capability claim. Ordinary assessment execution still stops after Preparation, and an unsigned development build fails the trust gate before persistent setup or plaintext export.

## First understand what is—and is not—shared

A **Recipient Profile** is non-secret. It contains a public RSA certificate, an operator-chosen label, its SHA-256 fingerprint, validity dates, the declared Recipient Protection Level, and the successful synthetic setup-test result. It never contains a private key, PFX, password, credential, recovery phrase, or assessment evidence.

The corresponding private key stays inside the Package Recipient's Windows cryptographic provider. WIN-PCInfo asks that provider to decrypt a small wrapped content key; it never exports the private key. A self-signed certificate does not prove who the recipient is. The assessment operator must compare the profile fingerprint with the recipient through an existing trusted relationship—for example, a known voice or video call—before approving the Preparation Summary.

Do not post a real Recipient Profile or fingerprint to an issue, Discussion, CI log, or public repository. They are not passwords, but this project treats real recipient identity material as private operational data.

## Create a Recipient Profile in the separate consultant workflow

Run this only as the Windows user who will receive packages. Choose a new file path in an existing local directory, read the whole command, and deliberately include `-ConfirmRecipientSetup`:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 `
  -Workflow RecipientProfileSetup `
  -RecipientProfileOutputPath C:\PrivateTransfer\consultant.recipient.json `
  -RecipientLabel 'Authorized endpoint consultant' `
  -ConfirmRecipientSetup
```

WIN-PCInfo defaults to RSA 3072 and never accepts less than RSA 2048. It first asks the Microsoft Platform Crypto Provider for a non-exportable Current User key. When that succeeds, the profile says `UserAndDeviceBound`: private operations remain tied to that Windows user and TPM-backed device. If the platform provider is genuinely unavailable, setup uses the Microsoft Software Key Storage Provider and says `WindowsUserBound`. The fallback must not be described as TPM- or hardware-bound.

Setup creates a self-signed public certificate only as a carrier for the encryption key. Its signature is not an identity or authorship claim. Before publishing the profile, setup wraps and unwraps a random synthetic 256-bit value with RSA-OAEP-SHA-256. If key creation, the round-trip, or profile publication fails, setup removes the exact certificate and provider key it created. `CleanupIncomplete` means that absence could not be proved; stop and investigate rather than creating another identity.

Successful setup prints the profile path, fingerprint, protection level, and `syntheticRoundTripVerified: true`. The recipient keeps their Windows account/profile/device and private key available. WIN-PCInfo creates no PFX, password, recovery phrase, scheduled task, backup, or background key monitor.

## Select zero or one recipient before collection

No recipient is the default. In automation, omission of `recipientSelection` normalizes to this exact choice. You may also state it explicitly:

```json
"recipientSelection": {
  "mode": "None",
  "profilePath": null,
  "fingerprintConfirmation": null
}
```

To select one recipient, obtain the profile file privately and obtain its SHA-256 fingerprint through a separate trusted contact with that recipient. Add both to the request before launch:

```json
"recipientSelection": {
  "mode": "Profile",
  "profilePath": "C:\\PrivateTransfer\\consultant.recipient.json",
  "fingerprintConfirmation": "<64 hexadecimal characters confirmed out of band>"
}
```

Guided mode uses the same two facts as explicit command parameters and displays them in the Preparation Summary before asking for `APPROVE`:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 `
  -Mode Guided `
  -AssessmentRecipientProfilePath C:\PrivateTransfer\consultant.recipient.json `
  -AssessmentRecipientFingerprintConfirmation '<64 hexadecimal characters confirmed out of band>'
```

Omit both parameters for zero recipients. Supplying only one fails request validation; Guided-only parameters cannot silently modify an Automation request.

Preparation validates the closed profile schema, exact public-certificate bytes and fingerprint, RSA size and exponent, protection label, synthetic round-trip result, and current validity. A wrong fingerprint or an expired/not-yet-valid certificate leaves the recipient prerequisite unresolved. Approval cannot override it. The Preparation Summary shows the label, fingerprint, and actual protection level for one final review, but never emits the private local profile path.

After approval, the package keeps its normal Local Package Protector access and adds one RSA-OAEP-SHA-256 wrap of the same fresh AES content key. The outer envelope exposes neither the profile, certificate, fingerprint, label, subject, issuer, user, device, nor organization. OAEP randomness also prevents the wrapped value from becoming a stable certificate identifier.

## Transfer and open a recipient package safely

Transfer only the encrypted `.winpcinfo` file to the preapproved Package Recipient through an authorized private route. Keep any separate recovery or access material on a different route. Never attach the package to a public project conversation, even though it is encrypted.

New-package admission checks certificate validity once during Preparation and packaging. Opening an existing package does not fail merely because the certificate later expired. It requires the matching usable private key in the recipient's Current User certificate store. `Open-ProtectedEvidencePackageForRecipient` performs one deliberate foreground lookup; there is no expiration monitor, store watcher, cloud recovery service, password bypass, or background task. Loss of the applicable Windows account, profile, device, or key can make recipient access unrecoverable.

An unavailable or unrelated private key returns `ProtectionUnavailable` and no plaintext. Authentication, archive, manifest, digest, and Assessment Contract checks still run before any artifact can be returned.

## Deliberately export only the HTML report

Restricted Report Export is a fallback for authorized private handling when an encrypted recipient workflow is unavailable. It is not a share button and never produces Publicly Shareable Evidence. The exported HTML remains unencrypted **Restricted Diagnostic Evidence**.

Read the warning phrase exactly, choose a new `.html` path in an existing local directory, and invoke the separate workflow:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 `
  -Workflow RestrictedReportExport `
  -ProtectedPackagePath C:\PrivateResults\package-example.winpcinfo `
  -RestrictedReportOutputPath C:\PrivateTransfer\restricted-report.html `
  -RestrictedReportWarningAcknowledgment 'I UNDERSTAND THIS IS RESTRICTED DIAGNOSTIC EVIDENCE'
```

The phrase must match exactly. Declining or mistyping it writes nothing. The workflow fully reopens and validates the package, selects only `assessment-report.html`, prepends a permanent visible `RESTRICTED DIAGNOSTIC EVIDENCE … NOT PUBLICLY SHAREABLE` banner, durably writes a provisional file, and publishes the final name only after success. An interruption removes and verifies the exact provisional plaintext. The workflow creates no upload, retention service, scheduled task, cleaner, or monitor.

The operator owns secure transfer and deletion of a completed export. Ordinary deletion is not forensic secure erasure; Windows and storage may retain recoverable blocks. Keep the encrypted package until its authorized retention purpose ends, delete the unencrypted export promptly after use, and never copy either artifact into a public issue, Discussion, repository, or general-purpose public file share.

## Completion Summary guidance

Every completed fixture produces `ResultSharingGuidance` covering:

- actual Local Package Protector access;
- whether one approved Package Recipient has access and at which protection level;
- encrypted private transfer with recovery material kept separate;
- the availability and completion state of Restricted Report Export;
- operator and authorized-recipient deletion responsibility; and
- prohibited public destinations.

The release policy is [`docs/spec/releases/2.0.0-preview.1-recipient-sharing.json`](spec/releases/2.0.0-preview.1-recipient-sharing.json). The closed schemas are [`schemas/recipient-sharing.schema.json`](../schemas/recipient-sharing.schema.json) and [`schemas/recipient-profile.schema.json`](../schemas/recipient-profile.schema.json). Public-safe validation evidence is in [`docs/validation/issue-47-recipient-sharing.md`](validation/issue-47-recipient-sharing.md).
