# Firmware, Secure Boot, and TPM readiness

WIN-PCInfo observes a narrow firmware-security projection after the operator approves the complete Preparation Plan. The release-owned collector runs inside the one bounded Administrator phase, makes no network request, changes no firmware or TPM setting, and returns only the fields admitted by the Assessment Contract.

## What is examined

The collector uses only these Windows interfaces and projections:

- `GetFirmwareType` for the Windows firmware mode;
- `Win32_BIOS` for BIOS and SMBIOS version text;
- `Confirm-SecureBootUEFI` for the Secure Boot enabled state; and
- `Win32_Tpm` for presence, enabled, activated, and specification-version facts.

The projection deliberately excludes BIOS serial numbers, TPM endorsement or storage keys, owner authorization, certificates, credentials, recovery material, and other stable hardware identifiers. Raw provider errors do not cross the privileged channel. The worker has one attempt, a five-second operation deadline, an 8 KiB result ceiling, no arbitrary command or parameter surface, and remains inside the coordinator-owned Job Object and one-use local pipe.

## How to read the result

Coverage and findings answer different questions. Coverage says whether a source was successfully examined. A finding interprets only validated observations. `Disabled` is an observed value, not a collection failure; `Absent` is not `AccessDenied`; `Unsupported`, `Malformed`, `TimedOut`, and `Failed` retain separate diagnostics. A source-wide failure creates no invented null observations.

The three release-owned rules each produce exactly one finding:

- **Firmware context** describes UEFI or legacy/unknown firmware readiness.
- **Secure Boot readiness** distinguishes enabled, disabled, unsupported/non-UEFI, and unavailable evidence.
- **TPM readiness** distinguishes an absent TPM, disabled or inactive readiness, a reported TPM 2.0-capable state, and indeterminate evidence.

These are readiness observations, not remediation actions. WIN-PCInfo does not enable Secure Boot, initialize or clear a TPM, enter firmware setup, install drivers, or change Windows security configuration.

## Physical and virtual limits

A guest-visible or virtual TPM can show that the guest operating system has a TPM interface. It cannot prove the physical host TPM identity, hardware-rooted attestation, or universal OEM support. Virtual evidence therefore remains explicitly limited and creates a follow-up Tenant Discovery Task for an authorized endpoint-security or hardware owner. Missing or non-UEFI firmware evidence can similarly create a bounded OEM-support discovery task. Those tasks contain no device identifier or secret.

## Packaging and beginner guidance

After both the standard-user device-context source and the privileged firmware source pass the canonical contract, WIN-PCInfo evaluates the bounded rules, renders the beginner report, encrypts the record and report into the Protected Evidence Package, reopens the package, and validates both artifacts. The report explains the observed state, gaps, virtual/physical limitation, and safe next owner without claiming physical attestation or making a device change.

The immutable policy is [`2.0.0-preview.1-firmware-readiness.json`](spec/releases/2.0.0-preview.1-firmware-readiness.json), and its closed schema is [`firmware-readiness.schema.json`](../schemas/firmware-readiness.schema.json). Public-safe validation evidence is in [issue #50 validation](validation/issue-50-firmware-readiness.md).
