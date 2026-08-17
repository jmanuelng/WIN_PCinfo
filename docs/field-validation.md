# Field Validation

Field Validation is an optional human process. It is not a WIN-PCInfo workflow, switch, or post-run prompt. Community Validation as a product workflow is not implemented. Ordinary Preview use never becomes validation evidence automatically.

WIN-PCInfo never uploads evidence, never displays a post-run validation request, and never treats a successful assessment, a comment, or product telemetry as Release Evidence.

## When this applies

Use these instructions only when you already have authority over the client, you intend to help the maintainer understand a real managed or physical scenario that a fresh Azure client cannot represent, and you are willing to keep the Protected Evidence Package private.

Do not use Field Validation to share a package, report, Recipient Profile, or any Restricted Diagnostic Evidence.

## Deliberate consent

Read this entire page first. If you still want to offer a sanitized attestation, include this exact phrase in the private maintainer conversation or reviewed attestation note:

```text
I CONSENT TO A PRIVACY-SANITIZED FIELD VALIDATION ATTESTATION
```

Anything else, including a successful run, is not consent. There is no `-ConfirmFieldValidation` switch and no in-product submission path.

## What you may send

Send only an identifier-free sanitized attestation. Allowed contents are:

- the exact public product or commit identity you ran, without a local path;
- the Windows family, edition, architecture, and generic scenario label, such as “Windows 11 Enterprise x64, Entra joined, Intune managed”;
- whether you used `LocalOnly` or `MicrosoftConnectivityEnabled`;
- the public terminal outcome and reason code;
- whether elevation was accepted, already present, or denied;
- statement that the Protected Evidence Package remains private.

## What you must never send

Never attach or paste:

- Assessment Records, `.winpcinfo` packages, exported HTML reports, or Run Recovery Journals;
- Recipient Profiles, fingerprints, certificates, or keys;
- tenant, subscription, device, user, host, IP, or serial identifiers;
- policy values, certificate details, software inventories, or mapped-resource names;
- credentials, tokens, recovery material, or license keys.

If you are unsure whether a value is identifying, omit it.

## Afterward

Keep the real package in your private store until your authorized retention purpose ends. The maintainer may accept, reject, or ignore the attestation. Acceptance is a separate review step. Your ordinary use of Preview remains ordinary use.
