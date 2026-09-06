# Purpose-bound certificates and local trust

WIN-PCInfo observes a narrow set of local certificate facts that may help a migration or support recipient ask better questions. It does not inventory every certificate. It does not prove that a remote service accepts a credential, that a tenant owns it, or that a particular executable is approved.

The operation is frozen in the Preparation Summary before approval. It runs as the Assessment User in the active PowerShell host only after that executable has a valid Microsoft Corporation Authenticode signature, without elevation, network access, installation, prompts, downloads, or certificate-store writes. The exact policy is [`2.0.0-preview.1-certificate-trust.json`](spec/releases/2.0.0-preview.1-certificate-trust.json).

## The six purposes

The collector keeps purpose and source together:

- **Management:** client-authentication certificates in `CurrentUser/My`. A matching EKU is relevant but does not prove MDM ownership.
- **Authentication:** client-authentication or smart-card-logon certificates in `CurrentUser/My`. Local evidence cannot prove acceptance by an identity provider.
- **Device identity:** client-authentication certificates in `LocalMachine/My`. Presence does not prove tenant registration or ownership.
- **Code trust:** code-signing certificates in the current-user and machine `TrustedPublisher` stores. Presence does not prove that a specific program is signed or approved.
- **TLS inspection:** reported as `NotApplicable` in Local Only because an arbitrary trusted root is not enough to attribute an inspection product or workflow.
- **Service connectivity:** reported as `NotApplicable` until an approved service target exists. WIN-PCInfo does not guess from unrelated local certificates.

Each selected store is opened with Windows `ReadOnly` and `OpenExistingOnly`. Candidate selection uses only the release-owned stores and EKU object identifiers above, with at most eight candidates per purpose. Store location and store name remain attached to each Restricted candidate so the source boundary can be audited later.

The worker examines at most eight matching candidates per purpose, including malformed matches. A ninth match stops further metadata projection and chain building for that purpose and reports `Constrained` with `CERTIFICATE.CANDIDATE_LIMIT_EXCEEDED`. The retained subset is not a complete inventory. A well-formed certificate without an approved EKU does not match a purpose and is omitted. Windows supplies a store-local certificate snapshot for selection; that snapshot never enters evidence and its certificate objects are disposed even when selection stops early. The existing worker deadline and output limit still apply.

## Why the states are separate

For each admitted candidate, WIN-PCInfo records distinct Restricted fields:

| Question | Example states | What it means |
| --- | --- | --- |
| Is a candidate present? | `true`, `false` | Purpose-selected presence only. |
| Is it within its dates? | `Valid`, `Expired`, `NotYetValid`, `Unknown` | Time validity, not trust. |
| Can an offline chain be built? | `Complete`, `Incomplete`, `NotEvaluated` | Local chain completeness. |
| Does that chain anchor locally? | `Trusted`, `Untrusted`, `Indeterminate` | Local trust only. |
| What is known about its key? | `NoPrivateKey`, `NonExportable`, `PresentProtectionNotInspected`, `UnknownNotInspected` | A bounded protection observation, never key material. |

An expired certificate can still have a complete, locally trusted chain. Leaf date errors are removed only from the local trust interpretation after the leaf and issuer chain statuses have been separated; an issuer date error remains a trust failure. A currently valid certificate can have an incomplete chain. Keeping these states separate prevents a reassuring value in one dimension from hiding a problem in another.

An inaccessible store, malformed entry, deadline, or incomplete chain becomes explicit coverage and an advisory finding. If one of Code Trust's two selected stores succeeds and the other fails, retained evidence is labeled `Partial` rather than being attached to a denied scope. Findings are emitted separately for every purpose, so a management-store gap cannot hide an observed expired authentication certificate. Absence from a successfully observed purpose is recorded against a purpose subject; it is never labeled synthetic during a live run. A purpose that cannot be honestly attributed remains `NotApplicable`; it is not presented as an empty successful inventory and remains an explicit run-level gap.

## Privacy and safety boundary

Certificate identifiers, SHA-256 fingerprints of public certificate bytes, dates, store identities, and all certificate field values are **Restricted Diagnostic Evidence**. They may exist only inside the protected Assessment Record and report. The public projection contains counts and state summaries, never the identifiers or fingerprints.

WIN-PCInfo checks only `HasPrivateKey`, a presence flag. It never requests a private-key handle, key bytes, PFX/PKCS#12 data, export policy, enrollment action, repair, import, deletion, or trust-setting operation. It makes no change to a store or trust configuration.

Chain evaluation is deliberately offline. Intermediate-certificate downloads are disabled and revocation mode is `NoCheck`; therefore the result makes no claim about current online revocation status. Store access and chain building run in a coordinator-owned Job Object worker. The 30-second operation limit covers those potentially blocking Windows APIs, and the coordinator must prove the entire worker tree absent before accepting its output. The application source comments explain these boundaries beside the security-sensitive Windows APIs.

If the current process cannot be verified as the Assessment User, all six purpose scopes fail safely before a store is opened. An alternate administrator is never silently treated as that user.

Admission also refuses observations attributed to an unverified user context, successful candidates attached to denied or unexamined scopes, reversed validity intervals, and trusted or untrusted conclusions for an incomplete or unevaluated chain. Assessment observations neither configure signing trust nor admit a Package Recipient. Those separate setup workflows retain their own authority and validation requirements.

## Reproduce the synthetic validation

Use PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
pwsh -NoLogo -NoProfile -File ./tests/CertificateTrustPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/CertificateTrust.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/CertificateTrustNativeSource.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/CertificateTrustApplication.Tests.ps1
```

The twelve fixtures cover valid/trusted, expired, not-yet-valid, untrusted, incomplete-chain, multiple-candidate, inaccessible-store, absent-purpose, non-exportable-key, alternate-administrator, virtual-device, and malformed-certificate behavior. They contain scenario names only; they cannot inject a certificate, fingerprint, private key, path, command, network target, or store action. The application seam parses embedded public-only synthetic DER certificates to exercise EKU, date, fingerprint, and malformed-certificate behavior. Private-key presence is a key-free provider fact at that seam; the genuine ephemeral CNG `ExportPolicy=None` check lives only in test code and never enters the built application or evidence.

The locally built artifact is unsigned, so normal Preparation rejects it at the release-integrity gate. Synthetic fixture execution exists only to validate the closed application seam and does not create a Preview/Supported capability claim.
