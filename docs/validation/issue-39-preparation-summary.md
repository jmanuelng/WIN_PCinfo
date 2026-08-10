# Issue 39 Preparation Summary evidence

This is the public-safe validation projection for the Preparation Summary tracer bullet. It contains only tracked synthetic fixture names, stable contract values, governed capability identifiers, and reproducible artifact facts. It contains no assessment evidence, machine identity, account, tenant, subscription, Azure resource, credential, private network fact, or private diagnostic data.

## Automated preparation matrix

`pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1` passed all eight test files:

- Validation-only guided and automation launches resolved equivalent input to the same request digest and immutable plan digest. Each emitted exactly one `win-pcinfo.preparation-summary`; separate accepted and declined decisions could not alter the plan.
- The Comprehensive Local Assessment exposed all 29 release-enabled Product Capabilities: 15 explicitly selected entries, dependency-added `CAP-0015`, and 13 release-enabled product obligations. Every entry retained its name, disposition, and governed dependencies.
- Local Only planned zero assessment requests. Microsoft Connectivity Enabled disclosed two bounded request classes—DNS and TCP/TLS/HTTP—without making a request. Both validated against the public Assessment Run Request and Preparation Plan schemas.
- Invalid automation covered malformed types, unknown security-sensitive fields, unsupported contract and network values, both network-envelope conflicts, absent elevation authority, attempted installation authority, and `RunAnyway`. All stopped at Request Validation with `NotStarted` / `20` and `collectionStarted: false`.
- Active preparation rejects UNC syntax before path access and tests local fixed-volume type before readiness or free-space access. It resolves and freezes the absolute destination, required free disk, actual Local Package Protector availability, the recipient choice, and the no-Windows-Feature-change boundary through metadata-only checks. Missing critical prerequisites emitted the trusted summary and stopped as `PREPARATION.PREREQUISITE_UNRESOLVED`. Unsigned artifact trust, synthetic integrity failure, and byte-level corruption of the real embedded definition all stopped as `PREPARATION.INTEGRITY_FAILED`; none had an override path.
- Runtime and preparation fixtures remained validation-only, created no working-directory entry, preserved a pre-existing sentinel byte-for-byte, and could not cross into collection.
- The generated application ran under Windows PowerShell 5.1 and stopped at the established runtime boundary. Its normal PowerShell 7 path performed no assessment network request, elevation, install, agreement, Windows Feature change, workspace creation, or collection before approval.
- Two builds to different output directories produced identical application bytes with UTF-8 BOM and CRLF. Build evidence recorded all seven modular sources, the build tool, both public schemas, and SHA-256 identities for all three governing preparation resources.

## Sanitized contract projection

The tracked synthetic requests and public-safe preparation fixture produced these stable identities. The accepted terminal is intentionally validation-only; this ticket makes no collection or capability-delivery claim.

| Fixture | Network behavior | Planned request classes | Request SHA-256 | Plan SHA-256 | Accepted terminal reason |
| --- | --- | ---: | --- | --- | --- |
| `automation-request.json` | `LocalOnly` | 0 | `090ef945d67afbd3400a7d242e6931f9dc1fbbee8ae25ddf1315aa6010afa1c2` | `880873ac7dc96129a079a9d567a30e04d42cc14960e0cef7e0334aa9b45a92ae` | `PREPARATION.VALIDATION_ONLY` |
| `automation-request-connectivity.json` | `MicrosoftConnectivityEnabled` | 2 | `5a5ac1ca9a6f1c8840c88492274c8684e1f1e4eb5b466bac19bc98f740adbe2e` | `026ff7b7abfa8f63fb775546fdb96c518fee439b036fcb4234115e8610897ac2` | `PREPARATION.VALIDATION_ONLY` |

Every successful preparation sequence emitted request-validation progress, runtime-validation progress, one Preparation Summary containing one immutable plan, and one `NotStarted` terminal. The summary disclosed scope, privilege, dependencies, estimates, network behavior, protected output, fixed recipient choice, Windows Feature behavior, limitations, later side effects, cleanup, and the exact approval instruction exactly once.

## Deterministic definition and build evidence

- Build contract: `win-pcinfo.build-evidence/1.0.0`
- Generated application SHA-256: `b619b8d609e7449743485973f688037a1eae074ca3e72e715b0187f2ca4256fc`
- Representation: UTF-8 with BOM and CRLF
- Governing release-definition SHA-256: `0d00048b445d803504813a34fbd3af4693c4d003d1a0e981651e11d4d8281913`
- Governing capability-ledger SHA-256: `295997eb8ed1bd4915b6799e532b51a6f75d392bd11b3ec2bde7f82c41a93039`
- Governing preparation-operation SHA-256: `c8541442269fd947c7f19513ad4ffcc9ed0e6bb2808e797f5720ef357e534fd4`
- Reproduction: `pwsh -NoLogo -NoProfile -File ./build/Build.ps1`

The build resolves the profile and capability dependencies from the release definition, capability ledger, and release-bound operation manifest. It binds all modular source, the build tool, and both public schemas into one application manifest, then embeds the normalized definition and a separate definition digest. Runtime checks the embedded bytes and manifest digest before using them. Changing a request changes its request and plan digests; changing governed definition or application-resource data changes the generated artifact and plan digest.

## Security-sensitive change trace

This is a **Security-sensitive Change** because preparation freezes Windows privilege, process, cryptographic package-protection, privacy, network, and Azure authority boundaries. It is traced to the public product threat model and security acceptance criteria in issue #12, the parent implementation specification #37, and issue #39.

- Unknown or conflicting automation fields fail rather than being ignored as if a newer safety constraint had applied.
- Approval is separate from the versioned request. Guided mode reads the exact `APPROVE` token after the summary; automation requires `-AcceptPreparation` in addition to the request. Absence or any other guided input declines.
- The plan admits no arbitrary command, network storage, install, agreement, persistent Windows change, authenticated tenant access, automatic telemetry, or Azure control-plane action.
- Local package protection and the zero-recipient choice are fixed before collection. A later recipient change requires a new governed request and plan.
- Synthetic fixtures can only reduce readiness or trust. An accepted validation fixture ends as `PREPARATION.VALIDATION_ONLY`, preserving the no-collector boundary for future slices.
- Digest, manifest, signature, attestation, substitution, and governing-resource failures have no Verification Override or **Run Anyway** route.

## Acceptance trace

- Release-derived complete scope and deterministic provenance: `build/Build.ps1`, `src/Preparation.ps1`, and `tests/BuildDeterminism.Tests.ps1`.
- Strict request and network-authority validation: `src/EntryAdapters.ps1`, `schemas/assessment-run-request.schema.json`, and `tests/RequestValidation.Tests.ps1`.
- Immutable plan, one complete summary, separate approval, and terminal binding: `src/Preparation.ps1`, `src/LaunchEngine.ps1`, `schemas/preparation-plan.schema.json`, and `tests/PreparationSummary.Tests.ps1`.
- Missing-prerequisite, integrity, validation-only, and no-side-effect gates: `tests/PreparationFailure.Tests.ps1` and `tests/RuntimeMatrix.Tests.ps1`.
- Beginner explanation and exact invocation: `README.md` and `docs/preparation-summary.md`.
