# Issue 40 Evidence Scope tracer-bullet evidence

This is the public-safe validation projection for the Assessment Contract tracer bullet. It contains only release-owned definitions, schema identities, stable reason codes, deterministic build facts, and provably synthetic fixtures. It contains no real Assessment Record, device or user identifier, tenant or subscription fact, credential, network fact, Recipient Profile, Protected Evidence Package, or private diagnostic detail.

## End-to-end synthetic path

The generated application accepts `contract-positive.json` only after request validation, runtime eligibility, one complete Preparation Summary, and explicit synthetic preparation approval. It then emits one minimized `win-pcinfo.contract-validation` record:

- `accepted: true`
- `reasonCode: CONTRACT.ACCEPTED`
- `documentKind: AssessmentRecord`
- `schemaDraft: 2020-12`
- `validationFixture: true`

The terminal remains `NotStarted` / exit `20` with `SLICE.CONTRACT_VALIDATION_COMPLETE`, `collectionStarted: false`, and `validationFixture: true`. No collector, Evidence Workspace, Protected Evidence Package, report, network request, elevation, installation, Windows change, authentication, or Azure action is available from this path. This ticket therefore creates no delivered Product Capability or Preview/Supported claim.

## Contract and fixture matrix

The release Contract Set admits one field from `source:synthetic.windows.os`. Its Evidence Field Definition binds `CAP-0001`, purpose, stable source identity, `String` type, Restricted Diagnostic Evidence sensitivity, 256-byte/one-per-subject bounds, prohibited-material omission, public definition eligibility, and non-public value eligibility. It separately declares `scope:synthetic.device.os`, binds that scope to the field and approved collector, and requires the record to report the exact release-declared scope set.

The positive fixture carries a French locale and multilingual value through Observation Provenance, one `ObservedValue` Assessment Observation, one `ProhibitedMaterialBlocked` Evidence Coverage State, an approved omission-only diagnostic marker, one Collector Result Envelope, an `Indeterminate` Assessment Finding, a Tenant-side Discovery Task, the canonical Assessment Record, and the release Contract Set.

Generated-application validation covers:

| Fixture class | Stable result |
| --- | --- |
| positive multilingual and non-English locale | `CONTRACT.ACCEPTED` |
| incomplete required shape | `CONTRACT.SCHEMA_INVALID` |
| malformed JSON | `CONTRACT.JSON_INVALID` |
| invalid UTF-8 / invalid Unicode | `CONTRACT.UTF8_INVALID` / `CONTRACT.UNICODE_INVALID` |
| duplicate property | `CONTRACT.DUPLICATE_PROPERTY` |
| oversize document / excessive depth / unsafe number / field bound | `CONTRACT.SIZE_EXCEEDED` / `CONTRACT.DEPTH_EXCEEDED` / `CONTRACT.NUMBER_INVALID` / `CONTRACT.FIELD_BOUND_EXCEEDED` |
| incompatible major / unknown Required Contract Feature | `CONTRACT.VERSION_INCOMPATIBLE` / `CONTRACT.REQUIRED_FEATURE_UNSUPPORTED` |
| dangling or ambiguous references / envelope mismatch | `CONTRACT.REFERENCE_INVALID` / `CONTRACT.REFERENCE_AMBIGUOUS` / `CONTRACT.ENVELOPE_INCONSISTENT` |
| cyclic recommendation dependency | `CONTRACT.GRAPH_INVALID` |
| coverage, observation, finding, or run-state conflict | the corresponding stable `CONTRACT.*_INCONSISTENT` reason |
| undeclared/omitted scope, orphan diagnostic, or incomplete envelope coverage | `CONTRACT.COVERAGE_INCONSISTENT` |
| envelope collector or subject not bound to its observation provenance | `CONTRACT.ENVELOPE_INCONSISTENT` |
| prohibited secret-like field | `CONTRACT.PRIVACY_VIOLATION`, with the synthetic value absent from application output |

Every fixture is synthetic. The positive record uses only package-local synthetic identities and fixed year-2000 timestamps. Invalid cases are either small tracked lexical fixtures or deterministic mutations of that positive record under `.test-output`; no native Windows or assessment source is read.

## Draft 2020-12 and semantic validation

Both public schemas declare `https://json-schema.org/draft/2020-12/schema`. `AssessmentContractSet.Tests.ps1` validates the actual Contract Set and positive record through PowerShell `Test-Json`, then runs an applicable `prefixItems` accept/reject dialect probe. This is evidence for the Draft 2020-12 behavior used by this Contract Set, not a claim that WIN-PCInfo republishes or reruns the complete upstream JSON Schema conformance suite.

After schema acceptance, the exported validator checks contract major compatibility, Required Contract Features, privacy, release field and scope definitions, field bounds, unique identities, exact references, Collector Result Envelope closure, Evidence Coverage State closure, state combinations, and recommendation graph validity. `NotStarted`, `Cancelled`, `TimedOut`, `IntegrityFailed`, and `CleanupIncomplete` each have a separate evidence/diagnostic consistency rule. Schema errors and semantic errors remain distinct.

## Secret Exclusion and public output

The admitted field catalog contains no secret-bearing field. An approved `prohibitedMaterial` marker records only `encountered: true`, `retained: false`, and `hashed: false`; it carries no value or digest. The negative secret-like fixture is rejected before ordinary reference interpretation, and tests prove its test-only value does not enter stdout. Public terminal and validation records contain only stable codes and booleans, never parser text or source content.

## Deterministic build evidence

- Build contract: `win-pcinfo.build-evidence/1.0.0`
- Generated application SHA-256: `a2640ce1ff092ff4d018d08f6104824b3ca9c00c79eae725eaab876328da3a3e`
- Representation: UTF-8 with BOM and CRLF
- Modular source inputs: 8
- Application-manifest resources: 15
- Contract Set SHA-256: `51d1fe45086cab58f629c7ffbb82b0d5233982e850e4312c91e6139166deccf6`
- Contract Set schema SHA-256: `df40852930596cb8f3d62021148c82e3f465b8aa9f1206fdcafa02acae086def`
- Assessment Record schema SHA-256: `1d98e45eaad47b9b96feae0a51949ebbd38d3b468829f781dc11ada30afdf5ac`
- Positive fixture SHA-256: `5cf6726daa5027749ffec8d1a6396a48f86d35bcced00a281c6a1cbf21ef6b48`
- Reproduction: `pwsh -NoLogo -NoProfile -File ./build/Build.ps1`

The build embeds the canonical UTF-8/LF Contract Set and Assessment Record schema with their SHA-256 identities and binds both schemas, the Contract Set, all modular source, and the build resources into the application manifest. Runtime artifact trust executes before contract validation. Embedded digests detect resource substitution inside that trusted boundary; modified code and modified digests cannot self-assert publisher trust.

## Acceptance trace

- Evidence Field Definitions, source, vocabularies, and schema routing: `docs/spec/releases/2.0.0-preview.1-contract-set.json`, `schemas/assessment-contract-set.schema.json`, and `tests/AssessmentContractSet.Tests.ps1`.
- Canonical Assessment Record structure: `schemas/assessment-record.schema.json` and `tests/fixtures/contract-positive.json`.
- I-JSON-style lexical gates and semantic validator: `src/ContractValidator.ps1` and `tests/ContractValidator.Tests.ps1`.
- State, reference, envelope, graph, and incomplete-record matrix: `tests/ContractSemanticMatrix.Tests.ps1`.
- Generated application and no-collection boundary: `src/ApplicationHeader.ps1`, `src/ApplicationMain.ps1`, `src/LaunchEngine.ps1`, and `src/Preparation.ps1`.
- Deterministic resource binding: `build/Build.ps1`, `tests/BuildDeterminism.Tests.ps1`, and `tests/PreparationSummary.Tests.ps1`.
- Beginner documentation: `README.md` and `docs/assessment-contract-validation.md`.
