# Assessment Contract validation

The Assessment Contract began with one safe synthetic observation. It now has two explicit profiles: the original one-field synthetic tracer and the eight-field Device and Windows readiness slice. The latter can collect after approval and produce a Protected Evidence Package, but it does not by itself mark a Product Capability delivered.

The release-owned [Assessment Contract Set](spec/releases/2.0.0-preview.1-contract-set.json) is the dictionary and rulebook for this slice. Its [schema](../schemas/assessment-contract-set.schema.json) requires every admitted Evidence Field Definition to state:

- why the field exists and which Product Capability it supports;
- the approved source and stable source identity;
- the value type and release-owned size and occurrence bounds;
- whether the value is Restricted Diagnostic Evidence;
- how prohibited material is omitted; and
- whether the definition or a value may appear in a public projection.

Only `field:device.os.display-name` is admitted in the original lifecycle profile, `profile:synthetic-contract-tracer`. Its source remains `SyntheticContractFixture`. The separate `profile:device-windows-readiness` owns `scope:device.windows-readiness` and exactly eight fields from the real standard-user collector. `Complete` coverage must contain the exact field set for the selected profile. A source-reported unknown field remains an explicit observation under `Partial`; a source-wide or payload failure produces no field observation and is carried by coverage, diagnostics, and the collector envelope. The schema admits honest `Synthetic`, `StandardUser`, and verified `LocalSystem` provenance.

## What validation does

The exported `Test-AssessmentContract` seam combines the [Draft 2020-12 Assessment Record schema](../schemas/assessment-record.schema.json) with project semantic checks. A schema proves shape. The semantic layer additionally proves that identities are unique, references resolve, dependency graphs are acyclic, field values satisfy their definitions, coverage agrees with diagnostics and the run outcome, and the reader understands every Required Contract Feature.

Before schema or semantic interpretation, the validator applies I-JSON-style safety rules:

- strict UTF-8 decoding;
- no duplicate property names;
- valid Unicode scalar pairs;
- interoperable integers from `-9007199254740991` through `9007199254740991` and finite floating-point numbers;
- at most 16 JSON levels, 32 KiB per document, 1 KiB per ordinary string, and the smaller field-specific bounds in the Contract Set.

Failures expose stable codes such as `CONTRACT.JSON_INVALID`, `CONTRACT.DUPLICATE_PROPERTY`, `CONTRACT.REQUIRED_FEATURE_UNSUPPORTED`, `CONTRACT.REFERENCE_INVALID`, `CONTRACT.COVERAGE_INCONSISTENT`, or `CONTRACT.PRIVACY_VIOLATION`. Parser exceptions, source values, and secret-like input are not copied into the public result.

## Why the states are separate

The synthetic record demonstrates five different kinds of state:

- `ObservedValue` says an approved source returned a value.
- `ProhibitedMaterialBlocked` says the Evidence Scope encountered material it was not allowed to retain.
- an Assessment Diagnostic records that collection problem with an approved marker.
- `Indeterminate` says a rule cannot reach an evidence-backed finding.
- `CompletedWithGaps` describes the overall synthetic run.

One state never substitutes for another. For example, a diagnostic is not an observation, `ObservedAbsent` is not a collection failure, and `Completed` is invalid while any Evidence Scope has a gap. `NotStarted` cannot contain post-start evidence; `Cancelled` and `TimedOut` require their matching coverage state; `IntegrityFailed` requires an integrity diagnostic; and `CleanupIncomplete` requires a cleanup diagnostic.

## Secret exclusion

Prohibited Secret Material never becomes an Evidence Field Definition. If a source encounters it, the value is omitted rather than retained, copied, redacted, encrypted, or hashed. The record may contain only the approved `prohibitedMaterial` marker (`encountered: true`, `retained: false`, `hashed: false`) and a linked diagnostic. A synthetic test also proves that a secret-bearing field identity is rejected and that its test-only value never appears in application output.

## Reproduce the public-safe test

Use stable PowerShell Core 7.6 or later 7.x:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/ContractValidator.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ContractSemanticMatrix.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AssessmentContractSet.Tests.ps1
```

The original `-ContractFixturePath` conformance seam still ends `NotStarted` and cannot enable collection. Device Readiness uses its separate closed scenario seam through the generated application; it produces typed synthetic samples and removes their protected packages before returning. Neither fixture can add elevation, network access, device mutation, authentication, or Azure activity.
