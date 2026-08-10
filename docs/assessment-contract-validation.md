# Assessment Contract validation

This tracer bullet proves that WIN-PCInfo can carry one safe synthetic observation through the same contracts that later collectors and reports will use. It does **not** collect information from your PC, create an Evidence Workspace, produce a Protected Evidence Package, or mark a Product Capability delivered.

The release-owned [Assessment Contract Set](spec/releases/2.0.0-preview.1-contract-set.json) is the dictionary and rulebook for this slice. Its [schema](../schemas/assessment-contract-set.schema.json) requires every admitted Evidence Field Definition to state:

- why the field exists and which Product Capability it supports;
- the approved source and stable source identity;
- the value type and release-owned size and occurrence bounds;
- whether the value is Restricted Diagnostic Evidence;
- how prohibited material is omitted; and
- whether the definition or a value may appear in a public projection.

Only `field:device.os.display-name` is admitted in this narrow slice. Its source is explicitly `SyntheticContractFixture`; it is not a Windows collector or a claim about the machine running the test.

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

One state never substitutes for another. For example, a diagnostic is not an observation, `ObservedAbsent` is not a collection failure, and `Completed` is invalid while any Evidence Scope has a gap.

## Secret exclusion

Prohibited Secret Material never becomes an Evidence Field Definition. If a source encounters it, the value is omitted rather than retained, copied, redacted, encrypted, or hashed. The record may contain only the approved `prohibitedMaterial` marker (`encountered: true`, `retained: false`, `hashed: false`) and a linked diagnostic. A synthetic test also proves that a secret-bearing field identity is rejected and that its test-only value never appears in application output.

## Reproduce the public-safe test

Use stable PowerShell Core 7.6 or later 7.x:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/ContractValidator.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ContractSemanticMatrix.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AssessmentContractSet.Tests.ps1
```

The generated-application cases use the existing synthetic preparation fixture and the hidden `-ContractFixturePath` test input. Even an accepted fixture ends with `NotStarted`, exit code `20`, `collectionStarted: false`, and `validationFixture: true`. The input cannot enable elevation, a collector, network access, device mutation, package creation, authentication, or Azure activity.
