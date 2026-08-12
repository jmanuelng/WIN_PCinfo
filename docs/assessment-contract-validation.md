# Assessment Contract validation

The Assessment Contract began with one safe synthetic observation. Contract Set 1.2 keeps the four historical profiles unchanged and adds `profile:device-firmware-and-identity-readiness`. The additive profile combines the existing 25 Device/Firmware fields with eleven bounded identity and enrollment fields across a separate User subject and four new Evidence Scopes. The current slice can collect after approval and produce a Protected Evidence Package, but it does not by itself mark a Product Capability delivered.

The release-owned [Assessment Contract Set](spec/releases/2.0.0-preview.1-contract-set.json) is the dictionary and rulebook for this slice. Its [schema](../schemas/assessment-contract-set.schema.json) requires every admitted Evidence Field Definition to state:

- why the field exists and which Product Capability it supports;
- the approved source and stable source identity;
- the value type and release-owned size and occurrence bounds;
- whether the value is Restricted Diagnostic Evidence;
- how prohibited material is omitted; and
- whether the definition or a value may appear in a public projection.

Only `field:device.os.display-name` is admitted in the original lifecycle profile, `profile:synthetic-contract-tracer`. Its source remains `SyntheticContractFixture`. `profile:device-windows-readiness` retains the original eight-field scope; `profile:device-windows-context` retains its 17-field scope; and `profile:device-and-firmware-readiness` retains the existing Device, firmware, Secure Boot, and TPM scopes. Contract Set 1.2 adds distinct Assessment User Context, registration, work-or-school, and LocalSystem MDM-provider scopes without redefining any historical `Complete` claim. A successful source may explicitly report an unknown or absent field; inaccessible or partial collection retains a reason and diagnostic. A source-wide, malformed, denied, or prohibited-material failure fabricates no field observation and is carried by coverage, diagnostics, and the collector envelope. The schema admits honest `Synthetic`, `StandardUser`, `Administrator`, and verified `LocalSystem` provenance.

## What validation does

The exported `Test-AssessmentContract` seam combines the [Draft 2020-12 Assessment Record schema](../schemas/assessment-record.schema.json) with project semantic checks. A schema proves shape. The semantic layer additionally proves that identities are unique, references resolve, dependency graphs are acyclic, field values satisfy their definitions, coverage agrees with diagnostics and the run outcome, and the reader understands every Required Contract Feature.

Before schema or semantic interpretation, the validator applies I-JSON-style safety rules:

- strict UTF-8 decoding;
- no duplicate property names;
- valid Unicode scalar pairs;
- interoperable integers from `-9007199254740991` through `9007199254740991` and finite floating-point numbers;
- at most 16 JSON levels, 64 KiB per Contract Set 1.2 document, 1 KiB per ordinary string, and the smaller field-specific bounds in the Contract Set.

Failures expose stable codes such as `CONTRACT.JSON_INVALID`, `CONTRACT.DUPLICATE_PROPERTY`, `CONTRACT.REQUIRED_FEATURE_UNSUPPORTED`, `CONTRACT.REFERENCE_INVALID`, `CONTRACT.COVERAGE_INCONSISTENT`, or `CONTRACT.PRIVACY_VIOLATION`. Parser exceptions, source values, and secret-like input are not copied into the public result.

## Why the states are separate

The synthetic record demonstrates five different kinds of state:

- `ObservedValue` says an approved source returned a value.
- `ProhibitedMaterialBlocked` says the Evidence Scope encountered material it was not allowed to retain.
- an Assessment Diagnostic records that collection problem with an approved marker.
- `Indeterminate` says a rule cannot reach an evidence-backed finding.
- `CompletedWithGaps` describes the overall synthetic run.

One state never substitutes for another. For example, a diagnostic is not an observation, `ObservedAbsent` is not a collection failure, and `Completed` is invalid while any Evidence Scope has a gap. `NotStarted` cannot contain post-start evidence; `Cancelled` and `TimedOut` require their matching coverage state; `IntegrityFailed` requires an integrity diagnostic; and `CleanupIncomplete` requires a cleanup diagnostic.

Absence is how the contract represents a rule that has not been attempted. The device-context source pass therefore contains no findings and omits the not-yet-run virtualization and form classifiers. After that pass is accepted, the classifiers append their derived observations; only then do the four bounded Rule Evaluations append their findings. `Indeterminate` is reserved for a rule that actually ran but lacked enough admitted evidence.

Evidence Coverage is aggregate scope state, so the Windows collector and both classifier envelopes may bind the same final coverage identity while each owns a disjoint observation set. This does not merge their provenance: every derived observation names the classifier identity and actual classifier completion time, and the Windows envelope remains bound only to the observations returned by its completed attempt.

## Secret exclusion

Prohibited Secret Material never becomes an Evidence Field Definition. If a source encounters it, the value is omitted rather than retained, copied, redacted, encrypted, or hashed. The record may contain only the approved `prohibitedMaterial` marker (`encountered: true`, `retained: false`, `hashed: false`) and a linked diagnostic. A synthetic test also proves that a secret-bearing field identity is rejected and that its test-only value never appears in application output.

## Reproduce the public-safe test

Use stable PowerShell Core 7.6 or later 7.x:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/ContractValidator.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ContractSemanticMatrix.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AssessmentContractSet.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/IdentityEnrollmentRecord.Tests.ps1
```

The original `-ContractFixturePath` conformance seam still ends `NotStarted` and cannot enable collection. Device context, firmware, and the thirteen identity/enrollment states use separate closed scenario seams through the generated application and immutable plan. These produce typed synthetic samples and remove their protected packages before returning. No fixture can provide an account, tenant, domain, device identifier, arbitrary elevation, network access, device mutation, authentication, or Azure activity.
