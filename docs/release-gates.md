# Automated release gates and evidence manifests

This page teaches the maintainer-only release-gate workflow. It does not create a Preview or Supported claim, and it does not mark `CAP-0030`, `CAP-0026`, or `CAP-0027` delivered.

WIN-PCInfo still does not publish a release, sign an artifact, contact Azure, or treat a successful local assessment as Release Evidence.

## What this slice does

The generated application can evaluate a **synthetic** evidence pack against the frozen 2.0.0-preview.1 gate contract. The pack names the exact unsigned generated-content identity, resource digests, source revision, runtime, architecture, definitions, schemas, catalogs, toolchain, and quality-budget version.

The gate then produces three public, identifier-free records:

1. a **Release Evidence Manifest** with one controlled result for every required gate
2. a **Preview Capability Matrix** and support snapshots derived from the frozen capability ledger and that evidence
3. **promotion decision inputs** that say whether unsigned content is qualified, whether a later final artifact is qualified, and why publication is still denied

The public records never include a workspace path, Azure identifier, credential, recipient fingerprint, Assessment Record, or other restricted material.

## Prerequisites

- An already installed stable PowerShell 7.6 or later 7.x host.
- A synthetic evidence pack that satisfies `schemas/release-evidence-pack.schema.json`.
- The reviewed capability ledger and release definition in this repository or in an authenticated portable package.

This slice does not download tools and does not require elevation.

## Safety reasoning

The threat is publishing a Preview or Supported claim from missing, failed, stale, waived, or private evidence, or treating an unsigned generated script as the later signed package. The mechanism is a closed result set, exact-candidate binding, and a public projection that cannot carry identifiers. The trust assumption is that the pack is synthetic and that the running generated application is the candidate being bound. Safe failure is `NotStarted` when the pack is unreadable or private, and an evaluated denial when the evidence is complete enough to judge but not enough to qualify.

## Controlled evidence results

Every required validation records exactly one of these results, with a stable reason and the claims it affects: Pass, ProductFail, InfrastructureInconclusive, NotRun, Expired, and Invalidated.

- **Pass** — the exact candidate satisfied that gate.
- **ProductFail** — the candidate failed the product contract. The failure cannot be retried into a pass.
- **InfrastructureInconclusive** — independent evidence shows the validation environment failed. One replacement attempt is allowed. The result cannot be averaged with a Pass.
- **NotRun** — the gate was not executed. Missing evidence is treated the same way.
- **Expired** — the result is older than the freshness window for its class.
- **Invalidated** — a later relevant change made the result unusable.

Missing, failed, stale, invalidated, wrong-candidate, or unsupported evidence blocks the applicable claim. Results cannot be averaged or waived.

## Two identities

Pre-signing gates bind the **unsigned generated-content identity**. That is the exact bytes of the generated `WIN-PCInfo.ps1` candidate.

Later Final Artifact Validation binds a **distinct final distributable identity**, usually the unsigned portable zip or a later Authenticode-signed package. The final identity must prove it was derived from exactly the already-qualified generated content. Checksums of the generated script are not the signed package, and an Attested Preview cannot satisfy the Stable signing gate.

## Quality budget

The frozen budget version is `1.0.0`. Preview requires three clean measurements. Binding limits are immediately enforced:

- first structured progress within 5 seconds
- no active-work heartbeat gap longer than 10 seconds
- cancellation acknowledgement within 2 seconds

These ceilings are provisional until a later ticket versions them, but they are still enforced here:

- 30-minute normal profile completion and a 60-minute absolute deadline
- 2-minute cancellation cleanup
- 768 MiB peak private memory and 512 MiB peak working set
- 256 MiB Evidence Workspace, 100 MiB package, and 25 MiB report

A real device assessment never reports that the operator “failed the benchmark.” Ordinary runs may show their own duration and size locally.

## How to run the gate

From a repository checkout, after `build/Build.ps1`:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow EvaluateReleaseGates -ReleaseEvidencePackPath ./tests/fixtures/release-evidence-pack-complete-presigning.json
```

A readable synthetic pack completes the evaluation and prints the manifest and matrix. Publication stays unauthorized because the pack is synthetic and this slice has no release-publication authority.

A missing path, a non-synthetic pack, a secret, a real identifier, a Terraform plan or state marker, a raw log, or a local user path returns `NotStarted` and writes no derived workspace residue.

## What the matrix is allowed to say

The matrix is generated from the frozen ledger snapshot plus the evidence results. It is never a hand-edited strongest-case table.

- A scenario row can be `Preview` only when every applicable gate for that claim is `Pass` and still fresh.
- `Supported` is not a Preview.1 outcome.
- A capability that depends on a weaker row cannot inherit a stronger state.
- Completing this workflow does not change delivery disposition in the ledger.

## Public versus private

Public and shareable:

- this page
- the gate, pack, manifest, and matrix schemas
- the release-owned policy
- synthetic fixtures under `tests/fixtures/release-evidence-pack-*.json`
- sanitized evaluation records

Private and never committed:

- real validation records
- Assessment Records and Protected Evidence Packages
- Azure, tenant, subscription, gallery, or host-network identifiers
- Terraform plans, state, locks, caches, and logs
- credentials, tokens, and recipient fingerprints

Prohibited Secret Material is never a template.

## Limitations

This slice does not publish, sign, or promote a release. It does not run Client VM Validation, measure a live quality-budget workload, or accept a real private evidence file. Later tickets must keep the same public/private boundary.

See the [Consultant Workbench](consultant-workbench.md) for the rest of the implemented product path.
