# WIN-PCInfo v2 capability ledger

This document is the public rulebook for the WIN-PCInfo v2 capability ledger. It explains how product scope is inventoried, classified, prioritized, selected for previews, and traced into release evidence.

The rulebook is intentionally separate from local agent instructions. A contributor or automation session should be able to discover and apply it from a fresh clone.

The governing decisions are [Define the v2 capability taxonomy and priority ledger](https://github.com/jmanuelng/WIN_PCinfo/issues/8), [Define support tiers and release-evidence thresholds](https://github.com/jmanuelng/WIN_PCinfo/issues/9), [Define modular architecture and dependency policy](https://github.com/jmanuelng/WIN_PCinfo/issues/10), [Define measurable product quality budgets](https://github.com/jmanuelng/WIN_PCinfo/issues/15), and [Reconcile capability-ledger support dependencies and operability obligations](https://github.com/jmanuelng/WIN_PCinfo/issues/29), part of the [WIN-PCInfo v2 product and release specification map](https://github.com/jmanuelng/WIN_PCinfo/issues/1).

## Why the ledger exists

The legacy script contains useful outcomes as well as unsafe or obsolete mechanics. The v2 design also introduces new outcomes. The ledger keeps both histories visible so preview and Stable scope can be chosen without silently losing a requirement.

The ledger is not a line-by-line source inventory or an implementation backlog. It records meaningful product outcomes and the components that make those outcomes possible.

## Core model

### Product Capability

A Product Capability is a user-observable assessment, interpretation, reporting, or operating outcome.

- Its immutable ID has the form `CAP-####`.
- Its name and classifications may change without changing the ID.
- An ID is never reused.
- A targeted or delivered capability links to at least one Capability Component.
- A removed, deferred, or outside-boundary capability may have no v2 component only when its source and rationale remain recorded.

### Capability Component

A Capability Component is a typed element that contributes to one or more Product Capabilities.

- Its immutable ID has the form `CMP-####`.
- Its name and classifications may change without changing the ID.
- An ID is never reused.
- Every component links to at least one capability.
- A shared component is recorded once and linked to every capability it supports.
- Components are not prioritized as though they were complete user outcomes.

The relationship between capabilities and components is many-to-many.

When one old record combines meanings that later decisions separate, its ID stays with the compatible core meaning and each newly separated meaning receives the next unused ID. The original ID is not reassigned to an unrelated outcome, and frozen historical release snapshots are never rewritten.

## Capability Areas

Every Product Capability has exactly one owning Capability Area and may link to related areas. The owning area determines where the capability is managed; related areas preserve cross-domain context without duplicating the record.

The canonical areas are:

1. Device and Windows Readiness
2. Identity, Enrollment, and Autopilot
3. Management and Policy
4. Endpoint Security
5. Software and Application Migration
6. Network, DNS, and Service Connectivity
7. Certificates and Trust
8. Assessment Run and Execution Profiles
9. Evidence, Findings, and Reporting
10. Privacy and Safe Sharing
11. User Experience, Accessibility, and Localization
12. Distribution, Updates, and Supply Chain
13. Documentation, Feedback, and Maintenance

Specialized tools, event sources, and diagnostic packages are components linked to the outcomes they serve, not independent areas.

## Component kinds

Each Capability Component has exactly one controlled kind:

| Kind | Meaning |
| --- | --- |
| Collector | Obtains evidence, including bounded diagnostic-tool invocation. |
| Rule | Interprets evidence into states, findings, or guidance. |
| Output | Produces a report, view, export, manifest, or sharing artifact. |
| Workflow | Defines an operator or automation interaction across an Assessment Run. |
| Catalog | Supplies versioned reference data to collectors or rules. |
| Control | Enforces a cross-cutting safety, privacy, integrity, cleanup, or release gate. |
| Documentation | Teaches a user or contributor how to understand or use a capability. |

Adding a kind is a ledger-schema change. A generic `Other` kind is not permitted.

## Independent classification axes

Do not combine history, scope, and scheduling into one status.

### Capability Lineage

- `legacy-derived`: originated in meaningful observable legacy behavior or a documented legacy claim.
- `v2-new`: introduced by the v2 baseline or a later governing decision.

### Migration Disposition

This field applies only to legacy-derived capabilities.

- `retain-outcome`: preserve the same user-visible purpose, regardless of rewritten code.
- `improve-outcome`: preserve the purpose while materially expanding quality, safety, clarity, or coverage.
- `replace-behavior`: serve the underlying need through a materially different workflow, evidence source, or output.
- `intentionally-remove`: provide no v2 equivalent because the behavior is unsafe, misleading, obsolete, or outside scope.

For example, clear-text Wi-Fi-key export is intentionally removed. Unsafe `Win32_Product` inventory is replaced by safer inventory sources rather than treating software inventory itself as removed.

### Delivery Disposition

- `unscheduled`: recognized but not assigned to a release.
- `release-targeted`: assigned to a named release but not yet delivered.
- `delivered`: implemented for the named release; this alone does not establish a support claim.
- `deferred`: deliberately postponed pending a later decision or release.
- `outside-v2-boundary`: explicitly excluded from v2.

### Capability Obligation

- `public-build-invariant`: required in every Preview and Stable Release, including applicable safety, privacy, consent, cleanup, provenance, and honest-failure behavior.
- `stable-required`: must be delivered and validated before Stable `2.0.0`.
- `preview-selectable`: eligible for an end-to-end Preview slice that tests value, design, or validation assumptions before Stable commitment.
- `later-candidate`: recorded and traceable but not required for Stable `2.0.0`.

The named release target belongs to Delivery Disposition, not Capability Obligation.

## Required operability and later accessibility

Every public build has an English, left-to-right product interface. Two minimum behaviors remain mandatory:

- **Language-neutral Execution** means the English interface and assessment logic work on every supported Windows display language and locale. The product preserves Unicode evidence, writes explicit UTF-8 artifacts, uses stable culture-independent codes and JSON meanings, and does not interpret translated Windows display text as authoritative data.
- **Basic Primary-path Operability** means a user can launch, approve preparation, follow progress, cancel, understand the terminal outcome, find the Protected Evidence Package, and navigate the report by keyboard. Primary controls are understandable, focus is visible, keyboard traps are prohibited, and color is not the only way meaning is communicated.

These behaviors do not claim formal accessibility conformance. A formal WCAG, WCAG2ICT, assistive-technology, or comparable conformance program is a distinct Later Candidate. It may be designed and validated in a later release, but its absence does not block v2 Preview or Stable publication when the mandatory baseline passes.

This split keeps the original public-build obligation focused on safe, dependable operation across Windows languages and locales. It also avoids promising a formal accessibility standard that the project has not selected or validated.

## Canonical data

The canonical machine-readable ledger is the tracked `docs/spec/capability-ledger.json` file. The initial inventory task creates and populates it; this rulebook remains authoritative for field meaning.

The JSON root contains:

- `schemaVersion`
- `capabilities`
- `components`

### Product Capability record

An initial record contains:

- `id`
- `name`
- `outcome`
- `owningArea`
- `relatedAreas`
- `lineage`
- `sourceReferences`
- `migrationDisposition` when legacy-derived
- `obligation`
- `deliveryDisposition`
- `targetRelease` when release-targeted or delivered
- `componentIds`
- `dependsOnCapabilityIds`
- `rationale`
- `governingReferences`

Acceptance criteria, support claims, and evidence references become required as the record matures.

### Capability Component record

An initial record contains:

- `id`
- `name`
- `kind`
- `purpose`
- `capabilityIds`
- `sourceReferences`

When a linked capability is release-targeted, the component also records or links:

- required execution context and privileges
- network activity and device side effects
- inputs and evidence sensitivity
- outputs or output-schema references
- expected unavailable, partial, timed-out, cancelled, and failed behavior
- dependencies
- documentation and verification plans

Documentation and verification evidence replace their plans as applicable before supported release claims are made.

## Runtime and portable-package boundary

WIN-PCInfo is portable application code, but PowerShell is an external prerequisite. This distinction keeps first-run behavior predictable:

- A supported execution attempt uses an already installed stable PowerShell `7.6` or later `7.x` runtime. PowerShell `8` or a later major version requires a new compatibility decision.
- WIN-PCInfo never installs, upgrades, downgrades, repairs, or changes PowerShell. If no eligible runtime is installed, execution ends before collection, network access, elevation, or device changes and explains how to obtain PowerShell from Microsoft's official instructions before retrying.
- A small Windows PowerShell prerequisite bootstrap may locate and launch an eligible `pwsh` host or provide the same retry guidance. It is not a second assessment engine and performs no collection.
- Before an Assessment Run begins, a local Runtime Compatibility Check verifies the active host's edition, stable version, architecture, required commands and .NET behavior, trusted built-in module and validator provenance, encoding, cryptography, module loading, and process-control behavior. Passing this check permits an execution attempt; it does not by itself establish a Supported Scenario or Release Evidence.
- A missing optional mechanism makes only its affected capability unavailable. A missing safety-critical mechanism stops the run as `NotStarted` with a stable reason and practical next step.

The tracked source remains modular so contributors can understand and test it. A deterministic build assembles that source into one primary generated PowerShell application. Developers do not hand-edit the generated application. The exact generated candidate—not an earlier source-only execution—is the artifact that proceeds through release validation and, when applicable, trusted Authenticode signing.

Schemas, catalogs, presentation resources, approved helpers, and other governing non-PowerShell resources may remain separate package files. The primary application authenticates them through a release-bound manifest of normalized identities and exact digests before use. A missing or modified governing resource stops the run; adjacency to an authentic application is not enough to make a resource trusted. An Attested Preview may use the separately governed unsigned fallback, but it must authenticate and attest the same generated candidate and supporting-resource manifest.

## Coverage and progressive traceability

Initial inventory covers:

- meaningful legacy behaviors, outputs, workflows, risks, and documented claims
- normative requirements in the approved v2 design baseline
- later Wayfinder decisions that add, change, defer, or remove scope

Each meaningful item maps to a Product Capability or Capability Component, or retains an explicit removed, deferred, or excluded rationale. Exact source-line classification is not required. Prefer durable references such as a function, output, design-brief section, or governing issue over line numbers that will drift.

Traceability grows with the strength of the product claim:

1. Every record starts with identity, classification, relationships, source references, and current disposition.
2. Release-targeted capabilities add operational details and verification plans.
3. Delivered or supported capabilities link applicable automated checks, Client VM Validation, Community Validation Runs, and Release Evidence.

Lightweight validation checks required fields for the record's maturity, unique IDs, valid references, reciprocal capability-component links, valid enum values, no self-dependencies, and an acyclic capability-dependency graph. It also verifies that mandatory operability and formal accessibility have distinct identities and that release promotion does not make Community Validation an unconditional dependency. It does not attempt to prove line-by-line coverage or the truth of Release Evidence.

## Scenario-dependent validation evidence

Controlled Client VM Validation is the normal evidence source when a named scenario can be reproduced credibly in the Azure validation lab. Community Validation is used only when material behavior cannot be established there, such as physical hardware, OEM or firmware behavior, battery or peripheral behavior, a real third-party security product, or externally managed policy.

Community Validation is therefore not a dependency of every Preview slice, every release promotion, or every support claim. The release-promotion gate always checks the universal gates and then checks only the validation sources applicable to the claim being made. Informal feedback and popularity never substitute for a qualifying validation record.

The Community Validation capability remains Stable-required so the privacy-safe workflow is available by Stable `2.0.0` for claims that need it. That obligation governs delivery of the workflow; it does not require every scenario or earlier Preview slice to use the workflow.

This conditional model keeps small Preview slices genuinely small while preserving stronger real-device evidence wherever a virtual client would be misleading.

## Selecting Preview scope

Each Preview slice:

- states one explicit learning or validation objective
- delivers one or more end-to-end Product Capabilities rather than disconnected components
- includes all dependency capabilities and every applicable public-build invariant
- prefers the smallest coherent slice that reduces the most important uncertainty
- records omitted related capabilities as later targets, deferred items, or explicit non-goals

The release-specific Preview Capability Matrix is generated from the ledger snapshot.

## Release definitions

A named release target has a human-readable and machine-readable definition under `docs/spec/releases/`. The capability ledger records which Product Capabilities are `release-targeted` and names their `targetRelease`; the release definition owns the complete objective, Assessment Profile, scenario-claim templates, explicit deferrals, boundaries, and required Release Evidence.

The first target is [WIN-PCInfo 2.0.0-preview.1](./releases/2.0.0-preview.1.md), with its [machine-readable release definition](./releases/2.0.0-preview.1.json). A release target is a planning commitment, not proof that a capability is implemented, validated, Preview, or Supported.

Release-bound supporting catalogs and optional external enrichment sources have public governance rules when their classification or interpretation can materially affect an assessment. The current rulebooks are [Software Recognition Catalog governance](./software-recognition-catalog.md) and [WinGet package-availability enrichment](./winget-package-availability.md).

## Freezing Stable scope

Before Stable `2.0.0`:

- every public-build invariant and stable-required capability is delivered
- every preview-selectable capability is explicitly promoted to stable-required or moved to later-candidate
- no capability remains ambiguously under consideration
- every included capability meets the separately governed support and release-evidence thresholds

## Release traceability

Each release tag freezes the exact ledger revision used for that release. The release manifest records the ledger schema version, content hash, and source revision. Historical release claims are derived from that frozen snapshot and are not rewritten when the live ledger changes.

For the runtime and generated package, Release Evidence also records:

- each exact PowerShell runtime version and channel that was tested
- PowerShell edition and processor architecture
- the exact built-in JSON/schema validator and other transitive runtime dependencies relied upon
- every bundled dependency's identity, version, source, digest, license status, and approved compatibility range where a range is used
- source revision, deterministic build-tool identity, modular-source inputs, generated regions or source map, and the exact generated application digest
- the authenticated supporting-resource manifest and resource digests
- modular-source-to-generated-artifact equivalence results, Runtime Compatibility Check results, schema-validator conformance results, and applicable automated and fresh-client validation references

A release may accept an eligible runtime that passes the Runtime Compatibility Check, but a support claim names only the exact runtime and architecture combinations backed by the required Release Evidence. A new runtime, validator, dependency, architecture, or generated-artifact identity receives impact review and all affected validation before it can inherit a claim.

## Change control

- Ordinary wording, references, and evidence links follow the project's normal PR and required-check process.
- A change to obligation, Migration Disposition, delivery target, or removal rationale includes a short reason and governing issue link.
- A schema change increments `schemaVersion` and includes a brief migration note.
- IDs are never reassigned or reused.
- Maintainer-authored changes require the same checks but no second reviewer.

## Documentation rule

Public product documentation is beginner-friendly and instructional. It explains terminology, purpose, prerequisites, reasoning, safe procedures, expected outcomes, and next steps through progressive disclosure. Examples and evidence are privacy-sanitized so restricted or sensitive information is not exposed.
