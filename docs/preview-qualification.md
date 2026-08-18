# Qualify the exact Preview candidate

This page teaches the maintainer-only Preview qualification workflow. It does not create a Preview or Supported claim, and it does not mark `CAP-0027`, `CAP-0026`, `CAP-0028`, or `CAP-0030` delivered.

WIN-PCInfo still does not publish a release, contact Azure, start an Assessment Run, or treat a successful local assessment as Release Evidence.

## What this slice does

The generated application can qualify one frozen candidate against the complete Preview.1 scenario plan. The candidate is either:

1. the **Authenticode-signed** final distributable, or
2. the governed **Attested Preview** fallback after Artifact Signing is genuinely not operational or during a verified service incident.

Qualification binds those bytes to the already-reviewed unsigned generated-content identity, walks every required gate, and emits three public, identifier-free records:

1. a **Release Evidence Manifest** with one controlled result for every required gate
2. a **Preview Capability Matrix** derived from the frozen ledger
3. an explicit **approval or denial packet**

A human must still accept that packet. Publication stays unauthorized. Completing this workflow does not deliver a Product Capability.

## Prerequisites

- An already installed stable PowerShell 7.6 or later 7.x host.
- A synthetic request that satisfies `schemas/preview-qualification-request.schema.json`.
- A private folder that is outside this repository and outside the Windows public profile folder.
- The privacy marker file `.win-pcinfo-qualification-workspace` in that folder, containing exactly `win-pcinfo.private-qualification-workspace`.

This slice does not download tools and does not require elevation.

## Safety reasoning

The threat is approving the wrong bytes, treating an Attested Preview as Trusted Authenticode, averaging a later Pass over a product failure, claiming live Azure evidence that never ran, or publishing a workspace path or cloud identifier. The mechanism is exact-digest binding, a closed scenario catalog, a private workspace marker, a Help-only launch smoke that cannot collect, and a public projection that cannot carry identifiers. The trust assumption is that the request is synthetic and that live Azure and Artifact Signing setup are absent on this host. Safe failure is `NotStarted` before any derived packet, or an evaluated denial that cannot be waived.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public policy, schemas, controller, tests, fixtures, and beginner docs. |
| Dependency acquisition | None. |
| Tool installation | None. |
| Elevation | None on this host. Disposable-client UAC stays inside admitted Validation Rounds. |
| Authentication | Existing GitHub authentication only. The approved Azure managed identity is not available on this controller host. |
| Azure resource change | None. Live create stays `NotStarted`. |
| Other external-service changes | Read-only verification of already-reviewed signing and evidence contracts. No publication. |
| Push, merge, or release publication | Not performed by this implementation slice. |
| Destructive cleanup | Only ticket-owned temporary qualification workspaces. |
| Human-only actions | Accept or reject the final decision packet. Product failures cannot be waived. |

Live Azure Client VM Validation stays `NotStarted`. A request that claims live Azure already started is denied as an overclaim.

## What must be present

Every required Preview.1 evidence class must appear, still bound to the exact candidate:

- deterministic privacy, security, integrity, correctness, evidence-protection, terminal-honesty, language-neutral, primary-operability, provenance, and cleanup gates
- three clean full-profile quality measurements under the frozen 5/10/2-second interaction limits and the provisional memory, workspace, package, and report ceilings
- fresh-client evidence for Windows 10 Enterprise x64 and Windows 11 Enterprise x64
- standard launch with one elevation, already-elevated launch, elevation denial with honest partial coverage, and the predefined SYSTEM sub-plan
- Local Only and Microsoft Connectivity Enabled
- Restricted Outbound and Full Outbound as validation controls only
- non-English locales `en-US`, `es-MX`, `tr-TR`, `ja-JP`, and `ar-SA`
- cancellation, timeout, crash, disk pressure, and corrupt evidence
- protected-package local and recipient opening, Restricted Report Export, viewing cleanup, and stale recovery
- independently verified Zero Round Residue
- Final Artifact Validation of a **distinct** signed or attested distributable that derives from the qualified unsigned generated content

Missing, failed, expired, invalidated, wrong-candidate, privacy-unsafe, cleanup-pending, or manually waived evidence produces a denial packet. Results cannot be averaged or waived.

## How to run qualification

Create the private folder and marker first. After `build/Build.ps1`:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow QualifyPreviewCandidate -QualificationRequestPath ./tests/fixtures/preview-qualification-complete-signed.json -QualificationWorkspacePath C:\PrivateQualification\session
```

Rewrite the fixture digests so they match the generated `WIN-PCInfo.ps1` you are about to qualify. A bound complete request finishes with `QUALIFY.APPROVED` and still cannot publish. The packet remains a human decision input.

A missing path, a non-synthetic request, a secret, a real identifier, a repository folder, or a public folder returns `NotStarted` and writes no derived residue.

## What an Attested Preview may do

The fallback is allowed only for `ArtifactSigningNotOperational` or `VerifiedServiceIncident`. Convenience is not a permitted reason. The attested unsigned zip must stay distinct from the generated script and must still derive from that script. It never becomes Trusted, never satisfies the Stable signing gate, and never weakens later signing requirements.

## Public versus private

Public and shareable:

- this page
- the policy, request, and packet schemas
- the release-owned policy
- synthetic fixtures under `tests/fixtures/preview-qualification-*.json`
- sanitized evaluation records that name only approved scenario descriptions

Private and never committed:

- real validation records
- Assessment Records and Protected Evidence Packages
- Azure, tenant, subscription, gallery, or host-network identifiers
- Terraform plans, state, locks, caches, and logs
- credentials, tokens, and recipient fingerprints
- exact tested Windows build numbers

Prohibited Secret Material is never a template.

## Limitations

This slice does not publish, sign, or promote a release. It does not create Azure clients. It does not start collection on the maintainer host. A later human accepts or rejects the packet; that choice cannot turn a product failure into a pass. The later [publication workflow](preview-publication.md) still cannot create a live GitHub release from synthetic evidence.

See the [Consultant Workbench](consultant-workbench.md) for the rest of the implemented product path.
