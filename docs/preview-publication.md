# Publish the approved Preview.1 release

This page teaches the maintainer-only Preview publication workflow. It does not create a Preview or Supported claim, and it does not mark `CAP-0026`, `CAP-0025`, `CAP-0027`, or `CAP-0030` delivered.

WIN-PCInfo still does not create a live GitHub release from a synthetic request, contact Azure, start an Assessment Run, or treat a successful local assessment as Release Evidence.

## What this slice does

The generated application can stage the exact qualified public assets, verify every digest and trust status again, and preview the public GitHub release record. After a human confirms the exact candidate digest, qualification packet, limitations, signing or attestation state, and complete public asset list, the workflow can publish **once** to a synthetic publisher and independently download the published bytes.

The live GitHub path stays `NotStarted` in this slice. A synthetic rehearsal cannot authorize the public tag. Completing this workflow does not deliver a Product Capability.

The public preview record is identifier-free and always says:

1. the release is Preview
2. no scenario is Supported
3. maintenance is best effort with no SLA
4. Microsoft lifecycle status is separate from WIN-PCInfo claims
5. known limitations apply
6. an Attested Preview stays unsigned and limited-trust when that path is used
7. the tag and assets must not be replaced silently

## Prerequisites

- An already installed stable PowerShell 7.6 or later 7.x host.
- A synthetic request that satisfies `schemas/preview-publication-request.schema.json`.
- A private folder that is outside this repository and outside the Windows public profile folder.
- The privacy marker file `.win-pcinfo-publication-workspace` in that folder, containing exactly `win-pcinfo.private-publication-workspace`.
- An already approved Preview qualification packet for the same candidate digest.

This slice does not download tools and does not require elevation.

## Safety reasoning

The threat is publishing the wrong bytes, replacing a published tag, treating an Attested Preview as Trusted or Supported, or leaking a workspace path, credential, or cloud identifier through the public release record. The mechanism is exact-digest binding, a closed public asset list, a required human confirmation phrase, an immutable-tag rule, and a public projection that cannot carry identifiers. The trust assumption is that the request is synthetic and that live GitHub publication remains a later human-approved action. Safe failure is `NotStarted` before any derived preview, or an evaluated denial that cannot be waived.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public policy, schemas, controller, tests, fixtures, and beginner docs. |
| Dependency acquisition | None. |
| Tool installation | None. |
| Elevation | None. |
| Authentication | Existing GitHub release authentication was available on this host. Live GitHub publication still stays `NotStarted` until a human approves the exact candidate. |
| Azure resource change | None. |
| Other external-service changes | Live GitHub tag and asset creation stay `NotStarted` in this slice. Tests use a synthetic publisher only. |
| Push, merge, or release publication | Not performed by this implementation slice. |
| Destructive cleanup | Only unpublished ticket-owned staging and synthetic publisher residue. Published tags are never replaced. |
| Human-only actions | Final release approval after reviewing the candidate digest, qualification packet, limitations, signing or attestation state, and exact public assets. |

A request that asks GitHub to publish from synthetic evidence is denied. A request that asks to replace an existing tag is denied.

## What must be present

Every required public asset must appear, still bound to the exact candidate:

- the distinct portable package
- checksums
- SBOM
- provenance
- dependency inventory
- beginner documentation
- Preview Capability Matrix
- limitations
- privacy-sanitized Release Evidence

The embedded qualification packet must already be `Approved` for the same generated-content digest. The packet itself cannot authorize publication.

Missing approval, a mismatched digest, a denied packet, a privacy-unsafe request, a waiver, or a silent-replacement request produces a denial or `NotStarted` result. Results cannot be averaged or waived.

## How to run publication

Create the private folder and marker first. After `build/Build.ps1`:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow PublishPreviewRelease -PublicationRequestPath ./tests/fixtures/preview-publication-complete-signed.json -PublicationWorkspacePath C:\PrivatePublication\session
```

Rewrite the fixture digests so they match the generated `WIN-PCInfo.ps1` you are about to publish, then rewrite the human-approval digests so they match the staged asset list, qualification packet, and limitations. A bound complete request with the phrase `APPROVE-PREVIEW-PUBLICATION` finishes with `PUBLISH.PUBLISHED_AND_VERIFIED` on the synthetic publisher. The live GitHub release is still not created.

A missing path, a non-synthetic request, a secret, a real identifier, a repository folder, or a public folder returns `NotStarted` and writes no derived residue.

A request without human approval still stages and previews the public record, then stops with `PUBLISH.HUMAN_APPROVAL_REQUIRED`.

## What an Attested Preview may do

The fallback is allowed only for `ArtifactSigningNotOperational` or `VerifiedServiceIncident`. Convenience is not a permitted reason. The public record must show the unsigned limited-trust warning first. The attested package never becomes Trusted, never satisfies the Stable signing gate, and never becomes Supported.

## Immutability

The public tag is `v2.0.0-preview.1`. If that tag already exists, publication stops. Asking to replace the tag or any asset is `PUBLISH.SILENT_REPLACEMENT_REJECTED`. Suspected compromise or error follows a new version or the Release Signing Incident process.

After a synthetic publish, the workflow independently downloads each asset and compares SHA-256. A mismatch is a denial. It never overwrites the published store to "fix" the digest.

## Public versus private

Public and shareable:

- this page
- the policy, request, preview, and result schemas
- the release-owned policy
- synthetic fixtures under `tests/fixtures/preview-publication-*.json`
- sanitized evaluation records that name only approved scenario descriptions
- public publisher identity, chain, serial, or thumbprint facts later extracted from a released Authenticode signature

Private and never committed:

- real validation records
- Assessment Records and Protected Evidence Packages
- Azure, tenant, subscription, gallery, or host-network identifiers
- Terraform plans, state, locks, caches, and logs
- credentials, tokens, and recipient fingerprints
- exact tested Windows build numbers
- local user paths

Prohibited Secret Material is never a template.

## Limitations

This slice does not create the live GitHub Preview.1 release. It does not sign, contact Azure, or start collection on the maintainer host. A later human approves or rejects the exact preview record; that choice cannot turn a product failure into a pass and cannot replace a published tag.

See the [Consultant Workbench](consultant-workbench.md) for the rest of the implemented product path.
