# Signing Boundary

This page teaches the maintainer-only Signing Boundary. It does not create a Preview or Supported claim, and it does not mark `CAP-0025` delivered.

WIN-PCInfo still does not publish a release, contact Azure, create an Artifact Signing account, or treat a synthetic session as a Trusted Authenticode release.

## What this slice does

The generated application can run a **synthetic** Release Signing Session against one frozen generated-content candidate. The session is allowed only when:

1. the applicable pre-signing release gates already qualified that exact unsigned digest, and
2. a human confirmed that same digest with the exact phrase `CONFIRM-CANDIDATE-DIGEST`.

If those checks pass, the boundary:

- opens one least-privilege, time-bounded, session-specific signing capability
- applies a governed synthetic Authenticode trailer to a **copy** of the candidate
- verifies the signature contract, Individual Publisher kind, chain status, timestamp status, candidate bytes, resource manifest, and package provenance
- rebuilds the outer manifest, checksums, provenance, and archive around that **fixed signed input**
- smoke-runs the signed script with `-Workflow Help`
- removes the temporary session capability

The signed primary script is a new identity. The final signed-distributable zip is another new identity. Both stay linked to the qualified unsigned generated-content identity. Timestamped signing is **not** claimed to be byte-reproducible.

A changed, unsigned, invalidly signed, unexpectedly signed, or wrong-candidate artifact fails closed and cannot be published as Trusted.

## Prerequisites

- An already installed stable PowerShell 7.6 or later 7.x host.
- A synthetic request that satisfies `schemas/signing-session-request.schema.json`.
- A private folder that is outside this repository and outside the Windows public profile folder.
- The privacy marker file `.win-pcinfo-signing-workspace` in that folder, containing exactly `win-pcinfo.private-signing-workspace`.

This slice does not download SignTool extras, the Azure signing library, or any other tool. It does not require elevation.

## Safety reasoning

The threat is signing the wrong bytes, treating checksums as Authenticode, leaving a standing signing role, leaking Azure profile or transaction identifiers, or silently weakening Stable when Artifact Signing is down. The mechanism is exact-digest eligibility, a closed scenario set, private workspace checks, a public identifier-free result, and mandatory session cleanup. The trust assumption is that the request is synthetic and that live Azure setup authority does not exist in this slice. Safe failure is `NotStarted` before any Trusted label, with the temporary capability removed.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public policy, schemas, controller, tests, fixtures, and beginner docs. |
| Dependency acquisition | None. |
| Tool installation | None. |
| Elevation | None. |
| Authentication | None. |
| Azure resource change | None. No Artifact Signing account, profile, policy, or persistent role is created. |
| Other external-service changes | None. Synthetic adapters only. |
| Push, merge, or release publication | Not performed by this implementation slice. |
| Destructive cleanup | Only ticket-owned temporary signing workspaces and synthetic session markers. |
| Human-only actions | Digest confirmation is the required request phrase. Live signing approval remains a later human action. |

Live Azure Artifact Signing stays `NotStarted` with `SIGNING.SETUP_AUTHORITY_REQUIRED` until a later ticket has separate setup authority.

## How to run the boundary

Create the private folder and marker first. After `build/Build.ps1`:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow SignAndVerifyCandidate -SigningSessionRequestPath ./tests/fixtures/signing-session-eligible.json -SigningWorkspacePath C:\PrivateSigning\session
```

Rewrite the fixture digests so they match the generated `WIN-PCInfo.ps1` you are about to sign. A bound eligible request completes with `SIGNING.SIGNED_AND_VERIFIED`. Publication stays unauthorized because the session is synthetic and this slice has no release-publication authority.

A missing path, a non-synthetic request, a secret, a real Azure identifier, a repository folder, or a public folder returns `NotStarted` and writes no Trusted label.

## What a genuine outage does

If Artifact Signing is not operational, the result is `AttestedFallbackEligible` with reason `ArtifactSigningNotOperational`. That path follows the [Attested Preview](attested-preview.md) contract. It never becomes Trusted, never satisfies the Stable signing gate, and never weakens future signing requirements. Convenience is not a permitted reason.

## Public versus private

Public and shareable:

- this page
- the policy, request, and result schemas
- the release-owned policy
- the synthetic fixture under `tests/fixtures/signing-session-eligible.json`
- sanitized status and public signature-verification facts (publisher kind, chain/status, synthetic thumbprint)

Private and never committed:

- Azure signing account, profile, or resource identifiers
- credentials, tokens, and transaction identifiers
- tenant, subscription, or billing facts
- real validation records and restricted signing evidence
- workspace paths

Prohibited Secret Material is never a template.

## Limitations

This slice does not publish, promote, or claim a Trusted release. It does not call Azure. Completing the workflow does not deliver `CAP-0025`. Later tickets must keep the same public/private boundary.

See the [Consultant Workbench](consultant-workbench.md) for the rest of the implemented product path.
