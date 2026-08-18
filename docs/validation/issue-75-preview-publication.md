# Issue #75 validation projection

This public projection contains identifier-free Preview publication, public-release preview, and independent-download checks only. It contains no Assessment Record value, package path, device identifier, tenant fact, recipient fingerprint, Terraform material, Azure signing account, exact tested Windows build, GitHub token, or protected evidence content.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public policy, schemas, controller, tests, fixtures, and beginner docs. |
| Dependency acquisition | None. |
| Tool installation | None. |
| Elevation | None. |
| Authentication | Existing GitHub release authentication was available. Live GitHub publication stays `NotStarted` until human approval of the exact candidate. |
| Azure resource change | None. |
| Other external-service changes | None. Synthetic publisher only. |
| Push, merge, or release | Not performed by this implementation slice. |
| Destructive cleanup | Only ticket-owned temporary private workspaces and unpublished synthetic residue. |
| Human-only actions | Approve or reject the exact candidate digest, qualification packet, limitations, trust state, and public asset list. Product failures cannot be waived. Silent replacement is forbidden. |

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Policy contract | `tests/PreviewPublicationPolicy.Tests.ps1` requires `docs/spec/releases/2.0.0-preview.1-preview-publication.json` to satisfy `schemas/preview-publication.schema.json`. Support, Preview, publication, GitHub-release, and capability-delivery claims stay false. |
| Decision engine | `tests/PreviewPublication.Tests.ps1` evaluates complete signed and attested packs plus missing approval, mismatched approval, denied qualification, unbound packet, waiver, wrong-candidate, privacy-unsafe, silent-replacement, GitHub-auth, immutable-tag, download-mismatch, duplicate-asset, unsafe file-name, and unknown-channel requests. Missing approval previews only. A product failure cannot be averaged or waived. |
| Generated-application seam | `tests/PreviewPublicationApplication.Tests.ps1` invokes `-Workflow PublishPreviewRelease`. A bound complete request finishes with `PUBLISH.PUBLISHED_AND_VERIFIED` on the synthetic publisher. A missing request or a privacy-violating request ends `NotStarted`. Help smoke runs; collection does not start; no GitHub release is created. |
| Live GitHub path | Without human approval the path is `NotStarted`. A synthetic request that names GitHub is denied. Existing tags cannot be replaced. |
| Public/private boundary | Public records omit workspace paths, Azure identifiers, credentials, exact builds, tokens, and local user paths. Non-synthetic requests are rejected. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/PreviewPublicationPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/PreviewPublication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/PreviewPublicationApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
