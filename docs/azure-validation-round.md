# One fresh Azure validation round

This page teaches the maintainer-only controller that admits, runs, and tears down one private Windows 11 Enterprise x64 Validation Round. It does not create a Preview or Supported claim, and it does not mark `CAP-0028` delivered.

A passing infrastructure round is a **controller or DEV tracer**. It becomes qualifying Preview evidence only when the admitted artifact already satisfies the selected signed or governed Attested Preview trust path and every other qualifying-evidence condition.

## What this slice does

The generated application can run `-Workflow RunValidationRound` against an already reviewed one-client plan. The controller:

1. Reuses [offline admission](azure-validation-admission.md) so the plan is still one small Trusted Launch client, Standard SSD, no VM public IP, and a marked private workspace.
2. Runs cleanup-first live admission probes: managed-identity authority, policy, locks, quota, image, SKU, Standard SSD, tags, expiry, subnet capacity, VM count, cleanup rights, empty transient scope, exclusive lease, and armed recovery.
3. Creates one fresh client from an approved pristine Azure Compute Gallery baseline on the round-scoped private network and NAT.
4. Controls the guest only through VM Agent Run Command. The bootstrap password never enters WIN-PCInfo, the operator console, or the sanitized outcome.
5. Reverifies the exact candidate and payload manifest inside the guest, then runs Local Only and approved egress checks before the assessment payload.
6. Returns only privacy-sanitized counts and booleans.
7. Tears down every round-created resource even when the product payload fails.
8. Proves Zero Round Residue before it removes private Terraform state or allows another round.

If the approved managed identity is missing, Terraform is still only a declared identity, or any admission probe fails, the workflow ends `NotStarted` and creates nothing.

## Prerequisites

- An already installed stable PowerShell 7.6 or later 7.x host.
- A private folder that is outside this repository and outside the Windows public profile folder.
- The privacy marker file `.win-pcinfo-private-workspace` in that folder, containing exactly `win-pcinfo.private-external-workspace`.
- The same pinned Terraform `1.12.2` and `hashicorp/azurerm` `4.37.0` identities used by offline admission. This slice does not download those tools.

Live Azure also needs the approved credentialless host managed identity, the dedicated Validation Resource Scope, and private gallery plus host-network inputs. Those facts stay outside this repository. This controller host does not have that identity, so the live path stays `NotStarted`.

## Safety reasoning

The threat is leaving a billed VM, a host-network peering, a captured image, a public IP, or a bootstrap password in a public log, then calling that residue a completed validation. The mechanism is cleanup-first admission, VM Agent-only guest control, a sanitized outcome, and independent absence checks before state removal. The trust assumption is that the operator chose a private folder they control and that live Azure uses the approved managed identity. Safe failure is `NotStarted` before create, or `CleanupIncomplete` while any exact target remains.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public policy, schemas, controller, tests, fixtures, and beginner docs. |
| Dependency acquisition | None. Terraform 1.12.2 and hashicorp/azurerm 4.37.0 stay declared-not-acquired. |
| Tool installation | None. This slice does not download Terraform, Azure CLI, or providers. |
| Elevation | None. |
| Authentication | The approved credentialless managed identity is unavailable on this controller host. Live Azure stays `NotStarted`. Tests use a synthetic platform that never carries a credential. |
| Azure resource change | None in this host. Creation is authorized only after identity, tooling, and every admission probe pass. |
| Other external-service changes | None beyond the admitted Validation Round contract. |
| Push, merge, or release publication | Not performed by this implementation slice. |
| Destructive cleanup | Ticket-owned temporary private workspaces and synthetic residue only. |
| Human-only actions | Initial identity consent remains a later human action if a different host has the approved identity. |

## How to run the controller

Create the private folder and marker first. After `build/Build.ps1`:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow RunValidationRound -ValidationRoundRequestPath ./tests/fixtures/azure-validation-round-one-client.json -ValidationPrivateWorkspacePath C:\PrivateValidation\round -ValidationRoundFixturePath ./tests/fixtures/azure-validation-round-execution-complete.json
```

A complete synthetic fixture finishes with `VALIDATION.ZERO_RESIDUE_PROVEN`. A bounded product failure still tears down and ends `CompletedWithGaps` with `VALIDATION.ASSESSMENT_FAILED`. The live command without a fixture ends `NotStarted` with `VALIDATION.IDENTITY_UNAVAILABLE` on a host that lacks the approved managed identity.

A fifth client, a repository folder, a public folder, or a missing privacy marker still fails in offline admission before any platform probe runs.

## What Zero Round Residue requires

Zero residue is proven only when all of the following are independently true:

- the transient scope is empty
- both round-owned peering links are absent
- every privately recorded round-owned exact ID is absent
- round transfer and coordination objects are removed
- the tag sweep is empty
- unprotected local working material is absent

The persistent Validation Resource Scope, Control Plane, budget, governance, and gallery baselines remain. Only after those checks pass may private Terraform state be removed and the next round become eligible.

## Public versus private

Public and shareable:

- this page
- the generic modules under `infra/azure-validation/`
- the policy, fixture, and outcome schemas
- synthetic fixtures under `tests/fixtures/azure-validation-round-*.json`

Private and never committed:

- rendered variable values
- backend files, plans, state, locks, provider caches, and logs
- recovery journals and exact Azure IDs
- real gallery, host-network, tenant, or subscription values
- bootstrap passwords and any other Prohibited Secret Material

## Limitations

This slice does not mark `CAP-0028` delivered, publish a Preview or Supported claim, or treat a passing infrastructure round as release-qualification evidence. Live create stays `NotStarted` until the approved managed identity and separately acquired pinned tooling are present.

See the [Consultant Workbench](consultant-workbench.md) for the rest of the implemented product path.
