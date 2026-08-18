# One fresh Azure validation round

This page teaches the maintainer-only controller that admits, runs, and tears down one to four private Windows 11 Enterprise x64 Validation Round clients. It does not create a Preview or Supported claim, and it does not mark `CAP-0028` delivered.

A passing infrastructure round is a **controller or DEV tracer**. It becomes qualifying Preview evidence only when the admitted artifact already satisfies the selected signed or governed Attested Preview trust path and every other qualifying-evidence condition.

## What this slice does

The generated application can run `-Workflow RunValidationRound` against an already reviewed one-to-four-client plan. A synthetic fixture walks this lifecycle without contacting Azure. This slice does not apply Terraform, call Azure APIs, or create a VM. Live create stays `NotStarted` without the approved managed identity, and it also stays `NotStarted` when only `IDENTITY_ENDPOINT` is visible because the pinned tools stay declared-not-acquired. The controller:

1. Reuses [offline admission](azure-validation-admission.md) so the plan is still one to four small Trusted Launch clients, Standard SSD, no VM public IP, and a marked private workspace. A fifth client, or a plan with no claiming Windows 11 route, is refused before create.
2. Takes one exclusive lease, then recounts live tagged validation VMs. Admission is serialized. If live VMs plus the requested clients would exceed four, the request is rejected.
3. Gives every round a visible six-hour hard expiry and a Cleanup Reserve of at least 30 minutes. When Cleanup Reserve or expiry begins, new tests and evidence export stop and the round enters Round Cleanup Mode.
4. Runs cleanup-first admission probes (synthetic flags on a fixture; live Azure stays `NotStarted` without identity and acquired tooling): managed-identity authority, policy, locks, quota, image, SKU, Standard SSD, tags, expiry, subnet capacity, VM count, cleanup rights, empty transient scope, exclusive lease, and armed recovery. Cleanup Pending also blocks a new admission.
5. Records the admitted clients from an approved pristine Azure Compute Gallery baseline on the round-scoped private network and NAT. A synthetic fixture records that create without contacting Azure.
6. Controls each guest only through closed VM Agent Run Command operation names, including payload transfer. The bootstrap password never enters WIN-PCInfo, the operator console, or the sanitized outcome.
7. Treats cancellation, partial provisioning, a shared-safety failure, host loss, and expiry as a one-way door into Round Cleanup Mode. The controller does not retry or widen the plan.
8. Returns only privacy-sanitized counts and booleans. A synthetic fixture reports `azureContacted` as false.
9. Tears down every exact, ownership-proven, round-created resource. Cleanup is idempotent. It never deletes an unresolved or unrelated object, and it preserves persistent control-plane controls.
10. Proves Zero Round Residue before it removes private Terraform state, rendered admission files, the recovery journal, or allows another round. On a synthetic fixture those proofs are separate predicates over the privately recorded token list and local folders, not live Azure queries.
11. Can finish leftover cleanup through `-Workflow RecoverValidationRound` from the private Round Recovery Record after the initiating process or its local files are gone.

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
| Azure resource change | None. This slice never applies Terraform or creates Azure resources. |
| Other external-service changes | None beyond the admitted Validation Round contract. |
| Push, merge, or release publication | Not performed by this implementation slice. |
| Destructive cleanup | Ticket-owned temporary private workspaces and synthetic residue only. |
| Human-only actions | Initial identity consent remains a later human action if a different host has the approved identity. |

## How to run the controller

Create the private folder and marker first. After `build/Build.ps1`:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow RunValidationRound -ValidationRoundRequestPath ./tests/fixtures/azure-validation-round-one-client.json -ValidationPrivateWorkspacePath C:\PrivateValidation\round -ValidationRoundFixturePath ./tests/fixtures/azure-validation-round-execution-complete.json
```

A complete synthetic fixture finishes with `VALIDATION.ZERO_RESIDUE_PROVEN`. A four-client synthetic plan uses the same fixture and also finishes at zero residue. A bounded product failure still tears down and ends `CompletedWithGaps` with `VALIDATION.ASSESSMENT_FAILED`. Cancellation, expiry, host loss, and independent recovery also tear down and end `CompletedWithGaps` so an infrastructure or abort path cannot look like a product pass. Remaining residue ends `CleanupIncomplete` with `VALIDATION.RESIDUE_REMAINS` and keeps the private recovery journal plus rendered admission files. The live command without a fixture ends `NotStarted` with `VALIDATION.IDENTITY_UNAVAILABLE` on a host that lacks the approved managed identity.

A fifth client, four live tagged VMs plus one more request, a busy exclusive lease, Cleanup Pending, a repository folder, a public folder, or a missing privacy marker fails before create.

Independent recovery after host loss:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow RecoverValidationRound -ValidationRoundFixturePath ./tests/fixtures/azure-validation-round-execution-independent-recovery.json -ValidationPrivateWorkspacePath C:\PrivateValidation\round
```

That worker uses the private Round Recovery Record. It does not need the initiating process or its local journal.

## What Zero Round Residue requires

Zero residue is proven only when all of the following are independently true:

- the transient scope is empty
- both round-owned peering links are absent
- every privately recorded round-owned exact ID is absent
- round transfer and coordination objects are removed
- the tag sweep is empty
- unprotected local working material is absent

The persistent Validation Resource Scope, Control Plane, budget, governance, and gallery baselines remain. Only after those checks pass may private Terraform state, rendered admission files, and the recovery journal be removed and the next round become eligible. A private restricted operations record may be retained by the operator for up to seven days outside this repository. This controller never commits that record. Cleanup Pending keeps that restricted operations data only until Zero Round Residue or a documented incident. Normal completed records are removed within seven days. The controller keeps the recovery journal in the private workspace while residue remains and deletes the journal after Zero Round Residue.

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

This slice does not mark `CAP-0028` delivered, publish a Preview or Supported claim, or treat a passing infrastructure round as release-qualification evidence. It does not apply Terraform, invoke Azure APIs, or create a VM. Live create stays `NotStarted` without the approved managed identity, and it also stays `NotStarted` when identity is visible because this slice does not acquire or invoke the pinned tools.

Cancellation, expiry, host loss, and leftover cleanup are honest `CompletedWithGaps` or `CleanupIncomplete` outcomes. They never become `VALIDATION.ZERO_RESIDUE_PROVEN`.

See the [Consultant Workbench](consultant-workbench.md) for the rest of the implemented product path.
