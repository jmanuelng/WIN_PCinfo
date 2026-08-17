# Offline Azure validation admission

This page teaches the maintainer-only admission gate that prepares a private validation-round plan. It does not create a Preview or Supported claim, and it does not mark `CAP-0028` delivered.

WIN-PCInfo still does not log in to Azure, query Azure, run `terraform plan` against a live backend, apply resources, or mutate a subscription.

## What this slice does

The generated application can admit a synthetic one-to-four-client round plan. If the plan is safe, it copies the generic Terraform templates from `infra/azure-validation/` into a caller-supplied private workspace and writes placeholder variable values there.

If the plan is unsafe, admission stops before any rendered file exists.

The only public result is a sanitized verdict. That verdict records counts, booleans, and a stable reason code. It does not record a workspace path, tenant, subscription, network, gallery, resource, certificate, device, IP, or credential.

## Prerequisites

- An already installed stable PowerShell 7.6 or later 7.x host.
- A private folder that is outside this repository and outside the Windows public profile folder.
- The privacy marker file `.win-pcinfo-private-workspace` in that folder, containing exactly `win-pcinfo.private-external-workspace`.
- A round request that names the pinned Terraform `1.12.2` identity and the pinned `hashicorp/azurerm` `4.37.0` identity. This slice does not download those tools.

## Safety reasoning

The threat is coupling the public repository to one Azure lab, or accidentally publishing state, identifiers, or a live plan. The mechanism is offline admission that rejects a repository path, a public path, a missing privacy marker, an unresolved tool version, or an unsafe shape before it copies templates. The trust assumption is that the operator chose a private folder they control. Safe failure is `NotStarted` with `azureContacted` remaining false.

## What admission requires

- one to four allowlisted small SKUs: `Standard_D2s_v5`, `Standard_D2as_v5`, `Standard_B2s`, or `Standard_B2ms`
- planned work plus a cleanup reserve of at least 30 minutes, totaling at most six hours
- Standard SSD only
- Gen2 with Trusted Launch, Secure Boot, and vTPM for a claiming Windows 11 client
- private NICs and no VM public IP
- a round VNet and subnet
- NAT with a Standard public IP
- narrow non-transitive peering
- the minimum non-sensitive tags `Purpose`, `Environment`, `Lifecycle`, `ManagingTool`, `RoundCorrelation`, `CreatedUtc`, and `ExpiresUtc`

A VM that is not Trusted Launch may exist only as a `NonClaimingDiagnostic` client with `claiming` set to false. It cannot become Preview or Supported evidence.

## How to run the gate

Create the private folder and marker first. Then, from a repository checkout:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow AdmitValidationRound -ValidationRoundRequestPath ./tests/fixtures/azure-validation-round-one-client.json -ValidationPrivateWorkspacePath C:\PrivateValidation\round
```

A successful run writes generic `.tf` files and `generated.auto.tfvars` under `rendered\` inside that private folder. It does not create Terraform state, lock files, or a provider cache, and it does not start Azure.

A fifth client, a lifetime over six hours, a missing cleanup reserve, a repository folder, a public folder, a floating provider version, a VM public IP, Premium SSD, or a claiming VM without Trusted Launch returns `NotStarted` and leaves the private folder unrendered.

## Public versus private

Public and shareable:

- the generic modules under `infra/azure-validation/`
- the request, policy, and verdict schemas
- synthetic fixtures under `tests/fixtures/azure-validation-round-*.json`
- this page

Private and never committed:

- rendered variable values
- backend files
- plans, state, locks, provider caches, and logs
- real gallery, host-network, tenant, or subscription values

Prohibited Secret Material is never a template.

## Limitations

This slice does not apply a round, recount live Azure VMs, tear down residue, or publish release evidence. Later tickets must keep the same privacy boundary.

See the [Consultant Workbench](consultant-workbench.md) for the rest of the implemented product path.
