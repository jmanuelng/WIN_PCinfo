# Windows-client validation infrastructure

Research current through 2026-08-04 for [Research Windows-client validation infrastructure](https://github.com/jmanuelng/WIN_PCinfo/issues/3), part of [\[Wayfinder\] Define WIN-PCInfo v2 product and release specification](https://github.com/jmanuelng/WIN_PCinfo/issues/1).

## Decision

A technically feasible, repeatable, and low-cost validation system exists, but it must be layered:

1. Use free, ephemeral GitHub-hosted runners for every **Automated Gate**. Pin `windows-2022` and `windows-2025` for x64 logic and add `windows-11-arm` for Arm64 architecture coverage. The x64 images are Windows Server rather than Windows client, and the Arm64 Windows 11 image is currently public preview, so neither is sufficient client-support evidence by itself.
2. Make licensed x64 Windows 11 generation-2 VMs on the existing Windows Server Hyper-V host the primary **Client VM Validation** environment. Recreate each run from a versioned clean base, drive it with Hyper-V PowerShell and PowerShell Direct, and retain only sanitized result summaries.
3. Keep paid GitHub larger runners and Azure Windows 11 VMs as optional overflow or specialty capacity. They are technically viable, but plan eligibility, Windows-client licensing, regional availability, and variable cost must be confirmed before adoption.
4. Require a **Community Validation Run** or maintainer-controlled physical-device run for hardware-, OEM-, firmware-, power-, security-product-, and managed-policy behavior. Virtual evidence alone must never promote such a row to Supported in the **Supported-device Validation Matrix**.

This topology can start at zero infrastructure spend beyond the existing host. The unresolved blocker is not technology; it is confirmation of the Windows-client license entitlement and physical host capacity before persistent Hyper-V client images are created.

## Terms and evidence boundary

This note applies the project glossary as follows; it does not replace the later [Define support tiers and release-evidence thresholds](https://github.com/jmanuelng/WIN_PCinfo/issues/9) decision.

- **Automated Gate**: deterministic, non-interactive checks required on every pull request and protected branch.
- **Client VM Validation**: a controlled Windows-client run from a declared clean image, covering client-only behavior, privilege modes, failure paths, and report generation.
- **Community Validation Run**: an opt-in run of an exact release candidate on an externally controlled real device, returning only the approved, locally reviewed, redacted evidence contract.
- **Supported-device Validation Matrix**: the evidence ledger keyed at minimum by Windows release/build, edition, architecture, physical/virtual device class, privilege posture, security posture, locale, artifact digest, run date, outcome, and sanitized evidence reference.

“Supported” must mean validated behavior, not merely that Windows or a runner can boot the code. A VM can establish OS-, architecture-, privilege-, locale-, and policy-path behavior; it cannot establish correct observation of the host's physical battery, firmware, TPM implementation, storage firmware/health, GPU, radios, sensors, dock, or OEM utilities.

## Feasibility and disposition

| Facility | Known facts and limits | Appropriate evidence | Disposition |
|---|---|---|---|
| Standard GitHub-hosted Windows x64 | For public repositories, the standard Windows labels provide fresh 4-core/16-GB/14-GB x64 VMs and are free and unlimited. Current x64 labels are `windows-2022`, `windows-2025`, and `windows-latest`; the maintained images are Windows Server images, not Windows 11 desktop images. ([runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [image repository](https://github.com/actions/runner-images)) | Unit, contract, schema, deterministic fixture, packaging, static-analysis, and PowerShell compatibility gates. Not Windows-client UX or hardware evidence. | Adopt now for every Automated Gate. Use explicit year labels, not `windows-latest`. |
| Standard GitHub-hosted Windows Arm64 | Public repositories currently have a 4-core/16-GB/14-GB `windows-11-arm` runner, but GitHub marks the image public preview; beta images are outside the Actions SLA and may lack support or warranty. ([runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [current Arm64 image inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows11-Arm64-Readme.md)) | Native Arm64 execution, architecture-specific path handling, dependency availability, and smoke tests on a Windows 11 guest. It still presents hosted virtual hardware. | Adopt as a non-release-blocking supplemental gate while preview. Reassess its status before making it mandatory. |
| Existing Windows Server Hyper-V host | Microsoft supports Windows 11 only as a generation-2 VM on Windows Server 2019 or later. Windows 11 VMs require Secure Boot, virtual TPM, at least 4 GB RAM, two vCPUs, and a host processor that meets the documented requirements. ([supported guests](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/supported-windows-guest-operating-systems-for-hyper-v-on-windows), [Windows 11 VM requirements](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements)) | Repeatable Windows-client behavior across editions, current supported builds, privilege levels, execution policy, locale, offline/degraded modes, and controlled policy states. | Preferred primary Client VM Validation lab, conditional on host audit and client licensing. |
| GitHub larger Windows runners | Larger runners are available only to organizations and enterprises on GitHub Team or Enterprise Cloud. They include partner Windows 11 desktop images, more resources, private networking, static IP options, and custom images; partner images come from Azure Marketplace and are not managed by GitHub. ([larger-runner reference](https://docs.github.com/en/actions/reference/runners/larger-runners), [management prerequisites](https://docs.github.com/en/actions/how-tos/manage-runners/larger-runners/manage-larger-runners)) | Ephemeral x64 Windows 11 client automation when local capacity is unavailable, or a custom pinned image is worth its storage and plan overhead. | Optional escalation, not phase-one infrastructure. Accept applicable image terms before use. |
| Azure Windows 11 x64 VMs / DevTest Labs | Azure publishes Windows 11 Marketplace images and supports scripted VM creation. Production Windows 11 use requires qualifying per-user Windows/Microsoft 365/VDA rights; separate dev/test client images are available to eligible Visual Studio subscribers. DevTest Labs supports templates, formulas, policies, VM limits, and autoshutdown. ([Windows 11 deployment and entitlement](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/windows-desktop-multitenant-hosting-deployment), [dev/test client eligibility](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/client-images), [DevTest Labs concepts](https://learn.microsoft.com/en-us/azure/devtest-labs/devtest-lab-concepts)) | Burstable client validation, geographically or policy-isolated testing, and disposable clean-room reproduction. | Optional only after eligibility, region, quota, and budget are verified. |
| Azure Windows 11 Arm64 VM | Microsoft documents Windows 11 Pro Arm64 on Ampere Altra Azure VMs, but the creation guide is marked Preview and requires confirmation of a qualifying Windows license for production workloads. ([Arm VM quickstart](https://learn.microsoft.com/en-us/windows/arm/create-arm-vm)) | Longer interactive Arm64 client runs or a controlled Arm64 VM when the GitHub preview runner is insufficient. Still not Snapdragon/OEM hardware evidence. | Contingency capacity; do not make it the sole Arm64 support basis. |
| Physical or externally managed Windows devices | Hyper-V on x64 cannot run Arm64 guests; Microsoft directs x64 users to Azure for an Arm64 VM, while local Arm64 Hyper-V requires an Arm-based host. ([Windows 11 Arm ISO guidance](https://learn.microsoft.com/en-us/windows/arm/iso), [Windows on Arm FAQ](https://learn.microsoft.com/en-us/windows/arm/faq)) Physical devices additionally expose the real firmware and peripherals that VMs abstract. | Real-device collector accuracy, OEM variance, battery/power, firmware/TPM, storage/GPU/network devices, endpoint security, standard-user experience, and managed-enterprise restrictions. | Required for affected Supported-device Validation Matrix rows. Prefer opt-in community evidence before buying a broad device fleet. |

## GitHub-hosted Automated Gates

GitHub provisions a new VM for each hosted job and decommissions it afterward, which provides a clean job boundary. Windows hosted VMs run as administrators with UAC disabled. GitHub-owned images receive weekly tool updates, and the exact image/software link is recorded in the `Set up job` log. ([hosted-runner lifecycle](https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners), [privilege and resources](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [image update behavior](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners))

Therefore:

- Use `windows-2022` and `windows-2025` rather than `windows-latest`; this pins the OS family but not the weekly image build. Record `ImageOS`, `ImageVersion`, PowerShell versions, architecture, workflow/run ID, commit, dependency lock data, and artifact SHA-256 in test output.
- Run Windows PowerShell 5.1 and the project-pinned PowerShell 7 version where both are supported. Install any missing test tools at explicit versions instead of depending silently on the weekly image contents.
- Treat `windows-11-arm` failures as required-to-triage but not release-blocking until the runner leaves preview and proves sufficiently reliable. A scheduled run can detect upstream image drift without making every pull request wait on preview capacity.
- Do not use the hosted Windows environment to accept UAC, standard-user UX, physical inventory, firmware, or OEM behavior: its administrator/UAC configuration and virtual hardware are intentionally unlike those target scenarios.
- Keep workflow permissions read-only by default, use no release credentials on pull-request tests, and pin third-party actions to full commit SHAs as GitHub recommends in its [secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use).

## Hyper-V Client VM Validation

### Technical design

The host must first pass a non-public capacity check for Windows Server release, available CPU/RAM/storage, virtualization support, and safe concurrency. Hyper-V requires a 64-bit processor with second-level address translation and hardware virtualization support. ([host requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements)) No host names, serials, network details, or license identifiers belong in the public research or evidence ledger.

Use one generation-2 base image per deliberately supported Windows client edition/release/architecture combination. For Windows 11, enable Secure Boot and vTPM; Hyper-V can provide virtual TPM independently of the host TPM version. ([generation-2 security](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/generation-2-virtual-machine-security-features), [Windows 11 VM requirements](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements)) Start with one current x64 Windows 11 Enterprise evaluation image and add licensed Pro/Home images only when a proposed support row requires them.

A repeatable run should:

1. Verify the base-image manifest: source URL, edition, release/build, architecture, patch cutoff, ISO/base hash, license class and expiry, VM generation, firmware settings, vCPU/RAM, locale, and installed prerequisites.
2. Create a disposable differencing VHDX from the read-only base. Hyper-V's `New-VHD -ParentPath ... -Differencing` directly supports this model. ([New-VHD](https://learn.microsoft.com/en-us/powershell/module/hyper-v/new-vhd))
3. Start the VM with a private or no-network switch for offline tests; enable only the network profile the scenario requires.
4. Copy the exact candidate artifact and invoke the non-interactive harness through PowerShell Direct. PowerShell Direct works from a Hyper-V host without guest networking or remote-management configuration, but requires host Hyper-V administrator rights and valid guest credentials. ([PowerShell Direct](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell-direct))
5. Run separate standard-user, consent/elevation, administrator, offline/degraded, and locale profiles. Interactive UAC and first-run usability checks must be observed through VMConnect/RDP rather than inferred from the privileged automation channel.
6. Export only the approved structured summary, compare it with deterministic expectations, then destroy the disposable child disk and temporary credentials.

Hyper-V checkpoints can restore a VM through PowerShell, and production checkpoints are data-consistent because they do not capture memory state. Standard checkpoints do capture memory and are not backups. ([checkpoint behavior](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/checkpoints)) Use checkpoints for investigation, but use a powered-off, patched base plus discarded differencing disks as the canonical clean-run reset; that makes state provenance and cleanup easier to audit.

### Licensing boundary

Windows Server licensing does not supply Windows-client guest rights. Microsoft's Windows Server terms describe rights to run the *server software* in virtual OSEs; Standard permits two and Datacenter permits unlimited Windows Server OSEs under their respective core-licensing conditions. ([Windows Server Product Terms](https://www.microsoft.com/licensing/terms/en-US/productoffering/WindowsServerDatacenter/all/Availability/526), [virtualization licensing guidance](https://www.microsoft.com/licensing/guidance/Windows-Server-Virtualization-Technologies)) A Windows 11 guest therefore needs its own applicable client entitlement.

Three legitimate paths are relevant:

- **Time-limited evaluation:** Microsoft offers a full-featured Windows 11 Enterprise ISO for a 90-day evaluation, explicitly aimed at IT professionals evaluating managed desktops. ([Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)) Microsoft's Windows license terms restrict evaluation software to evaluation/test/demonstration, prohibit live operational use, and prohibit use after the evaluation period. ([Windows 11 license terms](https://www.microsoft.com/content/dam/microsoft/usetm/documents/windows/11/oem-%28pre-installed%29/UseTerms_OEM_Windows_11_English.pdf)) This is appropriate for an initial test lab, provided the image is rebuilt before expiry and never used to extend or operate the product service.
- **Retail/OEM:** Current Windows terms permit one Windows instance on one physical or virtual licensed device and require a separate license for more than one virtual device. The same terms restrict installing Windows on a server for remote-only use, and OEM rights travel with the original device. ([Windows 11 license terms](https://www.microsoft.com/content/dam/microsoft/usetm/documents/windows/11/oem-%28pre-installed%29/UseTerms_OEM_Windows_11_English.pdf)) Retail is therefore not a blanket answer for a remotely accessed Hyper-V farm. If the specific local-use facts fit, Windows 11 Pro's current US public list price is $199.99 per download license. ([Microsoft Store](https://www.microsoft.com/en-us/d/windows-11-pro/dg7gmgf0d8h4))
- **Commercial Windows/VDA rights:** Microsoft Product Terms grant defined local and remote virtualization rights—commonly up to four Windows virtual OSEs—for eligible Windows Enterprise, Microsoft 365, or VDA per-user/per-device licenses, subject to qualifying-OS, assignment, access, outsourcing, and acquisition-channel conditions. ([current Windows Desktop Product Terms](https://www.microsoft.com/licensing/terms/en-US/productoffering/WindowsDesktopOperatingSystem/MPSA), [Windows virtual desktop licensing brief](https://www.microsoft.com/licensing/docs/documents/download/Licensing_brief_PLT_Licensing%20Windows%20365%20and%20Windows%2011%20Virtual%20Desktops%20for%20Remote%20Access.pdf)) This is the likely ongoing route for a remote Windows Server lab, but the exact entitlement and activation method require confirmation against the license actually procured.

The project should maintain a private entitlement ledger mapping every concurrently usable base/VM to its license channel and expiry. It must not reuse an OEM key from a physical PC, treat activation as proof of licensing, or assume a checkpoint/differencing-disk strategy permits extra concurrently usable instances. This is a planning interpretation, not legal advice; confirm the final topology with Microsoft or an authorized licensing provider before persistent use.

### Isolation

Do not register the Hyper-V host or reusable client VMs as GitHub self-hosted runners for public pull requests. GitHub states that self-hosted runners are not guaranteed clean and can be persistently compromised by untrusted workflow code; it says they should almost never be used for public repositories. ([secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use), [runner-group warning](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access))

Instead, a maintainer-controlled coordinator should accept only a reviewed commit or release-candidate digest, run with a least-privileged GitHub token or no GitHub credential, and publish results only after sanitization. Keep base images free of repository tokens, personal profiles, signing keys, assessment evidence, and production credentials. Separate the validation switch from sensitive host networks, deny inbound access by default, and destroy child disks after evidence extraction. A local scheduler may automate approved candidate runs without making the lab reachable by arbitrary Actions jobs.

## Optional cloud capacity and costs

GitHub standard runners are the default because public-repository use is currently free and unlimited. Paid larger runners are charged only while a workflow executes, are not free for public repositories, and do not consume included minutes. Current public rates include Windows x64 4-core at $0.022/minute ($1.32/hour), Windows x64 8-core at $0.042/minute ($2.52/hour), and Windows Arm64 4-core at $0.014/minute ($0.84/hour), before any required GitHub plan fee or custom-image storage. ([Actions runner pricing](https://docs.github.com/en/billing/reference/actions-runner-pricing)) A 30-minute 4-core x64 client run is therefore about $0.66 in execution charges; 100 such runs are about $66.

Azure is metered by region, size, disk, networking, and license offer, so no single honest hourly figure applies. Microsoft's public Windows VM pricing page advertises eligible Dev/Test savings of up to 55%, but that is not evidence that this project or a selected Windows 11/Arm64 image qualifies. ([Azure Windows VM pricing](https://azure.microsoft.com/en-us/pricing/details/virtual-machines/windows/)) Require a calculator export or price API result for the exact region/SKU/image before approval. Use templates, spending alerts, a one-VM quota, autoshutdown, and deletion on completion. Deallocated VMs stop compute billing, but disks and some network resources continue to incur charges. ([VM states and billing](https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing), [DevTest Labs autoshutdown](https://learn.microsoft.com/en-us/azure/devtest-labs/devtest-lab-auto-shutdown))

Recommended cost order:

1. Standard hosted Actions plus the existing Hyper-V host and a 90-day Enterprise evaluation during lab proving.
2. Confirm and procure the smallest valid ongoing Windows client virtualization entitlement before the evaluation expires.
3. Use paid GitHub Windows 11 runners only if their total monthly cost is lower than maintaining the local lab or when clean hosted scale is materially useful.
4. Use Azure only for a documented gap, such as interactive Arm64 client work that the GitHub preview runner cannot complete.
5. Recruit privacy-preserving community runs before purchasing broad physical coverage; buy a device only for a high-priority matrix gap that remains unfilled.

## Physical and externally managed validation

The following scenarios require physical or externally controlled devices for credible support evidence:

- battery and AC state; real TPM/UEFI/Secure Boot/firmware; BIOS and OEM WMI/providers;
- SATA/NVMe/RAID/storage-health implementations, discrete/integrated GPUs, monitors, radios, cameras, sensors, docks, and removable devices;
- Windows on Arm behavior specific to Snapdragon/Copilot+ hardware, OEM drivers, NPU, battery, and x86/x64 emulation—the hosted/Azure Ampere VM proves Arm64 execution, not those device characteristics;
- Windows Home, S mode, factory/OEM configurations, or editions not legitimately represented in the VM lab;
- real SmartScreen/download reputation, third-party EDR/AV, WDAC/AppLocker, Controlled Folder Access, enterprise proxy/VPN, MDM/domain policy, and standard-user help-desk workflows; and
- accessibility and multi-monitor/scale/DPI behavior where a VM or remote desktop changes the interaction.

A Community Validation Run should use a maintainer-published artifact digest, a fixed scenario ID, explicit consent, local preflight, no automatic upload, local report/redaction preview, and a structured pass/fail/unknown response. Public evidence must exclude raw assessment packages, logs, identifiers, account/tenant data, and unreviewed free-form diagnostics, matching the Wayfinder privacy boundary. A maintainer should verify the evidence contract and freshness before attaching the result to the Supported-device Validation Matrix.

For each proposed Supported row, require at least one current physical run for every hardware-dependent capability and independent corroboration when practical. VM evidence can keep a row in Preview and can prove software paths; it cannot, alone, promote physical collector behavior to Supported. Exact sample counts, defect tolerance, and recency windows remain decisions for [Define support tiers and release-evidence thresholds](https://github.com/jmanuelng/WIN_PCinfo/issues/9).

## Staged validation topology

| Stage | Trigger | Infrastructure | Required output | Promotion role |
|---|---|---|---|---|
| 0 — Automated Gate | Every pull request and protected-branch update | `windows-2022`, `windows-2025`; scheduled `windows-11-arm` while preview | Test results plus commit, runner image/version, tool versions, architecture, fixture/schema version, artifact digest | Blocks merge for deterministic failures; Arm64 preview failures require triage but are initially advisory. |
| 1 — Client VM Validation | Preview/release candidate and client-sensitive changes | Clean local Hyper-V Windows 11 x64 VM profiles | Standard-user/admin results, interaction checklist, cleanup result, OS/edition/build/config manifest, sanitized output | Blocks preview when a declared client path fails; supplies controlled evidence for Preview rows. |
| 2 — Optional cloud specialization | Capacity shortfall or unrepresented Arm64/client configuration | Paid GitHub Windows 11 larger runner or disposable Azure x64/Arm64 VM | Same evidence contract plus provider image/SKU and cost/run | Supplements, but does not replace, local or physical evidence. |
| 3 — Community Validation Run | Public preview candidate | Opt-in physical/external devices | Locally reviewed redacted result bound to scenario and artifact digest | Expands hardware/OEM/policy coverage; failures create or update matrix gaps. |
| 4 — Supported-device review | Stable candidate and scheduled recertification | Evidence ledger across all preceding stages | Supported-device Validation Matrix with provenance, recency, outcome, and known limitations | Only rows meeting [Define support tiers and release-evidence thresholds](https://github.com/jmanuelng/WIN_PCinfo/issues/9) may be called Supported; stable remains blocked if required rows lack current evidence. |

## Unresolved facts and pre-implementation checks

These facts cannot be resolved from public documentation and must remain explicit rather than assumed:

- Whether the available Windows Server host is 2019 or newer, has a Windows 11-compatible CPU, enough reserved RAM/storage/IOPS, and an operational backup/recovery boundary. Record only pass/fail and capacity class publicly.
- Which Windows client, VDA, Visual Studio, or Microsoft 365 rights—if any—are already available; which acquisition channel applies; whether the lab is locally or remotely accessed; and the approved activation method. Do not publish entitlement or tenant details.
- Whether the GitHub repository will be owned by an organization on Team/Enterprise and can create Windows 11 larger runners; partner-image region and terms must be checked at the time of creation.
- Azure subscription offer eligibility, Arm64/x64 regional image availability, quota, egress/storage requirements, and an exact capped monthly budget.
- Which Windows editions/releases and device classes [Define support tiers and release-evidence thresholds](https://github.com/jmanuelng/WIN_PCinfo/issues/9) will require. Microsoft currently lists supported client releases separately and updates the list over time, so the matrix must be generated from a versioned policy rather than hard-coded to this research date. ([supported Windows client releases](https://learn.microsoft.com/en-us/windows/release-health/supported-versions-windows-client))
- Availability of trustworthy community participants or physical devices for priority hardware and managed-policy rows.
- Whether interactive validation requires console access; PowerShell Direct and RDP are insufficient to judge every elevation, accessibility, scaling, and first-run experience.

## Decision-ready conclusion

Adopt the layered topology now: free GitHub-hosted x64 gates, advisory hosted Windows 11 Arm64, and a clean-reset Hyper-V x64 client lab. Prove the local harness with the 90-day Enterprise evaluation, but do not keep or expand the lab until host capacity and a valid ongoing Windows-client virtualization entitlement are confirmed. Do not expose the host as a public self-hosted runner. Escalate to paid GitHub or Azure capacity only against a measured gap and an explicit spend cap. Require privacy-preserving physical/community evidence for every hardware-dependent Supported claim; virtual evidence alone is insufficient.
