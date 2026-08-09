# Stable 2.0.0 supported-device matrix: factual constraints

Checked: 2026-08-09

This note gathers current Microsoft facts that constrain the Stable 2.0.0 device matrix. It does not decide the matrix. A WIN-PCInfo `Supported` claim remains capability-, scenario-, release-, and evidence-specific; it is not a promise that Microsoft supports the operating system or that every assessment will complete.

## Decision-ready summary

- **Use a release-bound Windows 11 Enterprise 25H2 x64 Azure baseline, not an unqualified “latest Windows 11” baseline.** Microsoft currently distributes 25H2 evaluation media, while 26H1 is intended for select new devices rather than ordinary in-place enterprise deployment.
- **Treat Windows 10 22H2 as an end-of-support/ESU compatibility lane.** It can remain runtime-eligible and could receive a WIN-PCInfo `Supported` claim, but only after the project establishes an approved Windows 10 image and licensing source. The former Evaluation Center page no longer supplies the media, and no baseline was created when the project adopted its image policy.
- **Claim x64 first.** Arm64 exists for Windows 11 evaluation and Trusted Launch, but it is a separate architecture and image/tooling lane. It should remain `Not yet supported` until it has its own complete evidence closure.
- **Keep the minimum virtual matrix small and named.** Cover a fresh workgroup/local-account VM with Defender active, Local Only/offline behavior, restricted Microsoft connectivity, a Full Outbound diagnostic control, the adopted privilege paths, and at least one real non-English Windows execution. Add Entra, Intune, Defender for Endpoint, hybrid, co-management, and third-party-security rows only when the actual external services and products are present.
- **Do not use Azure VM evidence for physical claims.** Microsoft explicitly excludes VMs from Windows enrollment TPM attestation even when vTPM is enabled. Firmware, OEM drivers, batteries, peripherals, biometrics, wireless hardware, and physical-device performance need physical or qualifying Community Validation evidence.

## Windows lifecycle and image availability

### Windows 10

Windows 10 Enterprise 22H2 was the final non-LTSC Windows 10 release. Ordinary support ended on 2025-10-14. This is independent of whether WIN-PCInfo chooses to validate a compatibility scenario. [Microsoft lifecycle: Windows 10 Enterprise and Education](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education)

The Windows 10 Extended Security Updates program can deliver critical and important security updates to enrolled 22H2 devices, but it does not add features, general product support, or a new lifecycle. Microsoft lists Azure virtual machines among the environments receiving ESU at no additional **ESU** charge. That statement must not be presented as proof of the underlying Windows client license. [Windows 10 ESU program](https://learn.microsoft.com/en-us/windows/whats-new/extended-security-updates)

Intune still permits Windows 10 enrollment after end of support, but Microsoft says eligible functionality is not guaranteed and can vary. A successful enrollment therefore cannot be reported as Microsoft lifecycle support. [Windows enrollment attestation](https://learn.microsoft.com/en-us/intune/device-enrollment/windows/attestation)

The former Windows 10 Enterprise Evaluation URL now redirects to end-of-support guidance rather than offering evaluation media. The current source-of-media policy cannot assume that a fresh Windows 10 evaluation ISO remains obtainable from that page. [Former Windows 10 Enterprise Evaluation URL](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise)

**Matrix consequence:** a Windows 10 Enterprise 22H2 x64 `Supported` row is conditional on all of the following being established at release time:

1. an approved lawful image source under the project’s licensing interpretation;
2. a pristine, generalized, release-approved gallery baseline created before any WIN-PCInfo or test configuration;
3. the exact current 22H2/ESU patch level used by the run; and
4. public wording that separates `WIN-PCInfo Supported` from `Microsoft lifecycle: end of support / ESU`.

If those conditions are not met, Windows 10 remains runtime-eligible but the scenario cannot be promoted to `Supported`.

### Windows 11

As checked, the Enterprise/Education lifecycle table lists these non-LTSC releases: 23H2 through 2026-11-10, 24H2 through 2027-10-12, 25H2 through 2028-10-10, and 26H1 through 2029-03-13. [Microsoft lifecycle: Windows 11 Enterprise and Education](https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education)

Microsoft describes 26H1 as a release for new devices that came to market in early 2026; it is not offered as an in-place update from 24H2 or 25H2. A matrix should therefore not interpret the highest version number as the single representative enterprise baseline. [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information)

The current Evaluation Center offers Windows 11 Enterprise 25H2 as a 90-day evaluation with no product key required. It provides x64 and Arm64 ISOs in English (US/UK), Chinese (Simplified/Traditional), French, German, Italian, Japanese, Korean, Portuguese (Brazil), and Spanish. [Windows 11 Enterprise Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)

**Matrix consequence:** select the exact approved image version at release time. Windows 11 Enterprise 25H2 x64 is the currently documented evaluation baseline. Older still-serviced feature versions need not inherit `Supported`, and 26H1 should remain `Not yet supported` unless an approved representative baseline and complete evidence are obtained.

## Azure image, architecture, and virtual hardware constraints

Microsoft’s Azure Marketplace Windows client dev/test path requires an appropriate Visual Studio subscription and documents Windows 10/11 Enterprise x64 images. Marketplace visibility is tied to eligible subscription offers. This is a different route from downloading a 90-day Evaluation Center ISO. [Use Windows client in Azure for dev/test scenarios](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/client-images)

The project’s adopted image policy permits a persistent **clean generalized gallery baseline** and requires every test client to be a fresh VM created from it. That is not the prohibited practice of capturing a configured or already-tested client. The project forbids capturing, restoring, or reusing post-configuration clients. See [Establish approved Azure Windows client gallery images and licensing](https://github.com/jmanuelng/WIN_PCinfo/issues/22).

For Windows 11 on Azure, Microsoft requires:

- Generation 2;
- at least 64 GB storage;
- Trusted Launch with Secure Boot and vTPM;
- at least 4 GB memory; and
- at least two virtual processors on a qualifying host processor.

[Windows 11 support on Azure virtual machines](https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/windows-11-support-azure-virtual-machines)

The project’s maximum of 2 vCPU and 8 GiB with a Standard SSD is compatible with these minimums only when the OS disk is at least 64 GB and the chosen VM SKU, gallery image, security profile, and region support the required configuration. Those values must be verified rather than inferred from deployment success.

Azure Trusted Launch supports x64 and Arm64, and its vTPM is explicitly a virtualized TPM 2.0 implementation. It can establish the VM’s virtual boot-chain state; it is not evidence about a device’s physical TPM, OEM firmware, or BIOS. [Trusted Launch for Azure virtual machines](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch)

Azure Compute Gallery image definitions can declare `hyperVGeneration: V2` and `SecurityType: TrustedLaunchSupported`. The platform’s newer automatic Trusted Launch image validation is documented as preview, so release admission should still verify the image definition and an actual test boot rather than relying on a default alone. [Azure Compute Gallery overview](https://learn.microsoft.com/en-us/azure/virtual-machines/azure-compute-gallery)

**Architecture consequence:** x64 should be the only mandatory Stable 2.0.0 architecture. Arm64 is feasible as a later, independently evidenced scenario, not an implied extension of x64 evidence.

## Identity and management states in disposable Azure clients

| State | Feasible in a fresh Azure client? | What the evidence can establish |
| --- | --- | --- |
| Workgroup/local account | Yes | The clean local/unmanaged path, local groups, UAC, and device-only evidence. This is the simplest mandatory virtual baseline. |
| Microsoft Entra joined | Yes, with a configured tenant and authorized identity path | A real join, local Entra-visible device state, and local collection under that state. Windows 10/11 editions other than Home support Entra join. [Microsoft Entra joined devices](https://learn.microsoft.com/en-us/entra/identity/devices/concept-directory-join) |
| Intune enrolled | Technically yes, with licenses, MDM scope, and actual enrollment, but Microsoft recommends against on-demand/nonpersistent VMs | Local MDM state and applied policy evidence for the enrolled disposable client. Automatic enrollment depends on the tenant MDM user scope and licensing. Every fresh VM must enroll separately and requires management-plane cleanup. [Windows enrollment guide](https://learn.microsoft.com/en-us/intune/device-enrollment/windows/guide) |
| AD domain joined | Only with a reachable AD DS test environment | Actual domain membership and locally applied domain policy. A standalone client-only round cannot create this state by assertion. |
| Microsoft Entra hybrid joined | Only with AD DS, synchronization, tenant configuration, and domain-controller line of sight | Actual hybrid identity behavior for that exact environment. Microsoft says hybrid devices require periodic domain-controller line of sight. [Plan Microsoft Entra hybrid join](https://learn.microsoft.com/en-us/entra/identity/devices/hybrid-join-plan) |
| Co-managed | Only with Intune, an Entra joined or hybrid-joined identity, and a supported Configuration Manager current-branch site/client | Actual co-management for that exact Configuration Manager/tenant setup. An Entra-registered-only device is insufficient, and remote ConfigMgr communication can require a cloud management gateway. [Co-management overview](https://learn.microsoft.com/en-us/intune/configmgr/comanage/overview) |

The current client-only ephemeral lab does not itself supply AD DS, Entra Connect, or Configuration Manager. Hybrid join and co-management should remain `Not yet supported` unless a separately approved external managed environment or qualifying Community Validation supplies the real state.

Microsoft supports Intune management of Windows Enterprise VMs with limitations, but recommends against on-demand/nonpersistent VMs because every new VM must enroll and routine deletion leaves orphaned device records until cleanup. It also states that RDP-only Azure VMs do not support Commercial OOBE, Autopilot, or Enrollment Status Page, and that VM scenarios do not support TPM-dependent Intune configuration such as BitLocker or DFCI. Intune also forbids cloning an image that is already enrolled; a clean generalized pre-enrollment baseline does not contain those replicated enrollment tokens. [Using Windows virtual machines with Intune](https://learn.microsoft.com/en-us/intune/solutions/windows-virtual-machines)

An Azure-specific Entra sign-in extension can join supported Azure VMs, but it requires a system-assigned managed identity, the extension, role assignments, and defined endpoints. It is an infrastructure-specific scenario and must not silently stand in for every ordinary Entra-join path. [Microsoft Entra sign-in for Windows Azure VMs](https://learn.microsoft.com/en-us/entra/identity/devices/howto-vm-sign-in-azure-ad-windows)

Managed scenarios also have management-plane teardown. Deleting a VM does not, by itself, prove removal of its Intune, Entra, or Defender for Endpoint records. Intune’s delete action removes management and may also require removal of the Entra record. Defender for Endpoint offboarding stops new reporting, but Microsoft keeps past service data under its retention policy and can show the empty device profile for up to 180 days. A truthful round contract can promise no active/reporting test endpoint and no active customer-created Azure, Intune, or Entra object; it cannot promise deletion of provider-retained history. [Intune device deletion](https://learn.microsoft.com/en-us/intune/device-management/actions/delete), [Defender for Endpoint offboarding](https://learn.microsoft.com/en-us/defender-endpoint/offboard-machines), and [Defender for Endpoint data retention](https://learn.microsoft.com/en-us/defender-endpoint/data-storage-privacy)

This is consistent with the project’s `Zero Round Residue` boundary, which already excludes unavoidable provider audit and security records. See [Define ephemeral Azure validation orchestration](https://github.com/jmanuelng/WIN_PCinfo/issues/20).

## Defender and third-party antivirus states

Microsoft’s Windows-client behavior requires separate scenarios rather than one “antivirus installed” row:

| Primary antivirus | Defender for Endpoint onboarded? | Expected Microsoft Defender Antivirus condition |
| --- | --- | --- |
| Microsoft Defender Antivirus | No or yes | Active |
| Genuine non-Microsoft antivirus | Yes | Passive automatically; EDR in block mode is a further distinct condition |
| Genuine non-Microsoft antivirus | No | Usually disabled automatically; Windows 11 Smart App Control can alter the observed passive/disabled result |

Passive mode requires Defender Antivirus installed, a non-Microsoft product acting as primary antivirus, Defender for Endpoint onboarding, and Windows Security Center running. `Normal`, `Passive`, and `EDR Block Mode` are distinct reported values. [Microsoft Defender Antivirus compatibility with other security products](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility)

**Matrix consequence:**

- require a fresh-client Defender-primary/active row as the virtual core;
- add Defender-primary/active plus Defender for Endpoint only when actual onboarding and cleanup are available;
- never synthesize a third-party state by changing a registry value or disabling a service;
- qualify each real third-party product/version and Defender-for-Endpoint combination separately; and
- leave broad “third-party antivirus compatible” or passive-mode claims `Not yet supported` until genuine evidence exists.

## Network, privilege, and locale dimensions

### Network

The matrix has two different concepts and should not merge them:

1. the **Assessment Network Behavior** chosen by WIN-PCInfo (`Local Only` or `Microsoft Connectivity Enabled`); and
2. the lab’s **Validation Egress Profile** (`Restricted` or the temporary diagnostic `Full Outbound`).

A small named set can cover the material behavior without testing every cross-product:

- `Local Only` with public outbound blocked, proving no unexpected assessment request;
- `Microsoft Connectivity Enabled` with the current versioned restricted profile; and
- one `Microsoft Connectivity Enabled` Full Outbound run as a diagnostic control.

The blocked profile is not a literal block on Azure’s platform channel. It must preserve the Azure VM Agent path to `168.63.129.16` on the documented ports, plus the project’s DNS and transfer invariants. That platform exception is infrastructure traffic and must not be mistaken for an assessment network request. [Azure Windows VM Agent troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/windows-azure-guest-agent)

Microsoft’s endpoint requirements change. Intune publishes a consolidated endpoint list and warns that TLS inspection is unsupported for several management and attestation destinations. Defender for Endpoint likewise publishes a current streamlined-connectivity list. The restricted profile should be versioned and refreshed from official sources, with observation time recorded; it should not be a permanent copied list. [Intune network endpoints](https://learn.microsoft.com/en-us/intune/fundamentals/endpoints) and [Defender for Endpoint streamlined connectivity](https://learn.microsoft.com/en-us/defender-endpoint/streamlined-device-connectivity-urls-commercial)

### Privilege

The adopted release gate already requires these meaningful paths:

- standard-user launch followed by the single approved elevation;
- already-elevated administrator launch with no redundant prompt;
- elevation denial with honest partial coverage; and
- the predefined, frozen SYSTEM evidence plan.

These are product execution paths, not four operating-system support editions. Avoid using only Azure’s initial built-in administrator as evidence for an ordinary split-token UAC experience. The privilege contract comes from [Define the first public preview slice](https://github.com/jmanuelng/WIN_PCinfo/issues/11) and the reference workload from [Define measurable product quality budgets](https://github.com/jmanuelng/WIN_PCinfo/issues/15).

### Locale

The Windows interface is English, but execution and evidence must remain language-neutral. Current Evaluation media directly supplies Spanish and Japanese, which makes either a practical real non-English VM row. Keep culture/Unicode fixtures for `en-US`, `es-MX`, `tr-TR`, `ja-JP`, and `ar-SA`; a fixture is not a substitute for at least one actual non-English Windows run.

Language packs and their Features on Demand must match the Windows version, and adding them changes the image. Prefer a release-approved Microsoft evaluation ISO in a supplied language for a pristine localized baseline. If language components are added, treat that as a separately governed generalized baseline created before test payloads, not a per-run mutation. [Add languages to Windows images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-language-packs-to-windows?view=windows-11)

## What virtual validation can and cannot establish

### Azure VM evidence can establish

- application installation, launch, runtime, progress, cancellation, collection, packaging, reporting, and cleanup behavior;
- standard/elevated/SYSTEM execution and permission-denied coverage behavior;
- Windows, registry, CIM/WMI, policy, filesystem, service, and virtual-device evidence exposed by the guest;
- actual network behavior under controlled egress and proxy/DNS/TLS scenarios;
- actual Entra join, Intune enrollment, MDM policy, or Defender for Endpoint state when the VM is genuinely connected to those services; and
- virtual Secure Boot, vTPM, BitLocker, VBS, and Trusted Launch observations for the exact Azure scenario.

### Azure VM evidence cannot establish

- physical TPM or Windows enrollment attestation: Microsoft explicitly says Azure and Hyper-V VMs cannot perform this attestation even with vTPM; [Windows enrollment attestation](https://learn.microsoft.com/en-us/intune/device-enrollment/windows/attestation)
- Commercial OOBE, Autopilot, Enrollment Status Page, and TPM-dependent Intune management on RDP-only Azure VMs; [Using Windows virtual machines with Intune](https://learn.microsoft.com/en-us/intune/solutions/windows-virtual-machines)
- OEM BIOS/UEFI behavior, firmware updates, physical TPM ownership, DFCI, or vendor-specific drivers;
- battery, docking, camera, biometric, Wi-Fi, Bluetooth, USB/removable-media, printer, or other physical peripheral behavior;
- physical-device power transitions, thermal behavior, or representative physical performance;
- Autopilot paths that depend on physical TPM attestation;
- organization-managed GPO, hybrid identity, Configuration Manager, co-management, proxy, or TLS-inspection behavior unless the VM is connected to a real representative environment; or
- broad compatibility with third-party security products from one vendor/version test.

Virtual evidence should explicitly label Azure Agent, virtual NIC/disk, vTPM, and virtual firmware observations as virtual artifacts rather than general physical-device evidence.

## Suggested minimum claim structure for Stable 2.0.0

This is a factual consequence, not the final decision:

1. **Mandatory virtual core:** Windows 11 Enterprise 25H2 x64, latest release-approved patch, fresh Gen2 Trusted Launch VM, workgroup/local account, unmanaged, Defender active, English, with the named network and privilege runs above.
2. **Language-neutral execution:** reuse one core scenario with an approved Spanish or Japanese baseline and the full automated culture/Unicode fixture set.
3. **Managed capability row:** add Entra joined + Intune enrolled and/or Defender for Endpoint only if actual tenant-backed setup, management-plane cleanup, and fresh evidence exist. This row supports only the capabilities materially exercised by management.
4. **Conditional Windows 10 lane:** Windows 10 Enterprise 22H2 x64, end-of-support/ESU, only if image/licensing/patch conditions are resolved. Do not let this block Windows 11 Stable publication unless the product decision explicitly makes Windows 10 mandatory.
5. **Remain `Not yet supported` initially:** Arm64, older Windows 11 feature-version families, 26H1, hybrid join, co-management, broad third-party antivirus, physical firmware/TPM/attestation, battery, peripherals, OEM drivers, and other physical-device claims unless their independent evidence closure is complete.

## Reconciliation with adopted project decisions

The constraints above preserve the existing decisions:

- [Define support tiers and release-evidence thresholds](https://github.com/jmanuelng/WIN_PCinfo/issues/9): claims stay capability/scenario/release-specific; LTSC is excluded; runtime eligibility is broader; Stable virtual rows require at least three successful fresh-client runs across at least two rounds; physical/external scenarios use their separate threshold.
- [Define the first public preview slice](https://github.com/jmanuelng/WIN_PCinfo/issues/11): latest-patched non-LTSC Enterprise x64 is the initial claim boundary; physical, externally managed, co-management, and real third-party scenarios need applicable evidence.
- [Define measurable product quality budgets](https://github.com/jmanuelng/WIN_PCinfo/issues/15): the reference class is 2 vCPU, 8 GiB, Standard SSD; offline/restricted/full egress, privilege, locale, and exact candidate evidence stay independent gates.
- [Define ephemeral Azure validation orchestration](https://github.com/jmanuelng/WIN_PCinfo/issues/20): every VM is fresh, at most four exist, Trusted Launch and Standard SSD are required, the lab is private, and each round proves zero customer-created residue.
- [Establish approved Azure Windows client gallery images and licensing](https://github.com/jmanuelng/WIN_PCinfo/issues/22): clean gallery baselines may persist, but no configured/tested client is captured or reused; the present Windows 10 source gap must be resolved rather than hidden.
- [Reconcile capability-ledger support dependencies and operability obligations](https://github.com/jmanuelng/WIN_PCinfo/issues/29): Community Validation remains conditional for scenarios the controlled VM lab cannot credibly establish, while language-neutral execution and basic primary-path operation remain mandatory.

## Decision gates still requiring an owner

1. Is a Stable Windows 10 `Supported` row mandatory, or may Windows 10 remain runtime-eligible/Preview until an approved media path exists?
2. If Windows 10 is mandatory, what lawful base-image source and ESU activation/patch evidence are approved?
3. Are Entra-joined, Intune-enrolled, and Defender-for-Endpoint-onboarded rows Stable requirements or later capability-specific promotions?
4. Which real non-English evaluation baseline is approved: Spanish or Japanese?
5. Which physical or Community Validation rows are mandatory for the specific Stable capabilities, rather than for the product as a whole?
