# #144 private read-only comparison handoff to #161

Status: **Pending live validation**. Controlled sources establish implementation
behavior only. Use #161's concrete candidate and authorized private evidence area;
do not reuse signatures, evidence, or approvals from the separate #160 candidate.
No live collection, elevation, trust change, security-setting change, or release
approval was performed for #144.

Use the delivered generated Comprehensive assessment, frozen upfront privilege
plan, existing initiating-user package protector, and protected viewing session.
Compare the record, individual provenance references, advisory outcomes, coverage
reasons and HTML against the following same-session local sources. Store actual
identifiers, source output, screenshots and measurements only in the approved
private area. Never attach them to GitHub or this repository.

| Required subfamily | Read-only comparison and expected distinction |
| --- | --- |
| BitLocker OS-volume state | Compare only `Win32_EncryptableVolume` status methods: `GetConversionStatus`, `GetProtectionStatus`, `GetEncryptionMethod`, `GetLockStatus`. Check encrypted, suspended/protection-off, unencrypted, unavailable and denied cases as applicable. Record the exact observed state without deriving tenant escrow or physical TPM attestation. |
| BitLocker protectors | Use only type-filtered `GetKeyProtectors` counts for the fixed ten numeric types; retain at most eight type groups and 32 protectors per group. Do not retain protector identifiers. **Do not call `Get-BitLockerVolume`**, which retrieves numerical recovery passwords internally; never call any recovery-key/password method. |
| VBS/Credential Guard/memory integrity/user-mode code integrity | Compare the four approved `Win32_DeviceGuard` properties. Configured services and running services must remain distinct. Missing properties must produce gaps without observations claiming absence. Test configured-but-not-running and VM constraints without claiming hardware attestation. |
| WDAC/App Control inventory | Confirm Windows build before the fixed inbox `CiTool.exe -lp -json` listing. Below Windows 11 22H2, inventory is Unsupported. Compare active/inactive, platform and signed-policy flags. `IsEnforced` identifies an active policy; it does not prove deny enforcement instead of audit. Deployment channel remains Unknown and coverage Partial when policies exist. No policy bodies, signer material, IDs, policy options, tokens or device ID enter the record. |
| AppLocker GP | Compare `Get-AppLockerPolicy -Effective` from the fixed inbox manifest in the admitted Core host. Only five rule-collection types and their mode are retained. Verify real native module compatibility; no implicit Windows PowerShell 5.1 compatibility process is permitted. GP cannot establish CSP state. |
| AppLocker CSP | Compare only the five declared local-system WMI Bridge classes and their `EnforcementMode` property. The existing SYSTEM phase owns this evidence, with its own collector, context and collection time. Empty/missing mode metadata does not justify reading rule XML or claiming no policy. Different modes across grouping instances remain Partial; GP/CSP disagreement is advisory NeedsAttention with no selected winner. |

The CSP metadata surface has limits: Microsoft's CSP documentation describes
EnforcementMode separately from the Policy XML attribute. A populated metadata
value is recorded only as that source's configured signal. Missing metadata stays
Unavailable even when another private management source shows an applied policy.
Any required richer reconstruction must receive a bounded source design and
tests; do not silently broaden this collector to unrestricted policy XML.

The transport now packs pairs of base64 symbols into a fixed BMP alphabet before
the existing Windows Unicode launch. The 32500-character guard, Brotli payload,
source identity, one-use pipes, Job ownership and SYSTEM boundary remain intact.
Controlled direct and ShellExecute launches do not prove real `runas`/UAC.
Validate both standard launch with its one UAC and already-elevated launch in
#161, including the alternate-administrator path without package ownership
transfer, non-English Windows, cancellation and verified child/task absence.

Check the final full-profile resource measurements in #158/#161. The historical
#138 working-set excess remains unresolved acceptance evidence. No deadline,
fixture pass, or source-size improvement waives it. The private handoff target is
before September 7 00:00 CDT / 05:00 UTC.

Sources: [BitLocker provider methods](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume-methods),
[type-filtered protectors](https://learn.microsoft.com/en-us/windows/win32/secprov/getkeyprotectors-win32-encryptablevolume),
[Device Guard states](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity),
[CiTool semantics and build boundary](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands),
[GP-only AppLocker interface](https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy),
[local-system AppLocker Bridge class](https://learn.microsoft.com/en-us/windows/win32/dmwmibridgeprov/mdm-applocker-dll03),
and [AppLocker CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/applocker-csp).
