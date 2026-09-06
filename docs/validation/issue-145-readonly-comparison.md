# Update, remote management, SMB and legacy-authentication comparison (#161)

Status: **Pending live acceptance**. This handoff does not authorize an assessment,
UAC, service/configuration change, request, certificate operation or publication.
Use the exact privately admitted candidate and frozen Preparation Plan in #161.
Keep machine identities, registry values, screenshots, observer logs and package
contents in the approved private workspace. Publish only sanitized outcomes.

## Implemented source comparisons

| Family | Bounded source and comparison | Honest interpretation |
| --- | --- | --- |
| Windows Update/WUfB | Read the three exact WindowsUpdate policy values: DeferFeatureUpdatesPeriodInDays, DeferQualityUpdatesPeriodInDays, DisableDualScan. Compare canonical values, absence, provenance and HTML with the same private read interval. | Configured signals with unproven freshness/channel. No update scan, success, active ring or tenant intent follows from the values. Windows 11 does not support DisableDualScan; Windows 10 uses legacy guidance. |
| RDP | Read fDenyTSConnections, the TermService StartMode/State, the fixed RDP-Tcp Win32_TSGeneralSetting projection and its fEnableWinStation value. | Configuration is separate from service runtime. Disabled configured listener and absent provider are different; neither establishes reachability, sessions or use. |
| WinRM | Read WinRM StartMode/State and five Service policy values. In Registry64 HKLM, compare the explicit WSMAN Service auth_certificate DWORD and at most 32 direct Listener selector records (Port/enabled DWORD, +HTTP/+HTTPS identity only). | Explicit local configuration does not establish effective authentication, listener completeness, defaults or runtime. Compare aggregate configured state; shared port/transport only when all records agree. |
| SMB | Import the fixed inbox SmbShare and DISM manifests in native Core mode. Compare the three client and five server Boolean settings, and SMB1Protocol optional-feature state. | No share/session enumeration, negotiated signing/encryption, guest use or SMB1 usage claim. EnableSecuritySignature is ignored by SMB2 and newer. |
| Legacy authentication | Read LmCompatibilityLevel and NtlmMinClientSec/NtlmMinServerSec from the fixed LSA paths. | Exact configuration levels/masks only; no traffic, dependency, organization-wide restriction or protocol-use claim. |

For each implemented field, compare its source identity, context, collection time,
typed value/value state, Evidence Coverage reason, rule input and protected HTML.
Exercise existing service-stopped, provider-unavailable and restricted-access
states without changing settings to manufacture a scenario. Check Windows build
and edition explicitly; catalog guidance does not confer a Supported claim.
Separate denied access, unsupported sources, malformed values and partial fields.
Confirm encrypted package reopening and complete owned viewing cleanup.

## Newly implemented sources; live comparison pending

The correction sources and static primary-code proof are recorded in
[issue-145-winrm-source-proof.md](issue-145-winrm-source-proof.md). Compare
explicit certificate true/false and unknown after absent/denied/malformed reads.
Do not infer absent defaults or inspect certificate-mapping/credential blobs.

For listeners, compare ConfiguredEnabled/ConfiguredDisabled/ConfiguredMixed with
the explicit local records and the separate observed service runtime. Verify
custom ports, multiple records with equal and differing ports/transports, denied
access, missing values and unsupported selector shapes. No selector address,
certificate thumbprint or hostname should enter canonical evidence or HTML.
Empty storage must remain unknown, not an observed absence of listeners.

Listener coverage stays Partial because policy-created, compatibility and default
expansion, override precedence and current listening remain unobserved. Check
those limits appear in the protected report, and validate Windows 10/11 source
applicability with the exact admitted candidate. No live OS compatibility result
follows from static inspection of one installed component.

An explicitly authorized manual WSMan comparison in a separate human session
remains external comparison evidence. Do not run it during the Local Only
observer gate. The product source sends no WSMan/HTTP requests in either mode.

## Request and privacy checks

Both product network modes use the same request-free sources for this family.
Observe the exact candidate in #161/#148: no WSMan provider, WinRM executable,
management session, protocol login, update scan or SMB enumeration is authorized
by this collector. Localhost is not an exception. Microsoft documents local
WinRM requests and fallback port 47001 in
[Obtaining Data from the Local Computer](https://learn.microsoft.com/en-us/windows/win32/winrm/obtaining-data-from-the-local-computer).

The reviewed finite policy mappings are corroborated by the inbox
WindowsRemoteManagement.admx Service mappings and Microsoft's
[RemoteManagement Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotemanagement).
The [WSMan provider reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/about/about_wsman_provider)
says configuration is stored in the registry, but does not establish a stable
direct mapping for listener/certificate-auth fields; the bounded installed-service code trace supplies that mapping for the inspected component.

Versioned guidance uses Microsoft's
[update scan-source guidance](https://learn.microsoft.com/en-us/windows/deployment/update/wufb-wsus)
and [SMB signing overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview).
Registry freshness stays unproven; the report identifies potentially stale
configuration without pretending to detect a last-applied time.

The frozen private #160 candidate, its signature/recipient/keys and its pending
live gates remain unchanged. Historical #138 resource excess remains unresolved
for #158/#161. This document claims no full-suite, live, device-support or release
acceptance result.
