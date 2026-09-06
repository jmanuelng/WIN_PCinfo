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
| WinRM | Read WinRM StartMode/State and five exact Service policy-registry values: AllowUnencryptedTraffic, AllowBasic, AllowKerberos, AllowNegotiate, AllowCredSSP. | Registry signals do not establish effective authentication or defaults. A running service cannot establish configured listeners. |
| SMB | Import the fixed inbox SmbShare and DISM manifests in native Core mode. Compare the three client and five server Boolean settings, and SMB1Protocol optional-feature state. | No share/session enumeration, negotiated signing/encryption, guest use or SMB1 usage claim. EnableSecuritySignature is ignored by SMB2 and newer. |
| Legacy authentication | Read LmCompatibilityLevel and NtlmMinClientSec/NtlmMinServerSec from the fixed LSA paths. | Exact configuration levels/masks only; no traffic, dependency, organization-wide restriction or protocol-use claim. |

For each implemented field, compare its source identity, context, collection time,
typed value/value state, Evidence Coverage reason, rule input and protected HTML.
Exercise existing service-stopped, provider-unavailable and restricted-access
states without changing settings to manufacture a scenario. Check Windows build
and edition explicitly; catalog guidance does not confer a Supported claim.
Separate denied access, unsupported sources, malformed values and partial fields.
Confirm encrypted package reopening and complete owned viewing cleanup.

## Unimplemented sources; no acceptance claim

- `field:policy.winrm.auth-certificate`: no released, documented request-free
  source is established. The authentication scope is Partial when policy values
  are usable, with an explicit source-not-implemented reason. The field is absent
  from observations; this never means certificate authentication is false.
- `field:policy.winrm.listener-state`, `listener-transport`, `listener-port`:
  no released request-free source is established. The listener scope is
  Constrained with `POLICY.WINRM_REQUEST_FREE_LISTENER_SOURCE_NOT_IMPLEMENTED`.
  No listener source executed in controlled or live validation. This is an
  implementation limitation, not an absent/disabled environmental listener.

These fields require a separately reviewed bounded local source before their
full product acceptance. Their required-field status must be resolved by the
#145 Spec review and parent acceptance register; honest coverage is not a waiver.
An explicitly authorized manual WSMan comparison in a separate human session
would remain external comparison evidence and would not implement these sources.
Do not run that comparison during the Local Only observer gate.

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
direct mapping for the excluded listener/certificate-auth fields.

Versioned guidance uses Microsoft's
[update scan-source guidance](https://learn.microsoft.com/en-us/windows/deployment/update/wufb-wsus)
and [SMB signing overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview).
Registry freshness stays unproven; the report identifies potentially stale
configuration without pretending to detect a last-applied time.

The frozen private #160 candidate, its signature/recipient/keys and its pending
live gates remain unchanged. Historical #138 resource excess remains unresolved
for #158/#161. This document claims no full-suite, live, device-support or release
acceptance result.
