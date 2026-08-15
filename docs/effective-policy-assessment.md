# Applied Group Policy and local security policy

This preview slice answers three related but different questions after the operator approves the immutable Preparation Plan:

1. **Applied Policy Evidence** reads the locally cached Resultant Set of Policy (RSoP) logging namespaces for the Assessment User Context and the computer. The standard-user identity collector verifies the interactive user through local WTS and LSA data, then sends that private SID only through the authenticated, ACL-protected one-run channel; the elevated worker uses the exact SID-specific cached user namespace. An alternate operator or administrator therefore cannot substitute their own user policy. It records bounded policy-object identity, enabled link state, link identity, and precedence only for the release-cataloged `RSOP_RegistryPolicySetting` extension. The base-class query reads only finite identity/reference fields so another derived extension becomes explicit `Unsupported` coverage; an extension-relative `id` is never treated as globally unique. It does not refresh Group Policy, contact a domain controller, enumerate unapplied policy, or parse a localized report.
2. **Configured Policy Signals** reads three exact local registry values: machine inactivity timeout, secure-attention-sequence behavior, and LAN Manager compatibility level. A value is a configured signal only. It does not prove who configured it, why it exists, or whether another mechanism currently enforces the related control.
3. **Policy CSP result signals** reuse the predefined SYSTEM sub-plan to read one fixed `MDMWinsOverGP` flag and the same three security-option fields from the release-owned Windows 10 and Windows 11 `MDM_Policy_Result01_*` catalogs. `MDMWinsOverGP` is reported only for that documented Policy CSP scope. WIN-PCInfo does not turn it into a blanket claim that all MDM, Intune, CSP, or tenant policy wins over Group Policy.
4. **Current Control State** reads the local SAM account and lockout policy, three Audit Policy subcategories, and three direct LSA user-right assignments. Local SAM policy applies to local accounts, not domain accounts. A user-right SID is a direct assignment only; WIN-PCInfo never expands groups to guess effective access.

Registry values do not expose a trustworthy last-applied timestamp through the approved read-only interface. The live collector therefore reports source attribution and freshness as unproven; it never labels a value fresh or stale. The synthetic `StaleRegistry` case verifies that an upstream typed stale state would remain an explicit gap, but it is not a claim that this preview detects live registry staleness.

## Sources and bounds

The frozen operation is `observe-effective-policy`. It runs once in the already-approved Administrator worker, offline, for at most five seconds, with a 16 KiB result ceiling. It may not prompt again, install or download a tool, invoke a caller command, write policy, refresh policy, or open a network connection.

The locale-neutral structured source catalog is:

- cached `RSOP_GPO` and `RSOP_GPLink` instances plus the finite `RSOP_RegistryPolicySetting` setting class in the Assessment User SID-specific and computer namespaces; the abstract `RSOP_PolicySetting` query is used only to detect and reject unsupported derived extensions;
- `NetUserModalsGet(NULL, 0)` and `NetUserModalsGet(NULL, 3)` for local SAM policy;
- `AuditQuerySystemPolicy` for the exact Logon, Process Creation, and User Account Management subcategory GUIDs;
- `LsaEnumerateAccountsWithUserRight` for `SeRemoteInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`, and `SeServiceLogonRight`; and
- the predefined SYSTEM sub-plan over `Root\cimv2\mdm\dmmap`, restricted to `MDM_Policy_Result01_ControlPolicyConflict02` and `MDM_Policy_Result01_LocalPoliciesSecurityOptions02` plus the four release-owned properties; and
- read-only `Microsoft.Win32.Registry.LocalMachine.OpenSubKey` calls for the three release-cataloged configured signals.

These interfaces are documented by Microsoft: [RSoP WMI classes](https://learn.microsoft.com/windows/win32/rsop/rsop-wmi-classes), [NetUserModalsGet](https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsget), [AuditQuerySystemPolicy](https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy), [LsaEnumerateAccountsWithUserRight](https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountswithuserright), [the LocalPoliciesSecurityOptions result class](https://learn.microsoft.com/en-us/windows/win32/dmwmibridgeprov/mdm-policy-result01-localpoliciessecurityoptions02), and [the documented scope of MDMWinsOverGP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-controlpolicyconflict#mdmwinsovergp).

WIN-PCInfo does not install LGPO, RSAT/GPMC, PsExec, or any other policy tool. It does not call `gpresult`, `secedit`, `auditpol`, `net.exe`, or `Get-GPO` and does not parse human-facing output.

## Missing and conflicting evidence

A successfully queried empty RSoP namespace or an absent enabled link is represented as observed absence. Multiple enabled links, missing namespaces, individual missing RSoP classes, an unsupported setting extension, a failed NetAPI level, denied sources, an upstream typed stale registry signal, unavailable registry signals, malformed values, timeouts, cancellation, and incomplete channels remain field-specific Evidence Coverage gaps with diagnostics. The frozen eight-policy and eight-setting ceilings are checked before projection; overflow retains only the bounded subset and reports `Partial` with `POLICY.RSOP_EVIDENCE_BOUND_EXCEEDED`. Negative or zero precedence and ambiguous links are never clamped or selected. These conditions never become a false empty policy or an affirmative setting.

Five bounded rules produce separate findings:

- whether applied-policy evidence is complete;
- whether the finite local-security catalog is complete; and
- whether the same setting has competing policy objects in the observed precedence data;
- whether the Policy CSP result catalog is completely observable on the current build; and
- whether the local configured signal and the Policy CSP result disagree for one of the three release-cataloged settings.

An observed conflict is `NeedsAttention`, not a compliance failure or remediation instruction. Insufficient evidence is `Indeterminate`. If Policy CSP coverage is incomplete, or if a local signal and a Policy CSP result disagree, WIN-PCInfo emits tenant-side discovery tasks instead of guessing assignment intent, winning source, remediation, compliance, or organization-wide state. WIN-PCInfo does not assign an overall score, infer organizational intent, or change a policy.

## Privacy and troubleshooting

Policy object IDs, link paths, setting IDs, configured values, local account-policy values, and assigned principal SIDs are Restricted Diagnostic Evidence. They appear only in the canonical record and beginner report inside the Protected Evidence Package. Progress and public validation output contain only release-owned states, findings, counts, and safety assertions.

If the report shows an RSoP gap, confirm that the device has a locally cached logging-mode RSoP namespace; do not install a tool merely to satisfy this preview. If a local source is denied, rerun only through the approved Preparation flow and its single UAC boundary. If a configured signal is unavailable—or another trusted source indicates it may be stale—treat the related finding as Indeterminate and investigate through the organization’s authorized policy-management process. If a Policy CSP result is unsupported, unavailable, or conflicting, confirm build support, deployment channel, assignment scope, and intended precedence through the organization’s authorized MDM administration process rather than guessing from one device.
