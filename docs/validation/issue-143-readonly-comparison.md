# Private security-control comparisons for #161

Status: **Pending live authorization and execution**. Synthetic success cannot
pass this session. Bind every comparison to the exact approved candidate and
protected output, capture source/context/version and collection time privately,
and retain Pass/Fail/Blocked or justified NotApplicable dispositions. Actual
machine identifiers, records, HTML, screenshots and diagnostic values belong in
the approved private location outside public source/issues/logs.

After the operator approves the candidate's complete Preparation Plan, perform
the generated Comprehensive run and reopen its protected report. Compare only
the release catalog's named values, close to collection time. Do not change
Defender, Firewall, policy, services or enrollment to manufacture a scenario.
Do not dump complete preferences (including exclusions), broad registry trees,
firewall rules, security event logs, credentials or other secret-adjacent data.

| Family / read-only source | Expected private comparison and limit |
| --- | --- |
| Defender AV / inbox `Get-MpComputerStatus` | Compare AMRunningMode, AntivirusEnabled and RealTimeProtectionEnabled. Normal, Passive Mode, SxS Passive Mode and EDR Block Mode remain observed values with distinct meaning. A missing/null property is Partial without a guessed boolean; zero results are Unavailable, denied queries Denied, absent provider Unsupported. A passive source does not prove tenant onboarding or primary AV identity. |
| Tamper protection / `IsTamperProtected` from the same status | Compare the reported boolean separately from AV mode/preferences. A missing field on the observed Windows/Defender version is an explicit runtime gap, never false. True produces only the existing advisory constraint; perform no tamper-protection toggle or write probe. |
| Firewall / inbox `Get-NetFirewallProfile -PolicyStore ActiveStore` | Compare Domain, Private and Public enabled, default inbound and default outbound values independently. Missing/duplicated/malformed profiles retain their own gaps. ActiveStore does not prove which profile is attached to every interface, firewall rule coverage or external reachability; no rule enumeration or connection test is part of this comparison. |
| ASR / `Get-MpPreference` projected to AttackSurfaceReductionRules_Ids and AttackSurfaceReductionRules_Actions only | Compare each paired rule ID/action; never expose exclusions. Null arrays in a successful complete result represent configured absence. Missing properties, unequal lengths, malformed pairs and more than sixteen rules must be explicit. The report retains at most sixteen pairs with a bound reason, and never claims those preferences prove effective blocking. |
| Network protection / EnableNetworkProtection only | Compare Disabled, Enabled, AuditMode or NotConfigured as configured preferences. Missing/unsupported/denied data stays a gap. Audit mode cannot be presented as blocking; no traffic or protection test is authorized by this row. |
| SmartScreen / exact release registry signals | Compare EnableSmartScreen and PreventOverrideForFilesInShell under the cataloged Windows System policy key, plus ConfigureAppInstallControlEnabled under the cataloged Windows Defender SmartScreen key. These are configured signals with Unproven attribution. Missing keys/values are Unavailable, not evidence of disabled shell/browser protection; malformed types are explicit. Do not infer policy provenance or uncataloged browser/app-install behavior. |
| Security Center context / bounded product registrations and category health | Compare the bounded registered names and WSC category health separately from runtime state. Multiple/stale/coexisting registrations must not select a winning or active provider. Keep all names private. |

For each family, verify that the same observed values, value states, coverage
reason, subject, approved source, execution context, time and source locale reach
the canonical record and the HTML security section after protected reopening.
Check applied policy remains in its separate section; registry/preferences are
Configured Policy Signals and runtime/ActiveStore are Current Control State.
Inspect the source details without scripting, compare the versioned findings and
recommendation evidence links, and confirm no unavailable protection setting is
rendered enabled/disabled or organizationally compliant. Review prerequisites and
tenant-side tasks with the responsible policy owner before any later change.

Use already-approved Windows 10/11 and managed/unmanaged/passive/non-English
environments where available. Missing environments remain Blocked/pending; an
unsupported field can pass only when collection actually executes and accurately
explains the legitimate environmental gap. Verify real viewing cleanup and keep
recoverable protected artifacts if cleanup fails. Local Only packet/process
attribution, live timing/resource budgets, full integration, recipient opening
and deliberate export remain their existing #158/#161 gates. This document
authorizes none of those live operations itself.
