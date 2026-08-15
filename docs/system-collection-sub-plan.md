# SYSTEM Collection Sub-plan

WIN-PCInfo has one deliberately narrow path for evidence that Windows does not expose to an ordinary administrator token. It is called the **SYSTEM Collection Sub-plan**. It is a subset of the already approved Privileged Collection Plan, not a second approval and not a SYSTEM shell.

This is still a tracer-bullet slice. The generated application exercises the full contract with synthetic, unelevated fixtures. Ordinary execution does not yet reach real collection or packaging, and this ticket does not make a Product Capability, Preview, or Supported claim.

## Why LocalSystem is necessary here

The release defines exactly one operation: read-only access to a fixed device-scoped MDM bridge surface in `Root\cimv2\mdm\dmmap`. It always records the provider-availability Boolean for `MDM_DeviceManageability_Provider01_01`. For the MDM Policy CSP slice it also reads the exact read-only `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber` value and one release-owned Policy CSP result catalog: the fixed `MDM_Policy_Result01_ControlPolicyConflict02` and `MDM_Policy_Result01_LocalPoliciesSecurityOptions02` classes, with only four approved properties. All four sources, exact result nodes, and five resulting Evidence Scopes are frozen in the operation. It does not invoke provider methods, change MDM state, collect tenant identifiers, dump classes, or admit an arbitrary registry or WMI query.

Microsoft documents that device settings exposed through the MDM WMI Bridge must be accessed as LocalSystem and marks the relevant classes with the `local-system` partition. That is why Administrator is not treated as a sufficient fallback. See [Using PowerShell scripting with the WMI Bridge Provider](https://learn.microsoft.com/en-us/windows/client-management/using-powershell-scripting-with-the-wmi-bridge-provider), [MDM_DeviceManageability_Provider01_01](https://learn.microsoft.com/en-us/windows/win32/dmwmibridgeprov/mdm-devicemanageability-provider01-01), and [MDM_Policy_Result01_LocalPoliciesSecurityOptions02](https://learn.microsoft.com/en-us/windows/win32/dmwmibridgeprov/mdm-policy-result01-localpoliciessecurityoptions02).

If LocalSystem activation is denied or unavailable, WIN-PCInfo reports an explicit coverage gap. It never retries with a broader command, weakens Windows controls, or guesses that the provider is absent.

## What the frozen plan can contain

The release policy and schema admit only:

- operation ID `op:windows.mdm-bridge.device-manageability`;
- parameter `queryKind` with the single value `PolicyCspResultCatalogV1`;
- Evidence Scope `scope:device.mdm-policy.system`;
- Boolean field `field:device.mdm-bridge.provider-available`; and
- collector `collector:windows.mdm-bridge.device-manageability` version `1.0.0`.

The same operation freezes `LocalSystemOnly`, `OfflineOnly`, the active Microsoft-signed PowerShell host, five named platform dependencies, one attempt, a 5-second operation deadline, an 8-KiB result bound, and coordinator-owned Job/task/pipe cleanup. These are operation fields, not assumptions inferred from the runner.

For the Policy CSP result branch, the frozen release catalogs admit only:

- Windows 10 catalog `catalog:policy-csp-result.windows10/1.0.0` for supported builds;
- Windows 11 catalog `catalog:policy-csp-result.windows11/1.0.0` for supported builds;
- field `field:policy.mdm.control-policy-conflict.mdm-wins-over-gp`;
- field `field:policy.mdm.security-option.machine-inactivity-limit-seconds`;
- field `field:policy.mdm.security-option.disable-cad`; and
- field `field:policy.mdm.security-option.lm-compatibility-level`.

Each class read is additionally fixed to the documented `./Vendor/MSFT/Policy/Result` parent and its exact `ControlPolicyConflict` or `LocalPoliciesSecurityOptions` instance. `InstanceID` and `ParentID` are WMI key properties: checking both prevents a class enumeration from silently becoming a node dump. Zero nodes, multiple nodes, unsupported classes, and operational query failures have different stable outcomes. Boolean values are restricted to `0` or `1`, machine inactivity to `0` through `599940` seconds, and LAN Manager authentication level to `0` through `5`; values outside those release bounds become malformed gaps before conversion. The worker never selects the first row, wraps an oversized integer, or coerces malformed data to `false`.

An unknown operation, missing parameter, alternate value, duplicate property, or extra property fails before activation. There is no parameter position for a script, command, executable path, WMI namespace, WMI class, user identity, task name, or evidence value.

## How live activation is contained

On an approved controlled client, the administrator coordinator creates the one-use pipe and a kill-on-close Windows Job Object before asking Windows Task Scheduler to start the fixed, digest-bound worker as LocalSystem. The Job uses the protected `Global\` kernel namespace because the interactive coordinator and Task Scheduler's SYSTEM worker normally run in different Windows sessions; a session-local Job would be invisible to the worker. Job ACLs still admit only the initiating administrator and LocalSystem. The transient task has a cryptographically random release prefix, no trigger, no password, a ten-second execution limit, and `CreateNewOnly` disposition. Its only action is the Microsoft-signed active `pwsh.exe` running the in-memory reviewed worker payload.

The worker joins the coordinator-owned Job Object before connecting or receiving the plan. The pipe ACL admits only the initiating administrator and LocalSystem. Both peers use the kernel-reported pipe process ID plus the exact executable digest; the worker also proves the LocalSystem SID. Only then does the coordinator send the one closed operation object.

Task Scheduler can start a process a moment before that process joins the Job. Cleanup therefore does not treat an empty Job as sufficient proof. It also follows the task's random instance identifier, captures every reported engine process ID, stops and deletes the exact task, and proves the instance, registration, and captured processes are all absent. If any check is uncertain, cleanup is incomplete and the run fails closed.

Why these details matter:

- The random names prevent one run from opening another run's objects.
- The ACL limits who can connect, while kernel process IDs prove which permitted process actually connected.
- The payload digest prevents a writable script-path replacement race; no script file is created.
- Job Object ownership gives the coordinator bounded authority over the complete worker tree, not only its root process.
- A LocalSystem provenance claim is emitted only after the worker token proves SID `S-1-5-18`. Synthetic validation instead records `Synthetic` and `localSystemIdentityVerified: false`.
- A live failure before that proof records `NotStarted` and `localSystemIdentityVerified: false`; asking Windows for a SYSTEM token is never reported as proof that one executed.

If any trust check fails, no evidence from that worker is accepted. A complete but malformed authenticated result is a protocol-integrity failure, not ordinary worker loss, and compromises run integrity. An ordinary activation failure, denial, incomplete frame paired with a verified worker exit, or timeout remains confined to the declared MDM Evidence Scope.

## Privacy and package ownership

The SYSTEM interface does not accept the Assessment User Context, Local Package Protector, Recipient Profile, credential material, package key, or arbitrary assessment evidence. Its only assessment-evidence contract is the fixed `PolicyCspResultCatalogV1` response; caller-selected fields or values cannot enter the task, worker configuration, named pipe request, or result.

The worker returns only the typed provider-availability result plus the four release-owned Policy CSP result fields when that catalog branch is active. The channel truthfully records that this restricted assessment evidence crossed under the fixed `PolicyCspResultCatalogV1` contract; it still rejects arbitrary assessment evidence. The coordinator re-projects the approved public portion into the normal Collector Result Envelope and keeps the bounded Policy CSP result fields inside Restricted Diagnostic Evidence for the dependent policy slice. Their canonical provenance retains the SYSTEM collector, operation, timing, and `LocalSystem` execution context rather than borrowing the Administrator collector used for local GPO signals. SYSTEM never writes a package, report, log, temporary evidence file, or protection metadata, and it never becomes a package protector.

The successful generated path also projects the envelope into the ordinary Assessment Record model. Provenance, observation, coverage, envelope, and finding references pass the shared schema and semantic graph checks. The schema admits `LocalSystem`, but the live coordinator still uses that value only after the identity proofs above.

## Outcomes and safe continuation

| SYSTEM outcome | Scope coverage | May unrelated safe work continue? |
| --- | --- | --- |
| Completed | Complete | Yes |
| Activation unavailable | Unavailable | Yes |
| Activation denied | Denied | Yes |
| Verified worker loss | Failed | Yes |
| Operation deadline | TimedOut | Yes |
| Operator cancellation | Cancelled | No; cancellation closes scheduling |
| Unknown operation or invalid parameters | NotAttempted | No; plan integrity failed |
| Peer, payload, or protocol integrity failure | Failed or NotAttempted | No; run integrity failed |
| Cleanup cannot be verified | Failed | No; terminal cleanup is incomplete |

The tracer-bullet generated application still ends with package-integrity failure after useful synthetic work because a real Protected Evidence Package finalizer belongs to a later ticket. That terminal does not erase the scoped coverage state.

## Cleanup and validation limitation

Every terminal path disposes the pipe, terminates and verifies the complete Job-owned tree, stops the exact transient task if it exists, deletes it, and verifies its registration, instance, and captured engine processes absent. Cleanup uses one bounded idempotent retry. A task-name prefix is never used as a deletion wildcard.

The twenty-case automated matrix covers allowed and unknown operation IDs, invalid parameters, activation failure, worker loss, cancellation, timeout, denial, abnormal cleanup, malformed/duplicate result fields, unknown catalogs, future builds, provider absence versus provider-query failure, empty versus multiple result nodes, unsupported classes, operational result-query failure, value bounds, and contradictory provider/catalog states. These cases run unelevated and therefore report:

- validation mode `SyntheticUnelevated`;
- observed execution context `Synthetic`;
- `localSystemIdentityVerified: false`; and
- `SYSTEM.LIVE_ACTIVATION_VALIDATION_UNAVAILABLE` with controlled-client remediation.

The abnormal-cleanup case creates a uniquely named Windows kernel event, deliberately retains that real IPC object on the first cleanup attempt, performs the single retry, and proves the exact name cannot be reopened. A second focused test simulates a task engine that never joined the Job and refuses to stop; deleting its registration cannot produce cleanup success while its captured process ID remains alive.

No approved disposable or controlled Windows client was available for this ticket, so no live UAC, Task Scheduler LocalSystem token, or real MDM provider observation is claimed. Live validation must use the exact generated candidate and publish only a sanitized, identifier-free projection.

See [issue #44 validation evidence](validation/issue-44-system-collection-sub-plan.md) for the public-safe matrix and commands.
