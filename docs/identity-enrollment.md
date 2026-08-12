# Registration, join, and enrollment context

WIN-PCInfo now carries a narrow, read-only identity tracer bullet through the generated application. It answers four local questions: which interactive Windows logon session is the Assessment User Context, whether Windows reports workgroup or domain join, whether the local structured API reports Microsoft Entra joined or registered state, and whether the predefined SYSTEM MDM Bridge provider source is available. It does not sign in to Microsoft, query a tenant, or change account, join, registration, or enrollment state.

## What happens after approval

The Preparation Summary freezes three collector contracts before the operator approves:

- `observe-device-registration` runs in the assessment coordinator's standard-user context and calls `NetGetJoinInformation`, `NetGetAadJoinInformation`, and Terminal Services session APIs in process;
- `observe-enrollment-context` uses only the default `NetGetAadJoinInformation` workplace-registration projection; and
- `observe-mdm-system-context` reuses the predefined SYSTEM Collection sub-plan for one read-only `MDM_DeviceManageability_Provider01_01` presence query.

All three are offline, bounded to one five-second attempt, cannot prompt, download, install, self-elevate, launch a caller command, or write Windows state. The SYSTEM worker cannot receive Assessment User Context, package authority, credentials, tenant values, or arbitrary evidence.

## Why Assessment User Context is separate

The account running WIN-PCInfo may be the initiating operator, an alternate administrator used for elevation, or another trusted process identity. None of those automatically identifies the interactive user whose user-scoped state the assessment intends to observe. WIN-PCInfo enumerates active Terminal Services sessions and accepts a user only when exactly one active session supplies a bounded account name and session identifier. It records the relationship to the process separately. Ambiguous, missing, denied, malformed, administrator, worker, or SYSTEM state never substitutes a different user.

## Structured, locale-neutral sources

`NetGetJoinInformation` returns a typed join-status enumeration and a domain/workgroup buffer. `NetGetAadJoinInformation` returns a `DSREG_JOIN_INFO` structure, including its typed join kind and bounded local identifiers. Terminal Services returns typed session records. Rules never parse `dsregcmd`, console labels, translated status text, regional dates, or localized Boolean words. Unicode account and domain values remain valid Restricted evidence, while `sourceLocale = und` records that the API structure itself is language-neutral.

The default Entra join structure is deliberately narrow. It does not enumerate every Web Account Manager account and does not claim complete tenant membership. `EntraRegistered` can support the bounded work-or-school account presence statement; absence of its optional identifier is not invented from another identity.

## Privacy and evidence

Account names, domain names, work-or-school identifiers, tenant IDs, and device IDs are `RestrictedDiagnosticEvidence`. They may appear only inside the canonical Assessment Record and encrypted report/package. They never enter progress, terminal output, the sanitized validation projection, repository evidence, or a public issue. The public Contract Set exposes definitions and bounds, never values.

Each observation names its source, collector, actual execution context, time, locale, and Device or User subject. Assessment User Context, registration, work-or-school, and SYSTEM MDM-provider coverage remain separate. A denied or failed source produces coverage and a diagnostic with no fabricated field observations.

## What the findings do not claim

The three local rules describe verified user context, device registration context, and locally observable work-or-school/MDM context. They do not declare compliance, tenant assignment, licensing, Microsoft service authorization, or organization-wide intent. When local Entra context makes those questions relevant, WIN-PCInfo creates four bounded Tenant-side Discovery Tasks for authorized roles and approved administration boundaries. The application does not perform those tasks.

The beginner report starts with coverage and advisory outcomes, explains the user/process distinction, and then shows Restricted identifiers only inside the Protected Evidence Package. A fixture package is reopened, validated, and removed before its sanitized terminal result; a real verified package remains protected for the initiating user and any preapproved recipient.

## Reproduce public-safe validation

Use stable PowerShell Core 7.6 or later 7.x:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/IdentityEnrollmentPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/IdentityEnrollmentContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/IdentityEnrollmentNativeSource.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/IdentityEnrollmentRecord.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/IdentityEnrollmentApplication.Tests.ps1
```

The native-source test keeps any real local identifiers in memory only and emits one identifier-free PASS line. The generated matrix uses synthetic workgroup, domain-joined, Entra-joined, registered, mixed, unenrolled, unavailable-user, standard-user, administrator, SYSTEM, non-English, malformed, and denied states. It performs no authentication or device-state change and verifies protected-package and run-owned cleanup.
