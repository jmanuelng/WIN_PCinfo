# Local administrator exposure and execution context

WIN-PCInfo now carries one read-only local-administrator slice through the generated application. It identifies the built-in Administrators group by its well-known SID, records only its direct members, keeps the administrator worker separate from the Assessment User Context, and packages the Restricted details locally. It does not change group membership or decide that an account is malicious.

## What happens after approval

The Preparation Summary freezes `observe-local-administrators` into the existing Privileged Collection Plan. The collector runs in the one approved Administrator worker, is offline, has one five-second attempt and a 16 KiB result ceiling, and remains in the coordinator-owned Job Object. It cannot accept a command, script, executable path, group name, account name, credential, network permission, or mutation request from the caller.

The worker selects the built-in group by the locale-neutral well-known SID `S-1-5-32-544`. It then calls `NetLocalGroupGetMembers` at level 0, which returns structured member SIDs rather than localized command text. The bound is eight distinct direct entries. Windows error codes become typed `Denied`, `Partial`, `Malformed`, or `Failed` coverage; a gap never becomes an empty group.

## Direct membership is not effective access

A group can itself be a direct member. WIN-PCInfo records that group as one direct entry and stops. It does not recursively expand nested local or domain groups, contact a domain controller, calculate token privileges, or guess effective access. Therefore a complete result means “the bounded direct list was examined,” not “every person who could obtain administrator rights is known.”

An unresolved SID remains an explicit principal with no invented account name or type. Duplicate source entries are admitted once by stable SID and reported only as a sanitized count. Non-English Windows installations use the same SID-selected source and do not depend on the displayed Administrators name.

## Why the administrator is not the assessed user

The account that approves UAC may be the initiating operator or an alternate administrator. It is only the privileged worker principal. The coordinator retains the original Assessment User Context, Local Package Protector, evidence ownership, and output destination. Those roles are never sent to or replaced by the worker. A denied elevation produces explicit coverage and allows already-approved standard-user work to finish; it does not create membership observations.

## Privacy and findings

Member SIDs, account names, principal kinds, origins, and direct-membership relationships are `RestrictedDiagnosticEvidence`. They may appear only in the canonical Assessment Record and encrypted beginner report. Progress, terminal output, sanitized validation, repository evidence, and public issues expose only coverage and bounded counts. No password, token, credential, private profile attribute, or group mutation crosses this slice.

The release-owned rule produces one advisory finding. Complete direct coverage is `Informational`; incomplete coverage is `Indeterminate`. The finding explains the evidence limit. It does not declare organizational intent, compromise, unnecessary access, or a removal recommendation because those conclusions require authorized organization context that this local source cannot establish.

## Reproduce public-safe validation

Use stable PowerShell Core 7.6 or later 7.x:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/AdministratorExposurePolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AdministratorExposure.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AdministratorExposureContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AdministratorExposurePrivilegedCollector.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AdministratorExposureApplication.Tests.ps1
```

The generated matrix covers local and domain principals, a nested group, an unresolved SID, duplicate input, an alternate administrator, denied and partial collection, a non-English case, and elevation denial. It verifies the record, report, protected-package reopen, stable terminal result, and absence of run-owned residue without changing a real group.

The immutable policy is [`2.0.0-preview.1-administrator-exposure.json`](spec/releases/2.0.0-preview.1-administrator-exposure.json), its closed schema is [`administrator-exposure.schema.json`](../schemas/administrator-exposure.schema.json), and the identifier-free closure projection is [issue #52 validation](validation/issue-52-administrator-exposure.md).
