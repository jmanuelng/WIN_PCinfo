# Safe Software Inventory

This preview slice records bounded Windows software registrations after the operator accepts the immutable Preparation Plan. It is migration evidence, not a compatibility scan, license audit, vulnerability scan, product-health check, or proof that an application is usable. A name or publisher is display metadata; it is never treated as the registration identity.

## What WIN-PCInfo reads

The frozen operation is `observe-installed-software`. One supervised Microsoft Windows PowerShell 5.1 child runs as the verified, non-elevated Assessment User, offline, for at most ten seconds. It can make one attempt, return at most 1 MiB, retain at most 64 registrations in each Evidence Scope, and retain at most 128 registrations across the complete attempt. The aggregate ceiling guarantees the normalized record and protected package remain composable.

The operation reads only three structured Windows source families:

- the explicit 32-bit and 64-bit uninstall registration views for `LocalMachine` and the already loaded `CurrentUser` hive;
- the inventory-only Windows Installer APIs `MsiEnumProductsExW` and `MsiGetProductInfoExW`, preserving machine, managed-user, unmanaged-user, installed, and advertised states; and
- `Windows.Management.Deployment.PackageManager` identity/status projections for the Assessment User and, when Windows permits it, all users.

The registry views are opened explicitly with `Microsoft.Win32.RegistryKey.OpenBaseKey`; redirection is not inferred from process bitness. MSI product codes and Windows package family/full names remain source identities. Version values remain bounded provider text: WIN-PCInfo does not assume semantic-version syntax. Main, bundle, framework, resource, and optional Windows packages remain distinct package types.

These interfaces and their relevant behavior are documented by Microsoft in [Registry Redirector](https://learn.microsoft.com/windows/win32/winprog64/registry-redirector), [MsiEnumProductsExW](https://learn.microsoft.com/windows/win32/api/msi/nf-msi-msienumproductsexw), [MsiGetProductInfoExW](https://learn.microsoft.com/windows/win32/api/msi/nf-msi-msigetproductinfoexw), and [PackageManager](https://learn.microsoft.com/uwp/api/windows.management.deployment.packagemanager).

## What it never does

The v2 collector never invokes `Win32_Product`, `Get-WmiObject`, or a Windows Installer consistency/repair action. It never installs, uninstalls, prompts, downloads, self-elevates, loads another user profile, opens package content, scans arbitrary files, hashes binaries, reads installation paths, collects product/license keys, contacts a network service, or changes Windows state.

That distinction matters because an inventory request must stay observational. The legacy `ComputerInfo.ps1` path used `Win32_Product`; it is retained only as migration history and is not part of this v2 operation.

## Context and coverage

Machine registration sources and the verified Assessment User sources remain separate. The Assessment User SID is private execution state used to prove that the standard-user worker is the approved user. An alternate administrator or `SYSTEM` cannot substitute for that user, and WIN-PCInfo does not load an absent profile.

Each of the following eight scopes closes independently:

- 32-bit and 64-bit machine uninstall registrations;
- 32-bit and 64-bit Assessment User uninstall registrations;
- machine and Assessment User MSI registrations; and
- Assessment User and all-user Windows package identities.

All-user package access can be denied on an otherwise valid standard-user run. That denial affects only its scope. Missing, denied, malformed, failed, timed-out, or over-ceiling sources retain a stable coverage reason and yield `Indeterminate` guidance; they do not erase independently completed scopes or fabricate absence. A `Complete` empty scope is the only path that creates `ObservedAbsent` evidence.

## Privacy and guidance

Exact registration IDs, MSI product codes, package identities, names, publishers, versions, states, types, architectures, and contexts are Restricted Diagnostic Evidence. They are persisted only in the canonical Assessment Record, beginner report, and encrypted Protected Evidence Package. The bounded child result and coordinator memory carry them transiently as Restricted evidence; those representations are never public and are never written as plaintext artifacts. Public progress, terminal, validation, issue, and CI evidence contain only bounded counts, coverage/finding states, stable reason codes, and assertions that prohibited behavior did not occur.

The report asks a consultant to review machine-wide and Assessment User application dependencies before migration. It does not infer support, compatibility, licensing, ownership, trust, security, installability, health, or business importance from presence, absence, a version string, name, or publisher.

## Cleanup and troubleshooting

The coordinator creates one GUID-named compiler boundary under the existing temporary root, assigns the worker to a Windows Job Object before it can run, bounds stdout/stderr, and verifies the complete worker tree absent. It deletes only the exact boundary it created and verifies the directory absent. Cleanup uncertainty takes precedence as `CleanupIncomplete` and prevents normal packaging.

If software evidence is incomplete:

1. read the scope-specific coverage and diagnostic in the protected report;
2. do not rerun under another user, Administrator, or `SYSTEM` to fill Assessment User evidence;
3. do not use `Win32_Product` as a fallback;
4. close unrelated installer/package-management activity and retry the approved run once; and
5. treat persistent denial, unsupported access, or a per-scope/aggregate entry ceiling as an explicit evidence limit, not proof of absence.

The frozen policy is [2.0.0-preview.1-software-inventory.json](spec/releases/2.0.0-preview.1-software-inventory.json), its schema is [software-inventory.schema.json](../schemas/software-inventory.schema.json), and public-safe validation evidence is [issue-58-software-inventory.md](validation/issue-58-software-inventory.md).
