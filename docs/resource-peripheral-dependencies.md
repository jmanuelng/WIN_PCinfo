# User resources and peripheral migration dependencies

This preview slice inventories a deliberately small set of local migration dependencies after the operator approves the immutable Preparation Plan. It observes mapped drives, UNC connection metadata, printers and their ports, printer drivers, and a release-cataloged set of common peripheral classes. The result is advisory: it helps a consultant ask the next migration question, but it does not promise that a share, printer, driver, dock, headset, camera, or other peripheral will work in every target environment.

## Why the Assessment User Context matters

Mapped resources and default printers are user-scoped. WIN-PCInfo first verifies one active interactive Assessment User Context through the existing local WTS/LSA identity boundary. The resource collector runs only when its standard-user process SID matches that verified SID and its token is not elevated. An alternate administrator used for UAC and `SYSTEM` are separate contexts and receive explicit `Denied` coverage; they can never silently supply another user's mapped-resource or printer evidence.

The Assessment User SID remains private execution state. It is used only to bind the supervised child and never becomes an Assessment Observation, report value, public projection, or issue attachment.

## Structured sources and hard bounds

The frozen operation is `observe-user-dependencies`. It runs offline in one Microsoft-signed PowerShell child for at most five seconds, with a 128 KiB output ceiling and verified whole-tree cleanup. It can make one attempt and cannot prompt, install, download, self-elevate, connect a resource, or write Windows state.

The release-owned sources are local Windows interfaces and an exact correlation by local drive name:

- the current user's `Network` registry definitions, opened read-only, for bounded mapped-drive definitions;
- `NetUseEnum` with a null server and level zero for local SMB session names and UNC endpoints. Higher levels are excluded because they include credential fields. This source does not cover DFS or WebDAV sessions or establish connection health;
- exact local-name correlation with remembered mappings. Connection health remains `Unavailable`; a remembered definition is never asserted to be connected or disconnected;
- `EnumPrintersW` with a null name, `LOCAL | CONNECTIONS`, and level four for local cached printer names and network attributes. No remote printer is opened;
- fixed read-only local print registry paths for port and driver binding, configured Work Offline state, current-user default name, and installed driver name/manufacturer/version/INF basename. An INF path is never opened. Uncached remote details remain `SourceReportedUnknown` with partial printer coverage; and
- `Win32_PnPSignedDriver`, filtered to `Bluetooth`, `HIDClass`, `Image`, `Keyboard`, `MEDIA`, `Mouse`, `Printer`, and `USB`, for common peripheral and driver metadata.

Each category admits at most eight unique entries. A ninth item is not silently discarded: retained evidence has `Partial` coverage with `RESOURCE.EVIDENCE_BOUND_EXCEEDED`. Native enumeration buffers and source output also have hard limits. Duplicate source rows are collapsed by case-insensitive local keys. Missing, malformed or denied categories remain separate from successfully read siblings.

Microsoft documents [level-four printer enumeration](https://learn.microsoft.com/en-us/windows/win32/printdocs/enumprinters) as registry/cache access, while level two opens remote connections. The [NetUseEnum contract](https://learn.microsoft.com/en-us/windows/win32/api/lmuse/nf-lmuse-netuseenum) defines the local-server and level-zero boundary and its SMB-only limitation. These call-surface choices and controlled tests are not a live packet-capture result. Private Windows/provider comparisons and the exact-candidate Local Only egress check remain pending in #161.

The collector never requests or enumerates share contents, documents, print jobs, stored credentials, Wi-Fi profiles or keys, `PNPDeviceID`, device serial numbers, or unrelated device classes. It never sends a print job, connects a drive, installs or updates a driver, or changes a default printer.

## Evidence, absence, and interpretation

Exact drive letters, UNC endpoints, provider names, printer and port names, driver details, and peripheral labels are Restricted Diagnostic Evidence. They appear only in the validated Assessment Record and beginner report inside the Protected Evidence Package. Public progress and validation output expose only release-owned coverage, findings, counts, and fixed safety assertions.

The five Evidence Scopes remain independent: mapped drives, UNC connections, printers, printer drivers, and common peripherals. A successfully completed empty scope explicitly records `ObservedAbsent` for its fields. Denied, unavailable, malformed, timed-out, failed, or bounded-partial sources create diagnostics and `Indeterminate` interpretation instead; missing evidence never becomes a claim that no dependency exists.

Three finite rules distinguish user-resource dependencies, peripheral dependencies, and overall coverage. Observed dependencies produce advisory `NeedsAttention` findings plus bounded next steps: validate authorized shares and printer deployment in the target user context, and confirm exact peripheral/driver support against Microsoft and vendor information. Empty complete scopes are informational. No result is a compliance decision, compatibility guarantee, purchase recommendation, or automatic migration plan.

## Reproduce public-safe validation

Use stable PowerShell Core 7.6 or later 7.x:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/ResourceDependenciesPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ResourceDependencies.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ResourceDependenciesNativeSource.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ResourceDependenciesContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ResourceDependenciesApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ResourceSourceApplication.Tests.ps1
```

The generated matrix uses identifier-free synthetic fixtures for mapped and disconnected drives, UNC resources, printers, ports and drivers, representative peripherals, empty, denied, partial, duplicate, long-Unicode, alternate-administrator, `SYSTEM`, and non-English cases. Every case crosses Preparation, the canonical record, beginner report, Protected Evidence Package reopen, terminal outcome, and verified validation cleanup without changing the assessed device.

The controlled-source matrix also executes the release-owned resource reducer and supervised worker. Only Windows identity, registry, native enumeration and CIM boundaries are substituted. Canonical validation, software annotation ownership, migration findings, HTML unknown-state/provenance rendering, protection, reopening and cleanup execute normally. No fixture switch is added to the public application.
