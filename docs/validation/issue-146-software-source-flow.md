# #146 software source flow checkpoint

Implementation checkpoint, **not complete acceptance**. The required maximum-inventory
report case still fails an inherited shared report/package limit. Both independent
Code Review axes remain pending dispatch by the orchestrator. No live assessment,
runtime installation, signing, certificate/trust change, catalog download, WinGet,
or publication was performed.

## Revision and exact candidate

- Fixed starting/review revision: `2ce76f668a4bca9bf100687982ff27f58791778a`.
- Source/test repair: `37b8608d0f7593f76a7f43723470216801f0ef9d` (DCO signed).
- Generated `WIN-PCInfo.ps1`: **3,213,633 bytes**, SHA-256
  `49f92b1d595b26a8844e7b3f9af80349be15600d41332efdfe9a867e545e888a`.
- Its embedded software worker: **14,915 UTF-8 bytes**, SHA-256
  `18fa3108ca68826c7a53cd28139b724ab766d98f0f78d620f15eb7302c679a83`;
  compressed encoded-command payload **17,116 characters**.
- Controller: installed PowerShell **7.6.5 x64**. The actual bounded software child
  remains the existing release-declared inbox **Windows PowerShell 5.1** dependency
  for WinRT package identities. This is separate from an unintended compatibility
  import or fallback; the source contract and runtime requirements were not widened.

## Repairs and test-first evidence

The generated ordinary Status desk scheduler executes the existing inventory worker
with only Windows identity, registry, MSI native calls and WinRT object boundaries
substituted by synthetic sources. Source projection, normalization, recognition,
canonical validation, findings, report, encryption, reopening and owned cleanup
remain production code. The original worker still runs in its bounded Job Object.
Catalog variants replace test-owned embedded data and its expected digest before
the real catalog loader. No fixture or replacement source is shipped in the app.

| Behavior | Red | Green |
| --- | --- | --- |
| MSI null-buffer size probe returns success with a positive required length | Zero MSI registrations instead of three, with entry-unavailable coverage | Machine, managed-user and unmanaged-user identities survive; installed/advertised states remain distinct |
| Unicode source output | All three MSI version values failed exact Unicode comparison | Explicit UTF-8 stdout preserves registry/MSI/package text through protected HTML |
| Native MSI access denied | Neither MSI scope was classified Denied | Win32 error 5 is recognized through a bounded eight-exception walk |
| MSI compiler initialization denied | Successful registry registrations disappeared with the failed worker | Only MSI scopes close Denied; eight registry and ten package entries survive |

The MSI sizing behavior is documented by Microsoft in
[MsiGetProductInfoExW](https://learn.microsoft.com/windows/win32/api/msi/nf-msi-msigetproductinfoexw).
A preliminary test-only C# constant-condition warning was corrected before the
authentic MSI red/green run; it is not claimed as a product defect.

## Focused checks

Commands use the installed `pwsh.exe -NoLogo -NoProfile -File` and the named test
path. Generated assessments were serialized. All listed results apply to the
source bytes in the checkpoint above.

| Check | Result |
| --- | --- |
| `tests/SoftwareSourceApplication.Tests.ps1` | **Pass**, all 11 cases: Complete, DeniedUser, DeniedAllUsers, MsiDenied, MsiCompilerDenied, AlternateAdministrator, Composite, Ambiguous, OrderReversed, Withdrawn, LogicalFailure; 21.1–26.7 seconds per case |
| `tests/SoftwareInventory.Tests.ps1` | **Pass**, identities, contexts, arbitrary versions, counts and declared payload bounds |
| `tests/SoftwareInventoryPolicy.Tests.ps1` | **Pass**, frozen collection authority |
| `tests/SoftwareInventoryNativeSource.Tests.ps1` | **Pass**, source contracts and pre-source denial; accidental automatic real collection removed in favor of the controlled generated flow |
| `tests/SoftwareRecognition.Tests.ps1` | **Pass**, exact MSI/PFN and UpgradeCode, Unicode composite, near misses, ambiguity, order independence, conservative failures |
| `tests/SoftwareRecognitionCatalog.Tests.ps1` | **Pass**, strict release catalog, lifecycle/withdrawal and integrity boundaries |
| `tests/SoftwareRecognitionApplication.Tests.ps1` | **Pass**, generated inventory preservation, protected report/package, logical failure and tampered catalog refusal before collection |
| PowerShell parser, all six affected `.ps1` files | **Pass** |
| `git diff --check` | **Pass** |
| `tests/SoftwareInventoryContract.Tests.ps1` | **Fail**, inherited maximum report composability described below; earlier canonical record/recognition checks pass |
| Generated application with `aggregate-maximum.json` software fixture | **Fail**, 128 accepted registrations cannot reach verified report/package; controlled refusal and cleanup described below |
| Whole repository suite | **Not run**, reserved for #158/final under the explicit testing-cadence override |

The source matrix retains duplicate registrations, all four explicit uninstall
views, all three MSI contexts, all five package types, exact and near PFNs, Unicode
and arbitrary version strings. Denied all-user packages do not erase the initiating
user's evidence. Unknown software remains ordinary inventory; recognition creates
annotations, not security/compatibility findings. Every selected source must execute
before a Complete source-matrix case can pass.

## Unresolved maximum report failure

The same `SoftwareInventoryContract.Tests.ps1` command was run against a clean
archive of exact starting commit `2ce76f6`, using the same installed runtime and
unchanged fixtures. **Both baseline and checkpoint produce 305,581 bytes**, above
the frozen **262,144-byte** report/package/export bound. The 128 registrations
remain valid canonical evidence. Section isolation measures **229,209 bytes** for
software and **76,372 bytes** for the rest of the report.

The generated application was also invoked through `Invoke-GeneratedApplication`
with Automation, `automation-request.json`, accepted `preparation-ready.json`, and
the software `aggregate-maximum.json` fixture. It collects **128 registrations**
(64 registry, 32 MSI, 32 MSIX), closes all eight software scopes Complete, accepts
the canonical record and adds 128 Unrecognized annotations. It then returns
**exit 50 / IntegrityFailed / DEVICE_READINESS.REPORT_FAILED**. Both
`beginnerReportVerified` and `protectedPackageVerified` are false; cleanup is
verified and stderr is empty. This is a bounded refusal without false success,
but otherwise admissible inventory does **not** reach a usable verified report or
package. Safe refusal does not satisfy #146's delivery requirement.

The unchanged rendering function is `New-DeviceReadinessReportBytes` in
`src/DeviceReadiness.ps1`. Its software projection already leaves full package
names in the canonical record rather than duplicating them in HTML. Neither
truncating registrations/versions nor raising package/export limits is an accepted
fix. Compressing only repeated fixture metadata would not establish the same
guarantee for valid distinct values or HTML escape expansion.

**Next owners: #151 / #154**, coordinated through #158: reconcile report rendering
and package/export composability with admitted inventory while preserving evidence,
coverage, identities, duplicates and release safety bounds. Keep #146 incomplete
until this required maximum case and its affected generated-package checks pass.
The orchestrator owns any issue/dependency and shared-register changes.

## Requirement-register contribution and private handoff

| Requirement | Current state | Next owner |
| --- | --- | --- |
| CAP-0009 / CMP-0009, CMP-0021: safe sources, contexts, identities and bounded collection | Controlled source/report checks pass; maximum report delivery **Fail** | #151/#154 repair, #146 retest, #158 integrated gate |
| CMP-0060; #37 stories 40–42: conservative recognition and failure isolation | Controlled/generated checks **Pass** | Independent review; #161 private comparison |
| #37 stories 39, 50–54, 66–67, 69: evidence, provenance, privacy, coverage and report | Focused checks pass except maximum report composability; no full-app acceptance claim | #158 and #161 |
| Story 90 / CMP-0061: live WinGet | Explicitly **Deferred**, unchanged | Future separately authorized implementation |
| Initiating-user ownership and #141 identity integration | Controlled alternate-administrator denial **Pass**; live **Pending** | #161 with #141 context expectations |
| Real registry/MSI/MSIX comparison and source cleanup | **NotStarted**, no live collection authority in this slice | #161 |

For #161, compare the exact candidate's protected software record/report with
approved local registration sources for the initiating user and machine across
32/64-bit views. Verify duplicate identities, provider version text, MSI
installed/advertised and managed/unmanaged contexts, package types and honest
inaccessible/all-user coverage. Exercise alternate-administrator elevation without
substituting that account for the #141 Assessment User, and verify the software
child repeats its context check before opening user sources. Compare Local Only
and approved connectivity runs without introducing software-network enrichment.
Record source constraints and exact owned worker/compiler cleanup privately.

Controlled runs verified their existing owned process/compiler, protected-package
and viewing cleanup. The temporary baseline archive and extracted tree were removed
after validating their exact resolved paths under the selected workspace's
`artifacts` directory; absence was checked. The tampered catalog candidate was
removed by its test. The ordinary generated candidate remains ignored build output
for review/retest. No restricted live evidence was produced or committed.

Real identifiers, screenshots, reports and packages remain in the approved private
area; public evidence contains only sanitized outcomes. The frozen #160 personally
signed candidate and keys remain unchanged. #145's incomplete effective WinRM
listener/certificate-auth requirements are not repaired or waived by this ticket.

## Required review handoff

Both axes are **unstarted/pending**, not passed. The retained nested-agent capacity
limitation and explicit orchestrator direction require fresh root-dispatched
Standards and Spec reviewers after this implementation turn ends.

- Diff: `git diff 2ce76f668a4bca9bf100687982ff27f58791778a...HEAD`.
- Commits: `git log 2ce76f668a4bca9bf100687982ff27f58791778a..HEAD --oneline`.
- Spec: complete issue #146 and its comments, with normative #134/#37/#158 context.
- Standards: original-checkout `AGENTS.md`, agent/domain instructions and
  `CONTEXT.md`; integration `CONTRIBUTING.md`, `.sandcastle/CODING_STANDARDS.md`,
  and the Code Review skill's complete smell baseline. No applicable ADR exists.
- Preserve separate axis reports, the known maximum-case failure and explicit
  live/integrated gates. No duplicate review layer over unchanged code is required.
