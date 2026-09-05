# First-run verification

This file is the first-run page inside the unsigned portable package. It does not create a Preview or Supported claim.

WIN-PCInfo never installs, upgrades, downgrades, or repairs PowerShell. Install a stable PowerShell 7.6 or later 7.x host from Microsoft first:

https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows

## Verify the package

From this extracted folder, using PowerShell 7:

```powershell
pwsh -NoLogo -NoProfile -File ./WIN-PCInfo.ps1 -Workflow Verify
```

That command authenticates every governing schema, catalog, definition, helper, and document against the generated application's embedded identity. A missing or altered resource returns `NotStarted` with `PREPARATION.INTEGRITY_FAILED`. There is no run-anyway switch.

This package is an unsigned precursor. It is not the later timestamped signed distributable.

## Start from Windows PowerShell

For the GUI entry, double-click `Start-WIN-PCInfo.cmd`. It retains visible failure
guidance if Windows policy prevents the PowerShell helper itself from starting.
The helper selects one verified eligible executable and requests NoProfile/STA
without elevation. Missing application, invalid signature and missing eligible
runtime stop before assessment. It never changes execution policy or unblocks a
download. The production Status desk displays the frozen preparation plan before
approval, runs the comprehensive assessment and offers Open report when a verified
protected package is available. Decline starts no collection. Cancel stops new
collection scheduling while owned work and protected finalization finish safely.

GUI and assessment launch require a valid application signature. The unsigned
source build permits only an exact passive Help, About, Verify or CheckRuntime
request through the helper; this cannot authorize assessment. An invalid or
altered signature is rejected even for those requests. Personally signed GUI
acceptance remains pending the dedicated live sessions #160 and #161.

Explicit application arguments retain guided-console and redirected automation
behavior and exit codes. Use `-Mode Guided` for console preparation.

Windows PowerShell 5.1 may only locate an eligible `pwsh` host or print official retry guidance. It is not a second assessment engine.

```text
powershell.exe -NoProfile -File .\Start-WIN-PCInfo.ps1 -Workflow Help
```

If no eligible host is installed, the helper ends at `RUNTIME.HOST_MISSING` and points to Microsoft's installation page.

## Next step

After verification succeeds, open Help or start guided preparation from the same folder. Ordinary assessment on this unsigned package still fails the Authenticode trust gate. An Attested Preview is a separately governed unsigned fallback described in docs/attested-preview.md. It is never Trusted, signed, or Supported.
