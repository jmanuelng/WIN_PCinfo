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

Windows PowerShell 5.1 may only locate an eligible `pwsh` host or print official retry guidance. It is not a second assessment engine.

```text
powershell.exe -NoProfile -File .\Start-WIN-PCInfo.ps1 -Workflow Help
```

If no eligible host is installed, the helper ends at `RUNTIME.HOST_MISSING` and points to Microsoft's installation page.

## Next step

After verification succeeds, open Help or start guided preparation from the same folder. Ordinary assessment on this unsigned package still fails the Authenticode trust gate until a later signed or attested release exists.
