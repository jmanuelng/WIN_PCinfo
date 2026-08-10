# WIN-PCInfo

WIN-PCInfo is being rebuilt as a safe, modular Windows assessment application. The current v2 tracer bullet provides a generated launch path, verifies the active PowerShell host, and presents one complete Preparation Summary **before any assessment collection or device change can begin**.

> [!IMPORTANT]
> The v2 tracer bullet does not collect computer information yet. An eligible host resolves an immutable plan, presents the Preparation Summary, records approval or decline, and still returns `NotStarted` with exit code `20`. An ineligible host returns the same outcome with a stable reason, official Microsoft installation guidance, and a retry step. This is intentional and does not claim that a Preview capability is delivered.

## Try the v2 launch safely

You need stable PowerShell Core 7.6 or a later 7.x version. WIN-PCInfo does not install, repair, or change PowerShell for you. See [Runtime prerequisites and safe launch](docs/runtime-prerequisites.md) for beginner-friendly installation, verification, guided and automation examples, troubleshooting, and the complete compatibility boundary.

From a PowerShell 7.6-or-later console:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Mode Guided
```

The tracked code under `src/` is the source of truth. `build/Build.ps1` deterministically assembles it into the ignored `artifacts/WIN-PCInfo.ps1`; do not edit the generated file.

Before approving anything, read [Preparation Summary and approval](docs/preparation-summary.md). It explains the two network choices, every disclosure in the summary, guided and automation approval, and why neither approval nor validation fixtures can start collection in this implementation slice.

## Legacy script

`ComputerInfo.ps1` is the legacy implementation and remains available as an outcome and migration reference. It gathers Windows information, but it does **not** implement the v2 safety, privacy, lifecycle, evidence-protection, or runtime contracts. Do not treat its behavior as the v2 launch path.

The legacy instructions and feature inventory below describe only that script.

## Version 2 specification

WIN-PCInfo v2 is defined through a public, decision-led specification and is now being implemented as narrow, verifiable vertical slices.

Start with the [v2 capability-ledger rulebook](docs/spec/capability-ledger.md) to understand how legacy and new capabilities are classified, prioritized, selected for previews, and traced into release evidence. The broader route is indexed in the [WIN-PCInfo v2 product and release specification map](https://github.com/jmanuelng/WIN_PCinfo/issues/1).

## Legacy features

The `ComputerInfo.ps1` script collects the following information:

1. **System Information**: This includes data such as the computer name, manufacturer, model, serial number, BIOS version, operating system version, installed RAM, processor details, and more. This information is gathered using WMI classes and the "systeminfo" command.

2. **User Information**: The script identifies the currently logged-in user and their associated Azure AD accounts. This is done by querying the WMI classes related to user accounts.

3. **Network Information**: The script collects details about the computer's network interfaces, including IP addresses, MAC addresses, and connection status. It also tests network connectivity to Microsoft Intune and Microsoft Defender for Endpoint endpoints. This information is gathered using WMI classes related to network interfaces and the "ping" command.

4. **Enterprise Enrollment DNS Resolution**: The script tests DNS resolution for Enterprise Enrollment and Enterprise Registration, using both the default DNS server and a set of known DNS servers. This is done using the "Resolve-DnsName" cmdlet.

5. **Software Inventory**: The script generates a list of all installed software, including details such as the software name, version, vendor, installation date, and more. This information is gathered using the "Get-WmiObject" cmdlet with the "Win32_Product" class.

6. **Battery Report**: If the computer is a laptop, the script generates a detailed battery report using the `powercfg /batteryreport` command.

All collected data is written to CSV files for easy analysis and record-keeping.

## Legacy usage

To use the `ComputerInfo.ps1` script, follow these steps:

1. Clone the `WIN_PCinfo` repository or download the `ComputerInfo.ps1` script directly.

2. Review the legacy script and its side effects in a controlled test environment before deciding whether to run it. It does not provide the v2 safety gate.

3. Navigate to the directory where you saved the `ComputerInfo.ps1` script.

4. Run the script by typing `.\ComputerInfo.ps1` and pressing Enter.

The legacy script begins collecting immediately and creates several output files. Prefer the v2 generated launch path when evaluating current v2 work.

## Contributing

Contributions to the `WIN_PCinfo` repository are welcome. If you have a feature request, bug report, or improvement to the script, please open an issue or submit a pull request.

## Author

Created and maintained by Manuel Nieto ([@jmanuelng](https://github.com/jmanuelng)).

## License

The `WIN_PCinfo` repository and the `ComputerInfo.ps1` script are provided under the MIT License. The MIT License is a permissive free software license that puts only very limited restriction on reuse and has, therefore, high license compatibility. It permits users to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of **WIN_PCinfo** - Detailed Computer Information PowerShell Script

## Disclaimer
This script is provided as-is with no warranties or guarantees of any kind. Always test scripts and tools in a controlled environment before deploying them in a production setting.
