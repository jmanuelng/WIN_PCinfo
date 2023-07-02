# WIN_PCinfo - Detailed Computer Information PowerShell Script

## Description

`WIN_PCinfo` repository contains a comprehensive PowerShell script named `ComputerInfo.ps1` that gathers a wide range of information about a Windows computer. I use it as a tool to perform a Windows device review as a first step on Microsoft Intune projects. Extract basic and complete computer information using various Windows Management Instrumentation (WMI) classes and the "systeminfo" command. Additionally, the script retrieves license, activation information using Software Licensing Management Tool, network device info, account details, makes dns validations and more.

It collects a comprehensive set of information from a device, allows understanding of current environment and helps identify potential issues that might cause problems during a Microsoft Intune project, this based on my experience.

## Features

The `ComputerInfo.ps1` script collects the following information:

1. **System Information**: This includes data such as the computer name, manufacturer, model, serial number, BIOS version, operating system version, installed RAM, processor details, and more. This information is gathered using WMI classes and the "systeminfo" command.

2. **User Information**: The script identifies the currently logged-in user and their associated Azure AD accounts. This is done by querying the WMI classes related to user accounts.

3. **Network Information**: The script collects details about the computer's network interfaces, including IP addresses, MAC addresses, and connection status. It also tests network connectivity to Microsoft Intune and Microsoft Defender for Endpoint endpoints. This information is gathered using WMI classes related to network interfaces and the "ping" command.

4. **Enterprise Enrollment DNS Resolution**: The script tests DNS resolution for Enterprise Enrollment and Enterprise Registration, using both the default DNS server and a set of known DNS servers. This is done using the "Resolve-DnsName" cmdlet.

5. **Software Inventory**: The script generates a list of all installed software, including details such as the software name, version, vendor, installation date, and more. This information is gathered using the "Get-WmiObject" cmdlet with the "Win32_Product" class.

6. **Battery Report**: If the computer is a laptop, the script generates a detailed battery report using the `powercfg /batteryreport` command.

All collected data is written to CSV files for easy analysis and record-keeping.

## Usage

To use the `ComputerInfo.ps1` script, follow these steps:

1. Clone the `WIN_PCinfo` repository or download the `ComputerInfo.ps1` script directly.

2. Open a PowerShell console with administrative privileges.

3. Navigate to the directory where you saved the `ComputerInfo.ps1` script.

4. Run the script by typing `.\ComputerInfo.ps1` and pressing Enter.

The script will begin collecting information and will create CSV files in the current directory for each category of information. If the computer is a laptop, an HTML file with a detailed battery report will also be created.

## Contributing

Contributions to the `WIN_PCinfo` repository are welcome. If you have a feature request, bug report, or improvement to the script, please open an issue or submit a pull request.

## License

The `WIN_PCinfo` repository and the `ComputerInfo.ps1` script are provided under the MIT License. The MIT License is a permissive free software license that puts only very limited restriction on reuse and has, therefore, high license compatibility. It permits users to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of **WIN_PCinfo** - Detailed Computer Information PowerShell Script

## Disclaimer
This script is provided as-is with no warranties or guarantees of any kind. Always test scripts and tools in a controlled environment before deploying them in a production setting.
