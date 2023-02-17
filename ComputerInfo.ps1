<#
.DESCRIPTION
	Sript to gather system information. Creates folders "Battery", Config", "Network", "Software", each with the corresponding log file. 
    It's intended to be executed at the beggining of MEM Intune project to understand the client's environment.
    - Are PCs AAD joined, hybrid joined or AD joined?
    - Types of systems in environment, brand, model, UUID unique information?

 .NOTES
    Sources and inspiration:
    https://sid-500.com/2018/04/02/powershell-how-to-get-a-list-of-all-installed-software-on-remote-computers/
    https://devblogs.microsoft.com/scripting/use-powershell-to-quickly-find-installed-software/
    https://www.techcrafters.com/portal/en/kb/articles/powershell-check-laptop-or-not#How_to_Check_if_a_machine_is_a_laptop_or_desktop_and_get_the_model_of_a_computer_using_Powershell
    https://stackoverflow.com/questions/59489885/identify-if-windows-hosted-on-physical-or-virtual-machine-powershell
    https://social.technet.microsoft.com/Forums/azure/en-US/06a7fed6-7775-4542-bf32-afbe8a48d49b/list-all-installed-appx-packages-along-with-their-display-names?forum=ITCG
    https://petri.com/how-to-back-up-and-restore-wireless-network-profiles/


.COMMENTS
    Should also add comment that to run script to verify 
    Set-ExecutionPolicy Bypass
    
#>


function fnGetMachineType {
    $ComputerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem
    switch ($ComputerSystemInfo.Model) { 

        # Check for VMware Machine Type 
        "VMware Virtual Platform" { 
            Write-Output "This Machine is Virtual on VMware Virtual Platform."
            Break 
        } 

        # Check for Oracle VM Machine Type 
        "VirtualBox" { 
            Write-Output "This Machine is Virtual on Oracle VM Platform."
            Break 
        } 
        default { 

            switch ($ComputerSystemInfo.Manufacturer) {

                # Check for Xen VM Machine Type
                "Xen" {
                    Write-Output "This Machine is Virtual on Xen Platform"
                    Break
                }

                # Check for KVM VM Machine Type
                "QEMU" {
                    Write-Output "This Machine is Virtual on KVM Platform."
                    Break
                }
                # Check for Hyper-V Machine Type 
                "Microsoft Corporation" { 
                    if (get-service WindowsAzureGuestAgent -ErrorAction SilentlyContinue) {
                        Write-Output "This Machine is Virtual on Azure Platform"
                    }
                    else {
                        Write-Output "This Machine is Virtual on Hyper-V Platform"
                    }
                    Break
                }
                # Check for Google Cloud Platform
                "Google" {
                    Write-Output "This Machine is Virtual on Google Cloud."
                    Break
                }

                # Check for AWS Cloud Platform
                default { 
                    if ((((Get-WmiObject -query "select uuid from Win32_ComputerSystemProduct" | Select-Object UUID).UUID).substring(0, 3) ) -match "EC2") {
                        Write-Output "This Machine is Virtual on AWS"
                    }
                    # Otherwise it is a physical Box 
                    else {
                        Write-Output "This Machine is Physical Platform"
                    }
                } 
            }                  
        } 
    } 

}



Function fnDetectLaptop {
    [cmdletbinding()]
    param (
        [string]$computer="localhost"
    )
        
    $isLaptop = $false
    #The chassis is the physical container that houses the components of a computer. Check if the machine’s chasis type is 9.Laptop 10.Notebook 14.Sub-Notebook
    if(Get-WmiObject -Class win32_systemenclosure -ComputerName $computer | Where-Object { $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 -or $_.chassistypes -eq 14})
        { $isLaptop = $true }
    #Shows battery status , if true then the machine is a laptop.
    if(Get-WmiObject -Class win32_battery -ComputerName $computer)
        { $isLaptop = $true }
    $isLaptop
}

$msg = "`n`nGathering information on: " + (Get-Childitem env:computername).value
Write-Host $msg -ForegroundColor White

# @jmanuelnieto: Verify administrative priviliges. Script has to be executed with Administrative priviliges.
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))
    {
        Write-Host "...User has to be an administrator to execute script. Please use an account with Administrative Priviliges." -ForegroundColor red
        Exit
    }

# @jmanuelnieto: Verify and/or install Microsoft.PowerShell.Management module.
If (!(Get-Module -listavailable | Where-Object {$_.name -like "*Microsoft.PowerShell.Management*"})) 
	{ 
		Write-Host "...Installing Management Module." -ForegroundColor Cyan
		Install-Module Microsoft.PowerShell.Management -Force -ErrorAction SilentlyContinue 
	} 
Else 
	{ 
		Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue 
	}


# ===========   @jmanuelnieto: System data collection.   ===========

# @jmanuelnieto: Collect DSReg status info
# @jmanuelnieto: File name and locations to store gathered info, the "output file".
$PC_folder = "Config"
If ( -not(Test-Path $PC_folder)) {  
    #Create folder if it does not exist
    New-Item -Path ".\$PC_folder" -ItemType Directory | Out-Null
}

$PC_filename = ".\$PC_folder\ComputerInfo_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).txt"

# == DSReg ==
# @jmanuelnieto: Collect DSReg status info
# Inform user on screen
$msg = "`...Getting DSReg information."
Write-Host $msg -ForegroundColor White
# @jmanuelnieto: The banner and footer to distinguish this section in Output File.
$logBanner = "==========================================================="
$logBanner += "          Device Registration Troubleshooter Command Tool          " 
$logBanner += "=========================================================== `n`n"
$logFooter = "`n`n==========================================================="
$logFooter += "          Device Registration Troubleshooter Command Tool          "
$logFooter += "==========================================================`n`n`n`n"
# @jmanuelnieto: running the diagnostics in SYSTEM context is closest to the actual join scenario. 
# To run diagnostics in SYSTEM context, the dsregcmd /status command must be run from an elevated command prompt.
$DSreg = dsregcmd /status
# @jmanuelnieto: Write DSReg results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logBanner -Encoding ASCII
Out-File -FilePath $PC_filename -InputObject $DSreg -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append


# ==== Computer Info ====
$msg = "`...Getting systemInfo."
Write-Host $msg -ForegroundColor White

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logBanner = "==========================================================="
$logBanner += "          Computer Information          " 
$logBanner += "===========================================================`n`n"

# == Computer information, CimInstace
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Basic Computer information: Name, owner, domain, memory, manufacturer and model from CimInstance:" 
$logFooter = "==========`n`n"
# @jmanuelnieto: Get basic Computer information: Name, owner, domain, memory, manufacturer and model from CimInstance
$PC_basicinfo = Get-CimInstance -ClassName Win32_ComputerSystem
# @jmanuelnieto: Write CiMInstance results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logBanner -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logHeading -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_basicinfo -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append

# == SystemInfo
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Complete Computer information using ""systeminfo"":" 
$logFooter = "==========`n`n"
# @jmanuelnieto: Get detailed System Information using "systeminfo" command
# Displays detailed configuration information about a computer and its operating system, including operating system configuration, security information, product ID, and hardware properties (such as RAM, disk space, and network cards).
# Systeminfo /fo = Format output to CSV.
# | Forma-List = Capture the output, convert it to a list to append to Output file
$PC_systeminfo = Systeminfo /fo CSV | ConvertFrom-CSV | Format-List
# @jmanuelnieto: Write SystemInfo results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logHeading -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_systeminfo -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append

# == Complete System Information from WmiObject ComputerSystemProduct
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Complete Computer information using ""WmiObject ComputerSystemProduct"":" 
$logFooter = "==========`n`n"
# The Win32_ComputerSystemProduct WMI class represents a product. This includes software and hardware used on the computer system.
$PC_product = Get-WmiObject -Class Win32_ComputerSystemProduct | Format-List -Property *
# @jmanuelnieto: Write Win32_ComputerSystemProduct results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logHeading -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_product -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append


# == Complete System Information from WmiObject ComputerSystem
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Complete Windows information using ""WmiObject ComputerSystem"":" 
$logFooter = "==========`n`n"
# The Win32_ComputerSystem WMI class represents a computer system running Windows.
$PC_system = Get-WmiObject -Class Win32_ComputerSystem | Format-List -Property *
# @jmanuelnieto: Write Win32_ComputerSystem results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logHeading -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_system -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append


# == Software Licensing Tool
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Software Licensing Management Tool, get license and activation information: `n" 
$logFooter = "==========`n`n"
# @jmanuelnieto: Get path to slmgr.vbs (Software Licensing Management Tool) script, and then execute script. 
# @jmanuelnieto: used with /dlv to display license information for the installed active Windows.
[string]$slmgrPath = Get-ChildItem -Path Env:\windir | Select-Object -ExpandProperty Value
$slmgrPath += "\System32\slmgr.vbs"
$PC_actinfo = cscript $slmgrPath /dlv
# @jmanuelnieto: Write Software Licensing Management Tool results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logHeading -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_actinfo -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append


# == Windows License details
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === License keys details from CimInstance, license information:" 
$logFooter = "==========`n`n"
# @jmanuelnieto: Get Windows keys detail information. This includes Firmware OEM License. 
# Upgrade to Enterprise requires Activation Keys. More info: https://docs.microsoft.com/en-us/windows/deployment/deploy-enterprise-licenses
$PC_winlicenseexpanded = Get-CimInstance -ClassName SoftwareLicensingService | Format-List -Property *
# @jmanuelnieto: Get Windows Firmware Embedded Activation Key (OEM Windows licenses), if blank, system does not have OEM license
$PC_winlicense = Get-CimInstance -ClassName SoftwareLicensingService | Select-Object -ExpandProperty OA3xOriginalProductKey
If( $PC_winlicense -eq "") 
    { 
        $PC_winlicense = "`n`nOA3xOriginalProductKey = N/A, no OEM Windows license in firmware`n"
    }
Else 
    {
        $PC_winlicense = "`n`nOA3xOriginalProductKey = " + $PC_winlicense + "`n"
    }
# @jmanuelnieto: Write License keys detailed results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logHeading -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_winlicenseexpanded -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_winlicense -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append


# @jmanuelnieto: Get BIOS and TPM information. This is to understando if the system hast TPM, and what version.
$PC_bios = Get-WmiObject -Class Win32_Bios | Format-List -Property *
$PC_tpm = Get-WmiObject -Class Win32_Tpm -Namespace root\cimv2\security\microsofttpm | Format-List -Property *

# @jmanuelnieto: It then adds BIOS and TPM info to file.
$msg = "`...Wiritng SystemInfo report."
Write-Host $msg -ForegroundColor White

Out-File -FilePath $PC_filename -InputObject $PC_bios -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_tpm -Encoding ASCII -Append

# === This is the end of System configuration info


# ===========   @jmanuelnieto: Networking details.   ===========

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logBanner = "==========================================================="
$logBanner += "          Network Adapter Info          " 
$logBanner += "===========================================================`n`n"

# == Computer information, CimInstace
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Detailed netwoek information from PS Get-NetAdapters" 
$logFooter = "==========`n`n"

$NET_folder = ".\Network"
If ( -not(Test-Path $NET_folder)) {  
    #Create folder if it does not exist
    New-Item -Path "$NET_folder" -ItemType Directory | Out-Null
}
$NET_folder = $PSScriptRoot + "\Network"
$NET_infofile = "$NET_folder\Networkinfo_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).txt"


# @jmanuelnieto: get network adapters list
$NET_adapter = Get-NetAdapter | Format-List -Property *

# @jmanuelnieto: get profile information for connected netwrok adapter using PS command
$NET_connection = Get-NetConnectionProfile | Format-List -Property *

# @jmanuelnieto: get Lan and WLan profiles with netsh
# @jmanuelnieto: netsh is used to get a list of all profiles, stores the list in a TXT file, puts in a folder
netsh wlan export profile key=clear folder="$NET_folder"

# Write info from PS commands to a log file.
Out-File -FilePath $NET_infofile -InputObject $logBanner -Encoding Default -Append
Out-File -FilePath $NET_infofile  -InputObject $logHeading -Encoding Default -Append
Out-File -FilePath $NET_infofile -InputObject $NET_adapter -Encoding Default -Append
Out-File -FilePath $NET_infofile  -InputObject $logFooter -Encoding Default -Append
Out-File -FilePath $NET_infofile -InputObject $NET_connection -Encoding Default -Append
Out-File -FilePath $NET_infofile  -InputObject $logFooter -Encoding Default -Append

# @jmanuelnieto: Get Software Inventory.
$msg = "`...Getting Software Inventory."
Write-Host $msg -ForegroundColor White

$SW_folder = "Software"
If ( -not(Test-Path $SW_folder)) {  
    #Create folder if it does not exist
    New-Item -Path ".\$SW_folder" -ItemType Directory | Out-Null
}


$PC_swReport = Get-CimInstance win32_product | Select-Object InstallState, Name, Description, Version, Vendor, InstallDate, PackageName, URLInfoAbout, URLUpdateInfo, ProductID, Language, InstallLocation, InstallSource
$PC_regswReport = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object SystemComponent, DisplayName, DisplayVersion, Publisher, InstallDate, Language, InstallLocation, InstallSource
$PC_appXReport = Get-AppxPackage | Select-Object Name, PackageFullName, Status, Version, Publisher, Architecture, InstallLocation, SignatureKind, NonRemovable, IsResourcePackage, IsBundle, IsDevelopmentMode 

# @jmanuelnieto: Create Software Inventory report.
$msg = "`...Writing Software Inventory to CSV file."
Write-Host $msg -ForegroundColor White

# @jmanuelnieto: Create Software Inventory report, show it in GridView.
$ExportCSV =".\$SW_folder\ComputerInfo_SW_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"
#$PC_swReport | out-gridview
$PC_swReport | Export-CSV -Path $ExportCSV -NoType

# @jmanuelnieto: Create Software Inventory report from the Uninstall info o system registry, show it in GridView.
$ExportCSV =".\$SW_folder\ComputerInfo_rSW_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"
#$PC_regswReport | out-gridview
$PC_regswReport | Export-CSV -Path $ExportCSV -NoType

# @jmanuelnieto: Create Software Inventory report for AppX apps (for example Microsoft Store), show it in GridView.
$ExportCSV =".\$SW_folder\ComputerInfo_axSW_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"
#$PC_appxReport | out-gridview
$PC_appxReport | Export-CSV -Path $ExportCSV -NoType

# @jmanuelnieto: If laptop, create battery report
If (fnDetectLaptop) 
    { 
        $msg = "`...Executing Battery Report."
        
        $BAT_folder = ".\Battery"
        Write-Host $msg -ForegroundColor White
        If ( -not(Test-Path $BAT_folder)) {
            #Create folder if it does not exist
            New-Item -Path "$BAT_folder" -ItemType Directory | Out-Null
        }        
        
        $batreportHtml = "$BAT_folder\BatteryReport_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).html"
        Powercfg /batteryreport /output $batreportHtml | Out-Null
    }


Write-Host "The end! `n`n" -ForegroundColor White
