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

#region Functions
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



function fnDetectLaptop {
    [cmdletbinding()]
        
    $isLaptop = $false
    # The chassis is the physical container that houses the components of a computer. Check if the machine’s chasis type is 9.Laptop 10.Notebook 14.Sub-Notebook
    $chassisType = (Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes
    if ($chassisType -contains 9 -or $chassisType -contains 10 -or $chassisType -contains 14) {
        # Shows battery status, if true then the machine is a laptop.
        if (Get-CimInstance -ClassName Win32_Battery) {
            $isLaptop = $true
        }
    }
    return $isLaptop
}

function Get-BiosTpm {
    # Error handling with Try/Catch
    try {
        # Get BIOS info using the Win32_BIOS WMI class
        $bios = Get-WmiObject -Class Win32_BIOS
        Write-Output "BIOS Manufacturer: $($bios.Manufacturer)"
        Write-Output "BIOS Version: $($bios.SMBIOSBIOSVersion)"

        # Get TPM info using the Win32_Tpm WMI class
        $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm

        if ($tpm) {
            Write-Output "TPM Manufacturer ID: $($tpm.ManufacturerID)"
            Write-Output "TPM Version: $($tpm.SpecVersion)"
            Write-Output "TPM Status: $($tpm.Status)"
        } else {
            Write-Output "TPM is not available on this system."
        }
    } catch {
        # Catch and display any errors
        Write-Output "An error occurred: $_"
    }
}


function Get-InstalledSoftware {
    # Initialize an empty array to hold software objects
    $allSoftware = @()

    # Error handling with Try/Catch
    try {
        # Get installed software from CIM
        $cimSoftware = Get-CimInstance -ClassName Win32_Product
        foreach ($software in $cimSoftware) {
            $allSoftware += New-Object -TypeName psobject -Property @{
                Name           = $software.Name
                Version        = $software.Version
                Vendor         = $software.Vendor
                InstallDate    = $software.InstallDate
                Description    = $software.Description
                InstallLocation = $software.InstallLocation
                InstallSource  = $software.InstallSource
                PackageName    = $software.PackageName
                InventorySource = "CimInstance"
            }
        }

        # Define registry paths for installed software
        $registryPaths = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 
                         'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                         'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'

        foreach($path in $registryPaths){
            # Get installed software from registry
            $registrySoftware = Get-ItemProperty $path
            foreach ($software in $registrySoftware) {
                if ($null -ne $software.DisplayName) {
                    $allSoftware += New-Object -TypeName psobject -Property @{
                        Name            = $software.DisplayName
                        Version         = $software.DisplayVersion
                        Vendor          = $software.Publisher
                        InstallDate     = $software.InstallDate
                        Description     = $software.DisplayName
                        InstallLocation = $software.InstallLocation
                        InstallSource   = $software.InstallSource
                        PackageName     = $software.PSChildName
                        InventorySource = "Registry"
                    }
                }
            }
        }

        # Get installed software from AppxPackage
        $appxSoftware = Get-AppxPackage
        foreach ($software in $appxSoftware) {
            $allSoftware += New-Object -TypeName psobject -Property @{
                Name            = $software.Name
                Version         = $software.Version
                Vendor          = $software.Publisher
                InstallDate     = $software.InstallDate
                Description     = $software.PackageFullName
                InstallLocation = $software.InstallLocation
                InstallSource   = $software.InstallLocation
                PackageName     = $software.PackageFullName
                InventorySource = "AppxPackage"
            }
        }

    } catch {
        # Catch and display any errors
        Write-Output "An error occurred while trying to retrieve Installed Software details: $_"
    }

    # Return the consolidated software list
    return $allSoftware
}

function Get-SharedFoldersInventory {
    try {
        # Get all shared folders
        $sharedFolders = Get-CimInstance -ClassName Win32_Share

        # Select specific properties for each shared folder
        $sharedFoldersInfo = $sharedFolders | Select-Object -Property Name, Path, Description, Status

        # Return the shared folders information
        return $sharedFoldersInfo

    } catch {
        # Catch and display any errors
        Write-Output "An error occurred: $_"
    }
}

function Get-NetworkDrivesInventory {
    try {
        # Get all PowerShell drives and filter for network drives
        $networkDrives = Get-PSDrive | Where-Object { $_.Provider -like "Microsoft.PowerShell.Core\FileSystem" -and $_.Root -like "\\*" }

        # Select specific properties for each network drive
        $networkDrivesInfo = $networkDrives | Select-Object -Property Name, Root, Description

        # Return the network drives information
        return $networkDrivesInfo

    } catch {
        # Catch and display any errors
        Write-Output "An error occurred: $_"
    }
}

function Get-GPOInventory {
    try {
        # Run gpresult and capture its output
        $gpresult = gpresult /h gpresult.html

        # Parse the gpresult output to find the applied policies
        $gpos = Select-String -Path gpresult.html -Pattern 'Applied Group Policy Objects'

        # Clean up the gpresult file
        Remove-Item -Path gpresult.html

        # Return the GPO information
        return $gpos

    } catch {
        # Catch and display any errors
        Write-Output "An error occurred: $_"
    }
}

function Get-PrinterInventory {
    try {
        # Get all printers
        $printers = Get-Printer

        # Select specific properties for each printer
        $printerInfo = $printers | Select-Object -Property Name, DriverName, PortName, Shared, ShareName, Location, Comment, PrinterStatus

        # Return the printer information
        return $printerInfo

    } catch {
        # Catch and display any errors
        Write-Output "An error occurred: $_"
    }
}


function Test-IntuneDefenderAndOtherEndpoints {
    # Initialize an array to store the results
    $testResults = @()

        # List of required service endpoints
    $allEndpoints = @(
        "https://portal.azure.com",
        "https://login.microsoftonline.com",
        # ... Include all endpoints here ...
        "https://portal.azure.com",
        "https://login.microsoftonline.com",
        "https://enterpriseregistration.windows.net",
        "https://mam.manage.microsoft.com"
        "https://manage.microsoft.com",
        "https://policy.manage.microsoft.com",
        "https://device.manage.microsoft.com",
        "https://provisioning.manage.microsoft.com",
        "https://portal.manage.microsoft.com",
        "https://diagnostics.manage.microsoft.com",
        "https://us.tip.manage.microsoft.com",
        "https://eu.tip.manage.microsoft.com",
        "https://apac.tip.manage.microsoft.com",
        "https://winatp-gw-cus.microsoft.com",
        "https://winatp-gw-eus.microsoft.com",
        "https://winatp-gw-weu.microsoft.com",
        "https://winatp-gw-neu.microsoft.com",
        "https://winatp-gw-uks.microsoft.com",
        "https://winatp-gw-ukw.microsoft.com",
        "https://winatp-gw-usgv.microsoft.com",
        "https://winatp-gw-usgt.microsoft.com",
        "https://eu.vortex-win.data.microsoft.com",
        "https://us.vortex-win.data.microsoft.com",
        "https://uk.vortex-win.data.microsoft.com",
        "https://events.data.microsoft.com",
        "https://settings-win.data.microsoft.com",
        "https://eu-v20.events.data.microsoft.com",
        "https://uk-v20.events.data.microsoft.com",
        "https://us-v20.events.data.microsoft.com",
        "https://us4-v20.events.data.microsoft.com",
        "https://us5-v20.events.data.microsoft.com",
        "https://ctldl.windowsupdate.com",
        "http://ctldl.windowsupdate.com",
        "https://validation-v2.sls.microsoft.com",
        "https://validation.sls.microsoft.com",
        "https://purchase.mp.microsoft.com",
        "https://purchase.md.mp.microsoft.com",
        "https://login.live.com",
        "https://licensing.md.mp.microsoft.com",
        "https://licensing.mp.microsoft.com",
        "https://go.microsoft.com",
        "https://displaycatalog.md.mp.microsoft.com",
        "https://displaycatalog.mp.microsoft.com",
        "https://activation-v2.sls.microsoft.com",
        "https://activation.sls.microsoft.com",
        "https://ekop.intel.com",
        "https://ekcert.spserv.microsoft.com",
        "https://ftpm.amd.com",
        "https://cs.dds.microsoft.com",
        "https://login.live.com",
        "https://ztd.dds.microsoft.com",
        "https://emdl.ws.microsoft.com",
        "https://dl.delivery.mp.microsoft.com",
        "https://geo-prod.do.dsp.mp.microsoft.com"
    )
    
    #From https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints
    #$onlineEndpoints = (invoke-restmethod -Uri ("https://endpoints.office.com/endpoints/WorldWide?ServiceAreas=MDE`&clientrequestid=" + ([GUID]::NewGuid()).Guid)) | ?{$_.ServiceArea -eq "MDE" -and $_.urls} | select -unique -ExpandProperty urls

    # Test each endpoint
    foreach ($endpoint in $allEndpoints) {
        # Initialize an object to store the test result for this endpoint
        $testResult = New-Object PSObject
        $testResult | Add-Member -MemberType NoteProperty -Name "URL" -Value $endpoint

        # Extract the scheme and host from the endpoint URL
        $uri = [Uri]$endpoint
        $scheme = $uri.Scheme
        $hostname = $uri.Host

        # Determine the port to test based on the scheme
        $port = if ($scheme -eq 'https') { 443 } else { 80 }

        # Test DNS resolution and connectivity to the endpoint
        try {
            $dnsResult = Resolve-DnsName -Name $hostname -ErrorAction Stop

            $connectionResult = Test-NetConnection -ComputerName $hostname -Port $port -InformationLevel Detailed -ErrorAction Stop

            if ($connectionResult.TcpTestSucceeded) {
                $testResult | Add-Member -MemberType NoteProperty -Name "TestResult" -Value "OK"
                $testResult | Add-Member -MemberType NoteProperty -Name "ResultDescription" -Value "Connected successfully to $endpoint on port $port"
            } else {
                $testResult | Add-Member -MemberType NoteProperty -Name "TestResult" -Value "Error"
                $testResult | Add-Member -MemberType NoteProperty -Name "ResultDescription" -Value "Failed to connect to $endpoint on port $port"
            }
        } catch {
            $testResult | Add-Member -MemberType NoteProperty -Name "TestResult" -Value "Error"
            $testResult | Add-Member -MemberType NoteProperty -Name "ResultDescription" -Value "An error occurred while trying to connect to $($endpoint): $_"
        }

        # Add the test result to the array
        $testResults += $testResult
    }

    # Return the test results
    return $testResults
}


function Invoke-AsSystem {
    <#
    .SYNOPSIS
    Function for running specified code under SYSTEM account locally.

    .DESCRIPTION
    Function for running specified code under SYSTEM account locally. This function creates a scheduled task to run a provided script block as SYSTEM.

    .PARAMETER scriptBlock
    Scriptblock that should be run under SYSTEM account.

    .PARAMETER returnTranscript
    If set, creates a transcript of the scriptBlock's output and returns it.

    .PARAMETER cacheToDisk
    If set, writes the script block to a temporary file on disk if it's too large to run normally.

    .PARAMETER argument
    Hashtable of variables to define at the start of the scriptBlock.

    .EXAMPLE
    Invoke-AsSystem {New-Item $env:TEMP\abc}

    Will call the given scriptblock under the SYSTEM account locally.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock] $scriptBlock,

        [switch] $returnTranscript,

        [hashtable] $argument,

        [switch] $CacheToDisk
    )

    # SYSTEM account string for scheduled tasks
    $runAs = "NT Authority\SYSTEM"

    # Check if running as administrator
    if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "You don't have administrator rights"
    }

    # Script block to create and run the scheduled task
    $command = {
        param ($scriptBlock, $runAs, $CacheToDisk, $VerbosePreference, $ReturnTranscript, $Argument)

        # Create a transcript if required
        $TranscriptPath = "$ENV:TEMP\Invoke-AsSYSTEM_$(Get-Random).log"
        if ($Argument -or $ReturnTranscript) {
            if ($Argument) {
                $VariableTextDef = Create-VariableTextDefinition $Argument
            }
            if ($ReturnTranscript) {
                $TranscriptStart = "Start-Transcript $TranscriptPath"
                $TranscriptEnd = 'Stop-Transcript'
            }

            # Create a new script block with the transcript and any arguments
            $ScriptBlockContent = ($TranscriptStart + "`n`n" + $VariableTextDef + "`n`n" + $ScriptBlock.ToString() + "`n`n" + $TranscriptEnd)
            $scriptBlock = [Scriptblock]::Create($ScriptBlockContent)
        }

        # Write the script block to a temporary file if it's too large or cacheToDisk is set
        if ($CacheToDisk) {
            $ScriptGuid = New-Guid
            $null = New-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Value $ScriptBlock -Force
            $pwshcommand = "-ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File `"$($ENV:TEMP)\$($ScriptGuid).ps1`""
        } else {
            $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
            $pwshcommand = "-ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -EncodedCommand $($encodedcommand)"
        }

        # Create and run the scheduled task
        $taskName = "RunAsSystem_" + (Get-Random)
        $A = New-ScheduledTaskAction -Execute "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe" -Argument $pwshcommand
        $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType ServiceAccount
        $S = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd

        try {
            $null = New-ScheduledTask -Action $A -Principal $P -Settings $S -ErrorAction Stop | Register-ScheduledTask -Force -TaskName $taskName -ErrorAction Stop
            Start-Sleep -Milliseconds 200
            Start-ScheduledTask $taskName

            # Wait for the task to complete
            Write-Verbose "Waiting for scheduled task to complete..."
            $i = 0
            while (((Get-ScheduledTask $taskName -ErrorAction SilentlyContinue).State -ne "Ready") -and $i -lt 500) {
                ++$i
                Start-Sleep -Milliseconds 200
            }

            # Get the task result code
            $result = (Get-ScheduledTaskInfo $taskName).LastTaskResult

            # If returnTranscript was set, get the transcript content
            if ($ReturnTranscript) {
                if (Test-Path $TranscriptPath) {
                    $transcriptContent = (Get-Content $TranscriptPath -Raw) -Split [regex]::Escape('**********************')
                    ($transcriptContent[2] -Split "`n" | Select-Object -Skip 2 | Select-Object -SkipLast 3) -Join "`n"
                    Remove-Item $TranscriptPath -Force
                } else {
                    Write-Warning "There is no transcript, command probably failed!"
                }
            }

            # If cacheToDisk was set, delete the temporary file
            if ($CacheToDisk) { $null = Remove-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Force }

            # Unregister (delete) the scheduled task
            try {
                Unregister-ScheduledTask $taskName -Confirm:$false -ErrorAction Stop
            } catch {
                throw "Unable to unregister scheduled task $taskName. Please remove it manually"
            }

            # If the task result code is not 0, throw an exception
            if ($result -ne 0) {
                throw "Command did not complete successfully ($result)"
            }
        } catch {
            throw $_.Exception
        }
    }

}



#Endregion Functions

#Region Main
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
# === This is the end of System configuration info

# ======= BIOS Info =======
$msg = "`...Getting BIOS information."
Write-Host $msg -ForegroundColor White

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logBanner = "==========================================================="
$logBanner += "          BIOS Information          " 
$logBanner += "===========================================================`n`n"
$logFooter = "`n`n==========`n`n"

# @jmanuelnieto: Get BIOS and TPM information. This is to understand if the system has TPM, and what version.
$PC_biostpm = Get-BiosTpm

# @jmanuelnieto: It then adds BIOS and TPM info to file.
$msg = "`...Wiritng BIOS report."
Write-Host $msg -ForegroundColor White

# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logBanner -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_biostpm -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append

# === End of BIOS information

# ======= Shares and Network Drives Info =======
$msg = "`...Getting Network Shares and Network Drives information."
Write-Host $msg -ForegroundColor White

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logBanner = "==========================================================="
$logBanner += "          Shared Folders and Network Drives Information          " 
$logBanner += "===========================================================`n`n"
$logSpacing = "`n`n"
$logHeading01 = " === Shared folders report using CimInstance:"
$logHeading02 = " === Connected Network drives report:"
$logFooter = "`n`n==========`n`n"

# Calls funcion to get Shares report.
$PC_Shares = Get-SharedFoldersInventory | Format-Table
# Calls the function to get Netowkr Drive info.
$PC_NetDrives = Get-NetworkDrivesInventory | Format-Table



# @jmanuelnieto: It then adds BIOS and TPM info to file.
$msg = "`...Wiritng Shares and Network Drives reporte."
Write-Host $msg -ForegroundColor White

# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logBanner -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logHeading01 -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_Shares -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logSpacing -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logHeading02 -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_NetDrives -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append

# === End of Shares and Network Drives information.

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logBanner = "==========================================================="
$logBanner += "          Group and Local Policies Information          " 
$logBanner += "===========================================================`n`n"
$logFooter = "`n`n==========`n`n"

# @jmanuelnieto: Get info for applied policies on device, it will list Local and Domain policies applied.
$PC_GpoInfo = Get-GPOInventory | Format-Table

# @jmanuelnieto: It then adds Policies information to file.
$msg = "`...Wiritng Policies report."
Write-Host $msg -ForegroundColor White

# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logBanner -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_GpoInfo -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append

# === End of Policies information

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logBanner = "==========================================================="
$logBanner += "          Installed Printers Information          " 
$logBanner += "===========================================================`n`n"
$logFooter = "`n`n==========`n`n"

# @jmanuelnieto: Get installed printers information. 
$PC_Printers = Get-PrinterInventory | Format-Table

# @jmanuelnieto: It then adds Policies information to file.
$msg = "`...Wiritng Installed printers report."
Write-Host $msg -ForegroundColor White

# Writing result to file after execution in case user cancels before ending execution. 
Out-File -FilePath $PC_filename -InputObject $logBanner -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $PC_Printers -Encoding ASCII -Append
Out-File -FilePath $PC_filename -InputObject $logFooter -Encoding ASCII -Append

# === End of Printers information


# ===========   @jmanuelnieto: Networking details.   ===========

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logBanner = "==========================================================="
$logBanner += "          Network Adapter Info          " 
$logBanner += "===========================================================`n`n"

# == Network information, Get-NetAdapter, netsh
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Detailed network information from PS Get-NetAdapters" 
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

<# 
=============================================================================
         Tests to Intune and Defender for Endpoint network Endpoints          
=============================================================================
#>

$msg = "`...Testing Network connectivity to Microsoft Intune and MDE endpoints (user)."
Write-Host $msg -ForegroundColor White

$EndPointTest_folder = ".\NetTestEndpoints"
If ( -not(Test-Path $EndPointTest_folder)) {  
    #Create folder if it does not exist
    New-Item -Path "$EndPointTest_folder" -ItemType Directory | Out-Null
}
$EndPointTest_folder = $PSScriptRoot + "\NetTestEndpoints"
$EndPoint_CSVfile = "$EndPointTest_folder\TestEndpoint_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"

# Call the function to test the endpoints
$NetTestResults = Test-IntuneDefenderAndOtherEndpoints | Select-Object URL, TestResult, ResultDescription

# @jmanuelnieto: Notify user of report fil creation.
$msg = "`...Writing network connectivity results to CSV file."
Write-Host $msg -ForegroundColor White

$NetTestResults | Export-CSV -Path $EndPoint_CSVfile -NoType

<#
$msg = "`...Testing Network connectivity to Microsoft Intune and MDE endpoints (system)."
Write-Host $msg -ForegroundColor White

$EndPointTest_folder = ".\NetTestEndpoints"
If ( -not(Test-Path $EndPointTest_folder)) {  
    #Create folder if it does not exist
    New-Item -Path "$EndPointTest_folder" -ItemType Directory | Out-Null
}
$EndPointTest_folder = $PSScriptRoot + "\NetTestEndpoints"
$EndPoint_CSVsysfile = "$EndPointTest_folder\SysTestEndpoint_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"
# Call the function to test the endpoints
$SysNetTestResults = Invoke-AsSystem -ScriptBlock { Test-IntuneDefenderAndOtherEndpoints } -ReturnTranscript -CacheToDisk
#$SysNetTestResults = Invoke-AsSystem { dsregcmd /status }
$msg = "`...Writing network connectivity results to CSV file."
Write-Host $msg -ForegroundColor White

#$SysNetTestResults | Export-CSV -Path $EndPoint_CSVsysfile -NoType
#>

<# 
=============================================================================
                      Device Software Inventory          
=============================================================================
#>

# @jmanuelnieto: Get Software Inventory.
$msg = "`...Getting Software Inventory."
Write-Host $msg -ForegroundColor White

$SW_folder = "Software"
If ( -not(Test-Path $SW_folder)) {  
    #Create folder if it does not exist
    New-Item -Path ".\$SW_folder" -ItemType Directory | Out-Null
}

# Call software inventory function and write results to CSV file
$PC_swReport = Get-InstalledSoftware | Select-Object Name, Version, Vendor, PackageName, InstallDate, Description, InstallLocation, InstallSource, InventorySource

# @jmanuelnieto: Notify about Software Inventory report.
$msg = "`...Writing Software Inventory to CSV file."
Write-Host $msg -ForegroundColor White

# @jmanuelnieto: Create Software Inventory report, show it in GridView.
$ExportCSV =".\$SW_folder\ComputerInfo_SW_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"
# gridview used while testing
#$PC_swReport | out-gridview
$PC_swReport | Export-CSV -Path $ExportCSV -NoType


<# 
=============================================================================
                      Device Battery Report          
=============================================================================
#>
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

#Endregion Main
