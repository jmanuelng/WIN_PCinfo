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

    To do:
    Get start menu apps
        Get-StartApps https://learn.microsoft.com/en-us/windows/configuration/find-the-application-user-model-id-of-an-installed-app
        Get info to customize task bar and start menu: https://learn.microsoft.com/en-us/windows/configuration/customize-taskbar-windows-11#get-the-aumid-and-desktop-app-link-path

.COMMENTS
    Should also add comment that to run script to verify 
    Set-ExecutionPolicy Bypass
    
#>

#region Functions

function Test-FolderExists {
    <#
    .SYNOPSIS
        Checks if a specified folder exists, and if it doesn't, creates it.

    .DESCRIPTION
        The function takes a parameter 'Folder', which specifies the path to the folder.
        If the folder does not exist, the function creates it.
        The function determines if the 'Folder' parameter is a full path or relative path based on the presence of a slash character.
        If the 'Folder' parameter does not contain a slash, it is treated as a relative path from the current directory.
        
    .PARAMETER Folder
        The path to the folder to check or create. This can be a full path or a relative path.
        
    .EXAMPLE
        Test-FolderExists -Folder "Config"
        Ensures that a folder named 'Config' exists in the current directory.
        
    .EXAMPLE
        Test-FolderExists -Folder "C:\Config"
        Ensures that a folder named 'Config' exists in the root of the C drive.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $Folder
    )

    try {
        # Check if the 'Folder' parameter contains a slash. If not, treat it as a relative path from the current directory.
        if ($Folder -notmatch '\\') {
            $Folder = ".\$Folder"
        }

        # Check if the folder exists
        if (-not (Test-Path $Folder)) {
            # If the folder does not exist, create it
            New-Item -Path $Folder -ItemType Directory -Force | Out-Null
        } 
    } catch {
        # Catch and display any errors that occurred during execution
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}

function Write-Log {
    <#
    .SYNOPSIS
    This function writes log information to a specified file.

    .DESCRIPTION
    The function accepts log data, a file path and an optional title.
    It formats the log data and writes it to the file. If a title is provided,
    it creates a formatted header and footer using the title. An additional
    optional parameter allows the user to specify whether they want to add
    the header, the footer, both, or none to the output file.

    .PARAMETER Log
    The log data to be written to the file.

    .PARAMETER Filename
    The path of the file where the log data will be written.

    .PARAMETER Title
    The title to be used for the header and footer. If not provided, no header or footer will be added.

    .PARAMETER HeaderFooter
    An optional parameter specifying whether to add Title to the header ("H"), or to the footer ("F"), both (not provided or any other value), or none ("").

    .EXAMPLE
    Write-Log -Log $LogData -Filename "log.txt" -Title "Log Title" -HeaderFooter "H"
    #>

    param (
        [Parameter(Mandatory=$false)]
        [Object]$Log,

        [Parameter(Mandatory=$true)]
        [string]$Filename,

        [Parameter(Mandatory=$false)]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [ValidateSet("H","F","")]
        [string]$HeaderFooter
    )

    # If Log is null or empty, return without doing anything
    if ([string]::IsNullOrEmpty($Log)) {
        return
    }

    # Convert the Log object to a string
    $Log = $Log | Out-String

    # Define the total line length
    $lineLength = 200

    # Check if Title is provided and not empty
    if (![string]::IsNullOrEmpty($Title)) {
        # Calculate the amount of padding needed on either side of the title to center it
        $padding = ($lineLength - $Title.Length) / 2

        # Create the banner and footer with the centered title
        $logBanner = "=" * $lineLength
        $logBanner += "`n" + (" " * [math]::Floor($padding)) + $Title + (" " * [math]::Ceiling($padding))
        $logBanner += "`n" + "=" * $lineLength + "`n`n"

        $logFooter = "`n`n" + "=" * $lineLength
        $logFooter += "`n" + (" " * [math]::Floor($padding)) + $Title + (" " * [math]::Ceiling($padding))
        $logFooter += "`n" + "=" * $lineLength + "`n`n`n`n"

        # Write the log information, banner and footer to the output file
        try {
            if ($HeaderFooter -ne "F") {
                Out-File -FilePath $Filename -InputObject $logBanner -Encoding ASCII -Append # If file already exists it will append.
            }

            Out-File -FilePath $Filename -InputObject $Log -Encoding ASCII -Append

            if ($HeaderFooter -ne "H") {
                Out-File -FilePath $Filename -InputObject $logFooter -Encoding ASCII -Append
            }
        }
        catch {
            # Catch any errors that occurred during the execution and print to the console
            Write-Host "An error occurred while writing to the log file: $_" -ForegroundColor Red
        }
    }
    else {
        # Write only log information to the output file, as Title was not provided
        try {
            Out-File -FilePath $Filename -InputObject $Log -Encoding ASCII -Append
        }
        catch {
            # Catch any errors that occurred during the execution and print to the console
            Write-Host "An error occurred while writing to the log file: $_" -ForegroundColor Red
        }
    }
}


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
    <#
    .SYNOPSIS
    Function to test connectivity to various Microsoft Intune and Defender endpoints.
    
    .DESCRIPTION
    Resolves the DNS for each endpoint and tests the connectivity to it. 
    It records the test results in an array and, if specified, writes the results to a CSV file.
    
    .PARAMETER outFilePath
    The full path of the CSV file to write the test results to. If not specified, the function returns the test results.
    #>

    [CmdletBinding()]
    param (
        [string] $outFilePath
    )
    # Initialize an array to store the results
    $testResults = @()

    # Error checking for file existence and overwrite
    if ($outFilePath -and (Test-Path -Path $outFilePath)) {
        Write-Host "File '$outFilePath' already exists. It will be overwritten."
    }

    # List of required service endpoints
    $allEndpoints = @(
        #  **Intune Service**
        "https://manage.microsoft.com",
        "https://prod.do.dsp.mp.microsoft.com",
        "https://device.listener.prod.microsoft.com",
        "https://device.listener.prod.eudb.microsoft.com",
        "https://payload.prod.blob.core.windows.net",
        "https://intune.cdn.pea.sd.azureedge.net",
        "https://mam.manage.microsoft.com",
        "https://manage.microsoft.com",
        "https://policy.manage.microsoft.com",
        "https://device.manage.microsoft.com",
        "https://provisioning.manage.microsoft.com",
        "https://portal.manage.microsoft.com",
        "https://diagnostics.manage.microsoft.com",
        "https://enterpriseregistration.windows.net",
        "https://enterpriseenrollment-s.manage.microsoft.us"
        "https://mam.manage.microsoft.com",
        
        # **Threat and Vulnerability Management (TVM)**
        "https://us.tip.manage.microsoft.com",
        "https://eu.tip.manage.microsoft.com",
        "https://apac.tip.manage.microsoft.com",
        
        #  **Windows Update and Delivery Optimization**
        "http://windowsupdate.com",
        "https://dl.delivery.mp.microsoft.com",
        "https://update.microsoft.com",
        "https://delivery.mp.microsoft.com",
        "https://tsfe.trafficshaping.dsp.mp.microsoft.com",
        "https://emdl.ws.microsoft.com",
        "https://do.dsp.mp.microsoft.com",
        "http://ctldl.windowsupdate.com",
        "https://ctldl.windowsupdate.com",
        "https://geo-prod.do.dsp.mp.microsoft.com",
        
        # **Push Notifications**
        "https://notify.windows.com",
        "https://wns.windows.com",

        # **NTP Sync**
        "http://time.windows.com",

        # **Scripts**
        "http://www.msftconnecttest.com",
        "http://www.msftncsi.com",

        # **Win32 Apps**
        "https://s.microsoft.com",

        #Other services, or I don't know the related service
        "https://portal.azure.com",
        "https://login.microsoftonline.com",

        # **Microsoft Defender for Endpoint
        "https://winatp-gw-cus.microsoft.com",
        "https://winatp-gw-eus.microsoft.com",
        "https://winatp-gw-weu.microsoft.com",
        "https://winatp-gw-neu.microsoft.com",
        "https://winatp-gw-uks.microsoft.com",
        "https://winatp-gw-ukw.microsoft.com",
        "https://winatp-gw-usgv.microsoft.com",
        "https://winatp-gw-usgt.microsoft.com",
        
        # **Windows Telemetry**
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

        # **Software Licensing Service (SLS)**
        "https://validation-v2.sls.microsoft.com",
        "https://validation.sls.microsoft.com",

        # **Software Activation**
        "https://activation-v2.sls.microsoft.com",
        "https://activation.sls.microsoft.com",

        # **Microsoft Account**
        "https://login.live.com",
        "https://login.windows.net",

        # **Intel EKOP**
        "https://ek.cert.spserv.microsoft.com",
        "https://ekop.intel.com",
        "https://ekcert.spserv.microsoft.com",

        # **AMD FTPM**
        "https://ftpm.amd.com",

        # **Device Health Attestation (DHA)**
        "https://cs.dds.microsoft.com",

        # **Remote Help**
        "https://remoteassistance.prod.acs.communication.azure.com",

        # **Autopilot Self-Deploy**
        "https://ztd.dds.microsoft.com",
        "https://storeclientconfig.passport.net",
        "https://windowsphone.com",
        "https://approdi.me.data.hotfix.azureedge.net",
        "https://approdi.me.data.pri.azureedge.net",
        "https://approdi.me.data.sec.azureedge.net",
        "https://eu.prodi.me.data.hotfix.azureedge.net",
        "https://eu.prodi.me.data.pri.azureedge.net",
        "https://eu.prodi.me.data.sec.azureedge.net",
        "https://na.prodi.me.data.hotfix.azureedge.net",
        "https://na.prodi.me.data.pri.azureedge.net",
        "https://sw.da.01.ms.cdn.azureedge.net",
        "https://sw.da.02.ms.cdn.azureedge.net",
        "https://sw.db.01.ms.cdn.azureedge.net",
        "https://sw.db.02.ms.cdn.azureedge.net",
        "https://sw.dc.01.ms.cdn.azureedge.net",
        "https://sw.dc.02.ms.cdn.azureedge.net",
        "https://sw.dd.01.ms.cdn.azureedge.net",
        "https://sw.dd.02.ms.cdn.azureedge.net",
        "https://sw.din.01.ms.cdn.azureedge.net",
        "https://sw.din.02.ms.cdn.azureedge.net",

        # **Microsoft Store**
        "https://purchase.mp.microsoft.com",
        "https://purchase.md.mp.microsoft.com",
        "https://licensing.md.mp.microsoft.com",
        "https://licensing.mp.microsoft.com",
        "https://displaycatalog.md.mp.microsoft.com",
        "https://displaycatalog.mp.microsoft.com",

        # ** Channel Services**
        "https://channel.services.microsoft.com", 

        # **Apple Device Management**
        "https://itunes.apple.com",
        "https://mzstatic.com",
        "https://phobos.apple.com",
        "https://5.courier-push.apple.com",
        "https://ax.itunes.apple.com.edgesuite.net",
        "http://ocsp.apple.com",
        "http://phobos.itunes.apple.com.akadns.net",

        # ... Include other endpoints here ...
        # Other services, or I didn't know where to classify them
        "https://go.microsoft.com"
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
    if ($outFilePath) {
        try {
            $testResults | Select-Object URL, TestResult, ResultDescription | Export-CSV -Path $outFilePath -NoTypeInformation -Force
        } catch {
            Write-Error -Message "An error occurred while trying to write to '$outFilePath': $_"
        }
    }
    else {
        return $testResults
    }
    
}


function Invoke-AsSystem {
    <#
    .SYNOPSIS
    Function for running specified code under SYSTEM account.

    .DESCRIPTION
    Function for running specified code under SYSTEM account.

    Helper files and sched. tasks are automatically deleted.

    .PARAMETER scriptBlock
    Scriptblock that should be run under SYSTEM account.

    .PARAMETER computerName
    Name of computer, where to run this.

    .PARAMETER returnTranscript
    Add creating of transcript to specified scriptBlock and returns its output.

    .PARAMETER cacheToDisk
    Necessity for long scriptBlocks. Content will be saved to disk and run from there.

    .PARAMETER argument
    If you need to pass some variables to the scriptBlock.
    Hashtable where keys will be names of variables and values will be, well values :)

    Example:
    [hashtable]$Argument = @{
        name = "John"
        cities = "Boston", "Prague"
        hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }}
    }

    Will in beginning of the scriptBlock define variables:
    $name = 'John'
    $cities = 'Boston', 'Prague'
    $hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }

    ! ONLY STRING, ARRAY and HASHTABLE variables are supported !

    .PARAMETER runAs
    Let you change if scriptBlock should be running under SYSTEM, LOCALSERVICE or NETWORKSERVICE account.

    Default is SYSTEM.

    .EXAMPLE
    Invoke-AsSystem {New-Item $env:TEMP\abc}

    On local computer will call given scriptblock under SYSTEM account.

    .EXAMPLE
    Invoke-AsSystem {New-Item "$env:TEMP\$name"} -computerName PC-01 -ReturnTranscript -Argument @{name = 'someFolder'} -Verbose

    On computer PC-01 will call given scriptblock under SYSTEM account i.e. will create folder 'someFolder' in C:\Windows\Temp.
    Transcript will be outputted in console too.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock] $scriptBlock,
        [string] $computerName,
        [switch] $returnTranscript,
        [hashtable] $argument,
        [ValidateSet('SYSTEM', 'NETWORKSERVICE', 'LOCALSERVICE')]
        [string] $runAs = "SYSTEM",
        [switch] $CacheToDisk
    )

    (Get-Variable runAs).Attributes.Clear()
    $runAs = "NT Authority\$runAs"

    #region prepare Invoke-Command parameters
    # export this function to remote session (so I am not dependant whether it exists there or not)
    $allFunctionDefs = "function Create-VariableTextDefinition { ${function:Create-VariableTextDefinition} }"

    $param = @{
        argumentList = $scriptBlock, $runAs, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument
    }

    if ($computerName -and $computerName -notmatch "localhost|$env:COMPUTERNAME") {
        $param.computerName = $computerName
    } else {
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "You don't have administrator rights"
        }
    }
    #endregion prepare Invoke-Command parameters

    Invoke-Command @param -ScriptBlock {
        param ($scriptBlock, $runAs, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument)

        foreach ($functionDef in $allFunctionDefs) {
            . ([ScriptBlock]::Create($functionDef))
        }

        $TranscriptPath = "$ENV:TEMP\Invoke-AsSYSTEM_$(Get-Random).log"

        if ($Argument -or $ReturnTranscript) {
            # define passed variables
            if ($Argument) {
                # convert hash to variables text definition
                $VariableTextDef = Create-VariableTextDefinition $Argument
            }

            if ($ReturnTranscript) {
                # modify scriptBlock to contain creation of transcript
                $TranscriptStart = "Start-Transcript $TranscriptPath"
                $TranscriptEnd = 'Stop-Transcript'
            }

            $ScriptBlockContent = ($TranscriptStart + "`n`n" + $VariableTextDef + "`n`n" + $ScriptBlock.ToString() + "`n`n" + $TranscriptEnd)
            Write-Verbose "####### SCRIPTBLOCK TO RUN"
            Write-Verbose $ScriptBlockContent
            Write-Verbose "#######"
            $scriptBlock = [Scriptblock]::Create($ScriptBlockContent)
        }

        if ($CacheToDisk) {
            $ScriptGuid = New-Guid
            $null = New-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Value $ScriptBlock -Force
            $pwshcommand = "-ExecutionPolicy Bypass -Window Hidden -noprofile -file `"$($ENV:TEMP)\$($ScriptGuid).ps1`""
        } else {
            $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
            $pwshcommand = "-ExecutionPolicy Bypass -Window Hidden -noprofile -EncodedCommand $($encodedcommand)"
        }

        $OSLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion
        if ($OSLevel -lt 6.2) { $MaxLength = 8190 } else { $MaxLength = 32767 }
        if ($encodedcommand.length -gt $MaxLength -and $CacheToDisk -eq $false) {
            throw "The encoded script is longer than the command line parameter limit. Please execute the script with the -CacheToDisk option."
        }

        try {
            #region create&run sched. task
            $A = New-ScheduledTaskAction -Execute "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe" -Argument $pwshcommand
            if ($runAs -match "\$") {
                # pod gMSA uctem
                $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType Password
            } else {
                # pod systemovym uctem
                $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType ServiceAccount
            }
            $S = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
            $taskName = "RunAsSystem_" + (Get-Random)
            try {
                $null = New-ScheduledTask -Action $A -Principal $P -Settings $S -ea Stop | Register-ScheduledTask -Force -TaskName $taskName -ea Stop
            } catch {
                if ($_ -match "No mapping between account names and security IDs was done") {
                    throw "Account $runAs doesn't exist or cannot be used on $env:COMPUTERNAME"
                } else {
                    throw "Unable to create helper scheduled task. Error was:`n$_"
                }
            }

            # run scheduled task
            Start-Sleep -Milliseconds 200
            Start-ScheduledTask $taskName

            # wait for sched. task to end
            Write-Verbose "waiting on sched. task end ..."
            $i = 0
            while (((Get-ScheduledTask $taskName -ErrorAction silentlyContinue).state -ne "Ready") -and $i -lt 500) {
                ++$i
                Start-Sleep -Milliseconds 200
            }

            # get sched. task result code
            $result = (Get-ScheduledTaskInfo $taskName).LastTaskResult
            Write-Verbose "Task result: $result"

            # read & delete transcript
            if ($ReturnTranscript) {
                # return just interesting part of transcript
                if (Test-Path $TranscriptPath) {
                    $transcriptContent = (Get-Content $TranscriptPath -Raw) -Split [regex]::escape('**********************')
                    # return command output
                    ($transcriptContent[2] -split "`n" | Select-Object -Skip 2 | Select-Object -SkipLast 3) -join "`n"

                    Remove-Item $TranscriptPath -Force
                } else {
                    Write-Warning "There is no transcript, command probably failed!"
                }
            }

            if ($CacheToDisk) { $null = Remove-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Force }

            try {
                Unregister-ScheduledTask $taskName -Confirm:$false -ea Stop
            } catch {
                throw "Unable to unregister sched. task $taskName. Please remove it manually"
            }

            if ($result -ne 0) {
                throw "Command wasn't successfully ended ($result)"
            }
            #endregion create&run sched. task
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


#region Main SystemConfig

# ===========   @jmanuelnieto: System data collection.   ===========

# @jmanuelnieto: Collect DSReg status info
# @jmanuelnieto: File name and locations to store gathered info, the "output file".
$PC_folder = "Config"
Test-FolderExists -Folder $PC_folder

$PC_filename = ".\$PC_folder\ComputerInfo_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).txt"


# == DSReg ==
# @jmanuelnieto: Title for Banner and heading to distinguish this section in Output File.
$logTitle = "Device Registration Troubleshooter Command Tool"
# @jmanuelnieto: Collect DSReg status info
# Inform user on screen
$msg = "`...Getting DSReg information."
Write-Host $msg -ForegroundColor White
# @jmanuelnieto: running the diagnostics in SYSTEM context is closest to the actual join scenario. 
# To run diagnostics in SYSTEM context, the dsregcmd /status command must be run from an elevated command prompt.
$DSreg = dsregcmd /status
# @jmanuelnieto: Write DSReg results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log $DSreg -Filename $PC_filename -Title "$logTitle"



# ==== Computer Info ====
$msg = "`...Getting systemInfo."
Write-Host $msg -ForegroundColor White

# @jmanuelnieto: Title for Banner and heading to distinguish this section in Output File.
$logTitle = "Detailed Computer, Windows and Licensing Information" 

# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Basic Computer information: Name, owner, domain, memory, manufacturer and model from CimInstance:`n`n" 

# == Computer information, CimInstace
# @jmanuelnieto: Get basic Computer information: Name, owner, domain, memory, manufacturer and model from CimInstance
$PC_basicinfo = Get-CimInstance -ClassName Win32_ComputerSystem
# Add heading to Log content

# @jmanuelnieto: Write CiMInstance results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log "$logHeading $PC_basicinfo" -Filename $PC_filename -Title $logTitle -HeaderFooter "H"


# == SystemInfo 
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Complete Computer information using ""systeminfo"": `n`n" 

# @jmanuelnieto: Get detailed System Information using "systeminfo" command
# Displays detailed configuration information about a computer and its operating system, including operating system configuration, security information, product ID, and hardware properties (such as RAM, disk space, and network cards).
# Systeminfo /fo = Format output to CSV.
# | Forma-List = Capture the output, convert it to a list to append to Output file
$PC_systeminfo = Systeminfo /fo CSV | ConvertFrom-CSV | Format-List | Out-String
# @jmanuelnieto: Write SystemInfo results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log "$logHeading $PC_systeminfo" -Filename $PC_filename


# == Complete System Information from WmiObject ComputerSystemProduct
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Complete Computer information using ""WmiObject ComputerSystemProduct"": `n`n" 

# The Win32_ComputerSystemProduct WMI class represents a product. This includes software and hardware used on the computer system.
$PC_product = Get-WmiObject -Class Win32_ComputerSystemProduct | Format-List -Property * | Out-String
# @jmanuelnieto: Write Win32_ComputerSystemProduct results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log "$logHeading $PC_product" -Filename $PC_filename


# == Complete System Information from WmiObject ComputerSystem
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Complete Windows information using ""WmiObject ComputerSystem"":" 

# The Win32_ComputerSystem WMI class represents a computer system running Windows.
$PC_system = Get-WmiObject -Class Win32_ComputerSystem | Format-List -Property * | Out-String
# @jmanuelnieto: Write Win32_ComputerSystem results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log "$logHeading $PC_system" -Filename $PC_filename


# == Software Licensing Tool
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Software Licensing Management Tool, get license and activation information: `n" 

# @jmanuelnieto: Get path to slmgr.vbs (Software Licensing Management Tool) script, and then execute script. 
# @jmanuelnieto: used with /dlv to display license information for the installed active Windows.
[string]$slmgrPath = Get-ChildItem -Path Env:\windir | Select-Object -ExpandProperty Value
$slmgrPath += "\System32\slmgr.vbs"
$PC_actinfo = cscript $slmgrPath /dlv | Out-String
# @jmanuelnieto: Write Software Licensing Management Tool results to output file.
# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log "$logHeading $PC_actinfo" -Filename $PC_filename


# == Windows License details
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === License keys details from CimInstance, license information:" 

# @jmanuelnieto: Get Windows keys detail information. This includes Firmware OEM License. 
# Upgrade to Enterprise requires Activation Keys. More info: https://docs.microsoft.com/en-us/windows/deployment/deploy-enterprise-licenses
$PC_winlicenseexpanded = Get-CimInstance -ClassName SoftwareLicensingService | Format-List -Property * | Out-String
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
Write-Log -Log "$logHeading $PC_winlicenseexpanded $PC_winlicense" -Filename $PC_filename -Title $logTitle -HeaderFooter "F"

# === This is the end of System configuration info

# ======= BIOS Info =======
$msg = "`...Getting BIOS information."
Write-Host $msg -ForegroundColor White

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logTitle = "BIOS Information"

# @jmanuelnieto: Get BIOS and TPM information. This is to understand if the system has TPM, and what version.
$PC_biostpm = Get-BiosTpm

# @jmanuelnieto: It then adds BIOS and TPM info to file.
$msg = "`...Wiritng BIOS report."
Write-Host $msg -ForegroundColor White

# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log $PC_biostpm -Filename $PC_filename -Title $logTitle

# === End of BIOS information

# ======= Shares and Network Drives Info =======
$msg = "`...Getting Network Shares and Network Drives information."
Write-Host $msg -ForegroundColor White

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logTitle = "Shared Folders and Network Drives Information" 
$logHeading01 = " === Shared folders report using CimInstance:`n"
$logHeading02 = " === Connected Network drives report:`n"


# Calls funcion to get Shares report.
$PC_Shares = Get-SharedFoldersInventory | Format-Table | Out-String
# Calls the function to get Netowkr Drive info.
$PC_NetDrives = Get-NetworkDrivesInventory | Format-Table | Out-String

# @jmanuelnieto: It then adds BIOS and TPM info to file.
$msg = "`...Wiritng Shares and Network Drives reporte."
Write-Host $msg -ForegroundColor White

# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log "$logHeading01 $PC_Shares $logHeading02 $PC_NetDrives" -Filename $PC_filename -Title $logTitle


# === End of Shares and Network Drives information.

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logTitle = "Group and Local Policies Information" 

# @jmanuelnieto: Get info for applied policies on device, it will list Local and Domain policies applied.
$PC_GpoInfo = Get-GPOInventory | Format-Table

# @jmanuelnieto: It then adds Policies information to file.
$msg = "`...Wiritng Policies report."
Write-Host $msg -ForegroundColor White

# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log $PC_GpoInfo -Filename $PC_filename -Title $logTitle


# === End of Policies information

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logTitle = "Installed Printers Information" 

# @jmanuelnieto: Get installed printers information. 
$PC_Printers = Get-PrinterInventory | Format-Table

# @jmanuelnieto: It then adds Policies information to file.
$msg = "`...Wiritng Installed printers report."
Write-Host $msg -ForegroundColor White

# Writing result to file after execution in case user cancels before ending execution. 
Write-Log -Log $PC_Printers -Filename $PC_filename -Title $logTitle


# === End of Printers information

#endregion Main SystemConfig

#region Main Network

# ===========   @jmanuelnieto: Networking details.   ===========

# @jmanuelnieto: Banner and heading to distinguish this section in Output File.
$logTitle = "Network Adapter Info" 

# == Network information, Get-NetAdapter, netsh
# @jmanuelnieto: Heading and Footer to distinguish this section in Output File.
$logHeading = " === Detailed network information from PS Get-NetAdapters" 

$NET_folder = ".\Network"
Test-FolderExists -Folder $NET_folder

$NET_folder = $PSScriptRoot + "\Network" # Had issues using netsh with relative Path
$NET_infofile = "$NET_folder\Networkinfo_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).txt"


# @jmanuelnieto: get network adapters list
$NET_adapter = Get-NetAdapter | Format-List -Property * | Out-String

# @jmanuelnieto: get profile information for connected netwrok adapter using PS command
$NET_connection = Get-NetConnectionProfile | Format-List -Property * | Out-String

# @jmanuelnieto: get Lan and WLan profiles with netsh
# @jmanuelnieto: netsh is used to get a list of all profiles, stores the list in a TXT file, puts in a folder
netsh wlan export profile key=clear folder="$NET_folder"

# Write info from PS commands to a log file.
Write-Log -Log "$NET_adapter `n`n  $NET_connection" -Filename $NET_infofile -Title $logTitle


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
$EndPoint_CSVfile = "$EndPointTest_folder\TestEndpoint_$((Get-Date -format yyyy-MMM-dd_`HH-mm).ToString()).csv"

# Call the function to test the endpoints
$NetTestResults = Test-IntuneDefenderAndOtherEndpoints

# @jmanuelnieto: Notify user of report fil creation.
$msg = "`...Writing network connectivity results to CSV file."
Write-Host $msg -ForegroundColor White

$NetTestResults | Export-CSV -Path $EndPoint_CSVfile -NoType

$msg = "`...Testing Network connectivity to Microsoft Intune and MDE endpoints (System)."
Write-Host $msg -ForegroundColor White

$EndPointTest_folder = ".\NetTestEndpoints"
If ( -not(Test-Path $EndPointTest_folder)) {  
    #Create folder if it does not exist
    New-Item -Path "$EndPointTest_folder" -ItemType Directory | Out-Null
}
$EndPointTest_folder = $PSScriptRoot + "\NetTestEndpoints"
$EndPoint_CSVsysfile = "$EndPointTest_folder\SysTestEndpoint_$((Get-Date -format yyyy-MMM-dd_`HH-mm).ToString()).csv"

# Convert the function to a string.
$functionString = ${function:Test-IntuneDefenderAndOtherEndpoints}.ToString()

# Now insert the function into the script block.
$ScriptBlock = [ScriptBlock]::Create(@"
function Test-IntuneDefenderAndOtherEndpoints { $functionString }
Test-IntuneDefenderAndOtherEndpoints -outFilePath "$EndPoint_CSVsysfile"
"@)

# Call the function as System using Invoke-AsSystem function, will test endpoint under System context.
Invoke-AsSystem $ScriptBlock
$msg = "`...Finished testing as SYSYTEM, results should be on CSV file, in folder $EndPointTest_folder"
Write-Host $msg -ForegroundColor White


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
