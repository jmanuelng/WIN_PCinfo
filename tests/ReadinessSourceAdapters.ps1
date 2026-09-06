Set-StrictMode -Version Latest

# Test-only adapters run the generated actual source code. They substitute only
# Windows reads; the scheduler, worker protocol, admission, rules, contracts,
# encrypted package, HTML and protected viewing remain the generated product.
function Add-ControlledReadinessSources {
    param([string] $ModuleText, [ValidateSet('Complete','Denied','NullLicense','MixedUnknownLicense','Bounded','Absent','Unsupported','Malformed','Virtual','MicrosoftPhysical','FirmwareBounded','TimedOut','MalformedOutput','OversizeOutput','Cancelled')] [string] $Scenario)
    $source = @'
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Globalization.CultureInfo]::CurrentCulture = 'fr-FR'
[Globalization.CultureInfo]::CurrentUICulture = 'fr-FR'
$script:ReadinessCase = '__CASE__'
function Get-CimInstance {
    param($ClassName, $Property, $Filter, $Namespace, $ErrorAction)
    $allowed = @{
        Win32_ComputerSystem='HypervisorPresent|Manufacturer|Model|PCSystemType|TotalPhysicalMemory'
        Win32_Processor='Name'; Win32_OperatingSystem='BuildNumber|OperatingSystemSKU'
        SoftwareLicensingProduct='LicenseStatus'; Win32_SystemEnclosure='ChassisTypes'
        Win32_Battery='BatteryStatus|EstimatedChargeRemaining|EstimatedRunTime'
        Win32_BIOS='SMBIOSBIOSVersion|SMBIOSMajorVersion|SMBIOSMinorVersion'
        Win32_Tpm='IsActivated_InitialValue|IsEnabled_InitialValue|SpecVersion'
    }
    if (-not $allowed.ContainsKey($ClassName) -or
        (@($Property | Sort-Object) -join '|') -cne $allowed[$ClassName]) {
        throw 'Unapproved controlled source projection.'
    }
    if ($ClassName -eq 'SoftwareLicensingProduct' -and $Filter -cne "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'") { throw 'Unapproved licensing filter.' }
    if ($ClassName -eq 'Win32_Tpm' -and $Namespace -cne 'root/CIMV2/Security/MicrosoftTpm') { throw 'Unapproved TPM namespace.' }
    if ($script:ReadinessCase -eq 'Denied' -and $ClassName -in @('SoftwareLicensingProduct','Win32_SystemEnclosure','Win32_Battery','Win32_BIOS','Win32_Tpm')) { throw [UnauthorizedAccessException]::new('Synthetic denied source') }
    if ($script:ReadinessCase -eq 'Unsupported' -and $ClassName -in @('SoftwareLicensingProduct','Win32_SystemEnclosure','Win32_Battery','Win32_Tpm')) { throw [PlatformNotSupportedException]::new('Synthetic unsupported source') }
    switch ($ClassName) {
        Win32_ComputerSystem {
            if ($script:ReadinessCase -in @('TimedOut','Cancelled')) { [Threading.Thread]::Sleep(10000) }
            if ($script:ReadinessCase -eq 'OversizeOutput') { [pscustomobject]@{ Manufacturer=('X'*20000); Model='Bounded'; TotalPhysicalMemory=17179869184L; PCSystemType=1; HypervisorPresent=$false }; return }
            if ($script:ReadinessCase -eq 'Virtual') { [pscustomobject]@{ Manufacturer='Microsoft Corporation'; Model='Virtual Machine'; TotalPhysicalMemory=17179869184L; PCSystemType=1; HypervisorPresent=$true }; return }
            if ($script:ReadinessCase -eq 'MicrosoftPhysical') { [pscustomobject]@{ Manufacturer='Microsoft Corporation'; Model='Surface Laptop'; TotalPhysicalMemory=17179869184L; PCSystemType=2; HypervisorPresent=$true }; return }
            [pscustomobject]@{ Manufacturer='Fabrikam 日本語'; Model='Modèle Δ'; TotalPhysicalMemory=17179869184L; PCSystemType=2; HypervisorPresent=$false }
        }
        Win32_Processor { [pscustomobject]@{ Name='Processeur العربية' } }
        Win32_OperatingSystem { [pscustomobject]@{ OperatingSystemSKU=48; BuildNumber=if($script:ReadinessCase -eq 'MalformedOutput'){'not-a-build'}else{'26100'} } }
        SoftwareLicensingProduct {
            if ($script:ReadinessCase -eq 'Bounded') { foreach ($index in 1..17) { [pscustomobject]@{ LicenseStatus=0 } }; return }
            if ($script:ReadinessCase -in @('NullLicense','Absent')) { [pscustomobject]@{ LicenseStatus=$null }; return }
            if ($script:ReadinessCase -eq 'MixedUnknownLicense') { [pscustomobject]@{LicenseStatus=0}; [pscustomobject]@{LicenseStatus=$null}; return }
            [pscustomobject]@{ LicenseStatus=1 }
        }
        Win32_SystemEnclosure {
            if ($script:ReadinessCase -eq 'Bounded') { [pscustomobject]@{ ChassisTypes=@(1..9) }; return }
            if ($script:ReadinessCase -eq 'Malformed') { [pscustomobject]@{ ChassisTypes=@(10,256) }; return }
            [pscustomobject]@{ ChassisTypes=@(10) }
        }
        Win32_Battery {
            if ($script:ReadinessCase -eq 'Bounded') { foreach ($index in 1..2) { [pscustomobject]@{ BatteryStatus=6; EstimatedChargeRemaining=72; EstimatedRunTime=180 } } }
            elseif ($script:ReadinessCase -notin @('NullLicense','Absent','Virtual')) { [pscustomobject]@{ BatteryStatus=6; EstimatedChargeRemaining=72; EstimatedRunTime=180 } }
        }
        Win32_BIOS {
            if ($script:ReadinessCase -eq 'FirmwareBounded') { [pscustomobject]@{ SMBIOSBIOSVersion=('界'*43); SMBIOSMajorVersion=3; SMBIOSMinorVersion=7 }; return }
            [pscustomobject]@{ SMBIOSBIOSVersion='UEFI 合成-Δ'; SMBIOSMajorVersion=3; SMBIOSMinorVersion=7 }
        }
        Win32_Tpm {
            if ($script:ReadinessCase -eq 'Absent') { return }
            [pscustomobject]@{ IsEnabled_InitialValue=if($script:ReadinessCase -eq 'Malformed'){'false'}else{$true}; IsActivated_InitialValue=$true; SpecVersion='2.0, 0, 1.59' }
        }
        default { throw [UnauthorizedAccessException]::new('Synthetic denied source') }
    }
}
function Get-Command {
    param($Name, $CommandType, $ErrorAction)
    if ($Name -ne 'Confirm-SecureBootUEFI' -or $CommandType -ne 'Cmdlet') { throw 'Unexpected controlled command lookup.' }
    if ($script:ReadinessCase -eq 'Unsupported') { return }
    $command={ $true }; $command | Add-Member -NotePropertyName ModuleName -NotePropertyValue SecureBoot
    $command
}
'@
    $source = $source.Replace('__CASE__', $Scenario)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
    $ModuleText = $ModuleText.Replace('function Get-SyntheticCollectorScriptBytes {', 'function Get-ControlledOriginalCollectorScriptBytes {')
    $ModuleText = $ModuleText.Replace('function Get-ApprovedCollectorCatalog {', 'function Get-ControlledOriginalCollectorCatalog {')
    $ModuleText = $ModuleText.Replace('function Get-PrivilegedCollectionWorkerSource {', 'function Get-ControlledOriginalPrivilegeWorkerSource {')
    $ModuleText = $ModuleText.Replace('function Get-PrivilegedCollectionPlanPolicy {', 'function Get-ControlledOriginalPrivilegePolicy {')
    $ModuleText = $ModuleText.Replace('-OperationId $OperationId -DeviceReadinessScenario Complete -CancellationToken $CancellationToken', '-OperationId $OperationId -CancellationToken $CancellationToken')
    if ($Scenario -eq 'Cancelled') {
        $ModuleText=$ModuleText.Replace('Invoke-ControlledApprovedCollectorProcess -OperationId', '$script:StatusDeskTransport.Cancellation.CancelAfter(1500); Invoke-ControlledApprovedCollectorProcess -OperationId')
    }
    $ModuleText + @'

function Get-SyntheticCollectorScriptBytes {
    $prefix = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE__'))
    $original = [Text.Encoding]::UTF8.GetString((Get-ControlledOriginalCollectorScriptBytes))
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($original,[ref]$tokens,[ref]$errors)
    $functions=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Get-BaseDeviceActualPayload','Get-DeviceSourceAccessState')}, $true)
    $actual=$ast.Find({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq "`$Operation -eq 'ContextActual'"}, $true)
    if ($null -eq $actual -or $errors.Count -ne 0) { throw 'Actual device source was not found.' }
    $body=$actual.Clauses[0].Item2.Extent.Text
    [Text.Encoding]::UTF8.GetBytes($prefix + "`n" + ($functions.Extent.Text -join "`n") + "`n" + $body.Substring(1,$body.Length-2))
}
function Get-ApprovedCollectorCatalog {
    param($ConvertFromJsonCommand)
    $result = Get-ControlledOriginalCollectorCatalog -ConvertFromJsonCommand $ConvertFromJsonCommand
    foreach ($collector in $result.Collectors) {
        $collector.payload.sha256 = Get-Sha256ForSupervisorBytes -Bytes (Get-SyntheticCollectorScriptBytes)
    }
    $result
}
function Get-PrivilegedCollectionWorkerSource {
    $source=Get-ControlledOriginalPrivilegeWorkerSource
    # Other families already use controlled adapters in this harness. Remove
    # their unreachable live implementations to leave room for source doubles
    # inside the unchanged Windows command-line ceiling.
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    foreach ($node in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Get-LiveEffectivePolicyResult','Get-LiveAdministratorResult')}, $false)) {
        $source=$source.Replace($node.Extent.Text, '')
    }
    # Substitute the one native firmware API read, and execute the actual
    # firmware source in the already controlled privileged worker protocol.
    $source=$source.Replace('[WinPCInfoPrivilegedWorkerPipe]::ReadFirmwareType()', '([uint32]2)')
    $source=$source.Replace('New-SyntheticFirmwareResult -Scenario ([string]$configuration.firmwareScenario)', 'Get-LiveFirmwareResult')
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE__')) + "`n" + $source
}
function Get-PrivilegedCollectionPlanPolicy {
    $policy=Get-ControlledOriginalPrivilegePolicy
    $source=(Get-PrivilegedCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
'@.Replace('__SOURCE__', $encoded)
}

function Assert-ReadinessSourceReport {
    param($Record, [string] $Html, [string] $Scenario)
    Assert-Equal 'profile:device-firmware-identity-administrator-policy-software-resource-network-certificate-and-microsoft-connectivity-readiness' $Record.run.evidenceProfileId 'source audit uses the Comprehensive profile'
    if ($Scenario -eq 'Denied') {
        foreach ($kind in @('ACTIVATION','CHASSIS','BATTERY')) {
            Assert-Equal 1 @($Record.diagnostics | Where-Object reasonCode -eq "COLLECTION.$($kind)_ACCESS_DENIED").Count 'actual source denial survives the encrypted record'
        }
        Assert-Equal 'Indeterminate' @($Record.findings | Where-Object ruleId -eq 'rule:windows.activation-context/1.0.0')[0].outcome 'denied activation cannot be a negative health claim'
    }
    if ($Scenario -in @('NullLicense','MixedUnknownLicense')) {
        Assert-Equal 'SourceReportedUnknown' @($Record.observations | Where-Object fieldId -eq 'field:device.windows.activation-state')[0].valueState 'null licensing status must not coerce to unactivated'
        Assert-Equal 'Indeterminate' @($Record.findings | Where-Object ruleId -eq 'rule:windows.activation-context/1.0.0')[0].outcome 'unknown licensing cannot create purchasing or activation advice'
    }
    if ($Scenario -eq 'Bounded') {
        Assert-Equal $false $Html.Contains('No source-specific access limitation was recorded.') 'HTML must not deny recorded source constraints'
        foreach ($kind in @('ACTIVATION','CHASSIS','BATTERY')) {
            Assert-Equal 1 @($Record.diagnostics | Where-Object reasonCode -eq "COLLECTION.$($kind)_OUTPUT_LIMIT_EXCEEDED").Count 'over-bound source cardinality must remain explicit'
        }
        Assert-Equal 0 @($Record.observations | Where-Object { $_.fieldId -eq 'field:device.windows.activation-state' -or $_.fieldId -like 'field:device.battery.*' -or $_.fieldId -eq 'field:device.chassis.type-codes' }).Count 'truncated sources cannot pretend to be complete observations'
    }
    if ($Scenario -in @('Unsupported','Malformed')) {
        $reason = if ($Scenario -eq 'Unsupported') {'COLLECTION.CHASSIS_SOURCE_UNSUPPORTED'} else {'COLLECTION.CHASSIS_PAYLOAD_MALFORMED'}
        Assert-Equal 1 @($Record.diagnostics | Where-Object reasonCode -eq $reason).Count 'native source failures retain their distinct reason'
    }
    $firmwareState = switch ($Scenario) { Denied {'Denied'} FirmwareBounded {'Malformed'} default {'Complete'} }
    $tpmState = switch ($Scenario) { Denied {'Denied'} Unsupported {'Unsupported'} Malformed {'Malformed'} default {'Complete'} }
    Assert-Equal $firmwareState @($Record.coverage | Where-Object scopeId -eq 'scope:device.firmware-context')[0].state 'actual firmware source scope reaches package'
    Assert-Equal $tpmState @($Record.coverage | Where-Object scopeId -eq 'scope:device.tpm-readiness')[0].state 'actual TPM source scope reaches package'
    foreach ($pair in @(
        @('scope:device.firmware-context','rule:device.firmware-context/1.0.0'),
        @('scope:device.secure-boot','rule:device.secure-boot-readiness/1.0.0'),
        @('scope:device.tpm-readiness','rule:device.tpm-readiness/1.0.0')
    )) {
        $scope=@($Record.coverage | Where-Object scopeId -eq $pair[0])[0]
        if ($scope.state -ne 'Complete') {
            Assert-Equal 0 @($scope.observationIds).Count 'unexamined firmware fields have no negative observations'
            Assert-Equal $true ([bool]$scope.reasonCode) 'firmware gaps carry stable reasons'
            Assert-Equal 'Indeterminate' @($Record.findings | Where-Object ruleId -eq $pair[1])[0].outcome 'missing firmware cannot establish health'
        }
    }
    if ($Scenario -eq 'Absent') {
        Assert-Equal $false @($Record.observations | Where-Object fieldId -eq 'field:device.tpm.present')[0].value 'empty successful TPM enumeration is observed absence'
        Assert-Equal $false @($Record.observations | Where-Object fieldId -eq 'field:device.battery.presence')[0].value 'empty successful battery enumeration is observed absence'
        foreach ($field in @('field:device.tpm.enabled','field:device.battery.status')) {
            Assert-Equal 'ObservedAbsent' @($Record.observations | Where-Object fieldId -eq $field)[0].valueState 'absent hardware details are distinct from inaccessible data'
        }
    }
    if ($Scenario -in @('TimedOut','MalformedOutput','OversizeOutput','Cancelled')) {
        Assert-Equal $true $Html.Contains('Virtualization could not be determined') 'an unexamined device cannot be reported as having no virtual signal'
        $state=switch ($Scenario) { TimedOut {'TimedOut'} MalformedOutput {'Malformed'} OversizeOutput {'Constrained'} Cancelled {'Cancelled'} }
        Assert-Equal $state @($Record.coverage | Where-Object scopeId -eq 'scope:device.windows-context')[0].state 'failed device attempt preserves earlier collected evidence with an explicit scope gap'
        Assert-Equal 0 @($Record.observations | Where-Object fieldId -in @('field:device.windows.build','field:device.battery.presence')).Count 'failed device attempt invents no negative observations'
        Assert-Equal 'Indeterminate' @($Record.findings | Where-Object ruleId -eq 'rule:device.readiness/1.0.0')[0].outcome 'failed source cannot establish readiness'
    }
    if ($Scenario -in @('Virtual','MicrosoftPhysical')) {
        Assert-Equal ($Scenario -eq 'Virtual') @($Record.observations | Where-Object fieldId -eq 'field:device.virtualization.detected')[0].value 'Microsoft OEM and a running hypervisor do not by themselves prove a VM guest'
        Assert-Equal $(if($Scenario -eq 'Virtual'){'Virtual'}else{'Laptop'}) @($Record.observations | Where-Object fieldId -eq 'field:device.form-factor')[0].value 'form reflects admitted source evidence'
    }
    if ($Scenario -eq 'Complete') {
        $expected = @{
            'device.manufacturer'=@('Fabrikam 日本語','windows.cim.computer-system')
            'device.model'=@('Modèle Δ','windows.cim.computer-system')
            'device.processor.name'=@('Processeur العربية','windows.cim.processor')
            'device.memory.physical-bytes'=@(17179869184L,'windows.cim.computer-system')
            'device.windows.edition'=@('Professional','windows.cim.operating-system')
            'device.windows.build'=@('26100','windows.cim.operating-system')
            'device.architecture'=@('X64','dotnet.runtime-information')
            'device.windows.activation-state'=@('Activated','windows.cim.software-licensing-product')
            'device.system-type-code'=@(2,'windows.cim.computer-system')
            'device.hypervisor-present'=@($false,'windows.cim.computer-system')
            'device.chassis.type-codes'=@('10','windows.cim.system-enclosure')
            'device.battery.presence'=@($true,'windows.cim.battery')
            'device.battery.status'=@('Charging','windows.cim.battery')
            'device.battery.charge-percent'=@(72,'windows.cim.battery')
            'device.battery.estimated-runtime-minutes'=@(180,'windows.cim.battery')
            'device.firmware.type'=@('Uefi','windows.api.get-firmware-type')
            'device.firmware.bios-version'=@('UEFI 合成-Δ','windows.cim.bios')
            'device.firmware.smbios-version'=@('3.7','windows.cim.bios')
            'device.secure-boot.enabled'=@($true,'windows.secure-boot.confirm')
            'device.tpm.present'=@($true,'windows.cim.tpm')
            'device.tpm.enabled'=@($true,'windows.cim.tpm')
            'device.tpm.activated'=@($true,'windows.cim.tpm')
            'device.tpm.specification'=@('2.0, 0, 1.59','windows.cim.tpm')
        }
        foreach ($field in $expected.Keys) {
            $observation=@($Record.observations | Where-Object fieldId -eq "field:$field")
            Assert-Equal 1 $observation.Count 'required source field has exactly one observation'
            Assert-Equal 'ObservedValue' $observation[0].valueState 'required source field is a typed value'
            Assert-Equal $expected[$field][0] $observation[0].value 'source value survives encrypted roundtrip'
            $provenance=@($Record.provenance | Where-Object provenanceId -eq $observation[0].provenanceId)[0]
            Assert-Equal "source:$($expected[$field][1])" $provenance.sourceId 'source identity is stable and traceable'
            Assert-Equal $true ([bool]$provenance.collectedAt) 'source observation retains collection time'
            if ($provenance.collectorId -eq 'collector:windows.device-context') {
                Assert-Equal 'fr-FR' $provenance.sourceLocale 'numeric evidence remains locale neutral under a French source culture'
            }
        }
        foreach ($text in @('Professional','26100','X64','Activated','Charging','72','180','3.7')) {
            Assert-Equal $true $Html.Contains($text) 'required source value appears in the offline HTML'
        }
        foreach ($text in @('Fabrikam 日本語','Modèle Δ','Processeur العربية','UEFI 合成-Δ')) {
            Assert-Equal $true $Html.Contains([Net.WebUtility]::HtmlEncode($text)) 'Unicode source values survive report encoding'
        }
    }
}
