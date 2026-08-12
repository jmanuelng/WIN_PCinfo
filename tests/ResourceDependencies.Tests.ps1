[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ResourceDependencies.ps1')
$json=Get-Command ConvertFrom-Json -CommandType Cmdlet
$policy=Get-ResourceDependenciesPolicy -ConvertFromJsonCommand $json

$expectations=@(
    @{scenario='MappedDrive';mapped=1;unc=0;printers=0;peripherals=0;user='Complete';peripheral='Complete'},
    @{scenario='DisconnectedDrive';mapped=1;unc=0;printers=0;peripherals=0;user='Complete';peripheral='Complete'},
    @{scenario='UncResource';mapped=0;unc=1;printers=0;peripherals=0;user='Complete';peripheral='Complete'},
    @{scenario='Printers';mapped=0;unc=0;printers=2;peripherals=0;user='Complete';peripheral='Complete'},
    @{scenario='PortsAndDrivers';mapped=0;unc=0;printers=1;peripherals=0;user='Complete';peripheral='Complete'},
    @{scenario='Peripherals';mapped=0;unc=0;printers=0;peripherals=3;user='Complete';peripheral='Complete'},
    @{scenario='Empty';mapped=0;unc=0;printers=0;peripherals=0;user='Complete';peripheral='Complete'},
    @{scenario='Denied';mapped=0;unc=0;printers=0;peripherals=0;user='Denied';peripheral='Denied'},
    @{scenario='Partial';mapped=8;unc=8;printers=8;peripherals=8;user='Partial';peripheral='Partial'},
    @{scenario='Duplicates';mapped=1;unc=1;printers=1;peripherals=1;user='Complete';peripheral='Complete'},
    @{scenario='LongUnicode';mapped=1;unc=0;printers=1;peripherals=1;user='Complete';peripheral='Complete'},
    @{scenario='AlternateAdministrator';mapped=0;unc=0;printers=0;peripherals=0;user='Denied';peripheral='Denied'},
    @{scenario='LocalSystem';mapped=0;unc=0;printers=0;peripherals=0;user='Denied';peripheral='Denied'},
    @{scenario='NonEnglish';mapped=1;unc=0;printers=1;peripherals=1;user='Complete';peripheral='Complete'}
)
foreach($case in $expectations){
    $result=Invoke-ResourceDependenciesCollection -Policy $policy -ValidationScenario $case.scenario
    Assert-Equal 'Completed' $result.state "$($case.scenario) returns one closed collector result"
    Assert-Equal $true (Test-ResourceDependenciesCollectorPayload -Payload $result.payload -Policy $policy) "$($case.scenario) satisfies the payload contract"
    Assert-Equal $case.mapped @($result.payload.mappedDrives).Count "$($case.scenario) has bounded mapped drives"
    Assert-Equal $case.unc @($result.payload.uncConnections).Count "$($case.scenario) has bounded UNC connections"
    Assert-Equal $case.printers @($result.payload.printers).Count "$($case.scenario) has bounded printers"
    Assert-Equal $case.peripherals @($result.payload.peripherals).Count "$($case.scenario) has bounded peripherals"
    $userStates=@($result.payload.scopeStates|Where-Object {$_.scopeId -in @($policy.layers[0].scopeIds)}|ForEach-Object state|Sort-Object -Unique)
    $peripheralStates=@($result.payload.scopeStates|Where-Object {$_.scopeId -in @($policy.layers[1].scopeIds)}|ForEach-Object state|Sort-Object -Unique)
    Assert-Equal $case.user ($userStates -join ',') "$($case.scenario) keeps user-resource coverage honest"
    Assert-Equal $case.peripheral ($peripheralStates -join ',') "$($case.scenario) keeps peripheral coverage honest"
}

$alternate=Invoke-ResourceDependenciesCollection -Policy $policy -ValidationScenario AlternateAdministrator
Assert-Equal 'AlternateAdministrator' $alternate.payload.processRelationship 'an alternate administrator is not the Assessment User'
Assert-Equal 0 @($alternate.payload.mappedDrives).Count 'alternate context cannot substitute mapped-resource evidence'
$system=Invoke-ResourceDependenciesCollection -Policy $policy -ValidationScenario LocalSystem
Assert-Equal 'ProhibitedSystemContext' $system.payload.processRelationship 'SYSTEM cannot substitute Assessment User Context'

$bad=Invoke-ResourceDependenciesCollection -Policy $policy -ValidationScenario MappedDrive
$bad.payload.mappedDrives[0]|Add-Member -NotePropertyName credential -NotePropertyValue 'synthetic-secret'
Assert-Equal $false (Test-ResourceDependenciesCollectorPayload -Payload $bad.payload -Policy $policy) 'an undeclared credential channel is rejected'
$bad=Invoke-ResourceDependenciesCollection -Policy $policy -ValidationScenario Peripherals
$bad.payload.peripherals[0]|Add-Member -NotePropertyName pnpDeviceId -NotePropertyValue 'USB\VID_SYNTHETIC\SERIAL'
Assert-Equal $false (Test-ResourceDependenciesCollectorPayload -Payload $bad.payload -Policy $policy) 'device IDs and embedded serials are rejected'
$bad=Invoke-ResourceDependenciesCollection -Policy $policy -ValidationScenario MappedDrive
$bad.payload.mappedDrives[0].remoteEndpoint='x'*513
Assert-Equal $false (Test-ResourceDependenciesCollectorPayload -Payload $bad.payload -Policy $policy) 'oversized exact resource values fail closed'

$projection=New-ResourceDependenciesPublicProjection -CollectorResult (
    Invoke-ResourceDependenciesCollection -Policy $policy -ValidationScenario NonEnglish
) -Policy $policy
Assert-Equal 'win-pcinfo.resource-dependencies-validation' $projection.recordType 'public evidence is an explicit sanitized projection'
Assert-Equal 1 $projection.mappedDriveCount 'public evidence exposes only a bounded count'
Assert-Equal $false $projection.resourceIdentifiersPublished 'exact resource identities remain Restricted'
Assert-Equal $false $projection.deviceIdentifiersCollected 'device identifiers and serials are never collected'
if(($projection|ConvertTo-Json -Depth 10 -Compress) -match '(?i)\\\\|imprimante|périphérique|USB\\|synthetic'){
    throw 'Restricted resource or peripheral evidence entered the public projection.'
}

Write-Output 'PASS: Resource Dependency fixtures preserve context, coverage, bounds, and privacy.'
