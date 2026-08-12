[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidatePath=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath=Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath|Out-Null
$cases=@(
    @{scenario='MappedDrive';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=1;unc=0;printers=0;drivers=0;devices=0;userFinding='NeedsAttention';peripheralFinding='Informational'},
    @{scenario='DisconnectedDrive';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=1;unc=0;printers=0;drivers=0;devices=0;userFinding='NeedsAttention';peripheralFinding='Informational'},
    @{scenario='UncResource';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=0;unc=1;printers=0;drivers=0;devices=0;userFinding='NeedsAttention';peripheralFinding='Informational'},
    @{scenario='Printers';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=0;unc=0;printers=2;drivers=2;devices=0;userFinding='NeedsAttention';peripheralFinding='NeedsAttention'},
    @{scenario='PortsAndDrivers';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=0;unc=0;printers=1;drivers=1;devices=0;userFinding='NeedsAttention';peripheralFinding='NeedsAttention'},
    @{scenario='Peripherals';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=0;unc=0;printers=0;drivers=0;devices=3;userFinding='Informational';peripheralFinding='NeedsAttention'},
    @{scenario='Empty';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=0;unc=0;printers=0;drivers=0;devices=0;userFinding='Informational';peripheralFinding='Informational'},
    @{scenario='Denied';exit=10;outcome='CompletedWithGaps';user='Denied';peripheral='Denied';mapped=0;unc=0;printers=0;drivers=0;devices=0;userFinding='Indeterminate';peripheralFinding='Indeterminate'},
    @{scenario='Partial';exit=10;outcome='CompletedWithGaps';user='Partial';peripheral='Partial';mapped=8;unc=8;printers=8;drivers=8;devices=8;userFinding='Indeterminate';peripheralFinding='Indeterminate'},
    @{scenario='Duplicates';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=1;unc=1;printers=1;drivers=1;devices=1;userFinding='NeedsAttention';peripheralFinding='NeedsAttention'},
    @{scenario='LongUnicode';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=1;unc=0;printers=1;drivers=1;devices=1;userFinding='NeedsAttention';peripheralFinding='NeedsAttention'},
    @{scenario='AlternateAdministrator';exit=10;outcome='CompletedWithGaps';user='Denied';peripheral='Denied';mapped=0;unc=0;printers=0;drivers=0;devices=0;userFinding='Indeterminate';peripheralFinding='Indeterminate'},
    @{scenario='LocalSystem';exit=10;outcome='CompletedWithGaps';user='Denied';peripheral='Denied';mapped=0;unc=0;printers=0;drivers=0;devices=0;userFinding='Indeterminate';peripheralFinding='Indeterminate'},
    @{scenario='NonEnglish';exit=0;outcome='Completed';user='Complete';peripheral='Complete';mapped=1;unc=0;printers=1;drivers=1;devices=1;userFinding='NeedsAttention';peripheralFinding='NeedsAttention'}
)
foreach($case in $cases){
    $fixture=Join-Path $PSScriptRoot "fixtures/resource-$($case.scenario.ToLowerInvariant()).json"
    $result=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,'-ResourceDependenciesFixturePath',$fixture
    )
    $validation=@($result.Records|Where-Object recordType -eq 'win-pcinfo.resource-dependencies-validation')
    $terminal=@($result.Records|Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $validation.Count "$($case.scenario) emits one sanitized projection"
    Assert-Equal 1 $terminal.Count "$($case.scenario) emits one terminal"
    Assert-Equal $case.exit $result.ExitCode "$($case.scenario) uses the stable exit code"
    Assert-Equal $case.outcome $terminal[0].outcome "$($case.scenario) preserves incomplete coverage"
    Assert-Equal $case.user $validation[0].userResourceCoverage "$($case.scenario) preserves user-resource coverage"
    Assert-Equal $case.peripheral $validation[0].peripheralCoverage "$($case.scenario) preserves peripheral coverage"
    Assert-Equal $case.mapped $validation[0].mappedDriveCount "$($case.scenario) publishes a safe mapped-drive count"
    Assert-Equal $case.unc $validation[0].uncConnectionCount "$($case.scenario) publishes a safe UNC count"
    Assert-Equal $case.printers $validation[0].printerCount "$($case.scenario) publishes a safe printer count"
    Assert-Equal $case.drivers $validation[0].printerDriverCount "$($case.scenario) publishes a safe driver count"
    Assert-Equal $case.devices $validation[0].peripheralCount "$($case.scenario) publishes a safe peripheral count"
    Assert-Equal $case.userFinding $validation[0].userResourceFinding "$($case.scenario) derives advisory user dependencies"
    Assert-Equal $case.peripheralFinding $validation[0].peripheralFinding "$($case.scenario) derives advisory peripheral dependencies"
    Assert-Equal $false $validation[0].resourceIdentifiersPublished "$($case.scenario) keeps exact values Restricted"
    Assert-Equal $false $validation[0].deviceIdentifiersCollected "$($case.scenario) excludes device IDs and serials"
    Assert-Equal $false $validation[0].shareContentsEnumerated "$($case.scenario) never enumerates share contents"
    Assert-Equal $false $validation[0].printJobsEnumerated "$($case.scenario) never enumerates print jobs"
    Assert-Equal $false $validation[0].storedCredentialsCollected "$($case.scenario) never collects stored credentials"
    Assert-Equal $false $validation[0].wifiKeysCollected "$($case.scenario) never collects Wi-Fi keys"
    Assert-Equal $false $validation[0].deviceStateChanged "$($case.scenario) performs no device change"
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) validates the canonical record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.scenario) verifies the beginner report"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) proves fixture artifacts absent"
    if($result.StandardOutput -match '(?i)synthetic-file|imprimante|périphérique|SYNTHETIC-PORT|USB\\VID_|S-1-5-21'){
        throw "$($case.scenario) leaked Restricted resource evidence into public output."
    }
    if($result.StandardError){throw "$($case.scenario) wrote stderr: $($result.StandardError)"}
}
$invalid=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
    '-PreparationFixturePath',$preparationPath,'-ResourceDependenciesFixturePath',(
        Join-Path $PSScriptRoot 'fixtures/resource-does-not-exist.json'
    )
)
Assert-Equal 1 @($invalid.Records|Where-Object recordType -eq 'win-pcinfo.terminal').Count 'an invalid resource fixture retains one stable terminal path'
Assert-Equal 0 @($invalid.Records|Where-Object recordType -eq 'win-pcinfo.resource-dependencies-validation').Count 'an invalid fixture cannot fabricate a resource projection'
if($invalid.StandardError){throw "Invalid fixture wrote stderr: $($invalid.StandardError)"}
Write-Output 'PASS: the generated application exercises Resource Dependency evidence, guidance, privacy, packaging, and cleanup.'
