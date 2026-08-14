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
    @{file='registry-views';scenario='RegistryViews';count=4;registry=4;msi=0;msix=0;machine='Complete';user='Complete';machineFinding='NeedsAttention';userFinding='NeedsAttention'},
    @{file='user-and-machine';scenario='UserAndMachine';count=6;registry=2;msi=2;msix=2;machine='Complete';user='Complete';machineFinding='NeedsAttention';userFinding='NeedsAttention'},
    @{file='msi-states';scenario='MsiStates';count=2;registry=0;msi=2;msix=0;machine='Complete';user='Complete';machineFinding='NeedsAttention';userFinding='NeedsAttention'},
    @{file='package-types';scenario='PackageTypes';count=5;registry=0;msi=0;msix=5;machine='Complete';user='Complete';machineFinding='Informational';userFinding='NeedsAttention'},
    @{file='duplicates';scenario='Duplicates';count=3;registry=2;msi=1;msix=0;machine='Complete';user='Complete';machineFinding='NeedsAttention';userFinding='Informational'},
    @{file='arbitrary-versions';scenario='ArbitraryVersions';count=2;registry=2;msi=0;msix=0;machine='Complete';user='Complete';machineFinding='NeedsAttention';userFinding='NeedsAttention'},
    @{file='malformed';scenario='Malformed';count=0;registry=0;msi=0;msix=0;machine='Partial';user='Complete';machineFinding='Indeterminate';userFinding='Informational'},
    @{file='oversize';scenario='Oversize';count=64;registry=64;msi=0;msix=0;machine='Partial';user='Complete';machineFinding='Indeterminate';userFinding='Informational'},
    @{file='aggregate-maximum';scenario='AggregateMaximum';count=128;registry=64;msi=32;msix=32;machine='Complete';user='Complete';machineFinding='NeedsAttention';userFinding='NeedsAttention'},
    @{file='denied-all-users';scenario='DeniedAllUsers';count=0;registry=0;msi=0;msix=0;machine='Denied';user='Complete';machineFinding='Indeterminate';userFinding='Informational'},
    @{file='denied-user';scenario='DeniedUser';count=0;registry=0;msi=0;msix=0;machine='Complete';user='Denied';machineFinding='Informational';userFinding='Indeterminate'},
    @{file='unicode';scenario='Unicode';count=3;registry=1;msi=1;msix=1;machine='Complete';user='Complete';machineFinding='NeedsAttention';userFinding='NeedsAttention'},
    @{file='empty';scenario='Empty';count=0;registry=0;msi=0;msix=0;machine='Complete';user='Complete';machineFinding='Informational';userFinding='Informational'},
    @{file='alternate-administrator';scenario='AlternateAdministrator';count=0;registry=0;msi=0;msix=0;machine='Denied';user='Denied';machineFinding='Indeterminate';userFinding='Indeterminate'},
    @{file='local-system';scenario='LocalSystem';count=0;registry=0;msi=0;msix=0;machine='Denied';user='Denied';machineFinding='Indeterminate';userFinding='Indeterminate'},
    @{file='partial';scenario='Partial';count=1;registry=1;msi=0;msix=0;machine='Partial';user='Complete';machineFinding='Indeterminate';userFinding='Informational'}
)

foreach($case in $cases){
    $fixture=Join-Path $PSScriptRoot "fixtures/software-inventory/$($case.file).json"
    $result=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,'-SoftwareInventoryFixturePath',$fixture
    )
    $validation=@($result.Records|Where-Object recordType -eq 'win-pcinfo.software-inventory-validation')
    $terminal=@($result.Records|Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $validation.Count "$($case.scenario) emits one sanitized projection"
    Assert-Equal 1 $terminal.Count "$($case.scenario) emits one terminal"
    Assert-Equal 10 $result.ExitCode "$($case.scenario) preserves Local Only network gaps"
    Assert-Equal 'CompletedWithGaps' $terminal[0].outcome "$($case.scenario) preserves complete combined-profile coverage"
    Assert-Equal $case.count $validation[0].registrationCount "$($case.scenario) publishes only the bounded registration count"
    Assert-Equal $case.registry $validation[0].registryCount "$($case.scenario) publishes only the registry count"
    Assert-Equal $case.msi $validation[0].msiCount "$($case.scenario) publishes only the MSI count"
    Assert-Equal $case.msix $validation[0].msixCount "$($case.scenario) publishes only the MSIX count"
    Assert-Equal $case.machine $validation[0].machineScopeCoverage "$($case.scenario) preserves machine coverage"
    Assert-Equal $case.user $validation[0].assessmentUserScopeCoverage "$($case.scenario) preserves Assessment User coverage"
    Assert-Equal $case.machineFinding $validation[0].machineFinding "$($case.scenario) derives machine guidance"
    Assert-Equal $case.userFinding $validation[0].assessmentUserFinding "$($case.scenario) derives user guidance"
    foreach($property in @('softwareIdentitiesPublished','displayNamesOrPublishersPublished','pathsOrHashesCollected','licenseMaterialCollected','binaryInspectionPerformed','consistencyActionInvoked','networkAccessPerformed','deviceStateChanged')){Assert-Equal $false $validation[0].$property "$($case.scenario) keeps $property false"}
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) validates the canonical record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.scenario) verifies the beginner report"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) proves fixture artifacts absent"
    if($result.StandardOutput -match '(?i)Same Product|Same Publisher|Publisher [A-D]|"publisher"\s*:\s*"Publisher"|Synthetic\.|00000000-0000|应用程序|パッケージ|reg:m|release-2026'){throw "$($case.scenario) leaked Restricted software evidence into public output."}
    if($result.StandardError){throw "$($case.scenario) wrote stderr: $($result.StandardError)"}
}
Write-Output 'PASS: the generated application proves safe Software Inventory evidence, guidance, privacy, packaging, and cleanup.'
