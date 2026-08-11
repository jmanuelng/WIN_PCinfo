[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidatePath=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath=Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

function Get-PackageValidationResidue {
    $root=Join-Path (Split-Path -Parent $candidatePath) '.protected-package-validation'
    if(-not[IO.Directory]::Exists($root)){return @()}
    @([IO.Directory]::EnumerateFileSystemEntries($root)|ForEach-Object{[IO.Path]::GetFileName($_)}|Sort-Object)
}
function Invoke-PackageFixture([string]$Name){
    Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,
        '-ProtectedPackageFixturePath',(Join-Path $PSScriptRoot "fixtures/$Name.json")
    )
}
$cases=@(
    @{Name='package-known-answer';Scenario='KnownAnswer';State='Validated';Exit=20;Final=$false},
    @{Name='package-maximum-size';Scenario='MaximumSize';State='Validated';Exit=20;Final=$true},
    @{Name='package-corruption';Scenario='Corruption';State='IntegrityFailed';Exit=50;Final=$false},
    @{Name='package-wrong-user';Scenario='WrongUser';State='IntegrityFailed';Exit=50;Final=$false},
    @{Name='package-wrong-device';Scenario='WrongDevice';State='IntegrityFailed';Exit=50;Final=$false},
    @{Name='package-interrupted-write';Scenario='InterruptedWrite';State='IntegrityFailed';Exit=50;Final=$false},
    @{Name='package-disk-exhaustion';Scenario='DiskExhaustion';State='IntegrityFailed';Exit=50;Final=$false},
    @{Name='package-malformed-archive';Scenario='MalformedArchive';State='IntegrityFailed';Exit=50;Final=$false},
    @{Name='package-invalid-manifest';Scenario='InvalidManifest';State='IntegrityFailed';Exit=50;Final=$false},
    @{Name='package-viewing-cleanup';Scenario='ViewingCleanup';State='Validated';Exit=20;Final=$true}
)
foreach($case in $cases){
    $before=@(Get-PackageValidationResidue)
    $result=Invoke-PackageFixture $case.Name
    $after=@(Get-PackageValidationResidue)
    $records=@($result.Records|Where-Object recordType -eq 'win-pcinfo.protected-package-validation')
    $terminals=@($result.Records|Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $records.Count "$($case.Scenario) emits one package result"
    Assert-Equal 1 $terminals.Count "$($case.Scenario) emits one terminal result"
    $record=$records[0];$terminal=$terminals[0]
    Assert-Equal $case.Scenario $record.scenario 'the closed scenario identity is preserved'
    Assert-Equal $case.State $record.state "$($case.Scenario) reports the expected protection state"
    Assert-Equal $case.Exit $result.ExitCode "$($case.Scenario) returns its matching stable exit code"
    Assert-Equal $(if($case.Exit-eq50){'IntegrityFailed'}else{'NotStarted'}) $terminal.outcome `
        "$($case.Scenario) reaches one matching terminal outcome"
    Assert-Equal $case.Final $record.packageFinalized 'only fully reopened ciphertext is reported as finalized'
    Assert-Equal $false $record.contentExposed 'no validation result exposes package plaintext'
    Assert-Equal $true $record.cryptography.fullTag 'every fixture retains the full GCM tag contract'
    Assert-Equal $true $record.validationCleanupVerified 'the harness removes every owned package and view'
    Assert-Equal ($before-join'|') ($after-join'|') 'the generated application leaves no validation residue'
    Assert-Equal $true $terminal.validationFixture 'package validation never creates a capability claim'
    if(($record|ConvertTo-Json -Compress -Depth 10)-match
        '(?i)packagePath|artifactPath|journalPath|workspacePath|protectedContentKey|noncePrefix|subject:|synthetic package report'){
        throw "$($case.Scenario) exposed restricted content, identity, key material, or paths."
    }
    if($result.StandardError){throw "$($case.Scenario) wrote stderr: $($result.StandardError)"}
}
Write-Output 'PASS: the generated application exposes all ten Protected Package scenarios without residue.'
