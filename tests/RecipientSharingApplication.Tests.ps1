[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$recipientValidationRoot = Join-Path (Split-Path -Parent $candidatePath) `
    '.recipient-sharing-validation'
if ([System.IO.Directory]::Exists($recipientValidationRoot)) {
    $preexistingResidue = @([System.IO.Directory]::EnumerateFileSystemEntries(
        $recipientValidationRoot
    ))
    if ($preexistingResidue.Count -gt 0) {
        throw 'Recipient Sharing validation found pre-existing residue and refused to delete it.'
    }
    [System.IO.Directory]::Delete($recipientValidationRoot)
}

$untrustedSetupPath = Join-Path $repositoryRoot '.test-output/untrusted-recipient-profile.json'
if ([System.IO.File]::Exists($untrustedSetupPath)) {
    [System.IO.File]::Delete($untrustedSetupPath)
}
$untrustedSetup = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Workflow', 'RecipientProfileSetup',
    '-RecipientProfileOutputPath', $untrustedSetupPath,
    '-RecipientLabel', 'Synthetic blocked setup', '-ConfirmRecipientSetup'
)
Assert-Equal 20 $untrustedSetup.ExitCode 'an unsigned development artifact cannot create a recipient identity'
Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $untrustedSetup.Records[-1].reasonCode `
    'persistent setup is gated by external artifact trust'
Assert-Equal $false ([System.IO.File]::Exists($untrustedSetupPath)) `
    'the trust failure occurs before profile or certificate creation'

function Get-RecipientValidationResidue {
    $root = Join-Path (Split-Path -Parent $candidatePath) '.recipient-sharing-validation'
    if (-not [System.IO.Directory]::Exists($root)) { return @() }
    @([System.IO.Directory]::EnumerateFileSystemEntries($root) | ForEach-Object {
        [System.IO.Path]::GetFileName($_)
    } | Sort-Object)
}

$cases = @(
    'TpmBackedSetup', 'SoftwareFallbackSetup', 'ProfileValidation',
    'WrongFingerprint', 'ExpiredAdmission', 'HistoricalOpening', 'MissingKey',
    'ZeroRecipient', 'OneRecipient', 'InterruptedExport', 'WarningDeclined'
)
foreach ($scenario in $cases) {
    $before = @(Get-RecipientValidationResidue)
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation', '-RequestPath', $requestPath, '-AcceptPreparation',
        '-PreparationFixturePath', $preparationPath,
        '-RecipientSharingFixturePath', (
            Join-Path $PSScriptRoot "fixtures/recipient-$($scenario.ToLowerInvariant()).json"
        )
    )
    $after = @(Get-RecipientValidationResidue)
    $records = @($result.Records | Where-Object `
        recordType -eq 'win-pcinfo.recipient-sharing-validation')
    $terminals = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $records.Count "$scenario emits one sanitized sharing result"
    Assert-Equal 1 $terminals.Count "$scenario emits one terminal result"
    Assert-Equal 20 $result.ExitCode "$scenario validates with the stable fixture exit"
    Assert-Equal 'Validated' $records[0].state "$scenario proves its expected safety behavior"
    Assert-Equal $true $records[0].validationCleanupVerified `
        "$scenario removes every synthetic profile, package, export, and key handle"
    Assert-Equal $true $records[0].completionGuidanceVerified `
        "$scenario retains all six Result-sharing Guidance topics"
    Assert-Equal $true $terminals[0].validationFixture `
        "$scenario cannot create a Product Capability claim"
    Assert-Equal ($before -join '|') ($after -join '|') `
        "$scenario leaves no generated-application validation residue"
    $serialized = $records[0] | ConvertTo-Json -Compress -Depth 10
    if ($serialized -match '(?i)"(?:profilePath|packagePath|reportPath|fingerprint|certificate|privateKey|pfx|password|credential|subject|issuer)"\s*:') {
        throw "$scenario exposed private paths, recipient identity, or key material."
    }
    if ($result.StandardError) { throw "$scenario wrote stderr: $($result.StandardError)" }
}

Assert-Equal $false ([System.IO.Directory]::Exists($recipientValidationRoot)) `
    'the generated application removes its validation root after the final case'
Write-Output 'PASS: the generated application validates all eleven recipient and export scenarios without residue.'
