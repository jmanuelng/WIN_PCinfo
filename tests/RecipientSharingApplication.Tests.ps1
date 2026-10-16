[CmdletBinding()]
param([string] $CandidatePath = '', [string] $PreparedManifestPath = '', [string] $PreparedManifestSha256 = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')
. (Join-Path $repositoryRoot 'src/RecipientSharing.ps1')
. (Join-Path $repositoryRoot 'src/ProtectedPackage.ps1')
Assert-QualificationCleanupReady
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidateUseError=$null
$selectionRoot=$null
$selectionRootOwned=$false
try {
if (-not $candidateContext.Prepared) {
    $PreparedManifestPath=Join-Path $candidateContext.OwnedDirectory 'prepared-test-candidate.json'
    [IO.File]::WriteAllText($PreparedManifestPath,((New-PreparedTestCandidateManifest -RepositoryRoot $repositoryRoot -CandidatePath $candidateContext.Path) | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    $PreparedManifestSha256=(Get-FileHash -LiteralPath $PreparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
# The producer still owns one fixed TEMP validation root. This campaign is
# exclusive; candidate admission and owned fixture paths do not certify partitioning.

$recipientValidationRoot = Join-Path ([IO.Path]::GetTempPath()) 'WIN-PCInfo-recipient-sharing-validation'
if ([System.IO.Directory]::Exists($recipientValidationRoot) -or
    [System.IO.File]::Exists($recipientValidationRoot)) {
    throw 'Recipient Sharing validation found a pre-existing fixed root and refused to remove it.'
}
$selectionRoot = Join-Path $repositoryRoot `
    ".test-output/recipient-application-fixture-$([guid]::NewGuid().ToString('N'))"
# New-Item without Force refuses existing state; ownership starts only on success.
$null = New-Item -ItemType Directory -Path $selectionRoot -ErrorAction Stop
$selectionRootOwned=$true
$untrustedSetupPath = Join-Path $selectionRoot 'untrusted-recipient-profile.json'
$missingPackagePath = Join-Path $selectionRoot 'does-not-exist.winpcinfo'
if ([IO.File]::Exists($untrustedSetupPath) -or [IO.Directory]::Exists($untrustedSetupPath)) {
    throw 'Recipient Sharing setup output already exists and is not owned.'
}
$untrustedSetup = Invoke-GeneratedApplication -CandidatePath $candidateContext.Path -Arguments @(
    '-Workflow', 'RecipientProfileSetup',
    '-RecipientProfileOutputPath', $untrustedSetupPath,
    '-RecipientLabel', 'Synthetic blocked setup', '-ConfirmRecipientSetup'
)
Assert-Equal 20 $untrustedSetup.ExitCode 'an unsigned development artifact cannot create a recipient identity'
Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $untrustedSetup.Records[-1].reasonCode `
    'persistent setup is gated by external artifact trust'
Assert-Equal $false ([System.IO.File]::Exists($untrustedSetupPath)) `
    'the trust failure occurs before profile or certificate creation'
foreach($workflow in @('OpenReport','RestrictedReportExport')) {
    $blocked=Invoke-GeneratedApplication -CandidatePath $candidateContext.Path -Arguments @(
        '-Workflow',$workflow,'-Mode','Gui','-PackageProtectionRoute','Recipient',
        '-ProtectedPackagePath',$missingPackagePath)
    Assert-Equal 20 $blocked.ExitCode "$workflow retains generated-artifact trust admission"
    Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $blocked.Records[-1].reasonCode "$workflow cannot use an unsigned artifact to open private evidence"
}

$selectedProfilePath = Join-Path $selectionRoot 'selected.recipient.json'
$selectedSetup = New-RecipientProfileSetup -Label 'Synthetic generated-app recipient' `
    -OutputPath $selectedProfilePath -ConfirmSetup `
    -SyntheticProtectionLevel WindowsUserBound
$selectedRequest = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json -Depth 10
$selectedRequest | Add-Member -MemberType NoteProperty -Name recipientSelection -Value (
    [pscustomobject][ordered]@{
        mode = 'Profile'; profilePath = $selectedProfilePath
        fingerprintConfirmation = [string] $selectedSetup.fingerprint
    }
)
$selectedRequestPath = Join-Path $selectionRoot 'selected-request.json'
[System.IO.File]::WriteAllText(
    $selectedRequestPath, ($selectedRequest | ConvertTo-Json -Compress -Depth 10),
    [System.Text.UTF8Encoding]::new($false)
)

function Get-RecipientValidationResidue {
    $root = Join-Path ([IO.Path]::GetTempPath()) 'WIN-PCInfo-recipient-sharing-validation'
    if (-not [System.IO.Directory]::Exists($root)) { return @() }
    @([System.IO.Directory]::EnumerateFileSystemEntries($root) | ForEach-Object {
        [System.IO.Path]::GetFileName($_)
    } | Sort-Object)
}

$cases = @(
    'TpmBackedSetup', 'SoftwareFallbackSetup', 'ProfileValidation',
    'WrongFingerprint', 'ExpiredAdmission', 'HistoricalOpening', 'MissingKey',
    'ZeroRecipient', 'OneRecipient', 'InterruptedExport', 'WarningDeclined',
    'RestrictedExport'
)
foreach ($scenario in $cases) {
    $before = @(Get-RecipientValidationResidue)
    $result = Invoke-GeneratedApplication -CandidatePath $candidateContext.Path -Arguments @(
        '-Mode', 'Automation', '-RequestPath', $(if ($scenario -eq 'OneRecipient') {
            $selectedRequestPath
        }
        else { $requestPath }), '-AcceptPreparation',
        '-PreparationFixturePath', $preparationPath,
        '-RecipientSharingFixturePath', (
            Join-Path $PSScriptRoot "fixtures/recipient-$($scenario.ToLowerInvariant()).json"
        )
    )
    $after = @(Get-RecipientValidationResidue)
    $records = @($result.Records | Where-Object `
        recordType -eq 'win-pcinfo.recipient-sharing-validation')
    $summaries = @($result.Records | Where-Object `
        recordType -eq 'win-pcinfo.completion-summary')
    $terminals = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $records.Count "$scenario emits one sanitized sharing result"
    Assert-Equal 1 $summaries.Count "$scenario emits one actual Completion Summary"
    Assert-Equal 1 $terminals.Count "$scenario emits one terminal result"
    Assert-Equal 20 $result.ExitCode "$scenario validates with the stable fixture exit"
    Assert-Equal 'Validated' $records[0].state "$scenario proves its expected safety behavior"
    Assert-Equal $true $records[0].validationCleanupVerified `
        "$scenario removes every synthetic profile, package, export, and key handle"
    Assert-Equal $true $records[0].completionGuidanceVerified `
        "$scenario retains all six Result-sharing Guidance topics"
    $expectedPackageVerified = $scenario -in @(
        'HistoricalOpening', 'MissingKey', 'ZeroRecipient', 'OneRecipient',
        'InterruptedExport', 'WarningDeclined', 'RestrictedExport'
    )
    Assert-Equal $expectedPackageVerified $summaries[0].packageVerified `
        "$scenario guidance reflects whether a package was actually verified"
    Assert-Equal 'VerifiedAbsent' $summaries[0].packageAvailability `
        "$scenario does not claim its removed validation package remains available"
    $expectedRecipientAccess = if ($scenario -in @(
        'HistoricalOpening', 'MissingKey', 'OneRecipient'
    )) {
        'Unavailable'
    }
    else { 'None' }
    Assert-Equal $expectedRecipientAccess $summaries[0].resultSharingGuidance.recipientAccess `
        "$scenario guidance reflects actual recipient access"
    Assert-Equal $false $summaries[0].resultSharingGuidance.privateTransfer.allowed `
        "$scenario does not permit transfer after validation cleanup"
    Assert-Equal 'None' $summaries[0].resultSharingGuidance.deletionResponsibility `
        "$scenario assigns no deletion duty for artifacts already removed"
    Assert-Equal ($scenario -eq 'RestrictedExport') `
        $summaries[0].resultSharingGuidance.restrictedExport.completed `
        "$scenario guidance reflects actual restricted export completion"
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
}
catch { $candidateUseError=$_ }
finally {
    # Close candidate ownership first. A close failure is unsafe and retains the
    # fixture evidence rather than deleting it before the candidate finalizer.
    try { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
    catch { $candidateUseError=$_ }
    Complete-QualificationHarness -BodyError $candidateUseError -Cleanup @({
        if ($selectionRootOwned -and -not ($null -ne $candidateUseError -and (Test-QualificationCleanupUnverified -Exception $candidateUseError.Exception))) {
            $resolved=[IO.Path]::GetFullPath($selectionRoot)
            $parent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))
            if (-not [IO.Path]::GetDirectoryName($resolved).Equals($parent,[StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($resolved) -cnotmatch '^recipient-application-fixture-[a-f0-9]{32}$') {
                throw 'Recipient Sharing fixture cleanup escaped its owned parent.'
            }
            if ([IO.Directory]::Exists($resolved)) {
                if (([IO.File]::GetAttributes($resolved) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Recipient Sharing fixture cleanup is redirected.'
                }
                [IO.Directory]::Delete($resolved,$true)
            }
            if ([IO.Directory]::Exists($resolved)) { throw 'Recipient Sharing owned fixture cleanup remains incomplete.' }
        }
    })
}
Write-Output 'PASS: the generated application validates all recipient and export scenarios without residue.'
