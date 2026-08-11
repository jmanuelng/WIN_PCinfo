[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')
. (Join-Path $repositoryRoot 'src/RecipientSharing.ps1')
. (Join-Path $repositoryRoot 'src/ProtectedPackage.ps1')
. (Join-Path $repositoryRoot 'src/Preparation.ps1')

$testRoot = Join-Path $repositoryRoot ".test-output/recipient-selection-$([guid]::NewGuid().ToString('N'))"
$null = [System.IO.Directory]::CreateDirectory($testRoot)
try {
    $profilePath = Join-Path $testRoot 'recipient.json'
    $setup = New-RecipientProfileSetup -Label 'Synthetic approved consultant' `
        -OutputPath $profilePath -ConfirmSetup -SyntheticProtectionLevel WindowsUserBound
    $profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json -Depth 10
    $request = [ordered]@{
        contractVersion = '1.0.0'
        profile = 'ComprehensiveLocalAssessment'
        outputDestination = './WIN-PCInfo-Results'
        networkBehavior = 'LocalOnly'
        updateChoice = 'NoUpdateCheck'
        diagnosticLevel = 'Standard'
        recipientSelection = [ordered]@{
            mode = 'Profile'
            profilePath = $profilePath
            fingerprintConfirmation = [string] $profile.fingerprint
        }
        automationChoices = [ordered]@{
            allowAssessmentNetwork = $false
            allowElevation = $true
            allowInstallation = $false
            allowPersistentChanges = $false
            allowStaleRecovery = $false
            verificationOverride = 'None'
        }
    }
    $requestPath = Join-Path $testRoot 'request.json'
    [System.IO.File]::WriteAllText($requestPath, ($request | ConvertTo-Json -Compress -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $frozenSelection = Resolve-PreparationRecipientSelection -Request (
        [pscustomobject] $request
    )
    Assert-Equal 'ApprovedRecipientForPackage' `
        $frozenSelection.approvedRecipient.admissionKind `
        'preparation carries the exact approved public certificate into packaging'
    [byte[]] $recordBytes = [System.IO.File]::ReadAllBytes(
        (Join-Path $PSScriptRoot 'fixtures/contract-positive.json')
    )
    [byte[]] $reportBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        '<!doctype html><title>Frozen recipient binding</title>'
    )
    try {
        $boundPackage = New-ProtectedEvidencePackage -DestinationDirectory $testRoot `
            -Artifacts ([ordered]@{
                'assessment-record.json' = $recordBytes
                'assessment-report.html' = $reportBytes
            }) -AssessmentContractSetVersion 1.0.0 -Completeness Complete `
            -ApprovedRecipient $frozenSelection.approvedRecipient
        Assert-Equal $true $boundPackage.verified `
            'packaging accepts the certificate frozen by preparation admission'
        Assert-Equal 'RSA-OAEP-SHA-256' `
            (Get-ProtectedPackageEnvelopeHeader $boundPackage.packagePath).recipientKeyProtection `
            'the frozen recipient drives the package key wrap'
    }
    finally {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($recordBytes)
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($reportBytes)
    }
    & (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation', '-RequestPath', $requestPath,
        '-PreparationFixturePath', $preparationPath
    )
    $summary = @($result.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary')[0]
    Assert-Equal 'Profile' $summary.plan.output.recipientProfile.mode `
        'the operator fixes one Recipient Profile before collection'
    Assert-Equal 'Synthetic approved consultant' $summary.plan.output.recipientProfile.label `
        'the summary identifies the operator-chosen profile label'
    Assert-Equal $profile.fingerprint $summary.plan.output.recipientProfile.fingerprint `
        'the summary displays the independently confirmed fingerprint'
    Assert-Equal 'WindowsUserBound' $summary.plan.output.recipientProfile.protectionLevel `
        'the summary clearly labels the software protection fallback'
    Assert-Equal $true $summary.plan.output.recipientProfile.profileValidated `
        'the profile is cryptographically and structurally validated before approval'
    Assert-Equal $true $summary.plan.output.recipientProfile.fingerprintConfirmed `
        'the out-of-band confirmation is frozen into the approved plan'
    Assert-Equal $true $summary.readyForApproval 'one valid profile satisfies the recipient prerequisite'
    if ($result.StandardOutput -match [regex]::Escape($profilePath)) {
        throw 'The private local Recipient Profile path leaked into the Preparation Summary.'
    }

    $guided = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Guided', '-PreparationFixturePath', $preparationPath,
        '-AssessmentRecipientProfilePath', $profilePath,
        '-AssessmentRecipientFingerprintConfirmation', [string] $profile.fingerprint
    ) -StandardInput "DECLINE`n"
    $guidedSummary = @($guided.Records | Where-Object `
        recordType -eq 'win-pcinfo.preparation-summary')[0]
    Assert-Equal 'Profile' $guidedSummary.plan.output.recipientProfile.mode `
        'Guided mode offers the same one-recipient choice before collection'
    Assert-Equal $profile.fingerprint $guidedSummary.plan.output.recipientProfile.fingerprint `
        'Guided mode freezes the independently confirmed fingerprint'

    $request.recipientSelection.fingerprintConfirmation = '0' * 64
    [System.IO.File]::WriteAllText($requestPath, ($request | ConvertTo-Json -Compress -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $wrong = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation', '-RequestPath', $requestPath,
        '-PreparationFixturePath', $preparationPath, '-AcceptPreparation'
    )
    Assert-Equal 'PREPARATION.PREREQUISITE_UNRESOLVED' $wrong.Records[-1].reasonCode `
        'a wrong recipient fingerprint blocks before collection'
    Assert-Equal $false $wrong.Records[-1].collectionStarted `
        'recipient mismatch cannot be overridden by preparation approval'
}
finally {
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Assert-Equal $false ([System.IO.Directory]::Exists($testRoot)) `
    'recipient selection validation removes every synthetic profile and request'
Write-Output 'PASS: zero or one fingerprint-confirmed recipient is frozen before collection.'
