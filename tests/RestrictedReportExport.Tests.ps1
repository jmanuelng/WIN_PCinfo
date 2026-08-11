[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')
. (Join-Path $repositoryRoot 'src/RecipientSharing.ps1')
. (Join-Path $repositoryRoot 'src/ProtectedPackage.ps1')

$testRoot = Join-Path $repositoryRoot ".test-output/restricted-export-$([guid]::NewGuid().ToString('N'))"
$null = [System.IO.Directory]::CreateDirectory($testRoot)
$recordBytes = $null
$reportBytes = $null
try {
    [byte[]] $recordBytes = [System.IO.File]::ReadAllBytes(
        (Join-Path $PSScriptRoot 'fixtures/contract-positive.json')
    )
    [byte[]] $reportBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        '<!doctype html><html><body><h1>Synthetic assessment</h1></body></html>'
    )
    $package = New-ProtectedEvidencePackage -DestinationDirectory $testRoot `
        -Artifacts ([ordered]@{
            'assessment-record.json' = $recordBytes
            'assessment-report.html' = $reportBytes
        }) -AssessmentContractSetVersion '1.0.0' -Completeness Complete
    Assert-Equal $true $package.verified 'the export source is a fully verified package'

    $declinedPath = Join-Path $testRoot 'declined.html'
    $declined = Export-RestrictedAssessmentReport -PackagePath $package.packagePath `
        -OutputPath $declinedPath -WarningAcknowledgment 'DECLINE'
    Assert-Equal 'NotStarted' $declined.state 'unacknowledged export performs no write'
    Assert-Equal 'EXPORT.WARNING_NOT_ACKNOWLEDGED' $declined.reasonCode `
        'warning refusal has a stable operator-facing reason'
    Assert-Equal $false ([System.IO.File]::Exists($declinedPath)) `
        'warning refusal leaves no plaintext report'

    $interruptedPath = Join-Path $testRoot 'interrupted.html'
    $interrupted = Export-RestrictedAssessmentReport -PackagePath $package.packagePath `
        -OutputPath $interruptedPath `
        -WarningAcknowledgment 'I UNDERSTAND THIS IS RESTRICTED DIAGNOSTIC EVIDENCE' `
        -SyntheticInterruption AfterWrite
    Assert-Equal 'IntegrityFailed' $interrupted.state 'an interrupted export is not reported complete'
    Assert-Equal $true $interrupted.cleanupVerified `
        'interrupted plaintext is removed and verified absent'
    Assert-Equal $false ([System.IO.File]::Exists($interruptedPath)) `
        'interrupted export leaves no final plaintext'
    Assert-Equal 0 @([System.IO.Directory]::EnumerateFiles($testRoot, '*.partial')).Count `
        'interrupted export leaves no provisional plaintext'

    $exportPath = Join-Path $testRoot 'restricted-report.html'
    $exported = Export-RestrictedAssessmentReport -PackagePath $package.packagePath `
        -OutputPath $exportPath `
        -WarningAcknowledgment 'I UNDERSTAND THIS IS RESTRICTED DIAGNOSTIC EVIDENCE'
    Assert-Equal 'Exported' $exported.state 'acknowledged export creates the requested report'
    Assert-Equal $true $exported.restrictedDiagnosticEvidence `
        'the completed export remains Restricted Diagnostic Evidence'
    Assert-Equal $false $exported.publiclyShareable `
        'the export never becomes publicly shareable'
    $html = [System.IO.File]::ReadAllText($exportPath, [System.Text.UTF8Encoding]::new($false, $true))
    if ($html -notmatch 'RESTRICTED DIAGNOSTIC EVIDENCE.*NOT PUBLICLY SHAREABLE') {
        throw 'The exported HTML does not carry the permanent prominent Restricted banner.'
    }
    if ($html -match 'win-pcinfo.assessment-record') {
        throw 'Restricted Report Export leaked the machine-readable Assessment Record.'
    }

    $summary = New-CompletionSummary -PackageVerified $true -RecipientSelected $true `
        -RecipientProtectionLevel WindowsUserBound -RestrictedReportExported $true
    Assert-Equal 'win-pcinfo.completion-summary' $summary.recordType `
        'completion emits the stable summary contract'
    Assert-Equal 'InitiatingWindowsUserAndDevice' $summary.resultSharingGuidance.localAccess `
        'the summary explains actual local DPAPI access'
    Assert-Equal 'ApprovedPackageRecipient' $summary.resultSharingGuidance.recipientAccess `
        'the summary explains actual recipient access'
    Assert-Equal $true $summary.resultSharingGuidance.privateTransfer.keepRecoveryMaterialSeparate `
        'safe private transfer keeps recovery material separate'
    Assert-Equal 'RestrictedDiagnosticEvidence' $summary.resultSharingGuidance.restrictedExport.classification `
        'the summary preserves the export classification'
    Assert-Equal 'OperatorAndAuthorizedRecipient' `
        $summary.resultSharingGuidance.deletionResponsibility `
        'the summary assigns deletion responsibility'
    Assert-Equal $true $summary.resultSharingGuidance.prohibitedPublicSharing `
        'the summary prohibits public issue, Discussion, and repository sharing'
}
finally {
    if ($null -ne $recordBytes) {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($recordBytes)
    }
    if ($null -ne $reportBytes) {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($reportBytes)
    }
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Assert-Equal $false ([System.IO.Directory]::Exists($testRoot)) `
    'restricted export tests remove the package and every plaintext artifact'
Write-Output 'PASS: warned report export and Result-sharing Guidance preserve restricted handling.'
