[CmdletBinding()]
param([switch]$ViewChild, [string]$ChildPackagePath, [string]$ChildRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
if(-not $ViewChild){& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null}
$regions = [regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
if($ViewChild){
    $interrupted=Open-EvidenceViewingSession -PackagePath $ChildPackagePath -RequestedArtifact assessment-report.html -ViewingBasePath $ChildRoot
    if(-not $interrupted.verified){throw 'Child view did not open.'}
    [IO.File]::WriteAllText((Join-Path $ChildRoot 'view-ready.json'),($interrupted | ConvertTo-Json -Depth 10))
    [Threading.Thread]::Sleep(60000)
    throw 'The interruption controller did not stop the child.'
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('winpcinfo-recipient-view-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$recipient = $null
$approved = $null
try {
    $recipient = New-SyntheticRecipientCertificate -KeyBits 3072 -Validity NotCurrentlyValid
    $setup = New-RecipientProfileSetup -Label 'Synthetic historical recipient' -OutputPath (Join-Path $root 'recipient.json') `
        -ConfirmSetup -SyntheticProtectionLevel WindowsUserBound -SyntheticCreatedCertificate $recipient
    $expired = Import-RecipientProfile -LiteralPath $setup.profilePath -ExpectedFingerprint $setup.fingerprint -ForNewPackage
    Assert-Equal 'RECIPIENT.CERTIFICATE_NOT_CURRENT' $expired.reasonCode 'expired profiles cannot admit a new assessment'
    $approved = Import-RecipientProfile -LiteralPath $setup.profilePath -ExpectedFingerprint $setup.fingerprint
    $package = New-ProtectedEvidencePackage -DestinationDirectory $root -Artifacts ([ordered]@{
        'assessment-record.json' = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
        'assessment-report.html' = [Text.Encoding]::UTF8.GetBytes('<html><body>Partial synthetic evidence remains advisory.</body></html>')
    }) -AssessmentContractSetVersion 1.0.0 -Completeness RecoverablePartial -ApprovedRecipient $approved `
        -SyntheticAdmissionTime ([DateTimeOffset]$approved.certificate.NotAfter).AddHours(-1)
    Assert-Equal $true $package.verified 'a partial package is admitted through full finalization'
    foreach ($route in @('Local','Recipient')) {
        $parameters = @{ PackagePath=$package.packagePath; RequestedArtifact='assessment-report.html'; ViewingBasePath=$root; ProtectionRoute=$route }
        if ($route -eq 'Recipient') { $parameters.RecipientCertificate=$recipient.certificate }
        $view = Open-EvidenceViewingSession @parameters
        Assert-Equal 'Opened' $view.state "$route independently opens the historical package"
        Assert-Equal 1 @([IO.Directory]::EnumerateFiles($view.workspacePath,'*',[IO.SearchOption]::AllDirectories)).Count 'only requested HTML is exposed'
        Assert-Equal $true (Test-EvidenceAccessBoundary -LiteralPath $view.workspacePath -ExpectedOwnerSid ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) 'view is ACL confined'
        Assert-Equal $true (Close-EvidenceViewingSession $view).verified 'explicit closure verifies owned plaintext removal'
        Assert-Equal $false ([IO.File]::Exists($view.artifactPath)) 'closed HTML is absent'
    }
    $before = @([IO.Directory]::EnumerateFileSystemEntries($root) | Sort-Object) -join '|'
    $refused = Export-RestrictedAssessmentReport -PackagePath $package.packagePath -OutputPath (Join-Path $root 'unsafe.html') `
        -WarningAcknowledgment (Get-RestrictedReportExportWarning).acknowledgmentRequired
    Assert-Equal 'EXPORT.DESTINATION_NOT_PRIVATE' $refused.reasonCode 'an inherited broadly accessible destination is refused'
    Assert-Equal $before (@([IO.Directory]::EnumerateFileSystemEntries($root) | Sort-Object) -join '|') 'destination refusal writes nothing'
    $repoBoundary=New-EvidenceWorkspaceValidationBoundary -ValidationRootPath (
        Join-Path $repositoryRoot ('.test-output/recipient-export-rejection-'+[guid]::NewGuid().ToString('N')))
    try {
        $repoExport=Export-RestrictedAssessmentReport -PackagePath $package.packagePath -OutputPath (Join-Path $repoBoundary.CaseRoot 'restricted.html') `
            -WarningAcknowledgment (Get-RestrictedReportExportWarning).acknowledgmentRequired
        Assert-Equal 'EXPORT.DESTINATION_NOT_PRIVATE' $repoExport.reasonCode 'repository destinations are refused even with a private ACL'
        Assert-Equal 0 @([IO.Directory]::EnumerateFileSystemEntries($repoBoundary.CaseRoot)).Count 'repository refusal creates neither temporary nor final plaintext'
    }
    finally {if(-not (Remove-EvidenceWorkspaceValidationBoundary $repoBoundary)){throw 'Repository destination test cleanup failed.'}}
    $private = New-EvidenceWorkspace -RequestedBasePath $root -RunId ([guid]::NewGuid())
    $savedPath = Join-Path $private.workspacePath 'consultant.html'
    $declined = Export-RestrictedAssessmentReport -PackagePath $package.packagePath -OutputPath $savedPath -WarningAcknowledgment 'DECLINE'
    Assert-Equal 'EXPORT.WARNING_NOT_ACKNOWLEDGED' $declined.reasonCode 'warning decline refuses export'
    Assert-Equal 0 @([IO.Directory]::EnumerateFileSystemEntries($private.workspacePath)).Count 'warning decline writes nothing'
    $saved = Export-RestrictedAssessmentReport -PackagePath $package.packagePath -OutputPath $savedPath `
        -ProtectionRoute Recipient -RecipientCertificate $recipient.certificate `
        -WarningAcknowledgment (Get-RestrictedReportExportWarning).acknowledgmentRequired
    Assert-Equal 'Exported' $saved.state 'recipient deliberately exports admitted historical partial HTML'
    Assert-Equal $true ([IO.File]::ReadAllText($savedPath).Contains('RESTRICTED DIAGNOSTIC EVIDENCE')) 'designation persists in saved bytes'
    $wrong = New-SyntheticRecipientCertificate -KeyBits 3072 -Validity CurrentlyValid
    try {
        $badView = Open-EvidenceViewingSession -PackagePath $package.packagePath -RequestedArtifact assessment-report.html `
            -ViewingBasePath $root -ProtectionRoute Recipient -RecipientCertificate $wrong.certificate
        Assert-Equal $false $badView.verified 'an unrelated recipient cannot fall back to the working local protector'
        Assert-Equal $true ($null -eq $badView.artifactPath) 'unrelated protector exposes no plaintext'
    }
    finally { $wrong.certificate.Dispose() }
    $missingView = Open-EvidenceViewingSession -PackagePath $package.packagePath -RequestedArtifact assessment-report.html `
        -ViewingBasePath $root -ProtectionRoute Recipient -RecipientCertificate $approved.certificate
    Assert-Equal $false $missingView.verified 'public-only recipient has no opening authority'
    [byte[]]$corrupt = [IO.File]::ReadAllBytes($package.packagePath)
    $corrupt[-1] = $corrupt[-1] -bxor 1
    $corruptPath = Join-Path $root 'corrupt.winpcinfo'
    [IO.File]::WriteAllBytes($corruptPath,$corrupt)
    foreach ($route in @('Local','Recipient')) {
        $invalid = Open-EvidenceViewingSession -PackagePath $corruptPath -RequestedArtifact assessment-report.html `
            -ViewingBasePath $root -ProtectionRoute $route -RecipientCertificate $recipient.certificate
        Assert-Equal $false $invalid.verified "$route refuses corruption before exposure"
    }
    $again = Open-EvidenceViewingSession -PackagePath $package.packagePath -RequestedArtifact assessment-report.html -ViewingBasePath $root
    Assert-Equal 'Opened' $again.state 'export and failed opening preserve subsequent protected reopening'
    Assert-Equal $true (Close-EvidenceViewingSession $again).verified 'subsequent reopening cleans up'
    $start=[Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'))
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    foreach($argument in @('-NoLogo','-NoProfile','-File',$PSCommandPath,'-ViewChild','-ChildPackagePath',$package.packagePath,'-ChildRoot',$root)){$start.ArgumentList.Add($argument)}
    $child=[Diagnostics.Process]::Start($start)
    try {
        $wait=[Diagnostics.Stopwatch]::StartNew()
        $readyPath=Join-Path $root 'view-ready.json'
        while(-not [IO.File]::Exists($readyPath) -and -not $child.HasExited -and $wait.Elapsed.TotalSeconds -lt 20){Start-Sleep -Milliseconds 50}
        Assert-Equal $true ([IO.File]::Exists($readyPath)) 'a separate foreground process registers a real temporary view'
        $interrupted=[IO.File]::ReadAllText($readyPath) | ConvertFrom-Json
        $child.Kill(); $child.WaitForExit()
        Assert-Equal $true ([IO.File]::Exists($interrupted.artifactPath)) 'abrupt process interruption leaves the owned view for recovery'
        $recovered=Invoke-AssessmentRecoveryGate -Destination $root -Authorized $true
        Assert-Equal $true $recovered.cleanup.verified "deliberate recovery verifies the interrupted process identity and removes plaintext: $($recovered.reasonCode)"
        Assert-Equal $false ([IO.File]::Exists($interrupted.artifactPath)) 'recovery removes the exact interrupted view'
        Assert-Equal $true ([IO.File]::Exists($package.packagePath)) 'recovery preserves the existing protected package'
    }
    finally { if(-not $child.HasExited){$child.Kill();$child.WaitForExit()};$child.Dispose() }
}
finally {
    if ($null -ne $approved) { $approved.certificate.Dispose() }
    if ($null -ne $recipient) { $recipient.certificate.Dispose() }
    $resolved = [IO.Path]::GetFullPath($root)
    if (-not $resolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test cleanup.' }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved,$true) }
}
Write-Output 'PASS: generated recipient/local viewing preserves historical admission and partial-result cleanup.'
