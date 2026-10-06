[CmdletBinding()]
param([switch]$ViewChild, [string]$ChildPackagePath, [string]$ChildRoot, [string]$CandidatePath, [string]$PreparedManifestPath, [string]$PreparedManifestSha256, [string]$InterruptionOwnerDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'QualificationRecipientViewingInterruption.ps1')
$candidateContext=$null;$candidateError=$null;$owner=$null;$child=$null;$fixtureCleanup=[pscustomobject]@{Unverified=$false;CandidateCloseAttempted=$false}
try {
if(-not $ViewChild){Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $repositoryRoot}
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidate=$candidateContext.Path
$regions = [regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
if($ViewChild){
    Assert-RecipientViewingInterruptionChild -RepositoryRoot $repositoryRoot -OwnerDirectory $InterruptionOwnerDirectory -Candidate $candidateContext -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256 -ChildRoot $ChildRoot -ChildPackagePath $ChildPackagePath
    $interrupted=Open-EvidenceViewingSession -PackagePath $ChildPackagePath -RequestedArtifact assessment-report.html -ViewingBasePath $ChildRoot
    if(-not $interrupted.verified){throw 'Child view did not open.'}
    [IO.File]::WriteAllText((Join-Path $ChildRoot 'view-ready.json'),($interrupted | ConvertTo-Json -Depth 10))
    [Threading.Thread]::Sleep(60000)
    throw 'The interruption controller did not stop the child.'
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('winpcinfo-recipient-view-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$recipient = $null
$approved = $null;$bodyError=$null
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
    foreach($argument in @('-NoLogo','-NoProfile','-File',$PSCommandPath,'-ViewChild','-ChildPackagePath',$package.packagePath,'-ChildRoot',$root,'-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)){$start.ArgumentList.Add($argument)}
    $owner=New-RecipientViewingInterruptionOwner -RepositoryRoot $repositoryRoot -Candidate $candidateContext -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256 -StartInfo $start -PackagePath $package.packagePath -FixtureRoot $root
    $childError=$null
    try {
    Assert-RecipientViewingInterruptionCreation -Owner $owner
    $child=[Diagnostics.Process]::Start($start)
    Register-RecipientViewingInterruptionProcess -Owner $owner -Process $child
        $wait=[Diagnostics.Stopwatch]::StartNew()
        $readyPath=Join-Path $root 'view-ready.json'
        $null=Wait-RecipientViewingInterruptionReady -Owner $owner
        Assert-Equal $true ([IO.File]::Exists($readyPath)) 'a separate foreground process registers a real temporary view'
        $interrupted=[IO.File]::ReadAllText($readyPath) | ConvertFrom-Json
        Interrupt-RecipientViewingOriginalProcess -Owner $owner
        Assert-Equal $true ([IO.File]::Exists($interrupted.artifactPath)) 'abrupt process interruption leaves the owned view for recovery'
        $recovered=Invoke-AssessmentRecoveryGate -Destination $root -Authorized $true
        Assert-Equal $true $recovered.cleanup.verified "deliberate recovery verifies the interrupted process identity and removes plaintext: $($recovered.reasonCode)"
        Assert-Equal $false ([IO.File]::Exists($interrupted.artifactPath)) 'recovery removes the exact interrupted view'
        Assert-Equal $true ([IO.File]::Exists($package.packagePath)) 'recovery preserves the existing protected package'
        Confirm-RecipientViewingInterruptionRecovery -Owner $owner -Recovery $recovered
    }
    catch {$childError=$_}
    finally {Complete-RecipientViewingInterruption -Owner $owner -Process $child -BodyError $childError}
}
catch {$bodyError=$_;if(Test-QualificationCleanupUnverified $_.Exception){$fixtureCleanup.Unverified=$true}}
finally {
    Complete-QualificationHarness -BodyError $bodyError -Cleanup @(
        {try{if($null -ne $approved){$approved.certificate.Dispose()}}catch{$fixtureCleanup.Unverified=$true;throw}},
        {try{if($null -ne $recipient){$recipient.certificate.Dispose()}}catch{$fixtureCleanup.Unverified=$true;throw}},
        {if($null -ne $candidateContext -and -not $fixtureCleanup.CandidateCloseAttempted){$fixtureCleanup.CandidateCloseAttempted=$true;try{Close-TestCandidate -Candidate $candidateContext -BodyError $bodyError}catch{$fixtureCleanup.Unverified=$true;throw}}},
        {
            if($fixtureCleanup.Unverified -or ($null -ne $owner -and ($owner.Unsafe -or -not $owner.RecoveryVerified -or -not $owner.Disposed))){throw 'Recipient fixture remains retained for exact recovery.'}
            $resolved=[IO.Path]::GetFullPath($root)
            if([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -cne [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -or [IO.Path]::GetFileName($resolved) -cnotmatch '^winpcinfo-recipient-view-[a-f0-9]{32}$'){throw 'Unsafe test cleanup.'}
            if([IO.Directory]::Exists($resolved)){
                if(@(Get-ChildItem -LiteralPath $resolved -Recurse -Force|Where-Object{($_.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0}).Count){throw 'Recipient fixture cleanup refuses redirected entries.'}
                [IO.Directory]::Delete($resolved,$true)
            }
        }
    )
}
}
catch {$candidateError=$_}
finally {Complete-QualificationHarness -BodyError $candidateError -Cleanup @({if($null -ne $candidateContext -and -not $fixtureCleanup.CandidateCloseAttempted){$fixtureCleanup.CandidateCloseAttempted=$true;Close-TestCandidate -Candidate $candidateContext -BodyError $candidateError}})}
Write-Output 'PASS: generated recipient/local viewing preserves historical admission and partial-result cleanup.'