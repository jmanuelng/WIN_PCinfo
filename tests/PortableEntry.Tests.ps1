[CmdletBinding()]
param([string] $CandidatePath,[string] $PreparedManifestPath,[string] $PreparedManifestSha256)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

function Assert-PortableEntryFixtureAncestors {
    param([string] $Path)
    $cursor=[IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (([IO.Directory]::Exists($cursor) -or [IO.File]::Exists($cursor)) -and
            ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Portable entry fixtures cannot use reparse paths.' }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
}

function Remove-PortableEntryFixtureRoot {
    param([AllowNull()] $Owner)
    if ($null -eq $Owner -or [string]::IsNullOrWhiteSpace($Owner.WorkRoot)) { return }
    $full=[IO.Path]::GetFullPath($Owner.WorkRoot)
    if (-not [IO.Path]::GetDirectoryName($full).Equals([IO.Path]::GetFullPath($Owner.Parent).TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($full) -cne ('portable-entry-'+$Owner.Nonce)) { throw 'Portable entry fixture boundary changed.' }
    $entry=$null
    try { $entry=Get-Item -LiteralPath $full -Force -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            $_.Exception -is [Management.Automation.ItemNotFoundException]) { return }
        throw
    }
    if ($entry -isnot [IO.DirectoryInfo] -or
        ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Portable entry fixture root type or attributes changed.' }
    Assert-PortableEntryFixtureAncestors -Path $full
    if (@(Get-ChildItem -LiteralPath $full -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count) { throw 'Portable entry fixture contains a reparse entry.' }
    if ([IO.File]::ReadAllText((Join-Path $full 'fixture-owner.txt')) -cne ('PortableEntry|'+$Owner.Nonce)) { throw 'Portable entry fixture marker changed.' }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    if ([IO.Directory]::Exists($full) -or [IO.File]::Exists($full)) { throw 'Portable entry fixture cleanup remains incomplete.' }
}

function Open-PortableEntryArtifact {
    param([string] $Path,[string] $WorkRoot,[AllowNull()] $ExpectedSha256,$Owner)
    if ($ExpectedSha256 -isnot [string] -or $ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Portable entry artifact requires its exact expected identity.' }
    $full=[IO.Path]::GetFullPath($Path)
    $boundary=[IO.Path]::GetFullPath($WorkRoot).TrimEnd('\')+[IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)) { throw 'Portable entry artifact escaped its fixture.' }
    Assert-PortableEntryFixtureAncestors -Path $full
    $entry=Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($entry -isnot [IO.FileInfo] -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Portable entry artifact type or attributes changed.' }
    # Register before allocation: the caller owns even a holder whose Open or
    # identity verification fails before the normal assignment can complete.
    $artifact=[pscustomobject]@{Path=$full;Sha256=$ExpectedSha256;Stream=$null;Owner=$Owner;CloseAttempted=$false;Disposed=$false;TerminalError=$null}
    $Owner.Artifacts.Add($artifact)
    $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $artifact.Stream=$stream
    try {
        $sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
        if ($sha -cne $ExpectedSha256) { throw 'Portable entry artifact differs from its admitted identity.' }
        return $artifact
    }
    catch {
        $openError=$_
        $artifact.CloseAttempted=$true
        try { Complete-QualificationHarness -BodyError $openError -Cleanup @({$stream.Dispose();$artifact.Disposed=$true}) }
        catch {
            $artifact.TerminalError=$_.Exception
            $_.Exception.Data['PortableEntryFixtureOwner']=$Owner
            throw
        }
    }
}

function Close-PortableEntryArtifact {
    param([AllowNull()] $Artifact)
    if ($null -eq $Artifact) { return }
    if ($Artifact.CloseAttempted) {
        if ($Artifact.Disposed) { return }
        $failure=[InvalidOperationException]::new('Portable entry original artifact disposal remains unverified.',$Artifact.TerminalError)
        $failure.Data['OwnedCleanupUnverified']=$true
        $failure.Data['PortableEntryFixtureOwner']=$Artifact.Owner
        throw $failure
    }
    $Artifact.CloseAttempted=$true
    $bodyError=$null
    try {
        $Artifact.Stream.Position=0
        $sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Artifact.Stream)).ToLowerInvariant()
        if ($sha -cne $Artifact.Sha256) { throw 'Portable entry artifact identity changed during use.' }
    }
    catch { $bodyError=$_ }
    try { Complete-QualificationHarness -BodyError $bodyError -Cleanup @({$Artifact.Stream.Dispose();$Artifact.Disposed=$true}) }
    catch {
        $Artifact.TerminalError=$_.Exception
        $_.Exception.Data['PortableEntryFixtureOwner']=$Artifact.Owner
        throw
    }
}

function Get-PortableEntryFixturePaths {
    param([string] $WorkRoot,$Policy)
    if ($Policy.archiveFileName -isnot [string] -or $Policy.archiveFileName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.zip$' -or
        $Policy.archiveRootName -isnot [string] -or $Policy.archiveRootName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw 'Portable entry archive policy paths are not literal names.' }
    $buildApplication=Join-Path (Join-Path $WorkRoot 'build') 'WIN-PCInfo.ps1'
    # Build.ps1 resolves OutputPath, then passes its parent as OutputDirectory
    # to New-PortableDistributionPackage; that owner joins archiveFileName there.
    $outputDirectory=Split-Path -Parent ([IO.Path]::GetFullPath($buildApplication))
    $extractRoot=Join-Path $WorkRoot 'extract'
    return [pscustomobject]@{BuildApplication=$buildApplication;ArchivePath=(Join-Path $outputDirectory $Policy.archiveFileName);ExtractRoot=$extractRoot;PackageRoot=(Join-Path $extractRoot $Policy.archiveRootName)}
}
$candidateContext=$null
$builtArtifact=$null
$packageArtifact=$null
$archiveArtifact=$null
$fixtureOwner=[pscustomobject]@{Nonce=[Guid]::NewGuid().ToString('N');Parent=(Join-Path $repositoryRoot '.test-output');WorkRoot=$null;Unsafe=$false;Artifacts=[Collections.Generic.List[object]]::new()}
$candidateUseError=$null
try {
    $supplied=-not [string]::IsNullOrEmpty($CandidatePath) -or -not [string]::IsNullOrEmpty($PreparedManifestPath) -or -not [string]::IsNullOrEmpty($PreparedManifestSha256)
    if ($supplied) {
        # Partial or stale explicit input fails before any fixture/build work.
        $candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
    }
    $workRoot=Join-Path $fixtureOwner.Parent ('portable-entry-'+$fixtureOwner.Nonce)
    Assert-PortableEntryFixtureAncestors -Path $workRoot
    if ([IO.Directory]::Exists($workRoot) -or [IO.File]::Exists($workRoot)) { throw 'Portable entry unique fixture already exists.' }
    $null=[IO.Directory]::CreateDirectory($workRoot)
    $fixtureOwner.WorkRoot=$workRoot
    [IO.File]::WriteAllText((Join-Path $workRoot 'fixture-owner.txt'),('PortableEntry|'+$fixtureOwner.Nonce),[Text.UTF8Encoding]::new($false))
    $portablePolicy=Get-Content -LiteralPath (Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-portable-distribution.json') -Raw | ConvertFrom-Json
    $paths=Get-PortableEntryFixturePaths -WorkRoot $workRoot -Policy $portablePolicy
    $buildApplication=$paths.BuildApplication
    # Intentional original packaging Build remains exactly once, also standalone.
    $buildEvidence=& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $buildApplication
    if ($buildEvidence.buildContract -cne 'win-pcinfo.build-evidence/1.0.0' -or
        $buildEvidence.outputPath -isnot [string] -or
        -not [IO.Path]::GetFullPath($buildEvidence.outputPath).Equals([IO.Path]::GetFullPath($buildApplication),[StringComparison]::OrdinalIgnoreCase) -or
        $buildEvidence.portablePackage.archiveFileName -cne $portablePolicy.archiveFileName -or
        $buildEvidence.portablePackage.unpackedRootName -cne $portablePolicy.archiveRootName) { throw 'Portable entry Build output binding differs from its fixture policy.' }
    $builtArtifact=Open-PortableEntryArtifact -Path $buildApplication -WorkRoot $workRoot -ExpectedSha256 $buildEvidence.sha256 -Owner $fixtureOwner
    if ($null -ne $candidateContext -and $builtArtifact.Sha256 -cne $candidateContext.Sha256) { throw 'Portable entry freshly built application differs from supplied candidate.' }
    $archiveArtifact=Open-PortableEntryArtifact -Path $paths.ArchivePath -WorkRoot $workRoot -ExpectedSha256 $buildEvidence.portablePackageIdentity.sha256 -Owner $fixtureOwner
    $extractRoot=$paths.ExtractRoot
    [IO.Compression.ZipFile]::ExtractToDirectory($paths.ArchivePath, $extractRoot)
    $packageRoot=$paths.PackageRoot
    $application=Join-Path $packageRoot 'WIN-PCInfo.ps1'
    $packageArtifact=Open-PortableEntryArtifact -Path $application -WorkRoot $workRoot -ExpectedSha256 $builtArtifact.Sha256 -Owner $fixtureOwner
    [IO.File]::WriteAllText((Join-Path $workRoot 'fixture-binding.json'),([ordered]@{contract='win-pcinfo.portable-entry-test-fixture/1.0.0';nonce=$fixtureOwner.Nonce;buildPath=$builtArtifact.Path;buildSha256=$builtArtifact.Sha256;archivePath=$archiveArtifact.Path;archiveSha256=$archiveArtifact.Sha256;packagePath=$packageArtifact.Path;packageSha256=$packageArtifact.Sha256;suppliedCandidate=$supplied;nativeOwnership='Existing authenticated native helper owns its original handle and binding.'}|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
. (Join-Path $packageRoot 'Start-WIN-PCInfo.ps1')
$hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$validSignature = { param($Path) [pscustomobject]@{ Status = 'Valid' } }
$eligibleProbe = { param($Path, $Application) [pscustomobject]@{ Eligible = $true } }
$launchObservation = {
    param($Executable, $Arguments)
    Assert-Equal $hostPath $Executable 'portable entry chooses one literal executable'
    Assert-Equal '-NoProfile' $Arguments[1] 'GUI launch excludes profiles'
    Assert-Equal '-STA' $Arguments[2] 'GUI launch requests STA'
    Assert-Equal 'Gui' $Arguments[-1] 'double-click dispatches the GUI mode'
    [pscustomobject]@{ ExitCode = 20; StandardOutput = ''; StandardError = ''; ReasonCode = 'GUI.ADAPTER_UNAVAILABLE' }
}
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui `
    -CandidatePaths @($hostPath) -ReadSignature $validSignature -Probe $eligibleProbe -Launch $launchObservation
Assert-Equal 20 $result.ExitCode 'unavailable GUI remains a visible NotStarted boundary'
Assert-Equal 'GUI.ADAPTER_UNAVAILABLE' $result.ReasonCode 'the next owning slice is explicit'

$mustNotLaunch = { throw 'Unexpected application launch at a rejected boundary.' }
$originalOutput = [Console]::Out
$capturedOutput = [IO.StringWriter]::new()
try {
    [Console]::SetOut($capturedOutput)
    $terminalExit = Write-WinPCInfoLaunchResult -Gui -ShowGuidance { param($Text) } -Result ([pscustomobject]@{
        ExitCode = 50; ReasonCode = ''; StandardError = ''
        StandardOutput = '{"recordType":"win-pcinfo.terminal","outcome":"CleanupIncomplete","exitCode":50,"reasonCode":"CLEANUP.INCOMPLETE","collectionStarted":true,"cleanup":{"verified":false}}'
    })
}
finally { [Console]::SetOut($originalOutput) }
$preserved = @($capturedOutput.ToString().Trim() -split "`r?`n" | ConvertFrom-Json)
$capturedOutput.Dispose()
Assert-Equal 1 $preserved.Count 'GUI failure must emit exactly one existing terminal'
Assert-Equal 'CleanupIncomplete' $preserved[0].outcome 'GUI guidance cannot rewrite the outcome'
Assert-Equal $true $preserved[0].collectionStarted 'GUI guidance cannot deny prior collection'
Assert-Equal $false $preserved[0].cleanup.verified 'GUI guidance cannot invent cleanup success'
Assert-Equal 50 $terminalExit 'GUI preserves the application exit code'
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui `
    -CandidatePaths @($hostPath) -ReadSignature $validSignature `
    -Probe { [pscustomobject]@{ Eligible = $false; ReasonCode = 'LAUNCH.POLICY_REJECTED' } } -Launch $mustNotLaunch
Assert-Equal 'LAUNCH.POLICY_REJECTED' $result.ReasonCode 'policy-blocked runtime probing is not missing installation'
foreach ($case in @(
    @{ Name = 'absent'; Paths = @(); Signature = $validSignature; Reason = 'RUNTIME.HOST_MISSING' }
    @{ Name = 'signature'; Paths = @($hostPath); Signature = { [pscustomobject]@{ Status = 'HashMismatch' } }; Reason = 'LAUNCH.SIGNATURE_INVALID' }
)) {
    $result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui `
        -CandidatePaths $case.Paths -ReadSignature $case.Signature `
        -Probe { [pscustomobject]@{ Eligible = $false } } -Launch $mustNotLaunch
    Assert-Equal 20 $result.ExitCode "$($case.Name) cannot start assessment"
    Assert-Equal $case.Reason $result.ReasonCode "$($case.Name) has visible stable retry guidance"
}
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath (Join-Path $packageRoot 'missing.ps1') `
    -CandidatePaths @() -Launch $mustNotLaunch
Assert-Equal 'LAUNCH.APPLICATION_MISSING' $result.ReasonCode 'missing application is distinct from missing runtime'
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui `
    -CandidatePaths @($hostPath) -ReadSignature $validSignature -Probe $eligibleProbe `
    -Launch { throw [System.Security.SecurityException]::new('Synthetic policy rejection') }
Assert-Equal 'LAUNCH.POLICY_REJECTED' $result.ReasonCode 'policy rejection remains visible without bypass'

# Synthetic admission can exercise only a generated validation invocation.
# The real eligible executable and the complete packaged application run here;
# preparation fixtures prevent these tests from authorizing collection.
foreach ($mode in @('Guided', 'Automation')) {
    $arguments = @('-Mode', $mode, '-PreparationFixturePath', (Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'))
    if ($mode -eq 'Automation') { $arguments += @('-RequestPath', (Join-Path $PSScriptRoot 'fixtures/automation-request.json')) }
    $result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -ApplicationArguments $arguments `
        -CandidatePaths @('C:\synthetic\rejected\pwsh.exe', $hostPath, $hostPath) `
        -ReadSignature $validSignature -Probe ${function:Invoke-WinPCInfoRuntimeProbe} -Launch {
            param($Executable, $Arguments)
            Invoke-GeneratedApplication -PowerShellPath $Executable -CandidatePath $Arguments[3] -Arguments $Arguments[4..($Arguments.Count - 1)]
        }
    Assert-Equal 20 $result.ExitCode "$mode preserves generated application exit code"
    Assert-Equal 'PREPARATION.DECLINED' $result.Records[-1].reasonCode "$mode reaches the generated preparation boundary"
    Assert-Equal $true $result.Records[-1].validationFixture "$mode is explicitly synthetic"
    Assert-Equal $false $result.Records[-1].collectionStarted "$mode cannot authorize live collection"
}

$runtimeOnly = Invoke-GeneratedApplication -PowerShellPath $hostPath -CandidatePath $application -Arguments @(
    '-Workflow', 'CheckRuntime', '-RuntimeFixturePath', (Join-Path $packageRoot 'missing-fixture.json'), '-AcceptPreparation'
)
Assert-Equal 0 $runtimeOnly.ExitCode 'runtime probe cannot load a fixture or accept preparation'
Assert-Equal 'RUNTIME.ELIGIBLE' $runtimeOnly.Records[-1].reasonCode 'the generated policy passes on the real installed host'
Assert-Equal $false $runtimeOnly.Records[-1].collectionStarted 'runtime probe has no assessment authority'

$cmdHelp=Invoke-PortableEntryCmdHelp -PackageRoot $packageRoot
Assert-Equal '' $cmdHelp.StandardError 'the generated double-click entry executes without shell errors'
Assert-Equal 0 $cmdHelp.ExitCode 'explicit passive Help preserves its successful exit through CMD'
$cmdRecords = @($cmdHelp.StandardOutput.Trim() -split "`r?`n" | ConvertFrom-Json)
Assert-Equal 'HELP.DISCOVERY_COMPLETE' $cmdRecords[-1].reasonCode 'CMD reaches the real generated application'
}
catch {
    $candidateUseError=$_
    $fixtureOwner.Unsafe=Test-QualificationCleanupUnverified -Exception $_.Exception
}
finally {
    # An unsafe supplied-context body is retained by Close-TestCandidate. The
    # standalone branch has no such context, so this finalizer retains it here.
    $finalBodyError=if($fixtureOwner.Unsafe -and $null -ne $candidateContext){$null}else{$candidateUseError}
    Complete-QualificationHarness -BodyError $finalBodyError -Cleanup @(
        {
            if ($null -ne $candidateContext) {
                try { Close-TestCandidate -Candidate $candidateContext -BodyError $(if($fixtureOwner.Unsafe){$candidateUseError}else{$null}) }
                catch { $fixtureOwner.Unsafe=$true; throw }
            }
        },
        { try { Close-PortableEntryArtifact -Artifact $packageArtifact } catch { $fixtureOwner.Unsafe=$true; throw } },
        { try { Close-PortableEntryArtifact -Artifact $archiveArtifact } catch { $fixtureOwner.Unsafe=$true; throw } },
        { try { Close-PortableEntryArtifact -Artifact $builtArtifact } catch { $fixtureOwner.Unsafe=$true; throw } },
        {
            # A failed Open cannot populate the normal named caller variable.
            # Check the pre-registered original holders without retrying Dispose.
            foreach ($allocated in $fixtureOwner.Artifacts) {
                if ($null -ne $allocated.Stream -and -not $allocated.Disposed) {
                    $fixtureOwner.Unsafe=$true
                    $failure=[InvalidOperationException]::new('Portable entry allocated artifact cleanup remains unverified.',$allocated.TerminalError)
                    $failure.Data['OwnedCleanupUnverified']=$true
                    $failure.Data['PortableEntryFixtureOwner']=$fixtureOwner
                    throw $failure
                }
            }
        },
        {
            if (-not $fixtureOwner.Unsafe) {
                try { Remove-PortableEntryFixtureRoot -Owner $fixtureOwner }
                catch { $fixtureOwner.Unsafe=$true; throw }
            }
        }
    )
}
Write-Output 'PASS: portable GUI entry selects one host with NoProfile/STA.'
