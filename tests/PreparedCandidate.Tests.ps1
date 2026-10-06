[CmdletBinding()]
param([string] $HarnessPath = (Join-Path $PSScriptRoot 'TestHarness.ps1'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. $HarnessPath
. (Join-Path (Split-Path $PSScriptRoot) 'build/PortableDistribution.ps1')
$parent=Join-Path (Split-Path $PSScriptRoot) '.test-output'
$root=Join-Path $parent ('prepared-input-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
$contexts=[Collections.Generic.List[object]]::new()
$checks=0
try {
    $repository=Join-Path $root 'repository'
    foreach ($directory in @('src','build','schemas','docs','tests')) { $null=[IO.Directory]::CreateDirectory((Join-Path $repository $directory)) }
    [IO.File]::WriteAllText((Join-Path $repository 'src/Fixture.ps1'),'# synthetic source')
    [IO.File]::WriteAllText((Join-Path $repository 'docs/fixture.json'),'{"synthetic":true}')
    [IO.File]::WriteAllText((Join-Path $repository 'SECURITY.md'),'synthetic packaged security guidance')
    [IO.File]::WriteAllText((Join-Path $repository 'tests/GeneratedApplicationNative.ps1'),'# synthetic native adapter')
    [IO.File]::WriteAllText((Join-Path $repository 'tests/GeneratedApplicationNativeSupervisor.cs'),'// synthetic native supervisor')
    [IO.File]::WriteAllText((Join-Path $repository 'tests/Invoke-TestFile.ps1'),'# synthetic fresh file bootstrap')
    [IO.File]::WriteAllText((Join-Path $repository 'tests/Run-Tests.ps1'),'# synthetic suite owner')
    foreach ($dependency in @('QualificationCleanup.ps1','QualificationCaseAdmission.ps1','Invoke-QualificationCase.ps1','Invoke-FocusedTest.ps1','QualificationFixtureProcess.ps1','QualificationCapabilityProcess.ps1','QualificationInlineRepresentation.ps1')) {
        [IO.File]::WriteAllText((Join-Path $repository ('tests/'+$dependency)),'# synthetic case/focused dependency')
    }
    # This bounded fixture substitutes the build owner only; it executes no
    # generated application, provider, task or native child.
    [IO.File]::WriteAllText((Join-Path $repository 'build/Build.ps1'),@'
param([string] $OutputPath)
[IO.File]::WriteAllText($OutputPath,'synthetic candidate')
[IO.File]::WriteAllText((Join-Path (Split-Path $OutputPath) 'fixture-output.txt'),'synthetic side output')
'@)
    $candidate=Join-Path $root 'candidate.ps1'
    [IO.File]::WriteAllText($candidate,'synthetic candidate')
    $manifestPath=Join-Path $root 'prepared.json'
    function Save-FixtureManifest {
        param($Manifest)
        [IO.File]::WriteAllText($manifestPath,($Manifest | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    function Assert-FixtureRefusal {
        param([scriptblock] $Action,[string] $Because)
        $refused=$false
        try {
            $unexpected=& $Action
            if ($null -ne $unexpected -and $null -ne $unexpected.PSObject.Properties['Stream']) { $unexpected.Stream.Dispose() }
        }
        catch { $refused=$true }
        Assert-Equal $true $refused $Because
    }
    $original=New-PreparedTestCandidateManifest -RepositoryRoot $repository -CandidatePath $candidate
    foreach ($dependency in @('tests/QualificationCapabilityProcess.ps1','tests/QualificationInlineRepresentation.ps1')) {
        Assert-Equal 1 @($original.inputs | Where-Object { $_.path -ceq $dependency }).Count "present ownership dependency is declared exactly once: $dependency"
        $checks++
    }
    $pin=Save-FixtureManifest $original
    $context=Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath $manifestPath -PreparedManifestSha256 $pin
    $contexts.Add($context)
    Assert-Equal $true $context.Prepared 'an admitted manifest selects prepared input'
    Assert-FixtureRefusal { [IO.File]::WriteAllText($candidate,'replacement') } 'prepared input refuses overlapping writer ownership'
    Assert-FixtureRefusal { [IO.File]::Delete($candidate) } 'prepared input refuses deletion during consumption'
    Close-TestCandidate -Candidate $context
    $contexts.Clear()
    Assert-Equal $true ([IO.File]::Exists($candidate)) 'prepared input is retained after consumption'
    $checks+=4

    [IO.File]::WriteAllText($candidate,'altered candidate')
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath $manifestPath -PreparedManifestSha256 $pin } 'candidate byte drift refuses before consumption'
    [IO.File]::WriteAllText($candidate,'synthetic candidate')
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath (Join-Path $root 'missing.ps1') -PreparedManifestPath $manifestPath -PreparedManifestSha256 $pin } 'missing candidate cannot fall back to a build'
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath $manifestPath -PreparedManifestSha256 ('0'*64) } 'stale manifest pin refuses'
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate } 'partial explicit input cannot fall back to a build'
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath ' ' } 'direct whitespace-only path refuses instead of choosing a standalone build'
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -PreparedManifestPath ' ' } 'direct whitespace-only manifest refuses instead of choosing a standalone build'
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -PreparedManifestSha256 $pin } 'direct hash-only input cannot fall back to a build'
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath (Join-Path $root 'missing.json') -PreparedManifestSha256 $pin } 'missing manifest cannot fall back to a build'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $repository -Directory -Filter '.test-output').Count 'direct whitespace/path/hash-only refusals create no passive build or output parent'
    $checks+=9

    foreach ($path in @('src/Fixture.ps1','docs/fixture.json','build/Build.ps1','SECURITY.md',
        'tests/GeneratedApplicationNative.ps1','tests/GeneratedApplicationNativeSupervisor.cs',
        'tests/Invoke-TestFile.ps1','tests/Run-Tests.ps1','tests/QualificationCleanup.ps1',
        'tests/QualificationCaseAdmission.ps1','tests/Invoke-QualificationCase.ps1','tests/Invoke-FocusedTest.ps1','tests/QualificationFixtureProcess.ps1',
        'tests/QualificationCapabilityProcess.ps1','tests/QualificationInlineRepresentation.ps1')) {
        $literal=Join-Path $repository $path
        $saved=[IO.File]::ReadAllBytes($literal)
        try {
            [IO.File]::AppendAllText($literal,'changed')
            Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath $manifestPath -PreparedManifestSha256 $pin } "changed source/resource/build input refuses: $path"
        }
        finally { [IO.File]::WriteAllBytes($literal,$saved) }
        $checks++
    }
    foreach ($dependency in @('tests/QualificationCapabilityProcess.ps1','tests/QualificationInlineRepresentation.ps1')) {
        $literal=Join-Path $repository $dependency
        $saved=[IO.File]::ReadAllBytes($literal)
        try {
            [IO.File]::Delete($literal)
            Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath $manifestPath -PreparedManifestSha256 $pin } "missing declared ownership dependency refuses: $dependency"
        }
        finally { [IO.File]::WriteAllBytes($literal,$saved) }
        $checks++
    }
    $added=Join-Path $repository 'src/Added.ps1'
    [IO.File]::WriteAllText($added,'# new source')
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath $manifestPath -PreparedManifestSha256 $pin } 'new undeclared input refuses'
    [IO.File]::Delete($added)
    $checks++
    foreach ($fault in @('MissingInput','DuplicateInput','Runtime','CandidatePath')) {
        $changed=$original | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10
        switch ($fault) {
            'MissingInput' { $changed.inputs=@($changed.inputs | Select-Object -Skip 1) }
            'DuplicateInput' { $changed.inputs[1]=$changed.inputs[0] }
            'Runtime' { $changed.runtime.sha256='0'*64 }
            'CandidatePath' { $changed.candidate.path=Join-Path $root 'other.ps1' }
        }
        $changedPin=Save-FixtureManifest $changed
        Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath $manifestPath -PreparedManifestSha256 $changedPin } "repinned invalid admission refuses: $fault"
        $checks++
    }
    $pin=Save-FixtureManifest $original
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $repository -Directory -Filter '.test-output').Count 'refused supplied inputs never invoke standalone build'
    $checks++

    $first=Open-TestCandidate -RepositoryRoot $repository
    $contexts.Add($first)
    $second=Open-TestCandidate -RepositoryRoot $repository
    $contexts.Add($second)
    Assert-Equal $false ($first.Path -eq $second.Path) 'standalone consumers cannot overlap writable output'
    Assert-Equal $false $first.Prepared 'standalone fixture reports actual build attribution'
    Close-TestCandidate -Candidate $first
    Close-TestCandidate -Candidate $second
    $contexts.Clear()
    Assert-Equal $false ([IO.Directory]::Exists($first.OwnedDirectory)) 'standalone output cleanup is verified'
    Assert-Equal $false ([IO.Directory]::Exists($second.OwnedDirectory)) 'the second standalone owner cleans only its output'
    $checks+=4

    $failed=Open-TestCandidate -RepositoryRoot $repository
    $contexts.Add($failed)
    $bodyError=$null
    try { throw 'Synthetic body assertion failure' } catch { $bodyError=$_ }
    $retainedCause=$false
    try { Close-TestCandidate -Candidate $failed -BodyError $bodyError }
    catch { $retainedCause=@($_.Exception.Flatten().InnerExceptions | Where-Object Message -eq 'Synthetic body assertion failure').Count -eq 1 }
    $contexts.Clear()
    Assert-Equal $true $retainedCause 'candidate finalization retains an ordinary body failure'
    Assert-Equal $false ([IO.Directory]::Exists($failed.OwnedDirectory)) 'verified output cleanup completes despite an ordinary body failure'
    $checks+=2

    function Invoke-SuitePreparationControls {
        # Execute the actual preparation/finalizer functions against a passive
        # fixture build. Only the blocker destination is substituted, into this
        # owned fake repository; no real unsafe hold is cleared or reused.
        $runnerAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Run-Tests.ps1'),[ref]$null,[ref]$null)
        foreach ($name in @('Open-TestSuiteCandidate','Close-TestSuiteCandidate','Save-TestSuitePreparedManifest')) {
            $definition=$runnerAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
            . ([scriptblock]::Create($definition.Extent.Text))
        }
        function Get-QualificationCleanupBlockerPath { Join-Path $repository '.test-output/synthetic-suite-blocker.json' }
        $buildPath=Join-Path $repository 'build/Build.ps1'
        $savedBuild=[IO.File]::ReadAllBytes($buildPath)
        $counter=Join-Path $repository '.test-output/build-count.txt'
        $suiteContexts=[Collections.Generic.List[object]]::new()
        try {
            [IO.File]::AppendAllText($buildPath,"`n[IO.File]::AppendAllText((Join-Path (Split-Path (Split-Path `$OutputPath)) 'build-count.txt'),'built;')")
            $authority=[DateTimeOffset]::UtcNow.AddMinutes(5)
            $suite=Open-TestSuiteCandidate -RepositoryRoot $repository -AuthorityEnds $authority
            $suiteContexts.Add($suite)
            Assert-Equal 'built;' ([IO.File]::ReadAllText($counter)) 'no-input suite prepares one passive owned candidate'
            $one=Open-TestCandidate -RepositoryRoot $repository -CandidatePath $suite.CandidatePath -PreparedManifestPath $suite.PreparedManifestPath -PreparedManifestSha256 $suite.PreparedManifestSha256
            $two=Open-TestCandidate -RepositoryRoot $repository -CandidatePath $suite.CandidatePath -PreparedManifestPath $suite.PreparedManifestPath -PreparedManifestSha256 $suite.PreparedManifestSha256
            Assert-Equal $one.Path $two.Path 'independent file readers reuse the exact root candidate'
            Close-TestCandidate -Candidate $one; Close-TestCandidate -Candidate $two
            Assert-Equal 'built;' ([IO.File]::ReadAllText($counter)) 'two immutable readers cannot rebuild'
            Assert-FixtureRefusal { [IO.File]::WriteAllText($suite.PreparedManifestPath,'changed') } 'root manifest remains read-owned across all files'
            Assert-FixtureRefusal { Open-TestSuiteCandidate -RepositoryRoot $repository -CandidatePath $suite.CandidatePath -AuthorityEnds $authority } 'partial root input refuses rather than rebuilding'
            Assert-FixtureRefusal { Open-TestSuiteCandidate -RepositoryRoot $repository -CandidatePath ' ' -AuthorityEnds $authority } 'explicit whitespace root input cannot select a default build'
            Assert-FixtureRefusal { Open-TestSuiteCandidate -RepositoryRoot $repository -PreparedManifestSha256 $suite.PreparedManifestSha256 -AuthorityEnds $authority } 'manifest-pin-only root input cannot select a default build'
            Assert-Equal 'built;' ([IO.File]::ReadAllText($counter)) 'partial input refusal cannot build'
            Assert-FixtureRefusal { Open-TestSuiteCandidate -RepositoryRoot $repository -AuthorityEnds ([DateTimeOffset]::UtcNow) } 'expired authority refuses before passive build'
            Assert-Equal 'built;' ([IO.File]::ReadAllText($counter)) 'authority refusal cannot build'
            $archive=Join-Path $repository '.test-output/default-preparation-archive'
            $null=[IO.Directory]::CreateDirectory($archive)
            $retainedPins=@(Save-TestSuitePreparedManifest -Context $suite -EvidenceRoot $archive)
            Assert-Equal 2 $retainedPins.Count 'raw manifest and independent origin record are closed file inputs'
            Assert-Equal $suite.PreparedManifestSha256 (Get-FileHash -LiteralPath (Join-Path $archive 'suite-prepared-candidate-manifest.json')).Hash.ToLowerInvariant() 'retained manifest preserves exact held bytes and admitted digest'
            $origin=Read-TestNativeRecord -Path (Join-Path $archive 'suite-candidate-preparation.json')
            Assert-Equal $true ($origin.rawRetentionVerified -and $origin.mode -ceq 'DefaultPassiveBuild' -and $origin.candidate.path -ceq $suite.CandidatePath -and $origin.candidate.sha256 -ceq $suite.Candidate.Sha256) 'retained origin links actual default candidate and raw manifest without rebuilding'
            $explicit=Open-TestSuiteCandidate -RepositoryRoot $repository -CandidatePath $suite.CandidatePath -PreparedManifestPath $suite.PreparedManifestPath -PreparedManifestSha256 $suite.PreparedManifestSha256 -AuthorityEnds $authority
            $suiteContexts.Add($explicit)
            $explicitArchive=Join-Path $repository '.test-output/explicit-preparation-archive'
            $null=[IO.Directory]::CreateDirectory($explicitArchive)
            $null=Save-TestSuitePreparedManifest -Context $explicit -EvidenceRoot $explicitArchive
            Assert-Equal 'ExplicitPrepared' (Read-TestNativeRecord -Path (Join-Path $explicitArchive 'suite-candidate-preparation.json')).mode 'explicit mode retains its exact supplied manifest attribution'
            Close-TestSuiteCandidate -Context $explicit -Unsafe $false
            Close-TestSuiteCandidate -Context $suite -Unsafe $false
            $suiteContexts.Clear()
            Assert-Equal $false ([IO.Directory]::Exists($suite.Candidate.OwnedDirectory)) 'verified root finalization closes both handles before owned output removal'
            Assert-Equal $true ([IO.File]::Exists((Join-Path $archive 'suite-prepared-candidate-manifest.json'))) 'raw suite evidence remains independently after normal candidate removal'

            $suite=Open-TestSuiteCandidate -RepositoryRoot $repository -AuthorityEnds $authority
            $suiteContexts.Add($suite)
            foreach ($fault in @('MissingStream','HashDrift','RawWriteDenied','BothWritesDenied')) {
                $failedArchive=Join-Path $repository ('.test-output/retention-'+$fault)
                $null=[IO.Directory]::CreateDirectory($failedArchive)
                $savedStream=$suite.ManifestStream; $savedPin=$suite.PreparedManifestSha256
                switch ($fault) {
                    MissingStream { $suite.ManifestStream=$null }
                    HashDrift { $suite.PreparedManifestSha256='0'*64 }
                    RawWriteDenied { $null=[IO.Directory]::CreateDirectory((Join-Path $failedArchive 'suite-prepared-candidate-manifest.json')) }
                    BothWritesDenied {
                        $null=[IO.Directory]::CreateDirectory((Join-Path $failedArchive 'suite-prepared-candidate-manifest.json'))
                        $null=[IO.Directory]::CreateDirectory((Join-Path $failedArchive 'suite-candidate-preparation.json'))
                    }
                }
                $retentionError=$null
                try { Save-TestSuitePreparedManifest -Context $suite -EvidenceRoot $failedArchive | Out-Null }
                catch { $retentionError=$_ }
                finally { $suite.ManifestStream=$savedStream; $suite.PreparedManifestSha256=$savedPin }
                Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $retentionError.Exception) "manifest $fault refuses admission as unsafe"
                Assert-Equal $true ([IO.Directory]::Exists($suite.Candidate.OwnedDirectory)) "manifest $fault does not discard candidate evidence"
                if ($fault -eq 'BothWritesDenied') {
                    Assert-Equal 2 $retentionError.Exception.InnerExceptions.Count 'independent raw and origin failures aggregate without masking either original cause'
                }
                else {
                    $failedOrigin=Read-TestNativeRecord -Path (Join-Path $failedArchive 'suite-candidate-preparation.json')
                    Assert-Equal $false $failedOrigin.rawRetentionVerified "manifest $fault retains explicit failed origin without claiming a valid archive"
                }
            }
            $originalRetention=$retentionError
            $finalError=$null
            try { Close-TestSuiteCandidate -Context $suite -BodyError $originalRetention -Unsafe $true | Out-Null }
            catch { $finalError=$_.Exception }
            Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $finalError) 'failed retention remains unsafe through suite candidate finalization'
            Assert-Equal 2 @($finalError.Flatten().InnerExceptions | Where-Object { $_ -in $originalRetention.Exception.InnerExceptions }).Count 'finalization retains both original retention exceptions'
            Assert-Equal $true ([IO.Directory]::Exists($suite.Candidate.OwnedDirectory)) 'unsafe retention finalization preserves owned candidate and original manifest'
            $suiteContexts.Clear()

            $suite=Open-TestSuiteCandidate -RepositoryRoot $repository -AuthorityEnds $authority
            $suiteContexts.Add($suite)
            $suite.PreparedManifestSha256='0'*64
            Assert-FixtureRefusal { Close-TestSuiteCandidate -Context $suite -Unsafe $false } 'manifest identity mismatch cannot become successful finalization'
            Assert-Equal $true ([IO.Directory]::Exists($suite.Candidate.OwnedDirectory)) 'manifest uncertainty preserves the actual owned candidate output'
            Assert-Equal $true ([IO.File]::Exists((Get-QualificationCleanupBlockerPath))) 'manifest uncertainty retains a durable scoped unsafe signal'
            $suiteContexts.Clear()

            $suite=Open-TestSuiteCandidate -RepositoryRoot $repository -AuthorityEnds $authority
            $suiteContexts.Add($suite)
            $failure=$null
            try { throw 'Synthetic full input inventory changed' } catch { $failure=$_ }
            Assert-FixtureRefusal { Close-TestSuiteCandidate -Context $suite -BodyError $failure -Unsafe $true } 'suite unsafe state cannot be lost at candidate finalization'
            Assert-Equal $true ([IO.Directory]::Exists($suite.Candidate.OwnedDirectory)) 'original suite uncertainty preserves candidate and pinned manifest'
            $suiteContexts.Clear()

            $sourcePath=Join-Path $repository 'src/Fixture.ps1'
            $savedSource=[IO.File]::ReadAllBytes($sourcePath)
            $ownedBefore=@(Get-ChildItem -LiteralPath (Join-Path $repository '.test-output') -Directory -Filter 'candidate-*').Count
            try {
                [IO.File]::WriteAllBytes($buildPath,$savedBuild)
                [IO.File]::AppendAllText($buildPath,"`n[IO.File]::AppendAllText((Join-Path (Split-Path (Split-Path (Split-Path `$OutputPath))) 'src/Fixture.ps1'),'changed during build')")
                Assert-FixtureRefusal { Open-TestSuiteCandidate -RepositoryRoot $repository -AuthorityEnds $authority } 'build-time source drift cannot bind a newer manifest to the older admitted cohort'
                Assert-Equal ($ownedBefore+1) @(Get-ChildItem -LiteralPath (Join-Path $repository '.test-output') -Directory -Filter 'candidate-*').Count 'build-time uncertainty preserves its separately owned output'
            }
            finally { [IO.File]::WriteAllBytes($sourcePath,$savedSource) }

            [IO.File]::WriteAllText($buildPath,"throw 'Synthetic suite build failure'")
            $ownedBefore=@(Get-ChildItem -LiteralPath (Join-Path $repository '.test-output') -Directory -Filter 'candidate-*').Count
            Assert-FixtureRefusal { Open-TestSuiteCandidate -RepositoryRoot $repository -AuthorityEnds $authority } 'failed root build never returns a file admission'
            Assert-Equal $ownedBefore @(Get-ChildItem -LiteralPath (Join-Path $repository '.test-output') -Directory -Filter 'candidate-*').Count 'failed passive build removes only its own incomplete output'

            [IO.File]::WriteAllText($buildPath,@'
param([string] $OutputPath)
[IO.File]::WriteAllText($OutputPath,'synthetic failed build output')
$global:WinPCInfoPreparedFixtureLock=[IO.File]::Open($OutputPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
throw 'Synthetic original build failure with owned lock'
'@)
            $retained=$null
            try { Open-TestSuiteCandidate -RepositoryRoot $repository -AuthorityEnds $authority | Out-Null }
            catch { $retained=$_.Exception }
            try {
                Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $retained) 'failed build cleanup cannot lose its unsafe ownership state'
                Assert-Equal 1 @($retained.Flatten().InnerExceptions | Where-Object Message -eq 'Synthetic original build failure with owned lock').Count 'cleanup failure retains the original passive build error independently'
                Assert-Equal $true ([IO.Directory]::Exists($retained.Data['OwnedCandidateDirectory'])) 'unverified setup cleanup retains its exact owned output path'
            }
            finally { $global:WinPCInfoPreparedFixtureLock.Dispose(); Remove-Variable -Name WinPCInfoPreparedFixtureLock -Scope Global }
        }
        finally {
            foreach ($suite in $suiteContexts) {
                if ($null -ne $suite.ManifestStream) { $suite.ManifestStream.Dispose() }
                $suite.Candidate.Stream.Dispose()
            }
            [IO.File]::WriteAllBytes($buildPath,$savedBuild)
        }
        43
    }
    $checks+=Invoke-SuitePreparationControls

    # Check closure against the existing package owner, rather than maintaining
    # a competing list of packaged documentation, schemas and release resources.
    $actualRepository=Split-Path $PSScriptRoot
    $policy=Get-PortableDistributionPolicy -RepositoryRoot $actualRepository
    $inputPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($inputFile in @(Get-TestCandidateInputInventory -RepositoryRoot $actualRepository)) { $null=$inputPaths.Add($inputFile.path) }
    $packagedInputs=@(Get-PortableSourceTreeFiles -RepositoryRoot $actualRepository -Policy $policy | ForEach-Object SourcePath)
    $packagedInputs+=@($policy.helperSourcePath,$policy.firstRunSourcePath,'build/RuntimeHost.ps1','build/Start-WIN-PCInfo.cmd')
    foreach ($sourcePath in $packagedInputs) {
        Assert-Equal $true ($inputPaths.Contains($sourcePath)) "prepared inventory covers actual packaged input: $sourcePath"
    }
    $checks++

    [IO.File]::WriteAllText((Join-Path $repository 'build/Build.ps1'),"throw 'Synthetic failed build'")
    $ownedBefore=@(Get-ChildItem -LiteralPath (Join-Path $repository '.test-output') -Directory).Count
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository } 'a failed standalone fixture build cannot return an admitted candidate'
    Assert-Equal $ownedBefore @(Get-ChildItem -LiteralPath (Join-Path $repository '.test-output') -Directory).Count 'failed build cleans only its newly owned output'
    $checks+=2
}
finally {
    foreach ($context in $contexts) { $context.Stream.Dispose() }
    $resolved=[IO.Path]::GetFullPath($root)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath($parent)) { throw 'Prepared-input fixture cleanup escaped its parent.' }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved,$true) }
    if ([IO.Directory]::Exists($resolved)) { throw 'Prepared-input fixture cleanup is unverified.' }
}
Write-Output "PASS: $checks bounded prepared-candidate controls; no generated application or native child."
