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
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath (Join-Path $root 'missing.json') -PreparedManifestSha256 $pin } 'missing manifest cannot fall back to a build'
    $checks+=5

    foreach ($path in @('src/Fixture.ps1','docs/fixture.json','build/Build.ps1','SECURITY.md')) {
        $literal=Join-Path $repository $path
        $saved=[IO.File]::ReadAllBytes($literal)
        try {
            [IO.File]::AppendAllText($literal,'changed')
            Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository -CandidatePath $candidate -PreparedManifestPath $manifestPath -PreparedManifestSha256 $pin } "changed source/resource/build input refuses: $path"
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
    Assert-FixtureRefusal { Open-TestCandidate -RepositoryRoot $repository } 'a failed standalone fixture build cannot return an admitted candidate'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath (Join-Path $repository '.test-output') -Directory).Count 'failed build cleans only its newly owned output'
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
