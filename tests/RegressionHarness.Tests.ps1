[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'Invoke-TestFile.ps1')
$runnerAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Run-Tests.ps1'),[ref]$null,[ref]$null)
$runnerCore=$runnerAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-TestSuiteFiles'},$true)
. ([scriptblock]::Create($runnerCore.Extent.Text))
$root = Join-Path (Split-Path $PSScriptRoot) ('.test-output/harness-' + [guid]::NewGuid().ToString('N'))
try {
    # Actual Windows ACLs on new synthetic children; no inner Help/native outcome is fabricated.
    $innerAclRoot=Join-Path $root 'inner-help-private-directory'
    $null=[IO.Directory]::CreateDirectory($innerAclRoot)
    $innerIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try { $innerSid=$innerIdentity.User } finally { $innerIdentity.Dispose() }
    $systemSid=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $actualPrivateSetter=(Get-Command Set-TestNativePrivateDirectory -CommandType Function).ScriptBlock
    function New-HarnessInnerHelpParent {
        param([string] $Name,[bool] $Broad)
        $parent=Join-Path $innerAclRoot $Name
        $null=[IO.Directory]::CreateDirectory($parent)
        $parentAcl=[Security.AccessControl.DirectorySecurity]::new()
        $parentAcl.SetAccessRuleProtection($true,$false)
        $parentAcl.SetOwner($innerSid)
        foreach ($principal in @($innerSid,$systemSid)) {
            $null=$parentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        if ($Broad) {
            $null=$parentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
        }
        Set-Acl -LiteralPath $parent -AclObject $parentAcl
        $parent
    }
    foreach ($broad in @($true,$false)) {
        $parent=New-HarnessInnerHelpParent -Name ('positive-'+$broad) -Broad $broad
        $child=Join-Path $parent 'child'
        New-ReleaseHelpPrivateDirectory -Path $child
        $childAcl=Get-Acl -LiteralPath $child
        $childRules=@($childAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        Assert-Equal $innerSid.Value ($childAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value) 'inner Help directory is owned by the initiating user'
        Assert-Equal $true $childAcl.AreAccessRulesProtected 'inner Help directory drops inherited broad permissions'
        Assert-Equal $true $childAcl.AreAccessRulesCanonical 'actual private directory DACL is canonical'
        Assert-Equal 2 $childRules.Count 'only initiating user and SYSTEM receive directory grants'
        foreach ($allowed in @($innerSid.Value,'S-1-5-18')) {
            $grants=@($childRules | Where-Object { $_.IdentityReference.Value -ceq $allowed })
            Assert-Equal 1 $grants.Count 'each exact allowed principal has one grant'
            Assert-Equal $false $grants[0].IsInherited 'directory grants are explicit'
            Assert-Equal ([Security.AccessControl.AccessControlType]::Allow) $grants[0].AccessControlType 'directory grant is Allow'
            Assert-Equal ([Security.AccessControl.FileSystemRights]::FullControl) $grants[0].FileSystemRights 'directory grant is full control'
            Assert-Equal 3 ([int]$grants[0].InheritanceFlags) 'private child records inherit both directory and file grants'
            Assert-Equal 0 ([int]$grants[0].PropagationFlags) 'private grants propagate normally'
        }
        # A harmless record is written only after the real directory helper returned.
        Write-ReleaseHelpPrivateRecord -Path (Join-Path $child 'synthetic.json') -Record @{synthetic=$true}
        $recordAcl=Get-Acl -LiteralPath (Join-Path $child 'synthetic.json')
        $recordRules=@($recordAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        Assert-Equal 2 $recordRules.Count 'new private record inherits only the allowed principal domain'
        Assert-Equal $true (@($recordRules | Where-Object { $_.IdentityReference.Value -cne $innerSid.Value -and $_.IdentityReference.Value -cne 'S-1-5-18' }).Count -eq 0) 'no broad principal can read the synthetic private record'
        Write-Output ('INNER_HELP_DIRECTORY_CONTROL_PASS: private-parent-'+$broad)
    }
    foreach ($mode in @('BroadGrant','MissingSystem','WrongOwner','InheritedBroadGrant','UnprotectedExactDomain','WrongRights','WrongInheritance','WrongPropagation')) {
        $parent=New-HarnessInnerHelpParent -Name ('negative-'+$mode) -Broad ($mode -eq 'InheritedBroadGrant')
        $child=Join-Path $parent 'child'
        & {
            param([scriptblock] $RealSetter,[string] $Child,[string] $Mode)
            $injection=@{applied=$false;actualAcl=$null}
            # Substitute only the setter at this owned test boundary. Get-Acl remains real.
            function Set-TestNativePrivateDirectory {
                param([string] $Path)
                $sid=& $RealSetter -Path $Path
                $changed=Get-Acl -LiteralPath $Path
                switch ($Mode) {
                    'BroadGrant' { $null=$changed.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')) }
                    'MissingSystem' {
                        foreach ($grant in @($changed.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -ceq 'S-1-5-18' })) { $null=$changed.RemoveAccessRuleSpecific($grant) }
                    }
                    'WrongOwner' { $changed.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')) }
                    'InheritedBroadGrant' { $changed.SetAccessRuleProtection($false,$false) }
                    'UnprotectedExactDomain' { $changed.SetAccessRuleProtection($false,$false) }
                    'WrongRights' { $changed.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')) }
                    'WrongInheritance' { $changed.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit','None','Allow')) }
                    'WrongPropagation' { $changed.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','NoPropagateInherit','Allow')) }
                }
                Set-Acl -LiteralPath $Path -AclObject $changed
                $injection.actualAcl=Get-Acl -LiteralPath $Path
                $injection.applied=$true
                $sid
            }
            $caught=$null
            try { New-ReleaseHelpPrivateDirectory -Path $Child } catch { $caught=$_.Exception }
            Assert-Equal $true $injection.applied 'the fault is an actually written and observed Windows ACL, not a setter exception'
            $actualRules=@($injection.actualAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
            switch ($Mode) {
                'BroadGrant' { Assert-Equal 1 @($actualRules | Where-Object { $_.IdentityReference.Value -ceq 'S-1-1-0' }).Count 'broad permission mutation exists' }
                'MissingSystem' { Assert-Equal 0 @($actualRules | Where-Object { $_.IdentityReference.Value -ceq 'S-1-5-18' }).Count 'SYSTEM grant was actually removed' }
                'WrongOwner' { Assert-Equal 'S-1-5-32-544' ($injection.actualAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value) 'wrong owner was actually applied' }
                'InheritedBroadGrant' { Assert-Equal $true (@($actualRules | Where-Object IsInherited).Count -gt 0) 'actual inherited grants reach this child' }
                'UnprotectedExactDomain' { Assert-Equal $false $injection.actualAcl.AreAccessRulesProtected 'actual DACL is unprotected'; Assert-Equal 0 @($actualRules | Where-Object { $_.IdentityReference.Value -cne $innerSid.Value -and $_.IdentityReference.Value -cne 'S-1-5-18' }).Count 'unprotected negative retains the same allowed SID domain' }
                'WrongRights' { Assert-Equal 1 @($actualRules | Where-Object { $_.IdentityReference.Value -ceq $innerSid.Value -and $_.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl }).Count 'wrong rights were actually applied' }
                'WrongInheritance' { Assert-Equal 1 @($actualRules | Where-Object { $_.IdentityReference.Value -ceq $innerSid.Value -and [int]$_.InheritanceFlags -eq 1 }).Count 'wrong inheritance flags were actually applied' }
                'WrongPropagation' { Assert-Equal 1 @($actualRules | Where-Object { $_.IdentityReference.Value -ceq $innerSid.Value -and [int]$_.PropagationFlags -eq 1 }).Count 'wrong propagation flags were actually applied' }
            }
            Assert-Equal $true ($null -ne $caught) 'directory helper refuses the actual faulty ACL'
            Assert-Equal 'Inner Help evidence directory ACL differs from its private boundary.' $caught.Message 'failure is the readback boundary, not a fixture setup error'
            Assert-Equal 0 ([IO.Directory]::GetFiles($Child).Length) 'no outcome or hold record exists before private-boundary verification'
        } $actualPrivateSetter $child $mode
        Write-Output ('INNER_HELP_DIRECTORY_CONTROL_PASS: reject-'+$mode)
    }
    $existingParent=New-HarnessInnerHelpParent -Name 'existing-paths' -Broad $false
    foreach ($kind in @('Directory','File')) {
        $existing=Join-Path $existingParent $kind
        if ($kind -eq 'Directory') { $null=[IO.Directory]::CreateDirectory($existing) }
        else { [IO.File]::WriteAllText($existing,'synthetic existing file') }
        $beforeAcl=(Get-Acl -LiteralPath $existing).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
        $caught=$null
        try { New-ReleaseHelpPrivateDirectory -Path $existing } catch { $caught=$_.Exception }
        Assert-Equal $true ($null -ne $caught) 'existing path remains a refusal'
        Assert-Equal 'Inner Help uncertainty directory already exists.' $caught.Message 'existing refusal precedes the private setter'
        Assert-Equal $beforeAcl ((Get-Acl -LiteralPath $existing).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)) 'refused original ACL remains unchanged'
        if ($kind -eq 'File') { Assert-Equal 'synthetic existing file' ([IO.File]::ReadAllText($existing)) 'refused file bytes remain unchanged' }
        Write-Output ('INNER_HELP_DIRECTORY_CONTROL_PASS: existing-'+$kind)
    }
    $testDirectory = Join-Path $root 'tests'
    $null = [IO.Directory]::CreateDirectory($testDirectory)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Run-Tests.ps1') -Destination $testDirectory
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'QualificationCleanup.ps1') -Destination $testDirectory
    foreach ($dependency in @('Invoke-TestFile.ps1','GeneratedApplicationNative.ps1','GeneratedApplicationNativeSupervisor.cs','QualificationCaseAdmission.ps1','Invoke-QualificationCase.ps1','Invoke-FocusedTest.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $dependency) -Destination $testDirectory
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'TestHarness.ps1') -Destination $testDirectory
    foreach ($directory in @('src','build','schemas','docs')) { $null=[IO.Directory]::CreateDirectory((Join-Path $root $directory)) }
    Copy-Item -LiteralPath (Join-Path (Split-Path $PSScriptRoot) 'build/RuntimeHost.ps1') -Destination (Join-Path $root 'build')
    [IO.File]::WriteAllText((Join-Path $root 'build/Build.ps1'),@'
param([string] $OutputPath)
# Passive fixture builder; no native application or process is started.
[IO.File]::WriteAllText($OutputPath,'synthetic candidate')
[IO.File]::AppendAllText((Join-Path (Split-Path (Split-Path $OutputPath)) 'build-count.txt'),'built;')
'@)
    [IO.File]::WriteAllText((Join-Path $testDirectory 'A.Tests.ps1'), "throw 'Synthetic expected failure'")
    [IO.File]::WriteAllText((Join-Path $testDirectory 'B.Tests.ps1'), "Write-Output 'SYNTHETIC_SECOND_FILE_EXECUTED'")
    foreach ($name in @('Open-TestSuiteCandidate','Close-TestSuiteCandidate')) {
        $definition=$runnerAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    $preparedSuite=Open-TestSuiteCandidate -RepositoryRoot $root -AuthorityEnds ([DateTimeOffset]::UtcNow.AddMinutes(5))
    try {
        $reader=Open-TestCandidate -RepositoryRoot $root -CandidatePath $preparedSuite.CandidatePath `
            -PreparedManifestPath $preparedSuite.PreparedManifestPath -PreparedManifestSha256 $preparedSuite.PreparedManifestSha256
        Close-TestCandidate -Candidate $reader
        Assert-Equal 'built;' ([IO.File]::ReadAllText((Join-Path $root '.test-output/build-count.txt'))) 'synthetic repository uses the actual default preparation once without replacing admission or cleanup functions'
    }
    finally { Close-TestSuiteCandidate -Context $preparedSuite -Unsafe $false }
    # The aggregation negative controls use disclosed native-result stubs.
    # Real unsafe native owners retain holds for root recovery and therefore
    # cannot be erased/reused by this fixture. Root separately certifies the
    # actual fresh-host bootstrap and nested generated-application boundary.
    function Invoke-RunnerNegativeFixture {
        param([switch] $Unsafe, [switch] $MarkerRetentionFailure)
        $pins=@(Get-ChildItem -LiteralPath $testDirectory -Filter '*.Tests.ps1' -File | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{file=$_.Name; sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}
        })
        $stub={param($Expected) [ordered]@{file=$Expected.file; sha256=$Expected.sha256;
            result=$(if ($Expected.file -eq 'A.Tests.ps1') {'Fail'} else {'Pass'}); elapsedMilliseconds=1;
            nativeExitCode=$(if ($Expected.file -eq 'A.Tests.ps1') {1} else {0}); completed=$true;
            cleanupVerified=(-not ($Unsafe -or $MarkerRetentionFailure))}}
        $ownedSummary=Join-Path $root ('.test-output/suite-'+[guid]::NewGuid().ToString('N'))
        $null=[IO.Directory]::CreateDirectory($ownedSummary)
        $save={param($Rows,$Final) [IO.File]::WriteAllText((Join-Path $ownedSummary 'suite-summary.json'),
            ([ordered]@{results=@($Rows); final=$Final} | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))}
        $suite=Invoke-TestSuiteFiles -Inventory $pins -InvokeFile $stub -RetainResults $save
        [pscustomobject]@{ExitCode=1; Output=$(if ($suite.Results[1].result -eq 'Pass') {'SYNTHETIC_SECOND_FILE_EXECUTED'} else {''})}
    }
    $observation=Invoke-RunnerNegativeFixture
    $output=$observation.Output
    $exitCode=$observation.ExitCode
    Assert-Equal $true ($exitCode -ne 0) 'a failed test file keeps the complete gate failed'
    Assert-Equal $true (($output -join "`n").Contains('SYNTHETIC_SECOND_FILE_EXECUTED')) 'a failing file cannot exclude subsequent test files'
    $summaryFiles = @(Get-ChildItem -LiteralPath (Join-Path $root '.test-output') -Filter suite-summary.json -Recurse)
    Assert-Equal 1 $summaryFiles.Count 'one gate retains one result inventory'
    $summary = Get-Content -LiteralPath $summaryFiles[0].FullName -Raw | ConvertFrom-Json
    Assert-Equal 'Fail' $summary.results[0].result 'the first failure survives in evidence'
    Assert-Equal 'Pass' $summary.results[1].result 'the subsequent executed file is independently recorded'

    [IO.File]::WriteAllText((Join-Path $testDirectory 'A.Tests.ps1'), @'
$blocker=Join-Path (Split-Path $PSScriptRoot) '.test-output/qualification-cleanup-blocked.json'
[IO.File]::WriteAllText($blocker,'{"state":"OwnedCleanupUnverified"}')
throw 'Synthetic unverified owned cleanup'
'@)
    $observation=Invoke-RunnerNegativeFixture -Unsafe
    $output=$observation.Output
    Assert-Equal $true ($observation.ExitCode -ne 0) 'unverified cleanup fails the suite'
    Assert-Equal $false (($output -join "`n").Contains('SYNTHETIC_SECOND_FILE_EXECUTED')) 'unverified cleanup blocks subsequent files'
    $summaryFiles = @(Get-ChildItem -LiteralPath (Join-Path $root '.test-output') -Filter suite-summary.json -Recurse)
    $blockedSummary=@($summaryFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } | Where-Object { $_.results[1].result -eq 'Blocked' })
    Assert-Equal 1 $blockedSummary.Count 'unexecuted files are explicitly blocked rather than passed'

    [IO.File]::WriteAllText((Join-Path $testDirectory 'A.Tests.ps1'), @'
$blocker=Get-QualificationCleanupBlockerPath
$null=[IO.Directory]::CreateDirectory($blocker)
Complete-QualificationHarness -Cleanup @({throw 'Synthetic owned worker remains active'})
'@)
    $observation=Invoke-RunnerNegativeFixture -MarkerRetentionFailure
    $output=$observation.Output
    Assert-Equal $true ($observation.ExitCode -ne 0) 'a stop-marker retention failure fails the suite'
    Assert-Equal $false (($output -join "`n").Contains('SYNTHETIC_SECOND_FILE_EXECUTED')) 'stop-marker write denial cannot permit subsequent files'

    $samplerPath = Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'
    $samplerAst = [Management.Automation.Language.Parser]::ParseFile($samplerPath, [ref]$null, [ref]$null)
    $sampler = $samplerAst.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Measure-QualificationWorkload'
    }, $true)
    . ([scriptblock]::Create($sampler.Extent.Text))
    $testRoot = $root
    $qualityWatch = [Diagnostics.Stopwatch]::StartNew()
    $RequireQualityBudgets = $false
    $quality = [ordered]@{
        sampledPrivateBytes=0L; sampledWorkingSetBytes=0L; sampledWorkspaceBytes=42L; workspaceSamplingLosses=0L
        sampleCount=0L; maximumSampleGapMilliseconds=0L; firstSampleMilliseconds=-1L; lastSampleMilliseconds=0L
    }
    function Get-ChildItem { param($LiteralPath, [switch]$File, [switch]$Recurse) throw $samplerFault }
    foreach ($samplerFault in @(
        [IO.DirectoryNotFoundException]::new('Synthetic owned directory removal'),
        [IO.FileNotFoundException]::new('Synthetic owned file removal'),
        [Management.Automation.ItemNotFoundException]::new('Synthetic owned item removal')
    )) {
        $previousLosses = $quality.workspaceSamplingLosses
        Measure-QualificationWorkload
        Assert-Equal ($previousLosses + 1) $quality.workspaceSamplingLosses 'owned path removal is counted as a lost sample'
        Assert-Equal 42L $quality.sampledWorkspaceBytes 'a lost sample preserves the previous observed maximum'
    }
    $samplerFault = [UnauthorizedAccessException]::new('Synthetic unexpected access denial')
    $denialPropagated = $false
    try { Measure-QualificationWorkload }
    catch [UnauthorizedAccessException] { $denialPropagated = $true }
    Assert-Equal $true $denialPropagated 'unexpected sampler errors still fail the test'
    Assert-Equal 3L $quality.workspaceSamplingLosses 'access denial is not relabeled as owned cleanup'
}
finally {
    $resolved = [IO.Path]::GetFullPath($root)
    $parent = [IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot) '.test-output'))
    if ([IO.Path]::GetDirectoryName($resolved) -ne $parent) { throw 'Harness cleanup escaped its owned parent.' }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved, $true) }
}
Write-Output 'PASS: full gate retains failure and executes the next file.'
