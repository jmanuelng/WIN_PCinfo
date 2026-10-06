Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')

function Get-TestNativeDigest {
    param([Parameter(Mandatory)] $Value)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 14 -Compress))
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Read-TestNativeRecord {
    param([Parameter(Mandatory)] [string] $Path)
    $item=Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt 4MB -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Test native admission record is not a bounded ordinary file.' }
    # Creation timestamps are identity bytes, not dates to normalize on read.
    [Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($Path)) | ConvertFrom-Json -Depth 14 -DateKind String
}

function Write-TestNativeNewRecord {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] $Value)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 14 -Compress))
    $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $file.Write($bytes); $file.Flush($true) } finally { $file.Dispose() }
}

function Assert-TestFileExecutableProtocol {
    param([Parameter(Mandatory)] [string] $Path)
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if ($errors.Count -or $null -ne $ast.Find({param($node) $node -is [Management.Automation.Language.ExitStatementAst]},$true)) {
        throw 'Admitted test files require the bootstrap completion protocol; executable exit statements or parse errors refuse before execution.'
    }
    # Fixture child script strings remain ordinary strings. Residual native
    # LASTEXITCODE from a passing negative test cannot determine file outcome.
    $ast
}

function Assert-TestFileLauncher {
    param([Parameter(Mandatory)] $Admission, [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] [string] $HostPath, [Parameter(Mandatory)] [string] $WorkingDirectory,
        [Parameter(Mandatory)] [string[]] $Arguments)
    Assert-TestFileAdmissionInputs -Admission $Admission
    if ($Admission.repositoryRoot -ine $RepositoryRoot -or $HostPath -ine $Admission.hostPath -or
        [IO.Path]::GetFullPath($WorkingDirectory) -ine [IO.Path]::GetFullPath($Admission.repositoryRoot) -or
        $Arguments.Count -ne 4 -or ($Arguments -join '|') -cne (@('-NoLogo','-NoProfile','-File',$Admission.bootstrapPath) -join '|')) {
        throw 'Test file launcher does not match its fixed admitted bootstrap and working directory.'
    }
}

function Assert-TestFileAdmissionInputs {
    param([Parameter(Mandatory)] $Admission)
    if ($Admission.contract -cne 'win-pcinfo.test-file-admission/1.0.0' -or
        $Admission.cohortSha256 -cne (Get-TestNativeDigest -Value @($Admission.inputs)) -or
        $Admission.inputs.Count -lt 1) { throw 'Test file input cohort is malformed.' }
    $paths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($inputPin in $Admission.inputs) {
        if (-not [IO.Path]::IsPathFullyQualified($inputPin.path) -or -not $paths.Add($inputPin.path) -or
            $inputPin.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Test file input paths or hashes are malformed.' }
        $item=Get-Item -LiteralPath $inputPin.path -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -ne $inputPin.bytes -or
            (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $inputPin.sha256) { throw 'Test file admitted inputs changed.' }
    }
    foreach ($required in @($Admission.testPath,$Admission.bootstrapPath,$Admission.hostPath,$Admission.inventoryPath)) {
        if (-not $paths.Contains($required)) { throw 'Test file admission omits a required executable or inventory.' }
    }
    $testPin=@($Admission.inputs | Where-Object path -IEQ $Admission.testPath)
    if ($testPin.Count -ne 1 -or $testPin[0].sha256 -cne $Admission.testSha256) { throw 'Test file source pin differs from its admitted cohort.' }
    $null=Assert-TestFileExecutableProtocol -Path $Admission.testPath
    $root=[IO.Path]::GetFullPath($Admission.repositoryRoot)
    $scope=Get-TestRecordOptionalProperty -Record $Admission -Name 'scope'
    $eligible=[IO.Path]::GetFileName($Admission.testPath) -clike '*.Tests.ps1'
    if ($scope -eq 'FocusedSafetyDriver' -and [IO.Path]::GetFullPath($Admission.testPath) -ieq (Join-Path $root 'tests/Invoke-AssessmentSafetyQualification.ps1')) { $eligible=$true }
    if ($null -ne $scope -and $scope -cnotin @('Full','FocusedTestFile','FocusedSafetyDriver')) { throw 'Test file scope is not reviewed.' }
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Admission.testPath)) -ine (Join-Path $root 'tests') -or
        -not $eligible -or
        [IO.Path]::GetFullPath($Admission.bootstrapPath) -ine (Join-Path $root 'tests/Invoke-TestFile.ps1') -or
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Admission.suiteEvidenceRoot)) -ine (Join-Path $root '.test-output') -or
        [IO.Path]::GetFileName($Admission.suiteEvidenceRoot) -cnotmatch '^suite-[a-f0-9]{32}$' -or
        [IO.Path]::GetFullPath($Admission.inventoryPath) -ine (Join-Path $Admission.suiteEvidenceRoot 'suite-inventory.json')) { throw 'Test file admission differs from the fixed bootstrap boundary.' }
    $prepared=@($Admission.candidatePath,$Admission.preparedManifestPath,$Admission.preparedManifestSha256)
    $supplied=@($prepared | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
    if ($supplied -ne 0 -and ($supplied -ne 3 -or -not $paths.Contains($Admission.candidatePath) -or
        -not $paths.Contains($Admission.preparedManifestPath) -or $Admission.preparedManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        (Get-FileHash -LiteralPath $Admission.preparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Admission.preparedManifestSha256)) { throw 'Test file prepared input is incomplete or changed.' }
    if ($supplied -eq 3) {
        $prepared=Read-TestNativeRecord -Path $Admission.preparedManifestPath
        if ($prepared.contract -cne 'win-pcinfo.test-prepared-candidate/1.0.0') { throw 'Test file prepared manifest contract differs.' }
        Assert-TestPreparedRuntimeDependencies -Dependencies $prepared.runtime.dependencies -VerifiedInputPins @($Admission.inputs)
        if ($Admission.hostPath -ine (Join-Path $prepared.runtime.dependencies.root 'pwsh.exe')) { throw 'Test file host differs from its prepared runtime.' }
    }
    $named=Get-TestRecordOptionalProperty -Record $Admission -Name 'namedParameters'
    if ($null -ne $named) {
        $parameters=ConvertFrom-TestNamedParameterRecord -Parameters $named
        Assert-TestNamedParameterRecord -Ast (Assert-TestFileExecutableProtocol -Path $Admission.testPath) -Parameters $parameters
    }
    if ($scope -in @('FocusedTestFile','FocusedSafetyDriver')) {
        $focused=Read-FocusedTestRequest -RepositoryRoot $root -Path $Admission.focusedRequestPath -Sha256 $Admission.focusedRequestSha256
        if (-not $paths.Contains($focused.RequestPath) -or $focused.TestPath -ine $Admission.testPath -or $focused.Scope -cne $scope -or
            (Get-TestNativeDigest -Value $focused.NamedParameters) -cne (Get-TestNativeDigest -Value $named)) { throw 'Focused file admission differs from the exact pinned request.' }
    }
}

function Get-TestNativeSelfIdentity {
    $process=[Diagnostics.Process]::GetCurrentProcess()
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try { [pscustomobject]@{Pid=$PID; CreationUtc=$process.StartTime.ToUniversalTime().ToString('o');
        OwnerSid=$identity.User.Value; HostPath=$process.MainModule.FileName} }
    finally { $process.Dispose(); $identity.Dispose() }
}

function Read-TestFileLease {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [string] $Nonce,
        [Parameter(Mandatory)] $SelfIdentity, [switch] $RequireClaim,
        [DateTimeOffset] $Now=[DateTimeOffset]::UtcNow)
    if ($Nonce -cnotmatch '^[a-f0-9]{32}$') { throw 'Inherited test file lease is malformed; standalone fallback is forbidden.' }
    $directory=Join-Path ([IO.Path]::GetFullPath($RepositoryRoot)) ('.test-output/test-file-native/'+$Nonce)
    $parent=Get-Item -LiteralPath (Split-Path $directory) -ErrorAction Stop
    $item=Get-Item -LiteralPath $directory -ErrorAction Stop
    if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Test file lease paths cannot be redirected.' }
    $pendingPath=Join-Path $directory 'owned-pending.json'
    $ackPath=Join-Path $directory 'startup-ack.json'
    $pending=Read-TestNativeRecord -Path $pendingPath
    $ack=Read-TestNativeRecord -Path $ackPath
    $startup=Read-TestNativeRecord -Path (Join-Path $directory 'startup.json')
    if ($pending.nativeRole -cne 'TestFile' -or $pending.nonce -cne $Nonce -or
        $ack.contract -cne 'win-pcinfo.test-file-startup/1.0.0' -or $ack.nonce -cne $Nonce -or
        $ack.directory -ine $directory -or $ack.pendingSha256 -cne (Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $ack.startupSha256 -cne (Get-FileHash -LiteralPath (Join-Path $directory 'startup.json') -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $ack.admissionSha256 -cne (Get-TestNativeDigest -Value $pending.admission) -or
        (Get-TestNativeDigest -Value $startup) -cne (Get-TestNativeDigest -Value $pending) -or
        $pending.childCreationRequested -isnot [bool] -or -not $pending.childCreationRequested -or
        $pending.child.Started -isnot [bool] -or -not $pending.child.Started -or
        $pending.child.ExactStartedProcessHandlePinned -isnot [bool] -or -not $pending.child.ExactStartedProcessHandlePinned -or
        $pending.child.Pid -isnot [long] -and $pending.child.Pid -isnot [int] -or
        $pending.child.Pid -lt 1 -or
        -not [string]::IsNullOrEmpty($pending.child.ObservationFailure) -or
        $pending.child.Pid -ne $SelfIdentity.Pid -or $pending.child.CreationUtc -cne $SelfIdentity.CreationUtc -or
        $pending.child.OwnerSid -cne $SelfIdentity.OwnerSid -or $pending.child.HostPath -ine $SelfIdentity.HostPath -or
        $pending.admission.repositoryRoot -ine [IO.Path]::GetFullPath($RepositoryRoot) -or
        $pending.admission.hostPath -ine $SelfIdentity.HostPath -or
        [DateTimeOffset]::Parse($pending.authorityEnds) -le $Now) { throw 'Test file startup acknowledgement or exact lifetime differs from admission.' }
    Assert-TestFileAdmissionInputs -Admission $pending.admission
    if ($RequireClaim) {
        $claim=Read-TestNativeRecord -Path (Join-Path $directory 'child-admission.claim')
        if ($claim.contract -cne 'win-pcinfo.test-file-claim/1.0.0' -or $claim.nonce -cne $Nonce -or
            $claim.ackSha256 -cne (Get-FileHash -LiteralPath $ackPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
            $claim.pid -ne $SelfIdentity.Pid -or $claim.creationUtc -cne $SelfIdentity.CreationUtc -or
            $claim.ownerSid -cne $SelfIdentity.OwnerSid) { throw 'Test file one-use child claim differs from its exact admitted lifetime.' }
    }
    [pscustomobject]@{Directory=$directory; PendingPath=$pendingPath; Pending=$pending; Admission=$pending.admission; AckPath=$ackPath}
}

function Set-TestNativePrivateDirectory {
    param([Parameter(Mandatory)] [string] $Path)
    $currentIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try { $sid=$currentIdentity.User } finally { $currentIdentity.Dispose() }
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($sid)
    foreach ($identity in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $null=$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    $sid
}

function Assert-TestNativeRoleReady {
    param([ValidateSet('GeneratedApplication','TestFile','QualificationCase')] [string] $NativeRole,
        [Parameter(Mandatory)] [string] $RepositoryRoot, [string] $InputLauncherOwnerDirectory)
    $generated=Join-Path $RepositoryRoot '.test-output/generated-native'
    $testFiles=Join-Path $RepositoryRoot '.test-output/test-file-native'
    $cases=Join-Path $RepositoryRoot '.test-output/qualification-case-native'
    Assert-GeneratedApplicationNativeReady -EvidenceParent $generated
    $inputBinding=$null; if (-not [string]::IsNullOrEmpty($InputLauncherOwnerDirectory)) { if ($NativeRole -cne 'GeneratedApplication') { throw 'Input launcher cannot delegate another native role.' }; $inputBinding=Get-InputLauncherContext -RepositoryRoot $RepositoryRoot -Directory $InputLauncherOwnerDirectory -SelfIdentity (Get-TestNativeSelfIdentity) -SelfArguments (Get-InputLauncherSelfArguments) }; $allowed=$null
    $allowedCases=@()
    if (-not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_FILE_LEASE) -or -not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_CASE_LEASE)) {
        if ($NativeRole -eq 'TestFile') { throw 'A test file lease cannot delegate another test file launch.' }
        $context=if ($null -ne $inputBinding) { $inputBinding.CreatorContext } else { Get-TestNativeAdmissionContext -RepositoryRoot $RepositoryRoot -SelfIdentity (Get-TestNativeSelfIdentity) }
        $allowed=$context.Root.PendingPath
        $allowedCases=@($context.AllowedCasePendingPaths)
    }
    elseif ($NativeRole -eq 'QualificationCase') { throw 'Qualification cases require an exact current file or case owner.' }
    Assert-GeneratedApplicationNativeReady -EvidenceParent $testFiles -AllowedPendingPath $allowed
    Assert-GeneratedApplicationNativeReady -EvidenceParent $cases -AllowedPendingPaths $allowedCases
    Assert-GeneratedApplicationNativeReady -EvidenceParent (Join-Path $RepositoryRoot '.test-output/input-launcher-native') -AllowedPendingPath $(if ($null -ne $inputBinding) { $inputBinding.PendingPath })
}

function Initialize-GeneratedApplicationNativeSupervisor {
    $path=Join-Path $PSScriptRoot 'GeneratedApplicationNativeSupervisor.cs'
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $type='WinPCInfoTestGeneratedApplicationNativeSupervisor' -as [type]
    if ($null -ne $type) {
        if ($type::SourceIdentity -cne $hash) { throw 'Generated application supervisor source changed in this host; use a fresh test host.' }
        return
    }
    $source=[IO.File]::ReadAllText($path,[Text.UTF8Encoding]::new($false,$true))
    Add-Type -TypeDefinition $source.Replace('__TEST_NATIVE_SOURCE_ID__',$hash) -ErrorAction Stop
}

function Assert-GeneratedApplicationNativeReady {
    param([Parameter(Mandatory)] [string] $EvidenceParent, [AllowNull()] [string] $AllowedPendingPath,
        [string[]] $AllowedPendingPaths=@())
    Assert-QualificationCleanupReady
    if ([IO.Directory]::Exists($EvidenceParent)) {
        $parent=Get-Item -LiteralPath $EvidenceParent -ErrorAction Stop
        if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Generated application evidence cannot use a reparse point.' }
        foreach ($directory in @(Get-ChildItem -LiteralPath $EvidenceParent -Directory -Force -ErrorAction Stop)) {
            $pending=Join-Path $directory.FullName 'owned-pending.json'
            if (($pending -ieq $AllowedPendingPath -or $pending -iin $AllowedPendingPaths) -and
                ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and [IO.File]::Exists($pending)) { continue }
            if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                [IO.File]::Exists((Join-Path $directory.FullName 'owned-pending.json')) -or
                [IO.Directory]::Exists((Join-Path $directory.FullName 'owned-pending.json'))) {
                throw 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: preserved generated application ownership requires root recovery.'
            }
        }
    }
}

function Get-GeneratedApplicationNativeBudget {
    param([long] $TimeoutMs, [long] $CleanupReserveMs, [DateTimeOffset] $AuthorityEnds,
        [DateTimeOffset] $Now = [DateTimeOffset]::UtcNow)
    if ($TimeoutMs -lt 1 -or $CleanupReserveMs -lt 1) { throw 'Generated application requires a finite execution and cleanup reservation.' }
    $defaultEnd=$Now.AddMilliseconds($TimeoutMs).AddMilliseconds($CleanupReserveMs)
    if ($AuthorityEnds -eq [DateTimeOffset]::MinValue -or $AuthorityEnds -gt $defaultEnd) { $AuthorityEnds=$defaultEnd }
    if ($AuthorityEnds -le $Now.AddMilliseconds($CleanupReserveMs+100)) { throw 'Generated application has insufficient authority for execution and cleanup.' }
    [pscustomobject]@{AuthorityEnds=$AuthorityEnds; TimeoutMs=$TimeoutMs; CleanupReserveMs=$CleanupReserveMs}
}

function Save-GeneratedApplicationNativeOutcome {
    param([Parameter(Mandatory)] [string] $Directory, [Parameter(Mandatory)] $Identity,
        [AllowNull()] $Outcome, [Parameter(Mandatory)] [AllowEmptyCollection()] [Collections.Generic.List[Exception]] $Failures,
        [scriptblock] $ObserveTerminal)
    $terminal=if ($null -ne $Outcome) { $Outcome | Select-Object -Property * -ExcludeProperty Lines } else {
        [ordered]@{Started=$Identity.Started; NativeTerminalObserved=$false}
    }
    # An admitted observer can flush the actual handle outcome before fallible
    # retention. Its pipeline output is suppressed; normal callers get no new
    # console metadata or return values. Observer failures cannot erase exit.
    if ($null -ne $Outcome -and $null -ne $ObserveTerminal) {
        try { & $ObserveTerminal $Identity $Outcome | Out-Null } catch { $Failures.Add($_.Exception) }
    }
    $record=[ordered]@{identity=$Identity; outcome=$terminal}
    foreach ($name in @('original-native-outcome.json','terminal.json')) {
        try {
            $value=if ($name -eq 'terminal.json') { $terminal } else { $record }
            [IO.File]::WriteAllText((Join-Path $Directory $name),($value | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
        } catch { $Failures.Add($_.Exception) }
    }
    # errors.json receives the same actual in-memory snapshot as an independent
    # retention fallback. Nothing reloads these files to infer native completion.
    [pscustomobject]$record
}

function Get-PortableBootstrapSourceBytes {
    param([Parameter(Mandatory)] [string] $RepositoryRoot)
    # Reuse the actual portable owner canonicalizer; do not approximate BOM or
    # newline rules in this development admission seam. No build executes.
    . (Join-Path $RepositoryRoot 'build/PortableDistribution.ps1')
    $hostSource=[IO.File]::ReadAllText((Join-Path $RepositoryRoot 'build/RuntimeHost.ps1'))
    $helperText=[IO.File]::ReadAllText((Join-Path $RepositoryRoot 'build/Start-WIN-PCInfo.ps1')).Replace('# __RUNTIME_HOST_FUNCTIONS__',$hostSource)
    ConvertTo-PortableScriptBytes -Text $helperText -IncludeBom
}

function Complete-PortableBootstrapNativeBinding {
    param([Parameter(Mandatory)] $Binding,
        [AllowNull()] [Management.Automation.ErrorRecord] $BodyError)
    try {
        Complete-QualificationHarness -BodyError $BodyError -Cleanup @(
            {if ($null -ne $Binding.TargetStream) { $Binding.TargetStream.Dispose() }},
            {if ($null -ne $Binding.HostStream) { $Binding.HostStream.Dispose() }}
        )
    }
    catch {
        if (Test-QualificationCleanupUnverified -Exception $_.Exception) {
            if ($null -eq (Get-Variable PortableBootstrapUnverifiedBindings -Scope Script -ErrorAction SilentlyContinue)) {
                $script:PortableBootstrapUnverifiedBindings=[Collections.Generic.List[object]]::new()
            }
            $script:PortableBootstrapUnverifiedBindings.Add($Binding)
        }
        throw
    }
}

function Open-PortableBootstrapNativeBinding {
    param([Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] [string] $HostPath, [Parameter(Mandatory)] [string] $WorkingDirectory,
        [Parameter(Mandatory)] [string[]] $Arguments, [hashtable] $ExactEnvironment)
    $root=[IO.Path]::GetFullPath($RepositoryRoot)
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $root -SelfIdentity (Get-TestNativeSelfIdentity)
    $testPath=Join-Path $root 'tests/PortableDistributionApplication.Tests.ps1'
    if ($context.Parent.Admission.testPath -isnot [string] -or $context.Parent.Admission.testPath -ine $testPath -or
        @($context.Root.Admission.inputs | Where-Object path -IEQ $testPath).Count -ne 1) {
        throw 'Portable bootstrap requires its exact currently admitted test source.'
    }
    $expectedHost=Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
    if ($HostPath -ine $expectedHost -or $Arguments.Count -ne 6 -or
        $Arguments[0] -cne '-NoLogo' -or $Arguments[1] -cne '-NoProfile' -or $Arguments[2] -cne '-File' -or
        $Arguments[4] -cne '-Workflow' -or $Arguments[5] -cne 'Help') { throw 'Portable bootstrap host or closed Help argv changed.' }
    $target=[IO.Path]::GetFullPath($Arguments[3])
    if (-not [IO.Path]::IsPathFullyQualified($Arguments[3]) -or $Arguments[3] -ine $target) {
        throw 'Portable bootstrap argv must name its exact absolute target.'
    }
    $parts=[IO.Path]::GetRelativePath($root,$target).Replace('\','/').Split('/')
    $policy=Read-TestNativeRecord -Path (Join-Path $root 'docs/spec/releases/2.0.0-preview.1-portable-distribution.json')
    if ($parts.Count -ne 5 -or $parts[0] -cne '.test-output' -or
        $parts[1] -cnotmatch '^portable-distribution-application-[a-f0-9]{32}$' -or $parts[2] -cne 'extract-a' -or
        $parts[3] -cne $policy.archiveRootName -or $parts[4] -cne 'Start-WIN-PCInfo.ps1' -or
        $WorkingDirectory -ine [IO.Path]::GetDirectoryName($target)) { throw 'Portable bootstrap target or working directory escaped its exact fixture.' }
    $workRoot=Join-Path (Join-Path $root '.test-output') $parts[1]
    for ($directory=[IO.Path]::GetDirectoryName($target); $directory.Length -ge $root.Length; $directory=[IO.Path]::GetDirectoryName($directory)) {
        if (((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Portable bootstrap fixture cannot be redirected.' }
        if ($directory -ieq $root) { break }
    }
    foreach ($path in @($HostPath,$target)) {
        if (((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Portable bootstrap executable cannot be redirected.' }
    }
    $clear=$PSBoundParameters.ContainsKey('ExactEnvironment')
    $map=$null
    if ($clear) {
        $emptyRoot=Join-Path $workRoot 'no-pwsh'
        $expected=@{PATH=(Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0');SystemRoot=$env:SystemRoot;WINDIR=$env:WINDIR;
            ProgramFiles=$emptyRoot;'ProgramFiles(x86)'=$emptyRoot;LOCALAPPDATA=$emptyRoot;USERPROFILE=$emptyRoot;
            ComSpec=(Join-Path $env:WINDIR 'System32/cmd.exe');PATHEXT='.COM;.EXE;.BAT;.CMD'}
        if ($null -eq $ExactEnvironment -or $ExactEnvironment.Count -ne $expected.Count -or -not [IO.Directory]::Exists($emptyRoot)) {
            throw 'Portable bootstrap exact environment differs from the missing-host fixture.'
        }
        $map=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $ExactEnvironment.Keys) {
            if (-not $expected.ContainsKey($key) -or [string]$ExactEnvironment[$key] -cne [string]$expected[$key]) { throw 'Portable bootstrap exact environment entry changed.' }
            $map.Add($key,[string]$ExactEnvironment[$key])
        }
    }
    $hostStream=$null; $targetStream=$null
    try {
        $hostStream=[IO.File]::Open($HostPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $targetStream=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $targetSha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($targetStream)).ToLowerInvariant()
        $expectedBytes=Get-PortableBootstrapSourceBytes -RepositoryRoot $root
        if ($targetStream.Length -ne $expectedBytes.Length -or $targetSha -cne
            [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$expectedBytes)).ToLowerInvariant()) {
            throw 'Portable bootstrap target bytes differ from the actual reviewed portable builder.'
        }
        $hostSha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($hostStream)).ToLowerInvariant()
        $hostStream.Position=0; $targetStream.Position=0
        $end=[DateTimeOffset]::ParseExact($context.Parent.Pending.authorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture).
            AddMilliseconds(-[long]$context.Parent.Pending.cleanupReserveMs-2000)
        [pscustomobject]@{HostStream=$hostStream;TargetStream=$targetStream;ClearEnvironment=$clear;Environment=$map;AuthorityEnds=$end;
            Record=[ordered]@{contract='win-pcinfo.portable-bootstrap-native/1.0.0';testPath=$testPath;
                parentPendingCanonicalSha256=(Get-TestNativeDigest -Value $context.Parent.Pending);
                hostPath=$HostPath;hostSha256=$hostSha;targetPath=$target;targetSha256=$targetSha;
                arguments=$Arguments;workingDirectory=$WorkingDirectory;environmentMode=$(if($clear){'ClearExact'}else{'Inherited'});
                explicitEnvironment=$map;redirectStandardInput=$false;processTreeAbsenceClaim=$false}}
    }
    catch {
        Complete-PortableBootstrapNativeBinding -Binding ([pscustomobject]@{TargetStream=$targetStream;HostStream=$hostStream;
            Phase='AdmissionFailedBeforeNativeCreation'}) -BodyError $_
    }
}

function Invoke-GeneratedApplicationNative {
    param([Parameter(Mandatory)] [string] $HostPath,
        [Parameter(Mandatory)] [string] $WorkingDirectory,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [AllowEmptyString()] [string] $StandardInput = '',
        [long] $TimeoutMs = 3600000, [long] $CleanupReserveMs = 120000,
        [DateTimeOffset] $AuthorityEnds = [DateTimeOffset]::MinValue,
        [int] $MaximumLines = 65536, [int] $MaximumLineCharacters = 16777216,
        [int] $MaximumTotalCharacters = 33554432,
        [scriptblock] $ObserveStartup, [scriptblock] $ObserveTerminal,
        [ValidateSet('GeneratedApplication','TestFile','QualificationCase')] [string] $NativeRole = 'GeneratedApplication',
        [AllowNull()] $TestFileAdmission, [AllowNull()] $QualificationCaseAdmission,
        [switch] $PortableBootstrap, [hashtable] $ExactEnvironment, [string] $InputLauncherOwnerDirectory,
        [AllowEmptyString()] [string] $PortableEntryCmdPackageRoot)

    $portableBinding=$null; $cmdBinding=$null; $inputBinding=$null; $inputUseError=$null; $inputResult=$null; $portableSafe=$false; $startRequested=$false; $owner=$null
    $cmdRequested=$PSBoundParameters.ContainsKey('PortableEntryCmdPackageRoot')
    try {
    Assert-PortableEntryCmdAdmissionReady
    if ($cmdRequested -and ($PortableBootstrap -or $NativeRole -cne 'GeneratedApplication' -or $null -ne $TestFileAdmission -or
        $null -ne $QualificationCaseAdmission -or $PSBoundParameters.ContainsKey('ExactEnvironment') -or
        -not [string]::IsNullOrEmpty($InputLauncherOwnerDirectory) -or -not [string]::IsNullOrEmpty($StandardInput) -or
        $TimeoutMs -gt 60000 -or $CleanupReserveMs -ne 10000 -or
        $HostPath -ine (Join-Path $env:WINDIR 'System32/cmd.exe') -or $WorkingDirectory -cne [Environment]::CurrentDirectory -or
        $Arguments.Count -ne 1 -or $Arguments[0] -cne 'PortableEntryCmdHelp')) { throw 'CMD Help cannot change its closed source, host, stdin, environment or finite reservation.' }
    if ($PSBoundParameters.ContainsKey('ExactEnvironment') -and -not $PortableBootstrap) { throw 'Exact environment requires the closed portable bootstrap caller.' }
    if ($PortableBootstrap -and ($NativeRole -cne 'GeneratedApplication' -or $null -ne $TestFileAdmission -or
        $null -ne $QualificationCaseAdmission -or -not [string]::IsNullOrEmpty($StandardInput))) { throw 'Portable bootstrap cannot change another native role or request stdin.' }
    if ($PortableBootstrap -and ($TimeoutMs -gt 60000 -or $CleanupReserveMs -lt 10000)) { throw 'Portable bootstrap requires its bounded execution and retention reservation.' }

    # Test execution is separate from product collection limits. The default
    # reserves the product's 60-minute ceiling plus two minutes for termination
    # and retention; an outer authority can only shorten this invocation.
    if (-not [string]::IsNullOrWhiteSpace($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC)) {
        $outer=[DateTimeOffset]::ParseExact($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC,'o',[Globalization.CultureInfo]::InvariantCulture)
        if ($AuthorityEnds -eq [DateTimeOffset]::MinValue -or $outer -lt $AuthorityEnds) { $AuthorityEnds=$outer }
    }
    $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $AuthorityEnds
    foreach ($path in @($HostPath,$WorkingDirectory)) {
        if (-not [IO.Path]::IsPathFullyQualified($path)) { throw 'Generated application native paths must be absolute.' }
    }
    if (-not [IO.File]::Exists($HostPath) -or -not [IO.Directory]::Exists($WorkingDirectory)) { throw 'Generated application native host or working directory is unavailable.' }
    $repository=Split-Path -Parent $PSScriptRoot
    $outputRoot=Join-Path $repository '.test-output'
    if ([IO.Directory]::Exists($outputRoot) -and ((Get-Item -LiteralPath $outputRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Generated application output root cannot use a reparse point.' }
    if (-not [string]::IsNullOrEmpty($InputLauncherOwnerDirectory)) {
        if ($NativeRole -cne 'GeneratedApplication' -or $PortableBootstrap -or $null -ne $TestFileAdmission -or $null -ne $QualificationCaseAdmission -or $PSBoundParameters.ContainsKey('ExactEnvironment')) { throw 'Input launcher cannot change another native role/environment.' }
        $inputBinding=Open-InputLauncherNativeBinding -RepositoryRoot $repository -Directory $InputLauncherOwnerDirectory
        Assert-InputLauncherNativeInvocation -Binding $inputBinding -HostPath $HostPath -WorkingDirectory $WorkingDirectory -Arguments $Arguments -StandardInput $StandardInput -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs
        if ($inputBinding.Ends -lt $budget.AuthorityEnds) { $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $inputBinding.Ends }
    }
    Assert-TestNativeRoleReady -NativeRole $NativeRole -RepositoryRoot $repository -InputLauncherOwnerDirectory $InputLauncherOwnerDirectory
    if ($cmdRequested) {
        $cmdBinding=Open-PortableEntryCmdBinding -RepositoryRoot $repository -PackageRoot $PortableEntryCmdPackageRoot
        $fixedCmdEnd=$budget.AuthorityEnds
        if ($cmdBinding.AuthorityEnds -lt $budget.AuthorityEnds) {
            $fixedCmdEnd=$cmdBinding.AuthorityEnds
        }
        # Binding cannot refresh the original local end when its parent ends later.
        $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $fixedCmdEnd
    }
    if ($PortableBootstrap) {
        $bindingArguments=@{RepositoryRoot=$repository;HostPath=$HostPath;WorkingDirectory=$WorkingDirectory;Arguments=$Arguments}
        if ($PSBoundParameters.ContainsKey('ExactEnvironment')) { $bindingArguments.ExactEnvironment=$ExactEnvironment }
        $portableBinding=Open-PortableBootstrapNativeBinding @bindingArguments
        if ($portableBinding.AuthorityEnds -lt $budget.AuthorityEnds) {
            $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $portableBinding.AuthorityEnds
        }
    }
    $parent=Join-Path $outputRoot $(switch ($NativeRole) {'TestFile' {'test-file-native'} 'QualificationCase' {'qualification-case-native'} default {'generated-native'}})
    $nonce=[guid]::NewGuid().ToString('N')
    $admission=if ($null -ne $inputBinding) { $inputBinding.Record } else { $null }
    if ($NativeRole -eq 'TestFile') {
        Assert-TestFileLauncher -Admission $TestFileAdmission -RepositoryRoot $repository -HostPath $HostPath -WorkingDirectory $WorkingDirectory -Arguments $Arguments
        $Arguments=@($Arguments)+@('-NativeLeaseId',$nonce)
        $admission=$TestFileAdmission
    }
    elseif ($NativeRole -eq 'QualificationCase') {
        $context=Get-TestNativeAdmissionContext -RepositoryRoot $repository -SelfIdentity (Get-TestNativeSelfIdentity)
        Assert-QualificationCaseAdmission -Admission $QualificationCaseAdmission -Parent $context.Parent -Root $context.Root -ParentDepth $context.Depth -AuthorityEnds $budget.AuthorityEnds
        $expected=@('-NoLogo','-NoProfile'); if ($QualificationCaseAdmission.sta) { $expected+=@('-STA') }; $expected+=@('-File',$QualificationCaseAdmission.bootstrapPath)
        if ($HostPath -ine $QualificationCaseAdmission.hostPath -or [IO.Path]::GetFullPath($WorkingDirectory) -ine $repository -or
            ($Arguments -join '|') -cne ($expected -join '|')) { throw 'Qualification native launcher differs from its exact bootstrap, host or working directory.' }
        $output=Get-TestRecordOptionalProperty -Record $QualificationCaseAdmission.namedParameters -Name 'OutputPath'
        if ($null -ne $output -and ([IO.File]::Exists($output) -or [IO.Directory]::Exists($output))) { throw 'Qualification mutator output is already owned.' }
        $Arguments=@($Arguments)+@('-NativeLeaseId',$nonce)
        $admission=$QualificationCaseAdmission
    }
    if (($NativeRole -ne 'TestFile' -and $null -ne $TestFileAdmission) -or
        ($NativeRole -ne 'QualificationCase' -and $null -ne $QualificationCaseAdmission)) { throw 'Native role cannot accept another role admission.' }
    Initialize-GeneratedApplicationNativeSupervisor
    if ($cmdRequested) {
        $admission=$cmdBinding.Record
        $owner=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::CreatePortableEntryCmdHelp($PortableEntryCmdPackageRoot,
            $MaximumLines,$MaximumLineCharacters,$MaximumTotalCharacters)
        Assert-PortableEntryCmdConfiguredOwner -Identity $owner.StartedIdentity -Binding $cmdBinding
    }
    elseif ($PortableBootstrap) {
        $admission=$portableBinding.Record
        $owner=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new($HostPath,$WorkingDirectory,$Arguments,$StandardInput,
            $MaximumLines,$MaximumLineCharacters,$MaximumTotalCharacters,$portableBinding.ClearEnvironment,$portableBinding.Environment,$false)
    }
    else {
        $owner=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new($HostPath,$WorkingDirectory,$Arguments,$StandardInput,
            $MaximumLines,$MaximumLineCharacters,$MaximumTotalCharacters)
    }
    $directory=Join-Path $parent $nonce
    $null=[IO.Directory]::CreateDirectory($parent)
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    # Raw argv, native streams and failure messages stay in this private test
    # directory. No inherited broad ACL is allowed when collection may start.
    $sid=Set-TestNativePrivateDirectory -Path $directory
    $pendingPath=Join-Path $directory 'owned-pending.json'
    $parentIdentity=Get-TestNativeSelfIdentity
    $pending=[ordered]@{contract='win-pcinfo.test-owned-native/1.0.0'; nonce=$nonce; nativeRole=$NativeRole; admission=$admission;
        requestedAt=[DateTimeOffset]::UtcNow.ToString('o'); authorityEnds=$budget.AuthorityEnds.ToString('o');
        timeoutMs=$TimeoutMs; cleanupReserveMs=$CleanupReserveMs;
        parent=[ordered]@{pid=$parentIdentity.Pid; creationUtc=$parentIdentity.CreationUtc; ownerSid=$sid.Value; hostPath=$parentIdentity.HostPath; arguments=[Environment]::GetCommandLineArgs()};
        hostSha256=(Get-FileHash -LiteralPath $HostPath -Algorithm SHA256).Hash.ToLowerInvariant();
        supervisorSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'GeneratedApplicationNativeSupervisor.cs') -Algorithm SHA256).Hash.ToLowerInvariant();
        childCreationRequested=$false; child=$null}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($pending | ConvertTo-Json -Depth 8 -Compress))
    $file=[IO.File]::Open($pendingPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $file.Write($bytes); $file.Flush($true) } finally { $file.Dispose() }
    $failures=[Collections.Generic.List[Exception]]::new()
    $outcome=$null
    $wait=$null
    $startRequested=$false
    try {
        # Arm durable ownership before requesting process creation. A parent
        # crash leaves admission blocked even before a child identity is saved.
        if ($cmdRequested) {
            # Compilation and first ownership retention consumed this fixed end.
            $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $budget.AuthorityEnds
        }
        $pending.childCreationRequested=$true
        [IO.File]::WriteAllText($pendingPath,($pending | ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))
        if ($cmdRequested) {
            # Recheck after fallible pending IO, immediately before actual Start.
            $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $budget.AuthorityEnds
        }
        $startRequested=$true
        $owner.Start()
        $wait=$owner.BeginWait($budget.AuthorityEnds,$CleanupReserveMs,$TimeoutMs)
        try {
            $pending.child=$owner.StartedIdentity
            [IO.File]::WriteAllText($pendingPath,($pending | ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $directory 'startup.json'),($pending | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
            if ($null -ne $ObserveStartup) { & $ObserveStartup $directory $owner.StartedIdentity | Out-Null }
            if ($NativeRole -in @('TestFile','QualificationCase')) {
                if (-not $owner.StartedIdentity.ExactStartedProcessHandlePinned -or -not [string]::IsNullOrEmpty($owner.StartedIdentity.ObservationFailure)) { throw 'Test file startup lacks its exact original-handle identity.' }
                Write-TestNativeNewRecord -Path (Join-Path $directory 'startup-ack.json') -Value ([ordered]@{
                    contract=$(if ($NativeRole -eq 'TestFile') {'win-pcinfo.test-file-startup/1.0.0'} else {'win-pcinfo.qualification-case-startup/1.0.0'}); nonce=$nonce; directory=$directory;
                    pendingSha256=(Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256).Hash.ToLowerInvariant();
                    startupSha256=(Get-FileHash -LiteralPath (Join-Path $directory 'startup.json') -Algorithm SHA256).Hash.ToLowerInvariant();
                    admissionSha256=(Get-TestNativeDigest -Value $admission)})
            }
        } catch { $failures.Add($_.Exception) }
        $outcome=$wait.GetAwaiter().GetResult()
    }
    catch {
        $failures.Add($_.Exception)
        if ($owner.StartedIdentity.Started) {
            try {
                if ($null -eq $wait) { $wait=$owner.BeginWait($budget.AuthorityEnds,$CleanupReserveMs,$TimeoutMs) }
                $outcome=$wait.GetAwaiter().GetResult()
            } catch { $failures.Add($_.Exception) }
        }
    }
    # Each terminal/stream/error write is attempted independently after the
    # actual original-handle outcome; files never substitute for native exit.
    $original=Save-GeneratedApplicationNativeOutcome -Directory $directory -Identity $owner.StartedIdentity -Outcome $outcome `
        -Failures $failures -ObserveTerminal $ObserveTerminal
    try {
        if ($null -ne $outcome) {
            $writer=[IO.StreamWriter]::new((Join-Path $directory 'streams.jsonl'),$false,[Text.UTF8Encoding]::new($false,$true))
            try { foreach ($line in $outcome.Lines) { $writer.WriteLine(($line | ConvertTo-Json -Compress)); } } finally { $writer.Dispose() }
        }
    } catch { $failures.Add($_.Exception) }
    if ($NativeRole -eq 'QualificationCase') {
        # Check the child protocol while its exact pending hold still exists.
        # Missing completion/claim or changed source must preserve this hold,
        # even if the original handle has already observed native zero.
        $null=Confirm-QualificationCaseNativeRetention -RepositoryRoot $repository -Directory $directory -Nonce $nonce -Admission $admission -NativeIdentity $owner.StartedIdentity -NativeOutcome $outcome -Failures $failures
    }
    elseif ($NativeRole -eq 'TestFile') {
        $null=Confirm-TestFileNativeRetention -RepositoryRoot $repository -Directory $directory -Nonce $nonce -Admission $admission -NativeIdentity $owner.StartedIdentity -NativeOutcome $outcome -Failures $failures
    }
    if ($cmdRequested -and $null -ne $outcome -and $outcome.NativeTerminalObserved -and -not $outcome.OwnedCleanupUnverified -and $failures.Count -eq 0) {
        # Verify/release every immutable input before releasing the native hold.
        # A fallible binding finalizer cannot erase the original native outcome.
        try { Complete-PortableEntryCmdBinding -Binding $cmdBinding }
        catch { $failures.Add($_.Exception) }
    }
    try {
        $errorRecord=[ordered]@{startRequested=$startRequested; started=$owner.StartedIdentity.Started; original=$original;
            failures=@($failures | ForEach-Object { [ordered]@{type=$_.GetType().FullName; message=$_.Message} })}
        [IO.File]::WriteAllText((Join-Path $directory 'errors.json'),($errorRecord | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
    } catch { $failures.Add($_.Exception) }
    $safe=$null -ne $outcome -and $outcome.NativeTerminalObserved -and -not $outcome.OwnedCleanupUnverified -and $failures.Count -eq 0
    if ($safe) {
        try {
            $raw=[IO.File]::ReadAllBytes($pendingPath)
            $record=[Text.UTF8Encoding]::new($false,$true).GetString($raw) | ConvertFrom-Json
            if ($record.nonce -cne $nonce) { throw 'Generated application pending identity changed.' }
            $archive=Join-Path $directory 'exact-pending-before-release.json'
            $archiveFile=[IO.File]::Open($archive,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            try { $archiveFile.Write($raw); $archiveFile.Flush($true) } finally { $archiveFile.Dispose() }
            if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256).Hash) { throw 'Generated application pending archive identity differs.' }
            [IO.File]::Delete($pendingPath)
            if ([IO.File]::Exists($pendingPath)) { throw 'Generated application pending release failed.' }
        } catch { $failures.Add($_.Exception); $safe=$false }
    }
    if (-not $safe) {
        if ($cmdRequested) { Retain-PortableEntryCmdBinding -Binding $cmdBinding }
        # Keep the original owner reachable if its native terminal is unknown.
        # Forced parent termination makes descendant cleanup unverified; this
        # helper never claims or kills descendants from an invented identity.
        if (-not (Get-Variable -Name GeneratedApplicationUnverifiedOwners -Scope Script -ErrorAction SilentlyContinue)) {
            $script:GeneratedApplicationUnverifiedOwners=[Collections.Generic.List[object]]::new()
        }
        $script:GeneratedApplicationUnverifiedOwners.Add($owner)
        $exception=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: generated application native ownership or evidence is incomplete.')
        $exception.Data['OwnedCleanupUnverified']=$true
        $exception.Data['OriginalNativeOutcome']=$original.outcome
        $exception.Data['NativeEvidenceDirectory']=$directory
        try { [IO.File]::WriteAllText((Get-QualificationCleanupBlockerPath),'{"state":"OwnedCleanupUnverified"}',[Text.UTF8Encoding]::new($false)) } catch { }
        Write-Output 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'
        throw $exception
    }
    $owner.Dispose()
    $portableSafe=$true
    # Natural nonzero exits are part of the existing negative-test contract.
    # Behavior assertions, including JSON parsing, run only after ownership is
    # retained and safely released. Their failure cannot erase native evidence.
    $stdout=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($outcome.Lines,'stdout')
    $stderr=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($outcome.Lines,'stderr')
    $nativeResult=[pscustomobject]@{ExitCode=$outcome.NativeExitCode; StandardOutput=$stdout; StandardError=$stderr;
        EvidenceDirectory=$directory; NativeIdentity=$owner.StartedIdentity; NativeOutcome=$original.outcome; Nonce=$nonce;
        StreamRecords=$outcome.Lines}
    if ($null -ne $inputBinding) { $inputResult=$nativeResult } else { $nativeResult }
    }
    catch {
        $inputUseError=$_
        if (($PortableBootstrap -or $cmdRequested -or $null -ne $inputBinding) -and $startRequested -and -not $portableSafe -and
            -not (Test-QualificationCleanupUnverified -Exception $_.Exception)) {
            if ($cmdRequested) { Retain-PortableEntryCmdBinding -Binding $cmdBinding }
            # Fallible post-start disposal/retention must not let the caller
            # delete its package root while original ownership is uncertain.
            $_.Exception.Data['OwnedCleanupUnverified']=$true
            $_.Exception.Data['NativeEvidenceDirectory']=$directory
            if ($null -ne $owner) {
                if ($null -eq (Get-Variable GeneratedApplicationUnverifiedOwners -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:GeneratedApplicationUnverifiedOwners=[Collections.Generic.List[object]]::new()
                }
                $script:GeneratedApplicationUnverifiedOwners.Add($owner)
            }
            try { [IO.File]::WriteAllText((Get-QualificationCleanupBlockerPath),'{"state":"OwnedCleanupUnverified"}',[Text.UTF8Encoding]::new($false)) } catch { }
            Write-Output 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'
        }
        throw
    }
    finally {
        if ($null -ne $cmdBinding -and -not $cmdBinding.Closed) {
            if ($startRequested -and -not $portableSafe) {
                Retain-PortableEntryCmdBinding -Binding $cmdBinding
            }
            else { Complete-PortableEntryCmdBinding -Binding $cmdBinding -BodyError $inputUseError }
        }
        if ($null -ne $inputBinding) {
            if ($startRequested -and -not $portableSafe) {
                if ($null -eq (Get-Variable InputLauncherUnverifiedBindings -Scope Script -ErrorAction SilentlyContinue)) { $script:InputLauncherUnverifiedBindings=[Collections.Generic.List[object]]::new() }
                $script:InputLauncherUnverifiedBindings.Add($inputBinding)
            }
            else { Close-InputLauncherNativeBinding -Binding $inputBinding -BodyError $inputUseError }
        }
        if ($null -ne $portableBinding) {
            if ($startRequested -and -not $portableSafe) {
                if ($null -eq (Get-Variable PortableBootstrapUnverifiedBindings -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:PortableBootstrapUnverifiedBindings=[Collections.Generic.List[object]]::new()
                }
                $script:PortableBootstrapUnverifiedBindings.Add($portableBinding)
            }
            else { Complete-PortableBootstrapNativeBinding -Binding $portableBinding }
        }
    }
    if ($null -ne $inputResult) { $inputResult }
}

. (Join-Path $PSScriptRoot 'QualificationCaseAdmission.ps1')

. (Join-Path $PSScriptRoot 'QualificationInputLauncher.ps1')

function ConvertTo-PortableEntryCmdProfile {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [string] $PackageRoot,
        [Parameter(Mandatory)] $Policy)
    $root=[IO.Path]::GetFullPath($RepositoryRoot)
    if ([string]::IsNullOrWhiteSpace($PackageRoot) -or -not [IO.Path]::IsPathFullyQualified($PackageRoot) -or
        $PackageRoot -cne [IO.Path]::GetFullPath($PackageRoot) -or $PackageRoot -match '["%!&|<>^\x00-\x1f\x7f]') {
        throw 'CMD Help package must be an exact literal absolute path without shell expansion or control characters.'
    }
    $parts=[IO.Path]::GetRelativePath($root,$PackageRoot).Replace('\','/').Split('/')
    if ($Policy.archiveRootName -isnot [string] -or $Policy.archiveRootName -cne 'WIN-PCInfo-2.0.0-preview.1' -or
        $Policy.archiveFileName -isnot [string] -or $Policy.archiveFileName -cne 'WIN-PCInfo-2.0.0-preview.1-portable.zip' -or
        $parts.Count -ne 4 -or $parts[0] -cne '.test-output' -or $parts[1] -cnotmatch '^portable-entry-[a-f0-9]{32}$' -or
        $parts[2] -cne 'extract' -or $parts[3] -cne $Policy.archiveRootName) { throw 'CMD Help package escaped its exact unique fixture.' }
    $workRoot=Join-Path (Join-Path $root '.test-output') $parts[1]
    $hostPath=Join-Path $env:WINDIR 'System32/cmd.exe'
    $launcher=Join-Path $PackageRoot 'Start-WIN-PCInfo.cmd'
    [pscustomobject]@{HostPath=$hostPath;WorkRoot=$workRoot;PackageRoot=$PackageRoot;
        ArchivePath=(Join-Path (Join-Path $workRoot 'build') $Policy.archiveFileName);
        BuiltCandidatePath=(Join-Path (Join-Path $workRoot 'build') 'WIN-PCInfo.ps1');
        RawArguments=('/d /c ""'+$launcher+'" -Workflow Help"');
        RedirectStandardInput=$false;WorkingDirectoryMode='Inherited';EnvironmentMode='Inherited';
        OutputDecoding='ProcessDefaultReader';TextEvidenceRepresentation='DecodedTextReencodedUtf8';ProcessTreeAbsenceClaim=$false}
}

# This closes only the selected PS7 implementation/default-reference inputs.
# It does not qualify transitive loader resolution or a Windows PowerShell compiler.
function Get-TestPreparedRuntimeDependencies {
    param([switch] $HashFiles)
    if ($PSVersionTable.PSVersion.ToString() -cne '7.6.5') { throw 'Prepared runtime reference selection is reviewed only for PowerShell 7.6.5.' }
    $root=[IO.Path]::GetFullPath($PSHOME)
    $entry=[Reflection.Assembly]::GetEntryAssembly()
    $automation=[Management.Automation.PSObject].Assembly
    $referenceRoot=Join-Path ([IO.Path]::GetDirectoryName($(if ($null -ne $entry) {$entry.Location} else {$automation.Location}))) 'ref'
    if ($referenceRoot -ine (Join-Path $root 'ref') -or $null -eq $entry) { throw 'Prepared runtime entry/reference root differs from the selected PowerShell host.' }
    $ancestor=$root
    while (-not [string]::IsNullOrEmpty($ancestor)) {
        $item=Get-Item -LiteralPath $ancestor -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Prepared runtime ancestor is redirected or not a directory.' }
        $ancestor=[IO.Path]::GetDirectoryName($ancestor)
    }
    $refItem=Get-Item -LiteralPath $referenceRoot -ErrorAction Stop
    if (-not $refItem.PSIsContainer -or ($refItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Prepared compiler reference root is redirected.' }
    $roleTypes=[ordered]@{
        Entry=$entry; Automation=$automation;
        Utility=('Microsoft.PowerShell.Commands.AddTypeCommand' -as [type]);
        ConvertFromJson=('Microsoft.PowerShell.Commands.ConvertFromJsonCommand' -as [type]);
        Newtonsoft=('Newtonsoft.Json.JsonTextReader' -as [type]);
        SystemTextJson=('System.Text.Json.JsonDocument' -as [type]);
        Roslyn=('Microsoft.CodeAnalysis.Compilation' -as [type]);
        RoslynCSharp=('Microsoft.CodeAnalysis.CSharp.CSharpCompilation' -as [type])
    }
    $roleFiles=[ordered]@{Entry='pwsh.dll';Automation='System.Management.Automation.dll';Utility='Microsoft.PowerShell.Commands.Utility.dll';
        ConvertFromJson='Microsoft.PowerShell.Commands.Utility.dll';Newtonsoft='Newtonsoft.Json.dll';SystemTextJson='System.Text.Json.dll';
        Roslyn='Microsoft.CodeAnalysis.dll';RoslynCSharp='Microsoft.CodeAnalysis.CSharp.dll'}
    $roles=@(foreach ($role in $roleTypes.Keys) {
        $value=$roleTypes[$role]
        if ($null -eq $value) { throw "Prepared runtime implementation is not resolved in this host: $role." }
        $assembly=if ($value -is [type]) {$value.Assembly} else {$value}
        $path=[IO.Path]::GetFullPath($assembly.Location)
        if ($path -ine (Join-Path $root $roleFiles[$role])) { throw "Prepared runtime implementation resolves outside the selected distribution: $role." }
        [pscustomobject][ordered]@{role=$role;name=$assembly.FullName;path=$path}
    })
    # Names are the current recorded direct implementations/configuration/core,
    # not a guessed exhaustive framework list. Ref membership follows AddType.cs.
    $names=[Collections.Generic.List[string]]::new()
    foreach ($name in @('pwsh.exe','pwsh.dll','pwsh.deps.json','pwsh.runtimeconfig.json','Newtonsoft.Json.dll','System.Text.Json.dll',
        'System.Management.Automation.dll','Microsoft.PowerShell.Commands.Utility.dll','Microsoft.CodeAnalysis.dll',
        'Microsoft.CodeAnalysis.CSharp.dll','coreclr.dll','hostfxr.dll','hostpolicy.dll','System.Private.CoreLib.dll')) { $names.Add($name) }
    $references=@(Get-ChildItem -LiteralPath $referenceRoot -Filter '*.dll' -File -Force -ErrorAction Stop)
    if ($references.Count -lt 1) { throw 'Prepared compiler reference inventory is empty.' }
    foreach ($file in $references) { $names.Add('ref/'+$file.Name) }
    $ordered=$names.ToArray(); [Array]::Sort($ordered,[StringComparer]::Ordinal)
    $inputs=@(foreach ($name in $ordered) {
        $file=Get-Item -LiteralPath (Join-Path $root $name) -ErrorAction Stop
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Prepared runtime input is not an ordinary file.' }
        [pscustomobject][ordered]@{relativePath=$name;path=$file.FullName;bytes=$file.Length;
            sha256=$(if ($HashFiles) {(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} else {$null})}
    })
    [pscustomobject][ordered]@{contract='win-pcinfo.test-prepared-runtime/1.0.0';scope='PS7ImplementationAndDefaultReferences';
        root=$root;referenceRoot=$referenceRoot;roles=$roles;inputs=$inputs}
}

function Assert-TestPreparedRuntimeDependencies {
    param([Parameter(Mandatory)] $Dependencies, [AllowNull()] [object[]] $VerifiedInputPins)
    $verified=$PSBoundParameters.ContainsKey('VerifiedInputPins')
    $actual=Get-TestPreparedRuntimeDependencies -HashFiles:(-not $verified)
    if ($Dependencies.contract -isnot [string] -or $Dependencies.contract -cne $actual.contract -or
        $Dependencies.scope -isnot [string] -or $Dependencies.scope -cne $actual.scope -or
        $Dependencies.root -isnot [string] -or $Dependencies.root -ine $actual.root -or
        $Dependencies.referenceRoot -isnot [string] -or $Dependencies.referenceRoot -ine $actual.referenceRoot -or
        $Dependencies.roles -isnot [array] -or $Dependencies.roles.Count -ne $actual.roles.Count -or
        $Dependencies.inputs -isnot [array] -or $Dependencies.inputs.Count -ne $actual.inputs.Count) { throw 'Prepared runtime dependency inventory is missing or differs.' }
    for ($index=0; $index -lt $actual.roles.Count; $index++) {
        $declared=$Dependencies.roles[$index]; $role=$actual.roles[$index]
        if ($declared.role -isnot [string] -or $declared.role -cne $role.role -or $declared.name -isnot [string] -or
            $declared.name -cne $role.name -or $declared.path -isnot [string] -or $declared.path -ine $role.path) { throw 'Prepared runtime loaded implementation identity changed.' }
    }
    for ($index=0; $index -lt $actual.inputs.Count; $index++) {
        $declared=$Dependencies.inputs[$index]; $inputPin=$actual.inputs[$index]
        if ($declared.relativePath -isnot [string] -or $declared.relativePath -cne $inputPin.relativePath -or
            $declared.path -isnot [string] -or $declared.path -ine $inputPin.path -or
            ($declared.bytes -isnot [int] -and $declared.bytes -isnot [long]) -or $declared.bytes -ne $inputPin.bytes -or
            $declared.sha256 -isnot [string] -or $declared.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Prepared runtime physical/default-reference member changed.' }
        if ($verified) {
            # The File guard already hashed this exact full cohort. Do not hash
            # every runtime file again on every recursive Case validation.
            $pins=@($VerifiedInputPins | Where-Object path -IEQ $declared.path)
            if ($pins.Count -ne 1 -or $pins[0].bytes -ne $declared.bytes -or $pins[0].sha256 -cne $declared.sha256) { throw 'Test file cohort omits or changes a prepared runtime input.' }
        }
        elseif ($declared.sha256 -cne $inputPin.sha256) { throw 'Prepared runtime file identity changed.' }
    }
}

function Assert-PortableEntryCmdOrdinaryPath {
    param([Parameter(Mandatory)] [string] $Path)
    $full=[IO.Path]::GetFullPath($Path)
    for ($current=$full; -not [string]::IsNullOrEmpty($current); $current=[IO.Path]::GetDirectoryName($current)) {
        $item=Get-Item -LiteralPath $current -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'CMD Help input or ancestor cannot be redirected.' }
    }
}

function Add-PortableEntryCmdFilePin {
    param([Parameter(Mandatory)] $Binding, [Parameter(Mandatory)] [string] $Path, [AllowNull()] $ExpectedPin)
    $full=[IO.Path]::GetFullPath($Path)
    if (@($Binding.Files | Where-Object { $_.Path -ieq $full }).Count) { throw 'CMD Help physical input is duplicated.' }
    Assert-PortableEntryCmdOrdinaryPath -Path $full
    $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    # Register ownership before hashing, Length, admission or disposal can fail.
    $pin=[pscustomobject]@{Path=$full;Stream=$stream;Sha256=$null;Bytes=$null;BaselineObserved=$false;Disposed=$false}
    $Binding.Files.Add($pin)
    $sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    $pin.Bytes=$stream.Length;$pin.Sha256=$sha;$pin.BaselineObserved=$true
    if ($null -ne $ExpectedPin -and ($ExpectedPin.sha256 -isnot [string] -or $ExpectedPin.sha256 -cne $sha -or
        $ExpectedPin.bytes -ne $pin.Bytes)) { throw 'CMD Help admitted physical input drifted.' }
    $stream.Position=0
    $pin
}

function Complete-PortableEntryCmdBinding {
    param([Parameter(Mandatory)] $Binding, [AllowNull()] [Management.Automation.ErrorRecord] $BodyError)
    # Retain the existing binding list before the shared finalizer attempts its
    # fallible durable blocker. In-progress verification also blocks admission.
    Retain-PortableEntryCmdBinding -Binding $Binding
    try {
        Complete-QualificationHarness -BodyError $BodyError -Cleanup @({
            $failures=[Collections.Generic.List[Exception]]::new()
            foreach ($pin in $Binding.Files) {
                try {
                    if ($pin.Disposed) { throw 'CMD Help held input was released prematurely.' }
                    if ($pin.BaselineObserved -isnot [bool] -or -not $pin.BaselineObserved) { throw 'CMD Help held input baseline is incomplete.' }
                    $pin.Stream.Position=0
                    $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($pin.Stream)).ToLowerInvariant()
                    if ($hash -cne $pin.Sha256 -or $pin.Stream.Length -ne $pin.Bytes) { throw 'CMD Help consumed input changed.' }
                }
                catch { $failures.Add($_.Exception) }
                finally { try { $pin.Stream.Dispose();$pin.Disposed=$true } catch { $failures.Add($_.Exception) } }
            }
            if ($failures.Count) { throw [AggregateException]::new('CMD Help input verification/release failed.',$failures.ToArray()) }
        },{
            if ($null -ne $Binding.Candidate) { Close-TestCandidate -Candidate $Binding.Candidate }
        })
        $Binding.Closed=$true
        $null=$script:PortableEntryCmdUnverifiedBindings.Remove($Binding)
    }
    catch {
        if (Test-QualificationCleanupUnverified -Exception $_.Exception) {
            # No native hold exists for a pre-creation binding failure. Keep
            # the private stop even when the common durable blocker write fails.
            Retain-PortableEntryCmdBinding -Binding $Binding
        }
        else { $null=$script:PortableEntryCmdUnverifiedBindings.Remove($Binding) }
        throw
    }
}

function Open-PortableEntryCmdBinding {
    param([Parameter(Mandatory)] [string] $RepositoryRoot,[Parameter(Mandatory)] [string] $PackageRoot)
    $root=[IO.Path]::GetFullPath($RepositoryRoot)
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $root -SelfIdentity (Get-TestNativeSelfIdentity)
    Assert-TestFileAdmissionInputs -Admission $context.Root.Admission
    $testPath=Join-Path $root 'tests/PortableEntry.Tests.ps1'
    if ($context.Parent.Admission.testPath -isnot [string] -or $context.Parent.Admission.testPath -ine $testPath -or
        @($context.Root.Admission.inputs | Where-Object path -IEQ $testPath).Count -ne 1) { throw 'CMD Help requires its exact admitted PortableEntry source.' }
    $admission=$context.Root.Admission
    foreach ($value in @($admission.candidatePath,$admission.preparedManifestPath,$admission.preparedManifestSha256)) {
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) { throw 'CMD Help requires the complete immutable root candidate triple.' }
    }
    if ($admission.preparedManifestSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'CMD Help root manifest pin is malformed.' }
    $policyPath=Join-Path $root 'docs/spec/releases/2.0.0-preview.1-portable-distribution.json'
    $policy=Read-TestNativeRecord -Path $policyPath
    $profile=ConvertTo-PortableEntryCmdProfile -RepositoryRoot $root -PackageRoot $PackageRoot -Policy $policy
    $end=[DateTimeOffset]::ParseExact($context.Parent.Pending.authorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture).
        AddMilliseconds(-[long]$context.Parent.Pending.cleanupReserveMs-2000)
    $binding=[pscustomobject]@{Files=[Collections.Generic.List[object]]::new();Candidate=$null;Closed=$false;Profile=$profile;AuthorityEnds=$end;Record=$null}
    try {
        $binding.Candidate=Open-TestCandidate -RepositoryRoot $root -CandidatePath $admission.candidatePath `
            -PreparedManifestPath $admission.preparedManifestPath -PreparedManifestSha256 $admission.preparedManifestSha256
        $paths=@('tests/PortableEntry.Tests.ps1','tests/GeneratedApplicationNative.ps1','tests/GeneratedApplicationNativeSupervisor.cs',
            'build/Build.ps1','build/PortableDistribution.ps1','build/RuntimeHost.ps1','build/Start-WIN-PCInfo.cmd',
            'build/Start-WIN-PCInfo.ps1','build/TextCanonicalization.ps1','docs/spec/releases/2.0.0-preview.1-portable-distribution.json')
        foreach ($member in $paths) {
            $path=Join-Path $root $member;$pins=@($admission.inputs|Where-Object path -IEQ $path)
            if ($pins.Count -ne 1) { throw 'CMD Help owning source is missing from the root cohort.' }
            $null=Add-PortableEntryCmdFilePin -Binding $binding -Path $path -ExpectedPin $pins[0]
        }
        foreach ($path in @($admission.preparedManifestPath,$profile.HostPath,$profile.BuiltCandidatePath,$profile.ArchivePath,(Join-Path $profile.WorkRoot 'fixture-owner.txt'))) {
            $pin=@($admission.inputs|Where-Object path -IEQ $path)
            if ($path -ieq $admission.preparedManifestPath -and $pin.Count -ne 1) { throw 'CMD Help root manifest is not physically pinned.' }
            $null=Add-PortableEntryCmdFilePin -Binding $binding -Path $path -ExpectedPin $(if($pin.Count-eq1){$pin[0]}else{$null})
        }
        $marker=@($binding.Files|Where-Object Path -IEQ (Join-Path $profile.WorkRoot 'fixture-owner.txt'))[0]
        $expectedMarker=[Text.UTF8Encoding]::new($false).GetBytes('PortableEntry|'+[IO.Path]::GetFileName($profile.WorkRoot).Substring('portable-entry-'.Length))
        if ($marker.Bytes -ne $expectedMarker.Length -or $marker.Sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expectedMarker)).ToLowerInvariant()) { throw 'CMD Help fixture marker differs from its unique owner.' }
        $built=@($binding.Files|Where-Object Path -IEQ $profile.BuiltCandidatePath)[0]
        if ($built.Sha256 -cne $binding.Candidate.Sha256 -or $built.Bytes -ne $binding.Candidate.Stream.Length) { throw 'CMD Help intentional package build differs from its immutable candidate.' }
        Assert-PortableEntryCmdOrdinaryPath -Path $PackageRoot
        $archive=@($binding.Files|Where-Object Path -IEQ $profile.ArchivePath)[0]
        $zip=[IO.Compression.ZipArchive]::new($archive.Stream,[IO.Compression.ZipArchiveMode]::Read,$true)
        $memberNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        try {
            foreach ($entry in $zip.Entries) {
                $prefix=$policy.archiveRootName+'/'
                if (-not $entry.FullName.StartsWith($prefix,[StringComparison]::Ordinal) -or $entry.FullName.Contains('\') -or
                    -not $memberNames.Add($entry.FullName) -or $entry.FullName.EndsWith('/')) { throw 'CMD Help archive contains an unexpected or duplicate member.' }
                $relative=$entry.FullName.Substring($prefix.Length)
                $path=[IO.Path]::GetFullPath((Join-Path $PackageRoot $relative))
                if (-not $path.StartsWith($PackageRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'CMD Help archive member escapes the package.' }
                $pin=Add-PortableEntryCmdFilePin -Binding $binding -Path $path -ExpectedPin $null
                $entryStream=$entry.Open()
                try { $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($entryStream)).ToLowerInvariant() }
                finally { $entryStream.Dispose() }
                if ($hash -cne $pin.Sha256 -or $entry.Length -ne $pin.Bytes) { throw 'CMD Help extracted member differs from its held archive.' }
            }
        }
        finally { $zip.Dispose();$archive.Stream.Position=0 }
        foreach ($required in $policy.requiredPackagePaths) {
            if (-not $memberNames.Contains($policy.archiveRootName+'/'+$required)) { throw 'CMD Help archive omits a required package member.' }
        }
        $physical=[Collections.Generic.List[string]]::new();$stack=[Collections.Generic.Stack[string]]::new();$stack.Push($PackageRoot)
        while ($stack.Count) {
            $directory=$stack.Pop();Assert-PortableEntryCmdOrdinaryPath -Path $directory
            foreach ($file in [IO.Directory]::GetFiles($directory)) { $physical.Add($file) }
            foreach ($child in [IO.Directory]::GetDirectories($directory)) { Assert-PortableEntryCmdOrdinaryPath -Path $child;$stack.Push($child) }
        }
        if ($physical.Count -ne $memberNames.Count) { throw 'CMD Help extracted inventory contains missing or extra members.' }
        foreach ($path in $physical) {
            if (-not $memberNames.Contains($policy.archiveRootName+'/'+[IO.Path]::GetRelativePath($PackageRoot,$path).Replace('\','/'))) { throw 'CMD Help physical member is not in its held archive.' }
        }
        $app=@($binding.Files|Where-Object Path -IEQ (Join-Path $PackageRoot 'WIN-PCInfo.ps1'))[0]
        if ($app.Sha256 -cne $binding.Candidate.Sha256 -or $app.Bytes -ne $binding.Candidate.Stream.Length) { throw 'CMD Help extracted application differs from the root candidate.' }
        $expected=@{ 'Start-WIN-PCInfo.ps1'=(Get-PortableBootstrapSourceBytes -RepositoryRoot $root);
            'Start-WIN-PCInfo.cmd'=(ConvertTo-PortableScriptBytes -Text ([IO.File]::ReadAllText((Join-Path $root 'build/Start-WIN-PCInfo.cmd')))) }
        foreach ($name in $expected.Keys) {
            $pin=@($binding.Files|Where-Object Path -IEQ (Join-Path $PackageRoot $name))[0]
            if ($pin.Bytes -ne $expected[$name].Length -or $pin.Sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$expected[$name])).ToLowerInvariant()) { throw 'CMD Help launcher differs from the actual pinned builder.' }
        }
        $binding.Record=[ordered]@{contract='win-pcinfo.portable-entry-cmd-native/1.0.0';testPath=$testPath;
            parentPendingCanonicalSha256=(Get-TestNativeDigest -Value $context.Parent.Pending);rootCohortSha256=$admission.cohortSha256;
            profile=$profile;physicalInputs=@($binding.Files|ForEach-Object{[ordered]@{path=$_.Path;sha256=$_.Sha256;bytes=$_.Bytes}});
            rootCandidate=[ordered]@{path=$binding.Candidate.Path;sha256=$binding.Candidate.Sha256;bytes=$binding.Candidate.Stream.Length};
            preparedManifestPath=$admission.preparedManifestPath;preparedManifestSha256=$admission.preparedManifestSha256;
            configuredOutputCodePageUnknown=$true;rawPipeByteRetentionClaim=$false;processTreeAbsenceClaim=$false}
        $binding
    }
    catch { Complete-PortableEntryCmdBinding -Binding $binding -BodyError $_ }
}

function Assert-PortableEntryCmdConfiguredOwner {
    param([Parameter(Mandatory)] $Identity,[Parameter(Mandatory)] $Binding)
    # Factory configuration is checked before durable ownership or Start. This
    # closes any WINDIR change between held executable binding and construction.
    if ($Identity.Started -isnot [bool] -or $Identity.Started -or
        $Identity.HostPath -isnot [string] -or $Identity.HostPath -ine $Binding.Profile.HostPath -or
        $Identity.RawArguments -isnot [string] -or $Identity.RawArguments -cne $Binding.Profile.RawArguments -or
        $Identity.ArgumentMode -cne 'RawCmdHelp' -or @($Identity.Arguments).Count -ne 0 -or
        $Identity.WorkingDirectory -cne '' -or $Identity.WorkingDirectoryMode -cne 'Inherited' -or
        $Identity.RedirectStandardInput -isnot [bool] -or $Identity.RedirectStandardInput -or
        $Identity.UseShellExecute -isnot [bool] -or $Identity.UseShellExecute -or
        $Identity.CreateNoWindow -isnot [bool] -or $Identity.CreateNoWindow -or
        $Identity.StdoutRedirected -isnot [bool] -or -not $Identity.StdoutRedirected -or
        $Identity.StderrRedirected -isnot [bool] -or -not $Identity.StderrRedirected -or
        $Identity.EnvironmentMode -cne 'Inherited' -or $Identity.OutputDecoding -cne 'ProcessDefaultReader' -or
        $Identity.ConfiguredOutputCodePage -isnot [int] -or $Identity.ConfiguredOutputCodePage -ne 0 -or
        $Identity.TextEvidenceRepresentation -cne 'DecodedTextReencodedUtf8') { throw 'CMD Help factory configuration differs from its held closed profile.' }
}

function Invoke-PortableEntryCmdHelp {
    param([Parameter(Mandatory)] [string] $PackageRoot,[ValidateRange(1,60000)] [long] $TimeoutMs=60000)
    Invoke-GeneratedApplicationNative -HostPath (Join-Path $env:WINDIR 'System32/cmd.exe') `
        -WorkingDirectory ([Environment]::CurrentDirectory) -Arguments @('PortableEntryCmdHelp') `
        -PortableEntryCmdPackageRoot $PackageRoot -TimeoutMs $TimeoutMs -CleanupReserveMs 10000
}

function Assert-PortableEntryCmdAdmissionReady {
    $held=Get-Variable PortableEntryCmdUnverifiedBindings -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $held -and $held.Value.Count -gt 0) {
        $error=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: retained CMD ownership uncertainty blocks further native admission.')
        $error.Data['OwnedCleanupUnverified']=$true
        throw $error
    }
}

function Retain-PortableEntryCmdBinding {
    param([Parameter(Mandatory)] $Binding)
    if ($null -eq (Get-Variable PortableEntryCmdUnverifiedBindings -Scope Script -ErrorAction SilentlyContinue)) {
        $script:PortableEntryCmdUnverifiedBindings=[Collections.Generic.List[object]]::new()
    }
    if (-not $script:PortableEntryCmdUnverifiedBindings.Contains($Binding)) { $script:PortableEntryCmdUnverifiedBindings.Add($Binding) }
}
