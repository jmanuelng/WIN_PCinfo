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
        [Parameter(Mandatory)] [string] $RepositoryRoot)
    $generated=Join-Path $RepositoryRoot '.test-output/generated-native'
    $testFiles=Join-Path $RepositoryRoot '.test-output/test-file-native'
    $cases=Join-Path $RepositoryRoot '.test-output/qualification-case-native'
    Assert-GeneratedApplicationNativeReady -EvidenceParent $generated
    $allowed=$null
    $allowedCases=@()
    if (-not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_FILE_LEASE) -or -not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_CASE_LEASE)) {
        if ($NativeRole -eq 'TestFile') { throw 'A test file lease cannot delegate another test file launch.' }
        $context=Get-TestNativeAdmissionContext -RepositoryRoot $RepositoryRoot -SelfIdentity (Get-TestNativeSelfIdentity)
        $allowed=$context.Root.PendingPath
        $allowedCases=@($context.AllowedCasePendingPaths)
    }
    elseif ($NativeRole -eq 'QualificationCase') { throw 'Qualification cases require an exact current file or case owner.' }
    Assert-GeneratedApplicationNativeReady -EvidenceParent $testFiles -AllowedPendingPath $allowed
    Assert-GeneratedApplicationNativeReady -EvidenceParent $cases -AllowedPendingPaths $allowedCases
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
        [AllowNull()] $TestFileAdmission, [AllowNull()] $QualificationCaseAdmission)

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
    Assert-TestNativeRoleReady -NativeRole $NativeRole -RepositoryRoot $repository
    $parent=Join-Path $outputRoot $(switch ($NativeRole) {'TestFile' {'test-file-native'} 'QualificationCase' {'qualification-case-native'} default {'generated-native'}})
    $nonce=[guid]::NewGuid().ToString('N')
    $admission=$null
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
    $owner=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new($HostPath,$WorkingDirectory,$Arguments,$StandardInput,
        $MaximumLines,$MaximumLineCharacters,$MaximumTotalCharacters)
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
        $pending.childCreationRequested=$true
        [IO.File]::WriteAllText($pendingPath,($pending | ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))
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
    # Natural nonzero exits are part of the existing negative-test contract.
    # Behavior assertions, including JSON parsing, run only after ownership is
    # retained and safely released. Their failure cannot erase native evidence.
    $stdout=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($outcome.Lines,'stdout')
    $stderr=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($outcome.Lines,'stderr')
    [pscustomobject]@{ExitCode=$outcome.NativeExitCode; StandardOutput=$stdout; StandardError=$stderr;
        EvidenceDirectory=$directory; NativeIdentity=$owner.StartedIdentity; NativeOutcome=$original.outcome; Nonce=$nonce;
        StreamRecords=$outcome.Lines}
}

. (Join-Path $PSScriptRoot 'QualificationCaseAdmission.ps1')
