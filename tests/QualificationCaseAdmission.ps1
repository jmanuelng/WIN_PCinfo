Set-StrictMode -Version Latest

function Get-TestRecordOptionalProperty {
    param([Parameter(Mandatory)] $Record, [Parameter(Mandatory)] [string] $Name)
    if ($Record -is [Collections.IDictionary]) { if ($Record.Contains($Name)) { return $Record[$Name] } }
    else { $property=$Record.PSObject.Properties[$Name]; if ($null -ne $property) { return $property.Value } }
    $null
}

function Read-FocusedTestRequest {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Sha256)
    if ($Sha256 -cnotmatch '^[a-f0-9]{64}$' -or -not [IO.Path]::IsPathFullyQualified($Path) -or
        (Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant() -cne $Sha256) { throw 'Focused request requires its exact absolute path and hash.' }
    $request=Read-TestNativeRecord -Path $Path
    $root=[IO.Path]::GetFullPath($RepositoryRoot)
    if ($request.contract -cne 'win-pcinfo.focused-test-request/1.0.0' -or $request.repositoryRoot -ine $root -or
        $request.scope -cnotin @('FocusedTestFile','FocusedSafetyDriver') -or
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($request.testPath)) -ine (Join-Path $root 'tests') -or
        ($request.scope -eq 'FocusedTestFile' -and [IO.Path]::GetFileName($request.testPath) -cnotlike '*.Tests.ps1') -or
        ($request.scope -eq 'FocusedSafetyDriver' -and [IO.Path]::GetFullPath($request.testPath) -ine (Join-Path $root 'tests/Invoke-AssessmentSafetyQualification.ps1')) -or
        $request.testSha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $request.testPath).Hash.ToLowerInvariant() -cne $request.testSha256) { throw 'Focused request differs from its enumerated scope or source pin.' }
    $named=ConvertFrom-TestNamedParameterRecord -Parameters $request.namedParameters
    Assert-TestNamedParameterRecord -Ast (Assert-TestFileExecutableProtocol -Path $request.testPath) -Parameters $named
    [pscustomobject]@{TestPath=$request.testPath; Scope=$request.scope; NamedParameters=$named; RequestPath=$Path; RequestSha256=$Sha256}
}

# These are tracked qualification leaves, not an arbitrary script/command
# delegation API. The ordinary script binder still enforces ValidateSet.
function Get-QualificationCaseProfile {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [string] $Path)
    $relative=[IO.Path]::GetRelativePath([IO.Path]::GetFullPath($RepositoryRoot),[IO.Path]::GetFullPath($Path)).Replace('\','/')
    $profiles=@{
        'tests/StatusDeskEngine.Tests.ps1'='OptionalSta'
        'tests/StatusDeskOpening.Tests.ps1'='NoSta'
        'tests/QualificationFixtureFinalizers.Tests.ps1'='NoSta'
        'tests/QualificationResourceBounds.ps1'='NoSta'
        'build/Build.ps1'='NoSta'
        'tests/StatusDeskChoices.Tests.ps1'='Sta'
        'tests/StatusDeskEntry.Tests.ps1'='OptionalSta'
        'tests/StatusDeskRecipientSelection.Tests.ps1'='Sta'
        'tests/StatusDeskViewing.Tests.ps1'='Sta'
        'tests/StatusDeskCleanupGate.Tests.ps1'='Sta'
        'tests/StatusDeskRecoveryCorrection.Tests.ps1'='Sta'
    }
    if (-not $profiles.ContainsKey($relative)) { throw 'Qualification leaf has no enumerated file profile.' }
    [pscustomobject]@{Path=[IO.Path]::GetFullPath($Path); RelativePath=$relative; Apartment=$profiles[$relative]}
}

function ConvertTo-TestNamedParameters {
    param([Parameter(Mandatory)] $Ast, [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Arguments)
    $declared=@{}
    if ($null -ne $Ast.ParamBlock) {
        foreach ($parameter in $Ast.ParamBlock.Parameters) { $declared[$parameter.Name.VariablePath.UserPath]=$parameter.StaticType }
    }
    $named=[ordered]@{}
    for ($index=0; $index -lt $Arguments.Count; $index++) {
        if ($Arguments[$index] -cnotmatch '^-(?<name>[A-Za-z][A-Za-z0-9]*)(?::(?<boolean>[Tt][Rr][Uu][Ee]|[Ff][Aa][Ll][Ss][Ee]))?$') { throw 'Qualification arguments require full declared named parameters.' }
        $name=$Matches['name']; $boolean=$Matches['boolean']
        if (-not $declared.ContainsKey($name) -or $named.Contains($name)) { throw 'Qualification parameter is unknown, abbreviated or duplicated.' }
        $type=$declared[$name]
        if ($type -eq [Management.Automation.SwitchParameter]) {
            $named[$name]=($boolean -ine 'false')
        }
        else {
            if (-not [string]::IsNullOrEmpty($boolean) -or $index+1 -ge $Arguments.Count) { throw 'Qualification scalar parameter has no value or an invalid Boolean suffix.' }
            $index++
            $value=$Arguments[$index]
            switch ($type.FullName) {
                'System.String' { $named[$name]=$value }
                'System.String[]' { $named[$name]=@($value) }
                'System.Int32' { $parsed=0; if (-not [int]::TryParse($value,[ref]$parsed)) { throw 'Qualification integer is malformed.' }; $named[$name]=$parsed }
                'System.Int64' { $parsed=0L; if (-not [long]::TryParse($value,[ref]$parsed)) { throw 'Qualification integer is malformed.' }; $named[$name]=$parsed }
                default { throw 'Qualification parameter type has no reviewed binding grammar.' }
            }
        }
    }
    $named
}

function ConvertTo-QualificationCaseInvocation {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [AllowEmptyString()] [string[]] $Arguments)
    if ($Arguments.Count -lt 4 -or $Arguments[0] -cne '-NoLogo' -or $Arguments[1] -cne '-NoProfile') { throw 'Qualification host flags differ from the closed file grammar.' }
    $fileIndex=2; $sta=$false
    if ($Arguments[$fileIndex] -ceq '-STA') { $sta=$true; $fileIndex++ }
    if ($Arguments.Count -le $fileIndex+1 -or $Arguments[$fileIndex] -cne '-File') { throw 'Qualification host requires one exact -File target; command forms are forbidden.' }
    $profile=Get-QualificationCaseProfile -RepositoryRoot $RepositoryRoot -Path $Arguments[$fileIndex+1]
    if (($profile.Apartment -eq 'Sta' -and -not $sta) -or ($profile.Apartment -eq 'NoSta' -and $sta)) { throw 'Qualification apartment differs from its enumerated profile.' }
    $ast=Assert-TestFileExecutableProtocol -Path $profile.Path
    $tail=if ($Arguments.Count -gt $fileIndex+2) {@($Arguments[($fileIndex+2)..($Arguments.Count-1)])} else {@()}
    $named=ConvertTo-TestNamedParameters -Ast $ast -Arguments $tail
    switch ($profile.RelativePath) {
        'build/Build.ps1' {
            if ($named.Count -ne 1 -or -not $named.Contains('OutputPath')) { throw 'Qualification build requires only an explicit unique output.' }
            Assert-QualificationCaseOutputPath -RepositoryRoot $RepositoryRoot -Path $named.OutputPath -ParentPattern '^candidate-[a-f0-9]{32}$' -FileName 'WIN-PCInfo.ps1'
        }
        'tests/QualificationResourceBounds.ps1' {
            if ($named.Count -ne 2 -or -not $named.Contains('Calibrate') -or -not $named.Calibrate -or -not $named.Contains('OutputPath')) { throw 'Qualification calibration requires its original explicit workload and output.' }
            Assert-QualificationCaseOutputPath -RepositoryRoot $RepositoryRoot -Path $named.OutputPath -ParentPattern '^resource-bounds-[a-f0-9]{32}$' -FileName 'calibration.json'
        }
        'tests/StatusDeskOpening.Tests.ps1' { if (-not $named.Contains('ColdProcess') -or -not $named.ColdProcess -or @($named.Keys | Where-Object { $_ -notin @('ColdProcess','EvidencePath','CandidatePath','PreparedManifestPath','PreparedManifestSha256') }).Count) { throw 'Qualification cold opening requires its recursion guard and closed prepared input interface.' } }
    }
    [pscustomobject]@{TestPath=$profile.Path; Sta=$sta; NamedParameters=$named; OriginalArguments=@($Arguments)}
}

function Assert-QualificationCaseOutputPath {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ParentPattern, [Parameter(Mandatory)] [string] $FileName)
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw 'Qualification output must be absolute.' }
    $parent=Split-Path ([IO.Path]::GetFullPath($Path))
    if ([IO.Path]::GetFileName($Path) -cne $FileName -or [IO.Path]::GetFileName($parent) -cnotmatch $ParentPattern -or
        [IO.Path]::GetDirectoryName($parent) -ine (Join-Path ([IO.Path]::GetFullPath($RepositoryRoot)) '.test-output')) { throw 'Qualification mutator output is outside its unique caller-owned boundary.' }
    foreach ($literal in @((Split-Path $parent),$parent)) {
        if (((Get-Item -LiteralPath $literal -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Qualification output directory is redirected.' }
    }
}

function Assert-TestNamedParameterRecord {
    param([Parameter(Mandatory)] $Ast, [Parameter(Mandatory)] $Parameters)
    if ($Parameters -isnot [Collections.IDictionary]) { throw 'Qualification named parameters must be a typed record.' }
    $declared=@{}
    if ($null -ne $Ast.ParamBlock) { foreach ($parameter in $Ast.ParamBlock.Parameters) { $declared[$parameter.Name.VariablePath.UserPath]=$parameter.StaticType } }
    foreach ($name in $Parameters.Keys) {
        if (-not $declared.ContainsKey($name)) { throw 'Qualification named parameter is not declared.' }
        $value=$Parameters[$name]; $type=$declared[$name]
        if ($type -eq [Management.Automation.SwitchParameter]) { if ($value -isnot [bool]) { throw 'Qualification switches require explicit Boolean values.' } }
        elseif ($type -eq [string]) { if ($value -isnot [string]) { throw 'Qualification scalar is not a string.' } }
        elseif ($type -eq [string[]]) { if ($value -isnot [array] -or @($value | Where-Object { $_ -isnot [string] }).Count) { throw 'Qualification array has an invalid shape.' } }
        elseif ($type -eq [int]) { if ($value -isnot [int] -and $value -isnot [long] -or $value -lt [int]::MinValue -or $value -gt [int]::MaxValue) { throw 'Qualification integer shape differs.' } }
        elseif ($type -eq [long]) { if ($value -isnot [int] -and $value -isnot [long]) { throw 'Qualification integer shape differs.' } }
        else { throw 'Qualification named type is not reviewed.' }
    }
}

function ConvertFrom-TestNamedParameterRecord {
    param([Parameter(Mandatory)] $Parameters)
    $named=[ordered]@{}
    if ($Parameters -is [Collections.IDictionary]) { foreach ($name in $Parameters.Keys) { $named[$name]=$Parameters[$name] } }
    elseif ($Parameters -is [pscustomobject]) { foreach ($property in $Parameters.PSObject.Properties) { $named[$property.Name]=$property.Value } }
    else { throw 'Qualification parameter record is not a named object.' }
    $named
}

function Read-QualificationCaseLease {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [string] $Nonce,
        [Parameter(Mandatory)] $SelfIdentity, [switch] $RequireClaim,
        [DateTimeOffset] $Now=[DateTimeOffset]::UtcNow, [int] $RemainingDepth=3)
    if ($RemainingDepth -lt 1 -or $Nonce -cnotmatch '^[a-f0-9]{32}$') { throw 'Qualification case nonce or bounded chain is malformed.' }
    $directory=Join-Path ([IO.Path]::GetFullPath($RepositoryRoot)) ('.test-output/qualification-case-native/'+$Nonce)
    foreach ($path in @((Split-Path $directory),$directory)) {
        if (((Get-Item -LiteralPath $path -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Qualification case lease cannot be redirected.' }
    }
    $pendingPath=Join-Path $directory 'owned-pending.json'; $ackPath=Join-Path $directory 'startup-ack.json'
    $pending=Read-TestNativeRecord -Path $pendingPath; $ack=Read-TestNativeRecord -Path $ackPath
    $startupPath=Join-Path $directory 'startup.json'; $startup=Read-TestNativeRecord -Path $startupPath
    $admission=$pending.admission
    if ($pending.nativeRole -cne 'QualificationCase' -or $pending.nonce -cne $Nonce -or
        $ack.contract -cne 'win-pcinfo.qualification-case-startup/1.0.0' -or $ack.nonce -cne $Nonce -or $ack.directory -ine $directory -or
        $ack.pendingSha256 -cne (Get-FileHash -LiteralPath $pendingPath).Hash.ToLowerInvariant() -or
        $ack.startupSha256 -cne (Get-FileHash -LiteralPath $startupPath).Hash.ToLowerInvariant() -or
        $ack.admissionSha256 -cne (Get-TestNativeDigest -Value $admission) -or
        (Get-TestNativeDigest -Value $startup) -cne (Get-TestNativeDigest -Value $pending) -or
        $pending.childCreationRequested -isnot [bool] -or -not $pending.childCreationRequested -or
        $pending.child.Started -isnot [bool] -or -not $pending.child.Started -or
        $pending.child.ExactStartedProcessHandlePinned -isnot [bool] -or -not $pending.child.ExactStartedProcessHandlePinned -or
        ($pending.child.Pid -isnot [long] -and $pending.child.Pid -isnot [int]) -or $pending.child.Pid -lt 1 -or
        -not [string]::IsNullOrEmpty($pending.child.ObservationFailure) -or
        $pending.child.Pid -ne $SelfIdentity.Pid -or $pending.child.CreationUtc -cne $SelfIdentity.CreationUtc -or
        $pending.child.OwnerSid -cne $SelfIdentity.OwnerSid -or $pending.child.HostPath -ine $SelfIdentity.HostPath -or
        [DateTimeOffset]::Parse($pending.authorityEnds) -le $Now) { throw 'Qualification case startup or exact current child differs.' }
    if ($admission.parentRole -eq 'TestFile') {
        $parent=Read-TestFileLease -RepositoryRoot $RepositoryRoot -Nonce $admission.parentNonce -SelfIdentity $pending.parent -RequireClaim -Now $Now
        $root=$parent; $parentDepth=0; $allowed=@()
    }
    elseif ($admission.parentRole -eq 'QualificationCase') {
        $parent=Read-QualificationCaseLease -RepositoryRoot $RepositoryRoot -Nonce $admission.parentNonce -SelfIdentity $pending.parent -RequireClaim -Now $Now -RemainingDepth ($RemainingDepth-1)
        $root=$parent.Root; $parentDepth=$parent.Admission.depth; $allowed=@($parent.AllowedCasePendingPaths)
    }
    else { throw 'Qualification case has no reviewed immediate parent role.' }
    Assert-QualificationCaseAdmission -Admission $admission -Parent $parent -Root $root -ParentDepth $parentDepth -AuthorityEnds ([DateTimeOffset]::Parse($pending.authorityEnds))
    if ($RequireClaim) {
        $claim=Read-TestNativeRecord -Path (Join-Path $directory 'child-admission.claim')
        if ($claim.contract -cne 'win-pcinfo.qualification-case-claim/1.0.0' -or $claim.nonce -cne $Nonce -or
            $claim.ackSha256 -cne (Get-FileHash -LiteralPath $ackPath).Hash.ToLowerInvariant() -or
            $claim.pid -ne $SelfIdentity.Pid -or $claim.creationUtc -cne $SelfIdentity.CreationUtc -or
            $claim.ownerSid -cne $SelfIdentity.OwnerSid) { throw 'Qualification one-use claim differs from its exact child.' }
    }
    [pscustomobject]@{Directory=$directory; PendingPath=$pendingPath; Pending=$pending; Admission=$admission; AckPath=$ackPath;
        Root=$root; AllowedCasePendingPaths=@($allowed)+@($pendingPath)}
}

function Assert-QualificationCaseAdmission {
    param([Parameter(Mandatory)] $Admission, [Parameter(Mandatory)] $Parent, [Parameter(Mandatory)] $Root,
        [int] $ParentDepth, [DateTimeOffset] $AuthorityEnds)
    $rootAdmission=$Root.Admission
    Assert-TestFileAdmissionInputs -Admission $rootAdmission
    if ($Admission.contract -cne 'win-pcinfo.qualification-case-admission/1.0.0' -or
        $Admission.depth -ne $ParentDepth+1 -or $Admission.depth -lt 1 -or $Admission.depth -gt 3 -or
        $Admission.rootNonce -cne $Root.Pending.nonce -or $Admission.cohortSha256 -cne $rootAdmission.cohortSha256 -or
        $Admission.parentNonce -cne $Parent.Pending.nonce -or $Admission.parentRole -cne $Parent.Pending.nativeRole -or
        $Admission.parentPendingSha256 -cne (Get-FileHash -LiteralPath $Parent.PendingPath).Hash.ToLowerInvariant() -or
        $Admission.parentClaimSha256 -cne (Get-FileHash -LiteralPath (Join-Path $Parent.Directory 'child-admission.claim')).Hash.ToLowerInvariant() -or
        $Admission.rootPendingSha256 -cne (Get-FileHash -LiteralPath $Root.PendingPath).Hash.ToLowerInvariant() -or
        $AuthorityEnds -gt [DateTimeOffset]::Parse($Parent.Pending.authorityEnds).AddMilliseconds(-$Parent.Pending.cleanupReserveMs-2000) -or
        $Admission.repositoryRoot -ine $rootAdmission.repositoryRoot -or $Admission.hostPath -ine $rootAdmission.hostPath -or
        $Admission.bootstrapPath -ine (Join-Path $rootAdmission.repositoryRoot 'tests/Invoke-QualificationCase.ps1')) { throw 'Qualification case changed its root cohort, immediate parent, depth or deadline.' }
    foreach ($path in @($Admission.testPath,$Admission.bootstrapPath)) {
        if (@($rootAdmission.inputs | Where-Object path -IEQ $path).Count -ne 1) { throw 'Qualification case executable is outside the root cohort.' }
    }
    $invocation=ConvertTo-QualificationCaseInvocation -RepositoryRoot $Admission.repositoryRoot -Arguments @($Admission.originalArguments)
    if ($invocation.TestPath -ine $Admission.testPath -or $invocation.Sta -ne $Admission.sta -or
        (Get-TestNativeDigest -Value $invocation.NamedParameters) -cne (Get-TestNativeDigest -Value $Admission.originalNamedParameters)) { throw 'Qualification original argv differs from its retained named binding.' }
    $parameters=ConvertTo-QualificationPreparedParameters -RootAdmission $rootAdmission -TestPath $Admission.testPath -Parameters $invocation.NamedParameters
    if ((Get-TestNativeDigest -Value $parameters) -cne (Get-TestNativeDigest -Value $Admission.namedParameters)) { throw 'Qualification prepared bindings differ from the immutable root input.' }
}

function ConvertTo-QualificationPreparedParameters {
    param([Parameter(Mandatory)] $RootAdmission, [Parameter(Mandatory)] [string] $TestPath,
        [Parameter(Mandatory)] $Parameters)
    $named=[ordered]@{}; foreach ($name in $Parameters.Keys) { $named[$name]=$Parameters[$name] }
    $ast=Assert-TestFileExecutableProtocol -Path $TestPath
    $names=if ($null -ne $ast.ParamBlock) {@($ast.ParamBlock.Parameters.Name.VariablePath.UserPath)} else {@()}
    $prepared=@('CandidatePath','PreparedManifestPath','PreparedManifestSha256')
    $count=@($prepared | Where-Object { $_ -in $names }).Count
    if ($count -ne 0 -and $count -ne 3) { throw 'Qualification leaf declares partial prepared input.' }
    $explicit=@($prepared | Where-Object { $named.Contains($_) }).Count
    if ($explicit -ne 0 -and ($explicit -ne 3 -or [string]::IsNullOrEmpty($RootAdmission.candidatePath))) { throw 'Qualification explicit prepared input must be complete and bound to its immutable root.' }
    if ($count -eq 3 -and -not [string]::IsNullOrEmpty($RootAdmission.candidatePath)) {
        $values=@($RootAdmission.candidatePath,$RootAdmission.preparedManifestPath,$RootAdmission.preparedManifestSha256)
        for ($index=0; $index -lt 3; $index++) {
            if ($named.Contains($prepared[$index]) -and $named[$prepared[$index]] -cne $values[$index]) { throw 'Qualification explicit prepared input differs from its root.' }
            $named[$prepared[$index]]=$values[$index]
        }
    }
    Assert-TestNamedParameterRecord -Ast $ast -Parameters $named
    $named
}

function Get-TestNativeAdmissionContext {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] $SelfIdentity,
        [DateTimeOffset] $Now=[DateTimeOffset]::UtcNow)
    if (-not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_CASE_LEASE)) {
        $case=Read-QualificationCaseLease -RepositoryRoot $RepositoryRoot -Nonce $env:WINPCINFO_TEST_CASE_LEASE -SelfIdentity $SelfIdentity -RequireClaim -Now $Now
        if ($env:WINPCINFO_TEST_FILE_LEASE -cne $case.Root.Pending.nonce) { throw 'Qualification current case lost its immutable file root.' }
        return [pscustomobject]@{Parent=$case; Root=$case.Root; Depth=$case.Admission.depth; AllowedCasePendingPaths=$case.AllowedCasePendingPaths}
    }
    if ([string]::IsNullOrEmpty($env:WINPCINFO_TEST_FILE_LEASE)) { throw 'Qualification requires a focused or full finite test-file entrypoint.' }
    $file=Read-TestFileLease -RepositoryRoot $RepositoryRoot -Nonce $env:WINPCINFO_TEST_FILE_LEASE -SelfIdentity $SelfIdentity -RequireClaim -Now $Now
    [pscustomobject]@{Parent=$file; Root=$file; Depth=0; AllowedCasePendingPaths=@()}
}

function Assert-QualificationCaseCompletion {
    param([Parameter(Mandatory)] $Completion, [Parameter(Mandatory)] $Admission,
        [Parameter(Mandatory)] [string] $Nonce, [Parameter(Mandatory)] $NativeOutcome)
    if ($Completion.contract -cne 'win-pcinfo.qualification-case-result/1.0.0' -or $Completion.nonce -cne $Nonce -or
        $Completion.admissionSha256 -cne (Get-TestNativeDigest -Value $Admission) -or
        $Completion.completed -isnot [bool] -or -not $Completion.completed -or
        $Completion.cleanupVerified -isnot [bool] -or -not $Completion.cleanupVerified -or
        $Completion.result -cnotin @('Pass','Fail') -or -not $NativeOutcome.NativeTerminalObserved -or
        $NativeOutcome.OwnedCleanupUnverified -or -not $NativeOutcome.StreamsDrained -or
        $NativeOutcome.StreamFailure -or $NativeOutcome.OutputOverflow -or
        ($Completion.result -eq 'Pass' -and $NativeOutcome.NativeExitCode -ne 0) -or
        ($Completion.result -eq 'Fail' -and $NativeOutcome.NativeExitCode -ne 1)) { throw 'Qualification completion does not match its original native outcome and admission.' }
}

function Confirm-QualificationCaseNativeRetention {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [string] $Directory,
        [Parameter(Mandatory)] [string] $Nonce, [Parameter(Mandatory)] $Admission,
        [Parameter(Mandatory)] $NativeIdentity, [AllowNull()] $NativeOutcome,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [Collections.Generic.List[Exception]] $Failures,
        [DateTimeOffset] $Now=[DateTimeOffset]::UtcNow)
    # The caller has already saved its actual in-memory native outcome. This
    # boundary only confirms child retention; it cannot synthesize an outcome,
    # release a hold or replace an original zero/nonzero/unknown result.
    try {
        $lease=Read-QualificationCaseLease -RepositoryRoot $RepositoryRoot -Nonce $Nonce -SelfIdentity $NativeIdentity -RequireClaim -Now $Now
        if ($Directory -ine $lease.Directory -or (Get-TestNativeDigest -Value $Admission) -cne (Get-TestNativeDigest -Value $lease.Admission)) { throw 'Qualification retained directory or admission differs from original ownership.' }
        $completion=Read-TestNativeRecord -Path (Join-Path $Directory 'case-result.json')
        Assert-QualificationCaseCompletion -Completion $completion -Admission $Admission -Nonce $Nonce -NativeOutcome $NativeOutcome
        $true
    }
    catch { $Failures.Add($_.Exception); $false }
}

function Confirm-TestFileNativeRetention {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [string] $Directory,
        [Parameter(Mandatory)] [string] $Nonce, [Parameter(Mandatory)] $Admission,
        [Parameter(Mandatory)] $NativeIdentity, [AllowNull()] $NativeOutcome,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [Collections.Generic.List[Exception]] $Failures,
        [DateTimeOffset] $Now=[DateTimeOffset]::UtcNow)
    try {
        $lease=Read-TestFileLease -RepositoryRoot $RepositoryRoot -Nonce $Nonce -SelfIdentity $NativeIdentity -RequireClaim -Now $Now
        if ($Directory -ine $lease.Directory -or (Get-TestNativeDigest -Value $Admission) -cne (Get-TestNativeDigest -Value $lease.Admission)) { throw 'Test file retained directory or admission differs from original ownership.' }
        $completion=Read-TestNativeRecord -Path (Join-Path $Directory 'file-result.json')
        Assert-TestFileCompletion -Completion $completion -Admission $Admission -Nonce $Nonce -NativeOutcome $NativeOutcome
        $true
    }
    catch { $Failures.Add($_.Exception); $false }
}

function Invoke-OwnedQualificationCase {
    param([Parameter(Mandatory)] [string] $HostPath, [Parameter(Mandatory)] [AllowEmptyString()] [string[]] $Arguments,
        [long] $TimeoutMs=3600000, [long] $CleanupReserveMs=10000,
        [DateTimeOffset] $AuthorityEnds=[DateTimeOffset]::MinValue)
    $repository=Split-Path -Parent $PSScriptRoot
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $repository -SelfIdentity (Get-TestNativeSelfIdentity)
    if ($context.Depth -ge 3) { throw 'Qualification case depth exceeds the reviewed three-level chain.' }
    $invocation=ConvertTo-QualificationCaseInvocation -RepositoryRoot $repository -Arguments $Arguments
    $parent=$context.Parent; $root=$context.Root
    $admission=[ordered]@{contract='win-pcinfo.qualification-case-admission/1.0.0'; repositoryRoot=$repository;
        testPath=$invocation.TestPath; bootstrapPath=(Join-Path $PSScriptRoot 'Invoke-QualificationCase.ps1'); hostPath=$HostPath;
        originalArguments=@($Arguments); originalNamedParameters=$invocation.NamedParameters; sta=$invocation.Sta;
        namedParameters=(ConvertTo-QualificationPreparedParameters -RootAdmission $root.Admission -TestPath $invocation.TestPath -Parameters $invocation.NamedParameters);
        parentRole=$parent.Pending.nativeRole; parentNonce=$parent.Pending.nonce; depth=$context.Depth+1;
        rootNonce=$root.Pending.nonce; cohortSha256=$root.Admission.cohortSha256;
        parentPendingSha256=(Get-FileHash -LiteralPath $parent.PendingPath).Hash.ToLowerInvariant();
        parentClaimSha256=(Get-FileHash -LiteralPath (Join-Path $parent.Directory 'child-admission.claim')).Hash.ToLowerInvariant();
        rootPendingSha256=(Get-FileHash -LiteralPath $root.PendingPath).Hash.ToLowerInvariant()}
    $parentEnd=[DateTimeOffset]::Parse($parent.Pending.authorityEnds).AddMilliseconds(-$parent.Pending.cleanupReserveMs-2000)
    if ($AuthorityEnds -eq [DateTimeOffset]::MinValue -or $parentEnd -lt $AuthorityEnds) { $AuthorityEnds=$parentEnd }
    $flags=@('-NoLogo','-NoProfile'); if ($invocation.Sta) { $flags+=@('-STA') }; $flags+=@('-File',$admission.bootstrapPath)
    $native=Invoke-GeneratedApplicationNative -NativeRole QualificationCase -QualificationCaseAdmission $admission -HostPath $HostPath -WorkingDirectory $repository -Arguments $flags -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $AuthorityEnds
    try {
        $completion=Read-TestNativeRecord -Path (Join-Path $native.EvidenceDirectory 'case-result.json')
        Assert-QualificationCaseCompletion -Completion $completion -Admission $admission -Nonce $native.Nonce -NativeOutcome $native.NativeOutcome
        Assert-QualificationCaseAdmission -Admission $admission -Parent $parent -Root $root -ParentDepth $context.Depth -AuthorityEnds $AuthorityEnds
    }
    catch {
        $_.Exception.Data['OwnedCleanupUnverified']=$true
        $_.Exception.Data['OriginalNativeOutcome']=$native.NativeOutcome
        $_.Exception.Data['NativeEvidenceDirectory']=$native.EvidenceDirectory
        try { [IO.File]::WriteAllText((Get-QualificationCleanupBlockerPath),'{"state":"OwnedCleanupUnverified"}',[Text.UTF8Encoding]::new($false)) } catch { }
        Write-Output 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'
        throw
    }
    $native
}

function Assert-TestFileCompletion {
    param([Parameter(Mandatory)] $Completion, [Parameter(Mandatory)] $Admission,
        [Parameter(Mandatory)] [string] $Nonce, [Parameter(Mandatory)] $NativeOutcome)
    if ($Completion.contract -cne 'win-pcinfo.test-file-result/1.0.0' -or $Completion.nonce -cne $Nonce -or
        $Completion.testPath -ine $Admission.testPath -or $Completion.testSha256 -cne $Admission.testSha256 -or
        $Completion.completed -isnot [bool] -or -not $Completion.completed -or
        $Completion.cleanupVerified -isnot [bool] -or -not $Completion.cleanupVerified -or
        $Completion.result -cnotin @('Pass','Fail') -or
        -not $NativeOutcome.NativeTerminalObserved -or $NativeOutcome.OwnedCleanupUnverified -or
        -not $NativeOutcome.StreamsDrained -or $NativeOutcome.StreamFailure -or $NativeOutcome.OutputOverflow -or
        ($Completion.result -eq 'Pass' -and $NativeOutcome.NativeExitCode -ne 0) -or
        ($Completion.result -eq 'Fail' -and $NativeOutcome.NativeExitCode -ne 1)) { throw 'Test file completion differs from its original native outcome or admission.' }
}
