Set-StrictMode -Version Latest

# Only these reviewed, child-free policy/schema leaves may share File hosts.
# A changed leaf needs a new isolation review rather than a filename exemption.
function Get-TestFilePairSelection {
    param([Parameter(Mandatory)] [object[]] $Inventory)
    $approved=@(
        @{file='GuidedRunwayPolicy.Tests.ps1'; bytes=4262; sha256='13ea3274b2afec0fba4875414b7383ebefccfe3b471bfa2ba775272494722a35'},
        @{file='RecipientSharingPolicy.Tests.ps1'; bytes=3247; sha256='952621be802c5aa77c313f50052630f21ffd84fac4815b8749c2d10815bb4de8'}
    )
    foreach ($pin in $approved) {
        $matches=@($Inventory | Where-Object file -CEQ $pin.file)
        if ($matches.Count -ne 1 -or $matches[0].sha256 -cne $pin.sha256 -or $matches[0].bytes -ne $pin.bytes) {
            throw 'Reviewed File pair differs from its exact two-member source inventory.'
        }
        $matches[0]
    }
}

function Copy-TestFilePairAdmissionCore {
    param([Parameter(Mandatory)] $Admission)
    $copy=[ordered]@{}
    $names=if ($Admission -is [Collections.IDictionary]) { @($Admission.Keys) } else { @($Admission.PSObject.Properties.Name) }
    foreach ($name in $names) {
        if ($name -cne 'filePair') { $copy[$name]=Get-TestRecordOptionalProperty -Record $Admission -Name $name }
    }
    $copy
}

function Get-TestFilePairPin {
    param([Parameter(Mandatory)] [string] $Path)
    # Validate ancestors as well as the record; a nonce alone is no authority.
    for ($part=[IO.Path]::GetFullPath($Path); -not [string]::IsNullOrEmpty($part); $part=[IO.Path]::GetDirectoryName($part)) {
        $item=Get-Item -LiteralPath $part -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'File pair input or ancestor is redirected.' }
    }
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt 4MB) { throw 'File pair requires a bounded ordinary record.' }
    [pscustomobject]@{path=$item.FullName; bytes=$item.Length; sha256=(Get-FileHash -LiteralPath $item.FullName).Hash.ToLowerInvariant()}
}

function Assert-TestFilePairIdentity {
    param([Parameter(Mandatory)] $Actual, [Parameter(Mandatory)] $Expected)
    if ($Actual.Pid -ne $Expected.Pid -or $Actual.CreationUtc -cne $Expected.CreationUtc -or
        $Actual.OwnerSid -cne $Expected.OwnerSid -or $Actual.HostPath -ine $Expected.HostPath) {
        throw 'File pair coordinator lifetime differs from its original identity.'
    }
}

function Read-TestFilePairBinding {
    param([Parameter(Mandatory)] $Reference, [Parameter(Mandatory)] $Admission,
        [Parameter(Mandatory)] $CoordinatorIdentity, [DateTimeOffset] $Now=[DateTimeOffset]::UtcNow,
        [switch] $ForFinalization)
    $pin=Get-TestFilePairPin -Path $Reference.path
    if ($pin.sha256 -cne $Reference.sha256 -or $pin.bytes -ne $Reference.bytes) { throw 'File pair descriptor changed.' }
    $record=Read-TestNativeRecord -Path $pin.path
    $root=[IO.Path]::GetFullPath($Admission.repositoryRoot)
    $directory=Join-Path $root ('.test-output/file-pair-native/'+$record.nonce)
    if ($record.contract -cne 'win-pcinfo.test-file-pair/1.0.0' -or $record.nonce -cnotmatch '^[a-f0-9]{32}$' -or
        $pin.path -ine (Join-Path $directory 'descriptor.json') -or $record.repositoryRoot -ine $root -or
        $record.members.Count -ne 2 -or $record.cohortSha256 -cne $Admission.cohortSha256 -or
        $record.suiteEvidenceRoot -ine $Admission.suiteEvidenceRoot) { throw 'File pair descriptor scope differs.' }
    $inventory=Read-TestNativeRecord -Path $Admission.inventoryPath
    $memberEnd=[DateTimeOffset]::Parse($record.authorityEnds)
    $coordinationEnd=[DateTimeOffset]::Parse($record.coordinationEnds)
    if ($coordinationEnd -ne [DateTimeOffset]::Parse($inventory.authorityEnds) -or
        $memberEnd.AddMilliseconds(2*$record.cleanupReserveMs+10000) -gt $coordinationEnd -or
        $Now -ge $(if ($ForFinalization) {$coordinationEnd} else {$memberEnd})) { throw 'File pair fixed authority or joint finalization reservation differs.' }
    Assert-TestFilePairIdentity -Actual $CoordinatorIdentity -Expected $record.parent
    $ordered=@(Get-TestFilePairSelection -Inventory @($record.members))
    if (($ordered.file -join '|') -cne ($record.members.file -join '|')) { throw 'File pair members are not in their reviewed order.' }
    $nonces=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($member in $record.members) {
        if ($member.nonce -cnotmatch '^[a-f0-9]{32}$' -or -not $nonces.Add($member.nonce) -or
            $member.path -ine (Join-Path $root ('tests/'+$member.file)) -or
            $member.admissionCoreSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'File pair member is malformed or duplicated.' }
    }
    $selected=@($record.members | Where-Object nonce -CEQ $Reference.memberNonce)
    if ($selected.Count -ne 1 -or $selected[0].path -ine $Admission.testPath -or
        $selected[0].sha256 -cne $Admission.testSha256 -or
        $selected[0].admissionCoreSha256 -cne (Get-TestNativeDigest -Value (Copy-TestFilePairAdmissionCore -Admission $Admission))) {
        throw 'File pair capability cannot change its member or admission.'
    }
    $pendingPin=Get-TestFilePairPin -Path (Join-Path $directory 'owned-pending.json')
    if ($pendingPin.sha256 -cne $Reference.pendingSha256) { throw 'File pair coordinator ownership changed or was released.' }
    $pending=Read-TestNativeRecord -Path $pendingPin.path
    if ($pending.contract -cne 'win-pcinfo.test-file-pair-owned/1.0.0' -or $pending.descriptorSha256 -cne $pin.sha256) {
        throw 'File pair coordinator ownership is not bound to its descriptor.'
    }
    Assert-TestFilePairIdentity -Actual $pending.parent -Expected $record.parent
    [pscustomobject]@{Record=$record; Reference=$Reference; Directory=$directory; PendingPath=$pendingPin.path;
        LockPath=(Join-Path $directory 'coordination.lock'); Member=$selected[0]}
}

function Enter-TestFilePairLock {
    param([Parameter(Mandatory)] $Binding, [switch] $Finalizing)
    for ($part=$Binding.LockPath; -not [string]::IsNullOrEmpty($part); $part=[IO.Path]::GetDirectoryName($part)) {
        $item=Get-Item -LiteralPath $part -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'File pair lock path is redirected.' }
    }
    $item=Get-Item -LiteralPath $Binding.LockPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -ne 0) { throw 'File pair lock is not its ordinary empty file.' }
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $end=if ($Finalizing) {[DateTimeOffset]::Parse($Binding.Record.coordinationEnds)} else {
        [DateTimeOffset]::Parse($Binding.Record.authorityEnds).AddMilliseconds(-$Binding.Record.cleanupReserveMs)
    }
    while ($watch.ElapsedMilliseconds -lt 10000 -and [DateTimeOffset]::UtcNow -lt $end) {
        try { return [IO.File]::Open($Binding.LockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
        catch [IO.IOException] {
            # Only a sharing violation may mean another admitted peer owns it.
            if (($_.Exception.HResult -band 0xffff) -notin @(32,33)) { throw }
            Start-Sleep -Milliseconds 20
        }
    }
    throw 'File pair lock could not be acquired within its original finite reservation.'
}

function Assert-TestFilePairOwnershipLocked {
    param([Parameter(Mandatory)] $Binding)
    $allowed=[Collections.Generic.List[string]]::new()
    foreach ($member in $Binding.Record.members) {
        $directory=Join-Path $Binding.Record.repositoryRoot ('.test-output/test-file-native/'+$member.nonce)
        $armedPath=Join-Path $Binding.Directory ($member.nonce+'.armed.json')
        $exists=[IO.Directory]::Exists($directory)
        if (-not [IO.File]::Exists($armedPath)) {
            if ($exists -or [IO.Directory]::Exists($armedPath)) { throw 'Unarmed File pair member output already exists.' }
            continue
        }
        $armed=Read-TestNativeRecord -Path $armedPath
        if ($armed.nonce -cne $member.nonce -or $armed.descriptorSha256 -cne $Binding.Reference.sha256 -or
            $armed.admissionCoreSha256 -cne $member.admissionCoreSha256) { throw 'File pair armed membership changed.' }
        $pendingPath=Join-Path $directory 'owned-pending.json'
        $pendingPin=Get-TestFilePairPin -Path $pendingPath
        $pending=Read-TestNativeRecord -Path $pendingPath
        $startupPath=Join-Path $directory 'startup.json'
        $startupPin=Get-TestFilePairPin -Path $startupPath
        $startup=Read-TestNativeRecord -Path $startupPath
        $ack=Read-TestNativeRecord -Path (Join-Path $directory 'startup-ack.json')
        if ($pending.contract -cne 'win-pcinfo.test-owned-native/1.0.0' -or $pending.nonce -cne $member.nonce -or $pending.nativeRole -cne 'TestFile' -or
            $pending.childCreationRequested -isnot [bool] -or -not $pending.childCreationRequested -or
            $pending.child.Started -isnot [bool] -or -not $pending.child.Started -or
            $pending.child.ExactStartedProcessHandlePinned -isnot [bool] -or -not $pending.child.ExactStartedProcessHandlePinned -or
            ($pending.child.Pid -isnot [int] -and $pending.child.Pid -isnot [long]) -or $pending.child.Pid -lt 1 -or
            $pending.child.OwnerSid -cne $Binding.Record.parent.OwnerSid -or $pending.child.HostPath -ine $pending.admission.hostPath -or
            $pending.child.CreationUtc -isnot [string] -or [string]::IsNullOrEmpty($pending.child.CreationUtc) -or
            -not [string]::IsNullOrEmpty($pending.child.ObservationFailure) -or
            $pending.timeoutMs -ne $Binding.Record.timeoutMs -or $pending.cleanupReserveMs -ne $Binding.Record.cleanupReserveMs -or
            $pending.authorityEnds -cne $Binding.Record.authorityEnds -or
            (Get-TestNativeDigest -Value $pending) -cne (Get-TestNativeDigest -Value $startup) -or
            $ack.contract -cne 'win-pcinfo.test-file-startup/1.0.0' -or $ack.nonce -cne $member.nonce -or
            $ack.directory -ine $directory -or $ack.pendingSha256 -cne $pendingPin.sha256 -or
            $ack.startupSha256 -cne $startupPin.sha256 -or
            $ack.admissionSha256 -cne (Get-TestNativeDigest -Value $pending.admission) -or
            $member.admissionCoreSha256 -cne (Get-TestNativeDigest -Value (Copy-TestFilePairAdmissionCore -Admission $pending.admission))) {
            throw 'File pair peer ownership/startup/acknowledgement differs from original admission.'
        }
        Assert-TestFilePairIdentity -Actual $pending.parent -Expected $Binding.Record.parent
        $peerReference=$pending.admission.filePair
        if ($peerReference.path -ine $Binding.Reference.path -or $peerReference.sha256 -cne $Binding.Reference.sha256 -or
            $peerReference.pendingSha256 -cne $Binding.Reference.pendingSha256 -or $peerReference.memberNonce -cne $member.nonce) {
            throw 'File pair peer capability differs from its coordinator.'
        }
        $allowed.Add($pendingPath)
    }
    $allowed.ToArray()
}

function Assert-TestFilePairCoordinatorReady {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [AllowNull()] $Binding)
    Assert-GeneratedApplicationNativeReady -EvidenceParent (Join-Path $RepositoryRoot '.test-output/file-pair-native') `
        -AllowedPendingPath $(if ($null -ne $Binding) {$Binding.PendingPath})
}

function New-TestFilePairContext {
    param([Parameter(Mandatory)] [object[]] $Admissions, [Parameter(Mandatory)] [DateTimeOffset] $AuthorityEnds,
        [Parameter(Mandatory)] [long] $TimeoutMs, [Parameter(Mandatory)] [long] $CleanupReserveMs)
    if ($Admissions.Count -ne 2 -or -not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_FILE_LEASE) -or
        -not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_CASE_LEASE)) { throw 'Only a nondelegated suite may coordinate a File pair.' }
    $rows=@(foreach ($admission in $Admissions) {
        $testPath=$admission.testPath
        $pin=@($admission.inputs | Where-Object path -IEQ $testPath)
        if ($pin.Count -ne 1) { throw 'File pair admission omits its exact source pin.' }
        [pscustomobject]@{file=[IO.Path]::GetFileName($testPath); path=$testPath; bytes=$pin[0].bytes; sha256=$admission.testSha256}
    })
    $ordered=@(Get-TestFilePairSelection -Inventory $rows)
    if (($ordered.file -join '|') -cne ($rows.file -join '|')) { throw 'File pair admissions are not in their reviewed order.' }
    $root=$Admissions[0].repositoryRoot
    Assert-TestNativeRoleReady -NativeRole TestFile -RepositoryRoot $root
    foreach ($admission in $Admissions) {
        Assert-TestFileAdmissionInputs -Admission $admission
        if ($admission.repositoryRoot -ine $root -or $admission.cohortSha256 -cne $Admissions[0].cohortSha256 -or
            $admission.suiteEvidenceRoot -ine $Admissions[0].suiteEvidenceRoot -or
            $null -ne (Get-TestRecordOptionalProperty -Record $admission -Name filePair)) { throw 'File pair requires one unchanged suite cohort.' }
    }
    $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $AuthorityEnds
    $inventory=Read-TestNativeRecord -Path $Admissions[0].inventoryPath
    $coordinationEnd=[DateTimeOffset]::Parse($inventory.authorityEnds)
    if (($budget.AuthorityEnds-[DateTimeOffset]::UtcNow).TotalMilliseconds -lt (2*$CleanupReserveMs+10000)) {
        throw 'File pair lacks both finalization reservations before its fixed end.'
    }
    if ($budget.AuthorityEnds.AddMilliseconds(2*$CleanupReserveMs+10000) -gt $coordinationEnd) {
        throw 'File pair finalization cannot fit inside the original suite cleanup authority.'
    }
    $nonce=[guid]::NewGuid().ToString('N')
    $directory=Join-Path $root ('.test-output/file-pair-native/'+$nonce)
    $null=[IO.Directory]::CreateDirectory((Split-Path $directory))
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    $null=Set-TestNativePrivateDirectory -Path $directory
    $parent=Get-TestNativeSelfIdentity
    $members=@(for ($index=0; $index -lt 2; $index++) {
        [ordered]@{file=$rows[$index].file; path=$rows[$index].path; bytes=$rows[$index].bytes; sha256=$rows[$index].sha256;
            nonce=[guid]::NewGuid().ToString('N'); admissionCoreSha256=(Get-TestNativeDigest -Value $Admissions[$index])}
    })
    $descriptor=[ordered]@{contract='win-pcinfo.test-file-pair/1.0.0'; nonce=$nonce; repositoryRoot=$root;
        suiteEvidenceRoot=$Admissions[0].suiteEvidenceRoot; cohortSha256=$Admissions[0].cohortSha256; parent=$parent;
        authorityEnds=$budget.AuthorityEnds.ToString('o'); coordinationEnds=$coordinationEnd.ToString('o');
        timeoutMs=$TimeoutMs; cleanupReserveMs=$CleanupReserveMs; members=$members}
    $descriptorPath=Join-Path $directory 'descriptor.json'
    Write-TestNativeNewRecord -Path $descriptorPath -Value $descriptor
    $pin=Get-TestFilePairPin -Path $descriptorPath
    $lock=[IO.File]::Open((Join-Path $directory 'coordination.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $lock.Dispose()
    $pendingPath=Join-Path $directory 'owned-pending.json'
    Write-TestNativeNewRecord -Path $pendingPath -Value ([ordered]@{contract='win-pcinfo.test-file-pair-owned/1.0.0';
        descriptorSha256=$pin.sha256; parent=$parent})
    $pendingPin=Get-TestFilePairPin -Path $pendingPath
    $references=@(foreach ($member in $members) {
        [pscustomobject]@{path=$pin.path; bytes=$pin.bytes; sha256=$pin.sha256; pendingSha256=$pendingPin.sha256; memberNonce=$member.nonce}
    })
    # Retain the original descriptor read handle until both members are finalized.
    $held=[IO.File]::Open($pin.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $heldHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($held)).ToLowerInvariant()
    $held.Position=0
    if ($heldHash -cne $pin.sha256 -or $held.Length -ne $pin.bytes) { $held.Dispose(); throw 'Original File pair descriptor stream differs from its admitted pin.' }
    [pscustomobject]@{Directory=$directory; Descriptor=$descriptor; DescriptorPin=$pin; DescriptorStream=$held; DescriptorHandle=$held.SafeFileHandle;
        PendingPin=$pendingPin; References=$references; Admissions=$Admissions; OutcomePin=$null; OverlapPin=$null; Closed=$false}
}

function Enter-TestFilePairMemberStartup {
    param([Parameter(Mandatory)] $Binding)
    $lock=Enter-TestFilePairLock -Binding $Binding
    try {
        $allowed=@(Assert-TestFilePairOwnershipLocked -Binding $Binding)
        Assert-TestFilePairCoordinatorReady -RepositoryRoot $Binding.Record.repositoryRoot -Binding $Binding
        Assert-GeneratedApplicationNativeReady -EvidenceParent (Join-Path $Binding.Record.repositoryRoot '.test-output/test-file-native') -AllowedPendingPaths $allowed
        Write-TestNativeNewRecord -Path (Join-Path $Binding.Directory ($Binding.Member.nonce+'.armed.json')) -Value ([ordered]@{
            nonce=$Binding.Member.nonce; descriptorSha256=$Binding.Reference.sha256;
            admissionCoreSha256=$Binding.Member.admissionCoreSha256})
        $lock
    }
    catch { $lock.Dispose(); throw }
}

function Save-TestFilePairMember {
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [int] $Index,
        [AllowNull()] $Value, [AllowNull()] [Management.Automation.ErrorRecord] $Failure)
    $admission=$Context.Admissions[$Index]
    if ($null -ne $Failure) {
        $native=$Failure.Exception.Data['OriginalNativeOutcome']
        $row=[ordered]@{file=[IO.Path]::GetFileName($admission.testPath); sha256=$admission.testSha256; result='Fail';
            elapsedMilliseconds=0; completed=$false; cleanupVerified=$false;
            nativeExitCode=$(if ($null -ne $native -and $native.NativeTerminalObserved) {$native.NativeExitCode} else {$null});
            nativeEvidence=$Failure.Exception.Data['NativeEvidenceDirectory']; failure=$Failure.Exception.Message}
        $record=[ordered]@{row=$row; native=$native; error=$Failure.Exception.Message}
    }
    else { $row=$Value.Row; $record=[ordered]@{row=$row; native=$Value.Native; error=$null} }
    $path=Join-Path $Context.Directory ($Context.Descriptor.members[$Index].nonce+'.result.json')
    $result=[pscustomobject]@{Row=$row; Native=$(if ($null -ne $Value) {$Value.Native} else {$null}); Pin=$null}
    try {
        Write-TestNativeNewRecord -Path $path -Value $record
        $result.Pin=Get-TestFilePairPin -Path $path
    }
    catch { $_.Exception.Data['OriginalPairMemberResult']=$result; throw }
    $result
}

function Save-TestFilePairOverlapObservation {
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] $FirstIdentity, [Parameter(Mandatory)] $SecondIdentity)
    $firstProcess=$null; $secondProcess=$null; $firstHandle=$null; $secondHandle=$null
    $observation=[ordered]@{contract='win-pcinfo.test-file-pair-overlap/1.0.0'; firstOriginalIdentity=$FirstIdentity;
        secondOriginalIdentity=$SecondIdentity; firstActiveBefore=$false; secondActive=$false; firstActiveAfter=$false;
        currentBirthAndHostMatched=$false; positiveCoexistence=$false; observationFailure=$null;
        ownerSidEvidence='Original native handle startup identities; current observation checks read-handle birth, host and active state.'}
    try {
        $firstProcess=[Diagnostics.Process]::GetProcessById($FirstIdentity.Pid)
        $firstHandle=$firstProcess.SafeHandle
        $secondProcess=[Diagnostics.Process]::GetProcessById($SecondIdentity.Pid)
        $secondHandle=$secondProcess.SafeHandle
        foreach ($pair in @(@($firstProcess,$FirstIdentity),@($secondProcess,$SecondIdentity))) {
            if ($pair[0].StartTime.ToUniversalTime().Ticks -ne [DateTime]::Parse($pair[1].CreationUtc).ToUniversalTime().Ticks -or
                $pair[0].MainModule.FileName -ine $pair[1].HostPath) { throw 'Current overlap observer cannot bind an original member lifetime.' }
        }
        $observation.currentBirthAndHostMatched=$true
        $observation.firstActiveBefore=(-not $firstProcess.HasExited)
        $observation.firstObservedAtUtc=[DateTimeOffset]::UtcNow.ToString('o')
        $observation.secondActive=(-not $secondProcess.HasExited)
        $observation.secondObservedAtUtc=[DateTimeOffset]::UtcNow.ToString('o')
        $firstProcess.Refresh()
        $observation.firstActiveAfter=(-not $firstProcess.HasExited)
        $observation.firstReobservedAtUtc=[DateTimeOffset]::UtcNow.ToString('o')
        $observation.positiveCoexistence=$observation.firstActiveBefore -and $observation.secondActive -and $observation.firstActiveAfter
    }
    catch { $observation.observationFailure=$_.Exception.Message }
    finally {
        if ($null -ne $firstProcess) { $firstProcess.Dispose() }
        if ($null -ne $secondProcess) { $secondProcess.Dispose() }
    }
    $observation.observerReadHandlesClosed=($null -eq $firstHandle -or $firstHandle.IsClosed) -and ($null -eq $secondHandle -or $secondHandle.IsClosed)
    if (-not $observation.observerReadHandlesClosed) { throw 'File pair overlap observer read handles remain open.' }
    $path=Join-Path $Context.Directory 'overlap-observation.json'
    Write-TestNativeNewRecord -Path $path -Value $observation
    $Context.OverlapPin=Get-TestFilePairPin -Path $path
}

function Complete-TestFilePairContext {
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [object[]] $Results)
    if ($Results.Count -ne 2 -or $Context.Closed -or $null -eq $Context.OutcomePin -or $null -eq $Context.OverlapPin) { throw 'File pair finalization requires exactly two retained original outcomes and observer record once.' }
    $firstAdmission=Copy-TestFilePairAdmissionCore -Admission $Context.Admissions[0]
    $firstAdmission.filePair=$Context.References[0]
    $binding=Read-TestFilePairBinding -Reference $Context.References[0] -Admission $firstAdmission -CoordinatorIdentity (Get-TestNativeSelfIdentity) -ForFinalization
    if ($Context.Directory -ine $binding.Directory -or (Get-TestNativeDigest -Value $Context.Descriptor) -cne (Get-TestNativeDigest -Value $binding.Record)) {
        throw 'Original File pair coordinator context differs from its held descriptor.'
    }
    $lock=Enter-TestFilePairLock -Binding $binding -Finalizing
    try {
        foreach ($receipt in @($Context.OutcomePin,$Context.OverlapPin)+@($Results | ForEach-Object Pin)) {
            if ($null -eq $receipt) { throw 'File pair original result receipt is missing.' }
            $physical=Get-TestFilePairPin -Path $receipt.path
            if ($physical.bytes -ne $receipt.bytes -or $physical.sha256 -cne $receipt.sha256) { throw 'File pair original result/observer receipt changed.' }
        }
        # Safe cleanup is independent of whether overlap was observed. Root's
        # separate concurrency certification must acquire a pinned positive
        # observation bound to both original lifetimes before full admission.
        $allowed=@(Assert-TestFilePairOwnershipLocked -Binding $binding)
        if ($allowed.Count -ne 2) { throw 'File pair finalization is missing an armed member.' }
        $archives=@(for ($index=0; $index -lt 2; $index++) {
            $result=$Results[$index]; $member=$Context.Descriptor.members[$index]
            if ($result.Row.file -cne $member.file -or $result.Row.sha256 -cne $member.sha256 -or
                -not $result.Row.completed -or -not $result.Row.cleanupVerified -or $null -eq $result.Native -or
                $result.Native.Nonce -cne $member.nonce -or $result.Native.PairHoldDisposition -cne 'AwaitingCoordinatorRelease' -or
                -not [string]::IsNullOrEmpty($result.Native.PairCallbackFailure)) {
                throw 'File pair original outcome or owned retention is incomplete.'
            }
            $directory=$result.Native.EvidenceDirectory
            $expectedDirectory=Join-Path $Context.Descriptor.repositoryRoot ('.test-output/test-file-native/'+$member.nonce)
            if ($directory -ine $expectedDirectory -or $null -eq $result.Native.PairReceiptPin) { throw 'File pair result is outside its original member output.' }
            $receiptPath=Join-Path $directory 'file-pair-member-retention.json'
            $receiptPin=Get-TestFilePairPin -Path $receiptPath
            if ($receiptPin.sha256 -cne $result.Native.PairReceiptPin.sha256 -or $receiptPin.bytes -ne $result.Native.PairReceiptPin.bytes) {
                throw 'Original File pair retention receipt changed.'
            }
            $retained=Read-TestNativeRecord -Path $receiptPath
            $pendingPath=Join-Path $directory 'owned-pending.json'
            $pin=Get-TestFilePairPin -Path $pendingPath
            if ($retained.nonce -cne $member.nonce -or -not $retained.originalOwnerDisposed -or
                $retained.descriptorSha256 -cne $Context.DescriptorPin.sha256 -or $retained.pendingSha256 -cne $pin.sha256 -or
                $retained.originalOutcomeSha256 -cne (Get-TestFilePairPin -Path (Join-Path $directory 'original-native-outcome.json')).sha256) {
                throw 'File pair member retention changed before joint release.'
            }
            foreach ($entry in @(@('file-result.json','completionSha256'),@('child-admission.claim','claimSha256'),
                @('startup-ack.json','ackSha256'),@('streams.jsonl','streamsSha256'),@('errors.json','errorsSha256'))) {
                if ((Get-TestFilePairPin -Path (Join-Path $directory $entry[0])).sha256 -cne $retained.($entry[1])) {
                    throw 'File pair originally confirmed completion, claim, acknowledgement or stream record changed.'
                }
            }
            $pending=Read-TestNativeRecord -Path $pendingPath
            $completion=Read-TestNativeRecord -Path (Join-Path $directory 'file-result.json')
            $original=Read-TestNativeRecord -Path (Join-Path $directory 'original-native-outcome.json')
            if ((Get-TestNativeDigest -Value $original.outcome) -cne (Get-TestNativeDigest -Value $result.Native.NativeOutcome)) {
                throw 'File pair supplied native outcome differs from the original retained outcome.'
            }
            Assert-TestFileCompletion -Completion $completion -Admission $pending.admission -Nonce $member.nonce -NativeOutcome $result.Native.NativeOutcome
            if ($result.Row.nativeExitCode -ne $result.Native.NativeOutcome.NativeExitCode -or $result.Row.result -cne $completion.result) {
                throw 'File pair canonical row differs from its actual completion and native exit.'
            }
            [pscustomobject]@{Original=$pin; Archive=(Join-Path $directory 'exact-pending-before-release.json')}
        })
        # Validate both first. Any failed copy/delete leaves the coordinator hold.
        foreach ($archive in $archives) {
            [IO.File]::Copy($archive.Original.path,$archive.Archive,$false)
            $pin=Get-TestFilePairPin -Path $archive.Archive
            if ($pin.sha256 -cne $archive.Original.sha256 -or $pin.bytes -ne $archive.Original.bytes) { throw 'File pair pending archive differs.' }
        }
        foreach ($archive in $archives) {
            [IO.File]::Delete($archive.Original.path)
            if ([IO.File]::Exists($archive.Original.path)) { throw 'File pair member hold could not be released.' }
        }
    }
    finally { $lock.Dispose() }
    $Context.DescriptorStream.Position=0
    $heldHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Context.DescriptorStream)).ToLowerInvariant()
    if ($heldHash -cne $Context.DescriptorPin.sha256 -or $Context.DescriptorStream.Length -ne $Context.DescriptorPin.bytes) { throw 'Held File pair descriptor changed during consumption.' }
    $Context.DescriptorStream.Dispose()
    if (-not $Context.DescriptorHandle.IsClosed) { throw 'Original File pair descriptor handle is not closed.' }
    Write-TestNativeNewRecord -Path (Join-Path $Context.Directory 'pair-finalization.json') -Value ([ordered]@{
        contract='win-pcinfo.test-file-pair-finalization/1.0.0'; descriptor=$Context.DescriptorPin;
        originalDescriptorHandleClosed=$true; outcomes=$Context.OutcomePin; overlap=$Context.OverlapPin;
        memberResults=@($Results | ForEach-Object Pin); memberArchives=$archives;
        atUtc=[DateTimeOffset]::UtcNow.ToString('o')})
    $archive=Join-Path $Context.Directory 'exact-pending-before-release.json'
    [IO.File]::Copy($Context.PendingPin.path,$archive,$false)
    if ((Get-TestFilePairPin -Path $archive).sha256 -cne $Context.PendingPin.sha256) { throw 'File pair coordinator archive differs.' }
    [IO.File]::Delete($Context.PendingPin.path)
    if ([IO.File]::Exists($Context.PendingPin.path)) { throw 'File pair coordinator hold remains.' }
    $Context.Closed=$true
}

function Invoke-TestFilePair {
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [scriptblock] $InvokeMember)
    $pairCoordinatorContext=$Context
    $pairCoordinatorState=[pscustomobject]@{Results=[object[]]::new(2); Failures=[Collections.Generic.List[Exception]]::new(); SecondInvoked=$false; FirstIdentity=$null}
    $afterAcknowledged={
        param($FirstEvidence,$FirstIdentity)
        if ($pairCoordinatorState.SecondInvoked) { throw 'File pair callback was already consumed.' }
        $pairCoordinatorState.SecondInvoked=$true
        $pairCoordinatorState.FirstIdentity=$FirstIdentity
        $observeSiblingStartup={
            param($SiblingEvidence,$SiblingIdentity)
            try { Save-TestFilePairOverlapObservation -Context $pairCoordinatorContext -FirstIdentity $pairCoordinatorState.FirstIdentity -SecondIdentity $SiblingIdentity }
            catch { $pairCoordinatorState.Failures.Add($_.Exception) }
        }
        $value=$null; $failure=$null
        try { $value=& $InvokeMember $pairCoordinatorContext.Admissions[1] $pairCoordinatorContext.References[1] $null $observeSiblingStartup }
        catch { $failure=$_ }
        try { $pairCoordinatorState.Results[1]=Save-TestFilePairMember -Context $pairCoordinatorContext -Index 1 -Value $value -Failure $failure }
        catch {
            $pairCoordinatorState.Results[1]=$_.Exception.Data['OriginalPairMemberResult']
            $pairCoordinatorState.Failures.Add($_.Exception)
        }
    }
    $value=$null; $failure=$null
    try { $value=& $InvokeMember $Context.Admissions[0] $Context.References[0] $afterAcknowledged $null }
    catch { $failure=$_ }
    try { $pairCoordinatorState.Results[0]=Save-TestFilePairMember -Context $Context -Index 0 -Value $value -Failure $failure }
    catch {
        $pairCoordinatorState.Results[0]=$_.Exception.Data['OriginalPairMemberResult']
        $pairCoordinatorState.Failures.Add($_.Exception)
    }
    try {
        $path=Join-Path $Context.Directory 'pair-original-outcomes.json'
        Write-TestNativeNewRecord -Path $path -Value ([ordered]@{contract='win-pcinfo.test-file-pair-outcomes/1.0.0';
            descriptor=$Context.DescriptorPin; secondInvoked=$pairCoordinatorState.SecondInvoked;
            members=$pairCoordinatorState.Results; overlap=$Context.OverlapPin;
            failures=@($pairCoordinatorState.Failures | ForEach-Object Message)})
        $Context.OutcomePin=Get-TestFilePairPin -Path $path
    }
    catch { $pairCoordinatorState.Failures.Add($_.Exception) }
    if ($pairCoordinatorState.Results[0] -and $pairCoordinatorState.Results[1] -and -not $pairCoordinatorState.Failures.Count) {
        try { Complete-TestFilePairContext -Context $Context -Results $pairCoordinatorState.Results }
        catch { $pairCoordinatorState.Failures.Add($_.Exception) }
    }
    if (-not $Context.Closed) {
        # A sibling's error never rewrites another original native outcome.
        # Keep the coordinator hold and original descriptor stream reachable.
        try {
            if ($null -eq (Get-Variable TestFilePairUnverifiedContexts -Scope Script -ErrorAction SilentlyContinue)) {
                $script:TestFilePairUnverifiedContexts=[Collections.Generic.List[object]]::new()
            }
            $script:TestFilePairUnverifiedContexts.Add($Context)
        }
        catch { $pairCoordinatorState.Failures.Add($_.Exception) }
        try {
            [IO.File]::WriteAllText((Join-Path $Context.Descriptor.repositoryRoot '.test-output/qualification-cleanup-blocked.json'),'{"state":"OwnedCleanupUnverified"}',[Text.UTF8Encoding]::new($false))
        }
        catch { $pairCoordinatorState.Failures.Add($_.Exception) }
    }
    $errorPin=$null
    if ($pairCoordinatorState.Failures.Count) {
        try {
            $errorPath=Join-Path $Context.Directory 'pair-coordination-errors.json'
            Write-TestNativeNewRecord -Path $errorPath -Value ([ordered]@{
                contract='win-pcinfo.test-file-pair-errors/1.0.0'; descriptor=$Context.DescriptorPin;
                failures=@($pairCoordinatorState.Failures | ForEach-Object Message)})
            $errorPin=Get-TestFilePairPin -Path $errorPath
        }
        catch { $pairCoordinatorState.Failures.Add($_.Exception) }
    }
    # Even failed error retention must return already executed members. The
    # coordinator hold remains durable and this Context keeps its handle reachable.
    [pscustomobject]@{Results=$pairCoordinatorState.Results; Stopped=(-not $Context.Closed); Failures=$pairCoordinatorState.Failures.ToArray(); ErrorPin=$errorPin; Context=$Context}
}
