Set-StrictMode -Version Latest
function Get-QualificationRecoveryFixtureSnapshot {
    param([Parameter(Mandatory)][string]$Destination,[Parameter(Mandatory)][string]$OwnedParent,
          [Parameter(Mandatory)][string]$InvocationId)
    $root=[IO.Path]::GetFullPath($Destination).TrimEnd('\')
    $boundary=[IO.Path]::GetFullPath($OwnedParent).TrimEnd('\')+'\'
    if(-not $root.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase) -or -not [IO.Directory]::Exists($root)){
        throw 'Recovery fixture snapshot requires an existing contained destination.'
    }
    $cursor=[IO.DirectoryInfo]::new($root)
    while($null -ne $cursor){
        if(([IO.File]::GetAttributes($cursor.FullName) -band [IO.FileAttributes]::ReparsePoint)-ne0){throw 'Recovery snapshot refuses reparse ancestors.'}
        $cursor=$cursor.Parent
    }
    $parent=[IO.Path]::GetDirectoryName($root)
    $parentIdentity=Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $parent
    $queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($root)
    $entries=[Collections.Generic.List[object]]::new();$bytes=0L
    while($queue.Count){
        $path=$queue.Dequeue()
        $attributes=[IO.File]::GetAttributes($path)
        if(($attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'Recovery snapshot refuses reparse entries.'}
        $identity=Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $path
        $directory=($attributes-band[IO.FileAttributes]::Directory)-ne0
        $item=Get-Item -LiteralPath $path -Force
        $entry=[ordered]@{relativePath=[IO.Path]::GetRelativePath($root,$path);directory=$directory;
            identity=$identity;attributes=[long]$attributes;creationTicks=$item.CreationTimeUtc.Ticks;lastWriteTicks=$item.LastWriteTimeUtc.Ticks;bytes=0L;sha256=''}
        if($directory){
            foreach($child in [IO.Directory]::EnumerateFileSystemEntries($path)){
                if($queue.Count+$entries.Count -ge 128){throw 'Recovery fixture entry bound exceeded.'}
                $queue.Enqueue($child)
            }
        }else{
            $stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try{
                # Verify the opened handle before reading: a path replacement
                # cannot redirect the hash to a different filesystem object.
                if((Get-EvidenceWorkspaceOwnedStreamIdentity -Stream $stream)-cne$identity){throw 'Recovery fixture open identity changed.'}
                $length=$stream.Length
                if($length -gt 1MB -or $bytes+$length -gt 1MB){throw 'Recovery fixture byte bound exceeded.'}
                $hash=[Security.Cryptography.SHA256]::Create()
                try{$entry.sha256=[Convert]::ToHexString($hash.ComputeHash($stream)).ToLowerInvariant()}finally{$hash.Dispose()}
                if($stream.Length-ne$length){throw 'Recovery fixture length changed.'}
                $entry.bytes=$length;$bytes+=$length
            }finally{$stream.Dispose()}
        }
        if((Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $path)-cne$identity -or
           [IO.File]::GetAttributes($path)-ne$attributes){throw 'Recovery fixture identity changed during snapshot.'}
        $entries.Add($entry)
        if($entries.Count -gt 128){throw 'Recovery fixture entry bound exceeded.'}
    }
    $orderedEntries=@($entries.ToArray()|Sort-Object relativePath -CaseSensitive)
    $content=[ordered]@{root=$root;parentIdentity=$parentIdentity;entries=$orderedEntries}
    [pscustomobject]@{kind='win-pcinfo.qualification-retained-recovery-fixture';invocationId=$InvocationId;
        capturedTimestamp=[Diagnostics.Stopwatch]::GetTimestamp();contentJson=($content|ConvertTo-Json -Depth 8 -Compress)}
}
function Test-QualificationRetainedRecoveryFixture {
    param($Snapshot,[long]$InvocationTimestamp,[string]$InvocationId,[string]$Destination,[string]$OwnedParent,
          [string]$ExpectedReason,[bool]$Authorized,$Session,$Terminal,$BodyError)
    if($null-ne$BodyError -or $null-eq$Snapshot -or $Snapshot.kind-cne'win-pcinfo.qualification-retained-recovery-fixture' -or
       $Snapshot.invocationId-cne$InvocationId -or $Snapshot.capturedTimestamp-isnot[long] -or
       $InvocationTimestamp-le0 -or $Snapshot.capturedTimestamp-gt$InvocationTimestamp){return $false}
    if($null-eq$Session -or $Session.Completed-isnot[bool] -or -not $Session.Completed -or
       $null-ne$Session.Worker -or $null-ne$Session.Runspace -or $null-ne$Session.Pending -or
       $null-eq$Session.PSObject.Properties['Finalization'] -or $null-ne$Session.Finalization.PrimaryError -or
       $Session.Finalization.WorkerDisposed-isnot[bool] -or -not $Session.Finalization.WorkerDisposed -or
       $Session.Finalization.RunspaceDisposed-isnot[bool] -or -not $Session.Finalization.RunspaceDisposed){return $false}
    $state=$Session.Transport.State
    if(-not $state.ContainsKey('CollectionStarted') -or $state.CollectionStarted-isnot[bool] -or $state.CollectionStarted -or
       -not $state.ContainsKey('PackagePath') -or $state.PackagePath-isnot[string] -or $state.PackagePath-cne''){return $false}
    foreach($flag in @('SystemInvoked','QualificationPrivilegeExecutionStarted','QualificationDeviceInvoked')){
        if($state.ContainsKey($flag) -and ($state[$flag]-isnot[bool] -or $state[$flag])){return $false}
    }
    if($Terminal-isnot[Collections.IDictionary] -or -not $Terminal.Contains('collectionStarted') -or
       $Terminal.collectionStarted-isnot[bool] -or $Terminal.collectionStarted -or
       -not $Terminal.Contains('reasonCode') -or $Terminal.reasonCode-isnot[string] -or
       $Terminal.cleanup.verified-isnot[bool] -or $Terminal.cleanup.verified -or
       $Session.ExitCode-isnot[int] -or -not $Terminal.Contains('exitCode') -or
       ($Terminal.exitCode-isnot[int] -and $Terminal.exitCode-isnot[long]) -or
       $Terminal.exitCode-ne$Session.ExitCode){return $false}
    $valid=if($ExpectedReason-ceq'RECOVERY.DELIBERATE_ACTION_REQUIRED'){
        -not $Authorized -and $Terminal.reasonCode-ceq$ExpectedReason -and $Terminal.outcome-ceq'NotStarted' -and $Session.ExitCode-eq20
    }elseif($ExpectedReason-ceq'RECOVERY.OWNERSHIP_UNVERIFIED'){
        $Authorized -and $Terminal.reasonCode-ceq$ExpectedReason -and $Terminal.outcome-ceq'CleanupIncomplete' -and $Session.ExitCode-eq60
    }else{$false}
    if(-not $valid){return $false}
    try{
        $current=Get-QualificationRecoveryFixtureSnapshot -Destination $Destination -OwnedParent $OwnedParent -InvocationId $InvocationId
        return [StringComparer]::Ordinal.Equals($Snapshot.contentJson,$current.contentJson)
    }catch{return $false}
}
