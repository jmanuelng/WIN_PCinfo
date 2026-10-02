# Internal qualification observer. This does not turn an access denial into
# absence unless the exact previously observed owned path is proved gone.
function Get-QualificationWorkspaceNativeErrorCode {
    param([Parameter(Mandatory)][Exception]$Exception)
    $cursor=$Exception
    while($null -ne $cursor){
        if($cursor -is [ComponentModel.Win32Exception]){return $cursor.NativeErrorCode}
        $cursor=$cursor.InnerException
    }
    -1
}
function Register-QualificationWorkspaceDirectoryIdentities {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root,[AllowEmptyCollection()][object[]]$Files,
          [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.Dictionary[string,string]]$Known)
    $rootPath=[IO.Path]::GetFullPath($Root)
    $sampled=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($file in $Files){
        $cursor=[IO.Path]::GetDirectoryName([string]$file.FullName)
        $ancestors=[Collections.Generic.Stack[string]]::new()
        while($cursor -and ($cursor.Equals($rootPath,[StringComparison]::OrdinalIgnoreCase) -or
              $cursor.StartsWith($rootPath+'\',[StringComparison]::OrdinalIgnoreCase))){
            if($ancestors.Count -ge 64){throw 'QUALIFICATION.WORKSPACE_IDENTITY_BOUND_EXCEEDED'}
            $ancestors.Push($cursor)
            if($cursor.Equals($rootPath,[StringComparison]::OrdinalIgnoreCase)){break}
            $cursor=[IO.Path]::GetDirectoryName($cursor)
        }
        if($ancestors.Count -eq 0 -or -not $ancestors.Peek().Equals($rootPath,[StringComparison]::OrdinalIgnoreCase)){throw 'QUALIFICATION.WORKSPACE_IDENTITY_UNVERIFIED'}
        # Check root first before descending. Revalidate even cached names:
        # the first object's identity is immutable disappearance provenance.
        foreach($ancestor in $ancestors){
            if(-not $sampled.Add($ancestor)){continue}
            if(([IO.File]::GetAttributes($ancestor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'QUALIFICATION.WORKSPACE_REPARSE_REFUSED'}
            try{$identity=Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $ancestor}
            catch{
                $nativeCode=Get-QualificationWorkspaceNativeErrorCode -Exception $_.Exception
                if($nativeCode -in @(2,3)){
                    throw [IO.DirectoryNotFoundException]::new('Owned sample directory disappeared.')
                }
                if($nativeCode -eq 5){
                    $denial=[Management.Automation.ErrorRecord]::new(
                        [UnauthorizedAccessException]::new('Owned sample directory access denied.', $_.Exception),
                        'QualificationWorkspaceDirectoryAccessDenied',
                        [Management.Automation.ErrorCategory]::PermissionDenied,$ancestor)
                    $PSCmdlet.ThrowTerminatingError($denial)
                }
                throw
            }
            if($identity -cnotmatch '\A[0-9a-f]{8}:[0-9a-f]{8}:[0-9a-f]{8}\z'){throw 'QUALIFICATION.WORKSPACE_IDENTITY_UNVERIFIED'}
            if($Known.ContainsKey($ancestor)){
                if($Known[$ancestor] -cne $identity){throw 'QUALIFICATION.WORKSPACE_IDENTITY_CHANGED'}
            }else{
                if($Known.Count -ge 256){throw 'QUALIFICATION.WORKSPACE_IDENTITY_BOUND_EXCEEDED'}
                $Known.Add($ancestor,$identity)
            }
        }
    }
}
function Test-QualificationWorkspaceDirectoryDisappeared {
    param([Parameter(Mandatory)][Management.Automation.ErrorRecord]$Failure,
          [Parameter(Mandatory)][string]$Root,
          [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.Dictionary[string,string]]$Known)
    # All failed proof attempts return false so the caller rethrows the original
    # access-denial error. Missing is never inferred from Directory.Exists.
    try{
        if($Failure.TargetObject -isnot [string]){return $false}
        $path=[string]$Failure.TargetObject
        $rootPath=[IO.Path]::GetFullPath($Root)
        if($path -cnotmatch '\A[A-Za-z]:\\' -or $path.Substring(2).Contains(':') -or
           -not [IO.Path]::GetFullPath($path).Equals($path,[StringComparison]::OrdinalIgnoreCase) -or
           -not $path.StartsWith($rootPath+'\',[StringComparison]::OrdinalIgnoreCase) -or
           -not $Known.ContainsKey($path) -or -not $Known.ContainsKey($rootPath)){return $false}
        $parent=[IO.Path]::GetDirectoryName($path)
        if(-not $Known.ContainsKey($parent)){return $false}
        $ancestors=[Collections.Generic.Stack[string]]::new()
        $cursor=$parent
        while($cursor){
            if($ancestors.Count -ge 64){return $false}
            $ancestors.Push($cursor)
            if($cursor.Equals($rootPath,[StringComparison]::OrdinalIgnoreCase)){break}
            $cursor=[IO.Path]::GetDirectoryName($cursor)
            if(-not $cursor -or (-not $cursor.Equals($rootPath,[StringComparison]::OrdinalIgnoreCase) -and
               -not $cursor.StartsWith($rootPath+'\',[StringComparison]::OrdinalIgnoreCase))){return $false}
        }
        foreach($ancestor in $ancestors){
            if(([IO.File]::GetAttributes($ancestor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){return $false}
        }
        try{
            if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){return $false}
        }catch [IO.FileNotFoundException],[IO.DirectoryNotFoundException]{
            # This is preliminary only; native missing and parent absence
            # must still be independently proved below.
        }
        if((Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $rootPath) -cne $Known[$rootPath] -or
           (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $parent) -cne $Known[$parent]){return $false}
        $missing=$false
        try{$null=Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $path}
        catch{$missing=(Get-QualificationWorkspaceNativeErrorCode -Exception $_.Exception) -in @(2,3)}
        if(-not $missing){return $false}
        $entries=0
        foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($parent)){
            if(++$entries -gt 128 -or $entry.Equals($path,[StringComparison]::OrdinalIgnoreCase)){return $false}
        }
        if((Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $parent) -cne $Known[$parent] -or
           (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $rootPath) -cne $Known[$rootPath]){return $false}
        foreach($ancestor in $ancestors){
            if(([IO.File]::GetAttributes($ancestor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){return $false}
        }
        $true
    }
    catch{$false}
}
