# Internal offline init boundary. It supplies no Azure/live-round authority.
# Closed reviewed local sources, exclusive filesystem-mirror configuration,
# exact acquired pins and a read-only dependency lock prevent code acquisition.
# Unknown inputs refuse before process creation; attempted local initialization
# stays registered with the outer round until its own cleanup is independently proved.
function Get-AzureTerraformReviewedTemplateHashes {
    $table=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $reviewed=@{
        'examples/synthetic-round.tfvars.example'='b96b688874d63a177d5e13e1e0fa6d53c4eb758bbfc6208a2d55e9e6cfddb836'
        'main.tf'='ecb0608e2bbbb6d9687fe38ddd5b51680d14f76c7843294bb3fe03501990a74a'
        'modules/round-network/main.tf'='02565bf3495c6afa02a059e60bd55bc9e07894acfdf7d146d6d09b733be8bd67'
        'modules/round-network/outputs.tf'='f592374324cf57dc154017eb061ce602182a8f9508b4ff6f744c7bbd9bb1b214'
        'modules/round-network/variables.tf'='ec24d6062e610c25dde2c5ee32884a33ed7bcb98b76fa89363d7abb5f767339c'
        'modules/round-network/versions.tf'='9f2cea43b294b8965662f09491fd26e2c6b668697e328897c2c05dce4f6438b5'
        'modules/validation-client/main.tf'='17bd9d76e4dbcba930cea821035e12fd5afa2276817089f792a5ef32c7d1adc0'
        'modules/validation-client/outputs.tf'='4ee7078a87b709236b5204f215e878ce2e97bc318b7595ec2e0b993acd5d77be'
        'modules/validation-client/variables.tf'='c991a0f7567fa55e208226abe8c32ae5872c7fd078341f51f2f0f84a9e449be0'
        'modules/validation-client/versions.tf'='9f2cea43b294b8965662f09491fd26e2c6b668697e328897c2c05dce4f6438b5'
        'outputs.tf'='e95b3aaaa006ffad781f731be15eec3673e3999a7e47a2b9343b51c99ed3f352'
        'README.md'='a3e9215d7ac26f1333a7fd26fb3eafc2e53ca0b023cb0621cebc7c8f465a3893'
        'variables.tf'='f307dc9127a5c1f31423bc530755baee0035f1e3915c4a34b64a09348dc7a47c'
        'versions.tf'='3598cff15cf52f474b9bd96b501ee669eaf5c7424bcf8c5dc188ead1e1fdb7d4'
    }
    foreach($key in $reviewed.Keys){$table.Add($key,$reviewed[$key])}
    [Collections.ObjectModel.ReadOnlyDictionary[string,string]]::new($table)
}
function Get-AzureTerraformOfflineMirrorConfiguration {
    param([Parameter(Mandatory)][string]$MirrorPath)
    if($MirrorPath -cnotmatch '\A[A-Za-z]:\\' -or $MirrorPath.Substring(2).Contains(':') -or
        $MirrorPath -match '[\x00-\x1f"{}$]' -or [IO.Path]::GetFullPath($MirrorPath) -cne $MirrorPath){
        throw 'VALIDATION.TOOLING_UNRESOLVED'
    }
    $mirror=$MirrorPath.Replace('\','/')
    @('disable_checkpoint = true','provider_installation {','  filesystem_mirror {',
      ('    path = "'+$mirror+'"'),'    include = ["registry.terraform.io/hashicorp/azurerm"]','  }','}') -join [char]10
}

function Assert-AzureTerraformLocalFixedDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if($Path -cnotmatch '\A[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or
       [IO.Path]::GetFullPath($Path) -cne $Path){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    # DriveType is checked before attributes, ACLs or opening this namespace;
    # a mapped share must never be contacted by this offline boundary.
    Assert-AzureTerraformDrivePath -Path $Path
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path))
    if($drive.DriveType -ne [IO.DriveType]::Fixed){throw 'VALIDATION.TOOLING_UNRESOLVED'}
}
function Assert-AzureTerraformDirectoryOnlyEntry {
    param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$ExpectedName,
          [Parameter(Mandatory)]$Channel)
    $enumerator=$null;$failure=$null
    try{
        $null=Assert-AzureTerraformChannelActive -Channel $Channel
        $enumerator=[IO.Directory]::EnumerateFileSystemEntries($Directory).GetEnumerator()
        if(-not $enumerator.MoveNext() -or [IO.Path]::GetFileName($enumerator.Current) -cne $ExpectedName){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $null=Assert-AzureTerraformChannelActive -Channel $Channel
        if($enumerator.MoveNext()){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    }
    catch{
        $reason=if($_.Exception.Message -ceq 'VALIDATION.ROUND_INTERRUPTED'){'VALIDATION.ROUND_INTERRUPTED'}else{'VALIDATION.TOOLING_UNRESOLVED'}
        $failure=[InvalidOperationException]::new($reason)
    }
    finally{
        if($null -ne $enumerator){
            try{$enumerator.Dispose()}
            catch{
                $unsafe=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
                $unsafe.Data['OwnedCleanupUnverified']=$true
                $unsafe.Data['OwnedLeaseCleanupUnverified']=$true
                if($null -ne $failure){$unsafe.Data['PrimaryReasonCode']=$failure.Message}
                $failure=$unsafe
            }
        }
    }
    if($null -ne $failure){throw $failure}
}
function Get-AzureTerraformReviewedModuleManifest {
    param([Parameter(Mandatory)][string]$WorkspacePath)
    $path=$WorkspacePath.Replace('\','/')
    [ordered]@{Modules=@(
        [ordered]@{Key='';Source='';Dir=$path}
        [ordered]@{Key='round_network';Source='./modules/round-network';Dir=($path+'/modules/round-network')}
        [ordered]@{Key='validation_clients';Source='./modules/validation-client';Dir=($path+'/modules/validation-client')}
    )}|ConvertTo-Json -Depth 5 -Compress
}
function Assert-AzureTerraformReadOnlyNodeAcl {
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Acl,
          [Parameter(Mandatory)][string]$Actor,[switch]$RequireProtected)
    if($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18' -or
       -not $Acl.AreAccessRulesCanonical -or ($RequireProtected -and -not $Acl.AreAccessRulesProtected)){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    $rules=@($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if($rules.Count -ne 2){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($rule in $rules){
        $sid=$rule.IdentityReference.Value
        if($sid -cnotin @($Actor,'S-1-5-18') -or -not $seen.Add($sid) -or
           $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
           $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $expected=if($sid -ceq $Actor){[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize}else{[Security.AccessControl.FileSystemRights]::FullControl}
        if($rule.FileSystemRights -ne $expected){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    }
    if(-not $seen.Contains($Actor) -or -not $seen.Contains('S-1-5-18')){throw 'VALIDATION.TOOLING_UNRESOLVED'}
}
function Initialize-AzureTerraformFrozenNamespaceType {
    Initialize-AzureTerraformPathLeaseType
}
function Lock-AzureTerraformFrozenSourceNamespace {
    param([Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)]$Channel,
          [Parameter(Mandatory)][string]$DataDirectory)
    # No ACL/owner/privilege mutation occurs here. A separately prepared
    # SYSTEM-owned source tree grants this non-elevated controller only RX.
    # SYSTEM remains trusted like the OS and admitted application publisher.
    # Held ancestor handles forbid renaming/replacing that namespace.
    $identity=$null;$lease=$null;$bodyFailure=$null
    try{
        $null=Assert-AzureTerraformChannelActive -Channel $Channel
        Assert-AzureTerraformLocalFixedDirectory -Path $Root
        Assert-AzureTerraformLocalFixedDirectory -Path $DataDirectory
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $actor=$identity.User.Value
        $principal=[Security.Principal.WindowsPrincipal]::new($identity)
        if($actor -ceq 'S-1-5-18' -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
           $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::BackupOperator)){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        Initialize-AzureTerraformFrozenNamespaceType
        $lease=[WinPCInfo.AzureTerraform.FrozenSourceNamespace]::HoldAncestors($Root)
        $lease.HoldAdditionalAncestors($DataDirectory)
        $moduleRoot=Join-Path $DataDirectory 'modules'
        $lease.HoldAdditionalAncestors($moduleRoot)
        $files=@(Get-AzureTerraformInitializationFiles -Root $Root -Channel $Channel)
        $nodes=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $null=$nodes.Add($Root)
        foreach($file in $files){
            $null=$nodes.Add($file)
            $parent=[IO.Path]::GetDirectoryName($file)
            while($parent.StartsWith($Root+'\',[StringComparison]::OrdinalIgnoreCase)){$null=$nodes.Add($parent);$parent=[IO.Path]::GetDirectoryName($parent)}
        }
        foreach($node in $nodes){
            $null=Assert-AzureTerraformChannelActive -Channel $Channel
            $acl=Get-Acl -LiteralPath $node
            Assert-AzureTerraformReadOnlyNodeAcl -Acl $acl -Actor $actor -RequireProtected:($node -ceq $Root)
        }
        if(-not [IO.Directory]::Exists($DataDirectory) -or
           ([IO.File]::GetAttributes($DataDirectory) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        Assert-AzureTerraformPrivateDataAcl -Acl (Get-Acl -LiteralPath $DataDirectory) -Actor $actor
        # The outer factory must register protected-workspace ownership and
        # privileged cleanup before acquiring these separately prepared trees.
        # Actor Modify on the SYSTEM-owned data root omits WRITE_DAC and
        # FILE_DELETE_CHILD; its protected modules subtree grants actor RX.
        Assert-AzureTerraformDirectoryOnlyEntry -Directory $DataDirectory -ExpectedName 'modules' -Channel $Channel
        Assert-AzureTerraformDirectoryOnlyEntry -Directory $moduleRoot -ExpectedName 'modules.json' -Channel $Channel
        $manifestPath=Join-Path $moduleRoot 'modules.json'
        if(-not [IO.File]::Exists($manifestPath)){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        Assert-AzureTerraformReadOnlyNodeAcl -Acl (Get-Acl -LiteralPath $moduleRoot) -Actor $actor -RequireProtected
        Assert-AzureTerraformReadOnlyNodeAcl -Acl (Get-Acl -LiteralPath $manifestPath) -Actor $actor
        if(([IO.File]::GetAttributes($manifestPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $null=Assert-AzureTerraformChannelActive -Channel $Channel
        $lease.MarkValidated()
    }
    catch{$bodyFailure=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception}
    Complete-AzureTerraformNamespaceSetup -Identity $identity -Lease $lease -BodyFailure $bodyFailure
}
function Complete-AzureTerraformNamespaceSetup {
    param([AllowNull()]$Identity,[AllowNull()]$Lease,[AllowNull()][Exception]$BodyFailure)
    $failures=[Collections.Generic.List[Exception]]::new()
    if($null -ne $BodyFailure){$failures.Add($BodyFailure)}
    $cleanupFailed=$false
    if($null -ne $Identity){
        try{$Identity.Dispose()}
        catch{
            $cleanupFailed=$true
            $failures.Add([InvalidOperationException]::new('VALIDATION.IDENTITY_LEASE_RELEASE_UNVERIFIED'))
        }
    }
    if(($null -ne $BodyFailure -or $cleanupFailed) -and $null -ne $Lease){
        try{$Lease.Dispose()}
        catch{
            $cleanupFailed=$true
            $failures.Add([InvalidOperationException]::new('VALIDATION.NAMESPACE_LEASE_RELEASE_UNVERIFIED'))
        }
    }
    if($cleanupFailed){
        $combined=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED',
            [AggregateException]::new('VALIDATION.CLEANUP_UNVERIFIED',$failures.ToArray()))
        $combined.Data['OwnedCleanupUnverified']=$true
        $combined.Data['OwnedLeaseCleanupUnverified']=$true
        if($null -ne $BodyFailure){
            $primary=$BodyFailure.Data['PrimaryReasonCode']
            $combined.Data['PrimaryReasonCode']=if($primary -is [string] -and
                $primary -cin @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED','VALIDATION.CLEANUP_UNVERIFIED')){
                $primary
            }else{$BodyFailure.Message}
        }
        throw $combined
    }
    if($null -ne $BodyFailure){throw $BodyFailure}
    $Lease
}
function Assert-AzureTerraformPrivateDataAcl {
    param([Parameter(Mandatory)][Security.AccessControl.DirectorySecurity]$Acl,
          [Parameter(Mandatory)][string]$Actor)
    if($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18' -or
       -not $Acl.AreAccessRulesCanonical -or -not $Acl.AreAccessRulesProtected){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    $rules=@($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if($rules.Count -ne 2){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($rule in $rules){
        $sid=$rule.IdentityReference.Value
        if($sid -cnotin @($Actor,'S-1-5-18') -or -not $seen.Add($sid) -or
           $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
           $rule.FileSystemRights -ne $(if($sid -ceq $Actor){[Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::Synchronize}else{[Security.AccessControl.FileSystemRights]::FullControl}) -or
           $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
           $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    }
    if(-not $seen.Contains($Actor) -or -not $seen.Contains('S-1-5-18')){throw 'VALIDATION.TOOLING_UNRESOLVED'}
}

function Get-AzureTerraformInitializationFiles {
    param([Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)]$Channel)
    $null=Assert-AzureTerraformChannelActive -Channel $Channel
    Assert-AzureTerraformLocalFixedDirectory -Path $Root
    if(-not [IO.Directory]::Exists($Root)){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    $pending=[Collections.Generic.Stack[string]]::new();$pending.Push($Root)
    $files=[Collections.Generic.List[string]]::new()
    $directories=0;$entries=0
    $allowedDirectories=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $null=$allowedDirectories.Add($Root)
    foreach($relative in (Get-AzureTerraformReviewedTemplateHashes).Keys){
        $parent=[IO.Path]::GetDirectoryName((Join-Path $Root $relative))
        while($parent.StartsWith($Root+'\',[StringComparison]::OrdinalIgnoreCase)){$null=$allowedDirectories.Add($parent);$parent=[IO.Path]::GetDirectoryName($parent)}
    }
    while($pending.Count){
        $null=Assert-AzureTerraformChannelActive -Channel $Channel
        if(++$directories -gt 64){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $directory=$pending.Pop()
        if(-not $allowedDirectories.Contains($directory)){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        if(([IO.File]::GetAttributes($directory) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)){
            $null=Assert-AzureTerraformChannelActive -Channel $Channel
            if(++$entries -gt 128){throw 'VALIDATION.TOOLING_UNRESOLVED'}
            $attrs=[IO.File]::GetAttributes($entry)
            if(($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'VALIDATION.TOOLING_UNRESOLVED'}
            if(($attrs -band [IO.FileAttributes]::Directory) -ne 0){$pending.Push($entry)}
            else{$files.Add($entry);if($files.Count -gt 64){throw 'VALIDATION.TOOLING_UNRESOLVED'}}
        }
    }
    $files.ToArray()
}
function Copy-AzureTerraformInitializationPin {
    param([Parameter(Mandatory)][Collections.IDictionary]$Pin,[Parameter(Mandatory)][string]$ExpectedPath)
    if($Pin.Count -ne 3 -or @($Pin.Keys|Where-Object{$_ -cnotin @('Path','Length','Sha256')}).Count -or
       $Pin.Path -isnot [string] -or $Pin.Path -cne $ExpectedPath -or $Pin.Length -isnot [long] -or
       $Pin.Length -lt 1 -or $Pin.Length -gt 1048576 -or $Pin.Sha256 -isnot [string] -or
       $Pin.Sha256 -cnotmatch '\A[0-9a-f]{64}\z'){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    $copy=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($name in @('Path','Length','Sha256')){$copy.Add($name,$Pin[$name])}
    [Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($copy)
}
function New-AzureTerraformInitializationBinding {
    param([Parameter(Mandatory)]$Channel,[Parameter(Mandatory)][string]$WorkspacePath,
          [Parameter(Mandatory)][Collections.IDictionary]$LockfilePin,
          [Parameter(Mandatory)][Collections.IDictionary]$GeneratedValuesPin,
          [Parameter()][scriptblock]$EnumerateFiles,[Parameter()][scriptblock]$FreezeNamespace,
          [Parameter(Mandatory)][string]$DataDirectory)
    if($Channel -isnot [Collections.ObjectModel.ReadOnlyDictionary[string,object]] -or
       $WorkspacePath -cnotmatch '\A[A-Za-z]:\\' -or $WorkspacePath.Substring(2).Contains(':') -or
       $WorkspacePath -match '[\x00-\x1f]' -or [IO.Path]::GetFullPath($WorkspacePath) -cne $WorkspacePath -or
       $WorkspacePath -ceq [IO.Path]::GetPathRoot($WorkspacePath) -or $WorkspacePath.EndsWith('\')){
        throw 'VALIDATION.TOOLING_UNRESOLVED'
    }
    if($DataDirectory -cnotmatch '\A[A-Za-z]:\\' -or $DataDirectory.Substring(2).Contains(':') -or
       $DataDirectory -match '[\x00-\x1f]' -or [IO.Path]::GetFullPath($DataDirectory) -cne $DataDirectory -or
       $DataDirectory.EndsWith('\') -or $DataDirectory -ceq [IO.Path]::GetPathRoot($DataDirectory) -or
       $DataDirectory.Equals($WorkspacePath,[StringComparison]::OrdinalIgnoreCase) -or
       $DataDirectory.StartsWith($WorkspacePath+'\',[StringComparison]::OrdinalIgnoreCase) -or
       $WorkspacePath.StartsWith($DataDirectory+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'VALIDATION.TOOLING_UNRESOLVED'}
    $null=Assert-AzureTerraformChannelActive -Channel $Channel
    $lock=Copy-AzureTerraformInitializationPin -Pin $LockfilePin -ExpectedPath (Join-Path $WorkspacePath '.terraform.lock.hcl')
    $values=Copy-AzureTerraformInitializationPin -Pin $GeneratedValuesPin -ExpectedPath (Join-Path $WorkspacePath 'generated.auto.tfvars')
    $providerSuffix='\registry.terraform.io\hashicorp\azurerm\4.37.0\windows_amd64\'+[IO.Path]::GetFileName($Channel.Pins.Provider.Path)
    if(-not $Channel.Pins.Provider.Path.EndsWith($providerSuffix,[StringComparison]::Ordinal)){
        throw 'VALIDATION.TOOLING_UNRESOLVED'
    }
    $mirror=$Channel.Pins.Provider.Path.Substring(0,$Channel.Pins.Provider.Path.Length-$providerSuffix.Length)
    $configuration=Get-AzureTerraformOfflineMirrorConfiguration -MirrorPath $mirror
    $nonQualifying=$Channel.Kind -cne 'PinnedNative'
    if($null -ne $EnumerateFiles){$nonQualifying=$true}
    else{$EnumerateFiles={param($path,$channel) Get-AzureTerraformInitializationFiles -Root $path -Channel $channel}}
    $nativeFreeze=$null -eq $FreezeNamespace
    if(-not $nativeFreeze){$nonQualifying=$true}
    else{$FreezeNamespace={param($path,$channel,$data) Lock-AzureTerraformFrozenSourceNamespace -Root $path -Channel $channel -DataDirectory $data}}
    $manifestBytes=[Text.UTF8Encoding]::new($false).GetBytes((Get-AzureTerraformReviewedModuleManifest -WorkspacePath $WorkspacePath))
    $manifestPath=Join-Path (Join-Path $DataDirectory 'modules') 'modules.json'
    $manifestPin=Copy-AzureTerraformInitializationPin -Pin @{
        Path=$manifestPath;Length=[long]$manifestBytes.Length
        Sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($manifestBytes)).ToLowerInvariant()
    } -ExpectedPath $manifestPath
    $binding=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($pair in @(@('Channel',$Channel),@('WorkspacePath',$WorkspacePath),@('LockfilePin',$lock),
        @('GeneratedValuesPin',$values),@('TemplateHashes',(Get-AzureTerraformReviewedTemplateHashes)),
        @('MirrorConfiguration',$configuration),@('EnumerateFiles',$EnumerateFiles),@('NonQualifying',$nonQualifying),
        @('FreezeNamespace',$FreezeNamespace),@('NativeFreeze',$nativeFreeze),@('DataDirectory',$DataDirectory),@('ModuleManifestPin',$manifestPin))){
        $binding.Add($pair[0],$pair[1])
    }
    [Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($binding)
}
function Invoke-AzureTerraformOfflineInitialization {
    param([Parameter(Mandatory)]$Binding)
    $channel=$Binding.Channel
    $leases=[Collections.Generic.List[IDisposable]]::new()
    $processAttempted=$false;$processAbsent=$false;$cleanupFailed=$false
    $failure=$null;$result=$null
    try{
        $null=Assert-AzureTerraformChannelActive -Channel $channel
        $expected=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($relative in $Binding.TemplateHashes.Keys){
            $expected.Add((Join-Path $Binding.WorkspacePath $relative),[pscustomobject]@{Kind='ReviewedTemplate';Digest=$Binding.TemplateHashes[$relative];Pin=$null})
        }
        foreach($pin in @($Binding.LockfilePin,$Binding.GeneratedValuesPin)){
            $expected.Add($pin.Path,[pscustomobject]@{Kind='PinnedPrivateInput';Digest=$pin.Sha256;Pin=$pin})
        }
        $namespaceProofs=@(& $Binding.FreezeNamespace $Binding.WorkspacePath $channel $Binding.DataDirectory)
        foreach($item in $namespaceProofs){if($item -is [IDisposable]){$leases.Add($item)}}
        if($namespaceProofs.Count -ne 1 -or $namespaceProofs[0] -isnot [IDisposable]){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $namespace=$namespaceProofs[0]
        if($namespace.Verified -isnot [bool] -or -not $namespace.Verified -or $namespace.Root -cne $Binding.WorkspacePath -or
           ($Binding.NativeFreeze -and $namespace.GetType().FullName -cne 'WinPCInfo.AzureTerraform.FrozenSourceNamespace')){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $found=@(& $Binding.EnumerateFiles $Binding.WorkspacePath $channel)
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($path in $found){
            if($path -isnot [string] -or -not $expected.ContainsKey($path) -or -not $seen.Add($path)){
                throw 'VALIDATION.TOOLING_UNRESOLVED'
            }
        }
        if($seen.Count -ne $expected.Count){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $null=Assert-AzureTerraformChannelActive -Channel $channel
        $checks=[Collections.Generic.List[object]]::new()
        foreach($role in @('Terraform','Provider','CliConfig')){
            $pin=$channel.Pins[$role]
            $checks.Add([pscustomobject]@{Path=$pin.Path;Kind='PinnedTool';Digest=$pin.Sha256;Pin=$pin;Role=$role})
        }
        $manifestPin=$Binding.ModuleManifestPin
        $checks.Add([pscustomobject]@{Path=$manifestPin.Path;Kind='PinnedPrivateInput';Digest=$manifestPin.Sha256;Pin=$manifestPin;Role=''})
        foreach($path in $expected.Keys){
            $item=$expected[$path]
            $checks.Add([pscustomobject]@{Path=$path;Kind=$item.Kind;Digest=$item.Digest;Pin=$item.Pin;Role=''})
        }
        foreach($check in $checks){
            $opened=@(& $channel.OpenPinnedFile $check.Path)
            foreach($item in $opened){if($item -is [IO.Stream]){$leases.Add($item)}}
            if($opened.Count -ne 1 -or $opened[0] -isnot [IO.Stream] -or -not $opened[0].CanRead -or
               -not $opened[0].CanSeek -or $opened[0].Position -ne 0){throw 'VALIDATION.TOOLING_UNRESOLVED'}
            $stream=$opened[0]
            if($null -ne $check.Pin){
                if($stream.Length -ne $check.Pin.Length){throw 'VALIDATION.TOOLING_UNRESOLVED'}
                $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
                if($digest -cne $check.Digest){throw 'VALIDATION.TOOLING_UNRESOLVED'}
            }
            if($check.Kind -ceq 'ReviewedTemplate' -or $check.Role -ceq 'CliConfig'){
                if($stream.Length -lt 1 -or $stream.Length -gt 1048576){throw 'VALIDATION.TOOLING_UNRESOLVED'}
                $stream.Position=0
                $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
                try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}
                $canonical=$text.Replace(([string][char]13+[char]10),[string][char]10).Replace([string][char]13,[string][char]10)
                if($check.Kind -ceq 'ReviewedTemplate'){
                    $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical))).ToLowerInvariant()
                    if($digest -cne $check.Digest){throw 'VALIDATION.TOOLING_UNRESOLVED'}
                }
                elseif($canonical -cne $Binding.MirrorConfiguration){throw 'VALIDATION.TOOLING_UNRESOLVED'}
            }
            $null=Assert-AzureTerraformChannelActive -Channel $channel
        }
        $version=Get-AzureValidationTerraformVersion -Channel $channel
        $found=@(& $Binding.EnumerateFiles $Binding.WorkspacePath $channel)
        $seen.Clear()
        foreach($path in $found){
            if($path -isnot [string] -or -not $expected.ContainsKey($path) -or -not $seen.Add($path)){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        }
        if($seen.Count -ne $expected.Count -or -not $namespace.Verified){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $moduleLeases=@(& $channel.OpenPinnedFile $Binding.ModuleManifestPin.Path)
        foreach($item in $moduleLeases){if($item -is [IO.Stream]){$leases.Add($item)}}
        if($moduleLeases.Count -ne 1 -or $moduleLeases[0] -isnot [IO.Stream] -or
           -not $moduleLeases[0].CanRead -or -not $moduleLeases[0].CanSeek -or
           $moduleLeases[0].Position -ne 0 -or $moduleLeases[0].Length -ne $Binding.ModuleManifestPin.Length){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        if([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($moduleLeases[0])).ToLowerInvariant() -cne
           $Binding.ModuleManifestPin.Sha256){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $now=Assert-AzureTerraformChannelActive -Channel $channel
        $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($name in @('SystemRoot','WINDIR')){$environment.Add($name,[Environment]::GetFolderPath('Windows'))}
        $environment.Add('CHECKPOINT_DISABLE','1');$environment.Add('TF_IN_AUTOMATION','1');$environment.Add('TF_INPUT','0')
        $environment.Add('TF_CLI_CONFIG_FILE',$channel.Pins.CliConfig.Path)
        $environment.Add('TF_DATA_DIR',$Binding.DataDirectory)
        $environment.Add('TF_WORKSPACE','default')
        $request=[pscustomobject]@{
            Executable=$channel.Pins.Terraform.Path
            Arguments=[string[]]@('init','-input=false','-no-color','-lockfile=readonly','-get=false','-reconfigure',
                ('-backend-config=path='+(Join-Path $Binding.DataDirectory 'round.tfstate')))
            WorkingDirectory=$Binding.WorkspacePath;Environment=$environment
            TimeoutMilliseconds=[int][Math]::Min(30000,[Math]::Ceiling(($channel.DeadlineUtc-$now).TotalMilliseconds))
            CancellationToken=$channel.CancellationToken;DeadlineUtc=$channel.DeadlineUtc
        }
        $processAttempted=$true
        $responses=@(& $channel.RunProcess $request)
        if($responses.Count -ne 1){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $response=$responses[0]
        if($response.Started -isnot [bool] -or $response.CompleteOwnedTreeAbsent -isnot [bool]){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $stage=[string]$response.FailureStage
        $preCreation=(-not $response.Started -and $stage -cin @('CreateJobObject','ConfigureJobObject','CreateOutputPipes','CreateProcess'))
        $processAbsent=($stage -cne 'TerminationIncomplete' -and ($response.CompleteOwnedTreeAbsent -or $preCreation))
        if(-not $processAbsent){throw 'VALIDATION.CLEANUP_UNVERIFIED'}
        $null=Assert-AzureTerraformChannelActive -Channel $channel
        if(-not $response.Started -or $stage -cne 'None' -or $response.CancellationMode -cne 'None' -or
           $response.ExitCode -isnot [int] -or $response.ExitCode -ne 0 -or
           $response.StandardOutput -isnot [byte[]] -or $response.StandardError -isnot [byte[]] -or
           $response.StandardOutputBytes -isnot [long] -or $response.StandardErrorBytes -isnot [long] -or
           $response.StandardOutputBytes -ne $response.StandardOutput.LongLength -or $response.StandardErrorBytes -ne $response.StandardError.LongLength -or
           $response.StandardOutputBytes -gt 65536 -or $response.StandardErrorBytes -gt 16384 -or
           $response.StandardOutputExceeded -isnot [bool] -or $response.StandardOutputExceeded -or
           $response.StandardErrorExceeded -isnot [bool] -or $response.StandardErrorExceeded){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $result=[pscustomobject]@{Initialized=$true;NonQualifying=[bool]$Binding.NonQualifying;AzureContacted=$false;QualifyingEvidence=$false;LocalInitializationMaterialMayExist=$true;PrivilegedWorkspaceCleanupRequired=$true;CompleteOwnedProcessTreeAbsent=$true}
    }
    catch{
        $boundaryFailure=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception
        $preStart=($channel.UsesNativeRunner -and $_.Exception.Data['AzureTerraformNativePreStartVerified'] -eq $true)
        $unsafe=($boundaryFailure.Data['OwnedCleanupUnverified'] -eq $true) -or
            ($boundaryFailure.Data['OwnedLeaseCleanupUnverified'] -eq $true) -or
            ($processAttempted -and -not $processAbsent -and -not $preStart)
        $reason='VALIDATION.TOOLING_UNRESOLVED'
        if($unsafe){$reason='VALIDATION.CLEANUP_UNVERIFIED'}
        else{try{$null=Assert-AzureTerraformChannelActive -Channel $channel}catch{$reason='VALIDATION.ROUND_INTERRUPTED'}}
        $failure=[InvalidOperationException]::new($reason)
        if($unsafe){$failure.Data['OwnedCleanupUnverified']=$true}
        $primary=$boundaryFailure.Data['PrimaryReasonCode']
        if($primary -is [string] -and $primary -cin @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED','VALIDATION.CLEANUP_UNVERIFIED')){
            $failure.Data['PrimaryReasonCode']=$primary
        }
        if($boundaryFailure.Data['OwnedLeaseCleanupUnverified'] -eq $true){
            $failure.Data['OwnedLeaseCleanupUnverified']=$true
        }
        $failure.Data['TerraformInitializationMaterialMayExist']=$processAttempted
        $failure.Data['PrivilegedWorkspaceCleanupRequired']=$true
    }
    finally{foreach($lease in $leases){try{$lease.Dispose()}catch{$cleanupFailed=$true}}}
    if($cleanupFailed){
        $failures=[Collections.Generic.List[Exception]]::new()
        if($null -ne $failure){$failures.Add($failure)}
        $failures.Add([InvalidOperationException]::new('VALIDATION.PIN_LEASE_RELEASE_UNVERIFIED'))
        $combined=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED',
            [AggregateException]::new('VALIDATION.CLEANUP_UNVERIFIED',$failures.ToArray()))
        $combined.Data['OwnedCleanupUnverified']=$true
        $combined.Data['OwnedLeaseCleanupUnverified']=$true
        if($null -ne $failure){
            $combined.Data['PrimaryReasonCode']=if($failure.Data.Contains('PrimaryReasonCode')){$failure.Data['PrimaryReasonCode']}else{$failure.Message}
        }
        $combined.Data['TerraformInitializationMaterialMayExist']=$processAttempted
        $combined.Data['PrivilegedWorkspaceCleanupRequired']=$true
        throw $combined
    }
    if($null -ne $failure){throw $failure}
    $result
}
