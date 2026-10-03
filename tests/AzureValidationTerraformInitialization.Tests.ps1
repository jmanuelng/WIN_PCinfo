[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
. (Join-Path $root 'src/AzureValidationArmTransport.ps1')
. (Join-Path $root 'src/AzureValidationTerraform.ps1')
. (Join-Path $root 'src/AzureValidationTerraformInitialization.ps1')
$script:NativeEnumeration=(Get-Command Get-AzureTerraformInitializationFiles -CommandType Function).ScriptBlock
Add-Type -TypeDefinition @'
using System;
using System.IO;
namespace WinPCInfo.TerraformInitializationTests {
    public sealed class PinStream : MemoryStream {
        public bool Attempted, ThrowOnDispose;
        public PinStream(byte[] bytes) : base(bytes,false) {}
        protected override void Dispose(bool disposing) {
            Attempted=true; base.Dispose(disposing);
            if(ThrowOnDispose) throw new IOException("private initializer pin release details");
        }
    }
    public sealed class NamespaceLease : IDisposable {
        public string Root { get; private set; }
        public bool Verified { get { return !Disposed; } }
        public bool Disposed, ThrowOnDispose;
        public NamespaceLease(string root) { Root=root; }
        public void Dispose() { Disposed=true; if(ThrowOnDispose) throw new InvalidOperationException("private namespace release details"); }
    }
}
'@
$script:Assertions=0
$script:NativeCalls=0
function Open-AzureTerraformPinnedFile {param($Path) $script:NativeCalls++;throw 'TEST.NATIVE_FILE_PROHIBITED'}
function Invoke-AzureTerraformNativeProcess {param($Request) $script:NativeCalls++;throw 'TEST.NATIVE_PROCESS_PROHIBITED'}
function Get-AzureTerraformInitializationFiles {param($Root) $script:NativeCalls++;throw 'TEST.NATIVE_ENUMERATION_PROHIBITED'}
function Assert-Init {param([bool]$Condition,[string]$Because) $script:Assertions++;if(-not $Condition){throw $Because}}
function New-InitFixture {
    param([string]$ConfigurationSuffix="")
    $workspace='C:\synthetic-private-round\rendered-admission'
    $mirror='C:\synthetic-private-tools\mirror'
    $state=[pscustomobject]@{Bytes=@{};Leases=[Collections.Generic.List[IO.Stream]]::new();Requests=[Collections.Generic.List[object]]::new();Now=[DateTimeOffset]::Parse('2030-01-01T00:00:00Z');Extra=@();Failure='';Lost=$false;InitOverrides=@{};AdvanceAfterVersion=$false;AddAfterVersion=$false;NamespaceLease=$null;ThrowPinOnDispose=$false;ThrowNamespaceOnDispose=$false;ThrowVersionPinsOnly=$false;VersionFailure=$false;AddCacheAfterVersion=$false}
    $templates=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/azure-validation-reviewed-templates.json') -Raw|ConvertFrom-Json -AsHashtable
    foreach($pair in $templates.GetEnumerator()){$state.Bytes[(Join-Path $workspace $pair.Key)]=[Text.Encoding]::UTF8.GetBytes($pair.Value)}
    $state.Bytes[(Join-Path $workspace 'generated.auto.tfvars')]=[Text.Encoding]::UTF8.GetBytes('synthetic = true')
    $state.Bytes[(Join-Path $workspace '.terraform.lock.hcl')]=[Text.Encoding]::UTF8.GetBytes('provider "registry.terraform.io/hashicorp/azurerm" { version = "4.37.0" constraints = "4.37.0" hashes = ["h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="] }')
    $files=@{
        Terraform='C:\synthetic-private-tools\terraform.exe'
        Provider=(Join-Path $mirror 'registry.terraform.io/hashicorp/azurerm/4.37.0/windows_amd64/terraform-provider-azurerm_v4.37.0_x5.exe')
        CliConfig='C:\synthetic-private-tools\round.tfrc'
    }
    $state.Bytes[$files.Terraform]=[Text.Encoding]::UTF8.GetBytes('synthetic exact Terraform')
    $state.Bytes[$files.Provider]=[Text.Encoding]::UTF8.GetBytes('synthetic exact provider')
    $config=(Get-AzureTerraformOfflineMirrorConfiguration -MirrorPath $mirror)+$ConfigurationSuffix
    $state.Bytes[$files.CliConfig]=[Text.Encoding]::UTF8.GetBytes($config)
    function Pin-Init {param($Path) @{Path=$Path;Length=[long]$state.Bytes[$Path].Length;Sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$state.Bytes[$Path])).ToLowerInvariant()}}
    $pins=@{};foreach($role in @('Terraform','Provider','CliConfig')){$pins[$role]=Pin-Init $files[$role]}
    $open={param($path) $lease=[WinPCInfo.TerraformInitializationTests.PinStream]::new([byte[]]$state.Bytes[$path]);$lease.ThrowOnDispose=($state.ThrowPinOnDispose -or ($state.ThrowVersionPinsOnly -and $state.Leases.Count -ge 20));$state.Leases.Add($lease);$lease}.GetNewClosure()
    $run={
        param($request)
        $state.Requests.Add($request)
        if($state.Lost -and $request.Arguments[0] -ceq 'init'){return}
        $bytes=if($request.Arguments[0] -ceq 'version'){[Text.Encoding]::UTF8.GetBytes('{"terraform_version":"1.12.2","platform":"windows_amd64"}')}else{[Text.Encoding]::UTF8.GetBytes('private initializer output')}
        $response=[pscustomobject]@{Started=$true;ExitCode=if(($state.Failure -and $request.Arguments[0] -ceq 'init') -or ($state.VersionFailure -and $request.Arguments[0] -ceq 'version')){1}else{0};FailureStage='None';CancellationMode='None';CompleteOwnedTreeAbsent=$true;StandardOutput=[byte[]]$bytes;StandardError=[byte[]]@();StandardOutputBytes=[long]$bytes.Length;StandardErrorBytes=0L;StandardOutputExceeded=$false;StandardErrorExceeded=$false}
        if($request.Arguments[0] -ceq 'init'){foreach($key in $state.InitOverrides.Keys){$response.$key=$state.InitOverrides[$key]}}
        if($state.AdvanceAfterVersion -and $request.Arguments[0] -ceq 'version'){$state.Now=$state.Now.AddMinutes(6)}
        if($state.AddAfterVersion -and $request.Arguments[0] -ceq 'version'){$state.Extra=@(Join-Path $workspace 'override.tf')}
        if($state.AddCacheAfterVersion -and $request.Arguments[0] -ceq 'version'){
            $state.Bytes['C:\synthetic-private-round\terraform-data\modules\modules.json']=[Text.Encoding]::UTF8.GetBytes('{"Modules":[{"Key":"round_network","Source":"./modules/round-network","Dir":"C:/unreviewed-local-source"}]}')
        }
        $response
    }.GetNewClosure()
    $channel=New-AzureValidationTerraformChannel -Pins $pins -DeadlineUtc $state.Now.AddMinutes(5) -OpenPinnedFile $open -RunProcess $run -UtcNow {$state.Now}.GetNewClosure()
    $enumerate={param($path) @($state.Bytes.Keys|Where-Object{$_.StartsWith($workspace+'\',[StringComparison]::OrdinalIgnoreCase)})+@($state.Extra)}.GetNewClosure()
    $lockPin=Pin-Init (Join-Path $workspace '.terraform.lock.hcl')
    $valuesPin=Pin-Init (Join-Path $workspace 'generated.auto.tfvars')
    $freeze={param($path,$channel,$data) $state.NamespaceLease=[WinPCInfo.TerraformInitializationTests.NamespaceLease]::new($path);$state.NamespaceLease.ThrowOnDispose=$state.ThrowNamespaceOnDispose;$state.NamespaceLease}.GetNewClosure()
    $dataDirectory='C:\synthetic-private-round\terraform-data'
    $state.Bytes[(Join-Path (Join-Path $dataDirectory 'modules') 'modules.json')]=[Text.UTF8Encoding]::new($false).GetBytes((Get-AzureTerraformReviewedModuleManifest -WorkspacePath $workspace))
    $binding=New-AzureTerraformInitializationBinding -Channel $channel -WorkspacePath $workspace -LockfilePin $lockPin -GeneratedValuesPin $valuesPin -EnumerateFiles $enumerate -FreezeNamespace $freeze -DataDirectory $dataDirectory
    [pscustomobject]@{Binding=$binding;State=$state;Pins=$pins;LockPin=$lockPin;ValuesPin=$valuesPin;Workspace=$workspace;DataDirectory=$dataDirectory}
}
function Assert-InitRefusal {
    param([scriptblock]$Action,[string]$Reason,[bool]$Unsafe=$false)
    $failure=$null;try{$null=& $Action}catch{$failure=$_.Exception}
    Assert-Init ($null -ne $failure -and $failure.Message -ceq $Reason) 'Initialization failed to retain the expected closed reason.'
    Assert-Init (($failure.Data['OwnedCleanupUnverified'] -eq $true) -eq $Unsafe) 'Initialization process ambiguity lost its cleanup stop signal.'
}
$f=New-InitFixture
$result=Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding
Assert-Init ($result.Initialized -and $result.NonQualifying -and -not $result.AzureContacted -and -not $result.QualifyingEvidence) 'Initializer promoted injected evidence or contacted Azure.'
Assert-Init ($f.State.Requests.Count -eq 2) 'Initialization skipped exact version validation or retried.'
$cmd=$f.State.Requests[1]
Assert-Init (($cmd.Arguments -join '|') -ceq ('init|-input=false|-no-color|-lockfile=readonly|-get=false|-reconfigure|-backend-config=path='+$f.DataDirectory+'\round.tfstate')) 'Initializer acquired tools, skipped locked checksums, used a shell, or changed backend scope.'
Assert-Init ($cmd.WorkingDirectory -ceq $f.Workspace -and -not $cmd.Environment.ContainsKey('PATH') -and -not $cmd.Environment.ContainsKey('ARM_USE_MSI')) 'Offline init inherited authentication or unapproved working directory.'
Assert-Init (@($f.State.Leases|Where-Object CanRead).Count -eq 0) 'Initializer retained owned pin leases.'
Assert-Init ($cmd.Environment.TF_WORKSPACE -ceq 'default' -and $cmd.Environment.TF_DATA_DIR -ceq $f.DataDirectory) 'Initialization inherited a writable workspace selector.'
$manifest=Get-AzureTerraformReviewedModuleManifest -WorkspacePath $f.Workspace|ConvertFrom-Json
Assert-Init ($manifest.Modules.Count -eq 3 -and @($manifest.Modules|Where-Object { $_.PSObject.Properties['Version'] }).Count -eq 0 -and ($manifest.Modules.Key -join '|') -ceq '|round_network|validation_clients') 'Module manifest admitted extra modules, versions or keys.'
$f=New-InitFixture;$f.LockPin.Sha256='0'*64
Assert-Init (Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding).Initialized 'Caller-mutated pin changed admitted initialization binding.'
foreach($relative in @('override.tf','extra.auto.tfvars','main.tf.json','modules/remote/main.tf','.terraform/providers/unapproved.exe')){
    $f=New-InitFixture;$f.State.Extra=@(Join-Path $f.Workspace $relative)
    Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
    Assert-Init ($f.State.Requests.Count -eq 0) 'Unapproved workspace file reached native version or init.'
}
foreach($role in @('CliConfig','Provider','Terraform')){
    $f=New-InitFixture;$f.State.Bytes[$f.Pins[$role].Path]=[Text.Encoding]::UTF8.GetBytes('changed private pin')
    Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
    Assert-Init ($f.State.Requests.Count -eq 0) 'Changed tooling reached process dispatch.'
}
$f=New-InitFixture;$f.State.Bytes[(Join-Path $f.Workspace 'versions.tf')]=[Text.Encoding]::UTF8.GetBytes('terraform { backend "azurerm" {} }')
Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
Assert-Init ($f.State.Requests.Count -eq 0) 'Changed reviewed local template reached process dispatch.'
$f=New-InitFixture;$f.State.Failure='private subscription and credential details'
Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
$f=New-InitFixture;$f.State.Lost=$true
Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.CLEANUP_UNVERIFIED' $true
$f=New-InitFixture;$f.State.Now=$f.State.Now.AddMinutes(6)
Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.ROUND_INTERRUPTED'
Assert-Init ($f.State.Requests.Count -eq 0) 'Expired round started initialization.'

foreach($suffix in @(([char]10+'direct {}'),([char]10+'credentials "private" {}'),([char]10+'plugin_cache_dir = "unapproved"'))){
    $f=New-InitFixture -ConfigurationSuffix $suffix
    Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
    Assert-Init ($f.State.Requests.Count -eq 0) 'Approved hash of unsafe CLI config bypassed exclusive mirror interpretation.'
}
foreach($relative in @('.terraform.lock.hcl','generated.auto.tfvars')){
    $f=New-InitFixture;$f.State.Bytes[(Join-Path $f.Workspace $relative)]=[Text.Encoding]::UTF8.GetBytes('changed private input')
    Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
    Assert-Init ($f.State.Requests.Count -eq 0) 'Changed private input reached initialization.'
}
$f=New-InitFixture;$f.State.AdvanceAfterVersion=$true
Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.ROUND_INTERRUPTED'
Assert-Init ($f.State.Requests.Count -eq 1 -and @($f.State.Leases|Where-Object CanRead).Count -eq 0) 'Version crossed deadline but init dispatched or leases survived.'
foreach($overrides in @(
    @{Started=$false;CompleteOwnedTreeAbsent=$false;FailureStage='TerminationIncomplete'},
    @{Started=$true;CompleteOwnedTreeAbsent=$false},
    @{Started=$false;CompleteOwnedTreeAbsent=$true;FailureStage='TerminationIncomplete'}
)){
    $f=New-InitFixture;$f.State.InitOverrides=$overrides
    Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.CLEANUP_UNVERIFIED' $true
    Assert-Init (@($f.State.Leases|Where-Object CanRead).Count -eq 0) 'Unverified process prevented independent lease disposal.'
}
foreach($overrides in @(
    @{StandardOutputBytes=1},
    @{StandardOutputExceeded=$true},
    @{ExitCode='0'},
    @{CancellationMode='Hard'}
)){
    $f=New-InitFixture;$f.State.InitOverrides=$overrides
    Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
}
$f=New-InitFixture;$f.State.AddAfterVersion=$true
Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
Assert-Init ($f.State.Requests.Count -eq 1) 'A late unapproved file reached initialization after exact version validation.'
Assert-Init $f.State.NamespaceLease.Disposed 'Namespace guard survived pre-dispatch late-file refusal.'
$f=New-InitFixture;$f.State.AddCacheAfterVersion=$true
Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
Assert-Init ($f.State.Requests.Count -eq 1) 'Late cached module metadata reached init and redirected source loading.'
foreach($disposal in @('Pin','Namespace','Both')){
    foreach($phase in @('Success','BodyFailure','LateFile','Deadline','AmbiguousProcess')){
        $f=New-InitFixture
        $f.State.ThrowPinOnDispose=$disposal -cin @('Pin','Both')
        $f.State.ThrowNamespaceOnDispose=$disposal -cin @('Namespace','Both')
        if($phase -ceq 'BodyFailure'){$f.State.Failure='private initialization error'}
        elseif($phase -ceq 'LateFile'){$f.State.AddAfterVersion=$true}
        elseif($phase -ceq 'Deadline'){$f.State.AdvanceAfterVersion=$true}
        elseif($phase -ceq 'AmbiguousProcess'){$f.State.Lost=$true}
        $caught=$null;try{$null=Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding}catch{$caught=$_.Exception}
        Assert-Init ($null -ne $caught -and $caught.Message -ceq 'VALIDATION.CLEANUP_UNVERIFIED' -and $caught.Data['OwnedCleanupUnverified'] -eq $true) 'Failed pin/namespace release lost the scheduling stop signal.'
        Assert-Init ($f.State.NamespaceLease.Disposed -and @($f.State.Leases|Where-Object { -not $_.Attempted }).Count -eq 0) 'Earlier disposal failure skipped a later pin/namespace release.'
        Assert-Init (-not $caught.ToString().Contains('private initializer') -and -not $caught.ToString().Contains('private namespace')) 'Disposal failure exposed private details.'
        if($disposal -ceq 'Pin' -or $disposal -ceq 'Both'){
            Assert-Init ($f.State.Requests.Count -eq 1) 'Version pin cleanup failure allowed initializer dispatch.'
        }
        else{
            $expected=if($phase -ceq 'Deadline'){'VALIDATION.ROUND_INTERRUPTED'}elseif($phase -ceq 'AmbiguousProcess'){'VALIDATION.CLEANUP_UNVERIFIED'}elseif($phase -ceq 'Success'){''}else{'VALIDATION.TOOLING_UNRESOLVED'}
            if($expected){Assert-Init ($caught.Data['PrimaryReasonCode'] -ceq $expected) 'Namespace release failure discarded the closed primary body reason.'}
        }
    }
}
$f=New-InitFixture
$f.State.ThrowVersionPinsOnly=$true;$f.State.VersionFailure=$true
$caught=$null;try{$null=Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding}catch{$caught=$_.Exception}
Assert-Init ($caught.Message -ceq 'VALIDATION.CLEANUP_UNVERIFIED' -and $caught.Data['OwnedCleanupUnverified'] -eq $true -and $caught.Data['OwnedLeaseCleanupUnverified'] -eq $true -and $caught.Data['PrimaryReasonCode'] -ceq 'VALIDATION.TOOLING_UNRESOLVED') 'Initializer wrapper lost version primary reason or lease cleanup uncertainty.'
Assert-Init ($f.State.Requests.Count -eq 1 -and $f.State.NamespaceLease.Disposed -and @($f.State.Leases|Where-Object { -not $_.Attempted }).Count -eq 0) 'Version-only disposal fault dispatched init or skipped outer cleanup.'
foreach($identityFailure in @($false,$true)){
    foreach($namespaceFailure in @($false,$true)){
        foreach($hasBodyFailure in @($false,$true)){
            $identity=[WinPCInfo.TerraformInitializationTests.NamespaceLease]::new('synthetic identity')
            $lease=[WinPCInfo.TerraformInitializationTests.NamespaceLease]::new('synthetic namespace')
            $identity.ThrowOnDispose=$identityFailure;$lease.ThrowOnDispose=$namespaceFailure
            $body=if($hasBodyFailure){[InvalidOperationException]::new('VALIDATION.ROUND_INTERRUPTED')}else{$null}
            $caught=$null;$returned=$null
            try{$returned=Complete-AzureTerraformNamespaceSetup -Identity $identity -Lease $lease -BodyFailure $body}catch{$caught=$_.Exception}
            Assert-Init $identity.Disposed 'Namespace setup retained the identity token.'
            $leaseMustDispose=$hasBodyFailure -or $identityFailure
            Assert-Init ($lease.Disposed -eq $leaseMustDispose) 'Identity cleanup or body failure skipped the held namespace release.'
            $unsafe=$identityFailure -or ($namespaceFailure -and $leaseMustDispose)
            if($unsafe){
                Assert-Init ($caught.Message -ceq 'VALIDATION.CLEANUP_UNVERIFIED' -and $caught.Data['OwnedCleanupUnverified'] -eq $true) 'Namespace setup lost independent cleanup uncertainty.'
                Assert-Init (-not $caught.ToString().Contains('private namespace')) 'Namespace setup exposed private identity/release details.'
            }elseif($hasBodyFailure){Assert-Init ($caught.Message -ceq 'VALIDATION.ROUND_INTERRUPTED') 'Namespace cleanup replaced the primary interruption.'}
            else{Assert-Init ([object]::ReferenceEquals($returned,$lease)) 'Successful setup discarded its held namespace.'}
        }
    }
}
function New-PrivateDataAclFixture {
    param([string]$Owner='S-1-5-18',[bool]$Protected=$true,
          [string]$Extra='',[bool]$InheritedChildren=$true,[Security.AccessControl.FileSystemRights]$ActorRights=[Security.AccessControl.FileSystemRights]::Modify)
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($Owner))
    $acl.SetAccessRuleProtection($Protected,$false)
    $flags=if($InheritedChildren){[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit}else{[Security.AccessControl.InheritanceFlags]::None}
    foreach($sid in @('S-1-5-21-100-200-300-1001','S-1-5-18')+@($Extra|Where-Object {$_})){
        $rights=if($sid -ceq 'S-1-5-21-100-200-300-1001'){$ActorRights}else{[Security.AccessControl.FileSystemRights]::FullControl}
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$rights,$flags,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    $acl
}
$acl=New-PrivateDataAclFixture
Assert-AzureTerraformPrivateDataAcl -Acl $acl -Actor 'S-1-5-21-100-200-300-1001'
Assert-Init $true 'Private actor/SYSTEM data ACL refused.'
foreach($parameters in @(@{Owner='S-1-5-21-100-200-300-1001'},@{Protected=$false},@{Extra='S-1-1-0'},@{InheritedChildren=$false},@{ActorRights=[Security.AccessControl.FileSystemRights]::FullControl},@{ActorRights=([Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)})){
    $acl=New-PrivateDataAclFixture @parameters
    Assert-InitRefusal {Assert-AzureTerraformPrivateDataAcl -Acl $acl -Actor 'S-1-5-21-100-200-300-1001'} 'VALIDATION.TOOLING_UNRESOLVED'
}
$acl=New-PrivateDataAclFixture -ActorRights ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
Assert-AzureTerraformReadOnlyNodeAcl -Acl $acl -Actor 'S-1-5-21-100-200-300-1001' -RequireProtected
Assert-Init $true 'Protected SYSTEM-owned source/module ACL refused.'
foreach($parameters in @(@{Owner='S-1-5-21-100-200-300-1001'},@{Protected=$false},@{ActorRights=[Security.AccessControl.FileSystemRights]::Modify},@{Extra='S-1-1-0'})){
    $p=@{ActorRights=[Security.AccessControl.FileSystemRights]::ReadAndExecute}
    foreach($key in $parameters.Keys){$p[$key]=$parameters[$key]}
    $acl=New-PrivateDataAclFixture @p
    Assert-InitRefusal {Assert-AzureTerraformReadOnlyNodeAcl -Acl $acl -Actor 'S-1-5-21-100-200-300-1001' -RequireProtected} 'VALIDATION.TOOLING_UNRESOLVED'
}
foreach($text in @(
    '{"Modules":[]}',
    '{"Modules":[{"Key":"round_network","Source":"./modules/round-network","Dir":"C:/unapproved"}]}',
    '{"Modules":[{"Key":"","Key":"duplicate","Source":"","Dir":"C:/synthetic-private-round/rendered-admission"}]}',
    'private malformed module manifest'
)){
    $f=New-InitFixture
    $f.State.Bytes[$f.Binding.ModuleManifestPin.Path]=[Text.Encoding]::UTF8.GetBytes($text)
    Assert-InitRefusal {Invoke-AzureTerraformOfflineInitialization -Binding $f.Binding} 'VALIDATION.TOOLING_UNRESOLVED'
    Assert-Init ($f.State.Requests.Count -eq 0) 'Unreviewed module metadata reached native version/init.'
}

# Native method-invocation wrapping must not erase owned acquisition stop flags.
Add-Type -TypeDefinition @'
using System;
namespace WinPCInfo.TerraformInitializationTests {
    public static class AcquisitionFault {
        public static void Raise(string primary) {
            var e=new InvalidOperationException("VALIDATION.CLEANUP_UNVERIFIED",
                new InvalidOperationException("private native acquisition details"));
            e.Data["OwnedCleanupUnverified"]=true;
            e.Data["OwnedLeaseCleanupUnverified"]=true;
            e.Data["PrimaryReasonCode"]=primary;
            throw e;
        }
    }
}
'@
foreach($phase in @('Freeze','Open')){
    foreach($wrapped in @($false,$true)){
        foreach($primary in @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED')){
            foreach($releaseFault in @($false,$true)){
                $f=New-InitFixture
                $f.State.ThrowNamespaceOnDispose=$releaseFault
                $direct=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED',
                    [InvalidOperationException]::new('private native acquisition details'))
                $direct.Data['OwnedCleanupUnverified']=$true
                $direct.Data['OwnedLeaseCleanupUnverified']=$true
                $direct.Data['PrimaryReasonCode']=$primary
                $fault={
                    param($path,$channel,$data)
                    if($wrapped){[WinPCInfo.TerraformInitializationTests.AcquisitionFault]::Raise($primary)}
                    else{throw $direct}
                }.GetNewClosure()
                $copy=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
                foreach($pair in $f.Binding.GetEnumerator()){$copy.Add($pair.Key,$pair.Value)}
                if($phase -ceq 'Freeze'){$copy['FreezeNamespace']=$fault}
                else{
                    $channelCopy=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
                    foreach($pair in $f.Binding.Channel.GetEnumerator()){$channelCopy.Add($pair.Key,$pair.Value)}
                    $channelCopy['OpenPinnedFile']=$fault
                    $copy['Channel']=[Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($channelCopy)
                }
                $binding=[Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($copy)
                $caught=$null
                try{$null=Invoke-AzureTerraformOfflineInitialization -Binding $binding}catch{$caught=$_.Exception}
                Assert-Init ($null -ne $caught -and $caught.Message -ceq 'VALIDATION.CLEANUP_UNVERIFIED' -and
                    $caught.Data['OwnedCleanupUnverified'] -eq $true -and $caught.Data['OwnedLeaseCleanupUnverified'] -eq $true) ('Initializer erased acquisition cleanup uncertainty: phase='+$phase+' wrapped='+$wrapped+' releaseFault='+$releaseFault)
                Assert-Init ($caught.Data['PrimaryReasonCode'] -ceq $primary) 'Initializer changed acquisition primary reason during independent cleanup.'
                Assert-Init ($caught.Data['PrivilegedWorkspaceCleanupRequired'] -eq $true) 'Initializer combined failure lost protected-workspace cleanup obligation.'
                Assert-Init (-not $caught.ToString().Contains('private native acquisition details')) 'Initializer leaked wrapped acquisition details.'
                Assert-Init ($f.State.Requests.Count -eq 0) 'Failed namespace acquisition reached native process dispatch.'
                if($phase -ceq 'Open'){Assert-Init $f.State.NamespaceLease.Disposed 'Acquisition failure skipped namespace release.'}
            }
        }
    }
}


foreach($primary in @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED')){
    foreach($release in @('Identity','Namespace','Both')){
        $identity=[WinPCInfo.TerraformInitializationTests.NamespaceLease]::new('synthetic identity')
        $lease=[WinPCInfo.TerraformInitializationTests.NamespaceLease]::new('synthetic namespace')
        $identity.ThrowOnDispose=$release -cin @('Identity','Both')
        $lease.ThrowOnDispose=$release -cin @('Namespace','Both')
        $body=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
        $body.Data['OwnedCleanupUnverified']=$true
        $body.Data['OwnedLeaseCleanupUnverified']=$true
        $body.Data['PrimaryReasonCode']=$primary
        $caught=$null
        try{$null=Complete-AzureTerraformNamespaceSetup -Identity $identity -Lease $lease -BodyFailure $body}catch{$caught=$_.Exception}
        Assert-Init ($caught.Message -ceq 'VALIDATION.CLEANUP_UNVERIFIED' -and $caught.Data['OwnedCleanupUnverified'] -eq $true) 'Namespace combined release lost cleanup uncertainty.'
        Assert-Init ($caught.Data['PrimaryReasonCode'] -ceq $primary) 'Namespace setup overwrote earlier closed acquisition primary reason.'
        Assert-Init ($identity.Disposed -and $lease.Disposed) 'Namespace combined release skipped another owned handle.'
    }
}

Assert-Init ($script:NativeCalls -eq 0) 'Injected tests reached native enumeration/file/process.'
[ordered]@{recordType='win-pcinfo.injected-terraform-initialization-tests';result='Pass';assertions=$script:Assertions;nonQualifying=$true;nativeCalls=$script:NativeCalls;scope='Pinned offline init interpretation only; no acquisition, Azure, plan/apply/destroy or live qualification'}|ConvertTo-Json -Compress|Write-Output
