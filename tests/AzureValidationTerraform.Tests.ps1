[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$source=Join-Path (Split-Path $PSScriptRoot) 'src'
. (Join-Path $source 'AzureValidationArmTransport.ps1')
. (Join-Path $source 'AzureValidationTerraform.ps1')
$script:NativeBridge=(Get-Command Invoke-AzureTerraformNativeProcess -CommandType Function).ScriptBlock
$script:Assertions=0
$script:NativeRequests=0
function Open-AzureTerraformPinnedFile { param($Path) $script:NativeRequests++; throw 'TEST.NATIVE_FILE_OPEN_PROHIBITED' }
function Invoke-AzureTerraformNativeProcess { param($Request) $script:NativeRequests++; throw 'TEST.NATIVE_PROCESS_PROHIBITED' }
function Assert-TerraformBoundary {
    param([bool] $Condition,[string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw $Message }
}
Add-Type -TypeDefinition @'
using System;
using System.IO;
namespace WinPCInfo.TerraformLeaseTests {
 public sealed class Stream : MemoryStream {
  public bool Attempted, ThrowOnDispose;
  public Stream(byte[] bytes) : base(bytes,false) {}
  protected override void Dispose(bool disposing) {
   Attempted=true; base.Dispose(disposing);
   if(ThrowOnDispose) throw new IOException("private pin cleanup detail");
  }
 }
}
'@
function New-TerraformFixture {
    $root='C:\synthetic-private-tools'
    $pins=[ordered]@{}
    $state=[pscustomobject]@{
        Bytes=@{};Streams=[Collections.Generic.List[IO.Stream]]::new()
        Requests=[Collections.Generic.List[object]]::new()
        Now=[DateTimeOffset]::Parse('2030-01-01T00:00:00Z');ThrowOnDispose=$false;AdvanceAfterProcess=$false
        Reply=[pscustomobject]@{
            Started=$true;ExitCode=0;FailureStage='None';CompleteOwnedTreeAbsent=$true
            StandardOutput=[Text.Encoding]::UTF8.GetBytes('{"terraform_version":"1.12.2","platform":"windows_amd64","provider_selections":{}}')
            StandardError=[byte[]]@();StandardOutputBytes=100L;StandardErrorBytes=0L
            StandardOutputExceeded=$false;StandardErrorExceeded=$false;CancellationMode='None'
        }
    }
    $files=@{Terraform='terraform.exe';Provider='terraform-provider-azurerm_v4.37.0_x5.exe';CliConfig='round.tfrc'}
    foreach ($role in @('Terraform','Provider','CliConfig')) {
        $path=Join-Path $root $files[$role]
        $bytes=[Text.Encoding]::UTF8.GetBytes('synthetic-pinned-'+$role)
        $state.Bytes[$path]=$bytes
        $pins[$role]=@{Path=$path;Length=[long]$bytes.Length;Sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()}
    }
    $state.Reply.StandardOutputBytes=[long]$state.Reply.StandardOutput.Length
    $open={
        param($path)
        $stream=[WinPCInfo.TerraformLeaseTests.Stream]::new([byte[]]$state.Bytes[$path]);$stream.ThrowOnDispose=$state.ThrowOnDispose
        $state.Streams.Add($stream)
        $stream
    }.GetNewClosure()
    $run={param($request) $state.Requests.Add($request);if($state.AdvanceAfterProcess){$state.Now=$state.Now.AddMinutes(6)};$state.Reply}.GetNewClosure()
    $clock={$state.Now}.GetNewClosure()
    $args=@{Pins=$pins;DeadlineUtc=$state.Now.AddMinutes(5);OpenPinnedFile=$open;RunProcess=$run;UtcNow=$clock}
    $channel=New-AzureValidationTerraformChannel @args
    [pscustomobject]@{Channel=$channel;State=$state;Pins=$pins}
}
$f=New-TerraformFixture
$result=Get-AzureValidationTerraformVersion -Channel $f.Channel
Assert-TerraformBoundary ($result.Version -ceq '1.12.2' -and $result.Platform -ceq 'windows_amd64' -and $result.NonQualifying) 'Pinned CLI version interpretation lost exact identity or promoted injected evidence.'
Assert-TerraformBoundary ($f.State.Requests.Count -eq 1 -and
    ($f.State.Requests[0].Arguments -join '|') -ceq 'version|-json' -and
    $f.State.Requests[0].Executable -ceq $f.Pins.Terraform.Path) 'CLI request used shell, PATH discovery or different command.'
Assert-TerraformBoundary ($f.State.Requests[0].Environment.CHECKPOINT_DISABLE -ceq '1' -and
    $f.State.Requests[0].Environment.TF_CLI_CONFIG_FILE -ceq $f.Pins.CliConfig.Path -and
    -not $f.State.Requests[0].Environment.ContainsKey('PATH')) 'CLI inherited checkpoint, config or PATH behavior.'
Assert-TerraformBoundary (@($f.State.Streams|Where-Object CanRead).Count -eq 0) 'Held pin streams survived the version probe.'
Assert-TerraformBoundary ($script:NativeRequests -eq 0) 'Injected CLI tests attempted native I/O.'
function Assert-TerraformRefusal {
    param([scriptblock]$Action,[string]$Reason,[bool]$CleanupUnverified=$false)
    $caught=$null
    try { $null=& $Action } catch { $caught=$_.Exception }
    Assert-TerraformBoundary ($null -ne $caught -and $caught.Message -ceq $Reason) 'CLI boundary did not retain the expected closed refusal.'
    Assert-TerraformBoundary (($caught.Data['OwnedCleanupUnverified'] -eq $true) -eq $CleanupUnverified) 'CLI ambiguity did not retain the expected scheduling stop signal.'
}
foreach($phase in @('Success','BodyFailure','Interruption','UnsafeProcess')) {
    $f=New-TerraformFixture;$f.State.ThrowOnDispose=$true
    if($phase -ceq 'BodyFailure'){$f.State.Reply.ExitCode=1}
    elseif($phase -ceq 'Interruption'){$f.State.AdvanceAfterProcess=$true}
    elseif($phase -ceq 'UnsafeProcess'){$f.State.Reply.CompleteOwnedTreeAbsent=$false}
    $caught=$null;try{$null=Get-AzureValidationTerraformVersion -Channel $f.Channel}catch{$caught=$_.Exception}
    Assert-TerraformBoundary ($null -ne $caught -and $caught.Message -ceq 'VALIDATION.CLEANUP_UNVERIFIED' -and $caught.Data['OwnedCleanupUnverified'] -eq $true -and $caught.Data['OwnedLeaseCleanupUnverified'] -eq $true) 'Pin disposal failure lost its owned cleanup stop signal.'
    Assert-TerraformBoundary (@($f.State.Streams|Where-Object { -not $_.Attempted }).Count -eq 0) 'One disposal failure skipped other leases.'
    Assert-TerraformBoundary (-not $caught.ToString().Contains('private pin cleanup detail')) 'Pin disposal exception exposed private details.'
}
# Acquisition can fail after native handles have already been opened.
# Its cleanup stop signal must survive normalization before any dispatch.
foreach($primary in @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED','VALIDATION.CLEANUP_UNVERIFIED','private rejected primary')){
    $f=New-TerraformFixture
    $openFailure=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
    $openFailure.Data['OwnedCleanupUnverified']=$true
    $openFailure.Data['OwnedLeaseCleanupUnverified']=$true
    $openFailure.Data['PrimaryReasonCode']=$primary
    $throwingOpen={param($path) throw $openFailure}.GetNewClosure()
    $parameters=@{Pins=$f.Pins;DeadlineUtc=$f.Channel.DeadlineUtc;UtcNow=$f.Channel.Clock;OpenPinnedFile=$throwingOpen;RunProcess=$f.Channel.RunProcess}
    $acquisitionChannel=New-AzureValidationTerraformChannel @parameters
    $caught=$null;try{$null=Get-AzureValidationTerraformVersion -Channel $acquisitionChannel}catch{$caught=$_.Exception}
    Assert-TerraformBoundary ($null -ne $caught -and $caught.Message -ceq 'VALIDATION.CLEANUP_UNVERIFIED' -and $caught.Data['OwnedCleanupUnverified'] -eq $true -and $caught.Data['OwnedLeaseCleanupUnverified'] -eq $true) 'Acquisition cleanup fault was downgraded to an ordinary tooling refusal.'
    if($primary -ceq 'private rejected primary'){
        Assert-TerraformBoundary (-not $caught.Data.Contains('PrimaryReasonCode') -and -not $caught.ToString().Contains($primary)) 'Acquisition cleanup fault exposed an unclosed private primary reason.'
    }else{
        Assert-TerraformBoundary ($caught.Data['PrimaryReasonCode'] -ceq $primary) 'Acquisition cleanup fault lost its closed primary reason.'
    }
    Assert-TerraformBoundary ($f.State.Requests.Count -eq 0 -and $f.State.Streams.Count -eq 0) 'Acquisition cleanup fault dispatched a process.'
}
foreach($withLeaseFlag in @($false,$true)){
    $f=New-TerraformFixture
    $inner=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
    $inner.Data['OwnedCleanupUnverified']=$true
    if($withLeaseFlag){$inner.Data['OwnedLeaseCleanupUnverified']=$true}
    $inner.Data['PrimaryReasonCode']='VALIDATION.TOOLING_UNRESOLVED'
    $wrapped=[Management.Automation.MethodInvocationException]::new('private wrapper details',$inner)
    $throwingOpen={param($path) throw $wrapped}.GetNewClosure()
    $parameters=@{Pins=$f.Pins;DeadlineUtc=$f.Channel.DeadlineUtc;UtcNow=$f.Channel.Clock;OpenPinnedFile=$throwingOpen;RunProcess=$f.Channel.RunProcess}
    $wrappedChannel=New-AzureValidationTerraformChannel @parameters
    $caught=$null;try{$null=Get-AzureValidationTerraformVersion -Channel $wrappedChannel}catch{$caught=$_.Exception}
    Assert-TerraformBoundary ($null -ne $caught -and $caught.Message -ceq 'VALIDATION.CLEANUP_UNVERIFIED' -and $caught.Data['OwnedCleanupUnverified'] -eq $true) 'CLR wrapper hid the acquisition owned-cleanup stop signal.'
    Assert-TerraformBoundary (($caught.Data['OwnedLeaseCleanupUnverified'] -eq $true) -eq $withLeaseFlag -and $caught.Data['PrimaryReasonCode'] -ceq 'VALIDATION.TOOLING_UNRESOLVED') 'CLR wrapper hid the acquisition lease/primary metadata.'
    Assert-TerraformBoundary (-not $caught.ToString().Contains('private wrapper details') -and $f.State.Requests.Count -eq 0) 'CLR wrapper details escaped or an unsafe acquisition dispatched.'
}
foreach($primary in @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED')){
    foreach($wrap in @($false,$true)){
        $f=New-TerraformFixture;$f.State.ThrowOnDispose=$true
        $acquisition=[pscustomobject]@{OpenCalls=0;ValidOpen=$f.Channel.OpenPinnedFile}
        $inner=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
        $inner.Data['OwnedCleanupUnverified']=$true;$inner.Data['OwnedLeaseCleanupUnverified']=$true
        $inner.Data['PrimaryReasonCode']=$primary
        $openFailure=$inner
        if($wrap){$openFailure=[Management.Automation.MethodInvocationException]::new('private combined acquisition detail',$inner)}
        $combinedOpen={
            param($path)
            if(++$acquisition.OpenCalls -eq 1){return & $acquisition.ValidOpen $path}
            throw $openFailure
        }.GetNewClosure()
        $parameters=@{Pins=$f.Pins;DeadlineUtc=$f.Channel.DeadlineUtc;UtcNow=$f.Channel.Clock;OpenPinnedFile=$combinedOpen;RunProcess=$f.Channel.RunProcess}
        $combinedChannel=New-AzureValidationTerraformChannel @parameters
        $caught=$null;try{$null=Get-AzureValidationTerraformVersion -Channel $combinedChannel}catch{$caught=$_.Exception}
        Assert-TerraformBoundary ($null -ne $caught -and $caught.Message -ceq 'VALIDATION.CLEANUP_UNVERIFIED' -and $caught.Data['PrimaryReasonCode'] -ceq $primary) 'Combined acquisition/release failure replaced the original primary reason.'
        Assert-TerraformBoundary ($caught.Data['OwnedCleanupUnverified'] -eq $true -and $caught.Data['OwnedLeaseCleanupUnverified'] -eq $true -and @($f.State.Streams|Where-Object { -not $_.Attempted }).Count -eq 0) 'Combined acquisition/release failure skipped a lease or lost the cleanup stop signal.'
        Assert-TerraformBoundary ($f.State.Requests.Count -eq 0 -and -not $caught.ToString().Contains('private combined acquisition detail') -and -not $caught.ToString().Contains('private pin cleanup detail')) 'Combined acquisition/release failure dispatched or leaked private details.'
    }
}
# Losing the process result cannot prove the owned tree absent.
$f=New-TerraformFixture
$f.State.Reply=$null
Assert-TerraformRefusal { Get-AzureValidationTerraformVersion -Channel $f.Channel } 'VALIDATION.CLEANUP_UNVERIFIED' $true
Assert-TerraformBoundary (@($f.State.Streams|Where-Object CanRead).Count -eq 0) 'Ambiguous process result skipped pin lease disposal.'
foreach ($role in @('Terraform','Provider','CliConfig')) {
    $f=New-TerraformFixture
    $observed=[byte[]]$f.State.Bytes[$f.Pins[$role].Path].Clone()
    $observed[0]=$observed[0] -bxor 1
    $f.State.Bytes[$f.Pins[$role].Path]=$observed
    Assert-TerraformRefusal { Get-AzureValidationTerraformVersion -Channel $f.Channel } 'VALIDATION.TOOLING_UNRESOLVED'
    Assert-TerraformBoundary ($f.State.Requests.Count -eq 0 -and @($f.State.Streams|Where-Object CanRead).Count -eq 0) 'Changed exact pin bytes executed a process or leaked a held stream.'
}
$f=New-TerraformFixture
$original=$f.Pins.Terraform.Path
$f.Pins.Terraform.Path='C:\synthetic-private-tools\substituted.exe'
$null=Get-AzureValidationTerraformVersion -Channel $f.Channel
Assert-TerraformBoundary ($f.State.Requests[0].Executable -ceq $original) 'Mutating caller pins substituted the admitted executable.'
$f=New-TerraformFixture
$f.State.Now=$f.State.Now.AddMinutes(5)
Assert-TerraformRefusal { Get-AzureValidationTerraformVersion -Channel $f.Channel } 'VALIDATION.ROUND_INTERRUPTED'
Assert-TerraformBoundary ($f.State.Requests.Count -eq 0 -and $f.State.Streams.Count -eq 0) 'Expired version request read pins or dispatched.'
foreach ($text in @(
    '{"terraform_version":"1.12.3","platform":"windows_amd64"}',
    '{"terraform_version":"1.12.2","platform":"windows_arm64"}',
    '{"Terraform_Version":"1.12.2","platform":"windows_amd64"}',
    '{"terraform_version":"1.12.2","terraform_version":"1.12.2","platform":"windows_amd64"}',
    'private non-json diagnostic')) {
    $f=New-TerraformFixture
    $f.State.Reply.StandardOutput=[Text.Encoding]::UTF8.GetBytes($text)
    $f.State.Reply.StandardOutputBytes=[long]$f.State.Reply.StandardOutput.Length
    Assert-TerraformRefusal { Get-AzureValidationTerraformVersion -Channel $f.Channel } 'VALIDATION.TOOLING_UNRESOLVED'
}
$f=New-TerraformFixture
$f.State.Reply.CompleteOwnedTreeAbsent=$false
Assert-TerraformRefusal { Get-AzureValidationTerraformVersion -Channel $f.Channel } 'VALIDATION.CLEANUP_UNVERIFIED' $true
$f=New-TerraformFixture
$f.State.Reply.StandardOutputBytes=[string]$f.State.Reply.StandardOutputBytes
Assert-TerraformRefusal { Get-AzureValidationTerraformVersion -Channel $f.Channel } 'VALIDATION.TOOLING_UNRESOLVED'
Assert-TerraformBoundary ($script:NativeRequests -eq 0) 'A negative injected fixture attempted native execution.'
$f=New-TerraformFixture
$f.Pins.Terraform.Path='\\unapproved.example\share\terraform.exe'
$channelParameters=@{Pins=$f.Pins;DeadlineUtc=$f.State.Now.AddMinutes(5);UtcNow={ [DateTimeOffset]::Parse('2030-01-01T00:00:00Z') }}
Assert-TerraformRefusal { New-AzureValidationTerraformChannel @channelParameters } 'VALIDATION.TOOLING_UNRESOLVED'
$f=New-TerraformFixture
$f.State.Reply.Started=$false
$f.State.Reply.CompleteOwnedTreeAbsent=$false
$f.State.Reply.FailureStage='TerminationIncomplete'
Assert-TerraformRefusal { Get-AzureValidationTerraformVersion -Channel $f.Channel } 'VALIDATION.CLEANUP_UNVERIFIED' $true
Assert-TerraformBoundary (@($f.State.Streams|Where-Object CanRead).Count -eq 0) 'Suspended process failure skipped pin disposal.'
# A CLR shim records dispatch but cannot create a process. Initialization
# deliberately crosses the real absolute deadline before the gateway runs.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Threading;
namespace WinPCInfo.TerraformBoundaryTests {
    public static class NativeRunner {
        public static int Calls;
        public static object Run(string executable,string[] arguments,string directory,
            IDictionary<string,string> environment,int timeout,int outLimit,int errLimit,
            CancellationToken cancellation,EventWaitHandle cancelEvent,int grace,int verification,bool simulation) {
            Calls++;
            return null;
        }
    }
}
'@
# Keep the synthetic runner type out of the production namespace. Only the
# final native dispatch type is substituted in the saved real gateway body;
# deadline checks and pre-start proof execute unchanged, without OS processes.
$script:NativeBridge=[scriptblock]::Create($script:NativeBridge.ToString().Replace(
    '[WinPCInfo.ProcessSupervisor.NativeRunner]', '[WinPCInfo.TerraformBoundaryTests.NativeRunner]').
    Replace('Assert-AzureTerraformNativeController','Assert-TestTerraformUnprivilegedController').
    Replace('Assert-AzureTerraformDrivePath','Assert-TestTerraformGlobalDrive'))
# The deadline fixture supplies injected admitted-controller/global-drive
# policy outcomes; actual path policy is tested separately through native API
# substitutes. No real process or privileged controller is admitted here.
function Assert-TestTerraformUnprivilegedController {}
function Assert-TestTerraformGlobalDrive {param($Path)}
function Initialize-ProcessSupervisorNativeType { Start-Sleep -Milliseconds 200 }
function Invoke-AzureTerraformNativeProcess { param($Request) & $script:NativeBridge -Request $Request }
$f=New-TerraformFixture
$deadlineParameters=@{Pins=$f.Pins;DeadlineUtc=[DateTimeOffset]::UtcNow.AddMilliseconds(150);OpenPinnedFile=$f.Channel.OpenPinnedFile}
$deadlineChannel=New-AzureValidationTerraformChannel @deadlineParameters
Assert-TerraformRefusal { Get-AzureValidationTerraformVersion -Channel $deadlineChannel } 'VALIDATION.ROUND_INTERRUPTED'
Assert-TerraformBoundary ([WinPCInfo.TerraformBoundaryTests.NativeRunner]::Calls -eq 0) 'Initialization crossed the deadline but still dispatched the process runner.'
Assert-TerraformBoundary (@($f.State.Streams|Where-Object CanRead).Count -eq 0) 'Pre-dispatch deadline refusal skipped pin disposal.'
[ordered]@{recordType='win-pcinfo.injected-terraform-boundary-tests';result='Pass';nonQualifying=$true;
    assertions=$script:Assertions;nativeRequests=$script:NativeRequests;
    scope='Exact pinned file leases and version command interpretation only; no init/apply/cloud/qualification'}|ConvertTo-Json -Compress|Write-Output
