[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
$source=Join-Path $root 'src/AzureValidationTerraform.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$null,[ref]$null)
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Threading;
using System.Security.Principal;
namespace WinPCInfo.ControllerTokenTests {
 public sealed class Sid { public string Value {get;set;} }
 public sealed class Identity : IDisposable {
  public static bool Impersonating, ProcessAdmin, ProcessSystem, ProcessBackup, NullProcess, ThrowOnDispose;
  public static int EffectiveReads, ImpersonationReads, ProcessReads, DisposeCalls;
  public static void Reset(){Impersonating=false;ProcessAdmin=false;ProcessSystem=false;ProcessBackup=false;NullProcess=false;ThrowOnDispose=false;EffectiveReads=0;ImpersonationReads=0;ProcessReads=0;DisposeCalls=0;}
  public Sid User {get;private set;} public bool Admin,Backup;
  private Identity(bool process){User=new Sid {Value=process && ProcessSystem ? "S-1-5-18" : "synthetic-ordinary-controller"};Admin=process && ProcessAdmin;Backup=process && ProcessBackup;}
  public static Identity GetCurrent(){EffectiveReads++;return new Identity(!Impersonating);}
  public static Identity GetCurrent(bool ifImpersonating){
   if(ifImpersonating){ImpersonationReads++;return Impersonating ? new Identity(false) : null;}
   ProcessReads++;return NullProcess ? null : new Identity(!Impersonating);
  }
  public void Dispose(){DisposeCalls++;if(ThrowOnDispose)throw new InvalidOperationException("private token release detail");}
 }
 public sealed class Principal {
  private readonly Identity identity;
  public Principal(Identity identity){if(identity==null)throw new ArgumentNullException();this.identity=identity;}
  public bool IsInRole(WindowsBuiltInRole role){return role==WindowsBuiltInRole.Administrator ? identity.Admin : role==WindowsBuiltInRole.BackupOperator && identity.Backup;}
 }
 public static class Runner {
  public static int Calls;
  public static object Run(string executable,string[] arguments,string directory,IDictionary<string,string> environment,int timeout,int outLimit,int errLimit,CancellationToken cancellation,EventWaitHandle cancelEvent,int grace,int verification,bool simulation){Calls++;return null;}
 }
}
'@
foreach($name in @('ConvertTo-AzureTerraformClosedBoundaryFailure','Assert-AzureTerraformNativeController','Invoke-AzureTerraformNativeProcess')){
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name}.GetNewClosure(),$true)
    if($null -eq $definition){throw 'TEST.CONTROLLER_SOURCE_MISSING'}
    $text=$definition.Extent.Text.Replace('[Security.Principal.WindowsIdentity]','[WinPCInfo.ControllerTokenTests.Identity]').
        Replace('[Security.Principal.WindowsPrincipal]','[WinPCInfo.ControllerTokenTests.Principal]').
        Replace('[WinPCInfo.ProcessSupervisor.NativeRunner]','[WinPCInfo.ControllerTokenTests.Runner]')
    . ([scriptblock]::Create($text))
}
$script:MappingChecks=0
function Assert-AzureTerraformDrivePath {param($Path) $script:MappingChecks++}
function Initialize-ProcessSupervisorNativeType {}
$environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
$environment.Add('TF_CLI_CONFIG_FILE','C:\synthetic\round.tfrc')
$request=[pscustomobject]@{Executable='C:\synthetic\terraform.exe';Arguments=[string[]]@('version','-json');WorkingDirectory='C:\synthetic';Environment=$environment;TimeoutMilliseconds=1000;DeadlineUtc=[DateTimeOffset]::UtcNow.AddMinutes(1);CancellationToken=[Threading.CancellationToken]::None}
$assertions=0
foreach($case in @('ImpersonatingAdminProcess','ImpersonatingOrdinaryProcess','AdminProcess','SystemProcess','BackupProcess','NullProcess','OrdinaryProcess','TokenDisposeFault')){
    [WinPCInfo.ControllerTokenTests.Identity]::Reset()
    [WinPCInfo.ControllerTokenTests.Runner]::Calls=0;$script:MappingChecks=0
    if($case -ceq 'ImpersonatingAdminProcess'){[WinPCInfo.ControllerTokenTests.Identity]::Impersonating=$true;[WinPCInfo.ControllerTokenTests.Identity]::ProcessAdmin=$true}
    elseif($case -ceq 'ImpersonatingOrdinaryProcess'){[WinPCInfo.ControllerTokenTests.Identity]::Impersonating=$true}
    elseif($case -ceq 'AdminProcess'){[WinPCInfo.ControllerTokenTests.Identity]::ProcessAdmin=$true}
    elseif($case -ceq 'SystemProcess'){[WinPCInfo.ControllerTokenTests.Identity]::ProcessSystem=$true}
    elseif($case -ceq 'BackupProcess'){[WinPCInfo.ControllerTokenTests.Identity]::ProcessBackup=$true}
    elseif($case -ceq 'NullProcess'){[WinPCInfo.ControllerTokenTests.Identity]::NullProcess=$true}
    elseif($case -ceq 'TokenDisposeFault'){[WinPCInfo.ControllerTokenTests.Identity]::ThrowOnDispose=$true}
    $caught=$null;try{$null=Invoke-AzureTerraformNativeProcess -Request $request}catch{$caught=$_.Exception}
    $assertions++
    if($case -ceq 'OrdinaryProcess'){
        if($null -ne $caught -or [WinPCInfo.ControllerTokenTests.Runner]::Calls -ne 1 -or $script:MappingChecks -ne 3){throw 'TEST.ORDINARY_CONTROLLER_NOT_ADMITTED_TO_INJECTED_RUNNER'}
    }else{
        if($null -eq $caught -or [WinPCInfo.ControllerTokenTests.Runner]::Calls -ne 0 -or $script:MappingChecks -ne 0 -or $caught.Data['AzureTerraformNativePreStartVerified'] -ne $true){throw 'TEST.UNSAFE_TOKEN_REACHED_MAPPING_OR_DISPATCH'}
    }
    $assertions++
    if($case.StartsWith('Impersonating')){
        if([WinPCInfo.ControllerTokenTests.Identity]::ProcessReads -ne 0 -or [WinPCInfo.ControllerTokenTests.Identity]::ImpersonationReads -ne 1 -or [WinPCInfo.ControllerTokenTests.Identity]::DisposeCalls -ne 1){throw 'TEST.IMPERSONATION_NOT_REFUSED_BEFORE_PROCESS_TOKEN_READ'}
    }elseif([WinPCInfo.ControllerTokenTests.Identity]::ImpersonationReads -ne 1 -or [WinPCInfo.ControllerTokenTests.Identity]::ProcessReads -ne 1){
        throw 'TEST.CONTROLLER_TOKEN_SELECTION_NOT_PROVED'
    }
    if($case -ceq 'TokenDisposeFault'){
        $assertions++
        if($caught.Message -cne 'VALIDATION.CLEANUP_UNVERIFIED' -or $caught.Data['OwnedCleanupUnverified'] -ne $true -or $caught.Data['OwnedLeaseCleanupUnverified'] -ne $true -or $caught.ToString().Contains('private token release detail')){throw 'TEST.CONTROLLER_TOKEN_RELEASE_FAULT_LOST_STOP_SIGNAL'}
    }
}
[ordered]@{recordType='win-pcinfo.injected-controller-token-tests';result='Pass';assertions=$assertions;nonQualifying=$true;nativeTokenChanges=0;nativeProcessLaunches=0;scope='Actual native gateway and controller guard under injected token selection, mapping and runner only; no Windows impersonation or native admission'}|ConvertTo-Json -Compress
