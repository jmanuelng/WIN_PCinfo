Set-StrictMode -Version Latest

function Get-ControlledSoftwareIdentity {
    [pscustomobject]@{User=[pscustomobject]@{Value=$(if('__SOFTWARE_CASE__' -eq 'AlternateAdministrator'){'S-1-5-21-100-200-300-1002'}else{'S-1-5-21-100-200-300-1001'})}}
}
function Get-ControlledSoftwarePrincipal {
    $principal=[pscustomobject]@{}
    $principal|Add-Member ScriptMethod IsInRole {param($Role) '__SOFTWARE_CASE__' -eq 'AlternateAdministrator'}
    $principal
}
function Get-SoftwareInventoryLiveSource {
    $source=Get-OriginalSoftwareInventoryLiveSource
    $source=$source.Replace('[Security.Principal.WindowsIdentity]::GetCurrent()', '(Get-ControlledSoftwareIdentity)')
    $source=$source.Replace('[Security.Principal.WindowsPrincipal]::new($identity)', '(Get-ControlledSoftwarePrincipal)')
    $source=$source.Replace('[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)', '(Open-ControlledSoftwareHive $hive $view)')
    $source=$source.Replace('[Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime]::new()', '(New-ControlledPackageManager)')
    $native=@'
    static int MsiEnumProductsExW(string product,string user,int contexts,int index,StringBuilder code,out int installedContext,StringBuilder sid,ref int sidLength){
      if(product!=null||user!=null||(contexts!=4&&contexts!=3))throw new Exception("Unapproved MSI enumeration");
      installedContext=contexts==4?4:index==0?1:2;
      if(String.Equals("__SOFTWARE_CASE__","MsiDenied",StringComparison.Ordinal))return 5;
      if(index>=(contexts==4?1:2))return 259;
      code.Append("{00000000-0000-0000-0000-000000000001}");
      if(contexts!=4)sid.Append("S-1-5-21-100-200-300-1001");
      return 0;
    }
    static int MsiGetProductInfoExW(string code,string user,int context,string property,StringBuilder value,ref int length){
      if(user!=null)throw new Exception("Unapproved MSI user");
      string text;
      switch(property){case "State":text=context==2?"1":"5";break;case "ProductName":text="MSI 应用";break;case "VersionString":text="release-2026+任意";break;case "Publisher":text="Synthetic Publisher";break;default:throw new Exception("Unapproved MSI property");}
      if(value==null){length=text.Length;return 0;}
      if(length<text.Length+1){length=text.Length;return 234;}
      value.Append(text);length=text.Length;return 0;
    }
'@
    $pattern='(?m)^    \[DllImport\("msi.dll"[^\r\n]+\r?\n    \[DllImport\("msi.dll"[^\r\n]+'
    if([regex]::Matches($source,$pattern).Count -ne 1){throw 'MSI OS boundary changed; refuse live fallback.'}
    $source=[regex]::Replace($source,$pattern,$native)
    if($source -match 'DllImport|WindowsIdentity\]::GetCurrent|RegistryKey\]::OpenBaseKey|ContentType=WindowsRuntime'){throw 'Uncontrolled Windows source remains.'}
    $prefix=@'
function Open-ControlledSoftwareHive {
    param($Hive,$View)
    if($Hive -notin @('LocalMachine','CurrentUser') -or $View -notin @('Registry32','Registry64')){throw 'Unapproved hive/view'}
    if('__SOFTWARE_CASE__' -eq 'DeniedUser' -and $Hive -eq 'CurrentUser'){throw [UnauthorizedAccessException]::new()}
    $key=[pscustomobject]@{}
    $key|Add-Member ScriptMethod Dispose {}
    $key|Add-Member ScriptMethod OpenSubKey {param($Path,$Writable)
        if($Writable -or $Path -notin @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','Synthetic.A','Synthetic.B')){throw 'Unapproved registry path/write'}
        $this
    }
    $key|Add-Member ScriptMethod GetSubKeyNames { @('Synthetic.A','Synthetic.B') }
    $key|Add-Member ScriptMethod GetValue {param($Name,$Default,$Options)
        switch($Name){
            DisplayName {'注册应用'}
            DisplayVersion {'release-2026+任意'}
            Publisher {'Synthetic Publisher'}
            UpgradeCode {$null}
            WindowsInstaller {0}
            SystemComponent {0}
            default {throw 'Unapproved registry property'}
        }
    }
    $key
}
function New-ControlledPackageManager {
    $manager=[pscustomobject]@{}
    $manager|Add-Member ScriptMethod FindPackagesForUser {param($Sid) if($Sid -ne ''){throw 'Unapproved user'}; Get-ControlledPackages}
    $manager|Add-Member ScriptMethod FindPackages {if('__SOFTWARE_CASE__' -eq 'DeniedAllUsers'){throw [UnauthorizedAccessException]::new()}; Get-ControlledPackages}
    $manager
}
function Get-ControlledPackages {
    foreach($kind in @('Main','Framework','Bundle','Resource','Optional')){
        $status=[pscustomobject]@{};$status|Add-Member ScriptMethod VerifyIsOK {$true}
        [pscustomobject]@{
            Id=[pscustomobject]@{FamilyName=$(if($kind -eq 'Main'){'Microsoft.CompanyPortal_8wekyb3d8bbwe'}else{'Microsoft.CompanyPortal_8wekyb3d8bbwe.near'});FullName="Synthetic.$kind.1.2.3.4";Name="应用 $kind";PublisherId='synthetic';Architecture='X64';Version=[pscustomobject]@{Major=1;Minor=2;Build=3;Revision=4}}
            IsBundle=$kind -eq 'Bundle';IsFramework=$kind -eq 'Framework';IsResourcePackage=$kind -eq 'Resource';IsOptional=$kind -eq 'Optional';Status=$status
        }
    }
}
'@
    if('__SOFTWARE_CASE__' -eq 'MsiCompilerDenied'){$prefix+="`nfunction Add-Type {throw [UnauthorizedAccessException]::new()}"}
    $identity=(Get-Command Get-ControlledSoftwareIdentity).ScriptBlock.ToString()
    $principal=(Get-Command Get-ControlledSoftwarePrincipal).ScriptBlock.ToString()
    "function Get-ControlledSoftwareIdentity {$identity}`nfunction Get-ControlledSoftwarePrincipal {$principal}`n"+$prefix+"`n"+$source
}
