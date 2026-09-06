[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/MicrosoftConnectivity.ps1')
$policy=Get-MicrosoftConnectivityPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)
# Only local OS context APIs are substituted; no real registry/interface is read.
$proxySource=${function:Get-MicrosoftConnectivityProxySelection}.ToString().Replace("`r`n","`n")
$proxySource=$proxySource.Replace("[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(`n            'Software\Microsoft\Windows\CurrentVersion\Internet Settings', `$false`n        )",'(New-ControlledInternetSettings)')
$proxySource=$proxySource.Replace("[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(`n            'Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections', `$false`n        )",'(New-ControlledInternetSettings -Connections)')
$proxySource=$proxySource.Replace('catch {','catch { $script:contextFailure=$_.Exception.Message;')
if($proxySource.Contains('[Microsoft.Win32.Registry]')){throw 'The approved context source boundary changed.'}
. ([scriptblock]::Create('function Get-MicrosoftConnectivityProxySelection {'+$proxySource+'}'))
function New-ControlledInternetSettings {
    param([switch]$Connections)
    $key=[pscustomobject]@{Connections=[bool]$Connections}
    $key|Add-Member ScriptMethod GetValue {
        param($name,$default)
        switch($name){
            ProxyEnable {if($script:contextCase -eq 'InvalidFlag'){2}elseif($script:contextCase -eq 'InvalidType'){'1'}else{1}}
            ProxyServer {'192.0.2.80:8080'}
            ProxyOverride {$null}
            AutoConfigURL {if($script:contextCase -eq 'Automatic'){'https://example.invalid/proxy.pac'}else{$null}}
            DefaultConnectionSettings {if($script:contextCase -eq 'MalformedBlob'){,[byte[]]@(1,2)}elseif($script:contextCase -eq 'Wpad'){,[byte[]]@(0,0,0,0,0,0,0,0,9)}else{,[byte[]]@(0,0,0,0,0,0,0,0,1)}}
            default {$default}
        }
    }
    $key|Add-Member ScriptMethod Dispose {$script:disposed++}
    $key
}
foreach($case in @('InvalidFlag','InvalidType','MalformedBlob','Automatic','Wpad','Static')){
    $script:contextCase=$case;$script:disposed=0;$script:contextFailure=''
    $result=Get-MicrosoftConnectivityProxySelection -EndpointUri ([Uri]$policy.endpoints[0].uri)
    Assert-Equal ($case -eq 'Static') $result.supported "malformed and automatic Windows proxy settings cannot authorize direct or proxy traffic: $case $script:contextFailure"
    Assert-Equal 2 $script:disposed 'both registry snapshots dispose on every context outcome'
}
$contextSource=${function:Get-MicrosoftConnectivityExecutionContext}.ToString()
if(-not $contextSource.Contains('[Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()')){throw 'The resolver context boundary changed.'}
$contextSource=$contextSource.Replace('[Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()','(Get-ControlledResolverInterfaces)')
. ([scriptblock]::Create('function Get-ControlledExecutionContext {'+$contextSource+'}'))
function Get-ControlledResolverInterfaces {
    $interface=[pscustomobject]@{Id='synthetic-interface';OperationalStatus=[Net.NetworkInformation.OperationalStatus]::Up}
    $interface|Add-Member ScriptMethod GetIPProperties {
        [pscustomobject]@{DnsAddresses=$(if($script:reverseResolvers){@([Net.IPAddress]::Parse('192.0.2.54'),[Net.IPAddress]::Parse('192.0.2.53'))}else{@([Net.IPAddress]::Parse('192.0.2.53'),[Net.IPAddress]::Parse('192.0.2.54'))})}
    }
    ,@($interface)
}
$script:reverseResolvers=$false
$initial=Get-ControlledExecutionContext -Policy $policy
$script:reverseResolvers=$true
$changed=Get-ControlledExecutionContext -Policy $policy
Assert-Equal 'Available' $initial.resolverState 'actual local context reducer retains controlled resolver configuration'
Assert-Equal $false ((Get-MicrosoftConnectivityContextDigest $initial) -ceq (Get-MicrosoftConnectivityContextDigest $changed)) 'a changed resolver priority changes the frozen context identity'
Write-Output 'PASS: actual Windows proxy context parsing fails closed for malformed flags, types, connection blobs and automatic discovery.'
