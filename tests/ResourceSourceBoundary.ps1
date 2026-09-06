Set-StrictMode -Version Latest

function Get-ControlledResourceIdentity {
    [pscustomobject]@{User=[pscustomobject]@{Value=$(switch('__RESOURCE_CASE__'){
        AlternateAdministrator {'S-1-5-21-100-200-300-1002'}
        LocalSystem {'S-1-5-18'}
        default {'S-1-5-21-100-200-300-1001'}
    })}}
}
function Get-ControlledResourcePrincipal {
    $value=[pscustomobject]@{}
    $value|Add-Member ScriptMethod IsInRole {param($Role) '__RESOURCE_CASE__' -in @('AlternateAdministrator','LocalSystem')}
    $value
}
function Get-ResourceDependenciesLiveSource {
    $source=Get-OriginalResourceDependenciesLiveSource
    $source=$source.Replace('[Security.Principal.WindowsIdentity]::GetCurrent()', '(Get-ControlledResourceIdentity)')
    $source=$source.Replace('[Security.Principal.WindowsPrincipal]::new($identity)', '(Get-ControlledResourcePrincipal)')
    $source=$source.Replace('[Microsoft.Win32.Registry]::CurrentUser', '(Open-ControlledResourceKey ''CurrentUser'')')
    $source=$source.Replace('[Microsoft.Win32.Registry]::LocalMachine', '(Open-ControlledResourceKey ''LocalMachine'')')
    $source=$source.Replace('Get-CimInstance -ClassName', 'Read-ControlledResourceCim -ClassName')
    $source=$source.Replace('[WinPCInfo.ResourceDependencies.PrinterCache]::Read()', '(Read-ControlledPrinterCache)')
    $source=$source.Replace('[WinPCInfo.ResourceDependencies.Connections]::Read([ref]$connectionBoundExceeded)', '(Read-ControlledResourceCim -ClassName Win32_NetworkConnection)')
    $source=$source.Replace('$null=Read-ResourcePeripheralDrivers |', '$null=Read-ControlledResourceCim -ClassName Win32_PnPSignedDriver |')
    if($source -match 'WindowsIdentity\]::GetCurrent|\[Microsoft.Win32.Registry\]|(?<!ControlledResource)CimInstance -ClassName|PrinterCache\]::Read|Connections\]::Read|\$null=Read-ResourcePeripheralDrivers'){
        throw 'Uncontrolled resource OS boundary remains; refuse live fallback.'
    }
    $prefix=@'
function Open-ControlledResourceKey {
    param([string]$Path)
    if('__RESOURCE_CASE__' -eq 'RegistryDenied' -and $Path -eq 'CurrentUser\Network'){throw [UnauthorizedAccessException]::new()}
    if('__RESOURCE_CASE__' -eq 'DefaultDenied' -and $Path -eq 'CurrentUser\Software\Microsoft\Windows NT\CurrentVersion\Windows'){throw [UnauthorizedAccessException]::new()}
    if('__RESOURCE_CASE__' -eq 'PrinterMetadataDenied' -and $Path -eq 'LocalMachine\SYSTEM\CurrentControlSet\Control\Print\Printers\Printer-東京'){throw [UnauthorizedAccessException]::new()}
    $key=[pscustomobject]@{Path=$Path}
    $key|Add-Member ScriptMethod Dispose {}
    $key|Add-Member ScriptMethod OpenSubKey {param($Name,$Writable)
        if($Writable){throw 'Registry write forbidden.'}
        Open-ControlledResourceKey ($this.Path+'\'+$Name)
    }
    $key|Add-Member ScriptMethod GetSubKeyNames {
        switch($this.Path){
            'CurrentUser\Network' {@('R','S')}
            'LocalMachine\SYSTEM\CurrentControlSet\Control\Print\Printers' {@('Printer-東京')}
            'LocalMachine\SYSTEM\CurrentControlSet\Control\Print\Environments' {@('Windows x64')}
            'LocalMachine\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers' {@('Version-3')}
            'LocalMachine\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3' {@('Driver-東京')}
            default {throw 'Unapproved registry enumeration.'}
        }
    }
    $key|Add-Member ScriptMethod GetValue {param($Name,$Default,$Options)
        if($Options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames){throw 'Registry expansion forbidden.'}
        switch($Name){
            RemotePath {if('__RESOURCE_CASE__' -eq 'Oversize'){return ('x'*513)}; return ('\\synthetic-file\'+$this.Path.Split('\')[-1]+'-東京')}
            ProviderName {return 'Microsoft Windows Network'}
            Port {return 'PORT-東京:'}
            'Printer Driver' {return 'Driver-東京'}
            Attributes {return 64}
            Manufacturer {return 'Vendor-東京'}
            DriverVersion {return '1.2.3'}
            InfPath {return 'synthetic.inf'}
            Device {return 'Printer-東京,winspool,PORT-東京:'}
            default {throw 'Unapproved registry value.'}
        }
    }
    $key
}
function Read-ControlledPrinterCache {
    if('__RESOURCE_CASE__' -eq 'PrinterDenied'){throw [UnauthorizedAccessException]::new()}
    [pscustomobject]@{Name='Printer-東京';Attributes=64}
    [pscustomobject]@{Name='\\synthetic-print\Queue-東京';Attributes=16}
}
function Read-ControlledResourceCim {
    param($ClassName,$Property,$ErrorAction)
    switch($ClassName){
        Win32_NetworkConnection {
            if('__RESOURCE_CASE__' -eq 'ConnectionDenied'){throw [UnauthorizedAccessException]::new()}
            [pscustomobject]@{LocalName='R:';RemoteName='\\synthetic-file\R-東京';ConnectionState='Disconnected';ProviderName='Microsoft Windows Network'}
            1..2|ForEach-Object {[pscustomobject]@{LocalName='';RemoteName='\\synthetic-file\UNC-東京';ConnectionState='Connected';ProviderName='Microsoft Windows Network'}}
        }
        Win32_Printer { [pscustomobject]@{Name='Printer-東京';PortName='PORT-東京:';DriverName='Driver-東京';Network=$false;Default=$true;WorkOffline=$false} }
        Win32_PrinterDriver { [pscustomobject]@{Name='Driver-東京';Manufacturer='Vendor-東京';DriverVersion='1.2.3';InfName='synthetic.inf'} }
        Win32_PnPSignedDriver {
            if('__RESOURCE_CASE__' -eq 'PeripheralUnavailable'){throw [InvalidOperationException]::new()}
            $count=if('__RESOURCE_CASE__' -eq 'Maximum'){9}else{2}
            1..$count|ForEach-Object {[pscustomobject]@{DeviceClass='USB';DeviceName=$(if($count -eq 9){"Dock-$_"}else{'Dock-東京'});Manufacturer='Vendor';DriverProviderName='Provider';DriverVersion='1.2';InfName='dock.inf';IsSigned=$true}}
        }
        default {throw 'Unapproved CIM source.'}
    }
}
'@
    $identity=(Get-Command Get-ControlledResourceIdentity).ScriptBlock.ToString()
    $principal=(Get-Command Get-ControlledResourcePrincipal).ScriptBlock.ToString()
    "function Get-ControlledResourceIdentity {$identity}`nfunction Get-ControlledResourcePrincipal {$principal}`n"+$prefix+"`n"+$source
}
