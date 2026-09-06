Set-StrictMode -Version Latest

function Add-ControlledResourceSources {
    param([string]$ModuleText,[string]$Scenario)
    $ModuleText=$ModuleText.Replace('Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty }',
        'Invoke-ControlledResourceDependenciesCollection -Policy $Policy -Live -AssessmentUserSid ''S-1-5-21-100-200-300-1001'' }')
    $ModuleText=$ModuleText.Replace('function Get-ResourceDependenciesLiveSource {','function Get-OriginalResourceDependenciesLiveSource {')
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($ModuleText,[ref]$tokens,[ref]$errors)
    $collector=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-ControlledResourceDependenciesCollection'},$false)
    $text=$collector.Extent.Text.Replace('[Security.Principal.WindowsIdentity]::GetCurrent()', '(Get-ControlledResourceIdentity)')
    $text=$text.Replace('[Security.Principal.WindowsPrincipal]::new($identity)', '(Get-ControlledResourcePrincipal)')
    $ModuleText=$ModuleText.Replace($collector.Extent.Text,$text)
    $ModuleText+"`n"+[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ResourceSourceBoundary.ps1')).Replace('__RESOURCE_CASE__',$Scenario)
}

function Assert-ResourceSourceReport {
    param($Record,[string]$Html,[string]$Scenario)
    function Coverage($Name){@($Record.coverage|Where-Object scopeId -eq "scope:resource.$Name")[0]}
    function Values($Name){@($Record.observations|Where-Object fieldId -eq "field:resource.$Name")}
    if($Scenario -in @('AlternateAdministrator','LocalSystem')){
        Assert-Equal 5 @($Record.coverage|Where-Object {$_.scopeId -like 'scope:resource.*' -and $_.state -eq 'Denied'}).Count 'other execution contexts cannot substitute user resources'
        Assert-Equal 0 @($Record.observations|Where-Object fieldId -like 'field:resource.*').Count 'context denial fabricates no absent resources'
        return
    }
    Assert-Equal $(switch($Scenario){RegistryDenied{'Denied'};Oversize{'Partial'};ConnectionDenied{'Partial'};default{'Complete'}}) (Coverage 'mapped-drives').state 'resource definitions retain scoped failure/size semantics'
    Assert-Equal $(if($Scenario -eq 'ConnectionDenied'){'Denied'}else{'Complete'}) (Coverage 'unc-connections').state 'local connection source denial is distinct from absence'
    Assert-Equal $(if($Scenario -eq 'PrinterDenied'){'Denied'}else{'Partial'}) (Coverage 'printers').state 'cached remote printer details are explicitly incomplete'
    Assert-Equal 'Complete' (Coverage 'printer-drivers').state 'independent local driver metadata survives unrelated gaps'
    if($Scenario -in @('Complete','ProviderMismatch','ProviderUnavailable')){
        $mapped=@(Values 'mapped-drive.local-name'|Where-Object value -eq 'R:')[0]
        $provider=@(Values 'mapped-drive.provider-name'|Where-Object subjectId -eq $mapped.subjectId)[0]
        if($Scenario -eq 'Complete'){
            Assert-Equal 'ObservedValue' $provider.valueState 'an exact drive and endpoint match preserves already-read provider metadata'
            Assert-Equal 'Microsoft Windows Network' $provider.value 'correlated provider survives protected reopening'
        }else{
            Assert-Equal 'SourceReportedUnknown' $provider.valueState 'a differing endpoint or unavailable registry provider cannot inherit metadata'
        }
        $endpoint=@(Values 'mapped-drive.remote-endpoint'|Where-Object subjectId -eq $mapped.subjectId)[0]
        Assert-Equal $(if($Scenario -eq 'ProviderMismatch'){'\\synthetic-file\Other-東京'}else{'\\synthetic-file\R-東京'}) $endpoint.value 'the local session table retains its actual target'
        Assert-Equal $true $Html.Contains('id="'+$provider.observationId+'"') 'the provider observation remains traceable in HTML'
    }
    if($Scenario -eq 'DriverRegistrations'){
        $drivers=@(Values 'printer-driver.name'|Where-Object value -eq 'Driver-東京')
        Assert-Equal 3 $drivers.Count 'same-name registrations retain distinct subjects through normalization and protected reopening'
        Assert-Equal 3 @($drivers.subjectId|Sort-Object -Unique).Count 'registration identity is not the display name'
        $registrations=foreach($driver in $drivers){
            $environment=@(Values 'printer-driver.environment'|Where-Object subjectId -eq $driver.subjectId)[0]
            $model=@(Values 'printer-driver.driver-model'|Where-Object subjectId -eq $driver.subjectId)[0]
            $version=@(Values 'printer-driver.version'|Where-Object subjectId -eq $driver.subjectId)[0]
            $inf=@(Values 'printer-driver.inf-name'|Where-Object subjectId -eq $driver.subjectId)[0]
            foreach($observation in @($driver,$environment,$model,$version,$inf)){
                Assert-Equal $true $Html.Contains('id="'+$observation.observationId+'"') 'each registration field is traceable in HTML'
                Assert-Equal $true $Html.Contains([Net.WebUtility]::HtmlEncode([string]$observation.value)) 'each exact registration value reaches HTML'
            }
            '{0}|{1}|{2}|{3}' -f $environment.value,$model.value,$version.value,$inf.value
        }
        Assert-Equal 'Windows ARM64|Version-3|1.2.3|synthetic.inf;Windows x64|Version-3|1.2.3|synthetic.inf;Windows x64|Version-4|4.5.6|synthetic-v4.inf' (@($registrations|Sort-Object)-join ';') 'environment, model, version and INF stay attached to their actual registration'
    }
    Assert-Equal $(switch($Scenario){PeripheralUnavailable{'Failed'};Maximum{'Partial'};default{'Complete'}}) (Coverage 'common-peripherals').state 'peripheral source failures and limits remain explicit'
    if($Scenario -ne 'PrinterDenied'){
        $remote=@(Values 'printer.name'|Where-Object value -eq '\\synthetic-print\Queue-東京')[0]
        $port=@(Values 'printer.port-name'|Where-Object subjectId -eq $remote.subjectId)[0]
        Assert-Equal 'SourceReportedUnknown' $port.valueState 'an unavailable remote port is never represented as absent or contacted'
        if($Scenario -ne 'PrinterMetadataDenied'){
            Assert-Equal 'Driver-東京' (@(Values 'printer.driver-name'|Where-Object valueState -eq ObservedValue)[0].value) 'typed local printer-to-driver binding survives protected reopening'
            Assert-Equal $true $Html.Contains('PORT-東京:') 'offline HTML retains exact local printer port metadata'
        }else{
            Assert-Equal 2 @(Values 'printer.name'|Where-Object valueState -eq ObservedValue).Count 'metadata denial preserves both cached printer names'
        }
    }
    Assert-Equal $true $Html.Contains('Driver-東京') 'offline HTML retains local driver evidence'
    Assert-Equal $true $Html.Contains('source:windows.local.print-cache') 'source provenance describes the actual cache/registry source'
    Assert-Equal 'Indeterminate' (@($Record.findings|Where-Object ruleId -eq 'rule:resource.user-migration-dependencies/1.0.0')[0].outcome) 'incomplete printer cache cannot produce a complete migration conclusion'
    Assert-Equal $true (@($Record.recommendations|Where-Object definitionId -eq 'recommendation:resource.validate-user-resources/1.0.0').Count -eq 1) 'coverage gap still has migration follow-up guidance'
    Assert-Equal $(if($Scenario -eq 'PeripheralUnavailable'){0}elseif($Scenario -eq 'Maximum'){8}else{1}) @(Values 'peripheral.name'|Where-Object valueState -eq ObservedValue).Count 'duplicate and unavailable devices remain bounded without false absence'
    if($Scenario -eq 'Complete'){
        Assert-Equal 2 @(Values 'mapped-drive.local-name').Count 'disconnected remembered mappings survive correlation'
        Assert-Equal 'Unavailable' (@(Values 'mapped-drive.connection-state')[0].value) 'a local session-table name does not claim remote reachability'
        Assert-Equal 1 @(Values 'share.endpoint').Count 'duplicate UNC entries produce one typed dependency'
    }
}
