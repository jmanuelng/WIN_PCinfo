Set-StrictMode -Version Latest

function Add-ControlledConnectivitySources {
    param([string]$ModuleText,[string]$Scenario)
    $ModuleText=$ModuleText.Replace('$failureReasonCode = if', '$script:StatusDeskTransport.State.ConnectivityFailure=$_.Exception.Message + $_.ScriptStackTrace; $failureReasonCode = if')
    $ModuleText=$ModuleText.Replace("if (`$NetworkBehavior -ne 'LocalOnly') { throw 'Unexpected assessment network authority.' }",'')
    $ModuleText=$ModuleText.Replace('Invoke-ControlledMicrosoftConnectivityCollection -Policy $Policy -ValidationScenario LocalOnly -NetworkBehavior LocalOnly',
        'Invoke-ControlledMicrosoftConnectivityCollection -Policy $Policy -Live -NetworkBehavior $NetworkBehavior -ConnectivityContext $ConnectivityContext -ContextDigest $ContextDigest')
    $ModuleText=$ModuleText.Replace('param($Policy, [switch]$Live, $NetworkBehavior, $AssessmentUserSid)',
        'param($Policy, [switch]$Live, $NetworkBehavior, $AssessmentUserSid, $ConnectivityContext, $ContextDigest)')
    foreach($name in @('Get-MicrosoftConnectivityExecutionContext','Invoke-MicrosoftConnectivityDnsPhase','Invoke-MicrosoftConnectivityTcpPhase','Invoke-MicrosoftConnectivityTlsPhase','Invoke-MicrosoftConnectivityHttpPhase')) {
        $ModuleText=$ModuleText.Replace("function $name {","function Unused-$name {")
    }
    $ModuleText += @'

$script:ConnectivityCase='__CASE__'
function Get-MicrosoftConnectivityExecutionContext {
    param($Policy,[switch]$Synthetic)
    $proxy=$script:ConnectivityCase -in @('WindowsProxy','ProxyBlocked','ProxyOnly','Suspected')
    $address=if($script:ConnectivityCase -eq 'ContextChanged' -and $script:StatusDeskTransport.State.ContainsKey('ConnectivityRequests')){'192.0.2.54'}else{'192.0.2.53'}
    [pscustomobject]@{ resolverState='Available'; resolvers=@($address); routes=@($Policy.endpoints | ForEach-Object {
        [pscustomobject]@{endpointId=$_.endpointId;supported=($script:ConnectivityCase -ne 'AutomaticProxy');transportMode=$(if($proxy){'WindowsProxy'}elseif($script:ConnectivityCase -eq 'AutomaticProxy'){'Indeterminate'}else{'Direct'});proxyState=$(if($proxy){'Used'}elseif($script:ConnectivityCase -eq 'AutomaticProxy'){'Unavailable'}else{'Bypassed'});proxyUri=$(if($proxy){'http://192.0.2.80:8080/'}else{$null})}
    }) }
}
function Register-ControlledConnectivityRequest {
    param([string]$Phase)
    if (-not $script:StatusDeskTransport.State.ContainsKey('ConnectivityRequests')) { $script:StatusDeskTransport.State.ConnectivityRequests=0 }
    $script:StatusDeskTransport.State.ConnectivityRequests++
}
function Invoke-MicrosoftConnectivityDnsPhase {
    param($DnsName,$DeadlineMilliseconds,$MaximumAddresses)
    Register-ControlledConnectivityRequest DNS
    if($script:ConnectivityCase -in @('DnsFailure','Timeout')){
        [pscustomobject]@{state=$(if($script:ConnectivityCase -eq 'Timeout'){'TimedOut'}else{'Failed'});count=0}
    }else{[pscustomobject]@{state='Succeeded';count=1}}
}
function Invoke-MicrosoftConnectivityTcpPhase {
    param($DnsName,$Port,$DeadlineMilliseconds)
    Register-ControlledConnectivityRequest TCP
    [pscustomobject]@{state=$(if($script:ConnectivityCase -in @('Blocked','ProxyOnly') -or ($script:ConnectivityCase -eq 'Partial' -and $DnsName -eq 'enterpriseregistration.windows.net')){'Blocked'}else{'Succeeded'})}
}
function Invoke-MicrosoftConnectivityTlsPhase {
    param($Endpoint,$DeadlineMilliseconds,$Policy)
    Register-ControlledConnectivityRequest TLS
    if($script:ConnectivityCase -eq 'InvalidChain'){
        [pscustomobject]@{state='Failed';chainState='Invalid';chainElementCount=3;chainStatusCodes='UntrustedRoot';leafSha256=('a'*64);protocol=$null;cipher=$null}
    }else{[pscustomobject]@{state='Succeeded';chainState='Trusted';chainElementCount=3;chainStatusCodes='NoError';leafSha256=('a'*64);protocol='Tls13';cipher='TLS_AES_256_GCM_SHA384'}}
}
function Invoke-MicrosoftConnectivityHttpPhase {
    param($Endpoint,$DeadlineMilliseconds,$Policy,$ProxySelection)
    Register-ControlledConnectivityRequest HTTP
    [pscustomobject]@{state=$(if($script:ConnectivityCase -eq 'Redirect'){'RedirectRejected'}elseif($script:ConnectivityCase -eq 'ProxyBlocked'){'Blocked'}else{'Succeeded'});statusCode=$(if($script:ConnectivityCase -eq 'Redirect'){302}elseif($script:ConnectivityCase -eq 'ProxyBlocked'){407}else{204});redirectState=$(if($script:ConnectivityCase -eq 'Redirect'){'Rejected'}else{'NotObserved'});headerCount=3;transportMode=$ProxySelection.transportMode;proxyState=$ProxySelection.proxyState;leafSha256=$(if($script:ConnectivityCase -eq 'Suspected'){'b'*64}else{'a'*64})}
}
'@.Replace('__CASE__',$Scenario)
    $ModuleText
}

function Assert-ConnectivitySourceReport {
    param($Record,[string]$Html,[string]$Scenario,$State)
    $expected=switch($Scenario){
        Direct {@(12,3,'NotObservedWithinCompletedTests')}
        WindowsProxy {@(12,3,'NotObservedWithinCompletedTests')}
        ProxyOnly {@(9,3,'Indeterminate')}
        Suspected {@(12,3,'Suspected')}
        Blocked {@(6,0,'Indeterminate')}
        Partial {@(10,2,'Indeterminate')}
        DnsFailure {@(3,0,'Indeterminate')}
        Timeout {@(3,0,'Indeterminate')}
        InvalidChain {@(9,0,'Indeterminate')}
        Redirect {@(12,0,'Indeterminate')}
        ProxyBlocked {@(12,0,'Indeterminate')}
        AutomaticProxy {@(9,0,'Indeterminate')}
        ContextChanged {@(1,0,'Indeterminate')}
        LocalOnly {@(0,0,'Indeterminate')}
        default {throw 'Undeclared controlled case.'}
    }
    $items=@($Record.observations | Where-Object fieldId -eq 'field:connectivity.http.state')
    Assert-Equal $(if($Scenario -eq 'LocalOnly'){0}else{3}) $items.Count 'actual protocol reducer reaches the closed endpoint record'
    $requests=if($State.ContainsKey('ConnectivityRequests')){$State.ConnectivityRequests}else{0}
    Assert-Equal $expected[0] $requests 'instrumented adapters account for the bounded protocol work'
    Assert-Equal $expected[1] @($items | Where-Object value -eq 'Succeeded').Count 'endpoint failures preserve truthful related observations'
    $inspection=@($Record.observations|Where-Object fieldId -eq 'field:connectivity.tls-inspection.outcome'|ForEach-Object value)
    $aggregate=if('Suspected' -in $inspection){'Suspected'}elseif('Indeterminate' -in $inspection -or $inspection.Count -eq 0){'Indeterminate'}else{'NotObservedWithinCompletedTests'}
    Assert-Equal $expected[2] $aggregate 'actual reducer preserves conservative inspection conclusions'
    Assert-Equal 8 @($Record.coverage|Where-Object scopeId -like 'scope:connectivity.*').Count 'eight protocol scopes remain individually traceable'
    Assert-Equal $true (@($Record.coverage|Where-Object { $_.scopeId -notlike 'scope:connectivity.*' -and $_.state -eq 'Complete' }).Count -gt 0) 'unrelated local evidence survives connectivity gaps'
    Assert-Equal $true $Html.Contains('Microsoft service connectivity') 'reopened report contains connectivity interpretation'
}
