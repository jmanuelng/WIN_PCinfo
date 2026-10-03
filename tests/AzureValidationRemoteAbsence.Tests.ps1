[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot) 'src'
. (Join-Path $source 'AzureValidationArmTransport.ps1')
. (Join-Path $source 'AzureValidationRemoteAbsence.ps1')
$script:AbsenceAssertions = 0
$script:AbsenceNativeRequests = 0
function Invoke-AzureArmHttpRequest {
    param($Request)
    $script:AbsenceNativeRequests++
    throw 'TEST.NATIVE_NETWORK_PROHIBITED'
}
function Assert-RemoteAbsence {
    param([bool] $Condition, [string] $Message)
    $script:AbsenceAssertions++
    if (-not $Condition) { throw $Message }
}
function New-RemoteAbsenceFixture {
    $sub = '/subscriptions/11111111-1111-1111-1111-111111111111'
    $group = $sub + '/resourceGroups/synthetic-round'
    $hostGroup = $sub + '/resourceGroups/synthetic-host'
    $roundVnet = $group + '/providers/Microsoft.Network/virtualNetworks/round'
    $hostVnet = $hostGroup + '/providers/Microsoft.Network/virtualNetworks/host'
    $principal = '22222222-2222-2222-2222-222222222222'
    $tenant = '33333333-3333-3333-3333-333333333333'
    $identity = $hostGroup+'/providers/Microsoft.Compute/virtualMachines/controller'
    $now = [DateTimeOffset]::Parse('2030-01-01T00:00:00Z')
    $targets = @(
        @{Role='RoundGroup';ReadRouteName='ReadGroup';Id=$group;Type='Microsoft.Resources/resourceGroups'}
        @{Role='RoundResource';ReadRouteName='ReadVnet';Id=$roundVnet;Type='Microsoft.Network/virtualNetworks'}
        @{Role='RoundPeering';ReadRouteName='ReadRoundPeering';Id=($roundVnet+'/virtualNetworkPeerings/to-host');Type='Microsoft.Network/virtualNetworks/virtualNetworkPeerings'}
        @{Role='HostPeering';ReadRouteName='ReadHostPeering';Id=($hostVnet+'/virtualNetworkPeerings/to-round');Type='Microsoft.Network/virtualNetworks/virtualNetworkPeerings'}
    )
    $routes = [Collections.Generic.List[object]]::new()
    foreach ($target in $targets) {
        $routes.Add(@{Name=$target.ReadRouteName;Method='GET';Path=$target.Id;ApiVersion=$(if($target.Role -ceq 'RoundGroup'){'2021-04-01'}else{'2025-09-01'});
            Paginated=$false;ScopePrefix='';ResourceType=''})
    }
    $routes.Add(@{Name='RoundResources';Method='GET';Path=($group+'/resources');ApiVersion='2021-04-01';
        Paginated=$true;ScopePrefix=$group;ResourceType='*'})
    $routes.Add(@{Name='SubscriptionResources';Method='GET';Path=($sub+'/resources');ApiVersion='2021-04-01';
        Paginated=$true;ScopePrefix=$sub;ResourceType='*'})
    $routes.Add(@{Name='HostPeerings';Method='GET';Path=($hostVnet+'/virtualNetworkPeerings');ApiVersion='2025-09-01';
        Paginated=$true;ScopePrefix=$hostGroup;ResourceType='Microsoft.Network/virtualNetworks/virtualNetworkPeerings'})
    $state = [pscustomobject]@{
        Replies=@{}; Requests=[Collections.Generic.List[object]]::new(); Now=$now
    }
    foreach ($target in $targets) { $state.Replies[$target.Id]=@{Status=404;Text=''} }
    $state.Replies[$group+'/resources']=@{Status=404;Text=''}
    $state.Replies[$sub+'/resources']=@{Status=200;Text='{"value":[]}'}
    $state.Replies[$hostVnet+'/virtualNetworkPeerings']=@{Status=200;Text='{"value":[]}'}
    $send = {
        param($request)
        $state.Requests.Add($request)
        if ($request.Uri.StartsWith('http://169.254.169.254/')) {
            $claims=@{oid=$principal;tid=$tenant;xms_mirid=$identity;aud='https://management.azure.com/';exp=$state.Now.AddHours(1).ToUnixTimeSeconds()}
            $claimsBytes=[Text.UTF8Encoding]::new($false).GetBytes(($claims | ConvertTo-Json -Compress))
            $payload=[Convert]::ToBase64String($claimsBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
            $text=@{token_type='Bearer';resource='https://management.azure.com/';access_token="e30.$payload.c3ludGhldGlj";
                expires_on=[string]$claims.exp} | ConvertTo-Json -Compress
            return [pscustomobject]@{StatusCode=200;Uri=$request.Uri;Body=[Text.UTF8Encoding]::new($false).GetBytes($text)}
        }
        $path=([uri]$request.Uri).AbsolutePath
        if (-not $state.Replies.ContainsKey($path)) { throw 'TEST.UNEXPECTED_ROUTE' }
        $reply=$state.Replies[$path]
        [pscustomobject]@{StatusCode=[int]$reply.Status;Uri=$request.Uri;Body=[Text.UTF8Encoding]::new($false).GetBytes($reply.Text)}
    }.GetNewClosure()
    $clock={ $state.Now }.GetNewClosure()
    $args=@{ExpectedPrincipalId=$principal;ExpectedTenantId=$tenant;ExpectedIdentityResourceId=$identity;Routes=$routes.ToArray();
        SendRequest=$send;UtcNow=$clock;DeadlineUtc=$now.AddMinutes(15)}
    $channel=New-AzureValidationArmChannel @args
    $args=@{Channel=$channel;Targets=$targets;TransientCollectionRouteName='RoundResources';
        TaggedCollectionRouteName='SubscriptionResources';HostPeeringCollectionRouteName='HostPeerings';RoundCorrelation='synthetic-round-token'}
    $plan=New-AzureValidationRemoteAbsencePlan @args
    [pscustomobject]@{Plan=$plan;Channel=$channel;State=$state;Targets=$targets;Routes=$routes;Sub=$sub;
        Group=$group;HostGroup=$hostGroup;RoundVnet=$roundVnet;HostVnet=$hostVnet;Token='synthetic-round-token'}
}
function Set-RemoteFixtureCollection {
    param($Fixture,[string] $Path,[object[]] $Items)
    $Fixture.State.Replies[$Path]=@{Status=200;Text=(@{value=$Items}|ConvertTo-Json -Depth 10 -Compress)}
}
function Get-RemoteFixtureReport {
    param($Fixture)
    $report=Get-AzureValidationRemoteAbsence -Plan $Fixture.Plan
    $json=$report|ConvertTo-Json -Depth 5 -Compress
    Assert-RemoteAbsence ($json -notmatch '/subscriptions/|access_token|synthetic-round-token') 'Private binding entered projected absence result.'
    Assert-RemoteAbsence ($report.NonQualifying -and -not $report.QualifyingEvidence) 'Injected observations became qualifying evidence.'
    $report
}
$f=New-RemoteAbsenceFixture
$f.Targets[0].Id=$f.HostGroup
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceProven' -and $report.Complete -and $report.ExactTargetsAbsent -and
    $report.BothPeeringsAbsent -and $report.TransientScopeEmpty -and $report.TagSweepEmpty) 'Complete404/empty remote queries did not prove the narrow remote absence predicates.'
Assert-RemoteAbsence ($null -eq $report.PSObject.Properties['ZeroResidue']) 'Remote queries alone claimed full zero residue.'
Assert-RemoteAbsence (@($f.State.Requests|Where-Object Method -ne GET).Count -eq 0) 'Absence proof dispatched a mutation.'

foreach ($targetRole in @('RoundResource','RoundPeering','HostPeering')) {
    $f=New-RemoteAbsenceFixture
    $target=@($f.Targets|Where-Object Role -eq $targetRole)[0]
    $f.State.Replies[$target.Id]=@{Status=200;Text=(@{id=$target.Id;type=$target.Type}|ConvertTo-Json -Compress)}
    $report=Get-RemoteFixtureReport $f
    Assert-RemoteAbsence ($report.State -ceq 'RemoteResiduePresent' -and -not $report.ExactTargetsAbsent) "Present $targetRole was reported absent."
}
$f=New-RemoteAbsenceFixture
$f.State.Replies[$f.Targets[3].Id]=@{Status=200;Text=(@{id=$f.Targets[3].Id;properties=@{remoteVirtualNetwork=@{id=$f.RoundVnet}}}|ConvertTo-Json -Depth 5 -Compress)}
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteResiduePresent' -and -not $report.BothPeeringsAbsent) 'Valid present peering with optional type omitted was not classified as residue.'
$f=New-RemoteAbsenceFixture
$unknown=@{id=($f.HostVnet+'/virtualNetworkPeerings/untyped');properties=@{remoteVirtualNetwork=@{id=$f.RoundVnet}}}
Set-RemoteFixtureCollection $f ($f.HostVnet+'/virtualNetworkPeerings') @($unknown)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteResiduePresent' -and -not $report.BothPeeringsAbsent) 'Legitimate typed-collection peering without optional type escaped sweep.'
$f=New-RemoteAbsenceFixture
$f.State.Replies[$f.Targets[1].Id]=@{Status=202;Text='{}'}
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceUnverified' -and -not $report.Complete) 'Accepted status became absence.'
$f=New-RemoteAbsenceFixture
$f.State.Replies[$f.Targets[1].Id]=@{Status=403;Text='private denied body'}
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceUnverified') 'Denied exact query became absence.'

$f=New-RemoteAbsenceFixture
$foreign=@{id=($f.HostGroup+'/providers/Microsoft.Compute/virtualMachines/unrelated');type='Microsoft.Compute/virtualMachines';tags=@{Purpose='Unrelated'}}
Set-RemoteFixtureCollection $f ($f.Sub+'/resources') @($foreign)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceProven') 'Unrelated subscription resource was adopted as round residue.'
$f=New-RemoteAbsenceFixture
$unknown=@{id=($f.HostGroup+'/providers/Microsoft.Compute/virtualMachines/unrecorded');type='Microsoft.Compute/virtualMachines';tags=@{RoundCorrelation=$f.Token}}
Set-RemoteFixtureCollection $f ($f.Sub+'/resources') @($unknown)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteResiduePresent' -and -not $report.TagSweepEmpty) 'Unrecorded matching-tag resource escaped independent sweep.'
$f=New-RemoteAbsenceFixture
$unknown=@{id=($f.HostGroup+'/providers/Microsoft.Compute/virtualMachines/lowercase-tag');type='Microsoft.Compute/virtualMachines';tags=@{roundcorrelation=$f.Token}}
Set-RemoteFixtureCollection $f ($f.Sub+'/resources') @($unknown)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteResiduePresent' -and -not $report.TagSweepEmpty) 'Case-insensitive Azure tag name concealed matching round residue.'
foreach ($outerField in @('Tags','TAGS')) {
    $f=New-RemoteAbsenceFixture
    $unknown=@{id=($f.HostGroup+'/providers/Microsoft.Compute/virtualMachines/outer-case');type='Microsoft.Compute/virtualMachines'}
    $unknown[$outerField]=@{RoundCorrelation=$f.Token}
    Set-RemoteFixtureCollection $f ($f.Sub+'/resources') @($unknown)
    $report=Get-RemoteFixtureReport $f
    Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceUnverified' -and -not $report.Complete) 'Malformed outer tag field was mistaken for absent tags.'
}
$f=New-RemoteAbsenceFixture
$unknown=@{id=($f.HostVnet+'/virtualNetworkPeerings/wrong-type-case');Type='Microsoft.Compute/virtualMachines';properties=@{remoteVirtualNetwork=@{id=($f.Sub+'/resourceGroups/unrelated/providers/Microsoft.Network/virtualNetworks/other')}}}
Set-RemoteFixtureCollection $f ($f.HostVnet+'/virtualNetworkPeerings') @($unknown)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceUnverified' -and -not $report.Complete) 'Malformed optional type field concealed contradictory resource kind.'
$f=New-RemoteAbsenceFixture
$unrelatedValue=@{id=($f.HostGroup+'/providers/Microsoft.Compute/virtualMachines/different-token-case');type='Microsoft.Compute/virtualMachines';tags=@{RoundCorrelation=$f.Token.ToUpperInvariant()}}
Set-RemoteFixtureCollection $f ($f.Sub+'/resources') @($unrelatedValue)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceProven') 'Case-sensitive correlation value adopted an unrelated resource.'
$f=New-RemoteAbsenceFixture
$unknown=@{id=($f.Group+'/providers/Microsoft.Compute/virtualMachines/untagged');type='Microsoft.Compute/virtualMachines'}
Set-RemoteFixtureCollection $f ($f.Sub+'/resources') @($unknown)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteResiduePresent' -and -not $report.TransientScopeEmpty) 'Subscription sweep contradiction or missing tags concealed scoped residue.'

$f=New-RemoteAbsenceFixture
$unknown=@{id=($f.HostVnet+'/virtualNetworkPeerings/unrecorded');type='Microsoft.Network/virtualNetworks/virtualNetworkPeerings';
    properties=@{remoteVirtualNetwork=@{id=$f.RoundVnet}}}
Set-RemoteFixtureCollection $f ($f.HostVnet+'/virtualNetworkPeerings') @($unknown)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteResiduePresent' -and -not $report.BothPeeringsAbsent) 'Unrecorded host-side edge to this round escaped peering enumeration.'
$f=New-RemoteAbsenceFixture
$unrelated=@{id=($f.HostVnet+'/virtualNetworkPeerings/unrelated');type='Microsoft.Network/virtualNetworks/virtualNetworkPeerings';
    properties=@{remoteVirtualNetwork=@{id=($f.Sub+'/resourceGroups/unrelated/providers/Microsoft.Network/virtualNetworks/other')}}}
Set-RemoteFixtureCollection $f ($f.HostVnet+'/virtualNetworkPeerings') @($unrelated)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceProven') 'Unrelated host peering was adopted.'
$f=New-RemoteAbsenceFixture
$broken=@{id=($f.HostVnet+'/virtualNetworkPeerings/broken');type='Microsoft.Network/virtualNetworks/virtualNetworkPeerings';properties=@{}}
Set-RemoteFixtureCollection $f ($f.HostVnet+'/virtualNetworkPeerings') @($broken)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceUnverified' -and -not $report.Complete) 'Malformed host edge became a complete empty proof.'
$f=New-RemoteAbsenceFixture
$f.State.Now=$f.State.Now.AddMinutes(15)
$report=Get-RemoteFixtureReport $f
Assert-RemoteAbsence ($report.State -ceq 'RemoteAbsenceUnverified' -and $report.ReasonCode -ceq 'VALIDATION.ROUND_INTERRUPTED') 'Expired observation lost interruption reason.'
Assert-RemoteAbsence ($f.State.Requests.Count -eq 0) 'Expired absence observation requested identity.'
Assert-RemoteAbsence ($script:AbsenceNativeRequests -eq 0) 'Remote absence tests attempted native HTTP.'
[ordered]@{recordType='win-pcinfo.injected-remote-absence-tests';result='Pass';nonQualifying=$true;
    assertions=$script:AbsenceAssertions;nativeHttpDispatches=$script:AbsenceNativeRequests;
    scope='Exact-ID, scope/tag and host-peer query interpretation only; local/transfer/recovery and live qualification remain separate'}|ConvertTo-Json -Compress|Write-Output
