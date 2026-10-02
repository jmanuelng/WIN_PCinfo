[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot) 'src/AzureValidationArmTransport.ps1')
$script:ArmAssertionCount = 0
$script:ArmRefusalCount = 0
$script:ArmNativeDispatchCount = 0
$script:ArmFixtures = [Collections.Generic.List[object]]::new()
# Injected contract tests must never reach the actual network implementation.
# Count and refuse even an accidental attempt; assert zero at the end.
function Invoke-AzureArmHttpRequest {
    param($Request)
    $script:ArmNativeDispatchCount++
    throw 'TEST.NATIVE_NETWORK_PROHIBITED'
}

function Assert-ArmCondition {
    param([bool] $Condition, [string] $Message)
    $script:ArmAssertionCount++
    if (-not $Condition) { throw $Message }
}
function Assert-ArmRefuses {
    param([scriptblock] $Action, [string] $Reason)
    $script:ArmRefusalCount++
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_.Exception.Message }
    $caller = @(Get-PSCallStack)[1].ScriptLineNumber
    Assert-ArmCondition ($null -ne $caught -and $caught.Contains($Reason)) "Expected refusal $Reason at test line $caller, observed $caught."
}
function ConvertTo-ArmTestBytes {
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Text)
    return ,([Text.UTF8Encoding]::new($false).GetBytes($Text))
}
function New-ArmTestResponse {
    param([string] $Text = '{"value":[]}', [int] $Status = 200, [string] $Uri = '')
    [pscustomobject]@{ StatusCode = $Status; Uri = $Uri; Body = (ConvertTo-ArmTestBytes $Text) }
}
function New-ArmFixture {
    param([Threading.CancellationToken] $CancellationToken = [Threading.CancellationToken]::None)
    $subscription = '11111111-1111-1111-1111-111111111111'
    $scope = "/subscriptions/$subscription/resourceGroups/synthetic-round"
    $identity = "/subscriptions/$subscription/resourceGroups/synthetic-host/providers/Microsoft.Compute/virtualMachines/controller"
    $principal = '22222222-2222-2222-2222-222222222222'
    $tenant = '33333333-3333-3333-3333-333333333333'
    $now = [DateTimeOffset]::Parse('2030-01-01T00:00:00Z')
    $state = [pscustomobject]@{
        Requests = [Collections.Generic.List[object]]::new()
        Responses = [Collections.Generic.Queue[object]]::new()
        Claims = @{ oid=$principal; tid=$tenant; xms_mirid=$identity;
            aud='https://management.azure.com/'; exp=$now.AddHours(1).ToUnixTimeSeconds() }
        TokenChanges = @{}
        TokenText = $null
        ThrowPrivate = $false
        Multiple = $false
        CurrentTime = $now
        AdvanceAfterArm = $false
        CancelDuringArmSource = $null
    }
    $script:ArmFixtures.Add($state)
    $routes = @(
        @{ Name='ListResources'; Method='GET'; Path="$scope/resources"; ApiVersion='2021-04-01'; Paginated=$true; ScopePrefix=$scope; ResourceType='*' }
        @{ Name='ReadVm'; Method='GET'; Path="$scope/providers/Microsoft.Compute/virtualMachines/client"; ApiVersion='2023-03-01'; Paginated=$false; ScopePrefix=''; ResourceType='' }
        @{ Name='DeleteVm'; Method='DELETE'; Path="$scope/providers/Microsoft.Compute/virtualMachines/client"; ApiVersion='2023-03-01'; Paginated=$false; ScopePrefix=''; ResourceType='' }
        @{ Name='PutCommand'; Method='PUT'; Path="$scope/providers/Microsoft.Compute/virtualMachines/client/runCommands/approved"; ApiVersion='2023-03-01'; Paginated=$false; ScopePrefix=''; ResourceType='' }
        @{ Name='ReadScope'; Method='GET'; Path=$scope; ApiVersion='2021-04-01'; Paginated=$false; ScopePrefix=''; ResourceType='' }
        @{ Name='TypedPeers'; Method='GET'; Path=($scope+'/providers/Microsoft.Network/virtualNetworks/round/virtualNetworkPeerings'); ApiVersion='2025-09-01'; Paginated=$true; ScopePrefix=$scope; ResourceType='Microsoft.Network/virtualNetworks/virtualNetworkPeerings' }
    )
    $send = {
        param($request)
        $state.Requests.Add($request)
        if ($state.ThrowPrivate) { throw 'private synthetic token must never appear' }
        if ($request.Uri.StartsWith('http://169.254.169.254/')) {
            $payload = [Convert]::ToBase64String((ConvertTo-ArmTestBytes ($state.Claims | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_')
            $token = @{ token_type='Bearer'; resource='https://management.azure.com/';
                access_token="e30.$payload.c3ludGhldGlj"; expires_on=[string]$state.Claims.exp }
            foreach ($key in $state.TokenChanges.Keys) { $token[$key] = $state.TokenChanges[$key] }
            $text = if ($null -eq $state.TokenText) { $token | ConvertTo-Json -Compress } else { $state.TokenText }
            return New-ArmTestResponse -Text $text -Uri $request.Uri
        }
        if ($null -ne $state.CancelDuringArmSource) {
            $state.CancelDuringArmSource.Cancel()
            throw 'private synthetic transport failure after cancellation'
        }
        $response = if ($state.Responses.Count -gt 0) { $state.Responses.Dequeue() } else { New-ArmTestResponse }
        if ([string]::IsNullOrEmpty($response.Uri)) { $response.Uri = $request.Uri }
        if ($state.AdvanceAfterArm) { $state.CurrentTime = $state.CurrentTime.AddMinutes(20) }
        if ($state.Multiple) { $response; $response; return }
        $response
    }.GetNewClosure()
    $clock = { $state.CurrentTime }.GetNewClosure()
    $arguments = @{ExpectedPrincipalId=$principal;ExpectedTenantId=$tenant;ExpectedIdentityResourceId=$identity;
        Routes=$routes;SendRequest=$send;UtcNow=$clock;DeadlineUtc=$now.AddMinutes(15);CancellationToken=$CancellationToken}
    $channel = New-AzureValidationArmChannel @arguments
    [pscustomobject]@{ Channel=$channel; State=$state; Routes=$routes; Scope=$scope; Now=$now }
}
function Get-ArmRequestCount {
    param($Fixture, [switch] $Arm)
    if ($Arm) { return @($Fixture.State.Requests | Where-Object Uri -Like 'https://management.azure.com/*').Count }
    $Fixture.State.Requests.Count
}

$f = New-ArmFixture
Assert-ArmCondition ((Get-ArmRequestCount $f) -eq 0) 'Channel construction contacted a service.'
$f.Routes[1].Path = '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/foreign/resources'
foreach ($mutate in @(
    { $f.Channel['PrincipalId'] = 'changed' },
    { $f.Channel.Routes['ReadVm'] = @{Path='@example.invalid/x'} },
    { $f.Channel.Routes['ReadVm']['Path'] = '@example.invalid/x' }
)) {
    $refused = $false
    try { & $mutate } catch { $refused = $true }
    Assert-ArmCondition $refused 'Admitted channel/route state remained mutable.'
}
Assert-ArmRefuses {
    Resolve-AzureArmRouteUri -Route @{Path='@example.invalid/x';ApiVersion='2023-03-01';Paginated=$false}
} 'VALIDATION.SERVICE_REQUEST_INVALID'
Assert-ArmCondition ((Get-ArmRequestCount $f) -eq 0) 'Mutable route attack requested identity.'

$result = Invoke-AzureValidationArmRoute -Channel $f.Channel -Name ReadVm
Assert-ArmCondition ($result.NonQualifying -and $result.StatusCode -eq 200) 'Injected service outcome was misclassified.'
Assert-ArmCondition ($f.State.Requests[0].Headers.Metadata -ceq 'true') 'IMDS metadata header missing.'
Assert-ArmCondition ($f.State.Requests[1].Uri -ceq (
    'https://management.azure.com' + $f.Scope + '/providers/Microsoft.Compute/virtualMachines/client?api-version=2023-03-01')) 'Caller route mutation widened authority.'
Assert-ArmCondition ($f.State.Requests[1].Headers.Authorization.StartsWith('Bearer ')) 'ARM authorization omitted.'
Assert-ArmCondition ($null -eq $result.PSObject.Properties['AccessToken']) 'Token leaked in route result.'

foreach ($case in @('Unknown','GetBody','PutEmpty','PutBadJson','BadContinuation')) {
    $f = New-ArmFixture
    Assert-ArmRefuses -Reason 'VALIDATION.SERVICE_' -Action {
        switch ($case) {
            Unknown { Invoke-AzureValidationArmRoute $f.Channel -Name Arbitrary }
            GetBody { Invoke-AzureValidationArmRoute $f.Channel -Name ReadVm -Body (ConvertTo-ArmTestBytes '{}') }
            PutEmpty { Invoke-AzureValidationArmRoute $f.Channel -Name PutCommand }
            PutBadJson { Invoke-AzureValidationArmRoute $f.Channel -Name PutCommand -Body (ConvertTo-ArmTestBytes '{"a":1,"a":2}') }
            BadContinuation { Invoke-AzureValidationArmRoute $f.Channel -Name ListResources -Continuation 'https://example.invalid/resources' }
        }
    }
    Assert-ArmCondition ((Get-ArmRequestCount $f) -eq 0) "Invalid $case requested identity or ARM."
}
foreach ($field in @('oid','tid','xms_mirid','aud','exp')) {
    $f = New-ArmFixture
    $f.State.Claims[$field] = if ($field -ceq 'exp') { $f.Now.AddMinutes(1).ToUnixTimeSeconds() } else { 'synthetic-wrong' }
    Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ReadVm } 'VALIDATION.IDENTITY_UNAVAILABLE'
    Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 0) "Wrong $field identity reached ARM."
}
foreach ($change in @(
    @{token_type='Basic'}, @{resource='https://example.invalid/'},
    @{access_token=('bad'+[char]13+[char]10+'token')}, @{expires_on='not-an-expiry'},
    @{access_token=('x' * 65537)}
)) {
    $f = New-ArmFixture; $f.State.TokenChanges = $change
    Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ReadVm } 'VALIDATION.IDENTITY_UNAVAILABLE'
    Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 0) 'Invalid token reached ARM.'
}
$f = New-ArmFixture; $f.State.TokenText = '{"token_type":"Bearer","TOKEN_TYPE":"Bearer"}'
Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ReadVm } 'VALIDATION.IDENTITY_UNAVAILABLE'

foreach ($bad in @(
    (New-ArmTestResponse -Status 302),
    (New-ArmTestResponse -Uri 'https://example.invalid/'),
    [pscustomobject]@{StatusCode='200'; Uri=''; Body=(ConvertTo-ArmTestBytes '{}')},
    [pscustomobject]@{StatusCode=200; Uri=''; Body='wrong-type'},
    [pscustomobject]@{StatusCode=200; Uri=''; Body=[byte[]]::new(4194305)}
)) {
    $f = New-ArmFixture; $f.State.Responses.Enqueue($bad)
    Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ReadVm } 'VALIDATION.SERVICE_TRANSPORT_FAILED'
}
$f = New-ArmFixture; $f.State.Multiple = $true
Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ReadVm } 'VALIDATION.SERVICE_TRANSPORT_FAILED'
$f = New-ArmFixture; $f.State.ThrowPrivate = $true
Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ReadVm } 'VALIDATION.SERVICE_TRANSPORT_FAILED'

$f = New-ArmFixture
$f.State.Responses.Enqueue((New-ArmTestResponse -Text '{}' -Status 202))
$result = Invoke-AzureValidationArmRoute $f.Channel -Name DeleteVm
Assert-ArmCondition ($result.StatusCode -eq 202 -and $null -eq $result.PSObject.Properties['Absent']) 'Delete acknowledgment fabricated absence.'
Assert-ArmCondition ($f.State.Requests[1].Method -ceq 'DELETE') 'Delete used the wrong method.'

$f = New-ArmFixture
$next = 'https://management.azure.com' + $f.Scope + '/resources?$skiptoken=page%2B2&api-version=2021-04-01'
$one = @{value=@(@{id=($f.Scope+'/providers/Microsoft.Compute/virtualMachines/one');type='Microsoft.Compute/virtualMachines'}); nextLink=$next} | ConvertTo-Json -Depth 5 -Compress
$two = @{value=@(@{id=($f.Scope+'/providers/Microsoft.Compute/virtualMachines/two');type='Microsoft.Compute/virtualMachines'})} | ConvertTo-Json -Depth 5 -Compress
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $one))
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $two))
$collection = Get-AzureValidationArmCollection $f.Channel -Name ListResources
Assert-ArmCondition ($collection.Complete -and $collection.NonQualifying -and $collection.Items.Count -eq 2) 'Pagination discarded or promoted evidence.'
Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 2) 'Pagination did not request both pages.'
Assert-ArmCondition ($f.State.Requests[3].Uri.EndsWith('?api-version=2021-04-01&$skiptoken=page%2B2')) 'Next link was not reconstructed from the admitted route.'

# A casing variant of the recognized continuation field is ambiguous,
# never proof that an apparently empty first page was complete.
$f = New-ArmFixture
$badContinuation = @{value=@();NextLink=('https://management.azure.com'+$f.Scope+'/resources?api-version=2021-04-01&$skiptoken=more')} | ConvertTo-Json -Depth 5 -Compress
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $badContinuation))
Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.SERVICE_RESPONSE_INVALID'
# Peering list examples legitimately omit optional type. A closed typed
# collection can verify resource kind from its exact ID without inventing an
# observed type property. A wildcard collection has no such fixed type.
$f = New-ArmFixture
$typed = @{value=@(@{id=($f.Scope+'/providers/Microsoft.Network/virtualNetworks/round/virtualNetworkPeerings/one')})} | ConvertTo-Json -Depth 5 -Compress
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $typed))
$peers = Get-AzureValidationArmCollection $f.Channel -Name TypedPeers
Assert-ArmCondition ($peers.Complete -and $peers.Items.Count -eq 1 -and -not $peers.Items[0].Contains('type')) 'Closed typed collection refused legitimate omitted type or fabricated an observation.'
$f = New-ArmFixture
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $typed))
Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.SERVICE_RESPONSE_INVALID'
# A deleted group yields a404 from its collection. Require independent
# exact-parent404 before interpreting that response as complete empty.
$f = New-ArmFixture
$f.State.Responses.Enqueue((New-ArmTestResponse -Status 404 -Text ''))
$f.State.Responses.Enqueue((New-ArmTestResponse -Status 404 -Text ''))
$goneScope = Get-AzureValidationArmCollection $f.Channel -Name ListResources -MissingParentRouteName ReadScope
Assert-ArmCondition ($goneScope.Complete -and $goneScope.ScopeAbsent -and $goneScope.Items.Count -eq 0 -and $goneScope.NonQualifying) 'Missing parent did not receive exact absence validation.'
Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 2) 'Missing collection skipped independent parent lookup.'

foreach ($parentStatus in @(200,403,500)) {
    $f = New-ArmFixture
    $f.State.Responses.Enqueue((New-ArmTestResponse -Status 404 -Text ''))
    $f.State.Responses.Enqueue((New-ArmTestResponse -Status $parentStatus -Text '{}'))
    Assert-ArmRefuses {
        Get-AzureValidationArmCollection $f.Channel -Name ListResources -MissingParentRouteName ReadScope
    } 'VALIDATION.SERVICE_RESPONSE_INVALID'
}
$f = New-ArmFixture
Assert-ArmRefuses {
    Get-AzureValidationArmCollection $f.Channel -Name ListResources -MissingParentRouteName ReadVm
} 'VALIDATION.SERVICE_REQUEST_INVALID'
Assert-ArmCondition ((Get-ArmRequestCount $f) -eq 0) 'Unrelated parent absence route requested identity.'
$f = New-ArmFixture
$first = @{value=@(@{id=($f.Scope+'/providers/Microsoft.Compute/virtualMachines/one');type='Microsoft.Compute/virtualMachines'});
    nextLink=('https://management.azure.com'+$f.Scope+'/resources?api-version=2021-04-01&$skiptoken=next')} | ConvertTo-Json -Depth 5 -Compress
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $first))
$f.State.Responses.Enqueue((New-ArmTestResponse -Status 404 -Text ''))
Assert-ArmRefuses {
    Get-AzureValidationArmCollection $f.Channel -Name ListResources -MissingParentRouteName ReadScope
} 'VALIDATION.SERVICE_RESPONSE_INVALID'
Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 2) 'Disappearing later page was accepted or retried as a complete empty collection.'

foreach ($text in @('{}','{"value":null}','{"value":true}','{"value":{}}','{"value":[],"Value":[]}',
    '{"value":[{"id":"../escape"}]}','{"value":[],"nextLink":""}','{"value":[],"nextLink":42}',
    '{"value":[],"nextLink":"https://example.invalid/"}')) {
    $f = New-ArmFixture; $f.State.Responses.Enqueue((New-ArmTestResponse -Text $text))
    Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.SERVICE_RESPONSE_INVALID'
}
foreach ($tail in @(
    '?api-version=2021-04-01&$skiptoken=x&other=y',
    '?api-version=2021-04-01&$skiptoken=x&$skiptoken=y',
    '?api-version=2020-01-01&$skiptoken=x',
    '?api-version=2021-04-01&$skiptoken=%GG',
    '?api-version=2021-04-01&$skiptoken=x#fragment',
    ('?api-version=2021-04-01&$skiptoken=x'+[char]10)
)) {
    $f = New-ArmFixture
    $uri = 'https://management.azure.com'+$f.Scope+'/resources'+$tail
    Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ListResources -Continuation $uri } 'VALIDATION.SERVICE_RESPONSE_INVALID'
    Assert-ArmCondition ((Get-ArmRequestCount $f) -eq 0) 'Unsafe pagination acquired identity.'
}
$f = New-ArmFixture
$dotPath = 'https://management.azure.com'+$f.Scope+'/other/../resources?api-version=2021-04-01&$skiptoken=x'
Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ListResources -Continuation $dotPath } 'VALIDATION.SERVICE_RESPONSE_INVALID'
Assert-ArmCondition ((Get-ArmRequestCount $f) -eq 0) 'Normalized path escape acquired identity.'
$f = New-ArmFixture
$f.State.TokenChanges = @{access_token=('e30.e30.signature'+[char]10)}
Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ReadVm } 'VALIDATION.IDENTITY_UNAVAILABLE'
Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 0) 'Terminal newline token reached ARM.'
$f = New-ArmFixture
$id = $f.Scope + '/providers/Microsoft.Compute/virtualMachines/one'
$duplicates = @{value=@(@{id=$id;type='Microsoft.Compute/virtualMachines'},@{id=$id.ToUpperInvariant();type='Microsoft.Compute/virtualMachines'})} | ConvertTo-Json -Depth 5 -Compress
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $duplicates))
Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.SERVICE_RESPONSE_INVALID'

$f = New-ArmFixture
$link = 'https://management.azure.com'+$f.Scope+'/resources?api-version=2021-04-01&$skiptoken=cycle'
$cycle = @{value=@();nextLink=$link} | ConvertTo-Json -Depth 5 -Compress
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $cycle))
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $cycle))
Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.SERVICE_RESPONSE_INVALID'
Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 2) 'Continuation cycle was not bounded.'

$f = New-ArmFixture
for ($i=1; $i -le 50; $i++) {
    $link = 'https://management.azure.com'+$f.Scope+'/resources?api-version=2021-04-01&$skiptoken='+$i
    $page = @{value=@();nextLink=$link} | ConvertTo-Json -Depth 5 -Compress
    $f.State.Responses.Enqueue((New-ArmTestResponse -Text $page))
}
Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.SERVICE_RESPONSE_INVALID'
Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 50) 'Pagination cap fabricated completeness or exceeded its bound.'

$cancel = [Threading.CancellationTokenSource]::new()
try {
    $cancel.Cancel()
    $f = New-ArmFixture -CancellationToken $cancel.Token
    Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.ROUND_INTERRUPTED'
    Assert-ArmCondition ((Get-ArmRequestCount $f) -eq 0) 'Cancellation requested identity or ARM.'
}
finally { $cancel.Dispose() }
$cancel = [Threading.CancellationTokenSource]::new()
try {
    $f = New-ArmFixture -CancellationToken $cancel.Token
    $f.State.CancelDuringArmSource = $cancel
    Assert-ArmRefuses { Invoke-AzureValidationArmRoute $f.Channel -Name ReadVm } 'VALIDATION.ROUND_INTERRUPTED'
    Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 1) 'Cancellation during dispatch was not exercised.'
}
finally { $cancel.Dispose() }
$f = New-ArmFixture
$f.State.CurrentTime = $f.Now.AddMinutes(15)
Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.ROUND_INTERRUPTED'
Assert-ArmCondition ((Get-ArmRequestCount $f) -eq 0) 'Expired channel requested identity or ARM.'
$f = New-ArmFixture
$f.State.AdvanceAfterArm = $true
Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.ROUND_INTERRUPTED'
Assert-ArmCondition ((Get-ArmRequestCount $f -Arm) -eq 1) 'Expired response started another page.'

$f = New-ArmFixture
$foreign = @{value=@(@{id='/subscriptions/44444444-4444-4444-4444-444444444444/resourceGroups/foreign/providers/Microsoft.Compute/virtualMachines/one';type='Microsoft.Compute/virtualMachines'})} | ConvertTo-Json -Depth 5 -Compress
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $foreign))
Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.SERVICE_RESPONSE_INVALID'
$f = New-ArmFixture
$foreign = @{value=@(@{id=($f.Scope+'/providers/Microsoft.Compute/virtualMachines/one');type='Microsoft.Network/networkInterfaces'})} | ConvertTo-Json -Depth 5 -Compress
$f.State.Responses.Enqueue((New-ArmTestResponse -Text $foreign))
Assert-ArmRefuses { Get-AzureValidationArmCollection $f.Channel -Name ListResources } 'VALIDATION.SERVICE_RESPONSE_INVALID'
# Explicit clock injection alone never produces qualifying status or network I/O.
$f = New-ArmFixture
$binding = @{ExpectedPrincipalId=$f.Channel.PrincipalId;ExpectedTenantId=$f.Channel.TenantId;
    ExpectedIdentityResourceId=$f.Channel.IdentityResourceId;Routes=$f.Routes;UtcNow=$f.Channel.Clock;DeadlineUtc=$f.Now.AddMinutes(10)}
$clockOnly = New-AzureValidationArmChannel @binding
Assert-ArmCondition ($clockOnly.Kind -ceq 'InjectedNonQualifying') 'Fixture clock permitted a qualifying channel.'
Assert-ArmCondition ($script:ArmNativeDispatchCount -eq 0) 'Injected tests attempted native HTTP dispatch.'
$totalRequests = @($script:ArmFixtures | ForEach-Object { $_.Requests.ToArray() })
$armRequests = @($totalRequests | Where-Object Uri -Like 'https://management.azure.com/*')
$imdsRequests = @($totalRequests | Where-Object Uri -Like 'http://169.254.169.254/*')
[ordered]@{
    recordType='win-pcinfo.injected-arm-transport-tests'
    result='Pass'; nonQualifying=$true
    assertions=$script:ArmAssertionCount
    expectedRefusals=$script:ArmRefusalCount
    fixtures=$script:ArmFixtures.Count
    injectedImdsRequests=$imdsRequests.Count
    injectedArmRequests=$armRequests.Count
    nativeHttpDispatches=$script:ArmNativeDispatchCount
    scope='Production transport interpretation under injected synthetic requests; no live Azure acceptance'
} | ConvertTo-Json -Depth 3 -Compress | Write-Output
Write-Output 'PASS: injected production ARM channel enforces fixed identity/route/response boundaries and complete bounded pagination; no Azure requests.'
