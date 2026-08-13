$script:NetworkTopologyPolicyBase64='__NETWORK_TOPOLOGY_POLICY_BASE64__'
$script:NetworkTopologyPolicyDigest='__NETWORK_TOPOLOGY_POLICY_SHA256__'

function Get-NetworkTopologySha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-NetworkTopologyPolicy {
    param([Parameter(Mandatory)]$ConvertFromJsonCommand)
    if($script:NetworkTopologyPolicyBase64 -eq '__NETWORK_TOPOLOGY_POLICY_BASE64__'){
        $path=Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-network-topology.json'
        $text=[IO.File]::ReadAllText($path,[Text.UTF8Encoding]::new($false,$true)).Replace("`r`n","`n").Replace("`r","`n")
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes($text)
        $expected=Get-NetworkTopologySha256 -Bytes $bytes
    }else{
        $bytes=[Convert]::FromBase64String($script:NetworkTopologyPolicyBase64)
        $expected=$script:NetworkTopologyPolicyDigest
    }
    if((Get-NetworkTopologySha256 -Bytes $bytes) -ne $expected){
        throw 'The embedded Network Topology policy failed integrity validation.'
    }
    $policy=& $ConvertFromJsonCommand -InputObject (
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    ) -Depth 30 -ErrorAction Stop
    if($policy.kind -ne 'win-pcinfo.network-topology-policy' -or
        $policy.contractVersion -ne '1.0.0' -or
        @($policy.localScopes).Count -ne 9 -or
        @($policy.networkDependentScopes).Count -ne 3 -or
        @($policy.sourceCatalog).Count -ne 9 -or
        @($policy.rules).Count -ne 3 -or
        @($policy.recommendations).Count -ne 3 -or
        @($policy.validationScenarios).Count -ne 14){
        throw 'The Network Topology policy is not semantically closed.'
    }
    $policy
}

function New-NetworkTopologyScopeState {
    param([string]$ScopeId,[string]$State='Complete',[string]$ReasonCode='')
    [pscustomobject][ordered]@{scopeId=$ScopeId;state=$State;reasonCode=$ReasonCode}
}

function Read-NetworkTopologyFixture {
    param([string]$LiteralPath,$ConvertFromJsonCommand,$Policy)
    try{
        $bytes=[IO.File]::ReadAllBytes([IO.Path]::GetFullPath($LiteralPath));if($bytes.Length -lt 1 -or $bytes.Length -gt 512){throw 'Fixture size is invalid.'}
        $json=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);$document=[Text.Json.JsonDocument]::Parse($json)
        try{$names=@($document.RootElement.EnumerateObject()|ForEach-Object Name);if($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or (@($names|Sort-Object)-join '|') -ne 'contractVersion|scenario'){throw 'Fixture shape is invalid.'}}finally{$document.Dispose()}
        $fixture=& $ConvertFromJsonCommand -InputObject $json -Depth 5 -ErrorAction Stop
        if($fixture.contractVersion -ne '1.0.0' -or $fixture.scenario -notin @($Policy.validationScenarios)){throw 'Fixture scenario is not release-owned.'}
        [string]$fixture.scenario
    }catch{throw [InvalidOperationException]::new('The synthetic Network Topology fixture is invalid.',$_.Exception)}
}

function New-NetworkTopologySyntheticPayload {
    param([Parameter(Mandatory)][string]$Scenario,[Parameter(Mandatory)]$Policy)
    $adapter=[pscustomobject][ordered]@{name='Synthetic Ethernet';description='Synthetic Adapter';status='Up';interfaceIndex=12;linkSpeed=1000000000;hardwareInterface=$true}
    $profile=[pscustomobject][ordered]@{name='Synthetic Private Profile';category='Private';ipv4Connectivity='Internet';ipv6Connectivity='LocalNetwork';interfaceIndex=12}
    $ipv4=[pscustomobject][ordered]@{interfaceIndex=12;addressFamily='IPv4';address='203.0.113.10';prefixLength=24;defaultGateway='203.0.113.1'}
    $ipv6=[pscustomobject][ordered]@{interfaceIndex=12;addressFamily='IPv6';address='2001:db8::10';prefixLength=64;defaultGateway='2001:db8::1'}
    $route4=[pscustomobject][ordered]@{addressFamily='IPv4';destinationPrefix='0.0.0.0/0';nextHop='203.0.113.1';interfaceIndex=12;metric=25}
    $route6=[pscustomobject][ordered]@{addressFamily='IPv6';destinationPrefix='::/0';nextHop='2001:db8::1';interfaceIndex=12;metric=25}
    $resolver4=[pscustomobject][ordered]@{interfaceIndex=12;addressFamily='IPv4';addresses=@('192.0.2.53')}
    $resolver6=[pscustomobject][ordered]@{interfaceIndex=12;addressFamily='IPv6';addresses=@('2001:db8::53')}
    $vpn=[pscustomobject][ordered]@{name='SYNTHETIC-VPN';serverAddress='vpn.synthetic.invalid';tunnelType='Ikev2';connectionStatus='Disconnected'}
    $security=[pscustomobject][ordered]@{kind='AntiVirus';name='Synthetic Security Component';stateCode=397568}
    $connection=[pscustomobject][ordered]@{state='Established';localAddress='203.0.113.10';localPort=49152;remoteAddress='198.51.100.20';remotePort=443}
    $adapters=@($adapter);$profiles=@($profile);$ips=@();$routes=@();$resolvers=@()
    $proxy=[pscustomobject][ordered]@{enabled=$false;server=$null;autoConfigUrl=$null}
    $vpns=@();$securityComponents=@();$connections=@();$localState='Complete';$localReason=''
    $locale='und'
    switch($Scenario){
        'MultipleAdapters'{
            $adapters=@($adapter,[pscustomobject][ordered]@{name='Synthetic Wi-Fi';description='Synthetic Wireless Adapter';status='Disconnected';interfaceIndex=13;linkSpeed=0;hardwareInterface=$true})
            $profiles=@($profile,[pscustomobject][ordered]@{name='Synthetic Public Profile';category='Public';ipv4Connectivity='Disconnected';ipv6Connectivity='Disconnected';interfaceIndex=13})
            $ips=@($ipv4);$routes=@($route4);$resolvers=@($resolver4)
        }
        'IPv4IPv6'{$ips=@($ipv4,$ipv6);$routes=@($route4,$route6);$resolvers=@($resolver4,$resolver6)}
        'Disconnected'{$adapters=@([pscustomobject][ordered]@{name='Synthetic Ethernet';description='Synthetic Adapter';status='Disconnected';interfaceIndex=12;linkSpeed=0;hardwareInterface=$true});$profiles=@([pscustomobject][ordered]@{name='Synthetic Disconnected Profile';category='Public';ipv4Connectivity='Disconnected';ipv6Connectivity='Disconnected';interfaceIndex=12})}
        'Routes'{$routes=@($route4,$route6)}
        'Resolvers'{$resolvers=@($resolver4,$resolver6)}
        'Proxy'{$proxy=[pscustomobject][ordered]@{enabled=$true;server='http://proxy.synthetic.invalid:8080';autoConfigUrl='https://config.synthetic.invalid/proxy.pac'}}
        'VpnAndSecurity'{$vpns=@($vpn);$securityComponents=@($security,[pscustomobject][ordered]@{kind='Firewall';name='Synthetic Firewall Component';stateCode=266240})}
        'ExistingConnections'{$connections=@($connection,[pscustomobject][ordered]@{state='Listen';localAddress='::';localPort=5357;remoteAddress='::';remotePort=0})}
        'Empty'{$adapters=@();$profiles=@()}
        'Malformed'{$adapters=@([pscustomobject][ordered]@{name='';description='Malformed synthetic adapter';status='Up';interfaceIndex=12;linkSpeed=1000000000;hardwareInterface=$true});$localState='Complete'}
        'Denied'{$adapters=@();$profiles=@();$localState='Denied';$localReason='NETWORK.SOURCE_ACCESS_DENIED'}
        'Partial'{
            $localState='Partial';$localReason='NETWORK.EVIDENCE_BOUND_EXCEEDED'
            $adapters=@(0..7|ForEach-Object {[pscustomobject][ordered]@{name="Synthetic Adapter $_";description="Synthetic Adapter $_";status='Up';interfaceIndex=20+$_;linkSpeed=1000000000;hardwareInterface=$true}})
            $profiles=@(0..7|ForEach-Object {[pscustomobject][ordered]@{name="Synthetic Profile $_";category='Private';ipv4Connectivity='LocalNetwork';ipv6Connectivity='Disconnected';interfaceIndex=20+$_}})
            $ips=@(0..7|ForEach-Object {[pscustomobject][ordered]@{interfaceIndex=20+$_;addressFamily='IPv4';address="203.0.113.$($_+1)";prefixLength=24;defaultGateway='203.0.113.254'}})
            $routes=@(0..7|ForEach-Object {[pscustomobject][ordered]@{addressFamily='IPv4';destinationPrefix="198.51.$_.0/24";nextHop='203.0.113.1';interfaceIndex=20+$_;metric=25+$_}})
            $resolvers=@(0..7|ForEach-Object {[pscustomobject][ordered]@{interfaceIndex=20+$_;addressFamily='IPv4';addresses=@("192.0.2.$($_+1)")}})
            $vpns=@(0..7|ForEach-Object {[pscustomobject][ordered]@{name="Synthetic VPN $_";serverAddress="vpn$_.synthetic.invalid";tunnelType='Ikev2';connectionStatus='Disconnected'}})
            $securityComponents=@(0..7|ForEach-Object {[pscustomobject][ordered]@{kind='AntiVirus';name="Synthetic Component $_";stateCode=397568}})
            $connections=@(0..7|ForEach-Object {[pscustomobject][ordered]@{state='Established';localAddress="203.0.113.$($_+1)";localPort=49152+$_;remoteAddress="198.51.100.$($_+1)";remotePort=443}})
        }
        'LocalOnly'{$ips=@($ipv4);$routes=@($route4);$resolvers=@($resolver4)}
        'Unicode'{
            $locale='ar-SA';$adapters=@([pscustomobject][ordered]@{name='شبكة-東京';description='Adaptateur-Δ';status='Up';interfaceIndex=12;linkSpeed=1000000000;hardwareInterface=$true})
            $profiles=@([pscustomobject][ordered]@{name='Réseau-東京';category='Private';ipv4Connectivity='Internet';ipv6Connectivity='LocalNetwork';interfaceIndex=12})
            $ips=@($ipv4);$routes=@($route4);$resolvers=@($resolver4)
            $proxy=[pscustomobject][ordered]@{enabled=$true;server='http://代理.synthetic.invalid:8080';autoConfigUrl=$null}
            $vpns=@($vpn);$securityComponents=@([pscustomobject][ordered]@{kind='Firewall';name='Pare-feu-東京';stateCode=266240});$connections=@($connection)
        }
        default{throw 'The Network Topology scenario is not release-owned.'}
    }
    $scopeStates=@($Policy.localScopes|ForEach-Object {
        $state=$localState;$reason=$localReason
        New-NetworkTopologyScopeState ([string]$_.scopeId) $state $reason
    })+@($Policy.networkDependentScopes|ForEach-Object {
        New-NetworkTopologyScopeState ([string]$_.scopeId) ([string]$_.localOnlyState) ([string]$_.reasonCode)
    })
    [pscustomobject][ordered]@{
        sourceLocale=$locale;assessmentUserContextVerified=$true;processRelationship='SameUser'
        networkBehavior='LocalOnly';outboundRequestCount=0;adapters=@($adapters);profiles=@($profiles)
        ipConfigurations=@($ips);routes=@($routes);resolvers=@($resolvers);proxy=$proxy
        vpnComponents=@($vpns);securityComponents=@($securityComponents);connections=@($connections)
        scopeStates=@($scopeStates);executionContext='Synthetic'
    }
}

function Test-NetworkTopologyObjectShape {
    param($Value,[string[]]$Names)
    $null -ne $Value -and (@($Value.PSObject.Properties.Name|Sort-Object)-join '|') -eq (@($Names|Sort-Object)-join '|')
}

function Test-NetworkTopologyString {
    param($Value,[int]$MaximumBytes,[switch]$AllowNull)
    if($null -eq $Value){return [bool]$AllowNull}
    $Value -is [string] -and -not [string]::IsNullOrWhiteSpace([string]$Value) -and
        [Text.UTF8Encoding]::new($false).GetByteCount([string]$Value) -le $MaximumBytes
}

function Test-NetworkTopologyInteger {
    param($Value,[long]$Minimum=[long]::MinValue,[long]$Maximum=[long]::MaxValue)
    ($Value -is [int] -or $Value -is [long]) -and [long]$Value -ge $Minimum -and [long]$Value -le $Maximum
}

function Test-NetworkTopologyTransportLength {
    param([Parameter(Mandatory)][long]$Utf8ByteCount,[Parameter(Mandatory)]$Policy)
    $Utf8ByteCount -ge 0 -and $Utf8ByteCount -le [long]$Policy.collector.resultMaximumUtf8Bytes
}

function ConvertFrom-NetworkTopologyTransport {
    param([Parameter(Mandatory)][byte[]]$Bytes,[Parameter(Mandatory)]$Policy)
    if(-not (Test-NetworkTopologyTransportLength -Utf8ByteCount $Bytes.LongLength -Policy $Policy)){
        throw 'The Network Topology transport exceeds its release-owned UTF-8 byte ceiling.'
    }
    $json=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
    ConvertFrom-Json -InputObject $json -Depth 20 -ErrorAction Stop
}

function Test-NetworkTopologyItem {
    param([string]$Kind,$Value)
    $x=$Value
    switch($Kind){
        'adapters'{return (Test-NetworkTopologyObjectShape $x @('name','description','status','interfaceIndex','linkSpeed','hardwareInterface')) -and (Test-NetworkTopologyString $x.name 256) -and (Test-NetworkTopologyString $x.description 512) -and [string]$x.status -in @('Up','Down','Disconnected','Disabled','Unknown') -and (Test-NetworkTopologyInteger $x.interfaceIndex 0 ([int]::MaxValue)) -and (Test-NetworkTopologyInteger $x.linkSpeed 0 ([long]::MaxValue)) -and $x.hardwareInterface -is [bool]}
        'profiles'{return (Test-NetworkTopologyObjectShape $x @('name','category','ipv4Connectivity','ipv6Connectivity','interfaceIndex')) -and (Test-NetworkTopologyString $x.name 256) -and [string]$x.category -in @('Public','Private','DomainAuthenticated','Unknown') -and (Test-NetworkTopologyString $x.ipv4Connectivity 32) -and (Test-NetworkTopologyString $x.ipv6Connectivity 32) -and (Test-NetworkTopologyInteger $x.interfaceIndex 0 ([int]::MaxValue))}
        'ipConfigurations'{return (Test-NetworkTopologyObjectShape $x @('interfaceIndex','addressFamily','address','prefixLength','defaultGateway')) -and (Test-NetworkTopologyInteger $x.interfaceIndex 0 ([int]::MaxValue)) -and [string]$x.addressFamily -in @('IPv4','IPv6') -and (Test-NetworkTopologyString $x.address 64) -and (Test-NetworkTopologyInteger $x.prefixLength 0 128) -and (Test-NetworkTopologyString $x.defaultGateway 64 -AllowNull)}
        'routes'{return (Test-NetworkTopologyObjectShape $x @('addressFamily','destinationPrefix','nextHop','interfaceIndex','metric')) -and [string]$x.addressFamily -in @('IPv4','IPv6') -and (Test-NetworkTopologyString $x.destinationPrefix 80) -and (Test-NetworkTopologyString $x.nextHop 64) -and (Test-NetworkTopologyInteger $x.interfaceIndex 0 ([int]::MaxValue)) -and (Test-NetworkTopologyInteger $x.metric ([int]::MinValue) ([int]::MaxValue))}
        'resolvers'{return (Test-NetworkTopologyObjectShape $x @('interfaceIndex','addressFamily','addresses')) -and (Test-NetworkTopologyInteger $x.interfaceIndex 0 ([int]::MaxValue)) -and [string]$x.addressFamily -in @('IPv4','IPv6') -and @($x.addresses).Count -le 4 -and @($x.addresses|Where-Object {-not (Test-NetworkTopologyString $_ 64)}).Count -eq 0}
        'vpnComponents'{return (Test-NetworkTopologyObjectShape $x @('name','serverAddress','tunnelType','connectionStatus')) -and (Test-NetworkTopologyString $x.name 256) -and (Test-NetworkTopologyString $x.serverAddress 512) -and (Test-NetworkTopologyString $x.tunnelType 64 -AllowNull) -and (Test-NetworkTopologyString $x.connectionStatus 32 -AllowNull)}
        'securityComponents'{return (Test-NetworkTopologyObjectShape $x @('kind','name','stateCode')) -and [string]$x.kind -in @('AntiVirus','Firewall') -and (Test-NetworkTopologyString $x.name 256) -and (Test-NetworkTopologyInteger $x.stateCode ([int]::MinValue) ([int]::MaxValue))}
        'connections'{return (Test-NetworkTopologyObjectShape $x @('state','localAddress','localPort','remoteAddress','remotePort')) -and (Test-NetworkTopologyString $x.state 32) -and (Test-NetworkTopologyString $x.localAddress 64) -and (Test-NetworkTopologyInteger $x.localPort 0 65535) -and (Test-NetworkTopologyString $x.remoteAddress 64) -and (Test-NetworkTopologyInteger $x.remotePort 0 65535)}
    }
    $false
}

function Test-NetworkTopologyCollectorPayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)]$Policy)
    try{
        if(-not (Test-NetworkTopologyObjectShape $Payload @('sourceLocale','assessmentUserContextVerified','processRelationship','networkBehavior','outboundRequestCount','adapters','profiles','ipConfigurations','routes','resolvers','proxy','vpnComponents','securityComponents','connections','scopeStates','executionContext'))){return $false}
        if($Payload.assessmentUserContextVerified -isnot [bool] -or
            [string]$Payload.processRelationship -notin @('SameUser','AlternateAdministrator','ElevatedAssessmentUser','DifferentStandardUser','ProhibitedSystemContext','Unavailable') -or [string]$Payload.networkBehavior -ne 'LocalOnly' -or
            -not (Test-NetworkTopologyInteger $Payload.outboundRequestCount 0 0) -or
            [string]$Payload.executionContext -notin @('Synthetic','StandardUser','Administrator','LocalSystem') -or
            -not (Test-NetworkTopologyString $Payload.sourceLocale 35)){return $false}
        if([bool]$Payload.assessmentUserContextVerified){
            if($Payload.processRelationship -ne 'SameUser' -or $Payload.executionContext -notin @('Synthetic','StandardUser')){return $false}
        }else{
            $expectedContext=switch([string]$Payload.processRelationship){
                'AlternateAdministrator'{'Administrator'};'ElevatedAssessmentUser'{'Administrator'}
                'DifferentStandardUser'{'StandardUser'};'ProhibitedSystemContext'{'LocalSystem'}
                'Unavailable'{'StandardUser'};default{return $false}
            }
            if($Payload.executionContext -ne $expectedContext){return $false}
        }
        foreach($collectionName in 'adapters','profiles','ipConfigurations','routes','resolvers','vpnComponents','securityComponents','connections'){
            if(@($Payload.$collectionName).Count -gt [int]$Policy.collector.maximumItemsPerScope){return $false}
        }
        foreach($kind in 'adapters','profiles','ipConfigurations','routes','resolvers','vpnComponents','securityComponents','connections'){
            foreach($x in @($Payload.$kind)){if(-not (Test-NetworkTopologyItem $kind $x)){return $false}}
        }
        if(-not (Test-NetworkTopologyObjectShape $Payload.proxy @('enabled','server','autoConfigUrl')) -or $Payload.proxy.enabled -isnot [bool] -or -not (Test-NetworkTopologyString $Payload.proxy.server 1024 -AllowNull) -or -not (Test-NetworkTopologyString $Payload.proxy.autoConfigUrl 1024 -AllowNull)){return $false}
        $expected=@($Policy.localScopes.scopeId)+@($Policy.networkDependentScopes.scopeId)
        if(@($Payload.scopeStates).Count -ne $expected.Count -or (@($Payload.scopeStates.scopeId|Sort-Object)-join '|') -ne (@($expected|Sort-Object)-join '|')){return $false}
        foreach($scope in @($Payload.scopeStates)){
            if(-not (Test-NetworkTopologyObjectShape $scope @('scopeId','state','reasonCode')) -or [string]$scope.state -notin @('Complete','Partial','Unavailable','Unsupported','Denied','Malformed','TimedOut','Cancelled','Failed','NotAttempted') -or ($scope.state -eq 'Complete' -and $scope.reasonCode) -or ($scope.state -ne 'Complete' -and (-not (Test-NetworkTopologyString $scope.reasonCode 128) -or [string]$scope.reasonCode -cnotmatch '^[A-Z][A-Z0-9_.-]+$'))){return $false}
        }
        foreach($scope in @($Policy.networkDependentScopes)){
            $actual=@($Payload.scopeStates|Where-Object scopeId -eq $scope.scopeId)[0]
            if($actual.state -ne 'NotAttempted' -or $actual.reasonCode -ne 'NETWORK.LOCAL_ONLY_NOT_ATTEMPTED'){return $false}
        }
        if(-not [bool]$Payload.assessmentUserContextVerified -and
            (@($Payload.adapters).Count+@($Payload.profiles).Count+@($Payload.ipConfigurations).Count+
            @($Payload.routes).Count+@($Payload.resolvers).Count+@($Payload.vpnComponents).Count+
            @($Payload.securityComponents).Count+@($Payload.connections).Count -gt 0 -or
            @($Payload.scopeStates|Where-Object {$_.scopeId -in @($Policy.localScopes.scopeId) -and $_.state -eq 'Complete'}).Count -gt 0)){return $false}
        $true
    }catch{$false}
}

function ConvertTo-NetworkTopologyAttemptPayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)]$Policy)
    $topLevel=@('sourceLocale','assessmentUserContextVerified','processRelationship','networkBehavior','outboundRequestCount','adapters','profiles','ipConfigurations','routes','resolvers','proxy','vpnComponents','securityComponents','connections','scopeStates','executionContext')
    if(-not (Test-NetworkTopologyObjectShape $Payload $topLevel)){throw 'The Network Topology attempt shape is outside the frozen contract.'}
    # First validate the attempt-level context and coverage independently from
    # provider items. This prevents a malformed provider row from discarding
    # already valid evidence returned by unrelated local sources.
    $base=[pscustomobject][ordered]@{
        sourceLocale=$Payload.sourceLocale;assessmentUserContextVerified=$Payload.assessmentUserContextVerified
        processRelationship=$Payload.processRelationship;networkBehavior=$Payload.networkBehavior
        outboundRequestCount=$Payload.outboundRequestCount;adapters=@();profiles=@();ipConfigurations=@()
        routes=@();resolvers=@();proxy=[pscustomobject][ordered]@{enabled=$false;server=$null;autoConfigUrl=$null}
        vpnComponents=@();securityComponents=@();connections=@();scopeStates=@($Payload.scopeStates)
        executionContext=$Payload.executionContext
    }
    if(-not (Test-NetworkTopologyCollectorPayload -Payload $base -Policy $Policy)){throw 'The Network Topology attempt context or coverage is outside the frozen contract.'}
    $states=@($Payload.scopeStates|ForEach-Object {[pscustomobject][ordered]@{scopeId=[string]$_.scopeId;state=[string]$_.state;reasonCode=[string]$_.reasonCode}})
    $scopeByCollection=@{adapters='scope:network.adapters';profiles='scope:network.connection-profiles';ipConfigurations='scope:network.ip-configuration';routes='scope:network.routes';resolvers='scope:network.resolvers';vpnComponents='scope:network.vpn-components';securityComponents='scope:network.security-components';connections='scope:network.local-connections'}
    $accepted=@{}
    foreach($kind in $scopeByCollection.Keys){
        $accepted[$kind]=@($Payload.$kind|Where-Object {Test-NetworkTopologyItem $kind $_})
        if($accepted[$kind].Count -ne @($Payload.$kind).Count){
            $scope=@($states|Where-Object scopeId -eq $scopeByCollection[$kind])[0]
            if($scope.state -eq 'Complete'){$scope.state='Partial';$scope.reasonCode='NETWORK.SOURCE_VALUE_MALFORMED'}
        }
    }
    $proxyValid=(Test-NetworkTopologyObjectShape $Payload.proxy @('enabled','server','autoConfigUrl')) -and
        $Payload.proxy.enabled -is [bool] -and (Test-NetworkTopologyString $Payload.proxy.server 1024 -AllowNull) -and
        (Test-NetworkTopologyString $Payload.proxy.autoConfigUrl 1024 -AllowNull)
    $proxy=if($proxyValid){$Payload.proxy}else{[pscustomobject][ordered]@{enabled=$false;server=$null;autoConfigUrl=$null}}
    if(-not $proxyValid){$scope=@($states|Where-Object scopeId -eq 'scope:network.proxy')[0];if($scope.state -eq 'Complete'){$scope.state='Partial';$scope.reasonCode='NETWORK.SOURCE_VALUE_MALFORMED'}}
    [pscustomobject][ordered]@{
        sourceLocale=$Payload.sourceLocale;assessmentUserContextVerified=$Payload.assessmentUserContextVerified
        processRelationship=$Payload.processRelationship;networkBehavior=$Payload.networkBehavior
        outboundRequestCount=$Payload.outboundRequestCount;adapters=@($accepted.adapters);profiles=@($accepted.profiles)
        ipConfigurations=@($accepted.ipConfigurations);routes=@($accepted.routes);resolvers=@($accepted.resolvers)
        proxy=$proxy;vpnComponents=@($accepted.vpnComponents);securityComponents=@($accepted.securityComponents)
        connections=@($accepted.connections);scopeStates=$states;executionContext=$Payload.executionContext
    }
}

function Copy-NetworkTopologyCollectorPayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)]$Policy)
    $Payload=ConvertTo-NetworkTopologyAttemptPayload -Payload $Payload -Policy $Policy
    if(-not (Test-NetworkTopologyCollectorPayload -Payload $Payload -Policy $Policy)){throw 'The Network Topology payload is outside the frozen contract.'}
    # Re-project every admitted primitive into coordinator-owned objects. This
    # avoids retaining an untrusted worker object after validation and avoids a
    # JSON round-trip, whose numeric coercion would weaken the primitive checks.
    function Copy-Items($Items,[string[]]$Names){
        @($Items|ForEach-Object {
            $copy=[ordered]@{};foreach($name in $Names){$copy[$name]=$_.($name)}
            [pscustomobject]$copy
        })
    }
    [pscustomobject][ordered]@{
        sourceLocale=[string]$Payload.sourceLocale
        assessmentUserContextVerified=[bool]$Payload.assessmentUserContextVerified
        processRelationship=[string]$Payload.processRelationship
        networkBehavior='LocalOnly';outboundRequestCount=0
        adapters=Copy-Items $Payload.adapters @('name','description','status','interfaceIndex','linkSpeed','hardwareInterface')
        profiles=Copy-Items $Payload.profiles @('name','category','ipv4Connectivity','ipv6Connectivity','interfaceIndex')
        ipConfigurations=Copy-Items $Payload.ipConfigurations @('interfaceIndex','addressFamily','address','prefixLength','defaultGateway')
        routes=Copy-Items $Payload.routes @('addressFamily','destinationPrefix','nextHop','interfaceIndex','metric')
        resolvers=@($Payload.resolvers|ForEach-Object {[pscustomobject][ordered]@{interfaceIndex=$_.interfaceIndex;addressFamily=[string]$_.addressFamily;addresses=@($_.addresses|ForEach-Object {[string]$_})}})
        proxy=[pscustomobject][ordered]@{enabled=[bool]$Payload.proxy.enabled;server=$Payload.proxy.server;autoConfigUrl=$Payload.proxy.autoConfigUrl}
        vpnComponents=Copy-Items $Payload.vpnComponents @('name','serverAddress','tunnelType','connectionStatus')
        securityComponents=Copy-Items $Payload.securityComponents @('kind','name','stateCode')
        connections=Copy-Items $Payload.connections @('state','localAddress','localPort','remoteAddress','remotePort')
        scopeStates=Copy-Items $Payload.scopeStates @('scopeId','state','reasonCode')
        executionContext=[string]$Payload.executionContext
    }
}

function Invoke-NetworkTopologyCollection {
    param(
        [Parameter(Mandatory)]$Policy,[Parameter()][string]$ValidationScenario,
        [Parameter(Mandatory)][ValidateSet('LocalOnly')][string]$NetworkBehavior,
        [Parameter()][switch]$Live,[Parameter()][string]$AssessmentUserSid,
        [Parameter()][ValidateSet('','Administrator','LocalSystem','AlternateUser')][string]$ProcessContextOverride=''
    )
    if($Live){
        $started=[DateTimeOffset]::UtcNow
        if(-not (Test-NetworkTopologySid $AssessmentUserSid)){
            $payload=New-NetworkTopologyGapPayload -Policy $Policy -State Unavailable -ReasonCode 'NETWORK.ASSESSMENT_USER_CONTEXT_UNAVAILABLE' -Relationship Unavailable -ObservedContext StandardUser
            return [pscustomobject][ordered]@{state='Completed';reasonCode='NETWORK.ASSESSMENT_USER_CONTEXT_UNAVAILABLE';payload=$payload;envelope=[pscustomobject][ordered]@{startedAt=$started.ToString('o');completedAt=([DateTimeOffset]::UtcNow).ToString('o');executionContext='StandardUser';attempts=1};cleanupVerified=$true}
        }
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($identity)
        $processSid=[string]$identity.User.Value;$isAdministrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        switch($ProcessContextOverride){
            'LocalSystem'{$processSid='S-1-5-18';$isAdministrator=$true}
            'Administrator'{$processSid=$AssessmentUserSid;$isAdministrator=$true}
            'AlternateUser'{$processSid='S-1-5-21-9-8-7-1002';$isAdministrator=$false}
        }
        $disposition=Get-NetworkTopologyProcessDisposition $processSid $AssessmentUserSid $isAdministrator
        if($null -ne $disposition){
            $payload=New-NetworkTopologyGapPayload -Policy $Policy -State Denied -ReasonCode 'NETWORK.ASSESSMENT_USER_CONTEXT_REQUIRED' -Relationship $disposition.relationship -ObservedContext $disposition.executionContext
            return [pscustomobject][ordered]@{state='Completed';reasonCode='NETWORK.ASSESSMENT_USER_CONTEXT_REQUIRED';payload=$payload;envelope=[pscustomobject][ordered]@{startedAt=$started.ToString('o');completedAt=([DateTimeOffset]::UtcNow).ToString('o');executionContext=$disposition.executionContext;attempts=1};cleanupVerified=$true}
        }
        $attempt=Invoke-BoundedNetworkTopologySnapshot -Policy $Policy -AssessmentUserSid $AssessmentUserSid
        if([bool]$attempt.succeeded){
            $payload=Copy-NetworkTopologyCollectorPayload -Payload $attempt.payload -Policy $Policy
            return [pscustomobject][ordered]@{state='Completed';reasonCode='NETWORK.COLLECTION_COMPLETED';payload=$payload;envelope=[pscustomobject][ordered]@{startedAt=([DateTimeOffset]$attempt.startedAt).ToString('o');completedAt=([DateTimeOffset]$attempt.completedAt).ToString('o');executionContext='StandardUser';attempts=1};cleanupVerified=$true}
        }
        $state=if($attempt.reasonCode -match 'TIMEOUT'){'TimedOut'}elseif($attempt.reasonCode -match 'CANCEL'){'Cancelled'}elseif($attempt.reasonCode -match 'DENIED'){'Denied'}else{'Failed'}
        $payload=New-NetworkTopologyGapPayload -Policy $Policy -State $state -ReasonCode ([string]$attempt.reasonCode) -Relationship SameUser -ObservedContext StandardUser
        return [pscustomobject][ordered]@{state='Completed';reasonCode=[string]$attempt.reasonCode;payload=$payload;envelope=[pscustomobject][ordered]@{startedAt=([DateTimeOffset]$attempt.startedAt).ToString('o');completedAt=([DateTimeOffset]$attempt.completedAt).ToString('o');executionContext='StandardUser';attempts=1};cleanupVerified=$true}
    }
    if($ValidationScenario -notin @($Policy.validationScenarios)){throw 'The Network Topology validation scenario is not release-owned.'}
    $started=[DateTimeOffset]::UtcNow
    $payload=Copy-NetworkTopologyCollectorPayload -Payload (New-NetworkTopologySyntheticPayload -Scenario $ValidationScenario -Policy $Policy) -Policy $Policy
    [pscustomobject][ordered]@{state='Completed';reasonCode='NETWORK.COLLECTION_COMPLETED';payload=$payload;envelope=[pscustomobject][ordered]@{startedAt=$started.ToString('o');completedAt=([DateTimeOffset]::UtcNow).ToString('o');executionContext='Synthetic';attempts=1};cleanupVerified=$true}
}

function Test-NetworkTopologySid {
    param([string]$Value)
    try{if([Text.Encoding]::UTF8.GetByteCount($Value)-gt 184){return $false};$sid=[Security.Principal.SecurityIdentifier]::new($Value);$sid.Value -ceq $Value}catch{$false}
}

function Get-NetworkTopologyProcessDisposition {
    param([string]$ProcessSid,[string]$AssessmentUserSid,[bool]$IsAdministrator)
    if($ProcessSid -eq 'S-1-5-18'){return [pscustomobject]@{relationship='ProhibitedSystemContext';executionContext='LocalSystem'}}
    if($IsAdministrator){return [pscustomobject]@{relationship=if($ProcessSid -eq $AssessmentUserSid){'ElevatedAssessmentUser'}else{'AlternateAdministrator'};executionContext='Administrator'}}
    if($ProcessSid -ne $AssessmentUserSid){return [pscustomobject]@{relationship='DifferentStandardUser';executionContext='StandardUser'}}
    $null
}

function New-NetworkTopologyGapPayload {
    param($Policy,[string]$State,[string]$ReasonCode,[string]$Relationship,[string]$ObservedContext)
    [pscustomobject][ordered]@{
        sourceLocale='und';assessmentUserContextVerified=($Relationship -eq 'SameUser');processRelationship=$Relationship
        networkBehavior='LocalOnly';outboundRequestCount=0;adapters=@();profiles=@();ipConfigurations=@();routes=@();resolvers=@()
        proxy=[pscustomobject][ordered]@{enabled=$false;server=$null;autoConfigUrl=$null};vpnComponents=@();securityComponents=@();connections=@()
        scopeStates=@($Policy.localScopes|ForEach-Object {New-NetworkTopologyScopeState $_.scopeId $State $ReasonCode})+@($Policy.networkDependentScopes|ForEach-Object {New-NetworkTopologyScopeState $_.scopeId $_.localOnlyState $_.reasonCode})
        executionContext=$ObservedContext
    }
}

function Get-NetworkTopologyLiveSource {
    # The child deliberately avoids PowerShell networking modules and CIM. Their
    # provider activation crossed the Local Only boundary during isolated ETW
    # validation. The replacements below read the local IP Helper tables, .NET's
    # local NetworkInformation projection, Network List Manager's already-known
    # profiles, Current User registry values, and the bounded Current User RAS
    # phonebook. None resolves a name or opens a connection.
    #
    # Each source owns one coverage result, and each output list stops after the
    # ninth unique item establishes overflow. A source error therefore cannot
    # erase accepted evidence from another source or fabricate Complete absence.
    # The only stdout write is one compressed UTF-8 JSON document; the parent
    # treats those bytes as hostile until exact shape/type/bound validation and
    # fresh-object projection complete.
@'
$ErrorActionPreference='Stop'
$PSModuleAutoLoadingPreference='None'
function New-Scope([string]$id){[pscustomobject][ordered]@{scopeId=$id;state='Complete';reasonCode=''}}
function Set-Scope($scopes,[string]$id,[string]$state,[string]$reason){$s=@($scopes|Where-Object scopeId -eq $id)[0];if($s.state -eq 'Complete' -or $state -in @('Denied','Failed','Malformed','Unsupported')){$s.state=$state;$s.reasonCode=$reason}}
function Failure-State([Exception]$e){if($e -is [UnauthorizedAccessException] -or $e.HResult -eq -2147024891){'Denied'}else{'Failed'}}
function Add-Bounded($list,$item,[int]$maximum,$scopes,[string]$scope){if($list.Count -ge $maximum){Set-Scope $scopes $scope 'Partial' 'NETWORK.EVIDENCE_BOUND_EXCEEDED';return};$null=$list.Add($item)}
function Valid-Text($value,[int]$maximum){$value -is [string] -and -not [string]::IsNullOrWhiteSpace([string]$value) -and [Text.Encoding]::UTF8.GetByteCount([string]$value) -le $maximum}
function Address-Family([Net.Sockets.AddressFamily]$family){if($family -eq [Net.Sockets.AddressFamily]::InterNetwork){'IPv4'}elseif($family -eq [Net.Sockets.AddressFamily]::InterNetworkV6){'IPv6'}else{$null}}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$actualSid=[string]$identity.User.Value;$expectedSid=[string]$env:WINPCINFO_NETWORK_ASSESSMENT_SID
if($actualSid -eq 'S-1-5-18' -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or -not [string]::Equals($actualSid,$expectedSid,[StringComparison]::OrdinalIgnoreCase)){throw 'The child is outside the verified Assessment User Context.'}
$maximum=[int]$env:WINPCINFO_NETWORK_MAXIMUM
$scopeIds=@('scope:network.adapters','scope:network.connection-profiles','scope:network.ip-configuration','scope:network.routes','scope:network.resolvers','scope:network.proxy','scope:network.vpn-components','scope:network.security-components','scope:network.local-connections')
$scopes=@($scopeIds|ForEach-Object {New-Scope $_})
$adapters=[Collections.Generic.List[object]]::new();$ips=[Collections.Generic.List[object]]::new();$resolvers=[Collections.Generic.List[object]]::new();$interfaceIndexById=@{}
try{
    [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|ForEach-Object {
        try{
            $properties=$_.GetIPProperties();$ipv4=$null;$ipv6=$null
            try{$ipv4=$properties.GetIPv4Properties()}catch{}
            try{$ipv6=$properties.GetIPv6Properties()}catch{}
            $index=if($null -ne $ipv4){[int]$ipv4.Index}elseif($null -ne $ipv6){[int]$ipv6.Index}else{$null}
            if($null -eq $index -or -not (Valid-Text $_.Name 256) -or -not (Valid-Text $_.Description 512)){Set-Scope $scopes 'scope:network.adapters' 'Partial' 'NETWORK.ADAPTER_MALFORMED'}else{
                $interfaceIndexById[[string]$_.Id]=$index
                $status=switch([string]$_.OperationalStatus){'Up'{'Up'};'Down'{'Down'};'NotPresent'{'Disconnected'};default{'Unknown'}}
                $hardware=if($_.NetworkInterfaceType -in @([Net.NetworkInformation.NetworkInterfaceType]::Loopback,[Net.NetworkInformation.NetworkInterfaceType]::Tunnel)){$false}else{$true}
                Add-Bounded $adapters ([pscustomobject][ordered]@{name=[string]$_.Name;description=[string]$_.Description;status=$status;interfaceIndex=$index;linkSpeed=[long][Math]::Max(0,$_.Speed);hardwareInterface=$hardware}) $maximum $scopes 'scope:network.adapters'
            }
            foreach($unicast in @($properties.UnicastAddresses)){
                $family=Address-Family $unicast.Address.AddressFamily;if($null -eq $family){continue}
                $prefix=if($family -eq 'IPv4'){$unicast.PrefixLength}else{$unicast.PrefixLength};$gateway=@($properties.GatewayAddresses|Where-Object {$_.Address.AddressFamily -eq $unicast.Address.AddressFamily}|Select-Object -First 1)
                Add-Bounded $ips ([pscustomobject][ordered]@{interfaceIndex=$index;addressFamily=$family;address=$unicast.Address.ToString();prefixLength=[int]$prefix;defaultGateway=if($gateway.Count){$gateway[0].Address.ToString()}else{$null}}) $maximum $scopes 'scope:network.ip-configuration'
            }
            foreach($family in @('IPv4','IPv6')){
                $addresses=@($properties.DnsAddresses|Where-Object {(Address-Family $_.AddressFamily) -eq $family}|Select-Object -First 5|ForEach-Object {$_.ToString()})
                if($addresses.Count -gt 4){Set-Scope $scopes 'scope:network.resolvers' 'Partial' 'NETWORK.EVIDENCE_BOUND_EXCEEDED';$addresses=@($addresses|Select-Object -First 4)}
                if($addresses.Count){Add-Bounded $resolvers ([pscustomobject][ordered]@{interfaceIndex=$index;addressFamily=$family;addresses=$addresses}) $maximum $scopes 'scope:network.resolvers'}
            }
        }catch{Set-Scope $scopes 'scope:network.adapters' 'Partial' 'NETWORK.ADAPTER_MALFORMED';Set-Scope $scopes 'scope:network.ip-configuration' 'Partial' 'NETWORK.IP_CONFIGURATION_MALFORMED';Set-Scope $scopes 'scope:network.resolvers' 'Partial' 'NETWORK.RESOLVER_MALFORMED'}
    }
}catch{$s=Failure-State $_.Exception;Set-Scope $scopes 'scope:network.adapters' $s 'NETWORK.ADAPTER_SOURCE_FAILED';Set-Scope $scopes 'scope:network.ip-configuration' $s 'NETWORK.IP_CONFIGURATION_SOURCE_FAILED';Set-Scope $scopes 'scope:network.resolvers' $s 'NETWORK.RESOLVER_SOURCE_FAILED'}
$profiles=[Collections.Generic.List[object]]::new()
try{
    if(-not ('WinPCInfo.NetworkTopology.NetworkProfileReader' -as [type])){$null=Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
namespace WinPCInfo.NetworkTopology {
  public sealed class ProfileValue { public string name; public string category; public string ipv4Connectivity; public string ipv6Connectivity; public int interfaceIndex; }
  public static class NetworkProfileReader {
    // Network List Manager is a dual COM interface. Calling its published
    // IDispatch-aware vtable slots avoids PowerShell module activation while
    // retaining the exact HRESULT for fail-closed coverage. Every acquired COM
    // pointer and BSTR is released inside this short-lived Job-owned worker.
    [DllImport("ole32.dll")] static extern int CoCreateInstance(ref Guid clsid,IntPtr outer,uint context,ref Guid iid,out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetNetworksDelegate(IntPtr self,int flags,out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int NextDelegate(IntPtr self,uint count,out IntPtr value,out uint fetched);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetStringDelegate(IntPtr self,out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetIntDelegate(IntPtr self,out int value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetObjectDelegate(IntPtr self,out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetGuidDelegate(IntPtr self,out Guid value);
    static T Method<T>(IntPtr self,int slot) where T:Delegate { IntPtr table=Marshal.ReadIntPtr(self);return Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(table,slot*IntPtr.Size)); }
    static void Check(int result){if(result<0)Marshal.ThrowExceptionForHR(result);}
    static string Connectivity(int value,int subnet,int local,int internet) { return (value&internet)!=0?"Internet":(value&local)!=0?"LocalNetwork":(value&subnet)!=0?"Subnet":"Disconnected"; }
    public static ProfileValue[] Read(int maximum,out bool exceeded,out bool malformed) {
      exceeded=false;malformed=false;var indices=new Dictionary<Guid,int>();foreach(var nic in NetworkInterface.GetAllNetworkInterfaces()){Guid id;try{if(Guid.TryParse(nic.Id,out id))indices[id]=nic.GetIPProperties().GetIPv4Properties().Index;}catch{}}
      var clsid=new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B");var iid=new Guid("DCB00000-570F-4A9B-8D69-199FDBA5723B");IntPtr manager=IntPtr.Zero,networks=IntPtr.Zero;var values=new List<ProfileValue>();
      try { Check(CoCreateInstance(ref clsid,IntPtr.Zero,23,ref iid,out manager));Check(Method<GetNetworksDelegate>(manager,7)(manager,1,out networks));
        while(true){IntPtr network=IntPtr.Zero;uint fetched;int next=Method<NextDelegate>(networks,8)(networks,1,out network,out fetched);if(next==1)break;Check(next);if(next!=0||fetched!=1)throw new COMException("The network enumerator returned an invalid success result.",next);try{IntPtr text;Check(Method<GetStringDelegate>(network,7)(network,out text));string name=Marshal.PtrToStringBSTR(text);Marshal.FreeBSTR(text);int category,connectivity;Check(Method<GetIntDelegate>(network,18)(network,out category));Check(Method<GetIntDelegate>(network,17)(network,out connectivity));IntPtr connections;Check(Method<GetObjectDelegate>(network,13)(network,out connections));try{while(true){IntPtr connection;uint connectionFetched;int connectionNext=Method<NextDelegate>(connections,8)(connections,1,out connection,out connectionFetched);if(connectionNext==1)break;Check(connectionNext);if(connectionNext!=0||connectionFetched!=1)throw new COMException("The connection enumerator returned an invalid success result.",connectionNext);try{Guid adapter;Check(Method<GetGuidDelegate>(connection,12)(connection,out adapter));int index;if(!indices.TryGetValue(adapter,out index)){malformed=true;continue;}if(values.Count>=maximum){exceeded=true;return values.ToArray();}values.Add(new ProfileValue{name=name,category=category==0?"Public":category==1?"Private":category==2?"DomainAuthenticated":"Unknown",ipv4Connectivity=Connectivity(connectivity,16,32,64),ipv6Connectivity=Connectivity(connectivity,256,512,1024),interfaceIndex=index});}finally{Marshal.Release(connection);}}}finally{Marshal.Release(connections);}}finally{Marshal.Release(network);}}
        return values.ToArray();
      } finally {if(networks!=IntPtr.Zero)Marshal.Release(networks);if(manager!=IntPtr.Zero)Marshal.Release(manager);}
    }
  }
}
"@}
    $exceeded=$false;$malformed=$false;foreach($profile in [WinPCInfo.NetworkTopology.NetworkProfileReader]::Read($maximum,[ref]$exceeded,[ref]$malformed)){$null=$profiles.Add([pscustomobject][ordered]@{name=[string]$profile.name;category=[string]$profile.category;ipv4Connectivity=[string]$profile.ipv4Connectivity;ipv6Connectivity=[string]$profile.ipv6Connectivity;interfaceIndex=[int]$profile.interfaceIndex})}
    if($exceeded){Set-Scope $scopes 'scope:network.connection-profiles' 'Partial' 'NETWORK.EVIDENCE_BOUND_EXCEEDED'};if($malformed){Set-Scope $scopes 'scope:network.connection-profiles' 'Partial' 'NETWORK.PROFILE_MALFORMED'}
}catch{$s=Failure-State $_.Exception;Set-Scope $scopes 'scope:network.connection-profiles' $s 'NETWORK.PROFILE_SOURCE_FAILED'}
$routes=[Collections.Generic.List[object]]::new()
try{
    if(-not ('WinPCInfo.NetworkTopology.NativeRouteReader' -as [type])){$null=Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
namespace WinPCInfo.NetworkTopology {
  public sealed class RouteValue { public string addressFamily; public string destinationPrefix; public string nextHop; public int interfaceIndex; public int metric; }
  public static class NativeRouteReader {
    // IP Helper returns one process-owned table containing the already-local
    // route state. Marshal derives the SDK structure sizes and table alignment;
    // no architecture-specific header or row stride is guessed. We project only
    // family/address/prefix/index/metric, never a best-route probe.
    // FreeMibTable runs even when a malformed row or managed projection fails.
    [StructLayout(LayoutKind.Sequential,Size=28)] struct SOCKADDR_INET { public ushort Family; [MarshalAs(UnmanagedType.ByValArray,SizeConst=26)] public byte[] Data; }
    [StructLayout(LayoutKind.Sequential,Size=32)] struct IP_ADDRESS_PREFIX { public SOCKADDR_INET Prefix; public byte PrefixLength; }
    [StructLayout(LayoutKind.Sequential)] struct MIB_IPFORWARD_ROW2 {
      public ulong InterfaceLuid; public uint InterfaceIndex; public IP_ADDRESS_PREFIX DestinationPrefix; public SOCKADDR_INET NextHop;
      public byte SitePrefixLength; public uint ValidLifetime; public uint PreferredLifetime; public uint Metric; public uint Protocol;
      [MarshalAs(UnmanagedType.U1)] public bool Loopback; [MarshalAs(UnmanagedType.U1)] public bool AutoconfigureAddress;
      [MarshalAs(UnmanagedType.U1)] public bool Publish; [MarshalAs(UnmanagedType.U1)] public bool Immortal; public uint Age; public uint Origin;
    }
    [StructLayout(LayoutKind.Sequential)] struct MIB_IPFORWARD_TABLE2 { public uint NumEntries; public MIB_IPFORWARD_ROW2 Table; }
    [DllImport("iphlpapi.dll")] static extern uint GetIpForwardTable2(ushort family,out IntPtr table);
    [DllImport("iphlpapi.dll")] static extern void FreeMibTable(IntPtr table);
    static IPAddress Address(SOCKADDR_INET value){int start=value.Family==2?2:6;int length=value.Family==2?4:16;var bytes=new byte[length];Array.Copy(value.Data,start,bytes,0,length);return new IPAddress(bytes);}
    public static RouteValue[] GetIpForwardTable(int maximum, out bool exceeded, out bool malformed) {
      exceeded=false; malformed=false;IntPtr table;uint status=GetIpForwardTable2(0,out table);if(status!=0)throw new Win32Exception((int)status);
      try {uint count=(uint)Marshal.ReadInt32(table);long tableOffset=Marshal.OffsetOf<MIB_IPFORWARD_TABLE2>("Table").ToInt64();int rowSize=Marshal.SizeOf<MIB_IPFORWARD_ROW2>();var values=new List<RouteValue>();
        for(uint index=0;index<count;index++){IntPtr pointer=IntPtr.Add(table,checked((int)(tableOffset+index*(long)rowSize)));var row=Marshal.PtrToStructure<MIB_IPFORWARD_ROW2>(pointer);ushort family=row.DestinationPrefix.Prefix.Family;byte prefixLength=row.DestinationPrefix.PrefixLength;if((family!=2&&family!=23)||row.NextHop.Family!=family||row.InterfaceIndex>Int32.MaxValue||row.Metric>Int32.MaxValue||prefixLength>(family==2?32:128)){malformed=true;continue;}if(values.Count>=maximum){exceeded=true;break;}values.Add(new RouteValue{addressFamily=family==2?"IPv4":"IPv6",destinationPrefix=Address(row.DestinationPrefix.Prefix)+"/"+prefixLength,nextHop=Address(row.NextHop).ToString(),interfaceIndex=(int)row.InterfaceIndex,metric=(int)row.Metric});}
        return values.ToArray();
      } finally {if(table!=IntPtr.Zero)FreeMibTable(table);}
    }
  }
}
"@}
    $exceeded=$false;$malformed=$false;foreach($route in [WinPCInfo.NetworkTopology.NativeRouteReader]::GetIpForwardTable($maximum,[ref]$exceeded,[ref]$malformed)){$null=$routes.Add([pscustomobject][ordered]@{addressFamily=[string]$route.addressFamily;destinationPrefix=[string]$route.destinationPrefix;nextHop=[string]$route.nextHop;interfaceIndex=[int]$route.interfaceIndex;metric=[int]$route.metric})}
    if($exceeded){Set-Scope $scopes 'scope:network.routes' 'Partial' 'NETWORK.EVIDENCE_BOUND_EXCEEDED'};if($malformed){Set-Scope $scopes 'scope:network.routes' 'Partial' 'NETWORK.ROUTE_MALFORMED'}
}catch{$s=Failure-State $_.Exception;Set-Scope $scopes 'scope:network.routes' $s 'NETWORK.ROUTE_SOURCE_FAILED'}
$proxy=[pscustomobject][ordered]@{enabled=$false;server=$null;autoConfigUrl=$null};try{$key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings',$false);try{if($null -ne $key){$enabled=$key.GetValue('ProxyEnable',$null);$server=$key.GetValue('ProxyServer',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);$auto=$key.GetValue('AutoConfigURL',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);if($null -ne $enabled -and $enabled -isnot [int]){Set-Scope $scopes 'scope:network.proxy' 'Partial' 'NETWORK.PROXY_MALFORMED'}else{$proxy=[pscustomobject][ordered]@{enabled=($null -ne $enabled -and [int]$enabled -eq 1);server=if($server -is [string]){[string]$server}else{$null};autoConfigUrl=if($auto -is [string]){[string]$auto}else{$null}}}}}finally{if($null -ne $key){$key.Dispose()}}}catch{$s=Failure-State $_.Exception;Set-Scope $scopes 'scope:network.proxy' $s 'NETWORK.PROXY_SOURCE_FAILED'}
$vpns=[Collections.Generic.List[object]]::new();try{$phonebook=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)) 'Microsoft\Network\Connections\Pbk\rasphone.pbk';if([IO.File]::Exists($phonebook)){$info=[IO.FileInfo]::new($phonebook);if($info.Length -gt 65536){Set-Scope $scopes 'scope:network.vpn-components' 'Partial' 'NETWORK.EVIDENCE_BOUND_EXCEEDED'}else{$entry=$null;foreach($line in [IO.File]::ReadLines($phonebook,[Text.Encoding]::UTF8)){if($line -match '^\[(.+)\]$'){if($null -ne $entry -and $entry.type -eq 2 -and $entry.server){Add-Bounded $vpns ([pscustomobject][ordered]@{name=$entry.name;serverAddress=$entry.server;tunnelType=$entry.tunnel;connectionStatus=$null}) $maximum $scopes 'scope:network.vpn-components'};$entry=[ordered]@{name=$Matches[1];type=$null;server=$null;tunnel=$null}}elseif($null -ne $entry -and $line -match '^Type=(\d+)$'){$entry.type=[int]$Matches[1]}elseif($null -ne $entry -and $line -match '^PhoneNumber=(.*)$'){$entry.server=$Matches[1]}elseif($null -ne $entry -and $line -match '^VpnStrategy=(\d+)$'){$entry.tunnel=switch([int]$Matches[1]){1{'Pptp'};2{'PptpFirst'};3{'L2tp'};4{'L2tpFirst'};5{'Sstp'};6{'SstpFirst'};7{'Ikev2'};8{'Ikev2First'};9{'PptpSstp'};10{'L2tpSstp'};11{'Ikev2Sstp'};12{'ProtocolList'};default{'Automatic'}}}};if($null -ne $entry -and $entry.type -eq 2 -and $entry.server){Add-Bounded $vpns ([pscustomobject][ordered]@{name=$entry.name;serverAddress=$entry.server;tunnelType=$entry.tunnel;connectionStatus=$null}) $maximum $scopes 'scope:network.vpn-components'}}}}catch{$s=Failure-State $_.Exception;Set-Scope $scopes 'scope:network.vpn-components' $s 'NETWORK.VPN_SOURCE_FAILED'}
$components=[Collections.Generic.List[object]]::new();Set-Scope $scopes 'scope:network.security-components' 'Unsupported' 'NETWORK.SECURITY_COMPONENT_OFFLINE_SOURCE_UNAVAILABLE'
$connections=[Collections.Generic.List[object]]::new();try{$properties=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties();foreach($connection in $properties.GetActiveTcpConnections()){Add-Bounded $connections ([pscustomobject][ordered]@{state=[string]$connection.State;localAddress=$connection.LocalEndPoint.Address.ToString();localPort=[int]$connection.LocalEndPoint.Port;remoteAddress=$connection.RemoteEndPoint.Address.ToString();remotePort=[int]$connection.RemoteEndPoint.Port}) $maximum $scopes 'scope:network.local-connections'};foreach($listener in $properties.GetActiveTcpListeners()){Add-Bounded $connections ([pscustomobject][ordered]@{state='Listen';localAddress=$listener.Address.ToString();localPort=[int]$listener.Port;remoteAddress=if($listener.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){'0.0.0.0'}else{'::'};remotePort=0}) $maximum $scopes 'scope:network.local-connections'}}catch{$s=Failure-State $_.Exception;Set-Scope $scopes 'scope:network.local-connections' $s 'NETWORK.CONNECTION_SOURCE_FAILED'}
$dependent=@('scope:network.microsoft-connectivity','scope:network.enrollment-dns','scope:network.tls-trust')|ForEach-Object {[pscustomobject][ordered]@{scopeId=$_;state='NotAttempted';reasonCode='NETWORK.LOCAL_ONLY_NOT_ATTEMPTED'}}
$payload=[pscustomobject][ordered]@{sourceLocale='und';assessmentUserContextVerified=$true;processRelationship='SameUser';networkBehavior='LocalOnly';outboundRequestCount=0;adapters=@($adapters);profiles=@($profiles);ipConfigurations=@($ips);routes=@($routes);resolvers=@($resolvers);proxy=$proxy;vpnComponents=@($vpns);securityComponents=@($components);connections=@($connections);scopeStates=@($scopes)+@($dependent);executionContext='StandardUser'}
$json=$payload|ConvertTo-Json -Compress -Depth 8;[Console]::Out.Write($json)
'@
}

function ConvertTo-NetworkTopologyEncodedCommand {
    param([Parameter(Mandatory)][string]$Source)
    # CreateProcess has a finite command-line limit. Compressing the immutable,
    # release-owned source keeps that launch boundary bounded without staging a
    # writable script pathname that another same-user process could replace.
    $input=[IO.MemoryStream]::new([Text.UTF8Encoding]::new($false).GetBytes($Source))
    $output=[IO.MemoryStream]::new()
    try{
        $gzip=[IO.Compression.GZipStream]::new($output,[IO.Compression.CompressionLevel]::Optimal,$true)
        try{$input.CopyTo($gzip)}finally{$gzip.Dispose()}
        $payload=[Convert]::ToBase64String($output.ToArray())
    }finally{$input.Dispose();$output.Dispose()}
    $bootstrap='$b=[Convert]::FromBase64String('''+$payload+''');$m=[IO.MemoryStream]::new($b);$g=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);$r=[IO.StreamReader]::new($g,[Text.Encoding]::UTF8);try{&([scriptblock]::Create($r.ReadToEnd()))}finally{$r.Dispose();$g.Dispose();$m.Dispose()}'
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
}

function Get-NetworkTopologyWorkerEnvironment {
    param([string]$AssessmentUserSid,[int]$MaximumItems)
    $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $environment['SystemRoot']=[Environment]::GetFolderPath('Windows')
    $environment['WINPCINFO_NETWORK_ASSESSMENT_SID']=$AssessmentUserSid
    $environment['WINPCINFO_NETWORK_MAXIMUM']=[string]$MaximumItems
    # PowerShell documents that telemetry and update preferences must be set
    # before pwsh starts. The supervised worker receives a closed environment
    # projection so host activation cannot violate the OfflineOnly operation.
    $environment['POWERSHELL_TELEMETRY_OPTOUT']='1'
    $environment['POWERSHELL_UPDATECHECK']='Off'
    $environment['POWERSHELL_DIAGNOSTICS_OPTOUT']='1'
    $environment['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
    $environment
}

function Invoke-BoundedNetworkTopologySnapshot {
    param($Policy,[string]$AssessmentUserSid)
    # Threat boundary: only this release-owned source string becomes an encoded
    # command. Neither a collector, fixture, request, nor worker can supply
    # script or executable text. The parent selects the active Microsoft-signed
    # pwsh path and starts it suspended inside the Process Supervisor Job Object.
    # We trust the inherited Windows user/session only after the child compares
    # its canonical SID with the separately verified Assessment User SID.
    # Output remains untrusted UTF-8 JSON bytes until the coordinator's exact
    # property/primitive validator and fresh-object projection accept it.
    # Timeout, output overflow, nonzero exit, decode failure, or any uncertain
    # owned-tree cleanup fails closed; cleanup uncertainty takes run precedence.
    Initialize-ProcessSupervisorNativeType
    $collector=$Policy.collector;$maximumMilliseconds=[int]$collector.deadlineMilliseconds
    $terminationMilliseconds=[Math]::Min(1000,[Math]::Max(1,[Math]::Floor($maximumMilliseconds/4)))
    $activeMilliseconds=[Math]::Max(1,$maximumMilliseconds-$terminationMilliseconds)
    $source=Get-NetworkTopologyLiveSource;$encoded=ConvertTo-NetworkTopologyEncodedCommand -Source $source
    $started=[DateTimeOffset]::UtcNow;$executable=[IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
    if(-not [IO.File]::Exists($executable) -or -not [string]::Equals($executable,[Environment]::ProcessPath,[StringComparison]::OrdinalIgnoreCase)){return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode='NETWORK.BOUNDARY_UNAVAILABLE';startedAt=$started;completedAt=[DateTimeOffset]::UtcNow}}
    $environment=Get-NetworkTopologyWorkerEnvironment -AssessmentUserSid $AssessmentUserSid -MaximumItems ([int]$collector.maximumItemsPerScope)
    $eventName="Local\WINPCInfo-NetworkTopology-$([Guid]::NewGuid().ToString('N'))";$created=$false;$event=$null
    try{
        $event=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$eventName,[ref]$created);if(-not $created){throw 'Event ownership failed.'}
        $native=[WinPCInfo.ProcessSupervisor.NativeRunner]::Run($executable,@('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded),$PSHOME,$environment,$activeMilliseconds,[int]$collector.resultMaximumUtf8Bytes,4096,[Threading.CancellationToken]::None,$event,1,$terminationMilliseconds,$false)
        if($native.Started -and -not $native.CompleteOwnedTreeAbsent){$e=[InvalidOperationException]::new('The Network Topology worker tree could not be proved absent.');$e.Data['ReasonCode']='NETWORK.COLLECTOR_CLEANUP_INCOMPLETE';throw $e}
        if(-not $native.Started -or $native.FailureStage -ne [WinPCInfo.ProcessSupervisor.NativeFailureStage]::None -or $native.ExitCode -ne 0 -or $native.StandardOutputExceeded -or $native.StandardErrorBytes -ne 0){$reason=Get-NativeSupervisorReasonCode -NativeResult $native;if(-not $reason){$reason='NETWORK.SOURCE_FAILED'};return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode=$reason;startedAt=$started;completedAt=[DateTimeOffset]::UtcNow}}
        if(-not (Test-NetworkTopologyTransportLength -Utf8ByteCount $native.StandardOutputBytes -Policy $Policy)){return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode='PROCESS.OUTPUT_LIMIT_EXCEEDED';startedAt=$started;completedAt=[DateTimeOffset]::UtcNow}}
        [pscustomobject]@{succeeded=$true;payload=ConvertFrom-NetworkTopologyTransport -Bytes $native.StandardOutput -Policy $Policy;reasonCode='';startedAt=$started;completedAt=[DateTimeOffset]::UtcNow}
    }catch{if($_.Exception.Data['ReasonCode']){throw};[pscustomobject]@{succeeded=$false;payload=$null;reasonCode='NETWORK.SOURCE_FAILED';startedAt=$started;completedAt=[DateTimeOffset]::UtcNow}}finally{if($null -ne $event){$event.Dispose()}}
}

function Add-NetworkTopologyEvidenceRecord {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$CollectorResult,[Parameter(Mandatory)]$Policy)
    if($Record.run.evidenceProfileId -ne 'profile:device-firmware-identity-administrator-policy-and-resource-dependencies'){
        throw 'Network Topology evidence requires the accepted resource-ready profile.'
    }
    if(-not $CollectorResult.cleanupVerified -or -not (Test-NetworkTopologyCollectorPayload $CollectorResult.payload $Policy)){
        throw 'Network Topology evidence requires a closed cleanup-verified collector result.'
    }
    $runId=[string]$Record.run.runId;$payload=$CollectorResult.payload;$collector=$Policy.collector
    $collectedAt=[string]$CollectorResult.envelope.completedAt;$context=[string]$CollectorResult.envelope.executionContext
    $observations=[Collections.Generic.List[object]]::new();$provenance=[Collections.Generic.List[object]]::new()
    $subjects=[Collections.Generic.List[object]]::new();$diagnostics=[Collections.Generic.List[object]]::new();$coverage=[Collections.Generic.List[object]]::new()
    $scopeObservationIds=@{};foreach($scope in @($Policy.localScopes)+@($Policy.networkDependentScopes)){$scopeObservationIds[[string]$scope.scopeId]=[Collections.Generic.List[string]]::new()}
    $scopeStateById=@{};foreach($state in $payload.scopeStates){$scopeStateById[[string]$state.scopeId]=[string]$state.state}
    $envelopeSubjects=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$null=$envelopeSubjects.Add('subject:device:primary');$null=$envelopeSubjects.Add('subject:assessment-user:primary')
    $sourceByField=@{};foreach($scope in $Policy.localScopes){foreach($fieldId in $scope.fieldIds){$sourceByField[[string]$fieldId]=[string]$scope.sourceId}}
    function Add-NetworkObservation([string]$scopeId,[string]$suffix,[string]$fieldId,[string]$subjectId,$value,[string]$valueState='ObservedValue'){
        $observationId="observation:network-$suffix`:$runId";$provenanceId="provenance:network-$suffix`:$runId"
        $entry=[ordered]@{observationId=$observationId;fieldId=$fieldId;subjectId=$subjectId;provenanceId=$provenanceId;valueState=$valueState};if($valueState -eq 'ObservedValue'){$entry.value=$value}
        $observations.Add([pscustomobject]$entry);$provenance.Add([pscustomobject][ordered]@{provenanceId=$provenanceId;fieldId=$fieldId;subjectId=$subjectId;sourceId=$sourceByField[$fieldId];collectorId=[string]$collector.collectorId;collectorVersion=[string]$collector.collectorVersion;executionContext=$context;collectedAt=$collectedAt;sourceLocale=[string]$payload.sourceLocale})
        $scopeObservationIds[$scopeId].Add($observationId);$null=$envelopeSubjects.Add($subjectId)
    }
    function Add-NetworkValue([string]$scopeId,[string]$suffix,[string]$fieldId,[string]$subjectId,$value){if($null -eq $value){Add-NetworkObservation $scopeId $suffix $fieldId $subjectId $null 'SourceReportedUnknown'}else{Add-NetworkObservation $scopeId $suffix $fieldId $subjectId $value}}
    $definitions=@(
        @{scope='scope:network.adapters';collection='adapters';kind='Interface';prefix='adapter';fields=@(@('name','field:network.adapter.name'),@('status','field:network.adapter.status'),@('interfaceIndex','field:network.adapter.interface-index'),@('hardwareInterface','field:network.adapter.hardware-interface'))},
        @{scope='scope:network.connection-profiles';collection='profiles';kind='Interface';prefix='profile';fields=@(@('name','field:network.profile.name'),@('category','field:network.profile.category'),@('connectivity','field:network.profile.connectivity'))},
        @{scope='scope:network.ip-configuration';collection='ipConfigurations';kind='Interface';prefix='ip';fields=@(@('interfaceIndex','field:network.ip.interface-index'),@('addressFamily','field:network.ip.address-family'),@('address','field:network.ip.address'),@('prefixLength','field:network.ip.prefix-length'))},
        @{scope='scope:network.routes';collection='routes';kind='Interface';prefix='route';fields=@(@('addressFamily','field:network.route.address-family'),@('destinationPrefix','field:network.route.destination-prefix'),@('nextHop','field:network.route.next-hop'),@('metric','field:network.route.metric'))},
        @{scope='scope:network.resolvers';collection='resolvers';kind='Interface';prefix='resolver';fields=@(@('addressFamily','field:network.resolver.address-family'),@('addressesText','field:network.resolver.addresses'))},
        @{scope='scope:network.vpn-components';collection='vpnComponents';kind='Interface';prefix='vpn';fields=@(@('name','field:network.vpn.name'),@('serverAddress','field:network.vpn.server-address'),@('tunnelType','field:network.vpn.tunnel-type'),@('connectionStatus','field:network.vpn.connection-status'))},
        @{scope='scope:network.security-components';collection='securityComponents';kind='Application';prefix='security-component';fields=@(@('kind','field:network.security-component.kind'),@('name','field:network.security-component.name'),@('stateCode','field:network.security-component.state-code'))},
        @{scope='scope:network.local-connections';collection='connections';kind='Interface';prefix='connection';fields=@(@('state','field:network.connection.state'),@('localEndpoint','field:network.connection.local-endpoint'),@('remoteEndpoint','field:network.connection.remote-endpoint'))}
    )
    foreach($definition in $definitions){
        if($scopeStateById[$definition.scope] -notin @('Complete','Partial')){continue};$index=0
        foreach($item in @($payload.($definition.collection))){
            $subjectId="subject:$($definition.prefix):$index";$subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind=$definition.kind})
            foreach($field in $definition.fields){
                $value=switch($field[0]){'connectivity'{"IPv4=$($item.ipv4Connectivity);IPv6=$($item.ipv6Connectivity)"};'addressesText'{@($item.addresses)-join ','};'localEndpoint'{"$($item.localAddress):$($item.localPort)"};'remoteEndpoint'{"$($item.remoteAddress):$($item.remotePort)"};default{$item.($field[0])}}
                Add-NetworkValue $definition.scope "$($definition.prefix)-$index-$($field[0])" $field[1] $subjectId $value
            };$index++
        }
    }
    if($scopeStateById['scope:network.proxy'] -in @('Complete','Partial')){
        $subjectId='subject:network-proxy:current-user';$subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='Interface'})
        Add-NetworkValue 'scope:network.proxy' 'proxy-enabled' 'field:network.proxy.enabled' $subjectId $payload.proxy.enabled
        foreach($definition in @(@('server','field:network.proxy.server'),@('autoConfigUrl','field:network.proxy.auto-config-url'))){
            if($null -eq $payload.proxy.($definition[0])){Add-NetworkObservation 'scope:network.proxy' "proxy-$($definition[0])" $definition[1] $subjectId $null 'ObservedAbsent'}else{Add-NetworkValue 'scope:network.proxy' "proxy-$($definition[0])" $definition[1] $subjectId $payload.proxy.($definition[0])}
        }
    }
    foreach($scope in $Policy.localScopes){
        if($scopeStateById[[string]$scope.scopeId] -eq 'Complete' -and $scopeObservationIds[[string]$scope.scopeId].Count -eq 0){
            $i=0;foreach($fieldId in $scope.fieldIds){Add-NetworkObservation ([string]$scope.scopeId) "absent-$(([string]$scope.scopeId).Split('.')[-1])-$i" ([string]$fieldId) 'subject:device:primary' $null 'ObservedAbsent';$i++}
        }
    }
    foreach($scopeState in $payload.scopeStates){
        $suffix=([string]$scopeState.scopeId).Substring('scope:network.'.Length).Replace('.','-');$coverageId="coverage:network-$suffix`:$runId"
        $entry=[ordered]@{coverageId=$coverageId;scopeId=[string]$scopeState.scopeId;state=[string]$scopeState.state;observationIds=@($scopeObservationIds[[string]$scopeState.scopeId]);diagnosticIds=@()}
        if($scopeState.state -ne 'Complete'){$diagnosticId="diagnostic:network-$suffix`:$runId";$entry.reasonCode=[string]$scopeState.reasonCode;$entry.diagnosticIds=@($diagnosticId);$diagnostics.Add([pscustomobject][ordered]@{diagnosticId=$diagnosticId;scopeId=[string]$scopeState.scopeId;phase='Collection';reasonCode=[string]$scopeState.reasonCode;operatorMessageId=if($scopeState.state -eq 'NotAttempted'){'network.local-only.not-attempted'}else{'network.local-collection.incomplete'}})}
        $coverage.Add([pscustomobject]$entry)
    }
    $Record.subjects=@($Record.subjects)+@($subjects);$Record.observations=@($Record.observations)+@($observations);$Record.provenance=@($Record.provenance)+@($provenance);$Record.coverage=@($Record.coverage)+@($coverage);$Record.diagnostics=@($Record.diagnostics)+@($diagnostics)
    $localCoverageIds=@($coverage|Where-Object scopeId -in @($Policy.localScopes.scopeId)|ForEach-Object coverageId)
    $localDiagnosticIds=@($diagnostics|Where-Object scopeId -in @($Policy.localScopes.scopeId)|ForEach-Object diagnosticId)
    $Record.collectorResults=@($Record.collectorResults)+[pscustomobject][ordered]@{envelopeId="envelope:network-topology:$runId";collectorId=[string]$collector.collectorId;collectorVersion=[string]$collector.collectorVersion;operationId=[string]$collector.operationId;intendedScopeIds=@($Policy.localScopes.scopeId);subjectIds=@($envelopeSubjects);startedAt=[string]$CollectorResult.envelope.startedAt;completedAt=$collectedAt;executionContext=$context;attempts=1;observationIds=@($observations|ForEach-Object observationId);coverageIds=$localCoverageIds;diagnosticIds=$localDiagnosticIds}
    $Record.run.evidenceProfileId=[string]$Policy.evidenceProfileId;$Record.run.outcome='CompletedWithGaps'
    $Record
}

function Invoke-NetworkTopologyRule {
    param($Rule,[int]$InputObservationCount,[scriptblock]$Evaluation)
    $watch=[Diagnostics.Stopwatch]::StartNew();$result=@(& $Evaluation);$watch.Stop()
    if($InputObservationCount -gt [int]$Rule.maximumInputObservations -or $watch.ElapsedMilliseconds -gt [int]$Rule.deadlineMilliseconds -or $result.Count -ne 1 -or $result[0].outcome -notin @('Informational','Indeterminate','NeedsAttention','ExpectedCondition')){throw "The release-owned $($Rule.operationId) rule violated its finite contract."}
    $result[0]
}

function Complete-ValidatedNetworkTopologyAssessmentRecord {
    param($Record,$Policy,$ContractValidation)
    if(-not $ContractValidation.accepted -or $Record.run.evidenceProfileId -ne $Policy.evidenceProfileId){throw 'Network Topology rules require an accepted source-only combined record.'}
    $localCoverage=@($Record.coverage|Where-Object scopeId -in @($Policy.localScopes.scopeId));$networkCoverage=@($Record.coverage|Where-Object scopeId -in @($Policy.networkDependentScopes.scopeId))
    $localObservations=@($Record.observations|Where-Object {$_.fieldId -like 'field:network.*' -and $_.fieldId -notlike '*.result'})
    $componentObservations=@($Record.observations|Where-Object {$_.fieldId -like 'field:network.vpn.*' -or $_.fieldId -like 'field:network.security-component.*'})
    $rules=@{};foreach($rule in $Policy.rules){$rules[[string]$rule.findingKind]=$rule}
    $evaluations=@(
        @{kind='local-network-configuration';target='subject:device:primary';observations=$localObservations;result=(Invoke-NetworkTopologyRule $rules['local-network-configuration'] $localObservations.Count {if(@($localCoverage|Where-Object state -ne 'Complete').Count){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.LOCAL_NETWORK_EVIDENCE_INCOMPLETE'}}else{[pscustomobject]@{outcome='Informational'}}})},
        @{kind='network-component-inventory';target='subject:device:primary';observations=$componentObservations;result=(Invoke-NetworkTopologyRule $rules['network-component-inventory'] $componentObservations.Count {if(@($localCoverage|Where-Object {$_.scopeId -in @('scope:network.vpn-components','scope:network.security-components') -and $_.state -ne 'Complete'}).Count){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.NETWORK_COMPONENT_EVIDENCE_INCOMPLETE'}}else{[pscustomobject]@{outcome='Informational'}}})},
        @{kind='local-only-network-coverage';target='subject:device:primary';observations=@();result=(Invoke-NetworkTopologyRule $rules['local-only-network-coverage'] 0 {[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.NETWORK_REQUESTS_NOT_ATTEMPTED'}})}
    )
    foreach($evaluation in $evaluations){
        $rule=$rules[$evaluation.kind];$findingId="finding:$($evaluation.kind):$($Record.run.runId)";$finding=[ordered]@{findingId=$findingId;ruleId=[string]$rule.ruleId;targetSubjectId=$evaluation.target;outcome=[string]$evaluation.result.outcome;evidenceReferences=@($evaluation.observations|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})};if($evaluation.result.PSObject.Properties['reasonCode']){$finding.reasonCode=[string]$evaluation.result.reasonCode};$Record.findings=@($Record.findings)+[pscustomobject]$finding
        $recommendation=@($Policy.recommendations|Where-Object findingKind -eq $evaluation.kind)[0];$Record.recommendations=@($Record.recommendations)+[pscustomobject][ordered]@{recommendationId="recommendation:$($evaluation.kind):$($Record.run.runId)";definitionId=[string]$recommendation.definitionId;kind='AssessmentRecommendation';findingIds=@($findingId)}
    }
    $Record.run.outcome='CompletedWithGaps';$Record
}

function New-NetworkTopologyPublicProjection {
    param([Parameter(Mandatory)]$CollectorResult,[Parameter(Mandatory)]$Policy)
    $payload=$CollectorResult.payload
    [pscustomobject][ordered]@{
        recordType='win-pcinfo.network-topology-validation';contractVersion='1.0.0'
        localScopeCoverage=if(@($payload.scopeStates|Where-Object {$_.scopeId -in @($Policy.localScopes.scopeId) -and $_.state -ne 'Complete'}).Count){'Partial'}else{'Complete'}
        networkDependentCoverage='NotAttempted';adapterCount=@($payload.adapters).Count
        profileCount=@($payload.profiles).Count;routeCount=@($payload.routes).Count
        resolverSetCount=@($payload.resolvers).Count;vpnComponentCount=@($payload.vpnComponents).Count
        securityComponentCount=@($payload.securityComponents).Count;connectionCount=@($payload.connections).Count
        outboundRequestCount=[int]$payload.outboundRequestCount;networkIdentifiersPublished=$false
        componentHealthInferred=$false;packetCapturePerformed=$false;networkConfigurationChanged=$false
    }
}
