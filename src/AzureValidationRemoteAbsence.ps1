# Read-only remote predicates for the admitted round adapter. This module
# neither mutates infrastructure nor establishes full Zero Round Residue.
# The outer factory supplies an independently constructed observation channel
# and authenticated private intent. Transfers, coordination, local cleanup and
# recovery records remain separate required predicates.

function New-AzureValidationRemoteAbsencePlan {
    param(
        [Parameter(Mandatory)] $Channel,
        [Parameter(Mandatory)][object[]] $Targets,
        [Parameter(Mandatory)][string] $TransientCollectionRouteName,
        [Parameter(Mandatory)][string] $TaggedCollectionRouteName,
        [Parameter(Mandatory)][string] $HostPeeringCollectionRouteName,
        [Parameter(Mandatory)][string] $RoundCorrelation
    )
    if ($Channel.Kind -cnotin @('ManagedIdentity','InjectedNonQualifying') -or
        $Targets.Count -lt 4 -or $Targets.Count -gt 64 -or
        $RoundCorrelation -cnotmatch '\A[A-Za-z0-9_-]{8,64}\z') {
        throw 'VALIDATION.ABSENCE_PLAN_INVALID'
    }
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $records = [Collections.Generic.List[object]]::new()
    foreach ($target in $Targets) {
        if ($target -isnot [Collections.IDictionary] -or $target.Count -ne 4 -or
            @($target.Keys | Where-Object { $_ -cnotin @('Role','ReadRouteName','Id','Type') }).Count -ne 0 -or
            [string] $target.Role -cnotin @('RoundGroup','RoundResource','RoundPeering','HostPeering') -or
            $target.Id -isnot [string] -or $target.Id.Length -gt 4096 -or
            $target.Type -isnot [string] -or
            -not $ids.Add($target.Id) -or -not $Channel.Routes.ContainsKey([string] $target.ReadRouteName)) {
            throw 'VALIDATION.ABSENCE_PLAN_INVALID'
        }
        $route = $Channel.Routes[[string] $target.ReadRouteName]
        if ($route.Method -cne 'GET' -or $route.Paginated -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals($route.Path, $target.Id)) {
            throw 'VALIDATION.ABSENCE_PLAN_INVALID'
        }
        $copy = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        foreach ($key in @('Role','ReadRouteName','Id','Type')) { $copy.Add($key,[string]$target[$key]) }
        $records.Add([Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($copy))
    }
    $group = @($records | Where-Object Role -CEQ RoundGroup)
    $hostPeer = @($records | Where-Object Role -CEQ HostPeering)
    $roundPeer = @($records | Where-Object Role -CEQ RoundPeering)
    if ($group.Count -ne 1 -or $hostPeer.Count -ne 1 -or $roundPeer.Count -ne 1 -or
        $group[0].Id -cnotmatch '\A/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()-]+\z' -or
        $group[0].Type -cne 'Microsoft.Resources/resourceGroups' -or
        $hostPeer[0].Type -cne 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings' -or
        $roundPeer[0].Type -cne 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings') {
        throw 'VALIDATION.ABSENCE_PLAN_INVALID'
    }
    $peeringPattern = '\A/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()-]+/providers/Microsoft.Network/virtualNetworks/[A-Za-z0-9_.()-]+/virtualNetworkPeerings/[A-Za-z0-9_.()-]+\z'
    if ($hostPeer[0].Id -cnotmatch $peeringPattern -or $roundPeer[0].Id -cnotmatch $peeringPattern) {
        throw 'VALIDATION.ABSENCE_PLAN_INVALID'
    }
    $hostVnet = $hostPeer[0].Id.Substring(0, $hostPeer[0].Id.LastIndexOf('/virtualNetworkPeerings/',[StringComparison]::Ordinal))
    $roundVnet = $roundPeer[0].Id.Substring(0, $roundPeer[0].Id.LastIndexOf('/virtualNetworkPeerings/',[StringComparison]::Ordinal))
    if ([StringComparer]::OrdinalIgnoreCase.Equals($hostVnet, $roundVnet) -or
        @($records | Where-Object {
            $_.Role -ceq 'RoundResource' -and [StringComparer]::OrdinalIgnoreCase.Equals($_.Id,$roundVnet) -and
            $_.Type -ceq 'Microsoft.Network/virtualNetworks'
        }).Count -ne 1) { throw 'VALIDATION.ABSENCE_PLAN_INVALID' }
    foreach ($target in $records) {
        if ($target.Role -cne 'RoundGroup' -and $target.Role -cne 'HostPeering' -and
            -not $target.Id.StartsWith(($group[0].Id+'/'),[StringComparison]::OrdinalIgnoreCase)) {
            throw 'VALIDATION.ABSENCE_PLAN_INVALID'
        }
    }
    foreach ($name in @($TransientCollectionRouteName,$TaggedCollectionRouteName,$HostPeeringCollectionRouteName)) {
        if (-not $Channel.Routes.ContainsKey($name) -or $Channel.Routes[$name].Method -cne 'GET' -or
            -not $Channel.Routes[$name].Paginated) { throw 'VALIDATION.ABSENCE_PLAN_INVALID' }
    }
    $subscription = $group[0].Id.Substring(0,$group[0].Id.IndexOf('/resourceGroups/',[StringComparison]::Ordinal))
    $transient = $Channel.Routes[$TransientCollectionRouteName]
    $tags = $Channel.Routes[$TaggedCollectionRouteName]
    $hostPeers = $Channel.Routes[$HostPeeringCollectionRouteName]
    if ($transient.Path -cne ($group[0].Id+'/resources') -or $transient.ScopePrefix -cne $group[0].Id -or
        $transient.ResourceType -cne '*' -or
        $tags.Path -cne ($subscription+'/resources') -or $tags.ScopePrefix -cne $subscription -or $tags.ResourceType -cne '*' -or
        $hostPeers.Path -cne ($hostVnet+'/virtualNetworkPeerings') -or
        $hostPeers.ResourceType -cne 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings') {
        throw 'VALIDATION.ABSENCE_PLAN_INVALID'
    }
    $values = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $values.Add('Channel',$Channel)
    $values.Add('Targets',[Array]::AsReadOnly([object[]]$records.ToArray()))
    $values.Add('GroupId',$group[0].Id)
    $values.Add('GroupRouteName',$group[0].ReadRouteName)
    $values.Add('RoundVnetId',$roundVnet)
    $values.Add('HostVnetId',$hostVnet)
    $values.Add('RoundCorrelation',$RoundCorrelation)
    $values.Add('TransientCollectionRouteName',$TransientCollectionRouteName)
    $values.Add('TaggedCollectionRouteName',$TaggedCollectionRouteName)
    $values.Add('HostPeeringCollectionRouteName',$HostPeeringCollectionRouteName)
    [Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($values)
}

function Get-AzureValidationRemoteAbsence {
    param([Parameter(Mandatory)] $Plan)
    $targetPresent = 0
    $peeringPresent = 0
    $scopePresent = 0
    $tagPresent = 0
    $complete = $false
    $reason = 'VALIDATION.REMOTE_ABSENCE_UNVERIFIED'
    $state = 'RemoteAbsenceUnverified'
    $queries = 0
    try {
        foreach ($target in $Plan.Targets) {
            $response = Invoke-AzureValidationArmRoute -Channel $Plan.Channel -Name $target.ReadRouteName
            $queries++
            if ($response.StatusCode -eq 404) { continue }
            if ($response.StatusCode -ne 200 -or
                $response.Document -isnot [Collections.IDictionary] -or
                -not $response.Document.Contains('id') -or
                $response.Document.id -isnot [string] -or
                -not [StringComparer]::OrdinalIgnoreCase.Equals($response.Document.id,$target.Id) -or
                ($response.Document.Contains('type') -and ($response.Document.type -isnot [string] -or
                    -not [StringComparer]::OrdinalIgnoreCase.Equals($response.Document.type,$target.Type)))) {
                throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
            }
            Assert-AzureArmProtocolFields -Document $response.Document -Names @('id','type')
            $targetPresent++
            if ($target.Role -cin @('HostPeering','RoundPeering')) { $peeringPresent++ }
        }
        $scope = Get-AzureValidationArmCollection -Channel $Plan.Channel -Name $Plan.TransientCollectionRouteName -MissingParentRouteName $Plan.GroupRouteName
        $scopePresent = $scope.Items.Count
        $tagged = Get-AzureValidationArmCollection -Channel $Plan.Channel -Name $Plan.TaggedCollectionRouteName
        foreach ($item in $tagged.Items) {
            if ($item.id.StartsWith(($Plan.GroupId+'/'),[StringComparison]::OrdinalIgnoreCase) -or
                [StringComparer]::OrdinalIgnoreCase.Equals($item.id,$Plan.GroupId)) { $scopePresent++ }
            if ($item.Contains('tags') -and $null -ne $item.tags) {
                if ($item.tags -isnot [Collections.IDictionary]) { throw 'VALIDATION.SERVICE_RESPONSE_INVALID' }
                # Azure tag names ignore case; correlation values retain case.
                $correlationNames = @($item.tags.Keys | Where-Object {
                    [StringComparer]::OrdinalIgnoreCase.Equals([string]$_,'RoundCorrelation')
                })
                if ($correlationNames.Count -gt 1) { throw 'VALIDATION.SERVICE_RESPONSE_INVALID' }
                if ($correlationNames.Count -eq 1) {
                    $correlationValue = $item.tags[$correlationNames[0]]
                    if ($correlationValue -isnot [string]) { throw 'VALIDATION.SERVICE_RESPONSE_INVALID' }
                    if ([StringComparer]::Ordinal.Equals($correlationValue,$Plan.RoundCorrelation)) { $tagPresent++ }
                }
            }
        }
        $peers = Get-AzureValidationArmCollection -Channel $Plan.Channel -Name $Plan.HostPeeringCollectionRouteName
        foreach ($peer in $peers.Items) {
            if (-not $peer.id.StartsWith(($Plan.HostVnetId+'/virtualNetworkPeerings/'),[StringComparison]::OrdinalIgnoreCase) -or
                $peer.properties -isnot [Collections.IDictionary] -or
                $peer.properties.remoteVirtualNetwork -isnot [Collections.IDictionary] -or
                $peer.properties.remoteVirtualNetwork.id -isnot [string] -or
                $peer.properties.remoteVirtualNetwork.id -cnotmatch '\A/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()-]+/providers/Microsoft.Network/virtualNetworks/[A-Za-z0-9_.()-]+\z') {
                throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
            }
            if ([StringComparer]::OrdinalIgnoreCase.Equals($peer.properties.remoteVirtualNetwork.id,$Plan.RoundVnetId)) { $peeringPresent++ }
        }
        $null = Assert-AzureArmChannelActive -Channel $Plan.Channel
        $complete = $true
        if ($targetPresent -eq 0 -and $scopePresent -eq 0 -and $tagPresent -eq 0 -and $peeringPresent -eq 0) {
            $state = 'RemoteAbsenceProven'
            $reason = 'VALIDATION.REMOTE_ABSENCE_PROVEN'
        }
        else {
            $state = 'RemoteResiduePresent'
            $reason = 'VALIDATION.REMOTE_RESIDUE_PRESENT'
        }
    }
    catch {
        # Every error or incomplete service interpretation fails the proof;
        # never project raw private IDs, response bodies or exception text.
        if ($_.Exception.Message -ceq 'VALIDATION.ROUND_INTERRUPTED') {
            $reason = 'VALIDATION.ROUND_INTERRUPTED'
        }
    }
    [pscustomobject][ordered]@{
        State=$state;ReasonCode=$reason;Complete=$complete
        ExactTargetsAbsent=($complete -and $targetPresent -eq 0)
        BothPeeringsAbsent=($complete -and $peeringPresent -eq 0)
        TransientScopeEmpty=($complete -and $scopePresent -eq 0)
        TagSweepEmpty=($complete -and $tagPresent -eq 0)
        CompletedExactTargetQueries=$queries
        NonQualifying=($Plan.Channel.Kind -ceq 'InjectedNonQualifying')
        QualifyingEvidence=$false
    }
}
