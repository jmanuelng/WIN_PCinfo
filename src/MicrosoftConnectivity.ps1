$script:MicrosoftConnectivityPolicyBase64 = '__MICROSOFT_CONNECTIVITY_POLICY_BASE64__'
$script:MicrosoftConnectivityPolicyDigest = '__MICROSOFT_CONNECTIVITY_POLICY_SHA256__'

function Get-MicrosoftConnectivitySha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-MicrosoftConnectivityPolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    if ($script:MicrosoftConnectivityPolicyBase64 -eq
        ('__MICROSOFT_CONNECTIVITY_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-microsoft-connectivity.json'
        $text = [IO.File]::ReadAllText(
            $path, [Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
        $expected = Get-MicrosoftConnectivitySha256 -Bytes $bytes
    }
    else {
        $bytes = [Convert]::FromBase64String($script:MicrosoftConnectivityPolicyBase64)
        $expected = $script:MicrosoftConnectivityPolicyDigest
    }
    if ((Get-MicrosoftConnectivitySha256 -Bytes $bytes) -ne $expected) {
        throw 'The embedded Microsoft Connectivity policy failed integrity validation.'
    }
    $policy = & $ConvertFromJsonCommand -InputObject (
        [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 30 -ErrorAction Stop
    if ($policy.kind -ne 'win-pcinfo.microsoft-connectivity-policy' -or
        $policy.contractVersion -ne '1.0.0' -or
        @($policy.endpoints).Count -ne 3 -or @($policy.scopes).Count -ne 8 -or
        @($policy.operations).Count -ne 8 -or @($policy.rules).Count -ne 2 -or
        @($policy.validationScenarios).Count -ne 14) {
        throw 'The Microsoft Connectivity policy is not semantically closed.'
    }
    $policy
}

function New-MicrosoftConnectivityScopeState {
    param([string] $ScopeId, [string] $State, [string] $ReasonCode = '')
    [pscustomobject][ordered]@{
        scopeId = $ScopeId
        state = $State
        reasonCode = $ReasonCode
    }
}

function New-MicrosoftConnectivityEndpointResult {
    param(
        [Parameter(Mandatory)] $Endpoint,
        [Parameter(Mandatory)] [string] $TransportMode
    )
    [pscustomobject][ordered]@{
        endpointId = [string] $Endpoint.endpointId
        service = [string] $Endpoint.service
        catalogState = 'Active'
        transportMode = $TransportMode
        dnsState = 'NotAttempted'
        addressCount = 0
        tcpState = 'NotAttempted'
        port = [int] $Endpoint.port
        tlsState = 'NotAttempted'
        certificateChainState = 'NotAttempted'
        chainElementCount = 0
        directLeafSha256 = $null
        httpLeafSha256 = $null
        chainStatusCodes = $null
        negotiatedProtocol = $null
        negotiatedCipher = $null
        proxyState = 'NotAttempted'
        httpState = 'NotAttempted'
        httpStatusCode = $null
        redirectState = 'NotObserved'
        httpHeaderCount = 0
        enrollmentDnsState = if ([string] $Endpoint.service -in @(
            'MicrosoftIntuneEnrollment', 'MicrosoftEntraDeviceRegistration'
        )) { 'NotAttempted' } else { 'NotApplicable' }
        tlsInspectionOutcome = 'Indeterminate'
        tlsInspectionCorroboration = 'InsufficientCompletedTests'
    }
}

function New-MicrosoftConnectivitySyntheticPayload {
    param(
        [Parameter(Mandatory)] [string] $Scenario,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)]
        [ValidateSet('LocalOnly', 'MicrosoftConnectivityEnabled')]
        [string] $NetworkBehavior
    )

    if ($Scenario -notin @($Policy.validationScenarios)) {
        throw 'The Microsoft Connectivity scenario is not release-owned.'
    }
    # A fixture is deliberately unable to widen a Local Only preparation
    # decision. Even a caller-selected enabled scenario collapses to the one
    # zero-outbound shape before any endpoint object can be materialized.
    if ($NetworkBehavior -eq 'LocalOnly') { $Scenario = 'LocalOnly' }
    $locale = if ($Scenario -eq 'Unicode') { 'ar-SA' } else { 'und' }
    $results = [Collections.Generic.List[object]]::new()
    $requests = 0
    $scopeState = 'Complete'
    $scopeReason = ''

    if ($Scenario -eq 'LocalOnly') {
        $scopeState = 'NotAttempted'
        $scopeReason = 'CONNECTIVITY.LOCAL_ONLY_NOT_ATTEMPTED'
    }
    else {
        foreach ($endpoint in @($Policy.endpoints)) {
            $mode = if ($Scenario -eq 'WindowsProxy') { 'WindowsProxy' } else { 'Direct' }
            $item = New-MicrosoftConnectivityEndpointResult -Endpoint $endpoint -TransportMode $mode
            $item.dnsState = 'Succeeded'; $item.addressCount = 2
            $item.tcpState = 'Succeeded'; $item.tlsState = 'Succeeded'
            $item.certificateChainState = 'Trusted'; $item.chainElementCount = 3
            $item.directLeafSha256 = ('a' * 64); $item.httpLeafSha256 = ('a' * 64)
            $item.chainStatusCodes = 'NoError'
            $item.negotiatedProtocol = 'Tls13'; $item.negotiatedCipher = 'TLS_AES_256_GCM_SHA384'
            $item.proxyState = if ($mode -eq 'WindowsProxy') { 'Used' } else { 'Bypassed' }
            $item.httpState = 'Succeeded'; $item.httpStatusCode = 200; $item.httpHeaderCount = 8
            if ($item.enrollmentDnsState -ne 'NotApplicable') { $item.enrollmentDnsState = 'Succeeded' }
            $item.tlsInspectionOutcome = 'NotObservedWithinCompletedTests'
            $item.tlsInspectionCorroboration = 'MatchingCompletedPaths'
            $requests += 4
            $results.Add($item)
        }
        switch ($Scenario) {
            'Blocked' {
                $scopeState = 'Partial'; $scopeReason = 'CONNECTIVITY.TRANSPORT_BLOCKED'
                $requests = 6
                foreach ($item in $results) {
                    $item.tcpState = 'Blocked'; $item.tlsState = 'NotAttempted'
                    $item.certificateChainState = 'NotAttempted'; $item.chainElementCount = 0
                    $item.directLeafSha256 = $null; $item.httpLeafSha256 = $null
                    $item.chainStatusCodes = $null; $item.negotiatedProtocol = $null
                    $item.negotiatedCipher = $null; $item.proxyState = 'Unavailable'
                    $item.httpState = 'NotAttempted'; $item.httpStatusCode = $null
                    $item.httpHeaderCount = 0; $item.tlsInspectionOutcome = 'Indeterminate'
                    $item.tlsInspectionCorroboration = 'InsufficientCompletedTests'
                }
            }
            'PartiallyReachable' {
                $scopeState = 'Partial'; $scopeReason = 'CONNECTIVITY.PARTIAL_REACHABILITY'
                $requests = 10
                $results[1].tcpState = 'Blocked'; $results[1].tlsState = 'NotAttempted'
                $results[1].certificateChainState = 'NotAttempted'; $results[1].chainElementCount = 0
                $results[1].directLeafSha256 = $null; $results[1].httpLeafSha256 = $null
                $results[1].chainStatusCodes = $null; $results[1].negotiatedProtocol = $null
                $results[1].negotiatedCipher = $null; $results[1].proxyState = 'Unavailable'
                $results[1].httpState = 'NotAttempted'; $results[1].httpStatusCode = $null
                $results[1].httpHeaderCount = 0; $results[1].tlsInspectionOutcome = 'Indeterminate'
                $results[1].tlsInspectionCorroboration = 'InsufficientCompletedTests'
                $results[2].httpState = 'Failed'; $results[2].httpStatusCode = $null
                $results[2].httpHeaderCount = 0; $results[2].tlsInspectionOutcome = 'Indeterminate'
                $results[2].tlsInspectionCorroboration = 'InsufficientCompletedTests'
            }
            'DnsFailure' {
                $scopeState = 'Partial'; $scopeReason = 'CONNECTIVITY.DNS_FAILED'
                $requests = 3
                foreach ($item in $results) {
                    $item.dnsState = 'Failed'; $item.addressCount = 0
                    $item.tcpState = 'NotAttempted'; $item.tlsState = 'NotAttempted'
                    $item.certificateChainState = 'NotAttempted'; $item.chainElementCount = 0
                    $item.directLeafSha256 = $null; $item.httpLeafSha256 = $null
                    $item.chainStatusCodes = $null; $item.negotiatedProtocol = $null
                    $item.negotiatedCipher = $null; $item.proxyState = 'NotAttempted'
                    $item.httpState = 'NotAttempted'; $item.httpStatusCode = $null
                    $item.httpHeaderCount = 0; $item.enrollmentDnsState = if (
                        $item.enrollmentDnsState -eq 'NotApplicable'
                    ) { 'NotApplicable' } else { 'Failed' }
                    $item.tlsInspectionOutcome = 'Indeterminate'
                    $item.tlsInspectionCorroboration = 'InsufficientCompletedTests'
                }
            }
            'Redirect' {
                $scopeState = 'Partial'; $scopeReason = 'CONNECTIVITY.REDIRECT_REJECTED'
                foreach ($item in $results) {
                    $item.httpState = 'RedirectRejected'; $item.httpStatusCode = 302
                    $item.redirectState = 'Rejected'; $item.httpHeaderCount = 4
                }
            }
            'Timeout' {
                $scopeState = 'Partial'; $scopeReason = 'CONNECTIVITY.DEADLINE_EXCEEDED'
                $requests = 3
                foreach ($item in $results) {
                    $item.dnsState = 'TimedOut'; $item.addressCount = 0
                    $item.tcpState = 'NotAttempted'; $item.tlsState = 'NotAttempted'
                    $item.certificateChainState = 'NotAttempted'; $item.chainElementCount = 0
                    $item.directLeafSha256 = $null; $item.httpLeafSha256 = $null
                    $item.chainStatusCodes = $null; $item.negotiatedProtocol = $null
                    $item.negotiatedCipher = $null; $item.proxyState = 'NotAttempted'
                    $item.httpState = 'NotAttempted'; $item.httpStatusCode = $null
                    $item.httpHeaderCount = 0; $item.enrollmentDnsState = if (
                        $item.enrollmentDnsState -eq 'NotApplicable'
                    ) { 'NotApplicable' } else { 'TimedOut' }
                    $item.tlsInspectionOutcome = 'Indeterminate'
                    $item.tlsInspectionCorroboration = 'InsufficientCompletedTests'
                }
            }
            'TlsInspectionConfirmed' {
                foreach ($item in $results) {
                    $item.httpLeafSha256 = ('b' * 64)
                    $item.tlsInspectionOutcome = 'Confirmed'
                    $item.tlsInspectionCorroboration = 'IndependentProxyPolicyAndCertificatePath'
                }
            }
            'TlsInspectionSuspected' {
                foreach ($item in $results) {
                    $item.httpLeafSha256 = ('b' * 64)
                    $item.tlsInspectionOutcome = 'Suspected'
                    $item.tlsInspectionCorroboration = 'DirectAndProxyCertificateDifference'
                }
            }
            'InvalidChain' {
                $scopeState = 'Partial'; $scopeReason = 'CONNECTIVITY.CERTIFICATE_CHAIN_INVALID'
                foreach ($item in $results) {
                    $item.tlsState = 'Failed'; $item.certificateChainState = 'Invalid'
                    $item.chainStatusCodes = 'UntrustedRoot'; $item.httpLeafSha256 = $null
                    $item.proxyState = 'Unavailable'; $item.httpState = 'NotAttempted'
                    $item.httpStatusCode = $null; $item.httpHeaderCount = 0
                    $item.tlsInspectionOutcome = 'Indeterminate'
                    $item.tlsInspectionCorroboration = 'InsufficientCompletedTests'
                }
            }
            'HttpMetadata' {
                foreach ($item in $results) {
                    $item.httpStatusCode = 204
                    $item.httpHeaderCount = [int] $Policy.collector.maximumHeaderEntries
                }
            }
            'EndpointRetired' {
                $scopeState = 'Partial'; $scopeReason = 'CONNECTIVITY.ENDPOINT_RETIRED'
                $requests = 8
                $item = $results[2]; $item.catalogState = 'Retired'
                $item.dnsState = 'NotAttempted'; $item.addressCount = 0
                $item.tcpState = 'NotAttempted'; $item.tlsState = 'NotAttempted'
                $item.certificateChainState = 'NotAttempted'; $item.chainElementCount = 0
                $item.directLeafSha256 = $null; $item.httpLeafSha256 = $null
                $item.chainStatusCodes = $null; $item.negotiatedProtocol = $null
                $item.negotiatedCipher = $null; $item.proxyState = 'NotAttempted'
                $item.httpState = 'NotAttempted'; $item.httpStatusCode = $null
                $item.httpHeaderCount = 0; $item.tlsInspectionOutcome = 'Indeterminate'
                $item.tlsInspectionCorroboration = 'InsufficientCompletedTests'
            }
        }
    }
    $scopeStates = @($Policy.scopes | ForEach-Object {
        New-MicrosoftConnectivityScopeState -ScopeId ([string] $_.scopeId) `
            -State $scopeState -ReasonCode $scopeReason
    })
    [pscustomobject][ordered]@{
        sourceLocale = $locale
        networkBehavior = $NetworkBehavior
        catalogVersion = [string] $Policy.catalogVersion
        endpointResults = @($results)
        scopeStates = $scopeStates
        outboundRequestCount = $requests
        credentialMaterialTransmitted = $false
        tenantIdentifierTransmitted = $false
        evidencePayloadTransmitted = $false
        transmittedBodyBytes = 0
        arbitraryPayloadTransmitted = $false
        packetCapturePerformed = $false
        networkConfigurationChanged = $false
        executionContext = 'Synthetic'
    }
}

function Test-MicrosoftConnectivityText {
    param($Value, [int] $MaximumBytes, [switch] $AllowNull)
    if ($null -eq $Value) { return [bool] $AllowNull }
    $Value -is [string] -and -not [string]::IsNullOrWhiteSpace([string] $Value) -and
        [Text.Encoding]::UTF8.GetByteCount([string] $Value) -le $MaximumBytes
}

function Test-MicrosoftConnectivityPayload {
    param([Parameter(Mandatory)] $Payload, [Parameter(Mandatory)] $Policy)
    try {
        $expectedPayloadNames = @(
            'sourceLocale', 'networkBehavior', 'catalogVersion', 'endpointResults',
            'scopeStates', 'outboundRequestCount', 'credentialMaterialTransmitted',
            'tenantIdentifierTransmitted', 'evidencePayloadTransmitted',
            'transmittedBodyBytes', 'arbitraryPayloadTransmitted',
            'packetCapturePerformed', 'networkConfigurationChanged', 'executionContext'
        )
        if ((@($Payload.PSObject.Properties.Name | Sort-Object) -join '|') -ne
            (@($expectedPayloadNames | Sort-Object) -join '|')) { return $false }
        if ([string] $Payload.networkBehavior -notin @('LocalOnly', 'MicrosoftConnectivityEnabled') -or
            [string] $Payload.catalogVersion -cne [string] $Policy.catalogVersion -or
            -not (Test-MicrosoftConnectivityText $Payload.sourceLocale 35) -or
            [string] $Payload.executionContext -notin @('Synthetic', 'StandardUser') -or
            $Payload.outboundRequestCount -isnot [int] -or
            [int] $Payload.outboundRequestCount -lt 0 -or [int] $Payload.outboundRequestCount -gt 12) {
            return $false
        }
        foreach ($flag in @(
            'credentialMaterialTransmitted', 'tenantIdentifierTransmitted',
            'evidencePayloadTransmitted', 'arbitraryPayloadTransmitted',
            'packetCapturePerformed', 'networkConfigurationChanged'
        )) { if ($Payload.$flag -isnot [bool] -or [bool] $Payload.$flag) { return $false } }
        if ($Payload.transmittedBodyBytes -isnot [int] -or [int] $Payload.transmittedBodyBytes -ne 0) {
            return $false
        }
        $expectedEndpointIds = @($Policy.endpoints.endpointId | Sort-Object)
        if (@($Payload.endpointResults).Count -gt [int] $Policy.collector.maximumEndpoints -or
            ($Payload.networkBehavior -eq 'LocalOnly' -and
                (@($Payload.endpointResults).Count -ne 0 -or $Payload.outboundRequestCount -ne 0)) -or
            ($Payload.networkBehavior -eq 'MicrosoftConnectivityEnabled' -and
                (@($Payload.endpointResults.endpointId | Sort-Object) -join '|') -ne
                ($expectedEndpointIds -join '|'))) { return $false }
        $endpointNames = @(
            'endpointId', 'service', 'catalogState', 'transportMode', 'dnsState',
            'addressCount', 'tcpState', 'port', 'tlsState', 'certificateChainState',
            'chainElementCount', 'directLeafSha256', 'httpLeafSha256', 'chainStatusCodes',
            'negotiatedProtocol', 'negotiatedCipher', 'proxyState', 'httpState',
            'httpStatusCode', 'redirectState', 'httpHeaderCount', 'enrollmentDnsState',
            'tlsInspectionOutcome', 'tlsInspectionCorroboration'
        )
        foreach ($item in @($Payload.endpointResults)) {
            if ((@($item.PSObject.Properties.Name | Sort-Object) -join '|') -ne
                (@($endpointNames | Sort-Object) -join '|')) { return $false }
            $definition = @($Policy.endpoints | Where-Object endpointId -eq $item.endpointId)
            if ($definition.Count -ne 1 -or [string] $item.service -cne [string] $definition[0].service -or
                [string] $item.catalogState -notin @('Active', 'Retired') -or
                [string] $item.transportMode -notin @('Direct', 'WindowsProxy') -or
                $item.addressCount -isnot [int] -or [int] $item.addressCount -lt 0 -or
                [int] $item.addressCount -gt [int] $Policy.collector.maximumAddressesPerEndpoint -or
                $item.port -isnot [int] -or [int] $item.port -ne 443 -or
                $item.chainElementCount -isnot [int] -or [int] $item.chainElementCount -lt 0 -or
                [int] $item.chainElementCount -gt [int] $Policy.collector.maximumCertificateChainElements -or
                $item.httpHeaderCount -isnot [int] -or [int] $item.httpHeaderCount -lt 0 -or
                [int] $item.httpHeaderCount -gt [int] $Policy.collector.maximumHeaderEntries) { return $false }
            $states = @('Succeeded', 'Failed', 'Blocked', 'TimedOut', 'Unavailable', 'NotAttempted')
            if ([string] $item.dnsState -notin $states -or [string] $item.tcpState -notin $states -or
                [string] $item.tlsState -notin $states -or
                [string] $item.proxyState -notin @($states + @('Used', 'Bypassed')) -or
                [string] $item.httpState -notin @($states + @('RedirectRejected')) -or
                [string] $item.enrollmentDnsState -notin @($states + @('NotApplicable')) -or
                [string] $item.certificateChainState -notin @(
                    'Trusted', 'Invalid', 'Failed', 'TimedOut', 'Unavailable', 'NotAttempted'
                ) -or [string] $item.redirectState -notin @('NotObserved', 'Rejected')) { return $false }
            foreach ($hashName in @('directLeafSha256', 'httpLeafSha256')) {
                $hash = $item.$hashName
                if ($null -ne $hash -and ($hash -isnot [string] -or
                    [string] $hash -cnotmatch '^[0-9a-f]{64}$')) { return $false }
            }
            foreach ($textName in @('chainStatusCodes', 'negotiatedProtocol', 'negotiatedCipher')) {
                if (-not (Test-MicrosoftConnectivityText $item.$textName 256 -AllowNull)) { return $false }
            }
            if ($null -ne $item.httpStatusCode -and
                ($item.httpStatusCode -isnot [int] -or [int] $item.httpStatusCode -lt 100 -or
                    [int] $item.httpStatusCode -gt 599)) { return $false }
            $outcome = [string] $item.tlsInspectionOutcome
            $corroboration = [string] $item.tlsInspectionCorroboration
            $expectedCorroboration = switch ($outcome) {
                'Confirmed' { 'IndependentProxyPolicyAndCertificatePath' }
                'Suspected' { 'DirectAndProxyCertificateDifference' }
                'NotObservedWithinCompletedTests' { 'MatchingCompletedPaths' }
                'Indeterminate' { 'InsufficientCompletedTests' }
                default { return $false }
            }
            if ($corroboration -cne $expectedCorroboration) { return $false }
        }
        $expectedScopes = @($Policy.scopes.scopeId | Sort-Object)
        if (@($Payload.scopeStates).Count -ne 8 -or
            (@($Payload.scopeStates.scopeId | Sort-Object) -join '|') -ne
            ($expectedScopes -join '|')) { return $false }
        foreach ($scope in @($Payload.scopeStates)) {
            if ((@($scope.PSObject.Properties.Name | Sort-Object) -join '|') -ne
                'reasonCode|scopeId|state' -or [string] $scope.state -notin @(
                    'Complete', 'Partial', 'Unavailable', 'TimedOut', 'NotAttempted'
                ) -or ($scope.state -eq 'Complete' -and $scope.reasonCode) -or
                ($scope.state -ne 'Complete' -and
                    ([string] $scope.reasonCode -cnotmatch '^[A-Z][A-Z0-9_.]+$' -or
                        [Text.Encoding]::UTF8.GetByteCount([string] $scope.reasonCode) -gt 96))) {
                return $false
            }
        }
        $true
    }
    catch { $false }
}

function Invoke-MicrosoftConnectivityCollection {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter()] [string] $ValidationScenario,
        [Parameter(Mandatory)]
        [ValidateSet('LocalOnly', 'MicrosoftConnectivityEnabled')]
        [string] $NetworkBehavior,
        [Parameter()] [switch] $Live
    )
    $started = [DateTimeOffset]::UtcNow
    if ($Live) {
        $payload = if ($NetworkBehavior -eq 'LocalOnly') {
            $value = New-MicrosoftConnectivitySyntheticPayload -Scenario LocalOnly `
                -Policy $Policy -NetworkBehavior LocalOnly
            $value.executionContext = 'StandardUser'
            $value
        }
        else {
            Invoke-MicrosoftConnectivityLiveProbe -Policy $Policy
        }
    }
    else {
        $payload = New-MicrosoftConnectivitySyntheticPayload -Scenario $ValidationScenario `
            -Policy $Policy -NetworkBehavior $NetworkBehavior
    }
    if (-not (Test-MicrosoftConnectivityPayload -Payload $payload -Policy $Policy)) {
        throw 'The Microsoft Connectivity payload is outside the frozen contract.'
    }
    # The collector is in-process, so there is no pipe limit to enforce this
    # on its behalf. Measure the same compact UTF-8 representation admitted to
    # the record and fail closed before unbounded evidence can cross the seam.
    $payloadJson = Microsoft.PowerShell.Utility\ConvertTo-Json `
        -InputObject $payload -Compress -Depth 10
    if ([Text.Encoding]::UTF8.GetByteCount($payloadJson) -gt
        [int] $Policy.collector.maximumResultUtf8Bytes) {
        throw 'The Microsoft Connectivity payload exceeds its release-owned byte bound.'
    }
    [pscustomobject][ordered]@{
        state = 'Completed'
        reasonCode = if ($NetworkBehavior -eq 'LocalOnly') {
            'CONNECTIVITY.LOCAL_ONLY_NOT_ATTEMPTED'
        } else { 'CONNECTIVITY.COLLECTION_COMPLETED' }
        payload = $payload
        envelope = [pscustomobject][ordered]@{
            startedAt = $started.ToString('o')
            completedAt = ([DateTimeOffset]::UtcNow).ToString('o')
            executionContext = [string] $payload.executionContext
            attempts = 1
        }
        cleanupVerified = $true
    }
}

function Get-MicrosoftConnectivityAggregateInspectionOutcome {
    param([object[]] $EndpointResults)
    $outcomes = @($EndpointResults | Where-Object catalogState -eq 'Active' | ForEach-Object {
        [string] $_.tlsInspectionOutcome
    })
    if ('Confirmed' -in $outcomes) { return 'Confirmed' }
    if ('Suspected' -in $outcomes) { return 'Suspected' }
    if ($outcomes.Count -gt 0 -and
        @($outcomes | Where-Object { $_ -ne 'NotObservedWithinCompletedTests' }).Count -eq 0) {
        return 'NotObservedWithinCompletedTests'
    }
    'Indeterminate'
}

function New-MicrosoftConnectivityPublicProjection {
    param([Parameter(Mandatory)] $CollectorResult, [Parameter(Mandatory)] $Policy)
    $payload = $CollectorResult.payload
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.microsoft-connectivity-validation'
        contractVersion = '1.0.0'
        networkBehavior = [string] $payload.networkBehavior
        catalogVersion = [string] $payload.catalogVersion
        endpointDefinitionCount = @($Policy.endpoints).Count
        reachableEndpointCount = @($payload.endpointResults | Where-Object httpState -eq 'Succeeded').Count
        outboundRequestCount = [int] $payload.outboundRequestCount
        tlsInspectionOutcome = Get-MicrosoftConnectivityAggregateInspectionOutcome `
            -EndpointResults @($payload.endpointResults)
        restrictedEvidencePublished = $false
        credentialsTransmitted = [bool] $payload.credentialMaterialTransmitted
        tenantIdentifierTransmitted = [bool] $payload.tenantIdentifierTransmitted
        evidencePayloadTransmitted = [bool] $payload.evidencePayloadTransmitted
        transmittedBodyBytes = [int] $payload.transmittedBodyBytes
        arbitraryPayloadTransmitted = [bool] $payload.arbitraryPayloadTransmitted
        packetCapturePerformed = [bool] $payload.packetCapturePerformed
        networkConfigurationChanged = [bool] $payload.networkConfigurationChanged
    }
}

function Read-MicrosoftConnectivityFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $Policy
    )
    try {
        $bytes = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($LiteralPath))
        if ($bytes.Length -lt 1 -or $bytes.Length -gt 512) {
            throw 'Fixture size is invalid.'
        }
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $document = [Text.Json.JsonDocument]::Parse($json)
        try {
            $names = @($document.RootElement.EnumerateObject() | ForEach-Object Name)
            if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
                (@($names | Sort-Object) -join '|') -ne 'contractVersion|scenario') {
                throw 'Fixture shape is invalid.'
            }
        }
        finally { $document.Dispose() }
        $fixture = & $ConvertFromJsonCommand -InputObject $json -Depth 5 -ErrorAction Stop
        if ($fixture.contractVersion -ne '1.0.0' -or
            $fixture.scenario -notin @($Policy.validationScenarios)) {
            throw 'Fixture scenario is not release-owned.'
        }
        [string] $fixture.scenario
    }
    catch {
        throw [InvalidOperationException]::new(
            'The synthetic Microsoft Connectivity fixture is invalid.', $_.Exception
        )
    }
}

function Get-MicrosoftConnectivityFailureState {
    param([Parameter(Mandatory)] [Exception] $Exception)
    if ($Exception -is [OperationCanceledException] -or
        $Exception -is [TimeoutException]) { return 'TimedOut' }
    if ($Exception -is [Net.Sockets.SocketException] -and
        $Exception.SocketErrorCode -in @(
            [Net.Sockets.SocketError]::AccessDenied,
            [Net.Sockets.SocketError]::ConnectionRefused,
            [Net.Sockets.SocketError]::HostUnreachable,
            [Net.Sockets.SocketError]::NetworkUnreachable
        )) { return 'Blocked' }
    'Failed'
}

function Get-MicrosoftConnectivityCertificateSha256 {
    param([Parameter(Mandatory)] [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Certificate.RawData)
    ).ToLowerInvariant()
}

function Get-MicrosoftConnectivityChainResult {
    param(
        [Parameter(Mandatory)] [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory)] $Policy
    )
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        # Chain building is deliberately offline. Windows can otherwise fetch
        # intermediate certificates or revocation data, which would create an
        # undeclared network path unrelated to the approved endpoint probes.
        # Disabling downloads and using NoCheck keeps the observation bounded:
        # it says what this device can build from material already available,
        # never that revocation or the remote service is universally healthy.
        $chain.ChainPolicy.DisableCertificateDownloads = $true
        $chain.ChainPolicy.RevocationMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $built = $chain.Build($Certificate)
        $count = [Math]::Min(
            $chain.ChainElements.Count,
            [int] $Policy.collector.maximumCertificateChainElements
        )
        $codes = @($chain.ChainStatus | ForEach-Object {
            [string] $_.Status
        } | Sort-Object -Unique)
        [pscustomobject][ordered]@{
            state = if ($built) { 'Trusted' } else { 'Invalid' }
            elementCount = $count
            statusCodes = if ($codes.Count -eq 0) { 'NoError' } else { $codes -join ',' }
        }
    }
    finally { $chain.Dispose() }
}

function Invoke-MicrosoftConnectivityDnsPhase {
    param([string] $DnsName, [int] $DeadlineMilliseconds, [int] $MaximumAddresses)
    $cts = [Threading.CancellationTokenSource]::new($DeadlineMilliseconds)
    try {
        # The cancellation-token overload prevents a timed-out resolver task
        # from becoming invisible background work after the assessment moves on.
        $addresses = [Net.Dns]::GetHostAddressesAsync($DnsName, $cts.Token).
            GetAwaiter().GetResult()
        [pscustomobject]@{
            state = 'Succeeded'
            count = [Math]::Min(@($addresses).Count, $MaximumAddresses)
        }
    }
    catch { [pscustomobject]@{ state = Get-MicrosoftConnectivityFailureState $_.Exception; count = 0 } }
    finally { $cts.Dispose() }
}

function Invoke-MicrosoftConnectivityTcpPhase {
    param([string] $DnsName, [int] $Port, [int] $DeadlineMilliseconds)
    $client = [Net.Sockets.TcpClient]::new()
    $cts = [Threading.CancellationTokenSource]::new($DeadlineMilliseconds)
    try {
        $client.ConnectAsync($DnsName, $Port, $cts.Token).GetAwaiter().GetResult()
        [pscustomobject]@{ state = 'Succeeded' }
    }
    catch { [pscustomobject]@{ state = Get-MicrosoftConnectivityFailureState $_.Exception } }
    finally { $cts.Dispose(); $client.Dispose() }
}

function Invoke-MicrosoftConnectivityTlsPhase {
    param([Parameter(Mandatory)] $Endpoint, [int] $DeadlineMilliseconds, [Parameter(Mandatory)] $Policy)
    $client = [Net.Sockets.TcpClient]::new()
    $stream = $null; $certificate = $null
    $cts = [Threading.CancellationTokenSource]::new($DeadlineMilliseconds)
    $capture = [pscustomobject]@{ RawData = $null }
    try {
        $client.ConnectAsync(
            [string] $Endpoint.dnsName, [int] $Endpoint.port, $cts.Token
        ).GetAwaiter().GetResult()
        $callback = [Net.Security.RemoteCertificateValidationCallback] {
            param($Sender, $RemoteCertificate, $Chain, $PolicyErrors)
            if ($null -ne $RemoteCertificate) {
                $capture.RawData = [byte[]] $RemoteCertificate.GetRawCertData()
            }
            # Trust errors are observed, never bypassed. Returning false lets
            # SslStream enforce the Windows trust decision and prevents this
            # assessment from turning an invalid chain into usable transport.
            $PolicyErrors -eq [Net.Security.SslPolicyErrors]::None
        }
        $stream = [Net.Security.SslStream]::new(
            $client.GetStream(), $false, $callback
        )
        $options = [Net.Security.SslClientAuthenticationOptions]::new()
        $options.TargetHost = [string] $Endpoint.dnsName
        $options.CertificateRevocationCheckMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $stream.AuthenticateAsClientAsync($options, $cts.Token).GetAwaiter().GetResult()
        if ($null -eq $capture.RawData) { throw 'TLS completed without a remote certificate.' }
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [byte[]] $capture.RawData
        )
        $chain = Get-MicrosoftConnectivityChainResult -Certificate $certificate -Policy $Policy
        [pscustomobject][ordered]@{
            state = 'Succeeded'
            chainState = [string] $chain.state
            chainElementCount = [int] $chain.elementCount
            chainStatusCodes = [string] $chain.statusCodes
            leafSha256 = Get-MicrosoftConnectivityCertificateSha256 -Certificate $certificate
            protocol = [string] $stream.SslProtocol
            cipher = [string] $stream.NegotiatedCipherSuite
        }
    }
    catch {
        $chainState = 'NotAttempted'; $chainCount = 0; $chainCodes = $null; $leaf = $null
        if ($null -ne $capture.RawData) {
            try {
                $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    [byte[]] $capture.RawData
                )
                $chain = Get-MicrosoftConnectivityChainResult -Certificate $certificate -Policy $Policy
                $chainState = [string] $chain.state; $chainCount = [int] $chain.elementCount
                $chainCodes = [string] $chain.statusCodes
                $leaf = Get-MicrosoftConnectivityCertificateSha256 -Certificate $certificate
            }
            catch { $chainState = 'Failed' }
        }
        [pscustomobject][ordered]@{
            state = Get-MicrosoftConnectivityFailureState $_.Exception
            chainState = $chainState; chainElementCount = $chainCount
            chainStatusCodes = $chainCodes; leafSha256 = $leaf
            protocol = $null; cipher = $null
        }
    }
    finally {
        if ($null -ne $certificate) { $certificate.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
        $cts.Dispose(); $client.Dispose()
    }
}

function Invoke-MicrosoftConnectivityHttpPhase {
    param([Parameter(Mandatory)] $Endpoint, [int] $DeadlineMilliseconds, [Parameter(Mandatory)] $Policy)
    $handler = [Net.Http.HttpClientHandler]::new()
    $client = $null; $request = $null; $response = $null; $certificate = $null
    $cts = [Threading.CancellationTokenSource]::new($DeadlineMilliseconds)
    $capture = [pscustomobject]@{ RawData = $null }
    try {
        # HttpClient uses the Windows system proxy but is explicitly forbidden
        # from sending user or proxy credentials, cookies, a request body, or a
        # redirected second request. A 407 is therefore useful proxy evidence,
        # not an invitation to request credentials after preparation approval.
        $handler.UseProxy = $true
        $handler.UseDefaultCredentials = $false
        $handler.Credentials = $null
        $handler.DefaultProxyCredentials = $null
        $handler.UseCookies = $false
        $handler.AllowAutoRedirect = $false
        $handler.MaxResponseHeadersLength = [Math]::Max(
            1, [int] ([int] $Endpoint.http.maximumHeaderBytes / 1024)
        )
        $handler.ServerCertificateCustomValidationCallback = {
            param($Message, $RemoteCertificate, $Chain, $PolicyErrors)
            if ($null -ne $RemoteCertificate) {
                $capture.RawData = [byte[]] $RemoteCertificate.RawData.Clone()
            }
            $PolicyErrors -eq [Net.Security.SslPolicyErrors]::None
        }
        $uri = [Uri]::new([string] $Endpoint.uri)
        $systemProxy = [Net.WebRequest]::GetSystemWebProxy()
        $proxyUri = if ($null -ne $systemProxy) { $systemProxy.GetProxy($uri) } else { $uri }
        $transportMode = if ($null -ne $proxyUri -and $proxyUri.AbsoluteUri -ne $uri.AbsoluteUri) {
            'WindowsProxy'
        } else { 'Direct' }
        $client = [Net.Http.HttpClient]::new($handler, $false)
        $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Head, $uri)
        $response = $client.SendAsync(
            $request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token
        ).GetAwaiter().GetResult()
        $status = [int] $response.StatusCode
        $redirected = $status -ge 300 -and $status -le 399
        $headerCount = @($response.Headers).Count + @($response.Content.Headers).Count
        if ($headerCount -gt [int] $Policy.collector.maximumHeaderEntries) {
            throw 'The HTTP metadata entry bound was exceeded.'
        }
        if ($null -ne $capture.RawData) {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                [byte[]] $capture.RawData
            )
        }
        [pscustomobject][ordered]@{
            state = if ($redirected) { 'RedirectRejected' } else { 'Succeeded' }
            statusCode = $status
            redirectState = if ($redirected) { 'Rejected' } else { 'NotObserved' }
            headerCount = $headerCount
            transportMode = $transportMode
            proxyState = if ($transportMode -eq 'WindowsProxy') { 'Used' } else { 'Bypassed' }
            leafSha256 = if ($null -ne $certificate) {
                Get-MicrosoftConnectivityCertificateSha256 -Certificate $certificate
            } else { $null }
        }
    }
    catch {
        [pscustomobject][ordered]@{
            state = Get-MicrosoftConnectivityFailureState $_.Exception
            statusCode = $null; redirectState = 'NotObserved'; headerCount = 0
            transportMode = 'Direct'; proxyState = 'Unavailable'; leafSha256 = $null
        }
    }
    finally {
        if ($null -ne $certificate) { $certificate.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $request) { $request.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        $handler.Dispose(); $cts.Dispose()
    }
}

function Get-MicrosoftConnectivityScopeDisposition {
    param([string[]] $States, [string[]] $CompletedStates)
    if ($States.Count -eq 0) {
        return [pscustomobject]@{ state = 'NotAttempted'; reason = 'CONNECTIVITY.NOT_ATTEMPTED' }
    }
    $complete = @($States | Where-Object { $_ -in $CompletedStates }).Count
    if ($complete -eq $States.Count) { return [pscustomobject]@{ state = 'Complete'; reason = '' } }
    # A returned, validated endpoint state is evidence even when every bounded
    # attempt failed or timed out. Partial preserves those observations;
    # Unavailable or TimedOut coverage requires zero attached observations.
    [pscustomobject]@{ state = 'Partial'; reason = 'CONNECTIVITY.PARTIAL_REACHABILITY' }
}

function Invoke-MicrosoftConnectivityLiveProbe {
    param([Parameter(Mandatory)] $Policy)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $results = [Collections.Generic.List[object]]::new()
    $requestCount = 0
    foreach ($endpoint in @($Policy.endpoints)) {
        $item = New-MicrosoftConnectivityEndpointResult -Endpoint $endpoint -TransportMode Direct
        $remaining = [int] $Policy.collector.deadlineMilliseconds - [int] $watch.ElapsedMilliseconds
        if ($remaining -le 0) { $results.Add($item); continue }
        $deadline = [Math]::Min(5000, $remaining)
        $requestCount++
        $dns = Invoke-MicrosoftConnectivityDnsPhase -DnsName ([string] $endpoint.dnsName) `
            -DeadlineMilliseconds $deadline `
            -MaximumAddresses ([int] $Policy.collector.maximumAddressesPerEndpoint
        )
        $item.dnsState = [string] $dns.state; $item.addressCount = [int] $dns.count
        if ($item.enrollmentDnsState -ne 'NotApplicable') {
            $item.enrollmentDnsState = [string] $dns.state
        }

        $remaining = [int] $Policy.collector.deadlineMilliseconds - [int] $watch.ElapsedMilliseconds
        if ($remaining -gt 0) {
            $requestCount++
            $tcp = Invoke-MicrosoftConnectivityTcpPhase -DnsName ([string] $endpoint.dnsName) `
                -Port ([int] $endpoint.port) -DeadlineMilliseconds ([Math]::Min(5000, $remaining))
            $item.tcpState = [string] $tcp.state
        }

        $remaining = [int] $Policy.collector.deadlineMilliseconds - [int] $watch.ElapsedMilliseconds
        if ($remaining -gt 0) {
            $requestCount++
            $tls = Invoke-MicrosoftConnectivityTlsPhase -Endpoint $endpoint `
                -DeadlineMilliseconds ([Math]::Min(5000, $remaining)) -Policy $Policy
            $item.tlsState = [string] $tls.state
            $item.certificateChainState = [string] $tls.chainState
            $item.chainElementCount = [int] $tls.chainElementCount
            $item.directLeafSha256 = $tls.leafSha256
            $item.chainStatusCodes = $tls.chainStatusCodes
            $item.negotiatedProtocol = $tls.protocol
            $item.negotiatedCipher = $tls.cipher
        }

        $remaining = [int] $Policy.collector.deadlineMilliseconds - [int] $watch.ElapsedMilliseconds
        if ($remaining -gt 0) {
            $requestCount++
            $http = Invoke-MicrosoftConnectivityHttpPhase -Endpoint $endpoint `
                -DeadlineMilliseconds ([Math]::Min(5000, $remaining)) -Policy $Policy
            $item.transportMode = [string] $http.transportMode
            $item.proxyState = [string] $http.proxyState
            $item.httpState = [string] $http.state
            $item.httpStatusCode = $http.statusCode
            $item.redirectState = [string] $http.redirectState
            $item.httpHeaderCount = [int] $http.headerCount
            $item.httpLeafSha256 = $http.leafSha256
        }

        # A certificate-path difference is only suspicion. Confirmation is
        # reserved for a release-owned fixture with independent proxy-policy
        # evidence; the live collector has no authority to inspect enterprise
        # configuration deeply enough to make that attribution.
        if ($null -ne $item.directLeafSha256 -and $null -ne $item.httpLeafSha256) {
            if ($item.directLeafSha256 -ceq $item.httpLeafSha256) {
                $item.tlsInspectionOutcome = 'NotObservedWithinCompletedTests'
                $item.tlsInspectionCorroboration = 'MatchingCompletedPaths'
            }
            else {
                $item.tlsInspectionOutcome = 'Suspected'
                $item.tlsInspectionCorroboration = 'DirectAndProxyCertificateDifference'
            }
        }
        $results.Add($item)
    }
    $watch.Stop()
    $scopeInputs = @{
        'scope:connectivity.dns' = @($results.dnsState), @('Succeeded')
        'scope:connectivity.tcp' = @($results.tcpState), @('Succeeded')
        'scope:connectivity.tls' = @($results.tlsState), @('Succeeded')
        'scope:connectivity.certificate-chain' = @($results.certificateChainState), @('Trusted', 'Invalid')
        'scope:connectivity.negotiation' = @($results | ForEach-Object { if ($_.negotiatedProtocol) { 'Succeeded' } else { 'Unavailable' } }), @('Succeeded')
        'scope:connectivity.proxy' = @($results.proxyState), @('Used', 'Bypassed')
        'scope:connectivity.http' = @($results.httpState), @('Succeeded', 'RedirectRejected')
        'scope:connectivity.enrollment-dns' = @($results | Where-Object enrollmentDnsState -ne 'NotApplicable' | ForEach-Object enrollmentDnsState), @('Succeeded')
    }
    $scopeStates = foreach ($scope in @($Policy.scopes)) {
        $input = $scopeInputs[[string] $scope.scopeId]
        $disposition = Get-MicrosoftConnectivityScopeDisposition `
            -States @($input[0]) -CompletedStates @($input[1])
        New-MicrosoftConnectivityScopeState -ScopeId ([string] $scope.scopeId) `
            -State ([string] $disposition.state) -ReasonCode ([string] $disposition.reason)
    }
    [pscustomobject][ordered]@{
        sourceLocale = 'und'
        networkBehavior = 'MicrosoftConnectivityEnabled'
        catalogVersion = [string] $Policy.catalogVersion
        endpointResults = @($results)
        scopeStates = @($scopeStates)
        outboundRequestCount = $requestCount
        credentialMaterialTransmitted = $false
        tenantIdentifierTransmitted = $false
        evidencePayloadTransmitted = $false
        transmittedBodyBytes = 0
        arbitraryPayloadTransmitted = $false
        packetCapturePerformed = $false
        networkConfigurationChanged = $false
        executionContext = 'StandardUser'
    }
}

function Add-MicrosoftConnectivityEvidenceRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $CollectorResult,
        [Parameter(Mandatory)] $Policy
    )
    $prerequisiteProfile =
        'profile:device-firmware-identity-administrator-policy-software-resource-network-and-certificate-trust-readiness'
    if ([string] $Record.run.evidenceProfileId -ne $prerequisiteProfile) {
        throw 'Microsoft Connectivity evidence requires the accepted certificate-ready profile.'
    }
    if (-not [bool] $CollectorResult.cleanupVerified -or
        -not (Test-MicrosoftConnectivityPayload -Payload $CollectorResult.payload -Policy $Policy)) {
        throw 'Microsoft Connectivity evidence requires a closed, cleanup-verified result.'
    }
    $runId = [string] $Record.run.runId
    $payload = $CollectorResult.payload
    $collector = $Policy.collector
    $oldScopeIds = @(
        'scope:network.microsoft-connectivity', 'scope:network.enrollment-dns',
        'scope:network.tls-trust'
    )
    $oldCoverage = @($Record.coverage | Where-Object scopeId -in $oldScopeIds)
    $oldDiagnosticIds = @($oldCoverage | ForEach-Object { @($_.diagnosticIds) })
    $Record.coverage = @($Record.coverage | Where-Object scopeId -notin $oldScopeIds)
    $Record.diagnostics = @($Record.diagnostics | Where-Object diagnosticId -notin $oldDiagnosticIds)
    $obsoleteFindingIds = @($Record.findings | Where-Object {
        $_.ruleId -eq 'rule:network.local-only-coverage/1.0.0'
    } | ForEach-Object findingId)
    $Record.findings = @($Record.findings | Where-Object findingId -notin $obsoleteFindingIds)
    $Record.recommendations = @($Record.recommendations | Where-Object {
        @($_.findingIds | Where-Object { $_ -in $obsoleteFindingIds }).Count -eq 0
    })

    $scopeById = @{}; $sourceByField = @{}
    foreach ($scope in @($Policy.scopes)) {
        $scopeById[[string] $scope.scopeId] = $scope
        foreach ($fieldId in @($scope.fieldIds)) {
            $sourceByField[[string] $fieldId] = [string] $scope.sourceId
        }
    }
    $scopeObservationIds = @{}
    foreach ($scope in @($Policy.scopes)) {
        $scopeObservationIds[[string] $scope.scopeId] = [Collections.Generic.List[string]]::new()
    }
    $subjects = [Collections.Generic.List[object]]::new()
    $observations = [Collections.Generic.List[object]]::new()
    $provenance = [Collections.Generic.List[object]]::new()
    function Add-ConnectivityObservation {
        param(
            [string] $ScopeId, [string] $Suffix, [string] $FieldId,
            [string] $SubjectId, $Value, [string] $ValueState = 'ObservedValue'
        )
        $observationId = "observation:connectivity-$Suffix`:$runId"
        $provenanceId = "provenance:connectivity-$Suffix`:$runId"
        $entry = [ordered]@{
            observationId = $observationId; fieldId = $FieldId
            subjectId = $SubjectId; provenanceId = $provenanceId
            valueState = $ValueState
        }
        if ($ValueState -eq 'ObservedValue') { $entry.value = $Value }
        $observations.Add([pscustomobject] $entry)
        $provenance.Add([pscustomobject][ordered]@{
            provenanceId = $provenanceId; fieldId = $FieldId; subjectId = $SubjectId
            sourceId = $sourceByField[$FieldId]
            collectorId = [string] $collector.collectorId
            collectorVersion = [string] $collector.collectorVersion
            executionContext = [string] $CollectorResult.envelope.executionContext
            collectedAt = [string] $CollectorResult.envelope.completedAt
            sourceLocale = [string] $payload.sourceLocale
        })
        $scopeObservationIds[$ScopeId].Add($observationId)
    }
    function Add-ConnectivityValue {
        param(
            [string] $ScopeId, [string] $Suffix, [string] $FieldId,
            [string] $SubjectId, $Value
        )
        if ($null -eq $Value) {
            Add-ConnectivityObservation $ScopeId $Suffix $FieldId $SubjectId $null `
                'SourceReportedUnknown'
        }
        else { Add-ConnectivityObservation $ScopeId $Suffix $FieldId $SubjectId $Value }
    }
    $mappings = @(
        @{ scope = 'scope:connectivity.dns'; fields = @(
            @('endpointId', 'endpoint-id'), @('service', 'service'),
            @('catalogState', 'catalog-state'), @('dnsState', 'dns.state'),
            @('addressCount', 'dns.address-count')) },
        @{ scope = 'scope:connectivity.tcp'; fields = @(
            @('tcpState', 'tcp.state'), @('port', 'tcp.port')) },
        @{ scope = 'scope:connectivity.tls'; fields = ,@('tlsState', 'tls.state') },
        @{ scope = 'scope:connectivity.certificate-chain'; fields = @(
            @('certificateChainState', 'certificate-chain.state'),
            @('chainElementCount', 'certificate-chain.element-count'),
            @('directLeafSha256', 'certificate-chain.direct-leaf-sha256'),
            @('httpLeafSha256', 'certificate-chain.http-leaf-sha256'),
            @('chainStatusCodes', 'certificate-chain.status-codes'),
            @('tlsInspectionOutcome', 'tls-inspection.outcome'),
            @('tlsInspectionCorroboration', 'tls-inspection.corroboration')) },
        @{ scope = 'scope:connectivity.negotiation'; fields = @(
            @('negotiatedProtocol', 'negotiated-protocol'),
            @('negotiatedCipher', 'negotiated-cipher')) },
        @{ scope = 'scope:connectivity.proxy'; fields = @(
            @('transportMode', 'proxy.mode'), @('proxyState', 'proxy.state')) },
        @{ scope = 'scope:connectivity.http'; fields = @(
            @('httpState', 'http.state'), @('httpStatusCode', 'http.status-code'),
            @('redirectState', 'http.redirect-state'), @('httpHeaderCount', 'http.header-count')) },
        @{ scope = 'scope:connectivity.enrollment-dns'; fields = ,@(
            'enrollmentDnsState', 'enrollment-dns.state') }
    )
    $index = 0
    foreach ($item in @($payload.endpointResults)) {
        $subjectId = "subject:connectivity-endpoint:$index"
        $subjects.Add([pscustomobject][ordered]@{ subjectId = $subjectId; kind = 'Interface' })
        foreach ($mapping in $mappings) {
            # The identity/security endpoint is not an enrollment-discovery
            # target, so NotApplicable is itself the typed observation rather
            # than an omitted field whose meaning a reader would have to guess.
            foreach ($field in $mapping.fields) {
                Add-ConnectivityValue $mapping.scope "$index-$($field[1].Replace('.', '-'))" `
                    "field:connectivity.$($field[1])" $subjectId $item.($field[0])
            }
        }
        $index++
    }
    $coverage = [Collections.Generic.List[object]]::new()
    $diagnostics = [Collections.Generic.List[object]]::new()
    foreach ($state in @($payload.scopeStates)) {
        $suffix = ([string] $state.scopeId).Substring('scope:connectivity.'.Length).
            Replace('.', '-')
        $coverageId = "coverage:connectivity-$suffix`:$runId"
        $entry = [ordered]@{
            coverageId = $coverageId; scopeId = [string] $state.scopeId
            state = [string] $state.state
            observationIds = @($scopeObservationIds[[string] $state.scopeId])
            diagnosticIds = @()
        }
        if ($state.state -ne 'Complete') {
            $diagnosticId = "diagnostic:connectivity-$suffix`:$runId"
            $entry.reasonCode = [string] $state.reasonCode
            $entry.diagnosticIds = @($diagnosticId)
            $diagnostics.Add([pscustomobject][ordered]@{
                diagnosticId = $diagnosticId; scopeId = [string] $state.scopeId
                phase = 'Collection'; reasonCode = [string] $state.reasonCode
                operatorMessageId = if ($state.state -eq 'NotAttempted') {
                    'connectivity.local-only.not-attempted'
                } else { 'connectivity.collection.incomplete' }
            })
        }
        $coverage.Add([pscustomobject] $entry)
    }
    $Record.subjects = @($Record.subjects) + @($subjects)
    $Record.observations = @($Record.observations) + @($observations)
    $Record.provenance = @($Record.provenance) + @($provenance)
    $Record.coverage = @($Record.coverage) + @($coverage)
    $Record.diagnostics = @($Record.diagnostics) + @($diagnostics)
    $attemptedCoverage = @($coverage | Where-Object state -ne 'NotAttempted')
    if ($attemptedCoverage.Count -gt 0) {
        $attemptedDiagnosticIds = @($attemptedCoverage | ForEach-Object { @($_.diagnosticIds) })
        $Record.collectorResults = @($Record.collectorResults) + [pscustomobject][ordered]@{
            envelopeId = "envelope:microsoft-connectivity:$runId"
            collectorId = [string] $collector.collectorId
            collectorVersion = [string] $collector.collectorVersion
            operationId = [string] $collector.operationId
            intendedScopeIds = @($attemptedCoverage | ForEach-Object scopeId)
            subjectIds = @('subject:device:primary') + @($subjects | ForEach-Object subjectId)
            startedAt = [string] $CollectorResult.envelope.startedAt
            completedAt = [string] $CollectorResult.envelope.completedAt
            executionContext = [string] $CollectorResult.envelope.executionContext
            attempts = 1
            observationIds = @($observations | ForEach-Object observationId)
            coverageIds = @($attemptedCoverage | ForEach-Object coverageId)
            diagnosticIds = $attemptedDiagnosticIds
        }
    }
    $Record.run.evidenceProfileId = [string] $Policy.evidenceProfileId
    $Record.run.outcome = 'CompletedWithGaps'
    $Record
}

function Invoke-MicrosoftConnectivityRule {
    param($Rule, [int] $InputCount, [scriptblock] $Evaluation)
    $watch = [Diagnostics.Stopwatch]::StartNew(); $result = @(& $Evaluation); $watch.Stop()
    if ($InputCount -gt [int] $Rule.maximumInputObservations -or
        $watch.ElapsedMilliseconds -gt [int] $Rule.deadlineMilliseconds -or
        $result.Count -ne 1 -or $result[0].outcome -notin @(
            'ExpectedCondition', 'NeedsAttention', 'Informational', 'Indeterminate'
        )) { throw "The release-owned $($Rule.operationId) rule violated its finite contract." }
    $result[0]
}

function Complete-ValidatedMicrosoftConnectivityAssessmentRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $ContractValidation
    )
    if (-not ([bool] $ContractValidation.accepted) -or
        ([string] $ContractValidation.reasonCode) -ne 'CONTRACT.ACCEPTED' -or
        ([string] $Record.run.evidenceProfileId) -ne ([string] $Policy.evidenceProfileId)) {
        throw 'Microsoft Connectivity rules require an accepted source-only record.'
    }
    $rules = @{}; foreach ($rule in @($Policy.rules)) { $rules[[string] $rule.findingKind] = $rule }
    $all = @($Record.observations | Where-Object fieldId -like 'field:connectivity.*')
    $http = @($all | Where-Object fieldId -eq 'field:connectivity.http.state')
    $httpValues = @($http | Where-Object valueState -eq ObservedValue | ForEach-Object value)
    $reachabilityResult = Invoke-MicrosoftConnectivityRule `
        -Rule $rules['microsoft-service-connectivity'] -InputCount $http.Count -Evaluation {
        if ($httpValues.Count -eq 0) {
            [pscustomobject]@{ outcome = 'Indeterminate'; reasonCode = 'FINDING.CONNECTIVITY_NOT_ATTEMPTED' }
        }
        elseif (@($httpValues | Where-Object { $_ -ne 'Succeeded' }).Count -eq 0) {
            [pscustomobject]@{ outcome = 'ExpectedCondition' }
        }
        elseif (@($httpValues | Where-Object { $_ -eq 'Succeeded' }).Count -gt 0) {
            [pscustomobject]@{ outcome = 'NeedsAttention' }
        }
        else { [pscustomobject]@{ outcome = 'Indeterminate'; reasonCode = 'FINDING.CONNECTIVITY_INCOMPLETE' } }
    }
    $inspection = @($all | Where-Object fieldId -eq 'field:connectivity.tls-inspection.outcome')
    $inspectionValues = @($inspection | Where-Object valueState -eq ObservedValue | ForEach-Object value)
    $inspectionResult = Invoke-MicrosoftConnectivityRule -Rule $rules['tls-inspection'] `
        -InputCount $inspection.Count -Evaluation {
        if ('Confirmed' -in $inspectionValues) { [pscustomobject]@{ outcome = 'NeedsAttention' } }
        elseif ('Suspected' -in $inspectionValues) { [pscustomobject]@{ outcome = 'Informational' } }
        elseif ($inspectionValues.Count -gt 0 -and
            @($inspectionValues | Where-Object { $_ -ne 'NotObservedWithinCompletedTests' }).Count -eq 0) {
            [pscustomobject]@{ outcome = 'ExpectedCondition' }
        }
        else { [pscustomobject]@{ outcome = 'Indeterminate'; reasonCode = 'FINDING.TLS_INSPECTION_INDETERMINATE' } }
    }
    foreach ($definition in @(
        @{ kind = 'microsoft-service-connectivity'; result = $reachabilityResult; inputs = $http },
        @{ kind = 'tls-inspection'; result = $inspectionResult; inputs = $inspection }
    )) {
        $rule = $rules[$definition.kind]
        $findingId = "finding:$($definition.kind):$($Record.run.runId)"
        $finding = [ordered]@{
            findingId = $findingId; ruleId = [string] $rule.ruleId
            targetSubjectId = 'subject:device:primary'; outcome = [string] $definition.result.outcome
            evidenceReferences = @($definition.inputs | Select-Object -First 16 | ForEach-Object {
                [pscustomobject][ordered]@{
                    observationId = $_.observationId; fieldId = $_.fieldId; subjectId = $_.subjectId
                }
            })
        }
        if ($definition.result.PSObject.Properties['reasonCode']) {
            $finding.reasonCode = [string] $definition.result.reasonCode
        }
        $Record.findings = @($Record.findings) + [pscustomobject] $finding
        $recommendation = @($Policy.recommendations | Where-Object findingKind -eq $definition.kind)[0]
        $Record.recommendations = @($Record.recommendations) + [pscustomobject][ordered]@{
            recommendationId = "recommendation:$($definition.kind):$($Record.run.runId)"
            definitionId = [string] $recommendation.definitionId
            kind = 'AssessmentRecommendation'; findingIds = @($findingId)
        }
    }
    $Record.run.outcome = if (@($Record.coverage | Where-Object state -ne 'Complete').Count) {
        'CompletedWithGaps'
    } else { 'Completed' }
    $Record
}
