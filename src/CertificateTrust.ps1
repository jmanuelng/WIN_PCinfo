$script:CertificateTrustPolicyBase64='__CERTIFICATE_TRUST_POLICY_BASE64__'
$script:CertificateTrustPolicyDigest='__CERTIFICATE_TRUST_POLICY_SHA256__'

function Get-CertificateTrustSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-CertificateTrustPolicy {
    param([Parameter(Mandatory)]$ConvertFromJsonCommand)
    $sentinel='__CERTIFICATE_TRUST_'+'POLICY_BASE64__'
    if($script:CertificateTrustPolicyBase64 -eq $sentinel){
        $path=Join-Path (Split-Path -Parent $PSScriptRoot) 'docs/spec/releases/2.0.0-preview.1-certificate-trust.json'
        $text=[IO.File]::ReadAllText($path,[Text.UTF8Encoding]::new($false,$true)).Replace("`r`n","`n").Replace("`r","`n")
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes($text)
        $expected=Get-CertificateTrustSha256 -Bytes $bytes
    }else{
        $bytes=[Convert]::FromBase64String($script:CertificateTrustPolicyBase64)
        $expected=$script:CertificateTrustPolicyDigest
    }
    if((Get-CertificateTrustSha256 -Bytes $bytes) -ne $expected){throw 'The embedded Certificate Trust policy failed integrity validation.'}
    $policy=& $ConvertFromJsonCommand -InputObject ([Text.UTF8Encoding]::new($false,$true).GetString($bytes)) -Depth 30 -ErrorAction Stop
    if($policy.kind -ne 'win-pcinfo.certificate-trust-policy' -or $policy.contractVersion -ne '1.0.0' -or
        $policy.policyId -ne 'win-pcinfo.certificate-trust/1.0.0' -or @($policy.purposes).Count -ne 6 -or
        @($policy.fieldIds).Count -ne 12 -or @($policy.rules).Count -ne 4 -or
        @($policy.validationScenarios).Count -ne 12){throw 'The Certificate Trust policy is not semantically closed.'}
    $policy
}

function Read-CertificateTrustFixture {
    param([Parameter(Mandatory)][string]$LiteralPath,[Parameter(Mandatory)]$ConvertFromJsonCommand,[Parameter(Mandatory)]$Policy)
    try{
        $bytes=[IO.File]::ReadAllBytes([IO.Path]::GetFullPath($LiteralPath))
        if($bytes.Length -lt 1 -or $bytes.Length -gt 512){throw 'Fixture size is invalid.'}
        $json=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);$document=[Text.Json.JsonDocument]::Parse($json)
        try{
            $names=@($document.RootElement.EnumerateObject()|ForEach-Object Name)
            if($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or (@($names|Sort-Object)-join '|') -ne 'contractVersion|scenario'){throw 'Fixture shape is invalid.'}
        }finally{$document.Dispose()}
        $fixture=& $ConvertFromJsonCommand -InputObject $json -Depth 5 -ErrorAction Stop
        if($fixture.contractVersion -ne '1.0.0' -or [string]$fixture.scenario -notin @($Policy.validationScenarios)){throw 'Fixture scenario is not release-owned.'}
        [string]$fixture.scenario
    }catch{throw [InvalidOperationException]::new('The Certificate Trust fixture is invalid.', $_.Exception)}
}

function New-CertificateTrustScopeState {
    param([Parameter(Mandatory)][string]$ScopeId,[Parameter(Mandatory)][string]$State,[string]$ReasonCode='')
    [pscustomobject][ordered]@{scopeId=$ScopeId;state=$State;reasonCode=$ReasonCode}
}

function New-CertificateTrustCandidate {
    param(
        [Parameter(Mandatory)][string]$PurposeId,[Parameter(Mandatory)][string]$ScopeId,
        [Parameter(Mandatory)][string]$CertificateId,[Parameter(Mandatory)][string]$Fingerprint,
        [Parameter(Mandatory)][string]$StoreLocation,[Parameter(Mandatory)][string]$StoreName,
        [Parameter(Mandatory)][string]$NotBefore,[Parameter(Mandatory)][string]$NotAfter,
        [Parameter(Mandatory)][string]$ValidityState,[Parameter(Mandatory)][string]$ChainState,
        [Parameter(Mandatory)][string]$TrustState,[Parameter(Mandatory)][string]$KeyProtectionState
    )
    [pscustomobject][ordered]@{
        purposeId=$PurposeId;scopeId=$ScopeId;certificateId=$CertificateId;fingerprint=$Fingerprint
        storeLocation=$StoreLocation;storeName=$StoreName;notBefore=$NotBefore;notAfter=$NotAfter
        validityState=$ValidityState;chainState=$ChainState;trustState=$TrustState
        keyProtectionState=$KeyProtectionState
    }
}

function Get-CertificateTrustPurposeCoverage {
    param([Parameter(Mandatory)]$Payload)
    $applicable=@($Payload.scopeStates|Where-Object state -ne NotApplicable)
    if($applicable.Count -eq 0){return 'NotApplicable'}
    if(@($applicable.state|Sort-Object -Unique).Count -eq 1){return [string]$applicable[0].state}
    'Partial'
}

function Resolve-CertificateTrustChainObservation {
    param(
        [Parameter(Mandatory)][bool]$BuildSucceeded,
        [object[]]$LeafStatusFlags=@(),
        [object[]]$IssuerStatusFlags=@()
    )
    $noError=[Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError
    $notTimeValid=[Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid
    $partialChain=[Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain
    $leaf=@($LeafStatusFlags|Where-Object {$_ -ne $noError})
    $issuer=@($IssuerStatusFlags|Where-Object {$_ -ne $noError})
    $materialLeaf=@($leaf|Where-Object {([int]$_ -band (-bnot [int]$notTimeValid)) -ne 0})
    $materialIssuer=@($issuer|Where-Object {([int]$_) -ne 0})
    $material=@($materialLeaf)+@($materialIssuer)
    if(@($material|Where-Object {([int]$_ -band [int]$partialChain) -ne 0}).Count){
        return [pscustomobject][ordered]@{chainState='Incomplete';trustState='Indeterminate'}
    }
    if($material.Count -gt 0){
        return [pscustomobject][ordered]@{chainState='Complete';trustState='Untrusted'}
    }
    if($BuildSucceeded -or $leaf.Count -gt 0){
        return [pscustomobject][ordered]@{chainState='Complete';trustState='Trusted'}
    }
    [pscustomobject][ordered]@{chainState='Complete';trustState='Untrusted'}
}

function Get-CertificateTrustEnhancedKeyUsageOids {
    param([Parameter(Mandatory)]$Certificate)
    @($Certificate.Extensions|Where-Object {$_.Oid.Value -eq '2.5.29.37'}|ForEach-Object {
        if($_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]){
            @($_.EnhancedKeyUsages|ForEach-Object Value)
        }
    })
}

function ConvertTo-CertificateTrustCandidate {
    param(
        [Parameter(Mandatory)]$Purpose,[Parameter(Mandatory)]$Certificate,
        [Parameter(Mandatory)][string]$StoreLocation,[Parameter(Mandatory)][string]$StoreName,
        [Parameter(Mandatory)][DateTimeOffset]$ObservedAt,[Parameter(Mandatory)]$ChainObservation,
        [string]$KnownKeyProtectionState=''
    )
    $eku=@(Get-CertificateTrustEnhancedKeyUsageOids $Certificate)
    if(@($Purpose.ekuOids|Where-Object {$_ -in $eku}).Count -eq 0){return $null}
    $notBefore=[DateTimeOffset]$Certificate.NotBefore;$notAfter=[DateTimeOffset]$Certificate.NotAfter
    $validity=if($ObservedAt -lt $notBefore){'NotYetValid'}elseif($ObservedAt -gt $notAfter){'Expired'}else{'Valid'}
    $fingerprint=Get-CertificateTrustSha256 -Bytes $Certificate.RawData
    $keyState=if(-not $Certificate.HasPrivateKey){'NoPrivateKey'}elseif($KnownKeyProtectionState -eq 'NonExportable'){'NonExportable'}else{'PresentProtectionNotInspected'}
    New-CertificateTrustCandidate -PurposeId ([string]$Purpose.purposeId) -ScopeId ([string]$Purpose.scopeId) `
        -CertificateId $fingerprint -Fingerprint $fingerprint -StoreLocation $StoreLocation -StoreName $StoreName `
        -NotBefore $notBefore.ToString('o') -NotAfter $notAfter.ToString('o') -ValidityState $validity `
        -ChainState ([string]$ChainObservation.chainState) -TrustState ([string]$ChainObservation.trustState) `
        -KeyProtectionState $keyState
}

function New-CertificateTrustSyntheticCertificate {
    param([Parameter(Mandatory)][string]$EkuOid,[switch]$WithPrivateKeyProviderFact)
    # These are public-only synthetic DER certificates. The built application
    # parses certificate shape, EKU, dates, and fingerprints without deriving,
    # retaining, or receiving any private-key material.
    $clientDer='MIIC7TCCAdWgAwIBAgIQSbozZ9RUscO7DDvPSXlvmjANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDExtXSU4tUENJbmZvIHN5bnRoZXRpYyBjbGllbnQwHhcNMjUwMTAxMDAwMDAwWhcNMzUxMjMxMjM1OTU5WjAmMSQwIgYDVQQDExtXSU4tUENJbmZvIHN5bnRoZXRpYyBjbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrSwPglwbnV2mo+5VATtu+NwWaupW47DAqbW6ZYauk+K5BAK9lfFUuEuhDpGae1waA66FMBU99OA2HxfJv6q0u2EmeoPla746QIfWZ08OD4w3FgX+npgIIgunrqvKo0D2sUqiSb0H3kiEpinalqsDd6N2Tc+40SE3hm2ct/FvDyis/j16LeH88ygh8vMIN7OVClWG/syM94X6G0/VlG/sdxtl7Rr0U4DY7NiLvuZx5JkgdawGVOG2cnplvXSA+tzXAwov3KN5DpL98OUIRz/7R9lNYw9HSyRXZkj8l3Rq+UD6wgTbZG7WXuRS4lacvJDiUybk6wv+gH57Z+w9WWD4NAgMBAAGjFzAVMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQCTSf0kqC5iAR2sLyZ88palVRbxxrukXZzz3uNeka1+CB1Sg2L+R7Kgv0x4JXgc7aXsXRwVF9M4+OdmWrN6OqSGjR2pqYWKOxi3LVFN44baaP/3b8dfNGbw49xs7rWYZLK0UgS/0ZHuz4snFVcu/wlMu9y5sqLkhmFEZ0Weai4CAL8iqKtc40uUIBJA2enuwjwPGM/SQ0eGoagIneVuIUU6bgBupOovI4ZOxHNmr01DXk1XXivi+F6Kheew22h4K/aOiR3g1GUrdmScQt3B9aH3pUDUX84sJpe0G48/kRfGFxfV0xbNGHVNNhiPeCTBGAtj7sXkqUyseqcv9WdizpBh'
    $codeDer='MIIC6jCCAdKgAwIBAgIRAMeyRvLOBPs3fNyhYMpDB9wwDQYJKoZIhvcNAQELBQAwJDEiMCAGA1UEAxMZV0lOLVBDSW5mbyBzeW50aGV0aWMgY29kZTAeFw0yNTAxMDEwMDAwMDBaFw0zNTEyMzEyMzU5NTlaMCQxIjAgBgNVBAMTGVdJTi1QQ0luZm8gc3ludGhldGljIGNvZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCAmLq2HIc+VWlt3IATLS8OPpMiwhxEYwYfqm8ND/Kh/shGyTR6/ucC70YxYqfcQWN6kCRbKrBknlpnlx/iglhRTMIfwvKS4Cnhf9y9n7puY1euolSHS9Ko5ROdqMk388Ft7j8KHmCHmrES8qxsO0+wDCFsIJRmH9AwNC9dPNzyEiGcxsSVvnOO/cjVy72zTG4qm5d7Zv0qf+byxCbyTcKRhaZz6BOwNeTXznRsOdcVwwHAG8FpvH/EqY7Q8ZhXli8fMpKs+i43AZeAoHnkLdxmAw3TsMaTMXcQbgeHWjc3EtIj3jlVdP1jLAEb0DBpZjO1Rk24I35SpRzzBDn8AcZAgMBAAGjFzAVMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IBAQA/BqLTmS67G0PqJndwElXmHELGjDKAZYE5Zx2SJxzl5g+O8UdrCMkH4ZYymRnqhnTJfoKz5gEMIQQaDNFurg0dH1y76fL1791OgFZ9L5V/4GYZWLidvkb6GoJXvxKchl821q7/P6A9bnIe3o4aqghrn3s+UnUFvNCaD7eQxGPF3mmBIg+7mchEE50bqci824b/TyHTal9gQBlJnuUIPNzRs6MXEQGbjeUbzfBdRAdVpW5FBLdBW8fCLVqTCbKhLZYZ+74uOLIiakrLuX+x69ecB+uxl8QJC+OOEF2koLy4O0UpqK/IIN7SyrsoC4MhiJnv0xyD7BuYj032LN30XvQE'
    $encoded=if($EkuOid -eq '1.3.6.1.5.5.7.3.3'){$codeDer}else{$clientDer}
    $owner=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($encoded))
    if($WithPrivateKeyProviderFact){
        $view=[pscustomobject]@{Extensions=$owner.Extensions;NotBefore=$owner.NotBefore;NotAfter=$owner.NotAfter;RawData=$owner.RawData;HasPrivateKey=$true}
        return [pscustomobject]@{certificate=$view;certificateOwner=$owner}
    }
    [pscustomobject]@{certificate=$owner;certificateOwner=$owner}
}

function New-CertificateTrustSyntheticPayload {
    param([Parameter(Mandatory)][string]$Scenario,[Parameter(Mandatory)]$Policy)
    if($Scenario -notin @($Policy.validationScenarios)){throw 'The Certificate Trust validation scenario is not release-owned.'}
    $states=[Collections.Generic.List[object]]::new()
    foreach($purpose in $Policy.purposes){$states.Add((New-CertificateTrustScopeState ([string]$purpose.scopeId) NotApplicable 'CERTIFICATE.PURPOSE_NOT_SELECTED'))}
    $candidates=[Collections.Generic.List[object]]::new()
    $selectPurpose={
        param([string]$PurposeId,[string]$State='Complete',[string]$ReasonCode='')
        $purpose=@($Policy.purposes|Where-Object purposeId -eq $PurposeId)[0]
        $entry=@($states|Where-Object scopeId -eq $purpose.scopeId)[0]
        $entry.state=$State;$entry.reasonCode=$ReasonCode
        $purpose
    }
    $observedAt=[DateTimeOffset]'2030-01-01T00:00:00+00:00'
    $addCandidate={
        param($Purpose,[string]$Suffix,[string]$Validity='Valid',[string]$Chain='Trusted',[string]$Key='NoPrivateKey',[int]$StoreIndex=0)
        if(@($Purpose.stores).Count -le $StoreIndex){throw 'Synthetic evidence requires a released purpose store.'}
        $parts=[string]$Purpose.stores[$StoreIndex] -split '/'
        $scenarioTime=if($Validity -eq 'NotYetValid'){[DateTimeOffset]'2020-01-01T00:00:00+00:00'}elseif($Validity -eq 'Expired'){[DateTimeOffset]'2040-01-01T00:00:00+00:00'}else{$observedAt}
        $source=New-CertificateTrustSyntheticCertificate -EkuOid ([string]@($Purpose.ekuOids)[0]) `
            -WithPrivateKeyProviderFact:($Key -ne 'NoPrivateKey')
        try{
            $leafFlags=[Collections.Generic.List[object]]::new();$built=$true
            if($Validity -in @('Expired','NotYetValid')){$leafFlags.Add([Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid);$built=$false}
            if($Chain -eq 'Untrusted'){$leafFlags.Add([Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot);$built=$false}
            if($Chain -eq 'Incomplete'){$leafFlags.Add([Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain);$built=$false}
            $chainObservation=Resolve-CertificateTrustChainObservation -BuildSucceeded $built -LeafStatusFlags @($leafFlags) -IssuerStatusFlags @()
            $candidate=ConvertTo-CertificateTrustCandidate -Purpose $Purpose -Certificate $source.certificate `
                -StoreLocation $parts[0] -StoreName $parts[1] -ObservedAt $scenarioTime `
                -ChainObservation $chainObservation -KnownKeyProtectionState $Key
            if($null -eq $candidate){throw 'The synthetic certificate did not match its declared purpose.'}
            $candidates.Add($candidate)
        }finally{
            $source.certificateOwner.Dispose()
        }
    }
    $deviceContext='Physical'
    switch($Scenario){
        'ValidTrusted'{$p=& $selectPurpose Management;& $addCandidate $p '01' Valid Trusted NonExportable}
        'Expired'{$p=& $selectPurpose Authentication;& $addCandidate $p '02' Expired Trusted NonExportable}
        'NotYetValid'{$p=& $selectPurpose Authentication;& $addCandidate $p '03' NotYetValid Trusted NonExportable}
        'Untrusted'{$p=& $selectPurpose DeviceIdentity;& $addCandidate $p '04' Valid Untrusted PresentProtectionNotInspected}
        'IncompleteChain'{$p=& $selectPurpose Management;& $addCandidate $p '05' Valid Incomplete NoPrivateKey}
        'MultipleCandidates'{$p=& $selectPurpose CodeTrust;& $addCandidate $p '06' Valid Trusted NoPrivateKey 0;& $addCandidate $p '07' Expired Untrusted NoPrivateKey 1}
        'InaccessibleStore'{$null=& $selectPurpose Management Denied 'CERTIFICATE.STORE_ACCESS_DENIED'}
        'AbsentPurpose'{$null=& $selectPurpose Management;$null=& $selectPurpose Authentication}
        'NonExportableKey'{$p=& $selectPurpose Management;& $addCandidate $p '08' Valid Trusted NonExportable}
        'AlternateAdministrator'{$null=& $selectPurpose Authentication Denied 'CERTIFICATE.ASSESSMENT_USER_CONTEXT_REQUIRED'}
        'VirtualDevice'{$deviceContext='Virtual';$p=& $selectPurpose DeviceIdentity;& $addCandidate $p '09' Valid Trusted PresentProtectionNotInspected}
        'MalformedCertificate'{
            $null=& $selectPurpose Management Malformed 'CERTIFICATE.SOURCE_ENTRY_MALFORMED'
            try{$invalid=[Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]](0x30,0x01,0x00));$invalid.Dispose();throw 'Malformed certificate fixture was unexpectedly accepted.'}catch [Security.Cryptography.CryptographicException]{}
        }
    }
    [pscustomobject][ordered]@{
        sourceLocale='en-US';processRelationship=if($Scenario -eq 'AlternateAdministrator'){'AlternateAdministrator'}else{'SameUser'}
        observedExecutionContext=if($Scenario -eq 'AlternateAdministrator'){'Administrator'}else{'StandardUser'}
        deviceContext=$deviceContext;scopeStates=@($states);candidates=@($candidates)
        privateMaterialAccessed=$false;storeChanged=$false
    }
}

function Test-CertificateTrustObjectShape {
    param($Value,[string[]]$Names)
    if($null -eq $Value -or $Value -is [string] -or $Value -is [Collections.IDictionary] -or $Value -is [Collections.IEnumerable]){return $false}
    (@($Value.PSObject.Properties.Name|Sort-Object)-join '|') -ceq (@($Names|Sort-Object)-join '|')
}

function Test-CertificateTrustText {
    param($Value,[int]$Maximum)
    $Value -is [string] -and $Value.Length -ge 1 -and [Text.Encoding]::UTF8.GetByteCount($Value) -le $Maximum
}

function Test-CertificateTrustPayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)]$Policy)
    try{
        if(-not (Test-CertificateTrustObjectShape $Payload @('sourceLocale','processRelationship','observedExecutionContext','deviceContext','scopeStates','candidates','privateMaterialAccessed','storeChanged')) -or
            -not (Test-CertificateTrustText $Payload.sourceLocale 35) -or
            [string]$Payload.processRelationship -notin @('SameUser','AlternateAdministrator','Unavailable') -or
            [string]$Payload.observedExecutionContext -notin @('StandardUser','Administrator','Unavailable') -or
            [string]$Payload.deviceContext -notin @('Physical','Virtual','Unknown') -or
            $Payload.privateMaterialAccessed -isnot [bool] -or [bool]$Payload.privateMaterialAccessed -or
            $Payload.storeChanged -isnot [bool] -or [bool]$Payload.storeChanged){return $false}
        if(@($Payload.scopeStates).Count -ne 6 -or @($Payload.scopeStates.scopeId|Sort-Object -Unique).Count -ne 6){return $false}
        foreach($state in @($Payload.scopeStates)){
            if(-not (Test-CertificateTrustObjectShape $state @('scopeId','state','reasonCode')) -or
                [string]$state.scopeId -notin @($Policy.purposes.scopeId) -or
                [string]$state.state -notin @('Complete','Partial','NotApplicable','Unavailable','Constrained','Denied','Malformed','TimedOut','Failed') -or
                ($state.state -eq 'Complete' -and $state.reasonCode) -or
                ($state.state -ne 'Complete' -and (-not (Test-CertificateTrustText $state.reasonCode 96) -or [string]$state.reasonCode -cnotmatch '^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$'))){return $false}
        }
        foreach($candidate in @($Payload.candidates)){
            $parsedNotBefore=[DateTimeOffset]::MinValue
            $parsedNotAfter=[DateTimeOffset]::MinValue
            $purpose=@($Policy.purposes|Where-Object purposeId -eq $candidate.purposeId)[0]
            if(-not (Test-CertificateTrustObjectShape $candidate @('purposeId','scopeId','certificateId','fingerprint','storeLocation','storeName','notBefore','notAfter','validityState','chainState','trustState','keyProtectionState')) -or
                [string]$candidate.purposeId -notin @($Policy.purposes.purposeId) -or
                [string]$candidate.scopeId -ne [string]$purpose.scopeId -or
                -not (Test-CertificateTrustText $candidate.certificateId 128) -or
                [string]$candidate.fingerprint -cnotmatch '^[0-9A-Fa-f]{64}$' -or
                [string]$candidate.storeLocation -notin @('CurrentUser','LocalMachine') -or
                [string]$candidate.storeName -notin @('My','TrustedPublisher') -or
                "$($candidate.storeLocation)/$($candidate.storeName)" -notin @($purpose.stores) -or
                -not [DateTimeOffset]::TryParse([string]$candidate.notBefore,[ref]$parsedNotBefore) -or
                -not [DateTimeOffset]::TryParse([string]$candidate.notAfter,[ref]$parsedNotAfter) -or
                [string]$candidate.validityState -notin @('Valid','Expired','NotYetValid','Unknown') -or
                [string]$candidate.chainState -notin @('Complete','Incomplete','NotEvaluated') -or
                [string]$candidate.trustState -notin @('Trusted','Untrusted','Indeterminate') -or
                [string]$candidate.keyProtectionState -notin @('NoPrivateKey','NonExportable','PresentProtectionNotInspected','UnknownNotInspected')){return $false}
        }
        foreach($purpose in $Policy.purposes){if(@($Payload.candidates|Where-Object purposeId -eq $purpose.purposeId).Count -gt [int]$Policy.collector.maximumCertificatesPerPurpose){return $false}}
        $true
    }catch{$false}
}

function Test-CertificateTrustSid {
    param([string]$Sid)
    try{$parsed=[Security.Principal.SecurityIdentifier]::new($Sid);$parsed.IsAccountSid()}catch{$false}
}

function New-CertificateTrustGapPayload {
    param([Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string]$State,[Parameter(Mandatory)][string]$ReasonCode,[string]$Relationship='Unavailable',[string]$Context='Unavailable')
    [pscustomobject][ordered]@{
        sourceLocale=[Globalization.CultureInfo]::CurrentUICulture.Name
        processRelationship=$Relationship;observedExecutionContext=$Context;deviceContext='Unknown'
        scopeStates=@($Policy.purposes|ForEach-Object {New-CertificateTrustScopeState ([string]$_.scopeId) $State $ReasonCode})
        candidates=@();privateMaterialAccessed=$false;storeChanged=$false
    }
}

function Get-CertificateTrustLiveSource {
    param([Parameter(Mandatory)]$Policy)
    # This release-owned worker is the complete live trust boundary. It opens
    # only the release-policy store/purpose pairs, read-only, performs offline chain
    # evaluation, and returns public-certificate metadata. It never requests a
    # private-key handle, exports material, or mutates a certificate store.
    $purposeProjection=@($Policy.purposes|ForEach-Object {[pscustomobject][ordered]@{
        purposeId=[string]$_.purposeId;scopeId=[string]$_.scopeId
        stores=@($_.stores|ForEach-Object {[string]$_});ekuOids=@($_.ekuOids|ForEach-Object {[string]$_})
    }})
    $purposeJson=$purposeProjection|ConvertTo-Json -Compress -Depth 5
    $purposeBase64=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($purposeJson))
    $source=@'
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$InformationPreference='SilentlyContinue'
function Scope([string]$id,[string]$state,[string]$reason=''){[pscustomobject][ordered]@{scopeId=$id;state=$state;reasonCode=$reason}}
function Resolve-Chain($chain,[bool]$built){
  $no=[Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError
  $time=[Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid
  $partial=[Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain
  if($chain.ChainElements.Count -gt 0){
    $leaf=@($chain.ChainElements[0].ChainElementStatus|ForEach-Object Status|Where-Object {$_ -ne $no})
    $issuer=@($chain.ChainElements|Select-Object -Skip 1|ForEach-Object {$_.ChainElementStatus|ForEach-Object Status}|Where-Object {$_ -ne $no})
  }else{$leaf=@();$issuer=@($chain.ChainStatus|ForEach-Object Status|Where-Object {$_ -ne $no})}
  $materialLeaf=@($leaf|Where-Object {([int]$_ -band (-bnot [int]$time)) -ne 0})
  $material=@($materialLeaf)+@($issuer)
  if(@($material|Where-Object {([int]$_ -band [int]$partial) -ne 0}).Count){return [pscustomobject]@{chainState='Incomplete';trustState='Indeterminate'}}
  if($material.Count -gt 0){return [pscustomobject]@{chainState='Complete';trustState='Untrusted'}}
  if($built -or $leaf.Count -gt 0){return [pscustomobject]@{chainState='Complete';trustState='Trusted'}}
  [pscustomobject]@{chainState='Complete';trustState='Untrusted'}
}
function Eku($certificate){
  $extension=@($certificate.Extensions|Where-Object {$_.Oid.Value -eq '2.5.29.37'})[0]
  if($null -eq $extension){return @()}
  $typed=if($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]){$extension}else{[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($extension,$extension.Critical)}
  @($typed.EnhancedKeyUsages|ForEach-Object Value)
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try{
  $sid=[string]$identity.User.Value;$principal=[Security.Principal.WindowsPrincipal]::new($identity)
  if($sid -ne $env:WINPCINFO_CERTIFICATE_ASSESSMENT_SID -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Assessment User context mismatch.'}
}finally{$identity.Dispose()}
$maximum=[int]$env:WINPCINFO_CERTIFICATE_MAXIMUM
$purposeBytes=[Convert]::FromBase64String('__CERTIFICATE_PURPOSES_BASE64__')
$purposes=@([Text.UTF8Encoding]::new($false,$true).GetString($purposeBytes)|ConvertFrom-Json -Depth 5)
$states=[Collections.Generic.List[object]]::new();$candidates=[Collections.Generic.List[object]]::new()
foreach($purpose in $purposes){
  if($purpose.stores.Count -eq 0){$reason=if($purpose.purposeId -eq 'ServiceConnectivity'){'CERTIFICATE.SERVICE_TARGET_ABSENT'}else{'CERTIFICATE.PURPOSE_ATTRIBUTION_UNAVAILABLE'};$states.Add((Scope $purpose.scopeId NotApplicable $reason));continue}
  $selected=[Collections.Generic.List[object]]::new();$state='Complete';$reason='';$successfulStores=0;$failedStoreState='';$failedStoreReason=''
  foreach($target in $purpose.stores){
    try{
      $parts=$target -split '/';$location=[Security.Cryptography.X509Certificates.StoreLocation]([Enum]::Parse([Security.Cryptography.X509Certificates.StoreLocation],$parts[0],$false));$name=[Security.Cryptography.X509Certificates.StoreName]([Enum]::Parse([Security.Cryptography.X509Certificates.StoreName],$parts[1],$false))
      $store=[Security.Cryptography.X509Certificates.X509Store]::new($name,$location)
      try{
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        foreach($certificate in @($store.Certificates)){
          try{
            $eku=@(Eku $certificate);if(@($purpose.ekuOids|Where-Object {$_ -in $eku}).Count -eq 0){continue}
            $now=[DateTimeOffset]::UtcNow;$notBefore=[DateTimeOffset]$certificate.NotBefore;$notAfter=[DateTimeOffset]$certificate.NotAfter
            $validity=if($now -lt $notBefore){'NotYetValid'}elseif($now -gt $notAfter){'Expired'}else{'Valid'}
            $chain=[Security.Cryptography.X509Certificates.X509Chain]::new()
            try{$chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck;if($chain.ChainPolicy.PSObject.Properties['DisableCertificateDownloads']){$chain.ChainPolicy.DisableCertificateDownloads=$true};$built=$chain.Build($certificate);$chainResult=Resolve-Chain $chain $built}finally{$chain.Dispose()}
            $fingerprint=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificate.RawData)).ToLowerInvariant()
            $selected.Add([pscustomobject][ordered]@{purposeId=$purpose.purposeId;scopeId=$purpose.scopeId;certificateId="sha256:$fingerprint";fingerprint=$fingerprint;storeLocation=[string]$location;storeName=[string]$name;notBefore=$notBefore.ToUniversalTime().ToString('o');notAfter=$notAfter.ToUniversalTime().ToString('o');validityState=$validity;chainState=$chainResult.chainState;trustState=$chainResult.trustState;keyProtectionState=if($certificate.HasPrivateKey){'PresentProtectionNotInspected'}else{'NoPrivateKey'}})
          }catch{$state='Partial';$reason='CERTIFICATE.SOURCE_ENTRY_MALFORMED'}
        }
      }finally{$store.Close();$store.Dispose()}
      $successfulStores++
    }catch [Security.SecurityException]{$failedStoreState='Denied';$failedStoreReason='CERTIFICATE.STORE_ACCESS_DENIED'}catch [UnauthorizedAccessException]{$failedStoreState='Denied';$failedStoreReason='CERTIFICATE.STORE_ACCESS_DENIED'}catch{if($failedStoreState -ne 'Denied'){$failedStoreState='Unavailable';$failedStoreReason='CERTIFICATE.STORE_UNAVAILABLE'}}
  }
  if($failedStoreReason){if($successfulStores -gt 0){$state='Partial';$reason='CERTIFICATE.STORE_ACCESS_PARTIAL'}else{$state=$failedStoreState;$reason=$failedStoreReason}}
  $ordered=@($selected|Sort-Object certificateId);if($ordered.Count -gt $maximum){$ordered=@($ordered|Select-Object -First $maximum);$state='Constrained';$reason='CERTIFICATE.CANDIDATE_LIMIT_EXCEEDED'}
  foreach($candidate in $ordered){$candidates.Add($candidate)};$states.Add((Scope $purpose.scopeId $state $reason))
}
$payload=[pscustomobject][ordered]@{sourceLocale='und';processRelationship='SameUser';observedExecutionContext='StandardUser';deviceContext='Unknown';scopeStates=@($states);candidates=@($candidates);privateMaterialAccessed=$false;storeChanged=$false}
[Console]::Out.Write(($payload|ConvertTo-Json -Compress -Depth 8))
'@
    $source.Replace('__CERTIFICATE_PURPOSES_BASE64__',$purposeBase64)
}

function ConvertTo-CertificateTrustEncodedCommand {
    param([Parameter(Mandatory)][string]$Source)
    $input=[IO.MemoryStream]::new([Text.UTF8Encoding]::new($false).GetBytes($Source));$output=[IO.MemoryStream]::new()
    try{$gzip=[IO.Compression.GZipStream]::new($output,[IO.Compression.CompressionLevel]::Optimal,$true);try{$input.CopyTo($gzip)}finally{$gzip.Dispose()};$payload=[Convert]::ToBase64String($output.ToArray())}finally{$input.Dispose();$output.Dispose()}
    $bootstrap='$b=[Convert]::FromBase64String('''+$payload+''');$m=[IO.MemoryStream]::new($b);$g=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);$r=[IO.StreamReader]::new($g,[Text.Encoding]::UTF8);try{&([scriptblock]::Create($r.ReadToEnd()))}finally{$r.Dispose();$g.Dispose();$m.Dispose()}'
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
}

function Test-CertificateTrustExecutableSignature {
    param([Parameter(Mandatory)][string]$LiteralPath)
    try{
        $signatureCommand=$ExecutionContext.InvokeCommand.GetCommand('Get-AuthenticodeSignature',[Management.Automation.CommandTypes]::Cmdlet)
        if($null -eq $signatureCommand -or $signatureCommand.CommandType -ne 'Cmdlet' -or $signatureCommand.ModuleName -ne 'Microsoft.PowerShell.Security'){return $false}
        $signature=& $signatureCommand -LiteralPath $LiteralPath -ErrorAction Stop
        [string]$signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate -and
            $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -eq 'Microsoft Corporation'
    }catch{$false}
}

function Invoke-BoundedCertificateTrustSnapshot {
    param([Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string]$AssessmentUserSid)
    Initialize-ProcessSupervisorNativeType
    $collector=$Policy.collector;$terminationMilliseconds=[Math]::Min(1000,[Math]::Max(1,[Math]::Floor([int]$collector.deadlineMilliseconds/4)));$activeMilliseconds=[Math]::Max(1,[int]$collector.deadlineMilliseconds-$terminationMilliseconds)
    $started=[DateTimeOffset]::UtcNow;$executable=[IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
    if(-not [IO.File]::Exists($executable) -or -not [string]::Equals($executable,[Environment]::ProcessPath,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-CertificateTrustExecutableSignature -LiteralPath $executable)){return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode='CERTIFICATE.BOUNDARY_UNAVAILABLE';startedAt=$started;completedAt=[DateTimeOffset]::UtcNow}}
    $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase);$environment['SystemRoot']=[Environment]::GetFolderPath('Windows');$environment['WINPCINFO_CERTIFICATE_ASSESSMENT_SID']=$AssessmentUserSid;$environment['WINPCINFO_CERTIFICATE_MAXIMUM']=[string]$collector.maximumCertificatesPerPurpose;$environment['POWERSHELL_TELEMETRY_OPTOUT']='1';$environment['POWERSHELL_UPDATECHECK']='Off';$environment['POWERSHELL_DIAGNOSTICS_OPTOUT']='1';$environment['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
    $encoded=ConvertTo-CertificateTrustEncodedCommand -Source (Get-CertificateTrustLiveSource -Policy $Policy);$eventName="Local\WINPCInfo-CertificateTrust-$([Guid]::NewGuid().ToString('N'))";$created=$false;$event=$null
    try{
        $event=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$eventName,[ref]$created);if(-not $created){throw 'Event ownership failed.'}
        $native=[WinPCInfo.ProcessSupervisor.NativeRunner]::Run($executable,@('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded),$PSHOME,$environment,$activeMilliseconds,[int]$collector.resultMaximumUtf8Bytes,4096,[Threading.CancellationToken]::None,$event,1,$terminationMilliseconds,$false)
        if($native.Started -and -not $native.CompleteOwnedTreeAbsent){$exception=[InvalidOperationException]::new('The Certificate Trust worker tree could not be proved absent.');$exception.Data['ReasonCode']='CERTIFICATE.COLLECTOR_CLEANUP_INCOMPLETE';throw $exception}
        if(-not $native.Started -or $native.FailureStage -ne [WinPCInfo.ProcessSupervisor.NativeFailureStage]::None -or $native.ExitCode -ne 0 -or $native.StandardOutputExceeded -or $native.StandardErrorBytes -ne 0){$reason=Get-NativeSupervisorReasonCode -NativeResult $native;if(-not $reason){$reason='CERTIFICATE.SOURCE_FAILED'};return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode=$reason;startedAt=$started;completedAt=[DateTimeOffset]::UtcNow}}
        $json=[Text.UTF8Encoding]::new($false,$true).GetString($native.StandardOutput);$payload=$json|ConvertFrom-Json -Depth 8 -ErrorAction Stop
        [pscustomobject]@{succeeded=$true;payload=$payload;reasonCode='';startedAt=$started;completedAt=[DateTimeOffset]::UtcNow}
    }catch{if($_.Exception.Data['ReasonCode']){throw};[pscustomobject]@{succeeded=$false;payload=$null;reasonCode='CERTIFICATE.SOURCE_FAILED';startedAt=$started;completedAt=[DateTimeOffset]::UtcNow}}finally{if($null -ne $event){$event.Dispose()}}
}

function Invoke-CertificateTrustCollection {
    param([Parameter(Mandatory)]$Policy,[string]$ValidationScenario,[switch]$Live,[string]$AssessmentUserSid)
    $started=[DateTimeOffset]::UtcNow;$completed=$null
    if($Live){
        if(-not (Test-CertificateTrustSid $AssessmentUserSid)){$payload=New-CertificateTrustGapPayload $Policy Unavailable 'CERTIFICATE.ASSESSMENT_USER_CONTEXT_UNAVAILABLE'}else{
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
            try{$processSid=[string]$identity.User.Value;$administrator=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}finally{$identity.Dispose()}
            if($processSid -ne $AssessmentUserSid -or $administrator){$payload=New-CertificateTrustGapPayload $Policy Denied 'CERTIFICATE.ASSESSMENT_USER_CONTEXT_REQUIRED' $(if($processSid -ne $AssessmentUserSid){'AlternateAdministrator'}else{'SameUser'}) Administrator}else{
                $snapshot=Invoke-BoundedCertificateTrustSnapshot -Policy $Policy -AssessmentUserSid $AssessmentUserSid;$started=$snapshot.startedAt;$completed=$snapshot.completedAt
                if($snapshot.succeeded){$payload=$snapshot.payload}else{$timedOut=$snapshot.reasonCode -eq 'PROCESS.DEADLINE_EXCEEDED';$payload=New-CertificateTrustGapPayload $Policy $(if($timedOut){'TimedOut'}else{'Failed'}) $(if($timedOut){'CERTIFICATE.DEADLINE_EXCEEDED'}else{'CERTIFICATE.SOURCE_FAILED'}) 'SameUser' 'StandardUser'}
            }
        }
    }else{$payload=New-CertificateTrustSyntheticPayload $ValidationScenario $Policy}
    if(-not (Test-CertificateTrustPayload $payload $Policy)){throw 'The Certificate Trust payload failed its closed contract.'}
    if($null -eq $completed){$completed=[DateTimeOffset]::UtcNow}
    [pscustomobject][ordered]@{
        state=if(@($payload.scopeStates|Where-Object {$_.state -notin @('Complete','NotApplicable')}).Count){'CompletedWithGaps'}else{'Completed'}
        reasonCode=if(@($payload.scopeStates|Where-Object {$_.state -notin @('Complete','NotApplicable')}).Count){'CERTIFICATE.COLLECTION_GAPS'}else{'CERTIFICATE.COLLECTION_COMPLETED'}
        validationFixture=-not $Live;cleanupVerified=$true
        envelope=[pscustomobject][ordered]@{startedAt=$started.ToString('o');completedAt=$completed.ToString('o');attempts=1;executionContext=if($Live){'StandardUser'}else{'Synthetic'}}
        payload=$payload
    }
}

function New-CertificateTrustPublicProjection {
    param([Parameter(Mandatory)]$CollectorResult)
    $payload=$CollectorResult.payload;$coverage=Get-CertificateTrustPurposeCoverage $payload
    [pscustomobject][ordered]@{
        recordType='win-pcinfo.certificate-trust-validation';contractVersion='1.0.0';state=[string]$CollectorResult.state
        purposeCoverage=$coverage;certificateCandidateCount=@($payload.candidates).Count
        deviceContext=[string]$payload.deviceContext
        expiredCount=@($payload.candidates|Where-Object validityState -eq Expired).Count
        notYetValidCount=@($payload.candidates|Where-Object validityState -eq NotYetValid).Count
        untrustedCount=@($payload.candidates|Where-Object trustState -eq Untrusted).Count
        incompleteChainCount=@($payload.candidates|Where-Object chainState -eq Incomplete).Count
        certificateIdentifiersPublished=$false;privateMaterialAccessed=[bool]$payload.privateMaterialAccessed
        privateMaterialPublished=$false;certificateStoreChanged=[bool]$payload.storeChanged
    }
}

function Add-CertificateTrustEvidenceRecord {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$CollectorResult,[Parameter(Mandatory)]$Policy)
    if([string]$Record.run.evidenceProfileId -ne 'profile:device-firmware-identity-administrator-policy-software-resource-and-network-readiness'){throw 'Certificate Trust evidence requires the accepted software-ready evidence profile.'}
    if(-not [bool]$CollectorResult.cleanupVerified -or -not (Test-CertificateTrustPayload $CollectorResult.payload $Policy)){throw 'Certificate Trust evidence requires a closed, cleanup-verified result.'}
    $runId=[string]$Record.run.runId;$payload=$CollectorResult.payload;$collector=$Policy.collector
    $scopeById=@{};foreach($purpose in $Policy.purposes){$scopeById[[string]$purpose.scopeId]=$purpose}
    $scopeObservationIds=@{};foreach($purpose in $Policy.purposes){$scopeObservationIds[[string]$purpose.scopeId]=[Collections.Generic.List[string]]::new()}
    $observations=[Collections.Generic.List[object]]::new();$provenance=[Collections.Generic.List[object]]::new();$subjects=[Collections.Generic.List[object]]::new()
    function Add-CertificateObservation {
        param([string]$ScopeId,[string]$Suffix,[string]$FieldId,[string]$SubjectId,$Value,[string]$ValueState='ObservedValue')
        $observationId="observation:certificate-$Suffix`:$runId";$provenanceId="provenance:certificate-$Suffix`:$runId"
        $entry=[ordered]@{observationId=$observationId;fieldId=$FieldId;subjectId=$SubjectId;provenanceId=$provenanceId;valueState=$ValueState};if($ValueState -eq 'ObservedValue'){$entry.value=$Value}
        $observations.Add([pscustomobject]$entry)
        $provenance.Add([pscustomobject][ordered]@{provenanceId=$provenanceId;fieldId=$FieldId;subjectId=$SubjectId;sourceId=[string]$scopeById[$ScopeId].sourceId;collectorId=[string]$collector.collectorId;collectorVersion=[string]$collector.collectorVersion;executionContext=[string]$CollectorResult.envelope.executionContext;collectedAt=[string]$CollectorResult.envelope.completedAt;sourceLocale=[string]$payload.sourceLocale})
        $scopeObservationIds[$ScopeId].Add($observationId)
    }
    $index=0
    foreach($candidate in @($payload.candidates)){
        $subjectId="subject:certificate:$index";$subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='Certificate'})
        Add-CertificateObservation $candidate.scopeId "$index-presence" 'field:certificate.presence' $subjectId $true
        foreach($mapping in @(
            @('purposeId','purpose'),@('certificateId','identifier'),@('fingerprint','fingerprint'),@('storeLocation','store-location'),@('storeName','store-name'),@('notBefore','not-before'),@('notAfter','not-after'),
            @('validityState','validity-state'),@('chainState','chain-state'),@('trustState','trust-state'),@('keyProtectionState','key-protection-state'))){
            # ConvertFrom-Json intentionally recognizes ISO 8601 tokens as
            # DateTime values. Prefixing the human-readable UTC form keeps the
            # canonical evidence field a String on every supported PowerShell
            # runtime while retaining an unambiguous point in time.
            $value=if($mapping[0] -in @('notBefore','notAfter')){
                'UTC '+([DateTimeOffset]::Parse([string]$candidate.($mapping[0]))).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss')
            }else{$candidate.($mapping[0])}
            Add-CertificateObservation $candidate.scopeId "$index-$($mapping[1])" "field:certificate.$($mapping[1])" $subjectId $value
        }
        $index++
    }
    foreach($state in $payload.scopeStates){
        if($state.state -eq 'Complete' -and $scopeObservationIds[[string]$state.scopeId].Count -eq 0){
            $suffix=([string]$state.scopeId).Substring('scope:certificate.'.Length)
            $absenceSubjectId="subject:certificate-purpose:$suffix"
            $subjects.Add([pscustomobject][ordered]@{subjectId=$absenceSubjectId;kind='CertificatePurpose'})
            Add-CertificateObservation ([string]$state.scopeId) "absent-$suffix-presence" 'field:certificate.presence' $absenceSubjectId $false
            foreach($fieldId in @($Policy.fieldIds|Where-Object {$_ -ne 'field:certificate.presence'})){
                $fieldSuffix=([string]$fieldId).Substring('field:certificate.'.Length)
                Add-CertificateObservation ([string]$state.scopeId) "absent-$suffix-$fieldSuffix" ([string]$fieldId) $absenceSubjectId $null 'ObservedAbsent'
            }
        }
    }
    $coverage=[Collections.Generic.List[object]]::new();$diagnostics=[Collections.Generic.List[object]]::new()
    foreach($state in $payload.scopeStates){
        $suffix=([string]$state.scopeId).Substring('scope:certificate.'.Length);$coverageId="coverage:certificate-$suffix`:$runId"
        $entry=[ordered]@{coverageId=$coverageId;scopeId=[string]$state.scopeId;state=[string]$state.state;observationIds=@($scopeObservationIds[[string]$state.scopeId]);diagnosticIds=@()}
        if($state.state -ne 'Complete'){$diagnosticId="diagnostic:certificate-$suffix`:$runId";$entry.reasonCode=[string]$state.reasonCode;$entry.diagnosticIds=@($diagnosticId);$diagnostics.Add([pscustomobject][ordered]@{diagnosticId=$diagnosticId;scopeId=[string]$state.scopeId;phase='Collection';reasonCode=[string]$state.reasonCode;operatorMessageId='certificate-trust.collection.incomplete'})}
        $coverage.Add([pscustomobject]$entry)
    }
    $Record.subjects=@($Record.subjects)+@($subjects);$Record.observations=@($Record.observations)+@($observations);$Record.provenance=@($Record.provenance)+@($provenance);$Record.coverage=@($Record.coverage)+@($coverage);$Record.diagnostics=@($Record.diagnostics)+@($diagnostics)
    $Record.collectorResults=@($Record.collectorResults)+[pscustomobject][ordered]@{envelopeId="envelope:certificate-trust:$runId";collectorId=[string]$collector.collectorId;collectorVersion=[string]$collector.collectorVersion;operationId=[string]$collector.operationId;intendedScopeIds=@($Policy.purposes.scopeId);subjectIds=@('subject:device:primary')+@($subjects|ForEach-Object subjectId);startedAt=[string]$CollectorResult.envelope.startedAt;completedAt=[string]$CollectorResult.envelope.completedAt;executionContext=[string]$CollectorResult.envelope.executionContext;attempts=1;observationIds=@($observations|ForEach-Object observationId);coverageIds=@($coverage|ForEach-Object coverageId);diagnosticIds=@($diagnostics|ForEach-Object diagnosticId)}
    $Record.run.evidenceProfileId=[string]$Policy.evidenceProfileId;$Record.run.outcome=if(@($Record.coverage|Where-Object {$_.state -ne 'Complete'}).Count){'CompletedWithGaps'}else{'Completed'};$Record
}

function Invoke-CertificateTrustRule {
    param($Rule,[int]$InputCount,[scriptblock]$Evaluation)
    $watch=[Diagnostics.Stopwatch]::StartNew();$result=@(& $Evaluation);$watch.Stop()
    if($InputCount -gt [int]$Rule.maximumInputObservations -or $watch.ElapsedMilliseconds -gt [int]$Rule.deadlineMilliseconds -or $result.Count -ne 1 -or [string]$result[0].outcome -notin @('ExpectedCondition','NeedsAttention','Informational','Indeterminate','NotApplicable')){throw "The release-owned $($Rule.operationId) rule violated its finite contract."}
    $result[0]
}

function Complete-ValidatedCertificateTrustAssessmentRecord {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$Policy,[Parameter(Mandatory)]$ContractValidation)
    if(-not [bool]$ContractValidation.accepted -or $ContractValidation.reasonCode -ne 'CONTRACT.ACCEPTED' -or [string]$Record.run.evidenceProfileId -ne [string]$Policy.evidenceProfileId){throw 'Certificate Trust rules require an accepted source-only record.'}
    $rules=@{};foreach($rule in $Policy.rules){$rules[[string]$rule.findingKind]=$rule}
    $certificateObservations=@($Record.observations|Where-Object fieldId -like 'field:certificate.*')
    foreach($purpose in $Policy.purposes){
        $scopeId=[string]$purpose.scopeId;$scopeSuffix=$scopeId.Substring('scope:certificate.'.Length)
        $coverage=@($Record.coverage|Where-Object scopeId -eq $scopeId)[0]
        $observationIds=@($coverage.observationIds)
        $observations=@($certificateObservations|Where-Object observationId -in $observationIds)
        $gap=$coverage.state -notin @('Complete','NotApplicable');$complete=$coverage.state -eq 'Complete'
        $presence=@($observations|Where-Object fieldId -eq 'field:certificate.presence');$present=@($presence|Where-Object {$_.valueState -eq 'ObservedValue' -and $_.value -eq $true}).Count
        $validity=@($observations|Where-Object fieldId -eq 'field:certificate.validity-state');$trust=@($observations|Where-Object fieldId -eq 'field:certificate.trust-state');$chain=@($observations|Where-Object fieldId -eq 'field:certificate.chain-state');$keys=@($observations|Where-Object fieldId -eq 'field:certificate.key-protection-state')
        $validityValues=@($validity|Where-Object valueState -eq ObservedValue|ForEach-Object value);$trustValues=@($trust|Where-Object valueState -eq ObservedValue|ForEach-Object value);$chainValues=@($chain|Where-Object valueState -eq ObservedValue|ForEach-Object value)
        $presenceResult=Invoke-CertificateTrustRule $rules['certificate-presence'] $presence.Count {if($gap){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.CERTIFICATE_PRESENCE_INCOMPLETE'}}elseif(-not $complete){[pscustomobject]@{outcome='NotApplicable';reasonCode='FINDING.CERTIFICATE_PURPOSE_NOT_APPLICABLE'}}elseif($present){[pscustomobject]@{outcome='ExpectedCondition'}}else{[pscustomobject]@{outcome='NeedsAttention'}}}
        $validityResult=Invoke-CertificateTrustRule $rules['certificate-validity'] $validity.Count {if(@($validityValues|Where-Object {$_ -in @('Expired','NotYetValid')}).Count){[pscustomobject]@{outcome='NeedsAttention'}}elseif($gap){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.CERTIFICATE_VALIDITY_INCOMPLETE'}}elseif(-not $present){[pscustomobject]@{outcome='NotApplicable';reasonCode='FINDING.CERTIFICATE_NOT_PRESENT'}}elseif(@($validityValues|Where-Object {$_ -eq 'Valid'}).Count -eq $present){[pscustomobject]@{outcome='ExpectedCondition'}}else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.CERTIFICATE_VALIDITY_UNKNOWN'}}}
        $trustResult=Invoke-CertificateTrustRule $rules['certificate-trust'] ($trust.Count+$chain.Count) {if(@($trustValues|Where-Object {$_ -eq 'Untrusted'}).Count){[pscustomobject]@{outcome='NeedsAttention'}}elseif(@($chainValues|Where-Object {$_ -eq 'Incomplete'}).Count -or @($trustValues|Where-Object {$_ -eq 'Indeterminate'}).Count){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.CERTIFICATE_CHAIN_INCOMPLETE'}}elseif($gap){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.CERTIFICATE_TRUST_EVIDENCE_INCOMPLETE'}}elseif(-not $present){[pscustomobject]@{outcome='NotApplicable';reasonCode='FINDING.CERTIFICATE_NOT_PRESENT'}}elseif(@($trustValues|Where-Object {$_ -eq 'Trusted'}).Count -eq $present){[pscustomobject]@{outcome='ExpectedCondition'}}else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.CERTIFICATE_TRUST_UNKNOWN'}}}
        $keyResult=Invoke-CertificateTrustRule $rules['certificate-key-protection'] $keys.Count {if($gap){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.CERTIFICATE_KEY_PROTECTION_INCOMPLETE'}}elseif(-not $present){[pscustomobject]@{outcome='NotApplicable';reasonCode='FINDING.CERTIFICATE_NOT_PRESENT'}}else{[pscustomobject]@{outcome='Informational'}}}
        foreach($definition in @(@{kind='certificate-presence';result=$presenceResult;inputs=$presence},@{kind='certificate-validity';result=$validityResult;inputs=$validity},@{kind='certificate-trust';result=$trustResult;inputs=@($trust)+@($chain)},@{kind='certificate-key-protection';result=$keyResult;inputs=$keys})){
            $rule=$rules[$definition.kind];$findingId="finding:$($definition.kind)-$scopeSuffix`:$($Record.run.runId)";$finding=[ordered]@{findingId=$findingId;ruleId=[string]$rule.ruleId;targetSubjectId='subject:device:primary';outcome=[string]$definition.result.outcome;evidenceReferences=@($definition.inputs|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})}
            if($definition.result.PSObject.Properties['reasonCode']){$finding.reasonCode=[string]$definition.result.reasonCode};$Record.findings=@($Record.findings)+[pscustomobject]$finding
            if($definition.kind -ne 'certificate-key-protection' -and $definition.result.outcome -in @('NeedsAttention','Indeterminate')){$recommendation=@($Policy.recommendations|Where-Object findingKind -eq $definition.kind)[0];$Record.recommendations=@($Record.recommendations)+[pscustomobject][ordered]@{recommendationId="recommendation:$($definition.kind)-$scopeSuffix`:$($Record.run.runId)";definitionId=[string]$recommendation.definitionId;kind='AssessmentRecommendation';findingIds=@($findingId)}}
        }
    }
    $Record.run.outcome=if(@($Record.coverage|Where-Object {$_.state -ne 'Complete'}).Count){'CompletedWithGaps'}else{'Completed'};$Record
}
