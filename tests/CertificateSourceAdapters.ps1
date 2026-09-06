Set-StrictMode -Version Latest

# Test-only adapters replace Windows identity, store and chain APIs. All purpose
# selection, source reduction and generated record/package/report code executes.
function Get-ControlledCertificateSource {
    param([string]$Source,[string]$Scenario)
    $replacements=@{
        '[Security.Principal.WindowsIdentity]::GetCurrent()'='(Get-ControlledCertificateIdentity)'
        '[Security.Principal.WindowsPrincipal]::new($identity)'='(Get-ControlledCertificatePrincipal)'
        '$env:WINPCINFO_CERTIFICATE_ASSESSMENT_SID'="'S-1-5-21-100-200-300-1001'"
        '$env:WINPCINFO_CERTIFICATE_MAXIMUM'='8'
        '[Security.Cryptography.X509Certificates.X509Store]::new($name,$location)'='(Get-ControlledCertificateStore $name $location)'
        '$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)'='Open-ControlledCertificateStore $store ([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)'
        '[Security.Cryptography.X509Certificates.X509Chain]::new()'='(Get-ControlledCertificateChain)'
        '[Console]::Out.Write(($payload|ConvertTo-Json -Compress -Depth 8))'='Write-Output ($payload|ConvertTo-Json -Compress -Depth 8)'
    }
    foreach($before in $replacements.Keys){
        if($Source.IndexOf($before,[StringComparison]::Ordinal) -lt 0 -or $Source.IndexOf($before,[StringComparison]::Ordinal) -ne $Source.LastIndexOf($before,[StringComparison]::Ordinal)){throw 'Controlled certificate API boundary changed; source must not execute.'}
        $Source=$Source.Replace($before,$replacements[$before])
    }
    $adapter=@'
$script:CertificateCase='__CASE__'
$script:CertificateBuilds=@{}
$script:CertificateDisposed=0;$script:CertificateStoresClosed=0;$script:CertificateStoresDisposed=0;$script:CertificateChainsDisposed=0
function Get-ControlledCertificateIdentity {
    $value=[pscustomobject]@{User=[pscustomobject]@{Value=if($script:CertificateCase -eq 'AlternateAdministrator'){'S-1-5-21-100-200-300-1002'}else{'S-1-5-21-100-200-300-1001'}}}
    $value|Add-Member ScriptMethod Dispose {}; $value
}
function Get-ControlledCertificatePrincipal {
    $value=[pscustomobject]@{}
    $value|Add-Member ScriptMethod IsInRole { param($role) $script:CertificateCase -eq 'AlternateAdministrator' }; $value
}
function Get-ControlledCertificateStore {
    param($name,$location)
    $value=[pscustomobject]@{Name=[string]$name;Location=[string]$location;Certificates=@()}
    $value|Add-Member ScriptMethod Close { $script:CertificateStoresClosed++ }
    $value|Add-Member ScriptMethod Dispose { $script:CertificateStoresDisposed++ }; $value
}
function Open-ControlledCertificateStore {
        # Throw the API exception directly: a PowerShell ScriptMethod adds an
        # extra RuntimeException wrapper that the Windows API does not produce.
        param($store,$flags)
        if([int]$flags -ne [int]([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)){throw 'Unexpected store write authority.'}
        if($store.Location -eq 'LocalMachine' -and $store.Name -eq 'TrustedPublisher' -and $script:CertificateCase -in @('Denied','Partial')){throw [UnauthorizedAccessException]::new('Synthetic denied store')}
        if($script:CertificateCase -eq 'Denied'){throw [UnauthorizedAccessException]::new('Synthetic denied store')}
        if($script:CertificateCase -eq 'NativeDenied'){throw [Security.Cryptography.CryptographicException]::new(-2147024891)}
        if($script:CertificateCase -eq 'AbsentPurpose'){return}
        $oid=if($store.Name -eq 'TrustedPublisher'){'1.3.6.1.5.5.7.3.3'}else{'1.3.6.1.5.5.7.3.2'}
        $oids=[Security.Cryptography.OidCollection]::new();$null=$oids.Add([Security.Cryptography.Oid]::new($oid))
        $extension=[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false)
        $count=if($script:CertificateCase -in @('Bounded','BoundedMalformed')){12}elseif($script:CertificateCase -eq 'MultipleCandidates'){2}else{1}
        $store.Certificates=@(foreach($index in 1..$count){
            $certificate=[pscustomobject]@{
                Extensions=@($extension);RawData=[Text.Encoding]::UTF8.GetBytes("synthetic-public-$($store.Location)-$($store.Name)-$index")
                NotBefore=[DateTimeOffset]::UtcNow.AddYears(-1).UtcDateTime
                NotAfter=[DateTimeOffset]::UtcNow.AddYears(1).UtcDateTime;HasPrivateKey=$true
            }
            if($script:CertificateCase -eq 'Expired'){$certificate.NotAfter=[DateTimeOffset]::UtcNow.AddDays(-1).UtcDateTime}
            if($script:CertificateCase -eq 'NotYetValid'){$certificate.NotBefore=[DateTimeOffset]::UtcNow.AddDays(1).UtcDateTime}
            if($script:CertificateCase -eq 'MissingEku'){$certificate.Extensions=@()}
            $certificate|Add-Member ScriptMethod Dispose { $script:CertificateDisposed++ }; $certificate
        })
}
function Get-ControlledCertificateChain {
    $flags=switch($script:CertificateCase){Untrusted {'UntrustedRoot'} IncompleteChain {'PartialChain'} default {'NoError'}}
    $status=[pscustomobject]@{Status=[Security.Cryptography.X509Certificates.X509ChainStatusFlags]$flags}
    $value=[pscustomobject]@{ChainPolicy=[pscustomobject]@{RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::Online;DisableCertificateDownloads=$false};ChainElements=@([pscustomobject]@{ChainElementStatus=@($status)});ChainStatus=@($status)}
    $value|Add-Member ScriptMethod Build {
        param($certificate)
        if(-not $this.ChainPolicy.DisableCertificateDownloads -or $this.ChainPolicy.RevocationMode -ne [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck){throw 'Synthetic retrieval boundary reached.'}
        $key=[string]$purpose.purposeId
        if(-not $script:CertificateBuilds.ContainsKey($key)){$script:CertificateBuilds[$key]=0}
        $script:CertificateBuilds[$key]++
        if($script:CertificateCase -eq 'BoundedMalformed' -and $script:CertificateBuilds[$key] -eq 1){throw 'Synthetic malformed first candidate.'}
        if($script:CertificateBuilds[$key] -gt 8){throw 'Synthetic candidate processing bound exceeded.'}
        $script:CertificateCase -notin @('Untrusted','IncompleteChain')
    }
    $value|Add-Member ScriptMethod Dispose { $script:CertificateChainsDisposed++ }; $value
}
'@.Replace('__CASE__',$Scenario)
    $adapter+"`n"+$Source
}

function Add-ControlledCertificateSources {
    param([string]$ModuleText,[string]$Scenario)
    $ModuleText=$ModuleText.Replace('function Invoke-BoundedCertificateTrustSnapshot {','function Invoke-UnusedCertificateTrustSnapshot {')
    $ModuleText=$ModuleText.Replace('Invoke-ControlledCertificateTrustCollection -Policy $Policy -ValidationScenario ValidTrusted',
        'Invoke-ControlledCertificateTrustCollection -Policy $Policy -Live -AssessmentUserSid ''S-1-5-21-100-200-300-1001''')
    # The collection context check uses the same controlled OS identity as the
    # worker; no real store or alternate-admin impersonation occurs.
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($ModuleText,[ref]$tokens,[ref]$errors)
    $node=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-ControlledCertificateTrustCollection'},$false)
    if($null -eq $node -or @($errors).Count){throw 'Generated certificate coordinator boundary changed.'}
    $replacement=$node.Extent.Text.Replace('[Security.Principal.WindowsIdentity]::GetCurrent()','(Get-ControlledCertificateIdentity)').Replace('[Security.Principal.WindowsPrincipal]::new($identity)','(Get-ControlledCertificatePrincipal)')
    $ModuleText=$ModuleText.Replace($node.Extent.Text,$replacement)
    $source=Get-ControlledCertificateSource -Source (Get-CertificateTrustLiveSource -Policy (Get-CertificateTrustPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json))) -Scenario $Scenario
    # Define only the adapter functions outside the source invocation for the
    # coordinator identity check; the original worker retains its second check.
    $adapter=$source.Substring(0,$source.IndexOf("`$ErrorActionPreference='Stop'",[StringComparison]::Ordinal))
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
    $ModuleText+"`n"+$adapter+@'

function Invoke-BoundedCertificateTrustSnapshot {
    param($Policy,$AssessmentUserSid)
    $script:StatusDeskTransport.State.CertificateSourceExecuted=$true
    $started=[DateTimeOffset]::UtcNow
    $json=& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE__'))))
    [pscustomobject]@{succeeded=$true;payload=($json|ConvertFrom-Json);startedAt=$started;completedAt=[DateTimeOffset]::UtcNow;reasonCode=''}
}
'@.Replace('__SOURCE__',$encoded)
}

function Assert-CertificateSourceReport {
    param($Record,[string]$Html,[string]$Scenario)
    $certificateCoverage=@($Record.coverage|Where-Object scopeId -like 'scope:certificate.*')
    $candidatePresence=@($Record.observations|Where-Object {$_.fieldId -eq 'field:certificate.presence' -and $_.valueState -eq 'ObservedValue' -and $_.value -eq $true})
    Assert-Equal 6 $certificateCoverage.Count 'all six purpose scopes survive the protected package'
    $expectedCount=switch($Scenario){Bounded {32} BoundedMalformed {28} MultipleCandidates {10} Partial {4} {$_ -in @('Denied','NativeDenied','AbsentPurpose','MissingEku','AlternateAdministrator')} {0} default {5}}
    Assert-Equal $expectedCount $candidatePresence.Count 'purpose-filtered user and machine observations retain their candidate counts'
    if($Scenario -in @('Bounded','BoundedMalformed')){
        Assert-Equal 4 @($certificateCoverage|Where-Object state -eq Constrained).Count 'source limits remain explicit after protected reopening'
        Assert-Equal 4 @($certificateCoverage|Where-Object reasonCode -eq 'CERTIFICATE.CANDIDATE_LIMIT_EXCEEDED').Count 'candidate limit reason survives record and package'
    }
    if($Scenario -eq 'MissingEku'){
        Assert-Equal 0 $candidatePresence.Count 'no EKU never attributes an unrelated certificate to an approved purpose'
        Assert-Equal 4 @($certificateCoverage|Where-Object state -eq Complete).Count 'well-formed certificates without EKU establish purpose-selected absence'
    }
    if($Scenario -eq 'Partial'){
        $scope=@($certificateCoverage|Where-Object scopeId -eq 'scope:certificate.code-trust')[0]
        Assert-Equal 'Partial' $scope.state 'one denied store does not discard the other approved store'
        Assert-Equal 'CERTIFICATE.STORE_ACCESS_PARTIAL' $scope.reasonCode 'partial store provenance keeps its reason'
        Assert-Equal $true $Html.Contains('Selected stores: CurrentUser/TrustedPublisher, LocalMachine/TrustedPublisher.') 'partial CodeTrust coverage explains both approved store contexts'
    }
    if($Scenario -eq 'AlternateAdministrator'){
        Assert-Equal 6 @($certificateCoverage|Where-Object state -eq Denied).Count 'alternate admin cannot replace Assessment User in any store scope'
    }elseif($Scenario -in @('Denied','NativeDenied')){
        Assert-Equal 4 @($certificateCoverage|Where-Object state -eq Denied).Count 'all selected denied purposes retain explicit coverage'
    }elseif($Scenario -notin @('Bounded','BoundedMalformed','Partial')){
        Assert-Equal 4 @($certificateCoverage|Where-Object state -eq Complete).Count 'completed selection distinguishes absence and chain gaps from collection failure'
    }
    foreach($scope in $certificateCoverage){
        $suffix=$scope.scopeId.Substring('scope:certificate.'.Length)
        $validity=@($Record.findings|Where-Object findingId -like "finding:certificate-validity-$suffix`:*")[0]
        $trust=@($Record.findings|Where-Object findingId -like "finding:certificate-trust-$suffix`:*")[0]
        if($scope.state -eq 'NotApplicable'){continue}
        $gap=$scope.state -ne 'Complete'
        $expectedValidity=if($gap){'Indeterminate'}elseif($Scenario -in @('AbsentPurpose','MissingEku')){'NotApplicable'}elseif($Scenario -in @('Expired','NotYetValid')){'NeedsAttention'}else{'ExpectedCondition'}
        $expectedTrust=if($gap -or $Scenario -eq 'IncompleteChain'){'Indeterminate'}elseif($Scenario -in @('AbsentPurpose','MissingEku')){'NotApplicable'}elseif($Scenario -eq 'Untrusted'){'NeedsAttention'}else{'ExpectedCondition'}
        Assert-Equal $expectedValidity $validity.outcome 'validity interpretation follows only the purpose evidence'
        Assert-Equal $expectedTrust $trust.outcome 'incomplete and untrusted chains remain distinct advisory outcomes'
        foreach($finding in @($validity,$trust)){
            foreach($reference in $finding.evidenceReferences){Assert-Equal $true ($reference.observationId -in $scope.observationIds) 'advisory references never cross into another purpose'}
        }
    }
    foreach($presence in $candidatePresence){
        $observations=@($Record.observations|Where-Object subjectId -eq $presence.subjectId)
        Assert-Equal 12 $observations.Count 'each candidate carries exactly the twelve released fields'
        foreach($observation in $observations){
            $provenance=@($Record.provenance|Where-Object provenanceId -eq $observation.provenanceId)[0]
            Assert-Equal 'source:windows.certificate-store.purpose-selected' $provenance.sourceId 'store source identity survives packaging'
            Assert-Equal 'StandardUser' $provenance.executionContext 'approved machine reads preserve the initiating user context'
            Assert-Equal $observation.subjectId $provenance.subjectId 'source provenance stays with the exact certificate subject'
            Assert-Equal $true $Html.Contains([Net.WebUtility]::HtmlEncode([string]$observation.value)) 'Restricted candidate values reach the protected HTML'
        }
    }
    Assert-Equal $true $Html.Contains('Assessment certificate observations do not configure signing trust or Package Recipient setup.') 'report separates observation from the two setup workflows'
}
