[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/CertificateTrust.ps1')
$json = Get-Command ConvertFrom-Json -CommandType Cmdlet
$policy = Get-CertificateTrustPolicy -ConvertFromJsonCommand $json

$workerSource=Get-CertificateTrustLiveSource -Policy $policy
$workerPurposeProjection=@($policy.purposes|ForEach-Object {[pscustomobject][ordered]@{
    purposeId=[string]$_.purposeId;scopeId=[string]$_.scopeId
    stores=@($_.stores|ForEach-Object {[string]$_});ekuOids=@($_.ekuOids|ForEach-Object {[string]$_})
}})
$workerPurposeJson=$workerPurposeProjection|ConvertTo-Json -Compress -Depth 5
$workerPurposeBase64=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($workerPurposeJson))
Assert-Equal $true $workerSource.Contains($workerPurposeBase64) `
    'the live worker receives its exact purpose, store, and EKU table from the validated release policy'
Assert-Equal $false $workerSource.Contains("purposeId='Management'") `
    'the live worker does not duplicate release configuration in source code'

$nonExportableProbe=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa)
try{
    Assert-Equal ([Security.Cryptography.CngExportPolicies]::None) $nonExportableProbe.ExportPolicy `
        'the test-only Windows provider fixture proves the non-exportable policy state'
    Assert-Equal $true $nonExportableProbe.IsEphemeral `
        'the test-only key-provider proof is never persisted'
}finally{$nonExportableProbe.Dispose()}

$notTimeValid=[Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid
$partialChain=[Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain
$leafTimeOnly=Resolve-CertificateTrustChainObservation -BuildSucceeded $false `
    -LeafStatusFlags @($notTimeValid) -IssuerStatusFlags @()
Assert-Equal 'Complete' $leafTimeOnly.chainState `
    'leaf time validity does not erase evidence that the chain is complete'
Assert-Equal 'Trusted' $leafTimeOnly.trustState `
    'leaf time validity is evaluated separately from local trust'
$issuerTimeFailure=Resolve-CertificateTrustChainObservation -BuildSucceeded $false `
    -LeafStatusFlags @() -IssuerStatusFlags @($notTimeValid)
Assert-Equal 'Untrusted' $issuerTimeFailure.trustState `
    'an issuer time failure remains material to the chain trust result'
$ignoredIssuerTimeFailure=Resolve-CertificateTrustChainObservation -BuildSucceeded $true `
    -LeafStatusFlags @() -IssuerStatusFlags @($notTimeValid)
Assert-Equal 'Untrusted' $ignoredIssuerTimeFailure.trustState `
    'verification flags cannot hide an issuer time failure from trust interpretation'
$incompleteChain=Resolve-CertificateTrustChainObservation -BuildSucceeded $false `
    -LeafStatusFlags @($partialChain) -IssuerStatusFlags @()
Assert-Equal 'Incomplete' $incompleteChain.chainState `
    'partial-chain status remains distinct from untrusted complete chains'
Assert-Equal 'Indeterminate' $incompleteChain.trustState `
    'an incomplete chain cannot claim a local trust result'

$cases = @(
    @{ scenario='ValidTrusted'; candidates=1; state='Completed' },
    @{ scenario='Expired'; candidates=1; state='Completed' },
    @{ scenario='NotYetValid'; candidates=1; state='Completed' },
    @{ scenario='Untrusted'; candidates=1; state='Completed' },
    @{ scenario='IncompleteChain'; candidates=1; state='Completed' },
    @{ scenario='MultipleCandidates'; candidates=2; state='Completed' },
    @{ scenario='InaccessibleStore'; candidates=0; state='CompletedWithGaps' },
    @{ scenario='AbsentPurpose'; candidates=0; state='Completed' },
    @{ scenario='NonExportableKey'; candidates=1; state='Completed' },
    @{ scenario='AlternateAdministrator'; candidates=0; state='CompletedWithGaps' },
    @{ scenario='VirtualDevice'; candidates=1; state='Completed' },
    @{ scenario='MalformedCertificate'; candidates=0; state='CompletedWithGaps' }
)
foreach ($case in $cases) {
    $result = Invoke-CertificateTrustCollection -Policy $policy -ValidationScenario $case.scenario
    Assert-Equal $true (Test-CertificateTrustPayload -Payload $result.payload -Policy $policy) `
        "$($case.scenario) satisfies the closed payload contract"
    Assert-Equal $case.candidates @($result.payload.candidates).Count `
        "$($case.scenario) preserves the expected bounded candidate count"
    Assert-Equal $case.state $result.state `
        "$($case.scenario) makes incomplete collection explicit"
    Assert-Equal $false $result.payload.privateMaterialAccessed `
        "$($case.scenario) never accesses reusable private material"
    Assert-Equal $false $result.payload.storeChanged `
        "$($case.scenario) never changes a certificate store or trust setting"
}

$expired = (Invoke-CertificateTrustCollection -Policy $policy -ValidationScenario Expired).payload.candidates[0]
Assert-Equal 'Expired' $expired.validityState 'validity is separate from chain and trust state'
Assert-Equal 'Complete' $expired.chainState 'an expired certificate can still have a complete chain'
Assert-Equal 'Trusted' $expired.trustState 'an expired certificate can still anchor in local trust'

$incomplete = (Invoke-CertificateTrustCollection -Policy $policy -ValidationScenario IncompleteChain).payload.candidates[0]
Assert-Equal 'Management' $incomplete.purposeId `
    'incomplete-chain evidence is bound to a purpose with a released store'
Assert-Equal 'Valid' $incomplete.validityState 'a currently valid certificate can have incomplete chain evidence'
Assert-Equal 'Incomplete' $incomplete.chainState 'chain completeness remains its own state'
Assert-Equal 'Indeterminate' $incomplete.trustState 'an incomplete chain cannot be presented as trusted or untrusted'

$nonExportable = (Invoke-CertificateTrustCollection -Policy $policy -ValidationScenario NonExportableKey).payload.candidates[0]
Assert-Equal 'NonExportable' $nonExportable.keyProtectionState `
    'synthetic evidence can prove non-exportability without containing key material'

$deviceIdentity = (Invoke-CertificateTrustCollection -Policy $policy -ValidationScenario Untrusted).payload.candidates[0]
Assert-Equal 'LocalMachine' $deviceIdentity.storeLocation `
    'device identity evidence stays in the released machine-store boundary'
Assert-Equal 'My' $deviceIdentity.storeName 'device identity evidence stays in the personal store'
$codeTrust = (Invoke-CertificateTrustCollection -Policy $policy -ValidationScenario MultipleCandidates).payload
Assert-Equal 2 @($codeTrust.candidates).Count 'the multiple-candidate scenario preserves both sources'
Assert-Equal 2 @($codeTrust.candidates | Where-Object storeName -eq TrustedPublisher).Count `
    'code-trust candidates cannot be mislabeled as personal-store evidence'
$partialCodeTrust=New-CertificateTrustSyntheticPayload -Scenario MultipleCandidates -Policy $policy
$partialCodeTrust.scopeStates|Where-Object scopeId -eq 'scope:certificate.code-trust'|ForEach-Object {$_.state='Partial';$_.reasonCode='CERTIFICATE.STORE_ACCESS_PARTIAL'}
Assert-Equal $true (Test-CertificateTrustPayload -Payload $partialCodeTrust -Policy $policy) `
    'successful evidence from one CodeTrust store remains admissible when another store fails'

$projection = New-CertificateTrustPublicProjection -CollectorResult (
    Invoke-CertificateTrustCollection -Policy $policy -ValidationScenario MultipleCandidates
)
Assert-Equal 2 $projection.certificateCandidateCount 'the public projection contains counts, not identities'
Assert-Equal $false $projection.certificateIdentifiersPublished 'certificate identities and fingerprints remain Restricted'
Assert-Equal $false $projection.privateMaterialPublished 'private material is neither collected nor published'
Assert-Equal $false $projection.certificateStoreChanged 'public evidence confirms the observation-only boundary'

$unexpectedPrivateMaterial = New-CertificateTrustSyntheticPayload -Scenario ValidTrusted -Policy $policy
$unexpectedPrivateMaterial.candidates[0] | Add-Member -NotePropertyName privateKey -NotePropertyValue 'prohibited'
Assert-Equal $false (Test-CertificateTrustPayload -Payload $unexpectedPrivateMaterial -Policy $policy) `
    'a private-key-shaped payload extension is rejected by the exact candidate schema'

$unexpectedTopLevel = New-CertificateTrustSyntheticPayload -Scenario ValidTrusted -Policy $policy
$unexpectedTopLevel | Add-Member -NotePropertyName pfxData -NotePropertyValue 'prohibited'
Assert-Equal $false (Test-CertificateTrustPayload -Payload $unexpectedTopLevel -Policy $policy) `
    'a PFX-shaped payload extension is rejected by the exact top-level schema'

$wrongPurposeStore = New-CertificateTrustSyntheticPayload -Scenario Untrusted -Policy $policy
$wrongPurposeStore.candidates[0].storeLocation = 'CurrentUser'
Assert-Equal $false (Test-CertificateTrustPayload -Payload $wrongPurposeStore -Policy $policy) `
    'a globally valid store cannot be relabeled as the wrong purpose source'

$invalidUser = Invoke-CertificateTrustCollection -Policy $policy -Live -AssessmentUserSid 'not-a-sid'
Assert-Equal 'CompletedWithGaps' $invalidUser.state `
    'an unverifiable Assessment User fails safely before a store is opened'
Assert-Equal 6 @($invalidUser.payload.scopeStates | Where-Object state -eq Unavailable).Count `
    'all purpose scopes retain explicit coverage when the user context is unavailable'

$runId='00000000-0000-4000-8000-000000000062'
$scopedRecord=[pscustomobject][ordered]@{
    run=[pscustomobject][ordered]@{runId=$runId;evidenceProfileId=[string]$policy.evidenceProfileId;outcome='Completed'}
    coverage=@(
        [pscustomobject]@{scopeId='scope:certificate.management';state='Denied';reasonCode='CERTIFICATE.STORE_ACCESS_DENIED';observationIds=@()},
        [pscustomobject]@{scopeId='scope:certificate.authentication';state='Complete';observationIds=@('observation:authentication-presence','observation:authentication-validity','observation:authentication-chain','observation:authentication-trust','observation:authentication-key')},
        [pscustomobject]@{scopeId='scope:certificate.device-identity';state='NotApplicable';observationIds=@()},
        [pscustomobject]@{scopeId='scope:certificate.code-trust';state='NotApplicable';observationIds=@()},
        [pscustomobject]@{scopeId='scope:certificate.tls-inspection';state='NotApplicable';observationIds=@()},
        [pscustomobject]@{scopeId='scope:certificate.service-connectivity';state='NotApplicable';observationIds=@()}
    )
    observations=@(
        [pscustomobject]@{observationId='observation:authentication-presence';fieldId='field:certificate.presence';subjectId='subject:certificate:authentication';valueState='ObservedValue';value=$true},
        [pscustomobject]@{observationId='observation:authentication-validity';fieldId='field:certificate.validity-state';subjectId='subject:certificate:authentication';valueState='ObservedValue';value='Expired'},
        [pscustomobject]@{observationId='observation:authentication-chain';fieldId='field:certificate.chain-state';subjectId='subject:certificate:authentication';valueState='ObservedValue';value='Complete'},
        [pscustomobject]@{observationId='observation:authentication-trust';fieldId='field:certificate.trust-state';subjectId='subject:certificate:authentication';valueState='ObservedValue';value='Trusted'},
        [pscustomobject]@{observationId='observation:authentication-key';fieldId='field:certificate.key-protection-state';subjectId='subject:certificate:authentication';valueState='ObservedValue';value='NonExportable'}
    )
    findings=@();recommendations=@()
}
$scopedRecord=Complete-ValidatedCertificateTrustAssessmentRecord -Record $scopedRecord -Policy $policy `
    -ContractValidation ([pscustomobject]@{accepted=$true;reasonCode='CONTRACT.ACCEPTED'})
$authenticationValidity=@($scopedRecord.findings|Where-Object findingId -eq "finding:certificate-validity-authentication:$runId")[0]
Assert-Equal 'NeedsAttention' $authenticationValidity.outcome `
    'an expired authentication certificate remains actionable despite an unrelated management gap'
Assert-Equal 'observation:authentication-validity' $authenticationValidity.evidenceReferences[0].observationId `
    'purpose findings reference only evidence declared for that purpose coverage'

$notApplicableRecord=[pscustomobject][ordered]@{
    run=[pscustomobject][ordered]@{runId=$runId;evidenceProfileId=[string]$policy.evidenceProfileId;outcome='Completed'}
    coverage=@($policy.purposes|ForEach-Object {[pscustomobject]@{scopeId=[string]$_.scopeId;state='NotApplicable';observationIds=@()}})
    observations=@();findings=@();recommendations=@()
}
$notApplicableRecord=Complete-ValidatedCertificateTrustAssessmentRecord -Record $notApplicableRecord `
    -Policy $policy -ContractValidation ([pscustomobject]@{accepted=$true;reasonCode='CONTRACT.ACCEPTED'})
Assert-Equal 'CompletedWithGaps' $notApplicableRecord.run.outcome `
    'NotApplicable purpose coverage remains a run-level gap under the canonical contract'

Write-Output 'PASS: Certificate Trust preserves purpose, state separation, privacy, bounds, and safe failure.'
