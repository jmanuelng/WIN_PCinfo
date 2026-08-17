[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/AzureValidationAdmission.ps1')
. (Join-Path $repositoryRoot 'src/AzureValidationRound.ps1')

$policy = Get-AzureValidationRoundPolicy
$outcomeSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-outcome.schema.json'
$oneClientPath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-one-client.json'
$plan = Get-Content -LiteralPath $oneClientPath -Raw | ConvertFrom-Json -Depth 20

function New-RoundWorkspace {
    param([Parameter(Mandatory)] [string] $Name)
    $root = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-azure-round-$Name"
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $root -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $root $policy.privacy.markerFileName),
        ($policy.privacy.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $root
}

function Remove-RoundWorkspace {
    param([Parameter(Mandatory)] [string] $Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Invoke-Round {
    param(
        [Parameter(Mandatory)] [string] $Scenario,
        [Parameter(Mandatory)] [string] $WorkspacePath,
        [Parameter()] $PlanObject = $plan
    )

    Invoke-AzureValidationRound -Plan $PlanObject `
        -Scenario $Scenario `
        -PrivateWorkspacePath $WorkspacePath `
        -RepositoryRoot $repositoryRoot `
        -ApplicationDirectory (Join-Path $repositoryRoot 'artifacts')
}

function Assert-PublicOutcome {
    param(
        [Parameter(Mandatory)] $Outcome,
        [Parameter(Mandatory)] [string] $Because,
        [Parameter()] [string] $WorkspacePath
    )

    $json = $Outcome | ConvertTo-Json -Compress -Depth 20
    Assert-Equal $true (Test-Json -Json $json -SchemaFile $outcomeSchemaPath) `
        "$Because outcome satisfies the public sanitized schema"
    Assert-Equal $false $Outcome.sliceDeliversCapability "$Because does not deliver a capability"
    Assert-Equal $false $Outcome.qualifyingEvidence "$Because is not qualifying evidence"
    Assert-Equal $false $Outcome.collectionStarted "$Because never starts assessment collection"
    Assert-Equal 'None' $Outcome.supportClaim "$Because makes no support claim"
    Assert-Equal 'None' $Outcome.previewOrStableClaim "$Because makes no Preview claim"
    Assert-Equal 'ControllerDevTracer' $Outcome.trustClass "$Because stays a controller tracer"
    if (-not [string]::IsNullOrWhiteSpace($WorkspacePath)) {
        Assert-Equal $false ($json -match [regex]::Escape($WorkspacePath)) `
            "$Because omits the private workspace path"
    }
    foreach ($needle in @(
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)gallery'
        '(?i)\.terraform'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)clientSecret'
        '(?i)temporary_admin_password'
        '(?i)\b\d{1,3}(\.\d{1,3}){3}\b'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
        '(?i)synthetic:round'
    )) {
        Assert-Equal $false ($json -match $needle) "$Because must not match $needle"
    }
}

$owned = New-Object System.Collections.Generic.List[string]
try {
    $completeWorkspace = New-RoundWorkspace -Name 'complete'
    $owned.Add($completeWorkspace)
    $complete = Invoke-Round -Scenario CompleteZeroResidue -WorkspacePath $completeWorkspace
    Assert-PublicOutcome $complete 'complete zero residue' -WorkspacePath $completeWorkspace
    Assert-Equal 'ZeroResidueProven' $complete.state 'a complete synthetic round proves zero residue'
    Assert-Equal 'VALIDATION.ZERO_RESIDUE_PROVEN' $complete.reasonCode `
        'the success reason is stable'
    Assert-Equal $true $complete.admitted 'complete rounds pass cleanup-first admission'
    Assert-Equal $true $complete.created 'complete rounds create the admitted client'
    Assert-Equal $true $complete.guestReady 'complete rounds wait for VM Agent readiness'
    Assert-Equal $true $complete.candidateVerified 'the guest reverifies the candidate'
    Assert-Equal $true $complete.payloadVerified 'the guest reverifies the payload manifest'
    Assert-Equal $true $complete.localOnlyChecked 'Local Only is checked inside the guest'
    Assert-Equal $true $complete.approvedEgressChecked 'approved egress is checked inside the guest'
    Assert-Equal $true $complete.assessmentExecuted 'the admitted candidate is executed'
    Assert-Equal $true $complete.sanitizedRetrieval 'only sanitized output returns'
    Assert-Equal $true $complete.cleanupFirst 'admission remains cleanup-first'
    Assert-Equal $true $complete.teardownCompleted 'teardown finished'
    Assert-Equal $true $complete.zeroResidue 'zero residue is independently true'
    Assert-Equal $true $complete.terraformStateRemoved 'state is removed only after zero residue'
    Assert-Equal $true $complete.nextRoundEligible 'the next round becomes eligible'
    Assert-Equal $true $complete.persistentScopePreserved 'persistent controls remain'
    Assert-Equal $true $complete.hostPeeringAbsent 'both round-owned peerings are absent'
    Assert-Equal $true $complete.tagSweepEmpty 'the tag sweep is empty'
    Assert-Equal $true $complete.unprotectedLocalMaterialAbsent `
        'unprotected local working material is absent'
    Assert-Equal 'VmAgentRunCommand' $complete.guestControl 'guest control stays on VM Agent'
    Assert-Equal $false $complete.bootstrapCredentialExposed 'no bootstrap credential is returned'
    Assert-Equal $false $complete.clientCapturedOrReused 'the client is not captured or reused'
    Assert-Equal $false $complete.vmPublicIpAssigned 'no VM public IP is assigned'
    Assert-Equal $true $complete.freshApprovedBaseline 'the client is a fresh approved baseline'
    Assert-Equal 1 $complete.clientCount 'one Windows 11 client is recorded'
    Assert-Equal $true $complete.windows11ClaimingRoute 'the claiming route is recorded'
    Assert-Equal $true $complete.synthetic 'the complete path is the synthetic controller'
    Assert-Equal 'Synthetic' $complete.platformKind 'the complete path uses the synthetic platform'
    Assert-Equal $true $complete.azureContacted 'the controller invoked the platform'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $completeWorkspace "$($policy.workspace.workingDirectoryName)"
    )) 'complete rounds remove unprotected working material'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $completeWorkspace "$($policy.workspace.recoveryDirectoryName)"
    )) 'recovery material is removed after zero residue'
    Assert-Equal $true (Test-Path -LiteralPath (
        Join-Path $completeWorkspace $policy.privacy.markerFileName
    )) 'the private workspace marker remains'

    $cleanupWorkspace = New-RoundWorkspace -Name 'cleanup-first'
    $owned.Add($cleanupWorkspace)
    $cleanupFirst = Invoke-Round -Scenario CleanupFirst -WorkspacePath $cleanupWorkspace
    Assert-PublicOutcome $cleanupFirst 'cleanup-first admission' -WorkspacePath $cleanupWorkspace
    Assert-Equal 'ZeroResidueProven' $cleanupFirst.state `
        'leftover residue is cleaned before a new create'
    Assert-Equal $true $cleanupFirst.cleanupFirst 'cleanup-first ran before creation'
    Assert-Equal $true $cleanupFirst.created 'cleanup-first still creates the admitted client'
    Assert-Equal $true $cleanupFirst.zeroResidue 'cleanup-first still ends at zero residue'

    $failedWorkspace = New-RoundWorkspace -Name 'assessment-failed'
    $owned.Add($failedWorkspace)
    $failed = Invoke-Round -Scenario AssessmentFailed -WorkspacePath $failedWorkspace
    Assert-PublicOutcome $failed 'assessment failure still cleans up' -WorkspacePath $failedWorkspace
    Assert-Equal 'FailedCleaned' $failed.state 'a product failure is not reported as success'
    Assert-Equal 'VALIDATION.ASSESSMENT_FAILED' $failed.reasonCode `
        'the product-failure reason is stable'
    Assert-Equal $true $failed.created 'the failed assessment still created the client'
    Assert-Equal $true $failed.assessmentExecuted 'the failed assessment still executed'
    Assert-Equal $true $failed.teardownCompleted 'a product failure still tears down'
    Assert-Equal $true $failed.zeroResidue 'a product failure still reaches zero residue'
    Assert-Equal $true $failed.terraformStateRemoved `
        'state is still removed after a cleaned product failure'
    Assert-Equal $true $failed.nextRoundEligible `
        'the next round is eligible after a cleaned product failure'

    $identityWorkspace = New-RoundWorkspace -Name 'identity'
    $owned.Add($identityWorkspace)
    $identity = Invoke-Round -Scenario IdentityUnavailable -WorkspacePath $identityWorkspace
    Assert-PublicOutcome $identity 'identity unavailable' -WorkspacePath $identityWorkspace
    Assert-Equal 'Blocked' $identity.state 'missing identity stays blocked'
    Assert-Equal 'VALIDATION.IDENTITY_UNAVAILABLE' $identity.reasonCode `
        'missing identity uses a typed reason'
    Assert-Equal $false $identity.created 'missing identity never creates a client'
    Assert-Equal $false $identity.azureContacted 'missing identity does not contact Azure'
    Assert-Equal 'Unavailable' $identity.platformKind 'missing identity is Unavailable'
    Assert-Equal $false $identity.nextRoundEligible `
        'a blocked admission does not unlock the next round by inventing success'

    $deniedWorkspace = New-RoundWorkspace -Name 'denied'
    $owned.Add($deniedWorkspace)
    $denied = Invoke-Round -Scenario AdmissionDenied -WorkspacePath $deniedWorkspace
    Assert-PublicOutcome $denied 'admission denied' -WorkspacePath $deniedWorkspace
    Assert-Equal 'Rejected' $denied.state 'a failed live probe rejects before create'
    Assert-Equal 'VALIDATION.LOCKS_PRESENT' $denied.reasonCode `
        'the representative admission denial names the failed probe'
    Assert-Equal $false $denied.created 'a failed live probe never creates a client'
    Assert-Equal $false $denied.terraformStateRemoved `
        'no Terraform state is invented for a rejected admission'

    $probeReasons = [ordered]@{
        Identity = 'VALIDATION.IDENTITY_UNAVAILABLE'
        Policy = 'VALIDATION.POLICY_DENIED'
        Locks = 'VALIDATION.LOCKS_PRESENT'
        Quota = 'VALIDATION.QUOTA_EXCEEDED'
        Image = 'VALIDATION.IMAGE_UNSAFE'
        Sku = 'VALIDATION.SKU_UNSAFE'
        StandardSsd = 'VALIDATION.DISK_UNSAFE'
        Tags = 'VALIDATION.TAGS_MISSING'
        Expiry = 'VALIDATION.LIFETIME_UNSAFE'
        SubnetCapacity = 'VALIDATION.SUBNET_CAPACITY_UNSAFE'
        VmCount = 'VALIDATION.VM_COUNT_UNSAFE'
        CleanupRights = 'VALIDATION.CLEANUP_RIGHTS_MISSING'
        ExclusiveLease = 'VALIDATION.LEASE_UNAVAILABLE'
        ArmedRecovery = 'VALIDATION.RECOVERY_NOT_ARMED'
    }
    foreach ($probeName in @($probeReasons.Keys)) {
        $probeWorkspace = New-RoundWorkspace -Name ("probe-" + $probeName.ToLowerInvariant())
        $owned.Add($probeWorkspace)
        $platform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
        $platform.Probes[$probeName] = $false
        $probeOutcome = Invoke-AzureValidationRound -Plan $plan `
            -Scenario CompleteZeroResidue `
            -PrivateWorkspacePath $probeWorkspace `
            -RepositoryRoot $repositoryRoot `
            -ApplicationDirectory (Join-Path $repositoryRoot 'artifacts') `
            -Platform $platform
        Assert-PublicOutcome $probeOutcome "probe $probeName" -WorkspacePath $probeWorkspace
        Assert-Equal $probeReasons[$probeName] $probeOutcome.reasonCode `
            "failing $probeName uses its typed reason"
        Assert-Equal $false $probeOutcome.created "failing $probeName never creates a client"
    }

    $scopeWorkspace = New-RoundWorkspace -Name 'scope-not-empty'
    $owned.Add($scopeWorkspace)
    $scopePlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    $scopePlatform.Probes['EmptyTransientScope'] = $false
    $scopePlatform.CleanupFirstSucceeds = $false
    $scopeOutcome = Invoke-AzureValidationRound -Plan $plan `
        -Scenario CompleteZeroResidue `
        -PrivateWorkspacePath $scopeWorkspace `
        -RepositoryRoot $repositoryRoot `
        -ApplicationDirectory (Join-Path $repositoryRoot 'artifacts') `
        -Platform $scopePlatform
    Assert-Equal 'VALIDATION.TRANSIENT_SCOPE_NOT_EMPTY' $scopeOutcome.reasonCode `
        'an uncleared transient scope blocks creation'
    Assert-Equal $false $scopeOutcome.created 'an uncleared transient scope never creates'

    $residueWorkspace = New-RoundWorkspace -Name 'residue'
    $owned.Add($residueWorkspace)
    $residue = Invoke-Round -Scenario ResidueRemains -WorkspacePath $residueWorkspace
    Assert-PublicOutcome $residue 'residue remains' -WorkspacePath $residueWorkspace
    Assert-Equal 'ResidueRemains' $residue.state 'leftover targets cannot be reported complete'
    Assert-Equal 'VALIDATION.RESIDUE_REMAINS' $residue.reasonCode `
        'remaining residue uses a typed reason'
    Assert-Equal $true $residue.created 'the residue scenario did create the client'
    Assert-Equal $false $residue.zeroResidue 'remaining residue is not zero residue'
    Assert-Equal $false $residue.terraformStateRemoved `
        'private Terraform state is kept until residue is gone'
    Assert-Equal $false $residue.nextRoundEligible `
        'the next round stays blocked while residue remains'
    Assert-Equal $true $residue.persistentScopePreserved `
        'persistent controls are not deleted to chase residue'

    $captureWorkspace = New-RoundWorkspace -Name 'capture'
    $owned.Add($captureWorkspace)
    $capture = Invoke-Round -Scenario CaptureAttempted -WorkspacePath $captureWorkspace
    Assert-PublicOutcome $capture 'capture attempted' -WorkspacePath $captureWorkspace
    Assert-Equal 'VALIDATION.CLIENT_CAPTURE_PROHIBITED' $capture.reasonCode `
        'capture or reuse is rejected'
    Assert-Equal $true $capture.clientCapturedOrReused `
        'the controller records the capture attempt without keeping the client'
    Assert-Equal $true $capture.teardownCompleted 'a capture attempt still tears down'
    Assert-Equal $true $capture.zeroResidue 'a rejected capture still reaches zero residue'

    $secretWorkspace = New-RoundWorkspace -Name 'credential'
    $owned.Add($secretWorkspace)
    $secret = Invoke-Round -Scenario CredentialExposed -WorkspacePath $secretWorkspace
    Assert-PublicOutcome $secret 'credential exposed' -WorkspacePath $secretWorkspace
    Assert-Equal 'VALIDATION.BOOTSTRAP_CREDENTIAL_EXPOSED' $secret.reasonCode `
        'an offered bootstrap password is rejected'
    Assert-Equal $true $secret.bootstrapCredentialExposed `
        'the controller records the exposure attempt without keeping the password'
    Assert-Equal $true $secret.teardownCompleted 'a credential exposure still tears down'
    Assert-Equal $true $secret.zeroResidue 'a credential exposure still reaches zero residue'

    $live = Test-AzureValidationRoundLiveIdentity
    Assert-Equal $false $live.Available 'this controller host has no approved managed identity'
    $liveWorkspace = New-RoundWorkspace -Name 'live'
    $owned.Add($liveWorkspace)
    $liveOutcome = Invoke-AzureValidationRound -Plan $plan `
        -PrivateWorkspacePath $liveWorkspace `
        -RepositoryRoot $repositoryRoot `
        -ApplicationDirectory (Join-Path $repositoryRoot 'artifacts')
    Assert-PublicOutcome $liveOutcome 'live identity unavailable' -WorkspacePath $liveWorkspace
    Assert-Equal 'Blocked' $liveOutcome.state 'live Azure without identity stays blocked'
    Assert-Equal 'VALIDATION.IDENTITY_UNAVAILABLE' $liveOutcome.reasonCode `
        'live Azure without identity uses the typed reason'
    Assert-Equal $false $liveOutcome.created 'live Azure without identity never creates'
    Assert-Equal $false $liveOutcome.synthetic 'the live path is not a synthetic fixture'
    Assert-Equal 'Unavailable' $liveOutcome.platformKind 'the live path is Unavailable'
    Assert-Equal $false $liveOutcome.azureContacted 'the live path does not contact Azure'

    $repoWorkspace = Join-Path $repositoryRoot '.test-output/azure-validation-round-forbidden'
    if (Test-Path -LiteralPath $repoWorkspace) {
        Remove-Item -LiteralPath $repoWorkspace -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $repoWorkspace -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $repoWorkspace $policy.privacy.markerFileName),
        ($policy.privacy.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $repoOutcome = Invoke-Round -Scenario CompleteZeroResidue -WorkspacePath $repoWorkspace
    Assert-Equal 'VALIDATION.WORKSPACE_REPOSITORY_PATH' $repoOutcome.reasonCode `
        'an in-repository workspace is rejected'
    Assert-Equal $false $repoOutcome.created 'an in-repository workspace never creates'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $repoWorkspace $policy.workspace.workingDirectoryName
    )) 'an in-repository workspace is not used as round working material'
    Remove-Item -LiteralPath $repoWorkspace -Recurse -Force
}
finally {
    foreach ($path in $owned) {
        Remove-RoundWorkspace $path
    }
}

Write-Output 'PASS: Azure validation-round controller proves admission, guest control, cleanup, and zero residue.'
