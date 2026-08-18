# Build.ps1 replaces both sentinels with the release-bound validation-round
# policy and its SHA-256 digest. The generated application treats that table
# as the only trusted copy of the controller contract.
$script:AzureValidationRoundPolicyBase64 = '__AZURE_VALIDATION_ROUND_POLICY_BASE64__'
$script:AzureValidationRoundPolicyDigest = '__AZURE_VALIDATION_ROUND_POLICY_SHA256__'

function Get-AzureValidationRoundSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-AzureValidationRoundPolicy {
    # The threat is a substituted policy that waives Zero Round Residue,
    # allows a public IP, or treats this tracer as qualifying Preview
    # evidence. The mechanism is an embedded digest, or the reviewed
    # repository file when this module is sourced during development. The
    # trust assumption is that those bytes were reviewed with the rest of
    # the release. Safe failure is to refuse the round rather than invent a
    # looser contract.
    if ($script:AzureValidationRoundPolicyBase64 -eq
        ('__AZURE_VALIDATION_ROUND_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-azure-validation-round.json'
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-AzureValidationRoundSha256 $bytes
    }
    else {
        [byte[]] $bytes = [System.Convert]::FromBase64String(
            $script:AzureValidationRoundPolicyBase64
        )
        $expectedDigest = $script:AzureValidationRoundPolicyDigest
    }
    if ((Get-AzureValidationRoundSha256 $bytes) -ne $expectedDigest) {
        throw 'The Azure validation-round policy failed its embedded digest check.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $json | ConvertFrom-Json -Depth 20
}

function Get-AzureValidationRoundCatalogPath {
    param(
        [Parameter()] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] [string] $RelativePath
    )

    # The generated application test and a portable extract may sit two
    # folders below the reviewed schemas. Walk a bounded ancestor list
    # rather than treating a missing sidecar as a valid fixture.
    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($start in @($ApplicationDirectory, $RepositoryRoot)) {
        if ([string]::IsNullOrWhiteSpace($start)) {
            continue
        }
        $cursor = $start
        for ($i = 0; $i -lt 4; $i++) {
            if (-not $roots.Contains($cursor)) {
                $null = $roots.Add($cursor)
            }
            $parent = Split-Path -Parent $cursor
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
                break
            }
            $cursor = $parent
        }
    }
    foreach ($root in $roots) {
        $candidate = Join-Path $root $RelativePath
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    $null
}

function Test-AzureValidationRoundPrivacyBoundary {
    param([Parameter(Mandatory)] [string] $Text)

    # Public round output is a projection, not a dump. The threat is
    # printing a subscription, gallery ID, bootstrap password, or local
    # user path. The mechanism is a closed needle list applied to the raw
    # request or fixture before any platform work. The trust assumption is
    # that approved fixtures stay synthetic. Safe failure is PRIVACY_REJECTED.
    $needles = @(
        '(?i)clientSecret'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)(password|secret|api[_-]?key|access_token)\s*[:=]'
        '(?i)temporary_admin_password'
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)\.terraform'
        '(?i)\.tfstate'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
        '(?i)\b\d{1,3}(\.\d{1,3}){3}\b'
        '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
    )
    foreach ($needle in $needles) {
        if ($Text -match $needle) {
            return 'VALIDATION.PRIVACY_REJECTED'
        }
    }
    $null
}

function Get-AzureValidationRoundProbeReason {
    param([Parameter(Mandatory)] [string] $Probe)

    switch ($Probe) {
        'Identity' { 'VALIDATION.IDENTITY_UNAVAILABLE' }
        'Policy' { 'VALIDATION.POLICY_DENIED' }
        'Locks' { 'VALIDATION.LOCKS_PRESENT' }
        'Quota' { 'VALIDATION.QUOTA_EXCEEDED' }
        'Image' { 'VALIDATION.IMAGE_UNSAFE' }
        'Sku' { 'VALIDATION.SKU_UNSAFE' }
        'StandardSsd' { 'VALIDATION.DISK_UNSAFE' }
        'Tags' { 'VALIDATION.TAGS_MISSING' }
        'Expiry' { 'VALIDATION.LIFETIME_UNSAFE' }
        'SubnetCapacity' { 'VALIDATION.SUBNET_CAPACITY_UNSAFE' }
        'VmCount' { 'VALIDATION.VM_COUNT_UNSAFE' }
        'CleanupRights' { 'VALIDATION.CLEANUP_RIGHTS_MISSING' }
        'EmptyTransientScope' { 'VALIDATION.TRANSIENT_SCOPE_NOT_EMPTY' }
        'ExclusiveLease' { 'VALIDATION.LEASE_UNAVAILABLE' }
        'ArmedRecovery' { 'VALIDATION.RECOVERY_NOT_ARMED' }
        default { 'VALIDATION.PLAN_UNSAFE' }
    }
}

function Get-AzureValidationRoundRecordedClientCount {
    param([Parameter()] $Count)

    if ($null -eq $Count) {
        return $null
    }
    $value = [int] $Count
    if ($value -ge 0 -and $value -le 4) {
        return $value
    }
    $null
}

function New-AzureValidationRoundOutcome {
    param(
        [Parameter(Mandatory)] [ValidateSet(
            'ZeroResidueProven', 'FailedCleaned', 'Rejected', 'Blocked', 'ResidueRemains'
        )] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [bool] $Admitted = $false,
        [Parameter()] [bool] $Created = $false,
        [Parameter()] [bool] $GuestReady = $false,
        [Parameter()] [bool] $CandidateVerified = $false,
        [Parameter()] [bool] $PayloadVerified = $false,
        [Parameter()] [bool] $LocalOnlyChecked = $false,
        [Parameter()] [bool] $ApprovedEgressChecked = $false,
        [Parameter()] [bool] $AssessmentExecuted = $false,
        [Parameter()] [bool] $SanitizedRetrieval = $false,
        [Parameter()] [bool] $CleanupFirst = $false,
        [Parameter()] [bool] $TeardownCompleted = $false,
        [Parameter()] [bool] $ZeroResidue = $false,
        [Parameter()] [bool] $TerraformStateRemoved = $false,
        [Parameter()] [bool] $NextRoundEligible = $false,
        [Parameter()] [bool] $PersistentScopePreserved = $true,
        [Parameter()] [bool] $HostPeeringAbsent = $false,
        [Parameter()] [bool] $TagSweepEmpty = $false,
        [Parameter()] [bool] $UnprotectedLocalMaterialAbsent = $false,
        [Parameter()] [ValidateSet('VmAgentRunCommand', 'None')]
        [string] $GuestControl = 'None',
        [Parameter()] [bool] $BootstrapCredentialExposed = $false,
        [Parameter()] [bool] $ClientCapturedOrReused = $false,
        [Parameter()] [bool] $VmPublicIpAssigned = $false,
        [Parameter()] [bool] $FreshApprovedBaseline = $false,
        [Parameter()] [Nullable[int]] $ClientCount,
        [Parameter()] [bool] $Windows11ClaimingRoute = $false,
        [Parameter()] [ValidateSet('ControllerDevTracer', 'None')]
        [string] $TrustClass = 'ControllerDevTracer',
        [Parameter()] [bool] $Synthetic = $false,
        [Parameter()] [ValidateSet('Synthetic', 'ManagedIdentity', 'Unavailable')]
        [string] $PlatformKind = 'Unavailable',
        [Parameter()] [bool] $AzureContacted = $false,
        [Parameter()] [ValidateSet('PrivateExternalWorkspace', 'Missing', 'Rejected')]
        [string] $PrivacyBoundary = 'Rejected',
        [Parameter()] [ValidateSet('None', 'RoundCleanupMode', 'CleanupPending')]
        [string] $CleanupMode = 'None',
        [Parameter()] [bool] $Cancelled = $false,
        [Parameter()] [ValidateSet(
            'None', 'Create', 'Readiness', 'Transfer', 'Execution', 'Retrieval', 'Teardown'
        )] [string] $CancelPhase = 'None',
        [Parameter()] [bool] $ExpiryReached = $false,
        [Parameter()] [bool] $CleanupReserveActive = $false,
        [Parameter()] [int] $HardExpiryMinutes = 360,
        [Parameter()] [Nullable[int]] $CleanupReserveMinutes,
        [Parameter()] [bool] $NewTestsStopped = $false,
        [Parameter()] [bool] $EvidenceExportStopped = $false,
        [Parameter()] [bool] $ExclusiveLeaseHeld = $false,
        [Parameter()] [Nullable[int]] $LiveTaggedVmCount,
        [Parameter()] [bool] $ResultingTotalExceedsMaximum = $false,
        [Parameter()] [bool] $RecoveryIndependent = $false,
        [Parameter()] [bool] $UnresolvedTargetPreserved = $false,
        [Parameter()] [bool] $UnrelatedTargetPreserved = $false,
        [Parameter()] [bool] $CleanupPending = $false,
        [Parameter()] [bool] $OperationsRecordRetained = $false,
        [Parameter()] [int] $CompletedRecordRetentionDays = 7,
        [Parameter()] [bool] $DocumentedIncident = $false
    )

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.azure-validation-round'
        contractVersion = '1.0.0'
        state = $State
        reasonCode = $ReasonCode
        admitted = [bool] $Admitted
        created = [bool] $Created
        guestReady = [bool] $GuestReady
        candidateVerified = [bool] $CandidateVerified
        payloadVerified = [bool] $PayloadVerified
        localOnlyChecked = [bool] $LocalOnlyChecked
        approvedEgressChecked = [bool] $ApprovedEgressChecked
        assessmentExecuted = [bool] $AssessmentExecuted
        sanitizedRetrieval = [bool] $SanitizedRetrieval
        cleanupFirst = [bool] $CleanupFirst
        teardownCompleted = [bool] $TeardownCompleted
        zeroResidue = [bool] $ZeroResidue
        terraformStateRemoved = [bool] $TerraformStateRemoved
        nextRoundEligible = [bool] $NextRoundEligible
        persistentScopePreserved = [bool] $PersistentScopePreserved
        hostPeeringAbsent = [bool] $HostPeeringAbsent
        tagSweepEmpty = [bool] $TagSweepEmpty
        unprotectedLocalMaterialAbsent = [bool] $UnprotectedLocalMaterialAbsent
        guestControl = $GuestControl
        bootstrapCredentialExposed = [bool] $BootstrapCredentialExposed
        clientCapturedOrReused = [bool] $ClientCapturedOrReused
        vmPublicIpAssigned = [bool] $VmPublicIpAssigned
        freshApprovedBaseline = [bool] $FreshApprovedBaseline
        clientCount = (Get-AzureValidationRoundRecordedClientCount -Count $ClientCount)
        windows11ClaimingRoute = [bool] $Windows11ClaimingRoute
        trustClass = $TrustClass
        qualifyingEvidence = $false
        sliceDeliversCapability = $false
        collectionStarted = $false
        synthetic = [bool] $Synthetic
        platformKind = $PlatformKind
        azureContacted = [bool] $AzureContacted
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        privacyBoundary = $PrivacyBoundary
        cleanupMode = $CleanupMode
        cancelled = [bool] $Cancelled
        cancelPhase = $CancelPhase
        expiryReached = [bool] $ExpiryReached
        cleanupReserveActive = [bool] $CleanupReserveActive
        hardExpiryMinutes = 360
        cleanupReserveMinutes = $CleanupReserveMinutes
        newTestsStopped = [bool] $NewTestsStopped
        evidenceExportStopped = [bool] $EvidenceExportStopped
        exclusiveLeaseHeld = [bool] $ExclusiveLeaseHeld
        liveTaggedVmCount = $LiveTaggedVmCount
        resultingTotalExceedsMaximum = [bool] $ResultingTotalExceedsMaximum
        recoveryIndependent = [bool] $RecoveryIndependent
        unresolvedTargetPreserved = [bool] $UnresolvedTargetPreserved
        unrelatedTargetPreserved = [bool] $UnrelatedTargetPreserved
        cleanupPending = [bool] $CleanupPending
        operationsRecordRetained = [bool] $OperationsRecordRetained
        completedRecordRetentionDays = 7
        documentedIncident = [bool] $DocumentedIncident
    }
}

function Test-AzureValidationRoundLiveIdentity {
    # The threat is treating an interactive user login, a stored secret, or
    # an absent identity as the approved credentialless managed identity.
    # The mechanism is the Azure Instance Metadata IDENTITY_ENDPOINT only.
    # The trust assumption is that only the host system-assigned identity
    # is authorized. Safe failure is Available=false with no account dump.
    [pscustomobject][ordered]@{
        Available = -not [string]::IsNullOrWhiteSpace([string] $env:IDENTITY_ENDPOINT)
        Kind = if ([string]::IsNullOrWhiteSpace([string] $env:IDENTITY_ENDPOINT)) {
            'Unavailable'
        }
        else {
            'ManagedIdentity'
        }
    }
}

function Get-AzureValidationRoundScenarioNames {
    @(
        'CompleteZeroResidue'
        'CleanupFirst'
        'AssessmentFailed'
        'IdentityUnavailable'
        'AdmissionDenied'
        'ResidueRemains'
        'CaptureAttempted'
        'CredentialExposed'
        'CancelDuringCreate'
        'CancelDuringReadiness'
        'CancelDuringTransfer'
        'CancelDuringExecution'
        'CancelDuringRetrieval'
        'CancelDuringTeardown'
        'HostLoss'
        'Expiry'
        'CleanupReserve'
        'PartialProvisioning'
        'SharedSafetyFailure'
        'IndependentRecovery'
        'CleanupPending'
        'LeaseBusy'
    )
}

function New-AzureValidationRoundPlatform {
    param(
        [Parameter()] [ValidateSet(
            'CompleteZeroResidue',
            'CleanupFirst',
            'AssessmentFailed',
            'IdentityUnavailable',
            'AdmissionDenied',
            'ResidueRemains',
            'CaptureAttempted',
            'CredentialExposed',
            'CancelDuringCreate',
            'CancelDuringReadiness',
            'CancelDuringTransfer',
            'CancelDuringExecution',
            'CancelDuringRetrieval',
            'CancelDuringTeardown',
            'HostLoss',
            'Expiry',
            'CleanupReserve',
            'PartialProvisioning',
            'SharedSafetyFailure',
            'IndependentRecovery',
            'CleanupPending',
            'LeaseBusy'
        )] [string] $Scenario = 'CompleteZeroResidue'
    )

    $probes = @{}
    foreach ($name in @(
        'Identity', 'Policy', 'Locks', 'Quota', 'Image', 'Sku', 'StandardSsd',
        'Tags', 'Expiry', 'SubnetCapacity', 'VmCount', 'CleanupRights',
        'EmptyTransientScope', 'ExclusiveLease', 'ArmedRecovery'
    )) {
        $probes[$name] = $true
    }

    $kind = 'Synthetic'
    if ($Scenario -eq 'IdentityUnavailable') {
        $kind = 'Unavailable'
        $probes['Identity'] = $false
    }

    $platform = [pscustomobject]@{
        Kind = $kind
        Scenario = $Scenario
        Probes = $probes
        CleanupFirstSucceeds = $true
        Created = $false
        Resources = [System.Collections.Generic.List[string]]::new()
        PersistentPresent = $true
        TerraformStatePresent = $false
        LeaveResidue = $false
        Capture = $false
        PublicIp = $false
        OfferBootstrapPassword = $false
        AssessmentFails = $false
        GuestReady = $true
        CandidateMatches = $true
        PayloadMatches = $true
        GuestCommands = [System.Collections.Generic.List[string]]::new()
        LeaseHeld = $false
        LeaseSerial = 0
        CleanupPending = $false
        CleanupMode = 'None'
        LiveTaggedVms = [System.Collections.Generic.List[string]]::new()
        UnrelatedResources = [System.Collections.Generic.List[string]]::new()
        UnresolvedResources = [System.Collections.Generic.List[string]]::new()
        ResidentRecoveryRecord = $null
        NowUtc = [datetimeoffset]::new(2026, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
        CancelAt = $null
        HostLost = $false
        PartialProvisioning = $false
        SharedSafetyFailed = $false
        NewTestsAllowed = $true
        EvidenceExportAllowed = $true
        OperationsRecords = [System.Collections.Generic.List[object]]::new()
        DocumentedIncident = $false
        UnresolvedPreserved = $false
        UnrelatedPreserved = $false
        IndependentRecovery = $false
    }
    $null = $platform.UnrelatedResources.Add('synthetic-persistent-control-plane')

    switch ($Scenario) {
        'AdmissionDenied' { $platform.Probes['Locks'] = $false }
        'CleanupFirst' {
            $platform.Probes['EmptyTransientScope'] = $false
            $null = $platform.Resources.Add('synthetic-leftover-nic')
        }
        'ResidueRemains' { $platform.LeaveResidue = $true }
        'CaptureAttempted' { $platform.Capture = $true }
        'CredentialExposed' { $platform.OfferBootstrapPassword = $true }
        'AssessmentFailed' { $platform.AssessmentFails = $true }
        'CancelDuringCreate' { $platform.CancelAt = 'Create' }
        'CancelDuringReadiness' { $platform.CancelAt = 'Readiness' }
        'CancelDuringTransfer' { $platform.CancelAt = 'Transfer' }
        'CancelDuringExecution' { $platform.CancelAt = 'Execution' }
        'CancelDuringRetrieval' { $platform.CancelAt = 'Retrieval' }
        'CancelDuringTeardown' { $platform.CancelAt = 'Teardown' }
        'HostLoss' { $platform.HostLost = $true }
        'PartialProvisioning' { $platform.PartialProvisioning = $true }
        'SharedSafetyFailure' { $platform.SharedSafetyFailed = $true }
        'IndependentRecovery' {
            $platform.IndependentRecovery = $true
            $platform.CleanupPending = $true
            foreach ($token in @(Get-AzureValidationRoundOwnedTokens -ClientCount 1)) {
                $null = $platform.Resources.Add($token)
            }
            $platform.ResidentRecoveryRecord = New-AzureValidationRoundResidentRecord `
                -Platform $platform
        }
        'CleanupPending' { $platform.CleanupPending = $true }
        'LeaseBusy' { $platform.LeaseHeld = $true }
    }

    $platform
}

function Get-AzureValidationRoundOwnedTokens {
    param([Parameter()] [int] $ClientCount = 1)

    $tokens = [System.Collections.Generic.List[string]]::new()
    $count = [Math]::Max(1, $ClientCount)
    for ($index = 1; $index -le $count; $index++) {
        $suffix = $index.ToString('00', [System.Globalization.CultureInfo]::InvariantCulture)
        $null = $tokens.Add("synthetic-round-vm-$suffix")
        $null = $tokens.Add("synthetic-round-nic-$suffix")
        $null = $tokens.Add("synthetic-round-disk-$suffix")
    }
    foreach ($shared in @(
        'synthetic-round-vnet'
        'synthetic-round-subnet'
        'synthetic-round-nsg'
        'synthetic-round-nat'
        'synthetic-round-pip'
        'synthetic-round-peering-host'
        'synthetic-round-peering-round'
        'synthetic-round-transfer'
        'synthetic-round-coordination'
    )) {
        $null = $tokens.Add($shared)
    }
    @($tokens)
}

function Initialize-AzureValidationRoundResources {
    param(
        [Parameter(Mandatory)] $Platform,
        [Parameter()] [int] $ClientCount = 1
    )

    $preserved = [System.Collections.Generic.List[string]]::new()
    foreach ($token in @($Platform.Resources)) {
        if (-not (Test-AzureValidationRoundRoundOwnedToken -Platform $Platform -Token $token)) {
            $null = $preserved.Add($token)
        }
    }
    $Platform.Resources.Clear()
    foreach ($token in $preserved) {
        $null = $Platform.Resources.Add($token)
    }
    if ([bool] $Platform.PartialProvisioning) {
        # Partial create still records only the objects that appeared.
        # The threat is deleting a guessed VM that was never created, or
        # retrying the rest of the plan after a failed apply. Safe failure
        # is to keep the short owned list and enter cleanup.
        $null = $Platform.Resources.Add('synthetic-round-vnet')
        $null = $Platform.Resources.Add('synthetic-round-nic-01')
    }
    else {
        foreach ($token in @(Get-AzureValidationRoundOwnedTokens -ClientCount $ClientCount)) {
            $null = $Platform.Resources.Add($token)
        }
    }
    $Platform.Created = $true
    $Platform.TerraformStatePresent = $true
}

function Test-AzureValidationRoundRoundOwnedToken {
    param(
        [Parameter(Mandatory)] $Platform,
        [Parameter(Mandatory)] [string] $Token
    )

    $unrelated = @()
    if ($null -ne $Platform.PSObject.Properties['UnrelatedResources']) {
        $unrelated = @($Platform.UnrelatedResources)
    }
    if ($unrelated -contains $Token) {
        return $false
    }
    $true
}

function Invoke-AzureValidationRoundDestroy {
    param([Parameter(Mandatory)] $Platform)

    # Teardown is independent of the product payload. The threat is leaving
    # a VM, peering, or NAT after an assessment failure and still reporting
    # completion, or deleting an unresolved or unrelated object to chase
    # a green result. The mechanism is a single idempotent destroy path
    # that names only privately recorded, ownership-proven, round-owned
    # tokens. The trust assumption is that the resident recovery record
    # and the in-memory token list agree. Safe failure is to keep residue
    # visible rather than invent absence.
    if ($Platform.LeaveResidue) {
        $kept = [System.Collections.Generic.List[string]]::new()
        foreach ($token in @($Platform.Resources)) {
            if ($token -match 'peering' -or -not (Test-AzureValidationRoundRoundOwnedToken `
                -Platform $Platform -Token $token)) {
                $null = $kept.Add($token)
            }
        }
        $Platform.Resources.Clear()
        foreach ($token in $kept) {
            $null = $Platform.Resources.Add($token)
        }
        if (@($Platform.UnrelatedResources).Count -gt 0) {
            $Platform.UnrelatedPreserved = $true
        }
        return $false
    }

    $remaining = [System.Collections.Generic.List[string]]::new()
    foreach ($token in @($Platform.Resources)) {
        if (@($Platform.UnresolvedResources) -contains $token) {
            $Platform.UnresolvedPreserved = $true
            $null = $remaining.Add($token)
            continue
        }
        if (-not (Test-AzureValidationRoundRoundOwnedToken -Platform $Platform -Token $token)) {
            $Platform.UnrelatedPreserved = $true
            $null = $remaining.Add($token)
            continue
        }
    }
    $Platform.Resources.Clear()
    foreach ($token in $remaining) {
        $null = $Platform.Resources.Add($token)
    }
    if (@($Platform.UnrelatedResources).Count -gt 0 -and -not $Platform.UnrelatedPreserved) {
        $Platform.UnrelatedPreserved = $true
    }

    $roundOwnedRemaining = @($Platform.Resources | Where-Object {
        Test-AzureValidationRoundRoundOwnedToken -Platform $Platform -Token $_
    })
    $roundOwnedRemaining.Count -eq 0
}

function Test-AzureValidationRoundGuestCommandSafe {
    param([Parameter(Mandatory)] [string] $Text)

    # VM Agent Run Command is a management channel, not a password pipe.
    # The threat is sending the bootstrap credential into WIN-PCInfo or
    # back through the sanitized retrieval. The mechanism is a closed
    # operation name with no free-form script and a needle check before
    # dispatch. The trust assumption is that Azure Run Command reaches
    # the guest without a public IP. Safe failure is to refuse the
    # command and tear down.
    if ($Text -match '(?i)(password|secret|clientSecret|temporary_admin|BEGIN (RSA |OPENSSH )?PRIVATE KEY)') {
        return $false
    }
    $true
}

function Invoke-AzureValidationRoundGuest {
    param(
        [Parameter(Mandatory)] $Platform,
        [Parameter(Mandatory)] [ValidateSet(
            'TransferPayload',
            'VerifyCandidate',
            'VerifyPayload',
            'RunLocalOnly',
            'RunApprovedEgress',
            'RunAssessment',
            'RetrieveSanitized'
        )] [string] $Operation
    )

    $command = [pscustomobject][ordered]@{
        control = 'VmAgentRunCommand'
        operation = $Operation
    }
    $commandText = $command | ConvertTo-Json -Compress
    if (-not (Test-AzureValidationRoundGuestCommandSafe -Text $commandText)) {
        return [pscustomobject]@{ Ok = $false; CredentialOffered = $true }
    }

    $null = $Platform.GuestCommands.Add($Operation)
    if ($Platform.OfferBootstrapPassword) {
        return [pscustomobject]@{ Ok = $false; CredentialOffered = $true }
    }

    $ok = $true
    switch ($Operation) {
        'VerifyCandidate' { $ok = [bool] $Platform.CandidateMatches }
        'VerifyPayload' { $ok = [bool] $Platform.PayloadMatches }
        'RunAssessment' { $ok = -not [bool] $Platform.AssessmentFails }
    }

    [pscustomobject]@{
        Ok = $ok
        CredentialOffered = $false
        LocalOnlyOutboundAttempts = 0
    }
}

function Get-AzureValidationRoundLocalAbsence {
    param(
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] $Policy
    )

    $empty = [pscustomobject]@{
        Resources = [System.Collections.Generic.List[string]]::new()
        PersistentPresent = $true
        UnrelatedResources = [System.Collections.Generic.List[string]]::new()
        UnresolvedResources = [System.Collections.Generic.List[string]]::new()
    }
    Get-AzureValidationRoundAbsence -Platform $empty `
        -PrivateWorkspacePath $PrivateWorkspacePath -Policy $Policy
}

function Get-AzureValidationRoundAbsence {
    param(
        [Parameter(Mandatory)] $Platform,
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] $Policy
    )

    # Zero Round Residue is a set of predicates, not a destroy exit code.
    # The threat is reporting absence from one leftover token or inventing
    # a live Azure sweep. The mechanism is separate checks over the
    # privately recorded token list and local folders. The trust
    # assumption is that only round-owned tokens were recorded. Safe
    # failure is to keep residue visible rather than infer emptiness.
    $tokens = @($Platform.Resources | Where-Object {
        Test-AzureValidationRoundRoundOwnedToken -Platform $Platform -Token $_
    })
    $peeringPresent = @($tokens | Where-Object { $_ -match 'peering' }).Count -gt 0
    $transferPresent = @($tokens | Where-Object { $_ -match 'transfer|coordination' }).Count -gt 0
    $workingPath = Join-Path $PrivateWorkspacePath ([string] $Policy.workspace.workingDirectoryName)
    $recoveryPath = Join-Path $PrivateWorkspacePath ([string] $Policy.workspace.recoveryDirectoryName)
    $renderedName = [string] $Policy.workspace.renderedDirectoryName
    $renderedPath = Join-Path $PrivateWorkspacePath $renderedName
    $partialRenderedPath = Join-Path $PrivateWorkspacePath ($renderedName + '.partial')
    # Recovery is protected until Zero Round Residue. Rendered admission
    # files and round-work are unprotected local working material.
    $unprotectedPresent = (Test-Path -LiteralPath $workingPath) -or
        (Test-Path -LiteralPath $renderedPath) -or
        (Test-Path -LiteralPath $partialRenderedPath)

    [pscustomobject][ordered]@{
        TransientEmpty = ($tokens.Count -eq 0)
        HostPeeringAbsent = -not $peeringPresent
        ExactIdsAbsent = ($tokens.Count -eq 0)
        TransferRemoved = -not $transferPresent
        TagSweepEmpty = ($tokens.Count -eq 0)
        PersistentPresent = [bool] $Platform.PersistentPresent
        UnprotectedAbsent = -not $unprotectedPresent
        RecoveryAbsent = -not (Test-Path -LiteralPath $recoveryPath)
    }
}

function Remove-AzureValidationRoundLocalMaterial {
    param(
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] $Policy,
        [Parameter()] [bool] $IncludingRecovery = $false
    )

    $workingPath = Join-Path $PrivateWorkspacePath ([string] $Policy.workspace.workingDirectoryName)
    if (Test-Path -LiteralPath $workingPath) {
        Remove-Item -LiteralPath $workingPath -Recurse -Force
    }
    if ($IncludingRecovery) {
        $recoveryPath = Join-Path $PrivateWorkspacePath ([string] $Policy.workspace.recoveryDirectoryName)
        if (Test-Path -LiteralPath $recoveryPath) {
            Remove-Item -LiteralPath $recoveryPath -Recurse -Force
        }
        $renderedName = [string] $Policy.workspace.renderedDirectoryName
        foreach ($relative in @($renderedName, ($renderedName + '.partial'))) {
            $localPath = Join-Path $PrivateWorkspacePath $relative
            if (Test-Path -LiteralPath $localPath) {
                Remove-Item -LiteralPath $localPath -Recurse -Force
            }
        }
    }
}

function Write-AzureValidationRoundRecovery {
    param(
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $Platform
    )

    # Recovery is private and identifier-tokenized. The threat is writing a
    # real resource ID into the repository or a public log. The mechanism is
    # a marked private folder plus synthetic tokens that never enter the
    # sanitized outcome. The trust assumption is that the operator chose
    # that folder. Safe failure is to keep the journal until absence is
    # proven, then delete it with the state.
    $recoveryPath = Join-Path $PrivateWorkspacePath ([string] $Policy.workspace.recoveryDirectoryName)
    $workingPath = Join-Path $PrivateWorkspacePath ([string] $Policy.workspace.workingDirectoryName)
    $null = New-Item -ItemType Directory -Path $recoveryPath -Force
    $null = New-Item -ItemType Directory -Path $workingPath -Force
    $lines = @(
        'kind=win-pcinfo.private-round-recovery'
        'synthetic=true'
    )
    foreach ($token in @($Platform.Resources)) {
        $lines += "owned=$token"
    }
    [System.IO.File]::WriteAllLines(
        (Join-Path $recoveryPath 'journal.txt'),
        $lines,
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText(
        (Join-Path $workingPath 'state.present'),
        "present`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    $Platform.ResidentRecoveryRecord = New-AzureValidationRoundResidentRecord -Platform $Platform
}

function New-AzureValidationRoundResidentRecord {
    param([Parameter(Mandatory)] $Platform)

    # The Round Recovery Record is conceptually Azure-resident. The threat
    # is tying cleanup to the initiating laptop, a temp folder, or a
    # public log that contains real resource IDs. The mechanism is a
    # closed synthetic token list that a later worker can use after host
    # loss. The trust assumption is that only privately recorded
    # round-owned tokens are listed. Safe failure is to refuse deletion
    # of anything not on this list.
    [pscustomobject][ordered]@{
        Kind = 'win-pcinfo.private-round-recovery'
        Synthetic = $true
        Owned = @($Platform.Resources | Where-Object {
            Test-AzureValidationRoundRoundOwnedToken -Platform $Platform -Token $_
        })
        PersistentPresent = [bool] $Platform.PersistentPresent
    }
}

function Enter-AzureValidationRoundCleanupMode {
    param(
        [Parameter(Mandatory)] $Platform,
        [Parameter()] [string] $Reason
    )

    # Round Cleanup Mode is a one-way door. The threat is retrying create,
    # widening the SKU set, or exporting more evidence after cancellation,
    # expiry, or a shared-safety fault. The mechanism is a mode flag that
    # stops new tests and evidence export and cannot return to testing.
    # The trust assumption is that only exact owned tokens will be
    # removed. Safe failure is to stay in cleanup rather than resume.
    if ([string] $Platform.CleanupMode -eq 'RoundCleanupMode') {
        return
    }
    $Platform.CleanupMode = 'RoundCleanupMode'
    $Platform.NewTestsAllowed = $false
    $Platform.EvidenceExportAllowed = $false
}

function Get-AzureValidationRoundClockState {
    param(
        [Parameter(Mandatory)] $Platform,
        [Parameter(Mandatory)] $Plan
    )

    $expires = ConvertTo-AzureValidationDateTimeOffset -Value $Plan.tags.ExpiresUtc
    $reserveMinutes = [int] $Plan.round.cleanupReserveMinutes
    $reserveStart = $expires.AddMinutes(-1 * $reserveMinutes)
    $now = [datetimeoffset] $Platform.NowUtc
    [pscustomobject][ordered]@{
        ExpiryReached = ($now -ge $expires)
        CleanupReserveActive = ($now -ge $reserveStart)
    }
}

function Update-AzureValidationRoundOperationsRecords {
    param(
        [Parameter(Mandatory)] $Platform,
        [Parameter(Mandatory)] $Policy
    )

    # Completed operations records are not a second evidence store. The
    # threat is keeping restricted round facts forever, or blocking the
    # next round after a clean finish. The mechanism is a seven-day
    # ceiling from the reviewed policy. A documented incident ends
    # controller retention because the incident record takes over.
    # Safe failure is to drop a completed record rather than invent a
    # longer private archive.
    $limit = [int] $Policy.lifetime.completedRecordRetentionDays
    $kept = [System.Collections.Generic.List[object]]::new()
    foreach ($record in @($Platform.OperationsRecords)) {
        $kind = [string] $record.Kind
        $age = [int] $record.AgeDays
        if ($kind -eq 'Completed' -and $age -ge $limit) {
            continue
        }
        if ([bool] $Platform.DocumentedIncident -and $kind -eq 'CleanupPending') {
            continue
        }
        $null = $kept.Add($record)
    }
    $Platform.OperationsRecords.Clear()
    foreach ($record in $kept) {
        $null = $Platform.OperationsRecords.Add($record)
    }
}

function Get-AzureValidationRoundOperationsRetention {
    param([Parameter(Mandatory)] $Platform)

    if ([bool] $Platform.DocumentedIncident) {
        return $false
    }
    @($Platform.OperationsRecords | Where-Object {
        [string] $_.Kind -eq 'CleanupPending'
    }).Count -gt 0
}

function Complete-AzureValidationRoundCleanup {
    param(
        [Parameter(Mandatory)] $Platform,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath
    )

    $teardownCompleted = $false
    try {
        $teardownCompleted = [bool] (Invoke-AzureValidationRoundDestroy -Platform $Platform)
    }
    catch {
        $teardownCompleted = $false
    }
    try {
        Remove-AzureValidationRoundLocalMaterial -PrivateWorkspacePath $PrivateWorkspacePath `
            -Policy $Policy
    }
    catch {
    }

    $absence = Get-AzureValidationRoundAbsence -Platform $Platform `
        -PrivateWorkspacePath $PrivateWorkspacePath -Policy $Policy
    $azureAbsent = [bool] $absence.TransientEmpty -and
        [bool] $absence.HostPeeringAbsent -and
        [bool] $absence.ExactIdsAbsent -and
        [bool] $absence.TransferRemoved -and
        [bool] $absence.TagSweepEmpty -and
        [bool] $absence.PersistentPresent

    $stateRemoved = $false
    $nextEligible = $false
    $zeroResidue = $false
    $reason = 'VALIDATION.RESIDUE_REMAINS'
    if ($azureAbsent) {
        $Platform.TerraformStatePresent = $false
        Remove-AzureValidationRoundLocalMaterial -PrivateWorkspacePath $PrivateWorkspacePath `
            -Policy $Policy -IncludingRecovery:$true
        $absence = Get-AzureValidationRoundAbsence -Platform $Platform `
            -PrivateWorkspacePath $PrivateWorkspacePath -Policy $Policy
        $zeroResidue = [bool] $absence.TransientEmpty -and
            [bool] $absence.HostPeeringAbsent -and
            [bool] $absence.UnprotectedAbsent -and
            [bool] $absence.RecoveryAbsent
        if ($zeroResidue) {
            $stateRemoved = $true
            $nextEligible = $true
            $Platform.CleanupPending = $false
            $Platform.CleanupMode = 'None'
            $Platform.ResidentRecoveryRecord = $null
            $reason = 'VALIDATION.ZERO_RESIDUE_PROVEN'
            $null = $Platform.OperationsRecords.Add([pscustomobject]@{
                Kind = 'Completed'
                AgeDays = 0
            })
        }
    }
    else {
        $Platform.CleanupPending = $true
        $null = $Platform.OperationsRecords.Add([pscustomobject]@{
            Kind = 'CleanupPending'
            AgeDays = 0
        })
    }

    Update-AzureValidationRoundOperationsRecords -Platform $Platform -Policy $Policy

    [pscustomobject][ordered]@{
        TeardownCompleted = $teardownCompleted
        ZeroResidue = $zeroResidue
        StateRemoved = $stateRemoved
        NextEligible = $nextEligible
        Absence = $absence
        Reason = $reason
        UnresolvedPreserved = [bool] $Platform.UnresolvedPreserved
        UnrelatedPreserved = [bool] $Platform.UnrelatedPreserved
        CleanupPending = [bool] $Platform.CleanupPending
        OperationsRecordRetained = (Get-AzureValidationRoundOperationsRetention -Platform $Platform)
        DocumentedIncident = [bool] $Platform.DocumentedIncident
    }
}

function Invoke-AzureValidationRoundRecovery {
    param(
        [Parameter(Mandatory)] $Platform,
        [Parameter(Mandatory)] $Policy,
        [Parameter()] [string] $PrivateWorkspacePath,
        [Parameter()] $Plan,
        [Parameter()] [hashtable] $Common
    )

    # Independent recovery must work after the initiating process and its
    # local files are gone. The threat is being unable to delete a billed
    # VM because a laptop died, or deleting whatever is left in a
    # subscription. The mechanism is the Azure-resident Round Recovery
    # Record. The trust assumption is that the record lists only
    # privately recorded tokens. Safe failure is ResidueRemains.
    if ([string]::IsNullOrWhiteSpace($PrivateWorkspacePath)) {
        $PrivateWorkspacePath = [System.IO.Path]::GetTempPath()
    }

    Enter-AzureValidationRoundCleanupMode -Platform $Platform `
        -Reason 'VALIDATION.RECOVERY_COMPLETED'
    $record = $Platform.ResidentRecoveryRecord
    if ($null -eq $record) {
        if ($null -ne $Common) {
            $Common.CleanupMode = 'RoundCleanupMode'
            $Common.NewTestsStopped = $true
            $Common.EvidenceExportStopped = $true
            $Common.RecoveryIndependent = $true
            return New-AzureValidationRoundOutcome -State Rejected `
                -ReasonCode 'VALIDATION.RECOVERY_NOT_ARMED' @Common
        }
        return $null
    }

    $Platform.Resources.Clear()
    foreach ($token in @($record.Owned)) {
        $null = $Platform.Resources.Add($token)
    }
    $Platform.PersistentPresent = [bool] $record.PersistentPresent
    $cleanup = Complete-AzureValidationRoundCleanup -Platform $Platform `
        -Policy $Policy -PrivateWorkspacePath $PrivateWorkspacePath

    if ($null -eq $Common) {
        return $cleanup
    }

    $Common.CleanupMode = $(if ([bool] $cleanup.CleanupPending) {
        'CleanupPending'
    } else {
        'RoundCleanupMode'
    })
    $Common.NewTestsStopped = $true
    $Common.EvidenceExportStopped = $true
    $Common.RecoveryIndependent = $true
    $Common.CleanupPending = [bool] $cleanup.CleanupPending
    $Common.OperationsRecordRetained = [bool] $cleanup.OperationsRecordRetained
    $Common.DocumentedIncident = [bool] $cleanup.DocumentedIncident
    $Common.UnresolvedTargetPreserved = [bool] $cleanup.UnresolvedPreserved
    $Common.UnrelatedTargetPreserved = [bool] $cleanup.UnrelatedPreserved
    $Common.HostPeeringAbsent = [bool] $cleanup.Absence.HostPeeringAbsent
    $Common.TagSweepEmpty = [bool] $cleanup.Absence.TagSweepEmpty
    $Common.UnprotectedLocalMaterialAbsent = [bool] $cleanup.Absence.UnprotectedAbsent

    $state = if (-not [bool] $cleanup.ZeroResidue) {
        'ResidueRemains'
    }
    else {
        'FailedCleaned'
    }
    $reason = if ($state -eq 'ResidueRemains') {
        'VALIDATION.RESIDUE_REMAINS'
    }
    else {
        'VALIDATION.RECOVERY_COMPLETED'
    }

    New-AzureValidationRoundOutcome -State $state -ReasonCode $reason `
        -TeardownCompleted:([bool] $cleanup.TeardownCompleted) `
        -ZeroResidue:([bool] $cleanup.ZeroResidue) `
        -TerraformStateRemoved:([bool] $cleanup.StateRemoved) `
        -NextRoundEligible:([bool] $cleanup.NextEligible) `
        @Common
}

function Invoke-AzureValidationRound {
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter()]
        [ValidateSet(
            'CompleteZeroResidue',
            'CleanupFirst',
            'AssessmentFailed',
            'IdentityUnavailable',
            'AdmissionDenied',
            'ResidueRemains',
            'CaptureAttempted',
            'CredentialExposed',
            'CancelDuringCreate',
            'CancelDuringReadiness',
            'CancelDuringTransfer',
            'CancelDuringExecution',
            'CancelDuringRetrieval',
            'CancelDuringTeardown',
            'HostLoss',
            'Expiry',
            'CleanupReserve',
            'PartialProvisioning',
            'SharedSafetyFailure',
            'IndependentRecovery',
            'CleanupPending',
            'LeaseBusy'
        )]
        [string] $Scenario,
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter()] $Platform,
        [Parameter()] [string] $FixtureText
    )

    $policy = Get-AzureValidationRoundPolicy
    $facts = $null
    try {
        $facts = Get-AzureValidationClientFacts -Request $Plan
    }
    catch {
        $facts = [pscustomobject]@{ Count = $null; Windows11ClaimingRoute = $false }
    }

    $reserveMinutes = $null
    try {
        $reserveMinutes = [int] $Plan.round.cleanupReserveMinutes
    }
    catch {
        $reserveMinutes = $null
    }

    $common = @{
        ClientCount = $facts.Count
        Windows11ClaimingRoute = [bool] $facts.Windows11ClaimingRoute
        TrustClass = 'ControllerDevTracer'
        PersistentScopePreserved = $true
        HostPeeringAbsent = $false
        TagSweepEmpty = $false
        UnprotectedLocalMaterialAbsent = $false
        CleanupMode = 'None'
        Cancelled = $false
        CancelPhase = 'None'
        ExpiryReached = $false
        CleanupReserveActive = $false
        CleanupReserveMinutes = $reserveMinutes
        NewTestsStopped = $false
        EvidenceExportStopped = $false
        ExclusiveLeaseHeld = $false
        LiveTaggedVmCount = $null
        ResultingTotalExceedsMaximum = $false
        RecoveryIndependent = $false
        UnresolvedTargetPreserved = $false
        UnrelatedTargetPreserved = $false
        CleanupPending = $false
        OperationsRecordRetained = $false
        DocumentedIncident = $false
    }
    $localAbsence = Get-AzureValidationRoundLocalAbsence `
        -PrivateWorkspacePath $PrivateWorkspacePath -Policy $policy
    $common.UnprotectedLocalMaterialAbsent = [bool] $localAbsence.UnprotectedAbsent

    if (-not [string]::IsNullOrWhiteSpace($FixtureText)) {
        $privacy = Test-AzureValidationRoundPrivacyBoundary -Text $FixtureText
        if ($privacy) {
            return New-AzureValidationRoundOutcome -State Rejected -ReasonCode $privacy `
                -PrivacyBoundary Rejected @common
        }
    }

    $admission = Invoke-AzureValidationAdmission -Request $Plan `
        -PrivateWorkspacePath $PrivateWorkspacePath `
        -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory
    $privacyBoundary = [string] $admission.privacyBoundary
    $localAbsence = Get-AzureValidationRoundLocalAbsence `
        -PrivateWorkspacePath $PrivateWorkspacePath -Policy $policy
    $common.UnprotectedLocalMaterialAbsent = [bool] $localAbsence.UnprotectedAbsent
    if (-not $admission.admitted) {
        return New-AzureValidationRoundOutcome -State Rejected `
            -ReasonCode ([string] $admission.reasonCode) `
            -PrivacyBoundary $privacyBoundary `
            -Synthetic:(-not [string]::IsNullOrWhiteSpace($Scenario)) `
            -PlatformKind $(if ([string]::IsNullOrWhiteSpace($Scenario)) { 'Unavailable' } else { 'Synthetic' }) `
            @common
    }

    # Offline admission already accepted one-to-four allowlisted clients.
    # A plan with no claiming Windows 11 route still cannot become this
    # tracer. Safe failure is to stop after admission and create nothing.
    if ($null -eq $facts.Count -or [int] $facts.Count -lt 1) {
        return New-AzureValidationRoundOutcome -State Rejected `
            -ReasonCode 'VALIDATION.VM_COUNT_UNSAFE' `
            -Admitted:$true `
            -PrivacyBoundary $privacyBoundary `
            -Synthetic:(-not [string]::IsNullOrWhiteSpace($Scenario)) `
            -PlatformKind $(if ([string]::IsNullOrWhiteSpace($Scenario)) { 'Unavailable' } else { 'Synthetic' }) `
            @common
    }
    if (-not [bool] $facts.Windows11ClaimingRoute) {
        return New-AzureValidationRoundOutcome -State Rejected `
            -ReasonCode 'VALIDATION.PLAN_UNSAFE' `
            -Admitted:$true `
            -PrivacyBoundary $privacyBoundary `
            -Synthetic:(-not [string]::IsNullOrWhiteSpace($Scenario)) `
            -PlatformKind $(if ([string]::IsNullOrWhiteSpace($Scenario)) { 'Unavailable' } else { 'Synthetic' }) `
            @common
    }

    if ($null -eq $Platform) {
        if ([string]::IsNullOrWhiteSpace($Scenario)) {
            $live = Test-AzureValidationRoundLiveIdentity
            if (-not $live.Available) {
                return New-AzureValidationRoundOutcome -State Blocked `
                    -ReasonCode 'VALIDATION.IDENTITY_UNAVAILABLE' `
                    -Admitted:$true `
                    -PrivacyBoundary $privacyBoundary `
                    -PlatformKind Unavailable @common
            }

            # Live identity is present, but this slice never acquires
            # Terraform or the provider. The threat is an opportunistic
            # download or an unpinned binary from PATH. Seeing
            # IDENTITY_ENDPOINT is not Azure contact. Safe failure is
            # NotStarted with the declared tooling still not acquired.
            return New-AzureValidationRoundOutcome -State Blocked `
                -ReasonCode 'VALIDATION.TOOLING_UNRESOLVED' `
                -Admitted:$true `
                -PrivacyBoundary $privacyBoundary `
                -PlatformKind ManagedIdentity `
                -AzureContacted:$false @common
        }

        $Platform = New-AzureValidationRoundPlatform -Scenario $Scenario
    }

    $synthetic = [string] $Platform.Kind -eq 'Synthetic'
    # A synthetic fixture stands in for Azure. It never contacts Azure.
    $azureContacted = $false
    $common.Synthetic = $synthetic
    $common.PlatformKind = [string] $Platform.Kind
    $common.AzureContacted = $azureContacted
    $common.PrivacyBoundary = $privacyBoundary
    $common.Admitted = $true
    $common.DocumentedIncident = [bool] $Platform.DocumentedIncident
    $common.CleanupPending = [bool] $Platform.CleanupPending
    try {
        $Platform.NowUtc = ConvertTo-AzureValidationDateTimeOffset -Value $Plan.tags.CreatedUtc
    }
    catch {
    }

    if ([bool] $Platform.IndependentRecovery -or $Scenario -eq 'IndependentRecovery') {
        return Invoke-AzureValidationRoundRecovery -Platform $Platform `
            -Policy $policy -PrivateWorkspacePath $PrivateWorkspacePath `
            -Plan $Plan -Common $common
    }

    if ([bool] $Platform.CleanupPending) {
        $common.CleanupMode = 'CleanupPending'
        $common.OperationsRecordRetained = -not [bool] $Platform.DocumentedIncident
        return New-AzureValidationRoundOutcome -State Rejected `
            -ReasonCode 'VALIDATION.CLEANUP_PENDING' @common
    }

    if ([string] $Platform.CleanupMode -eq 'RoundCleanupMode') {
        # Irreversible cleanup refuses to expand. Recover the leftover
        # tokens instead of creating another client.
        return Invoke-AzureValidationRoundRecovery -Platform $Platform `
            -Policy $policy -PrivateWorkspacePath $PrivateWorkspacePath `
            -Plan $Plan -Common $common
    }

    $acquiredLease = $false
    if (-not [bool] $Platform.Probes['ExclusiveLease']) {
        # A failed ExclusiveLease probe stays failed. Do not invent a hold.
    }
    elseif ([bool] $Platform.LeaseHeld) {
        # One exclusive lease serializes admission. The threat is two
        # maintainers recounting four live VMs at the same time and each
        # admitting one more. Safe failure is LEASE_UNAVAILABLE.
        $Platform.Probes['ExclusiveLease'] = $false
    }
    else {
        $Platform.LeaseHeld = $true
        $Platform.LeaseSerial = [int] $Platform.LeaseSerial + 1
        $acquiredLease = $true
        $common.ExclusiveLeaseHeld = $true
    }

    $liveCount = @($Platform.LiveTaggedVms).Count
    $common.LiveTaggedVmCount = $liveCount
    $requested = [int] $facts.Count
    if (($liveCount + $requested) -gt [int] $policy.clients.maximum) {
        # Recount under the lease. The threat is admitting a fifth live
        # tagged validation VM because a prior round was still running.
        $Platform.Probes['VmCount'] = $false
        $common.ResultingTotalExceedsMaximum = $true
    }

    if (-not [bool] $Platform.Probes['EmptyTransientScope']) {
        if ([bool] $Platform.CleanupFirstSucceeds) {
            $Platform.Resources.Clear()
            $Platform.Probes['EmptyTransientScope'] = $true
        }
        else {
            if ($acquiredLease) {
                $Platform.LeaseHeld = $false
            }
            return New-AzureValidationRoundOutcome -State Rejected `
                -ReasonCode 'VALIDATION.TRANSIENT_SCOPE_NOT_EMPTY' @common
        }
    }
    $common.CleanupFirst = $true

    foreach ($probe in @($policy.admissionProbes)) {
        if (-not [bool] $Platform.Probes[$probe]) {
            if ($acquiredLease) {
                $Platform.LeaseHeld = $false
            }
            $state = if ($probe -eq 'Identity') { 'Blocked' } else { 'Rejected' }
            if ($probe -eq 'Identity') {
                $common.AzureContacted = $false
                if ([string] $Platform.Kind -eq 'Unavailable') {
                    $common.PlatformKind = 'Unavailable'
                    $common.Synthetic = $false
                }
            }
            return New-AzureValidationRoundOutcome -State $state `
                -ReasonCode (Get-AzureValidationRoundProbeReason -Probe $probe) @common
        }
    }

    $created = $false
    $guestControl = 'None'
    $fresh = $true
    $captured = $false
    $publicIp = $false
    $credentialExposed = $false
    $guestReady = $false
    $candidateVerified = $false
    $payloadVerified = $false
    $localOnlyChecked = $false
    $approvedEgressChecked = $false
    $assessmentExecuted = $false
    $sanitizedRetrieval = $false
    $assessmentFailed = $false
    $reason = 'VALIDATION.ZERO_RESIDUE_PROVEN'
    $requestedCount = [int] $facts.Count

    try {
        # Create and the private recovery map are inside the same try as
        # guest work so a journal write failure still enters teardown.
        Initialize-AzureValidationRoundResources -Platform $Platform `
            -ClientCount $requestedCount
        $created = $true
        Write-AzureValidationRoundRecovery -PrivateWorkspacePath $PrivateWorkspacePath `
            -Policy $policy -Platform $Platform

        if ($Scenario -eq 'Expiry') {
            $Platform.NowUtc = (ConvertTo-AzureValidationDateTimeOffset `
                -Value $Plan.tags.ExpiresUtc)
        }
        elseif ($Scenario -eq 'CleanupReserve') {
            $Platform.NowUtc = (ConvertTo-AzureValidationDateTimeOffset `
                -Value $Plan.tags.ExpiresUtc).AddMinutes(
                -1 * [int] $Plan.round.cleanupReserveMinutes)
        }

        if ([string] $Platform.CancelAt -eq 'Create' -or [bool] $Platform.PartialProvisioning) {
            Enter-AzureValidationRoundCleanupMode -Platform $Platform
            if ([bool] $Platform.PartialProvisioning) {
                $reason = 'VALIDATION.PARTIAL_PROVISIONING'
            }
            else {
                $reason = 'VALIDATION.CANCELLED'
                $common.Cancelled = $true
                $common.CancelPhase = 'Create'
            }
        }
        elseif ([bool] $Platform.HostLost) {
            # Host loss drops local files. Cleanup continues from the
            # Azure-resident recovery record, not from this process tree.
            Enter-AzureValidationRoundCleanupMode -Platform $Platform
            Remove-AzureValidationRoundLocalMaterial -PrivateWorkspacePath $PrivateWorkspacePath `
                -Policy $policy -IncludingRecovery:$true
            $common.RecoveryIndependent = $true
            $reason = 'VALIDATION.HOST_LOST'
        }
        elseif ([bool] $Platform.SharedSafetyFailed) {
            Enter-AzureValidationRoundCleanupMode -Platform $Platform
            $reason = 'VALIDATION.SHARED_SAFETY_FAILED'
        }
        elseif ([bool] $Platform.PublicIp) {
            Enter-AzureValidationRoundCleanupMode -Platform $Platform
            $publicIp = $true
            $reason = 'VALIDATION.PUBLIC_IP_PROHIBITED'
        }
        elseif ([bool] $Platform.Capture) {
            Enter-AzureValidationRoundCleanupMode -Platform $Platform
            $captured = $true
            $fresh = $false
            $reason = 'VALIDATION.CLIENT_CAPTURE_PROHIBITED'
        }
        else {
            $clock = Get-AzureValidationRoundClockState -Platform $Platform -Plan $Plan
            if ([bool] $clock.ExpiryReached -or [bool] $clock.CleanupReserveActive) {
                Enter-AzureValidationRoundCleanupMode -Platform $Platform
                $common.ExpiryReached = [bool] $clock.ExpiryReached
                $common.CleanupReserveActive = [bool] $clock.CleanupReserveActive
                $reason = if ([bool] $clock.ExpiryReached) {
                    'VALIDATION.EXPIRY_REACHED'
                }
                else {
                    'VALIDATION.CLEANUP_RESERVE_ACTIVE'
                }
            }
            elseif ([string] $Platform.CancelAt -eq 'Readiness') {
                Enter-AzureValidationRoundCleanupMode -Platform $Platform
                $reason = 'VALIDATION.CANCELLED'
                $common.Cancelled = $true
                $common.CancelPhase = 'Readiness'
            }
            elseif (-not [bool] $Platform.GuestReady) {
                Enter-AzureValidationRoundCleanupMode -Platform $Platform
                $reason = 'VALIDATION.GUEST_NOT_READY'
            }
            else {
                $guestReady = $true
                $guestControl = 'VmAgentRunCommand'
                foreach ($step in @(
                    @{ Operation = 'TransferPayload'; Flag = 'transfer'; Phase = 'Transfer' }
                    @{ Operation = 'VerifyCandidate'; Flag = 'candidate'; Phase = 'Execution' }
                    @{ Operation = 'VerifyPayload'; Flag = 'payload'; Phase = 'Execution' }
                    @{ Operation = 'RunLocalOnly'; Flag = 'local'; Phase = 'Execution' }
                    @{ Operation = 'RunApprovedEgress'; Flag = 'egress'; Phase = 'Execution' }
                    @{ Operation = 'RunAssessment'; Flag = 'assessment'; Phase = 'Execution' }
                    @{ Operation = 'RetrieveSanitized'; Flag = 'retrieve'; Phase = 'Retrieval' }
                )) {
                    $clock = Get-AzureValidationRoundClockState -Platform $Platform -Plan $Plan
                    if ([bool] $clock.ExpiryReached -or [bool] $clock.CleanupReserveActive) {
                        Enter-AzureValidationRoundCleanupMode -Platform $Platform
                        $common.ExpiryReached = [bool] $clock.ExpiryReached
                        $common.CleanupReserveActive = [bool] $clock.CleanupReserveActive
                        $reason = if ([bool] $clock.ExpiryReached) {
                            'VALIDATION.EXPIRY_REACHED'
                        }
                        else {
                            'VALIDATION.CLEANUP_RESERVE_ACTIVE'
                        }
                        break
                    }
                    if (-not [bool] $Platform.NewTestsAllowed) {
                        break
                    }
                    if ([string] $Platform.CancelAt -eq [string] $step.Phase) {
                        Enter-AzureValidationRoundCleanupMode -Platform $Platform
                        $reason = 'VALIDATION.CANCELLED'
                        $common.Cancelled = $true
                        $common.CancelPhase = [string] $step.Phase
                        break
                    }
                    if ([string] $step.Flag -eq 'retrieve' -and
                        -not [bool] $Platform.EvidenceExportAllowed) {
                        break
                    }

                    $guest = Invoke-AzureValidationRoundGuest -Platform $Platform `
                        -Operation ([string] $step.Operation)
                    if ([bool] $guest.CredentialOffered) {
                        Enter-AzureValidationRoundCleanupMode -Platform $Platform
                        $credentialExposed = $true
                        $reason = 'VALIDATION.BOOTSTRAP_CREDENTIAL_EXPOSED'
                        break
                    }
                    switch ([string] $step.Flag) {
                        'transfer' { }
                        'candidate' {
                            if (-not [bool] $guest.Ok) {
                                $reason = 'VALIDATION.CANDIDATE_MISMATCH'
                                break
                            }
                            $candidateVerified = $true
                        }
                        'payload' {
                            if (-not [bool] $guest.Ok) {
                                $reason = 'VALIDATION.PAYLOAD_MISMATCH'
                                break
                            }
                            $payloadVerified = $true
                        }
                        'local' { $localOnlyChecked = $true }
                        'egress' { $approvedEgressChecked = $true }
                        'assessment' {
                            $assessmentExecuted = $true
                            if (-not [bool] $guest.Ok) {
                                $assessmentFailed = $true
                                $reason = 'VALIDATION.ASSESSMENT_FAILED'
                            }
                        }
                        'retrieve' {
                            if ($assessmentFailed) {
                                $sanitizedRetrieval = $true
                            }
                            elseif (-not [bool] $guest.Ok) {
                                $reason = 'VALIDATION.SANITIZED_RETRIEVAL_FAILED'
                            }
                            else {
                                $sanitizedRetrieval = $true
                            }
                        }
                    }
                    if ($reason -in @(
                        'VALIDATION.CANDIDATE_MISMATCH'
                        'VALIDATION.PAYLOAD_MISMATCH'
                        'VALIDATION.SANITIZED_RETRIEVAL_FAILED'
                    )) {
                        Enter-AzureValidationRoundCleanupMode -Platform $Platform
                        break
                    }
                }
            }
        }

        if ([string] $Platform.CancelAt -eq 'Teardown') {
            Enter-AzureValidationRoundCleanupMode -Platform $Platform
            $reason = 'VALIDATION.CANCELLED'
            $common.Cancelled = $true
            $common.CancelPhase = 'Teardown'
        }
    }
    catch {
        # After create, a journal or guest fault must not escape as
        # REQUEST_INVALID. Teardown still runs in finally. Safe failure is
        # FailedCleaned or ResidueRemains after independent absence checks.
        if (-not $created) {
            throw
        }
        Enter-AzureValidationRoundCleanupMode -Platform $Platform
        if ($reason -eq 'VALIDATION.ZERO_RESIDUE_PROVEN') {
            $reason = 'VALIDATION.GUEST_NOT_READY'
        }
    }
    finally {
        # A testing failure cannot prevent cleanup-first transition. The
        # finally block is the only create-to-teardown seam. The trust
        # assumption is that destroy names only privately recorded tokens.
        # Safe failure is ResidueRemains, never Completed, and never a
        # throw that ApplicationMain would map to REQUEST_INVALID.
        if ($acquiredLease) {
            $Platform.LeaseHeld = $false
        }
    }

    if ([string] $Platform.CleanupMode -eq 'RoundCleanupMode') {
        $common.CleanupMode = 'RoundCleanupMode'
        $common.NewTestsStopped = $true
        $common.EvidenceExportStopped = $true
    }

    $cleanup = Complete-AzureValidationRoundCleanup -Platform $Platform `
        -Policy $policy -PrivateWorkspacePath $PrivateWorkspacePath
    $teardownCompleted = [bool] $cleanup.TeardownCompleted
    $zeroResidue = [bool] $cleanup.ZeroResidue
    $stateRemoved = [bool] $cleanup.StateRemoved
    $nextEligible = [bool] $cleanup.NextEligible
    $absence = $cleanup.Absence
    $common.UnresolvedTargetPreserved = [bool] $cleanup.UnresolvedPreserved
    $common.UnrelatedTargetPreserved = [bool] $cleanup.UnrelatedPreserved
    $common.CleanupPending = [bool] $cleanup.CleanupPending
    $common.OperationsRecordRetained = [bool] $cleanup.OperationsRecordRetained
    $common.DocumentedIncident = [bool] $cleanup.DocumentedIncident
    if (-not $zeroResidue) {
        $reason = 'VALIDATION.RESIDUE_REMAINS'
        $common.CleanupMode = 'CleanupPending'
    }
    elseif ($reason -eq 'VALIDATION.ZERO_RESIDUE_PROVEN' -and
        [string] $cleanup.Reason -eq 'VALIDATION.ZERO_RESIDUE_PROVEN') {
        $reason = 'VALIDATION.ZERO_RESIDUE_PROVEN'
    }

    $state = if (-not $zeroResidue) {
        'ResidueRemains'
    }
    elseif ($credentialExposed) {
        'FailedCleaned'
    }
    elseif ($captured -or $publicIp) {
        'FailedCleaned'
    }
    elseif ($assessmentFailed) {
        'FailedCleaned'
    }
    elseif ($reason -ne 'VALIDATION.ZERO_RESIDUE_PROVEN') {
        'FailedCleaned'
    }
    else {
        'ZeroResidueProven'
    }

    if ($state -eq 'ResidueRemains') {
        $stateRemoved = $false
        $nextEligible = $false
        $reason = 'VALIDATION.RESIDUE_REMAINS'
    }

    $common.HostPeeringAbsent = [bool] $absence.HostPeeringAbsent
    $common.TagSweepEmpty = [bool] $absence.TagSweepEmpty
    $common.UnprotectedLocalMaterialAbsent = [bool] $absence.UnprotectedAbsent

    New-AzureValidationRoundOutcome -State $state -ReasonCode $reason `
        -Created:$created -GuestReady:$guestReady `
        -CandidateVerified:$candidateVerified -PayloadVerified:$payloadVerified `
        -LocalOnlyChecked:$localOnlyChecked -ApprovedEgressChecked:$approvedEgressChecked `
        -AssessmentExecuted:$assessmentExecuted -SanitizedRetrieval:$sanitizedRetrieval `
        -TeardownCompleted:$teardownCompleted -ZeroResidue:$zeroResidue `
        -TerraformStateRemoved:$stateRemoved -NextRoundEligible:$nextEligible `
        -GuestControl $guestControl `
        -BootstrapCredentialExposed:$credentialExposed `
        -ClientCapturedOrReused:$captured -VmPublicIpAssigned:$publicIp `
        -FreshApprovedBaseline:$fresh @common
}
