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
        [string] $PrivacyBoundary = 'Rejected'
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
        clientCount = $ClientCount
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
            'CredentialExposed'
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
    }

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
    }

    $platform
}

function Get-AzureValidationRoundOwnedTokens {
    @(
        'synthetic-round-vm-01'
        'synthetic-round-nic-01'
        'synthetic-round-disk-01'
        'synthetic-round-vnet'
        'synthetic-round-subnet'
        'synthetic-round-nsg'
        'synthetic-round-nat'
        'synthetic-round-pip'
        'synthetic-round-peering-host'
        'synthetic-round-peering-round'
        'synthetic-round-transfer'
        'synthetic-round-coordination'
    )
}

function Initialize-AzureValidationRoundResources {
    param([Parameter(Mandatory)] $Platform)

    $Platform.Resources.Clear()
    foreach ($token in @(Get-AzureValidationRoundOwnedTokens)) {
        $null = $Platform.Resources.Add($token)
    }
    $Platform.Created = $true
    $Platform.TerraformStatePresent = $true
}

function Invoke-AzureValidationRoundDestroy {
    param([Parameter(Mandatory)] $Platform)

    # Teardown is independent of the product payload. The threat is leaving
    # a VM, peering, or NAT after an assessment failure and still reporting
    # completion. The mechanism is a single destroy path that every created
    # round must enter. The trust assumption is that the platform can name
    # only privately recorded round-owned tokens. Safe failure is to keep
    # residue visible rather than invent absence.
    if ($Platform.LeaveResidue) {
        $Platform.Resources.Clear()
        $null = $Platform.Resources.Add('synthetic-round-peering-host')
        $null = $Platform.Resources.Add('synthetic-round-peering-round')
        return $false
    }

    $Platform.Resources.Clear()
    $true
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
    $tokens = @($Platform.Resources)
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
            'CredentialExposed'
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

    $common = @{
        ClientCount = $facts.Count
        Windows11ClaimingRoute = [bool] $facts.Windows11ClaimingRoute
        TrustClass = 'ControllerDevTracer'
        PersistentScopePreserved = $true
        HostPeeringAbsent = $false
        TagSweepEmpty = $false
        UnprotectedLocalMaterialAbsent = $false
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

    # This slice runs one Windows 11 claiming client. Admission still
    # accepts one-to-four-client plans for later tickets. The threat is
    # reporting a four-client or non-claiming diagnostic as this tracer.
    # Safe failure is to stop after admission and create nothing.
    if ($facts.Count -ne 1) {
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

    if (-not [bool] $Platform.Probes['EmptyTransientScope']) {
        if ([bool] $Platform.CleanupFirstSucceeds) {
            $Platform.Resources.Clear()
            $Platform.Probes['EmptyTransientScope'] = $true
        }
        else {
            return New-AzureValidationRoundOutcome -State Rejected `
                -ReasonCode 'VALIDATION.TRANSIENT_SCOPE_NOT_EMPTY' @common
        }
    }
    $common.CleanupFirst = $true

    foreach ($probe in @($policy.admissionProbes)) {
        if (-not [bool] $Platform.Probes[$probe]) {
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
    $teardownCompleted = $false
    $reason = 'VALIDATION.ZERO_RESIDUE_PROVEN'

    try {
        # Create and the private recovery map are inside the same try as
        # guest work so a journal write failure still enters teardown.
        Initialize-AzureValidationRoundResources -Platform $Platform
        $created = $true
        Write-AzureValidationRoundRecovery -PrivateWorkspacePath $PrivateWorkspacePath `
            -Policy $policy -Platform $Platform

        if ([bool] $Platform.PublicIp) {
            $publicIp = $true
            $reason = 'VALIDATION.PUBLIC_IP_PROHIBITED'
        }
        elseif ([bool] $Platform.Capture) {
            $captured = $true
            $fresh = $false
            $reason = 'VALIDATION.CLIENT_CAPTURE_PROHIBITED'
        }
        elseif (-not [bool] $Platform.GuestReady) {
            $reason = 'VALIDATION.GUEST_NOT_READY'
        }
        else {
            $guestReady = $true
            $guestControl = 'VmAgentRunCommand'
            foreach ($step in @(
                @{ Operation = 'VerifyCandidate'; Flag = 'candidate' }
                @{ Operation = 'VerifyPayload'; Flag = 'payload' }
                @{ Operation = 'RunLocalOnly'; Flag = 'local' }
                @{ Operation = 'RunApprovedEgress'; Flag = 'egress' }
                @{ Operation = 'RunAssessment'; Flag = 'assessment' }
                @{ Operation = 'RetrieveSanitized'; Flag = 'retrieve' }
            )) {
                $guest = Invoke-AzureValidationRoundGuest -Platform $Platform `
                    -Operation ([string] $step.Operation)
                if ([bool] $guest.CredentialOffered) {
                    $credentialExposed = $true
                    $reason = 'VALIDATION.BOOTSTRAP_CREDENTIAL_EXPOSED'
                    break
                }
                switch ([string] $step.Flag) {
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
                    break
                }
            }
        }
    }
    catch {
        # After create, a journal or guest fault must not escape as
        # REQUEST_INVALID. Teardown still runs in finally. Safe failure is
        # FailedCleaned or ResidueRemains after independent absence checks.
        if (-not $created) {
            throw
        }
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
        if ($created) {
            try {
                $teardownCompleted = [bool] (Invoke-AzureValidationRoundDestroy -Platform $Platform)
            }
            catch {
                $teardownCompleted = $false
            }
            try {
                Remove-AzureValidationRoundLocalMaterial -PrivateWorkspacePath $PrivateWorkspacePath `
                    -Policy $policy
            }
            catch {
            }
        }
    }

    $absence = Get-AzureValidationRoundAbsence -Platform $Platform `
        -PrivateWorkspacePath $PrivateWorkspacePath -Policy $policy
    $azureAbsent = [bool] $absence.TransientEmpty -and
        [bool] $absence.HostPeeringAbsent -and
        [bool] $absence.ExactIdsAbsent -and
        [bool] $absence.TransferRemoved -and
        [bool] $absence.TagSweepEmpty -and
        [bool] $absence.PersistentPresent

    $stateRemoved = $false
    $nextEligible = $false
    $zeroResidue = $false
    if ($azureAbsent) {
        # State removal is the last privilege. The threat is deleting the
        # only recovery map while a NIC or peering still exists. The
        # mechanism is independent Azure absence first, then state and
        # journal removal, then a local unprotected-material check. The
        # trust assumption is that absence was rechecked, not inferred
        # from a destroy exit code. Safe failure is to keep state.
        $Platform.TerraformStatePresent = $false
        Remove-AzureValidationRoundLocalMaterial -PrivateWorkspacePath $PrivateWorkspacePath `
            -Policy $policy -IncludingRecovery:$true
        $absence = Get-AzureValidationRoundAbsence -Platform $Platform `
            -PrivateWorkspacePath $PrivateWorkspacePath -Policy $policy
        $zeroResidue = [bool] $absence.TransientEmpty -and
            [bool] $absence.HostPeeringAbsent -and
            [bool] $absence.UnprotectedAbsent -and
            [bool] $absence.RecoveryAbsent
        if ($zeroResidue) {
            $stateRemoved = $true
            $nextEligible = $true
        }
        else {
            $reason = 'VALIDATION.RESIDUE_REMAINS'
        }
    }
    else {
        $reason = 'VALIDATION.RESIDUE_REMAINS'
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
