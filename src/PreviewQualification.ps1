# Build.ps1 replaces both sentinels with the release-bound qualification
# policy and its SHA-256 digest. The generated application treats that table
# as the only trusted copy of the Preview.1 qualification contract.
$script:PreviewQualificationPolicyBase64 = '__PREVIEW_QUALIFICATION_POLICY_BASE64__'
$script:PreviewQualificationPolicyDigest = '__PREVIEW_QUALIFICATION_POLICY_SHA256__'

function Get-PreviewQualificationSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-PreviewQualificationPolicy {
    # The threat is a substituted policy that waives missing Azure evidence,
    # treats an Attested Preview as Trusted, or publishes a support claim.
    # The mechanism is an embedded digest, or the reviewed repository file
    # when this module is sourced during development. The trust assumption
    # is that those bytes were reviewed with the rest of the release. Safe
    # failure is to refuse qualification rather than invent a looser contract.
    if ($script:PreviewQualificationPolicyBase64 -eq
        ('__PREVIEW_QUALIFICATION_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-preview-qualification.json'
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-PreviewQualificationSha256 $bytes
    }
    else {
        [byte[]] $bytes = [System.Convert]::FromBase64String(
            $script:PreviewQualificationPolicyBase64
        )
        $expectedDigest = $script:PreviewQualificationPolicyDigest
    }
    if ((Get-PreviewQualificationSha256 $bytes) -ne $expectedDigest) {
        throw 'The Preview qualification policy failed its embedded digest check.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $json | ConvertFrom-Json -Depth 30
}

function Get-PreviewQualificationProperty {
    param(
        [Parameter()] $Value,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($null -eq $Value) {
        return $null
    }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    $property.Value
}

function Test-PreviewQualificationPathUnderRoot {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Root
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $prefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    $fullPath.Equals($fullRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-PreviewQualificationPublicPath {
    param([Parameter(Mandatory)] [string] $Path)

    if ($Path.StartsWith('\\', [System.StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [System.StringComparison]::Ordinal)) {
        return $true
    }
    $publicRoot = [string] $env:PUBLIC
    if ([string]::IsNullOrWhiteSpace($publicRoot)) {
        return $false
    }
    if (-not (Test-Path -LiteralPath $publicRoot)) {
        return $false
    }
    Test-PreviewQualificationPathUnderRoot -Path $Path -Root $publicRoot
}

function Test-PreviewQualificationReparsePath {
    param([Parameter(Mandatory)] [string] $Path)

    # A junction or symlink can make a temp path write into the repository
    # or a network share after the string checks pass. Walk every existing
    # ancestor the same way Evidence Workspace does. The trust assumption is
    # that a ticket-owned qualification workspace is a real local directory.
    # Safe failure is to reject the path before any derived packet exists.
    try {
        $cursor = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath($Path))
    }
    catch {
        return $true
    }
    if (-not $cursor.Exists) {
        $cursor = $cursor.Parent
    }
    while ($null -ne $cursor) {
        if ($cursor.Exists -and
            ($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $true
        }
        $cursor = $cursor.Parent
    }
    $false
}

function Get-PreviewQualificationCatalogPath {
    param(
        [Parameter()] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] [string] $RelativePath
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($start in @($ApplicationDirectory, $RepositoryRoot)) {
        if ([string]::IsNullOrWhiteSpace($start)) {
            continue
        }
        $cursor = $start
        for ($i = 0; $i -lt 6; $i++) {
            if ([string]::IsNullOrWhiteSpace($cursor)) {
                break
            }
            if ($seen.Add($cursor)) {
                $roots.Add($cursor)
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

function Test-PreviewQualificationPrivacyBoundary {
    param([Parameter(Mandatory)] [string] $Text)

    # Public qualification output is a projection, not a dump. The threat is
    # printing a credential, a real cloud identifier, Terraform material, a
    # raw log, a local user path, or restricted assessment evidence. The
    # mechanism is a closed needle list applied to the raw request before
    # any derived file is written. The trust assumption is that approved
    # fixtures stay synthetic and identifier-free. Safe failure is
    # QUALIFY.PRIVACY_REJECTED with no workspace residue.
    $needles = @(
        '(?i)clientSecret'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)(password|secret|api[_-]?key|access_token)\s*[:=]'
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)\.terraform'
        '(?i)\.tfstate'
        '(?i)\.tfplan\b'
        '(?i)tfplan'
        '(?i)\.cache[\\/]'
        '(?i)crash(\..*)?\.log'
        '(?i)\.(log|evtx)\b'
        '(?i)win-pcinfo\.(assessment-record|protected-package)'
        '(?i)recipientFingerprint'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
        '(?i)\b\d{1,3}(\.\d{1,3}){3}\b'
        '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
    )
    foreach ($needle in $needles) {
        if ($Text -match $needle) {
            return 'QUALIFY.PRIVACY_REJECTED'
        }
    }
    $null
}

function Get-PreviewQualificationWorkspaceRejection {
    param(
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $Request
    )

    # The threat is writing a decision packet or restricted evidence into
    # the public repository or a shared folder. The mechanism is a
    # caller-supplied private directory that already carries the reviewed
    # marker. The trust assumption is that the operator chose a folder they
    # control. Safe failure is to stop before any derived file exists.
    if ([string] (Get-PreviewQualificationProperty $Request 'privacyBoundary') -ne
        [string] $Policy.workspace.requiredBoundary) {
        return 'QUALIFY.PRIVACY_BOUNDARY_MISSING'
    }
    if ([string]::IsNullOrWhiteSpace($PrivateWorkspacePath)) {
        return 'QUALIFY.PRIVACY_BOUNDARY_MISSING'
    }
    if (Test-PreviewQualificationPublicPath -Path $PrivateWorkspacePath) {
        return 'QUALIFY.WORKSPACE_PUBLIC_PATH'
    }
    if (Test-PreviewQualificationPathUnderRoot -Path $PrivateWorkspacePath `
        -Root $RepositoryRoot) {
        return 'QUALIFY.WORKSPACE_REPOSITORY_PATH'
    }
    if (-not [string]::IsNullOrWhiteSpace($ApplicationDirectory) -and
        (Test-Path -LiteralPath $ApplicationDirectory) -and
        (Test-PreviewQualificationPathUnderRoot -Path $PrivateWorkspacePath `
            -Root $ApplicationDirectory)) {
        return 'QUALIFY.WORKSPACE_REPOSITORY_PATH'
    }
    if (Test-PreviewQualificationReparsePath -Path $PrivateWorkspacePath) {
        return 'QUALIFY.WORKSPACE_REPARSE_POINT'
    }
    if (-not (Test-Path -LiteralPath $PrivateWorkspacePath -PathType Container)) {
        return 'QUALIFY.PRIVACY_BOUNDARY_MISSING'
    }
    $markerPath = Join-Path $PrivateWorkspacePath ([string] $Policy.workspace.markerFileName)
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        return 'QUALIFY.PRIVACY_BOUNDARY_MISSING'
    }
    $markerText = [System.IO.File]::ReadAllText($markerPath).Trim()
    if ($markerText -ne [string] $Policy.workspace.markerContent) {
        return 'QUALIFY.PRIVACY_BOUNDARY_MISSING'
    }
    $null
}

function Get-PreviewQualificationEmptyCoverage {
    [pscustomobject][ordered]@{
        gatesComplete = $false
        privilegeComplete = $false
        networkComplete = $false
        localeComplete = $false
        validationControlComplete = $false
        failureInjectionComplete = $false
        packageExerciseComplete = $false
        recoveryComplete = $false
    }
}

function New-PreviewQualificationPacket {
    param(
        [Parameter(Mandatory)] [ValidateSet('Approved', 'Denied', 'Rejected')] [string] $State,
        [Parameter(Mandatory)] [ValidateSet('Qualify', 'Deny', 'NotStarted')] [string] $Decision,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [string] $TrustPath = 'None',
        [Parameter()] [bool] $UnsignedContentQualified = $false,
        [Parameter()] [bool] $FinalArtifactQualified = $false,
        [Parameter()] [bool] $CandidateBound = $false,
        [Parameter()] [bool] $CleanupVerified = $true,
        [Parameter()] [bool] $ZeroResidueVerified = $false,
        [Parameter()] [bool] $AzureIdentityAvailable = $false,
        [Parameter()] [bool] $QualityThreeCleanPassed = $false,
        [Parameter()] $Smokes = @(),
        [Parameter()] $Coverage,
        [Parameter()] $ClaimedScenarios = @(),
        [Parameter()] $BlockingReasons = @(),
        [Parameter()] $Limitations = @()
    )

    if ($null -eq $Coverage) {
        $Coverage = Get-PreviewQualificationEmptyCoverage
    }
    if ($TrustPath -notin @('AuthenticodeSigned', 'AttestedPreview', 'None')) {
        $TrustPath = 'None'
    }
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.preview-qualification-packet'
        contractVersion = '1.0.0'
        state = $State
        decision = $Decision
        reasonCode = $ReasonCode
        syntheticEvidenceOnly = $true
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        sliceDeliversCapability = $false
        publicationAuthorized = $false
        humanApprovalRequired = $true
        trustPath = $TrustPath
        attestedPreviewSatisfiesStableSigning = $false
        unsignedContentQualified = [bool] $UnsignedContentQualified
        finalArtifactQualified = [bool] $FinalArtifactQualified
        candidateBound = [bool] $CandidateBound
        cleanupVerified = [bool] $CleanupVerified
        zeroResidueVerified = [bool] $ZeroResidueVerified
        azureIdentityAvailable = [bool] $AzureIdentityAvailable
        liveAzureStarted = $false
        collectionStarted = $false
        qualityThreeCleanPassed = [bool] $QualityThreeCleanPassed
        smokes = @($Smokes)
        coverage = $Coverage
        claimedScenarios = @($ClaimedScenarios)
        impactReview = [pscustomobject][ordered]@{
            required = $true
            completed = $false
            notes = @('human-approval-required')
        }
        blockingReasons = @($BlockingReasons)
        limitations = @($Limitations)
    }
}

function New-PreviewQualificationEvaluation {
    param(
        [Parameter(Mandatory)] [ValidateSet('Approved', 'Denied', 'Rejected')] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [ValidateSet('Completed', 'NotStarted', 'CleanupIncomplete')]
        [string] $ExitKind,
        [Parameter(Mandatory)] $Packet,
        [Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)] $Matrix,
        [Parameter()] [bool] $CleanupVerified = $true
    )

    [pscustomobject][ordered]@{
        State = $State
        ReasonCode = $ReasonCode
        ExitKind = $ExitKind
        Packet = $Packet
        Manifest = $Manifest
        Matrix = $Matrix
        CleanupVerified = [bool] $CleanupVerified
        CollectionStarted = $false
    }
}

function Get-PreviewQualificationRejectedEvaluation {
    param(
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] $Policy,
        [Parameter()] [string] $TrustPath = 'None',
        [Parameter()] [bool] $CleanupVerified = $true
    )

    $gatePolicy = Get-ReleaseGatesPolicy
    $gateRejected = Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.PACK_INVALID' `
        -Policy $gatePolicy
    $limitations = @('qualification-not-started')
    $packet = New-PreviewQualificationPacket -State Rejected -Decision NotStarted `
        -ReasonCode $ReasonCode -TrustPath $TrustPath -CleanupVerified:$CleanupVerified `
        -BlockingReasons @($ReasonCode) -Limitations $limitations
    $exitKind = if ($ReasonCode -eq 'QUALIFY.CLEANUP_INCOMPLETE') {
        'CleanupIncomplete'
    }
    else {
        'NotStarted'
    }
    New-PreviewQualificationEvaluation -State Rejected -ReasonCode $ReasonCode `
        -ExitKind $exitKind -Packet $packet -Manifest $gateRejected.Manifest `
        -Matrix $gateRejected.Matrix -CleanupVerified:$CleanupVerified
}

function Invoke-PreviewQualificationLaunchSmoke {
    param(
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter()] [string] $PowerShellPath
    )

    # Launch smoke proves the exact candidate still starts. The threat is
    # treating a bound digest as proof that the file runs, or starting
    # collection from a qualification session. The mechanism is a child
    # Help invocation with no assessment arguments. The trust assumption
    # is that Help cannot collect. Safe failure is to keep the smoke failed.
    if ([string]::IsNullOrWhiteSpace($PowerShellPath)) {
        $PowerShellPath = (Get-Command pwsh -CommandType Application).Source
    }
    if (-not (Test-Path -LiteralPath $CandidatePath -PathType Leaf)) {
        return $false
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PowerShellPath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
        '-NoLogo', '-NoProfile', '-File', $CandidatePath, '-Workflow', 'Help'
    )) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        $null = $process.Start()
        $standardOutput = $process.StandardOutput.ReadToEnd()
        $null = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            return $false
        }
        foreach ($line in @($standardOutput -split "`r?`n" | Where-Object { $_ })) {
            try {
                $record = $line | ConvertFrom-Json -Depth 10
            }
            catch {
                continue
            }
            if ([bool] (Get-PreviewQualificationProperty $record 'collectionStarted')) {
                return $false
            }
        }
        $true
    }
    catch {
        $false
    }
    finally {
        $process.Dispose()
    }
}

function Test-PreviewQualificationRowCoverage {
    param(
        [Parameter(Mandatory)] $Rows,
        [Parameter(Mandatory)] [string] $IdName,
        [Parameter(Mandatory)] $RequiredIds
    )

    foreach ($requiredId in @($RequiredIds)) {
        $row = @($Rows | Where-Object {
            [string] (Get-PreviewQualificationProperty $_ $IdName) -eq [string] $requiredId
        })
        if ($row.Count -eq 0 -or [string] $row[0].result -ne 'Pass') {
            return $false
        }
    }
    $true
}

function Get-PreviewQualificationSanitizedScenario {
    param(
        [Parameter(Mandatory)] [string] $ScenarioId,
        [Parameter(Mandatory)] [string] $WindowsFamily,
        [Parameter(Mandatory)] [string] $Result
    )

    $description = switch ($ScenarioId) {
        'windows-10-enterprise-x64' { 'Windows 10 Enterprise x64 Preview scenario' }
        'windows-11-enterprise-x64' { 'Windows 11 Enterprise x64 Preview scenario' }
        default { 'Windows Enterprise x64 Preview scenario' }
    }
    [pscustomobject][ordered]@{
        scenarioId = $ScenarioId
        windowsFamily = $WindowsFamily
        edition = 'Enterprise'
        architecture = 'x64'
        result = $Result
        sanitizedDescription = $description
    }
}

function ConvertTo-PreviewQualificationReason {
    param([Parameter(Mandatory)] [string] $ReasonCode)

    # Public packets use a closed QUALIFY reason set. The threat is leaking
    # an internal GATE code as the packet identity, or leaving the schema
    # unable to name a denial. The mechanism maps reviewed gate reasons
    # onto qualification reasons and keeps the original GATE codes in
    # blockingReasons. The trust assumption is that the packet is the
    # public decision. Safe failure is QUALIFY.DENIED.
    switch ($ReasonCode) {
        { $_ -like 'QUALIFY.*' } { return $ReasonCode }
        'GATE.PRODUCT_FAIL' { return 'QUALIFY.PRODUCT_FAIL' }
        'GATE.EXPIRED' { return 'QUALIFY.EXPIRED' }
        'GATE.INVALIDATED' { return 'QUALIFY.INVALIDATED' }
        'GATE.CANDIDATE_MISMATCH' { return 'QUALIFY.CANDIDATE_MISMATCH' }
        'GATE.WAIVER_REJECTED' { return 'QUALIFY.WAIVER_REJECTED' }
        'GATE.PRIVACY_REJECTED' { return 'QUALIFY.PRIVACY_REJECTED' }
        'GATE.CLEANUP_INCOMPLETE' { return 'QUALIFY.CLEANUP_INCOMPLETE' }
        'GATE.MISSING' { return 'QUALIFY.EVIDENCE_INCOMPLETE' }
        'GATE.QUALITY_BUDGET_FAIL' { return 'QUALIFY.EVIDENCE_INCOMPLETE' }
        default { return 'QUALIFY.DENIED' }
    }
}

function Invoke-PreviewQualificationWorkspaceCleanup {
    param(
        [Parameter()] [string] $WorkspacePath,
        [Parameter()] [string] $DerivedFileName = 'derived-qualification-packet.json'
    )

    if ([string]::IsNullOrWhiteSpace($WorkspacePath) -or
        -not (Test-Path -LiteralPath $WorkspacePath -PathType Container)) {
        return $true
    }
    $derived = Join-Path $WorkspacePath $DerivedFileName
    if (Test-Path -LiteralPath $derived -PathType Leaf) {
        Remove-Item -LiteralPath $derived -Force
    }
    -not (Test-Path -LiteralPath $derived -PathType Leaf)
}

function Invoke-PreviewQualification {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] [string] $RequestText,
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter()] $Ledger,
        [Parameter()] $ReleaseDefinition,
        [Parameter()] [string] $ExpectedLedgerSha256,
        [Parameter()] [datetimeoffset] $Now = [datetimeoffset]::UtcNow,
        [Parameter()] [string] $PowerShellPath
    )

    $policy = Get-PreviewQualificationPolicy
    $privacyReason = Test-PreviewQualificationPrivacyBoundary -Text $RequestText
    if ($privacyReason) {
        return Get-PreviewQualificationRejectedEvaluation -ReasonCode $privacyReason `
            -Policy $policy
    }
    if ($null -eq $Request -or
        [string] (Get-PreviewQualificationProperty $Request 'kind') -ne
            'win-pcinfo.preview-qualification-request') {
        return Get-PreviewQualificationRejectedEvaluation -ReasonCode 'QUALIFY.REQUEST_INVALID' `
            -Policy $policy
    }
    if (-not [bool] (Get-PreviewQualificationProperty $Request 'synthetic')) {
        return Get-PreviewQualificationRejectedEvaluation -ReasonCode 'QUALIFY.PRIVACY_REJECTED' `
            -Policy $policy
    }

    $workspaceReason = Get-PreviewQualificationWorkspaceRejection `
        -PrivateWorkspacePath $PrivateWorkspacePath -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory -Policy $policy -Request $Request
    if ($workspaceReason) {
        return Get-PreviewQualificationRejectedEvaluation -ReasonCode $workspaceReason `
            -Policy $policy
    }

    $trustPath = [string] (Get-PreviewQualificationProperty $Request 'trustPath')
    $bindings = Get-PreviewQualificationProperty $Request 'bindings'
    $candidateBytes = [System.IO.File]::ReadAllBytes($CandidatePath)
    $candidateDigest = Get-PreviewQualificationSha256 -Bytes $candidateBytes
    $declaredDigest = [string] (Get-PreviewQualificationProperty $bindings 'generatedContentSha256')
    $finalDigest = [string] (Get-PreviewQualificationProperty $bindings 'finalDistributableSha256')
    $derivedFrom = [string] (
        Get-PreviewQualificationProperty $bindings 'derivedFromGeneratedContentSha256'
    )
    $finalKind = [string] (
        Get-PreviewQualificationProperty $bindings 'finalDistributableIdentityKind'
    )
    $candidateBound = $declaredDigest -eq $candidateDigest
    $azureIdentity = [bool] (Get-PreviewQualificationProperty (
        Get-PreviewQualificationProperty $Request 'checkpoint'
    ) 'azureManagedIdentityAvailable')

    $blocking = [System.Collections.Generic.List[string]]::new()
    $limitations = [System.Collections.Generic.List[string]]::new()
    $limitations.Add('synthetic-evidence-not-promotable')
    $limitations.Add('human-approval-required')

    # Exact-candidate binding is the only identity that may be qualified.
    # The threat is approving a later rebuild, an adjacent file, or the
    # unsigned script as if it were the signed zip. The mechanism compares
    # SHA-256 of the running file to the request and requires a distinct
    # derived final identity. The trust assumption is that these bytes are
    # the candidate under test. Safe failure is a denial packet.
    if (-not $candidateBound) {
        $blocking.Add('QUALIFY.CANDIDATE_MISMATCH')
    }
    if ([bool] $policy.identity.finalMustBeDistinct -and $finalDigest -eq $candidateDigest) {
        $blocking.Add('QUALIFY.FINAL_IDENTITY_NOT_DISTINCT')
    }
    if ([bool] $policy.identity.finalMustDeriveFromQualifiedContent -and
        $derivedFrom -ne $candidateDigest) {
        $blocking.Add('QUALIFY.FINAL_IDENTITY_NOT_DERIVED')
    }

    $signingUnavailability = [string] (
        Get-PreviewQualificationProperty $Request 'signingUnavailability'
    )
    if ($trustPath -eq 'AttestedPreview') {
        # Convenience must not become an unsigned Preview. The threat is
        # skipping Artifact Signing because it is slower. The mechanism
        # accepts only the two reviewed outage reasons and only the
        # unsigned portable identity. The trust assumption is SHA-256 of
        # the reviewed zip, not Authenticode. Safe failure is denial.
        if ($signingUnavailability -notin @($policy.attestedFallback.permittedReasons)) {
            $blocking.Add('QUALIFY.ATTESTED_CONVENIENCE')
        }
        if ($finalKind -ne [string] $policy.identity.finalUnsignedKind) {
            $blocking.Add('QUALIFY.ATTESTED_UNSIGNED_REQUIRED')
        }
        $limitations.Add('attested-preview-not-trusted')
    }
    elseif ($trustPath -eq 'AuthenticodeSigned') {
        if ($finalKind -ne [string] $policy.identity.finalSignedKind) {
            $blocking.Add('QUALIFY.SIGNED_IDENTITY_REQUIRED')
        }
    }
    else {
        $blocking.Add('QUALIFY.REQUEST_INVALID')
        $trustPath = 'None'
    }

    if ([bool] (Get-PreviewQualificationProperty $Request 'waiverRequested')) {
        $blocking.Add('QUALIFY.WAIVER_REJECTED')
    }
    if ([bool] (Get-PreviewQualificationProperty $Request 'cleanupPending')) {
        $blocking.Add('QUALIFY.CLEANUP_PENDING')
    }
    if ([bool] (Get-PreviewQualificationProperty $Request 'liveAzureStarted')) {
        $blocking.Add('QUALIFY.AZURE_OVERCLAIM')
    }
    if ([string] (Get-PreviewQualificationProperty $Request 'evidenceKind') -eq
        'LiveValidation') {
        $blocking.Add('QUALIFY.LIVE_AZURE_NOT_STARTED')
        $limitations.Add('live-azure-not-started')
    }

    $coverage = [pscustomobject][ordered]@{
        gatesComplete = $false
        privilegeComplete = $false
        networkComplete = $false
        localeComplete = $false
        validationControlComplete = (Test-PreviewQualificationRowCoverage `
            -Rows @(Get-PreviewQualificationProperty $Request 'validationControls') `
            -IdName 'controlId' -RequiredIds $policy.requiredValidationControls)
        failureInjectionComplete = (Test-PreviewQualificationRowCoverage `
            -Rows @(Get-PreviewQualificationProperty $Request 'failureInjections') `
            -IdName 'faultId' -RequiredIds $policy.requiredFailureInjections)
        packageExerciseComplete = (Test-PreviewQualificationRowCoverage `
            -Rows @(Get-PreviewQualificationProperty $Request 'packageExercises') `
            -IdName 'exerciseId' -RequiredIds $policy.requiredPackageExercises)
        recoveryComplete = (Test-PreviewQualificationRowCoverage `
            -Rows @(Get-PreviewQualificationProperty $Request 'recoveryExercises') `
            -IdName 'exerciseId' -RequiredIds $policy.requiredRecoveryExercises)
    }
    if (-not $coverage.validationControlComplete -or
        -not $coverage.failureInjectionComplete -or
        -not $coverage.packageExerciseComplete -or
        -not $coverage.recoveryComplete) {
        $blocking.Add('QUALIFY.EVIDENCE_INCOMPLETE')
    }

    $smokePassed = Invoke-PreviewQualificationLaunchSmoke -CandidatePath $CandidatePath `
        -PowerShellPath $PowerShellPath
    $smokes = @(
        [pscustomobject][ordered]@{
            smokeId = 'launch'
            result = $(if ($smokePassed) { 'Pass' } else { 'ProductFail' })
            reasonCode = $(if ($smokePassed) { 'QUALIFY.PASS' } else { 'QUALIFY.SMOKE_FAILED' })
        }
        [pscustomobject][ordered]@{
            smokeId = 'trust'
            result = $(if ($candidateBound -and $blocking -notcontains 'QUALIFY.ATTESTED_CONVENIENCE' -and
                $blocking -notcontains 'QUALIFY.SIGNED_IDENTITY_REQUIRED' -and
                $blocking -notcontains 'QUALIFY.ATTESTED_UNSIGNED_REQUIRED') { 'Pass' } else { 'NotRun' })
            reasonCode = $(if ($candidateBound) { 'QUALIFY.PASS' } else { 'QUALIFY.CANDIDATE_MISMATCH' })
        }
    )
    if (-not $smokePassed) {
        $blocking.Add('QUALIFY.SMOKE_FAILED')
    }

    $pack = Get-PreviewQualificationProperty $Request 'evidencePack'
    $packText = $null
    if ($null -ne $pack) {
        $packText = $pack | ConvertTo-Json -Depth 30
    }
    $gatePolicy = Get-ReleaseGatesPolicy
    $gateWorkspace = Join-Path $PrivateWorkspacePath 'gate-derived'
    $null = New-Item -ItemType Directory -Path $gateWorkspace -Force
    $gateEvaluation = Invoke-ReleaseGateEvaluation -Pack $pack -Policy $gatePolicy `
        -Ledger $Ledger -ReleaseDefinition $ReleaseDefinition -PackText $packText `
        -ExpectedGeneratedContentSha256 $candidateDigest `
        -ExpectedLedgerSha256 $ExpectedLedgerSha256 -Now $Now `
        -WorkspacePath $gateWorkspace -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory

    $coverage.gatesComplete = $true
    foreach ($gate in @($gateEvaluation.Manifest.gates)) {
        if ([string] $gate.result -ne 'Pass') {
            $coverage.gatesComplete = $false
        }
    }
    $packPrivileges = @(Get-PreviewQualificationProperty $pack 'privilegePaths')
    $coverage.privilegeComplete = Test-PreviewQualificationRowCoverage `
        -Rows $packPrivileges -IdName 'pathId' `
        -RequiredIds $policy.requiredPrivilegePaths
    $packNetworks = @(Get-PreviewQualificationProperty $pack 'networkBehaviors')
    $coverage.networkComplete = Test-PreviewQualificationRowCoverage `
        -Rows $packNetworks -IdName 'behavior' `
        -RequiredIds $policy.requiredNetworkBehaviors
    $requiredLocales = @($policy.requiredLocales)
    $packLocales = @(Get-PreviewQualificationProperty $pack 'locales')
    $coverage.localeComplete = $true
    foreach ($locale in $requiredLocales) {
        if ($locale -notin $packLocales) {
            $coverage.localeComplete = $false
        }
    }

    foreach ($gateReason in @($gateEvaluation.Manifest.promotion.blockingReasons)) {
        if ($gateReason -in @(
            'GATE.SYNTHETIC_EVIDENCE_NOT_PROMOTABLE'
        )) {
            continue
        }
        if ($gateReason -notin $blocking) {
            $blocking.Add([string] $gateReason)
        }
    }
    if (-not [bool] $gateEvaluation.Manifest.unsignedContentQualified -and
        'GATE.MISSING' -in @($gateEvaluation.Manifest.promotion.blockingReasons) -and
        'QUALIFY.EVIDENCE_INCOMPLETE' -notin $blocking) {
        $blocking.Add('QUALIFY.EVIDENCE_INCOMPLETE')
    }

    $claimed = @()
    foreach ($snapshot in @($gateEvaluation.Matrix.scenarioSnapshots)) {
        $claimed += Get-PreviewQualificationSanitizedScenario `
            -ScenarioId ([string] $snapshot.scenarioId) `
            -WindowsFamily ([string] $snapshot.windowsFamily) `
            -Result ([string] $snapshot.evidenceResult)
    }
    if ($claimed.Count -eq 0) {
        $claimed += Get-PreviewQualificationSanitizedScenario `
            -ScenarioId 'windows-10-enterprise-x64' -WindowsFamily 'Windows 10' `
            -Result 'NotRun'
        $claimed += Get-PreviewQualificationSanitizedScenario `
            -ScenarioId 'windows-11-enterprise-x64' -WindowsFamily 'Windows 11' `
            -Result 'NotRun'
    }

    $finalSmokeResult = 'NotRun'
    $finalSmokeReason = 'QUALIFY.EVIDENCE_INCOMPLETE'
    if ([bool] $gateEvaluation.Manifest.finalArtifactQualified -and $smokePassed -and
        $candidateBound) {
        $finalSmokeResult = 'Pass'
        $finalSmokeReason = 'QUALIFY.PASS'
    }
    elseif (-not $smokePassed) {
        $finalSmokeResult = 'ProductFail'
        $finalSmokeReason = 'QUALIFY.SMOKE_FAILED'
    }
    $smokes += [pscustomobject][ordered]@{
        smokeId = 'final-artifact'
        result = $finalSmokeResult
        reasonCode = $finalSmokeReason
    }

    $uniqueBlocking = @($blocking | Select-Object -Unique)
    $approved = $uniqueBlocking.Count -eq 0 -and
        [bool] $gateEvaluation.Manifest.unsignedContentQualified -and
        [bool] $gateEvaluation.Manifest.finalArtifactQualified -and
        $smokePassed -and $candidateBound
    $primary = if ($approved) {
        'QUALIFY.APPROVED'
    }
    elseif ($uniqueBlocking.Count -gt 0) {
        ConvertTo-PreviewQualificationReason -ReasonCode ([string] $uniqueBlocking[0])
    }
    else {
        'QUALIFY.DENIED'
    }
    if (-not $approved -and $primary -notin $uniqueBlocking) {
        $uniqueBlocking = @($primary) + @($uniqueBlocking)
    }

    $zeroResidue = $false
    $zeroGate = @($gateEvaluation.Manifest.gates | Where-Object {
        [string] $_.gateId -eq 'zero-round-residue'
    })
    if ($zeroGate.Count -gt 0 -and [string] $zeroGate[0].result -eq 'Pass' -and
        [bool] $zeroGate[0].cleanupVerified) {
        $zeroResidue = $true
    }

    $state = if ($approved) { 'Approved' } else { 'Denied' }
    $decision = if ($approved) { 'Qualify' } else { 'Deny' }
    $packet = New-PreviewQualificationPacket -State $state -Decision $decision `
        -ReasonCode $primary -TrustPath $trustPath `
        -UnsignedContentQualified:([bool] $gateEvaluation.Manifest.unsignedContentQualified) `
        -FinalArtifactQualified:([bool] $gateEvaluation.Manifest.finalArtifactQualified -and $approved) `
        -CandidateBound:$candidateBound `
        -QualityThreeCleanPassed:([bool] $gateEvaluation.Manifest.qualityBudget.threeCleanPassed) `
        -AzureIdentityAvailable:$azureIdentity -ZeroResidueVerified:$zeroResidue `
        -Smokes $smokes -Coverage $coverage -ClaimedScenarios $claimed `
        -BlockingReasons $uniqueBlocking -Limitations @($limitations | Select-Object -Unique)

    $derived = Join-Path $PrivateWorkspacePath 'derived-qualification-packet.json'
    [System.IO.File]::WriteAllText(
        $derived,
        ($packet | ConvertTo-Json -Compress -Depth 20),
        [System.Text.UTF8Encoding]::new($false)
    )
    $cleanupVerified = Invoke-PreviewQualificationWorkspaceCleanup `
        -WorkspacePath $PrivateWorkspacePath
    $packet.cleanupVerified = [bool] $cleanupVerified
    if (-not $cleanupVerified) {
        $packet.state = 'Denied'
        $packet.decision = 'Deny'
        $packet.reasonCode = 'QUALIFY.CLEANUP_INCOMPLETE'
        return New-PreviewQualificationEvaluation -State Denied `
            -ReasonCode 'QUALIFY.CLEANUP_INCOMPLETE' -ExitKind CleanupIncomplete `
            -Packet $packet -Manifest $gateEvaluation.Manifest `
            -Matrix $gateEvaluation.Matrix -CleanupVerified:$false
    }

    New-PreviewQualificationEvaluation -State $state -ReasonCode $primary `
        -ExitKind Completed -Packet $packet -Manifest $gateEvaluation.Manifest `
        -Matrix $gateEvaluation.Matrix -CleanupVerified:$true
}
