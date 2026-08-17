# Build.ps1 replaces both sentinels with the release-bound gate policy
# and its SHA-256 digest. The generated application treats that table as
# the only trusted copy of the Preview.1 evidence contract.
$script:ReleaseGatesPolicyBase64 = '__RELEASE_GATES_POLICY_BASE64__'
$script:ReleaseGatesPolicyDigest = '__RELEASE_GATES_POLICY_SHA256__'

function Get-ReleaseGatesSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-ReleaseGatesPolicy {
    # The threat is a substituted policy that waives evidence, invents a
    # Supported claim, or treats checksums as Authenticode. The mechanism is
    # an embedded digest, or the reviewed repository file when this module is
    # sourced during development. The trust assumption is that those bytes
    # were reviewed with the rest of the release. Safe failure is to refuse
    # evaluation rather than invent a looser contract.
    if ($script:ReleaseGatesPolicyBase64 -eq
        ('__RELEASE_GATES_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-release-gates.json'
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-ReleaseGatesSha256 $bytes
    }
    else {
        [byte[]] $bytes = [System.Convert]::FromBase64String(
            $script:ReleaseGatesPolicyBase64
        )
        $expectedDigest = $script:ReleaseGatesPolicyDigest
    }
    if ((Get-ReleaseGatesSha256 $bytes) -ne $expectedDigest) {
        throw 'The release-gate policy failed its embedded digest check.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $json | ConvertFrom-Json -Depth 30
}

function Get-ReleaseGatesProperty {
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

function ConvertTo-ReleaseGatesDateTimeOffset {
    param([Parameter(Mandatory)] $Value)

    if ($Value -is [datetimeoffset]) {
        return $Value.ToUniversalTime()
    }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) {
            return [datetimeoffset]::new($Value, [TimeSpan]::Zero)
        }
        return [datetimeoffset] $Value.ToUniversalTime()
    }
    [datetimeoffset]::Parse(
        [string] $Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
            [System.Globalization.DateTimeStyles]::AdjustToUniversal
    )
}

function Test-ReleaseGatesPathUnderRoot {
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

function Test-ReleaseGatesPublicPath {
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
    Test-ReleaseGatesPathUnderRoot -Path $Path -Root $publicRoot
}

function Test-ReleaseGatesReparsePath {
    param([Parameter(Mandatory)] [string] $Path)

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

function Get-ReleaseGatesCatalogPath {
    param(
        [Parameter()] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] [string] $RelativePath
    )

    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($root in @($ApplicationDirectory, $RepositoryRoot)) {
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            $roots.Add($root)
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ApplicationDirectory)) {
        $parent = Split-Path -Parent $ApplicationDirectory
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
            $roots.Add($parent)
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

function Test-ReleaseGatesPrivacyBoundary {
    param([Parameter(Mandatory)] [string] $Text)

    # Public Release Evidence is a projection, not a dump. The threat is
    # committing or printing a credential, a real cloud identifier, a
    # Terraform plan, a local user path, or a non-synthetic validation
    # record. The mechanism is a closed needle list applied to the raw pack
    # text before any derived file is written. The trust assumption is that
    # approved fixtures stay synthetic and identifier-free. Safe failure is
    # GATE.PRIVACY_REJECTED with no workspace residue.
    $needles = @(
        '(?i)clientSecret'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)(password|secret|api[_-]?key|access_token)\s*[:=]'
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)\.terraform'
        '(?i)\.tfstate'
        '(?i)crash(\..*)?\.log'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
        '(?i)\b\d{1,3}(\.\d{1,3}){3}\b'
        '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
    )
    foreach ($needle in $needles) {
        if ($Text -match $needle) {
            return 'GATE.PRIVACY_REJECTED'
        }
    }
    $null
}

function Test-ReleaseGatesRuntime {
    param(
        [Parameter()] [string] $Version,
        [Parameter()] [string] $Architecture,
        [Parameter()] [string] $Product,
        [Parameter()] [string] $Edition,
        [Parameter(Mandatory)] $Policy
    )

    if ($Product -and $Product -ne [string] $Policy.runtime.product) {
        return $false
    }
    if ($Edition -and $Edition -ne [string] $Policy.runtime.edition) {
        return $false
    }
    if ($Architecture -ne [string] $Policy.runtime.claimArchitecture) {
        return $false
    }
    try {
        $parsed = [version] $Version
        $minimum = [version] [string] $Policy.runtime.minimumVersion
    }
    catch {
        return $false
    }
    if ($parsed -lt $minimum) {
        return $false
    }
    if ($parsed.Major -ge [int] $Policy.runtime.maximumMajorExclusive) {
        return $false
    }
    $true
}

function Test-ReleaseGatesExpired {
    param(
        [Parameter()] $ObservedAt,
        [Parameter(Mandatory)] [string] $FreshnessClass,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [datetimeoffset] $Now
    )

    if ($FreshnessClass -eq 'Automated' -and
        [bool] $Policy.freshness.automatedDoesNotExpireByAge) {
        return $false
    }
    if ($null -eq $ObservedAt) {
        return $true
    }
    $days = switch ($FreshnessClass) {
        'ClientVmValidation' { [int] $Policy.freshness.clientVmValidationDays }
        'CloudIdentityManagementSecurityNetwork' {
            [int] $Policy.freshness.cloudIdentityManagementSecurityNetworkDays
        }
        'PhysicalFirmwareOemBatteryPeripheral' {
            [int] $Policy.freshness.physicalFirmwareOemBatteryPeripheralDays
        }
        default { [int] $Policy.freshness.clientVmValidationDays }
    }
    try {
        $observed = ConvertTo-ReleaseGatesDateTimeOffset -Value $ObservedAt
    }
    catch {
        return $true
    }
    ($Now - $observed).TotalDays -gt [double] $days
}

function Get-ReleaseGatesEmptyQuality {
    param([Parameter(Mandatory)] $Policy)

    [pscustomobject][ordered]@{
        version = [string] $Policy.qualityBudget.version
        provisional = $true
        threeCleanPassed = $false
        attemptCount = 0
        passCount = 0
        infrastructureInconclusiveCount = 0
        outcome = 'NotRun'
        knownLimitations = @('evaluation-not-started')
    }
}

function New-ReleaseGatesManifest {
    param(
        [Parameter(Mandatory)] [ValidateSet('Evaluated', 'Rejected')] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [string] $Stage = 'None',
        [Parameter()] [bool] $SyntheticEvidenceOnly = $true,
        [Parameter()] [bool] $UnsignedContentQualified = $false,
        [Parameter()] [bool] $FinalArtifactQualified = $false,
        [Parameter()] $QualityBudget,
        [Parameter()] $Gates = @(),
        [Parameter()] $Promotion,
        [Parameter()] $Limitations = @(),
        [Parameter()] [bool] $CleanupVerified = $true
    )

    if ($null -eq $QualityBudget) {
        throw 'A Release Evidence Manifest requires a quality-budget projection.'
    }
    if ($null -eq $Promotion) {
        $Promotion = [pscustomobject][ordered]@{
            publicationAuthorized = $false
            previewPromotionReady = $false
            supportedPromotionReady = $false
            unsignedContentQualified = $false
            finalArtifactQualified = $false
            derivedClaimState = 'None'
            waiverApplied = $false
            blockingReasons = @($ReasonCode)
        }
    }
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.release-evidence-manifest'
        contractVersion = '1.0.0'
        state = $State
        reasonCode = $ReasonCode
        syntheticEvidenceOnly = [bool] $SyntheticEvidenceOnly
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        sliceDeliversCapability = $false
        collectionStarted = $false
        stage = $Stage
        unsignedContentQualified = [bool] $UnsignedContentQualified
        finalArtifactQualified = [bool] $FinalArtifactQualified
        qualityBudget = $QualityBudget
        gates = @($Gates)
        promotion = $Promotion
        limitations = @($Limitations)
        cleanupVerified = [bool] $CleanupVerified
    }
}

function New-ReleaseGatesMatrix {
    param(
        [Parameter(Mandatory)] [ValidateSet('Derived', 'Rejected')] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [bool] $DerivedFromFrozenLedger = $false,
        [Parameter()] $LedgerSchemaVersion,
        [Parameter()] $Rows = @(),
        [Parameter()] $ScenarioSnapshots = @(),
        [Parameter()] $Limitations = @()
    )

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.preview-capability-matrix'
        contractVersion = '1.0.0'
        state = $State
        reasonCode = $ReasonCode
        handEdited = $false
        derivedFromFrozenLedger = [bool] $DerivedFromFrozenLedger
        ledgerSchemaVersion = $LedgerSchemaVersion
        release = '2.0.0-preview.1'
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        rows = @($Rows)
        scenarioSnapshots = @($ScenarioSnapshots)
        limitations = @($Limitations)
    }
}

function New-ReleaseGatesEvaluation {
    param(
        [Parameter(Mandatory)] [ValidateSet('Evaluated', 'Rejected')] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [ValidateSet('Completed', 'NotStarted', 'CleanupIncomplete')]
        [string] $ExitKind,
        [Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)] $Matrix,
        [Parameter()] [bool] $CleanupVerified = $true
    )

    [pscustomobject][ordered]@{
        State = $State
        ReasonCode = $ReasonCode
        ExitKind = $ExitKind
        Manifest = $Manifest
        Matrix = $Matrix
        CleanupVerified = [bool] $CleanupVerified
        CollectionStarted = $false
    }
}

function Get-ReleaseGatesRejectedEvaluation {
    param(
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] $Policy,
        [Parameter()] [string] $Stage = 'None',
        [Parameter()] [bool] $CleanupVerified = $true
    )

    $exitKind = if ($ReasonCode -eq 'GATE.CLEANUP_INCOMPLETE') {
        'CleanupIncomplete'
    }
    else {
        'NotStarted'
    }
    $limitations = @('evaluation-not-started')
    $manifest = New-ReleaseGatesManifest -State Rejected -ReasonCode $ReasonCode `
        -Stage $Stage -QualityBudget (Get-ReleaseGatesEmptyQuality -Policy $Policy) `
        -Limitations $limitations -CleanupVerified:$CleanupVerified
    $matrix = New-ReleaseGatesMatrix -State Rejected -ReasonCode $ReasonCode `
        -Limitations $limitations
    New-ReleaseGatesEvaluation -State Rejected -ReasonCode $ReasonCode `
        -ExitKind $exitKind -Manifest $manifest -Matrix $matrix `
        -CleanupVerified:$CleanupVerified
}

function Get-ReleaseGatesRequiredDefinitions {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $Stage
    )

    @($Policy.gateDefinitions) | Where-Object {
        $Stage -in @($_.stages)
    }
}

function Resolve-ReleaseGatesEffectiveResult {
    param(
        [Parameter(Mandatory)] $Candidates,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $ExpectedDigest,
        [Parameter(Mandatory)] [datetimeoffset] $Now
    )

    $effective = 'NotRun'
    $reason = 'GATE.NOT_RUN'
    $expired = $false
    $candidateBound = $true
    $runtimeSupported = $true
    $cleanupVerified = $true
    $freshnessClass = 'Automated'
    $affected = @('CAP-0030')
    $latestPassAt = $null

    foreach ($candidate in @($Candidates | Sort-Object {
        try { ConvertTo-ReleaseGatesDateTimeOffset $_.observedAt } catch { [datetimeoffset]::MinValue }
    })) {
        $freshnessClass = [string] $candidate.freshnessClass
        $affected = @($candidate.affectedClaimIds)
        $cleanupVerified = $cleanupVerified -and [bool] $candidate.cleanupVerified
        $bound = [string] $candidate.generatedContentSha256 -eq $ExpectedDigest
        if (-not $bound) {
            $candidateBound = $false
            $effective = 'Invalidated'
            $reason = 'GATE.CANDIDATE_MISMATCH'
            continue
        }
        $supported = Test-ReleaseGatesRuntime -Version ([string] $candidate.runtimeVersion) `
            -Architecture ([string] $candidate.architecture) -Policy $Policy
        if (-not $supported) {
            $runtimeSupported = $false
            $effective = 'Invalidated'
            $reason = 'GATE.UNSUPPORTED_RUNTIME'
            continue
        }
        $isExpired = Test-ReleaseGatesExpired -ObservedAt $candidate.observedAt `
            -FreshnessClass $freshnessClass -Policy $Policy -Now $Now
        if ($isExpired -and [string] $candidate.result -eq 'Pass') {
            $expired = $true
            $effective = 'Expired'
            $reason = 'GATE.EXPIRED'
            continue
        }
        switch ([string] $candidate.result) {
            'ProductFail' {
                $effective = 'ProductFail'
                $reason = [string] $candidate.reasonCode
                if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'GATE.PRODUCT_FAIL' }
            }
            'Invalidated' {
                if ($effective -ne 'ProductFail') {
                    $effective = 'Invalidated'
                    $reason = [string] $candidate.reasonCode
                    if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'GATE.INVALIDATED' }
                }
            }
            'Pass' {
                if ($effective -notin @('ProductFail')) {
                    $effective = 'Pass'
                    $reason = 'GATE.PASS'
                    $expired = $false
                    try {
                        $latestPassAt = ConvertTo-ReleaseGatesDateTimeOffset $candidate.observedAt
                    }
                    catch {
                        $latestPassAt = $Now
                    }
                }
            }
            'InfrastructureInconclusive' {
                if ($effective -in @('NotRun', 'InfrastructureInconclusive')) {
                    $effective = 'InfrastructureInconclusive'
                    $reason = 'GATE.INFRASTRUCTURE_INCONCLUSIVE'
                }
            }
            'Expired' {
                if ($effective -in @('NotRun', 'Expired')) {
                    $expired = $true
                    $effective = 'Expired'
                    $reason = 'GATE.EXPIRED'
                }
            }
            default {
                if ($effective -eq 'NotRun') {
                    $effective = [string] $candidate.result
                    $reason = [string] $candidate.reasonCode
                }
            }
        }
    }

    if ($effective -eq 'Pass' -and $null -ne $latestPassAt) {
        $expired = $false
    }

    [pscustomobject][ordered]@{
        result = $effective
        reasonCode = $reason
        expired = [bool] $expired
        candidateBound = [bool] $candidateBound
        runtimeSupported = [bool] $runtimeSupported
        cleanupVerified = [bool] $cleanupVerified
        freshnessClass = $freshnessClass
        affectedClaimIds = @($affected)
    }
}

function Test-ReleaseGatesMeasurementPass {
    param(
        [Parameter(Mandatory)] $Measurement,
        [Parameter(Mandatory)] $Policy
    )

    if ([string] $Measurement.result -ne 'Pass') {
        return $false
    }
    $binding = $Policy.qualityBudget.binding
    $provisional = $Policy.qualityBudget.provisional
    if ([int] $Measurement.firstProgressMilliseconds -gt [int] $binding.firstProgressMilliseconds) {
        return $false
    }
    if ([int] $Measurement.heartbeatGapMilliseconds -gt [int] $binding.heartbeatGapMilliseconds) {
        return $false
    }
    if ([int] $Measurement.cancellationAckMilliseconds -gt [int] $binding.cancellationAckMilliseconds) {
        return $false
    }
    if ([bool] $provisional.enforced) {
        if ([int] $Measurement.wallTimeMilliseconds -gt [int] $provisional.profileCompletionMilliseconds) {
            return $false
        }
        if ([long] $Measurement.peakPrivateMemoryBytes -gt [long] $provisional.peakPrivateMemoryBytes) {
            return $false
        }
        if ([long] $Measurement.peakWorkingSetBytes -gt [long] $provisional.peakWorkingSetBytes) {
            return $false
        }
        if ([long] $Measurement.peakWorkspaceBytes -gt [long] $provisional.peakWorkspaceBytes) {
            return $false
        }
        if ([long] $Measurement.packageBytes -gt [long] $provisional.packageBytes) {
            return $false
        }
        if ([long] $Measurement.reportBytes -gt [long] $provisional.reportBytes) {
            return $false
        }
    }
    if (-not [bool] $Measurement.cleanupVerified) { return $false }
    if (-not [bool] $Measurement.localeNeutral) { return $false }
    if (-not [bool] $Measurement.deterministicDerivation) { return $false }
    $true
}

function Get-ReleaseGatesQualityProjection {
    param(
        [Parameter(Mandatory)] $Pack,
        [Parameter(Mandatory)] $Policy
    )

    $measurements = @($Pack.qualityMeasurements)
    $passCount = @($measurements | Where-Object { Test-ReleaseGatesMeasurementPass -Measurement $_ -Policy $Policy }).Count
    $infraCount = @($measurements | Where-Object { [string] $_.result -eq 'InfrastructureInconclusive' }).Count
    $failCount = @($measurements | Where-Object {
        [string] $_.result -eq 'ProductFail' -or (
            [string] $_.result -eq 'Pass' -and
            -not (Test-ReleaseGatesMeasurementPass -Measurement $_ -Policy $Policy)
        )
    }).Count
    $required = [int] $Policy.qualityBudget.previewCleanMeasurementCount
    $allowedInfra = [int] $Policy.qualityBudget.infrastructureReplacementAttempts
    $outcome = 'NotRun'
    $threeClean = $false
    $limitations = @('provisional-ceilings-enforced')
    if ($failCount -gt 0) {
        $outcome = 'ProductFail'
        $limitations += 'quality-measurement-product-fail'
    }
    elseif ($passCount -ge $required -and $infraCount -le $allowedInfra) {
        $outcome = 'Pass'
        $threeClean = $true
    }
    elseif ($infraCount -gt 0) {
        $outcome = 'InfrastructureInconclusive'
        $limitations += 'quality-measurement-infrastructure-inconclusive'
    }
    elseif ($measurements.Count -eq 0) {
        $outcome = 'NotRun'
    }
    else {
        $outcome = 'ProductFail'
        $limitations += 'quality-measurement-count-insufficient'
    }

    [pscustomobject][ordered]@{
        version = [string] $Policy.qualityBudget.version
        provisional = $true
        threeCleanPassed = [bool] $threeClean
        attemptCount = $measurements.Count
        passCount = $passCount
        infrastructureInconclusiveCount = $infraCount
        outcome = $outcome
        knownLimitations = @($limitations | Select-Object -Unique)
    }
}

function Get-ReleaseGatesWorkspaceRejection {
    param(
        [Parameter()] [string] $WorkspacePath,
        [Parameter()] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] $Policy
    )

    if ([string]::IsNullOrWhiteSpace($WorkspacePath)) {
        return $null
    }
    if ($WorkspacePath.StartsWith('\\', [System.StringComparison]::Ordinal) -or
        $WorkspacePath.StartsWith('//', [System.StringComparison]::Ordinal)) {
        return 'GATE.PRIVACY_REJECTED'
    }
    if ([bool] $Policy.workspace.rejectPublicPath -and
        (Test-ReleaseGatesPublicPath -Path $WorkspacePath)) {
        return 'GATE.PRIVACY_REJECTED'
    }
    if ([bool] $Policy.workspace.rejectRepositoryPath) {
        if (-not [string]::IsNullOrWhiteSpace($RepositoryRoot) -and
            (Test-Path -LiteralPath $RepositoryRoot) -and
            (Test-ReleaseGatesPathUnderRoot -Path $WorkspacePath -Root $RepositoryRoot)) {
            return 'GATE.PRIVACY_REJECTED'
        }
        if (-not [string]::IsNullOrWhiteSpace($ApplicationDirectory) -and
            (Test-Path -LiteralPath $ApplicationDirectory) -and
            (Test-ReleaseGatesPathUnderRoot -Path $WorkspacePath -Root $ApplicationDirectory)) {
            return 'GATE.PRIVACY_REJECTED'
        }
    }
    if (Test-ReleaseGatesReparsePath -Path $WorkspacePath) {
        return 'GATE.PRIVACY_REJECTED'
    }
    if (-not (Test-Path -LiteralPath $WorkspacePath -PathType Container)) {
        return 'GATE.PACK_INVALID'
    }
    $null
}

function Invoke-ReleaseGatesWorkspaceCleanup {
    param(
        [Parameter()] [string] $WorkspacePath,
        [Parameter()] [string] $DerivedFileName = 'derived-public-manifest.json'
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

function Get-ReleaseGatesScenarioLimitations {
    param([Parameter()] $ReleaseDefinition)

    $values = @()
    if ($null -ne $ReleaseDefinition) {
        $values = @($ReleaseDefinition.notYetSupportedScenarioDimensions)
    }
    if ($values.Count -eq 0) {
        $values = @(
            'untested-windows-edition-build-or-architecture'
            'physical-firmware-and-battery'
            'real-peripherals'
            'externally-managed-group-policy-or-mdm'
            'co-management'
            'real-third-party-security-products'
        )
    }
    @($values)
}

function Invoke-ReleaseGateEvaluation {
    param(
        [Parameter(Mandatory)] $Pack,
        [Parameter(Mandatory)] $Policy,
        [Parameter()] $Ledger,
        [Parameter()] $ReleaseDefinition,
        [Parameter()] [string] $PackText,
        [Parameter()] [string] $ExpectedGeneratedContentSha256,
        [Parameter()] [string] $ExpectedLedgerSha256,
        [Parameter()] [datetimeoffset] $Now = [datetimeoffset]::UtcNow,
        [Parameter()] [string] $WorkspacePath,
        [Parameter()] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory
    )

    $scanText = $PackText
    if ([string]::IsNullOrWhiteSpace($scanText)) {
        $scanText = $Pack | ConvertTo-Json -Compress -Depth 20
    }
    $privacyReason = Test-ReleaseGatesPrivacyBoundary -Text $scanText
    if ($privacyReason) {
        return Get-ReleaseGatesRejectedEvaluation -ReasonCode $privacyReason -Policy $Policy
    }
    if ($null -eq $Pack -or [string] (Get-ReleaseGatesProperty $Pack 'kind') -ne
        'win-pcinfo.release-evidence-pack') {
        return Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.PACK_INVALID' -Policy $Policy
    }
    if (-not [bool] (Get-ReleaseGatesProperty $Pack 'synthetic')) {
        return Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.PRIVACY_REJECTED' `
            -Policy $Policy
    }

    $workspaceReason = Get-ReleaseGatesWorkspaceRejection -WorkspacePath $WorkspacePath `
        -RepositoryRoot $RepositoryRoot -ApplicationDirectory $ApplicationDirectory `
        -Policy $Policy
    if ($workspaceReason) {
        return Get-ReleaseGatesRejectedEvaluation -ReasonCode $workspaceReason -Policy $Policy
    }

    $stage = [string] (Get-ReleaseGatesProperty $Pack 'stage')
    if ($stage -notin @('PreSigning', 'FinalArtifactValidation')) {
        return Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.PACK_INVALID' `
            -Policy $Policy -Stage 'None'
    }

    $bindings = Get-ReleaseGatesProperty $Pack 'bindings'
    if ($null -eq $bindings) {
        return Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.IDENTITY_BINDING_INVALID' `
            -Policy $Policy -Stage $stage
    }
    $boundDigest = [string] $bindings.generatedContentSha256
    if ($boundDigest -notmatch '^[0-9a-f]{64}$') {
        return Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.IDENTITY_BINDING_INVALID' `
            -Policy $Policy -Stage $stage
    }
    if ([string] $bindings.generatedContentIdentityKind -ne
        [string] $Policy.identity.preSigningKind) {
        return Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.IDENTITY_BINDING_INVALID' `
            -Policy $Policy -Stage $stage
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedGeneratedContentSha256) -and
        $ExpectedGeneratedContentSha256 -ne $boundDigest) {
        $boundDigest = $ExpectedGeneratedContentSha256
    }
    if ([string] $bindings.qualityBudgetVersion -ne [string] $Policy.qualityBudget.version) {
        return Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.QUALITY_BUDGET_FAIL' `
            -Policy $Policy -Stage $stage
    }
    $ledgerMatched = $true
    if (-not [string]::IsNullOrWhiteSpace($ExpectedLedgerSha256) -and
        $ExpectedLedgerSha256 -ne [string] $bindings.ledgerSha256) {
        $ledgerMatched = $false
    }

    $bindingRuntimeOk = Test-ReleaseGatesRuntime `
        -Version ([string] $bindings.runtime.version) `
        -Architecture ([string] $bindings.runtime.architecture) `
        -Product ([string] $bindings.runtime.product) `
        -Edition ([string] $bindings.runtime.edition) `
        -Policy $Policy

    $packGates = @($Pack.gates)
    $publicGates = @()
    $blocking = [System.Collections.Generic.List[string]]::new()
    $requiredDefinitions = Get-ReleaseGatesRequiredDefinitions -Policy $Policy -Stage $stage
    $allRequiredPass = $true

    foreach ($definition in $requiredDefinitions) {
        $matches = @($packGates | Where-Object { [string] $_.gateId -eq [string] $definition.gateId })
        if ($matches.Count -eq 0) {
            $effective = [pscustomobject][ordered]@{
                result = 'NotRun'
                reasonCode = 'GATE.MISSING'
                expired = $false
                candidateBound = $false
                runtimeSupported = $bindingRuntimeOk
                cleanupVerified = $false
                freshnessClass = [string] $definition.freshnessClass
                affectedClaimIds = @('CAP-0030')
            }
        }
        else {
            $effective = Resolve-ReleaseGatesEffectiveResult -Candidates $matches `
                -Policy $Policy -ExpectedDigest $boundDigest -Now $Now
            if ([string] $effective.freshnessClass -ne [string] $definition.freshnessClass) {
                $effective.freshnessClass = [string] $definition.freshnessClass
            }
        }
        if ([string] $effective.result -ne 'Pass') {
            $allRequiredPass = $false
            if ($effective.reasonCode -notin $blocking) {
                $blocking.Add([string] $effective.reasonCode)
            }
        }
        $publicGates += [pscustomobject][ordered]@{
            gateId = [string] $definition.gateId
            result = [string] $effective.result
            reasonCode = [string] $effective.reasonCode
            affectedClaimIds = @($effective.affectedClaimIds)
            freshnessClass = [string] $effective.freshnessClass
            expired = [bool] $effective.expired
            candidateBound = [bool] $effective.candidateBound
            runtimeSupported = [bool] $effective.runtimeSupported
            cleanupVerified = [bool] $effective.cleanupVerified
        }
    }

    $quality = Get-ReleaseGatesQualityProjection -Pack $Pack -Policy $Policy
    if (-not $quality.threeCleanPassed) {
        $allRequiredPass = $false
        if ($quality.outcome -eq 'InfrastructureInconclusive') {
            $blocking.Add('GATE.INFRASTRUCTURE_INCONCLUSIVE')
        }
        else {
            $blocking.Add('GATE.QUALITY_BUDGET_FAIL')
        }
    }

    $requiredLocales = @($Policy.locales)
    $packLocales = @($Pack.locales)
    $localesComplete = $true
    foreach ($locale in $requiredLocales) {
        if ($locale -notin $packLocales) {
            $localesComplete = $false
        }
    }
    if (-not $localesComplete) {
        $allRequiredPass = $false
        $blocking.Add('GATE.LOCALE_NON_NEUTRAL')
    }

    $privilegeComplete = $true
    $packPrivileges = @($Pack.privilegePaths)
    foreach ($pathId in @($Policy.requiredPrivilegePaths)) {
        $row = @($packPrivileges | Where-Object { [string] $_.pathId -eq [string] $pathId })
        if ($row.Count -eq 0 -or [string] $row[0].result -ne 'Pass') {
            $privilegeComplete = $false
        }
    }
    if (-not $privilegeComplete) {
        $allRequiredPass = $false
        $blocking.Add('GATE.MISSING')
    }

    $networkComplete = $true
    $packNetworks = @($Pack.networkBehaviors)
    foreach ($behavior in @($Policy.requiredNetworkBehaviors)) {
        $row = @($packNetworks | Where-Object { [string] $_.behavior -eq [string] $behavior })
        if ($row.Count -eq 0 -or [string] $row[0].result -ne 'Pass') {
            $networkComplete = $false
        }
    }
    if (-not $networkComplete) {
        $allRequiredPass = $false
        $blocking.Add('GATE.MISSING')
    }

    $scenarioById = @{}
    foreach ($claimed in @($Policy.claimedScenarios)) {
        $scenarioById[[string] $claimed.scenarioId] = [pscustomobject][ordered]@{
            scenarioId = [string] $claimed.scenarioId
            windowsFamily = [string] $claimed.windowsFamily
            edition = [string] $claimed.edition
            architecture = [string] $claimed.architecture
            supportState = 'NotYetSupported'
            evidenceResult = 'NotRun'
            reasonCode = 'GATE.MISSING'
            method = 'None'
        }
    }
    foreach ($scenario in @($Pack.scenarios)) {
        $id = [string] $scenario.scenarioId
        if (-not $scenarioById.ContainsKey($id)) {
            continue
        }
        $claimed = $scenarioById[$id]
        $result = [string] $scenario.result
        $reason = [string] $scenario.reasonCode
        $method = [string] $scenario.method
        $bound = [string] $scenario.generatedContentSha256 -eq $boundDigest
        $runtimeOk = Test-ReleaseGatesRuntime -Version ([string] $scenario.runtimeVersion) `
            -Architecture ([string] $scenario.architecture) -Policy $Policy
        $expired = Test-ReleaseGatesExpired -ObservedAt $scenario.observedAt `
            -FreshnessClass 'ClientVmValidation' -Policy $Policy -Now $Now
        if (-not $bound) {
            $result = 'Invalidated'
            $reason = 'GATE.CANDIDATE_MISMATCH'
        }
        elseif (-not $runtimeOk) {
            $result = 'Invalidated'
            $reason = 'GATE.UNSUPPORTED_RUNTIME'
        }
        elseif ($expired -and $result -eq 'Pass') {
            $result = 'Expired'
            $reason = 'GATE.EXPIRED'
        }
        elseif ([string] $scenario.windowsFamily -ne $claimed.windowsFamily -or
            [string] $scenario.edition -ne $claimed.edition -or
            [string] $scenario.architecture -ne $claimed.architecture) {
            $result = 'Invalidated'
            $reason = 'GATE.INVALIDATED'
        }
        $claimed.evidenceResult = $result
        $claimed.reasonCode = $reason
        $claimed.method = $method
        if ($result -eq 'Pass') {
            $claimed.supportState = 'Preview'
        }
        $scenarioById[$id] = $claimed
        if ($result -ne 'Pass') {
            $allRequiredPass = $false
            if ($reason -notin $blocking) { $blocking.Add($reason) }
        }
    }
    foreach ($claimed in @($scenarioById.Values)) {
        if ([string] $claimed.evidenceResult -eq 'NotRun') {
            $allRequiredPass = $false
            if ('GATE.MISSING' -notin $blocking) { $blocking.Add('GATE.MISSING') }
        }
    }

    if (-not $bindingRuntimeOk) {
        $allRequiredPass = $false
        $blocking.Add('GATE.UNSUPPORTED_RUNTIME')
    }
    if (-not $ledgerMatched) {
        $allRequiredPass = $false
        $blocking.Add('GATE.LEDGER_MISMATCH')
    }
    if ([bool] (Get-ReleaseGatesProperty $Pack 'waiverRequested')) {
        $allRequiredPass = $false
        $blocking.Add('GATE.WAIVER_REJECTED')
    }

    $final = Get-ReleaseGatesProperty $Pack 'finalDistributable'
    $finalQualified = $false
    if ($stage -eq 'FinalArtifactValidation') {
        $present = $null -ne $final -and [bool] (Get-ReleaseGatesProperty $final 'present')
        $finalKind = [string] (Get-ReleaseGatesProperty $final 'identityKind')
        $finalDigest = [string] (Get-ReleaseGatesProperty $final 'packageSha256')
        $derivedFrom = [string] (Get-ReleaseGatesProperty $final 'derivedFromGeneratedContentSha256')
        $allowedKinds = @(
            [string] $Policy.identity.finalUnsignedKind
            [string] $Policy.identity.finalSignedKind
        )
        if (-not $present) {
            $allRequiredPass = $false
            $blocking.Add('GATE.FINAL_ARTIFACT_NOT_RUN')
        }
        elseif ($finalKind -notin $allowedKinds) {
            $allRequiredPass = $false
            $blocking.Add('GATE.IDENTITY_BINDING_INVALID')
        }
        elseif ([bool] $Policy.identity.finalMustBeDistinct -and $finalDigest -eq $boundDigest) {
            $allRequiredPass = $false
            $blocking.Add('GATE.FINAL_IDENTITY_NOT_DISTINCT')
        }
        elseif ([bool] $Policy.identity.finalMustDeriveFromQualifiedContent -and
            $derivedFrom -ne [string] $bindings.generatedContentSha256) {
            $allRequiredPass = $false
            $blocking.Add('GATE.FINAL_IDENTITY_NOT_DERIVED')
        }
        else {
            $finalQualified = $allRequiredPass
        }
    }
    else {
        $blocking.Add('GATE.FINAL_ARTIFACT_NOT_RUN')
    }

    $unsignedQualified = $allRequiredPass -and $stage -in @('PreSigning', 'FinalArtifactValidation')
    if ($stage -eq 'FinalArtifactValidation') {
        $unsignedQualified = $allRequiredPass
        $finalQualified = $finalQualified -and $unsignedQualified
    }

    if ([bool] $Policy.syntheticCannotAuthorizePublication) {
        $blocking.Add('GATE.SYNTHETIC_EVIDENCE_NOT_PROMOTABLE')
    }

    $uniqueBlocking = @($blocking | Select-Object -Unique)
    $derivedClaim = 'NotYetSupported'
    $scenarioPassCount = @($scenarioById.Values | Where-Object { [string] $_.supportState -eq 'Preview' }).Count
    if ($unsignedQualified -and $scenarioPassCount -eq $scenarioById.Count) {
        $derivedClaim = 'Preview'
    }
    if ($stage -eq 'PreSigning' -and $unsignedQualified -and $scenarioPassCount -eq $scenarioById.Count) {
        $derivedClaim = 'Preview'
    }

    $promotion = [pscustomobject][ordered]@{
        publicationAuthorized = $false
        previewPromotionReady = $false
        supportedPromotionReady = $false
        unsignedContentQualified = [bool] $unsignedQualified
        finalArtifactQualified = [bool] $finalQualified
        derivedClaimState = $derivedClaim
        waiverApplied = $false
        blockingReasons = @($uniqueBlocking)
    }

    $reasonCode = if ($unsignedQualified -and $stage -eq 'PreSigning') {
        'GATE.PASS'
    }
    elseif ($finalQualified) {
        'GATE.PASS'
    }
    elseif ($uniqueBlocking.Count -gt 0) {
        [string] $uniqueBlocking[0]
    }
    else {
        'GATE.PASS'
    }

    $limitations = Get-ReleaseGatesScenarioLimitations -ReleaseDefinition $ReleaseDefinition
    if ($stage -eq 'PreSigning') {
        $limitations += 'final-artifact-validation-not-run'
    }
    $limitations += 'synthetic-evidence-not-promotable'
    $limitations = @($limitations | Select-Object -Unique)

    $manifest = New-ReleaseGatesManifest -State Evaluated -ReasonCode $reasonCode `
        -Stage $stage -SyntheticEvidenceOnly:$true `
        -UnsignedContentQualified:$unsignedQualified `
        -FinalArtifactQualified:$finalQualified `
        -QualityBudget $quality -Gates $publicGates -Promotion $promotion `
        -Limitations $limitations -CleanupVerified:$true

    $rows = @()
    $snapshots = @()
    $derivedFromLedger = $false
    $ledgerVersion = $null
    if ($null -ne $Ledger -and $null -ne $ReleaseDefinition -and $ledgerMatched) {
        $derivedFromLedger = $true
        $ledgerVersion = [int] $Ledger.schemaVersion
        $capabilitiesById = @{}
        foreach ($capability in @($Ledger.capabilities)) {
            $capabilitiesById[[string] $capability.id] = $capability
        }
        $enabledIds = @($ReleaseDefinition.releaseEnabledCapabilityIds)
        $evidenceByScenario = @{}
        foreach ($claimed in @($scenarioById.Values)) {
            $evidenceByScenario[[string] $claimed.scenarioId] = $claimed
        }
        $stateByKey = @{}
        foreach ($capabilityId in $enabledIds) {
            $capability = $capabilitiesById[[string] $capabilityId]
            $name = if ($null -eq $capability) { [string] $capabilityId } else { [string] $capability.name }
            foreach ($claimed in @($Policy.claimedScenarios)) {
                $scenarioId = [string] $claimed.scenarioId
                $evidence = $evidenceByScenario[$scenarioId]
                $rowState = 'NotYetSupported'
                $rowResult = 'NotRun'
                $rowReason = 'GATE.MISSING'
                if ($null -ne $evidence) {
                    $rowResult = [string] $evidence.evidenceResult
                    $rowReason = [string] $evidence.reasonCode
                    if ($unsignedQualified -and [string] $evidence.supportState -eq 'Preview') {
                        $rowState = 'Preview'
                    }
                }
                $key = "$capabilityId|$scenarioId"
                $stateByKey[$key] = [pscustomobject][ordered]@{
                    capabilityId = [string] $capabilityId
                    name = $name
                    scenarioId = $scenarioId
                    supportState = $rowState
                    evidenceResult = $rowResult
                    reasonCode = $rowReason
                    dependsOnCapabilityIds = @(
                        if ($null -ne $capability) { $capability.dependsOnCapabilityIds } else { @() }
                    )
                }
            }
        }
        $changed = $true
        while ($changed) {
            $changed = $false
            foreach ($entry in @($stateByKey.Values)) {
                if ([string] $entry.supportState -ne 'Preview') {
                    continue
                }
                foreach ($dependencyId in @($entry.dependsOnCapabilityIds)) {
                    $depKey = "$dependencyId|$($entry.scenarioId)"
                    if ($stateByKey.ContainsKey($depKey) -and
                        [string] $stateByKey[$depKey].supportState -ne 'Preview') {
                        $entry.supportState = 'NotYetSupported'
                        $entry.reasonCode = 'GATE.MISSING'
                        $changed = $true
                    }
                }
            }
        }
        foreach ($entry in @($stateByKey.Values | Sort-Object capabilityId, scenarioId)) {
            $rows += [pscustomobject][ordered]@{
                capabilityId = [string] $entry.capabilityId
                name = [string] $entry.name
                scenarioId = [string] $entry.scenarioId
                supportState = [string] $entry.supportState
                evidenceResult = [string] $entry.evidenceResult
                reasonCode = [string] $entry.reasonCode
                limitations = @($limitations)
            }
        }
        foreach ($claimed in @($Policy.claimedScenarios)) {
            $evidence = $evidenceByScenario[[string] $claimed.scenarioId]
            $snapshots += [pscustomobject][ordered]@{
                scenarioId = [string] $claimed.scenarioId
                windowsFamily = [string] $claimed.windowsFamily
                edition = [string] $claimed.edition
                architecture = [string] $claimed.architecture
                supportState = $(if ($null -ne $evidence) { [string] $evidence.supportState } else { 'NotYetSupported' })
                evidenceResult = $(if ($null -ne $evidence) { [string] $evidence.evidenceResult } else { 'NotRun' })
                reasonCode = $(if ($null -ne $evidence) { [string] $evidence.reasonCode } else { 'GATE.MISSING' })
                method = $(if ($null -ne $evidence) { [string] $evidence.method } else { 'None' })
                limitations = @($limitations)
            }
        }
    }

    $matrix = New-ReleaseGatesMatrix -State $(if ($derivedFromLedger) { 'Derived' } else { 'Rejected' }) `
        -ReasonCode $(if ($derivedFromLedger) { $reasonCode } else { 'GATE.LEDGER_MISMATCH' }) `
        -DerivedFromFrozenLedger:$derivedFromLedger -LedgerSchemaVersion $ledgerVersion `
        -Rows $rows -ScenarioSnapshots $snapshots -Limitations $limitations

    $cleanupVerified = $true
    if (-not [string]::IsNullOrWhiteSpace($WorkspacePath)) {
        # Ticket-owned residue must not survive the gate. The threat is leaving
        # a derived file that later looks like accepted Release Evidence. The
        # mechanism writes only the already-sanitized public manifest, then
        # deletes that exact file. The trust assumption is that the folder is
        # a real local directory the caller controls. Safe failure is
        # CleanupIncomplete when the derived file is still present.
        $derived = Join-Path $WorkspacePath 'derived-public-manifest.json'
        $projection = $manifest | ConvertTo-Json -Compress -Depth 20
        [System.IO.File]::WriteAllText(
            $derived,
            $projection,
            [System.Text.UTF8Encoding]::new($false)
        )
        $cleanupVerified = Invoke-ReleaseGatesWorkspaceCleanup -WorkspacePath $WorkspacePath
        $manifest.cleanupVerified = [bool] $cleanupVerified
    }

    $exitKind = if (-not $cleanupVerified) { 'CleanupIncomplete' } else { 'Completed' }
    $state = 'Evaluated'
    $finalReason = $reasonCode
    if (-not $cleanupVerified) {
        $finalReason = 'GATE.CLEANUP_INCOMPLETE'
        $manifest.reasonCode = $finalReason
    }

    New-ReleaseGatesEvaluation -State $state -ReasonCode $finalReason `
        -ExitKind $exitKind -Manifest $manifest -Matrix $matrix `
        -CleanupVerified:$cleanupVerified
}
