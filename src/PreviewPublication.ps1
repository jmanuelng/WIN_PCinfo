# Build.ps1 replaces both sentinels with the release-bound publication
# policy and its SHA-256 digest. The generated application treats that table
# as the only trusted copy of the Preview.1 publication contract.
$script:PreviewPublicationPolicyBase64 = '__PREVIEW_PUBLICATION_POLICY_BASE64__'
$script:PreviewPublicationPolicyDigest = '__PREVIEW_PUBLICATION_POLICY_SHA256__'

function Get-PreviewPublicationSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-PreviewPublicationPolicy {
    # The threat is a substituted policy that waives human approval, replaces
    # a published tag, or treats a synthetic rehearsal as a GitHub Preview.
    # The mechanism is an embedded digest, or the reviewed repository file
    # when this module is sourced during development. The trust assumption
    # is that those bytes were reviewed with the rest of the release. Safe
    # failure is to refuse publication rather than invent a looser contract.
    if ($script:PreviewPublicationPolicyBase64 -eq
        ('__PREVIEW_PUBLICATION_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-preview-publication.json'
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-PreviewPublicationSha256 $bytes
    }
    else {
        [byte[]] $bytes = [System.Convert]::FromBase64String(
            $script:PreviewPublicationPolicyBase64
        )
        $expectedDigest = $script:PreviewPublicationPolicyDigest
    }
    if ((Get-PreviewPublicationSha256 $bytes) -ne $expectedDigest) {
        throw 'The Preview publication policy failed its embedded digest check.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $json | ConvertFrom-Json -Depth 30
}

function Get-PreviewPublicationProperty {
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

function Test-PreviewPublicationPathUnderRoot {
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

function Test-PreviewPublicationPublicPath {
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
    Test-PreviewPublicationPathUnderRoot -Path $Path -Root $publicRoot
}

function Test-PreviewPublicationReparsePath {
    param([Parameter(Mandatory)] [string] $Path)

    # A junction or symlink can make a temp path write into the repository
    # or a network share after the string checks pass. Walk every existing
    # ancestor the same way Evidence Workspace does. The trust assumption is
    # that a ticket-owned publication workspace is a real local directory.
    # Safe failure is to reject the path before any derived preview exists.
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

function Get-PreviewPublicationCatalogPath {
    param(
        [Parameter()] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] [string] $RelativePath
    )

    # The generated application may live two or more directories below the
    # reviewed tree. The threat is judging a workspace against `docs` or
    # skipping schema validation because the sidecar was one extra hop away.
    # The mechanism walks a bounded ancestor list and returns only an exact
    # relative file. The trust assumption is that the reviewed ledger and
    # schemas keep those well-known paths. Safe failure is a missing path.
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

function Get-PreviewPublicationBoundRepositoryRoot {
    param(
        [Parameter()] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory
    )

    # A policy under docs/spec/releases is three hops from the repository
    # root. The threat is treating `docs` as the tree and then writing a
    # preview beside src or tests. The mechanism locates the frozen ledger
    # and walks the same hops qualification uses. Safe failure is the
    # caller-supplied root so later path checks still fail closed.
    $ledgerPath = Get-PreviewPublicationCatalogPath `
        -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory `
        -RelativePath 'docs/spec/capability-ledger.json'
    if (-not [string]::IsNullOrWhiteSpace($ledgerPath)) {
        return [System.IO.Path]::GetFullPath(
            (Join-Path (Split-Path -Parent $ledgerPath) '..\..')
        )
    }
    if (-not [string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        return [System.IO.Path]::GetFullPath($RepositoryRoot)
    }
    if (-not [string]::IsNullOrWhiteSpace($ApplicationDirectory)) {
        return [System.IO.Path]::GetFullPath($ApplicationDirectory)
    }
    $null
}

function Test-PreviewPublicationPrivacyBoundary {
    param([Parameter(Mandatory)] [string] $Text)

    # Public publication output is a projection, not a dump. The threat is
    # printing a credential, a real cloud identifier, Terraform material, a
    # raw log, a local user path, or restricted assessment evidence. The
    # mechanism is a closed needle list applied to the raw request before
    # any derived file is written. The trust assumption is that approved
    # fixtures stay synthetic and identifier-free. Safe failure is
    # PUBLISH.PRIVACY_REJECTED with no workspace residue.
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
        '(?i)gho_[A-Za-z0-9]+'
        '(?i)github_pat_[A-Za-z0-9_]+'
    )
    foreach ($needle in $needles) {
        if ($Text -match $needle) {
            return 'PUBLISH.PRIVACY_REJECTED'
        }
    }
    $null
}

function Get-PreviewPublicationWorkspaceRejection {
    param(
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $Request
    )

    # The threat is writing a public preview or staged assets into the
    # public repository or a shared folder. The mechanism is a
    # caller-supplied private directory that already carries the reviewed
    # marker. The trust assumption is that the operator chose a folder they
    # control. Safe failure is to stop before any derived file exists.
    if ([string] (Get-PreviewPublicationProperty $Request 'privacyBoundary') -ne
        [string] $Policy.workspace.requiredBoundary) {
        return 'PUBLISH.PRIVACY_BOUNDARY_MISSING'
    }
    if ([string]::IsNullOrWhiteSpace($PrivateWorkspacePath)) {
        return 'PUBLISH.PRIVACY_BOUNDARY_MISSING'
    }
    if ($PrivateWorkspacePath.StartsWith('\\', [System.StringComparison]::Ordinal) -or
        $PrivateWorkspacePath.StartsWith('//', [System.StringComparison]::Ordinal)) {
        return 'PUBLISH.WORKSPACE_UNC_PATH'
    }
    $boundRoot = Get-PreviewPublicationBoundRepositoryRoot `
        -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory
    if (-not [string]::IsNullOrWhiteSpace($boundRoot)) {
        $RepositoryRoot = $boundRoot
    }
    if (Test-PreviewPublicationPublicPath -Path $PrivateWorkspacePath) {
        return 'PUBLISH.WORKSPACE_PUBLIC_PATH'
    }
    if (-not [string]::IsNullOrWhiteSpace($RepositoryRoot) -and
        (Test-Path -LiteralPath $RepositoryRoot) -and
        (Test-PreviewPublicationPathUnderRoot -Path $PrivateWorkspacePath `
            -Root $RepositoryRoot)) {
        return 'PUBLISH.WORKSPACE_REPOSITORY_PATH'
    }
    if (-not [string]::IsNullOrWhiteSpace($ApplicationDirectory) -and
        (Test-Path -LiteralPath $ApplicationDirectory) -and
        (Test-PreviewPublicationPathUnderRoot -Path $PrivateWorkspacePath `
            -Root $ApplicationDirectory)) {
        return 'PUBLISH.WORKSPACE_REPOSITORY_PATH'
    }
    if (Test-PreviewPublicationReparsePath -Path $PrivateWorkspacePath) {
        return 'PUBLISH.WORKSPACE_REPARSE_POINT'
    }
    if (-not (Test-Path -LiteralPath $PrivateWorkspacePath -PathType Container)) {
        return 'PUBLISH.PRIVACY_BOUNDARY_MISSING'
    }
    $markerPath = Join-Path $PrivateWorkspacePath ([string] $Policy.workspace.markerFileName)
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        return 'PUBLISH.PRIVACY_BOUNDARY_MISSING'
    }
    $markerText = [System.IO.File]::ReadAllText($markerPath).Trim()
    if ($markerText -ne [string] $Policy.workspace.markerContent) {
        return 'PUBLISH.PRIVACY_BOUNDARY_MISSING'
    }
    $null
}

function Get-PreviewPublicationSyntheticAssetBytes {
    param([Parameter(Mandatory)] [string] $AssetId)

    # Staged bytes are a closed synthetic payload keyed only by asset id.
    # The threat is copying a real package, SBOM path, or local file into
    # the rehearsal. The mechanism is a fixed UTF-8 marker. The trust
    # assumption is that tests rewrite declared digests to match these
    # bytes. Safe failure is a digest mismatch later in the workflow.
    [System.Text.UTF8Encoding]::new($false).GetBytes(
        "win-pcinfo.preview-asset:$AssetId"
    )
}

function Get-PreviewPublicationCanonicalTextBytes {
    param([Parameter(Mandatory)] [string] $Text)

    [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
}

function Get-PreviewPublicationAssetListDigest {
    param([Parameter(Mandatory)] $Assets)

    $lines = @(
        @($Assets) | Sort-Object {
            [string] (Get-PreviewPublicationProperty $_ 'assetId')
        } | ForEach-Object {
            '{0}|{1}|{2}' -f @(
                [string] (Get-PreviewPublicationProperty $_ 'assetId')
                [string] (Get-PreviewPublicationProperty $_ 'fileName')
                [string] (Get-PreviewPublicationProperty $_ 'sha256')
            )
        }
    )
    Get-PreviewPublicationSha256 -Bytes (
        Get-PreviewPublicationCanonicalTextBytes -Text ($lines -join "`n")
    )
}

function Get-PreviewPublicationLimitationsDigest {
    param([Parameter(Mandatory)] $Limitations)

    $lines = @(@($Limitations) | ForEach-Object { [string] $_ } | Sort-Object)
    Get-PreviewPublicationSha256 -Bytes (
        Get-PreviewPublicationCanonicalTextBytes -Text ($lines -join "`n")
    )
}

function Get-PreviewPublicationPacketDigest {
    param([Parameter(Mandatory)] $Packet)

    Get-PreviewPublicationSha256 -Bytes (
        Get-PreviewPublicationCanonicalTextBytes -Text (
            $Packet | ConvertTo-Json -Compress -Depth 20
        )
    )
}

function New-PreviewPublicationPreview {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $TrustPath,
        [Parameter(Mandatory)] $Assets,
        [Parameter(Mandatory)] $Limitations
    )

    $attestedWarning = $TrustPath -eq 'AttestedPreview'
    $notes = [System.Collections.Generic.List[string]]::new()
    $notes.Add('This GitHub release is a Preview of WIN-PCInfo 2.0.0-preview.1.')
    $notes.Add('This Preview makes no Supported scenario claim.')
    $notes.Add('Maintenance is best effort and has no SLA.')
    $notes.Add('Microsoft lifecycle status is separate from WIN-PCInfo claims.')
    $notes.Add('Known limitations are listed in the public limitations asset.')
    $notes.Add('Do not replace this tag or these assets; use a new version.')
    if ($attestedWarning) {
        $notes.Insert(
            0,
            'UNSIGNED LIMITED-TRUST WARNING: Attested Preview is not Authenticode.'
        )
    }
    $publicAssets = @(
        foreach ($asset in @($Assets)) {
            [pscustomobject][ordered]@{
                assetId = [string] (Get-PreviewPublicationProperty $asset 'assetId')
                fileName = [string] (Get-PreviewPublicationProperty $asset 'fileName')
                sha256 = [string] (Get-PreviewPublicationProperty $asset 'sha256')
                role = [string] (Get-PreviewPublicationProperty $asset 'role')
            }
        }
    )
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.preview-publication-preview'
        contractVersion = '1.0.0'
        release = '2.0.0-preview.1'
        tag = [string] $Policy.immutableTag
        title = 'WIN-PCInfo 2.0.0-preview.1'
        channel = 'Preview'
        prerelease = $true
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        maintenance = 'BestEffortNoSla'
        microsoftLifecycleSeparated = $true
        attestedPreviewWarning = [bool] $attestedWarning
        silentReplacementForbidden = $true
        trustPath = $TrustPath
        assets = $publicAssets
        limitations = @($Limitations)
        notes = @($notes)
    }
}

function New-PreviewPublicationResult {
    param(
        [Parameter(Mandatory)] [ValidateSet(
            'Previewed', 'PublishedAndVerified', 'Denied', 'Rejected'
        )] [string] $State,
        [Parameter(Mandatory)] [ValidateSet(
            'AwaitingHumanApproval', 'Publish', 'Deny', 'NotStarted'
        )] [string] $Decision,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [string] $TrustPath = 'None',
        [Parameter()] [bool] $HumanApprovalPresent = $false,
        [Parameter()] [bool] $SilentReplacementAttempted = $false,
        [Parameter()] [bool] $CandidateBound = $false,
        [Parameter()] [bool] $QualificationApproved = $false,
        [Parameter()] [bool] $AssetsVerified = $false,
        [Parameter()] [bool] $DownloadVerified = $false,
        [Parameter()] $Smokes = @(),
        [Parameter()] $BlockingReasons = @(),
        [Parameter()] $Limitations = @()
    )

    if ($TrustPath -notin @('AuthenticodeSigned', 'AttestedPreview', 'None')) {
        $TrustPath = 'None'
    }
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.preview-publication-result'
        contractVersion = '1.0.0'
        state = $State
        decision = $Decision
        reasonCode = $ReasonCode
        syntheticEvidenceOnly = $true
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        sliceDeliversCapability = $false
        publicationAuthorized = $false
        githubReleaseCreated = $false
        humanApprovalRequired = $true
        humanApprovalPresent = [bool] $HumanApprovalPresent
        tagImmutable = $true
        silentReplacementAttempted = [bool] $SilentReplacementAttempted
        candidateBound = [bool] $CandidateBound
        qualificationApproved = [bool] $QualificationApproved
        assetsVerified = [bool] $AssetsVerified
        downloadVerified = [bool] $DownloadVerified
        collectionStarted = $false
        trustPath = $TrustPath
        attestedPreviewSatisfiesStableSigning = $false
        smokes = @($Smokes)
        blockingReasons = @($BlockingReasons)
        limitations = @($Limitations)
    }
}

function New-PreviewPublicationEvaluation {
    param(
        [Parameter(Mandatory)] [ValidateSet(
            'Previewed', 'PublishedAndVerified', 'Denied', 'Rejected'
        )] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [ValidateSet('Completed', 'NotStarted', 'CleanupIncomplete')]
        [string] $ExitKind,
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] $Preview,
        [Parameter()] [bool] $CleanupVerified = $true
    )

    [pscustomobject][ordered]@{
        State = $State
        ReasonCode = $ReasonCode
        ExitKind = $ExitKind
        Result = $Result
        Preview = $Preview
        CleanupVerified = [bool] $CleanupVerified
        CollectionStarted = $false
    }
}

function Get-PreviewPublicationEmptyPreview {
    param([Parameter(Mandatory)] $Policy)

    New-PreviewPublicationPreview -Policy $Policy -TrustPath 'None' `
        -Assets @() -Limitations @('publication-not-started')
}

function Get-PreviewPublicationRejectedEvaluation {
    param(
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] $Policy,
        [Parameter()] [string] $TrustPath = 'None',
        [Parameter()] [bool] $CleanupVerified = $true
    )

    $preview = Get-PreviewPublicationEmptyPreview -Policy $Policy
    $result = New-PreviewPublicationResult -State Rejected -Decision NotStarted `
        -ReasonCode $ReasonCode -TrustPath $TrustPath `
        -BlockingReasons @($ReasonCode) -Limitations @('publication-not-started')
    $exitKind = if ($ReasonCode -eq 'PUBLISH.CLEANUP_INCOMPLETE') {
        'CleanupIncomplete'
    }
    else {
        'NotStarted'
    }
    New-PreviewPublicationEvaluation -State Rejected -ReasonCode $ReasonCode `
        -ExitKind $exitKind -Result $result -Preview $preview `
        -CleanupVerified:$CleanupVerified
}

function Invoke-PreviewPublicationLaunchSmoke {
    param(
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter()] [string] $PowerShellPath
    )

    # Launch smoke proves the exact candidate still starts. The threat is
    # treating a bound digest as proof that the file runs, or starting
    # collection from a publication session. The mechanism is a child
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
            if ([bool] (Get-PreviewPublicationProperty $record 'collectionStarted')) {
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

function Invoke-PreviewPublicationWorkspaceCleanup {
    param([Parameter()] [string] $WorkspacePath)

    if ([string]::IsNullOrWhiteSpace($WorkspacePath) -or
        -not (Test-Path -LiteralPath $WorkspacePath -PathType Container)) {
        return $true
    }
    foreach ($name in @('staged-assets', 'synthetic-publisher', 'derived-publication-preview.json')) {
        $target = Join-Path $WorkspacePath $name
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
    }
    $left = @(Get-ChildItem -LiteralPath $WorkspacePath -Force | Where-Object {
        $_.Name -ne '.win-pcinfo-publication-workspace'
    })
    $left.Count -eq 0
}

function Test-PreviewPublicationNotes {
    param(
        [Parameter(Mandatory)] $Preview,
        [Parameter(Mandatory)] [bool] $Attested
    )

    $notes = @($Preview.notes)
    $joined = $notes -join ' '
    if ($joined -notmatch 'Preview') { return $false }
    if ($joined -notmatch 'no Supported') { return $false }
    if ($joined -notmatch 'best effort') { return $false }
    if ($joined -notmatch 'Microsoft lifecycle') { return $false }
    if ($joined -notmatch 'limitations') { return $false }
    if ($joined -notmatch 'Do not replace') { return $false }
    if ($Attested -and ($joined -notmatch 'UNSIGNED LIMITED-TRUST WARNING')) {
        return $false
    }
    $true
}

function Invoke-PreviewPublication {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] [string] $RequestText,
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter()] [string] $PowerShellPath
    )

    $policy = Get-PreviewPublicationPolicy
    $boundRoot = Get-PreviewPublicationBoundRepositoryRoot `
        -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory
    if (-not [string]::IsNullOrWhiteSpace($boundRoot)) {
        $RepositoryRoot = $boundRoot
    }
    $privacyReason = Test-PreviewPublicationPrivacyBoundary -Text $RequestText
    if ($privacyReason) {
        return Get-PreviewPublicationRejectedEvaluation -ReasonCode $privacyReason `
            -Policy $policy
    }
    if ($null -eq $Request -or
        [string] (Get-PreviewPublicationProperty $Request 'kind') -ne
            'win-pcinfo.preview-publication-request') {
        return Get-PreviewPublicationRejectedEvaluation -ReasonCode 'PUBLISH.REQUEST_INVALID' `
            -Policy $policy
    }
    if (-not [bool] (Get-PreviewPublicationProperty $Request 'synthetic')) {
        return Get-PreviewPublicationRejectedEvaluation -ReasonCode 'PUBLISH.PRIVACY_REJECTED' `
            -Policy $policy
    }

    $workspaceReason = Get-PreviewPublicationWorkspaceRejection `
        -PrivateWorkspacePath $PrivateWorkspacePath -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory -Policy $policy -Request $Request
    if ($workspaceReason) {
        return Get-PreviewPublicationRejectedEvaluation -ReasonCode $workspaceReason `
            -Policy $policy
    }

    $trustPath = [string] (Get-PreviewPublicationProperty $Request 'trustPath')
    $bindings = Get-PreviewPublicationProperty $Request 'bindings'
    $candidateBytes = [System.IO.File]::ReadAllBytes($CandidatePath)
    $candidateDigest = Get-PreviewPublicationSha256 -Bytes $candidateBytes
    $declaredDigest = [string] (Get-PreviewPublicationProperty $bindings 'generatedContentSha256')
    $finalDigest = [string] (Get-PreviewPublicationProperty $bindings 'finalDistributableSha256')
    $derivedFrom = [string] (
        Get-PreviewPublicationProperty $bindings 'derivedFromGeneratedContentSha256'
    )
    $finalKind = [string] (
        Get-PreviewPublicationProperty $bindings 'finalDistributableIdentityKind'
    )
    $candidateBound = $declaredDigest -eq $candidateDigest
    $humanApproval = Get-PreviewPublicationProperty $Request 'humanApproval'
    $approvalPresent = [bool] (Get-PreviewPublicationProperty $humanApproval 'present')
    $publisher = Get-PreviewPublicationProperty $Request 'publisher'
    $replaceRequested = [bool] (Get-PreviewPublicationProperty $publisher 'replaceRequested')
    $limitations = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($policy.requiredLimitations)) {
        $limitations.Add([string] $item)
    }
    $requestLimitations = @(Get-PreviewPublicationProperty $Request 'limitations')
    foreach ($item in $requestLimitations) {
        if ([string] $item -notin @($limitations)) {
            $limitations.Add([string] $item)
        }
    }

    $blocking = [System.Collections.Generic.List[string]]::new()
    if (-not $candidateBound) {
        $blocking.Add('PUBLISH.CANDIDATE_MISMATCH')
    }
    if ([bool] $policy.identity.finalMustBeDistinct -and $finalDigest -eq $candidateDigest) {
        $blocking.Add('PUBLISH.FINAL_IDENTITY_NOT_DISTINCT')
    }
    if ([bool] $policy.identity.finalMustDeriveFromQualifiedContent -and
        $derivedFrom -ne $candidateDigest) {
        $blocking.Add('PUBLISH.FINAL_IDENTITY_NOT_DERIVED')
    }

    $signingUnavailability = [string] (
        Get-PreviewPublicationProperty $Request 'signingUnavailability'
    )
    if ($trustPath -eq 'AttestedPreview') {
        # Convenience must not become an unsigned Preview release. The
        # threat is skipping Artifact Signing because it is slower. The
        # mechanism accepts only the two reviewed outage reasons and only
        # the unsigned portable identity. Safe failure is denial.
        if ($signingUnavailability -notin @($policy.attestedFallback.permittedReasons)) {
            $blocking.Add('PUBLISH.ATTESTED_CONVENIENCE')
        }
        if ($finalKind -ne [string] $policy.identity.finalUnsignedKind) {
            $blocking.Add('PUBLISH.ATTESTED_UNSIGNED_REQUIRED')
        }
        if ('attested-preview-not-trusted' -notin @($limitations)) {
            $limitations.Add('attested-preview-not-trusted')
        }
    }
    elseif ($trustPath -eq 'AuthenticodeSigned') {
        if ($finalKind -ne [string] $policy.identity.finalSignedKind) {
            $blocking.Add('PUBLISH.SIGNED_IDENTITY_REQUIRED')
        }
    }
    else {
        $blocking.Add('PUBLISH.REQUEST_INVALID')
        $trustPath = 'None'
    }

    if ([bool] (Get-PreviewPublicationProperty $Request 'waiverRequested')) {
        $blocking.Add('PUBLISH.WAIVER_REJECTED')
    }

    $packet = Get-PreviewPublicationProperty $Request 'qualificationPacket'
    $qualificationApproved = $false
    if ($null -eq $packet -or
        [string] (Get-PreviewPublicationProperty $packet 'recordType') -ne
            'win-pcinfo.preview-qualification-packet') {
        $blocking.Add('PUBLISH.QUALIFICATION_DENIED')
    }
    else {
        if ([bool] (Get-PreviewPublicationProperty $packet 'publicationAuthorized')) {
            $blocking.Add('PUBLISH.QUALIFICATION_OVERCLAIM')
        }
        $packetTrust = [string] (Get-PreviewPublicationProperty $packet 'trustPath')
        if ($packetTrust -ne $trustPath) {
            $blocking.Add('PUBLISH.QUALIFICATION_DENIED')
        }
        $packetState = [string] (Get-PreviewPublicationProperty $packet 'state')
        $packetDecision = [string] (Get-PreviewPublicationProperty $packet 'decision')
        $packetReason = [string] (Get-PreviewPublicationProperty $packet 'reasonCode')
        $qualificationApproved = $packetState -eq 'Approved' -and
            $packetDecision -eq 'Qualify' -and
            $packetReason -eq 'QUALIFY.APPROVED' -and
            [bool] (Get-PreviewPublicationProperty $packet 'finalArtifactQualified')
        if (-not $qualificationApproved) {
            $blocking.Add('PUBLISH.QUALIFICATION_DENIED')
        }
    }

    $assets = @(Get-PreviewPublicationProperty $Request 'assets')
    $assetIds = @($assets | ForEach-Object {
        [string] (Get-PreviewPublicationProperty $_ 'assetId')
    })
    $assetsVerified = $true
    foreach ($requiredAsset in @($policy.requiredAssets)) {
        if ($requiredAsset -notin $assetIds) {
            $assetsVerified = $false
            $blocking.Add('PUBLISH.ASSET_INCOMPLETE')
            break
        }
    }
    foreach ($requiredLimitation in @($policy.requiredLimitations)) {
        if ($requiredLimitation -notin $requestLimitations) {
            $blocking.Add('PUBLISH.LIMITATIONS_INCOMPLETE')
            break
        }
    }

    $packageAsset = @($assets | Where-Object {
        [string] (Get-PreviewPublicationProperty $_ 'assetId') -eq 'portable-package'
    })
    if ($packageAsset.Count -eq 1) {
        $packageSha = [string] (Get-PreviewPublicationProperty $packageAsset[0] 'sha256')
        if ($packageSha -ne $finalDigest) {
            $assetsVerified = $false
            $blocking.Add('PUBLISH.ASSET_MISMATCH')
        }
    }
    else {
        $assetsVerified = $false
    }

    foreach ($asset in $assets) {
        $assetId = [string] (Get-PreviewPublicationProperty $asset 'assetId')
        $declared = [string] (Get-PreviewPublicationProperty $asset 'sha256')
        $actual = Get-PreviewPublicationSha256 -Bytes (
            Get-PreviewPublicationSyntheticAssetBytes -AssetId $assetId
        )
        if ($declared -ne $actual) {
            $assetsVerified = $false
            if ('PUBLISH.ASSET_MISMATCH' -notin $blocking) {
                $blocking.Add('PUBLISH.ASSET_MISMATCH')
            }
        }
    }

    $preview = New-PreviewPublicationPreview -Policy $policy -TrustPath $trustPath `
        -Assets $assets -Limitations @($limitations | Select-Object -Unique)
    $notesOk = Test-PreviewPublicationNotes -Preview $preview `
        -Attested:($trustPath -eq 'AttestedPreview')
    if (-not $notesOk) {
        $blocking.Add('PUBLISH.NOTES_INCOMPLETE')
    }

    $expectedPacketDigest = if ($null -ne $packet) {
        Get-PreviewPublicationPacketDigest -Packet $packet
    }
    else {
        ''
    }
    $expectedLimitationsDigest = Get-PreviewPublicationLimitationsDigest -Limitations $requestLimitations
    $expectedAssetListDigest = Get-PreviewPublicationAssetListDigest -Assets $assets

    if ($approvalPresent) {
        $phrase = [string] (Get-PreviewPublicationProperty $humanApproval 'confirmationPhrase')
        $approvedCandidate = [string] (Get-PreviewPublicationProperty $humanApproval 'candidateDigest')
        $approvedPacket = [string] (
            Get-PreviewPublicationProperty $humanApproval 'qualificationPacketDigest'
        )
        $approvedLimitations = [string] (
            Get-PreviewPublicationProperty $humanApproval 'limitationsDigest'
        )
        $approvedTrust = [string] (Get-PreviewPublicationProperty $humanApproval 'trustPath')
        $approvedAssets = [string] (
            Get-PreviewPublicationProperty $humanApproval 'publicAssetListDigest'
        )
        $statements = @(Get-PreviewPublicationProperty $humanApproval 'confirmedStatements')
        $requiredStatements = @($policy.humanApproval.requiredStatements)
        $statementsComplete = $true
        foreach ($required in $requiredStatements) {
            if ($required -notin $statements) {
                $statementsComplete = $false
            }
        }
        if ($phrase -ne [string] $policy.confirmationPhrase -or
            $approvedCandidate -ne $candidateDigest -or
            $approvedPacket -ne $expectedPacketDigest -or
            $approvedLimitations -ne $expectedLimitationsDigest -or
            $approvedTrust -ne $trustPath -or
            $approvedAssets -ne $expectedAssetListDigest -or
            -not $statementsComplete) {
            $blocking.Add('PUBLISH.APPROVAL_MISMATCH')
        }
    }

    $channel = [string] (Get-PreviewPublicationProperty $publisher 'channel')
    $githubAuth = [bool] (Get-PreviewPublicationProperty $publisher 'githubAuthAvailable')
    $existingTag = [bool] (Get-PreviewPublicationProperty $publisher 'existingTag')
    $fault = [string] (Get-PreviewPublicationProperty $publisher 'fault')
    if ($channel -eq 'GitHub') {
        if (-not $githubAuth) {
            $blocking.Add('PUBLISH.GITHUB_AUTH_UNAVAILABLE')
        }
        else {
            $blocking.Add('PUBLISH.SYNTHETIC_CANNOT_PUBLISH_GITHUB')
        }
    }
    if ($replaceRequested) {
        $blocking.Add('PUBLISH.SILENT_REPLACEMENT_REJECTED')
    }
    elseif ($existingTag) {
        $blocking.Add('PUBLISH.IMMUTABLE_TAG_EXISTS')
    }

    $smokes = [System.Collections.Generic.List[object]]::new()
    $uniqueBlocking = [System.Collections.Generic.List[string]]::new()
    foreach ($reason in @($blocking | Select-Object -Unique)) {
        $uniqueBlocking.Add([string] $reason)
    }

    $canPreview = $candidateBound -and $qualificationApproved -and $assetsVerified -and $notesOk -and
        ('PUBLISH.ASSET_INCOMPLETE' -notin $uniqueBlocking) -and
        ('PUBLISH.LIMITATIONS_INCOMPLETE' -notin $uniqueBlocking) -and
        ('PUBLISH.FINAL_IDENTITY_NOT_DISTINCT' -notin $uniqueBlocking) -and
        ('PUBLISH.FINAL_IDENTITY_NOT_DERIVED' -notin $uniqueBlocking) -and
        ('PUBLISH.ATTESTED_CONVENIENCE' -notin $uniqueBlocking) -and
        ('PUBLISH.SIGNED_IDENTITY_REQUIRED' -notin $uniqueBlocking) -and
        ('PUBLISH.ATTESTED_UNSIGNED_REQUIRED' -notin $uniqueBlocking) -and
        ('PUBLISH.WAIVER_REJECTED' -notin $uniqueBlocking) -and
        ('PUBLISH.QUALIFICATION_DENIED' -notin $uniqueBlocking) -and
        ('PUBLISH.QUALIFICATION_OVERCLAIM' -notin $uniqueBlocking)

    $publicationBlockers = @(
        'PUBLISH.APPROVAL_MISMATCH'
        'PUBLISH.GITHUB_AUTH_UNAVAILABLE'
        'PUBLISH.SYNTHETIC_CANNOT_PUBLISH_GITHUB'
        'PUBLISH.SILENT_REPLACEMENT_REJECTED'
        'PUBLISH.IMMUTABLE_TAG_EXISTS'
    )
    $hasPublicationBlocker = $false
    foreach ($reason in @($uniqueBlocking)) {
        if ($reason -in $publicationBlockers) {
            $hasPublicationBlocker = $true
        }
    }

    $state = 'Denied'
    $decision = 'Deny'
    $primary = 'PUBLISH.DENIED'
    $downloadVerified = $false

    try {
        $stageRoot = Join-Path $PrivateWorkspacePath 'staged-assets'
        $publisherRoot = Join-Path $PrivateWorkspacePath 'synthetic-publisher'
        $null = New-Item -ItemType Directory -Path $stageRoot -Force
        foreach ($asset in $assets) {
            $assetId = [string] (Get-PreviewPublicationProperty $asset 'assetId')
            $fileName = [string] (Get-PreviewPublicationProperty $asset 'fileName')
            $bytes = Get-PreviewPublicationSyntheticAssetBytes -AssetId $assetId
            [System.IO.File]::WriteAllBytes((Join-Path $stageRoot $fileName), $bytes)
        }
        $derived = Join-Path $PrivateWorkspacePath 'derived-publication-preview.json'
        [System.IO.File]::WriteAllText(
            $derived,
            ($preview | ConvertTo-Json -Compress -Depth 20),
            [System.Text.UTF8Encoding]::new($false)
        )

        if (-not $canPreview) {
            $primary = [string] $uniqueBlocking[0]
        }
        elseif (-not $approvalPresent -and -not $hasPublicationBlocker) {
            $state = 'Previewed'
            $decision = 'AwaitingHumanApproval'
            $primary = 'PUBLISH.HUMAN_APPROVAL_REQUIRED'
        }
        elseif ($hasPublicationBlocker) {
            $primary = [string] (@($uniqueBlocking | Where-Object {
                $_ -in $publicationBlockers
            })[0])
        }
        else {
            # Synthetic publish-once. The threat is treating this rehearsal
            # as the public GitHub tag, or overwriting bytes after a failed
            # download check. The mechanism writes a one-use store, reads
            # it back independently, and refuses replacement. The trust
            # assumption is SHA-256 of the staged synthetic assets. Safe
            # failure is a denial that leaves no GitHub side effect.
            $releaseRoot = Join-Path $publisherRoot ([string] $policy.immutableTag)
            if ($existingTag -or (Test-Path -LiteralPath $releaseRoot)) {
                $uniqueBlocking.Add('PUBLISH.IMMUTABLE_TAG_EXISTS')
                $primary = 'PUBLISH.IMMUTABLE_TAG_EXISTS'
            }
            else {
                $null = New-Item -ItemType Directory -Path $releaseRoot -Force
                foreach ($asset in $assets) {
                    $fileName = [string] (Get-PreviewPublicationProperty $asset 'fileName')
                    $source = Join-Path $stageRoot $fileName
                    Copy-Item -LiteralPath $source -Destination (Join-Path $releaseRoot $fileName)
                }
                $downloadOk = $true
                foreach ($asset in $assets) {
                    $fileName = [string] (Get-PreviewPublicationProperty $asset 'fileName')
                    $expected = [string] (Get-PreviewPublicationProperty $asset 'sha256')
                    $downloaded = Join-Path $releaseRoot $fileName
                    if ($fault -eq 'TamperDownload') {
                        [System.IO.File]::WriteAllBytes(
                            $downloaded,
                            [System.Text.UTF8Encoding]::new($false).GetBytes('tampered')
                        )
                    }
                    if (-not (Test-Path -LiteralPath $downloaded -PathType Leaf)) {
                        $downloadOk = $false
                        continue
                    }
                    $actual = Get-PreviewPublicationSha256 -Bytes (
                        [System.IO.File]::ReadAllBytes($downloaded)
                    )
                    if ($actual -ne $expected) {
                        $downloadOk = $false
                    }
                }
                $downloadVerified = $downloadOk
                if (-not $downloadOk) {
                    $uniqueBlocking.Add('PUBLISH.DOWNLOAD_MISMATCH')
                    $primary = 'PUBLISH.DOWNLOAD_MISMATCH'
                    $assetsVerified = $false
                }
                else {
                    $state = 'PublishedAndVerified'
                    $decision = 'Publish'
                    $primary = 'PUBLISH.PUBLISHED_AND_VERIFIED'
                }
            }
        }
    }
    catch {
        $null = Invoke-PreviewPublicationWorkspaceCleanup -WorkspacePath $PrivateWorkspacePath
        return Get-PreviewPublicationRejectedEvaluation -ReasonCode 'PUBLISH.REQUEST_INVALID' `
            -Policy $policy
    }

    $launchPassed = Invoke-PreviewPublicationLaunchSmoke -CandidatePath $CandidatePath `
        -PowerShellPath $PowerShellPath
    $trustSmoke = if ($candidateBound -and
        ('PUBLISH.ATTESTED_CONVENIENCE' -notin $uniqueBlocking) -and
        ('PUBLISH.SIGNED_IDENTITY_REQUIRED' -notin $uniqueBlocking) -and
        ('PUBLISH.ATTESTED_UNSIGNED_REQUIRED' -notin $uniqueBlocking)) {
        'Pass'
    }
    else {
        'NotRun'
    }
    $launchResult = if ($launchPassed) { 'Pass' } else { 'ProductFail' }
    $downloadResult = if ($state -eq 'PublishedAndVerified') { 'Pass' } else { 'NotRun' }
    if ('PUBLISH.DOWNLOAD_MISMATCH' -in $uniqueBlocking) {
        $downloadResult = 'ProductFail'
    }
    $guidanceResult = if ($notesOk) { 'Pass' } else { 'ProductFail' }
    $beginnerPresent = 'beginner-documentation' -in $assetIds
    $packagePresent = 'portable-package' -in $assetIds -and
        'checksums' -in $assetIds -and
        'sbom' -in $assetIds
    $smokes.Add([pscustomobject][ordered]@{
        smokeId = 'trust'
        result = $trustSmoke
        reasonCode = $(if ($trustSmoke -eq 'Pass') { 'PUBLISH.PASS' } else { 'PUBLISH.CANDIDATE_MISMATCH' })
    })
    $smokes.Add([pscustomobject][ordered]@{
        smokeId = 'launch'
        result = $launchResult
        reasonCode = $(if ($launchPassed) { 'PUBLISH.PASS' } else { 'PUBLISH.SMOKE_FAILED' })
    })
    $smokes.Add([pscustomobject][ordered]@{
        smokeId = 'download'
        result = $downloadResult
        reasonCode = $(if ($downloadResult -eq 'Pass') { 'PUBLISH.PASS' } elseif ($downloadResult -eq 'ProductFail') { 'PUBLISH.DOWNLOAD_MISMATCH' } else { 'PUBLISH.NOT_PUBLISHED' })
    })
    $smokes.Add([pscustomobject][ordered]@{
        smokeId = 'runtime-guidance'
        result = $guidanceResult
        reasonCode = $(if ($notesOk) { 'PUBLISH.PASS' } else { 'PUBLISH.NOTES_INCOMPLETE' })
    })
    $smokes.Add([pscustomobject][ordered]@{
        smokeId = 'beginner-instructions'
        result = $(if ($beginnerPresent) { 'Pass' } else { 'ProductFail' })
        reasonCode = $(if ($beginnerPresent) { 'PUBLISH.PASS' } else { 'PUBLISH.ASSET_INCOMPLETE' })
    })
    $smokes.Add([pscustomobject][ordered]@{
        smokeId = 'package-resources'
        result = $(if ($packagePresent) { 'Pass' } else { 'ProductFail' })
        reasonCode = $(if ($packagePresent) { 'PUBLISH.PASS' } else { 'PUBLISH.ASSET_INCOMPLETE' })
    })
    if (-not $launchPassed) {
        if ('PUBLISH.SMOKE_FAILED' -notin $uniqueBlocking) {
            $uniqueBlocking.Add('PUBLISH.SMOKE_FAILED')
        }
        if ($state -eq 'PublishedAndVerified') {
            $state = 'Denied'
            $decision = 'Deny'
            $primary = 'PUBLISH.SMOKE_FAILED'
            $downloadVerified = $false
        }
    }

    $result = New-PreviewPublicationResult -State $state -Decision $decision `
        -ReasonCode $primary -TrustPath $trustPath `
        -HumanApprovalPresent:$approvalPresent `
        -SilentReplacementAttempted:$replaceRequested `
        -CandidateBound:$candidateBound `
        -QualificationApproved:$qualificationApproved `
        -AssetsVerified:$assetsVerified `
        -DownloadVerified:$downloadVerified `
        -Smokes @($smokes) `
        -BlockingReasons @($uniqueBlocking) `
        -Limitations @($limitations | Select-Object -Unique)

    $cleanupVerified = Invoke-PreviewPublicationWorkspaceCleanup `
        -WorkspacePath $PrivateWorkspacePath
    if (-not $cleanupVerified) {
        $result.state = 'Denied'
        $result.decision = 'Deny'
        $result.reasonCode = 'PUBLISH.CLEANUP_INCOMPLETE'
        return New-PreviewPublicationEvaluation -State Denied `
            -ReasonCode 'PUBLISH.CLEANUP_INCOMPLETE' -ExitKind CleanupIncomplete `
            -Result $result -Preview $preview -CleanupVerified:$false
    }

    $exitKind = 'Completed'
    New-PreviewPublicationEvaluation -State $state -ReasonCode $primary `
        -ExitKind $exitKind -Result $result -Preview $preview -CleanupVerified:$true
}
