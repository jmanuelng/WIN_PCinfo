[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policy = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-guided-runway.json'
) -Raw | ConvertFrom-Json -Depth 20

$headerText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src/ApplicationHeader.ps1') -Raw
$allowedWorkflows = @(
    'Assessment', 'RecipientProfileSetup', 'RestrictedReportExport', 'Help', 'About'
)
$allowedModes = @('Guided', 'Automation')
Assert-Equal $true (
    $headerText.Contains("ValidateSet('Assessment', 'RecipientProfileSetup', 'RestrictedReportExport', 'Help', 'About')")
) 'Help and About are first-class generated-application workflows'
Assert-Equal $true ($headerText.Contains("ValidateSet('Guided', 'Automation')")) `
    'Guided and Automation remain the implemented launch modes'

$documentTexts = [ordered]@{}
foreach ($document in @($policy.documents)) {
    $path = Join-Path $repositoryRoot ([string] $document.path)
    Assert-Equal $true (Test-Path -LiteralPath $path -PathType Leaf) `
        "$($document.id) exists at $($document.path)"
    $documentTexts[$document.id] = Get-Content -LiteralPath $path -Raw
}

$beginnerCorpus = @(
    $documentTexts.guidedRunway
    $documentTexts.consultantWorkbench
    $documentTexts.fieldValidation
    $documentTexts.syntheticExamples
    $documentTexts.security
    $documentTexts.contributing
    $documentTexts.readme
) -join "`n"

$topicPhrases = [ordered]@{
    purpose = 'What WIN-PCInfo is for'
    learningConsultingBoundary = 'learning and consulting'
    prerequisites = 'Prerequisites'
    terminology = 'Terminology'
    safetyReasoning = 'Safety reasoning'
    expectedOutcomes = 'Expected outcomes'
    limitations = 'Limitations'
    troubleshooting = 'Troubleshoot'
    sharing = 'Share'
    governance = 'Governance'
    bestEffortMaintenance = 'best effort'
}
foreach ($topic in @($policy.requiredTopics)) {
    $phrase = [string] $topicPhrases[$topic]
    Assert-Equal $true ($beginnerCorpus -match [regex]::Escape($phrase)) `
        "beginner documentation explains $topic using '$phrase'"
}

$runwayText = [string] $documentTexts.guidedRunway
foreach ($stage in @($policy.runway)) {
    Assert-Equal $true ($runwayText -match "(?m)^## $stage") `
        "the Guided Runway has a beginner heading for $stage"
}

$claimHeadings = [ordered]@{
    verifyBeforeRun = 'Verify before run'
    runtimeIntegrity = 'Runtime integrity'
    previewVersusStable = 'Preview versus Stable'
    attestedVersusTrusted = 'Attested versus trusted'
    capabilityMatrices = 'Capability matrices'
    supportClaims = 'Support claims'
    microsoftLifecycle = 'Microsoft lifecycle'
}
foreach ($claim in @($policy.claimSeparations)) {
    $heading = [string] $claimHeadings[$claim]
    Assert-Equal $true ($runwayText -match "(?m)^### $heading") `
        "$claim is explained under its own heading"
}

$exampleText = [string] $documentTexts.syntheticExamples
$exampleMarkers = [ordered]@{
    missingEvidence = 'Example: missing evidence'
    indeterminateFinding = 'Example: Indeterminate finding'
    tenantSideDiscoveryTask = 'Example: Tenant-side Discovery Task'
    restrictedSharing = 'Example: restricted sharing'
}
foreach ($example in @($policy.syntheticExamples)) {
    $marker = [string] $exampleMarkers[$example]
    Assert-Equal $true ($exampleText -match [regex]::Escape($marker)) `
        "synthetic examples teach $example"
}
Assert-Equal $true ($exampleText -match 'synthetic') `
    'worked examples identify themselves as synthetic'
Assert-Equal $true ($exampleText -match 'CONNECTIVITY\.LOCAL_ONLY_NOT_ATTEMPTED') `
    'missing-evidence example uses the implemented Local Only connectivity coverage reason'
Assert-Equal $false ($exampleText -match 'FINDING\.NETWORK_REQUESTS_NOT_ATTEMPTED') `
    'missing-evidence example does not teach the network-topology finding reason as connectivity coverage'
Assert-Equal $true ($exampleText -match 'device object and intended assignment') `
    'identity discovery-task example teaches an implemented identity task'
Assert-Equal $false ($exampleText -match 'Conditional Access and compliant-device') `
    'identity discovery-task example is not a cross-domain Conditional Access task'
Assert-Equal $false ($exampleText -match '(?i)\b(tenant id|subscription id|10\.\d+\.\d+\.\d+)\b') `
    'worked examples contain no real tenant, subscription, or host-network facts'

$procedurePhrases = [ordered]@{
    recipientSetup = '-Workflow RecipientProfileSetup'
    packageOpening = 'Evidence Viewing Session'
    staleRecovery = 'allowStaleRecovery'
    cancellation = 'Ctrl+C'
    restrictedReportExport = '-Workflow RestrictedReportExport'
    prohibitedPublicEvidence = 'never attach'
}
foreach ($procedure in @($policy.operatorProcedures)) {
    $phrase = [string] $procedurePhrases[$procedure]
    Assert-Equal $true ($beginnerCorpus -match [regex]::Escape($phrase)) `
        "beginner documentation teaches $procedure"
}

$fieldText = [string] $documentTexts.fieldValidation
Assert-Equal $true ($fieldText -match [regex]::Escape([string] $policy.fieldValidation.consentPhrase)) `
    'Field Validation instructions require the exact consent phrase'
Assert-Equal $true ($fieldText -match 'ordinary Preview use never becomes validation evidence automatically') `
    'Field Validation instructions keep ordinary use out of release evidence'
Assert-Equal $true ($fieldText -match 'sanitized attestation') `
    'Field Validation instructions require a sanitized attestation'
Assert-Equal $true ($fieldText -match 'never uploads evidence') `
    'Field Validation instructions prohibit evidence upload'
Assert-Equal $true ($fieldText -match 'never displays a post-run validation request') `
    'Field Validation instructions prohibit a post-run prompt'

$deferredClaims = @(
    @{ id = 'CAP-0021'; needle = 'safe public feedback bundle'; forbidden = 'feedback bundle is implemented' }
    @{ id = 'CAP-0029'; needle = 'Community Validation'; forbidden = 'Community Validation is implemented' }
    @{ id = 'CAP-0032'; needle = 'adoption and outcome measures'; forbidden = 'adoption measures are implemented' }
    @{ id = 'CAP-0039'; needle = 'formal accessibility'; forbidden = 'formal accessibility conformance is implemented' }
    @{ id = 'CMP-0061'; needle = 'WinGet'; forbidden = 'WinGet package-availability enrichment is implemented' }
)
foreach ($deferred in $deferredClaims) {
    Assert-Equal $true ($beginnerCorpus -match [regex]::Escape($deferred.needle)) `
        "documentation names deferred behavior $($deferred.id)"
    Assert-Equal $false ($beginnerCorpus -match [regex]::Escape($deferred.forbidden)) `
        "documentation does not claim $($deferred.id) is implemented"
}

$forbiddenImplementedClaims = @(
    'this slice creates a Preview/Supported capability claim',
    'this release is Supported',
    'Authenticode signing is complete',
    'the installer is available',
    'WIN-PCInfo installs PowerShell',
    'automatic telemetry'
)
foreach ($claim in $forbiddenImplementedClaims) {
    Assert-Equal $false ($beginnerCorpus -match [regex]::Escape($claim)) `
        "documentation does not claim '$claim'"
}

$brokenLinks = New-Object System.Collections.Generic.List[string]
$linkPattern = '\[(?:[^\]]+)\]\((?<target>[^)]+)\)'
foreach ($document in @($policy.documents)) {
    $text = [string] $documentTexts[$document.id]
    foreach ($match in [regex]::Matches($text, $linkPattern)) {
        $target = [string] $match.Groups['target'].Value
        if ($target -match '^(https?://|#)') { continue }
        $relative = ($target -split '#')[0]
        if ([string]::IsNullOrWhiteSpace($relative)) { continue }
        $resolved = [System.IO.Path]::GetFullPath(
            (Join-Path (Split-Path -Parent (Join-Path $repositoryRoot ([string] $document.path))) $relative)
        )
        if (-not (Test-Path -LiteralPath $resolved)) {
            $brokenLinks.Add("$($document.path) -> $target")
        }
    }
}
Assert-Equal 0 $brokenLinks.Count (
    "every local markdown link resolves: $($brokenLinks -join '; ')"
)

$offlineAssetPattern = '(?i)(https?://[^)\s]+\.(css|js|woff2?|png|jpe?g|gif|svg)|<script|<link\s+rel="stylesheet")'
foreach ($document in @($policy.documents)) {
    Assert-Equal $false ([string] $documentTexts[$document.id] -match $offlineAssetPattern) `
        "$($document.id) stays instructional markdown without remote presentation assets"
}

$commandPattern = '(?ms)```powershell\s*(?<body>.*?)```'
$seenCommands = New-Object System.Collections.Generic.HashSet[string]
foreach ($document in @($policy.documents)) {
    foreach ($match in [regex]::Matches([string] $documentTexts[$document.id], $commandPattern)) {
        $body = [string] $match.Groups['body'].Value
        $continued = $body -replace '`\s*\r?\n', ' '
        foreach ($line in @($continued -split '\r?\n')) {
            $normalized = ($line -replace '\s+', ' ').Trim()
            if ([string]::IsNullOrWhiteSpace($normalized)) { continue }
            $null = $seenCommands.Add($normalized)
            if ($normalized -notmatch '(?i)^pwsh -NoLogo -NoProfile -File ') {
                throw "$($document.id) documents a command that is not the pinned pwsh -NoLogo -NoProfile -File form: $normalized"
            }
            if ($normalized -match '(?i)-Workflow\s+(?<workflow>\S+)') {
                $workflow = $Matches['workflow']
                Assert-Equal $true ($workflow -in $allowedWorkflows) `
                    "$($document.id) documents an implemented -Workflow $workflow"
            }
            if ($normalized -match '(?i)-Mode\s+(?<mode>\S+)') {
                $mode = $Matches['mode']
                Assert-Equal $true ($mode -in $allowedModes) `
                    "$($document.id) documents an implemented -Mode $mode"
            }
            if ($normalized -match '(?i)-File\s+(?<file>\./(?:build|artifacts|tests)/[^\s]+)') {
                $file = $Matches['file']
                if ($file -notlike './artifacts/*') {
                    $resolvedFile = Join-Path $repositoryRoot ($file.TrimStart('.', '/', '\'))
                    $resolvedFile = $resolvedFile -replace '/', [System.IO.Path]::DirectorySeparatorChar
                    Assert-Equal $true (Test-Path -LiteralPath $resolvedFile) `
                        "$($document.id) documents an existing repository file $file"
                }
            }
        }
    }
}

foreach ($requiredCommand in @($policy.documentedCommands)) {
    $found = $false
    foreach ($seen in $seenCommands) {
        if ($seen -eq [string] $requiredCommand) { $found = $true; break }
    }
    Assert-Equal $true $found "beginner documentation includes the contracted command: $requiredCommand"
}

Write-Output 'PASS: Guided Runway documentation covers the content contract, links, commands, and claims.'
