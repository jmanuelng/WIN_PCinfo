[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TextCanonicalization.ps1')
$sourcePaths = @(
    'src/ApplicationHeader.ps1'
    'src/Contracts.ps1'
    'src/ContractValidator.ps1'
    'src/RuntimeCompatibility.ps1'
    'src/Preparation.ps1'
    'src/ProcessSupervisor.ps1'
    'src/PrivilegedCollectionPlan.ps1'
    'src/SystemCollectionPlan.ps1'
    'src/EvidenceWorkspace.ps1'
    'src/RunLifecycle.ps1'
    'src/LaunchEngine.ps1'
    'src/EntryAdapters.ps1'
    'src/ApplicationMain.ps1'
)

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

$releaseDefinitionPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1.json'
$capabilityLedgerPath = Join-Path $repositoryRoot 'docs/spec/capability-ledger.json'
$preparationPlanPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-preparation-plan.json'
$assessmentContractSetPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-contract-set.json'
$assessmentRecordSchemaPath = Join-Path $repositoryRoot 'schemas/assessment-record.schema.json'
$approvedCollectorCatalogPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
$approvedCollectorCatalogSchemaPath = Join-Path $repositoryRoot 'schemas/approved-collector-catalog.schema.json'
$runLifecyclePolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-run-lifecycle.json'
$runLifecycleSchemaPath = Join-Path $repositoryRoot 'schemas/run-lifecycle.schema.json'
$privilegedCollectionPlanPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-privileged-collection-plan.json'
$privilegedCollectionPlanSchemaPath = Join-Path $repositoryRoot 'schemas/privileged-collection-plan.schema.json'
$systemCollectionPlanPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-system-collection-plan.json'
$systemCollectionPlanSchemaPath = Join-Path $repositoryRoot 'schemas/system-collection-plan.schema.json'
$evidenceWorkspacePolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-evidence-workspace.json'
$evidenceWorkspaceSchemaPath = Join-Path $repositoryRoot 'schemas/evidence-workspace.schema.json'
$runRecoveryJournalSchemaPath = Join-Path $repositoryRoot 'schemas/run-recovery-journal.schema.json'
foreach ($requiredDefinitionPath in @(
    $releaseDefinitionPath, $capabilityLedgerPath, $preparationPlanPath,
    $assessmentContractSetPath, $assessmentRecordSchemaPath,
    $approvedCollectorCatalogPath, $approvedCollectorCatalogSchemaPath,
    $runLifecyclePolicyPath, $runLifecycleSchemaPath,
    $privilegedCollectionPlanPolicyPath, $privilegedCollectionPlanSchemaPath,
    $systemCollectionPlanPolicyPath, $systemCollectionPlanSchemaPath,
    $evidenceWorkspacePolicyPath, $evidenceWorkspaceSchemaPath,
    $runRecoveryJournalSchemaPath
)) {
    if (-not (Test-Path -LiteralPath $requiredDefinitionPath -PathType Leaf)) {
        throw "Preparation definition input is missing: $requiredDefinitionPath"
    }
}
$releaseDefinition = Get-Content -LiteralPath $releaseDefinitionPath -Raw | ConvertFrom-Json -Depth 30
$capabilityLedger = Get-Content -LiteralPath $capabilityLedgerPath -Raw | ConvertFrom-Json -Depth 30
$preparationPlan = Get-Content -LiteralPath $preparationPlanPath -Raw | ConvertFrom-Json -Depth 30
$assessmentContractSetBytes = Get-Utf8LfBytes -LiteralPath $assessmentContractSetPath
$assessmentRecordSchemaBytes = Get-Utf8LfBytes -LiteralPath $assessmentRecordSchemaPath
$assessmentContractSetBase64 = [System.Convert]::ToBase64String($assessmentContractSetBytes)
$assessmentRecordSchemaBase64 = [System.Convert]::ToBase64String($assessmentRecordSchemaBytes)
$assessmentContractSetDigest = Get-Sha256Hex -Bytes $assessmentContractSetBytes
$assessmentRecordSchemaDigest = Get-Sha256Hex -Bytes $assessmentRecordSchemaBytes
$approvedCollectorCatalogBytes = Get-Utf8LfBytes -LiteralPath $approvedCollectorCatalogPath
$approvedCollectorCatalogBase64 = [System.Convert]::ToBase64String($approvedCollectorCatalogBytes)
$approvedCollectorCatalogDigest = Get-Sha256Hex -Bytes $approvedCollectorCatalogBytes
$approvedCollectorCatalogJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $approvedCollectorCatalogBytes
)
$runLifecyclePolicyBytes = Get-Utf8LfBytes -LiteralPath $runLifecyclePolicyPath
$runLifecyclePolicyBase64 = [System.Convert]::ToBase64String($runLifecyclePolicyBytes)
$runLifecyclePolicyDigest = Get-Sha256Hex -Bytes $runLifecyclePolicyBytes
$runLifecyclePolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $runLifecyclePolicyBytes
)
$privilegedCollectionPlanPolicyBytes = Get-Utf8LfBytes -LiteralPath $privilegedCollectionPlanPolicyPath
$privilegedCollectionPlanPolicyBase64 = [System.Convert]::ToBase64String($privilegedCollectionPlanPolicyBytes)
$privilegedCollectionPlanPolicyDigest = Get-Sha256Hex -Bytes $privilegedCollectionPlanPolicyBytes
$privilegedCollectionPlanPolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $privilegedCollectionPlanPolicyBytes
)
$systemCollectionPlanPolicyBytes = Get-Utf8LfBytes -LiteralPath $systemCollectionPlanPolicyPath
$systemCollectionPlanPolicyBase64 = [System.Convert]::ToBase64String($systemCollectionPlanPolicyBytes)
$systemCollectionPlanPolicyDigest = Get-Sha256Hex -Bytes $systemCollectionPlanPolicyBytes
$systemCollectionPlanPolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $systemCollectionPlanPolicyBytes
)
$evidenceWorkspacePolicyBytes = Get-Utf8LfBytes -LiteralPath $evidenceWorkspacePolicyPath
$evidenceWorkspacePolicyBase64 = [System.Convert]::ToBase64String($evidenceWorkspacePolicyBytes)
$evidenceWorkspacePolicyDigest = Get-Sha256Hex -Bytes $evidenceWorkspacePolicyBytes
$evidenceWorkspacePolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $evidenceWorkspacePolicyBytes
)
$runRecoveryJournalSchemaBytes = Get-Utf8LfBytes -LiteralPath $runRecoveryJournalSchemaPath
$runRecoveryJournalSchemaBase64 = [System.Convert]::ToBase64String($runRecoveryJournalSchemaBytes)
$runRecoveryJournalSchemaDigest = Get-Sha256Hex -Bytes $runRecoveryJournalSchemaBytes
if (-not (Test-Json -Json $approvedCollectorCatalogJson -SchemaFile $approvedCollectorCatalogSchemaPath)) {
    throw 'The approved collector catalog does not satisfy its release schema.'
}
if (-not (Test-Json -Json $runLifecyclePolicyJson -SchemaFile $runLifecycleSchemaPath)) {
    throw 'The run lifecycle policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $privilegedCollectionPlanPolicyJson -SchemaFile $privilegedCollectionPlanSchemaPath)) {
    throw 'The Privileged Collection Plan policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $systemCollectionPlanPolicyJson -SchemaFile $systemCollectionPlanSchemaPath)) {
    throw 'The SYSTEM Collection sub-plan policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $evidenceWorkspacePolicyJson -SchemaFile $evidenceWorkspaceSchemaPath)) {
    throw 'The Evidence Workspace policy does not satisfy its release schema.'
}
$selectedIds = @($releaseDefinition.profile.selectedCapabilityIds)
$releaseEnabledIds = @($releaseDefinition.releaseEnabledCapabilityIds)
$capabilitiesById = @{}
foreach ($capability in @($capabilityLedger.capabilities)) { $capabilitiesById[[string] $capability.id] = $capability }
if (@($releaseEnabledIds | Where-Object { -not $capabilitiesById.ContainsKey([string] $_) }).Count -gt 0) {
    throw 'The release definition refers to an unknown capability.'
}
$operationCapabilityIds = @($preparationPlan.operations.capabilityId)
if ($operationCapabilityIds.Count -ne $releaseEnabledIds.Count -or
    @($operationCapabilityIds | Sort-Object -Unique).Count -ne $releaseEnabledIds.Count -or
    @($releaseEnabledIds | Where-Object { $_ -notin $operationCapabilityIds }).Count -gt 0) {
    throw 'The preparation operation manifest must resolve every release-enabled capability exactly once.'
}
$dependencyIds = @($selectedIds | ForEach-Object { @($capabilitiesById[[string] $_].dependsOnCapabilityIds) } |
    Where-Object { $_ -notin $selectedIds } | Sort-Object -Unique)
$resolvedCapabilities = foreach ($capabilityId in $releaseEnabledIds) {
    $disposition = if ($capabilityId -in $selectedIds) { 'Selected' }
        elseif ($capabilityId -in $dependencyIds) { 'DependencyAdded' }
        else { 'ReleaseEnabledProductCapability' }
    [pscustomobject][ordered]@{
        id = [string] $capabilityId
        name = [string] $capabilitiesById[[string] $capabilityId].name
        disposition = $disposition
        dependsOnCapabilityIds = @($capabilitiesById[[string] $capabilityId].dependsOnCapabilityIds)
    }
}
$applicationResourcePaths = @($sourcePaths) + @(
    'build/Build.ps1'
    'build/TextCanonicalization.ps1'
    'schemas/assessment-run-request.schema.json'
    'schemas/preparation-plan.schema.json'
    'schemas/assessment-record.schema.json'
    'schemas/assessment-contract-set.schema.json'
    'schemas/approved-collector-catalog.schema.json'
    'schemas/run-lifecycle.schema.json'
    'schemas/privileged-collection-plan.schema.json'
    'schemas/system-collection-plan.schema.json'
    'schemas/evidence-workspace.schema.json'
    'schemas/run-recovery-journal.schema.json'
    'docs/spec/releases/2.0.0-preview.1-contract-set.json'
    'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
    'docs/spec/releases/2.0.0-preview.1-run-lifecycle.json'
    'docs/spec/releases/2.0.0-preview.1-privileged-collection-plan.json'
    'docs/spec/releases/2.0.0-preview.1-system-collection-plan.json'
    'docs/spec/releases/2.0.0-preview.1-evidence-workspace.json'
)
$applicationResources = @(
    foreach ($path in $applicationResourcePaths) {
        # Git may materialize text as LF or CRLF. The application manifest binds
        # the reviewed logical text, while the generated signing representation
        # remains the separately fixed UTF-8-BOM/CRLF output below.
        $bytes = Get-Utf8LfBytes -LiteralPath (Join-Path $repositoryRoot $path)
        [pscustomobject][ordered]@{ path = $path; sha256 = Get-Sha256Hex -Bytes $bytes }
    }
)
$applicationManifestBody = [pscustomobject][ordered]@{
    contractVersion = '1.0.0'
    resources = $applicationResources
}
$applicationManifestBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
    ($applicationManifestBody | ConvertTo-Json -Compress -Depth 30)
)
$preparationDefinition = [pscustomobject][ordered]@{
    contractVersion = '1.0.0'
    release = [string] $releaseDefinition.release
    profileId = [string] $releaseDefinition.profile.id
    profileName = [string] $releaseDefinition.profile.name
    capabilities = @($resolvedCapabilities)
    operations = @($preparationPlan.operations)
    requiredFreeDiskMiB = [int] $preparationPlan.requiredFreeDiskMiB
    governingResources = @(
        foreach ($path in @(
            'docs/spec/releases/2.0.0-preview.1.json'
            'docs/spec/capability-ledger.json'
            'docs/spec/releases/2.0.0-preview.1-preparation-plan.json'
        )) {
            $bytes = Get-Utf8LfBytes -LiteralPath (Join-Path $repositoryRoot $path)
            [pscustomobject][ordered]@{ path = $path; sha256 = Get-Sha256Hex -Bytes $bytes }
        }
    )
    applicationManifest = [pscustomobject][ordered]@{
        contractVersion = $applicationManifestBody.contractVersion
        resources = $applicationManifestBody.resources
        sha256 = Get-Sha256Hex -Bytes $applicationManifestBytes
    }
}
$preparationJson = $preparationDefinition | ConvertTo-Json -Compress -Depth 30
$preparationBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($preparationJson)
$preparationBase64 = [System.Convert]::ToBase64String($preparationBytes)
$preparationDigest = Get-Sha256Hex -Bytes $preparationBytes

$sourceFiles = foreach ($relativePath in $sourcePaths) {
    $literalPath = Join-Path $repositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $literalPath -PathType Leaf)) {
        throw "Build input is missing: $relativePath"
    }
    $bytes = [System.IO.File]::ReadAllBytes($literalPath)
    [pscustomobject][ordered]@{
        path = $relativePath
        literalPath = $literalPath
        bytes = $bytes
        text = [System.IO.File]::ReadAllText($literalPath)
    }
}

$sourceInputs = foreach ($sourceFile in $sourceFiles) {
    [pscustomobject][ordered]@{
        path = $sourceFile.path
        sha256 = Get-Sha256Hex -Bytes $sourceFile.bytes
        byteLength = $sourceFile.bytes.Length
    }
}

$sections = foreach ($sourceFile in $sourceFiles) {
    $normalizedSource = $sourceFile.text -replace "`r`n", "`n" -replace "`r", "`n"
    if ($sourceFile.path -eq 'src/Preparation.ps1') {
        $normalizedSource = $normalizedSource.Replace('__PREPARATION_DEFINITION_BASE64__', $preparationBase64)
        $normalizedSource = $normalizedSource.Replace('__PREPARATION_DEFINITION_SHA256__', $preparationDigest)
    }
    if ($sourceFile.path -eq 'src/ContractValidator.ps1') {
        $normalizedSource = $normalizedSource.Replace('__ASSESSMENT_CONTRACT_SET_BASE64__', $assessmentContractSetBase64)
        $normalizedSource = $normalizedSource.Replace('__ASSESSMENT_CONTRACT_SET_SHA256__', $assessmentContractSetDigest)
        $normalizedSource = $normalizedSource.Replace('__ASSESSMENT_RECORD_SCHEMA_BASE64__', $assessmentRecordSchemaBase64)
        $normalizedSource = $normalizedSource.Replace('__ASSESSMENT_RECORD_SCHEMA_SHA256__', $assessmentRecordSchemaDigest)
    }
    if ($sourceFile.path -eq 'src/ProcessSupervisor.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__APPROVED_COLLECTOR_CATALOG_BASE64__', $approvedCollectorCatalogBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__APPROVED_COLLECTOR_CATALOG_SHA256__', $approvedCollectorCatalogDigest
        )
    }
    if ($sourceFile.path -eq 'src/RunLifecycle.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__RUN_LIFECYCLE_POLICY_BASE64__', $runLifecyclePolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RUN_LIFECYCLE_POLICY_SHA256__', $runLifecyclePolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/PrivilegedCollectionPlan.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__PRIVILEGED_COLLECTION_PLAN_POLICY_BASE64__', $privilegedCollectionPlanPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__PRIVILEGED_COLLECTION_PLAN_POLICY_SHA256__', $privilegedCollectionPlanPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/SystemCollectionPlan.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__SYSTEM_COLLECTION_PLAN_POLICY_BASE64__', $systemCollectionPlanPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__SYSTEM_COLLECTION_PLAN_POLICY_SHA256__', $systemCollectionPlanPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/EvidenceWorkspace.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__EVIDENCE_WORKSPACE_POLICY_BASE64__', $evidenceWorkspacePolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__EVIDENCE_WORKSPACE_POLICY_SHA256__', $evidenceWorkspacePolicyDigest
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RUN_RECOVERY_JOURNAL_SCHEMA_BASE64__', $runRecoveryJournalSchemaBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RUN_RECOVERY_JOURNAL_SCHEMA_SHA256__', $runRecoveryJournalSchemaDigest
        )
    }
    "#region Generated from $($sourceFile.path)`n$($normalizedSource.TrimEnd("`n"))`n#endregion Generated from $($sourceFile.path)"
}

$generated = (@(
    '# This file is generated by build/Build.ps1. Do not edit it by hand.'
    '# Build format: WIN-PCInfo deterministic PowerShell application v1.'
    $sections
) -join "`n`n") -replace "`n", "`r`n"
$generated += "`r`n"

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutput
$null = New-Item -ItemType Directory -Path $outputDirectory -Force

# The release signing contract requires UTF-8 with BOM and CRLF. Constructing the
# encoder explicitly avoids behavior changes between Windows PowerShell and pwsh.
$utf8WithBom = [System.Text.UTF8Encoding]::new($true)
[System.IO.File]::WriteAllText($resolvedOutput, $generated, $utf8WithBom)

$digest = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($resolvedOutput))
$buildToolPath = 'build/Build.ps1'
$buildToolDigest = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($PSCommandPath))

[pscustomobject]@{
    buildContract = 'win-pcinfo.build-evidence/1.0.0'
    outputPath = $resolvedOutput
    sha256 = $digest
    buildTool = [pscustomobject][ordered]@{
        path = $buildToolPath
        sha256 = $buildToolDigest
    }
    sourceInputs = $sourceInputs
    definitionInputs = @($preparationDefinition.governingResources)
    applicationManifest = $preparationDefinition.applicationManifest
    encoding = 'utf-8-bom'
    lineEndings = 'crlf'
}
