[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-evidence-workspace.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/evidence-workspace.schema.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyJson = [System.IO.File]::ReadAllText(
    $policyPath, [System.Text.UTF8Encoding]::new($false, $true)
)
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the release Evidence Workspace policy satisfies its closed schema'
$policy = $policyJson | ConvertFrom-Json -Depth 30

Assert-Equal 'win-pcinfo.evidence-workspace/1.0.0' $policy.policyId `
    'workspace and recovery behavior have one release-owned identity'
Assert-Equal $true $policy.workspace.newPerRun `
    'an assessment cannot reuse a prior evidence boundary'
Assert-Equal $true $policy.workspace.rejectExistingTarget `
    'an existing path cannot be adopted as a new workspace'
Assert-Equal $true $policy.workspace.rejectReparsePoints `
    'a junction or symbolic link cannot redirect restricted evidence'
Assert-Equal 'InitiatingUser|LocalSystem' (@($policy.workspace.access.allowedPrincipals) -join '|') `
    'only the initiating user and the predefined trusted SYSTEM process receive access'
Assert-Equal $true $policy.workspace.access.protectedDacl `
    'ambient inherited access is removed from the evidence boundary'
Assert-Equal 'LocalApplicationData' $policy.workspace.safeAlternative.knownFolder `
    'unsafe destinations receive one local per-user alternative'
Assert-Equal 1048576 $policy.temporaryEvidence.maximumArtifactBytes `
    'one unprotected collector artifact has a release-owned byte ceiling'
Assert-Equal 16 $policy.temporaryEvidence.maximumArtifactCount `
    'temporary evidence count cannot grow without a release change'
Assert-Equal $false $policy.temporaryEvidence.secureErasureClaim `
    'ordinary verified deletion is not described as forensic erasure'
Assert-Equal 32768 $policy.journal.maximumUtf8Bytes `
    'the non-secret recovery journal has a stable size bound'
Assert-Equal 'runId|planDigest|phase|owner|artifacts|cleanup|systemTasks' `
    (@($policy.journal.allowedPayloadFields) -join '|') `
    'the journal has no generic evidence, credential, or metadata channel'
Assert-Equal 'CleanupOnly' $policy.recovery.mode `
    'recovery can never resume collection'
Assert-Equal 'LeaveAndReportCleanupIncomplete' $policy.recovery.ambiguousTargetAction `
    'unverifiable ownership fails safe without deletion'
Assert-Equal 'Preserve' $policy.recovery.finalizedPackageAction `
    'a completed Protected Evidence Package is outside stale cleanup'
Assert-Equal 'ObserveOnly' $policy.recovery.windowsFeatureAction `
    'recovery cannot disable an existing Windows Feature'
Assert-Equal 2 $policy.recovery.maximumCleanupAttempts `
    'cleanup has at most one idempotent retry'

$requiredScenarios = @(
    'EligibleDestination', 'UnsafeDestination', 'InterruptedTemporaryEvidence',
    'StaleOwner', 'LiveOwner', 'AmbiguousTarget', 'PreservedPackage',
    'WindowsFeatureObservation', 'CleanupFailure'
)
Assert-Equal ($requiredScenarios -join '|') (@($policy.validationScenarios) -join '|') `
    'the release freezes every issue-required validation case'

Write-Output 'PASS: the release contract closes workspace access, journal privacy, evidence bounds, and recovery behavior.'
