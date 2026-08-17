[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-guided-runway.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/guided-runway.schema.json'

Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'the Guided Runway content contract is release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the Guided Runway content contract has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the Guided Runway content contract satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20

Assert-Equal 'win-pcinfo.guided-runway/1.0.0' $policy.policyId `
    'the content contract has a stable release identity'
Assert-Equal 'ConsultantWorkbenchAndGuidedRunway' $policy.presentation `
    'the contract is presented as Consultant Workbench and Guided Runway'
Assert-Equal 7 @($policy.runway).Count 'the beginner runway has seven stages'
Assert-Equal 'Choose' $policy.runway[0] 'the first stage is Choose'
Assert-Equal 'Verify' $policy.runway[1] 'the second stage is Verify'
Assert-Equal 'Prepare' $policy.runway[2] 'the third stage is Prepare'
Assert-Equal 'Run' $policy.runway[3] 'the fourth stage is Run'
Assert-Equal 'Interpret' $policy.runway[4] 'the fifth stage is Interpret'
Assert-Equal 'Troubleshoot' $policy.runway[5] 'the sixth stage is Troubleshoot'
Assert-Equal 'Share' $policy.runway[6] 'the seventh stage is Share'

$requiredTopics = @(
    'purpose',
    'learningConsultingBoundary',
    'prerequisites',
    'terminology',
    'safetyReasoning',
    'expectedOutcomes',
    'limitations',
    'troubleshooting',
    'sharing',
    'governance',
    'bestEffortMaintenance'
)
foreach ($topic in $requiredTopics) {
    Assert-Equal $true ($topic -in @($policy.requiredTopics)) `
        "the content contract requires the $topic topic"
}

$claimSeparations = @(
    'verifyBeforeRun',
    'runtimeIntegrity',
    'previewVersusStable',
    'attestedVersusTrusted',
    'capabilityMatrices',
    'supportClaims',
    'microsoftLifecycle'
)
foreach ($topic in $claimSeparations) {
    Assert-Equal $true ($topic -in @($policy.claimSeparations)) `
        "the content contract separates the $topic explanation"
}

$examples = @(
    'missingEvidence',
    'indeterminateFinding',
    'tenantSideDiscoveryTask',
    'restrictedSharing'
)
foreach ($example in $examples) {
    Assert-Equal $true ($example -in @($policy.syntheticExamples)) `
        "the content contract requires the $example synthetic example"
}

$procedures = @(
    'recipientSetup',
    'packageOpening',
    'staleRecovery',
    'cancellation',
    'restrictedReportExport',
    'prohibitedPublicEvidence'
)
foreach ($procedure in $procedures) {
    Assert-Equal $true ($procedure -in @($policy.operatorProcedures)) `
        "the content contract requires beginner $procedure instructions"
}

Assert-Equal $false $policy.fieldValidation.automaticFromOrdinaryUse `
    'ordinary Preview use never becomes Field Validation evidence'
Assert-Equal $true $policy.fieldValidation.requiresDeliberateConsent `
    'Field Validation requires deliberate consent'
Assert-Equal 'I CONSENT TO A PRIVACY-SANITIZED FIELD VALIDATION ATTESTATION' `
    $policy.fieldValidation.consentPhrase `
    'Field Validation uses one exact consent phrase'
Assert-Equal $true $policy.discovery.passiveOnly `
    'repository and feedback routes stay passive'
Assert-Equal $false $policy.discovery.promptDuringAssessment `
    'assessment runs must not prompt for feedback'
Assert-Equal $false $policy.help.networkRequested `
    'Help and About remain offline and do not fetch routes'
Assert-Equal $false $policy.help.artifactTrustRequired `
    'Help and About stay readable on an unsigned development artifact'

Write-Output 'PASS: the Guided Runway content contract is closed by release policy.'
