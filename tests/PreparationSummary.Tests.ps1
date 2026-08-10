[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationFixturePath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$guidedAccepted = Invoke-GeneratedApplication -CandidatePath $candidatePath `
    -Arguments @('-Mode', 'Guided', '-PreparationFixturePath', $preparationFixturePath) -StandardInput "APPROVE`n"
$automationAccepted = Invoke-GeneratedApplication -CandidatePath $candidatePath `
    -Arguments @('-Mode', 'Automation', '-RequestPath', $requestPath, '-AcceptPreparation', '-PreparationFixturePath', $preparationFixturePath)
$automationDeclined = Invoke-GeneratedApplication -CandidatePath $candidatePath `
    -Arguments @('-Mode', 'Automation', '-RequestPath', $requestPath, '-PreparationFixturePath', $preparationFixturePath)

foreach ($result in @($guidedAccepted, $automationAccepted, $automationDeclined)) {
    Assert-Equal 20 $result.ExitCode 'preparation cannot claim collection before collectors exist'
    Assert-Equal $false $result.Records[-1].collectionStarted 'preparation performs no collection'
    Assert-Equal 1 @($result.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary').Count `
        'one complete Preparation Summary is presented'
    Assert-Equal 0 @($result.Records | Where-Object recordType -eq 'win-pcinfo.preparation-plan').Count `
        'the plan is contained in the summary so disclosures are not repeated'
}

$guidedSummary = @($guidedAccepted.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary')[0]
$automationSummary = @($automationAccepted.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary')[0]
$guidedTerminal = $guidedAccepted.Records[-1]
$automationTerminal = $automationAccepted.Records[-1]
$declinedTerminal = $automationDeclined.Records[-1]

Assert-Equal 'win-pcinfo.preparation-summary' $guidedSummary.recordType 'the public summary contract is versioned'
Assert-Equal $true $automationSummary.readyForApproval 'active metadata-only prerequisite checks resolve before approval'
Assert-Equal 5 $automationSummary.criticalPrerequisites.checks.Count 'all active critical prerequisite classes are reported'
Assert-Equal 0 $automationSummary.criticalPrerequisites.unresolved.Count 'the accepted path has no unresolved critical prerequisite'
Assert-Equal $guidedSummary.planDigest $automationSummary.planDigest 'equivalent entry paths resolve one immutable plan'
Assert-Equal $guidedTerminal.planDigest $automationTerminal.planDigest 'accepted terminals bind to that immutable plan'
Assert-Equal 'Accepted' $guidedTerminal.preparationDecision 'guided approval is explicit after the summary'
Assert-Equal 'Accepted' $automationTerminal.preparationDecision 'automation approval requires the separate switch'
Assert-Equal 'PREPARATION.VALIDATION_ONLY' $automationTerminal.reasonCode `
    'synthetic approval remains validation-only without collection'
Assert-Equal 'Declined' $declinedTerminal.preparationDecision 'absence of automation approval safely declines'
Assert-Equal 'PREPARATION.DECLINED' $declinedTerminal.reasonCode 'decline remains NotStarted'
Assert-Equal $automationTerminal.planDigest $declinedTerminal.planDigest 'the decision cannot mutate the reviewed plan'

Assert-Equal 29 $automationSummary.plan.scope.capabilities.Count 'every release-enabled capability is disclosed'
Assert-Equal 15 @($automationSummary.plan.scope.capabilities | Where-Object disposition -eq 'Selected').Count `
    'the named profile preserves every explicitly selected capability'
Assert-Equal 1 @($automationSummary.plan.scope.capabilities | Where-Object disposition -eq 'DependencyAdded').Count `
    'dependency closure is explicit rather than silently changing scope'
Assert-Equal 13 @($automationSummary.plan.scope.capabilities | Where-Object disposition -eq 'ReleaseEnabledProductCapability').Count `
    'remaining release-enabled Product Capabilities stay visible rather than silently shrinking'
Assert-Equal 'CAP-0015' @($automationSummary.plan.scope.capabilities | Where-Object disposition -eq 'DependencyAdded')[0].id `
    'the controlled-run dependency is resolved'

Assert-Equal 29 $automationSummary.plan.operations.Count 'every release-enabled capability has one frozen operation or control'
Assert-Equal 5 $automationSummary.plan.privilege.privilegedOperations.Count 'administrator and SYSTEM work is concrete and frozen'
Assert-Equal 'LocalOnly' $automationSummary.plan.network.behavior 'local-only behavior is explicit'
Assert-Equal 0 $automationSummary.plan.network.plannedRequests.Count 'local-only plans no assessment requests'
Assert-Equal $true $automationSummary.plan.privilege.elevationRequired 'the frozen plan discloses its one elevation boundary'
Assert-Equal 1 $automationSummary.plan.privilege.maximumUacInteractions 'the privilege ceiling is disclosed once'
Assert-Equal $false $automationSummary.plan.privilege.laterPromptsAllowed 'no later authority or elevation prompt is permitted'
Assert-Equal $false $automationSummary.plan.privilege.elevationPromptAfterApprovalAllowed `
    'the frozen elevation boundary cannot become a later prompt'
Assert-Equal 0 $automationSummary.plan.dependencies.installations.Count 'preparation plans no dependency installation'
Assert-Equal 0 $automationSummary.plan.windowsFeatures.changes.Count 'preparation plans no Windows Feature changes'
Assert-Equal 'LocalPackageProtector' $automationSummary.plan.output.protection.mode 'output protection is disclosed'
Assert-Equal 'None' $automationSummary.plan.output.recipientProfile.mode 'the optional recipient choice is fixed before collection'
Assert-Equal 'C:\Synthetic\WIN-PCInfo-Results' $automationSummary.plan.output.destination `
    'the plan freezes the absolute destination resolved during preflight'
Assert-Equal $false $automationSummary.plan.sideEffects.performedDuringPreparation `
    'summary and approval occur before all side effects'
Assert-Equal $true $automationSummary.plan.cleanup.requiredAfterExecution 'later execution cleanup is disclosed upfront'
Assert-Equal 15 $automationSummary.plan.integrity.applicationResources.Count `
    'the plan is bound to modular source, build, public schemas, and the release Contract Set'

Write-Output 'PASS: one immutable Preparation Summary gates accepted and declined generated-app paths.'
