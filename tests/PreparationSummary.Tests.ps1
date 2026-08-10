[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$guidedAccepted = Invoke-GeneratedApplication -CandidatePath $candidatePath `
    -Arguments @('-Mode', 'Guided') -StandardInput "APPROVE`n"
$automationAccepted = Invoke-GeneratedApplication -CandidatePath $candidatePath `
    -Arguments @('-Mode', 'Automation', '-RequestPath', $requestPath, '-AcceptPreparation')
$automationDeclined = Invoke-GeneratedApplication -CandidatePath $candidatePath `
    -Arguments @('-Mode', 'Automation', '-RequestPath', $requestPath)

foreach ($result in @($guidedAccepted, $automationAccepted, $automationDeclined)) {
    Assert-Equal 20 $result.ExitCode 'preparation cannot claim collection before collectors exist'
    Assert-Equal $false $result.Records[-1].collectionStarted 'preparation performs no collection'
    Assert-Equal 1 @($result.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary').Count `
        'one complete Preparation Summary is presented'
}

$guidedSummary = @($guidedAccepted.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary')[0]
$automationSummary = @($automationAccepted.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary')[0]
$guidedTerminal = $guidedAccepted.Records[-1]
$automationTerminal = $automationAccepted.Records[-1]
$declinedTerminal = $automationDeclined.Records[-1]

Assert-Equal 'win-pcinfo.preparation-summary' $guidedSummary.recordType 'the public summary contract is versioned'
Assert-Equal $guidedSummary.planDigest $automationSummary.planDigest 'equivalent entry paths resolve one immutable plan'
Assert-Equal $guidedTerminal.planDigest $automationTerminal.planDigest 'accepted terminals bind to that immutable plan'
Assert-Equal 'Accepted' $guidedTerminal.preparationDecision 'guided approval is explicit after the summary'
Assert-Equal 'Accepted' $automationTerminal.preparationDecision 'automation approval requires the separate switch'
Assert-Equal 'SLICE.POST_APPROVAL_EXECUTION_NOT_IMPLEMENTED' $automationTerminal.reasonCode `
    'approval reaches the next unimplemented boundary without collection'
Assert-Equal 'Declined' $declinedTerminal.preparationDecision 'absence of automation approval safely declines'
Assert-Equal 'PREPARATION.DECLINED' $declinedTerminal.reasonCode 'decline remains NotStarted'
Assert-Equal $automationTerminal.planDigest $declinedTerminal.planDigest 'the decision cannot mutate the reviewed plan'

Assert-Equal 29 $automationSummary.scope.capabilities.Count 'every release-enabled capability is disclosed'
Assert-Equal 15 @($automationSummary.scope.capabilities | Where-Object disposition -eq 'Selected').Count `
    'the named profile preserves every explicitly selected capability'
Assert-Equal 1 @($automationSummary.scope.capabilities | Where-Object disposition -eq 'DependencyAdded').Count `
    'dependency closure is explicit rather than silently changing scope'
Assert-Equal 13 @($automationSummary.scope.capabilities | Where-Object disposition -eq 'ReleaseInvariant').Count `
    'remaining release invariants stay visible rather than silently shrinking'
Assert-Equal 'CAP-0015' @($automationSummary.scope.capabilities | Where-Object disposition -eq 'DependencyAdded')[0].id `
    'the controlled-run dependency is resolved'

Assert-Equal 'LocalOnly' $automationSummary.network.behavior 'local-only behavior is explicit'
Assert-Equal 0 $automationSummary.network.plannedRequests.Count 'local-only plans no assessment requests'
Assert-Equal $true $automationSummary.privilege.elevationRequired 'the frozen plan discloses its one elevation boundary'
Assert-Equal 1 $automationSummary.privilege.maximumUacInteractions 'the privilege ceiling is disclosed once'
Assert-Equal 0 $automationSummary.dependencies.installations.Count 'preparation plans no dependency installation'
Assert-Equal 0 $automationSummary.windowsFeatures.changes.Count 'preparation plans no Windows Feature changes'
Assert-Equal 'LocalPackageProtector' $automationSummary.output.protection.mode 'output protection is disclosed'
Assert-Equal 'None' $automationSummary.output.recipientProfile.mode 'the optional recipient choice is fixed before collection'
Assert-Equal $false $automationSummary.sideEffects.performedDuringPreparation `
    'summary and approval occur before all side effects'
Assert-Equal $true $automationSummary.cleanup.requiredAfterExecution 'later execution cleanup is disclosed upfront'

Write-Output 'PASS: one immutable Preparation Summary gates accepted and declined generated-app paths.'
