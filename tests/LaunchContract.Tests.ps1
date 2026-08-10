[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$guided = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @('-Mode', 'Guided')
$automation = Invoke-GeneratedApplication -CandidatePath $candidatePath `
    -Arguments @('-Mode', 'Automation', '-RequestPath', $requestPath)

$guidedTerminal = $guided.Records[-1]
$automationTerminal = $automation.Records[-1]

Assert-Equal 20 $guided.ExitCode 'the tracer bullet must not claim that collection completed'
Assert-Equal $guided.ExitCode $automation.ExitCode 'both entry adapters use one exit contract'
Assert-Equal 'win-pcinfo.terminal' $guidedTerminal.recordType 'the generated application emits the public terminal contract'
Assert-Equal $guidedTerminal.contractVersion $automationTerminal.contractVersion 'both entry adapters use one contract version'
Assert-Equal $guidedTerminal.outcome $automationTerminal.outcome 'both entry adapters use one terminal outcome'
Assert-Equal $guidedTerminal.reasonCode $automationTerminal.reasonCode 'both entry adapters reach the same engine boundary'
Assert-Equal $guidedTerminal.requestDigest $automationTerminal.requestDigest 'equivalent guided and automation requests normalize identically'
Assert-Equal 'PREPARATION.DECLINED' $guidedTerminal.reasonCode `
    'approval defaults safely to decline after the eligible host presents preparation'
Assert-Equal $true $guidedTerminal.runtime.eligible 'the installed stable host passes every live compatibility probe'
Assert-Equal $guidedTerminal.planDigest $automationTerminal.planDigest `
    'both entry adapters decline the same immutable reviewed plan'

$guidedProgressRecords = @($guided.Records | Where-Object recordType -eq 'win-pcinfo.progress')
$automationProgressRecords = @($automation.Records | Where-Object recordType -eq 'win-pcinfo.progress')
Assert-Equal $guidedProgressRecords.Count $automationProgressRecords.Count 'entry paths emit the same progress count'
for ($index = 0; $index -lt $guidedProgressRecords.Count; $index++) {
    $guidedProgress = $guidedProgressRecords[$index]
    $automationProgress = $automationProgressRecords[$index]
    Assert-Equal $guidedProgress.recordType $automationProgress.recordType 'entry paths use the same progress record type'
    Assert-Equal $guidedProgress.phase $automationProgress.phase 'entry paths use the same progress phases'
    Assert-Equal $guidedProgress.state $automationProgress.state 'entry paths use the same progress states'
    Assert-Equal $guidedProgress.messageId $automationProgress.messageId 'entry paths use the same stable progress identities'
    Assert-Equal $guidedProgress.completion.completedUnits $automationProgress.completion.completedUnits 'entry paths use the same bounded completion'
    Assert-Equal $guidedProgress.completion.totalUnits $automationProgress.completion.totalUnits 'entry paths use the same completion bound'
}

Write-Output 'PASS: generated guided and automation launches share request and terminal contracts.'
