Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'RequestValidation' -State 'Started' -MessageId 'request.validation.started')
try {
    $request = if ($Mode -eq 'Automation') {
        if ([string]::IsNullOrWhiteSpace($RequestPath)) {
            $exception = [System.ArgumentException]::new('Automation mode requires -RequestPath.')
            $exception.Data['ReasonCode'] = 'REQUEST.PATH_REQUIRED'
            throw $exception
        }
        Get-AutomationRequest -LiteralPath $RequestPath
    }
    else {
        Get-GuidedRequest
    }
}
catch {
    $reasonCode = if ($_.Exception.Data.Contains('ReasonCode')) {
        [string] $_.Exception.Data['ReasonCode']
    }
    else {
        'REQUEST.UNREADABLE'
    }
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'RequestValidation' -State 'Failed' -MessageId 'request.validation.failed')
    Write-ContractRecord (New-TerminalRecord -ReasonCode $reasonCode -Phase 'RequestValidation')
    exit 20
}
Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'RequestValidation' -State 'Succeeded' -MessageId 'request.validation.succeeded')

$usingRuntimeFixture = -not [string]::IsNullOrWhiteSpace($RuntimeFixturePath)
$runtimeFacts = if ($usingRuntimeFixture) {
    Read-RuntimeFixture -LiteralPath $RuntimeFixturePath
}
else {
    Get-ActiveRuntimeFacts
}

$applicationExitCode = Invoke-WinPCInfoLaunch -Request $request -RuntimeFacts $runtimeFacts `
    -ValidationFixture $usingRuntimeFixture
exit $applicationExitCode
