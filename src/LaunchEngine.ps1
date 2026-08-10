function Invoke-WinPCInfoLaunch {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $RuntimeFacts,
        [Parameter(Mandatory)] [bool] $ValidationFixture,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    $requestDigest = Get-RequestDigest -Request $Request -ConvertToJsonCommand $ConvertToJsonCommand
    Write-ContractRecord (New-ProgressRecord -Sequence 3 -State 'Started' -MessageId 'runtime.check.started' `
        -CompletedUnits 1 -TotalUnits 2) -ConvertToJsonCommand $ConvertToJsonCommand

    $runtime = Test-RuntimeCompatibility -Facts $RuntimeFacts
    if (-not $runtime.Eligible) {
        Write-ContractRecord (New-ProgressRecord -Sequence 4 -State 'Failed' -MessageId 'runtime.check.failed' `
            -CompletedUnits 1 -TotalUnits 2) -ConvertToJsonCommand $ConvertToJsonCommand
        Write-ContractRecord (New-TerminalRecord -ReasonCode $runtime.ReasonCode -RequestDigest $requestDigest `
            -ValidationFixture $ValidationFixture -RuntimeResult $runtime) -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    Write-ContractRecord (New-ProgressRecord -Sequence 4 -State 'Succeeded' -MessageId 'runtime.check.succeeded' `
        -CompletedUnits 2 -TotalUnits 2) -ConvertToJsonCommand $ConvertToJsonCommand
    Write-ContractRecord (New-TerminalRecord -ReasonCode 'SLICE.COLLECTION_NOT_IMPLEMENTED' -RequestDigest $requestDigest `
        -ValidationFixture $ValidationFixture -RuntimeResult $runtime) -ConvertToJsonCommand $ConvertToJsonCommand
    return 20
}
