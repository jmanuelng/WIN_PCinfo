function Invoke-WinPCInfoLaunch {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $RuntimeFacts,
        [Parameter(Mandatory)] [bool] $ValidationFixture
    )

    $requestDigest = Get-RequestDigest -Request $Request
    Write-ContractRecord (New-ProgressRecord -Sequence 3 -State 'Started' -MessageId 'runtime.check.started' `
        -CompletedUnits 1 -TotalUnits 2)

    $runtime = Test-RuntimeCompatibility -Facts $RuntimeFacts
    if (-not $runtime.Eligible) {
        Write-ContractRecord (New-ProgressRecord -Sequence 4 -State 'Failed' -MessageId 'runtime.check.failed' `
            -CompletedUnits 1 -TotalUnits 2)
        Write-ContractRecord (New-TerminalRecord -ReasonCode $runtime.ReasonCode -RequestDigest $requestDigest `
            -ValidationFixture $ValidationFixture -RuntimeResult $runtime)
        return 20
    }

    Write-ContractRecord (New-ProgressRecord -Sequence 4 -State 'Succeeded' -MessageId 'runtime.check.succeeded' `
        -CompletedUnits 2 -TotalUnits 2)
    Write-ContractRecord (New-TerminalRecord -ReasonCode 'SLICE.COLLECTION_NOT_IMPLEMENTED' -RequestDigest $requestDigest `
        -ValidationFixture $ValidationFixture -RuntimeResult $runtime)
    return 20
}
