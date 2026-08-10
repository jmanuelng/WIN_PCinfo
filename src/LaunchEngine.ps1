function Invoke-WinPCInfoLaunch {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $RuntimeFacts,
        [Parameter(Mandatory)] [ValidateSet('Guided', 'Automation')] [string] $Mode,
        [Parameter(Mandatory)] [bool] $AcceptPreparation,
        [Parameter()] [AllowEmptyString()] [string] $PreparationFixturePath,
        [Parameter(Mandatory)] [bool] $ValidationFixture,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
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
    Invoke-PreparationGate -Request $Request -RuntimeFacts $RuntimeFacts -RuntimeResult $runtime `
        -Mode $Mode -AcceptPreparation $AcceptPreparation -PreparationFixturePath $PreparationFixturePath `
        -ValidationFixture $ValidationFixture -ConvertFromJsonCommand $ConvertFromJsonCommand `
        -ConvertToJsonCommand $ConvertToJsonCommand
}
