function Invoke-WinPCInfoLaunch {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $RuntimeFacts,
        [Parameter(Mandatory)] [bool] $ArtifactTrustValid,
        [Parameter(Mandatory)] [ValidateSet('Guided', 'Automation')] [string] $Mode,
        [Parameter(Mandatory)] [bool] $AcceptPreparation,
        [Parameter()] [AllowEmptyString()] [string] $PreparationFixturePath,
        [Parameter()] [AllowEmptyString()] [string] $ContractFixturePath,
        [Parameter()] [AllowEmptyString()] [string] $RunFixturePath,
        [Parameter(Mandatory)] [bool] $ValidationFixture,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand,
        [Parameter(Mandatory)] $TestJsonCommand
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
    Invoke-PreparationGate -Request $Request -RuntimeResult $runtime `
        -ArtifactTrustValid $ArtifactTrustValid `
        -Mode $Mode -AcceptPreparation $AcceptPreparation -PreparationFixturePath $PreparationFixturePath `
        -ContractFixturePath $ContractFixturePath -RunFixturePath $RunFixturePath `
        -ValidationFixture $ValidationFixture -ConvertFromJsonCommand $ConvertFromJsonCommand `
        -ConvertToJsonCommand $ConvertToJsonCommand -TestJsonCommand $TestJsonCommand
}
