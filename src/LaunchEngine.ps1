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

    $definitionResult = Get-PreparationDefinition -ConvertFromJsonCommand $ConvertFromJsonCommand
    $preparationFacts = [pscustomobject]@{
        definitionIntegrityValid = $true
        criticalPrerequisitesAvailable = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($PreparationFixturePath)) {
        try {
            $preparationFacts = Read-PreparationFixture -LiteralPath $PreparationFixturePath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand
        }
        catch {
            $fixtureReason = if ($_.Exception.Data.Contains('ReasonCode')) {
                [string] $_.Exception.Data['ReasonCode']
            }
            else { 'PREPARATION.FIXTURE_INVALID' }
            Write-ContractRecord (New-TerminalRecord -ReasonCode $fixtureReason -RequestDigest $requestDigest `
                -ValidationFixture $true -RuntimeResult $runtime -Phase 'Preparation') `
                -ConvertToJsonCommand $ConvertToJsonCommand
            return 20
        }
    }

    # A fixture may only make integrity less trusted. It cannot make a corrupt
    # embedded definition valid or create a Verification Override for a digest,
    # manifest, signature, attestation, or governing-resource failure.
    if (-not $definitionResult.Valid -or -not $preparationFacts.definitionIntegrityValid) {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'PREPARATION.INTEGRITY_FAILED' `
            -RequestDigest $requestDigest -ValidationFixture $ValidationFixture -RuntimeResult $runtime `
            -Phase 'Preparation') -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $planResult = New-PreparationPlan -Request $Request -Definition $definitionResult.Definition `
        -ConvertToJsonCommand $ConvertToJsonCommand
    $summary = New-PreparationSummary -PlanResult $planResult `
        -CriticalPrerequisitesAvailable $preparationFacts.criticalPrerequisitesAvailable
    Write-ContractRecord $planResult.Plan -ConvertToJsonCommand $ConvertToJsonCommand
    Write-ContractRecord $summary -ConvertToJsonCommand $ConvertToJsonCommand

    if (-not $preparationFacts.criticalPrerequisitesAvailable) {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'PREPARATION.PREREQUISITE_UNRESOLVED' `
            -RequestDigest $requestDigest -ValidationFixture $ValidationFixture -RuntimeResult $runtime `
            -Phase 'Preparation' -PlanDigest $planResult.Digest -PreparationDecision 'Unavailable') `
            -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $accepted = if ($Mode -eq 'Automation') {
        $AcceptPreparation
    }
    else {
        [string]::Equals([System.Console]::In.ReadLine(), 'APPROVE', [System.StringComparison]::Ordinal)
    }
    $decision = if ($accepted) { 'Accepted' } else { 'Declined' }
    $reasonCode = if ($accepted -and $ValidationFixture) {
        # Synthetic runtime and preparation fixtures can prove plan resolution,
        # but must remain incapable of crossing into collectors when later
        # execution slices are added.
        'PREPARATION.VALIDATION_ONLY'
    }
    elseif ($accepted) {
        'SLICE.POST_APPROVAL_EXECUTION_NOT_IMPLEMENTED'
    }
    else { 'PREPARATION.DECLINED' }
    Write-ContractRecord (New-TerminalRecord -ReasonCode $reasonCode -RequestDigest $requestDigest `
        -ValidationFixture $ValidationFixture -RuntimeResult $runtime -Phase 'Preparation' `
        -PlanDigest $planResult.Digest -PreparationDecision $decision) `
        -ConvertToJsonCommand $ConvertToJsonCommand
    return 20
}
