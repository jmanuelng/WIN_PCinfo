if ($PSVersionTable.PSEdition -ne 'Core') {
    # Windows PowerShell cannot be trusted to provide the v2 JSON/validator
    # stack. Emit only this fixed public contract record; no ambient serializer,
    # profile function, collection, or relaunch is permitted on the wrong host.
    Write-BootstrapTerminal -ReasonCode 'RUNTIME.EDITION_UNSUPPORTED'
    exit 20
}

$moduleFacts = Get-BuiltInModuleCompatibilityFacts
if (-not $moduleFacts.contractCommandProvenance) {
    # A structured failure must not invoke an ambient JSON command after the
    # trusted serializer boundary fails. This literal contains only fixed public
    # contract values; it cannot include request or machine-controlled text.
    $bootstrapReason = if ($moduleFacts.moduleLoading) {
        'RUNTIME.VALIDATOR_PROVENANCE_INVALID'
    }
    else {
        'RUNTIME.MODULE_LOADING_INCOMPATIBLE'
    }
    Write-BootstrapTerminal -ReasonCode $bootstrapReason
    exit 20
}
$convertToJsonCommand = $moduleFacts.convertToJsonCommand
$convertFromJsonCommand = $moduleFacts.convertFromJsonCommand
$artifactTrustValid = Test-ApplicationArtifactTrust -LiteralPath $PSCommandPath `
    -AuthenticodeCommand $moduleFacts.authenticodeCommand

if ($Workflow -ne 'Assessment') {
    $workflowRuntime = Test-RuntimeCompatibility -Facts (
        Get-ActiveRuntimeFacts -ModuleFacts $moduleFacts
    )
    if (-not $workflowRuntime.Eligible -or -not $artifactTrustValid) {
        $reason = if (-not $workflowRuntime.Eligible) {
            [string] $workflowRuntime.ReasonCode
        }
        else { 'PREPARATION.INTEGRITY_FAILED' }
        Write-ContractRecord (New-TerminalRecord -ReasonCode $reason `
            -RuntimeResult $workflowRuntime -Phase $Workflow) `
            -ConvertToJsonCommand $convertToJsonCommand
        exit 20
    }
    if ($Workflow -eq 'RecipientProfileSetup') {
        $workflowResult = if ([string]::IsNullOrWhiteSpace($RecipientLabel) -or
            [string]::IsNullOrWhiteSpace($RecipientProfileOutputPath)) {
            [pscustomobject][ordered]@{
                state = 'NotStarted'; reasonCode = 'RECIPIENT.SETUP_INPUT_INVALID'
                profilePath = $null; fingerprint = $null; protectionLevel = $null
                syntheticRoundTripVerified = $false
            }
        }
        else {
            New-RecipientProfileSetup -Label $RecipientLabel `
                -OutputPath $RecipientProfileOutputPath `
                -ConfirmSetup:$ConfirmRecipientSetup
        }
        Write-ContractRecord ([pscustomobject][ordered]@{
            recordType = 'win-pcinfo.recipient-profile-setup'
            contractVersion = '1.0.0'
            state = $workflowResult.state
            reasonCode = $workflowResult.reasonCode
            profilePath = $workflowResult.profilePath
            fingerprint = $workflowResult.fingerprint
            protectionLevel = $workflowResult.protectionLevel
            syntheticRoundTripVerified = $workflowResult.syntheticRoundTripVerified
            privateKeyExported = $false
        }) -ConvertToJsonCommand $convertToJsonCommand
        $terminal = New-TerminalRecord -ReasonCode $workflowResult.reasonCode `
            -RuntimeResult $workflowRuntime -Phase RecipientProfileSetup
        $exitCode = 20
        if ($workflowResult.state -eq 'Created') {
            $terminal.outcome = 'Completed'; $terminal.exitCode = 0; $exitCode = 0
        }
        elseif ($workflowResult.state -eq 'CleanupIncomplete') {
            $terminal.outcome = 'CleanupIncomplete'; $terminal.exitCode = 60
            $terminal.cleanup.required = $true; $terminal.cleanup.verified = $false
            $exitCode = 60
        }
        Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
        exit $exitCode
    }
    $workflowResult = if ([string]::IsNullOrWhiteSpace($ProtectedPackagePath) -or
        [string]::IsNullOrWhiteSpace($RestrictedReportOutputPath) -or
        $null -eq $RestrictedReportWarningAcknowledgment) {
        [pscustomobject][ordered]@{
            state = 'NotStarted'; reasonCode = 'EXPORT.INPUT_INVALID'
            reportPath = $null; restrictedDiagnosticEvidence = $true
            publiclyShareable = $false; cleanupVerified = $true
        }
    }
    else {
        Export-RestrictedAssessmentReport `
            -PackagePath $ProtectedPackagePath -OutputPath $RestrictedReportOutputPath `
            -WarningAcknowledgment $RestrictedReportWarningAcknowledgment
    }
    Write-ContractRecord ([pscustomobject][ordered]@{
        recordType = 'win-pcinfo.restricted-report-export'
        contractVersion = '1.0.0'
        state = $workflowResult.state
        reasonCode = $workflowResult.reasonCode
        reportPath = $workflowResult.reportPath
        restrictedDiagnosticEvidence = $true
        publiclyShareable = $false
        cleanupVerified = $workflowResult.cleanupVerified
    }) -ConvertToJsonCommand $convertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode $workflowResult.reasonCode `
        -RuntimeResult $workflowRuntime -Phase RestrictedReportExport
    $exitCode = 20
    if ($workflowResult.state -eq 'Exported') {
        $terminal.outcome = 'Completed'; $terminal.exitCode = 0; $exitCode = 0
    }
    elseif ($workflowResult.state -eq 'IntegrityFailed') {
        $terminal.outcome = 'IntegrityFailed'; $terminal.exitCode = 50; $exitCode = 50
    }
    elseif ($workflowResult.state -eq 'CleanupIncomplete') {
        $terminal.outcome = 'CleanupIncomplete'; $terminal.exitCode = 60
        $terminal.cleanup.required = $true; $terminal.cleanup.verified = $false
        $exitCode = 60
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit $exitCode
}

Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'RequestValidation' -State 'Started' `
    -MessageId 'request.validation.started' -CompletedUnits 0 -TotalUnits 2) `
    -ConvertToJsonCommand $convertToJsonCommand
try {
    $request = if ($Mode -eq 'Automation') {
        if (-not [string]::IsNullOrWhiteSpace($AssessmentRecipientProfilePath) -or
            -not [string]::IsNullOrWhiteSpace($AssessmentRecipientFingerprintConfirmation)) {
            $exception = [System.ArgumentException]::new(
                'Guided recipient parameters cannot modify an automation request.'
            )
            $exception.Data['ReasonCode'] = 'REQUEST.RECIPIENT_SELECTION_INVALID'
            throw $exception
        }
        if ([string]::IsNullOrWhiteSpace($RequestPath)) {
            $exception = [System.ArgumentException]::new('Automation mode requires -RequestPath.')
            $exception.Data['ReasonCode'] = 'REQUEST.PATH_REQUIRED'
            throw $exception
        }
        Get-AutomationRequest -LiteralPath $RequestPath -ConvertFromJsonCommand $convertFromJsonCommand
    }
    else {
        Get-GuidedRequest -RecipientProfilePath $AssessmentRecipientProfilePath `
            -RecipientFingerprintConfirmation $AssessmentRecipientFingerprintConfirmation
    }
}
catch {
    $reasonCode = if ($_.Exception.Data.Contains('ReasonCode')) {
        [string] $_.Exception.Data['ReasonCode']
    }
    else {
        'REQUEST.UNREADABLE'
    }
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'RequestValidation' -State 'Failed' `
        -MessageId 'request.validation.failed' -CompletedUnits 0 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord (New-TerminalRecord -ReasonCode $reasonCode -Phase 'RequestValidation') `
        -ConvertToJsonCommand $convertToJsonCommand
    exit 20
}
Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'RequestValidation' -State 'Succeeded' `
    -MessageId 'request.validation.succeeded' -CompletedUnits 1 -TotalUnits 2) `
    -ConvertToJsonCommand $convertToJsonCommand

$usingRuntimeFixture = -not [string]::IsNullOrWhiteSpace($RuntimeFixturePath)
$runtimeFacts = if ($usingRuntimeFixture) {
    Read-RuntimeFixture -LiteralPath $RuntimeFixturePath -ConvertFromJsonCommand $convertFromJsonCommand
}
else {
    Get-ActiveRuntimeFacts -ModuleFacts $moduleFacts
}

$usingPreparationFixture = -not [string]::IsNullOrWhiteSpace($PreparationFixturePath)
$usingContractFixture = -not [string]::IsNullOrWhiteSpace($ContractFixturePath)
$usingRunFixture = -not [string]::IsNullOrWhiteSpace($RunFixturePath)
$usingPrivilegedCollectionFixture = -not [string]::IsNullOrWhiteSpace($PrivilegedCollectionFixturePath)
$usingSystemCollectionFixture = -not [string]::IsNullOrWhiteSpace($SystemCollectionFixturePath)
$usingEvidenceWorkspaceFixture = -not [string]::IsNullOrWhiteSpace($EvidenceWorkspaceFixturePath)
$usingProtectedPackageFixture = -not [string]::IsNullOrWhiteSpace($ProtectedPackageFixturePath)
$usingRecipientSharingFixture = -not [string]::IsNullOrWhiteSpace($RecipientSharingFixturePath)
$validationContext = [pscustomobject][ordered]@{
    PreparationFixturePath = $PreparationFixturePath
    ContractFixturePath = $ContractFixturePath
    RunFixturePath = $RunFixturePath
    PrivilegedCollectionFixturePath = $PrivilegedCollectionFixturePath
    SystemCollectionFixturePath = $SystemCollectionFixturePath
    EvidenceWorkspaceFixturePath = $EvidenceWorkspaceFixturePath
    ProtectedPackageFixturePath = $ProtectedPackageFixturePath
    RecipientSharingFixturePath = $RecipientSharingFixturePath
    IsFixture = ($usingRuntimeFixture -or $usingPreparationFixture -or
        $usingContractFixture -or $usingRunFixture -or $usingPrivilegedCollectionFixture -or
        $usingSystemCollectionFixture -or $usingEvidenceWorkspaceFixture -or
        $usingProtectedPackageFixture -or $usingRecipientSharingFixture)
}
$applicationExitCode = Invoke-WinPCInfoLaunch -Request $request -RuntimeFacts $runtimeFacts `
    -Mode $Mode -AcceptPreparation:$AcceptPreparation -ValidationContext $validationContext `
    -ArtifactTrustValid $artifactTrustValid `
    -ConvertFromJsonCommand $convertFromJsonCommand -ConvertToJsonCommand $convertToJsonCommand `
    -TestJsonCommand $moduleFacts.testJsonCommand
exit $applicationExitCode
