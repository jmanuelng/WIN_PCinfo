function Get-GuidedRequest {
    param(
        [Parameter()] [string] $RecipientProfilePath,
        [Parameter()] [string] $RecipientFingerprintConfirmation
    )

    $hasProfile = -not [string]::IsNullOrWhiteSpace($RecipientProfilePath)
    $hasConfirmation = -not [string]::IsNullOrWhiteSpace($RecipientFingerprintConfirmation)
    if ($hasProfile -ne $hasConfirmation -or
        ($hasProfile -and (Test-NetworkPathSyntax -Path $RecipientProfilePath)) -or
        ($hasConfirmation -and
            $RecipientFingerprintConfirmation.Replace(':', '').Replace(' ', '') `
                -notmatch '^[0-9A-Fa-f]{64}$')) {
        $exception = [System.ArgumentException]::new(
            'Guided recipient selection requires one local profile and its confirmed fingerprint.'
        )
        $exception.Data['ReasonCode'] = 'REQUEST.RECIPIENT_SELECTION_INVALID'
        throw $exception
    }
    $recipientSelection = if ($hasProfile) {
        [pscustomobject][ordered]@{
            mode = 'Profile'; profilePath = $RecipientProfilePath
            fingerprintConfirmation = $RecipientFingerprintConfirmation
        }
    }
    else {
        [pscustomobject][ordered]@{
            mode = 'None'; profilePath = $null; fingerprintConfirmation = $null
        }
    }
    $automationChoices = [pscustomobject]@{
        allowAssessmentNetwork = $false
        allowElevation = $true
        allowInstallation = $false
        allowPersistentChanges = $false
        allowStaleRecovery = $false
        verificationOverride = 'None'
    }
    New-NormalizedRequest -ContractVersion '1.0.0' `
        -Profile 'ComprehensiveLocalAssessment' `
        -OutputDestination './WIN-PCInfo-Results' `
        -NetworkBehavior 'LocalOnly' `
        -UpdateChoice 'NoUpdateCheck' `
        -DiagnosticLevel 'Standard' `
        -AutomationChoices $automationChoices `
        -RecipientSelection $recipientSelection
}

function Get-AutomationRequest {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    $requestText = [System.IO.File]::ReadAllText(
        [System.IO.Path]::GetFullPath($LiteralPath),
        [System.Text.UTF8Encoding]::new($false, $true)
    )
    try {
        $inputRequest = & $ConvertFromJsonCommand -InputObject $requestText -ErrorAction Stop
    }
    catch {
        $exception = [System.ArgumentException]::new('The automation request is not valid JSON.')
        $exception.Data['ReasonCode'] = 'REQUEST.JSON_INVALID'
        throw $exception
    }

    $requiredFields = @(
        'contractVersion', 'profile', 'outputDestination', 'networkBehavior',
        'updateChoice', 'diagnosticLevel', 'automationChoices'
    )
    $allowedFields = @($requiredFields) + @('recipientSelection')
    $actualFields = @($inputRequest.PSObject.Properties.Name)
    $unknownFields = @($actualFields | Where-Object { $_ -notin $allowedFields })
    if ($unknownFields.Count -gt 0) {
        # Unknown input could represent a safety control introduced by a newer
        # caller. Ignoring it would let automation believe a constraint applied
        # when the current application never enforced it, so the request fails.
        $exception = [System.ArgumentException]::new('The automation request contains an unknown field.')
        $exception.Data['ReasonCode'] = 'REQUEST.UNKNOWN_FIELD'
        throw $exception
    }

    $missingFields = @($requiredFields | Where-Object { $_ -notin $actualFields })
    if ($missingFields.Count -gt 0) {
        $exception = [System.ArgumentException]::new('The automation request is missing a required field.')
        $exception.Data['ReasonCode'] = 'REQUEST.REQUIRED_FIELD_MISSING'
        throw $exception
    }

    $stringFields = @(
        'contractVersion', 'profile', 'outputDestination', 'networkBehavior',
        'updateChoice', 'diagnosticLevel'
    )
    if (@($stringFields | Where-Object { $inputRequest.$_ -isnot [string] }).Count -gt 0 -or
        $inputRequest.automationChoices -isnot [pscustomobject] -or
        ('recipientSelection' -in $actualFields -and
            $inputRequest.recipientSelection -isnot [pscustomobject])) {
        $exception = [System.ArgumentException]::new('The automation request contains a field with an invalid type.')
        $exception.Data['ReasonCode'] = 'REQUEST.FIELD_TYPE_INVALID'
        throw $exception
    }

    if ([string] $inputRequest.contractVersion -ne '1.0.0') {
        $exception = [System.ArgumentException]::new('The automation request contract version is unsupported.')
        $exception.Data['ReasonCode'] = 'REQUEST.CONTRACT_VERSION_UNSUPPORTED'
        throw $exception
    }
    if ([string] $inputRequest.profile -ne 'ComprehensiveLocalAssessment') {
        $exception = [System.ArgumentException]::new('The requested assessment profile is unsupported.')
        $exception.Data['ReasonCode'] = 'REQUEST.PROFILE_UNSUPPORTED'
        throw $exception
    }
    if ([string]::IsNullOrWhiteSpace([string] $inputRequest.outputDestination)) {
        $exception = [System.ArgumentException]::new('The requested output destination is invalid.')
        $exception.Data['ReasonCode'] = 'REQUEST.OUTPUT_DESTINATION_INVALID'
        throw $exception
    }
    if ([string] $inputRequest.networkBehavior -notin @('LocalOnly', 'MicrosoftConnectivityEnabled')) {
        $exception = [System.ArgumentException]::new('The requested network mode is unsupported.')
        $exception.Data['ReasonCode'] = 'REQUEST.NETWORK_MODE_UNSUPPORTED'
        throw $exception
    }
    if ([string] $inputRequest.updateChoice -ne 'NoUpdateCheck') {
        $exception = [System.ArgumentException]::new('The requested update choice is unsupported.')
        $exception.Data['ReasonCode'] = 'REQUEST.UPDATE_CHOICE_UNSUPPORTED'
        throw $exception
    }
    if ([string] $inputRequest.diagnosticLevel -ne 'Standard') {
        $exception = [System.ArgumentException]::new('The requested diagnostic level is unsupported.')
        $exception.Data['ReasonCode'] = 'REQUEST.DIAGNOSTIC_LEVEL_UNSUPPORTED'
        throw $exception
    }

    $automationFields = @(
        'allowAssessmentNetwork', 'allowElevation', 'allowInstallation',
        'allowPersistentChanges', 'allowStaleRecovery', 'verificationOverride'
    )
    $actualAutomationFields = @($inputRequest.automationChoices.PSObject.Properties.Name)
    if (@($actualAutomationFields | Where-Object { $_ -notin $automationFields }).Count -gt 0) {
        $exception = [System.ArgumentException]::new('The automation choices contain an unknown field.')
        $exception.Data['ReasonCode'] = 'REQUEST.UNKNOWN_FIELD'
        throw $exception
    }
    if (@($automationFields | Where-Object { $_ -notin $actualAutomationFields }).Count -gt 0) {
        $exception = [System.ArgumentException]::new('The automation choices are incomplete.')
        $exception.Data['ReasonCode'] = 'REQUEST.REQUIRED_FIELD_MISSING'
        throw $exception
    }
    $booleanAutomationFields = @(
        'allowAssessmentNetwork', 'allowElevation', 'allowInstallation',
        'allowPersistentChanges', 'allowStaleRecovery'
    )
    if (@($booleanAutomationFields | Where-Object { $inputRequest.automationChoices.$_ -isnot [bool] }).Count -gt 0) {
        $exception = [System.ArgumentException]::new('Automation choices must be true or false.')
        $exception.Data['ReasonCode'] = 'REQUEST.FIELD_TYPE_INVALID'
        throw $exception
    }
    if (Test-NetworkPathSyntax -Path $inputRequest.outputDestination) {
        # Reject UNC syntax using only request text. This occurs before any path,
        # drive, provider, or free-space lookup, preserving Local Only even when
        # an automation caller supplies a remote output location.
        $exception = [System.ArgumentException]::new('A network output destination is not supported.')
        $exception.Data['ReasonCode'] = 'REQUEST.OUTPUT_DESTINATION_NETWORK_UNSUPPORTED'
        throw $exception
    }
    if ($inputRequest.automationChoices.verificationOverride -isnot [string]) {
        $exception = [System.ArgumentException]::new('The verification override must be a string.')
        $exception.Data['ReasonCode'] = 'REQUEST.FIELD_TYPE_INVALID'
        throw $exception
    }
    if ([string] $inputRequest.automationChoices.verificationOverride -ne 'None') {
        $exception = [System.ArgumentException]::new('The requested verification override is unsupported.')
        $exception.Data['ReasonCode'] = 'REQUEST.VERIFICATION_OVERRIDE_UNSUPPORTED'
        throw $exception
    }
    $networkAllowed = [bool] $inputRequest.automationChoices.allowAssessmentNetwork
    if (($inputRequest.networkBehavior -eq 'LocalOnly' -and $networkAllowed) -or
        ($inputRequest.networkBehavior -eq 'MicrosoftConnectivityEnabled' -and -not $networkAllowed)) {
        $exception = [System.ArgumentException]::new('The network behavior conflicts with the automation authority envelope.')
        $exception.Data['ReasonCode'] = 'REQUEST.NETWORK_CONFLICT'
        throw $exception
    }
    if (-not [bool] $inputRequest.automationChoices.allowElevation -or
        [bool] $inputRequest.automationChoices.allowInstallation -or
        [bool] $inputRequest.automationChoices.allowPersistentChanges) {
        $exception = [System.ArgumentException]::new('The authority choices conflict with this fixed assessment profile.')
        $exception.Data['ReasonCode'] = 'REQUEST.AUTHORITY_CONFLICT'
        throw $exception
    }
    $recipientSelection = if ('recipientSelection' -notin $actualFields) {
        [pscustomobject][ordered]@{
            mode = 'None'; profilePath = $null; fingerprintConfirmation = $null
        }
    }
    else { $inputRequest.recipientSelection }
    $recipientFields = @('mode', 'profilePath', 'fingerprintConfirmation')
    $actualRecipientFields = @($recipientSelection.PSObject.Properties.Name)
    if (@($actualRecipientFields | Where-Object { $_ -notin $recipientFields }).Count -gt 0 -or
        @($recipientFields | Where-Object { $_ -notin $actualRecipientFields }).Count -gt 0 -or
        $recipientSelection.mode -isnot [string] -or
        [string] $recipientSelection.mode -notin @('None', 'Profile')) {
        $exception = [System.ArgumentException]::new('The recipient selection is invalid.')
        $exception.Data['ReasonCode'] = 'REQUEST.RECIPIENT_SELECTION_INVALID'
        throw $exception
    }
    if ($recipientSelection.mode -eq 'None') {
        if ($null -ne $recipientSelection.profilePath -or
            $null -ne $recipientSelection.fingerprintConfirmation) {
            $exception = [System.ArgumentException]::new('A zero-recipient request cannot carry recipient data.')
            $exception.Data['ReasonCode'] = 'REQUEST.RECIPIENT_SELECTION_INVALID'
            throw $exception
        }
    }
    elseif ($recipientSelection.profilePath -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string] $recipientSelection.profilePath) -or
        (Test-NetworkPathSyntax -Path ([string] $recipientSelection.profilePath)) -or
        $recipientSelection.fingerprintConfirmation -isnot [string] -or
        ([string] $recipientSelection.fingerprintConfirmation).Replace(':', '').Replace(' ', '') `
            -notmatch '^[0-9A-Fa-f]{64}$') {
        $exception = [System.ArgumentException]::new('The selected Recipient Profile input is invalid.')
        $exception.Data['ReasonCode'] = 'REQUEST.RECIPIENT_SELECTION_INVALID'
        throw $exception
    }
    New-NormalizedRequest -ContractVersion $inputRequest.contractVersion `
        -Profile $inputRequest.profile `
        -OutputDestination $inputRequest.outputDestination `
        -NetworkBehavior $inputRequest.networkBehavior `
        -UpdateChoice $inputRequest.updateChoice `
        -DiagnosticLevel $inputRequest.diagnosticLevel `
        -AutomationChoices $inputRequest.automationChoices `
        -RecipientSelection $recipientSelection
}
