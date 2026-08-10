function Get-GuidedRequest {
    New-NormalizedRequest -ContractVersion '1.0.0' `
        -Profile 'ComprehensiveLocalAssessment' `
        -NetworkMode 'LocalOnly' `
        -AcceptPreparation $false
}

function Get-AutomationRequest {
    param([Parameter(Mandatory)] [string] $LiteralPath)

    $requestText = [System.IO.File]::ReadAllText(
        [System.IO.Path]::GetFullPath($LiteralPath),
        [System.Text.UTF8Encoding]::new($false, $true)
    )
    try {
        $inputRequest = $requestText | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $exception = [System.ArgumentException]::new('The automation request is not valid JSON.')
        $exception.Data['ReasonCode'] = 'REQUEST.JSON_INVALID'
        throw $exception
    }

    $requiredFields = @('contractVersion', 'profile', 'networkMode', 'acceptPreparation')
    $actualFields = @($inputRequest.PSObject.Properties.Name)
    $unknownFields = @($actualFields | Where-Object { $_ -notin $requiredFields })
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
    if ([string] $inputRequest.networkMode -notin @('LocalOnly', 'MicrosoftConnectivityEnabled')) {
        $exception = [System.ArgumentException]::new('The requested network mode is unsupported.')
        $exception.Data['ReasonCode'] = 'REQUEST.NETWORK_MODE_UNSUPPORTED'
        throw $exception
    }
    if ($inputRequest.acceptPreparation -isnot [bool]) {
        $exception = [System.ArgumentException]::new('acceptPreparation must be true or false.')
        $exception.Data['ReasonCode'] = 'REQUEST.FIELD_TYPE_INVALID'
        throw $exception
    }

    New-NormalizedRequest -ContractVersion $inputRequest.contractVersion `
        -Profile $inputRequest.profile `
        -NetworkMode $inputRequest.networkMode `
        -AcceptPreparation $inputRequest.acceptPreparation
}
