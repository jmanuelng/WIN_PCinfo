function New-NormalizedRequest {
    param(
        [Parameter(Mandatory)] [string] $ContractVersion,
        [Parameter(Mandatory)] [string] $Profile,
        [Parameter(Mandatory)] [string] $OutputDestination,
        [Parameter(Mandatory)] [string] $NetworkBehavior,
        [Parameter(Mandatory)] [string] $UpdateChoice,
        [Parameter(Mandatory)] [string] $DiagnosticLevel,
        [Parameter(Mandatory)] $AutomationChoices
    )

    [pscustomobject][ordered]@{
        contractVersion = $ContractVersion
        profile = $Profile
        outputDestination = $OutputDestination
        networkBehavior = $NetworkBehavior
        updateChoice = $UpdateChoice
        diagnosticLevel = $DiagnosticLevel
        automationChoices = [pscustomobject][ordered]@{
            acceptPreparation = [bool] $AutomationChoices.acceptPreparation
            allowElevation = [bool] $AutomationChoices.allowElevation
            allowInstallation = [bool] $AutomationChoices.allowInstallation
            allowPersistentChanges = [bool] $AutomationChoices.allowPersistentChanges
            allowStaleRecovery = [bool] $AutomationChoices.allowStaleRecovery
        }
    }
}

function Write-BootstrapTerminal {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'RUNTIME.EDITION_UNSUPPORTED',
            'RUNTIME.MODULE_LOADING_INCOMPATIBLE',
            'RUNTIME.VALIDATOR_PROVENANCE_INVALID'
        )]
        [string] $ReasonCode
    )

    # The trusted JSON command is not available at this earliest failure seam.
    # This template contains only fixed public values, and ValidateSet prevents
    # machine- or caller-controlled text from entering JSON through replacement.
    $terminalTemplate = '{"recordType":"win-pcinfo.terminal","contractVersion":"1.0.0","outcome":"NotStarted","exitCode":20,"reasonCode":"__REASON__","phase":"RuntimeCompatibility","collectionStarted":false,"requestDigest":"","validationFixture":false,"cleanup":{"required":false,"verified":true},"guidance":{"microsoftUrl":"https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows","retryStep":"Install or select stable PowerShell 7.6 or later 7.x from Microsoft, then rerun the same WIN-PCInfo command."}}'
    [System.Console]::Out.WriteLine($terminalTemplate.Replace('__REASON__', $ReasonCode))
}

function Get-RequestDigest {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    $json = & $ConvertToJsonCommand -InputObject $Request -Compress -Depth 10
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha256.Dispose()
    }
}

function New-ProgressRecord {
    param(
        [Parameter(Mandatory)] [int] $Sequence,
        [Parameter()] [string] $Phase = 'RuntimeCompatibility',
        [Parameter(Mandatory)] [string] $State,
        [Parameter(Mandatory)] [string] $MessageId,
        [Parameter(Mandatory)] [int] $CompletedUnits,
        [Parameter(Mandatory)] [int] $TotalUnits
    )

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.progress'
        contractVersion = '1.0.0'
        sequence = $Sequence
        phase = $Phase
        state = $State
        time = [System.DateTimeOffset]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        completion = [pscustomobject][ordered]@{
            completedUnits = $CompletedUnits
            totalUnits = $TotalUnits
            unit = 'LaunchGate'
        }
        messageId = $MessageId
    }
}

function New-TerminalRecord {
    param(
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [AllowEmptyString()] [string] $RequestDigest = '',
        [Parameter()] [bool] $ValidationFixture = $false,
        [Parameter()] $RuntimeResult,
        [Parameter()] [string] $Phase
    )

    $runtimeEligible = $null -ne $RuntimeResult -and [bool] $RuntimeResult.Eligible
    $terminal = [ordered]@{
        recordType = 'win-pcinfo.terminal'
        contractVersion = '1.0.0'
        outcome = 'NotStarted'
        exitCode = 20
        reasonCode = $ReasonCode
        phase = if ($Phase) { $Phase } elseif ($runtimeEligible) { 'Preparation' } else { 'RuntimeCompatibility' }
        collectionStarted = $false
        requestDigest = $RequestDigest
        validationFixture = $ValidationFixture
        cleanup = [pscustomobject][ordered]@{
            required = $false
            verified = $true
        }
    }

    if ($null -ne $RuntimeResult) {
        $terminal.runtime = [pscustomobject][ordered]@{
            eligible = [bool] $RuntimeResult.Eligible
            reasonCode = [string] $RuntimeResult.ReasonCode
            policyId = [string] $RuntimeResult.PolicyId
        }
    }

    if ($null -ne $RuntimeResult -and -not $RuntimeResult.Eligible) {
        $terminal.guidance = [pscustomobject][ordered]@{
            microsoftUrl = 'https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows'
            retryStep = 'Install or select stable PowerShell 7.6 or later 7.x from Microsoft, then rerun the same WIN-PCInfo command.'
        }
    }

    [pscustomobject] $terminal
}

function Write-ContractRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    # Contract records use stdout directly so invoking the Engine from another
    # PowerShell function cannot accidentally capture progress as a return value.
    [System.Console]::Out.WriteLine((& $ConvertToJsonCommand -InputObject $Record -Compress -Depth 20))
}
