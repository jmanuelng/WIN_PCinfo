function New-NormalizedRequest {
    param(
        [Parameter(Mandatory)] [string] $ContractVersion,
        [Parameter(Mandatory)] [string] $Profile,
        [Parameter(Mandatory)] [string] $NetworkMode,
        [Parameter(Mandatory)] [bool] $AcceptPreparation
    )

    [pscustomobject][ordered]@{
        contractVersion = $ContractVersion
        profile = $Profile
        networkMode = $NetworkMode
        acceptPreparation = $AcceptPreparation
    }
}

function Get-RequestDigest {
    param([Parameter(Mandatory)] $Request)

    $json = $Request | ConvertTo-Json -Compress -Depth 10
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
        [Parameter(Mandatory)] [string] $MessageId
    )

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.progress'
        contractVersion = '1.0.0'
        sequence = $Sequence
        phase = $Phase
        state = $State
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
    param([Parameter(Mandatory)] $Record)

    # Contract records use stdout directly so invoking the Engine from another
    # PowerShell function cannot accidentally capture progress as a return value.
    [System.Console]::Out.WriteLine(($Record | ConvertTo-Json -Compress -Depth 20))
}
