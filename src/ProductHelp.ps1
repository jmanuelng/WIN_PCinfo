$script:GuidedRunwayPolicyBase64 = '__GUIDED_RUNWAY_POLICY_BASE64__'
$script:GuidedRunwayPolicyDigest = '__GUIDED_RUNWAY_POLICY_SHA256__'

function Get-ProductHelpSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-ProductHelpPolicy {
    # Help is public instructional discovery. The threat is not leaking a secret
    # from this module; it is teaching the wrong contract or fetching a live
    # page that could change after release. The mechanism is a release-owned
    # policy whose exact bytes are either read from the reviewed repository
    # path or substituted at build time. The trust assumption is that those
    # bytes were reviewed with the rest of the release. Safe failure is to
    # refuse Help rather than emit a guessed repository or feedback route.
    if ($script:GuidedRunwayPolicyBase64 -eq ('__GUIDED_RUNWAY_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-guided-runway.json'
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-ProductHelpSha256 $bytes
    }
    else {
        [byte[]] $bytes = [System.Convert]::FromBase64String($script:GuidedRunwayPolicyBase64)
        $expectedDigest = $script:GuidedRunwayPolicyDigest
    }
    if ((Get-ProductHelpSha256 $bytes) -ne $expectedDigest) {
        throw 'The Guided Runway content contract failed its embedded digest check.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $json | ConvertFrom-Json -Depth 20
}

function Get-ProductHelpRecord {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Help', 'About')]
        [string] $Surface
    )

    $policy = Get-ProductHelpPolicy
    $documents = [ordered]@{}
    foreach ($document in @($policy.documents)) {
        $documents[[string] $document.id] = [string] $document.path
    }

    [pscustomobject][ordered]@{
        recordType = [string] $policy.help.recordType
        contractVersion = '1.0.0'
        surface = $Surface
        productName = 'WIN-PCInfo'
        release = [string] $policy.release
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        collectionStarted = [bool] $policy.help.collectionStarted
        feedbackPrompted = [bool] $policy.help.feedbackPrompted
        networkRequested = [bool] $policy.help.networkRequested
        learningConsultingBoundary = $true
        maintenance = 'BestEffortNoSla'
        runway = @($policy.runway)
        documents = [pscustomobject] $documents
        discovery = [pscustomobject][ordered]@{
            repository = [string] $policy.discovery.repository
            feedback = [string] $policy.discovery.feedback
            contribution = [string] $policy.discovery.contribution
            vulnerabilityReporting = [string] $policy.discovery.vulnerabilityReporting
        }
        fieldValidation = [pscustomobject][ordered]@{
            automaticFromOrdinaryUse = [bool] $policy.fieldValidation.automaticFromOrdinaryUse
            requiresDeliberateConsent = [bool] $policy.fieldValidation.requiresDeliberateConsent
            consentPhrase = [string] $policy.fieldValidation.consentPhrase
            productWorkflowImplemented = [bool] $policy.fieldValidation.productWorkflowImplemented
        }
    }
}
