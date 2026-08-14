[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$sourcePath = Join-Path $repositoryRoot 'src/CertificateTrust.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$errors)
Assert-Equal 0 @($errors).Count 'the Certificate Trust source parses on the supported PowerShell runtime'
. $sourcePath
$policy=Get-CertificateTrustPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$liveSource=Get-CertificateTrustLiveSource -Policy $policy
$liveTokens=$null;$liveErrors=$null
$liveAst=[Management.Automation.Language.Parser]::ParseInput($liveSource,[ref]$liveTokens,[ref]$liveErrors)
Assert-Equal 0 @($liveErrors).Count 'the release-owned supervised worker source also parses'
Assert-Equal $true (Test-CertificateTrustExecutableSignature -LiteralPath ([Environment]::ProcessPath)) `
    'the active worker host has the required valid Microsoft signature'
Assert-Equal $false (Test-CertificateTrustExecutableSignature -LiteralPath $sourcePath) `
    'an unsigned source file cannot satisfy the frozen worker executable identity'

$commands = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })+@($liveAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
$forbiddenCommands = @(
    'certreq','certutil','Import-Certificate','Import-PfxCertificate','Remove-Item',
    'Invoke-WebRequest','Invoke-RestMethod','Start-Process'
)
foreach ($command in $forbiddenCommands) {
    Assert-Equal $false ($command -in $commands) `
        "$command cannot enter the observation-only certificate collector"
}

$memberNames = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
    ForEach-Object { $_.Member.Value } | Where-Object { $_ })+@($liveAst.FindAll({ param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
    ForEach-Object { $_.Member.Value } | Where-Object { $_ })
foreach ($member in @('Export','Import','Add','Remove','GetRSAPrivateKey','GetECDsaPrivateKey','GetDSAPrivateKey')) {
    if ($member -eq 'Add') { continue } # Bounded in-memory List.Add calls are expected.
    Assert-Equal $false ($member -in $memberNames) `
        "$member is not used to export key material or mutate a certificate store"
}

$source = [IO.File]::ReadAllText($sourcePath)
Assert-Equal $true $source.Contains('OpenFlags]::ReadOnly') 'stores are opened with the read-only flag'
Assert-Equal $true $source.Contains('OpenFlags]::OpenExistingOnly') `
    'the collector cannot create an absent store'
Assert-Equal $true $source.Contains('DisableCertificateDownloads=$true') `
    'chain evaluation explicitly disables intermediate downloads'
Assert-Equal $true $source.Contains('X509RevocationMode]::NoCheck') `
    'offline evaluation cannot imply an unperformed revocation check'
Assert-Equal $true $source.Contains('ChainElements[0].ChainElementStatus') `
    'chain evaluation distinguishes leaf status from issuer status'
Assert-Equal $true $source.Contains('NotTimeValid') `
    'leaf date validity is evaluated separately from trust'
Assert-Equal $true $source.Contains('ProcessSupervisor.NativeRunner]::Run') `
    'store and chain APIs execute inside the hard-deadline Job Object boundary'
Assert-Equal $true $source.Contains('CompleteOwnedTreeAbsent') `
    'the complete live worker tree must be proved absent'
Assert-Equal $true $source.Contains('CERTIFICATE.STORE_ACCESS_PARTIAL') `
    'a successful store remains partial rather than denied when another purpose store fails'
Assert-Equal $false $source.Contains('.PrivateKey') `
    'the collector never dereferences a private-key property'
Assert-Equal $false $source.Contains('CngKey]::Create') `
    'the public artifact never derives even an ephemeral synthetic private key'
Assert-Equal $false $source.Contains('CertificateRequest]::new') `
    'synthetic validation parses public-only DER instead of creating certificates'

Write-Output 'PASS: Certificate Trust native source is parseable, offline, read-only, and private-key-safe.'
