[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')
. (Join-Path $repositoryRoot 'src/ProtectedPackage.ps1')
. (Join-Path $repositoryRoot 'src/RecipientSharing.ps1')
$root = Join-Path $repositoryRoot ('.test-output/recipient-repeat-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$profilePath = Join-Path $root 'synthetic.recipient.json'
$script:identityCreationAttempts = 0
function New-WindowsRecipientCertificate {
    param([int] $KeyBits)
    $script:identityCreationAttempts++
    throw 'Synthetic OS adapter: no persistent identity may be created.'
}
try {
    $initial = New-RecipientProfileSetup -Label 'Synthetic recipient' -OutputPath $profilePath `
        -ConfirmSetup -SyntheticProtectionLevel WindowsUserBound
    Assert-Equal 'Created' $initial.state 'the existing synthetic setup path remains usable'
    $digest = (Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash
    $repeated = New-RecipientProfileSetup -Label 'Synthetic recipient' -OutputPath $profilePath -ConfirmSetup
    Assert-Equal 0 $script:identityCreationAttempts 'repeated setup refuses before creating another identity'
    Assert-Equal 'NotStarted' $repeated.state 'repeated setup preserves the existing recipient'
    Assert-Equal $digest (Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash `
        'repeated setup never overwrites the existing profile'
    $missingParent = New-RecipientProfileSetup -Label 'Synthetic recipient' `
        -OutputPath (Join-Path $root 'missing/profile.json') -ConfirmSetup
    Assert-Equal 0 $script:identityCreationAttempts 'an unusable destination creates no certificate or key'
    Assert-Equal 'NotStarted' $missingParent.state 'missing destinations fail before setup'
}
finally {
    $ownedRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
    if (-not [IO.Path]::GetFullPath($root).StartsWith($ownedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unsafe cleanup target.'
    }
    Remove-Item -LiteralPath $root -Recurse -Force
}
Write-Output 'PASS: repeated recipient setup preserves profiles without new identities.'
