[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'build/TextCanonicalization.ps1')
. (Join-Path $repositoryRoot 'build/DeterministicArchive.ps1')
. (Join-Path $repositoryRoot 'build/PortableDistribution.ps1')
. (Join-Path $repositoryRoot 'src/PortableDistribution.ps1')
$policy = Get-PortableDistributionPolicy -RepositoryRoot $repositoryRoot
$arguments = @{ RepositoryRoot = $repositoryRoot; Policy = $policy; BuildToolDigest = '0' * 64 }
$baseline = Get-PortableGoverningResources @arguments
$helper = @($baseline.Resources | Where-Object path -eq 'Start-WIN-PCInfo.ps1')[0]
$root = Join-Path $repositoryRoot ('.test-output/personal-signing-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$signedHelper = Join-Path $root 'Start-WIN-PCInfo.ps1'
# A synthetic trust adapter admits inert trailer bytes only inside this module
# test. Build.ps1 exposes no trust override and rejects this file in production.
$trailer = [Text.UTF8Encoding]::new($false).GetBytes(
    "`r`n# SIG # Begin signature block`r`n# U1lOVEhFVElD`r`n# SIG # End signature block`r`n")
[byte[]] $signedBytes = [byte[]]$helper.bytes + $trailer
[IO.File]::WriteAllBytes($signedHelper, $signedBytes)
try {
    $governing = Get-PortableGoverningResources @arguments -SignedHelperPath $signedHelper `
        -ReadSignature { param($Path) [pscustomobject]@{ Status = 'Valid'; SignerCertificate = 'Synthetic signing identity' } }
    $admitted = @($governing.Resources | Where-Object path -eq 'Start-WIN-PCInfo.ps1')[0]
    Assert-Equal (Get-PortableDistributionSha256 $signedBytes) $admitted.sha256 `
        'the candidate authenticates the exact signed helper, including its trailer'
    Assert-Equal $true ([Linq.Enumerable]::SequenceEqual[byte]($signedBytes, [byte[]]$admitted.bytes)) `
        'packaging never rewrites a signed executable'
    # Exercise the same package verification contract used by generated Verify.
    # The primary is inert synthetic data; no signed or trusted app is claimed.
    [byte[]] $primary = [Text.UTF8Encoding]::new($false).GetBytes('# SYNTHETIC inert primary')
    $null = New-PortableDistributionPackage -OutputDirectory $root -ApplicationBytes $primary `
        -ApplicationDigest (Get-PortableDistributionSha256 $primary) -Governing $governing `
        -BuildTool ([pscustomobject]@{ path = 'build/Build.ps1'; sha256 = '0' * 64 })
    [byte[]] $tableBytes = ConvertTo-DeterministicJsonBytes $governing.EmbeddedTable
    $script:PortableGoverningResourcesBase64 = [Convert]::ToBase64String($tableBytes)
    $script:PortableGoverningResourcesDigest = Get-PortableDistributionSha256 $tableBytes
    $packageRoot = Join-Path $root $policy.archiveRootName
    $verified = Test-PortableDistributionIntegrity -PackageRoot $packageRoot -ManifestPresence Required `
        -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
    Assert-Equal $true $verified.Valid 'the full package authenticates a fixed signed-helper resource'
    $packagedHelper = Join-Path $packageRoot 'Start-WIN-PCInfo.ps1'
    [IO.File]::AppendAllText($packagedHelper, '# changed')
    $changedPackage = Test-PortableDistributionIntegrity -PackageRoot $packageRoot -ManifestPresence Required `
        -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
    Assert-Equal $false $changedPackage.Valid 'changed signed helper bytes fail authenticated resource verification'
    foreach ($status in @('NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError')) {
        $rejected = $false
        try {
            $null = Get-PortableGoverningResources @arguments -SignedHelperPath $signedHelper `
                -ReadSignature { param($Path) [pscustomobject]@{ Status = $status; SignerCertificate = $null } }
        }
        catch { $rejected = $_.Exception.Message -eq 'Signed helper failed Authenticode admission.' }
        Assert-Equal $true $rejected "$status cannot enter a generated candidate"
    }
    [byte[]] $changed = [Text.UTF8Encoding]::new($false).GetBytes(
        ([Text.UTF8Encoding]::new($false).GetString($signedBytes)).Replace(
            'Set-StrictMode -Version Latest', 'Set-StrictMode -Version 2'))
    [IO.File]::WriteAllBytes($signedHelper, $changed)
    $rejected = $false
    try {
        $null = Get-PortableGoverningResources @arguments -SignedHelperPath $signedHelper `
            -ReadSignature { param($Path) [pscustomobject]@{ Status = 'Valid'; SignerCertificate = 'Synthetic identity' } }
    }
    catch { $rejected = $_.Exception.Message -eq 'Signed helper differs from the generated launcher for this build.' }
    Assert-Equal $true $rejected 'even trusted changed helper code is refused'
    [IO.File]::WriteAllBytes($signedHelper, $signedBytes)
    $rejected = $false
    try {
        $null = & (Join-Path $repositoryRoot 'build/Build.ps1') `
            -OutputPath (Join-Path $root 'rejected/WIN-PCInfo.ps1') -SignedHelperPath $signedHelper
    }
    catch { $rejected = $_.Exception.Message -eq 'Signed helper failed Authenticode admission.' }
    Assert-Equal $true $rejected 'the public build command cannot treat a synthetic signature as Windows trust'
    Assert-Equal $false ([IO.File]::Exists((Join-Path $root 'rejected/WIN-PCInfo.ps1'))) `
        'failed signed-helper admission writes no generated application'
}
finally {
    $ownedRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
    if (-not [IO.Path]::GetFullPath($root).StartsWith($ownedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unsafe cleanup target.'
    }
    Remove-Item -LiteralPath $root -Recurse -Force
}
Write-Output 'PASS: personal signing preparation binds the exact authenticated generated helper.'
