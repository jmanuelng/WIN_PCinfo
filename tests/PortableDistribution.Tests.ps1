[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'build/TextCanonicalization.ps1')

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Assert-True {
    param([bool] $Condition, [string] $Because)
    if (-not $Condition) { throw "Assertion failed: $Because" }
}

function Assert-NoRestrictedMaterial {
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [string] $Because)
    $needles = @(
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
        '(?i)\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+\\'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)\.terraform[/\\]'
        '(?i)AKIA[0-9A-Z]{16}'
        '(?i)clientSecret\s*[:=]\s*\S+'
    )
    foreach ($needle in $needles) {
        Assert-Equal $false ($Text -match $needle) "$Because must not contain restricted material matching $needle"
    }
}

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-portable-distribution.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/portable-distribution.schema.json'
Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'the portable distribution contract is release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the portable distribution contract has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the portable distribution contract satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20
Assert-Equal $false $policy.installsRuntime 'the portable package must not install a runtime'
Assert-Equal $true $policy.unsignedPrecursorOnly `
    'this slice records only unsigned precursor identities'

$workRoot = Join-Path $repositoryRoot '.test-output/portable-distribution'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force

function Copy-IndependentBuildTree {
    param([Parameter(Mandatory)] [string] $DestinationRoot)
    $null = New-Item -ItemType Directory -Path $DestinationRoot -Force
    foreach ($directory in @('build', 'src', 'schemas', 'docs')) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot $directory) `
            -Destination (Join-Path $DestinationRoot $directory) -Recurse
    }
    foreach ($file in @('SECURITY.md', 'CONTRIBUTING.md', 'README.md')) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot $file) `
            -Destination (Join-Path $DestinationRoot $file)
    }
}

$firstRoot = Join-Path $workRoot 'work-a'
$secondRoot = Join-Path $workRoot 'work-b'
Copy-IndependentBuildTree -DestinationRoot $firstRoot
Copy-IndependentBuildTree -DestinationRoot $secondRoot

$firstApp = Join-Path $firstRoot 'out/WIN-PCInfo.ps1'
$secondApp = Join-Path $secondRoot 'out/WIN-PCInfo.ps1'
$first = & (Join-Path $firstRoot 'build/Build.ps1') -OutputPath $firstApp
$second = & (Join-Path $secondRoot 'build/Build.ps1') -OutputPath $secondApp

Assert-Equal 'win-pcinfo.unsigned-generated-content-identity' `
    $first.generatedContentIdentity.kind 'the generated-content identity is a named precursor'
Assert-Equal 'win-pcinfo.unsigned-portable-package-identity' `
    $first.portablePackageIdentity.kind 'the portable-package identity is a named precursor'
Assert-Equal $true ($first.generatedContentIdentity.sha256 -match '^[0-9a-f]{64}$') `
    'the generated-content identity is an exact SHA-256 digest'
Assert-Equal $true ($first.portablePackageIdentity.sha256 -match '^[0-9a-f]{64}$') `
    'the portable-package identity is an exact SHA-256 digest'
Assert-Equal $first.sha256 $first.generatedContentIdentity.sha256 `
    'the existing application digest remains the generated-content identity'
Assert-Equal $false $first.portablePackage.installsRuntime `
    'build evidence states that the package installs no runtime'

$firstZipPath = Join-Path (Split-Path -Parent $firstApp) ([string] $policy.archiveFileName)
$secondZipPath = Join-Path (Split-Path -Parent $secondApp) ([string] $policy.archiveFileName)
$firstZipBytes = [System.IO.File]::ReadAllBytes($firstZipPath)
$secondZipBytes = [System.IO.File]::ReadAllBytes($secondZipPath)
Assert-True ([System.Linq.Enumerable]::SequenceEqual[byte]($firstZipBytes, $secondZipBytes)) `
    'two clean independent work areas must produce identical portable-package bytes'
Assert-Equal $first.portablePackageIdentity.sha256 $second.portablePackageIdentity.sha256 `
    'independent builds must record the same unsigned portable-package identity'
Assert-Equal $first.generatedContentIdentity.sha256 $second.generatedContentIdentity.sha256 `
    'independent builds must record the same unsigned generated-content identity'
Assert-Equal (Get-Sha256Hex -Bytes $firstZipBytes) $first.portablePackageIdentity.sha256 `
    'the recorded portable-package identity is the SHA-256 of the exact archive bytes'

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$extractRoot = Join-Path $workRoot 'extract-primary'
[System.IO.Compression.ZipFile]::ExtractToDirectory($firstZipPath, $extractRoot)
$packageRoot = Join-Path $extractRoot ([string] $policy.archiveRootName)
Assert-Equal $true (Test-Path -LiteralPath $packageRoot -PathType Container) `
    'the archive uses the frozen package root name'
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
foreach ($leaf in @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File)) {
    if ($leaf.Extension -notin @('.md', '.json', '.txt', '.sha256', '.ps1')) { continue }
    $text = $utf8.GetString([System.IO.File]::ReadAllBytes($leaf.FullName))
    Assert-NoRestrictedMaterial -Text $text "packaged file $($leaf.Name)"
}

foreach ($requiredPath in @($policy.requiredPackagePaths)) {
    $resolved = Join-Path $packageRoot (($requiredPath -split '/') -join [System.IO.Path]::DirectorySeparatorChar)
    Assert-Equal $true (Test-Path -LiteralPath $resolved -PathType Leaf) `
        "the package contains required path $requiredPath"
}

$manifest = Get-Content -LiteralPath (Join-Path $packageRoot 'package-manifest.json') -Raw |
    ConvertFrom-Json -Depth 20
Assert-Equal 'win-pcinfo.portable-distribution-manifest' $manifest.kind `
    'the package manifest uses the portable-distribution kind'
Assert-Equal $first.generatedContentIdentity.sha256 `
    $manifest.unsignedGeneratedContentIdentity.sha256 `
    'the package manifest records the generated-content identity'
Assert-Equal $false ($manifest.PSObject.Properties.Name -contains 'unsignedPortablePackageIdentity') `
    'the zip identity is not embedded inside the zip'
$manifestPaths = @($manifest.resources.path)
$manifestListedPaths = @(
    $policy.requiredPackagePaths | Where-Object { $_ -notin @('package-manifest.json', 'checksums.sha256') }
)
foreach ($requiredPath in $manifestListedPaths) {
    Assert-Equal $true ($requiredPath -in $manifestPaths) `
        "the manifest authenticates required path $requiredPath"
}

$checksumLines = Get-Content -LiteralPath (Join-Path $packageRoot 'checksums.sha256')
$checksumMap = @{}
foreach ($line in $checksumLines) {
    Assert-Equal $true ($line -match '^[0-9a-f]{64}  [A-Za-z0-9._/-]+$') `
        'each checksum line is hex digest, two spaces, and a normalized package path'
    $digest = $line.Substring(0, 64)
    $path = $line.Substring(66)
    $checksumMap[$path] = $digest
}
foreach ($resource in @($manifest.resources)) {
    $leaf = Join-Path $packageRoot (($resource.path -split '/') -join [System.IO.Path]::DirectorySeparatorChar)
    $bytes = [System.IO.File]::ReadAllBytes($leaf)
    $digest = Get-Sha256Hex -Bytes $bytes
    Assert-Equal $resource.sha256 $digest "$($resource.path) matches its manifest digest"
    Assert-Equal $checksumMap[$resource.path] $digest "$($resource.path) matches its checksums digest"
    Assert-Equal $resource.byteLength $bytes.Length "$($resource.path) records its exact byte length"
}

$protectedClasses = @($manifest.resources.class | Sort-Object -Unique)
foreach ($class in @($policy.protectedClasses | Where-Object { $_ -ne 'manifest' })) {
    Assert-Equal $true ($class -in $protectedClasses) `
        "the package authenticates at least one $class resource"
}
Assert-Equal $true (Test-Path -LiteralPath (Join-Path $packageRoot 'package-manifest.json') -PathType Leaf) `
    'the package authenticates its manifest as an explicit file'

$inventory = Get-Content -LiteralPath (Join-Path $packageRoot 'dependency-inventory.json') -Raw |
    ConvertFrom-Json -Depth 20
Assert-Equal 'win-pcinfo.dependency-inventory' $inventory.kind 'dependency inventory is versioned'
Assert-Equal $false $inventory.installsRuntime 'dependency inventory states that no runtime is installed'
$runtime = @($inventory.dependencies | Where-Object id -eq 'powershell-core')[0]
Assert-Equal $false $runtime.bundled 'PowerShell remains an external prerequisite'
Assert-Equal 'MIT' $runtime.license 'the external runtime license is recorded'
Assert-Equal $true (@($inventory.dependencies | Where-Object {
    [string]::IsNullOrWhiteSpace($_.id) -or
        [string]::IsNullOrWhiteSpace($_.version) -or
        [string]::IsNullOrWhiteSpace($_.digest) -or
        [string]::IsNullOrWhiteSpace($_.license) -or
        [string]::IsNullOrWhiteSpace($_.provenance)
}).Count -eq 0) 'every dependency record is frozen with identity, version, digest, license, and provenance'

$sbomJson = Get-Content -LiteralPath (Join-Path $packageRoot 'sbom.spdx.json') -Raw
$sbom = $sbomJson | ConvertFrom-Json -Depth 20
Assert-Equal 'SPDX-2.3' $sbom.spdxVersion 'the SBOM uses SPDX 2.3'
Assert-Equal 'CC0-1.0' $sbom.dataLicense 'the SBOM document license is CC0-1.0'
Assert-Equal $true ($sbomJson -match '"created":"1980-01-01T00:00:00Z"') `
    'the SBOM timestamp is the frozen precursor date, not the build clock'
Assert-Equal $true (@($sbom.packages).Count -ge 2) 'the SBOM inventories the product and the external runtime'
Assert-NoRestrictedMaterial -Text ($sbom | ConvertTo-Json -Compress -Depth 12) 'the SPDX SBOM'

$provenanceJson = Get-Content -LiteralPath (Join-Path $packageRoot 'provenance.json') -Raw
$provenance = $provenanceJson | ConvertFrom-Json -Depth 20
Assert-Equal 'win-pcinfo.unsigned-precursor-provenance' $provenance.kind `
    'provenance is the unsigned precursor record'
Assert-Equal $true $provenance.notASignedDistributableIdentity `
    'provenance refuses to claim the later signed distributable identity'
Assert-Equal $first.generatedContentIdentity.sha256 $provenance.generatedContent.sha256 `
    'provenance binds the generated-content identity'
Assert-Equal $true ($provenance.sourceRevision.sha256 -match '^[0-9a-f]{64}$') `
    'provenance freezes a content-tree source revision'
Assert-Equal $true ($provenanceJson -match '"created":"1980-01-01T00:00:00Z"') `
    'provenance does not record a live build clock'
Assert-NoRestrictedMaterial -Text ($provenance | ConvertTo-Json -Compress -Depth 12) 'provenance'

$notice = Get-Content -LiteralPath (Join-Path $packageRoot 'NOTICE.txt') -Raw
Assert-Equal $true ($notice -match 'MIT License') 'NOTICE includes the MIT license review'
Assert-Equal $true ($notice -match 'PowerShell') 'NOTICE names the external PowerShell prerequisite'

$applicationBytes = [System.IO.File]::ReadAllBytes((Join-Path $packageRoot 'WIN-PCInfo.ps1'))
Assert-Equal $first.generatedContentIdentity.sha256 (Get-Sha256Hex -Bytes $applicationBytes) `
    'the packaged application bytes are the generated-content identity'
Assert-Equal $true ($applicationBytes[0] -eq 0xEF -and $applicationBytes[1] -eq 0xBB -and
    $applicationBytes[2] -eq 0xBF) 'the packaged application keeps the UTF-8 BOM signing representation'

Write-Output "PASS: portable distribution $($first.portablePackageIdentity.sha256) is deterministic and inventory-complete."
