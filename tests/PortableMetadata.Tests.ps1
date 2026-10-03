[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'build/PortableDistribution.ps1')

$seed = '1' * 64
$document = New-PortableSpdxDocument -SourceRevisionDigest $seed
$repeat = New-PortableSpdxDocument -SourceRevisionDigest $seed
Assert-Equal $document.documentNamespace $repeat.documentNamespace 'identical metadata has a stable namespace'
Assert-Equal $true ([Linq.Enumerable]::SequenceEqual[byte](
    [byte[]](ConvertTo-DeterministicJsonBytes $document), [byte[]](ConvertTo-DeterministicJsonBytes $repeat))) 'metadata rebuild bytes are deterministic'
foreach ($package in $document.packages) {
    Assert-Equal $false $package.filesAnalyzed 'the SPDX document asserts metadata rather than file analysis'
    Assert-Equal $false ($null -ne $package.PSObject.Properties['packageVerificationCode']) 'metadata-only packages omit verification code'
}
Assert-Equal $false ($null -ne $document.PSObject.Properties['files']) 'metadata-only document supplies no file list'
Assert-Equal $true ($document.comment.Contains('package-manifest.json') -and $document.comment.Contains('checksums.sha256')) 'metadata scope points to authenticated per-file identity records'
Assert-Equal $true ([string]$document.creationInfo.created -match '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$') 'metadata authoring time uses exact UTC syntax rather than the artificial ZIP epoch'
$created = [DateTimeOffset]::ParseExact($document.creationInfo.created, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
Assert-Equal $true ($created.Year -ge 2026) 'the source-controlled metadata timestamp records actual authoring rather than the ZIP epoch'
Assert-Equal $document.creationInfo.created ($created.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)) 'the recorded UTC authoring timestamp is a real round-trippable date'

foreach ($property in @('name', 'comment')) {
    $changed = $document | ConvertTo-Json -Depth 40 | ConvertFrom-Json -Depth 40
    $changed.$property += ' changed metadata'
    $changedNamespace = Get-PortableSpdxDocumentNamespace -Document $changed -SourceRevisionDigest $seed
    Assert-Equal $false ($document.documentNamespace -ceq $changedNamespace) 'changed metadata cannot reuse its document namespace'
}
foreach ($property in @('versionInfo', 'licenseDeclared', 'licenseConcluded')) {
    $nested = $document | ConvertTo-Json -Depth 40 | ConvertFrom-Json -Depth 40
    $nested.packages[0].$property += '-changed'
    Assert-Equal $false ($document.documentNamespace -ceq (Get-PortableSpdxDocumentNamespace -Document $nested -SourceRevisionDigest $seed)) 'nested package metadata changes require a distinct namespace'
}
$nested = $document | ConvertTo-Json -Depth 40 | ConvertFrom-Json -Depth 40
$nested.relationships[1].relationshipType = 'CONTAINS'
Assert-Equal $false ($document.documentNamespace -ceq (Get-PortableSpdxDocumentNamespace -Document $nested -SourceRevisionDigest $seed)) 'changed relationship metadata requires a distinct namespace'
$changed = $document | ConvertTo-Json -Depth 40 | ConvertFrom-Json -Depth 40
$changed.creationInfo.created = '2026-10-03T12:14:09Z'
Assert-Equal $false ($document.documentNamespace -ceq (Get-PortableSpdxDocumentNamespace -Document $changed -SourceRevisionDigest $seed)) 'a new document authoring event gets a distinct namespace'
$changed.documentNamespace = 'https://example.invalid/old-uri'
$one = Get-PortableSpdxDocumentNamespace -Document $changed -SourceRevisionDigest $seed
$changed.documentNamespace = 'https://example.invalid/another-uri'
Assert-Equal $one (Get-PortableSpdxDocumentNamespace -Document $changed -SourceRevisionDigest $seed) 'namespace computation excludes its own URI to avoid self-reference'
Assert-Equal $false ($document.documentNamespace -ceq (New-PortableSpdxDocument -SourceRevisionDigest ('2' * 64)).documentNamespace) 'changed governing resource seed gets a distinct namespace'

$inventory = New-PortableDependencyInventory -BuildToolDigest ('1' * 64) -HelperDigest ('2' * 64) -EntryDigest ('3' * 64) -CanonicalizationDigest ('4' * 64) -ArchiveToolDigest ('5' * 64) -PackagingToolDigest ('6' * 64)
$tools = @($inventory.dependencies | Where-Object role -eq 'build-tool')
Assert-Equal 4 $tools.Count 'the entry build tool and all three dot-sourced build tools remain inventoried'
foreach ($tool in $tools) {
    Assert-Equal $false $tool.bundled 'build-tool source is not a packaged runtime resource'
    Assert-Equal $true ([string]$tool.digest -match '^[0-9a-f]{64}$') 'unbundled build tools retain exact build provenance'
}
Write-Output 'PASS: SPDX metadata scope, source-controlled authoring time, content-derived namespace and unbundled build-tool provenance agree.'
