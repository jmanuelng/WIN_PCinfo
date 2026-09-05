function Get-PortableDistributionSha256 {
    param([Parameter(Mandatory)] $Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        [System.Convert]::ToHexString($sha256.ComputeHash([byte[]] $Bytes)).ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertTo-PortableScriptBytes {
    param([Parameter(Mandatory)] [string] $Text, [switch] $IncludeBom)
    $normalized = ($Text -replace "`r`n", "`n" -replace "`r", "`n").TrimEnd("`n") + "`n"
    $crlf = $normalized -replace "`n", "`r`n"
    $encoding = [System.Text.UTF8Encoding]::new([bool] $IncludeBom)
    [byte[]] ($encoding.GetPreamble() + $encoding.GetBytes($crlf))
}

function ConvertTo-DeterministicJsonBytes {
    param([Parameter(Mandatory)] $Value)

    $json = $Value | ConvertTo-Json -Compress -Depth 40
    [System.Text.UTF8Encoding]::new($false).GetBytes($json)
}

function New-PortableFileRecord {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Class,
        [Parameter(Mandatory)] $Bytes
    )

    $payload = [byte[]] $Bytes
    $record = [pscustomobject][ordered]@{
        path = $Path
        class = $Class
        sha256 = Get-PortableDistributionSha256 -Bytes $payload
        byteLength = $payload.Length
    }
    # A byte[] cannot be placed in [ordered] on Windows PowerShell-adjacent
    # ordered dictionaries; some hosts throw "Argument types do not match".
    Add-Member -InputObject $record -NotePropertyName bytes -NotePropertyValue $payload
    $record
}

function Get-PortableDistributionPolicy {
    param([Parameter(Mandatory)] [string] $RepositoryRoot)

    $path = Join-Path $RepositoryRoot 'docs/spec/releases/2.0.0-preview.1-portable-distribution.json'
    Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 20
}

function Get-PortableSourceTreeFiles {
    param(
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] $Policy
    )

    $catalogSet = @{}
    foreach ($catalogPath in @($Policy.catalogPaths)) {
        $catalogSet[[string] $catalogPath] = $true
    }

    $items = New-Object System.Collections.Generic.List[object]
    $schemaDirectory = Join-Path $RepositoryRoot 'schemas'
    foreach ($schema in @(Get-ChildItem -LiteralPath $schemaDirectory -Filter '*.json' -File | Sort-Object Name)) {
        $packagePath = 'schemas/' + $schema.Name
        $null = $items.Add([pscustomobject]@{
            PackagePath = $packagePath
            SourcePath = $packagePath
            Class = 'schema'
        })
    }

    $releaseDirectory = Join-Path $RepositoryRoot 'docs/spec/releases'
    foreach ($definition in @(Get-ChildItem -LiteralPath $releaseDirectory -Filter '*.json' -File | Sort-Object Name)) {
        $packagePath = 'docs/spec/releases/' + $definition.Name
        $class = if ($catalogSet.ContainsKey($packagePath)) { 'catalog' } else { 'definition' }
        $null = $items.Add([pscustomobject]@{
            PackagePath = $packagePath
            SourcePath = $packagePath
            Class = $class
        })
    }

    $ledgerPath = 'docs/spec/capability-ledger.json'
    $ledgerClass = if ($catalogSet.ContainsKey($ledgerPath)) { 'catalog' } else { 'definition' }
    $null = $items.Add([pscustomobject]@{
        PackagePath = $ledgerPath
        SourcePath = $ledgerPath
        Class = $ledgerClass
    })

    $docsRoot = Join-Path $RepositoryRoot 'docs'
    foreach ($document in @(Get-ChildItem -LiteralPath $docsRoot -Filter '*.md' -File -Recurse | Sort-Object FullName)) {
        $relative = $document.FullName.Substring($docsRoot.Length).TrimStart('\', '/').Replace('\', '/')
        $top = ($relative -split '/')[0]
        if ($top -in @('validation', 'research')) { continue }
        $packagePath = 'docs/' + $relative
        $null = $items.Add([pscustomobject]@{
            PackagePath = $packagePath
            SourcePath = $packagePath
            Class = 'documentation'
        })
    }

    foreach ($rootDocument in @('SECURITY.md', 'CONTRIBUTING.md')) {
        $null = $items.Add([pscustomobject]@{
            PackagePath = $rootDocument
            SourcePath = $rootDocument
            Class = 'documentation'
        })
    }

    $items
}

function New-PortableNoticeBytes {
    $text = @(
        'WIN-PCInfo portable distribution'
        'Release: 2.0.0-preview.1'
        ''
        'This archive is an unsigned precursor package. It is not a timestamped'
        'signed distributable and does not create a Preview or Supported claim.'
        ''
        'MIT License'
        ''
        'Permission is hereby granted, free of charge, to any person obtaining a copy'
        'of this software and associated documentation files (the "Software"), to deal'
        'in the Software without restriction, including without limitation the rights'
        'to use, copy, modify, merge, publish, distribute, sublicense, and/or sell'
        'copies of the Software, and to permit persons to whom the Software is'
        'furnished to do so, subject to the following conditions:'
        ''
        'The above copyright notice and this permission notice shall be included in all'
        'copies or substantial portions of the Software.'
        ''
        'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR'
        'IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,'
        'FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE'
        'AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER'
        'LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,'
        'OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE'
        'SOFTWARE.'
        ''
        'External runtime (not bundled, never installed by this package):'
        'PowerShell 7.6 or a later 7.x stable host, MIT licensed, obtained from'
        'https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows'
        ''
        'This package contains no third-party runtime binaries.'
    ) -join "`n"
    [System.Text.UTF8Encoding]::new($false).GetBytes($text + "`n")
}

function New-PortableDependencyInventory {
    param(
        [Parameter(Mandatory)] [string] $BuildToolDigest,
        [Parameter(Mandatory)] [string] $HelperDigest,
        [Parameter(Mandatory)] [string] $EntryDigest,
        [Parameter(Mandatory)] [string] $CanonicalizationDigest
    )

    [pscustomobject][ordered]@{
        kind = 'win-pcinfo.dependency-inventory'
        contractVersion = '1.0.0'
        release = '2.0.0-preview.1'
        installsRuntime = $false
        dependencies = @(
            [pscustomobject][ordered]@{
                id = 'powershell-core'
                role = 'external-runtime'
                product = 'PowerShell'
                version = '7.6.0'
                bundled = $false
                digest = 'not-bundled'
                license = 'MIT'
                provenance = 'https://github.com/PowerShell/PowerShell'
            }
            [pscustomobject][ordered]@{
                id = 'microsoft-powershell-utility'
                role = 'transitive-validator'
                product = 'Microsoft.PowerShell.Utility'
                version = 'inbox-pshome'
                bundled = $false
                digest = 'authenticode-microsoft-pshome'
                license = 'MIT'
                provenance = 'literal-pshome-microsoft-authenticode'
            }
            [pscustomobject][ordered]@{
                id = 'microsoft-powershell-management'
                role = 'inbox-module'
                product = 'Microsoft.PowerShell.Management'
                version = 'inbox-pshome'
                bundled = $false
                digest = 'authenticode-microsoft-pshome'
                license = 'MIT'
                provenance = 'literal-pshome-microsoft-authenticode'
            }
            [pscustomobject][ordered]@{
                id = 'microsoft-powershell-security'
                role = 'inbox-module'
                product = 'Microsoft.PowerShell.Security'
                version = 'inbox-pshome'
                bundled = $false
                digest = 'authenticode-microsoft-pshome'
                license = 'MIT'
                provenance = 'literal-pshome-microsoft-authenticode'
            }
            [pscustomobject][ordered]@{
                id = 'win-pcinfo-build'
                role = 'build-tool'
                product = 'build/Build.ps1'
                version = '1.0.0'
                bundled = $true
                digest = $BuildToolDigest
                license = 'MIT'
                provenance = 'repository-build/Build.ps1'
            }
            [pscustomobject][ordered]@{
                id = 'win-pcinfo-text-canonicalization'
                role = 'build-tool'
                product = 'build/TextCanonicalization.ps1'
                version = '1.0.0'
                bundled = $true
                digest = $CanonicalizationDigest
                license = 'MIT'
                provenance = 'repository-build/TextCanonicalization.ps1'
            }
            [pscustomobject][ordered]@{
                id = 'win-pcinfo-windows-powershell-helper'
                role = 'helper'
                product = 'Start-WIN-PCInfo.ps1'
                version = '1.0.0'
                bundled = $true
                digest = $HelperDigest
                license = 'MIT'
                provenance = 'package-helper'
            }
            [pscustomobject][ordered]@{
                id = 'win-pcinfo-double-click-entry'
                role = 'helper'
                product = 'Start-WIN-PCInfo.cmd'
                version = '1.0.0'
                bundled = $true
                digest = $EntryDigest
                license = 'MIT'
                provenance = 'repository-build/Start-WIN-PCInfo.cmd'
            }
        )
    }
}

function New-PortableSpdxDocument {
    param([Parameter(Mandatory)] [string] $SourceRevisionDigest)

    [pscustomobject][ordered]@{
        spdxVersion = 'SPDX-2.3'
        dataLicense = 'CC0-1.0'
        SPDXID = 'SPDXRef-DOCUMENT'
        name = 'WIN-PCInfo-2.0.0-preview.1'
        documentNamespace = "https://github.com/jmanuelng/WIN_PCinfo/spdx/2.0.0-preview.1/$SourceRevisionDigest"
        creationInfo = [pscustomobject][ordered]@{
            created = '1980-01-01T00:00:00Z'
            creators = @('Tool: win-pcinfo-build-1.0.0')
        }
        packages = @(
            [pscustomobject][ordered]@{
                name = 'WIN-PCInfo'
                SPDXID = 'SPDXRef-Package-WIN-PCInfo'
                versionInfo = '2.0.0-preview.1'
                downloadLocation = 'NOASSERTION'
                filesAnalyzed = $true
                licenseConcluded = 'MIT'
                licenseDeclared = 'MIT'
                copyrightText = 'NOASSERTION'
            }
            [pscustomobject][ordered]@{
                name = 'PowerShell'
                SPDXID = 'SPDXRef-Package-PowerShell'
                versionInfo = '7.6.0'
                downloadLocation = 'https://github.com/PowerShell/PowerShell'
                filesAnalyzed = $false
                licenseConcluded = 'MIT'
                licenseDeclared = 'MIT'
                copyrightText = 'NOASSERTION'
            }
        )
        relationships = @(
            [pscustomobject][ordered]@{
                spdxElementId = 'SPDXRef-DOCUMENT'
                relationshipType = 'DESCRIBES'
                relatedSpdxElement = 'SPDXRef-Package-WIN-PCInfo'
            }
            [pscustomobject][ordered]@{
                spdxElementId = 'SPDXRef-Package-WIN-PCInfo'
                relationshipType = 'DEPENDS_ON'
                relatedSpdxElement = 'SPDXRef-Package-PowerShell'
            }
        )
    }
}

function Get-PortableGoverningResources {
    param(
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $BuildToolDigest,
        [string] $SignedHelperPath,
        [scriptblock] $ReadSignature = {
            param($Path)
            Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        }
    )

    $resources = New-Object System.Collections.Generic.List[object]
    foreach ($item in @(Get-PortableSourceTreeFiles -RepositoryRoot $RepositoryRoot -Policy $Policy)) {
        $source = Join-Path $RepositoryRoot (($item.SourcePath -split '/') -join [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Portable package source is missing: $($item.SourcePath)"
        }
        $bytes = Get-Utf8LfBytes -LiteralPath $source
        $null = $resources.Add((New-PortableFileRecord -Path $item.PackagePath -Class $item.Class -Bytes $bytes))
    }

    $helperSource = Join-Path $RepositoryRoot (($Policy.helperSourcePath -split '/') -join [System.IO.Path]::DirectorySeparatorChar)
    $hostSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'build/RuntimeHost.ps1'))
    $helperText = [IO.File]::ReadAllText($helperSource).Replace('# __RUNTIME_HOST_FUNCTIONS__', $hostSource)
    $helperBytes = ConvertTo-PortableScriptBytes -Text $helperText -IncludeBom
    if (-not [string]::IsNullOrWhiteSpace($SignedHelperPath)) {
        # Sign the generated launcher first, then bind those fixed signed bytes
        # into the application before signing it. Otherwise signing the helper
        # invalidates its governing digest. A valid signature alone cannot admit
        # unrelated code: compare the complete generated payload too. Hold a
        # read-only file lock while Windows verifies the same literal file.
        $literalHelper = [IO.Path]::GetFullPath($SignedHelperPath)
        $stream = [IO.File]::Open($literalHelper, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            if ($stream.Length -le 0 -or $stream.Length -gt 1MB) { throw 'Signed helper exceeds its byte bound.' }
            [byte[]] $signedBytes = [byte[]]::new([int]$stream.Length)
            $stream.ReadExactly($signedBytes)
            $signature = & $ReadSignature $literalHelper
            if ([string]$signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
                throw 'Signed helper failed Authenticode admission.'
            }
            $encoding = [Text.UTF8Encoding]::new($false, $true)
            $signedText = $encoding.GetString($signedBytes)
            $signatureMatch = [regex]::Match($signedText,
                '(?s)\A(?<payload>.*?)\r\n# SIG # Begin signature block\r\n(?:# [A-Za-z0-9+/=]+\r\n)+# SIG # End signature block(?:\r\n)?\z')
            if (-not $signatureMatch.Success -or
                $signatureMatch.Groups['payload'].Value.TrimEnd("`r", "`n") -cne
                $encoding.GetString([byte[]]$helperBytes).TrimEnd("`r", "`n")) {
                throw 'Signed helper differs from the generated launcher for this build.'
            }
            $helperBytes = $signedBytes
        }
        finally { $stream.Dispose() }
    }
    $helperDigest = Get-PortableDistributionSha256 -Bytes $helperBytes
    $null = $resources.Add((New-PortableFileRecord -Path $Policy.helperPackagePath -Class 'helper' -Bytes $helperBytes))
    $entryBytes = ConvertTo-PortableScriptBytes -Text ([IO.File]::ReadAllText((Join-Path $RepositoryRoot 'build/Start-WIN-PCInfo.cmd')))
    $null = $resources.Add((New-PortableFileRecord -Path 'Start-WIN-PCInfo.cmd' -Class 'helper' -Bytes $entryBytes))

    $firstRunSource = Join-Path $RepositoryRoot (($Policy.firstRunSourcePath -split '/') -join [System.IO.Path]::DirectorySeparatorChar)
    $firstRunBytes = Get-Utf8LfBytes -LiteralPath $firstRunSource
    $null = $resources.Add((New-PortableFileRecord -Path $Policy.firstRunPackagePath -Class 'documentation' -Bytes $firstRunBytes))

    $noticeBytes = New-PortableNoticeBytes
    $null = $resources.Add((New-PortableFileRecord -Path 'NOTICE.txt' -Class 'documentation' -Bytes $noticeBytes))

    $canonicalizationPath = Join-Path $RepositoryRoot 'build/TextCanonicalization.ps1'
    $canonicalizationDigest = Get-PortableDistributionSha256 -Bytes (
        (Get-Utf8LfBytes -LiteralPath $canonicalizationPath)
    )
    $sourceRevisionSeed = @(
        $resources | Sort-Object path | ForEach-Object { "$($_.path)=$($_.sha256)" }
    ) -join "`n"
    $sourceRevisionDigest = Get-PortableDistributionSha256 -Bytes (
        [System.Text.UTF8Encoding]::new($false).GetBytes($sourceRevisionSeed)
    )

    $inventory = New-PortableDependencyInventory -BuildToolDigest $BuildToolDigest `
        -HelperDigest $helperDigest -EntryDigest (Get-PortableDistributionSha256 -Bytes $entryBytes) `
        -CanonicalizationDigest $canonicalizationDigest
    $inventoryBytes = ConvertTo-DeterministicJsonBytes -Value $inventory
    $null = $resources.Add((New-PortableFileRecord -Path 'dependency-inventory.json' -Class 'definition' -Bytes $inventoryBytes))

    $sbom = New-PortableSpdxDocument -SourceRevisionDigest $sourceRevisionDigest
    $sbomBytes = ConvertTo-DeterministicJsonBytes -Value $sbom
    $null = $resources.Add((New-PortableFileRecord -Path 'sbom.spdx.json' -Class 'definition' -Bytes $sbomBytes))

    $embedded = [pscustomobject][ordered]@{
        contractVersion = '1.0.0'
        policyId = [string] $Policy.policyId
        sourceRevisionSha256 = $sourceRevisionDigest
        resources = @(
            $resources | Sort-Object path | ForEach-Object {
                [pscustomobject][ordered]@{
                    path = $_.path
                    class = $_.class
                    sha256 = $_.sha256
                    byteLength = $_.byteLength
                }
            }
        )
    }

    [pscustomobject]@{
        Policy = $Policy
        Resources = $resources
        EmbeddedTable = $embedded
        SourceRevisionDigest = $sourceRevisionDigest
    }
}

function New-PortableDistributionPackage {
    param(
        [Parameter(Mandatory)] [string] $OutputDirectory,
        [Parameter(Mandatory)] $ApplicationBytes,
        [Parameter(Mandatory)] [string] $ApplicationDigest,
        [Parameter(Mandatory)] $Governing,
        [Parameter(Mandatory)] $BuildTool
    )
    $ApplicationBytes = [byte[]] $ApplicationBytes

    $policy = $Governing.Policy
    $packageRootName = [string] $policy.archiveRootName
    $unpackedRoot = Join-Path $OutputDirectory $packageRootName
    if (Test-Path -LiteralPath $unpackedRoot) {
        Remove-Item -LiteralPath $unpackedRoot -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $unpackedRoot -Force

    $packageFiles = New-Object System.Collections.Generic.List[object]
    $applicationRecord = New-PortableFileRecord -Path 'WIN-PCInfo.ps1' -Class 'application' -Bytes $ApplicationBytes
    if ($applicationRecord.sha256 -ne $ApplicationDigest) {
        throw 'The packaged application digest does not match the generated-content identity.'
    }
    $null = $packageFiles.Add($applicationRecord)
    foreach ($resource in $Governing.Resources) {
        $null = $packageFiles.Add($resource)
    }

    $provenance = [pscustomobject][ordered]@{
        kind = 'win-pcinfo.unsigned-precursor-provenance'
        contractVersion = '1.0.0'
        release = [string] $policy.release
        identityKind = 'unsigned-precursor'
        notASignedDistributableIdentity = $true
        generatedContent = [pscustomobject][ordered]@{
            path = 'WIN-PCInfo.ps1'
            sha256 = $ApplicationDigest
            encoding = 'utf-8-bom'
            lineEndings = 'crlf'
        }
        sourceRevision = [pscustomobject][ordered]@{
            kind = 'content-tree'
            sha256 = [string] $Governing.SourceRevisionDigest
        }
        buildTool = [pscustomobject][ordered]@{
            path = [string] $BuildTool.path
            sha256 = [string] $BuildTool.sha256
        }
        created = '1980-01-01T00:00:00Z'
    }
    $provenanceBytes = ConvertTo-DeterministicJsonBytes -Value $provenance
    $null = $packageFiles.Add((New-PortableFileRecord -Path 'provenance.json' -Class 'definition' -Bytes $provenanceBytes))

    $manifest = [pscustomobject][ordered]@{
        kind = 'win-pcinfo.portable-distribution-manifest'
        contractVersion = '1.0.0'
        release = [string] $policy.release
        policyId = [string] $policy.policyId
        installsRuntime = $false
        unsignedGeneratedContentIdentity = [pscustomobject][ordered]@{
            kind = 'win-pcinfo.unsigned-generated-content-identity'
            path = 'WIN-PCInfo.ps1'
            sha256 = $ApplicationDigest
            encoding = 'utf-8-bom'
            lineEndings = 'crlf'
        }
        sourceRevision = [pscustomobject][ordered]@{
            kind = 'content-tree'
            sha256 = [string] $Governing.SourceRevisionDigest
        }
        resources = @(
            $packageFiles | Sort-Object path | ForEach-Object {
                [pscustomobject][ordered]@{
                    path = $_.path
                    class = $_.class
                    sha256 = $_.sha256
                    byteLength = $_.byteLength
                }
            }
        )
    }
    $manifestBytes = ConvertTo-DeterministicJsonBytes -Value $manifest
    $null = $packageFiles.Add((New-PortableFileRecord -Path 'package-manifest.json' -Class 'manifest' -Bytes $manifestBytes))

    $checksumLines = @(
        $packageFiles | Sort-Object path | ForEach-Object { "$($_.sha256)  $($_.path)" }
    )
    $checksumBytes = [System.Text.UTF8Encoding]::new($false).GetBytes((($checksumLines -join "`n") + "`n"))
    $null = $packageFiles.Add((New-PortableFileRecord -Path 'checksums.sha256' -Class 'definition' -Bytes $checksumBytes))

    foreach ($file in $packageFiles) {
        $destination = Join-Path $unpackedRoot (($file.path -split '/') -join [System.IO.Path]::DirectorySeparatorChar)
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
        [System.IO.File]::WriteAllBytes($destination, [byte[]] $file.bytes)
    }

    $zipEntries = New-Object System.Collections.Generic.List[object]
    foreach ($file in $packageFiles) {
        $null = $zipEntries.Add([pscustomobject]@{
            Name = "$packageRootName/$($file.path)"
            Bytes = $file.bytes
        })
    }
    $zipPath = Join-Path $OutputDirectory ([string] $policy.archiveFileName)
    New-DeterministicZipArchive -LiteralPath $zipPath -Entries $zipEntries
    $zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
    $zipDigest = Get-PortableDistributionSha256 -Bytes $zipBytes

    [pscustomobject]@{
        installsRuntime = $false
        unpackedRootName = $packageRootName
        archiveFileName = [string] $policy.archiveFileName
        sha256 = $zipDigest
        generatedContentSha256 = $ApplicationDigest
        sourceRevisionSha256 = [string] $Governing.SourceRevisionDigest
    }
}
