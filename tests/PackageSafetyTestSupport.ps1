Set-StrictMode -Version Latest

function New-AuthenticatedTestArchive {
    param([byte[]] $Record, [byte[]] $Report, $Manifest)
    # Deliberately bypass record admission only when constructing hostile input.
    # ZIP and AES-GCM remain the platform/package implementations under test.
    $manifestCopy = $Manifest | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $entries = [ordered]@{ 'assessment-record.json' = $Record; 'assessment-report.html' = $Report }
    foreach ($content in $manifestCopy.contents) {
        $content.byteLength = $entries[$content.relativePath].Length
        $content.sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($entries[$content.relativePath])).ToLowerInvariant()
    }
    $entries['package-manifest.json'] = [Text.Encoding]::UTF8.GetBytes(($manifestCopy | ConvertTo-Json -Depth 20 -Compress))
    $memory = [IO.MemoryStream]::new()
    try {
        $zip = [IO.Compression.ZipArchive]::new($memory, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($name in $entries.Keys) {
                $stream = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::NoCompression).Open()
                try { $stream.Write([byte[]] $entries[$name]) }
                finally { $stream.Dispose() }
            }
        }
        finally { $zip.Dispose() }
        ,$memory.ToArray()
    }
    finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($memory.GetBuffer()); $memory.Dispose() }
}

function Add-PackageBufferObservation {
    param([string] $Source)
    # Test-only allocation observation, with no replaced crypto/validator/helper.
    # Keep references to allocated buffers so clearing can be checked after the
    # public operation returns. This does not assert helper calls or zero counts.
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Source, [ref] $tokens, [ref] $errors)
    if ($errors.Count) { throw 'Package source did not parse for buffer observation.' }
    $assignments = $ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -notmatch '\$(ciphertext|tag|nonce)$' -and
        $node.Right.Extent.Text -match '(?i)(\[byte\[\]\]\s*::new|\.ToArray\(|Read-ProtectedPackageZipEntry|Unprotect-(?:ProtectedPackage|Recipient)ContentKey|MemoryStream\]::new\(\))'
    }, $true)
    foreach ($node in @($assignments | Sort-Object { $_.Extent.EndOffset } -Descending)) {
        $left = $node.Left.Extent.Text -replace '^\[[^\r\n]+?\]\s*(?=\$)', ''
        $Source = $Source.Insert($node.Extent.EndOffset,
            "; `$script:ObservedPackageBuffers.Add([pscustomobject]@{ Name='$($left.Replace("'", "''"))'; Value=[object]($left) })")
    }
    $Source
}

function Assert-PackageBuffersCleared {
    param([string] $Because, [object[]] $Transferred = @())
    $checked = 0
    foreach ($allocation in $script:ObservedPackageBuffers) {
        $value = $allocation.Value
        if ($null -eq $value) { continue }
        $isTransferred = $false
        foreach ($owned in $Transferred) { if ([object]::ReferenceEquals($value, $owned)) { $isTransferred = $true } }
        if ($isTransferred) { continue }
        $buffer = $value
        if ($value -is [IO.MemoryStream]) { $buffer = $value.GetBuffer() }
        if ($buffer -isnot [byte[]]) { throw "Owned allocation lost its clearable byte-buffer type: $($buffer.GetType().Name)." }
        $checked++
        if (@($buffer | Where-Object { $_ -ne 0 }).Count) { throw "Owned plaintext/key buffer $($allocation.Name) survived $Because." }
    }
    if ($checked -eq 0) { throw 'Buffer clearing assertion observed no allocations.' }
}
