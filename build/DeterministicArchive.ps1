$script:WinPCInfoCrc32Table = $null

function Get-Crc32 {
    param([Parameter(Mandatory)] $Bytes)
    $Bytes = [byte[]] $Bytes

    # ZIP's CRC-32 is a public integrity check, not a secret. The threat is a
    # non-deterministic or host-dependent checksum that would make two honest
    # builds disagree. The mechanism is the fixed IEEE table and a single-pass
    # update. The trust assumption is that the table is the published ZIP
    # polynomial, not a host crypto provider. Safe failure is to refuse to
    # write an archive rather than emit an unverified extra field.
    $mask = [uint64] 4294967295
    $polynomial = [uint64] 3988292384
    if ($null -eq $script:WinPCInfoCrc32Table) {
        $table = [uint64[]]::new(256)
        for ($i = 0; $i -lt 256; $i++) {
            $entry = [uint64] $i
            for ($bit = 0; $bit -lt 8; $bit++) {
                if (($entry -band 1) -ne 0) {
                    $entry = [uint64] ((($entry -shr 1) -bxor $polynomial) -band $mask)
                }
                else {
                    $entry = [uint64] (($entry -shr 1) -band $mask)
                }
            }
            $table[$i] = $entry
        }
        $script:WinPCInfoCrc32Table = $table
    }

    $crc = $mask
    foreach ($byte in $Bytes) {
        $index = [int] (($crc -bxor [uint64] $byte) -band 0xFF)
        $crc = [uint64] (($script:WinPCInfoCrc32Table[$index] -bxor ($crc -shr 8)) -band $mask)
    }
    [uint32] ($crc -bxor $mask)
}

function New-DeterministicZipArchive {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $Entries
    )

    # System.IO.Compression.ZipArchive writes extra timestamp fields and uses
    # the current clock. That would make the portable-package identity a
    # machine-local value. This writer emits only the ZIP local headers, stored
    # payloads, central directory, and EOCD with a frozen 1980-01-01 DOS date
    # and no extra fields. Store (method 0) avoids Deflate implementation drift.
    $ordered = New-Object System.Collections.Generic.List[object]
    foreach ($entry in ($Entries | Sort-Object { [string] $_.Name })) {
        $null = $ordered.Add([pscustomobject]@{
            Name = ([string] $entry.Name).Replace('\', '/')
            Bytes = [byte[]] $entry.Bytes
        })
    }
    $directory = Split-Path -Parent $LiteralPath
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $stream = [System.IO.File]::Open(
        $LiteralPath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    $writer = [System.IO.BinaryWriter]::new($stream)
    try {
        $central = New-Object System.Collections.Generic.List[object]
        foreach ($entry in $ordered) {
            $nameBytes = [System.Text.Encoding]::ASCII.GetBytes($entry.Name)
            $payload = $entry.Bytes
            $crc = Get-Crc32 -Bytes $payload
            $offset = [uint32] $stream.Position
            $writer.Write([uint32] 0x04034b50)
            $writer.Write([uint16] 20)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0x0021)
            $writer.Write([uint32] $crc)
            $writer.Write([uint32] $payload.Length)
            $writer.Write([uint32] $payload.Length)
            $writer.Write([uint16] $nameBytes.Length)
            $writer.Write([uint16] 0)
            $writer.Write($nameBytes)
            if ($payload.Length -gt 0) {
                $writer.Write($payload)
            }
            $central.Add([pscustomobject]@{
                NameBytes = $nameBytes
                Crc = $crc
                Length = [uint32] $payload.Length
                Offset = $offset
            })
        }

        $centralOffset = [uint32] $stream.Position
        foreach ($record in $central) {
            $writer.Write([uint32] 0x02014b50)
            $writer.Write([uint16] 20)
            $writer.Write([uint16] 20)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0x0021)
            $writer.Write([uint32] $record.Crc)
            $writer.Write([uint32] $record.Length)
            $writer.Write([uint32] $record.Length)
            $writer.Write([uint16] $record.NameBytes.Length)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint32] 0)
            $writer.Write([uint32] $record.Offset)
            $writer.Write($record.NameBytes)
        }
        $centralSize = [uint32] ($stream.Position - $centralOffset)
        $writer.Write([uint32] 0x06054b50)
        $writer.Write([uint16] 0)
        $writer.Write([uint16] 0)
        $writer.Write([uint16] $central.Count)
        $writer.Write([uint16] $central.Count)
        $writer.Write([uint32] $centralSize)
        $writer.Write([uint32] $centralOffset)
        $writer.Write([uint16] 0)
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}
