function Get-Utf8LfBytes {
    param([Parameter(Mandatory)] [string] $LiteralPath)

    $text = [System.IO.File]::ReadAllText($LiteralPath)
    $lfText = $text -replace "`r`n", "`n" -replace "`r", "`n"
    [System.Text.UTF8Encoding]::new($false).GetBytes($lfText)
}
