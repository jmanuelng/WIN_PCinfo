[CmdletBinding()]
param([string] $CandidatePath, [string] $PreparedManifestPath, [string] $PreparedManifestSha256)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'ContractFormatTestSupport.ps1')
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidate=$candidateContext.Path
$candidateUseError=$null
try {
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
$validDates=@('2000-02-29','0000-02-29','1900-02-28','9999-12-31')
$invalidDates=@('1900-02-29','2026-04-31','2026-13-01','2026-00-01','2026-01-00','26-01-01','2026-1-01','٢٠٢٦-01-01',"2000-02-29`n")
$validTimes=@('2000-02-29T00:00:00Z','2000-02-29t23:59:59z','2000-02-29T23:59:59.123456789012Z',
    '2000-02-29T23:59:59-00:00','2000-02-29T23:59:59+23:59','0000-02-29T00:00:00Z',
    '1990-12-31T23:59:60Z','1991-01-01T00:59:60+01:00','1990-12-31T15:59:60-08:00')
$invalidTimes=@('not-a-time','2000-02-30T00:00:00Z','2000-01-01T24:00:00Z','2000-01-01T00:60:00Z',
    '2000-01-01T00:00:61Z','2000-01-01T00:00:60Z','2000-01-01T00:00:00','2000-01-01T00:00:00+24:00',
    '2000-01-01T00:00:00+01:60','2000-01-01T00:00:00.Z','2000-01-01 00:00:00Z',"2000-01-01T00:00:00Z`n")
$validUris=@('https://example.invalid','https://example.invalid/%E7%95%8C?q=one%20two#fragment',
    'https://[2001:db8::1]:443/a','https://[v1.test:future]/','https://example.invalid:99999/',
    'https://user:pass@example.invalid/a!$&''()*+,;=:@/?a=/?:@#/?')
$invalidUris=@('https://[','https://[invalid]/','https://[2001:db8::1','https://example.invalid/%',
    'https://example.invalid/%GG','https://example.invalid/a b','https://example.invalid/界',
    'https://example.invalid\path','https://example.invalid:abc/','https://example.invalid/a[b]',
    'https://example.invalid/#one#two',"https://example.invalid/`n")
$savedCulture=[cultureinfo]::CurrentCulture
$savedUiCulture=[cultureinfo]::CurrentUICulture
try {
    foreach($culture in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')) {
        [cultureinfo]::CurrentCulture=[cultureinfo]::GetCultureInfo($culture)
        [cultureinfo]::CurrentUICulture=[cultureinfo]::GetCultureInfo($culture)
        foreach($field in @('collectedAt','startedAt','completedAt','verifiedOn','url')) {
            $valid=if($field -eq 'url'){$validUris}elseif($field -eq 'verifiedOn'){$validDates}else{$validTimes}
            $invalid=if($field -eq 'url'){$invalidUris}elseif($field -eq 'verifiedOn'){$invalidDates}else{$invalidTimes}
            foreach($accepted in @($true,$false)) {
                foreach($value in $(if($accepted){$valid}else{$invalid})) {
                    $record=New-FormatContractRecord
                    Set-FormatContractValue $record $field $value
                    $bytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Depth 30 -Compress))
                    $result=Test-AssessmentContract -Utf8Bytes $bytes -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet) -TestJsonCommand (Get-Command Test-Json -CommandType Cmdlet)
                    Assert-Equal $(if($accepted){'CONTRACT.ACCEPTED'}else{'CONTRACT.FORMAT_INVALID'}) $result.reasonCode "$culture $field preserves the declared format: $value"
                    Assert-Equal $accepted $result.accepted 'the exported validator enforces semantic formats without returning material'
                }
            }
        }
        Write-Output "PASS: exported semantic date/time/URI and Unicode boundaries in $culture."
    }
} finally {
    [cultureinfo]::CurrentCulture=$savedCulture
    [cultureinfo]::CurrentUICulture=$savedUiCulture
}
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
