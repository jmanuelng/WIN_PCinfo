[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1')

# This exported launch boundary executes only synthetic arithmetic and hashing.
# High-entropy source ensures the test cannot pass by compressing repeated text.
$bytes=[Security.Cryptography.RandomNumberGenerator]::GetBytes(25000)
$literal=[Convert]::ToBase64String($bytes)
$source='[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String('''+$literal+'''))).ToLowerInvariant()'
$command=ConvertTo-PrivilegedCollectionInlineCommand -Source $source
Assert-Equal $true ($command.Length -le 32500) 'the fixed inline launch bound admits a growing reviewed collector'
$observed=& $hostPath -NoLogo -NoProfile -NonInteractive -Command $command
Assert-Equal 0 $LASTEXITCODE 'the Windows Unicode command line executes the packed representation'
Assert-Equal (Get-PrivilegedCollectionPlanSha256 $bytes) $observed 'inline packing preserves every byte of high-entropy source'
foreach($count in 1..9){
    $literal=[Convert]::ToBase64String([byte[]](1..$count))
    $observed=& $hostPath -NoLogo -NoProfile -NonInteractive -Command (ConvertTo-PrivilegedCollectionInlineCommand -Source "'$literal'")
    Assert-Equal $literal $observed 'short compressed streams preserve padding and final bytes'
}
$large=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(70000))
$refused=$false
try { $null=ConvertTo-PrivilegedCollectionInlineCommand -Source "'$large'" } catch {$refused=$_.Exception.Message -eq 'The reviewed privilege worker exceeds the Windows launch bound.'}
Assert-Equal $true $refused 'source expansion never relaxes the launch ceiling'
foreach($culture in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')){
    $source="[Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('$culture');'Synthetic 漢字 O''Brien'"
    $observed=& $hostPath -NoLogo -NoProfile -NonInteractive -Command (ConvertTo-PrivilegedCollectionInlineCommand $source)
    Assert-Equal "Synthetic 漢字 O'Brien" $observed 'culture and quoting cannot alter the packed script'
}
$command=ConvertTo-PrivilegedCollectionInlineCommand -Source "'synthetic-not-executed'"
$match=[regex]::Match($command,'[\u4000-\u5080]+')
Assert-Equal $true $match.Success 'the bootstrap contains a bounded BMP representation'
$malformed=$command.Remove($match.Index,1).Insert($match.Index,([char]0x3000).ToString())
$null=& $hostPath -NoLogo -NoProfile -NonInteractive -Command $malformed 2>$null
Assert-Equal $true ($LASTEXITCODE -ne 0) 'a character outside the packed alphabet is rejected'

# Exercise ShellExecute Unicode argument handling without the runas verb. This
# proves the OS parser path only; genuine UAC remains a private #161 gate.
$ownedRoot=Join-Path $repositoryRoot 'artifacts/tests/inline-representation'
$null=New-Item -ItemType Directory -Path $ownedRoot -Force
$outputPath=Join-Path $ownedRoot ('result-'+[guid]::NewGuid().ToString('N')+'.txt')
try {
    $source="[IO.File]::WriteAllText('"+$outputPath.Replace("'","''")+"','Synthetic 漢字 O''Brien',[Text.UTF8Encoding]::new(`$false))"
    $start=[Diagnostics.ProcessStartInfo]::new($hostPath)
    $start.UseShellExecute=$true;$start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    foreach($arg in @('-NoLogo','-NoProfile','-NonInteractive','-Command',(ConvertTo-PrivilegedCollectionInlineCommand $source))){$start.ArgumentList.Add($arg)}
    $child=[Diagnostics.Process]::Start($start)
    try {Assert-Equal $true $child.WaitForExit(10000) 'controlled ShellExecute exits within its deadline';Assert-Equal 0 $child.ExitCode 'controlled ShellExecute accepts exact Unicode arguments'}
    finally {if(-not $child.HasExited){$child.Kill($true);$null=$child.WaitForExit(1000)};$child.Dispose()}
    Assert-Equal "Synthetic 漢字 O'Brien" ([IO.File]::ReadAllText($outputPath)) 'ShellExecute preserves source, quotes, and Unicode'
} finally {
    $resolved=[IO.Path]::GetFullPath($outputPath)
    if(-not $resolved.StartsWith([IO.Path]::GetFullPath($ownedRoot)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected cleanup target.'}
    if([IO.File]::Exists($resolved)){[IO.File]::Delete($resolved)}
}
Write-Output 'PASS: exact inline source roundtrip, Windows Unicode launch, padding, and unchanged oversize refusal.'
