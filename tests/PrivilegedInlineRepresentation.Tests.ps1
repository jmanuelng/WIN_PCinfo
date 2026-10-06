[CmdletBinding()]
param([string] $CandidatePath,[string] $PreparedManifestPath,[string] $PreparedManifestSha256)
# Native coverage runs through Run-Tests/Invoke-FocusedTest with the exact
# admitted prepared triple. Bare standalone preparation grants no native
# authority and the closed binding refuses before runtime/inline creation.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'QualificationInlineRepresentation.ps1')
$candidate=$null;$binding=$null;$bodyError=$null
Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $repositoryRoot
try {
$candidate=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$binding=Open-QualificationInlineRepresentationBinding -RepositoryRoot $repositoryRoot -Candidate $candidate -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$hostPath=Resolve-QualificationInlineRuntime -Binding $binding

# This exported launch boundary executes only synthetic arithmetic and hashing.
# High-entropy source ensures the test cannot pass by compressing repeated text.
$bytes=[Security.Cryptography.RandomNumberGenerator]::GetBytes(25000)
$literal=[Convert]::ToBase64String($bytes)
$source='[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String('''+$literal+'''))).ToLowerInvariant()'
$command=ConvertTo-PrivilegedCollectionInlineCommand -Source $source
Assert-Equal $true ($command.Length -le 32500) 'the fixed inline launch bound admits a growing reviewed collector'
$observed=Invoke-QualificationInlineRepresentationNative -Binding $binding -Profile Hash -Inputs @{Bytes=$bytes}
Assert-Equal 0 $LASTEXITCODE 'the Windows Unicode command line executes the packed representation'
Assert-Equal (Get-PrivilegedCollectionPlanSha256 $bytes) $observed 'inline packing preserves every byte of high-entropy source'
foreach($count in 1..9){
    $literal=[Convert]::ToBase64String([byte[]](1..$count))
    $observed=Invoke-QualificationInlineRepresentationNative -Binding $binding -Profile Padding -Inputs @{Count=$count}
    Assert-Equal $literal $observed 'short compressed streams preserve padding and final bytes'
}
$large=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(70000))
$refused=$false
try { $null=ConvertTo-PrivilegedCollectionInlineCommand -Source "'$large'" } catch {$refused=$_.Exception.Message -eq 'The reviewed privilege worker exceeds the Windows launch bound.'}
Assert-Equal $true $refused 'source expansion never relaxes the launch ceiling'
foreach($culture in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')){
    $source="[Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('$culture');'Synthetic 漢字 O''Brien'"
    $observed=Invoke-QualificationInlineRepresentationNative -Binding $binding -Profile Culture -Inputs @{Culture=$culture}
    Assert-Equal "Synthetic 漢字 O'Brien" $observed 'culture and quoting cannot alter the packed script'
}
$command=ConvertTo-PrivilegedCollectionInlineCommand -Source "'synthetic-not-executed'"
$match=[regex]::Match($command,'[\u4000-\u5080]+')
Assert-Equal $true $match.Success 'the bootstrap contains a bounded BMP representation'
$malformed=$command.Remove($match.Index,1).Insert($match.Index,([char]0x3000).ToString())
$null=Invoke-QualificationInlineRepresentationNative -Binding $binding -Profile Malformed -Inputs @{}
Assert-Equal $true ($LASTEXITCODE -ne 0) 'a character outside the packed alphabet is rejected'

# Exercise ShellExecute Unicode argument handling without the runas verb. This
# proves the OS parser path only; genuine UAC remains a private #161 gate.
$ownedRoot=$binding.Directory
$outputPath=Join-Path $ownedRoot ('result-'+[guid]::NewGuid().ToString('N')+'.txt')
$child=$null;$shellOwner=$null;$shellError=$null;$shellOperationError=$null
try {
    $source="[IO.File]::WriteAllText('"+$outputPath.Replace("'","''")+"','Synthetic 漢字 O''Brien',[Text.UTF8Encoding]::new(`$false))"
    $start=[Diagnostics.ProcessStartInfo]::new($hostPath)
    $start.UseShellExecute=$true;$start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    foreach($arg in @('-NoLogo','-NoProfile','-NonInteractive','-Command',(ConvertTo-PrivilegedCollectionInlineCommand $source))){$start.ArgumentList.Add($arg)}
    Assert-QualificationInlineRepresentationBinding -Binding $binding -HostPath $hostPath
    $shellOwner=New-QualificationCapabilityProcessOwner -RepositoryRoot $repositoryRoot -Profile PrivilegedInlineShellExecute -StartInfo $start -OutputPath $outputPath
    try {
        Assert-QualificationCapabilityCreation -Owner $shellOwner
        $child=[Diagnostics.Process]::Start($start)
        Register-QualificationCapabilityProcess -Owner $shellOwner -Process $child
        Assert-Equal $true (Wait-QualificationInlineShellBody -Owner $shellOwner) 'controlled ShellExecute exits within its deadline';Assert-Equal 0 $child.ExitCode 'controlled ShellExecute accepts exact Unicode arguments'
    }
    catch {$shellError=$_}
    finally {Complete-QualificationCapabilityProcess -Owner $shellOwner -Process $child -BodyError $shellError}
    Assert-Equal "Synthetic 漢字 O'Brien" ([IO.File]::ReadAllText($outputPath)) 'ShellExecute preserves source, quotes, and Unicode'
} catch {
    $shellOperationError=$_
    if (($null -ne $shellOwner -and $shellOwner.Unsafe) -or (Test-QualificationCleanupUnverified -Exception $_.Exception)) {$binding.Unsafe=$true;$binding.UnsafeError=$_}
} finally {
    # An uncertain writer retains its exact fixture and original native record.
    Complete-QualificationHarness -BodyError $shellOperationError -Cleanup @({
        if (-not $binding.Unsafe -and $null -ne $shellOwner -and $shellOwner.TerminalVerified -and $shellOwner.TerminalRetained) {
            $resolved=[IO.Path]::GetFullPath($outputPath)
            if(-not $resolved.StartsWith([IO.Path]::GetFullPath($ownedRoot)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected cleanup target.'}
            if([IO.File]::Exists($resolved)){[IO.File]::Delete($resolved)}
        }
    })
}
Write-Output 'PASS: exact inline source roundtrip, Windows Unicode launch, padding, and unchanged oversize refusal.'
}
catch {
    $bodyError=$_
    if($null -ne $binding -and (Test-QualificationCleanupUnverified -Exception $_.Exception)){$binding.Unsafe=$true;$binding.UnsafeError=$_}
}
finally {
    Complete-QualificationHarness -BodyError $bodyError -Cleanup @(
        {if($null -ne $binding){Close-QualificationInlineRepresentationBinding -Binding $binding}},
        {if($null -ne $candidate){Close-TestCandidate -Candidate $candidate -BodyError $bodyError}}
    )
}
