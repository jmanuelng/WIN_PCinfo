[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
Assert-QualificationCleanupReady

# Run the actual replay file through the real native-output guard. Expected
# injected signals must remain local even though the real guard rejects them.
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @(
    '-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'QualificationFixtureFinalizers.Tests.ps1')
)

$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'QualificationFixtureFinalizers.Tests.ps1'),[ref]$tokens,[ref]$errors)
Assert-Equal 0 @($errors).Count 'actual replay source parses'
$outer=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[-1]
$text=$outer.Finally.Extent.Text
$actualOuterFinalizer=[scriptblock]::Create($text.Substring(1,$text.Length-2))
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$testRoot=Join-Path $repositoryRoot ('.test-output/fixture-signal-isolation-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($testRoot)
$testBodyError=$null

function Invoke-InjectedOuterFailure {
    # No child or worker is started. A deliberately wrong boundary exercises the
    # actual outer finalizer's safety check, not a replacement cleanup function.
    $fixtureRoot=Join-Path $testRoot 'synthetic-root'
    $repositoryRoot=Join-Path $testRoot 'wrong-boundary'
    $replayBodyError=$null
    $marker=Join-Path $testRoot 'synthetic-outer-blocker.json'
    function Get-QualificationCleanupBlockerPath { $marker }
    $originalBlockerFunction=(Get-Command Get-QualificationCleanupBlockerPath -CommandType Function).ScriptBlock
    $output=[Collections.Generic.List[object]]::new()
    $caught=$null
    try { . $actualOuterFinalizer | ForEach-Object {$output.Add($_)} }
    catch { $caught=$_ }
    Assert-Equal $true ($null-ne$caught-and(Test-QualificationCleanupUnverified -Exception $caught.Exception)) 'actual outer cleanup failure remains unsafe'
    Assert-Equal 1 @($output | Where-Object {$_.ToString() -ceq 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'}).Count 'actual outer finalizer propagates its native sentinel'
    Assert-Equal $true ([IO.File]::Exists($marker)) 'actual outer failure retains its synthetic blocker'
    $nativeGuardError=$null
    try { Assert-QualificationCleanupSignal -Output $output.ToArray() }
    catch { $nativeGuardError=$_ }
    Assert-Equal $true ($null-ne$nativeGuardError-and(Test-QualificationCleanupUnverified -Exception $nativeGuardError.Exception)) 'unchanged parent guard still rejects actual outer failure output'
}
try { Invoke-InjectedOuterFailure }
catch { $testBodyError=$_ }
finally {
    Complete-QualificationHarness -BodyError $testBodyError -Cleanup @({
        $allowed=[IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) '.test-output'))+[IO.Path]::DirectorySeparatorChar
        $resolved=[IO.Path]::GetFullPath($testRoot)
        if(-not$resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Signal-isolation cleanup escaped its synthetic root.'}
        if([IO.Directory]::Exists($resolved)){
            if(([IO.File]::GetAttributes($resolved)-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'Signal-isolation root is a reparse point.'}
            [IO.Directory]::Delete($resolved,$true)
        }
        if([IO.Directory]::Exists($resolved)){throw 'Signal-isolation synthetic root remains unverified.'}
    })
}
Write-Output 'PASS: actual injected replay output is contained; actual outer cleanup failure still reaches the unchanged native guard.'
