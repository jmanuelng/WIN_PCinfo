[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput((Get-PrivilegedCollectionWorkerSource),[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq 'Read-CiToolJson'},$false)
$source=$node.Extent.Text.Replace('[IO.File]::Exists($path)','(Test-ControlledCiToolPath $path)').Replace('[IO.File]::GetAttributes($path)','[IO.FileAttributes]::Normal').Replace('[Diagnostics.Process]::Start($start)','(Start-ControlledCiTool $start)')
. ([scriptblock]::Create($source))
function Test-ControlledCiToolPath($Path){
    Assert-Equal ([IO.Path]::Combine([Environment]::SystemDirectory,'CiTool.exe')) $Path 'CiTool cannot resolve through PATH or caller input'
    $true
}
$children=[Collections.Generic.List[int]]::new()
function Start-ControlledCiTool($Start){
    Assert-Equal '-lp,-json' ($Start.ArgumentList -join ',') 'only the fixed JSON inventory switches may execute'
    Assert-Equal $false $Start.UseShellExecute 'listing uses the owned direct process path'
    $scriptText=switch($case){
        Valid {'[Console]::Write(''{"Policies":[]}'')'}
        Bound {'[Console]::Write((''x''*65537))'}
        Denied {'exit 5'}
        Timeout {'[Threading.Thread]::Sleep(10000)'}
        NonUtf8 {'[Console]::OpenStandardOutput().WriteByte(255)'}
    }
    $Start.FileName=$hostPath;$Start.ArgumentList.Clear()
    foreach($argument in @('-NoLogo','-NoProfile','-NonInteractive','-Command',$scriptText)){$Start.ArgumentList.Add($argument)}
    $child=[Diagnostics.Process]::Start($Start);$children.Add($child.Id);$child
}
foreach($case in @('Valid','Bound','Denied','Timeout','NonUtf8')){
    $watch=[Diagnostics.Stopwatch]::StartNew();$failed=$false;$value=$null
    try {$value=Read-CiToolJson}catch{$failed=$true}
    Assert-Equal ($case -ne 'Valid') $failed 'native output, errors and deadlines remain bounded before parsing'
    if($case -eq 'Valid'){Assert-Equal '{"Policies":[]}' $value 'the native boundary preserves exact JSON bytes'}
    Assert-Equal $true ($watch.Elapsed.TotalSeconds -lt 5) 'native listing and cleanup stay within the operation budget'
    foreach($childId in $children){Assert-Equal 0 @(Get-Process -Id $childId -ErrorAction SilentlyContinue).Count 'no controlled CiTool child survives source completion'}
}
Write-Output 'PASS: real controlled child I/O, byte bound, denied exit, deadline, UTF-8 refusal, and owned child absence; no CiTool executed.'
