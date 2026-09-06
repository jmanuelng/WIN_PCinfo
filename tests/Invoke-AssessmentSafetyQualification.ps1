[CmdletBinding()]
param(
    [ValidateSet('Coverage','Cultures','Safety','Workers')] [string] $Mode = 'Safety',
    [Parameter(Mandatory)] [string] $ResultDirectory,
    [string] $CaseFilter = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$hostPath = Resolve-WinPCInfoRuntime -ApplicationPath $candidate
$provenance = [ordered]@{
    sourceRevision = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    candidateSha256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
    candidateBytes = (Get-Item -LiteralPath $candidate).Length
    powerShell = $PSVersionTable.PSVersion.ToString(); dotNet = [Environment]::Version.ToString()
    architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    windowsVersion = [Environment]::OSVersion.Version.ToString()
    inputs = @(foreach ($file in @('Invoke-AssessmentSafetyQualification.ps1','StatusDeskEngine.Tests.ps1',
        'AssessmentQualificationSupport.ps1','TestHarness.ps1','fixtures/assessment-safety-selection.json')) {
        [ordered]@{ file=$file; sha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $file) -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
}
$null = [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($ResultDirectory))
$cases = [Collections.Generic.List[object]]::new()
if ($Mode -eq 'Coverage') {
    $selection = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/assessment-safety-selection.json') -Raw | ConvertFrom-Json
    foreach ($family in $selection) {
        foreach ($scenario in $family.scenarios) {
            $cases.Add(@{ id="$($family.family)-$scenario"; arguments=@("-$($family.family)SourceScenario", $scenario) })
        }
    }
}
elseif ($Mode -eq 'Cultures') {
    $sources = [ordered]@{
        Readiness='Complete'; Identity='SystemAbsent'; Policy='MdmWindows11'; Security='Active'
        Platform='Running'; Remote='Configured'; Software='Complete'; Resource='Complete'
        Network='Complete'; Certificate='ValidTrusted'; Connectivity='Direct'
    }
    foreach ($culture in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')) {
        foreach ($family in $sources.Keys) {
            $cases.Add(@{ id="$family-$culture"; arguments=@("-$($family)SourceScenario", $sources[$family], '-QualificationCulture', $culture) })
        }
    }
}
elseif ($Mode -eq 'Workers') {
    foreach ($family in @('Software','Resource','Network','Certificate')) {
        foreach ($fault in @('Cancel','Timeout','Loss')) {
            $scenario = if($family -eq 'Certificate'){'ValidTrusted'}else{'Complete'}
            $cases.Add(@{ id="$family-$fault"; arguments=@("-$($family)SourceScenario",$scenario,
                '-QualificationWorkerFamily',$family,'-QualificationWorkerFault',$fault) })
        }
    }
}
else {
    foreach ($stage in @('Identity','Resource','Network','Software','Certificate','Connectivity')) {
        $cases.Add(@{ id="Cancel-$stage"; arguments=@('-QualificationCancelAfter', $stage) })
    }
    foreach ($boundary in @('Identity','Resource','Network','Software','Certificate','Connectivity','Firmware','Administrator','Policy')) {
        $cases.Add(@{ id="Prohibited-$boundary"; arguments=@('-QualificationProhibited', $boundary) })
    }
}
$results = [Collections.Generic.List[object]]::new()
foreach ($case in $cases) {
    if ($CaseFilter -and $case.id -notlike $CaseFilter) { continue }
    $resultPath = Join-Path ([IO.Path]::GetFullPath($ResultDirectory)) "$($case.id).json"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $arguments = @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'), '-QualificationPath', $resultPath) + $case.arguments
    & $hostPath @arguments
    if ($LASTEXITCODE -ne 0) { throw "Assessment qualification failed: $($case.id)" }
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    $results.Add([ordered]@{ id=$case.id; elapsedMilliseconds=$watch.ElapsedMilliseconds; evidence=$result })
    Write-Output "PASS: $Mode/$($case.id) in $($watch.ElapsedMilliseconds) ms."
}
if ($results.Count -eq 0) { throw 'Qualification selection matched no cases.' }
$summaryPath = Join-Path ([IO.Path]::GetFullPath($ResultDirectory)) "$Mode-summary.json"
[IO.File]::WriteAllText($summaryPath, ([ordered]@{ provenance=$provenance; results=$results.ToArray() } | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
