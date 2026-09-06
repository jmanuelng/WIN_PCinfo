[CmdletBinding()]
param([string[]] $Scenario = @('Workgroup','DomainJoined','Registered','EntraJoined',
    'SeparateUser','DifferentSession','UserDenied','UserUnavailable','WorkSchoolDenied',
    'Unavailable','AadMalformed','NoJoinSuccess','UnknownJoin','MissingIdentifiers',
    'Administrator','LocalSystem','SessionChanged','AdminDenied','AdminUnavailable',
    'AdminEmpty','AdminPartial','SystemDenied','SystemUnavailable','SystemAbsent'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath $candidate
foreach ($case in $Scenario) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -IdentitySourceScenario $case
    if ($LASTEXITCODE -ne 0) { throw "Generated identity source scenario $case failed." }
    Write-Output ('PASS: identity source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
