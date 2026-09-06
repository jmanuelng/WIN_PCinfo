[CmdletBinding()]
param([string[]] $Scenario = @('UserNamespace','ContextMismatch','ContextDenied',
    'ContextUnavailable','ContextChanged','DifferentSession','ReferenceCollision',
    'CimReference','SecurityDenied','SecurityAbsent','RightsBound','MdmConflict',
    'MdmWindows11','MdmDenied','MdmAbsent','MdmUnsupportedBuild','MdmMissingProperty','MdmUnavailable',
    'DomainPrecedence','MalformedReference','LateIdentityChange'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1')
foreach ($case in $Scenario) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -PolicySourceScenario $case
    if ($LASTEXITCODE -ne 0) { throw "Generated policy source scenario $case failed." }
    Write-Output ('PASS: policy source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
