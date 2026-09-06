[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$resultRoot = Join-Path $repositoryRoot ('.test-output/official-schema-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($resultRoot)
try {
    $resultPath = Join-Path $resultRoot 'results.json'
    & (Join-Path $PSScriptRoot 'Invoke-OfficialSchemaQualification.ps1') -ResultPath $resultPath
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    Assert-Equal 0 $result.summary.fail 'the installed release validator satisfies every selected official case'
    Assert-Equal 573 $result.summary.pass 'the reviewed selection cannot silently lose applicable cases'
    Assert-Equal 177 $result.summary.notApplicable 'every excluded official case has an explicit disposition'
    Assert-Equal 0 $result.externalFetches 'selected reference resolution remains offline'
}
finally {
    $resolved = [IO.Path]::GetFullPath($resultRoot)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))) {
        throw 'Official qualification cleanup escaped its owned parent.'
    }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved, $true) }
}
Write-Output 'PASS: pinned official Draft 2020-12 release selection, raw JSON, offline references and format annotations.'
