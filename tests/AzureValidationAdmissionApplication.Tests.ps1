[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policy = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-azure-validation-admission.json'
) -Raw | ConvertFrom-Json -Depth 20
$verdictSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-admission-verdict.schema.json'
$oneClientPath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-one-client.json'
$fiveRequestPath = Join-Path ([System.IO.Path]::GetTempPath()) (
    'win-pcinfo-azure-admission-five-' + [guid]::NewGuid().ToString('N') + '.json'
)

$workRoot = Join-Path $repositoryRoot '.test-output/azure-validation-admission-application'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force
$candidatePath = Join-Path $workRoot 'WIN-PCInfo.ps1'
$null = & (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath

function New-MarkedWorkspace {
    param([Parameter(Mandatory)] [string] $Name)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-azure-app-$Name"
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $path -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $path $policy.privacy.markerFileName),
        ($policy.privacy.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $path
}

$safeWorkspace = New-MarkedWorkspace -Name 'safe'
$repoWorkspace = Join-Path $workRoot 'forbidden-in-repo'
$null = New-Item -ItemType Directory -Path $repoWorkspace -Force
[System.IO.File]::WriteAllText(
    (Join-Path $repoWorkspace $policy.privacy.markerFileName),
    ($policy.privacy.markerContent + "`n"),
    [System.Text.UTF8Encoding]::new($false)
)

try {
    $admitted = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'AdmitValidationRound',
        '-ValidationRoundRequestPath', $oneClientPath,
        '-ValidationPrivateWorkspacePath', $safeWorkspace
    )
    Assert-Equal 0 $admitted.ExitCode 'the generated application admits a one-client synthetic plan'
    $progress = @($admitted.Records | Where-Object recordType -eq 'win-pcinfo.progress')
    $verdict = @($admitted.Records | Where-Object recordType -eq 'win-pcinfo.azure-validation-admission')
    $terminal = @($admitted.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 2 $progress.Count 'admission emits structured start and finish progress'
    Assert-Equal 'validation.admission.started' $progress[0].messageId 'admission starts with a stable message'
    Assert-Equal 'validation.admission.succeeded' $progress[1].messageId 'admission success uses a stable message'
    Assert-Equal 1 $verdict.Count 'admission emits one sanitized verdict'
    Assert-Equal 'Admitted' $verdict[0].state 'the generated application reports Admitted'
    Assert-Equal $false $verdict[0].azureContacted 'the generated application does not contact Azure'
    Assert-Equal $true $verdict[0].rendered 'the generated application renders only after admission'
    Assert-Equal $true (Test-Json -Json ($verdict[0] | ConvertTo-Json -Compress -Depth 10) `
        -SchemaFile $verdictSchemaPath) 'the application verdict satisfies the public schema'
    Assert-Equal $false (($verdict[0] | ConvertTo-Json -Compress -Depth 10) -match [regex]::Escape($safeWorkspace)) `
        'the application verdict omits the private workspace path'
    Assert-Equal 1 $terminal.Count 'admission ends with one terminal record'
    Assert-Equal 'Completed' $terminal[0].outcome 'admitted rounds complete without collection'
    Assert-Equal 'VALIDATION.ROUND_ADMITTED' $terminal[0].reasonCode 'the terminal reason matches admission'
    Assert-Equal $false $terminal[0].collectionStarted 'admission never starts assessment collection'
    Assert-Equal $true (Test-Path -LiteralPath (Join-Path $safeWorkspace "$($policy.renderedDirectoryName)/versions.tf")) `
        'the generated application writes generic Terraform only to the private workspace'

    $five = Get-Content -LiteralPath $oneClientPath -Raw | ConvertFrom-Json -Depth 20
    $five.clients = @($five.clients[0], $five.clients[0], $five.clients[0], $five.clients[0], $five.clients[0])
    [System.IO.File]::WriteAllText(
        $fiveRequestPath,
        ($five | ConvertTo-Json -Depth 20),
        [System.Text.UTF8Encoding]::new($false)
    )
    $fiveWorkspace = New-MarkedWorkspace -Name 'five'
    $rejected = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'AdmitValidationRound',
        '-ValidationRoundRequestPath', $fiveRequestPath,
        '-ValidationPrivateWorkspacePath', $fiveWorkspace
    )
    Assert-Equal 20 $rejected.ExitCode 'an unsafe fifth client ends NotStarted'
    $rejectedVerdict = @($rejected.Records | Where-Object recordType -eq 'win-pcinfo.azure-validation-admission')
    $rejectedTerminal = @($rejected.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'Rejected' $rejectedVerdict[0].state 'the generated application rejects a fifth client'
    Assert-Equal 'VALIDATION.CLIENT_COUNT_UNSAFE' $rejectedVerdict[0].reasonCode `
        'the generated application uses the fifth-client reason'
    Assert-Equal $false $rejectedVerdict[0].rendered 'rejected application plans are not rendered'
    Assert-Equal $false (Test-Path -LiteralPath (Join-Path $fiveWorkspace $policy.renderedDirectoryName)) `
        'the generated application does not render rejected plans'
    Assert-Equal 'NotStarted' $rejectedTerminal[0].outcome 'rejected admission stays NotStarted'
    Assert-Equal $false $rejectedTerminal[0].collectionStarted 'rejected admission never collects'
    Remove-Item -LiteralPath $fiveWorkspace -Recurse -Force

    $repoRejected = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'AdmitValidationRound',
        '-ValidationRoundRequestPath', $oneClientPath,
        '-ValidationPrivateWorkspacePath', $repoWorkspace
    )
    Assert-Equal 20 $repoRejected.ExitCode 'a repository workspace ends NotStarted'
    $repoVerdict = @($repoRejected.Records | Where-Object recordType -eq 'win-pcinfo.azure-validation-admission')
    Assert-Equal 'VALIDATION.WORKSPACE_REPOSITORY_PATH' $repoVerdict[0].reasonCode `
        'the generated application rejects an in-repository workspace'
    Assert-Equal $false $repoVerdict[0].rendered 'in-repository workspaces are not rendered'
    Assert-Equal $false (Test-Path -LiteralPath (Join-Path $repoWorkspace $policy.renderedDirectoryName)) `
        'the generated application never writes Terraform into the repository tree'
}
finally {
    if (Test-Path -LiteralPath $safeWorkspace) {
        Remove-Item -LiteralPath $safeWorkspace -Recurse -Force
    }
    if (Test-Path -LiteralPath $fiveRequestPath) {
        Remove-Item -LiteralPath $fiveRequestPath -Force
    }
}

Write-Output 'PASS: generated-application admission stays offline and private.'
