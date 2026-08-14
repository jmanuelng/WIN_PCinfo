[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$tamperedPath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo-recognition-tampered.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

function Invoke-RecognitionApplicationFixture {
    param([Parameter(Mandatory)] [string] $Name, [string] $ApplicationPath = $candidatePath)
    Invoke-GeneratedApplication -CandidatePath $ApplicationPath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,
        '-SoftwareInventoryFixturePath',(
            Join-Path $PSScriptRoot "fixtures/software-inventory/$Name.json"
        )
    )
}

$recognized = Invoke-RecognitionApplicationFixture -Name 'recognition'
$projection = @($recognized.Records | Where-Object recordType -eq `
    'win-pcinfo.software-inventory-validation')[0]
$terminal = @($recognized.Records | Where-Object recordType -eq 'win-pcinfo.terminal')[0]
Assert-Equal 10 $recognized.ExitCode 'Local Only network gaps remain honest after recognition'
Assert-Equal 'CompletedWithGaps' $terminal.outcome `
    'recognized and unknown applications are safe annotations rather than warnings or run failures'
Assert-Equal 5 $projection.registrationCount 'ordinary inventory remains complete and authoritative'
Assert-Equal 5 $projection.recognitionAnnotationCount `
    'every observed application receives one Software Recognition Outcome'
Assert-Equal 1 $projection.recognizedExactCount `
    'the release-seed PFN is recognized through the generated public application'
Assert-Equal 4 $projection.unrecognizedCount `
    'an unknown application remains ordinary inventory without suspicion'
Assert-Equal $false $projection.recognitionCreatedAssessmentFinding `
    'recognition is never promoted into an Assessment Finding by itself'
Assert-Equal $true $projection.beginnerReportVerified `
    'the protected report explains recognition and match strength'
Assert-Equal $true $projection.protectedPackageVerified `
    'recognition annotations survive protected packaging and reopening'

$logical = Invoke-RecognitionApplicationFixture -Name 'recognition-logical-failure'
$logicalProjection = @($logical.Records | Where-Object recordType -eq `
    'win-pcinfo.software-inventory-validation')[0]
$logicalTerminal = @($logical.Records | Where-Object recordType -eq 'win-pcinfo.terminal')[0]
Assert-Equal 5 $logicalProjection.registrationCount `
    'ordinary inventory survives a logical catalog evaluation failure'
Assert-Equal 5 $logicalProjection.notEvaluatedCount `
    'logical failure safely annotates every application NotEvaluated'
Assert-Equal 'CompletedWithGaps' $logicalTerminal.outcome `
    'a logical catalog failure is confined and unrelated assessment work completes'
Assert-Equal $true $logicalProjection.beginnerReportVerified `
    'NotEvaluated receives a safe beginner explanation rather than a warning'
Assert-Equal $true $logicalProjection.protectedPackageVerified `
    'NotEvaluated annotations remain available in the protected package'

$candidateText = [IO.File]::ReadAllText($candidatePath)
$pattern = "(?m)^(\`$script:SoftwareRecognitionCatalogBase64 = ')([^']+)(')\r?$"
$match = [regex]::Match($candidateText, $pattern)
if (-not $match.Success) { throw 'The generated catalog resource boundary was not found.' }
$base64 = $match.Groups[2].Value
$replacementCharacter = if ($base64[0] -eq 'A') { 'B' } else { 'A' }
$tamperedBase64 = $replacementCharacter + $base64.Substring(1)
$tamperedText = $candidateText.Substring(0, $match.Groups[2].Index) + $tamperedBase64 +
    $candidateText.Substring($match.Groups[2].Index + $match.Groups[2].Length)
[IO.File]::WriteAllText($tamperedPath, $tamperedText, [Text.UTF8Encoding]::new($true))
try {
    $tampered = Invoke-RecognitionApplicationFixture -Name 'recognition' `
        -ApplicationPath $tamperedPath
    $tamperedTerminal = @($tampered.Records | Where-Object recordType -eq `
        'win-pcinfo.terminal')[-1]
    Assert-Equal 20 $tampered.ExitCode `
        'a catalog digest mismatch uses the stable NotStarted exit code'
    Assert-Equal 'NotStarted' $tamperedTerminal.outcome `
        'authenticated-resource alteration stops before collection'
    Assert-Equal 'SOFTWARE_RECOGNITION.INTEGRITY_FAILED' $tamperedTerminal.reasonCode `
        'catalog authentication has one typed no-bypass failure reason'
    Assert-Equal $false $tamperedTerminal.collectionStarted `
        'no device collector starts after a catalog digest mismatch'
}
finally {
    if (Test-Path -LiteralPath $tamperedPath -PathType Leaf) {
        Remove-Item -LiteralPath $tamperedPath -Force
    }
}

Write-Output 'PASS: the generated application preserves inventory, annotates safely, packages outcomes, and fails closed on catalog alteration.'
