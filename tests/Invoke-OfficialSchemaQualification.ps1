[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$fixtureRoot = Join-Path $PSScriptRoot 'fixtures/json-schema-official'
$manifestPath = Join-Path $fixtureRoot 'source-manifest.json'
$selectionPath = Join-Path $fixtureRoot 'selection.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
    'a5951efb28a49b52006797f33cfb4b9a339cd5450b3090969af70450ab1b47b0') {
    throw 'The official source/hash/license manifest differs from the approved input.'
}
$selection = @(Get-Content -LiteralPath $selectionPath -Raw | ConvertFrom-Json)
$command = Get-Command Microsoft.PowerShell.Utility\Test-Json -CommandType Cmdlet
$clock = [Diagnostics.Stopwatch]::StartNew()

# Qualification is bound to the reviewed release vocabulary. A schema change
# requires an applicability review, not an automatic claim from old counts.
$schemaPins = [ordered]@{
    'assessment-record.schema.json' = 'c550ad7fcb86bb6d476f4da18c431b1c432f833ab5bbe34bfb5d4f1e5d327351'
    'assessment-contract-set.schema.json' = '84cbb34cf7db8f56f39ec5bb3db57f9cd7d57867f1160dfce654375645e392ff'
    'protected-package-envelope.schema.json' = '24976ea517f92c7338c77c9c30ba5ede082ea07c5dfffc89cb6f00d377c5cc85'
    'assessment-package-manifest.schema.json' = 'febfeb65bbc5909e00abecc4601cd98d9c262aecef8c6d496fe42b9af6ff72ec'
}
foreach ($name in $schemaPins.Keys) {
    $schemaText = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $PSScriptRoot) "schemas/$name")).Replace("`r`n", "`n").Replace("`r", "`n")
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($schemaText))).ToLowerInvariant()
    if ($digest -ne $schemaPins[$name]) { throw "Review official-case applicability for changed schema: $name" }
}
if ($manifest.commit -ne 'c9510e3bf8a896c3cba4e08509cf752b4f30dff8' -or
    $manifest.draftTree -ne 'db5782b10c73f2eee7bd3c9a0c57cfe24390e9b9' -or
    @($manifest.files | Where-Object file -like '*.json').Count -ne 24) {
    throw 'Official corpus differs from the approved pinned input.'
}

# Verify exact upstream bytes before any validator invocation. Git conversion is
# disabled for this fixture directory so checkout cannot change the corpus.
foreach ($file in $manifest.files) {
    $bytes = [IO.File]::ReadAllBytes((Join-Path $fixtureRoot $file.file))
    $header = [Text.Encoding]::UTF8.GetBytes("blob $($bytes.Length)`0")
    $blob = [Convert]::ToHexString([Security.Cryptography.SHA1]::HashData([byte[]] ($header + $bytes))).ToLowerInvariant()
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    if ($blob -ne $file.gitBlob -or $digest -ne $file.sha256 -or $bytes.Length -ne $file.bytes) {
        throw "Official corpus integrity failure: $($file.file)"
    }
}

$results = [Collections.Generic.List[object]]::new()
# Load the cmdlet's installed engine, then deny external document retrieval.
# No validator options are changed. Embedded resources and local pointers still
# use the ordinary registry; an unexpected retrieval fails this qualification.
$null = & $command -Json 'null' -Schema '{}'
$savedFetch = [Json.Schema.SchemaRegistry]::Global.Fetch
$fetches = [Collections.Generic.List[string]]::new()
[Json.Schema.SchemaRegistry]::Global.Fetch = [Func[Uri,Json.Schema.IBaseDocument]] {
    param($uri)
    $fetches.Add('UnexpectedExternalReference')
    throw 'Official qualification attempted external schema retrieval.'
}.GetNewClosure()
try {
foreach ($file in $manifest.files | Where-Object file -like '*.json') {
    $document = [Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText((Join-Path $fixtureRoot $file.file)))
    try {
        $groups = $document.RootElement
        $fileSelection = @($selection | Where-Object file -eq $file.file)
        if ($fileSelection.Count -ne $groups.GetArrayLength()) { throw "Incomplete selection: $($file.file)" }
        for ($groupIndex = 0; $groupIndex -lt $groups.GetArrayLength(); $groupIndex++) {
            $group = $groups[$groupIndex]
            $choice = @($fileSelection | Where-Object group -eq $groupIndex)
            if ($choice.Count -ne 1) { throw 'Duplicate or missing group selection' }
            $cases = $group.GetProperty('tests')
            if ($choice[0].description -cne $group.GetProperty('description').GetString() -or
                $choice[0].cases -ne $cases.GetArrayLength() -or
                [string]::IsNullOrWhiteSpace($choice[0].reason)) { throw 'Selection identity or disposition is incomplete.' }
            for ($caseIndex = 0; $caseIndex -lt $cases.GetArrayLength(); $caseIndex++) {
                $case = $cases[$caseIndex]
                $expected = $case.GetProperty('valid').GetBoolean()
                $actual = $null
                $errorIds = @()
                $status = 'NotApplicable'
                if ($choice[0].selected) {
                    $validationErrors = @()
                    $threw = $false
                    try {
                        # Same cmdlet arguments/configuration as ContractValidator.
                        # GetRawText avoids PowerShell number/date/array coercion.
                        $actual = & $command -Json $case.GetProperty('data').GetRawText() `
                            -Schema $group.GetProperty('schema').GetRawText() `
                            -ErrorAction SilentlyContinue -ErrorVariable validationErrors
                    }
                    catch { $threw = $true; $validationErrors += $_ }
                    $errorIds = @($validationErrors | ForEach-Object FullyQualifiedErrorId | Sort-Object -Unique)
                    $unexpectedErrors = @($errorIds | Where-Object {
                        $_ -ne 'InvalidJsonAgainstSchemaDetailed,Microsoft.PowerShell.Commands.TestJsonCommand'
                    })
                    $status = if (-not $threw -and $unexpectedErrors.Count -eq 0 -and
                        $actual -is [bool] -and $actual -eq $expected) { 'Pass' } else { 'Fail' }
                }
                $results.Add([ordered]@{
                    id = "$($file.file):$groupIndex`:$caseIndex"
                    group = $group.GetProperty('description').GetString()
                    description = $case.GetProperty('description').GetString()
                    expected = $expected; actual = $actual; status = $status
                    reason = $choice[0].reason; errorIds = $errorIds
                })
            }
        }
    }
    finally { $document.Dispose() }
}
}
finally { [Json.Schema.SchemaRegistry]::Global.Fetch = $savedFetch }
if ($fetches.Count -ne 0) { throw 'Selected official cases required external retrieval.' }
$assemblies = @(foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
    if ($assembly.GetName().Name -in @('Microsoft.PowerShell.Commands.Utility', 'JsonSchema.Net', 'JsonPointer.Net', 'Json.More')) {
        [ordered]@{
            name = $assembly.GetName().Name; version = $assembly.GetName().Version.ToString()
            fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($assembly.Location).FileVersion
            sha256 = (Get-FileHash -LiteralPath $assembly.Location -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
})
$clock.Stop()
$summary = [ordered]@{
    pass = @($results | Where-Object status -eq 'Pass').Count
    fail = @($results | Where-Object status -eq 'Fail').Count
    notApplicable = @($results | Where-Object status -eq 'NotApplicable').Count
}
$report = [ordered]@{
    upstreamCommit = $manifest.commit; draftTree = $manifest.draftTree
    manifestSha256 = (Get-FileHash $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    selectionSha256 = (Get-FileHash $selectionPath -Algorithm SHA256).Hash.ToLowerInvariant()
    runnerSha256 = (Get-FileHash $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    powerShell = $PSVersionTable.PSVersion.ToString(); dotNet = [Environment]::Version.ToString()
    architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    cmdlet = "$($command.ModuleName)\$($command.Name)"; assemblies = $assemblies
    cmdletOptions = @(); formatBehavior = 'AnnotationOnly'; externalFetches = $fetches.Count
    releaseSchemas = $schemaPins
    elapsedMilliseconds = $clock.ElapsedMilliseconds; summary = $summary; results = @($results.ToArray())
}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($ResultPath), ($report | ConvertTo-Json -Depth 12) + "`n", [Text.UTF8Encoding]::new($false))
$summary | ConvertTo-Json -Compress
if ($summary.fail -gt 0) { exit 1 }
