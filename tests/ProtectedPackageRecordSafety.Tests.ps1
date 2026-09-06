[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'PackageSafetyTestSupport.ps1')
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions = [regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$root = Join-Path $repositoryRoot ('.test-output/package-record-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
try {
    $originalText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
    $record = [Text.Encoding]::UTF8.GetBytes($originalText)
    $report = [Text.Encoding]::UTF8.GetBytes('<html>synthetic incompatible record qualification</html>')
    $inner = New-DeterministicAssessmentPackage -Artifacts ([ordered]@{
        'assessment-record.json' = $record; 'assessment-report.html' = $report
    }) -AssessmentContractSetVersion 1.0.0 -Completeness Complete
    $cases = [ordered]@{
        major = { param($r) $r.contractVersion = '99.0.0' }
        feature = { param($r) $r.requiredFeatures += 'unknown-required-feature' }
        field = { param($r) $r.observations[0].fieldId = 'field:undeclared.secret' }
        reference = { param($r) $r.observations[0].subjectId = 'subject:missing' }
        graph = { param($r) $r.recommendationRelationships += [pscustomobject]@{
            relationshipId = 'relationship:synthetic-cycle'
            fromRecommendationId = $r.recommendations[0].recommendationId
            toRecommendationId = $r.recommendations[0].recommendationId; kind = 'Requires' } }
        coverage = { param($r) $r.coverage[0].state = 'InventedSuccess' }
        bound = { param($r) $r.observations[0].value = '界' * 5000 }
        prohibited = { param($r) $r.observations[0] | Add-Member -NotePropertyName password -NotePropertyValue 'synthetic-never-retain-154' }
    }
    foreach ($name in @($cases.Keys) + @('duplicate', 'unicode', 'unsafe-integer')) {
        $changed = $originalText | ConvertFrom-Json -Depth 30
        if ($cases.Contains($name)) {
            & $cases[$name] $changed
            $bytes = [Text.Encoding]::UTF8.GetBytes(($changed | ConvertTo-Json -Depth 30 -Compress))
        }
        else {
            $text = switch ($name) {
                duplicate { $originalText.Replace('"contractVersion": "1.0.0"', '"contractVersion":"99.0.0","contractVersion":"1.0.0"') }
                unicode { $originalText.Replace('"contractVersion": "1.0.0"', '"contractVersion":"\uD800"') }
                unsafe-integer { $changed.observations[0].value = 9007199254740992L; $changed | ConvertTo-Json -Depth 30 -Compress }
            }
            $bytes = [Text.Encoding]::UTF8.GetBytes($text)
        }
        $semanticReason = @{ major='CONTRACT.VERSION_INCOMPATIBLE'; feature='CONTRACT.REQUIRED_FEATURE_UNSUPPORTED'; graph='CONTRACT.GRAPH_INVALID' }
        if ($semanticReason.ContainsKey($name)) {
            $validation = Test-AssessmentContract -Utf8Bytes $bytes -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet) -TestJsonCommand (Get-Command Test-Json -CommandType Cmdlet)
            Assert-Equal $semanticReason[$name] $validation.reasonCode 'the hostile fixture reaches the intended semantic gate before authenticated packaging'
        }
        $before = @([IO.Directory]::EnumerateFileSystemEntries($root) | Sort-Object)
        $finalization = New-ProtectedEvidencePackage -DestinationDirectory $root -Artifacts ([ordered]@{
            'assessment-record.json' = $bytes; 'assessment-report.html' = $report
        }) -AssessmentContractSetVersion 1.0.0 -Completeness Complete
        Assert-Equal 'IntegrityFailed' $finalization.state "$name cannot reach final naming"
        Assert-Equal $true ($null -eq $finalization.packagePath) "$name exposes no final package path"
        Assert-Equal ($before -join '|') (@([IO.Directory]::EnumerateFileSystemEntries($root) | Sort-Object) -join '|') "$name leaves no provisional archive"
        $hostile = New-AuthenticatedTestArchive -Record $bytes -Report $report -Manifest $inner.manifest
        $path = Join-Path $root "$name.winpcinfo"
        $null = Write-ProtectedPackageEnvelope -Plaintext $hostile -LiteralPath $path
        $opened = Read-ProtectedEvidencePackage -LiteralPath $path
        Assert-Equal 'IntegrityFailed' $opened.state "$name is rejected inside correctly authenticated ciphertext with matching artifact digests"
        Assert-Equal $true ($null -eq $opened.artifacts) "$name exposes no decrypted artifacts"
        $before = @([IO.Directory]::EnumerateFileSystemEntries($root) | Sort-Object)
        $view = Open-EvidenceViewingSession -PackagePath $path -RequestedArtifact 'assessment-report.html' -ViewingBasePath $root
        Assert-Equal 'IntegrityFailed' $view.state "$name cannot be viewed"
        Assert-Equal ($before -join '|') (@([IO.Directory]::EnumerateFileSystemEntries($root) | Sort-Object) -join '|') "$name creates no viewing artifact or journal"
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($hostile)
        Write-Output "PASS: authenticated package record $name refused before naming, admission and viewing."
    }
}
finally {
    $resolved = [IO.Path]::GetFullPath($root)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))) { throw 'Record test cleanup escaped its parent.' }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved, $true) }
}
