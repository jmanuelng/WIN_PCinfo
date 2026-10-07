[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$diagnostic = Join-Path $PSScriptRoot 'Get-QualificationInventoryOperands.ps1'
$root = Join-Path $repositoryRoot ('.test-output/inventory-operands-' + [guid]::NewGuid().ToString('N'))
$fixtureTests = Join-Path $root 'tests'
# Fixture allocation occurs inside the protected body below.
$manifestPath = Join-Path $fixtureTests 'qualification-resource-writers.json'
$candidate = Join-Path $root 'inert-candidate.ps1'
$harness = Join-Path $fixtureTests 'StatusDeskEngine.Tests.ps1'
$utf8 = [Text.UTF8Encoding]::new($false)
$results = [Collections.Generic.List[object]]::new()
$fixtureInputEvidence = [Collections.Generic.List[object]]::new()
$bodyError = $null
$finalizationErrors = [Collections.Generic.List[Exception]]::new()
$cleanupVerified = $false

function Assert-OperandCheck([bool] $Condition, [string] $Because) {
    if (-not $Condition) { throw $Because }
}
try {
    $null = [IO.Directory]::CreateDirectory($fixtureTests)
    # Copy the actual implementation unchanged so its original manifest lookup
    # uses this owned fixture, never the canonical inventory.
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'QualificationDiskBounds.ps1') -Destination $fixtureTests
    . (Join-Path $fixtureTests 'QualificationDiskBounds.ps1')
    [IO.File]::WriteAllText($candidate, "# inert candidate`n", $utf8)
    [IO.File]::WriteAllText($harness, "# inert harness`n", $utf8)
    $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'qualification-resource-writers.json') -Raw | ConvertFrom-Json
    $manifest.candidateSha256 = (Get-FileHash -LiteralPath $candidate).Hash.ToLowerInvariant()
    $manifest.harnessSha256 = Get-QualificationScriptIdentity -LiteralPath $harness
    # The governing repository registry is never written. This synthetic candidate
    # and inert harness belong only to the unique fixture. Copy all original
    # closed inputs byte-for-byte, retaining their actual source identities;
    # none of those source files executes.
    $fixtureInputEvidence = [Collections.Generic.List[object]]::new()
    foreach ($vector in @('inputs', 'executorInputs')) {
        $expectedPaths = if ($vector -ceq 'inputs') { @(Get-QualificationInventoryInputPaths) } else { @(Get-QualificationInventoryExecutorPaths) }
        $entries = @($manifest.$vector)
        Assert-OperandCheck ($entries.Count -eq $expectedPaths.Count) 'fixture requires the original closed input count'
        for ($index = 0; $index -lt $expectedPaths.Count; $index++) {
            Assert-OperandCheck ($entries[$index].path -ceq $expectedPaths[$index]) 'fixture requires the original ordered input paths'
            $source = Join-Path $repositoryRoot $expectedPaths[$index]
            $destination = Join-Path $root $expectedPaths[$index]
            # QualificationDiskBounds was copied and loaded above; every other
            # member is inert source custody for the real binder.
            if ($expectedPaths[$index] -cne 'tests/QualificationDiskBounds.ps1') {
                Copy-Item -LiteralPath $source -Destination $destination
            }
            $sourceSha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
            $copiedSha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
            Assert-OperandCheck ($copiedSha256 -ceq $sourceSha256) 'fixture input must be an exact source copy'
            $entries[$index].sha256 = Get-QualificationScriptIdentity -LiteralPath $destination
            $fixtureInputEvidence.Add([ordered]@{ vector=$vector; relativePath=$expectedPaths[$index]; sourceSha256=$sourceSha256; copiedSha256=$copiedSha256; canonicalSha256=$entries[$index].sha256 })
        }
    }
    $baseline = $manifest | ConvertTo-Json -Depth 20
    $instrumentedRoot = Join-Path $root 'must-not-be-created'
    foreach ($fault in @('Exact', 'CandidateChanged', 'CandidateRepresentation', 'HarnessChanged', 'HarnessRepresentation', 'UppercaseDeclaration',
        'CandidateMissing', 'HarnessMissing', 'KindMissing', 'CandidateMalformed', 'HarnessMalformed',
        'CandidateStale', 'HarnessStale', 'KindChanged', 'MalformedJson')) {
        $row = [ordered]@{ fault=$fault; identityAccepted=$false; originalAdmissionMessage=$null; originalAdmissionOperands=$null; comparison=$null; completed=$false }
        $results.Add($row)
        $manifest = $baseline | ConvertFrom-Json
        [IO.File]::WriteAllText($candidate, "# inert candidate`n", $utf8)
        [IO.File]::WriteAllText($harness, "# inert harness`n", $utf8)
        switch ($fault) {
            'CandidateChanged' { [IO.File]::AppendAllText($candidate, '# changed', $utf8) }
            'CandidateRepresentation' { [IO.File]::WriteAllText($candidate, "# inert candidate`r`n", [Text.UTF8Encoding]::new($true)) }
            'HarnessChanged' { [IO.File]::AppendAllText($harness, '# changed', $utf8) }
            'HarnessRepresentation' { [IO.File]::WriteAllText($harness, "# inert harness`r`n", [Text.UTF8Encoding]::new($true)) }
            'UppercaseDeclaration' { $manifest.candidateSha256 = $manifest.candidateSha256.ToUpperInvariant(); $manifest.harnessSha256 = $manifest.harnessSha256.ToUpperInvariant() }
            'CandidateMissing' { $manifest.PSObject.Properties.Remove('candidateSha256') }
            'HarnessMissing' { $manifest.PSObject.Properties.Remove('harnessSha256') }
            'KindMissing' { $manifest.PSObject.Properties.Remove('sourceIdentityKind') }
            'CandidateMalformed' { $manifest.candidateSha256 = 7 }
            'HarnessMalformed' { $manifest.harnessSha256 = @('invalid') }
            'CandidateStale' { $manifest.candidateSha256 = '0' * 64 }
            'HarnessStale' { $manifest.harnessSha256 = '0' * 64 }
            'KindChanged' { $manifest.sourceIdentityKind = 'RawBytes' }
        }
        $json = if ($fault -eq 'MalformedJson') { '{' } else { $manifest | ConvertTo-Json -Depth 20 }
        [IO.File]::WriteAllText($manifestPath, $json, $utf8)
        $positive = $fault -in @('Exact', 'HarnessRepresentation')
        $row.identityAccepted = [bool]$positive
        $comparison = $null
        if ($fault -ne 'MalformedJson') {
            $comparison = & $diagnostic -ManifestPath $manifestPath -CandidatePath $candidate -HarnessPath $harness
            $row.comparison = $comparison
            Assert-OperandCheck ($comparison.identityOperandsMatch -eq $positive) "$fault diagnostic verdict"
            if ($fault -in @('CandidateChanged', 'CandidateRepresentation')) {
                Assert-OperandCheck (-not $comparison.candidateMatches -and $comparison.harnessMatches) 'candidate mutation must isolate the candidate operand'
            }
            if ($fault -eq 'HarnessChanged') {
                Assert-OperandCheck ($comparison.candidateMatches -and -not $comparison.harnessMatches) 'harness mutation must isolate the harness operand'
            }
        }
        # Invalid module text is a downstream sentinel: exact identities reach
        # the real parser, while every bad declaration refuses before it. No
        # input script, generated workload, writer or native process executes.
        $message = $null
        try {
            $null = New-QualificationDiskInstrumentation -ModuleText 'function {' -Root $instrumentedRoot -CandidatePath $candidate -HarnessPath $harness
        }
        catch {
            $message = $_.Exception.Message
            $row.originalAdmissionOperands = $_.Exception.Data['QualificationInventoryOperands']
        }
        $row.originalAdmissionMessage = $message
        Assert-OperandCheck ($null -ne $message) "$fault real admission must terminate at its expected boundary"
        Assert-OperandCheck (($message -eq 'Qualification writer source does not parse.') -eq $positive) "$fault real admission disagrees with operand diagnosis"
        Assert-OperandCheck (-not [IO.Directory]::Exists($instrumentedRoot)) "$fault created an instrumentation root"
        $row.completed = $true
    }
    Write-Output "PASS: $($results.Count) pure inventory operand controls; exact and normalized harness identities reach the downstream parser; mutations and invalid declarations refuse."
}
catch { $bodyError = $_ }
finally {
    # Cleanup and evidence retention are independent; neither may hide the
    # original fault or prevent the other attempt.
    try {
        $resolvedRoot = [IO.Path]::GetFullPath($root)
        $expectedParent = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedRoot.StartsWith($expectedParent, [StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture cleanup path escaped its owned parent.' }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        Assert-OperandCheck (-not (Test-Path -LiteralPath $resolvedRoot)) 'owned fixture cleanup was not verified'
        $cleanupVerified = $true
    }
    catch {
        $finalizationErrors.Add($_.Exception)
        try { Write-Output 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED' }
        catch { $finalizationErrors.Add($_.Exception) }
    }
    try {
        if ($env:WINPCINFO_TEST_EVIDENCE) {
            $record = [ordered]@{ kind='QualificationInventoryOperandFixtureResults'; results=$results.ToArray(); fixtureInputs=$fixtureInputEvidence.ToArray(); cleanupVerified=$cleanupVerified; bodyError=if ($null -ne $bodyError) { $bodyError.ToString() } else { $null }; finalizationErrors=@($finalizationErrors.ToArray() | ForEach-Object { $_.ToString() }); qualificationAccepted=$false }
            [IO.File]::WriteAllText((Join-Path $env:WINPCINFO_TEST_EVIDENCE 'qualification-inventory-operands.json'), ($record | ConvertTo-Json -Depth 12), $utf8)
        }
    }
    catch { $finalizationErrors.Add($_.Exception) }
}
if ($null -ne $bodyError -or $finalizationErrors.Count -gt 0) {
    if ($finalizationErrors.Count -eq 0) { throw $bodyError }
    $causes = [Collections.Generic.List[Exception]]::new()
    if ($null -ne $bodyError) { $causes.Add($bodyError.Exception) }
    foreach ($cause in $finalizationErrors) { $causes.Add($cause) }
    $failure = [AggregateException]::new('Inventory fixture body or finalization failed.', $causes.ToArray())
    $failure.Data['OwnedCleanupUnverified'] = -not $cleanupVerified
    throw $failure
}
