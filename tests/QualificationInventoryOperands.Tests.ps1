[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$diagnostic = Join-Path $PSScriptRoot 'Get-QualificationInventoryOperands.ps1'
$root = Join-Path $repositoryRoot ('.test-output/inventory-operands-' + [guid]::NewGuid().ToString('N'))
$fixtureTests = Join-Path $root 'tests'
$null = [IO.Directory]::CreateDirectory($fixtureTests)
$manifestPath = Join-Path $fixtureTests 'qualification-resource-writers.json'
$candidate = Join-Path $root 'inert-candidate.ps1'
$harness = Join-Path $root 'inert-harness.ps1'
$utf8 = [Text.UTF8Encoding]::new($false)
$results = [Collections.Generic.List[object]]::new()

function Assert-OperandCheck([bool] $Condition, [string] $Because) {
    if (-not $Condition) { throw $Because }
}
try {
    # Copy the actual implementation unchanged so its original manifest lookup
    # uses this owned fixture, never the canonical inventory.
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'QualificationDiskBounds.ps1') -Destination $fixtureTests
    . (Join-Path $fixtureTests 'QualificationDiskBounds.ps1')
    [IO.File]::WriteAllText($candidate, "# inert candidate`n", $utf8)
    [IO.File]::WriteAllText($harness, "# inert harness`n", $utf8)
    $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'qualification-resource-writers.json') -Raw | ConvertFrom-Json
    $manifest.candidateSha256 = (Get-FileHash -LiteralPath $candidate).Hash.ToLowerInvariant()
    $manifest.harnessSha256 = Get-QualificationScriptIdentity -LiteralPath $harness
    $manifest.inputs = @()
    $baseline = $manifest | ConvertTo-Json -Depth 20
    $instrumentedRoot = Join-Path $root 'must-not-be-created'
    foreach ($fault in @('Exact', 'CandidateChanged', 'CandidateRepresentation', 'HarnessChanged', 'HarnessRepresentation', 'UppercaseDeclaration',
        'CandidateMissing', 'HarnessMissing', 'KindMissing', 'CandidateMalformed', 'HarnessMalformed',
        'CandidateStale', 'HarnessStale', 'KindChanged', 'MalformedJson')) {
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
        $positive = $fault -in @('Exact', 'HarnessRepresentation', 'UppercaseDeclaration')
        $comparison = $null
        if ($fault -ne 'MalformedJson') {
            $comparison = & $diagnostic -ManifestPath $manifestPath -CandidatePath $candidate -HarnessPath $harness
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
        catch { $message = $_.Exception.Message }
        Assert-OperandCheck ($null -ne $message) "$fault real admission must terminate at its expected boundary"
        Assert-OperandCheck (($message -eq 'Qualification writer source does not parse.') -eq $positive) "$fault real admission disagrees with operand diagnosis"
        Assert-OperandCheck (-not [IO.Directory]::Exists($instrumentedRoot)) "$fault created an instrumentation root"
        $results.Add([ordered]@{ fault=$fault; identityAccepted=$positive; originalAdmissionMessage=$message; comparison=$comparison })
    }
    Write-Output "PASS: $($results.Count) pure inventory operand controls; exact and normalized harness identities reach the downstream parser; mutations and invalid declarations refuse."
}
finally {
    # Remove only files in this uniquely created fixture; retain its result
    # record separately when the suite has supplied an evidence destination.
    try {
        if ($env:WINPCINFO_TEST_EVIDENCE) {
            [IO.File]::WriteAllText((Join-Path $env:WINPCINFO_TEST_EVIDENCE 'qualification-inventory-operands.json'),
                ($results.ToArray() | ConvertTo-Json -Depth 8), $utf8)
        }
    }
    finally {
        $resolvedRoot = [IO.Path]::GetFullPath($root)
        $expectedParent = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedRoot.StartsWith($expectedParent, [StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture cleanup path escaped its owned parent.' }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        Assert-OperandCheck (-not (Test-Path -LiteralPath $resolvedRoot)) 'owned fixture cleanup was not verified'
    }
}
