[CmdletBinding()]
param([ValidateSet('None','BypassContext','OmitRelease')] [string] $ConsumerFault = 'None')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

# Replay each actual consumer's admission/catch/finally statements. Substitute
# only its TestHarness import and complete calibration/witness workload. The
# API stubs expose caller ordering and arguments; they never build, start a
# child, query a native identity, write a fixture or claim native acceptance.
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $probe.events.Add('open')
    $probe.admission=[pscustomobject]@{root=$RepositoryRoot;candidate=$CandidatePath;manifest=$PreparedManifestPath;sha256=$PreparedManifestSha256}
    if ($probe.mode -eq 'Refuse') { throw $probe.bodyFailure }
    $probe.context=[pscustomobject]@{Path=(Join-Path $RepositoryRoot '.test-output/synthetic-owned-candidate/WIN-PCInfo.ps1');Prepared=-not [string]::IsNullOrWhiteSpace($CandidatePath)}
    $probe.context
}
function Close-TestCandidate {
    param($Candidate,$BodyError)
    $probe.events.Add('close')
    $probe.closedContext=$Candidate
    $probe.closedBodyError=$BodyError
    if ($null -ne $BodyError) { throw $BodyError.Exception }
    if ($probe.mode -eq 'CloseFailure') { throw $probe.cleanupFailure }
}

foreach ($name in @('QualificationResourceBounds.Tests.ps1','QualificationWitnessInventory.Tests.ps1')) {
    $path=Join-Path $PSScriptRoot $name
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Qualification candidate consumer source does not parse.' }
    $outer=@($ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.TryStatementAst] -and
        $null -ne $_.Finally -and $_.Finally.Extent.Text.Contains('Close-TestCandidate')
    })
    $imports=@($ast.EndBlock.Statements | Where-Object {
        $_.Extent.Text.StartsWith('. (Join-Path ',[StringComparison]::Ordinal) -and
        $_.Extent.Text.Contains("'TestHarness.ps1'")
    })
    if ($outer.Count -ne 1 -or $imports.Count -ne 1) { throw 'Qualification candidate consumer control seam is not unique.' }
    $workload=@'
{
    $probe.events.Add('work')
    $probe.usedCandidate=$candidate
    if ($probe.mode -in @('BodyFailure','BodyUnsafe')) { throw $probe.bodyFailure }
}
'@
    $source=$ast.Extent.Text.Replace($imports[0].Extent.Text,'# Disclosed in-process API stubs are inherited from the fixture.').
        Replace($outer[0].Body.Extent.Text,$workload)
    # Explicit red-capability controls mutate only the in-memory replay. The
    # production consumers, admitted candidate and all fixture files stay intact.
    if ($ConsumerFault -eq 'BypassContext') {
        $source=$source.Replace('$candidate=$candidateContext.Path',"`$candidate='synthetic-shared-artifact.ps1'")
    }
    elseif ($ConsumerFault -eq 'OmitRelease') { $source=$source.Replace($outer[0].Finally.Extent.Text,'{}') }
    $controlErrors=$null; $controlTokens=$null
    $controlAst=[Management.Automation.Language.Parser]::ParseInput($source,$path,[ref]$controlTokens,[ref]$controlErrors)
    if ($controlErrors.Count) { throw 'Qualification candidate consumer control does not parse.' }
    $control=$controlAst.GetScriptBlock()
    foreach ($mode in @('Prepared','Standalone','Refuse','BodyFailure','BodyUnsafe','CloseFailure')) {
        $probe=[pscustomobject]@{mode=$mode;events=[Collections.Generic.List[string]]::new();admission=$null;context=$null;
            usedCandidate=$null;closedContext=$null;closedBodyError=$null;
            bodyFailure=[InvalidOperationException]::new('Disclosed synthetic consumer body refusal.');
            cleanupFailure=[InvalidOperationException]::new('Disclosed synthetic candidate cleanup refusal.')}
        if ($mode -eq 'BodyUnsafe') { $probe.bodyFailure.Data['OwnedCleanupUnverified']=$true }
        $parameters=@{}
        if ($name -eq 'QualificationResourceBounds.Tests.ps1') {
            # The supplied repository is deliberately distinct from this file's
            # repository: admission must honor the existing RepoRoot parameter.
            $parameters.RepoRoot=Join-Path (Split-Path -Parent $PSScriptRoot) '.test-output/synthetic-other-repository'
        }
        if ($mode -ne 'Standalone') {
            $parameters.CandidatePath='synthetic-explicit-candidate.ps1'
            $parameters.PreparedManifestPath='synthetic-explicit-manifest.json'
            $parameters.PreparedManifestSha256=('a'*64)
        }
        $failure=$null
        try { & $control @parameters | Out-Null } catch { $failure=$_ }
        if ($mode -eq 'Refuse') {
            if (($probe.events -join ',') -cne 'open' -or $null -eq $failure) { throw 'Refused candidate admission reached workload or cleanup of an unowned context.' }
            continue
        }
        if (($probe.events -join ',') -cne 'open,work,close' -or
            -not [object]::ReferenceEquals($probe.context,$probe.closedContext) -or
            $probe.usedCandidate -cne $probe.context.Path) { throw 'Actual consumer bypassed its admitted context or final release.' }
        $expectedRoot=if ($parameters.ContainsKey('RepoRoot')) { $parameters.RepoRoot } else { Split-Path -Parent $PSScriptRoot }
        if ($probe.admission.root -cne $expectedRoot) { throw 'Actual candidate consumer lost its repository ownership.' }
        if ($mode -eq 'Standalone') {
            if ($probe.admission.candidate -or $probe.admission.manifest -or $probe.admission.sha256) { throw 'Standalone consumer supplied an implicit shared artifact.' }
        }
        elseif ($probe.admission.candidate -cne $parameters.CandidatePath -or
            $probe.admission.manifest -cne $parameters.PreparedManifestPath -or
            $probe.admission.sha256 -cne $parameters.PreparedManifestSha256) { throw 'Actual consumer changed explicit candidate admission operands.' }
        if ($mode -in @('BodyFailure','BodyUnsafe')) {
            if ($null -eq $probe.closedBodyError -or -not [object]::ReferenceEquals($probe.closedBodyError.Exception,$probe.bodyFailure) -or
                $null -eq $failure -or -not [object]::ReferenceEquals($failure.Exception,$probe.bodyFailure)) { throw 'Actual consumer lost the original body failure at candidate release.' }
            if ($mode -eq 'BodyUnsafe' -and $probe.closedBodyError.Exception.Data['OwnedCleanupUnverified'] -ne $true) { throw 'Actual consumer lost owned cleanup uncertainty.' }
        }
        elseif ($mode -eq 'CloseFailure') {
            if ($null -eq $failure -or -not [object]::ReferenceEquals($failure.Exception,$probe.cleanupFailure)) { throw 'Candidate release failure was normalized into success.' }
        }
        elseif ($null -ne $failure -or $null -ne $probe.closedBodyError) { throw 'Successful candidate consumer introduced a body failure.' }
    }
}
Write-Output 'PASS: both actual qualification consumers admit before workload, preserve explicit and standalone operands, honor repository ownership, and close exact contexts with original failure/unsafe state.'
