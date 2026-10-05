[CmdletBinding()]
param([string] $RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$writer = [IO.Path]::GetFullPath($RepositoryRoot)
. (Join-Path $writer 'tests/TestHarness.ps1')
$evidenceDirectory = if ([string]::IsNullOrWhiteSpace($env:WINPCINFO_TEST_EVIDENCE)) {
    Join-Path $writer ('.test-output/signing-finalization-' + [guid]::NewGuid().ToString('N'))
} else { $env:WINPCINFO_TEST_EVIDENCE }
[IO.Directory]::CreateDirectory($evidenceDirectory) | Out-Null
$recordPath = Join-Path $evidenceDirectory 'signing-finalization-controlled-cases.json'
$sourcePath = Join-Path $writer 'src/SigningBoundary.ps1'
$sourceDigest = (Get-FileHash -LiteralPath $sourcePath).Hash.ToLowerInvariant()
. $sourcePath
$policy = Get-SigningBoundaryPolicy
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'Signing source did not parse'}
$functions=@($ast.FindAll({param($n) $n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Invoke-SigningBoundarySession'},$true))
if($functions.Count-ne1){throw 'Expected one literal signing session definition'}
$fn=$functions[0]
$transactions=@($fn.Body.FindAll({param($n) $n-is[Management.Automation.Language.TryStatementAst]-and$null-ne$n.Finally},$false))
if($transactions.Count-ne1){throw 'Expected one actual transaction finalizer'}
$finalizer=$transactions[0].Finally
$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$ownedRoot=[IO.Path]::GetFullPath((Join-Path $base ('win-pcinfo-signing-order-'+[guid]::NewGuid().ToString('N'))))
if(-not$ownedRoot.StartsWith(($base.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Owned temp root escaped parent'}
$fixtureCreated = $false
$ownershipPath = Join-Path $ownedRoot '.signing-finalization-test-owner'
$ownershipToken = [guid]::NewGuid().ToString('N')
# Smoke and record transport are doubled; the body-fault case doubles trailer creation.
# These controlled replays execute no child, key, certificate, trust or service operation.
function Invoke-SigningBoundarySmoke { param($SignedScriptPath,$PowerShellPath) $true }
$originalTrailer=(Get-Command New-SigningBoundarySyntheticTrailer).ScriptBlock
. (Join-Path $writer 'src/Contracts.ps1')
$main = Join-Path $writer 'src/ApplicationMain.ps1'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($main,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'Caller source parse failure'}
$blocks=@($ast.FindAll({param($n) $n-is[Management.Automation.Language.IfStatementAst]-and@($n.Clauses|Where-Object{$_.Item1.Extent.Text-match'\$Workflow\s+-eq\s+''SignAndVerifyCandidate'''}).Count-eq1},$true))
if($blocks.Count-ne1){throw 'Expected one actual signing workflow branch'}
$block=$blocks[0].Clauses[0].Item2
$tries=@($block.FindAll({param($n)$n-is[Management.Automation.Language.TryStatementAst]-and$n.Body.Extent.Text.Contains('$signingRequestText =')},$false))
if($tries.Count-ne1-or$tries[0].CatchClauses.Count-ne1){throw 'Expected exact caller admission catch'}
$catchText=$tries[0].CatchClauses[0].Body.Extent.Text
$mainCatch=[scriptblock]::Create($catchText.Substring(1,$catchText.Length-2))
$text=$block.Extent.Text;$start=$text.IndexOf('    $signingSucceeded =')
if($start-lt0){throw 'Actual terminal projection missing'}
$tail=$text.Substring($start).TrimEnd();$tail=$tail.Substring(0,$tail.Length-1)
if(([regex]::Matches($tail,[regex]::Escape('exit $exitCode'))).Count-ne1){throw 'Expected one exact signing exit statement'}
$tail=$tail.Replace('exit $exitCode','$script:jointExitCode = $exitCode')
$mainTail=[scriptblock]::Create($tail)
function Write-ContractRecord {param($Record,$ConvertToJsonCommand) [void]$script:jointRecords.Add($Record)}
$convertToJsonCommand=Get-Command Microsoft.PowerShell.Utility\ConvertTo-Json

$rows = [Collections.Generic.List[object]]::new()
$record = [ordered]@{
    scope = 'ControlledActualSessionAndCallerAstReplay;SyntheticOnly'
    sourceSha256 = $sourceDigest
    callerSourceSha256 = (Get-FileHash -LiteralPath $main).Hash.ToLowerInvariant()
    owningDefinitionSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($fn.Extent.Text))).ToLowerInvariant()
    rows = @()
    nativeChildrenStarted = 0
    realSigningPerformed = $false
    capabilityRemovalQualified = $false
    actualClientAcceptance = $false
    fixtureDisposition = 'NotCreated'
    sourceUnchanged = $null
}
$bodyError = $null
try {
[IO.Directory]::CreateDirectory($ownedRoot)|Out-Null
$fixtureCreated = $true
[IO.File]::WriteAllText($ownershipPath, $ownershipToken, [Text.UTF8Encoding]::new($false))
$candidateDirectory=Join-Path $ownedRoot 'candidate';[IO.Directory]::CreateDirectory($candidateDirectory)|Out-Null
$candidate=Join-Path $candidateDirectory 'WIN-PCInfo.ps1';[IO.File]::WriteAllText($candidate,"# synthetic inert candidate`n",[Text.UTF8Encoding]::new($false))
$digest=Get-SigningBoundarySha256 -Bytes ([IO.File]::ReadAllBytes($candidate))

 foreach($case in @(
  @{name='success-order';scenario='EligibleSign';fault=$false;bodyFault=$false}
  @{name='fallback-order';scenario='ServiceUnavailable';fault=$false;bodyFault=$false}
  @{name='rejection-order';scenario='MissingSignature';fault=$false;bodyFault=$false}
  @{name='permission-denied-order';scenario='PermissionDenied';fault=$false;bodyFault=$false}
  @{name='body-only-failure-finalizes';scenario='EligibleSign';fault=$false;bodyFault=$true}
  @{name='finalizer-fault-withholds-success';scenario='EligibleSign';fault=$true;bodyFault=$false}
  @{name='concurrent-body-and-finalizer-faults';scenario='EligibleSign';fault=$true;bodyFault=$true}
 )){
  $script:orderEvents=[Collections.Generic.List[string]]::new();$script:escapedResults=[Collections.Generic.List[object]]::new()
  $definition=$fn.Extent.Text
  if($case.fault){
   $definition=$definition.Insert($finalizer.Extent.StartOffset-$fn.Extent.StartOffset+1,"`nthrow 'SYNTHETIC_FINALIZATION_FAILURE'`n")
  }else{
   $definition=$definition.Insert($finalizer.Extent.EndOffset-$fn.Extent.StartOffset-1,"`n[void]`$script:orderEvents.Add('Finalized')`n")
  }
  . ([scriptblock]::Create($definition))
  if($case.bodyFault){function New-SigningBoundarySyntheticTrailer { param($UnsignedSha256,$SignatureStatus,$IncludeMarker,$TimestampStatus) throw 'SYNTHETIC_BODY_FAILURE' }}
  else{Set-Item -LiteralPath Function:New-SigningBoundarySyntheticTrailer -Value $originalTrailer}
  $workspace=Join-Path $ownedRoot $case.name;[IO.Directory]::CreateDirectory($workspace)|Out-Null
  [IO.File]::WriteAllText((Join-Path $workspace $policy.workspace.markerFileName),($policy.workspace.markerContent+"`n"),[Text.UTF8Encoding]::new($false))
  $request=Get-Content -LiteralPath (Join-Path $writer 'tests/fixtures/signing-session-eligible.json') -Raw|ConvertFrom-Json -Depth 20
  $request.scenario=$case.scenario;$request.bindings.generatedContentSha256=$digest;$request.bindings.humanApproval.digestSha256=$digest
  $errorText=$null;$observedException=$null;$signingResult=$null;$script:jointRecords=[Collections.Generic.List[object]]::new();$script:jointExitCode=$null
  try{Invoke-SigningBoundarySession -Request $request -CandidatePath $candidate -PrivateWorkspacePath $workspace -RepositoryRoot $writer -ApplicationDirectory $candidateDirectory -Policy $policy|ForEach-Object{[void]$script:escapedResults.Add($_);[void]$script:orderEvents.Add(('Emitted:'+ $_.state))}}
  catch{$observedException=$_.Exception;$errorText=$observedException.ToString();. $mainCatch}
  if($null-eq$observedException){
   if($script:escapedResults.Count-ne1){throw 'Expected one finalized actual result'}
   $signingResult=$script:escapedResults[0]
  }
  . $mainTail
  $jointSessions=@($script:jointRecords|Where-Object recordType -eq 'win-pcinfo.signing-session-result')
  $jointTerminals=@($script:jointRecords|Where-Object recordType -eq 'win-pcinfo.terminal')
  $expectedExit=if($case.fault){60}elseif(-not$case.bodyFault-and$case.scenario-ceq'EligibleSign'){0}else{20}
  $expectedOutcome=if($expectedExit-eq60){'CleanupIncomplete'}elseif($expectedExit-eq0){'Completed'}else{'NotStarted'}
  $jointPass=$jointSessions.Count-eq1-and$jointTerminals.Count-eq1-and$script:jointExitCode-eq$expectedExit-and$jointTerminals[0].exitCode-eq$expectedExit-and$jointTerminals[0].outcome-ceq$expectedOutcome-and$jointSessions[0].sessionCapabilityRemoved-eq(-not$case.fault)-and$jointTerminals[0].cleanup.verified-eq(-not$case.fault)-and$jointTerminals[0].cleanup.required-eq$case.fault
  $jointProjection=$script:jointRecords|ConvertTo-Json -Depth 20 -Compress
  $jointPrivacy=$jointProjection-notmatch'SYNTHETIC_BODY_FAILURE|SYNTHETIC_FINALIZATION_FAILURE|[A-Z]:\\Users\\'

  $firstEmission=@($script:orderEvents|Where-Object {$_-like'Emitted:*'}).Count
  $orderingPass=if($case.fault){$script:escapedResults.Count-eq0}elseif($case.bodyFault){$script:escapedResults.Count-eq0-and$script:orderEvents.Count-eq1-and$script:orderEvents[0]-ceq'Finalized'}else{$script:orderEvents.Count-eq2-and$script:orderEvents[0]-ceq'Finalized'}
  $aggregate=$observedException
  while($null-ne$aggregate-and$aggregate-isnot[AggregateException]){$aggregate=$aggregate.InnerException}
  $causes=@(if($null-ne$aggregate){$aggregate.InnerExceptions|ForEach-Object Message})
  $structuredBoth=if($case.bodyFault-and$case.fault){$causes.Count-eq2-and$causes[0]-ceq'SYNTHETIC_BODY_FAILURE'-and$causes[1]-ceq'SYNTHETIC_FINALIZATION_FAILURE'}else{$null}
  $rows.Add([ordered]@{case=$case.name;scenario=$case.scenario;testCopyFinalizerFault=$case.fault;testCopyBodyFault=$case.bodyFault;events=$script:orderEvents.ToArray();escapedResultCount=$script:escapedResults.Count;escapedStates=@($script:escapedResults|ForEach-Object state);error=$errorText;orderingAssertionPass=$orderingPass;callerJointAssertionPass=$jointPass;callerJointSanitized=$jointPrivacy;callerJointExit=$script:jointExitCode;callerJointTerminalOutcome=$jointTerminals[0].outcome;callerJointRemoval=$jointSessions[0].sessionCapabilityRemoved;structuredCauseMessages=$causes;bothFailureCausesPreserved=$structuredBoth})
 }
 if((Get-FileHash -LiteralPath $sourcePath).Hash.ToLowerInvariant()-cne$sourceDigest){throw 'Frozen source was modified'}
 if((Get-FileHash -LiteralPath $main).Hash.ToLowerInvariant()-cne$record.callerSourceSha256){throw 'Caller source changed during the controlled replay'}
 $record.sourceUnchanged = $true
 $failed=@($rows|Where-Object {-not$_.orderingAssertionPass-or-not$_.callerJointAssertionPass-or-not$_.callerJointSanitized-or($_.testCopyBodyFault-and$_.testCopyFinalizerFault-and-not$_.bothFailureCausesPreserved)})
 if($failed.Count){throw "Controlled signing finalization failed: $($failed.Count) case assertions failed; real permission removal is not qualified."}
}
catch { $bodyError = $_ }
Complete-QualificationHarness -BodyError $bodyError -RetainEvidence {
    $record.rows = $rows.ToArray()
    $record.fixtureDisposition = if ($fixtureCreated) { 'CleanupPending' } else { 'NotCreated' }
    [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
} -Cleanup @({
    if (-not $fixtureCreated) { return }

    $resolvedRoot = [IO.Path]::GetFullPath($ownedRoot)
    $expectedPrefix = $base.TrimEnd('\') + '\'
    if (-not $resolvedRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Owned finalization fixture escaped its temporary parent'
    }
    if (-not [IO.File]::Exists($ownershipPath) -or
        [IO.File]::ReadAllText($ownershipPath) -cne $ownershipToken) {
        throw 'Owned finalization fixture marker is not verified'
    }
    if ((Get-Item -LiteralPath $resolvedRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Owned finalization fixture is a reparse point'
    }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    if (Test-Path -LiteralPath $resolvedRoot) { throw 'Owned synthetic fixture cleanup remains incomplete' }

}) -RetainCleanupEvidence {
    $record.fixtureDisposition = if ($fixtureCreated) { 'VerifiedAbsent' } else { 'NotCreated' }
    [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
Write-Output "EVIDENCE: $recordPath"

Write-Output 'PASS: actual signing finalization and caller preserve cleanup ordering and concurrent causes.'
