[CmdletBinding()]
param(
    [string]$RepoRoot=(Split-Path -Parent $PSScriptRoot),
    [string] $CandidatePath,
    [string] $PreparedManifestPath,
    [string] $PreparedManifestSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$testDirectory=Join-Path $RepoRoot 'tests'
. (Join-Path $testDirectory 'TestHarness.ps1')
$candidateContext=Open-TestCandidate -RepositoryRoot $RepoRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidate=$candidateContext.Path
$candidateUseError=$null
try {
. (Join-Path $testDirectory 'QualificationResourceBounds.ps1')
. (Join-Path $testDirectory 'QualificationDiskBounds.ps1')
. (Join-Path $RepoRoot 'src/StatusDesk.ps1')
$repositoryRoot=$RepoRoot
$root=Join-Path $repositoryRoot ('.test-output/resource-bounds-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
$calibrationPath=Join-Path $root 'calibration.json'
$bodyError=$null
try {
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @(
        '-NoLogo','-NoProfile','-File',(Join-Path $testDirectory 'QualificationResourceBounds.ps1'),
        '-Calibrate','-OutputPath',$calibrationPath)
    Assert-Equal $true (Test-QualificationMemoryCalibration -Path $calibrationPath) 'target-runtime native calibration is admitted'
    $original=[IO.File]::ReadAllText($calibrationPath)
    foreach($fault in @('AcceptedString','ReleaseString','Module','Runtime','Future','Stale','Allocation','MissedPeak','NotReleased','WrongKind','MissingBracket','CounterString','NegativeCounter','FractionCounter','Structure','Pointer','DecreasingPrivatePeak','DecreasingWorkingPeak','DotNetPrivateBelow','DotNetPrivateAbove','DotNetWorkingBelow','DotNetWorkingAbove','Malformed')){
        $record=$original|ConvertFrom-Json
        switch($fault){
            'AcceptedString'{$record.accepted='true'}
            'ReleaseString'{$record.allocationReleased='true'}
            'Module'{$record.moduleSha256=('0'*64)}
            'Runtime'{$record.runtimeSha256=('0'*64)}
            'Future'{$record.calibratedAtUtc=[datetime]::UtcNow.AddMinutes(1).ToString('o')}
            'Stale'{$record.calibratedAtUtc=[datetime]::UtcNow.AddHours(-25).ToString('o')}
            'Allocation'{$record.allocationBytes=1}
            'MissedPeak'{$record.after.PeakPrivateBytes=0}
            'NotReleased'{$record.allocationReleased=$false}
            'WrongKind'{$record.kind='DifferentCalibration'}
            'MissingBracket'{$record.PSObject.Properties.Remove('bracket')}
            'CounterString'{$record.after.PeakPrivateBytes=$record.after.PeakPrivateBytes.ToString()}
            'NegativeCounter'{$record.before.PrivateBytes=-1}
            'FractionCounter'{$record.before.PrivateBytes=0.5}
            'Structure'{$record.before.StructureBytes=1}
            'Pointer'{$record.during.PointerBytes=1}
            'DecreasingPrivatePeak'{$record.during.PeakPrivateBytes=$record.after.PeakPrivateBytes+1}
            'DecreasingWorkingPeak'{$record.during.PeakWorkingSetBytes=$record.after.PeakWorkingSetBytes+1}
            'DotNetPrivateBelow'{$record.dotNetPeakPrivateBytes=$record.after.PeakPrivateBytes-1}
            'DotNetPrivateAbove'{$record.dotNetPeakPrivateBytes=$record.after.PeakPrivateBytes+1GB}
            'DotNetWorkingBelow'{$record.dotNetPeakWorkingSetBytes=$record.after.PeakWorkingSetBytes-1}
            'DotNetWorkingAbove'{$record.dotNetPeakWorkingSetBytes=$record.after.PeakWorkingSetBytes+1GB}
        }
        $text=if($fault-eq'Malformed'){'{'}else{$record|ConvertTo-Json -Depth 6}
        [IO.File]::WriteAllText($calibrationPath,$text)
        Assert-Equal $false (Test-QualificationMemoryCalibration -Path $calibrationPath) "$fault cannot admit resource qualification"
    }
    [IO.File]::WriteAllText($calibrationPath,$original)
    Initialize-QualificationNativeMemory
    $rejected=$false
    try{$null=[WinPCInfo.Qualification.NativeMemory]::Read([IntPtr]::Zero)}catch{$rejected=$true}
    Assert-Equal $true $rejected 'native memory reads reject an absent process handle'
    $snapshot=Get-QualificationMemorySnapshot
    Assert-Equal ([IntPtr]::Size) $snapshot.PointerBytes 'native memory layout matches the target process architecture'
    Assert-Equal $true ($snapshot.PeakPrivateBytes-ge$snapshot.PrivateBytes) 'lifetime private peak covers current private memory'
    Assert-Equal $true ($snapshot.PeakWorkingSetBytes-ge$snapshot.WorkingSetBytes) 'lifetime working-set peak covers current resident memory'

    $lfSource=Join-Path $root 'source-lf.ps1'
    $crlfSource=Join-Path $root 'source-crlf.ps1'
    $lf=[string][char]10; $cr=[string][char]13
    [IO.File]::WriteAllText($lfSource,"function Example { 'same' }"+$lf,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($crlfSource,"function Example { 'same' }"+$cr+$lf,[Text.UTF8Encoding]::new($true))
    Assert-Equal (Get-QualificationScriptIdentity -LiteralPath $lfSource) (Get-QualificationScriptIdentity -LiteralPath $crlfSource) 'Git line-ending/BOM normalization preserves the pinned logical source identity'
    [IO.File]::WriteAllText($crlfSource,"function Example { 'different' }"+$cr+$lf,[Text.UTF8Encoding]::new($false))
    Assert-Equal $false ((Get-QualificationScriptIdentity -LiteralPath $lfSource)-eq(Get-QualificationScriptIdentity -LiteralPath $crlfSource)) 'a source value change cannot reuse the canonical inventory identity'
    $regions=[regex]::Matches([IO.File]::ReadAllText($candidate),
        '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
    $moduleText=($regions|ForEach-Object{$_.Groups[2].Value})-join[Environment]::NewLine
    $owned=Join-Path $root 'owned'
    $instrumentation=New-QualificationDiskInstrumentation -ModuleText $moduleText -Root $owned -CandidatePath $candidate -HarnessPath (Join-Path $testDirectory 'StatusDeskEngine.Tests.ps1')
    Assert-Equal ((Get-FileHash -LiteralPath (Join-Path $testDirectory 'QualificationDiskBounds.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()) $instrumentation.instrumentationSha256 'reservation formulas retain their exact instrumentation identity'
    # Inspect the actual emitted definitions, then load them in the caller's
    # real order. Startup must preserve independently installed controller polls.
    $expectedDefinitions=@('Write-RunRecoveryJournal','Write-RegisteredEvidenceArtifact',
        'Write-ProtectedPackageEnvelope','Write-RecipientProfileDocument',
        'Export-RestrictedAssessmentReport','New-EvidenceWorkspaceOwnedWriteStream',
        'Add-QualificationDiskReservation','Assert-QualificationDiskReservation',
        'Invoke-QualificationWitnessAdmission')
    foreach($projection in @(
        @{text=$instrumentation.ControllerDefinitions;expected=$expectedDefinitions;name='controller writers'}
        @{text=$instrumentation.ControllerWorker;expected=@('Initialize-StatusDeskWorker');name='worker invocation setup'}
    )){
        $projectionTokens=$null;$projectionErrors=$null
        $projectionAst=[Management.Automation.Language.Parser]::ParseInput($projection.text,[ref]$projectionTokens,[ref]$projectionErrors)
        Assert-Equal 0 $projectionErrors.Count ($projection.name+' source parses')
        $emitted=@($projectionAst.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]},$false))
        Assert-Equal $projection.expected.Count $emitted.Count ($projection.name+' emits only its intended function cohort')
        foreach($name in $projection.expected){
            Assert-Equal 1 @($emitted|Where-Object Name -CEQ $name).Count ($projection.name+' emits '+$name+' exactly once')
        }
    }
    # The final worker AST must include every reservation and helper that was
    # added after the original inventory parse. Never execute the stale AST.
    Assert-Equal $true ($instrumentation.DefinitionInitializer -is [scriptblock]) 'controlled parsed definitions are admitted only after instrumentation'
    $finalWorkerDefinitions=@($instrumentation.DefinitionInitializer.Ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})
    $controllerTokens=$null;$controllerErrors=$null
    $controllerAst=[Management.Automation.Language.Parser]::ParseInput($instrumentation.ControllerDefinitions,[ref]$controllerTokens,[ref]$controllerErrors)
    Assert-Equal 0 $controllerErrors.Count 'the narrow reserved controller definitions parse'
    foreach($controllerDefinition in @($controllerAst.EndBlock.Statements)) {
        $workerMatch=@($finalWorkerDefinitions | Where-Object Name -CEQ $controllerDefinition.Name)
        Assert-Equal 1 $workerMatch.Count 'the final controlled worker contains each reserved writer/helper exactly once'
        Assert-Equal $controllerDefinition.Extent.Text $workerMatch[0].Extent.Text 'the final controlled AST preserves the actual writer reservation formulas'
    }
    Assert-Equal $true $instrumentation.ControllerWorker.Contains('$script:QualificationDiskLedger=$DiskLedger; . $Definitions') 'the shared ledger is installed before parsed worker initialization'
    $controllerProjection=& {
        param($Definitions,$Start)
        . ([scriptblock]::Create($Definitions))
        function Send-StatusDeskRecord { 'inert.sender.sentinel' }
        function Complete-StatusDeskSession { 'inert.poll.sentinel' }
        $senderBefore=(Get-Command Send-StatusDeskRecord).ScriptBlock.ToString()
        $pollBefore=(Get-Command Complete-StatusDeskSession).ScriptBlock.ToString()
        $writerBefore=(Get-Command Export-RestrictedAssessmentReport).ScriptBlock.ToString()
        . ([scriptblock]::Create($Start))
        [pscustomobject]@{
            SenderPreserved=((Get-Command Send-StatusDeskRecord).ScriptBlock.ToString()-ceq$senderBefore)
            PollPreserved=((Get-Command Complete-StatusDeskSession).ScriptBlock.ToString()-ceq$pollBefore)
            WriterPreserved=((Get-Command Export-RestrictedAssessmentReport).ScriptBlock.ToString()-ceq$writerBefore)
            WriterIsBounded=$writerBefore.Contains('Add-QualificationDiskReservation -Path $partialPath')
        }
    } $instrumentation.ControllerDefinitions $instrumentation.ControllerWorker
    Assert-Equal $true $controllerProjection.SenderPreserved 'actual startup import preserves installed progress publication'
    Assert-Equal $true $controllerProjection.PollPreserved 'actual startup import preserves installed controller polling'
    Assert-Equal $true $controllerProjection.WriterPreserved 'actual startup import preserves bounded controller writers'
    Assert-Equal $true $controllerProjection.WriterIsBounded 'the preserved writer contains the actual reservation guard'

    $brokenRoot=Join-Path $root 'broken-source'
    $rejected=$false
    try{$null=New-QualificationDiskInstrumentation -ModuleText 'function unrelated {}' -Root $brokenRoot -CandidatePath $candidate -HarnessPath (Join-Path $testDirectory 'StatusDeskEngine.Tests.ps1')}catch{$rejected=$true}
    Assert-Equal $true $rejected 'changed writer derivation is refused'
    Assert-Equal $false ([IO.Directory]::Exists($brokenRoot)) 'failed derivation creates no unregistered owned directory'
    $script:QualificationDiskLedger=$instrumentation.Ledger
    $file=Join-Path $owned 'synthetic'
    Add-QualificationDiskReservation -Path $file -Bytes 100 -Kind FirstWrite
    [IO.File]::WriteAllBytes($file,[byte[]]::new(100))
    [IO.File]::Delete($file)
    Add-QualificationDiskReservation -Path $file -Bytes 60 -Kind Rewrite
    Assert-Equal 160L $script:QualificationDiskLedger.TotalBytes 'deletion and same-path rewrite never reduce the simultaneous-use upper bound'
    Assert-QualificationDiskReservation -Path $file
    $rejected=$false
    try{Assert-QualificationDiskReservation -Path (Join-Path $owned 'unaccounted')}catch{$rejected=$true}
    Assert-Equal $true $rejected 'unaccounted native file creation fails before mutation'
    Assert-Equal $false $script:QualificationDiskLedger.Valid 'an unaccounted writer invalidates qualification'
    $rejected=$false
    try{Add-QualificationDiskReservation -Path (Join-Path ($owned+'-sibling') 'foreign') -Bytes 1 -Kind Escape}catch{$rejected=$true}
    Assert-Equal $true $rejected 'a sibling prefix cannot escape the owned directory boundary'
    $rejected=$false
    try{Add-QualificationDiskReservation -Path $file -Bytes -1 -Kind InvalidGrowth}catch{$rejected=$true}
    Assert-Equal $true $rejected 'negative growth cannot reduce the conservative upper bound'
    $drift=Join-Path $root 'different-candidate.ps1'
    [IO.File]::WriteAllText($drift,'synthetic different source')
    $rejected=$false
    try{$null=New-QualificationDiskInstrumentation -ModuleText $moduleText -Root (Join-Path $root 'drift') -CandidatePath $drift -HarnessPath (Join-Path $testDirectory 'StatusDeskEngine.Tests.ps1')}catch{$rejected=$true}
    Assert-Equal $true $rejected 'different candidate bytes cannot reuse the reviewed writer inventory'
}
catch{$bodyError=$_}
finally {
    Complete-QualificationHarness -BodyError $bodyError -Cleanup @(
        {
            if($null-ne$bodyError-and(Test-QualificationCleanupUnverified -Exception $bodyError.Exception)){throw 'Preserve resource calibration evidence until owned cleanup is verified.'}
            $boundary=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
            $resolved=[IO.Path]::GetFullPath($root)
            if(-not$resolved.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)){throw 'Resource fixture cleanup escaped its owned parent.'}
            if([IO.Directory]::Exists($resolved)){Remove-Item -LiteralPath $resolved -Recurse -Force}
            if([IO.Directory]::Exists($resolved)){throw 'Owned resource fixture directory absence remains unverified.'}
        }
    )
}
Write-Output 'PASS: native lifetime calibration fails closed on invalid evidence; complete cumulative writer reservations preserve rewrites and reject escapes, unaccounted writers and candidate drift.'
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
