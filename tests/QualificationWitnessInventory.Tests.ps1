[CmdletBinding()]
param(
    [string] $CandidatePath,
    [string] $PreparedManifestPath,
    [string] $PreparedManifestSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidate=$candidateContext.Path
$candidateUseError=$null
try {
. (Join-Path $PSScriptRoot 'QualificationDiskBounds.ps1')
$null=Assert-QualificationResourceInventoryBinding -CandidatePath $candidate -HarnessPath (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -RepositoryRoot $repositoryRoot
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $repositoryRoot 'src/StatusDesk.ps1')
. (Join-Path $PSScriptRoot 'AssessmentQualificationSupport.ps1')
$script:QualificationWitnessOriginalWorker=Get-PrivilegedCollectionWorkerSource
function Get-PreStartOriginalPrivilegeWorkerSource { $script:QualificationWitnessOriginalWorker }
function Get-LossOriginalPrivilegeWorkerSource { $script:QualificationWitnessOriginalWorker }
$manifestPath=Join-Path $PSScriptRoot 'qualification-resource-writers.json'
$manifestText=[IO.File]::ReadAllText($manifestPath)
$harnessText=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'))
$tokens=$null; $errors=$null
$harnessAst=[Management.Automation.Language.Parser]::ParseInput($harnessText,[ref]$tokens,[ref]$errors)
Assert-Equal 0 $errors.Count 'actual qualification harness parses before source extraction'
$root=Join-Path $repositoryRoot ('.test-output/witness-inventory-'+[guid]::NewGuid().ToString('N'))
$bodyError=$null
function New-WitnessTestLedger {
    param([string] $Fault,[string] $CaseRoot,$Manifest)
    $descriptor=New-QualificationWitnessDescriptor -Fault $Fault -Root $CaseRoot -Manifest $Manifest
    [hashtable]::Synchronized(@{Root=([IO.Path]::GetFullPath($CaseRoot)+[IO.Path]::DirectorySeparatorChar);
        TotalBytes=0L;Valid=$true;Claims=@{};Counts=@{};Witness=$descriptor})
}
function Get-ActualWitnessTemplate {
    param([string] $Fault,$Descriptor)
    $generator=if ($Fault -ceq 'PrivilegePostStartLoss') { 'Get-LossOriginalPrivilegeWorkerSource' } else { 'Get-PreStartOriginalPrivilegeWorkerSource' }
    $snippets=@($harnessAst.FindAll({param($node)
        $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
        $node.StringConstantType -eq [Management.Automation.Language.StringConstantType]::SingleQuotedHereString -and
        $node.Value.Contains('function Get-PrivilegedCollectionWorkerSource {') -and
        $node.Value.Contains('$source='+$generator)
    }.GetNewClosure(),$true))
    Assert-Equal 1 $snippets.Count 'actual fault worker source definition is unique'
    # Execute the actual harness's two nested-source path substitutions.
    # The surrounding fault function contains a single-quoted string which
    # emits another single-quoted worker literal; both levels must survive.
    $moduleText=$snippets[0].Value
    $preStartWitness=$Descriptor.Path; $postStartWitness=$Descriptor.Path
    foreach ($marker in @('__PRE_START_WITNESS__','__POST_START_WITNESS__')) {
        $substitutions=@($harnessAst.FindAll({param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -ceq 'moduleText' -and
            $node.Right.Extent.Text.StartsWith('$moduleText.Replace(',[StringComparison]::Ordinal) -and
            $node.Right.Extent.Text.Contains("'"+$marker+"'")
        }.GetNewClosure(),$true))
        Assert-Equal 1 $substitutions.Count 'actual witness path substitution is unique'
        . ([scriptblock]::Create($substitutions[0].Extent.Text))
    }
    . ([scriptblock]::Create($moduleText))
    $lf=[string][char]10; $cr=[string][char]13
    (Get-PrivilegedCollectionWorkerSource).Replace($cr+$lf,$lf).Replace($cr,$lf)
}

function Invoke-WitnessDispatchProbe {
    Assert-Equal $true $script:QualificationDiskLedger.Valid 'actual dispatch sees a valid closed inventory'
    Assert-Equal 1L $script:QualificationDiskLedger.Witness.LaunchAdmissions 'actual dispatch follows one admission'
    Assert-Equal $script:QualificationDiskLedger.Witness.ReservationBytes $script:QualificationDiskLedger.TotalBytes 'actual dispatch sees witness reservation already counted'
    $script:WitnessDispatchCount++
    [pscustomobject]@{ syntheticDispatch=$true }
}
function Test-ActualWitnessControllerSeam {
    param([string] $Fault,[string] $ModuleText,[string] $CandidatePath,[string] $CaseRoot)
    $instrumentation=New-QualificationDiskInstrumentation -ModuleText $ModuleText -Root $CaseRoot `
        -CandidatePath $CandidatePath -HarnessPath (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -WitnessFault $Fault
    $localTokens=$null; $localErrors=$null
    $instrumentedAst=[Management.Automation.Language.Parser]::ParseInput($instrumentation.ModuleText,[ref]$localTokens,[ref]$localErrors)
    Assert-Equal 0 $localErrors.Count 'actual instrumented worker/controller module parses'
    $controllers=@($instrumentedAst.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-ControlledPrivilegedCollectionPlan'
    },$false))
    Assert-Equal 1 $controllers.Count 'actual instrumented controller remains unique'
    $admissions=@($controllers[0].FindAll({param($node)
        $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Invoke-QualificationWitnessAdmission'
    },$true))
    $launches=@($controllers[0].FindAll({param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static -and
        $node.Extent.Text -ceq '[System.Diagnostics.Process]::Start($startInfo)'
    },$true))
    Assert-Equal 1 $admissions.Count 'actual controller has exactly one witness admission'
    Assert-Equal 1 $launches.Count 'actual controller has exactly one native worker launch'
    $launchTry=$launches[0].Parent
    while ($null -ne $launchTry -and $launchTry -isnot [Management.Automation.Language.TryStatementAst]) { $launchTry=$launchTry.Parent }
    Assert-Equal $true ($null -ne $launchTry) 'actual launch belongs to its original guarded try'
    $admissionPipeline=$admissions[0].Parent
    while ($null -ne $admissionPipeline -and $admissionPipeline -isnot [Management.Automation.Language.PipelineAst]) { $admissionPipeline=$admissionPipeline.Parent }
    Assert-Equal $true ($null -ne $admissionPipeline -and $admissionPipeline.Parent -eq $launchTry.Parent) 'admission and native launch share the actual statement block'
    $statements=@($launchTry.Parent.Statements)
    $admissionIndex=[array]::IndexOf($statements,$admissionPipeline)
    $launchIndex=[array]::IndexOf($statements,$launchTry)
    Assert-Equal ($admissionIndex+1) $launchIndex 'admission immediately precedes actual native dispatch'
    Assert-Equal $true ($admissions[0].Extent.EndOffset -lt $launches[0].Extent.StartOffset) 'reservation occurs before process creation'
    # Execute actual adjacent caller statements, replacing only Process.Start
    # with an in-process probe. No controller or native worker process runs.
    $fragment=$admissionPipeline.Extent.Text+'; '+$launchTry.Extent.Text
    Assert-Equal 1 ([regex]::Matches($fragment,[regex]::Escape($launches[0].Extent.Text)).Count) 'dispatch substitution is exact and unique'
    $fragment=$fragment.Replace($launches[0].Extent.Text,'(Invoke-WitnessDispatchProbe)')
    $dispatchBlock=[scriptblock]::Create($fragment)
    $script:QualificationDiskLedger=$instrumentation.Ledger
    $workerSource=Get-ActualWitnessTemplate -Fault $Fault -Descriptor $script:QualificationDiskLedger.Witness
    $configurationLiteral='{"validationFixture":true,"workerFault":"FixedControlledFault"}'
    $launchWorkerSource=$workerSource.Replace('__PRIVILEGED_WORKER_CONFIGURATION__',$configurationLiteral)
    $script:WitnessDispatchCount=0
    . $dispatchBlock
    Assert-Equal 1 $script:WitnessDispatchCount 'actual admitted caller reaches stub dispatch once'
    Assert-Equal $false ([IO.File]::Exists($script:QualificationDiskLedger.Witness.Path)) 'in-process dispatch creates no witness file'
    $rejected=$false
    try { . $dispatchBlock } catch { $rejected=$true }
    Assert-Equal $true $rejected 'actual caller rejects repeated admission before dispatch'
    Assert-Equal 1 $script:WitnessDispatchCount 'rejected repeated caller cannot dispatch'
    Assert-Equal $false $script:QualificationDiskLedger.Valid 'actual repeated caller invalidates inventory'
    $script:QualificationDiskLedger=New-WitnessTestLedger -Fault $Fault -CaseRoot $CaseRoot -Manifest ($manifestText|ConvertFrom-Json)
    $workerSource+='; [IO.File]::WriteAllText(''foreign'',''unaccounted'')'
    $launchWorkerSource=$workerSource.Replace('__PRIVILEGED_WORKER_CONFIGURATION__',$configurationLiteral)
    $script:WitnessDispatchCount=0
    $rejected=$false
    try { . $dispatchBlock } catch { $rejected=$true }
    Assert-Equal $true $rejected 'actual caller rejects altered concrete source before dispatch'
    Assert-Equal 0 $script:WitnessDispatchCount 'invalid actual caller dispatch count remains zero'
    Assert-Equal $false $script:QualificationDiskLedger.Valid 'invalid actual caller cannot qualify after product fault mapping'
    Assert-Equal 0L $script:QualificationDiskLedger.TotalBytes 'invalid caller reserves no bytes and starts no process'
}

try {
    $null=[IO.Directory]::CreateDirectory($root)
    $manifest=$manifestText | ConvertFrom-Json
    $normalizers=@($harnessAst.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'ConvertTo-QualificationPlanFault'
    },$false))
    $normalizationAssignments=@($harnessAst.FindAll({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -ceq 'QualificationPlanFault' -and
        $node.Right.Extent.Text.Contains('ConvertTo-QualificationPlanFault')
    },$true))
    $witnessSelectors=@($harnessAst.FindAll({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -ceq 'witnessFault'
    },$true))
    Assert-Equal 1 $witnessSelectors.Count 'actual harness witness selection has one closed assignment'
    # The preserved round1 intentionally has no normalizer: these checks then
    # reproduce its real mixed-case selector failure, before any worker starts.
    foreach ($canonicalMode in @('PrivilegePreStartCancel','PrivilegePreStartTimeout','PrivilegePostStartLoss')) {
        foreach ($spelling in @($canonicalMode,$canonicalMode.ToUpperInvariant(),$canonicalMode.ToLowerInvariant(),
            ($canonicalMode.Substring(0,9)+$canonicalMode.Substring(9).ToUpperInvariant()))) {
            $projection=& {
                param($RawMode,$NormalizerNodes,$AssignmentNodes,$SelectorNode)
                $QualificationPlanFault=$RawMode
                if ($NormalizerNodes.Count -eq 1 -and $AssignmentNodes.Count -eq 1) {
                    . ([scriptblock]::Create($NormalizerNodes[0].Extent.Text))
                    . ([scriptblock]::Create($AssignmentNodes[0].Extent.Text))
                }
                . ([scriptblock]::Create($SelectorNode.Extent.Text))
                [pscustomobject]@{canonical=$QualificationPlanFault;witness=$witnessFault}
            } $spelling $normalizers $normalizationAssignments $witnessSelectors[0]
            Assert-Equal $canonicalMode $projection.witness 'every accepted case spelling selects its witness admission'
            Assert-Equal $canonicalMode $projection.canonical 'transformation, lifecycle and inventory consume the same canonical fault'
        }
    }
    $regions=[regex]::Matches([IO.File]::ReadAllText($candidate),
        '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
    Assert-Equal $true ($regions.Count -gt 0) 'actual pinned candidate has generated production module regions'
    $actualModuleText=($regions|ForEach-Object{$_.Groups[2].Value}) -join [Environment]::NewLine
    $actualModuleText=Rename-QualificationFunction -Source $actualModuleText -Name 'Invoke-PrivilegedCollectionPlan' -Replacement 'Invoke-ControlledPrivilegedCollectionPlan'
    foreach ($fault in @('PrivilegePreStartCancel','PrivilegePreStartTimeout','PrivilegePostStartLoss')) {
        Test-ActualWitnessControllerSeam -Fault $fault -ModuleText $actualModuleText -CandidatePath $candidate -CaseRoot (Join-Path $root ($fault+"-actual-controller-quote's path"))
    }

    Assert-Equal $true ($null -eq (New-QualificationWitnessDescriptor -Fault '' -Root $root -Manifest $manifest)) 'ordinary controlled assessments require no witness reservation'
    foreach ($fault in @('PrivilegePreStartCancel','PrivilegePreStartTimeout','PrivilegePostStartLoss')) {
        $caseRoot=Join-Path $root ($fault+"-quote's path")
        $null=[IO.Directory]::CreateDirectory($caseRoot)
        $script:QualificationDiskLedger=New-WitnessTestLedger -Fault $fault -CaseRoot $caseRoot -Manifest $manifest
        $descriptor=$script:QualificationDiskLedger.Witness
        $template=Get-ActualWitnessTemplate -Fault $fault -Descriptor $descriptor
        $repeated=Get-ActualWitnessTemplate -Fault $fault -Descriptor $descriptor
        Assert-Equal $template $repeated 'repeated real source generation is deterministic'
        Assert-Equal 0L $script:QualificationDiskLedger.TotalBytes 'policy/source evaluation does not reserve or write'
        Assert-Equal 0L $descriptor.LaunchAdmissions 'source generation cannot consume launch admission'
        $configuration='{"validationFixture":true,"workerFault":"FixedControlledFault"}'
        $launch=$template.Replace('__PRIVILEGED_WORKER_CONFIGURATION__',$configuration)
        Invoke-QualificationWitnessAdmission -TemplateSource $template -LaunchSource $launch -ConfigurationLiteral $configuration
        Assert-Equal 1L $descriptor.LaunchAdmissions 'one launch is admitted before process creation'
        Assert-Equal $descriptor.ReservationBytes $script:QualificationDiskLedger.TotalBytes 'all witness bytes reserved before any write'
        Assert-Equal $true $script:QualificationDiskLedger.Valid 'exact concrete worker source retains valid inventory'
        Assert-Equal 1L $script:QualificationDiskLedger.Counts.PrivilegedFaultWitness.writes 'one finite write is counted'
        # Exercise the same default WriteAllText overload in the actual pwsh host.
        [IO.File]::WriteAllText($descriptor.Path,$descriptor.Content)
        $actualBytes=([IO.FileInfo]$descriptor.Path).Length
        Assert-Equal $true ($actualBytes -le $descriptor.ReservationBytes) 'actual UTF8 witness bytes are covered including possible BOM'
        Assert-Equal $descriptor.Content ([IO.File]::ReadAllText($descriptor.Path)) 'witness contents remain unchanged'
        [IO.File]::Delete($descriptor.Path)
        Assert-Equal $descriptor.ReservationBytes $script:QualificationDiskLedger.TotalBytes 'deleting witness does not subtract reserved bytes'
        $rejected=$false
        try { Invoke-QualificationWitnessAdmission -TemplateSource $template -LaunchSource $launch -ConfigurationLiteral $configuration } catch { $rejected=$true }
        Assert-Equal $true $rejected 'second launch is refused before it can start'
        Assert-Equal $false $script:QualificationDiskLedger.Valid 'repeated launch independently invalidates qualification'
        Assert-Equal $descriptor.ReservationBytes $script:QualificationDiskLedger.TotalBytes 'rejected repeat cannot erase or duplicate reservation'

        foreach ($mutation in @('TemplateExtraWrite','TemplateContent','TemplateEscape','LaunchExtraWrite','LaunchConfiguration','ReservationString','AdmissionString')) {
            $script:QualificationDiskLedger=New-WitnessTestLedger -Fault $fault -CaseRoot $caseRoot -Manifest $manifest
            $descriptor=$script:QualificationDiskLedger.Witness
            $badTemplate=$template; $badLaunch=$launch
            switch ($mutation) {
                'TemplateExtraWrite' { $badTemplate+='; [IO.File]::WriteAllText(''unaccounted'',''extra'')' }
                'TemplateContent' { $badTemplate=$template.Replace($descriptor.Content,'ChangedWitness') }
                'TemplateEscape' { $badTemplate=$template.Replace($descriptor.Path.Replace("'","''"),'..\foreign.txt') }
                'LaunchExtraWrite' { $badLaunch+='; [IO.File]::WriteAllText(''unaccounted'',''extra'')' }
                'LaunchConfiguration' { $badLaunch=$template.Replace('__PRIVILEGED_WORKER_CONFIGURATION__','{"different":true}') }
                'ReservationString' { $descriptor.ReservationBytes=$descriptor.ReservationBytes.ToString() }
                'AdmissionString' { $descriptor.LaunchAdmissions='0' }
            }
            # A product reducer may map any caught exception to expected worker loss.
            $mappedReason=''
            try { Invoke-QualificationWitnessAdmission -TemplateSource $badTemplate -LaunchSource $badLaunch -ConfigurationLiteral $configuration }
            catch { $mappedReason='PRIVILEGE.WORKER_LOST' }
            Assert-Equal 'PRIVILEGE.WORKER_LOST' $mappedReason 'mutated launch evidence is rejected at admission'
            Assert-Equal $false $script:QualificationDiskLedger.Valid 'expected product fault mapping cannot qualify invalid inventory'
            Assert-Equal 0L $script:QualificationDiskLedger.TotalBytes 'rejection happens before byte reservation and process start'
            Assert-Equal $false ([IO.File]::Exists($descriptor.Path)) 'refused launch creates no witness'
        }
        # Admission is conservative if process creation fails after reservation.
        $script:QualificationDiskLedger=New-WitnessTestLedger -Fault $fault -CaseRoot $caseRoot -Manifest $manifest
        Invoke-QualificationWitnessAdmission -TemplateSource $template -LaunchSource $launch -ConfigurationLiteral $configuration
        Assert-Equal $false ([IO.File]::Exists($script:QualificationDiskLedger.Witness.Path)) 'launch preparation can reserve without a completed write'
        Assert-Equal $script:QualificationDiskLedger.Witness.ReservationBytes $script:QualificationDiskLedger.TotalBytes 'not reaching the write preserves worst-case reservation'
    }
    foreach ($mutation in @('Version','Scope','Duplicate','Unknown','Content','Escape','Encoding','LaunchCount','LaunchString','Bytes','BytesString')) {
        $invalid=$manifestText | ConvertFrom-Json
        switch ($mutation) {
            'Version' { $invalid.version='unknown' }
            'Scope' { $invalid.scope='unknown' }
            'Duplicate' { $invalid.privilegedFaultWitnesses[1].fault=$invalid.privilegedFaultWitnesses[0].fault }
            'Unknown' { $invalid.privilegedFaultWitnesses[0].fault='UnknownFault' }
            'Content' { $invalid.privilegedFaultWitnesses[0].content='Changed' }
            'Escape' { $invalid.privilegedFaultWitnesses[0].relativePath='..\foreign.txt' }
            'Encoding' { $invalid.privilegedFaultWitnesses[0].encodingBound='UnknownEncoding' }
            'LaunchCount' { $invalid.privilegedFaultWitnesses[0].maximumLaunches=2 }
            'LaunchString' { $invalid.privilegedFaultWitnesses[0].maximumLaunches='1' }
            'Bytes' { $invalid.privilegedFaultWitnesses[0].reservationBytes=0 }
            'BytesString' { $invalid.privilegedFaultWitnesses[0].reservationBytes=$invalid.privilegedFaultWitnesses[0].reservationBytes.ToString() }
        }
        $rejected=$false
        try { $null=New-QualificationWitnessDescriptor -Fault 'PrivilegePreStartCancel' -Root $root -Manifest $invalid } catch { $rejected=$true }
        Assert-Equal $true $rejected 'changed manifest descriptors cannot admit a witness launch'
    }
    $rejected=$false
    try { $null=New-QualificationWitnessDescriptor -Fault 'UnknownFault' -Root $root -Manifest $manifest } catch { $rejected=$true }
    Assert-Equal $true $rejected 'unknown requested witness mode is rejected'
    $recoveryGuard='if ($RecoveryDestination -or $InterruptHandoffPath) {'
    Assert-Equal 1 ([regex]::Matches($harnessText,[regex]::Escape($recoveryGuard)).Count) 'broader recovery and handoff configurations remain explicitly inadmissible'
}
catch { $bodyError=$_ }
finally {
    Complete-QualificationHarness -BodyError $bodyError -Cleanup @(
        {
            $boundary=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
            $resolved=[IO.Path]::GetFullPath($root)
            if (-not $resolved.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)) { throw 'Witness fixture cleanup escaped its owned parent.' }
            if ([IO.Directory]::Exists($resolved) -and ([IO.File]::GetAttributes($resolved) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Witness fixture root identity is ambiguous.' }
            if ([IO.Directory]::Exists($resolved)) { Remove-Item -LiteralPath $resolved -Recurse -Force }
            if ([IO.Directory]::Exists($resolved)) { throw 'Owned witness fixture absence remains unverified.' }
        }
    )
}

}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
Write-Output 'PASS: finite privileged witness inventory reserves before one launch, validates actual emitted source, and independently rejects tampering and repeat admission.'
