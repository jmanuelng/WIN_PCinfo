[CmdletBinding()]
param([string] $CandidatePath = '')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Pure controls extract the actual harness seam; no engine, native worker,
# process observer, mutex, task, trust store or resource sampler is invoked.
function Assert-ControlledLockEqual {
    param($Expected,$Actual,[string]$Message)
    if ($Expected -cne $Actual) { throw $Message }
}
function Assert-ControlledLockRefused {
    param([scriptblock]$Body,[string]$Message)
    $refused=$false
    try { $null=& $Body } catch { $refused=$true }
    Assert-ControlledLockEqual $true $refused $Message
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$harnessPath=Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'
$tokens=$null;$errors=$null
$harness=[Management.Automation.Language.Parser]::ParseFile($harnessPath,[ref]$tokens,[ref]$errors)
Assert-ControlledLockEqual 0 $errors.Count 'Actual controlled harness must parse.'
foreach($name in @('Get-ControlledRunLockAdmission','Add-ControlledRunLockNamespace')){
    $definitions=@($harness.FindAll({param($n)
        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name
    }.GetNewClosure(),$false))
    Assert-ControlledLockEqual 1 $definitions.Count 'Actual controlled seam must be unique.'
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
. (Join-Path $PSScriptRoot 'AssessmentQualificationSupport.ps1')
$cohort='a'*64
$namespace='Local\WINPCInfo-Qualification-'+$cohort+'-worker1'
$binding=@{
    ControlledRunLockNamespace=$namespace; CandidatePath='candidate.ps1'
    PreparedManifestPath='prepared.json'; PreparedManifestSha256=$cohort
    QualificationPath='controlled.json'; RemoteSourceScenario='Configured'
}
$admission=Get-ControlledRunLockAdmission -Namespace $namespace -Arguments $binding
$bindingReplay=[scriptblock]::Create('[CmdletBinding()]'+"`n"+$harness.ParamBlock.Extent.Text+
    "`nGet-ControlledRunLockAdmission -Namespace `$ControlledRunLockNamespace -Arguments `$PSBoundParameters")
$boundAdmission=& $bindingReplay @binding
Assert-ControlledLockEqual $namespace $boundAdmission.replacementNamespace 'Actual parameter binding dictionary must be admitted.'
$incompatible=$binding.Clone();$incompatible.Wpf=$false
Assert-ControlledLockRefused {& $bindingReplay @incompatible} 'Actual explicit false switch binding must be refused.'
Assert-ControlledLockEqual $namespace $admission.replacementNamespace 'Exact namespace must be disclosed.'
Assert-ControlledLockEqual $cohort $admission.cohort 'Exact cohort must be disclosed.'
Assert-ControlledLockEqual 1 $admission.worker 'Worker must be fixed to one or two.'
foreach($claim in @('productionLockQualification','resourceQualification','clientQualification')){
    Assert-ControlledLockEqual 'NotQualified' $admission[$claim] 'Controlled evidence cannot qualify physical/client gates.'
}
$platform=$binding.Clone();$platform.Remove('RemoteSourceScenario');$platform.PlatformSourceScenario='Running'
$platform.ControlledRunLockNamespace=$namespace.Replace('-worker1','-worker2')
$null=Get-ControlledRunLockAdmission -Namespace $platform.ControlledRunLockNamespace -Arguments $platform
Assert-ControlledLockEqual $null (Get-ControlledRunLockAdmission -Namespace '' -Arguments @{}) 'Empty default must preserve admission.'
Assert-ControlledLockEqual 'unchanged' (Add-ControlledRunLockNamespace -ModuleText 'unchanged' -Namespace '') 'Empty default must preserve source bytes.'
foreach($bad in @(
    $namespace.Replace('Local\','Global\'),$namespace.Replace('worker1','worker0'),
    $namespace.Replace('worker1','worker3'),$namespace.Replace('worker1','worker01'),
    $namespace.Replace($cohort,'a'*63),$namespace.Replace($cohort,'a'*65),
    $namespace.Replace($cohort,'g'*64),$namespace.Replace($cohort,'A'*64),
    ($namespace+"`n"),($namespace+'-extra'),'arbitrary')){
    $invalid=$binding.Clone();$invalid.ControlledRunLockNamespace=$bad
    Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $bad -Arguments $invalid} ('Malformed namespace must fail: '+$bad.Replace("`n",'<LF>'))
    Assert-ControlledLockRefused {Add-ControlledRunLockNamespace -ModuleText 'unchanged' -Namespace $bad} 'Transform must reject malformed namespace.'
}
foreach($missing in @('ControlledRunLockNamespace','CandidatePath','PreparedManifestPath','PreparedManifestSha256','QualificationPath')){
    $invalid=$binding.Clone();$invalid.Remove($missing)
    Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $namespace -Arguments $invalid} 'Missing root binding must fail.'
}
foreach($empty in @('CandidatePath','PreparedManifestPath','PreparedManifestSha256','QualificationPath')){
    $invalid=$binding.Clone();$invalid[$empty]=''
    Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $namespace -Arguments $invalid} 'Empty root binding must fail.'
}
$invalid=$binding.Clone();$invalid.PreparedManifestSha256='B'*64
Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $namespace -Arguments $invalid} 'Noncanonical manifest digest must fail.'
$invalid=$binding.Clone();$invalid.PreparedManifestSha256='b'*64
Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $namespace -Arguments $invalid} 'Stale valid namespace cohort must fail against another manifest.'
Assert-ControlledLockRefused {& $bindingReplay @invalid} 'Actual parameter binding must reject a stale cohort.'
$invalid=$binding.Clone();$invalid.PlatformSourceScenario='Running'
Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $namespace -Arguments $invalid} 'Two source cases must fail.'
$invalid=$binding.Clone();$invalid.Remove('RemoteSourceScenario')
Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $namespace -Arguments $invalid} 'No source case must fail.'
foreach($case in @('configured','Absent','')){
    $invalid=$binding.Clone();$invalid.RemoteSourceScenario=$case
    Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $namespace -Arguments $invalid} 'Nonexact Remote case must fail.'
}
$invalid=$platform.Clone();$invalid.PlatformSourceScenario='Configured'
Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $invalid.ControlledRunLockNamespace -Arguments $invalid} 'Nonexact Platform case must fail.'
$allowed=@('ControlledRunLockNamespace','CandidatePath','PreparedManifestPath','PreparedManifestSha256',
    'QualificationPath','RemoteSourceScenario','PlatformSourceScenario')
foreach($parameter in $harness.ParamBlock.Parameters){
    $name=$parameter.Name.VariablePath.UserPath
    if($name -in $allowed){continue}
    $invalid=$binding.Clone();$invalid[$name]=$false
    Assert-ControlledLockRefused {Get-ControlledRunLockAdmission -Namespace $namespace -Arguments $invalid} 'Every incompatible bound parameter, including false, must fail.'
}
$policyPath=Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-run-lifecycle.json'
$sourcePath=Join-Path $repositoryRoot 'src/RunLifecycle.ps1'
$sourceBefore=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
$candidateBefore=if($CandidatePath){(Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256).Hash}else{''}
$policyText=[IO.File]::ReadAllText($policyPath).Replace("`r`n","`n").Replace("`r","`n")
$bytes=[Text.UTF8Encoding]::new($false).GetBytes($policyText)
$digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
$originalSource=[IO.File]::ReadAllText($sourcePath).
    Replace('__RUN_LIFECYCLE_POLICY_BASE64__',[Convert]::ToBase64String($bytes)).
    Replace('__RUN_LIFECYCLE_POLICY_SHA256__',$digest)
$originalBytes=[Text.UTF8Encoding]::new($false).GetBytes($originalSource)
$originalHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($originalBytes))
$transformed=Add-ControlledRunLockNamespace -ModuleText $originalSource -Namespace $namespace
. ([scriptblock]::Create($transformed))
$actualOriginal=Get-ControlledOriginalAssessmentRunLifecyclePolicy
$copy=Get-AssessmentRunLifecyclePolicy
Assert-ControlledLockEqual $namespace $copy.activeRunLock.name 'Actual validated getter must receive replacement on clone.'
Assert-ControlledLockEqual 'Global\WINPCInfo-AssessmentRun-v1' $actualOriginal.activeRunLock.name 'Actual original getter must stay unchanged.'
$copy.activeRunLock.name=$actualOriginal.activeRunLock.name
Assert-ControlledLockEqual ($actualOriginal|ConvertTo-Json -Depth 100 -Compress) ($copy|ConvertTo-Json -Depth 100 -Compress) 'Only the lock name may differ in actual policy.'
$script:RunLifecyclePolicyDigest='0'*64
Assert-ControlledLockRefused {Get-AssessmentRunLifecyclePolicy} 'Original embedded integrity failure must propagate.'
$script:RunLifecyclePolicyDigest=$digest
$script:ControlledPolicyFixture=Get-ControlledOriginalAssessmentRunLifecyclePolicy
$script:ControlledOriginalCalls=0
$fixtureSource='function Get-AssessmentRunLifecyclePolicy { $script:ControlledOriginalCalls++; $script:ControlledPolicyFixture }'
. ([scriptblock]::Create((Add-ControlledRunLockNamespace -ModuleText $fixtureSource -Namespace $namespace)))
$originalJson=$script:ControlledPolicyFixture|ConvertTo-Json -Depth 100 -Compress
$copy=Get-AssessmentRunLifecyclePolicy
Assert-ControlledLockEqual 1 $script:ControlledOriginalCalls 'Wrapper must call original getter exactly once.'
Assert-ControlledLockEqual $false ([object]::ReferenceEquals($copy,$script:ControlledPolicyFixture)) 'Returned policy must be cloned.'
Assert-ControlledLockEqual $false ([object]::ReferenceEquals($copy.activeRunLock,$script:ControlledPolicyFixture.activeRunLock)) 'Nested lock must be cloned.'
$copy.outcomes[0].outcome='changed-copy'
Assert-ControlledLockEqual $originalJson ($script:ControlledPolicyFixture|ConvertTo-Json -Depth 100 -Compress) 'Clone mutation must not affect original policy.'
$script:ControlledPolicyFixture.activeRunLock.name='unexpected'
Assert-ControlledLockRefused {Get-AssessmentRunLifecyclePolicy} 'Unrecognized original production lock must fail.'
foreach($invalidSource in @('function Other {}',($fixtureSource+"`n"+$fixtureSource),
    ($fixtureSource+"`nfunction Get-ControlledOriginalAssessmentRunLifecyclePolicy {}"),
    ($fixtureSource+"`nfunction get-controlledoriginalassessmentrunlifecyclepolicy {}"),'function {')){
    Assert-ControlledLockRefused {Add-ControlledRunLockNamespace -ModuleText $invalidSource -Namespace $namespace} 'Missing, duplicate or competing getters must fail.'
}
Assert-ControlledLockEqual $originalHash ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($originalSource)))) 'Candidate module fixture bytes must stay unchanged.'
Assert-ControlledLockEqual $sourceBefore (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash 'Production getter source bytes must stay unchanged.'
if($CandidatePath){
    Assert-ControlledLockEqual $candidateBefore (Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256).Hash 'Supplied candidate file bytes must stay unchanged.'
}
Write-Output 'PASS: pure controlled run lock admission, validated getter, clone, refusal and byte preservation controls.'
