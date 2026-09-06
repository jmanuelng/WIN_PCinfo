[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $repositoryRoot 'src/SystemCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$source=Get-PolicyUserContextSource
if($source -match 'NetGetJoinInformation|NetGetAadJoinInformation|NTAccount|LookupAccountName'){
    throw 'Policy session verification cannot include directory-capable identity or join sources.'
}
. ([scriptblock]::Create($source))
Initialize-IdentityEnrollmentNativeSource

# Check the exact nested payload after the same source minimization performed
# at launch. No worker is launched and no Windows data source is invoked.
$worker=Get-PrivilegedCollectionWorkerSource
$minimized=@($worker -split "\r?\n" | Where-Object {
    $_ -notmatch '^\s*(?:#|//)' -and -not [string]::IsNullOrWhiteSpace($_)
} | ForEach-Object {$_.Trim()}) -join "`n"
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($minimized,[ref]$tokens,[ref]$errors)
Assert-Equal 0 $errors.Count 'the source with nested SYSTEM and policy verification parses after launch minimization'
$node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq 'Get-SystemCollectionWorkerSource'},$false)
$nested=& ([scriptblock]::Create($node.Extent.Text + "`nGet-SystemCollectionWorkerSource"))
Assert-Equal (Get-SystemCollectionWorkerSource) $nested 'launch composition preserves the exact reviewed SYSTEM worker source'
Assert-Equal $true ((ConvertTo-PrivilegedCollectionInlineCommand -Source $worker).Length -le 32500) 'the unchanged Windows launch bound admits the composed worker template'
$maximumLength=0
$policy=Get-PrivilegedCollectionPlanPolicy
foreach($sample in 1..8){
    # All source substitutions are coordinator-owned. Exercise maximum-width
    # numeric fields, the longest scenario names and independent full digests.
    $hex=@(1..5|ForEach-Object {[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()})
    $configuration=[ordered]@{
        pipe=$policy.channel.pipeNamePrefix+$hex[0].Substring(0,32);nonce=$hex[0]
        maximumBytes=16384;deadlineMilliseconds=2147483647;coordinatorProcessId=2147483647
        executableSha256=$hex[1];workerPayloadSha256=$hex[2];planDigest=$hex[3]
        workerFault='HangAfterPlan';firmwareScenario='SecureBootUnsupported'
        administratorScenario='DomainGroupUnresolved';effectivePolicyScenario='AppLockerChannelIncomplete'
        jobName=$policy.channel.jobNamePrefix+$hex[0].Substring(0,32)
        systemEnabled=$true;systemPlanDigest=$hex[4];validationFixture=$true
    }
    $configured=$worker.Replace('__PRIVILEGED_WORKER_CONFIGURATION__',($configuration|ConvertTo-Json -Compress).Replace("'","''"))
    $length=(ConvertTo-PrivilegedCollectionInlineCommand -Source $configured).Length
    $maximumLength=[Math]::Max($maximumLength,$length)
    Assert-Equal $true ($length -le 32500) 'fully configured high-entropy launch retains the fixed Windows guard'
}
Write-Output "PASS: configured launch bound samples; maximum command characters $maximumLength of 32500."
Write-Output 'PASS: local context native compilation, parser and exact nested SYSTEM source preservation; no live source calls.'
