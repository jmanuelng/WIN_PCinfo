[CmdletBinding()]
param([string] $CandidatePath = '', [string] $PreparedManifestPath = '', [string] $PreparedManifestSha256 = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'build/Start-WIN-PCInfo.ps1')
$candidateContext = Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidateUseError = $null
try {
$application = $candidateContext.Path
$hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$starting = 'Starting WIN-PCInfo - verifying application trust and runtime. No assessment has started.'
$opening = 'Opening guided window - preparation and approval are pending.'
$originalOut = [Console]::Out
$originalError = [Console]::Error
$output = [IO.StringWriter]::new()
$feedback = [IO.StringWriter]::new()
$validSignature = {
    Assert-Equal $starting $feedback.ToString().Trim() 'startup feedback is visible before trust checking'
    Start-Sleep -Milliseconds 20
    [pscustomobject]@{ Status = 'Valid' }
}
$probe = {
    Assert-Equal $starting $feedback.ToString().Trim() 'startup feedback is visible before runtime probing'
    Start-Sleep -Milliseconds 20
    [pscustomobject]@{ Eligible = $true }
}
$launch = {
    param($Executable, $Arguments)
    Assert-Equal ($starting + [Environment]::NewLine + $opening) $feedback.ToString().Trim() 'both messages precede delayed GUI launch'
    Assert-Equal $hostPath $Executable 'feedback cannot select another host'
    Assert-Equal '-STA' $Arguments[2] 'GUI still requires STA'
    Assert-Equal 'Gui' $Arguments[-1] 'GUI dispatch is unchanged'
    Start-Sleep -Milliseconds 20
    [pscustomobject]@{ ExitCode = 20; ReasonCode = 'PREPARATION.DECLINED'; StandardOutput = 'original'; StandardError = 'original error' }
}
$mustNotRun = { throw 'Rejected startup must not advance.' }
$originalDiscovery = ${function:Get-WinPCInfoRuntimeCandidates}
try {
    [Console]::SetOut($output)
    [Console]::SetError($feedback)
    function Get-WinPCInfoRuntimeCandidates {
        Assert-Equal $starting $feedback.ToString().Trim() 'default discovery also starts after feedback'
        $hostPath
    }
    $result = @(Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui -ReadSignature $validSignature -Probe $probe -Launch $launch)
    Assert-Equal 1 $result.Count 'status output cannot contaminate the launch result'
    Assert-Equal 'original' $result[0].StandardOutput 'application stdout is preserved'
    Assert-Equal 'original error' $result[0].StandardError 'application stderr is preserved'
    Assert-Equal '' $output.ToString() 'startup status never writes stdout'
    $null = $feedback.GetStringBuilder().Clear()
    function Get-WinPCInfoRuntimeCandidates { throw 'Explicit empty candidates must not discover.' }
    $empty = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui -CandidatePaths @() -ReadSignature $validSignature -Probe $mustNotRun -Launch $mustNotRun
    Assert-Equal 'RUNTIME.HOST_MISSING' $empty.ReasonCode 'explicit empty candidates preserve host-missing rejection'
    Assert-Equal $starting $feedback.ToString().Trim() 'empty candidates never promise a window'
    foreach ($failure in @('Signature', 'SignatureThrow', 'Runtime', 'Launch')) {
        $null = $feedback.GetStringBuilder().Clear()
        $signature = $validSignature
        $runtime = $probe
        $dispatch = $mustNotRun
        $reason = 'LAUNCH.SIGNATURE_INVALID'
        if ($failure -eq 'Signature') { $signature = { Assert-Equal $starting $feedback.ToString().Trim() 'blocked trust has truthful status'; [pscustomobject]@{ Status = 'HashMismatch' } }; $runtime = $mustNotRun }
        elseif ($failure -eq 'SignatureThrow') { $signature = { throw 'Trust adapter failed.' }; $runtime = $mustNotRun }
        elseif ($failure -eq 'Runtime') { $runtime = { Assert-Equal $starting $feedback.ToString().Trim() 'blocked runtime has truthful status'; [pscustomobject]@{ Eligible = $false; ReasonCode = 'LAUNCH.POLICY_REJECTED' } }; $reason = 'LAUNCH.POLICY_REJECTED' }
        else { $dispatch = { Assert-Equal ($starting + [Environment]::NewLine + $opening) $feedback.ToString().Trim() 'opening message precedes launch failure'; throw 'Launch rejected.' }; $reason = 'LAUNCH.POLICY_REJECTED' }
        $result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui -CandidatePaths @($hostPath) -ReadSignature $signature -Probe $runtime -Launch $dispatch
        Assert-Equal $reason $result.ReasonCode "$failure preserves original rejection"
        Assert-Equal 20 $result.ExitCode "$failure cannot claim an assessment"
        if ($failure -ne 'Launch') { Assert-Equal $starting $feedback.ToString().Trim() "$failure never promises a window" }
    }
    $quietSignature = { [pscustomobject]@{ Status = 'NotSigned' } }
    $quietLaunch = { param($Executable, $Arguments) [pscustomobject]@{ ExitCode = 0; ReasonCode = ''; StandardOutput = 'protocol'; StandardError = '' } }
    foreach ($workflow in @('Help', 'About', 'Verify', 'CheckRuntime')) {
        $null = $feedback.GetStringBuilder().Clear()
        $result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -ApplicationArguments @('-Workflow', $workflow) -CandidatePaths @($hostPath) -ReadSignature $quietSignature -Probe { [pscustomobject]@{ Eligible = $true } } -Launch $quietLaunch
        Assert-Equal '' $feedback.ToString() 'passive workflows remain quiet'
        Assert-Equal 'protocol' $result.StandardOutput 'non-GUI stdout contract is unchanged'
        Assert-Equal 0 $result.ExitCode 'passive unsigned admission is unchanged'
    }
    foreach ($sink in @({ param($Text) 'unwanted pipeline output' }, { throw 'Presentation failed.' })) {
        $result = @(Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui -CandidatePaths @($hostPath) -ReadSignature { [pscustomobject]@{ Status = 'HashMismatch' } } -Probe $mustNotRun -Launch $mustNotRun -WriteStatus $sink)
        Assert-Equal 1 $result.Count 'a noisy or failed sink cannot change result shape'
        Assert-Equal 'LAUNCH.SIGNATURE_INVALID' $result[0].ReasonCode 'presentation failure cannot grant authority'
    }
}
finally {
    Set-Item -LiteralPath Function:Get-WinPCInfoRuntimeCandidates -Value $originalDiscovery
    [Console]::SetOut($originalOut)
    [Console]::SetError($originalError)
    $output.Dispose()
    $feedback.Dispose()
}
}
catch { $candidateUseError = $_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
Write-Output 'PASS: GUI startup stderr precedes trust, discovery, runtime and launch without changing authority or stdout.'
