[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$fixtureRoot = Join-Path $repositoryRoot ('.test-output/generated-input-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$candidatePath = Join-Path $fixtureRoot 'candidate.ps1'
$launcherPath = Join-Path $fixtureRoot 'launcher.ps1'
$evidencePath = Join-Path $fixtureRoot 'result.json'
$hostPath = Join-Path $PSHOME 'pwsh.exe'
$ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bodyError = $null
$observations = [Collections.Generic.List[object]]::new()

[IO.File]::WriteAllText($candidatePath, @'
param([string] $WitnessPath)
$ErrorActionPreference = 'Stop'
$self = [Diagnostics.Process]::GetCurrentProcess()
try {
    [IO.File]::WriteAllText($WitnessPath, ([ordered]@{
        processId = $PID
        processStartUtc = $self.StartTime.ToUniversalTime().ToString('o')
        inputRedirected = [Console]::IsInputRedirected
    } | ConvertTo-Json -Compress))
}
finally { $self.Dispose() }
$line = [Console]::In.ReadLine()
[ordered]@{ recordType = 'test.input'; eof = ($null -eq $line); line = $line } | ConvertTo-Json -Compress
'@, [Text.UTF8Encoding]::new($false))

[IO.File]::WriteAllText($launcherPath, @'
param([string] $HarnessPath, [string] $CandidatePath, [string] $HostPath, [string] $WitnessPath, [string] $Case)
$ErrorActionPreference = 'Stop'
. $HarnessPath
$parameters = @{
    CandidatePath = $CandidatePath
    PowerShellPath = $HostPath
    Arguments = @('-WitnessPath', $WitnessPath)
}
switch ($Case) {
    'Empty' { $parameters.StandardInput = '' }
    'Approve' { $parameters.StandardInput = "APPROVE`n" }
    'Decline' { $parameters.StandardInput = "decline`n" }
    'Omitted' { }
    default { throw 'Unknown input regression case' }
}
$result = Invoke-GeneratedApplication @parameters
[ordered]@{ exitCode = $result.ExitCode; records = $result.Records; stderr = $result.StandardError } | ConvertTo-Json -Depth 5 -Compress
'@, [Text.UTF8Encoding]::new($false))

function Stop-ExactInputRegressionProcess {
    param([Parameter(Mandatory)] $Process, [Parameter(Mandatory)] [string] $ExpectedPath,
        [Parameter(Mandatory)] [datetime] $StartUtc, [Parameter(Mandatory)] [int] $ExpectedParentId)

    if ($Process.HasExited) { return }
    $native = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $Process.Id)
    if ($null -eq $native -or $native.ParentProcessId -ne $ExpectedParentId -or
        [Math]::Abs(($native.CreationDate.ToUniversalTime() - $StartUtc).TotalMilliseconds) -gt 1 -or
        [Math]::Abs(($Process.StartTime.ToUniversalTime() - $StartUtc).TotalMilliseconds) -gt 1 -or
        -not $native.CommandLine.Contains($ExpectedPath)) {
        $exception = [InvalidOperationException]::new('Input regression exact process ownership changed')
        $exception.Data['OwnedCleanupUnverified'] = $true
        throw $exception
    }
    $owner = Invoke-CimMethod -InputObject $native -MethodName GetOwnerSid
    if ($owner.ReturnValue -ne 0 -or $owner.Sid -cne $ownerSid) {
        $exception = [InvalidOperationException]::new('Input regression process owner changed')
        $exception.Data['OwnedCleanupUnverified'] = $true
        throw $exception
    }
    $Process.Kill()
    if (-not $Process.WaitForExit(5000)) {
        $exception = [InvalidOperationException]::new('Input regression owned process did not stop')
        $exception.Data['OwnedCleanupUnverified'] = $true
        throw $exception
    }
}

try {
    foreach ($case in @('Omitted', 'Empty', 'Approve', 'Decline')) {
        $witnessPath = Join-Path $fixtureRoot ($case + '-witness.json')
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $hostPath
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in @('-NoLogo', '-NoProfile', '-File', $launcherPath,
            '-HarnessPath', (Join-Path $PSScriptRoot 'TestHarness.ps1'), '-CandidatePath', $candidatePath,
            '-HostPath', $hostPath, '-WitnessPath', $witnessPath, '-Case', $case)) {
            $null = $startInfo.ArgumentList.Add($argument)
        }
        $launcher = [Diagnostics.Process]::new()
        $launcher.StartInfo = $startInfo
        $launcherStart = $null
        $timedOut = $false
        $candidate = $null
        $caseError = $null
        try {
            $null = $launcher.Start()
            $launcherStart = $launcher.StartTime.ToUniversalTime()
            # Intentionally leave the launcher's redirected input open and empty.
            # The nested harness must supply its own EOF rather than inherit this pipe.
            $stdout = $launcher.StandardOutput.ReadToEndAsync()
            $stderr = $launcher.StandardError.ReadToEndAsync()
            if (-not $launcher.WaitForExit(15000)) {
                $timedOut = $true
                throw 'Generated application inherited open stdin instead of receiving deterministic EOF'
            }
            $output = $stdout.GetAwaiter().GetResult()
            $errors = $stderr.GetAwaiter().GetResult()
            Assert-Equal 0 $launcher.ExitCode 'the isolated harness invocation exits successfully'
            Assert-Equal '' $errors 'the isolated harness emits no outer stderr'
            $result = $output | ConvertFrom-Json -Depth 6
            Assert-Equal 0 $result.exitCode 'the nested native input candidate terminates normally'
            Assert-Equal '' $result.stderr 'the nested candidate emits no stderr'
            Assert-Equal 1 @($result.records).Count 'the helper preserves exactly one input record'
            $record = $result.records[0]
            $expectedEof = $case -in @('Omitted', 'Empty')
            Assert-Equal $expectedEof $record.eof 'omitted or empty input supplies EOF'
            if ($case -eq 'Approve') { Assert-Equal 'APPROVE' $record.line 'explicit approval bytes are preserved' }
            if ($case -eq 'Decline') { Assert-Equal 'decline' $record.line 'explicit nonapproval bytes are preserved' }
        }
        catch { $caseError = $_ }
        $observation = [ordered]@{ case = $case; timedOut = $timedOut; witnessRecorded = $false; inputRedirected = $null; exactOwnedCleanupVerified = $false }
        $observations.Add($observation)
        # Each cleanup action is attempted independently. The shared finalizer
        # retains the case failure and marks any unverified cleanup as unsafe.
        Complete-QualificationHarness -BodyError $caseError -Cleanup @(
            {
                if ($null -ne $launcherStart) {
                    if (-not (Test-Path -LiteralPath $witnessPath)) { throw 'Input candidate lifetime witness missing' }
                    $witness = Get-Content $witnessPath -Raw | ConvertFrom-Json
                    $observation.witnessRecorded = $true
                    $observation.inputRedirected = $witness.inputRedirected
                }
            },
            {
                if ($null -ne $launcherStart) {
                    Stop-ExactInputRegressionProcess -Process $launcher -ExpectedPath $launcherPath -StartUtc $launcherStart -ExpectedParentId $PID
                }
            },
            {
                if ($null -ne $launcherStart) {
                    $children = @(Get-CimInstance Win32_Process -Filter ('ParentProcessId=' + $launcher.Id))
                    foreach ($child in $children) {
                        if (-not $child.CommandLine.Contains($candidatePath) -or $child.CreationDate.ToUniversalTime() -lt $launcherStart) {
                            throw 'Unexpected isolated launcher descendant; owned cleanup refused'
                        }
                        $candidate = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
                        if ($null -eq $candidate) {
                            $fresh = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $child.ProcessId)
                            if ($null -ne $fresh -and [Math]::Abs(($fresh.CreationDate.ToUniversalTime() - $child.CreationDate.ToUniversalTime()).TotalMilliseconds) -le 1) {
                                throw 'Recorded input child could not be opened for owned cleanup'
                            }
                            continue
                        }
                        try { Stop-ExactInputRegressionProcess -Process $candidate -ExpectedPath $candidatePath -StartUtc $child.CreationDate.ToUniversalTime() -ExpectedParentId $launcher.Id }
                        finally { $candidate.Dispose() }
                    }
                }
            },
            {
                if (@(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($fixtureRoot) }).Count) {
                    throw 'Owned isolated input fixture process remains present'
                }
            },
            { $launcher.Dispose() }
        ) -RetainCleanupEvidence { $observation.exactOwnedCleanupVerified = $true }
    }
}
catch { $bodyError = $_ }
Complete-QualificationHarness -BodyError $bodyError -RetainEvidence {
    [IO.File]::WriteAllText($evidencePath, ([ordered]@{ scope = 'SyntheticNativeHarnessInputOnly'; applicationExecuted = $false; qualificationAccepted = $false; cases = $observations.ToArray() } | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
}
Write-Output 'PASS: subprocess harness supplies EOF with inherited input open and preserves explicit approval/nonapproval input.'
