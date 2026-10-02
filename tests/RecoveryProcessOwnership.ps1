Set-StrictMode -Version Latest

function Test-RecoveryProcessObservation {
    param(
        [Parameter(Mandatory)] $Entry,
        [Parameter(Mandatory)] [Diagnostics.Process] $Process,
        [Parameter(Mandatory)] [Diagnostics.Process] $Parent,
        [Parameter(Mandatory)] [string] $ExpectedImage,
        [Parameter(Mandatory)] [datetime] $ObservedAtUtc
    )
    if ($Parent.HasExited -or $Process.HasExited -or
        [int]$Entry.ProcessId -ne $Process.Id -or [int]$Entry.ParentProcessId -ne $Parent.Id -or
        [string]::IsNullOrWhiteSpace([string]$Entry.ExecutablePath) -or $null -eq $Entry.CreationDate) { return $false }
    $image = [IO.Path]::GetFullPath($ExpectedImage)
    if (-not [IO.Path]::GetFullPath([string]$Entry.ExecutablePath).Equals($image, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($Process.MainModule.FileName).Equals($image, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $createdUtc = ([datetime]$Entry.CreationDate).ToUniversalTime()
    $actualUtc = $Process.StartTime.ToUniversalTime()
    # Win32_Process represents creation time to microsecond precision. Match
    # the held process's native timestamp within strictly less than one us.
    if ([Math]::Abs($createdUtc.Ticks - $actualUtc.Ticks) -ge 10 -or
        $actualUtc -lt $Parent.StartTime.ToUniversalTime() -or $actualUtc -gt $ObservedAtUtc.ToUniversalTime()) { return $false }
    return (-not $Parent.HasExited -and -not $Process.HasExited)
}

function Open-VerifiedRecoveryProcess {
    param(
        [Parameter(Mandatory)] $Entry,
        [Parameter(Mandatory)] [Diagnostics.Process] $Parent,
        [Parameter(Mandatory)] [string] $ExpectedImage,
        [Parameter(Mandatory)] [datetime] $ObservedAtUtc
    )
    # Admission precedes opening the recorded descendant PID. A held, still-
    # alive parent prevents an unrelated lifetime from becoming this ancestor.
    if ($Parent.HasExited -or [int]$Entry.ParentProcessId -ne $Parent.Id -or
        [string]::IsNullOrWhiteSpace([string]$Entry.ExecutablePath) -or $null -eq $Entry.CreationDate -or
        -not [IO.Path]::GetFullPath([string]$Entry.ExecutablePath).Equals(
            [IO.Path]::GetFullPath($ExpectedImage), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Recovery descendant admission does not match its exact-owned parent and approved image.'
    }
    $process = [Diagnostics.Process]::GetProcessById([int]$Entry.ProcessId)
    try {
        $null = $process.Handle
        if (-not (Test-RecoveryProcessObservation -Entry $Entry -Process $process -Parent $Parent `
            -ExpectedImage $ExpectedImage -ObservedAtUtc $ObservedAtUtc)) {
            throw 'Recovery descendant PID, creation lifetime or image ownership could not be verified.'
        }
        return $process
    }
    catch { $process.Dispose(); throw }
}

function Stop-RecoveryApplication {
    param([Parameter(Mandatory)] [Diagnostics.Process] $Process)
    # A held application handle is termination authority only for that lifetime.
    # Descendant absence must be proved separately; never recursively kill an
    # unadmitted tree after a failed or incomplete observation.
    if (-not $Process.HasExited) { $Process.Kill() }
    if (-not $Process.WaitForExit(5000)) { throw 'Exact-owned recovery application remains active.' }
}
