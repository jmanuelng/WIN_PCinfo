[CmdletBinding()]
param([ValidateSet('Pure','Native')] [string] $Mode = 'Pure',
    [ValidateSet('NaturalZero','NaturalNonzero','Utf8Both','EofEmpty','EofInput','PipePressure','Timeout','InvalidUtf8','Overflow','UnsafeMarker','TerminalRetentionFailure')]
    [string] $Case = 'NaturalZero')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GeneratedApplicationNative.ps1')

function Assert-NativeFixture {
    param([bool] $Condition,[string] $Because)
    if (-not $Condition) { throw "Generated native fixture assertion failed: $Because" }
}

if ($Mode -eq 'Pure') {
    Initialize-GeneratedApplicationNativeSupervisor
    $checks=0
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    function Read-CaptureFixture {
        param([byte[]] $OutputBytes,[byte[]] $ErrorBytes,[int] $Lines=32,[int] $LineCharacters=512,[int] $TotalCharacters=4096)
        $owner=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new('','',[string[]]@(),'', $Lines,$LineCharacters,$TotalCharacters)
        try { $owner.CaptureFixture($OutputBytes,$ErrorBytes) } finally { $owner.Dispose() }
    }
    foreach ($text in @('',"one`r`ntwo`nthree`r", "`n`r`n", '日本語 ñ 😀')) {
        $capture=Read-CaptureFixture -OutputBytes $utf8.GetBytes($text) -ErrorBytes $utf8.GetBytes("error`r`n")
        Assert-NativeFixture ([WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($capture.Lines,'stdout') -ceq $text) 'stdout retains CRLF, LF and unterminated CR exactly'
        Assert-NativeFixture ([WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($capture.Lines,'stderr') -ceq "error`r`n") 'stderr is independently preserved'
        Assert-NativeFixture (-not $capture.OwnedCleanupUnverified -and -not $capture.Started) 'pure capture starts no process'
        $checks+=3
    }
    $capture=Read-CaptureFixture -OutputBytes ([byte[]]@(0xff)) -ErrorBytes ([byte[]]@())
    Assert-NativeFixture ($capture.StreamFailure -and $capture.OwnedCleanupUnverified) 'invalid UTF8 remains unsafe despite raw remainder draining'
    $checks++
    $capture=Read-CaptureFixture -OutputBytes $utf8.GetBytes(('x'*513)) -ErrorBytes ([byte[]]@())
    Assert-NativeFixture ($capture.OutputOverflow -and $capture.DroppedLines -eq 1 -and $capture.Lines.Count -eq 0) 'oversized line cannot become a truncated pass'
    $checks++
    $capture=Read-CaptureFixture -OutputBytes $utf8.GetBytes("accepted`nQUALIFICATION.OWNED_CLEANUP_UNVERIFIED`n") -ErrorBytes ([byte[]]@()) -Lines 1
    Assert-NativeFixture ($capture.UnsafeSignalObserved -and $capture.OutputOverflow -and $capture.OwnedCleanupUnverified) 'unsafe marker is recognized after retention fills'
    $checks++
    $capture=Read-CaptureFixture -OutputBytes $utf8.GetBytes("four`n") -ErrorBytes ([byte[]]@()) -TotalCharacters 4
    Assert-NativeFixture ($capture.OutputOverflow -and $capture.DroppedCharacters -eq 5) 'terminators participate in the total capture bound'
    $checks++
    $now=[DateTimeOffset]::Parse('2026-10-06T12:00:00Z')
    $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs 1000 -CleanupReserveMs 500 -AuthorityEnds $now.AddSeconds(30) -Now $now
    Assert-NativeFixture ($budget.AuthorityEnds -eq $now.AddMilliseconds(1500)) 'outer authority cannot enlarge a native execution budget'
    $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs 1000 -CleanupReserveMs 500 -AuthorityEnds $now.AddMilliseconds(800) -Now $now
    Assert-NativeFixture ($budget.AuthorityEnds -eq $now.AddMilliseconds(800)) 'earlier outer deadline is preserved'
    foreach ($timeout in @(0,-1)) {
        $rejected=$false
        try { Get-GeneratedApplicationNativeBudget -TimeoutMs $timeout -CleanupReserveMs 500 -AuthorityEnds $now.AddSeconds(30) -Now $now | Out-Null } catch { $rejected=$true }
        Assert-NativeFixture $rejected 'nonpositive execution admission is rejected'
        $checks++
    }
    $rejected=$false
    try { Get-GeneratedApplicationNativeBudget -TimeoutMs 1000 -CleanupReserveMs 500 -AuthorityEnds $now.AddMilliseconds(600) -Now $now | Out-Null } catch { $rejected=$true }
    Assert-NativeFixture $rejected 'insufficient execution and cleanup reserve refuses'
    $checks+=3
    # An already compiled helper cannot silently survive a source identity
    # change inside the same suite host. Substitute only the hash query here;
    # neither the tracked source nor the compiled fixture type is modified.
    function Get-FileHash { param([string] $LiteralPath,[string] $Algorithm) [pscustomobject]@{Hash=('0'*64)} }
    try {
        $rejected=$false
        try { Initialize-GeneratedApplicationNativeSupervisor } catch { $rejected=$true }
        Assert-NativeFixture $rejected 'cached supervisor identity refuses drifting source'
        $checks++
    } finally { Remove-Item Function:\Get-FileHash }
    # Preserve the public adapter contract without launching a leaf. Substitute
    # only the native owner and inspect the exact arguments and budget forwarded.
    . (Join-Path $PSScriptRoot 'TestHarness.ps1')
    function Invoke-GeneratedApplicationNative {
        param($HostPath,$WorkingDirectory,$Arguments,$StandardInput,$TimeoutMs,$CleanupReserveMs,$AuthorityEnds)
        $script:NativeForwarded=[pscustomobject]@{Arguments=$Arguments; StandardInput=$StandardInput; TimeoutMs=$TimeoutMs;
            CleanupReserveMs=$CleanupReserveMs; AuthorityEnds=$AuthorityEnds}
        [pscustomobject]@{ExitCode=7; StandardOutput="{`"value`":42}`r`n{`"value`":43}`n"; StandardError="error`r`n"}
    }
    $adapter=Invoke-GeneratedApplication -CandidatePath 'synthetic-candidate.ps1' -Arguments @('-Fixture','benign') `
        -PowerShellPath (Join-Path $PSHOME 'pwsh.exe') -StandardInput 'fixture input' -TimeoutMs 1500 -CleanupReserveMs 500 -AuthorityEnds $now.AddSeconds(2)
    Assert-NativeFixture ($adapter.ExitCode -eq 7 -and $adapter.Records.Count -eq 2 -and $adapter.Records[1].value -eq 43) 'natural nonzero and parsed Records remain compatible'
    Assert-NativeFixture ($adapter.StandardOutput -ceq "{`"value`":42}`r`n{`"value`":43}`n" -and $adapter.StandardError -ceq "error`r`n") 'public adapter preserves both exact stream strings'
    Assert-NativeFixture (($script:NativeForwarded.Arguments -join '|') -ceq '-NoLogo|-NoProfile|-File|synthetic-candidate.ps1|-Fixture|benign') 'argument forwarding adds no implicit execution flags'
    Assert-NativeFixture ($script:NativeForwarded.StandardInput -ceq 'fixture input' -and $script:NativeForwarded.TimeoutMs -eq 1500 -and
        $script:NativeForwarded.CleanupReserveMs -eq 500 -and $script:NativeForwarded.AuthorityEnds -eq $now.AddSeconds(2)) 'stdin and the original finite budget propagate unchanged'
    $checks+=4
    $fixture=Join-Path (Split-Path $PSScriptRoot) ('.test-output/native-pure-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory((Join-Path $fixture 'owned'))
    try {
        [IO.File]::WriteAllText((Join-Path $fixture 'owned/owned-pending.json'),'{"fixture":true}')
        $rejected=$false
        try { Assert-GeneratedApplicationNativeReady -EvidenceParent $fixture } catch { $rejected=$true }
        Assert-NativeFixture $rejected 'a preserved prearm blocks the next admission without querying processes'
        $checks++
        # Disclosed synthetic outcome: exercise the same retention seam without
        # a native handle. A terminal-file directory cannot erase the original
        # supplied zero outcome from the independent record or error fallback.
        $retention=Join-Path $fixture 'retention'
        $null=[IO.Directory]::CreateDirectory((Join-Path $retention 'terminal.json'))
        $failures=[Collections.Generic.List[Exception]]::new()
        $synthetic=[pscustomobject]@{Started=$true; NativeTerminalObserved=$true; NativeExitCode=0; Lines=@('synthetic private line')}
        $original=Save-GeneratedApplicationNativeOutcome -Directory $retention -Identity ([pscustomobject]@{Started=$true; Pid=0; Fixture=$true}) `
            -Outcome $synthetic -Failures $failures -ObserveTerminal { throw 'synthetic observer failure' }
        $saved=Get-Content -LiteralPath (Join-Path $retention 'original-native-outcome.json') -Raw | ConvertFrom-Json
        Assert-NativeFixture ($saved.outcome.NativeExitCode -eq 0 -and $saved.outcome.NativeTerminalObserved -and $saved.identity.Fixture) 'independent retention preserves the disclosed synthetic zero outcome'
        Assert-NativeFixture ($original.outcome.NativeExitCode -eq 0 -and $failures.Count -eq 2 -and $null -eq $saved.outcome.PSObject.Properties['Lines']) 'terminal and observer failures aggregate without leaking stream content into fallback metadata'
        $checks+=2
    } finally {
        $expected=[IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot) '.test-output'))
        if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($fixture)) -cne $expected) { throw 'Pure fixture cleanup is outside its owned boundary.' }
        [IO.Directory]::Delete($fixture,$true)
    }
    [pscustomobject]@{mode='Pure'; checks=$checks; nativeStarts=0; nativeQueries=0}
    return
}

# Native mode is an explicit root-admitted benign proof. Unsafe cases preserve
# their pending state and fixture directory for exact root recovery; they must
# never run as an automatic retry or an ordinary full-suite fixture.
$fixture=Join-Path (Split-Path $PSScriptRoot) ('.test-output/native-benign-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($fixture)
$leaf=Join-Path $fixture 'leaf.ps1'
$scripts=@{
    NaturalZero='[Console]::Out.WriteLine(''{"fixture":"natural"}''); exit 0'
    NaturalNonzero='[Console]::Out.WriteLine(''{"fixture":"nonzero"}''); exit 7'
    Utf8Both='[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::Out.WriteLine(''{"fixture":"日本語 ñ"}''); [Console]::Error.WriteLine(''日本語 ñ''); exit 0'
    EofEmpty='$inputText=[Console]::In.ReadToEnd(); [Console]::Out.WriteLine((''{"length":''+$inputText.Length+''}'')); exit 0'
    EofInput='$inputText=[Console]::In.ReadToEnd(); [Console]::Out.WriteLine(($inputText | ConvertTo-Json -Compress)); exit 0'
    PipePressure='[Console]::Error.Write((''e''*1048576)); [Console]::Out.WriteLine(''{"fixture":"pressure"}''); exit 0'
    Timeout='Start-Sleep -Seconds 30; exit 0'
    InvalidUtf8='$output=[Console]::OpenStandardOutput(); $output.WriteByte(255); $output.Flush(); exit 0'
    Overflow='[Console]::Out.WriteLine((''x''*1024)); exit 0'
    UnsafeMarker='[Console]::Out.WriteLine(''QUALIFICATION.OWNED_CLEANUP_UNVERIFIED''); exit 0'
    TerminalRetentionFailure='[Console]::Out.WriteLine(''{"fixture":"retention"}''); exit 0'
}
$encoding='[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); '
[IO.File]::WriteAllText($leaf,($encoding+$scripts[$Case]),[Text.UTF8Encoding]::new($false))
$arguments=@('-NoLogo','-NoProfile','-File',$leaf)
$parameters=@{HostPath=(Join-Path $PSHOME 'pwsh.exe'); WorkingDirectory=$fixture; Arguments=$arguments;
    TimeoutMs=10000; CleanupReserveMs=3000; AuthorityEnds=[DateTimeOffset]::UtcNow.AddSeconds(13);
    ObserveTerminal={param($Identity,$Outcome) [Console]::WriteLine(('TEST.NATIVE.TERMINAL '+$Outcome.NativeExitCode+' observed='+$Outcome.NativeTerminalObserved+' forced='+$Outcome.TerminationAttempted)); [Console]::Out.Flush()}}
if ($Case -eq 'EofInput') { $parameters.StandardInput='日本語 input' }
if ($Case -eq 'Timeout') { $parameters.TimeoutMs=500; $parameters.AuthorityEnds=[DateTimeOffset]::UtcNow.AddMilliseconds(3500) }
if ($Case -eq 'Overflow') { $parameters.MaximumLineCharacters=128; $parameters.MaximumTotalCharacters=256 }
if ($Case -eq 'TerminalRetentionFailure') {
    $parameters.ObserveStartup={param($Directory,$Identity) $null=[IO.Directory]::CreateDirectory((Join-Path $Directory 'terminal.json'))}
}
$expectedUnsafe=$Case -in @('Timeout','InvalidUtf8','Overflow','UnsafeMarker','TerminalRetentionFailure')
$bodyError=$null
try {
    $result=Invoke-GeneratedApplicationNative @parameters
    Assert-NativeFixture (-not $expectedUnsafe) 'unsafe proof cannot return a normal result'
    Assert-NativeFixture ($result.ExitCode -eq $(if ($Case -eq 'NaturalNonzero') {7} else {0})) 'actual native code is preserved'
    switch ($Case) {
        Utf8Both { Assert-NativeFixture ($result.StandardOutput.Contains('日本語 ñ') -and $result.StandardError.Contains('日本語 ñ')) 'both strict UTF8 streams are complete' }
        EofEmpty { Assert-NativeFixture (($result.StandardOutput | ConvertFrom-Json).length -eq 0) 'stdin closes without supplied input' }
        EofInput { Assert-NativeFixture (($result.StandardOutput | ConvertFrom-Json) -ceq '日本語 input') 'supplied input drains before EOF' }
        PipePressure { Assert-NativeFixture ($result.StandardError.Length -eq 1048576 -and $result.StandardOutput.Contains('pressure')) 'stderr pipe pressure does not deadlock stdout capture' }
    }
    [pscustomobject]@{mode='Native'; case=$Case; actualExit=$result.ExitCode; unsafe=$false}
}
catch {
    $bodyError=$_
    if (-not $expectedUnsafe -or -not (Test-QualificationCleanupUnverified -Exception $_.Exception)) { throw }
    [pscustomobject]@{mode='Native'; case=$Case; unsafe=$true; furtherAdmissionAllowed=$false}
}
finally {
    if ($expectedUnsafe -or ($null -ne $bodyError -and (Test-QualificationCleanupUnverified -Exception $bodyError.Exception))) {
        Write-Output 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'
    }
    else {
        $expected=[IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot) '.test-output'))
        if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($fixture)) -cne $expected) { throw 'Native fixture cleanup is outside its owned boundary.' }
        [IO.Directory]::Delete($fixture,$true)
    }
}
