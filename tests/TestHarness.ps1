Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
. (Join-Path $PSScriptRoot 'GeneratedApplicationNative.ps1')
Assert-QualificationCleanupReady
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'build/RuntimeHost.ps1')

function Assert-Equal {
    param(
        [Parameter(Mandatory)] $Expected,
        [Parameter(Mandatory)] $Actual,
        [Parameter(Mandatory)] [string] $Because
    )
    if ($Expected -ne $Actual) {
        throw "Expected '$Expected' but received '$Actual': $Because"
    }
}

# Prepared test input is a development admission boundary. It does not qualify
# a release or grant authority to collect from a real device.
function Get-TestCandidateInputInventory {
    param([Parameter(Mandatory)] [string] $RepositoryRoot)
    $root=[IO.Path]::GetFullPath($RepositoryRoot)
    $paths=[Collections.Generic.List[string]]::new()
    foreach ($directory in @('src','build','schemas','docs')) {
        $inputRoot=Get-Item -LiteralPath (Join-Path $root $directory)
        if (($inputRoot.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            @(Get-ChildItem -LiteralPath $inputRoot.FullName -Directory -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count) { throw 'Prepared test input directories cannot use reparse points.' }
        foreach ($file in @(Get-ChildItem -LiteralPath $inputRoot.FullName -File -Recurse -Force)) {
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Prepared test inputs cannot use reparse points.' }
            $paths.Add([IO.Path]::GetRelativePath($root,$file.FullName).Replace('\','/'))
        }
    }
    foreach ($path in @('README.md','SECURITY.md','CONTRIBUTING.md','package.json','package-lock.json','LICENSE',
        'tests/TestHarness.ps1','tests/StatusDeskEngine.Tests.ps1','tests/Invoke-AssessmentSafetyQualification.ps1',
        'tests/QualificationDiskBounds.ps1','tests/qualification-resource-writers.json',
        'tests/GeneratedApplicationNative.ps1','tests/GeneratedApplicationNativeSupervisor.cs',
        'tests/Invoke-TestFile.ps1','tests/Run-Tests.ps1','tests/QualificationCleanup.ps1',
        'tests/QualificationCaseAdmission.ps1','tests/Invoke-QualificationCase.ps1','tests/Invoke-FocusedTest.ps1',
        'tests/QualificationFixtureProcess.ps1','tests/QualificationCapabilityProcess.ps1',
        'tests/QualificationInlineRepresentation.ps1','tests/QualificationRecipientViewingInterruption.ps1',
        'tests/QualificationInputLauncher.ps1')) {
        if ([IO.File]::Exists((Join-Path $root $path))) { $paths.Add($path) }
    }
    foreach ($path in @($paths | Sort-Object -CaseSensitive -Unique)) {
        $file=Get-Item -LiteralPath (Join-Path $root $path)
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Prepared test inputs cannot use reparse points.' }
        [pscustomobject][ordered]@{path=$path; bytes=$file.Length; sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
}

function New-PreparedTestCandidateManifest {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [Parameter(Mandatory)] [string] $CandidatePath)
    $candidate=Get-Item -LiteralPath ([IO.Path]::GetFullPath($CandidatePath))
    [pscustomobject][ordered]@{
        contract='win-pcinfo.test-prepared-candidate/1.0.0'
        candidate=[ordered]@{path=$candidate.FullName; bytes=$candidate.Length; sha256=(Get-FileHash -LiteralPath $candidate.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        inputs=@(Get-TestCandidateInputInventory -RepositoryRoot $RepositoryRoot)
        runtime=[ordered]@{sha256=(Get-FileHash -LiteralPath (Join-Path $PSHOME 'pwsh.exe') -Algorithm SHA256).Hash.ToLowerInvariant();
            powerShell=$PSVersionTable.PSVersion.ToString(); dotNet=[Environment]::Version.ToString(); architecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString();
            dependencies=(Get-TestPreparedRuntimeDependencies -HashFiles)}
    }
}

function Open-TestCandidate {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [string] $CandidatePath,
        [string] $PreparedManifestPath, [string] $PreparedManifestSha256, [switch] $SeparateBuildProcess)
    $supplied=-not [string]::IsNullOrEmpty($CandidatePath) -or
        -not [string]::IsNullOrEmpty($PreparedManifestPath) -or -not [string]::IsNullOrEmpty($PreparedManifestSha256)
    $ownedDirectory=$null
    $stream=$null
    try {
        if ($supplied) {
            if ([string]::IsNullOrWhiteSpace($CandidatePath) -or [string]::IsNullOrWhiteSpace($PreparedManifestPath) -or
                $PreparedManifestSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Prepared candidate requires its explicit path, manifest and pinned SHA256.' }
            $manifestFile=Get-Item -LiteralPath ([IO.Path]::GetFullPath($PreparedManifestPath))
            if (($manifestFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $manifestFile.Length -gt 2MB) { throw 'Prepared candidate manifest is not an admitted bounded file.' }
            $manifestStream=[IO.File]::Open($manifestFile.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try {
                $manifestBytes=[byte[]]::new([int]$manifestStream.Length)
                $manifestStream.ReadExactly($manifestBytes)
                if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($manifestBytes)).ToLowerInvariant() -cne $PreparedManifestSha256) { throw 'Prepared candidate manifest identity changed.' }
                $manifest=[Text.UTF8Encoding]::new($false,$true).GetString($manifestBytes) | ConvertFrom-Json -Depth 10
            }
            finally { $manifestStream.Dispose() }
            if ($manifest.contract -cne 'win-pcinfo.test-prepared-candidate/1.0.0') { throw 'Prepared candidate manifest contract is not admitted.' }
            $resolvedCandidate=[IO.Path]::GetFullPath($CandidatePath)
            if (-not [string]::Equals($resolvedCandidate,[IO.Path]::GetFullPath($manifest.candidate.path),[StringComparison]::OrdinalIgnoreCase)) { throw 'Prepared candidate path differs from its manifest.' }
            $actualInputs=@(Get-TestCandidateInputInventory -RepositoryRoot $RepositoryRoot)
            $declaredInputs=@($manifest.inputs)
            if ($declaredInputs.Count -ne $actualInputs.Count) { throw 'Prepared candidate input inventory is incomplete or unexpected.' }
            for ($index=0; $index -lt $actualInputs.Count; $index++) {
                $actual=$actualInputs[$index]; $declared=$declaredInputs[$index]
                if ($actual.path -cne $declared.path -or $actual.bytes -ne $declared.bytes -or $actual.sha256 -cne $declared.sha256) {
                    throw "Prepared candidate source/resource/toolchain input changed: $($actual.path)."
                }
            }
            Assert-TestPreparedRuntimeDependencies -Dependencies $manifest.runtime.dependencies
            if ($manifest.runtime.sha256 -cne (Get-FileHash -LiteralPath (Join-Path $PSHOME 'pwsh.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -or
                $manifest.runtime.powerShell -cne $PSVersionTable.PSVersion.ToString() -or $manifest.runtime.dotNet -cne [Environment]::Version.ToString() -or
                $manifest.runtime.architecture -cne [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()) { throw 'Prepared candidate runtime identity changed.' }
        }
        else {
            $parent=Join-Path ([IO.Path]::GetFullPath($RepositoryRoot)) '.test-output'
            $null=[IO.Directory]::CreateDirectory($parent)
            $candidateDirectory=Join-Path $parent ('candidate-'+[guid]::NewGuid().ToString('N'))
            if ([IO.Directory]::Exists($candidateDirectory) -or [IO.File]::Exists($candidateDirectory)) { throw 'Standalone candidate output is already owned.' }
            $null=New-Item -ItemType Directory -Path $candidateDirectory -ErrorAction Stop
            $ownedDirectory=$candidateDirectory
            $resolvedCandidate=Join-Path $ownedDirectory 'WIN-PCInfo.ps1'
            if ($SeparateBuildProcess) {
                Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @(
                    '-NoLogo','-NoProfile','-File',(Join-Path $RepositoryRoot 'build/Build.ps1'),'-OutputPath',$resolvedCandidate) | Out-Null
            }
            else { & (Join-Path $RepositoryRoot 'build/Build.ps1') -OutputPath $resolvedCandidate | Out-Null }
            $manifest=New-PreparedTestCandidateManifest -RepositoryRoot $RepositoryRoot -CandidatePath $resolvedCandidate
        }
        $candidateFile=Get-Item -LiteralPath $resolvedCandidate
        if (($candidateFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Prepared candidate cannot use a reparse point.' }
        $stream=[IO.File]::Open($resolvedCandidate,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $actualDigest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
        if ($stream.Length -ne $manifest.candidate.bytes -or $actualDigest -cne $manifest.candidate.sha256) { throw 'Prepared candidate bytes changed.' }
        $stream.Position=0
        [pscustomobject]@{Path=$resolvedCandidate; Sha256=$actualDigest; Stream=$stream; OwnedDirectory=$ownedDirectory; Prepared=$supplied}
    }
    catch {
        $original=$_
        $cleanupFailures=[Collections.Generic.List[Exception]]::new()
        if ($null -ne $stream) {
            try { $stream.Dispose() } catch { $cleanupFailures.Add($_.Exception) }
        }
        if ($null -ne $ownedDirectory) {
            try {
                if ([IO.Directory]::Exists($ownedDirectory)) { [IO.Directory]::Delete($ownedDirectory,$true) }
                if ([IO.Directory]::Exists($ownedDirectory)) { throw 'Failed candidate preparation output remains owned.' }
            }
            catch { $cleanupFailures.Add($_.Exception) }
        }
        if ($cleanupFailures.Count) {
            $failures=[Collections.Generic.List[Exception]]::new()
            $failures.Add($original.Exception)
            foreach ($failure in $cleanupFailures) { $failures.Add($failure) }
            $exception=[AggregateException]::new('Candidate preparation failed and owned cleanup remains unverified.',$failures.ToArray())
            $exception.Data['OwnedCleanupUnverified']=$true
            $exception.Data['OwnedCandidateDirectory']=$ownedDirectory
            throw $exception
        }
        throw
    }
}

function Close-TestCandidate {
    param([Parameter(Mandatory)] $Candidate, [AllowNull()] [Management.Automation.ErrorRecord] $BodyError)
    # The open read handle prevents all consumers from replacing this input.
    # Verify it again before releasing ownership; never turn drift into a pass.
    $runtimeUnsafe=Get-Variable -Name WinPCInfoTestRuntimeProbeUnsafe -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $runtimeUnsafe) {
        if ($null -eq $BodyError) { $BodyError=$runtimeUnsafe.Value }
        elseif (-not [object]::ReferenceEquals($BodyError,$runtimeUnsafe.Value)) {
            $failure=[AggregateException]::new('Original candidate body and retained unsafe runtime probe both failed.',
                [Exception[]]@($BodyError.Exception,$runtimeUnsafe.Value.Exception))
            foreach($key in $BodyError.Exception.Data.Keys){$failure.Data[$key]=$BodyError.Exception.Data[$key]}
            $failure.Data['OwnedCleanupUnverified']=$true
            $BodyError=[Management.Automation.ErrorRecord]::new($failure,'TestRuntimeProbeUnsafe',
                [Management.Automation.ErrorCategory]::InvalidOperation,$Candidate.Path)
        }
    }
    $preserveOutput=$null -ne $BodyError -and (Test-QualificationCleanupUnverified -Exception $BodyError.Exception)
    Complete-QualificationHarness -BodyError $BodyError -Cleanup @({
    try {
        $Candidate.Stream.Position=0
        $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Candidate.Stream)).ToLowerInvariant()
        if ($digest -cne $Candidate.Sha256) { throw 'Consumed candidate identity changed.' }
    }
    finally { $Candidate.Stream.Dispose() }
    if ($null -ne $Candidate.OwnedDirectory -and -not $preserveOutput) {
        $directory=[IO.Path]::GetFullPath($Candidate.OwnedDirectory)
        if ([IO.Path]::GetDirectoryName($Candidate.Path) -ne $directory -or [IO.Path]::GetFileName($directory) -notmatch '^candidate-[a-f0-9]{32}$') { throw 'Standalone candidate cleanup is outside its owned boundary.' }
        if ([IO.Directory]::Exists($directory)) { [IO.Directory]::Delete($directory,$true) }
        if ([IO.Directory]::Exists($directory)) { throw 'Standalone candidate output remains after cleanup.' }
    }
    })
}

# Runtime discovery retains the product signature and eligibility interpreter.
# Test-only transport is admitted by the current immutable File/Case root; no
# alternate installed host gains authority merely by having a valid signature.
function Assert-TestRuntimeProbeReady {
    $latch=Get-Variable -Name WinPCInfoTestRuntimeProbeUnsafe -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $latch) { throw $latch.Value }
}

function Get-TestRuntimeAdmission {
    Assert-TestRuntimeProbeReady
    $repository=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
    Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $repository
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $repository -SelfIdentity (Get-TestNativeSelfIdentity)
    $root=$context.Root.Admission
    if ($root.hostPath -isnot [string] -or -not [IO.Path]::IsPathFullyQualified($root.hostPath) -or
        $root.hostPath.StartsWith('\\') -or [IO.Path]::GetFileName($root.hostPath) -ine 'pwsh.exe' -or
        $root.cohortSha256 -isnot [string] -or $root.cohortSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Test runtime transport requires the exact scalar current root host and cohort.'
    }
    $hostPin=@($root.inputs | Where-Object path -IEQ $root.hostPath)
    if ($hostPin.Count -ne 1 -or $hostPin[0].sha256 -isnot [string] -or
        $hostPin[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        ($hostPin[0].bytes -isnot [int] -and $hostPin[0].bytes -isnot [long]) -or $hostPin[0].bytes -lt 1) {
        throw 'Test runtime transport lacks its closed current host input pin.'
    }
    $end=[DateTimeOffset]::ParseExact($context.Parent.Pending.authorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture)
    $end=$end.AddMilliseconds(-[long]$context.Parent.Pending.cleanupReserveMs-2000)
    if ([string]::IsNullOrEmpty($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC)) { throw 'Test runtime authority is missing.' }
    $inherited=[DateTimeOffset]::ParseExact($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC,'o',[Globalization.CultureInfo]::InvariantCulture)
    if ($end.Offset -ne [TimeSpan]::Zero -or $inherited.Offset -ne [TimeSpan]::Zero) { throw 'Test runtime authority must be UTC.' }
    if ($inherited -lt $end) { $end=$inherited }
    if ($end -le [DateTimeOffset]::UtcNow.AddMilliseconds(5100)) { throw 'Test runtime authority has no unchanged cleanup reserve.' }
    [pscustomobject]@{RepositoryRoot=$repository;HostPath=$root.hostPath;HostPin=$hostPin[0];AuthorityEnds=$end;
        ParentDigest=(Get-TestNativeDigest -Value $context.Parent.Pending);CohortSha256=$root.cohortSha256;
        PreparedManifestSha256=$root.preparedManifestSha256}
}

function Open-TestRuntimeHostStream {
    param([Parameter(Mandatory)] $Admission)
    $stream=$null;$bodyError=$null
    try {
        $item=Get-Item -LiteralPath $Admission.HostPath -ErrorAction Stop
        if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Test runtime transport cannot substitute a redirected host.'
        }
        $stream=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
        $stream.Position=0
        if ($stream.Length -ne $Admission.HostPin.bytes -or $digest -cne $Admission.HostPin.sha256) {
            throw 'Test runtime bytes differ from the current admitted host.'
        }
    }
    catch { $bodyError=$_ }
    if ($null -ne $bodyError) {
        Complete-QualificationHarness -BodyError $bodyError -Cleanup @({if($null -ne $stream){$stream.Dispose()}})
    }
    $stream
}

function Get-TestAdmittedRuntimeHost {
    # Campaign transport does not repeat runtime eligibility probing. Engine
    # leaves still receive their original root prepared triple through the
    # existing Case parameter converter and execute the original assertions.
    $admission=Get-TestRuntimeAdmission
    $stream=$null;$bodyError=$null
    try { $stream=Open-TestRuntimeHostStream -Admission $admission }
    catch { $bodyError=$_ }
    finally { Complete-QualificationHarness -BodyError $bodyError -Cleanup @({if($null -ne $stream){$stream.Dispose()}}) }
    $admission.HostPath
}

function Invoke-TestOwnedRuntimeProbe {
    param([Parameter(Mandatory)] $Admission,[Parameter(Mandatory)] [string] $Executable,
        [Parameter(Mandatory)] [string] $ApplicationPath)
    Assert-TestRuntimeProbeReady
    $current=Get-TestRuntimeAdmission
    if ($Executable -ine $current.HostPath -or $Admission.HostPath -cne $current.HostPath -or
        $Admission.HostPin.sha256 -cne $current.HostPin.sha256 -or $Admission.ParentDigest -cne $current.ParentDigest -or
        $Admission.CohortSha256 -cne $current.CohortSha256 -or
        $Admission.PreparedManifestSha256 -cne $current.PreparedManifestSha256) {
        throw 'Runtime probing cannot execute another installed host or transfer File/Case authority.'
    }
    $stream=$null;$bodyError=$null;$native=$null
    try {
        try {
            $stream=Open-TestRuntimeHostStream -Admission $current
            $end=if($Admission.AuthorityEnds-lt$current.AuthorityEnds){$Admission.AuthorityEnds}else{$current.AuthorityEnds}
            # Original argv and environment/CWD semantics are retained. Package
            # candidates are held by the native consumed-input boundary rather
            # than forcibly replaced with the root candidate path.
            $native=Invoke-GeneratedApplicationNative -HostPath $current.HostPath -WorkingDirectory ([Environment]::CurrentDirectory) `
                -Arguments @('-NoLogo','-NoProfile','-NonInteractive','-File',$ApplicationPath,'-Workflow','CheckRuntime') `
                -TimeoutMs 15000 -CleanupReserveMs 5000 -AuthorityEnds $end `
                -MaximumLines 128 -MaximumLineCharacters 8192 -MaximumTotalCharacters 32768
            if ($native.ExitCode -isnot [int]) {
                $failure=[InvalidOperationException]::new('Runtime probe actual native terminal is unknown.')
                $failure.Data['OwnedCleanupUnverified']=$true
                throw $failure
            }
        }
        catch { $bodyError=$_ }
        finally { Complete-QualificationHarness -BodyError $bodyError -Cleanup @({if($null -ne $stream){$stream.Dispose()}}) }
    }
    catch {
        if (Test-QualificationCleanupUnverified -Exception $_.Exception) { $script:WinPCInfoTestRuntimeProbeUnsafe=$_ }
        throw
    }
    $native
}

function Invoke-TestRuntimeProbe {
    param([string] $Executable,[string] $ApplicationPath,
        [scriptblock] $ReadSignature={param($Path) Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path})
    # Missing/stale File/Case admission is a test failure before the product's
    # intentional catch-all can sanitize it into a host rejection.
    $admission=Get-TestRuntimeAdmission
    $runProbe={param($Executable,$ApplicationPath);Invoke-TestOwnedRuntimeProbe -Admission $admission -Executable $Executable -ApplicationPath $ApplicationPath}
    $result=Invoke-WinPCInfoRuntimeProbe -Executable $Executable -ApplicationPath $ApplicationPath -ReadSignature $ReadSignature -RunProbe $runProbe
    Assert-TestRuntimeProbeReady
    $result
}

function Resolve-TestRuntime {
    param([Parameter(Mandatory)] [string] $ApplicationPath,
        [AllowEmptyCollection()] [string[]] $CandidatePaths)
    $null=Get-TestRuntimeAdmission
    if (-not $PSBoundParameters.ContainsKey('CandidatePaths')) { $CandidatePaths=@(Get-WinPCInfoRuntimeCandidates) }
    Resolve-WinPCInfoRuntime -ApplicationPath $ApplicationPath -CandidatePaths $CandidatePaths -Probe ${function:Invoke-TestRuntimeProbe}
}
function Invoke-GeneratedApplication {
    param(
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter()] [AllowEmptyString()] [string] $StandardInput,
        [Parameter()] [string] $PowerShellPath,
        [Parameter()] [string] $WorkingDirectory = (Get-Location).Path,
        [long] $TimeoutMs = 3600000,
        [long] $CleanupReserveMs = 120000,
        [DateTimeOffset] $AuthorityEnds = [DateTimeOffset]::MinValue, [string] $InputLauncherOwnerDirectory
    )

    Assert-TestRuntimeProbeReady
    Assert-ReleaseHelpInnerAdmission
    if ([string]::IsNullOrWhiteSpace($PowerShellPath)) {
        $runtimeAdmission=Get-TestRuntimeAdmission
        $candidateIdentity=(Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $cacheIdentity=Get-TestNativeDigest -Value ([ordered]@{
            candidatePath=[IO.Path]::GetFullPath($CandidatePath);candidateSha256=$candidateIdentity;
            hostPath=$runtimeAdmission.HostPath;hostSha256=$runtimeAdmission.HostPin.sha256;
            cohortSha256=$runtimeAdmission.CohortSha256;parentDigest=$runtimeAdmission.ParentDigest;
            preparedManifestSha256=$runtimeAdmission.PreparedManifestSha256})
        $cache=Get-Variable -Name WinPCInfoTestHostCache -Scope Script -ErrorAction SilentlyContinue
        if ($null -ne $cache -and $cache.Value.Identity -ceq $cacheIdentity -and $cache.Value.Executable -ceq $runtimeAdmission.HostPath) {
            $PowerShellPath=$cache.Value.Executable
        }
        else {
            $PowerShellPath=Resolve-TestRuntime -ApplicationPath $CandidatePath
            $script:WinPCInfoTestHostCache=@{Identity=$cacheIdentity;Executable=$PowerShellPath}
        }
    }
    $native=Invoke-GeneratedApplicationNative -HostPath ([IO.Path]::GetFullPath($PowerShellPath)) -WorkingDirectory ([IO.Path]::GetFullPath($WorkingDirectory)) `
        -Arguments (@('-NoLogo','-NoProfile','-File',$CandidatePath)+$Arguments) -StandardInput $StandardInput `
        -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $AuthorityEnds -InputLauncherOwnerDirectory $InputLauncherOwnerDirectory
    $records=[Collections.Generic.List[object]]::new()
    $parseError=$null
    foreach ($line in @($native.StandardOutput -split "`r?`n" | Where-Object { $_ })) {
        try { $records.Add(($line | ConvertFrom-Json -Depth 20 -ErrorAction Stop)) }
        catch { if ($null -eq $parseError) { $parseError=$_ } }
    }
    Assert-ReleaseHelpInnerOutcome -Native $native -Records $records.ToArray() -ParseError $parseError
    if ($null -ne $parseError) { throw $parseError }
    [pscustomobject]@{
        ExitCode=$native.ExitCode
        Records=$records.ToArray()
        StandardOutput=$native.StandardOutput
        StandardError=$native.StandardError
    }
}
function Assert-ReleaseHelpInnerAdmission {
    $latch=Get-Variable -Name WinPCInfoReleaseHelpInnerUncertainty -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $latch) {
        $failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: retained inner Help ownership blocks admission.')
        $failure.Data['OwnedCleanupUnverified']=$true
        $failure.Data['ReleaseHelpInnerUncertainty']=$latch.Value
        throw $failure
    }
}

function Get-ReleaseHelpReservedPhase {
    param([AllowNull()] $Reason)
    if ($Reason -isnot [string]) { return $null }
    switch -CaseSensitive ($Reason) {
        'SIGNING.SMOKE_OWNERSHIP_UNVERIFIED' { return 'SigningBoundary' }
        'QUALIFY.SMOKE_OWNERSHIP_UNVERIFIED' { return 'PreviewQualification' }
        'PUBLISH.SMOKE_OWNERSHIP_UNVERIFIED' { return 'PreviewPublication' }
    }
    return $null
}

function Test-ReleaseHelpJsonUniqueMembers {
    param([Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element)
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $keys.Add($property.Name) -or -not (Test-ReleaseHelpJsonUniqueMembers -Element $property.Value)) { return $false }
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($member in $Element.EnumerateArray()) { if (-not (Test-ReleaseHelpJsonUniqueMembers -Element $member)) { return $false } }
    }
    return $true
}

function Test-ReleaseHelpJsonReservedReason {
    param([Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element)
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        foreach ($property in $Element.EnumerateObject()) {
            # Enumerate every decoded occurrence before PowerShell's JSON
            # projection can erase an earlier duplicate or an escaped name.
            if ($property.Name.Equals('reasonCode',[StringComparison]::OrdinalIgnoreCase) -and
                $property.Value.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                $reason=$property.Value.GetString()
                foreach ($reserved in @('SIGNING.SMOKE_OWNERSHIP_UNVERIFIED','QUALIFY.SMOKE_OWNERSHIP_UNVERIFIED','PUBLISH.SMOKE_OWNERSHIP_UNVERIFIED')) {
                    if ($reason.Equals($reserved,[StringComparison]::OrdinalIgnoreCase)) { return $true }
                }
            }
            if (Test-ReleaseHelpJsonReservedReason -Element $property.Value) { return $true }
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($member in $Element.EnumerateArray()) { if (Test-ReleaseHelpJsonReservedReason -Element $member) { return $true } }
    }
    return $false
}

function Test-ReleaseHelpRawReservedReason {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)
    $jsonInput=[IO.StringReader]::new($Text)
    $reader=[Newtonsoft.Json.JsonTextReader]::new($jsonInput)
    $reader.MaxDepth=20
    $reader.DateParseHandling=[Newtonsoft.Json.DateParseHandling]::None
    $reader.SupportMultipleContent=$true
    try {
        while ($reader.Read()) {
            if ($reader.TokenType -eq [Newtonsoft.Json.JsonToken]::PropertyName -and
                $reader.Value -is [string] -and $reader.Value.Equals('reasonCode',[StringComparison]::OrdinalIgnoreCase)) {
                if ($reader.Read() -and $reader.TokenType -eq [Newtonsoft.Json.JsonToken]::String) {
                    foreach ($reserved in @('SIGNING.SMOKE_OWNERSHIP_UNVERIFIED','QUALIFY.SMOKE_OWNERSHIP_UNVERIFIED','PUBLISH.SMOKE_OWNERSHIP_UNVERIFIED')) {
                        if ([string]::Equals([string]$reader.Value,$reserved,[StringComparison]::OrdinalIgnoreCase)) { return $true }
                    }
                }
            }
        }
    }
    catch {
        # Recognition is independent of full acceptance. A decoded reserved
        # token returns immediately, before a later damaged envelope can erase
        # it; ordinary malformed output retains its existing parse exception.
    }
    finally { $reader.Close(); $jsonInput.Dispose() }
    return $false
}

function Write-ReleaseHelpPrivateRecord {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] $Record)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 40 -Compress))
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function New-ReleaseHelpPrivateDirectory {
    param([Parameter(Mandatory)] [string] $Path)
    $cursor=[IO.Path]::GetFullPath($Path)
    while ($null -ne $cursor) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Inner Help evidence ancestor is a reparse point.' }
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
    if ([IO.Directory]::Exists($Path) -or [IO.File]::Exists($Path)) { throw 'Inner Help uncertainty directory already exists.' }
    $null=[IO.Directory]::CreateDirectory($Path)
}

function Assert-ReleaseHelpInnerOutcome {
    param([Parameter(Mandatory)] $Native, [AllowEmptyCollection()] [object[]] $Records,
        [AllowNull()] [Management.Automation.ErrorRecord] $ParseError)
    $known=Test-ReleaseHelpRawReservedReason -Text $Native.StandardOutput
    foreach ($line in @($Native.StandardOutput -split "`r?`n" | Where-Object { $_ })) {
        $json=$null
        try {
            $json=[System.Text.Json.JsonDocument]::Parse([string]$line)
            if (Test-ReleaseHelpJsonReservedReason -Element $json.RootElement) { $known=$true }
        }
        catch {
            # Keep the conservative raw marker fallback below. Complete output
            # parsing/duplicate/terminal checks still occur after recognition;
            # nonreserved malformed output keeps its ordinary parse semantics.
        }
        finally { if ($null -ne $json) { $json.Dispose() } }
    }
    foreach ($record in $Records) {
        if ($null -eq $record) { continue }
        $property=$record.PSObject.Properties['reasonCode']
        if ($null -ne $property -and $null -ne (Get-ReleaseHelpReservedPhase -Reason $property.Value)) { $known=$true }
    }
    if ($Native.StandardOutput -match '"reasonCode"\s*:\s*"(?:SIGNING|QUALIFY|PUBLISH)\.SMOKE_OWNERSHIP_UNVERIFIED"') { $known=$true }
    if (-not $known) { return }

    $failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: the generated application reported inner Help ownership uncertainty.')
    $failure.Data['OwnedCleanupUnverified']=$true
    $validation=[Collections.Generic.List[Exception]]::new()
    try {
        if ($null -ne $ParseError) { throw 'Reserved Help output could not be parsed completely.' }
        $terminals=@($Records | Where-Object { $null -ne $_ -and $_.PSObject.Properties['recordType'] -and $_.recordType -is [string] -and $_.recordType -ceq 'win-pcinfo.terminal' })
        if ($terminals.Count -ne 1) { throw 'Reserved Help output requires exactly one terminal.' }
        $terminal=$terminals[0]
        $phase=Get-ReleaseHelpReservedPhase -Reason $terminal.reasonCode
        if ($null -eq $phase -or $terminal.contractVersion -isnot [string] -or $terminal.contractVersion -cne '1.0.0' -or
            $terminal.requestDigest -isnot [string] -or $terminal.validationFixture -isnot [bool] -or
            $terminal.phase -isnot [string] -or $terminal.phase -cne $phase -or
            $terminal.outcome -isnot [string] -or $terminal.outcome -cne 'CleanupIncomplete' -or
            $terminal.exitCode -isnot [long] -and $terminal.exitCode -isnot [int] -or $terminal.exitCode -ne 60 -or
            $Native.ExitCode -isnot [int] -or $Native.ExitCode -ne 60 -or
            $terminal.collectionStarted -isnot [bool] -or $terminal.collectionStarted -or
            $terminal.cleanup.required -isnot [bool] -or -not $terminal.cleanup.required -or
            $terminal.cleanup.verified -isnot [bool] -or $terminal.cleanup.verified) { throw 'Reserved Help terminal is malformed or inconsistent.' }
        foreach ($line in @($Native.StandardOutput -split "`r?`n" | Where-Object { $_ })) {
            $json=[System.Text.Json.JsonDocument]::Parse([string]$line)
            try { if (-not (Test-ReleaseHelpJsonUniqueMembers -Element $json.RootElement)) { throw 'Reserved Help output contains duplicate JSON members.' } }
            finally { $json.Dispose() }
        }
    }
    catch { $validation.Add($_.Exception) }
    $record=[ordered]@{
        state='InnerHelpOwnershipUnverified'; observedUtc=[DateTimeOffset]::UtcNow.ToString('o')
        outerNative=$Native; parsedRecords=$Records
        parseError=$(if ($null -ne $ParseError) { $ParseError.ToString() } else { $null })
        terminalValidationErrors=@($validation | ForEach-Object { $_.Message })
        innerIdentityReported=$false; outerOutcomeReclassified=$false
    }
    # Latch before every fallible path or write. The outer creation handle has
    # already ended and been released by its owner; this is a separate inner hold.
    $script:WinPCInfoReleaseHelpInnerUncertainty=$record
    $failure.Data['ReleaseHelpInnerUncertainty']=$record
    $failure.Data['OriginalOuterNativeOutcome']=$Native.NativeOutcome
    $failure.Data['OriginalOuterEvidenceDirectory']=$Native.EvidenceDirectory
    $failures=[Collections.Generic.List[Exception]]::new()
    $failures.Add($failure)
    foreach ($error in $validation) { $failures.Add([InvalidOperationException]::new('Inner Help terminal validation failed.',$error)) }
    if ($null -ne $ParseError) { $failures.Add([InvalidOperationException]::new('Reserved inner Help output parsing failed.',$ParseError.Exception)) }
    $directory=$null
    $directoryCreated=$false
    try {
        if ($Native.Nonce -isnot [string] -or $Native.Nonce -cnotmatch '^[a-f0-9]{32}$') { throw 'Original outer nonce is malformed.' }
        $directory=Join-Path (Split-Path -Parent $PSScriptRoot) ('.test-output/release-help-inner-uncertainty/'+$Native.Nonce)
        New-ReleaseHelpPrivateDirectory -Path $directory
        $directoryCreated=$true
    }
    catch { $failures.Add([InvalidOperationException]::new('Inner Help evidence directory retention failed.',$_.Exception)) }
    if ($directoryCreated) {
        foreach ($entry in @(@('original-outer-outcome.json',$record),@('owned-pending.json',[ordered]@{state='InnerHelpOwnershipUnverified';outerNonce=$Native.Nonce;innerIdentityReported=$false}))) {
            try { Write-ReleaseHelpPrivateRecord -Path (Join-Path $directory $entry[0]) -Record $entry[1] }
            catch { $failures.Add([InvalidOperationException]::new('Inner Help private outcome or hold retention failed.',$_.Exception)) }
        }
    }
    try { Write-ReleaseHelpPrivateRecord -Path (Get-QualificationCleanupBlockerPath) -Record ([ordered]@{state='OwnedCleanupUnverified';origin='ReleaseHelpInnerUncertainty'}) }
    catch { $failures.Add([InvalidOperationException]::new('Inner Help shared blocker retention failed.',$_.Exception)) }
    Write-Output 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'
    $aggregate=[AggregateException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: inner Help uncertainty and retention errors are preserved.',$failures.ToArray())
    $aggregate.Data['OwnedCleanupUnverified']=$true
    $aggregate.Data['ReleaseHelpInnerUncertainty']=$record
    throw $aggregate
}
