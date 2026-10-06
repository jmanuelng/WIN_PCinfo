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
        'tests/QualificationFixtureProcess.ps1')) {
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
            powerShell=$PSVersionTable.PSVersion.ToString(); dotNet=[Environment]::Version.ToString(); architecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()}
    }
}

function Open-TestCandidate {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [string] $CandidatePath,
        [string] $PreparedManifestPath, [string] $PreparedManifestSha256, [switch] $SeparateBuildProcess)
    $supplied=-not [string]::IsNullOrWhiteSpace($CandidatePath) -or
        -not [string]::IsNullOrWhiteSpace($PreparedManifestPath) -or -not [string]::IsNullOrWhiteSpace($PreparedManifestSha256)
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
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $ownedDirectory -and [IO.Directory]::Exists($ownedDirectory)) { [IO.Directory]::Delete($ownedDirectory,$true) }
        throw
    }
}

function Close-TestCandidate {
    param([Parameter(Mandatory)] $Candidate, [AllowNull()] [Management.Automation.ErrorRecord] $BodyError)
    # The open read handle prevents all consumers from replacing this input.
    # Verify it again before releasing ownership; never turn drift into a pass.
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

function Invoke-GeneratedApplication {
    param(
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter()] [AllowEmptyString()] [string] $StandardInput,
        [Parameter()] [string] $PowerShellPath,
        [Parameter()] [string] $WorkingDirectory = (Get-Location).Path,
        [long] $TimeoutMs = 3600000,
        [long] $CleanupReserveMs = 120000,
        [DateTimeOffset] $AuthorityEnds = [DateTimeOffset]::MinValue
    )

    if ([string]::IsNullOrWhiteSpace($PowerShellPath)) {
        # Reuse selection within this test file only for identical application
        # bytes. Every application invocation still runs its own safety checks.
        $candidateIdentity = (Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256).Hash
        $cache = Get-Variable -Name WinPCInfoTestHostCache -Scope Script -ErrorAction SilentlyContinue
        if ($null -ne $cache -and $cache.Value.Identity -eq $candidateIdentity) {
            $PowerShellPath = $cache.Value.Executable
        }
        else {
            $PowerShellPath = Resolve-WinPCInfoRuntime -ApplicationPath $CandidatePath
            $script:WinPCInfoTestHostCache = @{ Identity = $candidateIdentity; Executable = $PowerShellPath }
        }
    }
    $native=Invoke-GeneratedApplicationNative -HostPath ([IO.Path]::GetFullPath($PowerShellPath)) -WorkingDirectory ([IO.Path]::GetFullPath($WorkingDirectory)) `
        -Arguments (@('-NoLogo','-NoProfile','-File',$CandidatePath)+$Arguments) -StandardInput $StandardInput `
        -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $AuthorityEnds
    [pscustomobject]@{
        ExitCode=$native.ExitCode
        Records=@($native.StandardOutput -split "`r?`n" | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json -Depth 20 })
        StandardOutput=$native.StandardOutput
        StandardError=$native.StandardError
    }
}
