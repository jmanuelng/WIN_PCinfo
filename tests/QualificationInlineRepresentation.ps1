Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'QualificationCapabilityProcess.ps1')

# This constructor supplies only the sixteen existing synthetic inline cases.
# It accepts bounded operands, never a script, executable, environment or argv.
# Host/candidate admission and execution remain separate reviewed boundaries.
function Get-QualificationInlineRepresentationProfile {
    param([Parameter(Mandatory)] $Profile,[Parameter(Mandatory)] $Inputs)
    if ($Profile -isnot [string] -or $Profile -cnotin @('Hash','Padding','Culture','Malformed') -or
        $Inputs -isnot [Collections.IDictionary]) { throw 'Inline representation requires a closed scalar profile and operand record.' }
    $keys=@(switch ($Profile) { Hash {'Bytes'}; Padding {'Count'}; Culture {'Culture'}; Malformed {} })
    if ($Inputs.psbase.Count -ne $keys.Count -or @($Inputs.psbase.Keys | Where-Object {$_ -isnot [string] -or $_ -cnotin $keys}).Count) {
        throw 'Inline representation operands differ from the exact declared profile.'
    }
    $expected=$null
    switch ($Profile) {
        Hash {
            if ($Inputs.Bytes -isnot [byte[]] -or $Inputs.Bytes.Length -ne 25000) { throw 'Inline hash requires the original 25000-byte operand.' }
            $literal=[Convert]::ToBase64String($Inputs.Bytes)
            $source='[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String('''+$literal+'''))).ToLowerInvariant()'
            $expected=Get-PrivilegedCollectionPlanSha256 $Inputs.Bytes
        }
        Padding {
            if ($Inputs.Count -isnot [int] -or $Inputs.Count -lt 1 -or $Inputs.Count -gt 9) { throw 'Inline padding requires an original integer count from 1 through 9.' }
            $literal=[Convert]::ToBase64String([byte[]](1..$Inputs.Count))
            $source="'$literal'"
            $expected=$literal
        }
        Culture {
            if ($Inputs.Culture -isnot [string] -or $Inputs.Culture -cnotin @('en-US','es-MX','tr-TR','ja-JP','ar-SA')) {
                throw 'Inline culture requires one of the five original scalar culture names.'
            }
            $culture=$Inputs.Culture
            $source="[Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('$culture');'Synthetic 漢字 O''Brien'"
            $expected="Synthetic 漢字 O'Brien"
        }
        Malformed { $source="'synthetic-not-executed'" }
    }
    $command=ConvertTo-PrivilegedCollectionInlineCommand -Source $source
    if ($command -isnot [string] -or $command.Length -gt 32500 -or [string]::IsNullOrEmpty($command)) {
        throw 'Inline representation retains the original scalar Windows launch ceiling.'
    }
    if ($Profile -ceq 'Malformed') {
        $match=[regex]::Match($command,'[\u4000-\u5080]+')
        if (-not $match.Success) { throw 'The exact malformed fixture requires its original packed BMP representation.' }
        $command=$command.Remove($match.Index,1).Insert($match.Index,([char]0x3000).ToString())
    }
    [pscustomobject]@{Profile=$Profile;Source=$source;
        SourceSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false,$true).GetBytes($source))).ToLowerInvariant());
        Arguments=@('-NoLogo','-NoProfile','-NonInteractive','-Command',$command);
        ExpectedStandardOutput=$expected;ExpectedNaturalNonzero=($Profile -ceq 'Malformed')}
}

function Open-QualificationInlineRepresentationBinding {
    param([Parameter(Mandatory)] [string] $RepositoryRoot,[Parameter(Mandatory)] $Candidate,
        [Parameter(Mandatory)] [string] $PreparedManifestPath,[Parameter(Mandatory)] [string] $PreparedManifestSha256)
    $root=[IO.Path]::GetFullPath($RepositoryRoot)
    $admission=Get-QualificationFixtureAdmission -RepositoryRoot $root
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $root -SelfIdentity $admission.Creator
    $testPath=Join-Path $root 'tests/PrivilegedInlineRepresentation.Tests.ps1'
    $governing=$context.Root.Admission
    if ($context.Parent.Admission.testPath -isnot [string] -or $context.Parent.Admission.testPath -ine $testPath -or
        @($governing.inputs | Where-Object path -IEQ $testPath).Count -ne 1 -or
        (Get-TestNativeDigest -Value $admission.Parent.Pending) -cne (Get-TestNativeDigest -Value $context.Parent.Pending)) {
        throw 'Inline representation requires its unchanged exact named File/Case source and cohort.'
    }
    if ($Candidate.Prepared -isnot [bool] -or -not $Candidate.Prepared -or -not $Candidate.Stream.CanRead -or
        $Candidate.Path -isnot [string] -or $Candidate.Sha256 -isnot [string] -or $Candidate.Sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $governing.candidatePath -isnot [string] -or $governing.preparedManifestPath -isnot [string] -or $governing.preparedManifestSha256 -isnot [string] -or
        $Candidate.Path -cne $governing.candidatePath -or $PreparedManifestPath -cne $governing.preparedManifestPath -or
        $PreparedManifestSha256 -cne $governing.preparedManifestSha256 -or $PreparedManifestSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Inline candidate/manifest must be the actual immutable root prepared triple.'
    }
    if ($governing.hostPath -isnot [string]) {throw 'Inline runtime requires a scalar admitted host.'}
    $candidatePin=@($governing.inputs | Where-Object path -IEQ $Candidate.Path)
    $manifestPin=@($governing.inputs | Where-Object path -IEQ $PreparedManifestPath)
    $hostPin=@($governing.inputs | Where-Object path -IEQ $governing.hostPath)
    if ($candidatePin.Count -ne 1 -or $candidatePin[0].sha256 -cne $Candidate.Sha256 -or
        $manifestPin.Count -ne 1 -or $manifestPin[0].sha256 -cne $PreparedManifestSha256 -or $hostPin.Count -ne 1 -or
        $governing.hostPath -isnot [string] -or -not [IO.Path]::IsPathFullyQualified($governing.hostPath) -or
        [IO.Path]::GetFileName($governing.hostPath) -ine 'pwsh.exe') { throw 'Inline runtime/candidate/manifest lacks its exact root cohort pin.' }
    $hostStream=$null;$binding=$null
    try {
        if (((Get-Item -LiteralPath $governing.hostPath).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Inline runtime cannot be redirected.'
        }
        $hostStream=[IO.File]::Open($governing.hostPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $hostDigest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($hostStream)).ToLowerInvariant()
        $hostStream.Position=0
        if ($hostDigest -cne $hostPin[0].sha256) { throw 'Inline runtime bytes differ from the governing cohort.' }
        $directory=Join-Path $root ('.test-output/inline-representation-'+[guid]::NewGuid().ToString('N'))
        $null=[IO.Directory]::CreateDirectory((Split-Path -Parent $directory))
        if (((Get-Item -LiteralPath (Split-Path -Parent $directory)).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Inline private output cannot be redirected.'
        }
        $null=New-Item -ItemType Directory -Path $directory
        $null=Set-TestNativePrivateDirectory -Path $directory
        $binding=[pscustomobject]@{RepositoryRoot=$root;Directory=$directory;Candidate=$Candidate;HostPath=$governing.hostPath;
            HostStream=$hostStream;HostSha256=$hostDigest;AuthorityEnds=$admission.Ends;
            ParentDigest=(Get-TestNativeDigest -Value $context.Parent.Pending);CohortSha256=$governing.cohortSha256;
            UnsafeError=$null;Unsafe=$false;Record=$null}
        $binding.Record=[ordered]@{contract='win-pcinfo.inline-representation-binding/1.0.0';testPath=$testPath;
            hostPath=$binding.HostPath;hostSha256=$hostDigest;candidatePath=$Candidate.Path;candidateSha256=$Candidate.Sha256;
            preparedManifestPath=$PreparedManifestPath;preparedManifestSha256=$PreparedManifestSha256;
            parentPendingCanonicalSha256=$binding.ParentDigest;cohortSha256=$binding.CohortSha256;
            authorityEnds=$binding.AuthorityEnds.ToString('o');processTreeAbsenceClaim=$false}
        Write-QualificationFixtureRecord -Path (Join-Path $directory 'original-binding.json') -Value $binding.Record
        $binding
    }
    catch {
        $original=$_
        Complete-QualificationHarness -BodyError $original -Cleanup @({if($null -ne $hostStream){$hostStream.Dispose()}})
    }
}

function Assert-QualificationInlineRepresentationBinding {
    param([Parameter(Mandatory)] $Binding,[Parameter(Mandatory)] [string] $HostPath)
    if ($null -ne $Binding.UnsafeError) { throw $Binding.UnsafeError }
    if ($HostPath -cne $Binding.HostPath -or -not $Binding.HostStream.CanRead -or -not $Binding.Candidate.Stream.CanRead) {
        throw 'Inline native creation requires the unchanged exact admitted runtime and held candidate.'
    }
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $Binding.RepositoryRoot -SelfIdentity (Get-TestNativeSelfIdentity)
    $root=$context.Root.Admission
    $hostPin=@($root.inputs | Where-Object path -IEQ $root.hostPath)
    $candidatePin=@($root.inputs | Where-Object path -IEQ $root.candidatePath)
    if ($Binding.HostPath -isnot [string] -or $Binding.HostPath -cne $root.hostPath -or
        $Binding.Record.hostPath -cne $root.hostPath -or $Binding.HostStream.Name -cne $root.hostPath -or
        $hostPin.Count -ne 1 -or $hostPin[0].sha256 -cne $Binding.HostSha256 -or
        $Binding.Candidate.Path -isnot [string] -or $Binding.Candidate.Path -cne $root.candidatePath -or
        $candidatePin.Count -ne 1 -or $candidatePin[0].sha256 -cne $Binding.Candidate.Sha256 -or
        $Binding.Record.preparedManifestPath -cne $root.preparedManifestPath -or
        $Binding.Record.preparedManifestSha256 -cne $root.preparedManifestSha256 -or
        $context.Parent.Admission.testPath -cne $Binding.Record.testPath -or
        (Get-TestNativeDigest -Value $context.Parent.Pending) -cne $Binding.ParentDigest -or
        $context.Root.Admission.cohortSha256 -cne $Binding.CohortSha256) { throw 'Inline source/parent/cohort changed before native creation.' }
}

function Invoke-QualificationInlineRepresentationNative {
    param([Parameter(Mandatory)] $Binding,[Parameter(Mandatory)] $Profile,[Parameter(Mandatory)] $Inputs)
    Assert-QualificationInlineRepresentationBinding -Binding $Binding -HostPath $Binding.HostPath
    $specification=Get-QualificationInlineRepresentationProfile -Profile $Profile -Inputs $Inputs
    $record=[ordered]@{binding=$Binding.Record;profile=$specification.Profile;sourceSha256=$specification.SourceSha256;
        arguments=$specification.Arguments;expectedNaturalNonzero=$specification.ExpectedNaturalNonzero}
    try {
        $native=Invoke-GeneratedApplicationNative -HostPath $Binding.HostPath -WorkingDirectory $Binding.RepositoryRoot `
            -Arguments $specification.Arguments -TimeoutMs 10000 -CleanupReserveMs 5000 -AuthorityEnds $Binding.AuthorityEnds `
            -MaximumLines 128 -MaximumLineCharacters 8192 -MaximumTotalCharacters 32768 `
            -ObserveStartup {param($Directory,$Identity);Write-QualificationFixtureRecord -Path (Join-Path $Directory 'original-inline-profile.json') -Value $record}
        if ($native.ExitCode -isnot [int]) {
            $exception=[InvalidOperationException]::new('Inline native status is unknown.')
            $exception.Data['OwnedCleanupUnverified']=$true
            throw $exception
        }
    }
    catch {
        if (Test-QualificationCleanupUnverified -Exception $_.Exception) {$Binding.Unsafe=$true;$Binding.UnsafeError=$_}
        throw
    }
    Set-Variable -Name LASTEXITCODE -Value $native.ExitCode -Scope 1
    $native.StreamRecords | Where-Object Stream -CEQ 'stdout' | Sort-Object Sequence | ForEach-Object Text
}

function Invoke-QualificationInlineRuntimeProbe {
    param([Parameter(Mandatory)] $Binding,[Parameter(Mandatory)] [string] $Executable,[Parameter(Mandatory)] [string] $ApplicationPath)
    Assert-QualificationInlineRepresentationBinding -Binding $Binding -HostPath $Executable
    if ($ApplicationPath -cne $Binding.Candidate.Path) { throw 'Inline runtime probe cannot substitute its admitted candidate.' }
    try {
        $native=Invoke-GeneratedApplicationNative -HostPath $Executable -WorkingDirectory $Binding.RepositoryRoot `
            -Arguments @('-NoLogo','-NoProfile','-NonInteractive','-File',$ApplicationPath,'-Workflow','CheckRuntime') `
            -TimeoutMs 15000 -CleanupReserveMs 5000 -AuthorityEnds $Binding.AuthorityEnds `
            -MaximumLines 128 -MaximumLineCharacters 8192 -MaximumTotalCharacters 32768 `
            -ObserveStartup {param($Directory,$Identity);Write-QualificationFixtureRecord -Path (Join-Path $Directory 'original-inline-runtime-probe.json') -Value $Binding.Record}
        if ($native.ExitCode -isnot [int]) {
            $exception=[InvalidOperationException]::new('Inline runtime probe native status is unknown.')
            $exception.Data['OwnedCleanupUnverified']=$true
            throw $exception
        }
        $native
    }
    catch {
        if (Test-QualificationCleanupUnverified -Exception $_.Exception) {$Binding.Unsafe=$true;$Binding.UnsafeError=$_}
        throw
    }
}

function Resolve-QualificationInlineRuntime {
    param([Parameter(Mandatory)] $Binding)
    $runProbe={param($Executable,$ApplicationPath);Invoke-QualificationInlineRuntimeProbe -Binding $Binding -Executable $Executable -ApplicationPath $ApplicationPath}
    $probe={
        param($Executable,$ApplicationPath)
        if ($null -ne $Binding.UnsafeError) { throw $Binding.UnsafeError }
        $result=Invoke-WinPCInfoRuntimeProbe -Executable $Executable -ApplicationPath $ApplicationPath -RunProbe $runProbe
        # The product probe intentionally sanitizes all exceptions into a host
        # rejection. Preserve actual unsafe ownership outside that catch-all.
        if ($null -ne $Binding.UnsafeError) { throw $Binding.UnsafeError }
        $result
    }
    Resolve-WinPCInfoRuntime -ApplicationPath $Binding.Candidate.Path -Probe $probe
}

function Get-QualificationInlineShellSpecification {
    param([Parameter(Mandatory)] [string] $RepositoryRoot,[Parameter(Mandatory)] [string] $OutputPath)
    $root=[IO.Path]::GetFullPath($RepositoryRoot)
    $path=[IO.Path]::GetFullPath($OutputPath)
    $parts=[IO.Path]::GetRelativePath($root,$path).Replace('\','/').Split('/')
    if ($OutputPath -cne $path -or $parts.Count -ne 3 -or $parts[0] -cne '.test-output' -or
        $parts[1] -cnotmatch '^inline-representation-[a-f0-9]{32}$' -or $parts[2] -cnotmatch '^result-[a-f0-9]{32}\.txt$') {
        throw 'Inline ShellExecute output escaped its closed unique fixture.'
    }
    $source="[IO.File]::WriteAllText('"+$OutputPath.Replace("'","''")+"','Synthetic 漢字 O''Brien',[Text.UTF8Encoding]::new(`$false))"
    [pscustomobject]@{Source=$source;Arguments=@('-NoLogo','-NoProfile','-NonInteractive','-Command',(ConvertTo-PrivilegedCollectionInlineCommand $source))}
}

function Close-QualificationInlineRepresentationBinding {
    param([Parameter(Mandatory)] $Binding)
    if ($Binding.Unsafe -or $null -ne $Binding.UnsafeError) {
        if ($null -eq (Get-Variable QualificationInlineUnverifiedBindings -Scope Script -ErrorAction SilentlyContinue)) {
            $script:QualificationInlineUnverifiedBindings=[Collections.Generic.List[object]]::new()
        }
        $script:QualificationInlineUnverifiedBindings.Add($Binding)
        $exception=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: inline original binding and fixture remain retained.')
        $exception.Data['OwnedCleanupUnverified']=$true
        throw $exception
    }
    $Binding.HostStream.Dispose()
}
