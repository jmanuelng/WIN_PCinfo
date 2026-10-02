# Internal exact-pinned Terraform boundary. Construction is not cloud authority.
# The admitted outer factory must supply approved tool/config identities.
function Open-AzureTerraformPinnedFile {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -cnotmatch '\A[A-Za-z]:\\' -or $Path.Substring(2).Contains(':')) {
        throw 'VALIDATION.TOOLING_UNRESOLVED'
    }
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'VALIDATION.TOOLING_UNRESOLVED' }
    $cursor=$Path
    while (-not [string]::IsNullOrEmpty($cursor)) {
        if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'VALIDATION.TOOLING_UNRESOLVED'
        }
        $parent=[IO.Path]::GetDirectoryName($cursor)
        if ($parent -ceq $cursor) { break }
        $cursor=$parent
    }
    # Keep this handle through the entire process lifetime. Denying write and
    # delete sharing prevents replacing these exact bytes while they execute.
    [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
}
function Invoke-AzureTerraformNativeProcess {
    param([Parameter(Mandatory)]$Request)
    # Initialization can consume the remaining lifetime. This proof is
    # issued only before calling the native runner; the channel accepts it
    # only from its fixed default gateway, never an injected runner.
    try {
        if ($Request.DeadlineUtc -isnot [DateTimeOffset] -or
            $Request.CancellationToken -isnot [Threading.CancellationToken] -or
            $Request.TimeoutMilliseconds -isnot [int] -or
            $Request.TimeoutMilliseconds -lt 1 -or $Request.TimeoutMilliseconds -gt 30000) {
            throw 'VALIDATION.TOOLING_UNRESOLVED'
        }
        if ($Request.CancellationToken.IsCancellationRequested -or [DateTimeOffset]::UtcNow -ge $Request.DeadlineUtc) {
            throw 'VALIDATION.ROUND_INTERRUPTED'
        }
        Initialize-ProcessSupervisorNativeType
        $remaining=[long][Math]::Ceiling(($Request.DeadlineUtc-[DateTimeOffset]::UtcNow).TotalMilliseconds)
        if ($Request.CancellationToken.IsCancellationRequested -or $remaining -le 0) {
            throw 'VALIDATION.ROUND_INTERRUPTED'
        }
        $timeout=[int][Math]::Min([long]$Request.TimeoutMilliseconds,$remaining)
    }
    catch {
        $reason='VALIDATION.TOOLING_UNRESOLVED'
        if ($_.Exception.Message -ceq 'VALIDATION.ROUND_INTERRUPTED') { $reason='VALIDATION.ROUND_INTERRUPTED' }
        $refusal=[InvalidOperationException]::new($reason)
        $refusal.Data['AzureTerraformNativePreStartVerified']=$true
        throw $refusal
    }
    [WinPCInfo.ProcessSupervisor.NativeRunner]::Run(
        $Request.Executable,$Request.Arguments,$Request.WorkingDirectory,
        $Request.Environment,$timeout,65536,16384,
        $Request.CancellationToken,$null,2000,10000,$false)
}
function Assert-AzureTerraformChannelActive {
    param([Parameter(Mandatory)]$Channel)
    $times=@(& $Channel.Clock)
    if ($times.Count -ne 1 -or $times[0] -isnot [DateTimeOffset] -or
        $Channel.CancellationToken.IsCancellationRequested -or $times[0] -ge $Channel.DeadlineUtc) {
        throw 'VALIDATION.ROUND_INTERRUPTED'
    }
    $times[0]
}
function New-AzureValidationTerraformChannel {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Pins,
        [Parameter(Mandatory)][DateTimeOffset]$DeadlineUtc,
        [Parameter()][Threading.CancellationToken]$CancellationToken=[Threading.CancellationToken]::None,
        [Parameter()][scriptblock]$OpenPinnedFile,
        [Parameter()][scriptblock]$RunProcess,
        [Parameter()][scriptblock]$UtcNow={ [DateTimeOffset]::UtcNow }
    )
    $roles=@('Terraform','Provider','CliConfig')
    if ($Pins.Count -ne 3 -or @($Pins.Keys|Where-Object { $_ -cnotin $roles }).Count -ne 0) {
        throw 'VALIDATION.TOOLING_UNRESOLVED'
    }
    $copied=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($role in $roles) {
        $pin=$Pins[$role]
        if ($pin -isnot [Collections.IDictionary] -or $pin.Count -ne 3 -or
            @($pin.Keys|Where-Object{$_ -cnotin @('Path','Length','Sha256')}).Count -ne 0 -or
            $pin.Path -isnot [string] -or -not [IO.Path]::IsPathFullyQualified($pin.Path) -or
            $pin.Path -cnotmatch '\A[A-Za-z]:\\' -or $pin.Path.Substring(2).Contains(':') -or
            $pin.Path -match '[\x00-\x1f]' -or
            [IO.Path]::GetFullPath($pin.Path) -cne $pin.Path -or
            $pin.Length -isnot [long] -or $pin.Length -lt 1 -or $pin.Length -gt 1073741824 -or
            $pin.Sha256 -isnot [string] -or $pin.Sha256 -cnotmatch '\A[0-9a-f]{64}\z') {
            throw 'VALIDATION.TOOLING_UNRESOLVED'
        }
        $leaf=[IO.Path]::GetFileName($pin.Path)
        if (($role -ceq 'Terraform' -and $leaf -cne 'terraform.exe') -or
            ($role -ceq 'Provider' -and $leaf -cnotmatch '\Aterraform-provider-azurerm_v4\.37\.0(_x5)?\.exe\z') -or
            ($role -ceq 'CliConfig' -and $leaf -cnotmatch '\A[A-Za-z0-9_.-]+\.tfrc\z')) {
            throw 'VALIDATION.TOOLING_UNRESOLVED'
        }
        $value=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        foreach ($name in @('Path','Length','Sha256')) { $value.Add($name,$pin[$name]) }
        $copied.Add($role,[Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($value))
    }
    $times=@(& $UtcNow)
    if ($times.Count -ne 1 -or $times[0] -isnot [DateTimeOffset] -or
        $DeadlineUtc -le $times[0] -or $DeadlineUtc -gt $times[0].AddHours(6)) {
        throw 'VALIDATION.ROUND_INTERRUPTED'
    }
    $kind='PinnedNative'
    $usesNativeRunner=($null -eq $RunProcess)
    if ($null -eq $OpenPinnedFile) { $OpenPinnedFile={param($path) Open-AzureTerraformPinnedFile -Path $path} }
    else { $kind='InjectedNonQualifying' }
    if ($null -eq $RunProcess) { $RunProcess={param($request) Invoke-AzureTerraformNativeProcess -Request $request} }
    else { $kind='InjectedNonQualifying' }
    if ($PSBoundParameters.ContainsKey('UtcNow')) { $kind='InjectedNonQualifying' }
    $binding=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $binding.Add('Kind',$kind)
    $binding.Add('UsesNativeRunner',$usesNativeRunner)
    $binding.Add('Pins',[Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($copied))
    $binding.Add('DeadlineUtc',$DeadlineUtc)
    $binding.Add('CancellationToken',$CancellationToken)
    $binding.Add('Clock',$UtcNow)
    $binding.Add('OpenPinnedFile',$OpenPinnedFile)
    $binding.Add('RunProcess',$RunProcess)
    [Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($binding)
}
function Get-AzureValidationTerraformVersion {
    param([Parameter(Mandatory)]$Channel)
    $leases=[Collections.Generic.List[IO.Stream]]::new()
    $failure=$null
    $result=$null
    $cleanupFailed=$false
    $processAttempted=$false
    $processAbsenceProven=$false
    try {
        $null=Assert-AzureTerraformChannelActive -Channel $Channel
        foreach ($role in @('Terraform','Provider','CliConfig')) {
            $pin=$Channel.Pins[$role]
            $opened=@(& $Channel.OpenPinnedFile $pin.Path)
            # Dispose every returned stream even when cardinality is malformed.
            foreach ($candidate in $opened) { if ($candidate -is [IO.Stream]) { $leases.Add($candidate) } }
            if ($opened.Count -ne 1 -or $opened[0] -isnot [IO.Stream] -or
                -not $opened[0].CanRead -or -not $opened[0].CanSeek -or
                $opened[0].Position -ne 0 -or $opened[0].Length -ne $pin.Length) {
                throw 'VALIDATION.TOOLING_UNRESOLVED'
            }
            $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($opened[0])).ToLowerInvariant()
            if ($digest -cne $pin.Sha256) { throw 'VALIDATION.TOOLING_UNRESOLVED' }
            $null=Assert-AzureTerraformChannelActive -Channel $Channel
        }
        $now=Assert-AzureTerraformChannelActive -Channel $Channel
        $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        $environment.Add('SystemRoot',[Environment]::GetFolderPath('Windows'))
        $environment.Add('WINDIR',[Environment]::GetFolderPath('Windows'))
        $environment.Add('CHECKPOINT_DISABLE','1')
        $environment.Add('TF_IN_AUTOMATION','1')
        $environment.Add('TF_INPUT','0')
        $environment.Add('TF_CLI_CONFIG_FILE',$Channel.Pins.CliConfig.Path)
        $request=[pscustomobject]@{
            Executable=$Channel.Pins.Terraform.Path
            Arguments=[string[]]@('version','-json')
            WorkingDirectory=[IO.Path]::GetDirectoryName($Channel.Pins.CliConfig.Path)
            Environment=$environment
            TimeoutMilliseconds=[int][Math]::Min(30000,[Math]::Ceiling(($Channel.DeadlineUtc-$now).TotalMilliseconds))
            CancellationToken=$Channel.CancellationToken
            DeadlineUtc=$Channel.DeadlineUtc
        }
        $processAttempted=$true
        $responses=@(& $Channel.RunProcess $request)
        if ($responses.Count -ne 1) { throw 'VALIDATION.TOOLING_UNRESOLVED' }
        $response=$responses[0]
        if ($response.Started -isnot [bool] -or $response.CompleteOwnedTreeAbsent -isnot [bool]) { throw 'VALIDATION.TOOLING_UNRESOLVED' }
        # Started means the runner admitted/resumed the root, not that
        # CreateProcess never succeeded. Assignment can fail with a suspended
        # root still alive. Only closed pre-creation stages or verified tree
        # absence discharge process cleanup; contradictory termination never does.
        $failureStage=[string]$response.FailureStage
        $preCreationFailure=(-not $response.Started -and $failureStage -cin @(
            'CreateJobObject','ConfigureJobObject','CreateOutputPipes','CreateProcess'))
        $processAbsenceProven=($failureStage -cne 'TerminationIncomplete' -and
            ($response.CompleteOwnedTreeAbsent -or $preCreationFailure))
        if (-not $processAbsenceProven) {
            $failure=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
            $failure.Data['OwnedCleanupUnverified']=$true
            throw $failure
        }
        $null=Assert-AzureTerraformChannelActive -Channel $Channel
        if (-not $response.Started -or $response.ExitCode -isnot [int] -or $response.ExitCode -ne 0 -or
            [string]$response.FailureStage -cne 'None' -or [string]$response.CancellationMode -cne 'None' -or
            $response.StandardOutput -isnot [byte[]] -or $response.StandardError -isnot [byte[]] -or
            $response.StandardOutput.LongLength -gt 65536 -or $response.StandardError.LongLength -gt 16384 -or
            $response.StandardOutputBytes -isnot [long] -or $response.StandardErrorBytes -isnot [long] -or
            $response.StandardOutputBytes -ne $response.StandardOutput.LongLength -or
            $response.StandardErrorBytes -ne $response.StandardError.LongLength -or
            $response.StandardOutputExceeded -isnot [bool] -or $response.StandardOutputExceeded -or
            $response.StandardErrorExceeded -isnot [bool] -or $response.StandardErrorExceeded) {
            throw 'VALIDATION.TOOLING_UNRESOLVED'
        }
        $document=ConvertFrom-AzureArmPrivateJson -Bytes $response.StandardOutput
        if ($document -isnot [Collections.IDictionary]) { throw 'VALIDATION.TOOLING_UNRESOLVED' }
        Assert-AzureArmProtocolFields -Document $document -Names @('terraform_version','platform')
        if (-not $document.Contains('terraform_version') -or $document.terraform_version -cne '1.12.2' -or
            -not $document.Contains('platform') -or $document.platform -cne 'windows_amd64') {
            throw 'VALIDATION.TOOLING_UNRESOLVED'
        }
        $result=[pscustomobject]@{
            Version='1.12.2';Platform='windows_amd64'
            NonQualifying=($Channel.Kind -ceq 'InjectedNonQualifying')
            QualifyingEvidence=$false
        }
    }
    catch {
        $nativePreStartVerified=($Channel.UsesNativeRunner -and
            $_.Exception.Data['AzureTerraformNativePreStartVerified'] -eq $true)
        if ($processAttempted -and -not $processAbsenceProven -and -not $nativePreStartVerified) {
            $failure=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
            $failure.Data['OwnedCleanupUnverified']=$true
        }
        elseif ($null -eq $failure) {
            $reason='VALIDATION.TOOLING_UNRESOLVED'
            try { $null=Assert-AzureTerraformChannelActive -Channel $Channel }
            catch { $reason='VALIDATION.ROUND_INTERRUPTED' }
            $failure=[InvalidOperationException]::new($reason)
        }
    }
    finally {
        foreach ($lease in $leases) {
            try { $lease.Dispose() } catch { $cleanupFailed=$true }
        }
    }
    if ($null -ne $failure) { throw $failure }
    if ($cleanupFailed) { throw 'VALIDATION.TOOLING_UNRESOLVED' }
    $result
}
