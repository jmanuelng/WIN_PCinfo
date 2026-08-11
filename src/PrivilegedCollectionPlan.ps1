$script:PrivilegedCollectionPlanPolicyBase64 = '__PRIVILEGED_COLLECTION_PLAN_POLICY_BASE64__'
$script:PrivilegedCollectionPlanPolicyDigest = '__PRIVILEGED_COLLECTION_PLAN_POLICY_SHA256__'

function Get-PrivilegedCollectionPlanSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-PrivilegedCollectionPlanPolicy {
    $convertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $convertFromJsonCommand -or
        $convertFromJsonCommand.ModuleName -ne 'Microsoft.PowerShell.Utility') {
        throw 'The privilege policy JSON command does not have built-in provenance.'
    }

    if ($script:PrivilegedCollectionPlanPolicyBase64 -eq '__PRIVILEGED_COLLECTION_PLAN_POLICY_BASE64__') {
        $repositoryRoot = Split-Path -Parent $PSScriptRoot
        $text = [System.IO.File]::ReadAllText(
            (Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-privileged-collection-plan.json'),
            [System.Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text)
        $expectedDigest = Get-PrivilegedCollectionPlanSha256 -Bytes $bytes
    }
    else {
        $bytes = [System.Convert]::FromBase64String($script:PrivilegedCollectionPlanPolicyBase64)
        $expectedDigest = $script:PrivilegedCollectionPlanPolicyDigest
    }
    if ((Get-PrivilegedCollectionPlanSha256 -Bytes $bytes) -ne $expectedDigest) {
        throw 'The embedded privilege policy failed integrity validation.'
    }

    $policy = & $convertFromJsonCommand -InputObject (
        [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 30 -ErrorAction Stop
    $operationIds = @($policy.operations.operationId)
    if ($policy.kind -ne 'win-pcinfo.privileged-collection-plan-policy' -or
        $policy.contractVersion -ne '1.0.0' -or
        $policy.release -ne '2.0.0-preview.1' -or
        $policy.policyId -ne 'win-pcinfo.privileged-collection-plan/1.0.0' -or
        $policy.elevation.maximumUacInteractions -ne 1 -or
        @($operationIds).Count -ne 4 -or
        @($operationIds | Sort-Object -Unique).Count -ne 4 -or
        $policy.channel.maximumServerInstances -ne 1 -or
        @($policy.validationScenarios).Count -ne 9) {
        throw 'The privilege policy is not semantically closed.'
    }
    $policy
}

function Get-PrivilegedCollectionValidationScenario {
    param([Parameter(Mandatory)] [string] $Name)

    # Validation faults are release-owned data, not scattered control flow.
    # Keeping the complete behavior tuple here makes a new fixture an explicit
    # policy decision: the coordinator, worker, and cancellation seam cannot
    # silently disagree about what the scenario is meant to prove.
    $defaults = [ordered]@{
        isFixture = $true
        alreadyElevated = $false
        workerPrincipalRelationship = 'SelectedAdministrator'
        elevationDenied = $false
        launchUnexpectedClient = $false
        workerFault = 'None'
        failureReasonCode = $null
        cancellationDelayMilliseconds = $null
    }
    $scenarios = @{
        Live = @{
            isFixture = $false
            alreadyElevated = $null
            workerPrincipalRelationship = $null
        }
        AcceptedElevation = @{}
        AlreadyElevated = @{
            alreadyElevated = $true
            workerPrincipalRelationship = 'AssessmentOperator'
        }
        AlternateAdministrator = @{
            workerPrincipalRelationship = 'AlternateAdministrator'
        }
        ElevationDenied = @{
            workerPrincipalRelationship = 'NotStarted'
            elevationDenied = $true
        }
        WrongPipeClient = @{
            launchUnexpectedClient = $true
            workerFault = 'DelayConnect'
            failureReasonCode = 'PRIVILEGE.PEER_IDENTITY_INVALID'
        }
        AlteredPlan = @{
            workerPrincipalRelationship = 'NotStarted'
            failureReasonCode = 'PRIVILEGE.PLAN_INTEGRITY_INVALID'
        }
        LostWorker = @{
            workerFault = 'ExitAfterHello'
            failureReasonCode = 'PRIVILEGE.WORKER_LOST'
        }
        Timeout = @{ workerFault = 'HangAfterPlan' }
        Cancellation = @{
            workerFault = 'HangAfterPlan'
            cancellationDelayMilliseconds = 200
        }
    }
    if (-not $scenarios.ContainsKey($Name)) {
        throw 'The privileged collection validation scenario is not release-defined.'
    }
    $scenario = [ordered]@{ name = $Name }
    foreach ($property in $defaults.Keys) {
        $scenario[$property] = if ($scenarios[$Name].ContainsKey($property)) {
            $scenarios[$Name][$property]
        }
        else { $defaults[$property] }
    }
    [pscustomobject] $scenario
}

function Get-PrivilegedCollectionWorkerSource {
    # This is reviewed product source, not caller input. It is encoded directly
    # into the fixed PowerShell launch argument so there is no writable script
    # file to replace between validation and elevation. The worker understands
    # one tiny framed protocol and four empty-parameter operation identities; it
    # has no command parser, plug-in loader, path parameter, evidence serializer,
    # or credential input.
    @'
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$configurationJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    [System.Convert]::FromBase64String('__PRIVILEGED_WORKER_CONFIGURATION__')
)
$configurationDocument = [System.Text.Json.JsonDocument]::Parse($configurationJson)
try {
    $configurationRoot = $configurationDocument.RootElement
    $configurationNames = @(
        $configurationRoot.EnumerateObject() | ForEach-Object Name
    )
    if ($configurationRoot.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
        $configurationNames.Count -ne 11 -or
        @($configurationNames | Sort-Object -Unique).Count -ne 11) {
        throw 'The privilege worker configuration is invalid.'
    }
}
finally { $configurationDocument.Dispose() }
$configuration = $configurationJson | ConvertFrom-Json -Depth 5

Add-Type -TypeDefinition @"
using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class WinPCInfoPrivilegedWorkerPipe
{
    private const uint JOB_OBJECT_ASSIGN_PROCESS = 0x0001;
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenJobObject(uint desiredAccess, bool inheritHandle, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFirmwareType(out uint firmwareType);
    public static void JoinOwnedProcessTree(string name)
    {
        IntPtr job = OpenJobObject(JOB_OBJECT_ASSIGN_PROCESS, false, name);
        if (job == IntPtr.Zero)
            throw new InvalidOperationException("Unable to open the coordinator-owned worker job.");
        try
        {
            if (!AssignProcessToJobObject(job, GetCurrentProcess()))
                throw new InvalidOperationException("Unable to join the coordinator-owned worker job.");
        }
        finally { CloseHandle(job); }
    }
    public static int GetServerProcessId(PipeStream pipe)
    {
        uint processId;
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out processId))
            throw new InvalidOperationException("Unable to bind the coordinator process.");
        return checked((int)processId);
    }
    public static uint ReadFirmwareType()
    {
        uint value;
        if (!GetFirmwareType(out value))
            throw new InvalidOperationException("Unable to read the Windows firmware type.");
        return value;
    }
}
"@

# UAC gives the worker more authority than the coordinator, so the worker must
# join the coordinator's private kill-on-close Windows Job Object before it
# connects or executes an operation. The standard-user coordinator deliberately
# retains the controlling handle across UAC; every future worker descendant
# inherits membership, and the coordinator can terminate and query that kernel
# object without needing PROCESS_TERMINATE access to a high-integrity process.
# If nested Job policy or the protected name is incompatible, the worker fails
# before the coordinator sends the plan.
[WinPCInfoPrivilegedWorkerPipe]::JoinOwnedProcessTree([string] $configuration.jobName)

function Read-ExactBytes {
    param($Stream, [int] $Count, [System.Threading.CancellationToken] $Token)
    $bytes = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.ReadAsync($bytes, $offset, $Count - $offset, $Token).GetAwaiter().GetResult()
        if ($read -eq 0) { throw 'Privilege channel closed before a complete frame.' }
        $offset += $read
    }
    $bytes
}

function Read-Frame {
    param($Stream, [int] $MaximumBytes, [System.Threading.CancellationToken] $Token)
    $lengthBytes = Read-ExactBytes -Stream $Stream -Count 4 -Token $Token
    $length = [System.BitConverter]::ToInt32($lengthBytes, 0)
    if ($length -le 0 -or $length -gt $MaximumBytes) { throw 'Privilege frame length is invalid.' }
    $payload = Read-ExactBytes -Stream $Stream -Count $length -Token $Token
    [System.Text.UTF8Encoding]::new($false, $true).GetString($payload)
}

function Write-Frame {
    param($Stream, [string] $Json, [int] $MaximumBytes, [System.Threading.CancellationToken] $Token)
    $payload = [System.Text.UTF8Encoding]::new($false).GetBytes($Json)
    if ($payload.Length -le 0 -or $payload.Length -gt $MaximumBytes) { throw 'Privilege frame length is invalid.' }
    $lengthBytes = [System.BitConverter]::GetBytes([int] $payload.Length)
    $null = $Stream.WriteAsync($lengthBytes, 0, 4, $Token).GetAwaiter().GetResult()
    $null = $Stream.WriteAsync($payload, 0, $payload.Length, $Token).GetAwaiter().GetResult()
    $null = $Stream.FlushAsync($Token).GetAwaiter().GetResult()
}

function New-EmptyFirmwareResult {
    param([string] $State)
    [ordered]@{
        sourceLocale = 'und'
        firmwareState = $State; firmwareType = $null; biosVersion = $null
        smbiosVersion = $null; secureBootState = $State; secureBootEnabled = $null
        tpmState = $State; tpmPresent = $null; tpmEnabled = $null
        tpmActivated = $null; tpmSpecification = $null
    }
}

function New-SyntheticFirmwareResult {
    param([string] $Scenario)
    $base = [ordered]@{
        sourceLocale='und';firmwareState='Complete';firmwareType='Uefi'
        biosVersion='SYNTHETIC-UEFI-1.0';smbiosVersion='3.4'
        secureBootState='Complete';secureBootEnabled=$true
        tpmState='Complete';tpmPresent=$true;tpmEnabled=$true
        tpmActivated=$true;tpmSpecification='2.0'
    }
    switch ($Scenario) {
        'Supported' { }
        'Disabled' {
            $base.secureBootEnabled = $false
            $base.tpmEnabled = $false; $base.tpmActivated = $false
        }
        'Absent' {
            $base.tpmPresent = $false; $base.tpmEnabled = $null
            $base.tpmActivated = $null; $base.tpmSpecification = $null
        }
        'Virtual' { }
        'NonUefi' {
            $base.firmwareType = 'LegacyBios'
            $base.secureBootState = 'Unsupported'; $base.secureBootEnabled = $null
        }
        'AccessDenied' { return New-EmptyFirmwareResult -State Denied }
        'Unsupported' {
            $base.secureBootState = 'Unsupported'; $base.secureBootEnabled = $null
            $base.tpmState = 'Unsupported'; $base.tpmPresent = $null
            $base.tpmEnabled = $null; $base.tpmActivated = $null
            $base.tpmSpecification = $null
        }
        'Malformed' { return New-EmptyFirmwareResult -State Malformed }
        'Timeout' { return New-EmptyFirmwareResult -State TimedOut }
        'CollectorFailure' { return New-EmptyFirmwareResult -State Failed }
        default { throw 'The firmware validation scenario is not release-defined.' }
    }
    $base
}

function Get-WorkerAccessState {
    param($Failure)
    $exception = $Failure.Exception
    $nativeCode = [int]($exception.HResult -band 0xffff)
    if ($exception -is [System.UnauthorizedAccessException] -or $nativeCode -eq 5) {
        'Denied'
    } else { 'Failed' }
}

function Get-LiveFirmwareResult {
    # Firmware and TPM interfaces sit behind powerful Windows providers. The
    # worker performs only explicit reads: no WMI method, Secure Boot variable
    # write, TPM provisioning call, ownership action, or feature change exists.
    # Serial numbers, manufacturer identifiers, keys, owner authorization, and
    # endorsement/recovery material are never projected. This trusts Windows'
    # structured API/CIM/module results; access or provider failure becomes a
    # typed coverage gap instead of a guessed disabled/absent value.
    $result = New-EmptyFirmwareResult -State Failed
    try {
        $nativeFirmware = [WinPCInfoPrivilegedWorkerPipe]::ReadFirmwareType()
        $bios = @(Get-CimInstance -ClassName Win32_BIOS -Property @(
            'SMBIOSBIOSVersion','SMBIOSMajorVersion','SMBIOSMinorVersion'
        ) -ErrorAction Stop)
        if ($bios.Count -ne 1) { throw 'The bounded BIOS projection is ambiguous.' }
        $firmwareType = switch ([uint32]$nativeFirmware) {
            1 { 'LegacyBios' } 2 { 'Uefi' } default { 'Unknown' }
        }
        $biosVersion = ([string]$bios[0].SMBIOSBIOSVersion).Trim()
        $smbiosVersion = "$([int]$bios[0].SMBIOSMajorVersion).$([int]$bios[0].SMBIOSMinorVersion)"
        if ([Text.Encoding]::UTF8.GetByteCount($biosVersion) -gt 128 -or
            [Text.Encoding]::UTF8.GetByteCount($smbiosVersion) -gt 16) {
            throw 'The bounded BIOS projection is oversized.'
        }
        $result.firmwareState='Complete';$result.firmwareType=$firmwareType
        $result.biosVersion=$biosVersion;$result.smbiosVersion=$smbiosVersion
    }
    catch {
        $result.firmwareState = Get-WorkerAccessState -Failure $_
    }
    if ($result.firmwareState -eq 'Complete' -and $result.firmwareType -eq 'LegacyBios') {
        $result.secureBootState = 'Unsupported'
    }
    elseif ($result.firmwareState -eq 'Complete') {
        $secureBootCommand = Get-Command -Name Confirm-SecureBootUEFI `
            -CommandType Cmdlet -ErrorAction SilentlyContinue
        if ($null -eq $secureBootCommand -or $secureBootCommand.ModuleName -ne 'SecureBoot') {
            $result.secureBootState = 'Unsupported'
        }
        else {
            try {
                $result.secureBootEnabled = [bool](& $secureBootCommand -ErrorAction Stop)
                $result.secureBootState = 'Complete'
            }
            catch { $result.secureBootState = Get-WorkerAccessState -Failure $_ }
        }
    }
    else { $result.secureBootState = $result.firmwareState }
    try {
        $tpm = @(Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftTpm' `
            -ClassName Win32_Tpm -Property @(
                'SpecVersion','IsEnabled_InitialValue','IsActivated_InitialValue'
            ) -ErrorAction Stop)
        if ($tpm.Count -gt 1) { throw 'The bounded TPM projection is ambiguous.' }
        $result.tpmState = 'Complete'
        $result.tpmPresent = $tpm.Count -eq 1
        if ($tpm.Count -eq 1) {
            $result.tpmEnabled = [bool]$tpm[0].IsEnabled_InitialValue
            $result.tpmActivated = [bool]$tpm[0].IsActivated_InitialValue
            $specification = ([string]$tpm[0].SpecVersion).Trim()
            if ([Text.Encoding]::UTF8.GetByteCount($specification) -gt 32) {
                throw 'The bounded TPM specification is oversized.'
            }
            $result.tpmSpecification = $specification
        }
    }
    catch {
        $result.tpmState = Get-WorkerAccessState -Failure $_
        $result.tpmPresent=$null;$result.tpmEnabled=$null
        $result.tpmActivated=$null;$result.tpmSpecification=$null
    }
    $result
}

$maximumBytes = [int] $configuration.maximumBytes
$deadline = [int] $configuration.deadlineMilliseconds
$tokenSource = [System.Threading.CancellationTokenSource]::new($deadline)
$pipe = $null
$workerStage = 'Connect'
try {
    if ($configuration.workerFault -eq 'DelayConnect') {
        [System.Threading.Thread]::Sleep(750)
    }
    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
        '.', [string] $configuration.pipe,
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous
    )
    $pipe.ConnectAsync($tokenSource.Token).GetAwaiter().GetResult()

    # The nonce binds this process to one run, while the kernel-reported server
    # PID prevents a same-machine process from redirecting the trusted worker to
    # its own pipe. The worker then hashes the actual coordinator image. This
    # trusts Windows pipe/process accounting and the reviewed PowerShell image;
    # any mismatch exits before an operation runs.
    $workerStage = 'PeerIdentity'
    $serverProcessId = [WinPCInfoPrivilegedWorkerPipe]::GetServerProcessId($pipe)
    if ($serverProcessId -ne [int] $configuration.coordinatorProcessId) {
        throw 'The privilege coordinator process is not the approved peer.'
    }
    $serverImage = [System.Diagnostics.Process]::GetProcessById($serverProcessId).MainModule.FileName
    $serverImageDigest = [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData([System.IO.File]::ReadAllBytes($serverImage))
    ).ToLowerInvariant()
    if ($serverImageDigest -ne $configuration.executableSha256) {
        throw 'The privilege coordinator artifact is not approved.'
    }
    $workerImage = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $workerImageDigest = [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData([System.IO.File]::ReadAllBytes($workerImage))
    ).ToLowerInvariant()
    if ($workerImageDigest -ne $configuration.executableSha256) {
        throw 'The privilege worker artifact is not approved.'
    }

    $workerStage = 'Hello'
    $hello = [ordered]@{
        kind = 'WorkerHello'
        contractVersion = '1.0.0'
        nonce = [string] $configuration.nonce
        workerProcessId = $PID
        coordinatorProcessId = $serverProcessId
        workerPayloadSha256 = [string] $configuration.workerPayloadSha256
        executableSha256 = $workerImageDigest
        treeControl = 'WorkerOwnedJobObject'
    } | ConvertTo-Json -Compress
    Write-Frame -Stream $pipe -Json $hello -MaximumBytes $maximumBytes -Token $tokenSource.Token
    if ($configuration.workerFault -eq 'ExitAfterHello') { exit 71 }

    $workerStage = 'PlanValidation'
    $requestJson = Read-Frame -Stream $pipe -MaximumBytes $maximumBytes -Token $tokenSource.Token
    $requestDocument = [System.Text.Json.JsonDocument]::Parse($requestJson)
    try {
        $root = $requestDocument.RootElement
        $names = @($root.EnumerateObject() | ForEach-Object Name)
        if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            $names.Count -ne 5 -or @($names | Sort-Object -Unique).Count -ne 5 -or
            $root.GetProperty('kind').GetString() -ne 'ExecutePlan' -or
            $root.GetProperty('contractVersion').GetString() -ne '1.0.0' -or
            $root.GetProperty('nonce').GetString() -ne $configuration.nonce -or
            $root.GetProperty('planDigest').GetString() -ne $configuration.planDigest) {
            throw 'The privilege request envelope is invalid.'
        }
        $allowed = @(
            'observe-firmware-tpm', 'observe-local-administrators',
            'observe-effective-policy', 'observe-certificate-trust'
        )
        $operations = @($root.GetProperty('operations').EnumerateArray())
        if ($operations.Count -ne 4) { throw 'The privileged operation set is incomplete.' }
        for ($index = 0; $index -lt $operations.Count; $index++) {
            $operation = $operations[$index]
            $operationNames = @($operation.EnumerateObject() | ForEach-Object Name)
            if ($operationNames.Count -ne 2 -or
                @($operationNames | Sort-Object -Unique).Count -ne 2 -or
                $operation.GetProperty('operationId').GetString() -ne $allowed[$index] -or
                $operation.GetProperty('parameters').ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                @($operation.GetProperty('parameters').EnumerateObject()).Count -ne 0) {
                throw 'A privileged operation or typed parameter is not release-defined.'
            }
        }
    }
    finally { $requestDocument.Dispose() }

    $workerStage = 'OperationExecution'
    if ($configuration.workerFault -eq 'HangAfterPlan') {
        # This fixed validation fault creates one fixed child and then becomes
        # deliberately uncooperative. No child path or command crosses the
        # channel: both are release source, and the child reuses the already
        # verified PowerShell image. The child automatically inherits Job
        # membership, so a passing absence check proves tree-wide termination
        # instead of merely proving that this root process disappeared.
        $childStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $childStartInfo.FileName = $workerImage
        $childStartInfo.UseShellExecute = $false
        $childStartInfo.CreateNoWindow = $true
        $childStartInfo.WorkingDirectory = [System.IO.Path]::GetDirectoryName($workerImage)
        foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
            [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(
                '[System.Threading.Thread]::Sleep(10000)'
            ))
        )) { $null = $childStartInfo.ArgumentList.Add($argument) }
        $childStartInfo.Environment.Clear()
        $childStartInfo.Environment['SystemRoot'] = [System.Environment]::GetFolderPath('Windows')
        $null = [System.Diagnostics.Process]::Start($childStartInfo)
        [System.Threading.Thread]::Sleep(10000)
    }
    $phaseId = 'phase:privileged:primary'
    $resultBody = [ordered]@{
        kind = 'PlanResult'
        contractVersion = '1.0.0'
        nonce = [string] $configuration.nonce
        planDigest = [string] $configuration.planDigest
        phaseId = $phaseId
        operations = @(
            'observe-firmware-tpm', 'observe-local-administrators',
            'observe-effective-policy', 'observe-certificate-trust'
        ) | ForEach-Object { [ordered]@{ operationId = $_; state = 'Completed'; phaseId = $phaseId } }
    }
    if ([string]$configuration.firmwareScenario -ne 'None') {
        $resultBody.firmwareTpm = if ([string]$configuration.firmwareScenario -eq 'Live') {
            Get-LiveFirmwareResult
        } else { New-SyntheticFirmwareResult -Scenario ([string]$configuration.firmwareScenario) }
    }
    $result = $resultBody | ConvertTo-Json -Compress -Depth 5
    Write-Frame -Stream $pipe -Json $result -MaximumBytes $maximumBytes -Token $tokenSource.Token
}
catch {
    # Never return exception text: it can contain a user, path, policy value, or
    # other restricted diagnostic. A fixed stage is enough for the coordinator
    # to fail safely while keeping the public result privacy-sanitized.
    if ($null -ne $pipe -and $pipe.IsConnected) {
        try {
            $failure = [ordered]@{
                kind = 'WorkerFailure'
                contractVersion = '1.0.0'
                stage = $workerStage
            } | ConvertTo-Json -Compress
            Write-Frame -Stream $pipe -Json $failure -MaximumBytes $maximumBytes `
                -Token ([System.Threading.CancellationToken]::None)
        }
        catch {}
    }
    exit 1
}
finally {
    if ($null -ne $pipe) { $pipe.Dispose() }
    $tokenSource.Dispose()
}
'@
}

function Initialize-PrivilegedCollectionPlanNativeType {
    if ('WinPCInfo.PrivilegedCollectionPlan.PipePeer' -as [type]) { return }

    # Named-pipe ACLs decide who may open the channel, but they do not tell the
    # application which permitted administrator actually connected. Windows
    # exposes the client PID attached to this exact pipe handle. Comparing that
    # kernel value with the one process we launched closes a race in which a
    # different local administrator connects first. A failed query is a safe
    # integrity failure, never a reason to trust a self-reported PID.
    Add-Type -TypeDefinition @'
using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace WinPCInfo.PrivilegedCollectionPlan
{
    public static class PipePeer
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
        public static int GetClientProcessId(PipeStream pipe)
        {
            uint processId;
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out processId))
                throw new InvalidOperationException("Unable to bind the worker process.");
            return checked((int)processId);
        }
    }

    public sealed class OwnedJob : IDisposable
    {
        private const uint JOB_OBJECT_TERMINATE = 0x0008;
        private const uint JOB_OBJECT_QUERY = 0x0004;
        private const uint JOB_OBJECT_ASSIGN_PROCESS = 0x0001;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectBasicProcessIdList = 3;
        private const int JobObjectExtendedLimitInformation = 9;
        private const int ERROR_ALREADY_EXISTS = 183;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public uint nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass, SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
            public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string descriptor, uint revision, out IntPtr securityDescriptor, out uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(ref SECURITY_ATTRIBUTES attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int informationClass,
            ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int informationClass,
            IntPtr information, uint length, out uint returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        private IntPtr handle;
        private OwnedJob(IntPtr value) { handle = value; }

        public static OwnedJob Create(string name, string securityDescriptor)
        {
            IntPtr descriptor;
            uint descriptorSize;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                securityDescriptor, 1, out descriptor, out descriptorSize))
                throw new InvalidOperationException("Unable to protect the worker job.");
            try
            {
                SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
                attributes.nLength = (uint)Marshal.SizeOf<SECURITY_ATTRIBUTES>();
                attributes.lpSecurityDescriptor = descriptor;
                attributes.bInheritHandle = false;
                IntPtr job = CreateJobObject(ref attributes, name);
                if (job == IntPtr.Zero || Marshal.GetLastWin32Error() == ERROR_ALREADY_EXISTS)
                {
                    if (job != IntPtr.Zero) CloseHandle(job);
                    throw new InvalidOperationException("Unable to create a unique worker job.");
                }
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION information =
                    new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                    ref information,
                    (uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()))
                {
                    CloseHandle(job);
                    throw new InvalidOperationException("Unable to configure worker-tree ownership.");
                }
                return new OwnedJob(job);
            }
            finally { LocalFree(descriptor); }
        }

        public bool Terminate()
        {
            return handle != IntPtr.Zero && TerminateJobObject(handle, 1);
        }

        public bool IsEmpty()
        {
            if (handle == IntPtr.Zero) return false;
            // 64 KiB can enumerate more processes than this deliberately tiny
            // worker could reasonably own. Overflow or query failure is
            // treated as non-empty, never as proof of cleanup.
            IntPtr buffer = Marshal.AllocHGlobal(65536);
            try
            {
                uint returned;
                return QueryInformationJobObject(handle, JobObjectBasicProcessIdList,
                    buffer, 65536, out returned) && Marshal.ReadInt32(buffer, 4) == 0;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; }
        }
    }
}
'@
}

function ConvertTo-PrivilegedCollectionEncodedCommand {
    param([Parameter(Mandatory)] [string] $Source)

    $sourceBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Source)
    $compressedStream = [System.IO.MemoryStream]::new()
    try {
        $compressor = [System.IO.Compression.GZipStream]::new(
            $compressedStream, [System.IO.Compression.CompressionMode]::Compress, $true
        )
        try { $compressor.Write($sourceBytes, 0, $sourceBytes.Length) }
        finally { $compressor.Dispose() }
        $compressedBase64 = [System.Convert]::ToBase64String($compressedStream.ToArray())
    }
    finally { $compressedStream.Dispose() }
    if ($compressedBase64.Length -gt 16384) {
        throw 'The reviewed privilege worker exceeds its compressed launch bound.'
    }

    # EncodedCommand itself expands UTF-16 source by 4/3. Compressing the fixed
    # worker before that encoding keeps the complete Windows command line below
    # its 32,767-character limit without creating a script file. The bootstrap
    # has no parser or caller input: it only inflates the exact in-memory bytes
    # constructed from the digest-verified template and runs them in this worker.
    $bootstrap = @"
`$b=[Convert]::FromBase64String('$compressedBase64');`$m=[IO.MemoryStream]::new([byte[]]`$b);`$g=[IO.Compression.GZipStream]::new(`$m,[IO.Compression.CompressionMode]::Decompress);`$r=[IO.StreamReader]::new(`$g,[Text.UTF8Encoding]::new(`$false,`$true));try{&([scriptblock]::Create(`$r.ReadToEnd()))}finally{`$r.Dispose();`$g.Dispose();`$m.Dispose()}
"@.Trim()
    $encoded = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($bootstrap)
    )
    if ($encoded.Length -gt 30000) {
        throw 'The reviewed privilege bootstrap exceeds the Windows launch bound.'
    }
    $encoded
}

function Wait-PrivilegedCollectionOwnedTreeAbsent {
    param(
        [Parameter()] $OwnedJob,
        [Parameter()] [AllowNull()] [System.Diagnostics.Process] $WorkerRoot,
        [Parameter(Mandatory)] [ValidateRange(0, 10000)] [int] $MaximumMilliseconds
    )

    # A worker must open and join the named Job after process launch. An
    # immediate cancellation can reach cleanup while that startup is still in
    # flight, so an empty Job alone is not yet proof: the launched root may not
    # have joined it. Require both the kernel Job list and the original Process
    # handle to report absence inside one shared finite window.
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        $jobEmpty = $null -eq $OwnedJob -or $OwnedJob.IsEmpty()
        $rootExited = if ($null -eq $WorkerRoot) {
            $true
        }
        else {
            try { $WorkerRoot.HasExited }
            catch { $false }
        }
        if ($jobEmpty -and $rootExited) { return $true }
        if ($watch.ElapsedMilliseconds -ge $MaximumMilliseconds) { break }
        [System.Threading.Thread]::Sleep(10)
    }
    while ($true)
    $false
}

function Read-BoundedCollectionChannelExactBytes {
    param(
        [Parameter(Mandatory)] $Stream,
        [Parameter(Mandatory)] [int] $Count,
        [Parameter(Mandatory)] [System.Threading.CancellationToken] $CancellationToken
    )

    $bytes = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.ReadAsync(
            $bytes, $offset, $Count - $offset, $CancellationToken
        ).GetAwaiter().GetResult()
        if ($read -eq 0) { throw 'The collection channel closed before a complete frame.' }
        $offset += $read
    }
    $bytes
}

function Read-BoundedCollectionChannelFrame {
    param(
        [Parameter(Mandatory)] $Stream,
        [Parameter(Mandatory)] [int] $MaximumBytes,
        [Parameter(Mandatory)] [System.Threading.CancellationToken] $CancellationToken
    )

    $lengthBytes = Read-BoundedCollectionChannelExactBytes -Stream $Stream -Count 4 `
        -CancellationToken $CancellationToken
    # Every supported Windows architecture is little-endian; BitConverter keeps
    # the fixed 32-bit prefix explicit without asking PowerShell to bind a
    # byref-like Span<T>, which it intentionally cannot marshal.
    $length = [System.BitConverter]::ToInt32($lengthBytes, 0)
    if ($length -le 0 -or $length -gt $MaximumBytes) {
        throw 'The collection frame exceeds its release byte bound.'
    }
    $payload = Read-BoundedCollectionChannelExactBytes -Stream $Stream -Count $length `
        -CancellationToken $CancellationToken
    [System.Text.UTF8Encoding]::new($false, $true).GetString($payload)
}

function Write-BoundedCollectionChannelFrame {
    param(
        [Parameter(Mandatory)] $Stream,
        [Parameter(Mandatory)] [string] $Json,
        [Parameter(Mandatory)] [int] $MaximumBytes,
        [Parameter(Mandatory)] [System.Threading.CancellationToken] $CancellationToken
    )

    $payload = [System.Text.UTF8Encoding]::new($false).GetBytes($Json)
    if ($payload.Length -le 0 -or $payload.Length -gt $MaximumBytes) {
        throw 'The collection frame exceeds its release byte bound.'
    }
    $lengthBytes = [System.BitConverter]::GetBytes([int] $payload.Length)
    $null = $Stream.WriteAsync(
        $lengthBytes, 0, 4, $CancellationToken
    ).GetAwaiter().GetResult()
    $null = $Stream.WriteAsync(
        $payload, 0, $payload.Length, $CancellationToken
    ).GetAwaiter().GetResult()
    $null = $Stream.FlushAsync($CancellationToken).GetAwaiter().GetResult()
}

function Test-PrivilegedCollectionPlan {
    param(
        [Parameter(Mandatory)] $PreparationPlan,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] $Policy
    )

    $convertToJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $convertToJsonCommand -or
        $convertToJsonCommand.ModuleName -ne 'Microsoft.PowerShell.Utility') {
        return $false
    }
    if ((Get-ObjectDigest -Value $PreparationPlan -ConvertToJsonCommand $convertToJsonCommand) -ne
        $PlanDigest -or $PreparationPlan.recordType -ne 'win-pcinfo.preparation-plan' -or
        $PreparationPlan.contractVersion -ne '1.0.0' -or
        $PreparationPlan.release -ne '2.0.0-preview.1' -or
        -not [bool] $PreparationPlan.privilege.privilegedOperationsFrozen -or
        [int] $PreparationPlan.privilege.maximumUacInteractions -ne 1) {
        return $false
    }
    $operations = @($PreparationPlan.privilege.privilegedOperations | Where-Object context -eq 'Administrator')
    if ($operations.Count -ne @($Policy.operations).Count) { return $false }
    for ($index = 0; $index -lt $operations.Count; $index++) {
        $operation = $operations[$index]
        $parameterProperties = @(if ($operation.PSObject.Properties['parameters']) {
            $operation.parameters.PSObject.Properties
        })
        if ($operation.operationId -ne $Policy.operations[$index].operationId -or
            $operation.context -ne 'Administrator' -or
            $parameterProperties.Count -ne 0) {
            return $false
        }
    }
    $true
}

function New-PrivilegedCollectionResult {
    param(
        [Parameter(Mandatory)] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] [string] $AssessmentUserContext,
        [Parameter(Mandatory)] [string] $LocalPackageProtector,
        [Parameter(Mandatory)] [int] $UacInteractionCount,
        [Parameter(Mandatory)] [bool] $AlreadyElevated,
        [Parameter(Mandatory)] [string] $WorkerPrincipalRelationship,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Operations,
        [Parameter(Mandatory)] [bool] $ChannelVerified,
        [Parameter(Mandatory)] [bool] $CleanupVerified,
        [Parameter(Mandatory)] [string] $ValidationScenario,
        [Parameter()] $PrivateFirmwareCollectorResult
    )

    $coverageState = switch ($State) {
        'Completed' { 'Complete' }
        'Unavailable' { 'Unavailable' }
        'TimedOut' { 'TimedOut' }
        'Cancelled' { 'Cancelled' }
        default { 'Failed' }
    }
    $liveValidation = $ValidationScenario -eq 'Live'
    $result = [ordered]@{
        recordType = 'win-pcinfo.privileged-collection-phase'
        contractVersion = '1.0.0'
        state = $State
        reasonCode = $ReasonCode
        planDigest = $PlanDigest
        operations = @($Operations)
        coverage = @([pscustomobject][ordered]@{
            scopeId = 'scope:synthetic.privileged-collection-plan'
            state = $coverageState
            reasonCode = $ReasonCode
        })
        elevation = [pscustomobject][ordered]@{
            uacInteractionCount = $UacInteractionCount
            alreadyElevated = $AlreadyElevated
            retryAllowed = $false
        }
        identity = [pscustomobject][ordered]@{
            assessmentUserContext = $AssessmentUserContext
            localPackageProtector = $LocalPackageProtector
            workerPrincipalRelationship = $WorkerPrincipalRelationship
        }
        channel = [pscustomobject][ordered]@{
            oneInstance = $true
            lengthBounded = $true
            aclProtected = $true
            nonceVerified = $ChannelVerified
            schemaValidated = $ChannelVerified
            peerProcessVerified = $ChannelVerified
            peerArtifactVerified = $ChannelVerified
            assessmentEvidenceCrossed = $null -ne $PrivateFirmwareCollectorResult
        }
        standardUserWorkMayContinue = $State -in @('Completed', 'Unavailable')
        cleanup = [pscustomobject][ordered]@{
            workerTreeAbsent = $CleanupVerified
            channelAbsent = $CleanupVerified
            stagingAbsent = $true
            verified = $CleanupVerified
        }
        validation = [pscustomobject][ordered]@{
            mode = if ($liveValidation) { 'Live' } else { 'SyntheticUnelevated' }
            livePathExercised = $liveValidation
            environmentalLimitation = if ($liveValidation) {
                $null
            }
            else {
                [pscustomobject][ordered]@{
                    state = 'NotStarted'
                    reasonCode = 'PRIVILEGE.LIVE_ELEVATION_VALIDATION_UNAVAILABLE'
                    remediation = 'Repeat this scenario on an approved disposable or controlled Windows client.'
                }
            }
        }
    }
    if ($null -ne $PrivateFirmwareCollectorResult) {
        # This property is an in-memory Restricted Diagnostic Evidence handoff
        # to the assessment orchestrator. Callers that emit the public privilege
        # record must re-project the closed public properties and omit it.
        $result.PrivateFirmwareCollectorResult = $PrivateFirmwareCollectorResult
    }
    [pscustomobject]$result
}

function New-PrivilegedCollectionStoppedResult {
    param(
        [Parameter(Mandatory)] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter()] [bool] $AlreadyElevated = $false,
        [Parameter()] [int] $UacInteractionCount = 0,
        [Parameter()] [string] $WorkerPrincipalRelationship = 'NotStarted'
    )

    New-PrivilegedCollectionResult -State $State -ReasonCode $ReasonCode `
        -PlanDigest $Context.PlanDigest `
        -AssessmentUserContext $Context.AssessmentUserContext `
        -LocalPackageProtector $Context.LocalPackageProtector `
        -UacInteractionCount $UacInteractionCount -AlreadyElevated $AlreadyElevated `
        -WorkerPrincipalRelationship $WorkerPrincipalRelationship -Operations @() `
        -ChannelVerified $false -CleanupVerified $true `
        -ValidationScenario $Context.ValidationScenario
}

function Test-PrivilegedCollectionOperationResult {
    param(
        [Parameter(Mandatory)] $Operation,
        [Parameter(Mandatory)] [string] $ExpectedOperationId,
        [Parameter(Mandatory)] [string] $ExpectedPhaseId
    )

    $names = @($Operation.PSObject.Properties.Name)
    $names.Count -eq 3 -and @($names | Sort-Object -Unique).Count -eq 3 -and
        @($names | Where-Object {
            $_ -notin @('operationId', 'state', 'phaseId')
        }).Count -eq 0 -and
        $Operation.operationId -eq $ExpectedOperationId -and
        $Operation.state -eq 'Completed' -and
        $Operation.phaseId -eq $ExpectedPhaseId
}

function Invoke-PrivilegedCollectionPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $PreparationPlan,
        [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{64}$')] [string] $PlanDigest,
        [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z][A-Za-z0-9._:/-]{0,127}$')]
        [string] $AssessmentUserContext,
        [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z][A-Za-z0-9._:/-]{0,127}$')]
        [string] $LocalPackageProtector,
        [Parameter()]
        [ValidateSet(
            'Live',
            'AcceptedElevation', 'AlreadyElevated', 'AlternateAdministrator', 'ElevationDenied',
            'WrongPipeClient', 'AlteredPlan', 'LostWorker', 'Timeout', 'Cancellation'
        )]
        [string] $ValidationScenario = 'Live',
        [Parameter()]
        [ValidateSet(
            'None','Live','Supported','Disabled','Absent','Virtual','NonUefi',
            'AccessDenied','Unsupported','Malformed','Timeout','CollectorFailure'
        )]
        [string] $FirmwareScenario = 'None',
        [Parameter()] [System.Threading.CancellationToken] $CancellationToken =
            [System.Threading.CancellationToken]::None
    )

    $policy = Get-PrivilegedCollectionPlanPolicy
    $scenario = Get-PrivilegedCollectionValidationScenario -Name $ValidationScenario
    if (($ValidationScenario -eq 'Live' -and
            $FirmwareScenario -notin @('None','Live')) -or
        ($ValidationScenario -ne 'Live' -and $FirmwareScenario -eq 'Live')) {
        throw 'Live and synthetic firmware collection boundaries cannot be mixed.'
    }
    $resultContext = @{
        PlanDigest = $PlanDigest
        AssessmentUserContext = $AssessmentUserContext
        LocalPackageProtector = $LocalPackageProtector
        ValidationScenario = $ValidationScenario
    }
    if ($scenario.failureReasonCode -eq 'PRIVILEGE.PLAN_INTEGRITY_INVALID' -or
        -not (Test-PrivilegedCollectionPlan -PreparationPlan $PreparationPlan `
            -PlanDigest $PlanDigest -Policy $policy)) {
        return New-PrivilegedCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode 'PRIVILEGE.PLAN_INTEGRITY_INVALID' -Context $resultContext
    }

    $validationFixture = $scenario.isFixture
    $alreadyElevated = if ($validationFixture) {
        [bool] $scenario.alreadyElevated
    }
    else {
        $principal = [System.Security.Principal.WindowsPrincipal]::new(
            [System.Security.Principal.WindowsIdentity]::GetCurrent()
        )
        $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    $uacInteractionCount = if ($alreadyElevated) { 0 } else { 1 }
    $workerRelationship = if ($validationFixture) {
        [string] $scenario.workerPrincipalRelationship
    }
    elseif ($alreadyElevated) { 'AssessmentOperator' }
    else { 'SelectedAdministrator' }
    if ($scenario.elevationDenied) {
        return New-PrivilegedCollectionStoppedResult -State 'Unavailable' `
            -ReasonCode 'PRIVILEGE.ELEVATION_DENIED' -Context $resultContext `
            -UacInteractionCount $uacInteractionCount `
            -WorkerPrincipalRelationship 'NotStarted'
    }

    Initialize-PrivilegedCollectionPlanNativeType
    $workerSource = (Get-PrivilegedCollectionWorkerSource).Replace("`r`n", "`n").Replace("`r", "`n")
    $workerBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($workerSource)
    $workerDigest = Get-PrivilegedCollectionPlanSha256 -Bytes $workerBytes
    if ($workerDigest -ne [string] $policy.worker.payloadSha256) {
        return New-PrivilegedCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode 'PRIVILEGE.WORKER_IDENTITY_INVALID' -Context $resultContext `
            -AlreadyElevated $alreadyElevated
    }

    $approvedExecutable = [System.IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
    $activeExecutable = [System.IO.Path]::GetFullPath(
        [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    )
    if (-not $approvedExecutable.Equals(
        $activeExecutable, [System.StringComparison]::OrdinalIgnoreCase
    )) {
        return New-PrivilegedCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode 'PRIVILEGE.EXECUTABLE_IDENTITY_INVALID' -Context $resultContext `
            -AlreadyElevated $alreadyElevated
    }
    $authenticodeCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'Get-AuthenticodeSignature', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $authenticodeCommand -or
        $authenticodeCommand.ModuleName -ne 'Microsoft.PowerShell.Security') {
        return New-PrivilegedCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode 'PRIVILEGE.EXECUTABLE_IDENTITY_INVALID' -Context $resultContext `
            -AlreadyElevated $alreadyElevated
    }
    $signature = & $authenticodeCommand -LiteralPath $approvedExecutable -ErrorAction Stop
    if ([string] $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false
        ) -ne [string] $policy.worker.signerCommonName) {
        return New-PrivilegedCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode 'PRIVILEGE.EXECUTABLE_IDENTITY_INVALID' -Context $resultContext `
            -AlreadyElevated $alreadyElevated
    }
    $executableDigest = Get-PrivilegedCollectionPlanSha256 -Bytes ([System.IO.File]::ReadAllBytes($approvedExecutable))

    # The pipe name contains a cryptographically random nonce so it cannot be
    # reused across runs. The nonce is an anti-confusion token, not a password:
    # access still comes from the Windows ACL. The ACL grants the initiating
    # identity and the local Administrators group so a deliberately selected
    # alternate administrator can connect after UAC. Everyone else is absent
    # from the DACL. If Windows cannot apply this descriptor, no worker starts.
    $nonceBytes = [byte[]]::new([int] $policy.channel.nonceBytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
    $nonce = [System.Convert]::ToHexString($nonceBytes).ToLowerInvariant()
    $pipeName = "$($policy.channel.pipeNamePrefix)$($nonce.Substring(0, 32))"
    $jobName = "$($policy.channel.jobNamePrefix)$($nonce.Substring(0, 32))"
    $initiatingSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $pipeSecurity = [System.IO.Pipes.PipeSecurity]::new()
    $pipeSecurity.SetSecurityDescriptorSddlForm("D:P(A;;GA;;;$initiatingSid)(A;;GA;;;BA)")
    # The coordinator creates the Job Object at its own integrity level and
    # keeps that handle for the whole phase. Its explicit DACL lets either the
    # initiating identity or the selected local administrator join the worker,
    # but the random one-use name prevents cross-run reuse. Crucially, UAC does
    # not take termination authority away from the handle already held here.
    $ownedJob = $null
    $server = $null
    $worker = $null
    $unexpectedClient = $null
    $deadline = [System.Threading.CancellationTokenSource]::CreateLinkedTokenSource($CancellationToken)
    $deadline.CancelAfter([int] $policy.deadlines.operationMaximumMilliseconds)
    $channelVerified = $false
    $operations = @()
    $cleanupVerified = $false
    $state = 'IntegrityFailed'
    $reasonCode = 'PRIVILEGE.CHANNEL_FAILED'
    $failureStage = 'CREATE_CHANNEL'
    $firmwareOperationStartedAt = [DateTimeOffset]::UtcNow
    $privateFirmwareCollectorResult = $null
    try {
        $ownedJob = [WinPCInfo.PrivilegedCollectionPlan.OwnedJob]::Create(
            $jobName, "D:P(A;;GA;;;$initiatingSid)(A;;GA;;;BA)"
        )
        $server = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create(
            $pipeName, [System.IO.Pipes.PipeDirection]::InOut,
            [int] $policy.channel.maximumServerInstances,
            [System.IO.Pipes.PipeTransmissionMode]::Byte,
            [System.IO.Pipes.PipeOptions]::Asynchronous,
            [int] $policy.channel.maximumMessageUtf8Bytes,
            [int] $policy.channel.maximumMessageUtf8Bytes,
            $pipeSecurity, [System.IO.HandleInheritability]::None,
            [System.IO.Pipes.PipeAccessRights] 0
        )
        # Only protocol mechanics cross the launch command line: a random pipe
        # name/nonce, fixed byte/deadline bounds, peer/digest expectations, and
        # the approved plan digest. No Windows identity, credential, secret,
        # operation parameter value, or assessment evidence is present.
        $workerConfiguration = [pscustomobject][ordered]@{
            pipe = $pipeName
            nonce = $nonce
            maximumBytes = [int] $policy.channel.maximumMessageUtf8Bytes
            deadlineMilliseconds = [int] $policy.deadlines.operationMaximumMilliseconds
            coordinatorProcessId = $PID
            executableSha256 = $executableDigest
            workerPayloadSha256 = $workerDigest
            planDigest = $PlanDigest
            workerFault = [string] $scenario.workerFault
            firmwareScenario = $FirmwareScenario
            jobName = $jobName
        }
        $encodedConfiguration = [System.Convert]::ToBase64String(
            [System.Text.UTF8Encoding]::new($false).GetBytes(
                ($workerConfiguration | ConvertTo-Json -Compress -Depth 5)
            )
        )
        # The policy digest binds the reviewed template. Replacing its one fixed
        # configuration marker happens only in memory after the configuration's
        # closed shape is constructed. The resulting source goes straight to
        # EncodedCommand, so neither a path nor a writable script can be swapped
        # between identity validation and process creation.
        if ($workerSource.IndexOf('__PRIVILEGED_WORKER_CONFIGURATION__') -ne
            $workerSource.LastIndexOf('__PRIVILEGED_WORKER_CONFIGURATION__')) {
            throw 'The privilege worker template contains an ambiguous configuration marker.'
        }
        $launchWorkerSource = $workerSource.Replace(
            '__PRIVILEGED_WORKER_CONFIGURATION__', $encodedConfiguration
        )
        $encodedWorker = ConvertTo-PrivilegedCollectionEncodedCommand -Source $launchWorkerSource
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $approvedExecutable
        # ShellExecute's runas verb is the Windows UAC boundary. It is selected
        # once only for a real standard-user launch. An already-elevated token
        # takes the direct path, and every synthetic fixture also stays direct
        # so automated validation never displays or approves a real UAC dialog.
        $startInfo.UseShellExecute = -not $validationFixture -and -not $alreadyElevated
        if ($startInfo.UseShellExecute) { $startInfo.Verb = 'runas' }
        else {
            $startInfo.CreateNoWindow = $true
            $startInfo.RedirectStandardError = $true
        }
        $startInfo.WorkingDirectory = $PSHOME
        foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedWorker
        )) {
            $null = $startInfo.ArgumentList.Add($argument)
        }
        if (-not $startInfo.UseShellExecute) {
            $startInfo.Environment.Clear()
            $startInfo.Environment['SystemRoot'] = [System.Environment]::GetFolderPath('Windows')
        }
        $failureStage = 'LAUNCH_WORKER'
        try { $worker = [System.Diagnostics.Process]::Start($startInfo) }
        catch [System.ComponentModel.Win32Exception] {
            if ($_.Exception.NativeErrorCode -eq 1223) {
                $failureStage = 'ELEVATION_DENIED'
            }
            throw
        }

        if ($scenario.launchUnexpectedClient) {
            # The hostile fixture is also fixed source. It can only connect and
            # wait; it receives no plan, identity, or evidence. Starting it
            # while the approved worker deliberately delays proves that the
            # server uses the PID Windows attached to the pipe handle, not a PID
            # claimed in JSON or an assumption about connection order.
            $unexpectedSource = @'
$pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
    '.', $env:WINPCINFO_PRIVILEGE_PIPE,
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::Asynchronous
)
try {
    $pipe.Connect(2000)
    [System.Threading.Thread]::Sleep(10000)
}
finally { $pipe.Dispose() }
'@
            $unexpectedStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
            $unexpectedStartInfo.FileName = $approvedExecutable
            $unexpectedStartInfo.UseShellExecute = $false
            $unexpectedStartInfo.CreateNoWindow = $true
            $unexpectedStartInfo.WorkingDirectory = $PSHOME
            foreach ($argument in @(
                '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                [System.Convert]::ToBase64String(
                    [System.Text.Encoding]::Unicode.GetBytes($unexpectedSource)
                )
            )) { $null = $unexpectedStartInfo.ArgumentList.Add($argument) }
            $unexpectedStartInfo.Environment.Clear()
            $unexpectedStartInfo.Environment['SystemRoot'] = [System.Environment]::GetFolderPath('Windows')
            $unexpectedStartInfo.Environment['WINPCINFO_PRIVILEGE_PIPE'] = $pipeName
            $unexpectedClient = [System.Diagnostics.Process]::Start($unexpectedStartInfo)
        }

        $failureStage = 'CONNECT_WORKER'
        $null = $server.WaitForConnectionAsync($deadline.Token).GetAwaiter().GetResult()
        $failureStage = 'QUERY_WORKER_PID'
        $clientProcessId = [WinPCInfo.PrivilegedCollectionPlan.PipePeer]::GetClientProcessId($server)
        if ($clientProcessId -ne $worker.Id) {
            $failureStage = 'PEER_IDENTITY'
            throw 'The connected pipe client is not the owned worker.'
        }
        $clientImage = [System.IO.Path]::GetFullPath(
            [System.Diagnostics.Process]::GetProcessById($clientProcessId).MainModule.FileName
        )
        if (-not $clientImage.Equals(
            $approvedExecutable, [System.StringComparison]::OrdinalIgnoreCase
        ) -or (Get-PrivilegedCollectionPlanSha256 -Bytes ([System.IO.File]::ReadAllBytes($clientImage))) -ne
            $executableDigest) {
            $failureStage = 'PEER_IDENTITY'
            throw 'The connected worker image is not the release-defined executable.'
        }
        $failureStage = 'READ_WORKER_HELLO'
        $helloJson = Read-BoundedCollectionChannelFrame -Stream $server `
            -MaximumBytes ([int] $policy.channel.maximumMessageUtf8Bytes) `
            -CancellationToken $deadline.Token
        $hello = $helloJson | ConvertFrom-Json -Depth 10
        if ($hello.kind -eq 'WorkerFailure' -and
            $hello.stage -in @('Connect', 'PeerIdentity', 'Hello', 'PlanValidation', 'OperationExecution')) {
            $failureStage = "WORKER_$([string] $hello.stage)".ToUpperInvariant()
            throw 'The privilege worker failed before its hello completed.'
        }
        $failureStage = 'VALIDATE_WORKER_HELLO'
        $helloNames = @($hello.PSObject.Properties.Name)
        if ($clientProcessId -ne $worker.Id -or $helloNames.Count -ne 8 -or
            @($helloNames | Sort-Object -Unique).Count -ne 8 -or
            $hello.kind -ne 'WorkerHello' -or $hello.contractVersion -ne '1.0.0' -or
            $hello.nonce -ne $nonce -or [int] $hello.workerProcessId -ne $clientProcessId -or
            [int] $hello.coordinatorProcessId -ne $PID -or
            $hello.workerPayloadSha256 -ne $workerDigest -or
            $hello.executableSha256 -ne $executableDigest -or
            $hello.treeControl -ne 'WorkerOwnedJobObject') {
            throw 'The privilege worker did not prove peer and artifact identity.'
        }

        $request = [pscustomobject][ordered]@{
            kind = 'ExecutePlan'
            contractVersion = '1.0.0'
            nonce = $nonce
            planDigest = $PlanDigest
            operations = @($PreparationPlan.privilege.privilegedOperations |
                Where-Object context -eq 'Administrator' | ForEach-Object {
                    [pscustomobject][ordered]@{
                        operationId = [string] $_.operationId
                        parameters = [pscustomobject]@{}
                    }
                })
        }
        $requestJson = $request | ConvertTo-Json -Compress -Depth 10
        $failureStage = 'SEND_PLAN'
        Write-BoundedCollectionChannelFrame -Stream $server -Json $requestJson `
            -MaximumBytes ([int] $policy.channel.maximumMessageUtf8Bytes) `
            -CancellationToken $deadline.Token
        $failureStage = 'READ_RESULT'
        $resultJson = Read-BoundedCollectionChannelFrame -Stream $server `
            -MaximumBytes ([int] $policy.channel.maximumMessageUtf8Bytes) `
            -CancellationToken $deadline.Token
        $workerResult = $resultJson | ConvertFrom-Json -Depth 10
        $resultNames = @($workerResult.PSObject.Properties.Name)
        $expectedResultNames = if ($FirmwareScenario -eq 'None') {
            @('kind','contractVersion','nonce','planDigest','phaseId','operations')
        } else {
            @('kind','contractVersion','nonce','planDigest','phaseId','operations','firmwareTpm')
        }
        if ($resultNames.Count -ne $expectedResultNames.Count -or
            (@($resultNames | Sort-Object) -join '|') -ne
                (@($expectedResultNames | Sort-Object) -join '|') -or
            $workerResult.kind -ne 'PlanResult' -or
            $workerResult.contractVersion -ne '1.0.0' -or
            $workerResult.nonce -ne $nonce -or $workerResult.planDigest -ne $PlanDigest -or
            [string]::IsNullOrWhiteSpace([string] $workerResult.phaseId) -or
            @($workerResult.operations).Count -ne 4) {
            throw 'The privilege worker result failed its closed schema.'
        }
        for ($index = 0; $index -lt 4; $index++) {
            $operation = $workerResult.operations[$index]
            if (-not (Test-PrivilegedCollectionOperationResult -Operation $operation `
                -ExpectedOperationId $policy.operations[$index].operationId `
                -ExpectedPhaseId $workerResult.phaseId)) {
                throw 'The privilege worker returned an invalid operation result.'
            }
        }
        # Re-project the closed shape instead of returning deserialized worker
        # objects. Even a future parser mistake therefore cannot carry an
        # undeclared credential, command, or evidence property to the caller.
        $operations = @($workerResult.operations | ForEach-Object {
            [pscustomobject][ordered]@{
                operationId = [string] $_.operationId
                state = [string] $_.state
                phaseId = [string] $_.phaseId
            }
        })
        if ($FirmwareScenario -ne 'None') {
            # The pipe has a wider framing ceiling because it also carries the
            # four operation results. Enforce the narrower firmware contract
            # independently so a valid frame cannot silently widen evidence.
            $firmwareResultUtf8Bytes = [System.Text.Encoding]::UTF8.GetByteCount(
                ($workerResult.firmwareTpm | ConvertTo-Json -Compress -Depth 5)
            )
            if ($firmwareResultUtf8Bytes -gt 8192 -or
                -not (Test-FirmwareReadinessCollectorPayload -Payload $workerResult.firmwareTpm)) {
                throw 'The privileged firmware projection failed its closed evidence contract.'
            }
            $privateFirmwareCollectorResult = [pscustomobject][ordered]@{
                state='Completed';reasonCode='FIRMWARE.COLLECTION_COMPLETED'
                validationFixture=[bool]$validationFixture
                envelope=[pscustomobject][ordered]@{
                    startedAt=$firmwareOperationStartedAt.ToString('o')
                    completedAt=[DateTimeOffset]::UtcNow.ToString('o');attempts=1
                }
                payload=[pscustomobject][ordered]@{
                    sourceLocale=[string]$workerResult.firmwareTpm.sourceLocale
                    firmwareState=[string]$workerResult.firmwareTpm.firmwareState
                    firmwareType=$workerResult.firmwareTpm.firmwareType
                    biosVersion=$workerResult.firmwareTpm.biosVersion
                    smbiosVersion=$workerResult.firmwareTpm.smbiosVersion
                    secureBootState=[string]$workerResult.firmwareTpm.secureBootState
                    secureBootEnabled=$workerResult.firmwareTpm.secureBootEnabled
                    tpmState=[string]$workerResult.firmwareTpm.tpmState
                    tpmPresent=$workerResult.firmwareTpm.tpmPresent
                    tpmEnabled=$workerResult.firmwareTpm.tpmEnabled
                    tpmActivated=$workerResult.firmwareTpm.tpmActivated
                    tpmSpecification=$workerResult.firmwareTpm.tpmSpecification
                }
            }
        }
        $channelVerified = $true
        $state = 'Completed'
        $reasonCode = 'PRIVILEGE.COMPLETED'
    }
    catch [System.OperationCanceledException] {
        $state = if ($CancellationToken.IsCancellationRequested) { 'Cancelled' } else { 'TimedOut' }
        $reasonCode = if ($state -eq 'Cancelled') {
            'PRIVILEGE.CANCELLED'
        }
        else { 'PRIVILEGE.DEADLINE_EXCEEDED' }
    }
    catch {
        $state = if ($failureStage -eq 'ELEVATION_DENIED') { 'Unavailable' }
            else { 'IntegrityFailed' }
        $reasonCode = if ($failureStage -eq 'ELEVATION_DENIED') {
            'PRIVILEGE.ELEVATION_DENIED'
        }
        elseif ($failureStage -eq 'PEER_IDENTITY') {
            'PRIVILEGE.PEER_IDENTITY_INVALID'
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string] $scenario.failureReasonCode)) {
            [string] $scenario.failureReasonCode
        }
        else { "PRIVILEGE.$failureStage`_FAILED" }
    }
    finally {
        if ($null -ne $server) { $server.Dispose() }
        # Query the coordinator-owned Job Object, not merely the root Process.
        # If any worker or descendant remains, terminate the complete kernel-
        # tracked tree and wait only for the release-owned verification bound.
        # A failed query/termination is reported as incomplete cleanup; closing
        # the kill-on-close handle is still a final safety action, but is never
        # misrepresented as verified absence.
        $cleanupVerified = Wait-PrivilegedCollectionOwnedTreeAbsent `
            -OwnedJob $ownedJob -WorkerRoot $worker `
            -MaximumMilliseconds ([int] $policy.deadlines.cancellationGraceMilliseconds)
        if (-not $cleanupVerified) {
            if ($null -ne $ownedJob) { $null = $ownedJob.Terminate() }
            # Process.Kill is only a secondary best effort for the pre-Job
            # assignment race. It may be denied across UAC integrity levels,
            # so the result depends solely on the subsequent bounded absence
            # proof, never on whether Kill returned without throwing.
            if ($null -ne $worker) {
                try {
                    if (-not $worker.HasExited) { $worker.Kill($true) }
                }
                catch {}
            }
            $cleanupVerified = Wait-PrivilegedCollectionOwnedTreeAbsent `
                -OwnedJob $ownedJob -WorkerRoot $worker `
                -MaximumMilliseconds ([int] $policy.deadlines.terminationVerificationMilliseconds)
        }
        if ($null -ne $worker) { $worker.Dispose() }
        if ($null -ne $unexpectedClient) {
            if (-not $unexpectedClient.HasExited) {
                try { $unexpectedClient.Kill($true) } catch {}
            }
            $unexpectedClientAbsent = $unexpectedClient.WaitForExit(
                [int] $policy.deadlines.terminationVerificationMilliseconds
            )
            $unexpectedClient.Dispose()
            $cleanupVerified = $cleanupVerified -and $unexpectedClientAbsent
        }
        if ($null -ne $ownedJob) { $ownedJob.Dispose() }
        $deadline.Dispose()
    }
    if (-not $cleanupVerified) {
        $state = 'IntegrityFailed'
        $reasonCode = 'PRIVILEGE.TERMINATION_INCOMPLETE'
    }
    New-PrivilegedCollectionResult -State $state -ReasonCode $reasonCode `
        -PlanDigest $PlanDigest -AssessmentUserContext $AssessmentUserContext `
        -LocalPackageProtector $LocalPackageProtector `
        -UacInteractionCount $uacInteractionCount -AlreadyElevated $alreadyElevated `
        -WorkerPrincipalRelationship $workerRelationship -Operations $operations `
        -ChannelVerified $channelVerified -CleanupVerified $cleanupVerified `
        -ValidationScenario $ValidationScenario `
        -PrivateFirmwareCollectorResult $privateFirmwareCollectorResult
}

function Read-PrivilegedCollectionPlanFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    try {
        $resolved = [System.IO.Path]::GetFullPath($LiteralPath)
        $file = [System.IO.FileInfo]::new($resolved)
        if (-not $file.Exists -or $file.Length -gt 1024) {
            throw 'The privilege fixture is unavailable or oversize.'
        }
        $json = [System.IO.File]::ReadAllText(
            $resolved, [System.Text.UTF8Encoding]::new($false, $true)
        )
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.MaxDepth = 4
        $document = [System.Text.Json.JsonDocument]::Parse($json, $options)
        try {
            $names = @($document.RootElement.EnumerateObject() | ForEach-Object Name)
            if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                $names.Count -ne 2 -or @($names | Sort-Object -Unique).Count -ne 2) {
                throw 'The privilege fixture is not lexically closed.'
            }
        }
        finally { $document.Dispose() }
        $fixture = & $ConvertFromJsonCommand -InputObject $json -ErrorAction Stop
        $properties = @($fixture.PSObject.Properties.Name | Sort-Object)
        if ($fixture.contractVersion -ne '1.0.0' -or $properties.Count -ne 2 -or
            $properties[0] -ne 'contractVersion' -or $properties[1] -ne 'scenario' -or
            $fixture.scenario -notin @((Get-PrivilegedCollectionPlanPolicy).validationScenarios)) {
            throw 'The privilege fixture is outside the release scenario set.'
        }
        $fixture
    }
    catch {
        $exception = [System.InvalidOperationException]::new(
            'The synthetic privilege fixture is invalid.'
        )
        $exception.Data['ReasonCode'] = 'PRIVILEGE.FIXTURE_INVALID'
        throw $exception
    }
}

function Invoke-PrivilegedCollectionPlanFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $PreparationPlan,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    try {
        $fixture = Read-PrivilegedCollectionPlanFixture -LiteralPath $LiteralPath `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
    }
    catch {
        Write-ContractRecord ([pscustomobject][ordered]@{
            recordType = 'win-pcinfo.terminal'
            contractVersion = '1.0.0'
            outcome = 'NotStarted'
            exitCode = 20
            reasonCode = 'PRIVILEGE.FIXTURE_INVALID'
            phase = 'PrivilegedCollection'
            collectionStarted = $false
            validationFixture = $true
            coverage = @()
            cleanup = [pscustomobject][ordered]@{ required = $false; verified = $true }
        }) -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $scenario = [string] $fixture.scenario
    $scenarioPolicy = Get-PrivilegedCollectionValidationScenario -Name $scenario
    $fixtureCancellation = if ($null -ne $scenarioPolicy.cancellationDelayMilliseconds) {
        [System.Threading.CancellationTokenSource]::new()
    }
    else { $null }
    try {
        if ($null -ne $fixtureCancellation) {
            $fixtureCancellation.CancelAfter(
                [int] $scenarioPolicy.cancellationDelayMilliseconds
            )
        }
        $privilegeResult = Invoke-PrivilegedCollectionPlan -PreparationPlan $PreparationPlan `
            -PlanDigest $PlanDigest `
            -AssessmentUserContext 'subject:synthetic-user:primary' `
            -LocalPackageProtector 'protector:synthetic-initiator' `
            -ValidationScenario $scenario `
            -CancellationToken $(if ($null -ne $fixtureCancellation) {
                $fixtureCancellation.Token
            } else { [System.Threading.CancellationToken]::None })
    }
    finally {
        if ($null -ne $fixtureCancellation) { $fixtureCancellation.Dispose() }
    }
    Write-ContractRecord $privilegeResult -ConvertToJsonCommand $ConvertToJsonCommand

    # Elevation denial is an evidence gap, not permission to end unrelated safe
    # work. The synthetic standard-user collector therefore still runs after a
    # completed or unavailable Privileged Collection Phase. Integrity failure, timeout, or
    # cancellation closes scheduling. This generated seam remains honest about
    # packaging: issue #46 has not supplied a real protector, so even useful
    # synthetic collection cannot claim Completed.
    $standardResult = if ([bool] $privilegeResult.standardUserWorkMayContinue) {
        Invoke-ApprovedCollectorProcess -OperationId 'op:synthetic.windows.os.success'
    }
    else { $null }
    $cleanupVerified = [bool] $privilegeResult.cleanup.verified -and (
        $null -eq $standardResult -or (
            [bool] $standardResult.Supervision.completeOwnedTreeAbsent -and
            [bool] $standardResult.Supervision.temporaryArtifactsAbsent
        )
    )
    $outcome = switch ([string] $privilegeResult.state) {
        'Cancelled' { 'Cancelled' }
        'TimedOut' { 'TimedOut' }
        default { 'IntegrityFailed' }
    }
    if (-not $cleanupVerified) { $outcome = 'CleanupIncomplete' }
    $reasonCode = if (-not $cleanupVerified) {
        'RUN.CLEANUP_INCOMPLETE'
    }
    elseif ($outcome -eq 'Cancelled') {
        'RUN.CANCELLED'
    }
    elseif ($outcome -eq 'TimedOut') {
        'RUN.TIMED_OUT'
    }
    elseif ($privilegeResult.state -eq 'IntegrityFailed') {
        [string] $privilegeResult.reasonCode
    }
    else { 'RUN.PACKAGE_INTEGRITY_FAILED' }

    $terminal = [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.terminal'
        contractVersion = '1.0.0'
        outcome = $outcome
        exitCode = Get-AssessmentRunExitCode -Outcome $outcome
        reasonCode = $reasonCode
        phase = 'Terminal'
        collectionStarted = ($null -ne $standardResult -or @($privilegeResult.operations).Count -gt 0)
        validationFixture = $true
        planDigest = $PlanDigest
        privilege = [pscustomobject][ordered]@{
            state = $privilegeResult.state
            reasonCode = $privilegeResult.reasonCode
            uacInteractionCount = $privilegeResult.elevation.uacInteractionCount
        }
        coverage = @($privilegeResult.coverage) + $(if ($null -ne $standardResult) {
            @($standardResult.Coverage)
        } else { @() })
        package = [pscustomobject][ordered]@{
            state = 'IntegrityFailed'
            verified = $false
            protection = 'None'
            recoverable = $false
        }
        cleanup = [pscustomobject][ordered]@{
            required = $true
            verified = $cleanupVerified
        }
        scheduling = [pscustomobject][ordered]@{
            privilegedOperationCount = @($privilegeResult.operations).Count
            standardOperationStarted = $null -ne $standardResult
            schedulingClosed = $true
        }
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $ConvertToJsonCommand
    [int] $terminal.exitCode
}
