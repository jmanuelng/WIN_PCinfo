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

    if ($script:PrivilegedCollectionPlanPolicyBase64 -eq ('__PRIVILEGED_COLLECTION_PLAN_' + 'POLICY_BASE64__')) {
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
        @($operationIds).Count -ne 3 -or
        @($operationIds | Sort-Object -Unique).Count -ne 3 -or
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

function Test-PrivilegedCollectionSid {
    param($Value)

    if($Value -isnot [string] -or [Text.Encoding]::UTF8.GetByteCount($Value) -gt 184){return $false}
    try{
        $sid=[System.Security.Principal.SecurityIdentifier]::new($Value)
        $sid.Value -ceq $Value
    }
    catch{return $false}
}

function Get-PrivilegedCollectionWorkerSource {
    # This is reviewed product source, not caller input. It is encoded directly
    # into the fixed PowerShell launch argument so there is no writable script
    # file to replace between validation and elevation. The worker understands
    # one tiny framed protocol and three empty-parameter operation identities; it
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
        $configurationNames.Count -ne 13 -or
        @($configurationNames | Sort-Object -Unique).Count -ne 13) {
        throw 'The privilege worker configuration is invalid.'
    }
}
finally { $configurationDocument.Dispose() }
$configuration = $configurationJson | ConvertFrom-Json -Depth 5

function Test-PrivilegedCollectionSid {
    param($Value)

    if($Value -isnot [string] -or [Text.Encoding]::UTF8.GetByteCount($Value) -gt 184){return $false}
    try{
        $sid=[System.Security.Principal.SecurityIdentifier]::new($Value)
        $sid.Value -ceq $Value
    }
    catch{return $false}
}

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

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;

public sealed class WinPCInfoLocalAdministratorsSnapshot
{
    public string State { get; set; }
    public bool Complete { get; set; }
    public int SourceReturnedEntries { get; set; }
    public int DuplicateEntriesRemoved { get; set; }
    public string[] Sids { get; set; }
}

public static class WinPCInfoLocalAdministratorsSource
{
    private const int ERROR_SUCCESS = 0;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_MORE_DATA = 234;
    private const int MAX_PREFERRED_LENGTH = -1;

    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_MEMBERS_INFO_0 { public IntPtr Sid; }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(
        string serverName, string localGroupName, int level, out IntPtr buffer,
        int preferredMaximumLength, out int entriesRead, out int totalEntries,
        ref IntPtr resumeHandle);

    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountSid(
        string systemName, byte[] sid, System.Text.StringBuilder name, ref int nameLength,
        System.Text.StringBuilder domain, ref int domainLength, out int use);

    private static string GetBuiltinAdministratorsName()
    {
        var sid = new SecurityIdentifier("S-1-5-32-544");
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        int nameLength = 0, domainLength = 0, use;
        LookupAccountSid(null, bytes, null, ref nameLength, null, ref domainLength, out use);
        if (nameLength <= 0) throw new InvalidOperationException("Unable to resolve the built-in alias.");
        var name = new System.Text.StringBuilder(nameLength);
        var domain = new System.Text.StringBuilder(Math.Max(1, domainLength));
        if (!LookupAccountSid(null, bytes, name, ref nameLength, domain, ref domainLength, out use))
            throw new InvalidOperationException("Unable to resolve the built-in alias.");
        return name.ToString();
    }

    public static WinPCInfoLocalAdministratorsSnapshot Read(int maximumMembers)
    {
        string groupName = GetBuiltinAdministratorsName();
        var distinct = new HashSet<string>(StringComparer.Ordinal);
        IntPtr resume = IntPtr.Zero;
        int reportedTotal = 0;
        int duplicates = 0;
        bool complete = false;
        while (true)
        {
            IntPtr buffer;
            int read, total;
            int status = NetLocalGroupGetMembers(
                null, groupName, 0, out buffer, MAX_PREFERRED_LENGTH,
                out read, out total, ref resume);
            if (status == ERROR_ACCESS_DENIED)
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
                return new WinPCInfoLocalAdministratorsSnapshot {
                    State="Denied", Complete=false, SourceReturnedEntries=0,
                    DuplicateEntriesRemoved=0, Sids=Array.Empty<string>()
                };
            }
            if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA)
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
                return new WinPCInfoLocalAdministratorsSnapshot {
                    State="Failed", Complete=false, SourceReturnedEntries=0,
                    DuplicateEntriesRemoved=0, Sids=Array.Empty<string>()
                };
            }
            reportedTotal = Math.Max(reportedTotal, total);
            bool malformed = false;
            try
            {
                int size = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_0>();
                for (int index = 0; index < read && distinct.Count < maximumMembers; index++)
                {
                    var item = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_0>(
                        IntPtr.Add(buffer, index * size));
                    if (item.Sid == IntPtr.Zero)
                    {
                        malformed = true;
                        break;
                    }
                    else
                    {
                        try
                        {
                            if (!distinct.Add(new SecurityIdentifier(item.Sid).Value))
                                duplicates++;
                        }
                        catch { malformed = true; break; }
                    }
                }
            }
            finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
            if (malformed)
                return new WinPCInfoLocalAdministratorsSnapshot {
                    State="Malformed", Complete=false, SourceReturnedEntries=0,
                    DuplicateEntriesRemoved=0, Sids=Array.Empty<string>()
                };
            if (reportedTotal > maximumMembers || distinct.Count >= maximumMembers && status == ERROR_MORE_DATA)
                break;
            if (status == ERROR_SUCCESS) { complete = true; break; }
        }
        var values = new List<string>(distinct);
        values.Sort(StringComparer.Ordinal);
        return new WinPCInfoLocalAdministratorsSnapshot {
            State = complete ? "Complete" : "Partial", Complete=complete,
            SourceReturnedEntries=reportedTotal, DuplicateEntriesRemoved=duplicates,
            Sids=values.ToArray()
        };
    }
}
"@

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public sealed class WinPCInfoLocalSamPolicySnapshot
{
    public uint MinimumLength { get; set; }
    public uint MaximumAgeSeconds { get; set; }
    public uint MinimumAgeSeconds { get; set; }
    public uint HistoryLength { get; set; }
    public uint LockoutDurationSeconds { get; set; }
    public uint LockoutWindowSeconds { get; set; }
    public uint LockoutThreshold { get; set; }
}

public sealed class WinPCInfoSystemAuditingSnapshot
{
    public string CatalogId { get; set; }
    public bool SuccessEnabled { get; set; }
    public bool FailureEnabled { get; set; }
}

public sealed class WinPCInfoUserRightSnapshot
{
    public string CatalogId { get; set; }
    public string[] DirectSids { get; set; }
    public bool BoundExceeded { get; set; }
}

public static class WinPCInfoEffectivePolicyNativeSource
{
    private const uint POLICY_LOOKUP_NAMES = 0x00000800;
    private const int STATUS_SUCCESS = 0;
    private const int STATUS_NO_MORE_ENTRIES = unchecked((int)0x8000001A);
    private const uint WSC_SECURITY_PROVIDER_FIREWALL = 0x1;
    private const uint WSC_SECURITY_PROVIDER_ANTIVIRUS = 0x4;

    private enum WSC_SECURITY_PROVIDER_HEALTH : int
    {
        GOOD = 0,
        NOTMONITORED = 1,
        POOR = 2,
        SNOOZE = 3
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_MODALS_INFO_0
    {
        public uint MinLength, MaxAge, MinAge, ForceLogoff, HistoryLength;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct USER_MODALS_INFO_3
    {
        public uint LockoutDuration, LockoutWindow, LockoutThreshold;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct AUDIT_POLICY_INFORMATION
    {
        public Guid SubCategoryGuid;
        public uint AuditingInformation;
        public Guid CategoryGuid;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING
    {
        public ushort Length, MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_ENUMERATION_INFORMATION { public IntPtr Sid; }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserModalsGet(string serverName, int level, out IntPtr buffer);
    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
    [DllImport("Advapi32.dll", SetLastError = true)]
    private static extern bool AuditQuerySystemPolicy(
        [In] Guid[] subCategoryGuids, uint count, out IntPtr policy);
    [DllImport("Advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);
    [DllImport("Advapi32.dll")]
    private static extern int LsaOpenPolicy(
        IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attributes,
        uint desiredAccess, out IntPtr policyHandle);
    [DllImport("Advapi32.dll")]
    private static extern int LsaEnumerateAccountsWithUserRight(
        IntPtr policyHandle, ref LSA_UNICODE_STRING userRight,
        out IntPtr buffer, out ulong countReturned);
    [DllImport("Advapi32.dll")]
    private static extern int LsaNtStatusToWinError(int status);
    [DllImport("Advapi32.dll")]
    private static extern int LsaFreeMemory(IntPtr buffer);
    [DllImport("Advapi32.dll")]
    private static extern int LsaClose(IntPtr handle);
    [DllImport("Wscapi.dll")]
    private static extern int WscGetSecurityProviderHealth(
        uint providers, out WSC_SECURITY_PROVIDER_HEALTH health);

    private static void ThrowStatus(int status, string source)
    {
        if (status != STATUS_SUCCESS)
            throw new Win32Exception(LsaNtStatusToWinError(status), source + " failed.");
    }

    public static WinPCInfoLocalSamPolicySnapshot ReadLocalSamPassword()
    {
        IntPtr level0 = IntPtr.Zero;
        try
        {
            int status = NetUserModalsGet(null, 0, out level0);
            if (status != 0) throw new Win32Exception(status, "NetUserModalsGet(0) failed.");
            var password = Marshal.PtrToStructure<USER_MODALS_INFO_0>(level0);
            return new WinPCInfoLocalSamPolicySnapshot {
                MinimumLength=password.MinLength, MaximumAgeSeconds=password.MaxAge,
                MinimumAgeSeconds=password.MinAge, HistoryLength=password.HistoryLength
            };
        }
        finally { if (level0 != IntPtr.Zero) NetApiBufferFree(level0); }
    }

    public static WinPCInfoLocalSamPolicySnapshot ReadLocalSamLockout()
    {
        IntPtr level3 = IntPtr.Zero;
        try
        {
            int status = NetUserModalsGet(null, 3, out level3);
            if (status != 0) throw new Win32Exception(status, "NetUserModalsGet(3) failed.");
            var lockout = Marshal.PtrToStructure<USER_MODALS_INFO_3>(level3);
            return new WinPCInfoLocalSamPolicySnapshot {
                LockoutDurationSeconds=lockout.LockoutDuration,
                LockoutWindowSeconds=lockout.LockoutWindow,
                LockoutThreshold=lockout.LockoutThreshold
            };
        }
        finally { if (level3 != IntPtr.Zero) NetApiBufferFree(level3); }
    }

    public static WinPCInfoSystemAuditingSnapshot[] ReadSystemAuditing()
    {
        string[] ids = { "audit:logon", "audit:process-creation", "audit:user-account-management" };
        Guid[] guids = {
            new Guid("0cce9215-69ae-11d9-bed3-505054503030"),
            new Guid("0cce922b-69ae-11d9-bed3-505054503030"),
            new Guid("0cce9235-69ae-11d9-bed3-505054503030")
        };
        IntPtr buffer;
        if (!AuditQuerySystemPolicy(guids, (uint)guids.Length, out buffer))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "AuditQuerySystemPolicy failed.");
        try
        {
        var values = new WinPCInfoSystemAuditingSnapshot[guids.Length];
            int size = Marshal.SizeOf<AUDIT_POLICY_INFORMATION>();
            for (int index = 0; index < values.Length; index++)
            {
                var item = Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(IntPtr.Add(buffer, index * size));
                if (item.SubCategoryGuid != guids[index])
                    throw new InvalidOperationException("Audit policy returned an unexpected subcategory.");
                values[index] = new WinPCInfoSystemAuditingSnapshot {
                    CatalogId=ids[index], SuccessEnabled=(item.AuditingInformation & 1) != 0,
                    FailureEnabled=(item.AuditingInformation & 2) != 0
                };
            }
            return values;
        }
        finally { if (buffer != IntPtr.Zero) AuditFree(buffer); }
    }

    public static WinPCInfoUserRightSnapshot ReadUserRight(string catalogId, int maximumPrincipals)
    {
        string[] ids = { "right:remote-interactive-logon", "right:deny-remote-interactive-logon", "right:service-logon" };
        string[] names = { "SeRemoteInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight", "SeServiceLogonRight" };
        int rightIndex = Array.IndexOf(ids, catalogId);
        if (rightIndex < 0) throw new InvalidOperationException("The user right is not release-cataloged.");
        var attributes = new LSA_OBJECT_ATTRIBUTES { Length = Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
        IntPtr policy;
        ThrowStatus(LsaOpenPolicy(IntPtr.Zero, ref attributes, POLICY_LOOKUP_NAMES, out policy), "LsaOpenPolicy");
        try
        {
            IntPtr text = Marshal.StringToHGlobalUni(names[rightIndex]);
            IntPtr buffer = IntPtr.Zero;
            try
            {
                var right = new LSA_UNICODE_STRING {
                    Buffer=text, Length=checked((ushort)(names[rightIndex].Length * 2)),
                    MaximumLength=checked((ushort)((names[rightIndex].Length + 1) * 2))
                };
                ulong count;
                int status = LsaEnumerateAccountsWithUserRight(policy, ref right, out buffer, out count);
                if (status == STATUS_NO_MORE_ENTRIES)
                    return new WinPCInfoUserRightSnapshot { CatalogId=ids[rightIndex], DirectSids=Array.Empty<string>(), BoundExceeded=false };
                ThrowStatus(status, "LsaEnumerateAccountsWithUserRight");
                bool boundExceeded = count > (ulong)maximumPrincipals;
                ulong admittedCount = Math.Min(count, (ulong)maximumPrincipals);
                var sids = new List<string>();
                int size = Marshal.SizeOf<LSA_ENUMERATION_INFORMATION>();
                for (ulong index = 0; index < admittedCount; index++)
                {
                    var item = Marshal.PtrToStructure<LSA_ENUMERATION_INFORMATION>(IntPtr.Add(buffer, checked((int)index * size)));
                    if (item.Sid == IntPtr.Zero) throw new InvalidOperationException("A user-right SID is missing.");
                    sids.Add(new SecurityIdentifier(item.Sid).Value);
                }
                sids.Sort(StringComparer.Ordinal);
                return new WinPCInfoUserRightSnapshot { CatalogId=ids[rightIndex], DirectSids=sids.ToArray(), BoundExceeded=boundExceeded };
            }
            finally
            {
                if (buffer != IntPtr.Zero) LsaFreeMemory(buffer);
                Marshal.FreeHGlobal(text);
            }
        }
        finally { LsaClose(policy); }
    }

    public static string ReadSecurityProviderHealth(uint provider)
    {
        if (provider != WSC_SECURITY_PROVIDER_FIREWALL &&
            provider != WSC_SECURITY_PROVIDER_ANTIVIRUS)
            throw new InvalidOperationException("The WSC provider category is not release-cataloged.");
        WSC_SECURITY_PROVIDER_HEALTH health;
        int hr = WscGetSecurityProviderHealth(provider, out health);
        if (hr < 0) Marshal.ThrowExceptionForHR(hr);
        switch (health)
        {
            case WSC_SECURITY_PROVIDER_HEALTH.GOOD: return "Good";
            case WSC_SECURITY_PROVIDER_HEALTH.NOTMONITORED: return "NotMonitored";
            case WSC_SECURITY_PROVIDER_HEALTH.POOR: return "Poor";
            case WSC_SECURITY_PROVIDER_HEALTH.SNOOZE: return "Snooze";
            default:
                throw new InvalidOperationException("Windows Security Center returned an unknown provider health.");
        }
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

function New-SyntheticAdministratorResult {
    param([string] $Scenario)
    function New-Member([string]$Sid,$AccountName,[string]$Kind,[string]$Origin){
        [ordered]@{sid=$Sid;accountName=$AccountName;principalKind=$Kind;origin=$Origin}
    }
    $local=New-Member 'S-1-5-21-111111111-222222222-333333333-1001' 'SYNTHETIC\local-admin' User Local
    $builtin=New-Member 'S-1-5-21-111111111-222222222-333333333-500' 'SYNTHETIC\built-in-admin' User Local
    $domainUser=New-Member 'S-1-5-21-444444444-555555555-666666666-1101' 'SYNTHETIC-DOMAIN\domain-admin' User Domain
    $domainGroup=New-Member 'S-1-5-21-444444444-555555555-666666666-2101' 'SYNTHETIC-DOMAIN\endpoint-admins' Group Domain
    $members=@($builtin,$local);$state='Complete';$complete=$true;$locale='en-US';$sourceCount=2
    switch($Scenario){
        'LocalPrincipal' {}
        'DomainPrincipal' {$members=@($domainGroup,$domainUser)}
        'NestedGroup' {$members=@($domainGroup,$local)}
        'UnresolvedSid' {$members=@((New-Member 'S-1-5-21-777777777-888888888-999999999-4040' $null Unknown Unresolved),$local)}
        'DuplicateMembership' {$members=@($domainUser,$local);$sourceCount=3}
        'AlternateAdministrator' {}
        'Denied' {$state='Denied';$complete=$false;$members=@();$sourceCount=0}
        'Partial' {$state='Partial';$complete=$false;$members=@($domainGroup,$local)}
        'NonEnglish' {
            $locale='fr-FR';$members=@(
                (New-Member $domainGroup.sid 'DOMAINE-ÉQUIPE\administrateurs-poste' Group Domain),
                (New-Member $local.sid 'ÉQUIPE\administrateur-local' User Local)
            )
        }
        default {throw 'The administrator validation scenario is not release-defined.'}
    }
    [ordered]@{
        sourceLocale=$locale;groupSid='S-1-5-32-544';enumerationState=$state
        enumerationComplete=$complete;directMembers=@($members);sourceReturnedEntries=$sourceCount
        duplicateEntriesRemoved=[int]($sourceCount-@($members).Count);limitation='DirectMembersOnly'
    }
}

function Get-LiveAdministratorResult {
    # Threat: localized group names and command output can identify the wrong
    # group or misparse a principal. Mechanism: Windows first resolves the
    # well-known built-in alias SID, then NetLocalGroupGetMembers level 0
    # returns only structured SIDs. Trust assumption: local NetAPI/SID services
    # faithfully describe direct local-group membership without a network or
    # credential request. Safe failure: access denial, API failure, or the
    # eight-member evidence ceiling becomes a gap; it never becomes an empty
    # group and nested groups are never recursively expanded.
    $snapshot=[WinPCInfoLocalAdministratorsSource]::Read(8)
    $members=@($snapshot.Sids|ForEach-Object {
        [ordered]@{sid=[string]$_;accountName=$null;principalKind='Unknown';origin='Unresolved'}
    })
    [ordered]@{
        sourceLocale='und';groupSid='S-1-5-32-544';enumerationState=[string]$snapshot.State
        enumerationComplete=[bool]$snapshot.Complete;directMembers=$members
        sourceReturnedEntries=[int]$snapshot.SourceReturnedEntries
        duplicateEntriesRemoved=[int]$snapshot.DuplicateEntriesRemoved
        limitation='DirectMembersOnly'
    }
}

function Get-WorkerAccessState {
    param($Failure)
    $exception = $Failure.Exception
    $nativeCode = [int]($exception.HResult -band 0xffff)
    $providerCode = ''
    $cursor = $exception
    while ($null -ne $cursor -and [string]::IsNullOrWhiteSpace($providerCode)) {
        if ($cursor.PSObject.Properties['NativeErrorCode']) {
            $providerCode = [string]$cursor.NativeErrorCode
        }
        $cursor = $cursor.InnerException
    }
    if ($exception -is [System.UnauthorizedAccessException] -or $nativeCode -eq 5 -or
        $providerCode -eq 'AccessDenied') {
        'Denied'
    }
    elseif ($exception -is [System.PlatformNotSupportedException] -or
        [string]$Failure.FullyQualifiedErrorId -match '^CmdletNotSupported' -or
        $providerCode -in @('InvalidNamespace','InvalidClass','NotSupported','MethodNotAvailable')) {
        'Unsupported'
    }
    else { 'Failed' }
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
        if ($bios.Count -ne 1) {
            $result.firmwareState = 'Malformed'
        }
        else {
            $firmwareType = switch ([uint32]$nativeFirmware) {
                1 { 'LegacyBios' } 2 { 'Uefi' } default { 'Unknown' }
            }
            $biosVersion = if ($null -eq $bios[0].SMBIOSBIOSVersion) {
                $null
            } else { ([string]$bios[0].SMBIOSBIOSVersion).Trim() }
            $smbiosVersion = if ($null -eq $bios[0].SMBIOSMajorVersion -or
                $null -eq $bios[0].SMBIOSMinorVersion) {
                $null
            } else {
                "$([int]$bios[0].SMBIOSMajorVersion).$([int]$bios[0].SMBIOSMinorVersion)"
            }
            if (($null -ne $biosVersion -and (
                    [string]::IsNullOrWhiteSpace($biosVersion) -or
                    [Text.Encoding]::UTF8.GetByteCount($biosVersion) -gt 128
                )) -or ($null -ne $smbiosVersion -and (
                    [string]::IsNullOrWhiteSpace($smbiosVersion) -or
                    [Text.Encoding]::UTF8.GetByteCount($smbiosVersion) -gt 16
                ))) {
                $result.firmwareState = 'Malformed'
            }
            else {
                $result.firmwareState='Complete';$result.firmwareType=$firmwareType
                $result.biosVersion=$biosVersion;$result.smbiosVersion=$smbiosVersion
            }
        }
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
                $secureBootValue = & $secureBootCommand -ErrorAction Stop
                if ($secureBootValue -isnot [bool]) {
                    $result.secureBootState = 'Malformed'
                }
                else {
                    $result.secureBootEnabled = [bool]$secureBootValue
                    $result.secureBootState = 'Complete'
                }
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
        if ($tpm.Count -gt 1) {
            $result.tpmState = 'Malformed'
        }
        elseif ($tpm.Count -eq 0) {
            $result.tpmState = 'Complete';$result.tpmPresent = $false
        }
        else {
            $enabled = $tpm[0].IsEnabled_InitialValue
            $activated = $tpm[0].IsActivated_InitialValue
            $specification = if ($null -eq $tpm[0].SpecVersion) {
                $null
            } else { ([string]$tpm[0].SpecVersion).Trim() }
            if ($enabled -isnot [bool] -or $activated -isnot [bool] -or
                ($null -ne $specification -and (
                    [string]::IsNullOrWhiteSpace($specification) -or
                    [Text.Encoding]::UTF8.GetByteCount($specification) -gt 32
                ))) {
                $result.tpmState = 'Malformed'
            }
            else {
                $result.tpmState='Complete';$result.tpmPresent=$true
                $result.tpmEnabled=$enabled;$result.tpmActivated=$activated
                $result.tpmSpecification=$specification
            }
        }
    }
    catch {
        $result.tpmState = Get-WorkerAccessState -Failure $_
        $result.tpmPresent=$null;$result.tpmEnabled=$null
        $result.tpmActivated=$null;$result.tpmSpecification=$null
    }
    $result
}

function New-EffectivePolicyScopeState {
    param([string]$ScopeId,[string]$State='Complete',[string]$ReasonCode='')
    [ordered]@{scopeId=$ScopeId;state=$State;reasonCode=$ReasonCode}
}

function Get-EffectivePolicyScopeIds {
    @(
        'scope:policy.applied.user.identity','scope:policy.applied.user.applicability',
        'scope:policy.applied.user.link','scope:policy.applied.user.precedence',
        'scope:policy.applied.computer.identity','scope:policy.applied.computer.applicability',
        'scope:policy.applied.computer.link','scope:policy.applied.computer.precedence',
        'scope:policy.local-sam.password','scope:policy.local-sam.lockout',
        'scope:policy.local-audit','scope:policy.local-user-rights',
        'scope:policy.security-option.machine-inactivity-limit',
        'scope:policy.security-option.disable-cad',
        'scope:policy.security-option.lm-compatibility-level',
        'scope:policy.defender.asr','scope:policy.defender.network-protection',
        'scope:policy.smartscreen.shell','scope:policy.smartscreen.app-install-control',
        'scope:policy.security-center.antivirus-providers',
        'scope:policy.security-center.firewall-providers',
        'scope:policy.defender.runtime',
        'scope:policy.firewall.domain-profile','scope:policy.firewall.private-profile',
        'scope:policy.firewall.public-profile'
    )
}

function Complete-EffectivePolicyLayerStates {
    param([Parameter(Mandatory)]$Result)
    function Get-LayerState([int[]]$Indexes){
        $values=@($Indexes|ForEach-Object {[string]$Result.scopeStates[$_].state})
        if(@($values|Where-Object {$_ -ne 'Complete'}).Count -eq 0){return 'Complete'}
        if(@($values|Select-Object -Unique).Count -eq 1){return [string]$values[0]}
        'Partial'
    }
    $Result.layerStates=[ordered]@{
        AppliedPolicyEvidence=Get-LayerState (0..7)
        ConfiguredPolicySignals=Get-LayerState (12..18)
        CurrentControlState=Get-LayerState @(8,9,10,11,19,20,21,22,23,24)
    }
    $Result
}

function New-EffectivePolicyBaseResult {
    param([string]$State='Complete')
    $reason=if($State -eq 'Complete'){''}else{'POLICY.SOURCE_UNAVAILABLE'}
    [ordered]@{
        sourceLocale='und'
        layerStates=[ordered]@{AppliedPolicyEvidence=$State;ConfiguredPolicySignals=$State;CurrentControlState=$State}
        scopeStates=@(Get-EffectivePolicyScopeIds|ForEach-Object {New-EffectivePolicyScopeState $_ $State $reason})
        appliedPolicies=@();policySettings=@()
        localSam=[ordered]@{
            minimumPasswordLength=$null;maximumPasswordAgeSeconds=$null;minimumPasswordAgeSeconds=$null
            passwordHistoryLength=$null;lockoutDurationSeconds=$null;lockoutWindowSeconds=$null;lockoutThreshold=$null
        }
        auditSubcategories=@(
            [ordered]@{catalogId='audit:logon';state=$State;successEnabled=$null;failureEnabled=$null},
            [ordered]@{catalogId='audit:process-creation';state=$State;successEnabled=$null;failureEnabled=$null},
            [ordered]@{catalogId='audit:user-account-management';state=$State;successEnabled=$null;failureEnabled=$null}
        )
        userRights=@(
            [ordered]@{catalogId='right:remote-interactive-logon';state=$State;directSids=@()},
            [ordered]@{catalogId='right:deny-remote-interactive-logon';state=$State;directSids=@()},
            [ordered]@{catalogId='right:service-logon';state=$State;directSids=@()}
        )
        securityOptions=@(
            [ordered]@{catalogId='security-option:machine-inactivity-limit-seconds';state=$State;value=$null;sourceAttribution='Unproven'},
            [ordered]@{catalogId='security-option:disable-cad';state=$State;value=$null;sourceAttribution='Unproven'},
            [ordered]@{catalogId='security-option:lm-compatibility-level';state=$State;value=$null;sourceAttribution='Unproven'}
        )
        antivirusProviders=@()
        firewallProviders=@()
        defenderRuntime=[ordered]@{
            runningMode=$null;antivirusEnabled=$null
            realTimeProtectionEnabled=$null;tamperProtected=$null
        }
        defenderNetworkProtection=[ordered]@{
            state=$State;value=$null;sourceAttribution='Unproven'
        }
        defenderAsrRules=@()
        smartScreenSignals=@(
            [ordered]@{catalogId='smartscreen:enable-in-shell';state=$State;value=$null;sourceAttribution='Unproven'},
            [ordered]@{catalogId='smartscreen:prevent-override-for-files';state=$State;value=$null;sourceAttribution='Unproven'},
            [ordered]@{catalogId='smartscreen:app-install-control';state=$State;value=$null;sourceAttribution='Unproven'}
        )
        firewallProfiles=[ordered]@{
            domain=[ordered]@{state=$State;enabled=$null;defaultInboundAction=$null;defaultOutboundAction=$null}
            private=[ordered]@{state=$State;enabled=$null;defaultInboundAction=$null;defaultOutboundAction=$null}
            public=[ordered]@{state=$State;enabled=$null;defaultInboundAction=$null;defaultOutboundAction=$null}
        }
        appliedOrderConflict=$false
        localAccountPolicySemantics='LocalSamAccountsOnly'
        userRightSemantics='DirectAssignmentsOnly'
    }
}

function Set-EffectivePolicyScopeState {
    param($Result,[int[]]$Indexes,[string]$State,[string]$ReasonCode)
    foreach($index in $Indexes){
        $Result.scopeStates[$index].state=$State
        $Result.scopeStates[$index].reasonCode=if($State -eq 'Complete'){''}else{$ReasonCode}
    }
}

function New-SyntheticEffectivePolicyResult {
    param([string]$Scenario)
    # Synthetic evidence is produced and validated by the standard-user
    # coordinator from the same release policy used by unit tests. The elevated
    # worker returns only this closed scenario marker, so the launch payload
    # stays below Windows' immutable command-line ceiling without weakening the
    # real collector or accepting caller-provided scripts.
    [ordered]@{validationScenario=$Scenario}
}

function Convert-EffectivePolicyRegistryUnsignedIntegerValue {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter()][UInt64]$Maximum = [uint64]4294967295
    )

    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    $normalized = switch ($Value.GetType().FullName) {
        'System.Byte' { [uint64][byte]$Value; break }
        'System.UInt16' { [uint64][uint16]$Value; break }
        'System.UInt32' { [uint64][uint32]$Value; break }
        'System.UInt64' { [uint64]$Value; break }
        'System.SByte' {
            if ([sbyte]$Value -lt 0) { return $null }
            [uint64][sbyte]$Value
            break
        }
        'System.Int16' {
            if ([int16]$Value -lt 0) { return $null }
            [uint64][int16]$Value
            break
        }
        'System.Int32' {
            if ([int32]$Value -lt 0) { return $null }
            [uint64][int32]$Value
            break
        }
        'System.Int64' {
            if ([int64]$Value -lt 0) { return $null }
            [uint64][int64]$Value
            break
        }
        default { return $null }
    }
    if ($normalized -gt $Maximum -or $normalized -gt [uint64][long]::MaxValue) {
        return $null
    }
    [long]$normalized
}

function Convert-EffectivePolicyRegistryBooleanValue {
    param([Parameter(Mandatory)]$Value)

    if ($Value -is [bool]) { return [bool]$Value }
    $normalized = Convert-EffectivePolicyRegistryUnsignedIntegerValue -Value $Value -Maximum 1
    if ($null -eq $normalized) { return $null }
    [bool]$normalized
}

function Convert-EffectivePolicyDefenderActionValue {
    param($Value)
    switch -Regex ([string]$Value) {
        '^(?:0|Disabled|Off)$' { 'Disabled'; break }
        '^(?:1|Enabled|Block)$' { 'Block'; break }
        '^(?:2|Audit|AuditMode)$' { 'Audit'; break }
        '^(?:5|NotConfigured)$' { 'NotConfigured'; break }
        '^(?:6|Warn|Warning)$' { 'Warn'; break }
        default { $null }
    }
}

function Convert-EffectivePolicyNetworkProtectionValue {
    param($Value)
    switch -Regex ([string]$Value) {
        '^(?:0|Disabled|Off)$' { 'Disabled'; break }
        '^(?:1|Enabled|Block)$' { 'Enabled'; break }
        '^(?:2|Audit|AuditMode)$' { 'AuditMode'; break }
        '^(?:5|NotConfigured)$' { 'NotConfigured'; break }
        default { $null }
    }
}

function Convert-EffectivePolicyFirewallEnabled {
    param($Value)
    switch -Regex ([string]$Value) {
        '^(?:True|1|On|Enabled)$' { $true; break }
        '^(?:False|0|Off|Disabled)$' { $false; break }
        default { $null }
    }
}

function Convert-EffectivePolicyFirewallAction {
    param($Value)
    switch -Regex ([string]$Value) {
        '^(?:Allow|1)$' { 'Allow'; break }
        '^(?:Block|2)$' { 'Block'; break }
        '^(?:NotConfigured|0)$' { 'NotConfigured'; break }
        default { $null }
    }
}

function Get-LiveEffectivePolicyResult {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$AssessmentUserSid)
    # Threat: human-facing policy reports are localized and can merge intended,
    # configured, and effective state. Mechanism: this operation reads only
    # structured Windows interfaces and projects a fixed catalog. It never
    # refreshes policy, invokes a policy tool, resolves groups recursively, or
    # contacts a domain controller. Trust assumption: the local cached RSoP,
    # NetAPI, Audit, LSA, Windows Security Center, Defender cmdlets, NetSecurity,
    # and registry providers truthfully report their own layer. Policy CSP
    # comparisons for MDM_Policy_Result01_Update02
    # (DeferFeatureUpdatesPeriodInDays, DeferQualityUpdatesPeriodInDays,
    # DisableDualScan) cross the separate LocalSystem SYSTEM sub-plan and are
    # deliberately not queried here under Administrator. The Administrator seam
    # does, however, own the local structured sources named in the release:
    # Win32_TSGeneralSetting, WSMan:\\localhost\\Service\\Auth,
    # WSMan:\\localhost\\Listener, Get-SmbClientConfiguration,
    # Get-SmbServerConfiguration, Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol,
    # NtlmMinClientSec, and NtlmMinServerSec. Safe failure:
    # each independent source becomes a field-specific gap; an empty or denied
    # source never becomes affirmative compliance evidence.
    $result=New-EffectivePolicyBaseResult Failed
    $rsopSources=[Collections.Generic.List[object]]::new()
    if([string]::IsNullOrWhiteSpace($AssessmentUserSid)){
        Set-EffectivePolicyScopeState $result (0..3) Unavailable 'POLICY.ASSESSMENT_USER_CONTEXT_UNAVAILABLE'
    }else{
        $rsopSources.Add([ordered]@{target='User';namespace="root/RSOP/User/$AssessmentUserSid";offset=0})
    }
    $rsopSources.Add([ordered]@{target='Computer';namespace='root/RSOP/Computer';offset=4})
    foreach($source in $rsopSources){
        $target=[string]$source.target;$offset=[int]$source.offset
        try {
            $namespace=[string]$source.namespace
            $gpos=@(Get-CimInstance -Namespace $namespace -ClassName RSOP_GPO -Property @('id','guidName','enabled','accessDenied','filterAllowed') -ErrorAction Stop)
        } catch {
            $state=Get-WorkerAccessState $_;Set-EffectivePolicyScopeState $result ($offset..($offset+3)) $state "POLICY.RSOP_GPO_$($state.ToUpperInvariant())"
            continue
        }
        $gpoOverflow=$gpos.Count -gt 8
        $links=@();$linkState='Complete';$linkReason=''
        try {
            $links=@(Get-CimInstance -Namespace $namespace -ClassName RSOP_GPLink -Property @('GPO','SOM','appliedOrder','enabled') -ErrorAction Stop)
        } catch {
            $linkState=Get-WorkerAccessState $_;$linkReason="POLICY.RSOP_LINK_$($linkState.ToUpperInvariant())"
        }
        $settings=@();$settingState='Complete';$settingReason=''
        try {
            $settings=@(Get-CimInstance -Namespace $namespace -Query 'SELECT __CLASS,id,GPOID,SOMID,precedence FROM RSOP_PolicySetting' -ErrorAction Stop)
        } catch {
            $settingState=Get-WorkerAccessState $_;$settingReason="POLICY.RSOP_SETTING_$($settingState.ToUpperInvariant())"
        }
        try {
            $objectIdByRsopId=@{}
            foreach($gpo in $gpos|Select-Object -First 8){
                $isLocal=[string]$gpo.id -eq 'LocalGPO'
                $id=if($isLocal){'LocalGPO'}else{([string]$gpo.guidName).Trim('{}').ToLowerInvariant()}
                if($id -notmatch '^(?:LocalGPO|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$' -or
                    $gpo.enabled -isnot [bool] -or $gpo.accessDenied -isnot [bool] -or $gpo.filterAllowed -isnot [bool]){throw 'Malformed RSoP GPO identity or applicability.'}
                $objectIdByRsopId[[string]$gpo.id]=$id
                $linkId=$null;$order=$null;$applicable=$null
                if($linkState -eq 'Complete'){
                    $rsopId=[string]$gpo.id
                    $link=@($links|Where-Object {
                        $reference=[string]$_.GPO
                        $reference -eq $rsopId -or $reference -eq $id -or
                            $reference -match [regex]::Escape($rsopId) -or
                            $reference -match [regex]::Escape($id)
                    })
                    if(@($link|Where-Object {$_.enabled -isnot [bool]}).Count -gt 0){
                        $linkState='Malformed';$linkReason='POLICY.RSOP_LINK_MALFORMED'
                    }
                    $enabledLinks=@($link|Where-Object {$_.enabled -is [bool] -and [bool]$_.enabled})
                    if($enabledLinks.Count -gt 1){
                        $linkState='Partial';$linkReason='POLICY.RSOP_LINK_AMBIGUOUS'
                    }elseif($enabledLinks.Count -eq 1 -and $linkState -eq 'Complete'){
                        if([string]::IsNullOrWhiteSpace([string]$enabledLinks[0].SOM) -or
                            $null -eq $enabledLinks[0].appliedOrder -or [int]$enabledLinks[0].appliedOrder -lt 0 -or
                            [int]$enabledLinks[0].appliedOrder -gt 64){
                            $linkState='Malformed';$linkReason='POLICY.RSOP_LINK_MALFORMED'
                        }else{
                            $linkId=[string]$enabledLinks[0].SOM;$order=[int]$enabledLinks[0].appliedOrder
                            $applicable=([bool]$gpo.enabled -and -not [bool]$gpo.accessDenied -and [bool]$gpo.filterAllowed)
                        }
                    }elseif($enabledLinks.Count -eq 0 -and $linkState -eq 'Complete'){
                        $applicable=if($isLocal){([bool]$gpo.enabled -and -not [bool]$gpo.accessDenied -and [bool]$gpo.filterAllowed)}else{$false}
                    }
                }
                $result.appliedPolicies+=,[ordered]@{target=$target;origin=if($isLocal){'Local'}else{'Domain'};objectId=$id;applicable=$applicable;linkId=$linkId;appliedOrder=$order}
            }
            $settingOverflow=$settings.Count -gt 8
            foreach($setting in $settings|Select-Object -First 8){
                $settingClass=[string]$setting.CimClass.CimClassName
                if($settingClass -ne 'RSOP_RegistryPolicySetting'){
                    $settingState='Unsupported';$settingReason='POLICY.RSOP_EXTENSION_UNSUPPORTED';continue
                }
                $gpoReference=[string]$setting.GPOID
                $matchingRsopIds=@($objectIdByRsopId.Keys|Where-Object {
                    $gpoReference -eq $_ -or $gpoReference -match [regex]::Escape([string]$_)
                })
                if($matchingRsopIds.Count -ne 1){
                    if($gpoOverflow){$settingOverflow=$true;continue}
                    $settingState='Malformed';$settingReason='POLICY.RSOP_SETTING_MALFORMED';continue
                }
                $gpoId=[string]$objectIdByRsopId[[string]$matchingRsopIds[0]]
                $settingId="registry:$([string]$setting.id)"
                if($gpoId -notmatch '^(?:LocalGPO|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$' -or $settingId -notmatch '^[A-Za-z0-9._:/{}-]{1,128}$' -or
                    $null -eq $setting.precedence -or [int]$setting.precedence -lt 1 -or [int]$setting.precedence -gt 64){
                    $settingState='Malformed';$settingReason='POLICY.RSOP_SETTING_MALFORMED';continue
                }
                $result.policySettings+=,[ordered]@{target=$target;settingId=$settingId;objectId=$gpoId;precedence=[int]$setting.precedence}
            }
            $boundState=if($gpoOverflow){'Partial'}else{'Complete'}
            $boundReason=if($gpoOverflow){'POLICY.RSOP_EVIDENCE_BOUND_EXCEEDED'}else{''}
            Set-EffectivePolicyScopeState $result @($offset) $boundState $boundReason
            $finalLinkState=if($linkState -ne 'Complete'){$linkState}elseif($gpoOverflow){'Partial'}else{'Complete'}
            $finalLinkReason=if($linkState -ne 'Complete'){$linkReason}elseif($gpoOverflow){'POLICY.RSOP_EVIDENCE_BOUND_EXCEEDED'}else{''}
            Set-EffectivePolicyScopeState $result @($offset+1) $finalLinkState $finalLinkReason
            $finalSettingState=if($settingState -ne 'Complete'){$settingState}elseif($gpoOverflow -or $settingOverflow){'Partial'}else{'Complete'}
            $finalSettingReason=if($settingState -ne 'Complete'){$settingReason}elseif($gpoOverflow -or $settingOverflow){'POLICY.RSOP_EVIDENCE_BOUND_EXCEEDED'}else{''}
            Set-EffectivePolicyScopeState $result @($offset+2) $finalLinkState $finalLinkReason
            Set-EffectivePolicyScopeState $result @($offset+3) $finalSettingState $finalSettingReason
        } catch {
            $state=Get-WorkerAccessState $_;Set-EffectivePolicyScopeState $result ($offset..($offset+3)) $state "POLICY.RSOP_$($state.ToUpperInvariant())"
        }
    }
    try {
        $sam=[WinPCInfoEffectivePolicyNativeSource]::ReadLocalSamPassword()
        $result.localSam.minimumPasswordLength=[int]$sam.MinimumLength;$result.localSam.maximumPasswordAgeSeconds=[long]$sam.MaximumAgeSeconds;$result.localSam.minimumPasswordAgeSeconds=[long]$sam.MinimumAgeSeconds;$result.localSam.passwordHistoryLength=[int]$sam.HistoryLength
        Set-EffectivePolicyScopeState $result @(8) Complete ''
    } catch {$state=Get-WorkerAccessState $_;Set-EffectivePolicyScopeState $result @(8) $state "POLICY.LOCAL_SAM_PASSWORD_$($state.ToUpperInvariant())"}
    try {
        $sam=[WinPCInfoEffectivePolicyNativeSource]::ReadLocalSamLockout()
        $result.localSam.lockoutDurationSeconds=[long]$sam.LockoutDurationSeconds;$result.localSam.lockoutWindowSeconds=[long]$sam.LockoutWindowSeconds;$result.localSam.lockoutThreshold=[int]$sam.LockoutThreshold
        Set-EffectivePolicyScopeState $result @(9) Complete ''
    } catch {$state=Get-WorkerAccessState $_;Set-EffectivePolicyScopeState $result @(9) $state "POLICY.LOCAL_SAM_LOCKOUT_$($state.ToUpperInvariant())"}
    try {
        $result.auditSubcategories=@([WinPCInfoEffectivePolicyNativeSource]::ReadSystemAuditing()|ForEach-Object {[ordered]@{catalogId=$_.CatalogId;state='Complete';successEnabled=$_.SuccessEnabled;failureEnabled=$_.FailureEnabled}})
        Set-EffectivePolicyScopeState $result @(10) Complete ''
    } catch {$state=Get-WorkerAccessState $_;foreach($item in $result.auditSubcategories){$item.state=$state};Set-EffectivePolicyScopeState $result @(10) $state "POLICY.AUDIT_$($state.ToUpperInvariant())"}
    $rightGap=$false;$rightBoundExceeded=$false
    for($index=0;$index -lt $result.userRights.Count;$index++){
        try {
            $snapshot=[WinPCInfoEffectivePolicyNativeSource]::ReadUserRight([string]$result.userRights[$index].catalogId,8)
            $result.userRights[$index]=[ordered]@{catalogId=$snapshot.CatalogId;state=if($snapshot.BoundExceeded){'Partial'}else{'Complete'};directSids=@($snapshot.DirectSids)}
            if($snapshot.BoundExceeded){$rightBoundExceeded=$true}
        } catch {$state=Get-WorkerAccessState $_;$result.userRights[$index].state=$state;$rightGap=$true}
    }
    if($rightGap){Set-EffectivePolicyScopeState $result @(11) Partial 'POLICY.USER_RIGHTS_INCOMPLETE'}
    elseif($rightBoundExceeded){Set-EffectivePolicyScopeState $result @(11) Partial 'POLICY.USER_RIGHTS_EVIDENCE_BOUND_EXCEEDED'}
    else{Set-EffectivePolicyScopeState $result @(11) Complete ''}
    $optionDefinitions=@(
        @('security-option:machine-inactivity-limit-seconds','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','InactivityTimeoutSecs','Integer'),
        @('security-option:disable-cad','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','DisableCAD','Boolean'),
        @('security-option:lm-compatibility-level','SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel','Integer')
    )
    for($index=0;$index -lt $optionDefinitions.Count;$index++){
        try {
            $definition=$optionDefinitions[$index];$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($definition[1],$false)
            try {$rawValue=if($null -eq $key){$null}else{$key.GetValue($definition[2],$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}}finally{if($null -ne $key){$key.Dispose()}}
            $value = if ($null -eq $rawValue) { $null }
            elseif ($definition[3] -eq 'Boolean') { Convert-EffectivePolicyRegistryBooleanValue -Value $rawValue }
            else { Convert-EffectivePolicyRegistryUnsignedIntegerValue -Value $rawValue }
            if ($null -ne $rawValue -and $null -eq $value) {
                $result.securityOptions[$index].state='Malformed'
                Set-EffectivePolicyScopeState $result @(12+$index) Malformed 'POLICY.SECURITY_OPTION_MALFORMED'
            } else {
                $result.securityOptions[$index].state='Complete';$result.securityOptions[$index].value=$value
                Set-EffectivePolicyScopeState $result @(12+$index) Complete ''
            }
        } catch {$state=Get-WorkerAccessState $_;$result.securityOptions[$index].state=$state;Set-EffectivePolicyScopeState $result @(12+$index) $state "POLICY.SECURITY_OPTION_$($state.ToUpperInvariant())"}
    }
    $preferenceCommand=Get-Command Get-MpPreference -CommandType Cmdlet -ErrorAction SilentlyContinue
    if($null -eq $preferenceCommand){
        Set-EffectivePolicyScopeState $result @(15,16) Unsupported 'POLICY.DEFENDER_MODULE_UNAVAILABLE'
        $result.defenderNetworkProtection.state='Unsupported'
    } else {
        # Defender preferences can include highly sensitive exclusions and broad
        # policy surfaces. The worker reads only the release-cataloged ASR IDs,
        # ASR actions, and Network Protection mode. It discards every other
        # property immediately so no excluded path or secret-adjacent value can
        # cross the privilege boundary. If the module or one property is missing,
        # coverage degrades explicitly instead of inventing a default.
        try {
            $preferences=& $preferenceCommand -ErrorAction Stop
            $idsProperty=$preferences.PSObject.Properties['AttackSurfaceReductionRules_Ids']
            $actionsProperty=$preferences.PSObject.Properties['AttackSurfaceReductionRules_Actions']
            if($null -eq $idsProperty -or $null -eq $actionsProperty){
                Set-EffectivePolicyScopeState $result @(15) Partial 'POLICY.DEFENDER_PROPERTY_UNAVAILABLE'
            } else {
                $pairCount=[Math]::Min(@($idsProperty.Value).Count,@($actionsProperty.Value).Count)
                $boundedPairCount=[Math]::Min($pairCount,16)
                $asrRules=@()
                $asrMalformed=$false
                for($index=0;$index -lt $boundedPairCount;$index++){
                    $ruleId=([string]@($idsProperty.Value)[$index]).Trim().ToLowerInvariant()
                    $action=Convert-EffectivePolicyDefenderActionValue @($actionsProperty.Value)[$index]
                    if($ruleId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
                        [string]::IsNullOrWhiteSpace([string]$action)){
                        $asrMalformed=$true
                        break
                    }
                    $asrRules+=,[ordered]@{ruleId=$ruleId;action=[string]$action}
                }
                $result.defenderAsrRules=@($asrRules)
                if($asrMalformed){
                    Set-EffectivePolicyScopeState $result @(15) Malformed 'POLICY.DEFENDER_ASR_MALFORMED'
                    $result.defenderAsrRules=@()
                } elseif(@($idsProperty.Value).Count -ne @($actionsProperty.Value).Count){
                    Set-EffectivePolicyScopeState $result @(15) Partial 'POLICY.DEFENDER_PROPERTY_UNAVAILABLE'
                } elseif($pairCount -gt 16){
                    Set-EffectivePolicyScopeState $result @(15) Partial 'POLICY.DEFENDER_ASR_EVIDENCE_BOUND_EXCEEDED'
                } else {
                    Set-EffectivePolicyScopeState $result @(15) Complete ''
                }
            }
            $networkProtectionProperty=$preferences.PSObject.Properties['EnableNetworkProtection']
            if($null -eq $networkProtectionProperty){
                Set-EffectivePolicyScopeState $result @(16) Partial 'POLICY.DEFENDER_PROPERTY_UNAVAILABLE'
                $result.defenderNetworkProtection.state='Unavailable'
            } else {
                $networkProtection=Convert-EffectivePolicyNetworkProtectionValue $networkProtectionProperty.Value
                if([string]::IsNullOrWhiteSpace([string]$networkProtection)){
                    Set-EffectivePolicyScopeState $result @(16) Malformed 'POLICY.DEFENDER_NETWORK_PROTECTION_MALFORMED'
                    $result.defenderNetworkProtection.state='Malformed'
                } else {
                    $result.defenderNetworkProtection.state='Complete'
                    $result.defenderNetworkProtection.value=[string]$networkProtection
                    Set-EffectivePolicyScopeState $result @(16) Complete ''
                }
            }
        } catch {
            $state=Get-WorkerAccessState $_
            Set-EffectivePolicyScopeState $result @(15,16) $state "POLICY.DEFENDER_$($state.ToUpperInvariant())"
            $result.defenderNetworkProtection.state=$state
            $result.defenderAsrRules=@()
        }
    }
    $smartScreenDefinitions=@(
        [ordered]@{scopeIndex=17;signalIndex=0;path='SOFTWARE\Policies\Microsoft\Windows\System';valueName='EnableSmartScreen';valueType='Boolean';reasonPrefix='POLICY.SMARTSCREEN_SHELL'},
        [ordered]@{scopeIndex=17;signalIndex=1;path='SOFTWARE\Policies\Microsoft\Windows\System';valueName='PreventOverrideForFilesInShell';valueType='Boolean';reasonPrefix='POLICY.SMARTSCREEN_SHELL'},
        [ordered]@{scopeIndex=18;signalIndex=2;path='SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen';valueName='ConfigureAppInstallControlEnabled';valueType='Integer';reasonPrefix='POLICY.SMARTSCREEN_APP_INSTALL'}
    )
    $smartScreenScopeState=@{17=@();18=@()}
    foreach($definition in $smartScreenDefinitions){
        try {
            $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey([string]$definition.path,$false)
            try {$rawValue=if($null -eq $key){$null}else{$key.GetValue([string]$definition.valueName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}}finally{if($null -ne $key){$key.Dispose()}}
            if($null -eq $rawValue){
                $result.smartScreenSignals[$definition.signalIndex].state='Unavailable'
                $smartScreenScopeState[$definition.scopeIndex]+=,[ordered]@{state='Unavailable';reasonCode="$($definition.reasonPrefix)_UNAVAILABLE"}
                continue
            }
            $normalizedValue = if([string]$definition.valueType -eq 'Boolean'){
                Convert-EffectivePolicyRegistryBooleanValue -Value $rawValue
            } else {
                Convert-EffectivePolicyRegistryUnsignedIntegerValue -Value $rawValue -Maximum 3
            }
            if($null -eq $normalizedValue){
                $result.smartScreenSignals[$definition.signalIndex].state='Malformed'
                $smartScreenScopeState[$definition.scopeIndex]+=,[ordered]@{state='Malformed';reasonCode="$($definition.reasonPrefix)_MALFORMED"}
                continue
            }
            $result.smartScreenSignals[$definition.signalIndex].state='Complete'
            $result.smartScreenSignals[$definition.signalIndex].value=$normalizedValue
            $smartScreenScopeState[$definition.scopeIndex]+=,[ordered]@{state='Complete';reasonCode=''}
        } catch {
            $state=Get-WorkerAccessState $_
            $result.smartScreenSignals[$definition.signalIndex].state=$state
            $smartScreenScopeState[$definition.scopeIndex]+=,[ordered]@{state=$state;reasonCode="$($definition.reasonPrefix)_$($state.ToUpperInvariant())"}
        }
    }
    foreach($scopeIndex in @(17,18)){
        $entries=@($smartScreenScopeState[$scopeIndex])
        if(@($entries|Where-Object state -eq 'Complete').Count -eq $entries.Count){
            Set-EffectivePolicyScopeState $result @($scopeIndex) Complete ''
        } elseif(@($entries|Select-Object -ExpandProperty state -Unique).Count -eq 1){
            Set-EffectivePolicyScopeState $result @($scopeIndex) ([string]$entries[0].state) ([string]$entries[0].reasonCode)
        } else {
            Set-EffectivePolicyScopeState $result @($scopeIndex) Partial 'POLICY.SMARTSCREEN_INCOMPLETE'
        }
    }
    # Windows Security Center is the supported provider-registration seam.
    # Names alone are not trusted because an installed product can remain
    # registered after removal or coexist with Defender in passive mode. The
    # worker therefore reads product names from the WSC registration list and
    # category health from WscGetSecurityProviderHealth(). Windows exposes
    # those as separate seams: one says which providers are registered, the
    # other says how the category is doing overall. The worker keeps them
    # separate and repeats only the category health onto each bounded provider
    # subject so the protected record can compare names and category state
    # without inventing a per-product winner from ambiguous registrations.
    foreach($providerDefinition in @(
        [ordered]@{providerValue=4;scopeIndex=19;reasonPrefix='POLICY.SECURITY_CENTER_ANTIVIRUS';property='antivirusProviders'},
        [ordered]@{providerValue=1;scopeIndex=20;reasonPrefix='POLICY.SECURITY_CENTER_FIREWALL';property='firewallProviders'}
    )){
        try {
            $health=[WinPCInfoEffectivePolicyNativeSource]::ReadSecurityProviderHealth([uint32]$providerDefinition.providerValue)
            $productList=New-Object -ComObject 'WSCProductList'
            $null=$productList.Initialize([int]$providerDefinition.providerValue)
            $providers=@()
            for($index=0;$index -lt [Math]::Min([int]$productList.Count,4);$index++){
                $product=$productList.Item($index)
                $name=[string]$product.ProductName
                if([string]::IsNullOrWhiteSpace($name)){
                    throw 'A Security Center provider property was missing or malformed.'
                }
                $providers+=,[ordered]@{name=$name;health=[string]$health}
            }
            $result.($providerDefinition.property)=@($providers)
            if([int]$productList.Count -gt 4){
                Set-EffectivePolicyScopeState $result @($providerDefinition.scopeIndex) Partial "$($providerDefinition.reasonPrefix)_EVIDENCE_BOUND_EXCEEDED"
            } elseif(@($providers).Count -gt 1){
                Set-EffectivePolicyScopeState $result @($providerDefinition.scopeIndex) Partial 'POLICY.SECURITY_PROVIDER_MULTIPLE_REGISTRATIONS'
            } else {
                Set-EffectivePolicyScopeState $result @($providerDefinition.scopeIndex) Complete ''
            }
        } catch {
            $state=Get-WorkerAccessState $_
            $result.($providerDefinition.property)=@()
            Set-EffectivePolicyScopeState $result @($providerDefinition.scopeIndex) $state "$($providerDefinition.reasonPrefix)_$($state.ToUpperInvariant())"
        }
    }
    $computerStatusCommand=Get-Command Get-MpComputerStatus -CommandType Cmdlet -ErrorAction SilentlyContinue
    if($null -eq $computerStatusCommand){
        Set-EffectivePolicyScopeState $result @(21) Unsupported 'POLICY.DEFENDER_MODULE_UNAVAILABLE'
    } else {
        # Defender runtime is separate from Defender preferences on purpose.
        # Runtime answers "what is active now" while preferences answer
        # "what mode was configured". The worker keeps those channels separate
        # so passive mode, disabled protection, or tamper constraints are not
        # silently rewritten into intended policy. Missing runtime properties
        # degrade coverage to Partial instead of guessing a safe-looking default.
        try {
            $status=& $computerStatusCommand -ErrorAction Stop
            $runtimeMissingProperty=$false
            $runningMode=$status.PSObject.Properties['AMRunningMode']
            if($null -eq $runningMode -or [string]::IsNullOrWhiteSpace([string]$runningMode.Value)){
                $runtimeMissingProperty=$true
            } else {
                $result.defenderRuntime.runningMode=[string]$runningMode.Value
            }
            foreach($mapping in @(
                [ordered]@{propertyName='AntivirusEnabled';target='antivirusEnabled'},
                [ordered]@{propertyName='RealTimeProtectionEnabled';target='realTimeProtectionEnabled'},
                [ordered]@{propertyName='IsTamperProtected';target='tamperProtected'}
            )){
                $property=$status.PSObject.Properties[[string]$mapping.propertyName]
                if($null -eq $property){
                    $runtimeMissingProperty=$true
                    continue
                }
                $value=$property.Value
                if($null -ne $value -and $value -isnot [bool]){
                    throw 'A Defender runtime property was malformed.'
                }
                $result.defenderRuntime.([string]$mapping.target)=$value
            }
            if($runtimeMissingProperty){
                Set-EffectivePolicyScopeState $result @(21) Partial 'POLICY.DEFENDER_PROPERTY_UNAVAILABLE'
            } else {
                Set-EffectivePolicyScopeState $result @(21) Complete ''
            }
        } catch {
            $state=Get-WorkerAccessState $_
            Set-EffectivePolicyScopeState $result @(21) $state "POLICY.DEFENDER_RUNTIME_$($state.ToUpperInvariant())"
        }
    }
    $firewallCommand=Get-Command Get-NetFirewallProfile -CommandType Cmdlet -ErrorAction SilentlyContinue
    if($null -eq $firewallCommand){
        Set-EffectivePolicyScopeState $result @(22,23,24) Unsupported 'POLICY.FIREWALL_MODULE_UNAVAILABLE'
    } else {
        # ActiveStore is the firewall "what actually applies now" seam. It
        # already merges local and policy-backed sources, so the worker does
        # not inspect rules, enumerate interfaces, or infer current state from
        # static registry policy. Missing or duplicated profiles become typed
        # gaps rather than optimistic defaults.
        try {
            $profiles=@(& $firewallCommand -PolicyStore ActiveStore -ErrorAction Stop)
            foreach($mapping in @(
                [ordered]@{name='Domain';scopeIndex=22;property='domain'},
                [ordered]@{name='Private';scopeIndex=23;property='private'},
                [ordered]@{name='Public';scopeIndex=24;property='public'}
            )){
                $matching=@($profiles|Where-Object { [string]$_.Name -eq [string]$mapping.name })
                if($matching.Count -eq 0){
                    $result.firewallProfiles.([string]$mapping.property).state='Unavailable'
                    Set-EffectivePolicyScopeState $result @($mapping.scopeIndex) Unavailable 'POLICY.FIREWALL_PROFILE_UNAVAILABLE'
                    continue
                }
                if($matching.Count -gt 1){
                    $result.firewallProfiles.([string]$mapping.property).state='Unavailable'
                    Set-EffectivePolicyScopeState $result @($mapping.scopeIndex) Partial 'POLICY.FIREWALL_PROFILE_AMBIGUOUS'
                    continue
                }
                $profile=$matching[0]
                $enabled=Convert-EffectivePolicyFirewallEnabled $profile.Enabled
                $inbound=Convert-EffectivePolicyFirewallAction $profile.DefaultInboundAction
                $outbound=Convert-EffectivePolicyFirewallAction $profile.DefaultOutboundAction
                if($null -eq $enabled -or [string]::IsNullOrWhiteSpace([string]$inbound) -or
                    [string]::IsNullOrWhiteSpace([string]$outbound)){
                    $result.firewallProfiles.([string]$mapping.property).state='Malformed'
                    Set-EffectivePolicyScopeState $result @($mapping.scopeIndex) Malformed 'POLICY.FIREWALL_PROFILE_MALFORMED'
                    continue
                }
                $result.firewallProfiles.([string]$mapping.property)=[ordered]@{
                    state='Complete';enabled=$enabled
                    defaultInboundAction=[string]$inbound
                    defaultOutboundAction=[string]$outbound
                }
                Set-EffectivePolicyScopeState $result @($mapping.scopeIndex) Complete ''
            }
        } catch {
            $state=Get-WorkerAccessState $_
            foreach($mapping in @(
                [ordered]@{scopeIndex=22;property='domain'},
                [ordered]@{scopeIndex=23;property='private'},
                [ordered]@{scopeIndex=24;property='public'}
            )){
                $result.firewallProfiles.([string]$mapping.property).state=$state
                Set-EffectivePolicyScopeState $result @($mapping.scopeIndex) $state "POLICY.FIREWALL_PROFILE_$($state.ToUpperInvariant())"
            }
        }
    }
    $groups=$result.policySettings|Group-Object target,settingId
    $result.appliedOrderConflict=@($groups|Where-Object {@($_.Group.objectId|Select-Object -Unique).Count -gt 1}).Count -gt 0
    Complete-EffectivePolicyLayerStates $result
}

$maximumBytes = [int] $configuration.maximumBytes
$deadline = [int] $configuration.deadlineMilliseconds
$tokenSource = [System.Threading.CancellationTokenSource]::new($deadline)
$pipe = $null
$assessmentUserSid = ''
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
            $names.Count -ne 6 -or @($names | Sort-Object -Unique).Count -ne 6 -or
            $root.GetProperty('kind').GetString() -ne 'ExecutePlan' -or
            $root.GetProperty('contractVersion').GetString() -ne '1.0.0' -or
            $root.GetProperty('nonce').GetString() -ne $configuration.nonce -or
            $root.GetProperty('planDigest').GetString() -ne $configuration.planDigest -or
            $null -eq $root.GetProperty('assessmentUserSid').GetString() -or
            ($root.GetProperty('assessmentUserSid').GetString().Length -gt 0 -and
                -not (Test-PrivilegedCollectionSid $root.GetProperty('assessmentUserSid').GetString()))) {
            throw 'The privilege request envelope is invalid.'
        }
        $assessmentUserSid=$root.GetProperty('assessmentUserSid').GetString()
        $allowed = @(
            'observe-firmware-tpm', 'observe-local-administrators',
            'observe-effective-policy'
        )
        $operations = @($root.GetProperty('operations').EnumerateArray())
        if ($operations.Count -ne 3) { throw 'The privileged operation set is incomplete.' }
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
            'observe-effective-policy'
        ) | ForEach-Object { [ordered]@{ operationId = $_; state = 'Completed'; phaseId = $phaseId } }
    }
    if ([string]$configuration.firmwareScenario -ne 'None') {
        $resultBody.firmwareTpm = if ([string]$configuration.firmwareScenario -eq 'Live') {
            Get-LiveFirmwareResult
        } else { New-SyntheticFirmwareResult -Scenario ([string]$configuration.firmwareScenario) }
    }
    if ([string]$configuration.administratorScenario -ne 'None') {
        $resultBody.administratorExposure = if ([string]$configuration.administratorScenario -eq 'Live') {
            Get-LiveAdministratorResult
        } else { New-SyntheticAdministratorResult -Scenario ([string]$configuration.administratorScenario) }
    }
    if ([string]$configuration.effectivePolicyScenario -ne 'None') {
        $resultBody.effectivePolicy = if ([string]$configuration.effectivePolicyScenario -eq 'Live') {
            Get-LiveEffectivePolicyResult -AssessmentUserSid $assessmentUserSid
        } else { New-SyntheticEffectivePolicyResult -Scenario ([string]$configuration.effectivePolicyScenario) }
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

    # The reviewed template keeps explanatory comments and indentation for
    # humans. The launched representation removes only whole comment lines,
    # blank lines, and surrounding indentation before compression. It never
    # rewrites tokens or strings. This preserves the reviewed behavior while
    # keeping the fixed in-memory payload under Windows' command-line ceiling.
    $launchLines = @($Source -split "`r?`n" | Where-Object {
        $_ -notmatch '^\s*(?:#|//)' -and -not [string]::IsNullOrWhiteSpace($_)
    } | ForEach-Object { $_.Trim() })
    $launchSource = $launchLines -join "`n"
    $sourceBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($launchSource)
    $compressedStream = [System.IO.MemoryStream]::new()
    try {
        $compressor = [System.IO.Compression.BrotliStream]::new(
            $compressedStream, [System.IO.Compression.CompressionLevel]::SmallestSize, $true
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
`$b=[Convert]::FromBase64String('$compressedBase64');`$m=[IO.MemoryStream]::new([byte[]]`$b);`$g=[IO.Compression.BrotliStream]::new(`$m,[IO.Compression.CompressionMode]::Decompress);`$r=[IO.StreamReader]::new(`$g,[Text.UTF8Encoding]::new(`$false,`$true));try{&([scriptblock]::Create(`$r.ReadToEnd()))}finally{`$r.Dispose();`$g.Dispose();`$m.Dispose()}
"@.Trim()
    $encoded = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($bootstrap)
    )
    # Leave more than 250 characters for the executable and fixed switches
    # under Windows' 32,767-character process-command-line ceiling.
    if ($encoded.Length -gt 32500) {
        throw 'The reviewed privilege bootstrap exceeds the Windows launch bound.'
    }
    $encoded
}

function ConvertTo-PrivilegedCollectionInlineCommand {
    param([Parameter(Mandatory)] [string] $Source)

    $launchLines = @($Source -split "`r?`n" | Where-Object {
        $_ -notmatch '^\s*(?:#|//)' -and -not [string]::IsNullOrWhiteSpace($_)
    } | ForEach-Object { $_.Trim() })
    $sourceBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($launchLines -join "`n")
    )
    $compressedStream = [System.IO.MemoryStream]::new()
    try {
        $compressor = [System.IO.Compression.BrotliStream]::new(
            $compressedStream, [System.IO.Compression.CompressionLevel]::SmallestSize, $true
        )
        try { $compressor.Write($sourceBytes, 0, $sourceBytes.Length) }
        finally { $compressor.Dispose() }
        $compressedBase64 = [System.Convert]::ToBase64String($compressedStream.ToArray())
    }
    finally { $compressedStream.Dispose() }
    # ArgumentList passes this fixed command directly to pwsh; no command shell
    # interprets it. Avoiding a second UTF-16/base64 expansion preserves the
    # in-memory boundary and remains well below Windows' command-line ceiling.
    $inlineCommand="`$b=[Convert]::FromBase64String('$compressedBase64');`$m=[IO.MemoryStream]::new([byte[]]`$b);`$g=[IO.Compression.BrotliStream]::new(`$m,[IO.Compression.CompressionMode]::Decompress);`$r=[IO.StreamReader]::new(`$g,[Text.UTF8Encoding]::new(`$false,`$true));try{&([scriptblock]::Create(`$r.ReadToEnd()))}finally{`$r.Dispose();`$g.Dispose();`$m.Dispose()}"
    if ($inlineCommand.Length -gt 32500) {
        throw 'The reviewed privilege worker exceeds the Windows launch bound.'
    }
    $inlineCommand
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
        [Parameter()] $PrivateFirmwareCollectorResult,
        [Parameter()] $PrivateAdministratorCollectorResult,
        [Parameter()] $PrivateEffectivePolicyCollectorResult
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
            assessmentEvidenceCrossed = $null -ne $PrivateFirmwareCollectorResult -or
                $null -ne $PrivateAdministratorCollectorResult -or
                $null -ne $PrivateEffectivePolicyCollectorResult
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
    if ($null -ne $PrivateAdministratorCollectorResult) {
        # Principal identities and direct relationships remain an in-memory
        # Restricted handoff. The public phase result never serializes them.
        $result.PrivateAdministratorCollectorResult = $PrivateAdministratorCollectorResult
    }
    if ($null -ne $PrivateEffectivePolicyCollectorResult) {
        # Policy-object, registry, and rights details are Restricted evidence.
        # Only the orchestrator receives this closed private handoff; the public
        # phase record above contains no identity, link, SID, or setting value.
        $result.PrivateEffectivePolicyCollectorResult = $PrivateEffectivePolicyCollectorResult
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
        [AllowEmptyString()] [ValidateScript({
            [string]::IsNullOrEmpty($_) -or (Test-PrivilegedCollectionSid $_)
        })] [string] $AssessmentUserSid = '',
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
        [Parameter()]
        [ValidateSet(
            'None','Live','LocalPrincipal','DomainPrincipal','NestedGroup','UnresolvedSid',
            'DuplicateMembership','AlternateAdministrator','Denied','Partial','NonEnglish',
            'ElevationDenied'
        )]
        [string] $AdministratorScenario = 'None',
        [Parameter()]
        [ValidateSet(
            'None','Live','Workgroup','Domain','UserAndComputerRsop','MissingRsop',
            'StaleRegistry','DeniedAdministrator','DeniedSystem','NonEnglish',
            'AppliedOrderConflict','AccountLockout','AuditPolicy','UserRights',
            'SecurityOptions','PartialChannel','NonMdm','UnsupportedMdmBuild',
            'MissingMdmClass','MissingMdmProperty','MdmPolicyConflict',
            'MdmWinsOverGpScoped','WindowsUpdatePolicy','RemoteManagementCombinations',
            'SmbPosture','LegacyAuthMasks','ThirdPartyRegistration','DefenderDisabled',
            'DefenderUnavailable','AmbiguousSecurityCenter','TamperProtected',
            'MissingDefenderProperty','FirewallProfiles','AsrRulePairs',
            'BitLockerEncrypted','BitLockerUnencrypted','BitLockerUnknown',
            'VbsCredentialGuardRunning','VbsConfiguredNotRunning',
            'WdacWindows11Policies','WdacWindows10Unsupported',
            'AppLockerGpOnly','AppLockerCspOnly','AppLockerGpCspConflict',
            'AppLockerChannelIncomplete','VirtualMachineSecurity'
        )]
        [string] $EffectivePolicyScenario = 'None',
        [Parameter()] [System.Threading.CancellationToken] $CancellationToken =
            [System.Threading.CancellationToken]::None
    )

    $policy = Get-PrivilegedCollectionPlanPolicy
    $scenario = Get-PrivilegedCollectionValidationScenario -Name $ValidationScenario
    if (($ValidationScenario -eq 'Live' -and (
            $FirmwareScenario -notin @('None','Live') -or
            $AdministratorScenario -notin @('None','Live') -or
            $EffectivePolicyScenario -notin @('None','Live'))) -or
        ($ValidationScenario -ne 'Live' -and (
            $FirmwareScenario -eq 'Live' -or $AdministratorScenario -eq 'Live' -or
            $EffectivePolicyScenario -eq 'Live'))) {
        throw 'Live and synthetic privileged collection boundaries cannot be mixed.'
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
    $administratorOperationStartedAt = [DateTimeOffset]::UtcNow
    $effectivePolicyOperationStartedAt = [DateTimeOffset]::UtcNow
    $privateFirmwareCollectorResult = $null
    $privateAdministratorCollectorResult = $null
    $privateEffectivePolicyCollectorResult = $null
    try {
        $failureStage = 'CREATE_JOB'
        $ownedJob = [WinPCInfo.PrivilegedCollectionPlan.OwnedJob]::Create(
            $jobName, "D:P(A;;GA;;;$initiatingSid)(A;;GA;;;BA)"
        )
        $failureStage = 'CREATE_PIPE'
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
            administratorScenario = $AdministratorScenario
            effectivePolicyScenario = $EffectivePolicyScenario
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
        # the fixed inline command, so neither a path nor a writable script can be swapped
        # between identity validation and process creation.
        if ($workerSource.IndexOf('__PRIVILEGED_WORKER_CONFIGURATION__') -ne
            $workerSource.LastIndexOf('__PRIVILEGED_WORKER_CONFIGURATION__')) {
            throw 'The privilege worker template contains an ambiguous configuration marker.'
        }
        $launchWorkerSource = $workerSource.Replace(
            '__PRIVILEGED_WORKER_CONFIGURATION__', $encodedConfiguration
        )
        $failureStage = 'ENCODE_WORKER'
        $inlineWorker = ConvertTo-PrivilegedCollectionInlineCommand -Source $launchWorkerSource
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
            '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $inlineWorker
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
            assessmentUserSid = $AssessmentUserSid
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
        $expectedResultNames = @('kind','contractVersion','nonce','planDigest','phaseId','operations')
        if ($FirmwareScenario -ne 'None') { $expectedResultNames += 'firmwareTpm' }
        if ($AdministratorScenario -ne 'None') { $expectedResultNames += 'administratorExposure' }
        if ($EffectivePolicyScenario -ne 'None') { $expectedResultNames += 'effectivePolicy' }
        if ($resultNames.Count -ne $expectedResultNames.Count -or
            (@($resultNames | Sort-Object) -join '|') -ne
                (@($expectedResultNames | Sort-Object) -join '|') -or
            $workerResult.kind -ne 'PlanResult' -or
            $workerResult.contractVersion -ne '1.0.0' -or
            $workerResult.nonce -ne $nonce -or $workerResult.planDigest -ne $PlanDigest -or
            [string]::IsNullOrWhiteSpace([string] $workerResult.phaseId) -or
            @($workerResult.operations).Count -ne 3) {
            throw 'The privilege worker result failed its closed schema.'
        }
        for ($index = 0; $index -lt 3; $index++) {
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
        if ($AdministratorScenario -ne 'None') {
            $administratorBytes=[Text.Encoding]::UTF8.GetByteCount(
                ($workerResult.administratorExposure|ConvertTo-Json -Compress -Depth 8)
            )
            $administratorPolicy=Get-AdministratorExposurePolicy `
                -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
            if($administratorBytes -gt [int]$administratorPolicy.collectors[0].resultMaximumUtf8Bytes -or
                -not (Test-AdministratorExposureCollectorPayload `
                    -Payload $workerResult.administratorExposure -Policy $administratorPolicy)){
                throw 'The privileged administrator projection failed its closed evidence contract.'
            }
            $memberCopies=@($workerResult.administratorExposure.directMembers|ForEach-Object {
                [pscustomobject][ordered]@{
                    sid=[string]$_.sid;accountName=$_.accountName
                    principalKind=[string]$_.principalKind;origin=[string]$_.origin
                }
            })
            $privateAdministratorCollectorResult=[pscustomobject][ordered]@{
                state='Completed';reasonCode='ADMINISTRATOR_EXPOSURE.COLLECTION_COMPLETED'
                validationScenario=$AdministratorScenario;validationFixture=[bool]$validationFixture
                processRelationship=[string]$workerRelationship
                assessmentUserContext=$AssessmentUserContext
                localPackageProtector=$LocalPackageProtector;membershipSemantics='DirectMembersOnly'
                envelope=[pscustomobject][ordered]@{
                    startedAt=$administratorOperationStartedAt.ToString('o')
                    completedAt=[DateTimeOffset]::UtcNow.ToString('o');attempts=1
                    executionContext=if($validationFixture){'Synthetic'}else{'Administrator'}
                }
                payload=[pscustomobject][ordered]@{
                    sourceLocale=[string]$workerResult.administratorExposure.sourceLocale
                    groupSid=[string]$workerResult.administratorExposure.groupSid
                    enumerationState=[string]$workerResult.administratorExposure.enumerationState
                    enumerationComplete=[bool]$workerResult.administratorExposure.enumerationComplete
                    directMembers=$memberCopies
                    sourceReturnedEntries=[int]$workerResult.administratorExposure.sourceReturnedEntries
                    duplicateEntriesRemoved=[int]$workerResult.administratorExposure.duplicateEntriesRemoved
                    limitation=[string]$workerResult.administratorExposure.limitation
                }
            }
        }
        if ($EffectivePolicyScenario -ne 'None') {
            $effectivePolicyDefinition=Get-EffectivePolicyPolicy `
                -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
            $effectivePolicyPayload=if($validationFixture){
                if([string]$workerResult.effectivePolicy.validationScenario -ne $EffectivePolicyScenario){
                    throw 'The privilege worker returned the wrong Effective Policy validation marker.'
                }
                New-EffectivePolicySyntheticPayload -Policy $effectivePolicyDefinition `
                    -Scenario $EffectivePolicyScenario
            } else {$workerResult.effectivePolicy}
            $effectivePolicyBytes=[Text.Encoding]::UTF8.GetByteCount(
                ($effectivePolicyPayload|ConvertTo-Json -Compress -Depth 12)
            )
            if($effectivePolicyBytes -gt [int]$effectivePolicyDefinition.collectors[0].resultMaximumUtf8Bytes -or
                -not (Test-EffectivePolicyCollectorPayload -Payload $effectivePolicyPayload `
                    -Policy $effectivePolicyDefinition)){
                throw 'The privileged Effective Policy projection failed its closed evidence contract.'
            }
            # Re-project every nested collection. A future JSON parser or worker
            # change therefore cannot smuggle an undeclared property across the
            # privilege boundary even when the outer frame remains well-formed.
            $payloadCopy=Copy-EffectivePolicyCollectorPayload -Payload $effectivePolicyPayload `
                -Policy $effectivePolicyDefinition
            $privateEffectivePolicyCollectorResult=[pscustomobject][ordered]@{
                state='Completed';reasonCode='EFFECTIVE_POLICY.COLLECTION_COMPLETED'
                validationScenario=$EffectivePolicyScenario;validationFixture=[bool]$validationFixture
                envelope=[pscustomobject][ordered]@{
                    startedAt=$effectivePolicyOperationStartedAt.ToString('o')
                    completedAt=[DateTimeOffset]::UtcNow.ToString('o');attempts=1
                    executionContext=if($validationFixture){'Synthetic'}else{'Administrator'}
                }
                payload=$payloadCopy
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
        -PrivateFirmwareCollectorResult $privateFirmwareCollectorResult `
        -PrivateAdministratorCollectorResult $privateAdministratorCollectorResult `
        -PrivateEffectivePolicyCollectorResult $privateEffectivePolicyCollectorResult
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
