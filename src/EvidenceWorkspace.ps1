$script:EvidenceWorkspacePolicyBase64 = '__EVIDENCE_WORKSPACE_POLICY_BASE64__'
$script:EvidenceWorkspacePolicyDigest = '__EVIDENCE_WORKSPACE_POLICY_SHA256__'
$script:RunRecoveryJournalSchemaBase64 = '__RUN_RECOVERY_JOURNAL_SCHEMA_BASE64__'
$script:RunRecoveryJournalSchemaDigest = '__RUN_RECOVERY_JOURNAL_SCHEMA_SHA256__'

function Get-EvidenceWorkspaceSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-EvidenceWorkspacePolicy {
    $convertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $convertFromJsonCommand -or
        $convertFromJsonCommand.ModuleName -ne 'Microsoft.PowerShell.Utility') {
        throw 'The Evidence Workspace policy JSON command does not have built-in provenance.'
    }

    if ($script:EvidenceWorkspacePolicyBase64 -eq ('__EVIDENCE_WORKSPACE_' + 'POLICY_BASE64__')) {
        $repositoryRoot = Split-Path -Parent $PSScriptRoot
        $path = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-evidence-workspace.json'
        $text = [System.IO.File]::ReadAllText(
            $path, [System.Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text)
        $expectedDigest = Get-EvidenceWorkspaceSha256 -Bytes $bytes
    }
    else {
        $bytes = [System.Convert]::FromBase64String($script:EvidenceWorkspacePolicyBase64)
        $expectedDigest = $script:EvidenceWorkspacePolicyDigest
    }
    # The digest binds the release policy to the deterministic application
    # bytes and detects accidental or post-build mutation. It is not a trust
    # signature for an unsigned developer build; provenance still comes from
    # reviewed source and the repository signing/release process.
    if ((Get-EvidenceWorkspaceSha256 -Bytes $bytes) -ne $expectedDigest) {
        throw 'The embedded Evidence Workspace policy failed integrity validation.'
    }
    & $convertFromJsonCommand -InputObject (
        [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 30 -ErrorAction Stop
}

function Initialize-EvidenceWorkspaceNative {
    if ('WinPCInfo.EvidenceWorkspaceNative' -as [type]) { return }

    # Directory creation is the security boundary, so applying an ACL after an
    # ordinary CreateDirectory call is too late: another local identity could
    # enter during that gap. CreateDirectoryW accepts a self-relative Windows
    # security descriptor and applies it atomically to the new directory. The
    # descriptor is protected from inheritance, owned by the initiating user,
    # and grants access only to that user and LocalSystem. The trust assumption
    # is the Windows object manager and NTFS/ReFS ACL implementation; any native
    # conversion or creation failure stops before restricted evidence exists.
    $source = @'
using System;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace WinPCInfo
{
    public static class EvidenceWorkspaceNative
    {
        private static string ToExtendedPath(string path)
        {
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
            if (path.StartsWith(@"\\", StringComparison.Ordinal))
                return @"\\?\UNC\" + path.Substring(2);
            return @"\\?\" + path;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string stringSecurityDescriptor,
            uint stringSDRevision,
            out IntPtr securityDescriptor,
            out uint securityDescriptorSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateDirectoryW(
            string path,
            ref SECURITY_ATTRIBUTES securityAttributes);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint low;
            public uint high;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint fileAttributes;
            public FILETIME creationTime;
            public FILETIME lastAccessTime;
            public FILETIME lastWriteTime;
            public uint volumeSerialNumber;
            public uint fileSizeHigh;
            public uint fileSizeLow;
            public uint numberOfLinks;
            public uint fileIndexHigh;
            public uint fileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern SafeFileHandle CreateOwnedFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            IntPtr file,
            out BY_HANDLE_FILE_INFORMATION information);

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_DISPOSITION_INFO
        {
            [MarshalAs(UnmanagedType.Bool)] public bool deleteFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int fileInformationClass,
            ref FILE_DISPOSITION_INFO fileInformation,
            uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        public static void CreateRestrictedDirectory(string path, string initiatingUserSid)
        {
            string sddl = "O:" + initiatingUserSid + "G:" + initiatingUserSid
                + "D:P(A;OICI;FA;;;" + initiatingUserSid + ")(A;OICI;FA;;;SY)";
            IntPtr descriptor;
            uint descriptorSize;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, out descriptor, out descriptorSize))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES
                {
                    nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
                    lpSecurityDescriptor = descriptor,
                    bInheritHandle = false
                };
                if (!CreateDirectoryW(ToExtendedPath(path), ref attributes))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                LocalFree(descriptor);
            }
        }

        public static string GetFileSystemIdentity(string path)
        {
            const uint FILE_SHARE_READ = 1;
            const uint FILE_SHARE_WRITE = 2;
            const uint FILE_SHARE_DELETE = 4;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            IntPtr handle = CreateFileW(
                ToExtendedPath(path), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);
            if (handle == new IntPtr(-1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return information.volumeSerialNumber.ToString("x8") + ":"
                    + information.fileIndexHigh.ToString("x8") + ":"
                    + information.fileIndexLow.ToString("x8");
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        public static SafeFileHandle CreateOwnedWriteThroughFile(string path)
        {
            const uint GENERIC_WRITE = 0x40000000;
            const uint DELETE = 0x00010000;
            const uint FILE_SHARE_READ = 1;
            const uint CREATE_NEW = 1;
            const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;
            SafeFileHandle handle = CreateOwnedFileW(
                ToExtendedPath(path), GENERIC_WRITE | DELETE, FILE_SHARE_READ,
                IntPtr.Zero, CREATE_NEW, FILE_FLAG_WRITE_THROUGH, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error);
            }
            return handle;
        }

        public static string GetFileSystemIdentity(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
                throw new ArgumentException("The owned file handle is unavailable.", "handle");
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle.DangerousGetHandle(), out information))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return information.volumeSerialNumber.ToString("x8") + ":"
                + information.fileIndexHigh.ToString("x8") + ":"
                + information.fileIndexLow.ToString("x8");
        }

        public static void MarkOwnedFileForDeletion(SafeFileHandle handle)
        {
            FILE_DISPOSITION_INFO information = new FILE_DISPOSITION_INFO { deleteFile = true };
            if (!SetFileInformationByHandle(
                handle, 4, ref information,
                (uint)Marshal.SizeOf<FILE_DISPOSITION_INFO>()))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop | Out-Null
}

function Get-EvidenceWorkspaceFileSystemIdentity {
    param([Parameter(Mandatory)] [string] $LiteralPath)

    Initialize-EvidenceWorkspaceNative
    [WinPCInfo.EvidenceWorkspaceNative]::GetFileSystemIdentity(
        [System.IO.Path]::GetFullPath($LiteralPath)
    )
}

function Get-RunRecoveryJournalSchemaText {
    if ($script:RunRecoveryJournalSchemaBase64 -eq ('__RUN_RECOVERY_JOURNAL_' + 'SCHEMA_BASE64__')) {
        $repositoryRoot = Split-Path -Parent $PSScriptRoot
        $path = Join-Path $repositoryRoot 'schemas/run-recovery-journal.schema.json'
        $text = [System.IO.File]::ReadAllText(
            $path, [System.Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text)
        $expectedDigest = Get-EvidenceWorkspaceSha256 -Bytes $bytes
    }
    else {
        $bytes = [System.Convert]::FromBase64String($script:RunRecoveryJournalSchemaBase64)
        $expectedDigest = $script:RunRecoveryJournalSchemaDigest
    }
    if ((Get-EvidenceWorkspaceSha256 -Bytes $bytes) -ne $expectedDigest) {
        throw 'The embedded Run Recovery Journal schema failed integrity validation.'
    }
    [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
}

function Write-RunRecoveryJournal {
    param(
        [Parameter(Mandatory)] $Journal,
        [Parameter(Mandatory)] [string] $LiteralPath
    )

    $convertToJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    $testJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'Test-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $convertToJsonCommand -or $null -eq $testJsonCommand -or
        $convertToJsonCommand.ModuleName -ne 'Microsoft.PowerShell.Utility' -or
        $testJsonCommand.ModuleName -ne 'Microsoft.PowerShell.Utility') {
        throw 'The Run Recovery Journal JSON commands do not have built-in provenance.'
    }

    $json = & $convertToJsonCommand -InputObject $Journal -Compress -Depth 12 -ErrorAction Stop
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    $policy = Get-EvidenceWorkspacePolicy
    if ($bytes.Length -gt [int] $policy.journal.maximumUtf8Bytes -or
        -not (& $testJsonCommand -Json $json -Schema (Get-RunRecoveryJournalSchemaText) -ErrorAction Stop)) {
        throw 'The Run Recovery Journal violates its closed release contract.'
    }

    # A same-directory create-new file, durable flush, and atomic rename prevent
    # a power interruption from exposing a partially serialized journal. A
    # leftover .new file is a fixed run-owned name inside the protected journal
    # directory; failure leaves both versions for deliberate recovery rather
    # than guessing which bytes were committed.
    $temporaryPath = $LiteralPath + '.new'
    $stream = $null
    try {
        $stream = [System.IO.FileStream]::new(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        [System.IO.File]::Move($temporaryPath, $LiteralPath, $true)
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Read-RunRecoveryJournal {
    param([Parameter(Mandatory)] [string] $LiteralPath)

    $policy = Get-EvidenceWorkspacePolicy
    $bytes = [System.IO.File]::ReadAllBytes([System.IO.Path]::GetFullPath($LiteralPath))
    if ($bytes.Length -gt [int] $policy.journal.maximumUtf8Bytes) {
        throw 'The Run Recovery Journal exceeds its release byte bound.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $document = $null
    try {
        $document = [System.Text.Json.JsonDocument]::Parse($json)
        $lexicalReason = Get-JsonLexicalSafetyReason -Element $document.RootElement -Limits ([pscustomobject]@{
            maximumJsonDepth = 12
            maximumStringUtf8Bytes = 8192
            maximumSafeInteger = 9007199254740991
        })
        if ($lexicalReason) { throw "Journal lexical validation failed: $lexicalReason" }
    }
    finally {
        if ($null -ne $document) { $document.Dispose() }
    }

    $testJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'Test-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    $convertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $testJsonCommand -or $null -eq $convertFromJsonCommand -or
        -not (& $testJsonCommand -Json $json -Schema (Get-RunRecoveryJournalSchemaText) -ErrorAction Stop)) {
        throw 'The Run Recovery Journal violates its closed release contract.'
    }
    & $convertFromJsonCommand -InputObject $json -Depth 12 -ErrorAction Stop
}

function New-RunRecoveryJournal {
    param(
        [Parameter(Mandatory)] $Workspace,
        [Parameter(Mandatory)] [string] $RecoveryBasePath,
        [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{64}$')] [string] $PlanDigest,
        [Parameter(Mandatory)]
        [ValidateSet('Preparation', 'Collection', 'Packaging', 'Viewing', 'Cleanup', 'Terminal')]
        [string] $Phase,
        [Parameter()] [AllowNull()] [System.Diagnostics.Process] $OwnerProcess
    )

    if ($Workspace.state -ne 'Created' -or
        -not [System.IO.Directory]::Exists([string] $Workspace.workspacePath)) {
        throw 'A created Evidence Workspace is required before journal creation.'
    }
    $recoveryBase = [System.IO.Path]::GetFullPath($RecoveryBasePath)
    if (-not [System.IO.Directory]::Exists($recoveryBase)) {
        throw 'The recovery base must already exist.'
    }
    $runId = [guid]::Parse([string] $Workspace.runId)
    $policy = Get-EvidenceWorkspacePolicy
    $journalDirectory = Join-Path $recoveryBase (
        'WINPCInfo-Recovery-v1-' + $runId.ToString('D')
    )
    Initialize-EvidenceWorkspaceNative
    $initiatingSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    [WinPCInfo.EvidenceWorkspaceNative]::CreateRestrictedDirectory(
        $journalDirectory, $initiatingSid
    )
    $journalPath = Join-Path $journalDirectory ([string] $policy.journal.fileName)
    $disposeOwnerProcess = $false
    if ($null -eq $OwnerProcess) {
        $OwnerProcess = [System.Diagnostics.Process]::GetCurrentProcess()
        $disposeOwnerProcess = $true
    }
    try {
        $ownerStart = $OwnerProcess.StartTime.ToUniversalTime().ToString('O')
        $ownerProcessId = $OwnerProcess.Id
    }
    finally {
        if ($disposeOwnerProcess) { $OwnerProcess.Dispose() }
    }

    $journal = [pscustomobject][ordered]@{
        kind = [string] $policy.journal.kind
        contractVersion = [string] $policy.journal.contractVersion
        runId = $runId.ToString('D')
        planDigest = $PlanDigest
        phase = $Phase
        owner = [pscustomobject][ordered]@{
            processId = $ownerProcessId
            processStartUtc = $ownerStart
            initiatingUserSid = $initiatingSid
        }
        artifacts = @(
            [pscustomobject][ordered]@{
                artifactId = [guid]::NewGuid().ToString('D')
                kind = 'Workspace'
                path = [System.IO.Path]::GetFullPath([string] $Workspace.workspacePath)
                fileSystemIdentity = Get-EvidenceWorkspaceFileSystemIdentity `
                    -LiteralPath ([string] $Workspace.workspacePath)
                cleanupAction = 'RemoveWhenEmpty'
                finalized = $false
            }
        )
        systemTasks = @()
        cleanup = [pscustomobject][ordered]@{
            state = 'Pending'
            attempts = 0
            lastReasonCode = 'CLEANUP.NOT_STARTED'
        }
    }
    Write-RunRecoveryJournal -Journal $journal -LiteralPath $journalPath
    [pscustomobject][ordered]@{
        state = 'Created'
        reasonCode = 'RECOVERY.JOURNAL_CREATED'
        journalPath = $journalPath
        journalDirectory = $journalDirectory
    }
}

function Register-FinalizedEvidencePackage {
    param(
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [string] $LiteralPath
    )

    $journal = Read-RunRecoveryJournal -LiteralPath $JournalPath
    $workspace = @($journal.artifacts | Where-Object kind -eq 'Workspace')
    $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
    if ($workspace.Count -ne 1 -or
        -not [System.IO.File]::Exists($fullPath) -or
        -not (Test-EvidenceArtifactWithinWorkspace -ArtifactPath $fullPath `
            -WorkspacePath $workspace[0].path) -or
        ([System.IO.File]::GetAttributes($fullPath) -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'A finalized package must be a regular file inside the registered workspace.'
    }
    if (@($journal.artifacts | Where-Object kind -eq 'ProtectedEvidencePackage').Count -gt 0) {
        throw 'The release permits only one finalized Protected Evidence Package per run.'
    }
    $artifact = [pscustomobject][ordered]@{
        artifactId = [guid]::NewGuid().ToString('D')
        kind = 'ProtectedEvidencePackage'
        path = $fullPath
        fileSystemIdentity = Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $fullPath
        cleanupAction = 'Preserve'
        finalized = $true
    }
    $journal.artifacts = @($journal.artifacts) + $artifact
    Write-RunRecoveryJournal -Journal $journal -LiteralPath $JournalPath
    [pscustomobject][ordered]@{
        state = 'RegisteredForPreservation'
        reasonCode = 'RECOVERY.FINALIZED_PACKAGE_PRESERVED'
        artifactId = $artifact.artifactId
    }
}

function Test-EvidenceAccessBoundary {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] [string] $ExpectedOwnerSid
    )

    $getAclCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'Get-Acl', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $getAclCommand -or
        $getAclCommand.ModuleName -ne 'Microsoft.PowerShell.Security') {
        return $false
    }
    try {
        $acl = & $getAclCommand -LiteralPath $LiteralPath -ErrorAction Stop
        $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $actualSids = @($acl.Access | ForEach-Object {
            $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        } | Sort-Object -Unique)
        $allowedSids = @($ExpectedOwnerSid, 'S-1-5-18' | Sort-Object -Unique)
        $ownerSid -eq $ExpectedOwnerSid -and
            $acl.AreAccessRulesProtected -and
            ($actualSids -join '|') -eq ($allowedSids -join '|') -and
            @($acl.Access | Where-Object {
                $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow
            }).Count -eq 0
    }
    catch { $false }
}

function Get-RunRecoveryOwnerState {
    param([Parameter(Mandatory)] $Owner)

    # A PID alone is reusable, so the exact process start instant is part of
    # ownership. The Windows process table is the observation boundary. If it
    # cannot be inspected, Ambiguous deliberately forbids destructive cleanup.
    $process = $null
    try {
        $process = [System.Diagnostics.Process]::GetProcessById([int] $Owner.processId)
        $observedStart = $process.StartTime.ToUniversalTime()
        $recordedStart = if ($Owner.processStartUtc -is [System.DateTime]) {
            ([System.DateTime] $Owner.processStartUtc).ToUniversalTime()
        }
        elseif ($Owner.processStartUtc -is [System.DateTimeOffset]) {
            ([System.DateTimeOffset] $Owner.processStartUtc).UtcDateTime
        }
        else {
            [System.DateTimeOffset]::Parse(
                [string] $Owner.processStartUtc,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind
            ).UtcDateTime
        }
        if ($observedStart.Ticks -eq $recordedStart.Ticks) { 'Live' } else { 'Stale' }
    }
    catch [System.ArgumentException] { 'Stale' }
    catch [System.InvalidOperationException] { 'Stale' }
    catch { 'Ambiguous' }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function New-StaleRunRecoveryResult {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('NotStarted', 'CleanupIncomplete')]
        [string] $Outcome,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [bool] $CleanupVerified,
        [Parameter(Mandatory)] [int] $CleanupAttempts,
        [Parameter()] [bool] $WorkspacePreserved = $false
    )

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.stale-run-recovery'
        contractVersion = '1.0.0'
        outcome = $Outcome
        exitCode = if ($Outcome -eq 'CleanupIncomplete') { 60 } else { 20 }
        reasonCode = $ReasonCode
        collectionResumed = $false
        cleanup = [pscustomobject][ordered]@{
            verified = $CleanupVerified
            attempts = $CleanupAttempts
            workspacePreserved = $WorkspacePreserved
        }
        windowsFeatures = [pscustomobject][ordered]@{
            action = 'ObserveOnly'
            changesAttempted = $false
        }
        guidance = if ($ReasonCode -eq 'RECOVERY.LIVE_OWNER') {
            'Allow the active Assessment Run to finish, then retry deliberate recovery.'
        }
        elseif ($ReasonCode -eq 'RECOVERY.FINALIZED_PACKAGE_PRESERVED') {
            'Keep the finalized package protected. Move or finish handling it deliberately, then retry recovery so every registered object can be verified absent.'
        }
        elseif ($ReasonCode -eq 'RECOVERY.JOURNAL_WRITE_INTERRUPTED') {
            'Keep both protected journal files for deliberate local inspection. Resolve the interrupted journal write, then retry recovery without guessing which record is authoritative.'
        }
        elseif ($Outcome -eq 'CleanupIncomplete') {
            'Close software using the registered artifact, verify ownership, and retry deliberate recovery. Do not delete an ambiguous target.'
        }
        else {
            'Verified stale residue was handled without resuming collection. Start a new Assessment Run deliberately.'
        }
    }
}

function Set-RunRecoveryIncomplete {
    param(
        [Parameter(Mandatory)] $Journal,
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [int] $Attempts,
        [Parameter(Mandatory)] [string] $ReasonCode
    )

    $Journal.phase = 'Cleanup'
    $Journal.cleanup.state = 'Incomplete'
    $Journal.cleanup.attempts = $Attempts
    $Journal.cleanup.lastReasonCode = $ReasonCode
    try { Write-RunRecoveryJournal -Journal $Journal -LiteralPath $JournalPath }
    catch { }
}

function Invoke-StaleRunRecovery {
    param([Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(DontShow)] [switch] $CurrentRunCleanup,
        [Parameter()] [string] $ExpectedWorkspaceBase = '')

    $journalFullPath = [System.IO.Path]::GetFullPath($JournalPath)
    $pendingJournalPath = $journalFullPath + '.new'
    $journalDirectory = [System.IO.Path]::GetDirectoryName($journalFullPath)
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $policy = Get-EvidenceWorkspacePolicy
    $fixedJournalName = [System.IO.Path]::GetFileName($journalFullPath) -eq
        [string] $policy.journal.fileName
    $fixedDirectoryName = [System.IO.Path]::GetFileName($journalDirectory) -match
        '^WINPCInfo-Recovery-v1-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if (-not [System.IO.File]::Exists($journalFullPath) -and
        ([System.IO.File]::Exists($pendingJournalPath) -or
            [System.IO.Directory]::Exists($pendingJournalPath)) -and
        $fixedJournalName -and $fixedDirectoryName -and
        (Test-EvidenceAccessBoundary -LiteralPath $journalDirectory `
            -ExpectedOwnerSid $currentSid)) {
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.JOURNAL_WRITE_INTERRUPTED' `
            -CleanupVerified $false -CleanupAttempts 0
    }
    try { $journal = Read-RunRecoveryJournal -LiteralPath $journalFullPath }
    catch {
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.JOURNAL_INVALID' -CleanupVerified $false -CleanupAttempts 0
    }
    $expectedJournalDirectory = 'WINPCInfo-Recovery-v1-' + [string] $journal.runId
    if (-not $fixedJournalName -or $currentSid -ne [string] $journal.owner.initiatingUserSid -or
        [System.IO.Path]::GetFileName($journalDirectory) -ne $expectedJournalDirectory -or
        -not (Test-EvidenceAccessBoundary -LiteralPath $journalDirectory `
            -ExpectedOwnerSid ([string] $journal.owner.initiatingUserSid))) {
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.JOURNAL_OWNERSHIP_UNVERIFIED' `
            -CleanupVerified $false -CleanupAttempts 0
    }

    $ownerState = Get-RunRecoveryOwnerState -Owner $journal.owner
    $currentOwner = $CurrentRunCleanup -and (Test-RunRecoveryJournalCurrentOwner -Journal $journal)
    if ($CurrentRunCleanup -and -not $currentOwner) {
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.OWNER_UNVERIFIED' -CleanupVerified $false -CleanupAttempts 0
    }
    if ($ownerState -eq 'Live' -and -not $currentOwner) {
        return New-StaleRunRecoveryResult -Outcome 'NotStarted' `
            -ReasonCode 'RECOVERY.LIVE_OWNER' -CleanupVerified $false -CleanupAttempts 0
    }
    # Atomic journal updates intentionally use one fixed create-new sibling. If
    # it survived a crash, neither version can be guessed authoritative. Leave
    # both protected objects and all evidence untouched for deliberate review.
    if ([System.IO.File]::Exists($pendingJournalPath) -or
        [System.IO.Directory]::Exists($pendingJournalPath)) {
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.JOURNAL_WRITE_INTERRUPTED' `
            -CleanupVerified $false -CleanupAttempts 0
    }
    if ($ownerState -eq 'Ambiguous') {
        Set-RunRecoveryIncomplete -Journal $journal -JournalPath $journalFullPath `
            -Attempts 0 -ReasonCode 'RECOVERY.OWNER_UNVERIFIED'
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.OWNER_UNVERIFIED' -CleanupVerified $false -CleanupAttempts 0
    }

    $workspaceArtifacts = @($journal.artifacts | Where-Object kind -eq 'Workspace')
    if ($workspaceArtifacts.Count -ne 1) {
        Set-RunRecoveryIncomplete -Journal $journal -JournalPath $journalFullPath `
            -Attempts 0 -ReasonCode 'RECOVERY.OWNERSHIP_UNVERIFIED'
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.OWNERSHIP_UNVERIFIED' -CleanupVerified $false -CleanupAttempts 0
    }
    $workspace = $workspaceArtifacts[0]
    if ($ExpectedWorkspaceBase -and -not [string]::Equals(
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath([string]$workspace.path)),
        [IO.Path]::GetFullPath($ExpectedWorkspaceBase).TrimEnd([IO.Path]::DirectorySeparatorChar),
        [StringComparison]::OrdinalIgnoreCase)) {
        return New-StaleRunRecoveryResult -Outcome CleanupIncomplete -ReasonCode RECOVERY.OWNERSHIP_UNVERIFIED `
            -CleanupVerified $false -CleanupAttempts 0
    }
    $policy = Get-EvidenceWorkspacePolicy
    $expectedWorkspaceName = [string] $policy.workspace.directoryNamePrefix + [string] $journal.runId
    if ([System.IO.Path]::GetFileName([string] $workspace.path) -ne $expectedWorkspaceName) {
        Set-RunRecoveryIncomplete -Journal $journal -JournalPath $journalFullPath `
            -Attempts 0 -ReasonCode 'RECOVERY.OWNERSHIP_UNVERIFIED'
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.OWNERSHIP_UNVERIFIED' -CleanupVerified $false -CleanupAttempts 0
    }

    $ownershipVerified = $true
    if ([System.IO.Directory]::Exists([string] $workspace.path)) {
        $ownershipVerified = (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $workspace.path) -eq
            [string] $workspace.fileSystemIdentity -and
            (Test-EvidenceAccessBoundary -LiteralPath $workspace.path `
                -ExpectedOwnerSid ([string] $journal.owner.initiatingUserSid)) -and
            (([System.IO.File]::GetAttributes([string] $workspace.path) -band
                [System.IO.FileAttributes]::ReparsePoint) -eq 0)
    }
    foreach ($artifact in @($journal.artifacts | Where-Object kind -ne 'Workspace')) {
        if (-not (Test-EvidenceArtifactWithinWorkspace -ArtifactPath $artifact.path `
                -WorkspacePath $workspace.path)) {
            $ownershipVerified = $false
            break
        }
        $exists = [System.IO.File]::Exists([string] $artifact.path)
        if ($exists) {
            if (([System.IO.File]::GetAttributes([string] $artifact.path) -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $artifact.path) -ne
                    [string] $artifact.fileSystemIdentity) {
                $ownershipVerified = $false
                break
            }
        }
        # A missing Preserve registration means the operator already moved or
        # finished handling it. Recovery never deletes such an object; absence
        # merely permits cleanup of the now-empty registered workspace.
    }
    if (-not $ownershipVerified) {
        Set-RunRecoveryIncomplete -Journal $journal -JournalPath $journalFullPath `
            -Attempts 0 -ReasonCode 'RECOVERY.OWNERSHIP_UNVERIFIED'
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.OWNERSHIP_UNVERIFIED' -CleanupVerified $false -CleanupAttempts 0
    }

    if ($journal.PSObject.Properties['systemTasks'] -and @($journal.systemTasks).Count -gt 0 -and
        -not (Remove-RecoverySystemCollectionTasks -Journal $journal -JournalPath $journalFullPath)) {
        Set-RunRecoveryIncomplete -Journal $journal -JournalPath $journalFullPath -Attempts 1 -ReasonCode RECOVERY.SYSTEM_TASK_UNVERIFIED
        return New-StaleRunRecoveryResult -Outcome CleanupIncomplete -ReasonCode RECOVERY.SYSTEM_TASK_UNVERIFIED `
            -CleanupVerified $false -CleanupAttempts 1
    }
    $preservedPackages = @($journal.artifacts | Where-Object {
        $_.kind -eq 'ProtectedEvidencePackage' -and $_.cleanupAction -eq 'Preserve' -and $_.finalized
    } | Where-Object {
        [System.IO.File]::Exists([string] $_.path)
    })
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $cleanupSucceeded = $false
    $attempt = 0
    while ($attempt -lt [int] $policy.recovery.maximumCleanupAttempts -and
        $watch.ElapsedMilliseconds -lt [int] $policy.recovery.cleanupDeadlineMilliseconds) {
        $attempt++
        $journal.phase = 'Cleanup'
        $journal.cleanup.state = 'InProgress'
        $journal.cleanup.attempts = $attempt
        $journal.cleanup.lastReasonCode = 'CLEANUP.IN_PROGRESS'
        Write-RunRecoveryJournal -Journal $journal -LiteralPath $journalFullPath

        $attemptFailed = $false
        foreach ($artifact in @($journal.artifacts | Where-Object cleanupAction -eq 'Remove')) {
            try {
                if ([System.IO.File]::Exists([string] $artifact.path)) {
                    [System.IO.File]::Delete([string] $artifact.path)
                }
            }
            catch { $attemptFailed = $true }
            if ([System.IO.File]::Exists([string] $artifact.path)) { $attemptFailed = $true }
        }

        $temporaryDirectory = Join-Path ([string] $workspace.path) `
            ([string] $policy.temporaryEvidence.directoryName)
        try {
            if ([System.IO.Directory]::Exists($temporaryDirectory)) {
                if (([System.IO.File]::GetAttributes($temporaryDirectory) -band
                        [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    [System.IO.Directory]::EnumerateFileSystemEntries($temporaryDirectory).GetEnumerator().MoveNext()) {
                    $attemptFailed = $true
                }
                else { [System.IO.Directory]::Delete($temporaryDirectory, $false) }
            }
        }
        catch { $attemptFailed = $true }

        if ($preservedPackages.Count -eq 0) {
            try {
                if ([System.IO.Directory]::Exists([string] $workspace.path)) {
                    [System.IO.Directory]::Delete([string] $workspace.path, $false)
                }
            }
            catch { $attemptFailed = $true }
            if ([System.IO.Directory]::Exists([string] $workspace.path)) { $attemptFailed = $true }
        }
        else {
            foreach ($package in $preservedPackages) {
                if (-not [System.IO.File]::Exists([string] $package.path) -or
                    (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $package.path) -ne
                        [string] $package.fileSystemIdentity) {
                    $attemptFailed = $true
                }
            }
        }
        if (-not $attemptFailed) {
            $cleanupSucceeded = $true
            break
        }
    }
    $watch.Stop()

    if (-not $cleanupSucceeded) {
        Set-RunRecoveryIncomplete -Journal $journal -JournalPath $journalFullPath `
            -Attempts $attempt -ReasonCode 'RECOVERY.CLEANUP_FAILED'
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.CLEANUP_FAILED' -CleanupVerified $false `
            -CleanupAttempts $attempt -WorkspacePreserved ($preservedPackages.Count -gt 0)
    }

    # A finalized package is intentionally preserved, but it and its containing
    # workspace are still registered run-owned objects. Retaining the journal is
    # therefore the only honest terminal state until the operator deliberately
    # moves or consumes the package and retries cleanup.
    if ($preservedPackages.Count -gt 0) {
        Set-RunRecoveryIncomplete -Journal $journal -JournalPath $journalFullPath `
            -Attempts $attempt -ReasonCode 'RECOVERY.FINALIZED_PACKAGE_PRESERVED'
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.FINALIZED_PACKAGE_PRESERVED' `
            -CleanupVerified $false -CleanupAttempts $attempt -WorkspacePreserved $true
    }

    $journal.cleanup.state = 'Verified'
    $journal.cleanup.attempts = $attempt
    $journal.cleanup.lastReasonCode = 'CLEANUP.VERIFIED'
    Write-RunRecoveryJournal -Journal $journal -LiteralPath $journalFullPath
    try {
        [System.IO.File]::Delete($journalFullPath)
        if ([System.IO.File]::Exists($journalFullPath)) { throw 'Journal survived deletion.' }
        if ([System.IO.Directory]::EnumerateFileSystemEntries($journalDirectory).GetEnumerator().MoveNext()) {
            throw 'Journal directory contains an unexpected object.'
        }
        [System.IO.Directory]::Delete($journalDirectory, $false)
        if ([System.IO.Directory]::Exists($journalDirectory)) { throw 'Journal directory survived deletion.' }
    }
    catch {
        return New-StaleRunRecoveryResult -Outcome 'CleanupIncomplete' `
            -ReasonCode 'RECOVERY.JOURNAL_REMOVAL_UNVERIFIED' -CleanupVerified $false `
            -CleanupAttempts $attempt -WorkspacePreserved ($preservedPackages.Count -gt 0)
    }
    New-StaleRunRecoveryResult -Outcome 'NotStarted' `
        -ReasonCode 'RECOVERY.STALE_RESIDUE_REMOVED' -CleanupVerified $true `
        -CleanupAttempts $attempt -WorkspacePreserved ($preservedPackages.Count -gt 0)
}

function Invoke-AssessmentRecoveryGate {
    param([Parameter(Mandatory)] [string] $Destination, [Parameter(Mandatory)] [bool] $Authorized)
    if (-not [IO.Directory]::Exists($Destination)) {
        if ($Authorized) { return New-StaleRunRecoveryResult -Outcome NotStarted -ReasonCode RECOVERY.NO_RESIDUE -CleanupVerified $true -CleanupAttempts 0 }
        return
    }
    # Inspect only immediate, fixed-namespace entries in the approved destination.
    # Each journal still has to prove its ACL, owner, exact identities and paths.
    $paths = @(Get-ChildItem -LiteralPath $Destination -Filter 'WINPCInfo-Recovery-v1-*' -Directory -Force |
        Select-Object -First 33)
    if ($paths.Count -eq 0) {
        if ($Authorized) { return New-StaleRunRecoveryResult -Outcome NotStarted -ReasonCode RECOVERY.NO_RESIDUE -CleanupVerified $true -CleanupAttempts 0 }
        return
    }
    if (-not $Authorized) {
        return New-StaleRunRecoveryResult -Outcome NotStarted -ReasonCode RECOVERY.DELIBERATE_ACTION_REQUIRED `
            -CleanupVerified $false -CleanupAttempts 0
    }
    if ($paths.Count -gt 32) {
        return New-StaleRunRecoveryResult -Outcome CleanupIncomplete -ReasonCode RECOVERY.JOURNAL_LIMIT `
            -CleanupVerified $false -CleanupAttempts 0
    }
    foreach ($path in $paths) {
        if (($path.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return New-StaleRunRecoveryResult -Outcome CleanupIncomplete -ReasonCode RECOVERY.OWNERSHIP_UNVERIFIED `
                -CleanupVerified $false -CleanupAttempts 0
        }
        $result = Invoke-StaleRunRecovery -JournalPath (Join-Path $path.FullName 'run-recovery.json') -ExpectedWorkspaceBase $Destination
        if (-not $result.cleanup.verified) { return $result }
    }
    # Even successful recovery ends this invocation. A fresh approved run is required.
    $result
}

function Test-EvidenceArtifactWithinWorkspace {
    param(
        [Parameter(Mandatory)] [string] $ArtifactPath,
        [Parameter(Mandatory)] [string] $WorkspacePath
    )

    $artifactFullPath = [System.IO.Path]::GetFullPath($ArtifactPath)
    $workspaceFullPath = [System.IO.Path]::GetFullPath($WorkspacePath).TrimEnd('\')
    $artifactFullPath.Equals($workspaceFullPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        $artifactFullPath.StartsWith(
            $workspaceFullPath + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        )
}

function Test-RunRecoveryJournalCurrentOwner {
    param([Parameter(Mandatory)] $Journal)

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    [int] $Journal.owner.processId -eq [int] $PID -and
        [string] $Journal.owner.initiatingUserSid -eq $currentSid -and
        (Get-RunRecoveryOwnerState -Owner $Journal.owner) -eq 'Live'
}

function Get-OwnedEvidenceArtifactDefinition {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('TemporaryEvidence', 'EvidenceViewingArtifact')]
        [string] $Kind
    )

    $policy = Get-EvidenceWorkspacePolicy
    if ($Kind -eq 'TemporaryEvidence') {
        return [pscustomobject][ordered]@{
            kind = $Kind
            directoryName = [string] $policy.temporaryEvidence.directoryName
            extension = '.bin'
            maximumBytes = [int] $policy.temporaryEvidence.maximumArtifactBytes
            maximumCount = [int] $policy.temporaryEvidence.maximumArtifactCount
            sizeReasonCode = 'TEMPORARY_EVIDENCE.SIZE_EXCEEDED'
            ownerReasonCode = 'TEMPORARY_EVIDENCE.RUN_OWNER_MISMATCH'
            countReasonCode = 'TEMPORARY_EVIDENCE.COUNT_EXCEEDED'
            ownershipReasonCode = 'TEMPORARY_EVIDENCE.OWNERSHIP_UNVERIFIED'
            registeredReasonCode = 'TEMPORARY_EVIDENCE.REGISTERED'
        }
    }
    [pscustomobject][ordered]@{
        kind = $Kind
        directoryName = 'evidence-viewing'
        extension = '.view'
        maximumBytes = [int] $policy.temporaryEvidence.maximumArtifactBytes
        maximumCount = 1
        sizeReasonCode = 'VIEWING.ARTIFACT_SIZE_EXCEEDED'
        ownerReasonCode = 'VIEWING.RUN_OWNER_MISMATCH'
        countReasonCode = 'VIEWING.ARTIFACT_COUNT_EXCEEDED'
        ownershipReasonCode = 'VIEWING.ARTIFACT_OWNERSHIP_UNVERIFIED'
        registeredReasonCode = 'VIEWING.ARTIFACT_REGISTERED'
    }
}

function New-EvidenceWorkspaceOwnedWriteStream {
    param([Parameter(Mandatory)] [string] $LiteralPath)

    Initialize-EvidenceWorkspaceNative
    $handle = [WinPCInfo.EvidenceWorkspaceNative]::CreateOwnedWriteThroughFile(
        [System.IO.Path]::GetFullPath($LiteralPath)
    )
    try {
        [System.IO.FileStream]::new($handle, [System.IO.FileAccess]::Write, 4096, $false)
    }
    catch {
        try { [WinPCInfo.EvidenceWorkspaceNative]::MarkOwnedFileForDeletion($handle) }
        finally { $handle.Dispose() }
        throw
    }
}

function Get-EvidenceWorkspaceOwnedStreamIdentity {
    param([Parameter(Mandatory)] [System.IO.FileStream] $Stream)

    Initialize-EvidenceWorkspaceNative
    [WinPCInfo.EvidenceWorkspaceNative]::GetFileSystemIdentity($Stream.SafeFileHandle)
}

function Remove-EvidenceWorkspaceOwnedStreamOnClose {
    param([Parameter(Mandatory)] [System.IO.FileStream] $Stream)

    Initialize-EvidenceWorkspaceNative
    [WinPCInfo.EvidenceWorkspaceNative]::MarkOwnedFileForDeletion($Stream.SafeFileHandle)
}

function New-RegisteredEvidenceArtifact {
    param(
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [int] $ExpectedContentLength,
        [Parameter(Mandatory)]
        [ValidateSet('TemporaryEvidence', 'EvidenceViewingArtifact')]
        [string] $Kind
    )

    $definition = Get-OwnedEvidenceArtifactDefinition -Kind $Kind
    if ($ExpectedContentLength -lt 0 -or
        $ExpectedContentLength -gt $definition.maximumBytes) {
        return [pscustomobject][ordered]@{
            state = 'Rejected'
            reasonCode = $definition.sizeReasonCode
            artifactId = ''
            literalPath = ''
        }
    }
    $journal = Read-RunRecoveryJournal -LiteralPath $JournalPath
    if (-not (Test-RunRecoveryJournalCurrentOwner -Journal $journal)) {
        return [pscustomobject][ordered]@{
            state = 'Rejected'
            reasonCode = $definition.ownerReasonCode
            artifactId = ''
            literalPath = ''
        }
    }
    if (@($journal.artifacts | Where-Object kind -eq $Kind).Count -ge
        $definition.maximumCount) {
        return [pscustomobject][ordered]@{
            state = 'Rejected'
            reasonCode = $definition.countReasonCode
            artifactId = ''
            literalPath = ''
        }
    }
    $workspace = @($journal.artifacts | Where-Object kind -eq 'Workspace')
    if ($workspace.Count -ne 1) { throw 'The journal does not bind exactly one workspace.' }
    $artifactDirectory = Join-Path $workspace[0].path $definition.directoryName
    if (-not [System.IO.Directory]::Exists($artifactDirectory)) {
        $null = [System.IO.Directory]::CreateDirectory($artifactDirectory)
    }
    if (([System.IO.File]::GetAttributes($artifactDirectory) -band
        [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The $Kind directory is a reparse point."
    }

    $artifactId = [guid]::NewGuid().ToString('D')
    $literalPath = Join-Path $artifactDirectory ($artifactId + $definition.extension)
    $file = [System.IO.FileStream]::new(
        $literalPath, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None
    )
    $file.Dispose()
    $artifact = [pscustomobject][ordered]@{
        artifactId = $artifactId
        kind = $Kind
        path = $literalPath
        fileSystemIdentity = Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $literalPath
        cleanupAction = 'Remove'
        finalized = $false
    }
    $journal.artifacts = @($journal.artifacts) + $artifact
    Write-RunRecoveryJournal -Journal $journal -LiteralPath $JournalPath

    [pscustomobject][ordered]@{
        state = 'Registered'
        reasonCode = $definition.registeredReasonCode
        artifactId = $artifactId
        literalPath = $literalPath
    }
}

function Write-RegisteredEvidenceArtifact {
    param(
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [guid] $ArtifactId,
        [Parameter(Mandatory)] [byte[]] $Content,
        [Parameter(Mandatory)]
        [ValidateSet('TemporaryEvidence', 'EvidenceViewingArtifact')]
        [string] $Kind
    )

    $definition = Get-OwnedEvidenceArtifactDefinition -Kind $Kind
    if ($Content.Length -gt $definition.maximumBytes) {
        return [pscustomobject][ordered]@{
            state = 'Rejected'
            reasonCode = $definition.sizeReasonCode
            artifactId = $ArtifactId.ToString('D')
            literalPath = ''
        }
    }
    $journal = Read-RunRecoveryJournal -LiteralPath $JournalPath
    if (-not (Test-RunRecoveryJournalCurrentOwner -Journal $journal)) {
        return [pscustomobject][ordered]@{
            state = 'Rejected'
            reasonCode = $definition.ownerReasonCode
            artifactId = $ArtifactId.ToString('D')
            literalPath = ''
        }
    }
    $artifact = @($journal.artifacts | Where-Object {
        $_.kind -eq $Kind -and $_.artifactId -eq $ArtifactId.ToString('D')
    })
    if ($artifact.Count -ne 1 -or
        -not [System.IO.File]::Exists([string] $artifact[0].path) -or
        (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $artifact[0].path) -ne
            [string] $artifact[0].fileSystemIdentity) {
        return [pscustomobject][ordered]@{
            state = 'Rejected'
            reasonCode = $definition.ownershipReasonCode
            artifactId = $ArtifactId.ToString('D')
            literalPath = ''
        }
    }

    try {
        $stream = [System.IO.FileStream]::new(
            [string] $artifact[0].path, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None,
            4096, [System.IO.FileOptions]::WriteThrough
        )
        try {
            $stream.Write($Content, 0, $Content.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
    }
    catch {
        # The empty or partial object remains registered. Recovery therefore
        # has an exact path and filesystem identity after a crash or write fault.
        throw
    }

    [pscustomobject][ordered]@{
        state = 'Registered'
        reasonCode = $definition.registeredReasonCode
        artifactId = $ArtifactId.ToString('D')
        literalPath = [string] $artifact[0].path
    }
}

function New-TemporaryEvidenceRegistration {
    param(
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [int] $ExpectedContentLength
    )

    New-RegisteredEvidenceArtifact -JournalPath $JournalPath `
        -ExpectedContentLength $ExpectedContentLength -Kind TemporaryEvidence
}

function Write-RegisteredTemporaryEvidence {
    param(
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [guid] $ArtifactId,
        [Parameter(Mandatory)] [byte[]] $Content
    )

    Write-RegisteredEvidenceArtifact -JournalPath $JournalPath `
        -ArtifactId $ArtifactId -Content $Content -Kind TemporaryEvidence
}

function Add-TemporaryEvidence {
    param(
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [byte[]] $Content
    )

    $registration = New-TemporaryEvidenceRegistration -JournalPath $JournalPath `
        -ExpectedContentLength $Content.Length
    if ($registration.state -ne 'Registered') { return $registration }
    Write-RegisteredTemporaryEvidence -JournalPath $JournalPath `
        -ArtifactId $registration.artifactId -Content $Content
}

function New-EvidenceViewingArtifact {
    param(
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [byte[]] $Content
    )

    $registration = New-RegisteredEvidenceArtifact -JournalPath $JournalPath `
        -ExpectedContentLength $Content.Length -Kind EvidenceViewingArtifact
    if ($registration.state -ne 'Registered') { return $registration }
    Write-RegisteredEvidenceArtifact -JournalPath $JournalPath `
        -ArtifactId $registration.artifactId -Content $Content `
        -Kind EvidenceViewingArtifact
}

function Remove-EvidenceViewingArtifactAndBoundary {
    param(
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [guid] $ArtifactId
    )

    $incomplete = [pscustomobject][ordered]@{
        state = 'CleanupIncomplete'; verified = $false
        reasonCode = 'VIEWING.CLEANUP_INCOMPLETE'; recoveryRetained = $true
    }
    try {
        $journal = Read-RunRecoveryJournal -LiteralPath $JournalPath
        if (-not (Test-RunRecoveryJournalCurrentOwner -Journal $journal)) { return $incomplete }
        $workspace = @($journal.artifacts | Where-Object kind -eq 'Workspace')
        $artifact = @($journal.artifacts | Where-Object {
            $_.kind -eq 'EvidenceViewingArtifact' -and
            $_.artifactId -eq $ArtifactId.ToString('D')
        })
        if ($workspace.Count -ne 1 -or $artifact.Count -ne 1 -or
            -not (Test-EvidenceArtifactWithinWorkspace -ArtifactPath $artifact[0].path `
                -WorkspacePath $workspace[0].path) -or
            (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $workspace[0].path) -ne
                [string] $workspace[0].fileSystemIdentity -or
            (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $artifact[0].path) -ne
                [string] $artifact[0].fileSystemIdentity) { return $incomplete }

        [System.IO.File]::Delete([string] $artifact[0].path)
        if ([System.IO.File]::Exists([string] $artifact[0].path)) { return $incomplete }
        $journal.artifacts = @($journal.artifacts | Where-Object {
            $_.artifactId -ne $ArtifactId.ToString('D')
        })
        Write-RunRecoveryJournal -Journal $journal -LiteralPath $JournalPath
        $viewingDirectory = Split-Path -Parent ([string] $artifact[0].path)
        if ([System.IO.Directory]::Exists($viewingDirectory)) {
            if ([System.IO.Directory]::EnumerateFileSystemEntries($viewingDirectory) |
                Select-Object -First 1) { return $incomplete }
            [System.IO.Directory]::Delete($viewingDirectory, $false)
        }
        if ([System.IO.Directory]::EnumerateFileSystemEntries($workspace[0].path) |
            Select-Object -First 1) { return $incomplete }
        [System.IO.Directory]::Delete([string] $workspace[0].path, $false)
        if ([System.IO.Directory]::Exists([string] $workspace[0].path)) { return $incomplete }

        # Remove recovery ownership last, after its registered plaintext and
        # restricted boundary are both verified absent.
        $journalDirectory = Split-Path -Parent ([System.IO.Path]::GetFullPath($JournalPath))
        [System.IO.File]::Delete([System.IO.Path]::GetFullPath($JournalPath))
        if ([System.IO.File]::Exists([System.IO.Path]::GetFullPath($JournalPath))) { return $incomplete }
        if ([System.IO.Directory]::Exists($journalDirectory) -and
            -not ([System.IO.Directory]::EnumerateFileSystemEntries($journalDirectory) |
                Select-Object -First 1)) {
            [System.IO.Directory]::Delete($journalDirectory, $false)
        }
        [pscustomobject][ordered]@{
            state = 'Closed'; verified = $true
            reasonCode = 'VIEWING.PLAINTEXT_REMOVED'; recoveryRetained = $false
        }
    }
    catch { $incomplete }
}

function Complete-TemporaryEvidenceIngestion {
    param(
        [Parameter(Mandatory)] [string] $JournalPath,
        [Parameter(Mandatory)] [guid] $ArtifactId,
        [Parameter(Mandatory)] [scriptblock] $IngestAction
    )

    $journal = Read-RunRecoveryJournal -LiteralPath $JournalPath
    if (-not (Test-RunRecoveryJournalCurrentOwner -Journal $journal)) {
        return [pscustomobject][ordered]@{
            state = 'IngestionFailed'
            reasonCode = 'TEMPORARY_EVIDENCE.RUN_OWNER_MISMATCH'
        }
    }
    $workspace = @($journal.artifacts | Where-Object kind -eq 'Workspace')
    $artifact = @($journal.artifacts | Where-Object {
        $_.kind -eq 'TemporaryEvidence' -and $_.artifactId -eq $ArtifactId.ToString('D')
    })
    if ($workspace.Count -ne 1 -or $artifact.Count -ne 1 -or
        -not (Test-EvidenceArtifactWithinWorkspace -ArtifactPath $artifact[0].path `
            -WorkspacePath $workspace[0].path) -or
        (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $artifact[0].path) -ne
            [string] $artifact[0].fileSystemIdentity) {
        return [pscustomobject][ordered]@{
            state = 'CleanupIncomplete'
            reasonCode = 'TEMPORARY_EVIDENCE.OWNERSHIP_UNVERIFIED'
        }
    }

    $policy = Get-EvidenceWorkspacePolicy
    $file = [System.IO.FileInfo]::new([string] $artifact[0].path)
    if ($file.Length -gt [int] $policy.temporaryEvidence.maximumArtifactBytes) {
        return [pscustomobject][ordered]@{
            state = 'CleanupIncomplete'
            reasonCode = 'TEMPORARY_EVIDENCE.SIZE_EXCEEDED'
        }
    }
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    try { & $IngestAction $bytes }
    catch {
        return [pscustomobject][ordered]@{
            state = 'IngestionFailed'
            reasonCode = 'TEMPORARY_EVIDENCE.INGESTION_FAILED'
        }
    }
    finally {
        # Temporary evidence is already unprotected on disk, but the additional
        # managed copy used during ingestion is controllable. Clear that buffer
        # on every path so viewing cleanup does not extend plaintext lifetime.
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }

    # File.Delete is ordinary filesystem deletion. It removes the product-owned
    # directory entry and we verify absence, but storage media and Windows may
    # retain recoverable blocks. The product therefore makes no forensic secure-
    # erasure claim and gives cleanup failure precedence over useful ingestion.
    [System.IO.File]::Delete($file.FullName)
    if ([System.IO.File]::Exists($file.FullName)) {
        return [pscustomobject][ordered]@{
            state = 'CleanupIncomplete'
            reasonCode = 'TEMPORARY_EVIDENCE.REMOVAL_UNVERIFIED'
        }
    }
    $journal.artifacts = @($journal.artifacts | Where-Object {
        $_.artifactId -ne $ArtifactId.ToString('D')
    })
    Write-RunRecoveryJournal -Journal $journal -LiteralPath $JournalPath
    [pscustomobject][ordered]@{
        state = 'IngestedAndRemoved'
        reasonCode = 'TEMPORARY_EVIDENCE.INGESTED_AND_REMOVED'
    }
}

function Get-EvidenceWorkspaceSafeAlternativePath {
    $policy = Get-EvidenceWorkspacePolicy
    $knownFolder = [System.Environment]::GetFolderPath(
        [System.Environment+SpecialFolder]::LocalApplicationData
    )
    if ([string]::IsNullOrWhiteSpace($knownFolder)) { return '' }
    [System.IO.Path]::GetFullPath((
        Join-Path $knownFolder ([string] $policy.workspace.safeAlternative.relativePath)
    ))
}

function Test-EvidenceWorkspaceDestination {
    param(
        [Parameter(Mandatory)] [string] $RequestedBasePath,
        [Parameter(Mandatory)] [guid] $RunId
    )

    $policy = Get-EvidenceWorkspacePolicy
    $safeAlternative = Get-EvidenceWorkspaceSafeAlternativePath

    if ($RequestedBasePath.StartsWith('\\', [System.StringComparison]::Ordinal)) {
        return [pscustomobject][ordered]@{
            eligible = $false
            reasonCode = 'WORKSPACE.DESTINATION_NETWORK'
            requestedBasePath = $RequestedBasePath
            workspacePath = ''
            safeAlternative = $safeAlternative
        }
    }

    try {
        $basePath = [System.IO.Path]::GetFullPath($RequestedBasePath)
        $root = [System.IO.Path]::GetPathRoot($basePath)
        if ([string]::IsNullOrWhiteSpace($root)) {
            throw [System.IO.IOException]::new('The destination has no volume root.')
        }
        if ($basePath.TrimEnd('\') -eq $root.TrimEnd('\')) {
            return [pscustomobject][ordered]@{
                eligible = $false
                reasonCode = 'WORKSPACE.DESTINATION_ROOT'
                requestedBasePath = $basePath
                workspacePath = ''
                safeAlternative = $safeAlternative
            }
        }
        if ([System.IO.File]::Exists($basePath)) {
            return [pscustomobject][ordered]@{
                eligible = $false
                reasonCode = 'WORKSPACE.DESTINATION_NOT_DIRECTORY'
                requestedBasePath = $basePath
                workspacePath = ''
                safeAlternative = $safeAlternative
            }
        }
        if (-not [System.IO.Directory]::Exists($basePath)) {
            return [pscustomobject][ordered]@{
                eligible = $false
                reasonCode = 'WORKSPACE.DESTINATION_NOT_FOUND'
                requestedBasePath = $basePath
                workspacePath = ''
                safeAlternative = $safeAlternative
            }
        }

        $drive = [System.IO.DriveInfo]::new($root)
        if (-not $drive.IsReady -or
            [string] $drive.DriveType -notin @($policy.workspace.allowedDriveTypes) -or
            $drive.DriveFormat -notin @($policy.workspace.allowedFileSystems)) {
            return [pscustomobject][ordered]@{
                eligible = $false
                reasonCode = 'WORKSPACE.DESTINATION_VOLUME_UNSAFE'
                requestedBasePath = $basePath
                workspacePath = ''
                safeAlternative = $safeAlternative
            }
        }

        # Reparse points can redirect a visually local path to a network share
        # or a different local object after validation. Every existing ancestor
        # is inspected and the request fails closed if any hop is redirected.
        $cursor = [System.IO.DirectoryInfo]::new($basePath)
        while ($null -ne $cursor) {
            if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return [pscustomobject][ordered]@{
                    eligible = $false
                    reasonCode = 'WORKSPACE.DESTINATION_REPARSE_POINT'
                    requestedBasePath = $basePath
                    workspacePath = ''
                    safeAlternative = $safeAlternative
                }
            }
            $cursor = $cursor.Parent
        }

        $workspacePath = Join-Path $basePath (
            [string] $policy.workspace.directoryNamePrefix + $RunId.ToString('D')
        )
        if ([System.IO.Directory]::Exists($workspacePath) -or
            [System.IO.File]::Exists($workspacePath)) {
            return [pscustomobject][ordered]@{
                eligible = $false
                reasonCode = 'WORKSPACE.TARGET_ALREADY_EXISTS'
                requestedBasePath = $basePath
                workspacePath = $workspacePath
                safeAlternative = $safeAlternative
            }
        }

        [pscustomobject][ordered]@{
            eligible = $true
            reasonCode = 'WORKSPACE.DESTINATION_ELIGIBLE'
            requestedBasePath = $basePath
            workspacePath = $workspacePath
            safeAlternative = $safeAlternative
        }
    }
    catch {
        [pscustomobject][ordered]@{
            eligible = $false
            reasonCode = 'WORKSPACE.DESTINATION_INVALID'
            requestedBasePath = $RequestedBasePath
            workspacePath = ''
            safeAlternative = $safeAlternative
        }
    }
}

function New-EvidenceWorkspace {
    param(
        [Parameter(Mandatory)] [string] $RequestedBasePath,
        [Parameter(Mandatory)] [guid] $RunId
    )

    $decision = Test-EvidenceWorkspaceDestination -RequestedBasePath $RequestedBasePath `
        -RunId $RunId
    if (-not $decision.eligible) {
        return [pscustomobject][ordered]@{
            state = 'Rejected'
            reasonCode = $decision.reasonCode
            runId = $RunId.ToString('D')
            workspacePath = ''
            safeAlternative = $decision.safeAlternative
            created = $false
        }
    }

    Initialize-EvidenceWorkspaceNative
    $initiatingSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    try {
        [WinPCInfo.EvidenceWorkspaceNative]::CreateRestrictedDirectory(
            $decision.workspacePath, $initiatingSid
        )
    }
    catch {
        return [pscustomobject][ordered]@{
            state = 'Rejected'
            reasonCode = 'WORKSPACE.CREATE_FAILED'
            runId = $RunId.ToString('D')
            workspacePath = ''
            safeAlternative = $decision.safeAlternative
            created = $false
        }
    }

    [pscustomobject][ordered]@{
        state = 'Created'
        reasonCode = 'WORKSPACE.CREATED'
        runId = $RunId.ToString('D')
        workspacePath = $decision.workspacePath
        safeAlternative = $decision.safeAlternative
        created = $true
    }
}

function Read-EvidenceWorkspaceFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    try {
        $bytes = [System.IO.File]::ReadAllBytes([System.IO.Path]::GetFullPath($LiteralPath))
        if ($bytes.Length -gt 4096) { throw 'Fixture exceeds its byte bound.' }
        $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $document = [System.Text.Json.JsonDocument]::Parse($json)
        try {
            $reason = Get-JsonLexicalSafetyReason -Element $document.RootElement -Limits ([pscustomobject]@{
                maximumJsonDepth = 4
                maximumStringUtf8Bytes = 256
                maximumSafeInteger = 9007199254740991
            })
            if ($reason) { throw "Fixture lexical rejection: $reason" }
        }
        finally { $document.Dispose() }
        $fixture = & $ConvertFromJsonCommand -InputObject $json -Depth 5 -ErrorAction Stop
        $actualFields = @($fixture.PSObject.Properties.Name)
        if ($actualFields.Count -ne 2 -or
            'contractVersion' -notin $actualFields -or 'scenario' -notin $actualFields -or
            [string] $fixture.contractVersion -ne '1.0.0' -or
            [string] $fixture.scenario -notin @((Get-EvidenceWorkspacePolicy).validationScenarios)) {
            throw 'Fixture contract rejected.'
        }
        [string] $fixture.scenario
    }
    catch {
        $exception = [System.ArgumentException]::new('The Evidence Workspace fixture is invalid.')
        $exception.Data['ReasonCode'] = 'WORKSPACE.FIXTURE_INVALID'
        throw $exception
    }
}

function New-EvidenceWorkspaceValidationBoundary {
    param([Parameter()] [string] $ValidationRootPath)

    if ([string]::IsNullOrWhiteSpace($ValidationRootPath)) {
        $localApplicationData = [System.Environment]::GetFolderPath(
            [System.Environment+SpecialFolder]::LocalApplicationData
        )
        if ([string]::IsNullOrWhiteSpace($localApplicationData)) {
            throw 'Local application data is unavailable.'
        }
        $productRoot = Join-Path $localApplicationData 'WIN-PCInfo'
        $validationRoot = Join-Path $productRoot 'Validation'
        $productRootCreated = -not [System.IO.Directory]::Exists($productRoot)
        $null = [System.IO.Directory]::CreateDirectory($productRoot)
    }
    else {
        # The generated validation path is fixed beside the generated candidate,
        # never derived from fixture content. It exists only so repository tests
        # can prove cleanup without writing private validation data elsewhere.
        $validationRoot = [System.IO.Path]::GetFullPath($ValidationRootPath)
        $productRoot = [System.IO.Path]::GetDirectoryName($validationRoot)
        $productRootCreated = $false
    }
    $validationRootCreated = -not [System.IO.Directory]::Exists($validationRoot)
    $null = [System.IO.Directory]::CreateDirectory($validationRoot)
    foreach ($path in @($productRoot, $validationRoot)) {
        if (([System.IO.File]::GetAttributes($path) -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The release validation boundary is redirected.'
        }
    }
    $caseRoot = Join-Path $validationRoot ('case-' + [guid]::NewGuid().ToString('D'))
    Initialize-EvidenceWorkspaceNative
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    [WinPCInfo.EvidenceWorkspaceNative]::CreateRestrictedDirectory($caseRoot, $sid)
    [pscustomobject]@{
        ProductRoot = $productRoot
        ValidationRoot = $validationRoot
        CaseRoot = $caseRoot
        ProductRootCreated = $productRootCreated
        ValidationRootCreated = $validationRootCreated
    }
}

function Remove-EvidenceWorkspaceValidationBoundary {
    param([Parameter(Mandatory)] $Boundary)

    $caseRoot = [System.IO.Path]::GetFullPath([string] $Boundary.CaseRoot)
    $validationRoot = [System.IO.Path]::GetFullPath([string] $Boundary.ValidationRoot).TrimEnd('\')
    if (-not $caseRoot.StartsWith(
            $validationRoot + [System.IO.Path]::DirectorySeparatorChar + 'case-',
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        return $false
    }
    try {
        if ([System.IO.Directory]::Exists($caseRoot)) {
            # Validation teardown is not Stale-run Recovery. This fresh GUID
            # boundary and every descendant were created by this fixture in the
            # current invocation, so recursive removal has an exact ownership
            # proof. Product recovery itself never receives this operation.
            [System.IO.Directory]::Delete($caseRoot, $true)
        }
        if ([System.IO.Directory]::Exists($caseRoot)) { return $false }
        if ($Boundary.ValidationRootCreated -and
            [System.IO.Directory]::Exists($validationRoot) -and
            -not [System.IO.Directory]::EnumerateFileSystemEntries($validationRoot).GetEnumerator().MoveNext()) {
            [System.IO.Directory]::Delete($validationRoot, $false)
        }
        if ($Boundary.ProductRootCreated -and
            [System.IO.Directory]::Exists([string] $Boundary.ProductRoot) -and
            -not [System.IO.Directory]::EnumerateFileSystemEntries(
                [string] $Boundary.ProductRoot
            ).GetEnumerator().MoveNext()) {
            [System.IO.Directory]::Delete([string] $Boundary.ProductRoot, $false)
        }
        $true
    }
    catch { $false }
}

function New-EvidenceWorkspaceFixtureContext {
    param([Parameter(Mandatory)] $Boundary)

    $workspaceBase = Join-Path $Boundary.CaseRoot 'workspace-base'
    $recoveryBase = Join-Path $Boundary.CaseRoot 'recovery-base'
    $null = [System.IO.Directory]::CreateDirectory($workspaceBase)
    $null = [System.IO.Directory]::CreateDirectory($recoveryBase)
    $workspace = New-EvidenceWorkspace -RequestedBasePath $workspaceBase `
        -RunId ([guid]::NewGuid())
    if ($workspace.state -ne 'Created') { throw 'Synthetic workspace creation failed.' }

    $journal = New-RunRecoveryJournal -Workspace $workspace `
        -RecoveryBasePath $recoveryBase -PlanDigest ('c' * 64) -Phase 'Collection'
    [pscustomobject]@{ Workspace = $workspace; Journal = $journal }
}

function Set-EvidenceWorkspaceFixtureOwnerStale {
    param([Parameter(Mandatory)] [string] $JournalPath)

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $PSHOME 'pwsh.exe'
    $start.UseShellExecute = $false
    $null = $start.ArgumentList.Add('-NoLogo')
    $null = $start.ArgumentList.Add('-NoProfile')
    $null = $start.ArgumentList.Add('-Command')
    $null = $start.ArgumentList.Add('[System.Threading.Thread]::Sleep(30000)')
    $ownerProcess = [System.Diagnostics.Process]::Start($start)
    try {
        $journal = Read-RunRecoveryJournal -LiteralPath $JournalPath
        $journal.owner.processId = $ownerProcess.Id
        $journal.owner.processStartUtc = $ownerProcess.StartTime.ToUniversalTime().ToString('O')
        Write-RunRecoveryJournal -Journal $journal -LiteralPath $JournalPath
    }
    finally {
        if (-not $ownerProcess.HasExited) {
            $ownerProcess.Kill($true)
            $ownerProcess.WaitForExit()
        }
        $ownerProcess.Dispose()
    }
}

function Invoke-EvidenceWorkspaceFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $RuntimeResult,
        [Parameter(Mandatory)] [string] $RequestDigest,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] [bool] $RecoveryAuthorized,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    try {
        $scenario = Read-EvidenceWorkspaceFixture -LiteralPath $LiteralPath `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
    }
    catch {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'WORKSPACE.FIXTURE_INVALID' `
            -RequestDigest $RequestDigest -ValidationFixture $true -RuntimeResult $RuntimeResult `
            -Phase 'Preparation' -PlanDigest $PlanDigest -PreparationDecision 'Accepted') `
            -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }
    if (-not $RecoveryAuthorized -and $scenario -notin @('EligibleDestination', 'UnsafeDestination')) {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'WORKSPACE.RECOVERY_NOT_AUTHORIZED' `
            -RequestDigest $RequestDigest -ValidationFixture $true -RuntimeResult $RuntimeResult `
            -Phase 'Preparation' -PlanDigest $PlanDigest -PreparationDecision 'Accepted') `
            -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $boundary = $null
    $lock = $null
    $state = 'IntegrityFailed'
    $reasonCode = 'WORKSPACE.VALIDATION_FAILED'
    $recoveryResult = $null
    $workspaceAccessRestricted = $false
    $safeAlternativeOffered = $false
    $temporaryRemoved = $true
    $targetRetainedDuringRecovery = $false
    $finalizedPackagePreserved = $false
    try {
        $boundary = New-EvidenceWorkspaceValidationBoundary -ValidationRootPath (
            Join-Path $PSScriptRoot '.evidence-workspace-validation'
        )
        if ($scenario -eq 'UnsafeDestination') {
            $unsafe = New-EvidenceWorkspace -RequestedBasePath '\\synthetic.invalid\share' `
                -RunId ([guid]::NewGuid())
            $state = 'Rejected'
            $reasonCode = [string] $unsafe.reasonCode
            $safeAlternativeOffered = -not [string]::IsNullOrWhiteSpace([string] $unsafe.safeAlternative)
        }
        else {
            $context = New-EvidenceWorkspaceFixtureContext -Boundary $boundary
            $workspaceAccessRestricted = Test-EvidenceAccessBoundary `
                -LiteralPath $context.Workspace.workspacePath `
                -ExpectedOwnerSid ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)

            switch ($scenario) {
                'InterruptedTemporaryEvidence' {
                    $temporary = Add-TemporaryEvidence -JournalPath $context.Journal.journalPath `
                        -Content ([System.Text.Encoding]::UTF8.GetBytes('synthetic-private-marker'))
                    Set-EvidenceWorkspaceFixtureOwnerStale `
                        -JournalPath $context.Journal.journalPath
                    $recoveryResult = Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
                    $temporaryRemoved = -not [System.IO.File]::Exists($temporary.literalPath)
                    $state = 'Recovered'
                    $reasonCode = [string] $recoveryResult.reasonCode
                }
                'StaleOwner' {
                    Set-EvidenceWorkspaceFixtureOwnerStale `
                        -JournalPath $context.Journal.journalPath
                    $recoveryResult = Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
                    $state = 'Recovered'
                    $reasonCode = [string] $recoveryResult.reasonCode
                }
                'LiveOwner' {
                    $temporary = Add-TemporaryEvidence -JournalPath $context.Journal.journalPath `
                        -Content ([System.Text.Encoding]::UTF8.GetBytes('synthetic-private-marker'))
                    $recoveryResult = Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
                    $targetRetainedDuringRecovery = [System.IO.File]::Exists($temporary.literalPath)
                    $temporaryRemoved = $false
                    $state = 'Deferred'
                    $reasonCode = [string] $recoveryResult.reasonCode
                }
                'AmbiguousTarget' {
                    $temporary = Add-TemporaryEvidence -JournalPath $context.Journal.journalPath `
                        -Content ([System.Text.Encoding]::UTF8.GetBytes('synthetic-original-marker'))
                    [System.IO.File]::Move($temporary.literalPath, $temporary.literalPath + '.owned-original')
                    [System.IO.File]::WriteAllText($temporary.literalPath, 'synthetic-replacement-marker')
                    Set-EvidenceWorkspaceFixtureOwnerStale `
                        -JournalPath $context.Journal.journalPath
                    $recoveryResult = Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
                    $targetRetainedDuringRecovery = [System.IO.File]::Exists($temporary.literalPath)
                    $temporaryRemoved = $false
                    $state = 'CleanupIncomplete'
                    $reasonCode = [string] $recoveryResult.reasonCode
                }
                'PreservedPackage' {
                    $packagePath = Join-Path $context.Workspace.workspacePath 'assessment.winpci'
                    [System.IO.File]::WriteAllBytes($packagePath, [byte[]](1, 2, 3, 4))
                    Register-FinalizedEvidencePackage -JournalPath $context.Journal.journalPath `
                        -LiteralPath $packagePath | Out-Null
                    Set-EvidenceWorkspaceFixtureOwnerStale `
                        -JournalPath $context.Journal.journalPath
                    $recoveryResult = Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
                    $finalizedPackagePreserved = [System.IO.File]::Exists($packagePath)
                    $state = 'Deferred'
                    $reasonCode = [string] $recoveryResult.reasonCode
                }
                'WindowsFeatureObservation' {
                    Set-EvidenceWorkspaceFixtureOwnerStale `
                        -JournalPath $context.Journal.journalPath
                    $recoveryResult = Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
                    $state = 'ObservedOnly'
                    $reasonCode = 'RECOVERY.WINDOWS_FEATURE_OBSERVED'
                }
                'CleanupFailure' {
                    $temporary = Add-TemporaryEvidence -JournalPath $context.Journal.journalPath `
                        -Content ([System.Text.Encoding]::UTF8.GetBytes('synthetic-locked-marker'))
                    $lock = [System.IO.FileStream]::new(
                        $temporary.literalPath, [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Read, [System.IO.FileShare]::None
                    )
                    Set-EvidenceWorkspaceFixtureOwnerStale `
                        -JournalPath $context.Journal.journalPath
                    $recoveryResult = Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
                    $state = 'CleanupIncomplete'
                    $reasonCode = [string] $recoveryResult.reasonCode
                    $temporaryRemoved = $false
                }
                default {
                    Set-EvidenceWorkspaceFixtureOwnerStale `
                        -JournalPath $context.Journal.journalPath
                    $recoveryResult = Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
                    $state = 'Validated'
                    $reasonCode = 'WORKSPACE.CREATED'
                }
            }
        }
    }
    catch {
        $state = 'IntegrityFailed'
        $reasonCode = 'WORKSPACE.VALIDATION_FAILED'
    }
    finally {
        if ($null -ne $lock) { $lock.Dispose() }
        $validationCleanupVerified = if ($null -ne $boundary) {
            Remove-EvidenceWorkspaceValidationBoundary -Boundary $boundary
        }
        else { $true }
    }

    $record = [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.evidence-workspace-validation'
        contractVersion = '1.0.0'
        scenario = $scenario
        state = $state
        reasonCode = $reasonCode
        collectionStarted = $false
        workspace = [pscustomobject][ordered]@{
            newPerRun = $true
            accessRestricted = $workspaceAccessRestricted
            unsafeDestinationRejected = $scenario -eq 'UnsafeDestination' -and $state -eq 'Rejected'
            safeAlternativeOffered = $safeAlternativeOffered
        }
        journal = [pscustomobject][ordered]@{
            payloadRestricted = $true
            evidenceOrSecretStored = $false
            crossRunIdentityStored = $false
        }
        temporaryEvidence = [pscustomobject][ordered]@{
            bounded = $true
            sameRunIngestionRequired = $true
            removed = $temporaryRemoved
            secureErasureClaim = $false
        }
        recovery = [pscustomobject][ordered]@{
            mode = 'CleanupOnly'
            deliberatelyRequested = $RecoveryAuthorized
            collectionResumed = $false
            targetRetainedDuringRecovery = $targetRetainedDuringRecovery
            finalizedPackagePreserved = $finalizedPackagePreserved
            cleanupVerified = if ($null -ne $recoveryResult) {
                [bool] $recoveryResult.cleanup.verified
            }
            else { $true }
        }
        windowsFeatures = [pscustomobject][ordered]@{
            action = 'ObserveOnly'
            changesAttempted = $false
        }
        guidance = if ($null -ne $recoveryResult) {
            [string] $recoveryResult.guidance
        }
        elseif ($state -eq 'Rejected') {
            'Choose the offered existing local per-user destination and start a new Assessment Run deliberately.'
        }
        else {
            'No recovery action is required.'
        }
        validationCleanupVerified = [bool] $validationCleanupVerified
        validation = [pscustomobject][ordered]@{
            mode = 'SyntheticUnelevated'
            capabilityClaimCreated = $false
        }
    }
    Write-ContractRecord $record -ConvertToJsonCommand $ConvertToJsonCommand

    $cleanupIncomplete = $state -eq 'CleanupIncomplete' -or
        ($null -ne $recoveryResult -and $recoveryResult.outcome -eq 'CleanupIncomplete')
    $terminalReasonCode = if ($cleanupIncomplete) {
        $reasonCode
    }
    else { 'WORKSPACE.VALIDATION_COMPLETE' }
    $terminal = New-TerminalRecord -ReasonCode $terminalReasonCode `
        -RequestDigest $RequestDigest -ValidationFixture $true -RuntimeResult $RuntimeResult `
        -Phase 'Cleanup' -PlanDigest $PlanDigest -PreparationDecision 'Accepted'
    $exitCode = 20
    if ($cleanupIncomplete -or -not $validationCleanupVerified) {
        $terminal.outcome = 'CleanupIncomplete'
        $terminal.exitCode = 60
        $terminal.reasonCode = if (-not $validationCleanupVerified) {
            'WORKSPACE.VALIDATION_CLEANUP_INCOMPLETE'
        }
        else { $reasonCode }
        $terminal.cleanup.required = $true
        $terminal.cleanup.verified = $false
        $exitCode = 60
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $ConvertToJsonCommand
    $exitCode
}
