$script:ApprovedCollectorCatalogBase64 = '__APPROVED_COLLECTOR_CATALOG_BASE64__'
$script:ApprovedCollectorCatalogDigest = '__APPROVED_COLLECTOR_CATALOG_SHA256__'

function Get-CanonicalSupervisorTextBytes {
    param([Parameter(Mandatory)] [string] $LiteralPath)

    $text = [System.IO.File]::ReadAllText(
        [System.IO.Path]::GetFullPath($LiteralPath),
        [System.Text.UTF8Encoding]::new($false, $true)
    )
    $normalized = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    [System.Text.UTF8Encoding]::new($false).GetBytes($normalized)
}

function Get-ApprovedCollectorCatalog {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    try {
        if ($script:ApprovedCollectorCatalogBase64 -eq ('__APPROVED_COLLECTOR_' + 'CATALOG_BASE64__')) {
            # Modular source tests use the reviewed repository catalog. The
            # deterministic build replaces this branch's sentinel with those
            # exact canonical bytes and their digest, so the generated public
            # artifact has no mutable sidecar policy dependency.
            $repositoryRoot = Split-Path -Parent $PSScriptRoot
            $catalogPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
            $bytes = Get-CanonicalSupervisorTextBytes -LiteralPath $catalogPath
            $expectedDigest = Get-Sha256ForSupervisorBytes -Bytes $bytes
        }
        else {
            $bytes = [System.Convert]::FromBase64String($script:ApprovedCollectorCatalogBase64)
            $expectedDigest = $script:ApprovedCollectorCatalogDigest
        }
        $actualDigest = Get-Sha256ForSupervisorBytes -Bytes $bytes
        if ($actualDigest -ne $expectedDigest) { throw 'Collector catalog digest mismatch.' }
        $catalog = & $ConvertFromJsonCommand -InputObject (
            [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        ) -Depth 30 -ErrorAction Stop

        $syntheticCollector = @($catalog.collectors | Where-Object collectorId -eq 'collector:synthetic.windows.os')
        $deviceCollector = @($catalog.collectors | Where-Object collectorId -eq 'collector:windows.device-readiness')
        $contextCollector = @($catalog.collectors | Where-Object collectorId -eq 'collector:windows.device-context')
        $legacyOperation = @($syntheticCollector.operations | Where-Object operationId -eq 'op:synthetic.windows.os.success')
        $deviceOperation = @($deviceCollector.operations | Where-Object operationId -eq 'op:device.windows-readiness.collect')
        $contextOperation = @($contextCollector.operations | Where-Object operationId -eq 'op:device.windows-context.collect')
        if ($catalog.kind -ne 'win-pcinfo.approved-collector-catalog' -or
            $catalog.contractVersion -ne '1.0.0' -or $catalog.release -ne '2.0.0-preview.1' -or
            @($catalog.collectors).Count -ne 3 -or $syntheticCollector.Count -ne 1 -or
            $deviceCollector.Count -ne 1 -or $contextCollector.Count -ne 1 -or
            @($catalog.collectors | Where-Object {
                $_.executable.resolver -ne 'ActivePowerShellHost' -or
                $_.workingBoundary.kind -ne 'ActivePowerShellHome' -or
                $_.environment.inheritParent -ne $false -or
                $_.treeControl.mode -ne 'WindowsJobObjectRequired' -or
                $_.treeControl.incompatibleDisposition -ne 'NotStarted'
            }).Count -gt 0 -or $legacyOperation.Count -ne 1 -or $deviceOperation.Count -ne 1 -or
            $contextOperation.Count -ne 1) {
            throw 'Collector catalog semantic closure failed.'
        }

        [pscustomobject]@{
            Valid = $true
            ReasonCode = 'PROCESS.POLICY_READY'
            Digest = $actualDigest
            Catalog = $catalog
            Collectors = @($catalog.collectors)
        }
    }
    catch {
        [pscustomobject]@{
            Valid = $false
            ReasonCode = 'PROCESS.POLICY_INTEGRITY_FAILED'
            Digest = ''
        }
    }
}

function Initialize-ProcessSupervisorNativeType {
    if ('WinPCInfo.ProcessSupervisor.NativeRunner' -as [type]) { return }

    # Process.Start cannot create a Windows process suspended. Starting normally
    # and assigning the process to a Job Object afterward leaves a small but real
    # window in which hostile or simply fast collector code could create a child
    # outside the job. This first-party interop closes that spawn-to-assignment
    # race: CreateProcessW creates the approved image suspended, the supervisor
    # assigns it to its own Job Object, and only then resumes its first thread.
    # The trust assumption is the Windows kernel process and Job Object API. If
    # any native call fails, the suspended process is terminated before it can
    # execute and the collector attempt fails closed.
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace WinPCInfo.ProcessSupervisor
{
    public enum NativeFailureStage
    {
        None,
        CreateJobObject,
        ConfigureJobObject,
        CreateOutputPipes,
        CreateProcess,
        AssignJobObjectIncompatible,
        AssignJobObject,
        ResumeProcess,
        WaitForProcess,
        CaptureOutput,
        OutputLimit,
        CooperativeCancellation,
        HardCancellation,
        Deadline,
        TerminationIncomplete
    }

    public enum NativeCancellationMode { None, Cooperative, Hard }

    public sealed class NativeRunResult
    {
        public bool Started { get; set; }
        public int ExitCode { get; set; }
        public NativeFailureStage FailureStage { get; set; }
        public int NativeError { get; set; }
        public byte[] StandardOutput { get; set; }
        public byte[] StandardError { get; set; }
        public long StandardOutputBytes { get; set; }
        public long StandardErrorBytes { get; set; }
        public bool StandardOutputExceeded { get; set; }
        public bool StandardErrorExceeded { get; set; }
        public bool CompleteOwnedTreeAbsent { get; set; }
        public int PeakActiveProcesses { get; set; }
        public NativeCancellationMode CancellationMode { get; set; }
    }

    internal sealed class CaptureResult
    {
        internal byte[] Prefix;
        internal long TotalBytes;
        internal bool Exceeded;
    }

    internal sealed class CaptureBuffer
    {
        private readonly int limit;
        private readonly MemoryStream prefix;
        internal long TotalBytes { get; private set; }
        internal bool Exceeded { get { return TotalBytes > limit; } }

        internal CaptureBuffer(int maximumBytes)
        {
            limit = maximumBytes;
            prefix = new MemoryStream(Math.Min(maximumBytes, 4096));
        }

        internal void Append(byte[] bytes, int count)
        {
            int remaining = Math.Max(0, limit - (int)prefix.Length);
            if (remaining > 0) prefix.Write(bytes, 0, Math.Min(remaining, count));
            TotalBytes += count;
        }

        internal CaptureResult Snapshot()
        {
            return new CaptureResult {
                Prefix = prefix.ToArray(), TotalBytes = TotalBytes, Exceeded = Exceeded
            };
        }
    }

    public static class NativeRunner
    {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const uint WAIT_OBJECT_0 = 0;
        private const uint WAIT_TIMEOUT = 258;
        private const int JobObjectBasicAccountingInformation = 1;
        private const int JobObjectExtendedLimitInformation = 9;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            internal int nLength;
            internal IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] internal bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            internal int cb;
            internal string lpReserved;
            internal string lpDesktop;
            internal string lpTitle;
            internal uint dwX;
            internal uint dwY;
            internal uint dwXSize;
            internal uint dwYSize;
            internal uint dwXCountChars;
            internal uint dwYCountChars;
            internal uint dwFillAttribute;
            internal uint dwFlags;
            internal short wShowWindow;
            internal short cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal uint dwProcessId;
            internal uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal UIntPtr MinimumWorkingSetSize;
            internal UIntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal UIntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            internal IO_COUNTERS IoInfo;
            internal UIntPtr ProcessMemoryLimit;
            internal UIntPtr JobMemoryLimit;
            internal UIntPtr PeakProcessMemoryUsed;
            internal UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            internal long TotalUserTime;
            internal long TotalKernelTime;
            internal long ThisPeriodTotalUserTime;
            internal long ThisPeriodTotalKernelTime;
            internal uint TotalPageFaultCount;
            internal uint TotalProcesses;
            internal uint ActiveProcesses;
            internal uint TotalTerminatedProcesses;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job, int informationClass, IntPtr information, uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(
            IntPtr job, int informationClass, IntPtr information, uint length, IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(
            out IntPtr readPipe, out IntPtr writePipe, ref SECURITY_ATTRIBUTES attributes, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool PeekNamedPipe(
            IntPtr pipe, IntPtr buffer, uint bufferSize, IntPtr bytesRead,
            out uint totalBytesAvailable, IntPtr bytesLeftThisMessage);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(
            IntPtr file, byte[] buffer, uint bytesToRead, out uint bytesRead, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcess(
            string applicationName, StringBuilder commandLine, IntPtr processAttributes,
            IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment,
            string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private static string QuoteArgument(string value)
        {
            if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0)
                return value;
            var quoted = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\') { backslashes++; continue; }
                if (character == '"')
                {
                    quoted.Append('\\', backslashes * 2 + 1).Append(character);
                    backslashes = 0;
                    continue;
                }
                quoted.Append('\\', backslashes).Append(character);
                backslashes = 0;
            }
            quoted.Append('\\', backslashes * 2).Append('"');
            return quoted.ToString();
        }

        private static IntPtr CreateEnvironmentBlock(IDictionary<string, string> environment)
        {
            var block = new StringBuilder();
            foreach (var pair in new SortedDictionary<string, string>(environment, StringComparer.OrdinalIgnoreCase))
                block.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');
            block.Append('\0');
            return Marshal.StringToHGlobalUni(block.ToString());
        }

        private static bool DrainAvailablePipe(
            IntPtr readHandle, CaptureBuffer capture, int maximumBytesPerPass, out int nativeError)
        {
            nativeError = 0;
            var buffer = new byte[4096];
            int remainingBudget = maximumBytesPerPass;
            while (remainingBudget > 0)
            {
                uint available;
                if (!PeekNamedPipe(readHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();
                    // ERROR_BROKEN_PIPE means every writer closed. That is the
                    // normal EOF signal for an anonymous Windows pipe.
                    if (error == 109) return true;
                    nativeError = error;
                    return false;
                }
                if (available == 0) return true;
                uint requested = Math.Min(
                    available, (uint)Math.Min(buffer.Length, remainingBudget));
                uint read;
                if (!ReadFile(readHandle, buffer, requested, out read, IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 109) return true;
                    nativeError = error;
                    return false;
                }
                if (read == 0) return true;
                capture.Append(buffer, (int)read);
                remainingBudget -= (int)read;
            }
            return true;
        }

        private static uint ActiveProcessCount(IntPtr job)
        {
            int size = Marshal.SizeOf<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>();
            IntPtr information = Marshal.AllocHGlobal(size);
            try
            {
                if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                    information, (uint)size, IntPtr.Zero)) return UInt32.MaxValue;
                return Marshal.PtrToStructure<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>(information).ActiveProcesses;
            }
            finally { Marshal.FreeHGlobal(information); }
        }

        private static bool TerminateProcessWithin(IntPtr process, int verificationMilliseconds)
        {
            bool submitted = TerminateProcess(process, 0xee);
            return submitted && WaitForSingleObject(process, (uint)verificationMilliseconds) == WAIT_OBJECT_0;
        }

        private static bool TerminateJobWithin(
            IntPtr job, IntPtr rootProcess, int verificationMilliseconds)
        {
            bool submitted = TerminateJobObject(job, 0xee);
            return submitted &&
                WaitForSingleObject(rootProcess, (uint)verificationMilliseconds) == WAIT_OBJECT_0;
        }

        public static NativeRunResult Run(
            string executable, string[] arguments, string workingDirectory,
            IDictionary<string, string> environment, int deadlineMilliseconds,
            int standardOutputLimit, int standardErrorLimit,
            System.Threading.CancellationToken cancellationToken,
            System.Threading.EventWaitHandle cancellationEvent,
            int cancellationGraceMilliseconds, int terminationVerificationMilliseconds,
            bool simulateJobIncompatible)
        {
            var result = new NativeRunResult { FailureStage = NativeFailureStage.None, ExitCode = -1,
                StandardOutput = Array.Empty<byte>(), StandardError = Array.Empty<byte>(),
                CancellationMode = NativeCancellationMode.None };
            IntPtr job = IntPtr.Zero, stdoutRead = IntPtr.Zero, stdoutWrite = IntPtr.Zero;
            IntPtr stderrRead = IntPtr.Zero, stderrWrite = IntPtr.Zero, environmentBlock = IntPtr.Zero;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            int peakActive = 0;
            try
            {
                job = CreateJobObject(IntPtr.Zero, null);
                if (job == IntPtr.Zero) { result.FailureStage = NativeFailureStage.CreateJobObject; result.NativeError = Marshal.GetLastWin32Error(); return result; }

                var extended = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                extended.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                int extendedSize = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
                IntPtr extendedPointer = Marshal.AllocHGlobal(extendedSize);
                try
                {
                    Marshal.StructureToPtr(extended, extendedPointer, false);
                    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                        extendedPointer, (uint)extendedSize))
                    { result.FailureStage = NativeFailureStage.ConfigureJobObject; result.NativeError = Marshal.GetLastWin32Error(); return result; }
                }
                finally { Marshal.FreeHGlobal(extendedPointer); }

                var attributes = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(), bInheritHandle = true };
                if (!CreatePipe(out stdoutRead, out stdoutWrite, ref attributes, 0) ||
                    !SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0) ||
                    !CreatePipe(out stderrRead, out stderrWrite, ref attributes, 0) ||
                    !SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0))
                { result.FailureStage = NativeFailureStage.CreateOutputPipes; result.NativeError = Marshal.GetLastWin32Error(); return result; }

                var startup = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(),
                    dwFlags = STARTF_USESTDHANDLES, hStdInput = IntPtr.Zero,
                    hStdOutput = stdoutWrite, hStdError = stderrWrite };
                var commandLine = new StringBuilder(QuoteArgument(executable));
                foreach (string argument in arguments) commandLine.Append(' ').Append(QuoteArgument(argument));
                environmentBlock = CreateEnvironmentBlock(environment);
                uint flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
                if (!CreateProcess(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true, flags,
                    environmentBlock, workingDirectory, ref startup, out process))
                { result.FailureStage = NativeFailureStage.CreateProcess; result.NativeError = Marshal.GetLastWin32Error(); return result; }
                if (simulateJobIncompatible)
                {
                    // The conformance fixture models the documented Windows
                    // assignment-incompatible branch while the process remains
                    // suspended. Terminating this never-resumed root is the safe
                    // fallback; root-only supervision would overstate control.
                    result.FailureStage = NativeFailureStage.AssignJobObjectIncompatible;
                    result.CompleteOwnedTreeAbsent = TerminateProcessWithin(
                        process.hProcess, terminationVerificationMilliseconds);
                    if (!result.CompleteOwnedTreeAbsent)
                        result.FailureStage = NativeFailureStage.TerminationIncomplete;
                    return result;
                }

                if (!AssignProcessToJobObject(job, process.hProcess))
                {
                    result.FailureStage = NativeFailureStage.AssignJobObject;
                    result.NativeError = Marshal.GetLastWin32Error();
                    result.CompleteOwnedTreeAbsent = TerminateProcessWithin(
                        process.hProcess, terminationVerificationMilliseconds);
                    if (!result.CompleteOwnedTreeAbsent)
                        result.FailureStage = NativeFailureStage.TerminationIncomplete;
                    return result;
                }

                result.Started = true;
                var stdoutCapture = new CaptureBuffer(standardOutputLimit);
                var stderrCapture = new CaptureBuffer(standardErrorLimit);
                CloseHandle(stdoutWrite); stdoutWrite = IntPtr.Zero;
                CloseHandle(stderrWrite); stderrWrite = IntPtr.Zero;

                if (ResumeThread(process.hThread) == UInt32.MaxValue)
                {
                    result.FailureStage = NativeFailureStage.ResumeProcess;
                    result.NativeError = Marshal.GetLastWin32Error();
                    if (!TerminateJobWithin(job, process.hProcess, terminationVerificationMilliseconds))
                        result.FailureStage = NativeFailureStage.TerminationIncomplete;
                }
                else
                {
                    DateTime deadline = DateTime.UtcNow.AddMilliseconds(deadlineMilliseconds);
                    DateTime cancellationDeadline = DateTime.MaxValue;
                    bool cancellationRequested = false;
                    bool outputLimitObserved = false;
                    while (true)
                    {
                        int outputError;
                        int outputPassLimit = Math.Max(
                            4096, Math.Max(standardOutputLimit, standardErrorLimit) + 4096);
                        if (!DrainAvailablePipe(stdoutRead, stdoutCapture, outputPassLimit, out outputError) ||
                            !DrainAvailablePipe(stderrRead, stderrCapture, outputPassLimit, out outputError))
                        {
                            result.FailureStage = NativeFailureStage.CaptureOutput;
                            result.NativeError = outputError;
                            if (!TerminateJobWithin(job, process.hProcess, terminationVerificationMilliseconds))
                                result.FailureStage = NativeFailureStage.TerminationIncomplete;
                            break;
                        }
                        uint activeDuringRun = ActiveProcessCount(job);
                        if (activeDuringRun != UInt32.MaxValue)
                            peakActive = Math.Max(peakActive, (int)activeDuringRun);
                        uint wait = WaitForSingleObject(process.hProcess, 25);
                        if (wait == WAIT_OBJECT_0)
                        {
                            if (cancellationRequested)
                            {
                                result.FailureStage = NativeFailureStage.CooperativeCancellation;
                                result.CancellationMode = NativeCancellationMode.Cooperative;
                            }
                            break;
                        }
                        if (wait != WAIT_TIMEOUT)
                        {
                            result.FailureStage = NativeFailureStage.WaitForProcess;
                            result.NativeError = Marshal.GetLastWin32Error();
                            if (!TerminateJobWithin(job, process.hProcess, terminationVerificationMilliseconds))
                                result.FailureStage = NativeFailureStage.TerminationIncomplete;
                            break;
                        }

                        if (stdoutCapture.Exceeded || stderrCapture.Exceeded)
                        {
                            // One additional bounded poll lets the sibling pipe
                            // drain independently when the child filled stdout
                            // before it could write stderr. A continuously
                            // writing process is still terminated on the next
                            // 25 ms iteration.
                            if (!outputLimitObserved)
                            {
                                outputLimitObserved = true;
                                continue;
                            }
                            result.FailureStage = NativeFailureStage.OutputLimit;
                            if (!TerminateJobWithin(job, process.hProcess, terminationVerificationMilliseconds))
                                result.FailureStage = NativeFailureStage.TerminationIncomplete;
                            break;
                        }

                        DateTime now = DateTime.UtcNow;
                        if (!cancellationRequested && cancellationToken.IsCancellationRequested)
                        {
                            cancellationRequested = true;
                            cancellationDeadline = now.AddMilliseconds(cancellationGraceMilliseconds);
                            try { cancellationEvent.Set(); }
                            catch
                            {
                                result.FailureStage = NativeFailureStage.HardCancellation;
                                result.CancellationMode = NativeCancellationMode.Hard;
                                if (!TerminateJobWithin(job, process.hProcess, terminationVerificationMilliseconds))
                                    result.FailureStage = NativeFailureStage.TerminationIncomplete;
                                break;
                            }
                        }
                        if (cancellationRequested && now >= cancellationDeadline)
                        {
                            result.FailureStage = NativeFailureStage.HardCancellation;
                            result.CancellationMode = NativeCancellationMode.Hard;
                            if (!TerminateJobWithin(job, process.hProcess, terminationVerificationMilliseconds))
                                result.FailureStage = NativeFailureStage.TerminationIncomplete;
                            break;
                        }
                        if (!cancellationRequested && now >= deadline)
                        {
                            result.FailureStage = NativeFailureStage.Deadline;
                            if (!TerminateJobWithin(job, process.hProcess, terminationVerificationMilliseconds))
                                result.FailureStage = NativeFailureStage.TerminationIncomplete;
                            break;
                        }
                    }
                }

                uint exitCode;
                if (GetExitCodeProcess(process.hProcess, out exitCode)) result.ExitCode = unchecked((int)exitCode);

                // A successful root may still have descendants. Terminating the
                // job after the root exits is deliberate: collectors return data,
                // not background services. The accounting query is the kernel's
                // proof that every process assigned to this owned tree is gone.
                TerminateJobObject(job, 0xee);
                int accountingAttempts = Math.Max(1, terminationVerificationMilliseconds / 10);
                for (int attempt = 0; attempt < accountingAttempts; attempt++)
                {
                    uint active = ActiveProcessCount(job);
                    if (active != UInt32.MaxValue) peakActive = Math.Max(peakActive, (int)active);
                    if (active == 0) { result.CompleteOwnedTreeAbsent = true; break; }
                    System.Threading.Thread.Sleep(10);
                }
                result.PeakActiveProcesses = peakActive;

                // Pipe reads never wait for EOF. PeekNamedPipe reports only
                // bytes already buffered by the kernel, and ReadFile consumes
                // no more than that reported amount. Consequently a failed
                // TerminateJobObject cannot strand the supervisor in a pipe
                // task after the finite termination/accounting interval.
                int finalOutputError;
                int finalPassLimit = Math.Max(
                    4096, Math.Max(standardOutputLimit, standardErrorLimit) + 4096);
                if ((!DrainAvailablePipe(stdoutRead, stdoutCapture, finalPassLimit, out finalOutputError) ||
                    !DrainAvailablePipe(stderrRead, stderrCapture, finalPassLimit, out finalOutputError)) &&
                    result.FailureStage == NativeFailureStage.None)
                {
                    result.FailureStage = NativeFailureStage.CaptureOutput;
                    result.NativeError = finalOutputError;
                }
                CaptureResult stdout = stdoutCapture.Snapshot();
                CaptureResult stderr = stderrCapture.Snapshot();
                result.StandardOutput = stdout.Prefix;
                result.StandardError = stderr.Prefix;
                result.StandardOutputBytes = stdout.TotalBytes;
                result.StandardErrorBytes = stderr.TotalBytes;
                result.StandardOutputExceeded = stdout.Exceeded;
                result.StandardErrorExceeded = stderr.Exceeded;
                return result;
            }
            finally
            {
                if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
                if (stdoutRead != IntPtr.Zero) CloseHandle(stdoutRead);
                if (stdoutWrite != IntPtr.Zero) CloseHandle(stdoutWrite);
                if (stderrRead != IntPtr.Zero) CloseHandle(stderrRead);
                if (stderrWrite != IntPtr.Zero) CloseHandle(stderrWrite);
                if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
                if (job != IntPtr.Zero) CloseHandle(job);
            }
        }
    }
}
'@
}

function Get-SyntheticCollectorScriptBytes {
$script = @'
$ErrorActionPreference = 'Stop'
[System.Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[System.Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$Operation = [System.Environment]::GetEnvironmentVariable('WINPCINFO_OPERATION_MODE')
function Get-BaseDeviceActualPayload {
    param([Parameter(Mandatory)] [string[]] $ComputerSystemProperties)

    # The historical readiness and expanded context operations deliberately
    # keep separate identities and authority. This helper shares only their
    # common bounded projections; each caller still supplies its own exact
    # ComputerSystem property allowlist before adding operation-specific facts.
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem `
        -Property $ComputerSystemProperties -ErrorAction Stop
    $processor = @(Get-CimInstance -ClassName Win32_Processor -Property Name -ErrorAction Stop)[0]
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem `
        -Property OperatingSystemSKU, BuildNumber -ErrorAction Stop
    [pscustomobject]@{
        computer = $computer
        device = [ordered]@{
            manufacturer = if ($null -eq $computer.Manufacturer) { $null } else { [string] $computer.Manufacturer }
            model = if ($null -eq $computer.Model) { $null } else { [string] $computer.Model }
            processorName = if ($null -eq $processor.Name) { $null } else { [string] $processor.Name }
            memoryBytes = if ($null -eq $computer.TotalPhysicalMemory) { $null } else { [long] $computer.TotalPhysicalMemory }
            operatingSystemSku = if ($null -eq $operatingSystem.OperatingSystemSKU) { $null } else { [int] $operatingSystem.OperatingSystemSKU }
            build = if ($null -eq $operatingSystem.BuildNumber) { $null } else { [string] $operatingSystem.BuildNumber }
            architecture = [string] [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
            sourceLocale = [System.Globalization.CultureInfo]::CurrentUICulture.Name
        }
    }
}
function New-SyntheticBaseDevicePayload {
    param([Parameter(Mandatory)] [string] $Model)
    [ordered]@{
        manufacturer = 'Fabrikam'; model = $Model; processorName = 'Synthetic Processor'
        memoryBytes = [long]17179869184; operatingSystemSku = 48; build = '26100'
        architecture = 'X64'; sourceLocale = 'en-US'
    }
}
function Set-SyntheticBaseDeviceScenario {
    param([Parameter(Mandatory)] $Device, [Parameter(Mandatory)] [string] $Scenario)
    if ($Scenario -eq 'Partial') { $Device.memoryBytes = $null }
    if ($Scenario -eq 'Virtual') {
        $Device.manufacturer = 'Microsoft Corporation'; $Device.model = 'Virtual Machine'
    }
    if ($Scenario -eq 'Unicode') {
        $Device.manufacturer = 'Fabrikam 日本語'; $Device.model = 'Modèle Δ'
        $Device.processorName = 'Processeur synthétique العربية'
    }
    if ($Scenario -eq 'NonEnglish') { $Device.sourceLocale = 'fr-FR' }
}
if ($Operation -eq 'Success') {
    [System.Console]::Out.Write('{"displayName":"WIN-PCInfo synthétique 日本語 العربية"}')
    [System.Console]::Error.Write('synthetic collector diagnostic')
    exit 0
}
if ($Operation -like 'Context*') {
    if ($Operation -eq 'ContextMalformed') {
        [System.Console]::Out.Write('{not-json')
        exit 0
    }
    if ($Operation -eq 'ContextOversize') {
        [System.Console]::Out.Write(('X' * 70000))
        exit 0
    }
    if ($Operation -eq 'ContextUnavailable') {
        [System.Console]::Out.Write('{"availability":"Unavailable"}')
        exit 0
    }
    if ($Operation -eq 'ContextActual') {
        # Every Windows query below names an exact property projection. This is
        # especially important for SoftwareLicensingProduct: that provider also
        # exposes key-adjacent identity properties that the assessment has no
        # authority to collect. Selecting LicenseStatus alone prevents those
        # values from crossing the source boundary, so omission does not depend
        # on later redaction, logging discipline, or a best-effort cleanup.
        $base = Get-BaseDeviceActualPayload -ComputerSystemProperties @(
            'Manufacturer','Model','TotalPhysicalMemory','PCSystemType','HypervisorPresent'
        )
        $computer = $base.computer

        $activationAvailability = 'Available'
        $activationStatus = $null
        try {
            $licenseRows = @(Get-CimInstance -ClassName SoftwareLicensingProduct `
                -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" `
                -Property LicenseStatus -ErrorAction Stop | Select-Object -First 16)
            $statusCodes = @($licenseRows | ForEach-Object { [int] $_.LicenseStatus })
            if (1 -in $statusCodes) { $activationStatus = 1 }
            elseif ($statusCodes.Count -gt 0) { $activationStatus = [int] $statusCodes[0] }
        }
        catch { $activationAvailability = 'Unavailable' }

        $chassisAvailability = 'Available'
        $chassisTypeCodes = $null
        try {
            $enclosure = @(Get-CimInstance -ClassName Win32_SystemEnclosure `
                -Property ChassisTypes -ErrorAction Stop | Select-Object -First 1)[0]
            if ($null -ne $enclosure -and $null -ne $enclosure.ChassisTypes) {
                $codes = @($enclosure.ChassisTypes | ForEach-Object { [int] $_ } |
                    Where-Object { $_ -ge 0 -and $_ -le 255 } | Sort-Object -Unique |
                    Select-Object -First 8)
                if ($codes.Count -gt 0) { $chassisTypeCodes = $codes -join ',' }
            }
        }
        catch { $chassisAvailability = 'Unavailable' }

        $batteryAvailability = 'Available'
        $batteryPresent = $null
        $batteryStatus = $null
        $batteryChargePercent = $null
        $batteryRuntimeMinutes = $null
        try {
            # Win32_Battery is guest-visible and provider-dependent. One exact
            # instance keeps output bounded; missing properties and documented
            # sentinel-like runtime values remain unknown. Query denial is
            # reduced to an availability code so native error text, paths, and
            # identifiers cannot leak into diagnostics or trigger a retry.
            $battery = @(Get-CimInstance -ClassName Win32_Battery `
                -Property BatteryStatus, EstimatedChargeRemaining, EstimatedRunTime `
                -ErrorAction Stop | Select-Object -First 1)[0]
            $batteryPresent = $null -ne $battery
            if ($batteryPresent) {
                if ($null -ne $battery.BatteryStatus) { $batteryStatus = [int] $battery.BatteryStatus }
                if ($null -ne $battery.EstimatedChargeRemaining) {
                    $charge = [int] $battery.EstimatedChargeRemaining
                    if ($charge -ge 0 -and $charge -le 100) { $batteryChargePercent = $charge }
                }
                if ($null -ne $battery.EstimatedRunTime) {
                    $runtime = [int64] $battery.EstimatedRunTime
                    if ($runtime -ge 0 -and $runtime -le 10080) {
                        $batteryRuntimeMinutes = [int] $runtime
                    }
                }
            }
        }
        catch { $batteryAvailability = 'Unavailable' }

        $device = $base.device
        $device['activationStatus'] = $activationStatus
        $device['activationAvailability'] = $activationAvailability
        $device['computerSystemType'] = if ($null -eq $computer.PCSystemType) { $null } else { [int] $computer.PCSystemType }
        $device['hypervisorPresent'] = if ($null -eq $computer.HypervisorPresent) { $null } else { [bool] $computer.HypervisorPresent }
        $device['chassisTypeCodes'] = $chassisTypeCodes
        $device['chassisAvailability'] = $chassisAvailability
        $device['batteryAvailability'] = $batteryAvailability
        $device['batteryPresent'] = $batteryPresent
        $device['batteryStatus'] = $batteryStatus
        $device['batteryChargePercent'] = $batteryChargePercent
        $device['batteryRuntimeMinutes'] = $batteryRuntimeMinutes
        [System.Console]::Out.Write(($device | ConvertTo-Json -Compress))
        exit 0
    }
    $device = New-SyntheticBaseDevicePayload -Model 'Model-49'
    $device += [ordered]@{
        activationStatus = 1
        activationAvailability = 'Available'
        computerSystemType = 1
        hypervisorPresent = $false
        chassisTypeCodes = '3'
        chassisAvailability = 'Available'
        batteryAvailability = 'Available'
        batteryPresent = $false
        batteryStatus = $null
        batteryChargePercent = $null
        batteryRuntimeMinutes = $null
    }
    $contextScenario = $Operation.Substring('Context'.Length)
    Set-SyntheticBaseDeviceScenario -Device $device -Scenario $contextScenario
    if ($Operation -eq 'ContextPartial') { $device.activationStatus = $null }
    if ($Operation -eq 'ContextVirtual') {
        $device.hypervisorPresent = $true; $device.computerSystemType = 1
    }
    if ($Operation -eq 'ContextUnactivated') { $device.activationStatus = 0 }
    if ($Operation -eq 'ContextLaptop') {
        $device.computerSystemType = 2; $device.chassisTypeCodes = '9'
    }
    if ($Operation -eq 'ContextBatteryPresent') {
        $device.computerSystemType = 2; $device.chassisTypeCodes = '10'
        $device.batteryPresent = $true; $device.batteryStatus = 6
        $device.batteryChargePercent = 72; $device.batteryRuntimeMinutes = 180
    }
    if ($Operation -eq 'ContextBatteryUnavailable') {
        $device.batteryAvailability = 'Unavailable'; $device.batteryPresent = $null
    }
    if ($Operation -eq 'ContextDenied') {
        $device.activationAvailability = 'Denied'; $device.activationStatus = $null
        $device.chassisAvailability = 'Denied'; $device.chassisTypeCodes = $null
        $device.batteryAvailability = 'Denied'; $device.batteryPresent = $null
    }
    if ($Operation -eq 'ContextProhibitedMaterial') {
        $blockedName = 'partial' + 'Product' + 'Key'
        $device[$blockedName] = 'synthetic-prohibited-marker'
    }
    [System.Console]::Out.Write(($device | ConvertTo-Json -Compress))
    exit 0
}
if ($Operation -like 'Device*') {
    if ($Operation -eq 'DeviceMalformed') {
        [System.Console]::Out.Write('{not-json')
        exit 0
    }
    if ($Operation -eq 'DeviceOversize') {
        [System.Console]::Out.Write(('X' * 70000))
        exit 0
    }
    if ($Operation -eq 'DeviceUnavailable') {
        [System.Console]::Out.Write('{"availability":"Unavailable"}')
        exit 0
    }
    if ($Operation -eq 'DeviceActual') {
        # These are projection queries, not broad object dumps. Explicit
        # property lists prevent a future provider from silently widening the
        # evidence set, while numeric OperatingSystemSKU avoids treating a
        # localized marketing Caption as a stable identifier.
        $device = (Get-BaseDeviceActualPayload -ComputerSystemProperties @(
            'Manufacturer','Model','TotalPhysicalMemory'
        )).device
        [System.Console]::Out.Write(($device | ConvertTo-Json -Compress))
        exit 0
    }
    $device = New-SyntheticBaseDevicePayload -Model 'Model-48'
    Set-SyntheticBaseDeviceScenario -Device $device `
        -Scenario $Operation.Substring('Device'.Length)
    [System.Console]::Out.Write(($device | ConvertTo-Json -Compress))
    exit 0
}
if ($Operation -eq 'ExcessOutput') {
    [System.Console]::Out.Write(('O' * 8192))
    [System.Console]::Error.Write(('E' * 6144))
    exit 0
}
if ($Operation -eq 'Timeout') {
    [System.Threading.Thread]::Sleep(30000)
    exit 0
}
if ($Operation -eq 'CooperativeCancel') {
    $eventName = [System.Environment]::GetEnvironmentVariable('WINPCINFO_CANCEL_EVENT')
    if ([string]::IsNullOrWhiteSpace($eventName)) { exit 65 }
    $cancelEvent = [System.Threading.EventWaitHandle]::OpenExisting($eventName)
    try {
        while (-not $cancelEvent.WaitOne(25)) { }
    }
    finally {
        $cancelEvent.Dispose()
    }
    exit 75
}
if ($Operation -eq 'HardCancel') {
    [System.Threading.Thread]::Sleep(30000)
    exit 0
}
if ($Operation -eq 'ChildProcess') {
    $childInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $childInfo.FileName = [System.IO.Path]::Combine($PSHOME, 'pwsh.exe')
    $childInfo.UseShellExecute = $false
    $encodedPayload = [System.Environment]::GetEnvironmentVariable('WINPCINFO_ENCODED_PAYLOAD')
    foreach ($argument in @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedPayload
    )) {
        $null = $childInfo.ArgumentList.Add($argument)
    }
    $childInfo.Environment['WINPCINFO_OPERATION_MODE'] = 'ChildLeaf'
    $child = [System.Diagnostics.Process]::Start($childInfo)
    try {
        [System.Threading.Thread]::Sleep(300)
        [System.Console]::Out.Write('{"displayName":"WIN-PCInfo synthétique 日本語 العربية"}')
    }
    finally {
        $child.Dispose()
    }
    exit 0
}
if ($Operation -eq 'ChildLeaf') {
    [System.Threading.Thread]::Sleep(30000)
    exit 0
}
exit 64
'@
    # Windows bounds a process command line and environment block. The source
    # above stays generously commented for reviewers, while the executed copy
    # deterministically removes blank/comment-only lines and indentation. This
    # is not an obfuscator or trust shortcut: the exact compact bytes are hashed
    # into the release catalog, reverified before launch, and remain readable
    # PowerShell. If compaction ever exceeds the fixed launch bound, collection
    # fails before CreateProcess rather than switching to a writable script.
    $compactLines = foreach ($line in $script.Replace("`r`n", "`n").Split("`n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -gt 0 -and -not $trimmed.StartsWith('#')) { $trimmed }
    }
    [System.Text.UTF8Encoding]::new($false).GetBytes($compactLines -join "`n")
}

function Get-Sha256ForSupervisorBytes {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-NativeSupervisorReasonCode {
    param([Parameter(Mandatory)] $NativeResult)

    if ($NativeResult.FailureStage -eq
        [WinPCInfo.ProcessSupervisor.NativeFailureStage]::AssignJobObjectIncompatible) {
        return 'PROCESS.JOB_INCOMPATIBLE'
    }
    if ($NativeResult.FailureStage -eq
        [WinPCInfo.ProcessSupervisor.NativeFailureStage]::TerminationIncomplete) {
        return 'PROCESS.TERMINATION_INCOMPLETE'
    }
    if ($NativeResult.StandardOutputExceeded -or $NativeResult.StandardErrorExceeded) {
        return 'PROCESS.OUTPUT_LIMIT_EXCEEDED'
    }
    if ($NativeResult.FailureStage -eq [WinPCInfo.ProcessSupervisor.NativeFailureStage]::Deadline) {
        return 'PROCESS.DEADLINE_EXCEEDED'
    }
    if ($NativeResult.FailureStage -eq
        [WinPCInfo.ProcessSupervisor.NativeFailureStage]::CooperativeCancellation) {
        return 'PROCESS.CANCELLED_COOPERATIVELY'
    }
    if ($NativeResult.FailureStage -eq
        [WinPCInfo.ProcessSupervisor.NativeFailureStage]::HardCancellation) {
        return 'PROCESS.CANCELLED_HARD'
    }
    ''
}

function New-ProcessSupervisorResult {
    param(
        [Parameter(Mandatory)] [string] $OperationId,
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [System.DateTimeOffset] $StartedAt,
        [Parameter(Mandatory)] [string] $Outcome,
        [Parameter(Mandatory)] [string] $CoverageState,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [AllowEmptyString()] [string] $CoverageReasonCode = '',
        [Parameter()] [AllowEmptyString()] [string] $PolicyDigest = '',
        [Parameter()] [AllowEmptyString()] [string] $PayloadDigest = '',
        [Parameter(Mandatory)] [int] $StandardOutputMaximumBytes,
        [Parameter(Mandatory)] [int] $StandardErrorMaximumBytes,
        [Parameter()] $NativeResult,
        [Parameter()] [AllowEmptyString()] [string] $ObservationValue,
        [Parameter()] $PrivatePayload
    )

    $coverageId = "coverage:synthetic-device-os:$RunId"
    $diagnosticId = "diagnostic:process-supervisor:$RunId"
    $hasObservation = $PSBoundParameters.ContainsKey('ObservationValue')
    $observationId = if ($hasObservation) { "observation:synthetic-os-name:$RunId" } else { '' }
    $hasDiagnostic = -not $hasObservation
    if (-not $CoverageReasonCode) {
        $CoverageReasonCode = $ReasonCode
    }
    $observationIds = if ($hasObservation) { @($observationId) } else { @() }
    $diagnosticIds = if ($hasDiagnostic) { @($diagnosticId) } else { @() }
    $observations = if ($hasObservation) {
        @([pscustomobject][ordered]@{
            observationId = $observationId
            fieldId = 'field:device.os.display-name'
            subjectId = 'subject:synthetic-device:primary'
            valueState = 'ObservedValue'
            value = $ObservationValue
        })
    }
    else {
        @()
    }
    $diagnostics = if ($hasDiagnostic) {
        @([pscustomobject][ordered]@{
            diagnosticId = $diagnosticId
            phase = 'Collection'
            reasonCode = $ReasonCode
            messageId = if ($Outcome -eq 'NotStarted') {
                'process.supervisor.not-started'
            }
            else {
                'process.supervisor.attempt-failed'
            }
        })
    }
    else {
        @()
    }
    $processStarted = $null -ne $NativeResult -and [bool] $NativeResult.Started
    $treeControlMode = if ($processStarted) { 'WindowsJobObject' } else { 'NoLaunch' }
    $outputBytes = if ($null -ne $NativeResult) { $NativeResult.StandardOutputBytes } else { 0 }
    $errorBytes = if ($null -ne $NativeResult) { $NativeResult.StandardErrorBytes } else { 0 }
    $outputExceeded = $null -ne $NativeResult -and [bool] $NativeResult.StandardOutputExceeded
    $errorExceeded = $null -ne $NativeResult -and [bool] $NativeResult.StandardErrorExceeded
    $completeTreeAbsent = $null -eq $NativeResult -or [bool] $NativeResult.CompleteOwnedTreeAbsent
    $terminationMode = if ($null -ne $NativeResult) { [string] $NativeResult.CancellationMode } else { 'None' }
    $deviceOperation = $OperationId -eq 'op:device.windows-readiness.collect'
    $contextOperation = $OperationId -eq 'op:device.windows-context.collect'
    $resultCollectorId = if ($contextOperation) { 'collector:windows.device-context' }
        elseif ($deviceOperation) { 'collector:windows.device-readiness' }
        else { 'collector:synthetic.windows.os' }
    $resultScopeId = if ($contextOperation) { 'scope:device.windows-context' }
        elseif ($deviceOperation) { 'scope:device.windows-readiness' }
        else { 'scope:synthetic.device.os' }
    $resultSubjectId = if ($deviceOperation -or $contextOperation) { 'subject:device:primary' }
        else { 'subject:synthetic-device:primary' }

    $result = [pscustomobject][ordered]@{
        Envelope = [pscustomobject][ordered]@{
            envelopeId = "envelope:synthetic-windows-os:$RunId"
            collectorId = $resultCollectorId
            collectorVersion = '1.0.0'
            operationId = $OperationId
            intendedScopeIds = @($resultScopeId)
            subjectIds = @($resultSubjectId)
            startedAt = $StartedAt.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            completedAt = [System.DateTimeOffset]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            executionContext = 'Synthetic'
            attempts = 1
            observationIds = $observationIds
            coverageIds = @($coverageId)
            diagnosticIds = $diagnosticIds
        }
        Observations = $observations
        Coverage = @([pscustomobject][ordered]@{
            coverageId = $coverageId
            scopeId = $resultScopeId
            state = $CoverageState
            reasonCode = $CoverageReasonCode
            observationIds = $observationIds
            diagnosticIds = $diagnosticIds
        })
        Diagnostics = $diagnostics
        Supervision = [pscustomobject][ordered]@{
            outcome = $Outcome
            reasonCode = $ReasonCode
            policyDigest = $PolicyDigest
            payloadDigest = $PayloadDigest
            processStarted = $processStarted
            treeControlMode = $treeControlMode
            workingBoundaryKind = 'ActivePowerShellHome'
            standardOutput = [pscustomobject][ordered]@{
                byteCount = $outputBytes
                maximumBytes = $StandardOutputMaximumBytes
                exceeded = $outputExceeded
            }
            standardError = [pscustomobject][ordered]@{
                byteCount = $errorBytes
                maximumBytes = $StandardErrorMaximumBytes
                exceeded = $errorExceeded
            }
            peakActiveProcesses = if ($null -ne $NativeResult) { $NativeResult.PeakActiveProcesses } else { 0 }
            terminationMode = $terminationMode
            completeOwnedTreeAbsent = $completeTreeAbsent
            temporaryArtifactsAbsent = $false
        }
    }
    if ($PSBoundParameters.ContainsKey('PrivatePayload')) {
        # This member is deliberately absent from every public record. The
        # caller must normalize it into typed observations before it can cross
        # the evidence boundary; raw collector output is never logged.
        $result | Add-Member -NotePropertyName PrivatePayload -NotePropertyValue $PrivatePayload
    }
    $result
}

function Test-BoundedBaseDevicePayload {
    param([Parameter(Mandatory)] $Payload)

    # Both release-owned device operations share these eight base facts. Shape
    # closure remains operation-specific below; this helper centralizes their
    # type, locale, range, and UTF-8 bounds so a safety correction cannot drift
    # between historical readiness and the expanded context collector.
    $basePropertyNames = @(
        'manufacturer','model','processorName','memoryBytes','operatingSystemSku',
        'build','architecture','sourceLocale'
    )
    $presentNames = @($Payload.PSObject.Properties.Name)
    if (@($basePropertyNames | Where-Object { $_ -notin $presentNames }).Count -gt 0) {
        return $false
    }
    ($null -eq $Payload.manufacturer -or $Payload.manufacturer -is [string]) -and
        ($null -eq $Payload.model -or $Payload.model -is [string]) -and
        ($null -eq $Payload.processorName -or $Payload.processorName -is [string]) -and
        ($null -eq $Payload.build -or $Payload.build -is [string]) -and
        ($null -eq $Payload.architecture -or $Payload.architecture -is [string]) -and
        $Payload.sourceLocale -is [string] -and
        ($null -eq $Payload.memoryBytes -or $Payload.memoryBytes -is [long] -or
            $Payload.memoryBytes -is [int]) -and
        ($null -eq $Payload.operatingSystemSku -or $Payload.operatingSystemSku -is [long] -or
            $Payload.operatingSystemSku -is [int]) -and
        ($null -eq $Payload.manufacturer -or
            -not [string]::IsNullOrWhiteSpace([string]$Payload.manufacturer)) -and
        ($null -eq $Payload.model -or -not [string]::IsNullOrWhiteSpace([string]$Payload.model)) -and
        ($null -eq $Payload.processorName -or
            -not [string]::IsNullOrWhiteSpace([string]$Payload.processorName)) -and
        ($null -eq $Payload.build -or [string]$Payload.build -match '^[0-9]{1,10}$') -and
        ($null -eq $Payload.architecture -or
            [string]$Payload.architecture -match '^(?i:X64|AMD64|Arm64|X86)$') -and
        [string]$Payload.sourceLocale -match '^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$' -and
        ($null -eq $Payload.operatingSystemSku -or ([long]$Payload.operatingSystemSku -ge 0 -and
            [long]$Payload.operatingSystemSku -le 1000)) -and
        ($null -eq $Payload.memoryBytes -or ([long]$Payload.memoryBytes -ge 1 -and
            [long]$Payload.memoryBytes -le 9007199254740991)) -and
        @($Payload.manufacturer, $Payload.model, $Payload.processorName, $Payload.build,
            $Payload.architecture, $Payload.sourceLocale | Where-Object {
                [System.Text.Encoding]::UTF8.GetByteCount([string]$_) -gt 512
            }).Count -eq 0
}

function Invoke-ApprovedCollectorProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $OperationId,

        [Parameter()]
        [System.Threading.CancellationToken] $CancellationToken = [System.Threading.CancellationToken]::None,

        # A fixture selects only one release-owned adapter behavior. It cannot
        # supply evidence, WMI/CIM text, a command, executable, or argument.
        [Parameter(DontShow)]
        [ValidateSet('', 'Complete', 'Partial', 'Unavailable', 'Malformed', 'Oversize',
            'Virtual', 'Unicode', 'NonEnglish', 'Activated', 'Physical', 'Desktop',
            'BatteryAbsent', 'Unactivated', 'Laptop', 'BatteryPresent', 'BatteryUnavailable',
            'Denied', 'ProhibitedMaterial')]
        [string] $DeviceReadinessScenario = ''
    )

    Initialize-ProcessSupervisorNativeType
    $startedAt = [System.DateTimeOffset]::UtcNow
    $runId = [System.Guid]::NewGuid().ToString('N')
    $workingDirectory = ''
    $cancellationEventName = ''
    $cancellationEvent = $null
    $temporaryArtifactsAbsent = $false
    $collectorResult = $null
    $native = $null
    $policyDigest = ''
    $payloadDigest = ''
    $standardOutputMaximumBytes = 4096
    $standardErrorMaximumBytes = 4096

    try {
        $convertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
            'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
        )
        if ($null -eq $convertFromJsonCommand -or
            $convertFromJsonCommand.ModuleName -ne 'Microsoft.PowerShell.Utility') {
            throw 'The collector policy JSON command does not have built-in provenance.'
        }
        $policy = Get-ApprovedCollectorCatalog -ConvertFromJsonCommand $convertFromJsonCommand
        if (-not $policy.Valid) {
            $exception = [System.InvalidOperationException]::new('The approved collector policy failed integrity validation.')
            $exception.Data['ReasonCode'] = $policy.ReasonCode
            throw $exception
        }
        $policyDigest = [string] $policy.Digest
        $fixtureId = if ($OperationId.StartsWith('fixture:synthetic.', [System.StringComparison]::Ordinal)) {
            $OperationId.Substring('fixture:synthetic.'.Length)
        }
        else { '' }
        $selectedCollectorId = if ($OperationId -eq 'op:device.windows-context.collect') {
            'collector:windows.device-context'
        }
        elseif ($OperationId -eq 'op:device.windows-readiness.collect') {
            'collector:windows.device-readiness'
        }
        else { 'collector:synthetic.windows.os' }
        $collectorPolicy = @($policy.Collectors | Where-Object collectorId -eq $selectedCollectorId)[0]
        $selectedOperationId = if ($fixtureId) { 'op:synthetic.windows.os.success' } else { $OperationId }
        $operationPolicy = @($collectorPolicy.operations | Where-Object operationId -eq $selectedOperationId)[0]
        if ($null -eq $operationPolicy) {
            $exception = [System.InvalidOperationException]::new('The operation is not release-defined.')
            $exception.Data['ReasonCode'] = 'PROCESS.OPERATION_INVALID'
            throw $exception
        }
        $payloadDigest = [string] $collectorPolicy.payload.sha256
        $standardOutputMaximumBytes = [int] $operationPolicy.standardOutputMaximumBytes
        $standardErrorMaximumBytes = [int] $operationPolicy.standardErrorMaximumBytes
        $fixturePolicy = if ($fixtureId) {
            @($policy.Catalog.validationFixtures | Where-Object fixtureId -eq $fixtureId)[0]
        }
        else {
            $null
        }
        if ($fixtureId -and $null -eq $fixturePolicy) {
            $exception = [System.InvalidOperationException]::new('The validation fixture is not release-defined.')
            $exception.Data['ReasonCode'] = 'PROCESS.OPERATION_INVALID'
            throw $exception
        }

        if (-not (Get-Command Get-BuiltInModuleCompatibilityFacts -CommandType Function -ErrorAction SilentlyContinue)) {
            throw 'The trusted runtime module discovery function is unavailable.'
        }
        $moduleFacts = Get-BuiltInModuleCompatibilityFacts
        $AuthenticodeCommand = $moduleFacts.authenticodeCommand

        $scriptBytes = Get-SyntheticCollectorScriptBytes
        if ((Get-Sha256ForSupervisorBytes -Bytes $scriptBytes) -ne $payloadDigest) {
            throw 'The embedded synthetic collector identity does not match the release catalog.'
        }
        $scriptText = [System.Text.UTF8Encoding]::new($false, $true).GetString($scriptBytes)
        $encodedPayload = [System.Convert]::ToBase64String(
            [System.Text.Encoding]::Unicode.GetBytes($scriptText)
        )

        # Cancellation uses a run-unique named kernel event rather than a file.
        # The event gives the approved child one cooperative signal without a
        # writable script or marker path. Windows keeps it alive only while an
        # owned process holds a handle; disposing the last handle removes the
        # object. Name collision fails closed before the collector is resumed.
        $cancellationEventName = "Local\WINPCInfo-ProcessSupervisor-$runId"
        [bool] $createdNewCancellationEvent = $false
        $cancellationEvent = [System.Threading.EventWaitHandle]::new(
            $false, [System.Threading.EventResetMode]::ManualReset,
            $cancellationEventName, [ref] $createdNewCancellationEvent
        )
        if (-not $createdNewCancellationEvent) {
            throw 'The run-owned cancellation event already exists.'
        }

        # The operation catalog resolves the current signed PowerShell host; no
        # executable path crosses the caller boundary. Comparing the literal
        # active image with PSHOME prevents PATH search, aliases, file-association
        # launch, or a same-named executable elsewhere from gaining approval.
        $approvedExecutableName = if ($null -ne $fixturePolicy -and
            $fixturePolicy.fault -eq 'ExecutableIdentityMismatch') {
            'not-approved.exe'
        }
        else {
            [string] $collectorPolicy.executable.fileName
        }
        $approvedExecutable = [System.IO.Path]::GetFullPath(
            [System.IO.Path]::Combine($PSHOME, $approvedExecutableName)
        )
        $activeExecutable = [System.IO.Path]::GetFullPath(
            [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        )
        if (-not $approvedExecutable.Equals($activeExecutable, [System.StringComparison]::OrdinalIgnoreCase)) {
            $exception = [System.InvalidOperationException]::new(
                'The active executable is not the release-defined PowerShell host.'
            )
            $exception.Data['ReasonCode'] = 'PROCESS.EXECUTABLE_IDENTITY_INVALID'
            throw $exception
        }
        $workingDirectory = [System.IO.Path]::GetFullPath($PSHOME)
        if (-not [System.IO.Path]::GetDirectoryName($activeExecutable).Equals(
            $workingDirectory, [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw 'The release-defined working boundary does not match the active PowerShell home.'
        }
        if ($null -eq $AuthenticodeCommand -or $AuthenticodeCommand.CommandType -ne 'Cmdlet' -or
            $AuthenticodeCommand.ModuleName -ne 'Microsoft.PowerShell.Security') {
            throw 'The Authenticode verifier does not have the required built-in command provenance.'
        }
        $signature = & $AuthenticodeCommand -LiteralPath $approvedExecutable -ErrorAction Stop
        if ([string] $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
            $signature.SignerCertificate.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false
            ) -ne [string] $collectorPolicy.executable.signerCommonName) {
            throw 'The release-defined PowerShell host does not have the approved Microsoft signature.'
        }

        $operationMode = if ($OperationId -eq 'op:device.windows-context.collect') {
            if ($DeviceReadinessScenario) { "Context$DeviceReadinessScenario" } else { 'ContextActual' }
        }
        elseif ($OperationId -eq 'op:device.windows-readiness.collect') {
            if ($DeviceReadinessScenario) { "Device$DeviceReadinessScenario" } else { 'DeviceActual' }
        }
        elseif ($null -ne $fixturePolicy) {
            [string] $fixturePolicy.operationMode
        }
        else {
            'Success'
        }
        $arguments = @($operationPolicy.arguments | ForEach-Object {
            if ($_ -eq '{EncodedCollectorPayload}') { $encodedPayload } else { [string] $_ }
        })
        if ($null -ne $fixturePolicy -and $fixturePolicy.fault -eq 'SecretShapedArgument') {
            $arguments += '--password=synthetic-prohibited-marker'
        }
        if ($arguments.Count -gt [int] $policy.Catalog.limits.maximumArgumentCount -or @($arguments | Where-Object {
            [System.Text.Encoding]::UTF8.GetByteCount([string] $_) -gt
                [int] $policy.Catalog.limits.maximumArgumentUtf8Bytes
        }).Count -gt 0 -or @($arguments | Where-Object {
            [string] $_ -match '(?i)(password|passwd|secret|token|credential|private[-_]?key|recovery[-_]?key)\s*[:=]'
        }).Count -gt 0) {
            $exception = [System.InvalidOperationException]::new(
                'The release-defined argument vector failed its bounded non-secret policy.'
            )
            $exception.Data['ReasonCode'] = 'PROCESS.ARGUMENT_INVALID'
            throw $exception
        }

        # CreateProcess receives a replacement environment block instead of the
        # parent environment. This prevents tokens, credentials, proxy values,
        # module paths, or attacker-controlled variables from leaking into an
        # otherwise approved collector. Only names required by Windows/.NET and
        # the supervisor's own cancellation protocol are admitted and bounded.
        $environment = [System.Collections.Generic.Dictionary[string,string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        foreach ($variablePolicy in @($collectorPolicy.environment.variables)) {
            $value = switch ([string] $variablePolicy.valueSource) {
                'WindowsDirectory' { [System.Environment]::GetFolderPath('Windows') }
                'CancellationEventName' { $cancellationEventName }
                'OperationMode' { $operationMode }
                'EncodedPayload' { $encodedPayload }
                default { '' }
            }
            $environment[[string] $variablePolicy.name] = $value
        }
        if ($environment.Count -gt [int] $policy.Catalog.limits.maximumEnvironmentVariables) {
            throw 'The release-defined environment block contains too many variables.'
        }
        foreach ($entry in $environment.GetEnumerator()) {
            if ([string]::IsNullOrWhiteSpace($entry.Key) -or
                [System.Text.Encoding]::UTF8.GetByteCount($entry.Value) -gt
                    [int] $policy.Catalog.limits.maximumEnvironmentValueUtf8Bytes) {
                throw 'The release-defined environment block is invalid.'
            }
        }

        $deadlineMilliseconds = if ($null -ne $fixturePolicy -and
            $fixturePolicy.PSObject.Properties['deadlineMilliseconds']) {
            [int] $fixturePolicy.deadlineMilliseconds
        }
        else {
            [int] $operationPolicy.deadlineMilliseconds
        }
        $native = [WinPCInfo.ProcessSupervisor.NativeRunner]::Run(
            $approvedExecutable, $arguments, $workingDirectory, $environment,
            $deadlineMilliseconds, $standardOutputMaximumBytes, $standardErrorMaximumBytes,
            $CancellationToken, $cancellationEvent,
            [int] $operationPolicy.cancellationGraceMilliseconds,
            [int] $operationPolicy.terminationVerificationMilliseconds,
            ($null -ne $fixturePolicy -and $fixturePolicy.fault -eq 'JobAssignmentIncompatible')
        )
        $nativeReasonCode = Get-NativeSupervisorReasonCode -NativeResult $native
        if ($native.Started -and -not $native.CompleteOwnedTreeAbsent) {
            $nativeReasonCode = 'PROCESS.TERMINATION_INCOMPLETE'
        }
        if ($nativeReasonCode) {
            $exception = [System.InvalidOperationException]::new(
                'The native process attempt ended with a sanitized supervisor reason.'
            )
            $exception.Data['ReasonCode'] = $nativeReasonCode
            throw $exception
        }
        if (-not $native.Started -or
            $native.FailureStage -ne [WinPCInfo.ProcessSupervisor.NativeFailureStage]::None -or
            $native.ExitCode -ne 0 -or
            -not $native.CompleteOwnedTreeAbsent) {
            throw 'The approved synthetic collector did not complete its bounded process contract.'
        }

        # Output is untrusted even from an approved executable: signing proves
        # code identity, not that live output is well-formed or privacy-safe.
        # Strict UTF-8 and a tiny expected JSON shape convert it into one typed
        # observation. The raw stdout/stderr bytes are discarded and never enter
        # progress, a public diagnostic, the envelope, or a repository artifact.
        $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
        try {
            $output = $strictUtf8.GetString($native.StandardOutput) | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            if ($OperationId -in @('op:device.windows-readiness.collect',
                    'op:device.windows-context.collect')) {
                $exception = [System.IO.InvalidDataException]::new(
                    'The approved device collector returned malformed JSON.'
                )
                $exception.Data['ReasonCode'] = 'PROCESS.PAYLOAD_MALFORMED'
                throw $exception
            }
            throw
        }
        if ($OperationId -eq 'op:device.windows-context.collect') {
            $propertyNames = @($output.PSObject.Properties.Name)
            $prohibitedNamePattern = '(?i)(password|passphrase|credential|token|(?:private|recovery|license|product)[._-]?key|pfx|secret)'
            if (@($propertyNames | Where-Object { [string]$_ -match $prohibitedNamePattern }).Count -gt 0) {
                # The public result records only that prohibited material was
                # blocked. Neither the field name nor its value is logged,
                # hashed, diagnosed, reported, or admitted as an observation.
                $exception = [System.Security.SecurityException]::new(
                    'The approved device-context collector returned prohibited material.'
                )
                $exception.Data['ReasonCode'] = 'PROCESS.PROHIBITED_MATERIAL_BLOCKED'
                throw $exception
            }
            $unavailableShape = $propertyNames.Count -eq 1 -and
                $propertyNames[0] -eq 'availability' -and $output.availability -eq 'Unavailable'
            $contextShape = $propertyNames.Count -eq 19 -and
                (@($propertyNames | Sort-Object) -join '|') -eq
                    'activationAvailability|activationStatus|architecture|batteryAvailability|batteryChargePercent|batteryPresent|batteryRuntimeMinutes|batteryStatus|build|chassisAvailability|chassisTypeCodes|computerSystemType|hypervisorPresent|manufacturer|memoryBytes|model|operatingSystemSku|processorName|sourceLocale' -and
                (Test-BoundedBaseDevicePayload -Payload $output) -and
                [string]$output.activationAvailability -in @('Available','Unavailable','Denied') -and
                [string]$output.chassisAvailability -in @('Available','Unavailable','Denied') -and
                [string]$output.batteryAvailability -in @('Available','Unavailable','Denied') -and
                ($null -eq $output.activationStatus -or (
                    ($output.activationStatus -is [long] -or $output.activationStatus -is [int]) -and
                    [long]$output.activationStatus -ge 0 -and [long]$output.activationStatus -le 6)) -and
                ($null -eq $output.computerSystemType -or (
                    ($output.computerSystemType -is [long] -or $output.computerSystemType -is [int]) -and
                    [long]$output.computerSystemType -ge 0 -and [long]$output.computerSystemType -le 255)) -and
                ($null -eq $output.hypervisorPresent -or $output.hypervisorPresent -is [bool]) -and
                ($null -eq $output.chassisTypeCodes -or
                    ($output.chassisTypeCodes -is [string] -and
                    [string]$output.chassisTypeCodes -match '^[0-9]{1,3}(?:,[0-9]{1,3}){0,7}$')) -and
                ($null -eq $output.batteryPresent -or $output.batteryPresent -is [bool]) -and
                ($null -eq $output.batteryStatus -or (
                    ($output.batteryStatus -is [long] -or $output.batteryStatus -is [int]) -and
                    [long]$output.batteryStatus -ge 1 -and [long]$output.batteryStatus -le 11)) -and
                ($null -eq $output.batteryChargePercent -or (
                    ($output.batteryChargePercent -is [long] -or $output.batteryChargePercent -is [int]) -and
                    [long]$output.batteryChargePercent -ge 0 -and [long]$output.batteryChargePercent -le 100)) -and
                ($null -eq $output.batteryRuntimeMinutes -or (
                    ($output.batteryRuntimeMinutes -is [long] -or $output.batteryRuntimeMinutes -is [int]) -and
                    [long]$output.batteryRuntimeMinutes -ge 0 -and [long]$output.batteryRuntimeMinutes -le 10080))
            if (-not $unavailableShape -and -not $contextShape) {
                $exception = [System.IO.InvalidDataException]::new(
                    'The approved device-context collector returned an invalid bounded payload.'
                )
                $exception.Data['ReasonCode'] = 'PROCESS.PAYLOAD_MALFORMED'
                throw $exception
            }
            $coverageState = if ($unavailableShape) { 'Unavailable' }
                elseif ($output.activationAvailability -ne 'Available' -or
                    $output.chassisAvailability -ne 'Available' -or
                    $output.batteryAvailability -ne 'Available' -or $null -eq $output.memoryBytes) {
                    'Partial'
                } else { 'Complete' }
            $coverageReasonCode = if ($coverageState -eq 'Complete') { 'COLLECTION.COMPLETE' }
                elseif ($coverageState -eq 'Partial') { 'COLLECTION.FIELD_UNAVAILABLE' }
                else { 'COLLECTION.SOURCE_UNAVAILABLE' }
            $collectorResult = New-ProcessSupervisorResult -OperationId $OperationId `
                -RunId $runId -StartedAt $startedAt -Outcome 'Completed' -CoverageState $coverageState `
                -ReasonCode 'PROCESS.COMPLETED' -CoverageReasonCode $coverageReasonCode `
                -PolicyDigest $policyDigest -PayloadDigest $payloadDigest `
                -StandardOutputMaximumBytes $standardOutputMaximumBytes `
                -StandardErrorMaximumBytes $standardErrorMaximumBytes `
                -NativeResult $native -PrivatePayload $output
        }
        elseif ($OperationId -eq 'op:device.windows-readiness.collect') {
            $propertyNames = @($output.PSObject.Properties.Name)
            $unavailableShape = $propertyNames.Count -eq 1 -and
                $propertyNames[0] -eq 'availability' -and $output.availability -eq 'Unavailable'
            $deviceShape = $propertyNames.Count -eq 8 -and
                (@($propertyNames | Sort-Object) -join '|') -eq
                    'architecture|build|manufacturer|memoryBytes|model|operatingSystemSku|processorName|sourceLocale' -and
                (Test-BoundedBaseDevicePayload -Payload $output)
            if (-not $unavailableShape -and -not $deviceShape) {
                $exception = [System.IO.InvalidDataException]::new(
                    'The approved device collector returned an invalid bounded payload.'
                )
                $exception.Data['ReasonCode'] = 'PROCESS.PAYLOAD_MALFORMED'
                throw $exception
            }
            $coverageState = if ($unavailableShape) { 'Unavailable' }
                elseif ($null -eq $output.memoryBytes) { 'Partial' } else { 'Complete' }
            $coverageReasonCode = if ($coverageState -eq 'Complete') { 'COLLECTION.COMPLETE' }
                elseif ($coverageState -eq 'Partial') { 'COLLECTION.FIELD_UNAVAILABLE' }
                else { 'COLLECTION.SOURCE_UNAVAILABLE' }
            $collectorResult = New-ProcessSupervisorResult -OperationId $OperationId `
                -RunId $runId -StartedAt $startedAt -Outcome 'Completed' -CoverageState $coverageState `
                -ReasonCode 'PROCESS.COMPLETED' -CoverageReasonCode $coverageReasonCode `
                -PolicyDigest $policyDigest -PayloadDigest $payloadDigest `
                -StandardOutputMaximumBytes $standardOutputMaximumBytes `
                -StandardErrorMaximumBytes $standardErrorMaximumBytes `
                -NativeResult $native -PrivatePayload $output
        }
        else {
            if (@($output.PSObject.Properties.Name).Count -ne 1 -or
                @($output.PSObject.Properties.Name)[0] -ne 'displayName' -or
                $output.displayName -isnot [string] -or
                [System.Text.Encoding]::UTF8.GetByteCount($output.displayName) -gt 256) {
                throw 'The approved synthetic collector returned an invalid observation payload.'
            }
            $collectorResult = New-ProcessSupervisorResult -OperationId $OperationId `
                -RunId $runId -StartedAt $startedAt -Outcome 'Completed' -CoverageState 'Complete' `
                -ReasonCode 'PROCESS.COMPLETED' -CoverageReasonCode 'COLLECTION.COMPLETE' `
                -PolicyDigest $policyDigest -PayloadDigest $payloadDigest `
                -StandardOutputMaximumBytes $standardOutputMaximumBytes `
                -StandardErrorMaximumBytes $standardErrorMaximumBytes `
                -NativeResult $native -ObservationValue ([string] $output.displayName)
        }
    }
    catch {
        $reasonCode = if ($_.Exception.Data.Contains('ReasonCode')) {
            [string] $_.Exception.Data['ReasonCode']
        }
        else {
            'PROCESS.SUPERVISOR_FAILED'
        }
        if ($null -ne $native -and ($native.Started -or $native.FailureStage -eq
            [WinPCInfo.ProcessSupervisor.NativeFailureStage]::TerminationIncomplete)) {
            $attemptOutcome = if ($reasonCode -eq 'PROCESS.DEADLINE_EXCEEDED') {
                'TimedOut'
            }
            elseif ($reasonCode -like 'PROCESS.CANCELLED_*') {
                'Cancelled'
            }
            elseif ($reasonCode -eq 'PROCESS.TERMINATION_INCOMPLETE') {
                'CleanupIncomplete'
            }
            else {
                'Failed'
            }
            $coverageState = if ($attemptOutcome -eq 'CleanupIncomplete') { 'Failed' } else { $attemptOutcome }
            $collectorResult = New-ProcessSupervisorResult -OperationId $OperationId `
                -RunId $runId -StartedAt $startedAt -Outcome $attemptOutcome -CoverageState $coverageState `
                -ReasonCode $reasonCode -NativeResult $native `
                -PolicyDigest $policyDigest -PayloadDigest $payloadDigest `
                -StandardOutputMaximumBytes $standardOutputMaximumBytes `
                -StandardErrorMaximumBytes $standardErrorMaximumBytes
        }
        else {
            $collectorResult = New-ProcessSupervisorResult -OperationId $OperationId `
                -RunId $runId -StartedAt $startedAt -Outcome 'NotStarted' `
                -CoverageState 'NotAttempted' -ReasonCode $reasonCode `
                -PolicyDigest $policyDigest -PayloadDigest $payloadDigest `
                -StandardOutputMaximumBytes $standardOutputMaximumBytes `
                -StandardErrorMaximumBytes $standardErrorMaximumBytes
            if ($reasonCode -eq 'PROCESS.JOB_INCOMPATIBLE') {
                $collectorResult.Supervision.treeControlMode = 'IncompatibleNoLaunch'
            }
        }
    }
    finally {
        # Captured pipe bytes are needed only long enough to validate and
        # normalize the approved success payload. Clearing both retained prefixes
        # avoids preserving unexpected sensitive text in managed buffers. This
        # is best-effort memory hygiene, not a forensic secure-erasure claim.
        if ($null -ne $native) {
            if ($null -ne $native.StandardOutput -and $native.StandardOutput.Length -gt 0) {
                [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($native.StandardOutput)
            }
            if ($null -ne $native.StandardError -and $native.StandardError.Length -gt 0) {
                [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($native.StandardError)
            }
        }
        if ($null -ne $cancellationEvent) {
            $cancellationEvent.Dispose()
        }
        $temporaryArtifactsAbsent = $true
        if ($cancellationEventName) {
            try {
                $eventProbe = [System.Threading.EventWaitHandle]::OpenExisting($cancellationEventName)
                $temporaryArtifactsAbsent = $false
                $eventProbe.Dispose()
            }
            catch [System.Threading.WaitHandleCannotBeOpenedException] {
                $temporaryArtifactsAbsent = $true
            }
            catch {
                $temporaryArtifactsAbsent = $false
            }
        }
        if ($null -ne $collectorResult) {
            $collectorResult.Supervision.temporaryArtifactsAbsent = $temporaryArtifactsAbsent
        }
    }

    $collectorResult
}

function Get-AssessmentCancellationToken {
    $transport = Get-Variable -Name StatusDeskTransport -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $transport) { return $transport.Value.Cancellation.Token }
    [Threading.CancellationToken]::None
}

function Enter-AssessmentCollectionStage {
    param([Parameter(Mandatory)] [string] $Stage)
    if ((Get-AssessmentCancellationToken).IsCancellationRequested) {
        $exception = [OperationCanceledException]::new('Assessment scheduling was cancelled.')
        $exception.Data['ReasonCode'] = 'RUN.CANCELLED'
        throw $exception
    }
    $sequence = Get-Variable -Name AssessmentCollectionSequence -Scope Script -ErrorAction SilentlyContinue
    if ($null -eq $sequence) { $script:AssessmentCollectionSequence = 4 }
    $script:AssessmentCollectionSequence++
    $transport = Get-Variable -Name StatusDeskTransport -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $transport) { $transport.Value.State.CollectionStarted = $true }
    Write-ContractRecord (New-ProgressRecord -Sequence $script:AssessmentCollectionSequence -Phase Collection -State Started `
        -MessageId ('collection.' + $Stage.ToLowerInvariant()) -CompletedUnits 0 -TotalUnits 1) `
        -ConvertToJsonCommand (Get-Command ConvertTo-Json -CommandType Cmdlet)
}

function Test-AssessmentCollectionStage {
    param([Parameter(Mandatory)] [string] $Stage)
    if ((Get-AssessmentCancellationToken).IsCancellationRequested) { return $false }
    Enter-AssessmentCollectionStage -Stage $Stage
    $true
}
