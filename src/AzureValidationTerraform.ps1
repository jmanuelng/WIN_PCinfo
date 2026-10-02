function Initialize-AzureTerraformPathLeaseType {
    if('WinPCInfo.AzureTerraform.FrozenSourceNamespace' -as [type]){return}
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace WinPCInfo.AzureTerraform {
    public sealed class FrozenSourceNamespace : IDisposable {
        private readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
        private bool verified, disposed, cleanupUnverified;
        public string Root { get; private set; }
        public bool Verified { get { return verified && !disposed; } }
        private FrozenSourceNamespace(string root) { Root = root; }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool CloseHandle(IntPtr handle);
        internal static void ReleaseFileHandle(SafeFileHandle handle) {
            if(handle==null || handle.IsClosed) return;
            if(handle.IsInvalid) { handle.Dispose(); return; }
            // Single-close ownership: detach before the native attempt. Neither
            // Dispose nor a finalizer may retry an uncertain raw handle.
            IntPtr raw=handle.DangerousGetHandle();
            handle.SetHandleAsInvalid();
            bool closed=false;
            try { closed=CloseHandle(raw); } catch { closed=false; }
            finally { handle.Dispose(); }
            if(!closed) {
                var failure=new InvalidOperationException("VALIDATION.CLEANUP_UNVERIFIED");
                failure.Data["OwnedCleanupUnverified"]=true;
                failure.Data["OwnedLeaseCleanupUnverified"]=true;
                throw failure;
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString { public ushort Length,MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes {
            public int Length; public IntPtr RootDirectory,ObjectName;
            public uint Attributes; public IntPtr SecurityDescriptor,SecurityQualityOfService;
        }
        [DllImport("ntdll.dll")]
        private static extern int NtOpenSymbolicLinkObject(out IntPtr handle,uint access,ref ObjectAttributes attributes);
        [DllImport("ntdll.dll")]
        private static extern int NtQueryObject(IntPtr handle,int kind,IntPtr buffer,uint length,out uint required);
        [DllImport("ntdll.dll")]
        private static extern int NtQuerySymbolicLinkObject(IntPtr handle,ref UnicodeString target,out uint required);
        [DllImport("ntdll.dll")]
        private static extern int NtClose(IntPtr handle);
        public static void AssertGlobalDriveMapping(string path) {
            if(String.IsNullOrEmpty(path) || path.Length<3 || path[1]!=':' || path[2]!='\\' ||
               path.IndexOf(':',2)>=0 || Char.ToUpperInvariant(path[0])<'A' || Char.ToUpperInvariant(path[0])>'Z')
                throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
            // Ordinary controllers cannot create a local DOS name shadowing an
            // existing global name via DefineDosDevice. Require the effective
            // link object itself to be global, not merely an equal target string.
            // This is an observation under the documented trusted runtime model,
            // not a lifetime guarantee against deliberate native device-map
            // mutation or hostile process injection.
            string drive=Char.ToUpperInvariant(path[0])+":";
            IntPtr text=IntPtr.Zero,unicode=IntPtr.Zero,handle=IntPtr.Zero,buffer=IntPtr.Zero,targetBuffer=IntPtr.Zero;
            bool valid=false,closed=true;
            try {
                string link=@"\??\"+drive;
                text=Marshal.StringToHGlobalUni(link);
                var name=new UnicodeString {Length=(ushort)(link.Length*2),MaximumLength=(ushort)(link.Length*2+2),Buffer=text};
                unicode=Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
                Marshal.StructureToPtr(name,unicode,false);
                var attributes=new ObjectAttributes {Length=Marshal.SizeOf<ObjectAttributes>(),ObjectName=unicode,Attributes=0x40};
                if(NtOpenSymbolicLinkObject(out handle,1,ref attributes)!=0 || handle==IntPtr.Zero)
                    throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
                // Bound every native response. Neither query follows a filesystem
                // path or contacts a mapped network target.
                buffer=Marshal.AllocHGlobal(2048);
                uint required;
                if(NtQueryObject(handle,1,buffer,2048,out required)!=0 ||
                   required<(uint)Marshal.SizeOf<UnicodeString>() || required>2048)
                    throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
                var actual=Marshal.PtrToStructure<UnicodeString>(buffer);
                long start=buffer.ToInt64(),position=actual.Buffer.ToInt64();
                if(actual.Length==0 || actual.Length%2!=0 || actual.Length>actual.MaximumLength ||
                   position<start+Marshal.SizeOf<UnicodeString>() || position>start+2048-actual.Length ||
                   !String.Equals(Marshal.PtrToStringUni(actual.Buffer,actual.Length/2),@"\GLOBAL??\"+drive,StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
                targetBuffer=Marshal.AllocHGlobal(512);
                var target=new UnicodeString {Length=0,MaximumLength=512,Buffer=targetBuffer};
                if(NtQuerySymbolicLinkObject(handle,ref target,out required)!=0 ||
                   required>512 || target.Buffer!=targetBuffer || target.MaximumLength!=512 ||
                   target.Length==0 || target.Length>512 || target.Length%2!=0 ||
                   !System.Text.RegularExpressions.Regex.IsMatch(Marshal.PtrToStringUni(target.Buffer,target.Length/2),
                     @"\A\\Device\\HarddiskVolume[0-9]+\z",
                     System.Text.RegularExpressions.RegexOptions.CultureInvariant))
                    throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
                valid=true;
            } catch { valid=false; }
            finally {
                if(handle!=IntPtr.Zero) closed=NtClose(handle)==0;
                if(targetBuffer!=IntPtr.Zero) Marshal.FreeHGlobal(targetBuffer);
                if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                if(unicode!=IntPtr.Zero) Marshal.FreeHGlobal(unicode);
                if(text!=IntPtr.Zero) Marshal.FreeHGlobal(text);
            }
            if(!closed) {
                var failure=new InvalidOperationException("VALIDATION.CLEANUP_UNVERIFIED");
                failure.Data["OwnedCleanupUnverified"]=true;
                failure.Data["OwnedLeaseCleanupUnverified"]=true;
                if(!valid) failure.Data["PrimaryReasonCode"]="VALIDATION.TOOLING_UNRESOLVED";
                throw failure;
            }
            if(!valid) throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
        }
        public static FrozenSourceNamespace HoldAncestors(string root) {
            var lease = new FrozenSourceNamespace(root);
            try {
                lease.HoldAdditionalAncestors(root);
                return lease;
            } catch {
                try { lease.Dispose(); }
                catch {
                    var failure = new InvalidOperationException("VALIDATION.CLEANUP_UNVERIFIED");
                    failure.Data["OwnedCleanupUnverified"]=true;
                    failure.Data["OwnedLeaseCleanupUnverified"]=true;
                    failure.Data["PrimaryReasonCode"]="VALIDATION.TOOLING_UNRESOLVED";
                    throw failure;
                }
                throw;
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
            public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out ByHandleFileInformation information);
        private static SafeFileHandle OpenNoReparse(string path,uint access,bool directory) {
            // With ancestors already held, OPEN_REPARSE_POINT prevents following
            // this component. Inspect its attributes on this same handle.
            var handle=CreateFileW(path,access,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
            if(handle==null || handle.IsInvalid) {
                if(handle!=null) handle.Dispose();
                throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
            }
            ByHandleFileInformation info;
            if(!GetFileInformationByHandle(handle,out info) ||
               (info.FileAttributes & (uint)FileAttributes.ReparsePoint)!=0 ||
               (((info.FileAttributes & (uint)FileAttributes.Directory)!=0)!=directory)) {
                try { ReleaseFileHandle(handle); }
                catch {
                    var failure=new InvalidOperationException("VALIDATION.CLEANUP_UNVERIFIED");
                    failure.Data["OwnedCleanupUnverified"]=true;
                    failure.Data["OwnedLeaseCleanupUnverified"]=true;
                    failure.Data["PrimaryReasonCode"]="VALIDATION.TOOLING_UNRESOLVED";
                    throw failure;
                }
                throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
            }
            return handle;
        }
        public void HoldAdditionalAncestors(string root) {
            if(disposed || String.IsNullOrEmpty(root) ||
               !String.Equals(Path.GetFullPath(root),root,StringComparison.Ordinal) ||
               root.Length<3 || root[1]!=':' || root[2]!='\\' || root.IndexOf(':',2)>=0)
                throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
            AssertGlobalDriveMapping(root);
            var ancestors=new Stack<string>();
            string cursor=root;
            while(!String.IsNullOrEmpty(cursor)) {
                if(ancestors.Count>=64) throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
                ancestors.Push(cursor);
                string parent=Path.GetDirectoryName(cursor);
                if(parent==cursor) break;
                cursor=parent;
            }
            // Retain every handle before opening the next child. LIST_DIRECTORY
            // makes share exclusion effective. Deny WRITE as well as DELETE so
            // an ancestor cannot be changed into a reparse point in place.
            foreach(string ancestor in ancestors)
                handles.Add(OpenNoReparse(ancestor,0x20081,true));
        }
        public static Stream OpenPinned(string path) {
            var lease=HoldAncestors(Path.GetDirectoryName(path));
            SafeFileHandle handle=null;
            FileStream file=null;
            try {
                handle=OpenNoReparse(path,0x80000000,false);
                // FileStream borrows the handle; explicit owned release below
                // records CloseHandle's result instead of SafeHandle's ignored bool.
                file=new FileStream(new SafeFileHandle(handle.DangerousGetHandle(),false),FileAccess.Read);
                return new PinnedPathStream(file,handle,lease);
            } catch {
                var failures=new List<Exception>();
                try { if(file!=null) file.Dispose(); }
                catch { failures.Add(new InvalidOperationException("VALIDATION.PIN_LEASE_RELEASE_UNVERIFIED")); }
                try { ReleaseFileHandle(handle); }
                catch { failures.Add(new InvalidOperationException("VALIDATION.PIN_LEASE_RELEASE_UNVERIFIED")); }
                try { lease.Dispose(); }
                catch { failures.Add(new InvalidOperationException("VALIDATION.NAMESPACE_LEASE_RELEASE_UNVERIFIED")); }
                if(failures.Count!=0) {
                    var failure=new InvalidOperationException("VALIDATION.CLEANUP_UNVERIFIED",
                        new AggregateException("VALIDATION.CLEANUP_UNVERIFIED",failures));
                    failure.Data["OwnedCleanupUnverified"]=true;
                    failure.Data["OwnedLeaseCleanupUnverified"]=true;
                    failure.Data["PrimaryReasonCode"]="VALIDATION.TOOLING_UNRESOLVED";
                    throw failure;
                }
                throw;
            }
        }
        public void MarkValidated() {
            if(disposed || handles.Count==0) throw new InvalidOperationException("VALIDATION.TOOLING_UNRESOLVED");
            verified=true;
        }
        public void Dispose() {
            var failures = new List<Exception>();
            if(!disposed) {
                foreach(var handle in handles) {
                    try { ReleaseFileHandle(handle); }
                    catch { failures.Add(new InvalidOperationException("VALIDATION.NAMESPACE_LEASE_RELEASE_UNVERIFIED")); }
                }
                cleanupUnverified=failures.Count!=0;
                disposed=true;
            }
            verified=false;
            if(cleanupUnverified) {
                var failure = new InvalidOperationException("VALIDATION.CLEANUP_UNVERIFIED");
                failure.Data["OwnedCleanupUnverified"]=true;
                failure.Data["OwnedLeaseCleanupUnverified"]=true;
                throw failure;
            }
        }
    }
    internal sealed class PinnedPathStream : Stream {
        private readonly FileStream file;
        private readonly FrozenSourceNamespace ancestors;
        private readonly SafeFileHandle handle;
        private bool disposed, cleanupUnverified;
        internal PinnedPathStream(FileStream file,SafeFileHandle handle,FrozenSourceNamespace ancestors) {
            this.file=file; this.handle=handle; this.ancestors=ancestors;
        }
        public override bool CanRead { get { return !disposed && file.CanRead; } }
        public override bool CanSeek { get { return !disposed && file.CanSeek; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return file.Length; } }
        public override long Position { get { return file.Position; } set { file.Position=value; } }
        public override int Read(byte[] buffer,int offset,int count) { return file.Read(buffer,offset,count); }
        public override long Seek(long offset,SeekOrigin origin) { return file.Seek(offset,origin); }
        public override void Flush() { file.Flush(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer,int offset,int count) { throw new NotSupportedException(); }
        protected override void Dispose(bool disposing) {
            if(disposing && !disposed) {
                var failures=new List<Exception>();
                try { file.Dispose(); } catch { failures.Add(new InvalidOperationException("VALIDATION.PIN_LEASE_RELEASE_UNVERIFIED")); }
                try { FrozenSourceNamespace.ReleaseFileHandle(handle); } catch { failures.Add(new InvalidOperationException("VALIDATION.PIN_LEASE_RELEASE_UNVERIFIED")); }
                try { ancestors.Dispose(); } catch { failures.Add(new InvalidOperationException("VALIDATION.NAMESPACE_LEASE_RELEASE_UNVERIFIED")); }
                disposed=true;
                cleanupUnverified=failures.Count!=0;
                if(cleanupUnverified) {
                    var failure=new InvalidOperationException("VALIDATION.CLEANUP_UNVERIFIED",
                        new AggregateException("VALIDATION.CLEANUP_UNVERIFIED",failures));
                    failure.Data["OwnedCleanupUnverified"]=true;
                    failure.Data["OwnedLeaseCleanupUnverified"]=true;
                    throw failure;
                }
            }
            if(disposing && cleanupUnverified) {
                var failure=new InvalidOperationException("VALIDATION.CLEANUP_UNVERIFIED");
                failure.Data["OwnedCleanupUnverified"]=true;
                failure.Data["OwnedLeaseCleanupUnverified"]=true;
                throw failure;
            }
            base.Dispose(disposing);
        }
    }
}
'@
}

function ConvertTo-AzureTerraformClosedBoundaryFailure {
    param([Parameter(Mandatory)][Exception]$Exception)
    $reason='VALIDATION.TOOLING_UNRESOLVED';$owned=$false;$lease=$false;$primary=$null
    $cursor=$Exception;$depth=0
    while($null -ne $cursor -and ++$depth -le 16){
        if($cursor.Message -cin @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED','VALIDATION.CLEANUP_UNVERIFIED')){$reason=$cursor.Message}
        $owned=$owned -or $cursor.Data['OwnedCleanupUnverified'] -eq $true
        $lease=$lease -or $cursor.Data['OwnedLeaseCleanupUnverified'] -eq $true
        $value=$cursor.Data['PrimaryReasonCode']
        if($value -is [string] -and $value -cin @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED','VALIDATION.CLEANUP_UNVERIFIED')){$primary=$value}
        $cursor=$cursor.InnerException
    }
    if($owned -or $lease){$reason='VALIDATION.CLEANUP_UNVERIFIED'}
    $closed=[InvalidOperationException]::new($reason)
    if($owned -or $lease){$closed.Data['OwnedCleanupUnverified']=$true}
    if($lease){$closed.Data['OwnedLeaseCleanupUnverified']=$true}
    if($null -ne $primary){$closed.Data['PrimaryReasonCode']=$primary}
    $closed
}
function Assert-AzureTerraformDrivePath {
    param([Parameter(Mandatory)][string]$Path)
    try{
        Initialize-AzureTerraformPathLeaseType
        [WinPCInfo.AzureTerraform.FrozenSourceNamespace]::AssertGlobalDriveMapping($Path)
    }catch{throw (ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception)}
}
function Assert-AzureTerraformNativeController {
    $threadIdentity=$null;$identity=$null;$failure=$null
    try{
        # CreateProcessW uses the primary process token, not a thread token.
        # Reject impersonation before reading/checking the ordinary process.
        $threadIdentity=[Security.Principal.WindowsIdentity]::GetCurrent($true)
        if($null -ne $threadIdentity){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent($false)
        if($null -eq $identity){throw 'VALIDATION.TOOLING_UNRESOLVED'}
        $principal=[Security.Principal.WindowsPrincipal]::new($identity)
        if($identity.User.Value -ceq 'S-1-5-18' -or
           $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
           $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::BackupOperator)){
            throw 'VALIDATION.TOOLING_UNRESOLVED'
        }
    }catch{$failure=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception}
    finally{
        foreach($tokenIdentity in @($threadIdentity,$identity)){
            if($null -ne $tokenIdentity){
                try{$tokenIdentity.Dispose()}
                catch{
                    $unsafe=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
                    $unsafe.Data['OwnedCleanupUnverified']=$true
                    $unsafe.Data['OwnedLeaseCleanupUnverified']=$true
                    if($null -ne $failure){
                        $primary=$failure.Data['PrimaryReasonCode']
                        if($primary -is [string] -and $primary -cin @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED','VALIDATION.CLEANUP_UNVERIFIED')){
                            $unsafe.Data['PrimaryReasonCode']=$primary
                        }else{$unsafe.Data['PrimaryReasonCode']=$failure.Message}
                    }
                    $failure=$unsafe
                }
            }
        }
    }
    if($null -ne $failure){throw $failure}
}
# Internal exact-pinned Terraform boundary. Construction is not cloud authority.
# The admitted outer factory must supply approved tool/config identities.
function Open-AzureTerraformPinnedFile {
    param([Parameter(Mandatory)][string]$Path)
    try{
        if ($Path -cnotmatch '\A[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or
            [IO.Path]::GetFullPath($Path) -cne $Path) { throw 'VALIDATION.TOOLING_UNRESOLVED' }
        # Namespace proof precedes DriveInfo and all filesystem I/O.
        Assert-AzureTerraformDrivePath -Path $Path
        $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path))
        if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'VALIDATION.TOOLING_UNRESOLVED' }
        [WinPCInfo.AzureTerraform.FrozenSourceNamespace]::OpenPinned($Path)
    }catch{throw (ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception)}
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
        Assert-AzureTerraformNativeController
        foreach($path in @($Request.Executable,$Request.WorkingDirectory,$Request.Environment['TF_CLI_CONFIG_FILE'])){
            Assert-AzureTerraformDrivePath -Path ([string]$path)
        }
        if($Request.Environment.ContainsKey('TF_DATA_DIR')){
            Assert-AzureTerraformDrivePath -Path ([string]$Request.Environment['TF_DATA_DIR'])
        }
        Initialize-ProcessSupervisorNativeType
        $remaining=[long][Math]::Ceiling(($Request.DeadlineUtc-[DateTimeOffset]::UtcNow).TotalMilliseconds)
        if ($Request.CancellationToken.IsCancellationRequested -or $remaining -le 0) {
            throw 'VALIDATION.ROUND_INTERRUPTED'
        }
        $timeout=[int][Math]::Min([long]$Request.TimeoutMilliseconds,$remaining)
    }
    catch {
        $refusal=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception
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
        $boundaryFailure=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception
        $nativePreStartVerified=($Channel.UsesNativeRunner -and
            $_.Exception.Data['AzureTerraformNativePreStartVerified'] -eq $true)
        if ($processAttempted -and -not $processAbsenceProven -and -not $nativePreStartVerified) {
            $failure=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
            $failure.Data['OwnedCleanupUnverified']=$true
        }
        elseif ($boundaryFailure.Data['OwnedCleanupUnverified'] -eq $true -or $boundaryFailure.Data['OwnedLeaseCleanupUnverified'] -eq $true) {
            $failure=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED')
            $failure.Data['OwnedCleanupUnverified']=$true
            if($boundaryFailure.Data['OwnedLeaseCleanupUnverified'] -eq $true){$failure.Data['OwnedLeaseCleanupUnverified']=$true}
            $primary=$boundaryFailure.Data['PrimaryReasonCode']
            if($primary -is [string] -and $primary -cin @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED','VALIDATION.CLEANUP_UNVERIFIED')){$failure.Data['PrimaryReasonCode']=$primary}
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
    if ($cleanupFailed) {
        $failures=[Collections.Generic.List[Exception]]::new()
        if($null -ne $failure){$failures.Add($failure)}
        $failures.Add([InvalidOperationException]::new('VALIDATION.PIN_LEASE_RELEASE_UNVERIFIED'))
        $combined=[InvalidOperationException]::new('VALIDATION.CLEANUP_UNVERIFIED',
            [AggregateException]::new('VALIDATION.CLEANUP_UNVERIFIED',$failures.ToArray()))
        $combined.Data['OwnedCleanupUnverified']=$true
        $combined.Data['OwnedLeaseCleanupUnverified']=$true
        if($null -ne $failure){
            $primary=$failure.Data['PrimaryReasonCode']
            if($primary -is [string] -and $primary -cin @('VALIDATION.TOOLING_UNRESOLVED','VALIDATION.ROUND_INTERRUPTED','VALIDATION.CLEANUP_UNVERIFIED')){
                $combined.Data['PrimaryReasonCode']=$primary
            }else{$combined.Data['PrimaryReasonCode']=$failure.Message}
        }
        throw $combined
    }
    if ($null -ne $failure) { throw $failure }
    $result
}
