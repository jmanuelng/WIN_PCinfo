[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
$combined=[IO.File]::ReadAllText((Join-Path $root 'src/AzureValidationTerraform.ps1'))+[IO.File]::ReadAllText((Join-Path $root 'src/AzureValidationTerraformInitialization.ps1'))
$match=[regex]::Match($combined,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@")
if(-not $match.Success){throw 'TEST.NATIVE_SOURCE_NOT_FOUND'}
$native=$match.Groups[1].Value.Replace('namespace WinPCInfo.AzureTerraform {','namespace WinPCInfo.TerraformPathOrderingTests {')
$native=$native.Replace('File.GetAttributes(cursor)','TestApi.GetAttributes(cursor)')
$create='(?s)\[DllImport\("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true\)\]\s*private static extern SafeFileHandle CreateFileW\(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template\);'
if(-not [regex]::IsMatch($native,$create)){throw 'TEST.CREATE_FILE_DECLARATION_NOT_FOUND'}
$native=[regex]::Replace($native,$create,'private static SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template) { return TestApi.Open(path,access,share,flags); }')
$info='(?s)\[DllImport\("kernel32.dll", SetLastError=true\)\]\s*private static extern bool GetFileInformationByHandle\(SafeFileHandle handle,out ByHandleFileInformation information\);'
$native=[regex]::Replace($native,$info,'private static bool GetFileInformationByHandle(SafeFileHandle handle,out ByHandleFileInformation information) { information=new ByHandleFileInformation(); if(TestApi.FailInformationNumber==handle.DangerousGetHandle().ToInt64()) return false; information.FileAttributes=(uint)TestApi.GetAttributesForHandle(handle); return true; }')
$close='(?s)\[DllImport\("kernel32.dll", SetLastError=true\)\]\s*private static extern bool CloseHandle\(IntPtr handle\);'
$native=[regex]::Replace($native,$close,'private static bool CloseHandle(IntPtr handle) { return TestApi.CloseFile(handle); }')
# Substitute only native dispatch, retaining the actual global-link
# namespace/target parsing, bounded buffers, refusal and release algorithm.
$native=[regex]::Replace($native,'(?s)\[DllImport\("ntdll.dll"\)\]\s*private static extern int NtOpenSymbolicLinkObject\(out IntPtr handle,uint access,ref ObjectAttributes attributes\);',
 'private static int NtOpenSymbolicLinkObject(out IntPtr handle,uint access,ref ObjectAttributes attributes) { var name=Marshal.PtrToStructure<UnicodeString>(attributes.ObjectName); return TestApi.OpenLink(Marshal.PtrToStringUni(name.Buffer,name.Length/2),out handle); }')
$native=[regex]::Replace($native,'(?s)\[DllImport\("ntdll.dll"\)\]\s*private static extern int NtQueryObject\(IntPtr handle,int kind,IntPtr buffer,uint length,out uint required\);',
 'private static int NtQueryObject(IntPtr handle,int kind,IntPtr buffer,uint length,out uint required) { return TestApi.QueryObject(buffer,length,out required); }')
$native=[regex]::Replace($native,'(?s)\[DllImport\("ntdll.dll"\)\]\s*private static extern int NtQuerySymbolicLinkObject\(IntPtr handle,ref UnicodeString target,out uint required\);',
 'private static int NtQuerySymbolicLinkObject(IntPtr handle,ref UnicodeString target,out uint required) { ushort written; int status=TestApi.QueryLink(target.Buffer,target.MaximumLength,out written,out required); target.Length=written; return status; }')
$native=[regex]::Replace($native,'(?s)\[DllImport\("ntdll.dll"\)\]\s*private static extern int NtClose\(IntPtr handle\);',
 'private static int NtClose(IntPtr handle) { return TestApi.CloseLink(handle); }')
# Substitute managed file I/O with a one-byte stream in these algorithm
# tests. Native handle acquisition/release and production stream disposal
# logic remain the actual extracted code; no fake OS handle is read.
$native=[regex]::Replace($native,'\bFileStream\b','TestFileStream')
$api=@'
namespace WinPCInfo.TerraformPathOrderingTests {
 public sealed class TestFileStream : System.IO.MemoryStream {
  private readonly Microsoft.Win32.SafeHandles.SafeFileHandle borrowed;
  public TestFileStream(Microsoft.Win32.SafeHandles.SafeFileHandle handle,System.IO.FileAccess access) : base(new byte[1],false) { borrowed=handle; }
  protected override void Dispose(bool disposing) {
   if(disposing) borrowed.Dispose();
   base.Dispose(disposing);
   if(disposing && TestApi.FailManagedFileDispose) throw new System.IO.IOException("private managed file release details");
  }
 }
 public static class TestApi {
  public static readonly System.Collections.Generic.List<string> Touched = new System.Collections.Generic.List<string>();
  public static readonly System.Collections.Generic.List<uint> Flags = new System.Collections.Generic.List<uint>();
  public static readonly System.Collections.Generic.List<uint> Shares = new System.Collections.Generic.List<uint>();
  private static readonly System.Collections.Generic.Dictionary<long,string> Names = new System.Collections.Generic.Dictionary<long,string>();
  public static readonly System.Collections.Generic.List<Microsoft.Win32.SafeHandles.SafeFileHandle> Handles = new System.Collections.Generic.List<Microsoft.Win32.SafeHandles.SafeFileHandle>();
  public static int FailOpenNumber, FailInformationNumber, FailCloseNumber;
  public static readonly System.Collections.Generic.Dictionary<long,int> CloseAttempts = new System.Collections.Generic.Dictionary<long,int>();
  public static bool LocalAlias, RebindOnFirstAccess, Rebound, FailManagedFileDispose;
  public static int LinkOpened, LinkClosed; public static string LinkDrive;
  public static bool LinkOpenFail, LinkQueryFail, LinkCloseFail; public static int ObjectFault;
  public static string LinkTarget;
  public static string Reparse = @"C:\owned\junction";
  public static void Reset() { Touched.Clear(); Flags.Clear(); Shares.Clear(); Names.Clear(); Handles.Clear(); FailOpenNumber=0; FailInformationNumber=0; FailCloseNumber=0; CloseAttempts.Clear(); LocalAlias=false; RebindOnFirstAccess=false; Rebound=false; FailManagedFileDispose=false; LinkOpened=0; LinkClosed=0; LinkDrive=null; LinkOpenFail=false; LinkQueryFail=false; LinkCloseFail=false; ObjectFault=0; LinkTarget=@"\Device\HarddiskVolume1"; }
  [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
  private struct UnicodeName { public ushort Length,MaximumLength; public System.IntPtr Buffer; }
  public static int OpenLink(string path,out System.IntPtr handle) {
   if(path.Length!=6 || !path.StartsWith(@"\??\",System.StringComparison.Ordinal) || path[5]!=':') { handle=System.IntPtr.Zero; return -1; }
   if(LinkOpenFail){handle=System.IntPtr.Zero;return -1;}
   LinkDrive=path.Substring(4); LinkOpened++; handle=new System.IntPtr(4096); return 0;
  }
  public static int QueryObject(System.IntPtr buffer,uint length,out uint required) {
   if(ObjectFault==1){required=0;return -1;}
   string name=(LocalAlias ? @"\Sessions\0\DosDevices\synthetic\" : @"\GLOBAL??\")+LinkDrive;
   byte[] bytes=System.Text.Encoding.Unicode.GetBytes(name);
   int header=System.Runtime.InteropServices.Marshal.SizeOf<UnicodeName>();
   required=(uint)(header+bytes.Length);
   var value=new UnicodeName {Length=(ushort)bytes.Length,MaximumLength=(ushort)bytes.Length,Buffer=System.IntPtr.Add(buffer,header)};
   if(ObjectFault==2) required=4096;
   if(ObjectFault==3) value.Buffer=System.IntPtr.Add(buffer,2048);
   if(ObjectFault==4) value.Length--;
   if(ObjectFault==5) value.MaximumLength=0;
   if(ObjectFault==6) {
    bytes=System.Text.Encoding.Unicode.GetBytes(@"\GLOBAL??\D:");
    value.Length=(ushort)bytes.Length;value.MaximumLength=(ushort)bytes.Length;
   }
   System.Runtime.InteropServices.Marshal.StructureToPtr(value,buffer,false);
   if(ObjectFault!=3) System.Runtime.InteropServices.Marshal.Copy(bytes,0,value.Buffer,bytes.Length);
   return 0;
  }
  public static int QueryLink(System.IntPtr buffer,ushort length,out ushort written,out uint required) {
   if(LinkQueryFail){written=0;required=0;return -1;}
   byte[] bytes=System.Text.Encoding.Unicode.GetBytes(LinkTarget);
   written=(ushort)bytes.Length;required=(uint)bytes.Length;
   System.Runtime.InteropServices.Marshal.Copy(bytes,0,buffer,bytes.Length);
   return 0;
  }
  public static bool CloseFile(System.IntPtr handle) {
   long key=handle.ToInt64();
   if(!CloseAttempts.ContainsKey(key)) CloseAttempts.Add(key,0);
   CloseAttempts[key]++;
   return key!=FailCloseNumber;
  }
  public static int CloseLink(System.IntPtr handle) { LinkClosed++; return LinkCloseFail ? -1 : 0; }
  public static Microsoft.Win32.SafeHandles.SafeFileHandle Open(string path,uint access,uint share,uint flags) {
   Touched.Add(path); Flags.Add(flags); Shares.Add(share);
   if(RebindOnFirstAccess && Touched.Count==1) { Rebound=true; LocalAlias=true; }
   if(Touched.Count==FailOpenNumber) return new Microsoft.Win32.SafeHandles.SafeFileHandle(new System.IntPtr(-1),false);
   long key=Names.Count+1; Names.Add(key,path);
   var handle=new Microsoft.Win32.SafeHandles.SafeFileHandle(new System.IntPtr(key),false);
   Handles.Add(handle); return handle;
  }
  public static System.IO.FileAttributes GetAttributes(string path) {
   Touched.Add(path);
   return path==Reparse ? System.IO.FileAttributes.Directory|System.IO.FileAttributes.ReparsePoint : System.IO.FileAttributes.Directory;
  }
  public static System.IO.FileAttributes GetAttributesForHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
   string path=Names[handle.DangerousGetHandle().ToInt64()];
   return path==Reparse ? System.IO.FileAttributes.Directory|System.IO.FileAttributes.ReparsePoint :
       (path.EndsWith(".exe",System.StringComparison.Ordinal) ? System.IO.FileAttributes.Normal : System.IO.FileAttributes.Directory);
  }
 }
}
'@
Add-Type -TypeDefinition ($native+[char]10+$api)
[WinPCInfo.TerraformPathOrderingTests.TestApi]::Reset()
$failure=$null;$lease=$null
try{$lease=[WinPCInfo.TerraformPathOrderingTests.FrozenSourceNamespace]::HoldAncestors('C:\owned\junction\source')}catch{$failure=$_.Exception}
finally{if($null -ne $lease){$lease.Dispose()}}
$touches=@([WinPCInfo.TerraformPathOrderingTests.TestApi]::Touched)
if($touches -ccontains 'C:\owned\junction\source'){throw 'TEST.DESCENDANT_IO_BEFORE_ANCESTOR_REPARSE_REFUSAL'}
if($null -eq $failure -or $touches.Count -ne 3 -or $touches[0] -cne 'C:\' -or $touches[1] -cne 'C:\owned' -or $touches[2] -cne 'C:\owned\junction'){throw 'TEST.ROOT_FIRST_REPARSE_REFUSAL_UNPROVED'}
foreach($flag in [WinPCInfo.TerraformPathOrderingTests.TestApi]::Flags){if(($flag -band 0x00200000) -eq 0){throw 'TEST.FINAL_COMPONENT_FOLLOWED'}}
foreach($share in [WinPCInfo.TerraformPathOrderingTests.TestApi]::Shares){if($share -ne 1){throw 'TEST.DIRECTORY_WRITE_OR_DELETE_SHARING_ALLOWED'}}
[WinPCInfo.TerraformPathOrderingTests.TestApi]::Reset()
$failure=$null
try{$null=[WinPCInfo.TerraformPathOrderingTests.FrozenSourceNamespace]::OpenPinned('C:\owned\junction\child\terraform.exe')}catch{$failure=$_.Exception}
$touches=@([WinPCInfo.TerraformPathOrderingTests.TestApi]::Touched)
if($null -eq $failure -or $touches.Count -ne 3 -or $touches -ccontains 'C:\owned\junction\child' -or $touches -ccontains 'C:\owned\junction\child\terraform.exe'){throw 'TEST.PIN_DESCENDANT_IO_BEFORE_ANCESTOR_REPARSE_REFUSAL'}
foreach($fault in @('Open','Information')){
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reset()
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reparse=''
    if($fault -ceq 'Open'){[WinPCInfo.TerraformPathOrderingTests.TestApi]::FailOpenNumber=3}
    else{[WinPCInfo.TerraformPathOrderingTests.TestApi]::FailInformationNumber=3}
    $failure=$null;$lease=$null
    try{$lease=[WinPCInfo.TerraformPathOrderingTests.FrozenSourceNamespace]::HoldAncestors('C:\owned\source')}catch{$failure=$_.Exception}
    finally{if($null -ne $lease){$lease.Dispose()}}
    if($null -eq $failure){throw 'TEST.NATIVE_ACQUISITION_FAULT_IGNORED'}
    foreach($handle in [WinPCInfo.TerraformPathOrderingTests.TestApi]::Handles){if(-not $handle.IsClosed){throw 'TEST.NATIVE_ACQUISITION_FAULT_LEAKED_PRIOR_HANDLE'}}
    if([WinPCInfo.TerraformPathOrderingTests.TestApi]::Touched.Count -ne 3){throw 'TEST.NATIVE_ACQUISITION_FAULT_DESCENDED_FURTHER'}
}
# A local drive alias can change separately from held file handles.
# This fixture would rebind it on the first filesystem access. Admission
# must reject it before any access, even if it points at a local volume.
[WinPCInfo.TerraformPathOrderingTests.TestApi]::Reset()
[WinPCInfo.TerraformPathOrderingTests.TestApi]::Reparse=''
[WinPCInfo.TerraformPathOrderingTests.TestApi]::LocalAlias=$true
[WinPCInfo.TerraformPathOrderingTests.TestApi]::RebindOnFirstAccess=$true
$failure=$null;$lease=$null
try{$lease=[WinPCInfo.TerraformPathOrderingTests.FrozenSourceNamespace]::HoldAncestors('C:\owned\source')}catch{$failure=$_.Exception}
finally{if($null -ne $lease){$lease.Dispose()}}
if($null -eq $failure -or [WinPCInfo.TerraformPathOrderingTests.TestApi]::Touched.Count -ne 0 -or [WinPCInfo.TerraformPathOrderingTests.TestApi]::Rebound){throw 'TEST.MUTABLE_DRIVE_ALIAS_ACCESSED_BEFORE_REFUSAL'}
$extraAssertions=0
foreach($fault in @('Open','Query','Object1','Object2','Object3','Object4','Object5','Object6','ForeignTarget','NetworkTarget','LocalAlias')){
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reset()
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reparse=''
    if($fault -ceq 'Open'){[WinPCInfo.TerraformPathOrderingTests.TestApi]::LinkOpenFail=$true}
    elseif($fault -ceq 'Query'){[WinPCInfo.TerraformPathOrderingTests.TestApi]::LinkQueryFail=$true}
    elseif($fault.StartsWith('Object')){[WinPCInfo.TerraformPathOrderingTests.TestApi]::ObjectFault=[int]$fault.Substring(6)}
    elseif($fault -ceq 'ForeignTarget'){[WinPCInfo.TerraformPathOrderingTests.TestApi]::LinkTarget='\??\C:\synthetic'}
    elseif($fault -ceq 'NetworkTarget'){[WinPCInfo.TerraformPathOrderingTests.TestApi]::LinkTarget='\Device\Mup\synthetic'}
    else{[WinPCInfo.TerraformPathOrderingTests.TestApi]::LocalAlias=$true}
    $failure=$null;$lease=$null
    try{$lease=[WinPCInfo.TerraformPathOrderingTests.FrozenSourceNamespace]::HoldAncestors('C:\owned\source')}catch{$failure=$_.Exception}
    finally{if($null -ne $lease){$lease.Dispose()}}
    $extraAssertions++
    if($null -eq $failure -or [WinPCInfo.TerraformPathOrderingTests.TestApi]::Touched.Count -ne 0){throw 'TEST.UNVERIFIED_DRIVE_ACCESSED_FILESYSTEM'}
    $extraAssertions++
    if([WinPCInfo.TerraformPathOrderingTests.TestApi]::LinkOpened -ne [WinPCInfo.TerraformPathOrderingTests.TestApi]::LinkClosed){throw 'TEST.DRIVE_PROOF_FAILURE_SKIPPED_NATIVE_LINK_RELEASE'}
}
# Exercise the actual PowerShell exception normalization at the native seam.
# Only the C# dispatch type and its initializer are substituted.
$sourceAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'src/AzureValidationTerraform.ps1'),[ref]$null,[ref]$null)
foreach($name in @('ConvertTo-AzureTerraformClosedBoundaryFailure','Assert-AzureTerraformDrivePath')){
    $definition=$sourceAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name}.GetNewClosure(),$true)
    if($null -eq $definition){throw 'TEST.BOUNDARY_NORMALIZER_SOURCE_NOT_FOUND'}
    . ([scriptblock]::Create($definition.Extent.Text.Replace('[WinPCInfo.AzureTerraform.FrozenSourceNamespace]','[WinPCInfo.TerraformPathOrderingTests.FrozenSourceNamespace]')))
}
function Initialize-AzureTerraformPathLeaseType {}
foreach($bodyFailure in @($false,$true)){
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reset()
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reparse=''
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::LocalAlias=$bodyFailure
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::LinkCloseFail=$true
    $failure=$null;try{Assert-AzureTerraformDrivePath -Path 'C:\owned\source'}catch{$failure=$_.Exception}
    $extraAssertions++
    if($null -eq $failure -or $failure.Message -cne 'VALIDATION.CLEANUP_UNVERIFIED' -or $failure.Data['OwnedCleanupUnverified'] -ne $true -or $failure.Data['OwnedLeaseCleanupUnverified'] -ne $true){throw 'TEST.NATIVE_LINK_CLOSE_FAULT_LOST_OWNED_STOP_SIGNAL'}
    $extraAssertions++
    if([WinPCInfo.TerraformPathOrderingTests.TestApi]::Touched.Count -ne 0 -or [WinPCInfo.TerraformPathOrderingTests.TestApi]::LinkOpened -ne [WinPCInfo.TerraformPathOrderingTests.TestApi]::LinkClosed){throw 'TEST.NATIVE_LINK_CLOSE_FAULT_DISPATCHED_OR_SKIPPED_RELEASE'}
    if($bodyFailure){
        $extraAssertions++
        if($failure.Data['PrimaryReasonCode'] -cne 'VALIDATION.TOOLING_UNRESOLVED'){throw 'TEST.NATIVE_LINK_CLOSE_FAULT_LOST_PRIMARY_REASON'}
    }
}

foreach($closeNumber in @(1,2,3)){
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reset()
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reparse=''
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::FailCloseNumber=$closeNumber
    $lease=[WinPCInfo.TerraformPathOrderingTests.FrozenSourceNamespace]::HoldAncestors('C:\owned\source')
    $lease.MarkValidated()
    $failure=$null
    try{$lease.Dispose()}catch{$failure=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception}
    $extraAssertions++
    if($null -eq $failure -or $failure.Message -cne 'VALIDATION.CLEANUP_UNVERIFIED' -or
        $failure.Data['OwnedCleanupUnverified'] -ne $true -or $failure.Data['OwnedLeaseCleanupUnverified'] -ne $true){throw 'TEST.FALSE_NATIVE_CLOSE_REPORTED_AS_VERIFIED_RELEASE'}
    $extraAssertions++
    if($lease.Verified){throw 'TEST.NAMESPACE_VALIDATED_AFTER_CLOSE_UNCERTAINTY'}
    $extraAssertions++
    if([WinPCInfo.TerraformPathOrderingTests.TestApi]::CloseAttempts.Count -ne 3){throw 'TEST.FALSE_CLOSE_SKIPPED_OTHER_OWNED_HANDLE'}
    foreach($count in [WinPCInfo.TerraformPathOrderingTests.TestApi]::CloseAttempts.Values){
        $extraAssertions++
        if($count -ne 1){throw 'TEST.UNCERTAIN_NATIVE_HANDLE_CLOSE_RETRIED'}
    }
    $failure=$null
    try{$lease.Dispose()}catch{$failure=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception}
    $extraAssertions++
    if($null -eq $failure -or $failure.Data['OwnedCleanupUnverified'] -ne $true){throw 'TEST.REPEATED_DISPOSAL_CLEARED_NATIVE_CLOSE_UNCERTAINTY'}
    foreach($count in [WinPCInfo.TerraformPathOrderingTests.TestApi]::CloseAttempts.Values){
        $extraAssertions++
        if($count -ne 1){throw 'TEST.REPEATED_DISPOSAL_RETRIED_UNCERTAIN_RAW_HANDLE'}
    }
}


foreach($managedFault in @($false,$true)){
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reset()
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::Reparse=''
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::FailCloseNumber=4
    [WinPCInfo.TerraformPathOrderingTests.TestApi]::FailManagedFileDispose=$managedFault
    $pinned=[WinPCInfo.TerraformPathOrderingTests.FrozenSourceNamespace]::OpenPinned('C:\owned\source\terraform.exe')
    $failure=$null
    try{$pinned.Dispose()}catch{$failure=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception}
    $extraAssertions++
    if($null -eq $failure -or $failure.Message -cne 'VALIDATION.CLEANUP_UNVERIFIED' -or
       $failure.Data['OwnedCleanupUnverified'] -ne $true -or $failure.Data['OwnedLeaseCleanupUnverified'] -ne $true){throw 'TEST.FALSE_PINNED_FILE_CLOSE_REPORTED_AS_RELEASE'}
    $extraAssertions++
    if([WinPCInfo.TerraformPathOrderingTests.TestApi]::CloseAttempts.Count -ne 4){throw 'TEST.PINNED_FILE_CLOSE_FAILURE_SKIPPED_ANCESTORS'}
    $extraAssertions++
    if($pinned.CanRead -or $pinned.CanSeek){throw 'TEST.PINNED_FILE_ACTIVE_AFTER_RELEASE_ATTEMPT'}
    $extraAssertions++
    if($failure.ToString().Contains('private managed file release details')){throw 'TEST.NATIVE_CLOSE_FAILURE_LEAKED_PRIVATE_FILE_DETAILS'}
    $failure=$null
    try{$pinned.Dispose()}catch{$failure=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception}
    $extraAssertions++
    if($null -eq $failure -or $failure.Data['OwnedCleanupUnverified'] -ne $true){throw 'TEST.PINNED_FILE_REPEAT_DISPOSAL_CLEARED_UNCERTAINTY'}
    foreach($count in [WinPCInfo.TerraformPathOrderingTests.TestApi]::CloseAttempts.Values){
        $extraAssertions++
        if($count -ne 1){throw 'TEST.PINNED_FILE_UNCERTAIN_NATIVE_CLOSE_RETRIED'}
    }
}
# A later acquisition information fault must preserve failed close and
# independently release every earlier acquired ancestor.
[WinPCInfo.TerraformPathOrderingTests.TestApi]::Reset()
[WinPCInfo.TerraformPathOrderingTests.TestApi]::Reparse=''
[WinPCInfo.TerraformPathOrderingTests.TestApi]::FailInformationNumber=3
[WinPCInfo.TerraformPathOrderingTests.TestApi]::FailCloseNumber=3
$failure=$null
try{$null=[WinPCInfo.TerraformPathOrderingTests.FrozenSourceNamespace]::HoldAncestors('C:\owned\source')}catch{$failure=ConvertTo-AzureTerraformClosedBoundaryFailure -Exception $_.Exception}
$extraAssertions++
if($null -eq $failure -or $failure.Data['OwnedCleanupUnverified'] -ne $true -or
   $failure.Data['OwnedLeaseCleanupUnverified'] -ne $true -or $failure.Data['PrimaryReasonCode'] -cne 'VALIDATION.TOOLING_UNRESOLVED'){throw 'TEST.NATIVE_ACQUISITION_CLOSE_FAULT_LOST_PRIMARY_OR_STOP_SIGNAL'}
$extraAssertions++
if([WinPCInfo.TerraformPathOrderingTests.TestApi]::CloseAttempts.Count -ne 3){throw 'TEST.NATIVE_ACQUISITION_CLOSE_FAULT_LEAKED_PRIOR_HANDLES'}
foreach($count in [WinPCInfo.TerraformPathOrderingTests.TestApi]::CloseAttempts.Values){
    $extraAssertions++
    if($count -ne 1){throw 'TEST.NATIVE_ACQUISITION_RETRIED_UNCERTAIN_CLOSE'}
}

[ordered]@{recordType='win-pcinfo.injected-native-path-ordering-tests';result='Pass';nonQualifying=$true;nativeFilesystemCalls=0;assertions=(12+$extraAssertions);scope='Actual native acquisition algorithm with in-memory Win32 dispatch; rejects local reparse ancestor before any descendant I/O'}|ConvertTo-Json -Compress|Write-Output
