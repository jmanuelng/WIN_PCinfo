using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

// Adapted from the retained finite Case29 development supervisor. Test-only;
// changes add bounded stdin/EOF, exact stream terminators and pure capture controls.
public sealed class WinPCInfoTestGeneratedApplicationNativeSupervisor : IDisposable {
 public const string SourceIdentity="__TEST_NATIVE_SOURCE_ID__";
 public sealed class Line { public long Sequence; public string Stream; public string Text; public string Terminator; }
 public sealed class Identity {
  public bool Started; public int Pid; public string CreationUtc; public string OwnerSid;
  public string HostPath; public string WorkingDirectory; public string[] Arguments;
  public bool UseShellExecute=false, RedirectStandardInput=true, CreateNoWindow=false;
  public bool StdoutRedirected=true, StderrRedirected=true; public int ConfiguredOutputCodePage=65001;
  public bool ExactStartedProcessHandlePinned; public string ObservationFailure;
 }
 public sealed class Outcome {
  public bool Started, NativeTerminalObserved, DeadlineReached, TerminationAttempted, TerminationSucceeded;
  public bool StreamsDrained, StreamFailure, OutputOverflow, UnsafeSignalObserved, OwnedCleanupUnverified;
  public bool InputCompleted, InputFailure;
  public int? NativeExitCode; public string ObservedTerminalUtc, Failure;
  public long TotalLines, DroppedLines, TotalCharacters, DroppedCharacters, RetainedCharacters;
  public Line[] Lines;
 }
 private const string UnsafeMarker="QUALIFICATION.OWNED_CLEANUP_UNVERIFIED";
 private readonly Process process=new Process();
 private SafeProcessHandle ownedHandle;
 private readonly object gate=new object();
 private readonly List<Line> lines=new List<Line>();
 private readonly CancellationTokenSource drainCancellation=new CancellationTokenSource();
 private Task stdoutTask,stderrTask,inputTask;
 private readonly Stopwatch lifetimeClock=new Stopwatch();
 private readonly string standardInput;
 private Task<Outcome> waitTask;
 private readonly int maxLines,maxLineChars,maxTotalChars;
 private long sequence,totalLines,droppedLines,totalChars,droppedChars,retainedChars;
 private bool streamFailure,overflow,unsafeSignal,inputFailure;
 private string streamFailureMessage;
 public readonly Identity StartedIdentity=new Identity();
 [DllImport("advapi32.dll",SetLastError=true)] private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out IntPtr token);
 [DllImport("kernel32.dll",SetLastError=true)] private static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] private static extern bool TerminateProcess(SafeProcessHandle process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetProcessId(SafeProcessHandle process);
 [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint timeout);
 [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint code);
 public WinPCInfoTestGeneratedApplicationNativeSupervisor(string host,string directory,string[] args,string input,int lineLimit,int lineCharsLimit,int totalCharsLimit) {
  if(lineLimit<1||lineCharsLimit<1||totalCharsLimit<1)throw new ArgumentOutOfRangeException("capture bounds");
  maxLines=lineLimit;maxLineChars=lineCharsLimit;maxTotalChars=totalCharsLimit;
  standardInput=input??String.Empty;
  StartedIdentity.HostPath=host;StartedIdentity.WorkingDirectory=directory;StartedIdentity.Arguments=(string[])args.Clone();
  process.StartInfo=new ProcessStartInfo {FileName=host,WorkingDirectory=directory,UseShellExecute=false,RedirectStandardInput=true,CreateNoWindow=false,RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false,true),StandardOutputEncoding=new UTF8Encoding(false,true),StandardErrorEncoding=new UTF8Encoding(false,true)};
  foreach(string arg in args)process.StartInfo.ArgumentList.Add(arg);
 }
 public void Start() {
  if(StartedIdentity.Started)throw new InvalidOperationException("Native instance already started");
  lifetimeClock.Start();
  if(!process.Start())throw new InvalidOperationException("Native process was not created");
  StartedIdentity.Started=true;
  // All killing and terminal reads use this original process handle. No PID reopen.
  ownedHandle=process.SafeHandle;StartedIdentity.ExactStartedProcessHandlePinned=!ownedHandle.IsInvalid&&!ownedHandle.IsClosed;
  stdoutTask=Task.Run(()=>Drain(new StreamReader(process.StandardOutput.BaseStream,new UTF8Encoding(false,true),false,4096,true),"stdout"));
  stderrTask=Task.Run(()=>Drain(new StreamReader(process.StandardError.BaseStream,new UTF8Encoding(false,true),false,4096,true),"stderr"));
  inputTask=Task.Run(WriteInput);
  try {
   StartedIdentity.Pid=process.Id;StartedIdentity.CreationUtc=process.StartTime.ToUniversalTime().ToString("o");
   IntPtr token;
   if(!OpenProcessToken(ownedHandle,8,out token))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),"Owned native token observation failed");
   try {using(var identity=new WindowsIdentity(token)){StartedIdentity.OwnerSid=identity.User.Value;}}
   finally {CloseHandle(token);}
  }catch(Exception e){StartedIdentity.ObservationFailure=e.GetType().FullName+": "+e.Message;}
 }
 private async Task WriteInput() {
  try {
   await process.StandardInput.WriteAsync(standardInput.AsMemory(),drainCancellation.Token).ConfigureAwait(false);
   await process.StandardInput.FlushAsync(drainCancellation.Token).ConfigureAwait(false);
   process.StandardInput.Close(); // EOF is delivered even for empty input.
  }catch(Exception e){lock(gate){inputFailure=true;streamFailureMessage=e.GetType().FullName+": "+e.Message;}}
 }
 private async Task Drain(StreamReader reader,string stream) {
  var buffer=new char[4096];var prefix=new StringBuilder(Math.Min(maxLineChars,4096));
  long lineLength=0;bool markerValid=true,markerCr=false;int markerIndex=0;char last='\0';
  try {
   int n;
   while((n=await reader.ReadAsync(buffer.AsMemory(),drainCancellation.Token).ConfigureAwait(false))>0){
    for(int i=0;i<n;i++){
     char c=buffer[i];Interlocked.Increment(ref totalChars);
     if(c=='\n'){
      SaveLine(stream,prefix,lineLength,last,true,markerValid&&markerIndex==UnsafeMarker.Length);
      prefix.Clear();lineLength=0;markerValid=true;markerCr=false;markerIndex=0;last='\0';
      continue;
     }
     lineLength++;last=c;if(prefix.Length<maxLineChars)prefix.Append(c);
     if(markerValid){
      if(markerIndex<UnsafeMarker.Length){if(c==UnsafeMarker[markerIndex])markerIndex++;else markerValid=false;}
      else if(c=='\r'&&!markerCr){markerCr=true;}else markerValid=false;
     }
    }
   }
   if(lineLength>0)SaveLine(stream,prefix,lineLength,last,false,markerValid&&markerIndex==UnsafeMarker.Length);
  }catch(Exception e){
   lock(gate){streamFailure=true;streamFailureMessage=e.GetType().FullName+": "+e.Message;}
   // A decoding/read failure must not leave a native producer blocked on its pipe.
   // Discarding subsequent bytes is explicitly a stream failure, never loss-free.
   if(!drainCancellation.IsCancellationRequested){
    try{var raw=new byte[4096];while(await reader.BaseStream.ReadAsync(raw.AsMemory(),drainCancellation.Token).ConfigureAwait(false)>0){}}
    catch(Exception){lock(gate){streamFailure=true;}}
   }
  }
 }
 private void SaveLine(string stream,StringBuilder prefix,long actualLength,char last,bool newline,bool marker) {
  long logicalLength=actualLength-(newline&&last=='\r'?1:0);
  string terminator=newline?(last=='\r'?"\r\n":"\n"):String.Empty;
  lock(gate){
   totalLines++;if(marker)unsafeSignal=true; // Before every retention/cap decision.
   if(logicalLength>maxLineChars||lines.Count>=maxLines||retainedChars+logicalLength+terminator.Length>maxTotalChars){
    overflow=true;droppedLines++;droppedChars+=logicalLength+terminator.Length;return;
   }
   string text=prefix.ToString();if(newline&&last=='\r'&&text.EndsWith("\r",StringComparison.Ordinal))text=text.Substring(0,text.Length-1);
   lines.Add(new Line {Sequence=++sequence,Stream=stream,Text=text,Terminator=terminator});retainedChars+=text.Length+terminator.Length;
  }
 }
 private bool Signaled(){return ownedHandle!=null&&!ownedHandle.IsClosed&&!ownedHandle.IsInvalid&&WaitForSingleObject(ownedHandle,0)==0;}
 public Task<Outcome> BeginWait(DateTimeOffset authorityEnds,long cleanupReserveMs,long maximumExecutionMs) {
  if(waitTask!=null)throw new InvalidOperationException("Owned wait already armed");
  waitTask=Task.Run(()=>Wait(authorityEnds,cleanupReserveMs,maximumExecutionMs));return waitTask;
 }
 public Outcome Wait(DateTimeOffset authorityEnds,long cleanupReserveMs,long maximumExecutionMs) {
  if(!StartedIdentity.Started||cleanupReserveMs<1||maximumExecutionMs<1)throw new InvalidOperationException("Owned wait has no finite reservation");
  var result=new Outcome {Started=true};
  DateTimeOffset executionEnds=authorityEnds.AddMilliseconds(-cleanupReserveMs);
  while(!Signaled()){
   if(DateTimeOffset.UtcNow>=executionEnds||lifetimeClock.ElapsedMilliseconds>=maximumExecutionMs){result.DeadlineReached=true;break;}
   WaitForSingleObject(ownedHandle,50);
  }
  if(result.DeadlineReached&&!Signaled()){
   result.TerminationAttempted=true;
   if(ownedHandle!=null&&!ownedHandle.IsClosed&&!ownedHandle.IsInvalid&&GetProcessId(ownedHandle)==StartedIdentity.Pid){
    result.TerminationSucceeded=TerminateProcess(ownedHandle,57005);
    if(!result.TerminationSucceeded)result.Failure="Exact owned handle termination failed: "+Marshal.GetLastWin32Error();
   }else result.Failure="Original owned process handle identity unavailable";
  }
  var cleanupClock=Stopwatch.StartNew();
  while(!Signaled()&&cleanupClock.ElapsedMilliseconds<cleanupReserveMs&&DateTimeOffset.UtcNow<authorityEnds){WaitForSingleObject(ownedHandle,25);}
  uint exit;
  if(Signaled()&&GetExitCodeProcess(ownedHandle,out exit)){
   result.NativeTerminalObserved=true;result.NativeExitCode=unchecked((int)exit);result.ObservedTerminalUtc=DateTimeOffset.UtcNow.ToString("o");
  }
  while((!stdoutTask.IsCompleted||!stderrTask.IsCompleted||!inputTask.IsCompleted)&&cleanupClock.ElapsedMilliseconds<cleanupReserveMs&&DateTimeOffset.UtcNow<authorityEnds){Thread.Sleep(10);}
  result.StreamsDrained=stdoutTask.IsCompletedSuccessfully&&stderrTask.IsCompletedSuccessfully;
  result.InputCompleted=inputTask.IsCompletedSuccessfully;
  if(!result.StreamsDrained||!result.InputCompleted){drainCancellation.Cancel();try{process.StandardInput.BaseStream.Dispose();}catch{}try{process.StandardOutput.Dispose();}catch{}try{process.StandardError.Dispose();}catch{} }
  lock(gate){
   result.StreamFailure=streamFailure;result.OutputOverflow=overflow;result.UnsafeSignalObserved=unsafeSignal;
   result.InputFailure=inputFailure;
   result.TotalLines=totalLines;result.DroppedLines=droppedLines;result.TotalCharacters=totalChars;result.DroppedCharacters=droppedChars;result.RetainedCharacters=retainedChars;
   result.Lines=lines.ToArray();if(result.Failure==null)result.Failure=streamFailureMessage;
  }
  // Forced parent termination interrupts application-owned cleanup. Child/tree
  // cleanup is unknown even if this exact parent handle is now signaled.
  // Decoding/read loss can hide an unsafe marker in the discarded remainder.
  // Drained raw bytes therefore do not establish safety-signal coverage.
  result.OwnedCleanupUnverified=result.DeadlineReached||result.TerminationAttempted||!result.NativeTerminalObserved||!result.StreamsDrained||!result.InputCompleted||result.InputFailure||result.UnsafeSignalObserved||result.StreamFailure||result.OutputOverflow||!String.IsNullOrEmpty(StartedIdentity.ObservationFailure);
  return result;
 }
 // This exercises the same decoder, splitter and capture bounds without starting
 // any process or reading a native identity. It is a test fixture, not acceptance.
 public Outcome CaptureFixture(byte[] stdout,byte[] stderr) {
  if(StartedIdentity.Started)throw new InvalidOperationException("Capture fixture cannot use a started owner");
  using(var output=new StreamReader(new MemoryStream(stdout),new UTF8Encoding(false,true),false))
  using(var error=new StreamReader(new MemoryStream(stderr),new UTF8Encoding(false,true),false)) {
   Task.WhenAll(Drain(output,"stdout"),Drain(error,"stderr")).GetAwaiter().GetResult();
  }
  lock(gate){return new Outcome {StreamsDrained=true,StreamFailure=streamFailure,OutputOverflow=overflow,UnsafeSignalObserved=unsafeSignal,OwnedCleanupUnverified=streamFailure||overflow||unsafeSignal,TotalLines=totalLines,DroppedLines=droppedLines,TotalCharacters=totalChars,DroppedCharacters=droppedChars,RetainedCharacters=retainedChars,Lines=lines.ToArray()};}
 }
 public static string Reconstruct(Line[] captured,string stream) {
  var text=new StringBuilder();foreach(var line in captured)if(line.Stream==stream)text.Append(line.Text).Append(line.Terminator);return text.ToString();
 }
 public void Dispose(){
  // No disposal can stand in for proof of native termination. The caller retains
  // the outcome before this cleanup and must preserve unsafe state separately.
  if(waitTask!=null&&!waitTask.IsCompleted){waitTask.ContinueWith(_=>Dispose());return;}
  if(StartedIdentity.Started&&!Signaled())return; // Retain the live exact handle; never substitute disposal for cleanup.
  drainCancellation.Cancel();process.Dispose();drainCancellation.Dispose();
 }
}
