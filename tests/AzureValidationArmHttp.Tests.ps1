[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot) 'src/AzureValidationArmTransport.ps1')
# Exercise the production HttpClient request/read/dispose boundary using an
# in-memory message handler. This class opens no socket or child process.
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
namespace WinPcInfo.ArmHttpTests {
    public sealed class Handler : HttpMessageHandler {
        public int Calls;
        public bool Disposed;
        public bool ContentDisposed;
        public string SeenUri;
        public bool StreamDisposed;
        public bool Streaming;
        public long StreamLength;
        public long BytesRead;
        public bool ThrowPrivate;
        public bool StreamThrowOnDispose;
        public bool ContentThrowOnDispose;
        public bool HandlerThrowOnDispose;
        public bool CancelOnSend;
        public bool CancelOnRead;
        public CancellationTokenSource ExternalCancellation;
        public string SeenMethod;
        public string SeenAuthorization;
        public byte[] Bytes = new byte[] {123,125};
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            Calls++;
            if (CancelOnSend) ExternalCancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            if (ThrowPrivate) throw new IOException("private synthetic credential detail");
            SeenUri=request.RequestUri.AbsoluteUri;
            SeenMethod=request.Method.Method;
            SeenAuthorization=request.Headers.Authorization.ToString();
            var response=new HttpResponseMessage(HttpStatusCode.OK);
            response.RequestMessage=request;
            response.Content=Streaming
                ? (HttpContent)new StreamContent(new BoundedTestStream(this))
                : new Content(this,Bytes);
            return Task.FromResult(response);
        }
        protected override void Dispose(bool disposing) {
            Disposed=true; base.Dispose(disposing);
            if (HandlerThrowOnDispose) throw new IOException("private synthetic handler cleanup detail");
        }
    }
    public sealed class BoundedTestStream : Stream {
        private readonly Handler owner;
        public BoundedTestStream(Handler owner) { this.owner=owner; }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { return owner.BytesRead; } set { throw new NotSupportedException(); } }
        public override void Flush() { }
        public override long Seek(long offset,SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer,int offset,int count) { throw new NotSupportedException(); }
        public override int Read(byte[] buffer,int offset,int count) {
            int n=(int)Math.Min(count,owner.StreamLength-owner.BytesRead);
            Array.Fill<byte>(buffer,65,offset,n);
            owner.BytesRead+=n;
            return n;
        }
        public override Task<int> ReadAsync(byte[] buffer,int offset,int count,CancellationToken token) {
            if (owner.CancelOnRead) owner.ExternalCancellation.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.FromResult(Read(buffer,offset,count));
        }
        protected override void Dispose(bool disposing) {
            owner.StreamDisposed=true; base.Dispose(disposing);
            if (owner.StreamThrowOnDispose) throw new IOException("private synthetic stream cleanup detail");
        }
    }
    public sealed class Content : ByteArrayContent {
        private readonly Handler owner;
        public Content(Handler owner,byte[] bytes):base(bytes) { this.owner=owner; }
        protected override void Dispose(bool disposing) {
            owner.ContentDisposed=true; base.Dispose(disposing);
            if (owner.ContentThrowOnDispose) throw new IOException("private synthetic content cleanup detail");
        }
    }
}
'@
$script:Assertions=0
function Assert-HttpBoundary {
    param([bool] $Condition,[string] $Message)
    $script:Assertions++
    if (-not $Condition) { throw $Message }
}
function New-HttpBoundaryRequest {
    [pscustomobject]@{
        Uri='https://management.azure.com/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic?api-version=2021-04-01'
        Method='GET';Headers=@{Accept='application/json';Authorization='Bearer e30.e30.c3ludGhldGlj'}
        Body=$null;MaximumBytes=4194304
        DeadlineUtc=[DateTimeOffset]::UtcNow.AddMinutes(1)
        TimeoutMilliseconds=30000;CancellationToken=[Threading.CancellationToken]::None
    }
}
$handler=[WinPcInfo.ArmHttpTests.Handler]::new()
$request=New-HttpBoundaryRequest
$response=Invoke-AzureArmHttpRequest -Request $request -InternalMessageHandler $handler
Assert-HttpBoundary ($response.StatusCode -eq 200 -and $response.Uri -ceq $request.Uri -and
    [Text.Encoding]::UTF8.GetString($response.Body) -ceq '{}') 'HTTP boundary changed response bytes, status or actual response URI.'
Assert-HttpBoundary ($handler.Calls -eq 1 -and $handler.SeenMethod -ceq 'GET' -and
    $handler.SeenUri -ceq $request.Uri -and $handler.SeenAuthorization -ceq $request.Headers.Authorization) 'HTTP boundary did not dispatch the admitted request exactly.'
Assert-HttpBoundary ($handler.Disposed -and $handler.ContentDisposed) 'HTTP client or response content survived successful dispatch.'
function Assert-HttpRefusal {
    param([scriptblock] $Action,[string] $Reason)
    $observed=''
    try { $null=& $Action } catch { $observed=$_.Exception.Message }
    Assert-HttpBoundary ($observed -ceq $Reason) ('HTTP refusal differed from the closed reason: '+$observed)
}
# Declared lengths and streaming bodies both obey the same bound.
$handler=[WinPcInfo.ArmHttpTests.Handler]::new()
$handler.Bytes=[byte[]]::new(4194305)
$request=New-HttpBoundaryRequest
Assert-HttpRefusal { Invoke-AzureArmHttpRequest -Request $request -InternalMessageHandler $handler } 'VALIDATION.SERVICE_TRANSPORT_FAILED'
Assert-HttpBoundary ($handler.Disposed -and $handler.ContentDisposed) 'Declared oversize response escaped disposal.'
$handler=[WinPcInfo.ArmHttpTests.Handler]::new()
$handler.Streaming=$true
$handler.StreamLength=4194305
$request=New-HttpBoundaryRequest
Assert-HttpRefusal { Invoke-AzureArmHttpRequest -Request $request -InternalMessageHandler $handler } 'VALIDATION.SERVICE_TRANSPORT_FAILED'
Assert-HttpBoundary ($handler.BytesRead -eq 4194305 -and $handler.Disposed -and $handler.StreamDisposed) 'Streaming overflow was unbounded or escaped disposal.'
# Cancellation before dispatch, during send, and during streaming preserves
# the interruption reason without exposing private transport exception text.
foreach ($phase in @('Before','Send','Read')) {
    $cancel=[Threading.CancellationTokenSource]::new()
    try {
        $handler=[WinPcInfo.ArmHttpTests.Handler]::new()
        $handler.ExternalCancellation=$cancel
        $request=New-HttpBoundaryRequest
        $request.CancellationToken=$cancel.Token
        if ($phase -ceq 'Before') { $cancel.Cancel() }
        elseif ($phase -ceq 'Send') { $handler.CancelOnSend=$true }
        else { $handler.Streaming=$true; $handler.StreamLength=10; $handler.CancelOnRead=$true }
        Assert-HttpRefusal { Invoke-AzureArmHttpRequest -Request $request -InternalMessageHandler $handler } 'VALIDATION.ROUND_INTERRUPTED'
        Assert-HttpBoundary ($handler.Disposed) ('Client survived '+$phase+' cancellation.')
        if ($phase -ceq 'Before') { Assert-HttpBoundary ($handler.Calls -eq 0) 'Pre-cancelled request dispatched.' }
        if ($phase -ceq 'Read') { Assert-HttpBoundary ($handler.StreamDisposed -and $handler.BytesRead -eq 0) 'Cancelled read consumed body or survived cleanup.' }
    }
    finally { $cancel.Dispose() }
}
$handler=[WinPcInfo.ArmHttpTests.Handler]::new()
$request=New-HttpBoundaryRequest
$request.DeadlineUtc=[DateTimeOffset]::UtcNow.AddSeconds(-1)
Assert-HttpRefusal { Invoke-AzureArmHttpRequest -Request $request -InternalMessageHandler $handler } 'VALIDATION.ROUND_INTERRUPTED'
Assert-HttpBoundary ($handler.Calls -eq 0 -and $handler.Disposed) 'Expired request dispatched or leaked its client.'
$handler=[WinPcInfo.ArmHttpTests.Handler]::new()
$handler.ThrowPrivate=$true
$request=New-HttpBoundaryRequest
Assert-HttpRefusal { Invoke-AzureArmHttpRequest -Request $request -InternalMessageHandler $handler } 'VALIDATION.SERVICE_TRANSPORT_FAILED'
Assert-HttpBoundary ($handler.Disposed) 'Failed send escaped client disposal.'
$handler=[WinPcInfo.ArmHttpTests.Handler]::new()
$request=New-HttpBoundaryRequest
$request.Uri='https://unapproved.invalid/'
try {
    Assert-HttpRefusal { Invoke-AzureArmHttpRequest -Request $request -InternalMessageHandler $handler } 'VALIDATION.SERVICE_REQUEST_INVALID'
    Assert-HttpBoundary ($handler.Calls -eq 0) 'Substituted origin reached the HTTP handler.'
}
finally { $handler.Dispose() }
foreach ($fault in @('Stream','Content','Handler')) {
    $handler=[WinPcInfo.ArmHttpTests.Handler]::new()
    $request=New-HttpBoundaryRequest
    if ($fault -ceq 'Stream') { $handler.Streaming=$true; $handler.StreamLength=10; $handler.StreamThrowOnDispose=$true }
    elseif ($fault -ceq 'Content') { $handler.ContentThrowOnDispose=$true }
    else { $handler.HandlerThrowOnDispose=$true }
    Assert-HttpRefusal { Invoke-AzureArmHttpRequest -Request $request -InternalMessageHandler $handler } 'VALIDATION.SERVICE_TRANSPORT_FAILED'
    Assert-HttpBoundary ($handler.Disposed) ('Earlier '+$fault+' disposal failure skipped client disposal.')
}
$cancel=[Threading.CancellationTokenSource]::new()
try {
    $handler=[WinPcInfo.ArmHttpTests.Handler]::new()
    $handler.Streaming=$true; $handler.StreamLength=10
    $handler.CancelOnRead=$true; $handler.ExternalCancellation=$cancel; $handler.StreamThrowOnDispose=$true
    $request=New-HttpBoundaryRequest; $request.CancellationToken=$cancel.Token
    Assert-HttpRefusal { Invoke-AzureArmHttpRequest -Request $request -InternalMessageHandler $handler } 'VALIDATION.ROUND_INTERRUPTED'
    Assert-HttpBoundary ($handler.Disposed) 'Stream disposal failure replaced interruption or skipped client disposal.'
}
finally { $cancel.Dispose() }
[ordered]@{recordType='win-pcinfo.in-memory-http-boundary-tests';result='Pass';nonQualifying=$true;
    assertions=$script:Assertions;socketDispatches=0;scope='Production HttpClient framing/stream/disposal under in-memory message handler only'} |
    ConvertTo-Json -Compress | Write-Output
