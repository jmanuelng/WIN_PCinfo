[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $repositoryRoot 'src/SystemCollectionPlan.ps1')
# Exercise the exported activation worker with its actual framed transport.
# Invalid input must return refusal as its first frame, before activation-ready
# or registration. Every case is explicitly synthetic and starts no OS source.
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput((Get-PrivilegedCollectionWorkerSource),[ref]$tokens,[ref]$errors)
foreach ($name in @('Read-ExactBytes','Read-Frame','Write-Frame')) {
    $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name}.GetNewClosure(),$false)
    . ([scriptblock]::Create($function.Extent.Text))
}
$nonce='a'*64
$settings=[ordered]@{
    nonce=$nonce;pipe=('WINPCInfo-SystemCollection-v1-'+$nonce.Substring(0,32))
    jobName=('Global\WINPCInfo-SystemCollection-v1-'+$nonce.Substring(0,32));maximumBytes=8192
    deadlineMilliseconds=5000;coordinatorProcessId=$PID;executableSha256=('b'*64)
    workerPayloadSha256=(Get-SystemCollectionSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes((Get-SystemCollectionWorkerSource))))
    planDigest=('c'*64);validationFixture=$true;workerFault=''
}
$configuration=[pscustomobject]@{coordinatorProcessId=$PID;executableSha256=('b'*64);systemPlanDigest=('c'*64);validationFixture=$true}
foreach ($case in @('UnknownOperation','OwnershipTransfer','UntypedDeadline','WrongPlan','Expired')) {
    $request=[ordered]@{kind='ActivateSystemPlan';configuration=($settings|ConvertTo-Json|ConvertFrom-Json)}
    switch ($case) {
        UnknownOperation { $request.kind='ExecuteCommand' }
        OwnershipTransfer { $request.configuration|Add-Member -NotePropertyName localPackageProtector -NotePropertyValue 'protector:alternate' }
        UntypedDeadline { $request.configuration.deadlineMilliseconds='5000' }
        WrongPlan { $request.configuration.planDigest='d'*64 }
    }
    $stream=[IO.MemoryStream]::new(); $deadline=[Threading.CancellationTokenSource]::new(2000)
    try {
        Write-BoundedCollectionChannelFrame -Stream $stream -Json ($request|ConvertTo-Json -Compress -Depth 5) -MaximumBytes 16384 -CancellationToken $deadline.Token
        $inputLength=$stream.Length; $stream.Position=0
        if ($case -eq 'Expired') { $deadline.Cancel() }
        Invoke-SystemActivationWorker -Stream $stream -Configuration $configuration -InitiatingSid 'S-1-5-21-100-200-300-1001' -Token $deadline.Token
        $stream.Position=if($case -eq 'Expired'){0}else{$inputLength}
        $reply=(Read-BoundedCollectionChannelFrame -Stream $stream -MaximumBytes 16384 -CancellationToken ([Threading.CancellationToken]::None))|ConvertFrom-Json
        Assert-Equal 'SystemReleased' $reply.kind "$case is refused before activation-ready"
        Assert-Equal 'ProtocolRejected' $reply.reason "$case is an explicit protocol rejection"
        Assert-Equal $true $reply.absent "$case leaves no SYSTEM activation resource"
    } finally { $deadline.Dispose(); $stream.Dispose() }
}
Write-Output 'PASS: SYSTEM broker refuses arbitrary operations, ownership transfer, untyped parameters, changed plans and expired input.'
