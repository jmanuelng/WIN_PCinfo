[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'QualificationCapabilityProcess.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $repositoryRoot 'src/SystemCollectionPlan.ps1')
Initialize-PrivilegedCollectionPlanNativeType
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$nonce=[guid]::NewGuid().ToString('N')
$jobName='Local\WINPCInfo-System-Peer-'+$nonce
$job=$null
$otherJob=$null
$server=$null
$deadline=$null
$worker=$null
$workerOwner=$null
$bodyError=$null
try {
    $job=[WinPCInfo.PrivilegedCollectionPlan.OwnedJob]::Create($jobName,"D:P(A;;GA;;;$sid)")
    $otherJob=[WinPCInfo.PrivilegedCollectionPlan.OwnedJob]::Create(($jobName+'-other'),"D:P(A;;GA;;;$sid)")
    $server=[IO.Pipes.NamedPipeServerStream]::new(('WINPCInfo-System-Peer-'+$nonce),[IO.Pipes.PipeDirection]::InOut,1,[IO.Pipes.PipeTransmissionMode]::Byte,[IO.Pipes.PipeOptions]::Asynchronous)
    $deadline=[Threading.CancellationTokenSource]::new(10000)
    # The real release SYSTEM worker joins the owned Job and connects with an
    # Identification token. It is explicitly synthetic and receives no plan.
    $source=Get-SystemCollectionWorkerSource
    $executable=Join-Path $PSHOME 'pwsh.exe'
    $digest=Get-SystemCollectionSha256 -Bytes ([IO.File]::ReadAllBytes($executable))
    $config=@{nonce=('a'*64);pipe=('WINPCInfo-System-Peer-'+$nonce);jobName=$jobName;maximumBytes=8192;deadlineMilliseconds=10000;coordinatorProcessId=$PID;executableSha256=$digest;workerPayloadSha256=(Get-SystemCollectionSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source)));planDigest=('b'*64);validationFixture=$true;workerFault=''}
    $source=$source.Replace('__SYSTEM_WORKER_CONFIGURATION__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($config|ConvertTo-Json -Compress))))
    $start=[Diagnostics.ProcessStartInfo]::new($executable)
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    foreach($arg in @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',(ConvertTo-PrivilegedCollectionEncodedCommand -Source $source))){$start.ArgumentList.Add($arg)}
    $workerOwner=New-QualificationCapabilityProcessOwner -RepositoryRoot $repositoryRoot -Profile SystemWorkerPeer -StartInfo $start
    Assert-QualificationCapabilityCreation -Owner $workerOwner
    $worker=[Diagnostics.Process]::Start($start)
    Register-QualificationCapabilityProcess -Owner $workerOwner -Process $worker
    $null=$server.WaitForConnectionAsync($deadline.Token).GetAwaiter().GetResult()
    $hello=Read-BoundedCollectionChannelFrame -Stream $server -MaximumBytes 8192 -CancellationToken $deadline.Token
    $identityHandle=$null
    $peer=$null
    $peerError=$null
    try {
        $peer=Get-SystemCollectionWorkerPeer -Server $server -OwnedJob $job -ExpectedExecutable $executable -ExpectedDigest $digest -ExpectedSid $sid -ExpectedProcessId 0 -IdentityHandle ([ref]$identityHandle)
        Assert-Equal $worker.Id $peer.Id 'kernel worker admission needs no equality with unrelated scheduler-engine PID'
    } catch {$peerError=$_}
    finally {Complete-QualificationHarness -BodyError $peerError -Cleanup @({if($null -ne $peer){$peer.Dispose()}},{if($null -ne $identityHandle){$identityHandle.Dispose()}})}
    foreach($case in @('WrongJob','WrongSid','WrongImage','WrongDigest','WrongPid')) {
        $identityHandle=$null
        $arguments=@{Server=$server;OwnedJob=$job;ExpectedExecutable=$executable;ExpectedDigest=$digest;ExpectedSid=$sid;ExpectedProcessId=$worker.Id;IdentityHandle=([ref]$identityHandle)}
        switch($case) {
            WrongJob {$arguments.OwnedJob=$otherJob}
            WrongSid {$arguments.ExpectedSid='S-1-5-18'}
            WrongImage {$arguments.ExpectedExecutable=Join-Path $PSHOME 'unadmitted.exe'}
            WrongDigest {$arguments.ExpectedDigest='0'*64}
            WrongPid {$arguments.ExpectedProcessId=$PID}
        }
        $rejected=$false
        $unexpected=$null
        try {$unexpected=Get-SystemCollectionWorkerPeer @arguments} catch {$rejected=$true}
        finally {Complete-QualificationHarness -Cleanup @({if($null -ne $unexpected){$unexpected.Dispose()}},{if($null -ne $identityHandle){$identityHandle.Dispose()}})}
        Assert-Equal $true $rejected "$case cannot enter the SYSTEM plan"
        Assert-Equal $true ($null -eq [Security.Principal.WindowsIdentity]::GetCurrent($true)) 'identification always reverts the thread token'
    }
}
catch {$bodyError=$_}
finally {
    Complete-QualificationCapabilityProcess -Owner $workerOwner -Process $worker -BodyError $bodyError -Cleanup @(
        {if($null -ne $server){$server.Dispose()}},
        {if($null -ne $job){if(-not $job.Terminate()){throw 'The original SYSTEM peer Job termination was not verified.'}}},
        {if($null -ne $deadline){$deadline.Dispose()}},
        {if($null -ne $job){$job.Dispose()}},
        {if($null -ne $otherJob){$otherJob.Dispose()}}
    )
}
Write-Output 'PASS: kernel SYSTEM worker PID, owned Job, Identification SID and admitted image are jointly required.'
