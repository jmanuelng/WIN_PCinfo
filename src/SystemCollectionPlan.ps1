$script:SystemCollectionPlanPolicyBase64 = '__SYSTEM_COLLECTION_PLAN_POLICY_BASE64__'
$script:SystemCollectionPlanPolicyDigest = '__SYSTEM_COLLECTION_PLAN_POLICY_SHA256__'

function Get-SystemCollectionSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-SystemCollectionPlanPolicy {
    $convertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $convertFromJsonCommand -or
        $convertFromJsonCommand.ModuleName -ne 'Microsoft.PowerShell.Utility') {
        throw 'The SYSTEM policy JSON command does not have built-in provenance.'
    }

    if ($script:SystemCollectionPlanPolicyBase64 -eq ('__SYSTEM_COLLECTION_PLAN_' + 'POLICY_BASE64__')) {
        $repositoryRoot = Split-Path -Parent $PSScriptRoot
        $path = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-system-collection-plan.json'
        $text = [System.IO.File]::ReadAllText(
            $path, [System.Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text)
        $expectedDigest = Get-SystemCollectionSha256 -Bytes $bytes
    }
    else {
        $bytes = [System.Convert]::FromBase64String($script:SystemCollectionPlanPolicyBase64)
        $expectedDigest = $script:SystemCollectionPlanPolicyDigest
    }
    if ((Get-SystemCollectionSha256 -Bytes $bytes) -ne $expectedDigest) {
        throw 'The embedded SYSTEM policy failed integrity validation.'
    }
    & $convertFromJsonCommand -InputObject (
        [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 30 -ErrorAction Stop
}

function Get-SystemCollectionValidationScenario {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Name)

    # A fixture name controls several cooperating seams: whether Task
    # Scheduler is used, how long the coordinator waits, what the worker does,
    # and whether cleanup injects its one allowed retry. Keeping that behavior
    # in one tuple prevents a future test case from meaning different things to
    # the coordinator and worker. The empty name is the live controlled-client
    # path; it is data here too, rather than a special string scattered through
    # the security-sensitive control flow.
    $defaults = [ordered]@{
        isFixture = $true
        activationFailure = $false
        activationDenied = $false
        operationDeadlineMilliseconds = $null
        workerDeadlineMilliseconds = $null
        workerFault = ''
        workerLossExpected = $false
        injectCleanupFailure = $false
        planMutation = 'None'
        cancellationDelayMilliseconds = $null
    }
    $scenarios = @{
        '' = @{ isFixture = $false }
        SyntheticSuccess = @{}
        UnknownOperation = @{ planMutation = 'UnknownOperation' }
        InvalidParameters = @{ planMutation = 'InvalidParameters' }
        ActivationFailure = @{ activationFailure = $true }
        WorkerLost = @{ workerFault = 'Lost'; workerLossExpected = $true }
        Cancellation = @{ workerFault = 'Wait'; cancellationDelayMilliseconds = 200 }
        Timeout = @{
            operationDeadlineMilliseconds = 200
            workerDeadlineMilliseconds = 30000
            workerFault = 'Wait'
        }
        Denied = @{ activationDenied = $true }
        AbnormalCleanup = @{ injectCleanupFailure = $true }
    }
    if (-not $scenarios.ContainsKey($Name)) {
        throw 'The SYSTEM collection validation scenario is not release-defined.'
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

function Get-SystemCollectionWorkerSource {
    # This worker is release source, not a caller script. The only substituted
    # value is a coordinator-created, closed protocol configuration containing
    # random object names, digests, process identity, timing, and a synthetic
    # fault selector. It contains no Assessment User Context, package authority,
    # credential, evidence value, executable path, operation ID, or parameter.
    @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$configurationJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    [System.Convert]::FromBase64String('__SYSTEM_WORKER_CONFIGURATION__')
)
$configuration = $configurationJson | ConvertFrom-Json -Depth 10

Add-Type -TypeDefinition @"
using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace WinPCInfo.SystemCollectionWorker
{
    public static class KernelTrust
    {
        private const uint JOB_OBJECT_ASSIGN_PROCESS = 0x0001;
        private const uint JOB_OBJECT_QUERY = 0x0004;
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

        public static void JoinOwnedJob(string name)
        {
            IntPtr job = OpenJobObject(JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY, false, name);
            if (job == IntPtr.Zero) throw new InvalidOperationException("Owned job unavailable.");
            try
            {
                if (!AssignProcessToJobObject(job, GetCurrentProcess()))
                    throw new InvalidOperationException("Worker tree ownership failed.");
            }
            finally { CloseHandle(job); }
        }

        public static int GetServerProcessId(PipeStream pipe)
        {
            uint processId;
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out processId))
                throw new InvalidOperationException("Coordinator identity unavailable.");
            return checked((int)processId);
        }
    }
}
"@

function Read-ExactSystemBytes {
    param($Stream, [int] $Count, [System.Threading.CancellationToken] $Token)
    $bytes = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.ReadAsync(
            $bytes, $offset, $Count - $offset, $Token
        ).GetAwaiter().GetResult()
        if ($read -eq 0) { throw 'The SYSTEM channel closed early.' }
        $offset += $read
    }
    $bytes
}

function Read-SystemFrame {
    param($Stream, [int] $MaximumBytes, [System.Threading.CancellationToken] $Token)
    $lengthBytes = Read-ExactSystemBytes -Stream $Stream -Count 4 -Token $Token
    $length = [System.BitConverter]::ToInt32($lengthBytes, 0)
    if ($length -le 0 -or $length -gt $MaximumBytes) { throw 'Invalid SYSTEM frame length.' }
    [System.Text.UTF8Encoding]::new($false, $true).GetString(
        (Read-ExactSystemBytes -Stream $Stream -Count $length -Token $Token)
    )
}

function Write-SystemFrame {
    param($Stream, [string] $Json, [int] $MaximumBytes, [System.Threading.CancellationToken] $Token)
    $payload = [System.Text.UTF8Encoding]::new($false).GetBytes($Json)
    if ($payload.Length -le 0 -or $payload.Length -gt $MaximumBytes) { throw 'Invalid SYSTEM frame payload.' }
    $length = [System.BitConverter]::GetBytes([int] $payload.Length)
    $null = $Stream.WriteAsync($length, 0, 4, $Token).GetAwaiter().GetResult()
    $null = $Stream.WriteAsync($payload, 0, $payload.Length, $Token).GetAwaiter().GetResult()
    $null = $Stream.FlushAsync($Token).GetAwaiter().GetResult()
}

$deadline = [System.Threading.CancellationTokenSource]::new([int] $configuration.deadlineMilliseconds)
$pipe = $null
try {
    # The Job handle is created by the administrator coordinator before any
    # activation. The fixed worker joins it before connecting or receiving the
    # plan. Failure means no source access: unowned SYSTEM execution is never an
    # accepted fallback, and kill-on-close covers every descendant thereafter.
    [WinPCInfo.SystemCollectionWorker.KernelTrust]::JoinOwnedJob([string] $configuration.jobName)
    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
        '.', [string] $configuration.pipe,
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous
    )
    $pipe.ConnectAsync($deadline.Token).GetAwaiter().GetResult()
    $serverProcessId = [WinPCInfo.SystemCollectionWorker.KernelTrust]::GetServerProcessId($pipe)
    if ($serverProcessId -ne [int] $configuration.coordinatorProcessId) {
        throw 'The SYSTEM coordinator process does not match the frozen launch.'
    }
    $serverImage = [System.Diagnostics.Process]::GetProcessById($serverProcessId).MainModule.FileName
    $serverDigest = [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData([System.IO.File]::ReadAllBytes($serverImage))
    ).ToLowerInvariant()
    if ($serverDigest -ne [string] $configuration.executableSha256) {
        throw 'The SYSTEM coordinator executable identity changed.'
    }

    $workerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $isLocalSystem = $workerSid -eq 'S-1-5-18'
    if (-not [bool] $configuration.validationFixture -and -not $isLocalSystem) {
        throw 'The device-level source requires LocalSystem.'
    }
    $workerImage = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $workerImageDigest = [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData([System.IO.File]::ReadAllBytes($workerImage))
    ).ToLowerInvariant()
    $hello = [pscustomobject][ordered]@{
        kind = 'SystemWorkerHello'
        contractVersion = '1.0.0'
        nonce = [string] $configuration.nonce
        workerProcessId = $PID
        coordinatorProcessId = $serverProcessId
        workerPayloadSha256 = [string] $configuration.workerPayloadSha256
        executableSha256 = $workerImageDigest
        executionContext = if ($isLocalSystem) { 'LocalSystem' } else { 'Synthetic' }
        localSystemSidVerified = $isLocalSystem
        treeControl = 'CoordinatorOwnedJobObject'
    }
    Write-SystemFrame -Stream $pipe -Json ($hello | ConvertTo-Json -Compress -Depth 5) `
        -MaximumBytes ([int] $configuration.maximumBytes) -Token $deadline.Token

    $requestJson = Read-SystemFrame -Stream $pipe -MaximumBytes ([int] $configuration.maximumBytes) `
        -Token $deadline.Token
    $documentOptions = [System.Text.Json.JsonDocumentOptions]::new()
    $documentOptions.MaxDepth = 8
    $document = [System.Text.Json.JsonDocument]::Parse($requestJson, $documentOptions)
    try {
        $root = $document.RootElement
        $names = @($root.EnumerateObject() | ForEach-Object Name)
        if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            $names.Count -ne 6 -or @($names | Sort-Object -Unique).Count -ne 6 -or
            $root.GetProperty('kind').GetString() -ne 'ExecuteSystemPlan' -or
            $root.GetProperty('contractVersion').GetString() -ne '1.0.0' -or
            $root.GetProperty('nonce').GetString() -ne [string] $configuration.nonce -or
            $root.GetProperty('planDigest').GetString() -ne [string] $configuration.planDigest -or
            $root.GetProperty('operations').GetArrayLength() -ne 1) {
            throw 'The SYSTEM request failed its closed protocol.'
        }
        $phaseId = $root.GetProperty('phaseId').GetString()
        $operation = $root.GetProperty('operations')[0]
        $operationNames = @($operation.EnumerateObject() | ForEach-Object Name)
        $parameters = $operation.GetProperty('parameters')
        $parameterNames = @($parameters.EnumerateObject() | ForEach-Object Name)
        if ($operationNames.Count -ne 2 -or @($operationNames | Sort-Object -Unique).Count -ne 2 -or
            $operation.GetProperty('operationId').GetString() -ne 'op:windows.mdm-bridge.device-manageability' -or
            $parameters.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            $parameterNames.Count -ne 1 -or @($parameterNames | Sort-Object -Unique).Count -ne 1 -or
            $parameters.GetProperty('queryKind').GetString() -ne 'DeviceManageabilityAvailability') {
            throw 'The SYSTEM operation or parameters are not release-defined.'
        }
    }
    finally { $document.Dispose() }

    if ([string] $configuration.workerFault -eq 'Lost') { exit 73 }
    if ([string] $configuration.workerFault -eq 'Wait') {
        [System.Threading.Thread]::Sleep(30000)
        exit 0
    }

    $providerAvailable = if ([bool] $configuration.validationFixture) {
        $true
    }
    else {
        # The live operation is deliberately read-only and fixed to one class.
        # It records provider presence only; it neither reads policy values nor
        # invokes a method, so SYSTEM cannot become a general WMI query surface.
        @(Get-CimInstance -Namespace 'Root\cimv2\mdm\dmmap' `
            -ClassName 'MDM_DeviceManageability_Provider01_01' -ErrorAction Stop).Count -gt 0
    }
    $result = [pscustomobject][ordered]@{
        kind = 'SystemPlanResult'
        contractVersion = '1.0.0'
        nonce = [string] $configuration.nonce
        planDigest = [string] $configuration.planDigest
        phaseId = $phaseId
        executionContext = if ($isLocalSystem) { 'LocalSystem' } else { 'Synthetic' }
        operations = @([pscustomobject][ordered]@{
            operationId = 'op:windows.mdm-bridge.device-manageability'
            state = 'Completed'
            providerAvailable = [bool] $providerAvailable
        })
    }
    Write-SystemFrame -Stream $pipe -Json ($result | ConvertTo-Json -Compress -Depth 5) `
        -MaximumBytes ([int] $configuration.maximumBytes) -Token ([System.Threading.CancellationToken]::None)
}
finally {
    if ($null -ne $pipe) { $pipe.Dispose() }
    $deadline.Dispose()
}
'@
}

function New-SystemCollectionPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $PreparationPlan,
        [Parameter(Mandatory)] [string] $PreparationPlanDigest
    )

    $policy = Get-SystemCollectionPlanPolicy
    $convertToJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $convertToJsonCommand -or
        (Get-ObjectDigest -Value $PreparationPlan -ConvertToJsonCommand $convertToJsonCommand) -ne
            $PreparationPlanDigest -or
        $PreparationPlan.release -ne $policy.release -or
        $PreparationPlan.privilege.privilegedOperationsFrozen -ne $true) {
        throw 'The approved Preparation Plan is not an eligible SYSTEM plan source.'
    }
    $systemOperations = @($PreparationPlan.privilege.privilegedOperations |
        Where-Object context -eq 'LocalSystem')
    if ($systemOperations.Count -ne 1 -or
        $systemOperations[0].operationId -ne 'observe-mdm-system-context') {
        throw 'The Preparation Plan does not contain the exact release SYSTEM operation.'
    }

    $plan = [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.system-collection-plan'
        contractVersion = '1.0.0'
        release = [string] $policy.release
        policyId = [string] $policy.policyId
        preparationPlanDigest = $PreparationPlanDigest
        phaseId = "system-phase:$([System.Guid]::NewGuid().ToString('N'))"
        operations = @([pscustomobject][ordered]@{
            operationId = [string] $policy.operations[0].operationId
            parameters = [pscustomobject][ordered]@{
                queryKind = [string] $policy.operations[0].parameters.queryKind.const
            }
        })
    }
    [pscustomobject][ordered]@{
        Plan = $plan
        Digest = Get-ObjectDigest -Value $plan -ConvertToJsonCommand $convertToJsonCommand
    }
}

function Get-SystemCollectionPlanValidationReason {
    param([Parameter(Mandatory)] $Plan, [Parameter(Mandatory)] $Policy)

    $names = @($Plan.PSObject.Properties.Name)
    if ($names.Count -ne 7 -or @($names | Sort-Object -Unique).Count -ne 7 -or
        $Plan.recordType -ne 'win-pcinfo.system-collection-plan' -or
        $Plan.contractVersion -ne '1.0.0' -or $Plan.release -ne $Policy.release -or
        $Plan.policyId -ne $Policy.policyId -or
        [string]::IsNullOrWhiteSpace([string] $Plan.preparationPlanDigest) -or
        [string]::IsNullOrWhiteSpace([string] $Plan.phaseId) -or
        @($Plan.operations).Count -ne 1) {
        return 'SYSTEM.PLAN_INTEGRITY_INVALID'
    }
    $operation = $Plan.operations[0]
    $operationNames = @($operation.PSObject.Properties.Name)
    if ($operationNames.Count -ne 2 -or
        @($operationNames | Sort-Object -Unique).Count -ne 2 -or
        $operation.operationId -ne $Policy.operations[0].operationId) {
        return 'SYSTEM.OPERATION_INVALID'
    }
    $parameterNames = @($operation.parameters.PSObject.Properties.Name)
    if ($parameterNames.Count -ne 1 -or $parameterNames[0] -ne 'queryKind' -or
        $operation.parameters.queryKind -ne $Policy.operations[0].parameters.queryKind.const -or
        [System.Text.Encoding]::UTF8.GetByteCount([string] $operation.parameters.queryKind) -gt
            [int] $Policy.operations[0].parameters.queryKind.maximumUtf8Bytes) {
        return 'SYSTEM.PARAMETERS_INVALID'
    }
    ''
}

function New-SystemCollectorResult {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [string] $CoverageState,
        [Parameter(Mandatory)] [string] $ObservedExecutionContext,
        [Parameter(Mandatory)] [bool] $LocalSystemIdentityVerified,
        [Parameter(Mandatory)] [bool] $CleanupVerified,
        [Parameter(Mandatory)] [bool] $TaskAbsent,
        [Parameter(Mandatory)] [bool] $PipeAbsent,
        [Parameter(Mandatory)] [bool] $WorkerTreeAbsent,
        [Parameter()] [AllowNull()] [Nullable[bool]] $ProviderAvailable,
        [Parameter()] [int] $CleanupRetries = 0,
        [Parameter()] [bool] $RunIntegrityCompromised = $false,
        [Parameter()] [Nullable[System.DateTimeOffset]] $StartedAt,
        [Parameter()] [Nullable[System.DateTimeOffset]] $CompletedAt,
        [Parameter()] [Nullable[System.DateTimeOffset]] $CollectedAt
    )

    $runId = [System.Guid]::NewGuid().ToString('N')
    $effectiveStartedAt = if ($null -ne $StartedAt) {
        [System.DateTimeOffset] $StartedAt
    }
    else { [System.DateTimeOffset]::UtcNow }
    $effectiveCompletedAt = if ($null -ne $CompletedAt) {
        [System.DateTimeOffset] $CompletedAt
    }
    else { [System.DateTimeOffset]::UtcNow }
    $effectiveCollectedAt = if ($null -ne $CollectedAt) {
        [System.DateTimeOffset] $CollectedAt
    }
    else { $effectiveCompletedAt }
    $operation = $Policy.operations[0]
    $coverageId = "coverage:mdm-system:$runId"
    $observationId = "observation:mdm-provider:$runId"
    $provenanceId = "provenance:mdm-system:$runId"
    $diagnosticId = "diagnostic:system-collection:$runId"
    $hasObservation = $null -ne $ProviderAvailable
    $observationIds = if ($hasObservation) { @($observationId) } else { @() }
    $diagnosticIds = if ($hasObservation) { @() } else { @($diagnosticId) }
    $observations = if ($hasObservation) {
        @([pscustomobject][ordered]@{
            observationId = $observationId
            fieldId = [string] $operation.result.fieldId
            subjectId = [string] $operation.subjectIds[0]
            provenanceId = $provenanceId
            valueState = 'ObservedValue'
            value = [bool] $ProviderAvailable
        })
    }
    else { @() }
    $provenance = if ($hasObservation) {
        @([pscustomobject][ordered]@{
            provenanceId = $provenanceId
            fieldId = [string] $operation.result.fieldId
            subjectId = [string] $operation.subjectIds[0]
            sourceId = [string] $operation.source.sourceId
            collectorId = [string] $operation.collectorId
            collectorVersion = [string] $operation.collectorVersion
            executionContext = $ObservedExecutionContext
            collectedAt = $effectiveCollectedAt.ToString(
                'o', [System.Globalization.CultureInfo]::InvariantCulture
            )
            sourceLocale = 'und'
        })
    }
    else { @() }
    $diagnostics = if ($hasObservation) { @() } else {
        @([pscustomobject][ordered]@{
            diagnosticId = $diagnosticId
            scopeId = [string] $operation.intendedScopeIds[0]
            phase = if ($State -eq 'CleanupIncomplete') { 'Cleanup' } else { 'Collection' }
            reasonCode = $ReasonCode
            operatorMessageId = 'system.collection.unavailable'
        })
    }

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.system-collection-phase'
        contractVersion = '1.0.0'
        state = $State
        reasonCode = $ReasonCode
        planDigest = $PlanDigest
        collectorResult = [pscustomobject][ordered]@{
            Envelope = [pscustomobject][ordered]@{
                envelopeId = "envelope:mdm-system:$runId"
                collectorId = [string] $operation.collectorId
                collectorVersion = [string] $operation.collectorVersion
                operationId = [string] $operation.operationId
                intendedScopeIds = @($operation.intendedScopeIds)
                subjectIds = @($operation.subjectIds)
                startedAt = $effectiveStartedAt.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                completedAt = $effectiveCompletedAt.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                executionContext = $ObservedExecutionContext
                attempts = 1
                observationIds = @($observationIds)
                coverageIds = @($coverageId)
                diagnosticIds = @($diagnosticIds)
            }
            Provenance = $provenance
            Observations = $observations
            Coverage = @([pscustomobject][ordered]@{
                coverageId = $coverageId
                scopeId = [string] $operation.intendedScopeIds[0]
                state = $CoverageState
                reasonCode = if ($CoverageState -eq 'Complete') { 'COLLECTION.COMPLETE' } else { $ReasonCode }
                observationIds = @($observationIds)
                diagnosticIds = @($diagnosticIds)
            })
            Diagnostics = $diagnostics
        }
        activation = [pscustomobject][ordered]@{
            requiredExecutionContext = 'LocalSystem'
            observedExecutionContext = $ObservedExecutionContext
            localSystemIdentityVerified = $LocalSystemIdentityVerified
            mechanism = if ($ObservedExecutionContext -eq 'Synthetic') { 'SyntheticDirect' } else { 'TransientTaskSchedulerCom' }
        }
        channel = [pscustomobject][ordered]@{
            oneInstance = $true
            aclProtected = $true
            peerProcessVerified = $State -eq 'Completed'
            peerArtifactVerified = $State -eq 'Completed'
            planSchemaValidated = $State -eq 'Completed'
            assessmentEvidenceCrossed = $false
        }
        cleanup = [pscustomobject][ordered]@{
            verified = $CleanupVerified
            workerTreeAbsent = $WorkerTreeAbsent
            taskAbsent = $TaskAbsent
            pipeAbsent = $PipeAbsent
            retries = $CleanupRetries
        }
        standardUserWorkMayContinue = -not $RunIntegrityCompromised -and $State -notin @('Cancelled', 'CleanupIncomplete')
        runIntegrityCompromised = $RunIntegrityCompromised
        validation = [pscustomobject][ordered]@{
            mode = if ($ObservedExecutionContext -eq 'Synthetic') { 'SyntheticUnelevated' } else { 'ControlledClient' }
            environmentalLimitation = if ($ObservedExecutionContext -eq 'Synthetic') {
                [pscustomobject][ordered]@{
                    state = 'NotStarted'
                    reasonCode = 'SYSTEM.LIVE_ACTIVATION_VALIDATION_UNAVAILABLE'
                    remediation = 'Run the exact generated candidate on an approved disposable or controlled Windows client and record a sanitized LocalSystem validation result.'
                }
            }
            else { $null }
        }
    }
}

function New-SystemCollectionStoppedResult {
    param(
        [Parameter(Mandatory)] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [string] $CoverageState,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter()] [bool] $RunIntegrityCompromised = $false
    )

    # Pre-activation failures all share the same important absence proof: no
    # task, worker, pipe, or temporary object was created. Centralizing that
    # tuple makes it difficult for one rejection branch to accidentally claim a
    # different cleanup or execution-context fact.
    $startedAt = if ($Context.ContainsKey('StartedAt')) {
        [System.DateTimeOffset] $Context.StartedAt
    }
    else { [System.DateTimeOffset]::UtcNow }
    New-SystemCollectorResult -Policy $Context.Policy -Plan $Context.Plan `
        -PlanDigest $Context.PlanDigest -State $State -ReasonCode $ReasonCode `
        -CoverageState $CoverageState `
        -ObservedExecutionContext $Context.ObservedExecutionContext `
        -LocalSystemIdentityVerified $false -CleanupVerified $true `
        -TaskAbsent $true -PipeAbsent $true -WorkerTreeAbsent $true `
        -RunIntegrityCompromised $RunIntegrityCompromised -StartedAt $startedAt
}

function Get-SystemAssessmentContractDefinition {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    $base = (Get-EmbeddedAssessmentContractSet `
        -ConvertFromJsonCommand $ConvertFromJsonCommand).Definition
    $operation = $Policy.operations[0]
    [pscustomobject][ordered]@{
        contractVersion = [string] $base.contractVersion
        schemaDraft = [string] $base.schemaDraft
        requiredFeatures = @($base.requiredFeatures)
        limits = $base.limits
        fieldDefinitions = @([pscustomobject][ordered]@{
            fieldId = [string] $operation.result.fieldId
            source = [pscustomobject][ordered]@{
                sourceId = [string] $operation.source.sourceId
            }
            valueType = [string] $operation.result.valueType
            bounds = [pscustomobject][ordered]@{
                maximumUtf8Bytes = 5 # UTF-8 bytes in "False", the longest Boolean spelling.
                maximumOccurrencesPerSubject = [int] $operation.result.maximumObservations
            }
        })
        scopeDefinitions = @([pscustomobject][ordered]@{
            scopeId = [string] $operation.intendedScopeIds[0]
            profileIds = @('profile:synthetic-contract-tracer')
            fieldIds = @([string] $operation.result.fieldId)
            collectorIds = @([string] $operation.collectorId)
        })
    }
}

function New-SystemAssessmentRecord {
    param([Parameter(Mandatory)] $SystemResult)

    if ($SystemResult.state -ne 'Completed' -or
        @($SystemResult.collectorResult.Observations).Count -ne 1 -or
        @($SystemResult.collectorResult.Provenance).Count -ne 1) {
        throw 'Only a completed SYSTEM collector result can form an Assessment Record.'
    }
    $envelope = $SystemResult.collectorResult.Envelope
    $observation = $SystemResult.collectorResult.Observations[0]
    $provenance = $SystemResult.collectorResult.Provenance[0]
    $coverageSource = $SystemResult.collectorResult.Coverage[0]
    $runId = "run:system:$([System.Guid]::NewGuid().ToString('N'))"
    $coverage = [pscustomobject][ordered]@{
        coverageId = [string] $coverageSource.coverageId
        scopeId = [string] $coverageSource.scopeId
        state = 'Complete'
        observationIds = @($coverageSource.observationIds)
        diagnosticIds = @()
    }
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.assessment-record'
        contractVersion = '1.0.0'
        requiredFeatures = @(
            'closed-scope-coverage'
            'evidence-references'
            'prohibited-material-omission'
        )
        run = [pscustomobject][ordered]@{
            runId = $runId
            outcome = 'Completed'
            validationFixture = [string] $envelope.executionContext -eq 'Synthetic'
        }
        subjects = @([pscustomobject][ordered]@{
            subjectId = [string] $envelope.subjectIds[0]
            kind = 'Device'
        })
        provenance = @($provenance)
        observations = @($observation)
        coverage = @($coverage)
        diagnostics = @()
        collectorResults = @($envelope)
        findings = @([pscustomobject][ordered]@{
            findingId = "finding:mdm-provider:$($runId.Substring(11))"
            ruleId = 'rule:mdm-provider-observed/1.0.0'
            targetSubjectId = [string] $observation.subjectId
            outcome = 'Informational'
            evidenceReferences = @([pscustomobject][ordered]@{
                observationId = [string] $observation.observationId
                fieldId = [string] $observation.fieldId
                subjectId = [string] $observation.subjectId
            })
        })
        recommendations = @()
        recommendationRelationships = @()
    }
}

function Get-SystemAssessmentRecordValidationReason {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    $embedded = Get-EmbeddedAssessmentContractSet `
        -ConvertFromJsonCommand $ConvertFromJsonCommand
    $json = & $ConvertToJsonCommand -InputObject $Record -Compress -Depth 30
    if (-not (& $TestJsonCommand -Json $json `
        -Schema $embedded.AssessmentRecordSchema -ErrorAction SilentlyContinue)) {
        return 'CONTRACT.SCHEMA_INVALID'
    }
    $definition = Get-SystemAssessmentContractDefinition -Policy $Policy `
        -ConvertFromJsonCommand $ConvertFromJsonCommand
    Get-AssessmentRecordSemanticReason -Record $Record -ContractDefinition $definition
}

function Test-SystemCollectionAdministrator {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { $false }
}

function Get-SystemCollectionFailureDisposition {
    param(
        [Parameter(Mandatory)] [string] $FailureStage,
        [Parameter(Mandatory)] [System.Exception] $Exception,
        [Parameter()] [bool] $WorkerExited = $false,
        [Parameter()] [bool] $WorkerLossExpected = $false
    )

    if ($FailureStage -eq 'ACTIVATION') {
        $denied = $Exception -is [System.UnauthorizedAccessException] -or
            ($Exception -is [System.Runtime.InteropServices.COMException] -and
                $Exception.HResult -eq -2147024891)
        return [pscustomobject][ordered]@{
            state = 'Unavailable'
            reasonCode = if ($denied) { 'SYSTEM.ACTIVATION_DENIED' } else { 'SYSTEM.ACTIVATION_FAILED' }
            coverageState = if ($denied) { 'Denied' } else { 'Unavailable' }
            runIntegrityCompromised = $false
        }
    }
    if ($FailureStage -eq 'RESULT_READ' -and ($WorkerLossExpected -or $WorkerExited)) {
        return [pscustomobject][ordered]@{
            state = 'Failed'
            reasonCode = 'SYSTEM.WORKER_LOST'
            coverageState = 'Failed'
            runIntegrityCompromised = $false
        }
    }
    # Once a complete frame exists, any JSON or closed-schema rejection means
    # the authenticated endpoint violated the protocol. Before authentication,
    # an unknown client/channel failure is equally unconfined. Both fail the
    # run's integrity instead of being laundered into an ordinary source gap.
    [pscustomobject][ordered]@{
        state = 'IntegrityFailed'
        reasonCode = 'SYSTEM.CHANNEL_INTEGRITY_FAILED'
        coverageState = 'Failed'
        runIntegrityCompromised = $true
    }
}

function Start-SystemCollectionTransientTask {
    param(
        [Parameter(Mandatory)] [string] $TaskName,
        [Parameter(Mandatory)] [string] $Executable,
        [Parameter(Mandatory)] [string] $EncodedWorker,
        [Parameter(Mandatory)] [string] $WorkingDirectory,
        [Parameter(Mandatory)] [string] $InitiatingSid
    )

    if ($TaskName -notmatch '^WINPCInfo-SystemCollection-v1-[0-9a-f]{32}$') {
        throw 'The transient SYSTEM task identity is outside the release-owned namespace.'
    }
    # Task Scheduler is used only as the Windows-owned LocalSystem token
    # broker. The task definition is built in memory from fixed release values:
    # one Microsoft-signed pwsh image and one digest-bound EncodedCommand. No
    # caller command, path, identity, password, trigger, or persistence setting
    # enters this definition. TASK_CREATE (not create-or-update) makes a random
    # name collision fail closed instead of replacing an unrelated task.
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\')
    $definition = $service.NewTask(0)
    $definition.RegistrationInfo.Description =
        'WIN-PCInfo run-owned LocalSystem evidence worker; deleted before terminal output.'
    $definition.Principal.UserId = 'SYSTEM'
    $definition.Principal.LogonType = 5 # TASK_LOGON_SERVICE_ACCOUNT
    $definition.Principal.RunLevel = 1 # TASK_RUNLEVEL_HIGHEST
    $definition.Settings.Enabled = $true
    $definition.Settings.Hidden = $true
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.StartWhenAvailable = $false
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.ExecutionTimeLimit = 'PT10S'
    $definition.Settings.MultipleInstances = 2 # TASK_INSTANCES_IGNORE_NEW
    $action = $definition.Actions.Create(0) # TASK_ACTION_EXEC
    $action.Path = $Executable
    $action.Arguments = "-NoLogo -NoProfile -NonInteractive -EncodedCommand $EncodedWorker"
    $action.WorkingDirectory = $WorkingDirectory
    $task = $null
    $runningTask = $null
    try {
        $task = $folder.RegisterTaskDefinition(
            $TaskName, $definition, 2, $null, $null, 5,
            "D:P(A;;GA;;;SY)(A;;GA;;;$InitiatingSid)"
        ) # TASK_CREATE, TASK_LOGON_SERVICE_ACCOUNT
        # Registration crosses into Task Scheduler's persistent store. Read the
        # accepted definition back before starting it and compare every action
        # and principal fact with the frozen values. The protected task DACL
        # excludes other administrator identities. The remaining trust
        # assumption is the already-approved initiating administrator context
        # and Windows Task Scheduler itself; a mismatch is deleted without run.
        $acceptedDefinition = $task.Definition
        $acceptedAction = $acceptedDefinition.Actions.Item(1)
        $expectedArguments = "-NoLogo -NoProfile -NonInteractive -EncodedCommand $EncodedWorker"
        if ($acceptedDefinition.Actions.Count -ne 1 -or
            $acceptedDefinition.Triggers.Count -ne 0 -or
            -not [string]::Equals(
                [System.IO.Path]::GetFullPath([string] $acceptedAction.Path),
                [System.IO.Path]::GetFullPath($Executable),
                [System.StringComparison]::OrdinalIgnoreCase
            ) -or [string] $acceptedAction.Arguments -ne $expectedArguments -or
            -not [string]::Equals(
                [System.IO.Path]::GetFullPath([string] $acceptedAction.WorkingDirectory),
                [System.IO.Path]::GetFullPath($WorkingDirectory),
                [System.StringComparison]::OrdinalIgnoreCase
            ) -or [string] $acceptedDefinition.Principal.UserId -notin @('SYSTEM', 'S-1-5-18') -or
            [int] $acceptedDefinition.Principal.LogonType -ne 5 -or
            [int] $acceptedDefinition.Principal.RunLevel -ne 1) {
            throw 'The accepted SYSTEM task definition does not match the frozen activation.'
        }
        $runningTask = $task.Run($null)
        [pscustomobject][ordered]@{
            Service = $service
            Folder = $folder
            RegisteredTask = $task
            RunningTask = $runningTask
            InstanceGuid = [string] $runningTask.InstanceGuid
        }
    }
    catch {
        # Registration and activation are not atomic. If Windows accepted the
        # task but could not start it, remove that exact random task before the
        # failure crosses the module interface. Failure to prove deletion is
        # raised to the caller, which reports cleanup uncertainty rather than a
        # harmless activation gap.
        if ($null -ne $task) {
            $partialActivation = [pscustomobject][ordered]@{
                Service = $service
                Folder = $folder
                RegisteredTask = $task
                RunningTask = $runningTask
                InstanceGuid = if ($null -ne $runningTask) {
                    [string] $runningTask.InstanceGuid
                }
                else { '' }
            }
            $cleanup = Remove-SystemCollectionTransientTask -Activation $partialActivation `
                -TaskName $TaskName -MaximumMilliseconds 3000
            if (-not $cleanup.Absent) {
                $_.Exception.Data['SystemTaskCleanupUnverified'] = $true
            }
        }
        throw
    }
}

function Get-SystemCollectionOwnedTaskInstances {
    param([Parameter(Mandatory)] $Activation)

    if ([string]::IsNullOrWhiteSpace([string] $Activation.InstanceGuid)) { return @() }
    try {
        $running = $Activation.Service.GetRunningTasks(0)
        @(
            for ($index = 1; $index -le [int] $running.Count; $index++) {
                $candidate = $running.Item($index)
                if ([string] $candidate.InstanceGuid -eq [string] $Activation.InstanceGuid) {
                    $candidate
                }
            }
        )
    }
    catch {
        # Failure to enumerate the scheduler-owned instance is uncertainty, not
        # absence. Return the originally owned instance so cleanup fails closed.
        @($Activation.RunningTask | Where-Object { $null -ne $_ })
    }
}

function Test-SystemCollectionProcessIdsAbsent {
    param([Parameter(Mandatory)] [System.Collections.Generic.HashSet[int]] $ProcessIds)

    foreach ($processId in $ProcessIds) {
        $process = $null
        try {
            $process = [System.Diagnostics.Process]::GetProcessById($processId)
            if (-not $process.HasExited) { return $false }
        }
        catch [System.ArgumentException] {}
        catch { return $false }
        finally { if ($null -ne $process) { $process.Dispose() } }
    }
    $true
}

function Remove-SystemCollectionTransientTask {
    param(
        [Parameter()] [AllowNull()] $Activation,
        [Parameter(Mandatory)] [string] $TaskName,
        [Parameter(Mandatory)] [int] $MaximumMilliseconds
    )

    if ($null -eq $Activation) {
        return [pscustomobject][ordered]@{
            Absent = $true; Retries = 0; InstanceAbsent = $true; EngineProcessAbsent = $true
        }
    }
    if ($TaskName -notmatch '^WINPCInfo-SystemCollection-v1-[0-9a-f]{32}$') {
        return [pscustomobject][ordered]@{
            Absent = $false; Retries = 0; InstanceAbsent = $false; EngineProcessAbsent = $false
        }
    }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $retries = 0
    $deleteAttempts = 0
    $ownedProcessIds = [System.Collections.Generic.HashSet[int]]::new()
    while ($watch.ElapsedMilliseconds -lt $MaximumMilliseconds) {
        $instances = @(Get-SystemCollectionOwnedTaskInstances -Activation $Activation)
        foreach ($instance in $instances) {
            try {
                $engineProcessId = [int] $instance.EnginePID
                if ($engineProcessId -gt 0) { $null = $ownedProcessIds.Add($engineProcessId) }
            }
            catch {}
            try { $instance.Stop() } catch {}
        }
        if ($null -ne $Activation.RunningTask) {
            try {
                $engineProcessId = [int] $Activation.RunningTask.EnginePID
                if ($engineProcessId -gt 0) { $null = $ownedProcessIds.Add($engineProcessId) }
            }
            catch {}
            try { $Activation.RunningTask.Stop(0) } catch {}
        }
        if ($deleteAttempts -lt 2) {
            try { $Activation.Folder.DeleteTask($TaskName, 0) } catch {}
            $deleteAttempts++
            $retries = [Math]::Max(0, $deleteAttempts - 1)
        }
        $registrationAbsent = $false
        try {
            $null = $Activation.Folder.GetTask($TaskName)
        }
        catch { $registrationAbsent = $true }
        $instanceAbsent = @(Get-SystemCollectionOwnedTaskInstances -Activation $Activation).Count -eq 0
        $engineProcessAbsent = Test-SystemCollectionProcessIdsAbsent -ProcessIds $ownedProcessIds
        if ($registrationAbsent -and $instanceAbsent -and $engineProcessAbsent) {
            return [pscustomobject][ordered]@{
                Absent = $true
                Retries = $retries
                InstanceAbsent = $true
                EngineProcessAbsent = $true
            }
        }
        [System.Threading.Thread]::Sleep(25)
    }
    [pscustomobject][ordered]@{
        Absent = $false
        Retries = $retries
        InstanceAbsent = $instanceAbsent
        EngineProcessAbsent = $engineProcessAbsent
    }
}

function Invoke-SystemCollectionSyntheticCleanupProbe {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [int] $MaximumMilliseconds
    )

    # Synthetic validation cannot register a real SYSTEM task. It can still
    # exercise an actual owned Windows artifact and the same bounded retry
    # rule. This named event is an IPC kernel object. The first cleanup attempt
    # deliberately leaves its handle open, proves the object remains, then the
    # sole retry disposes it and proves the exact name can no longer be opened.
    $createdNew = $false
    $ownedEvent = [System.Threading.EventWaitHandle]::new(
        $false, [System.Threading.EventResetMode]::ManualReset, $Name, [ref] $createdNew
    )
    if (-not $createdNew) {
        $ownedEvent.Dispose()
        return [pscustomobject][ordered]@{ Absent = $false; Retries = 0 }
    }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $retries = 0
    try {
        for ($attempt = 0; $attempt -le 1 -and
            $watch.ElapsedMilliseconds -lt $MaximumMilliseconds; $attempt++) {
            if ($attempt -eq 1) {
                $ownedEvent.Dispose()
                $ownedEvent = $null
            }
            $opened = $null
            $exists = [System.Threading.EventWaitHandle]::TryOpenExisting($Name, [ref] $opened)
            if ($null -ne $opened) { $opened.Dispose() }
            if (-not $exists) {
                return [pscustomobject][ordered]@{ Absent = $true; Retries = $retries }
            }
            if ($attempt -eq 0) {
                $retries++
                [System.Threading.Thread]::Sleep(25)
            }
        }
        [pscustomobject][ordered]@{ Absent = $false; Retries = $retries }
    }
    finally { if ($null -ne $ownedEvent) { $ownedEvent.Dispose() } }
}

function Invoke-SystemCollectionPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter()] [ValidateSet(
            '', 'SyntheticSuccess', 'UnknownOperation', 'InvalidParameters',
            'ActivationFailure', 'WorkerLost', 'Cancellation', 'Timeout',
            'Denied', 'AbnormalCleanup'
        )] [string] $ValidationScenario = '',
        [Parameter()] [System.Threading.CancellationToken] $CancellationToken =
            [System.Threading.CancellationToken]::None
    )

    $attemptStartedAt = [System.DateTimeOffset]::UtcNow
    $policy = Get-SystemCollectionPlanPolicy
    $scenario = Get-SystemCollectionValidationScenario -Name $ValidationScenario
    $resultContext = @{
        Policy = $policy
        Plan = $Plan
        PlanDigest = $PlanDigest
        StartedAt = $attemptStartedAt
        ObservedExecutionContext = if ($scenario.isFixture) { 'Synthetic' } else { 'NotStarted' }
    }
    $convertToJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $convertToJsonCommand -or
        (Get-ObjectDigest -Value $Plan -ConvertToJsonCommand $convertToJsonCommand) -ne $PlanDigest) {
        return New-SystemCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode 'SYSTEM.PLAN_INTEGRITY_INVALID' -CoverageState 'NotAttempted' `
            -Context $resultContext -RunIntegrityCompromised $true
    }
    $validationReason = Get-SystemCollectionPlanValidationReason -Plan $Plan -Policy $policy
    if ($validationReason) {
        return New-SystemCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode $validationReason -CoverageState 'NotAttempted' `
            -Context $resultContext -RunIntegrityCompromised $true
    }

    $validationFixture = [bool] $scenario.isFixture
    if ($scenario.activationFailure) {
        return New-SystemCollectionStoppedResult -State 'Unavailable' `
            -ReasonCode 'SYSTEM.ACTIVATION_FAILED' -CoverageState 'Unavailable' `
            -Context $resultContext
    }
    if ($scenario.activationDenied) {
        return New-SystemCollectionStoppedResult -State 'Unavailable' `
            -ReasonCode 'SYSTEM.ACTIVATION_DENIED' -CoverageState 'Denied' `
            -Context $resultContext
    }
    if (-not $validationFixture -and -not (Test-SystemCollectionAdministrator)) {
        return New-SystemCollectionStoppedResult -State 'Unavailable' `
            -ReasonCode 'SYSTEM.ACTIVATION_DENIED' -CoverageState 'Denied' `
            -Context $resultContext
    }

    Initialize-PrivilegedCollectionPlanNativeType
    $workerSource = (Get-SystemCollectionWorkerSource).Replace("`r`n", "`n").Replace("`r", "`n")
    $workerDigest = Get-SystemCollectionSha256 -Bytes (
        [System.Text.UTF8Encoding]::new($false).GetBytes($workerSource)
    )
    if ($workerDigest -ne [string] $policy.activation.payloadSha256) {
        return New-SystemCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode 'SYSTEM.WORKER_INTEGRITY_INVALID' -CoverageState 'NotAttempted' `
            -Context $resultContext -RunIntegrityCompromised $true
    }

    $approvedExecutable = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($PSHOME, [string] $policy.activation.executableFileName)
    )
    $activeExecutable = [System.IO.Path]::GetFullPath(
        [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    )
    if (-not $approvedExecutable.Equals($activeExecutable, [System.StringComparison]::OrdinalIgnoreCase)) {
        return New-SystemCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode 'SYSTEM.EXECUTABLE_IDENTITY_INVALID' -CoverageState 'NotAttempted' `
            -Context $resultContext -RunIntegrityCompromised $true
    }
    $authenticodeCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'Get-AuthenticodeSignature', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    $signature = & $authenticodeCommand -LiteralPath $approvedExecutable -ErrorAction Stop
    if ([string] $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false
        ) -ne [string] $policy.activation.signerCommonName) {
        return New-SystemCollectionStoppedResult -State 'IntegrityFailed' `
            -ReasonCode 'SYSTEM.EXECUTABLE_IDENTITY_INVALID' -CoverageState 'NotAttempted' `
            -Context $resultContext -RunIntegrityCompromised $true
    }

    $executableDigest = Get-SystemCollectionSha256 -Bytes ([System.IO.File]::ReadAllBytes($approvedExecutable))
    $nonceBytes = [byte[]]::new([int] $policy.channel.nonceBytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
    $nonce = [System.Convert]::ToHexString($nonceBytes).ToLowerInvariant()
    $pipeName = "$($policy.channel.pipeNamePrefix)$($nonce.Substring(0, 32))"
    $jobName = "$($policy.channel.jobNamePrefix)$($nonce.Substring(0, 32))"
    $taskName = "$($policy.activation.taskNamePrefix)$($nonce.Substring(0, 32))"
    $initiatingSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $pipeSecurity = [System.IO.Pipes.PipeSecurity]::new()
    $pipeSecurity.SetSecurityDescriptorSddlForm("D:P(A;;GA;;;$initiatingSid)(A;;GA;;;SY)")

    $ownedJob = $null
    $server = $null
    $worker = $null
    $taskActivation = $null
    $deadline = [System.Threading.CancellationTokenSource]::CreateLinkedTokenSource($CancellationToken)
    $deadline.CancelAfter($(if ($null -ne $scenario.operationDeadlineMilliseconds) {
        [int] $scenario.operationDeadlineMilliseconds
    }
    else { [int] $policy.deadlines.operationMaximumMilliseconds }))
    $cleanupVerified = $false
    $pipeAbsent = $false
    $workerTreeAbsent = $false
    $taskAbsent = $validationFixture
    $cleanupRetries = 0
    $syntheticCleanupAbsent = $true
    $providerAvailable = $null
    $attemptCompletedAt = $null
    $observationCollectedAt = $null
    $state = 'IntegrityFailed'
    $reasonCode = 'SYSTEM.CHANNEL_FAILED'
    $coverageState = 'Failed'
    $runIntegrityCompromised = $false
    $activationCleanupUnverified = $false
    $failureStage = 'SETUP'
    $peerVerified = $false
    try {
        $ownedJob = [WinPCInfo.PrivilegedCollectionPlan.OwnedJob]::Create(
            $jobName, "D:P(A;;GA;;;$initiatingSid)(A;;GA;;;SY)"
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
        $configuration = [pscustomobject][ordered]@{
            pipe = $pipeName
            nonce = $nonce
            jobName = $jobName
            maximumBytes = [int] $policy.channel.maximumMessageUtf8Bytes
            deadlineMilliseconds = $(if ($null -ne $scenario.workerDeadlineMilliseconds) {
                [int] $scenario.workerDeadlineMilliseconds
            }
            else { [int] $policy.deadlines.operationMaximumMilliseconds })
            coordinatorProcessId = $PID
            executableSha256 = $executableDigest
            workerPayloadSha256 = $workerDigest
            planDigest = $PlanDigest
            validationFixture = $validationFixture
            workerFault = [string] $scenario.workerFault
        }
        $configurationBase64 = [System.Convert]::ToBase64String(
            [System.Text.UTF8Encoding]::new($false).GetBytes(
                ($configuration | ConvertTo-Json -Compress -Depth 5)
            )
        )
        $launchSource = $workerSource.Replace('__SYSTEM_WORKER_CONFIGURATION__', $configurationBase64)
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $approvedExecutable
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.WorkingDirectory = $PSHOME
        foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
            (ConvertTo-PrivilegedCollectionEncodedCommand -Source $launchSource)
        )) { $null = $startInfo.ArgumentList.Add($argument) }
        $startInfo.Environment.Clear()
        $startInfo.Environment['SystemRoot'] = [System.Environment]::GetFolderPath('Windows')
        $failureStage = 'ACTIVATION'
        if ($validationFixture) {
            $worker = [System.Diagnostics.Process]::Start($startInfo)
        }
        else {
            $taskActivation = Start-SystemCollectionTransientTask -TaskName $taskName `
                -Executable $approvedExecutable `
                -EncodedWorker $startInfo.ArgumentList[4] -WorkingDirectory $PSHOME `
                -InitiatingSid $initiatingSid
        }

        $null = $server.WaitForConnectionAsync($deadline.Token).GetAwaiter().GetResult()
        $failureStage = 'PEER_IDENTITY'
        $clientProcessId = [WinPCInfo.PrivilegedCollectionPlan.PipePeer]::GetClientProcessId($server)
        if ($validationFixture) {
            if ($clientProcessId -ne $worker.Id) { throw 'The connected SYSTEM worker is not owned.' }
        }
        else {
            $worker = [System.Diagnostics.Process]::GetProcessById($clientProcessId)
            if ([int] $taskActivation.RunningTask.EnginePID -ne $clientProcessId) {
                throw 'The connected SYSTEM worker is not the run-owned scheduled task process.'
            }
        }
        $hello = (Read-BoundedCollectionChannelFrame -Stream $server `
            -MaximumBytes ([int] $policy.channel.maximumMessageUtf8Bytes) `
            -CancellationToken $deadline.Token) | ConvertFrom-Json -Depth 10
        $helloNames = @($hello.PSObject.Properties.Name)
        if ($helloNames.Count -ne 10 -or @($helloNames | Sort-Object -Unique).Count -ne 10 -or
            $hello.kind -ne 'SystemWorkerHello' -or $hello.contractVersion -ne '1.0.0' -or
            $hello.nonce -ne $nonce -or [int] $hello.workerProcessId -ne $clientProcessId -or
            [int] $hello.coordinatorProcessId -ne $PID -or
            $hello.workerPayloadSha256 -ne $workerDigest -or
            $hello.executableSha256 -ne $executableDigest -or
            $hello.executionContext -ne $(if ($validationFixture) { 'Synthetic' } else { 'LocalSystem' }) -or
            [bool] $hello.localSystemSidVerified -ne (-not $validationFixture) -or
            $hello.treeControl -ne 'CoordinatorOwnedJobObject') {
            throw 'The SYSTEM worker hello failed identity validation.'
        }
        $peerVerified = $true
        if (-not $validationFixture) {
            # LocalSystem provenance becomes true only after the authenticated
            # worker has proved SID S-1-5-18, its process identity, payload
            # digest, executable digest, nonce, and Job membership. Merely
            # asking Task Scheduler to start SYSTEM is not evidence that it did.
            $resultContext.ObservedExecutionContext = 'LocalSystem'
        }

        $failureStage = 'EXECUTION'
        $request = [pscustomobject][ordered]@{
            kind = 'ExecuteSystemPlan'
            contractVersion = '1.0.0'
            nonce = $nonce
            planDigest = $PlanDigest
            phaseId = [string] $Plan.phaseId
            operations = @($Plan.operations)
        }
        Write-BoundedCollectionChannelFrame -Stream $server `
            -Json ($request | ConvertTo-Json -Compress -Depth 10) `
            -MaximumBytes ([int] $policy.channel.maximumMessageUtf8Bytes) `
            -CancellationToken $deadline.Token
        $failureStage = 'RESULT_READ'
        $resultJson = Read-BoundedCollectionChannelFrame -Stream $server `
            -MaximumBytes ([int] $policy.channel.maximumMessageUtf8Bytes) `
            -CancellationToken $deadline.Token
        # A complete frame from the authenticated worker is now untrusted input
        # to the closed result parser. Malformed JSON or an unexpected field is
        # protocol corruption, not ordinary worker loss, and therefore closes
        # the run's integrity boundary.
        $failureStage = 'RESULT_PROTOCOL'
        $result = $resultJson | ConvertFrom-Json -Depth 10
        $resultNames = @($result.PSObject.Properties.Name)
        $resultOperation = @($result.operations)[0]
        if ($resultNames.Count -ne 7 -or @($resultNames | Sort-Object -Unique).Count -ne 7 -or
            $result.kind -ne 'SystemPlanResult' -or $result.contractVersion -ne '1.0.0' -or
            $result.nonce -ne $nonce -or $result.planDigest -ne $PlanDigest -or
            $result.phaseId -ne $Plan.phaseId -or
            $result.executionContext -ne $(if ($validationFixture) { 'Synthetic' } else { 'LocalSystem' }) -or
            @($result.operations).Count -ne 1 -or
            @($resultOperation.PSObject.Properties.Name).Count -ne 3 -or
            $resultOperation.operationId -ne $policy.operations[0].operationId -or
            $resultOperation.state -ne 'Completed' -or $resultOperation.providerAvailable -isnot [bool]) {
            throw 'The SYSTEM result failed its closed schema.'
        }
        $providerAvailable = [bool] $resultOperation.providerAvailable
        $observationCollectedAt = [System.DateTimeOffset]::UtcNow
        $attemptCompletedAt = $observationCollectedAt
        $state = 'Completed'
        $reasonCode = 'SYSTEM.COMPLETED'
        $coverageState = 'Complete'
    }
    catch [System.OperationCanceledException] {
        $attemptCompletedAt = [System.DateTimeOffset]::UtcNow
        if ($CancellationToken.IsCancellationRequested) {
            $state = 'Cancelled'
            $reasonCode = 'SYSTEM.CANCELLED'
            $coverageState = 'Cancelled'
        }
        else {
            $state = 'TimedOut'
            $reasonCode = 'SYSTEM.DEADLINE_EXCEEDED'
            $coverageState = 'TimedOut'
        }
    }
    catch {
        $attemptCompletedAt = [System.DateTimeOffset]::UtcNow
        $workerExited = $false
        if ($failureStage -eq 'RESULT_READ' -and $null -ne $worker) {
            try { $workerExited = $worker.HasExited -or $worker.WaitForExit(100) } catch {}
        }
        $disposition = Get-SystemCollectionFailureDisposition `
            -FailureStage $failureStage -Exception $_.Exception -WorkerExited $workerExited `
            -WorkerLossExpected ([bool] $scenario.workerLossExpected)
        $state = [string] $disposition.state
        $reasonCode = [string] $disposition.reasonCode
        $coverageState = [string] $disposition.coverageState
        $runIntegrityCompromised = [bool] $disposition.runIntegrityCompromised
        if ($failureStage -eq 'ACTIVATION') {
            $activationCleanupUnverified =
                $_.Exception.Data.Contains('SystemTaskCleanupUnverified')
        }
    }
    finally {
        if ($null -ne $server) { $server.Dispose(); $pipeAbsent = $true }
        $workerTreeAbsent = Wait-PrivilegedCollectionOwnedTreeAbsent -OwnedJob $ownedJob `
            -WorkerRoot $worker -MaximumMilliseconds ([int] $policy.deadlines.cancellationGraceMilliseconds)
        if (-not $workerTreeAbsent -and $null -ne $ownedJob) {
            $terminationIssued = $ownedJob.Terminate()
            # TerminateJobObject and KILL_ON_JOB_CLOSE initiate whole-tree
            # termination, but process signaling is asynchronous under load.
            # Close the Job now, retain the root handle, and spend the one
            # release-owned verification bound proving that exact process has
            # signaled. A pre-Job Task Scheduler engine is independently proved
            # absent below from its captured EnginePID.
            $ownedJob.Dispose()
            $ownedJob = $null
            $workerTreeAbsent = $terminationIssued -and (
                Wait-PrivilegedCollectionOwnedTreeAbsent -OwnedJob $null `
                    -WorkerRoot $worker `
                    -MaximumMilliseconds ([int] $policy.deadlines.terminationVerificationMilliseconds)
            )
        }
        if ($null -ne $worker) { $worker.Dispose() }
        if ($null -ne $ownedJob) { $ownedJob.Dispose() }
        $taskCleanup = Remove-SystemCollectionTransientTask -Activation $taskActivation `
            -TaskName $taskName `
            -MaximumMilliseconds ([int] $policy.deadlines.cleanupMaximumMilliseconds)
        $taskAbsent = [bool] $taskCleanup.Absent -and -not $activationCleanupUnverified
        $cleanupRetries = [int] $taskCleanup.Retries
        if ($scenario.injectCleanupFailure -and $validationFixture) {
            $cleanupProbe = Invoke-SystemCollectionSyntheticCleanupProbe `
                -Name "Local\WINPCInfo-SystemCollection-Cleanup-v1-$($nonce.Substring(0, 32))" `
                -MaximumMilliseconds ([int] $policy.deadlines.cleanupMaximumMilliseconds
                )
            $syntheticCleanupAbsent = [bool] $cleanupProbe.Absent
            $cleanupRetries += [int] $cleanupProbe.Retries
        }
        $deadline.Dispose()
        $cleanupVerified = $workerTreeAbsent -and $pipeAbsent -and $taskAbsent -and
            $syntheticCleanupAbsent
    }

    if (-not $cleanupVerified) {
        $state = 'CleanupIncomplete'
        $reasonCode = 'SYSTEM.CLEANUP_INCOMPLETE'
        $coverageState = 'Failed'
        $runIntegrityCompromised = $true
        $providerAvailable = $null
    }
    New-SystemCollectorResult -Policy $policy -Plan $Plan -PlanDigest $PlanDigest `
        -State $state -ReasonCode $reasonCode -CoverageState $coverageState `
        -ObservedExecutionContext $resultContext.ObservedExecutionContext `
        -LocalSystemIdentityVerified ($resultContext.ObservedExecutionContext -eq 'LocalSystem') `
        -CleanupVerified $cleanupVerified -TaskAbsent $taskAbsent -PipeAbsent $pipeAbsent `
        -WorkerTreeAbsent $workerTreeAbsent -ProviderAvailable $providerAvailable `
        -CleanupRetries $cleanupRetries -RunIntegrityCompromised $runIntegrityCompromised `
        -StartedAt $attemptStartedAt -CompletedAt $attemptCompletedAt `
        -CollectedAt $observationCollectedAt
}

function Read-SystemCollectionPlanFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    try {
        $resolved = [System.IO.Path]::GetFullPath($LiteralPath)
        $file = [System.IO.FileInfo]::new($resolved)
        if (-not $file.Exists -or $file.Length -gt 1024) {
            throw 'The SYSTEM fixture is unavailable or oversize.'
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
                throw 'The SYSTEM fixture is not lexically closed.'
            }
        }
        finally { $document.Dispose() }
        $fixture = & $ConvertFromJsonCommand -InputObject $json -ErrorAction Stop
        $properties = @($fixture.PSObject.Properties.Name | Sort-Object)
        if ($fixture.contractVersion -ne '1.0.0' -or $properties.Count -ne 2 -or
            $properties[0] -ne 'contractVersion' -or $properties[1] -ne 'scenario' -or
            $fixture.scenario -notin @((Get-SystemCollectionPlanPolicy).validationScenarios)) {
            throw 'The SYSTEM fixture is outside the release scenario set.'
        }
        $fixture
    }
    catch {
        $exception = [System.InvalidOperationException]::new(
            'The synthetic SYSTEM fixture is invalid.'
        )
        $exception.Data['ReasonCode'] = 'SYSTEM.FIXTURE_INVALID'
        throw $exception
    }
}

function Invoke-SystemCollectionPlanFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $PreparationPlan,
        [Parameter(Mandatory)] [string] $PreparationPlanDigest,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    try {
        $fixture = Read-SystemCollectionPlanFixture -LiteralPath $LiteralPath `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
        $planResult = New-SystemCollectionPlan -PreparationPlan $PreparationPlan `
            -PreparationPlanDigest $PreparationPlanDigest
    }
    catch {
        Write-ContractRecord ([pscustomobject][ordered]@{
            recordType = 'win-pcinfo.terminal'
            contractVersion = '1.0.0'
            outcome = 'NotStarted'
            exitCode = 20
            reasonCode = 'SYSTEM.FIXTURE_INVALID'
            phase = 'SystemCollection'
            collectionStarted = $false
            validationFixture = $true
            coverage = @()
            cleanup = [pscustomobject][ordered]@{ required = $false; verified = $true }
        }) -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $scenario = [string] $fixture.scenario
    $scenarioPolicy = Get-SystemCollectionValidationScenario -Name $scenario
    $systemPlan = $planResult.Plan
    $systemPlanDigest = $planResult.Digest
    if ($scenarioPolicy.planMutation -eq 'UnknownOperation') {
        $systemPlan = $systemPlan | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
        $systemPlan.operations[0].operationId = 'op:validation.unknown-system-operation'
        $systemPlanDigest = Get-ObjectDigest -Value $systemPlan `
            -ConvertToJsonCommand $ConvertToJsonCommand
    }
    elseif ($scenarioPolicy.planMutation -eq 'InvalidParameters') {
        $systemPlan = $systemPlan | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
        $systemPlan.operations[0].parameters | Add-Member -NotePropertyName command `
            -NotePropertyValue 'synthetic-prohibited-marker'
        $systemPlanDigest = Get-ObjectDigest -Value $systemPlan `
            -ConvertToJsonCommand $ConvertToJsonCommand
    }

    $fixtureCancellation = if ($null -ne $scenarioPolicy.cancellationDelayMilliseconds) {
        [System.Threading.CancellationTokenSource]::new()
    }
    else { $null }
    try {
        if ($null -ne $fixtureCancellation) {
            $fixtureCancellation.CancelAfter([int] $scenarioPolicy.cancellationDelayMilliseconds)
        }
        $systemResult = Invoke-SystemCollectionPlan -Plan $systemPlan `
            -PlanDigest $systemPlanDigest -ValidationScenario $scenario `
            -CancellationToken $(if ($null -ne $fixtureCancellation) {
                $fixtureCancellation.Token
            }
            else { [System.Threading.CancellationToken]::None })
    }
    finally {
        if ($null -ne $fixtureCancellation) { $fixtureCancellation.Dispose() }
    }
    $assessmentRecord = $null
    if ($systemResult.state -eq 'Completed') {
        $testJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
            'Test-Json', [System.Management.Automation.CommandTypes]::Cmdlet
        )
        if ($null -eq $testJsonCommand -or
            $testJsonCommand.ModuleName -ne 'Microsoft.PowerShell.Utility') {
            throw 'The Assessment Record schema command does not have built-in provenance.'
        }
        $assessmentRecord = New-SystemAssessmentRecord -SystemResult $systemResult
        $assessmentReason = Get-SystemAssessmentRecordValidationReason `
            -Record $assessmentRecord -Policy (Get-SystemCollectionPlanPolicy) `
            -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand -TestJsonCommand $testJsonCommand
        if ($assessmentReason) {
            throw "The SYSTEM Assessment Record failed validation: $assessmentReason"
        }
    }
    Write-ContractRecord $systemResult -ConvertToJsonCommand $ConvertToJsonCommand
    if ($null -ne $assessmentRecord) {
        Write-ContractRecord $assessmentRecord -ConvertToJsonCommand $ConvertToJsonCommand
    }

    # A source-scoped SYSTEM failure does not gain authority over the rest of
    # the Assessment Run. Safe standard-user work continues after activation
    # failure, denial, verified worker loss, or a bounded timeout. Only operator
    # cancellation, plan/channel integrity loss, or unverifiable cleanup closes
    # scheduling. Packaging is still unavailable in this tracer bullet, so the
    # terminal result never converts synthetic evidence into Completed.
    $standardResult = if ([bool] $systemResult.standardUserWorkMayContinue) {
        Invoke-ApprovedCollectorProcess -OperationId 'op:synthetic.windows.os.success'
    }
    else { $null }
    $cleanupVerified = [bool] $systemResult.cleanup.verified -and (
        $null -eq $standardResult -or (
            [bool] $standardResult.Supervision.completeOwnedTreeAbsent -and
            [bool] $standardResult.Supervision.temporaryArtifactsAbsent
        )
    )
    $outcome = if (-not $cleanupVerified) {
        'CleanupIncomplete'
    }
    elseif ($systemResult.state -eq 'Cancelled') {
        'Cancelled'
    }
    else { 'IntegrityFailed' }
    $reasonCode = if (-not $cleanupVerified) {
        'RUN.CLEANUP_INCOMPLETE'
    }
    elseif ($outcome -eq 'Cancelled') {
        'RUN.CANCELLED'
    }
    elseif ([bool] $systemResult.runIntegrityCompromised) {
        [string] $systemResult.reasonCode
    }
    else { 'RUN.PACKAGE_INTEGRITY_FAILED' }

    $terminal = [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.terminal'
        contractVersion = '1.0.0'
        outcome = $outcome
        exitCode = Get-AssessmentRunExitCode -Outcome $outcome
        reasonCode = $reasonCode
        phase = 'Terminal'
        collectionStarted = @($systemResult.collectorResult.Observations).Count -gt 0 -or
            $systemResult.state -in @('Failed', 'TimedOut', 'Cancelled') -or $null -ne $standardResult
        validationFixture = $true
        planDigest = $PreparationPlanDigest
        system = [pscustomobject][ordered]@{
            state = $systemResult.state
            reasonCode = $systemResult.reasonCode
            localSystemIdentityVerified = $systemResult.activation.localSystemIdentityVerified
        }
        coverage = @($systemResult.collectorResult.Coverage) + $(if ($null -ne $standardResult) {
            @($standardResult.Coverage)
        }
        else { @() })
        collectorResults = @($systemResult.collectorResult.Envelope) + $(if ($null -ne $standardResult) {
            @($standardResult.Envelope)
        }
        else { @() })
        package = [pscustomobject][ordered]@{
            state = 'IntegrityFailed'
            verified = $false
            protection = 'None'
            recoverable = $false
        }
        cleanup = [pscustomobject][ordered]@{
            required = $true
            verified = $cleanupVerified
            taskAbsent = [bool] $systemResult.cleanup.taskAbsent
            workerTreeAbsent = [bool] $systemResult.cleanup.workerTreeAbsent
            pipeAbsent = [bool] $systemResult.cleanup.pipeAbsent
        }
        scheduling = [pscustomobject][ordered]@{
            systemOperationCount = @($systemResult.collectorResult.Envelope).Count
            standardOperationStarted = $null -ne $standardResult
            schedulingClosed = $true
        }
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $ConvertToJsonCommand
    [int] $terminal.exitCode
}
