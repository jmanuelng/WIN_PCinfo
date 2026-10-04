[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$tokens=$null;$errors=$null
$applicationAst=[Management.Automation.Language.Parser]::ParseFile($candidate,[ref]$tokens,[ref]$errors)
Assert-Equal 0 $errors.Count 'the generated initializer must parse as part of the delivered application'
$initializers=@($applicationAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Initialize-WinPCInfoDefinitions'
})
Assert-Equal 1 $initializers.Count 'the running candidate must own exactly one top-level parsed initializer'
$initializer=$initializers[0].Body.GetScriptBlock()
$regions=[regex]::Matches($initializer.Ast.Extent.Text,
    '(?ms)^#region Generated from src/([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
Assert-Equal 39 $regions.Count 'all original definition regions remain inside the parsed initializer'
Assert-Equal 0 @($regions | Where-Object {$_.Groups[1].Value -in @('ApplicationHeader.ps1','ApplicationMain.ps1')}).Count 'entry parameters and application execution remain outside initialization'
$expectedFunctions=@($initializer.Ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})
Assert-Equal 700 $expectedFunctions.Count 'the complete original definition inventory is retained'
$initializationOutput=@(. $initializer)
Assert-Equal 0 $initializationOutput.Count 'initialization emits no records and authorizes no collection'

# Parameter conflicts must fail before either entry point can allocate a worker
# or create a UI. The real advanced-function binder rejects the conflicting sets.
foreach($entry in @('Start-StatusDeskSession','Invoke-StatusDesk')) {
    $conflict=$null
    try { & $entry -ModuleText 'throw "Must not initialize"' -DefinitionInitializer $initializer -LaunchParameters @{} }
    catch {$conflict=$_}
    Assert-Equal 'AmbiguousParameterSet' $conflict.Exception.ErrorRecord.FullyQualifiedErrorId.Split(',')[0] 'text and parsed definitions cannot be admitted together'
}

# A malformed compatibility payload must fail parsing before creating either
# transport or UI resources. Inert sentinels make accidental allocation visible.
$originalTransport=${function:New-StatusDeskTransport}
$originalWindow=${function:New-StatusDeskWindow}
try {
    function New-StatusDeskTransport {throw 'Unexpected transport allocation'}
    function New-StatusDeskWindow {throw 'Unexpected window allocation'}
    foreach($entry in @('Start-StatusDeskSession','Invoke-StatusDesk')) {
        $parseFailure=$null
        try { & $entry -ModuleText 'function Broken {' -LaunchParameters @{} }
        catch {$parseFailure=$_}
        Assert-Equal $true ($null -ne $parseFailure -and $parseFailure.Exception.InnerException -is [Management.Automation.ParseException]) 'malformed text fails before allocating controller resources'
    }
} finally {
    Set-Item -LiteralPath Function:New-StatusDeskTransport -Value $originalTransport
    Set-Item -LiteralPath Function:New-StatusDeskWindow -Value $originalWindow
}

$request=Get-AutomationRequest -LiteralPath (Join-Path $PSScriptRoot 'fixtures/automation-request.json') `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$context=@{IsFixture=$true}
foreach($name in @('Preparation','Contract','Run','PrivilegedCollection','SystemCollection',
    'EvidenceWorkspace','ProtectedPackage','RecipientSharing','DeviceReadiness','IdentityEnrollment',
    'AdministratorExposure','EffectivePolicy','ResourceDependencies','NetworkTopology',
    'SoftwareInventory','CertificateTrust','MicrosoftConnectivity')) {$context[$name+'FixturePath']=''}
$context.PreparationFixturePath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
$launch=@{Request=$request;RuntimeFacts=(Get-ActiveRuntimeFacts -ModuleFacts (Get-BuiltInModuleCompatibilityFacts));
    ArtifactTrustValid=$false;ValidationContext=[pscustomobject]$context}
$script:ProtectedPackageJsonCommands=[pscustomobject]@{FixtureSentinel='RootOnly'}
foreach($iteration in @(1,2)) {
    $session=$null;$bodyError=$null
    try {
        $session=Start-StatusDeskSession -DefinitionInitializer $initializer -LaunchParameters $launch
        $watch=[Diagnostics.Stopwatch]::StartNew()
        while(-not $session.Transport.State.Preparation -and -not $session.Pending.IsCompleted -and $watch.ElapsedMilliseconds -lt 30000) {Start-Sleep -Milliseconds 20}
        Assert-Equal $true ([bool]$session.Transport.State.Preparation) 'a fresh parsed-definition worker reaches frozen preparation'
        Assert-Equal $false $session.Transport.State.CollectionStarted 'worker initialization cannot imply assessment consent'
        $summary=$session.Transport.State.Preparation | ConvertFrom-Json
        Set-StatusDeskDecision -Session $session -Approve $false -PlanDigest $summary.planDigest
        while(-not (Complete-StatusDeskSession $session) -and $watch.ElapsedMilliseconds -lt 45000) {Start-Sleep -Milliseconds 20}
        Assert-Equal $true $session.Completed 'the actual parsed-definition worker completes'
        Assert-Equal 'PREPARATION.DECLINED' ($session.Transport.State.Terminal | ConvertFrom-Json).reasonCode 'decline remains an explicit preparation decision'
        Assert-Equal $false ($session.Transport.State.Terminal | ConvertFrom-Json).collectionStarted 'decline admits no collection'
        Assert-Equal 'RootOnly' (Get-ProtectedPackageJsonCommands).FixtureSentinel 'fresh worker binding cannot mutate the root module cache'
        Assert-Equal $true ($null -eq $session.Worker -and $null -eq $session.Runspace -and $null -eq $session.Pending) 'both owned handles and the definition graph are released'
    } catch {$bodyError=$_}
    finally {
        Complete-QualificationHarness -BodyError $bodyError -Cleanup @(
            {if($null -ne $session -and -not $session.Completed){Set-StatusDeskDecision -Session $session -Approve $false -PlanDigest 'test-decline';$deadline=[Diagnostics.Stopwatch]::StartNew();while(-not (Complete-StatusDeskSession $session) -and $deadline.ElapsedMilliseconds -lt 45000){Start-Sleep -Milliseconds 20};if(-not $session.Completed){throw 'Owned parsed worker completion remains unverified'}}},
            {if($null -ne $session){if(-not $session.Completed){throw 'Preserve unfinished owned worker handles'};$session.Transport.Cancellation.Dispose()}},
            {if($null -ne $session){if(-not $session.Completed){throw 'Preserve unfinished owned worker handles'};$session.Transport.DecisionReady.Dispose()}},
            {if($null -ne $session){if(-not $session.Completed){throw 'Preserve unfinished owned worker handles'};$session.Transport.Events.Dispose()}}
        )
    }
}
Remove-Variable -Name ProtectedPackageJsonCommands -Scope Script
Write-Output 'PASS: generated original initializer and fresh parsed workers retain complete definitions, explicit decline and independent state.'
