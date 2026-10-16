[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

# This pure contract executes the actual UI callbacks with fake controls and a
# recording setup provider. It creates no window, key, trust change, assessment,
# native child or recipient profile; WPF wiring and real setup remain separate.
$sourcePath=Join-Path (Split-Path $PSScriptRoot) 'src/StatusDesk.ps1'
$parseErrors=$null
$sourceAst=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$null,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'Status desk source must parse before handler controls.' }
$checks=0

function Assert-SetupContract {
    param([bool] $Condition,[string] $Message)
    if (-not $Condition) { throw ('Setup handler contract: '+$Message) }
    $script:checks++
}

function Get-ActualSetupHandler {
    param([string] $FunctionName,[string] $Receiver)
    $definitions=@($sourceAst.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $FunctionName
    },$true))
    Assert-SetupContract ($definitions.Count -eq 1) ('unique source function '+$FunctionName)
    $calls=@($definitions[0].Body.FindAll({param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and
        $node.Expression.Extent.Text -ceq $Receiver -and $node.Member.Value -ceq 'Add_Click'
    },$true))
    Assert-SetupContract ($calls.Count -eq 1) ('unique actual click handler '+$Receiver)
    Assert-SetupContract ($calls[0].Arguments.Count -eq 1 -and
        $calls[0].Arguments[0] -is [Management.Automation.Language.ScriptBlockExpressionAst]) 'callback is an explicit script block'
    $calls[0].Arguments[0].ScriptBlock.GetScriptBlock()
}

$confirmHandler=Get-ActualSetupHandler 'Show-StatusDeskRecipientDialog' '$fields.ConfirmRecipient'
$cancelHandler=Get-ActualSetupHandler 'Show-StatusDeskRecipientDialog' '$fields.CancelRecipient'
$setupHandler=Get-ActualSetupHandler 'Invoke-StatusDesk' '$controls.SetupRecipient'
$cleanupDefinitions=@($sourceAst.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Stop-StatusDeskForCleanupFailure'
},$true))
Assert-SetupContract ($cleanupDefinitions.Count -eq 1) 'unique actual cleanup blocking function'
. ([scriptblock]::Create($cleanupDefinitions[0].Extent.Text))

function New-SetupHandlerFixture {
    param([string] $State='Created',[string] $Label='Synthetic recipient',[string] $Destination='synthetic-public-profile.json',
        [switch] $Cancel,[switch] $Unsafe,[switch] $Disabled,[switch] $Decided,[switch] $Completed)
    $fields=@{
        ProfilePath=[pscustomobject]@{Text=$Destination}
        Fingerprint=[pscustomobject]@{Text=$Label}
        RecipientStatus=[pscustomobject]@{Text=''}
        ConfirmRecipient=[pscustomobject]@{IsEnabled=$true}
    }
    $controls=@{}
    foreach ($name in @('Approve','Decline','Cancel','SelectRecipient','SetupRecipient','OpenExisting','OpenReport','SaveHtml','ChangeChoices','Retry')) {
        $controls[$name]=[pscustomobject]@{IsEnabled=$true}
    }
    $controls.SetupRecipient.IsEnabled=-not $Disabled
    $controls.Status=[pscustomobject]@{Text=''}
    $controls.Details=[pscustomobject]@{Text=''}
    $dialog=[pscustomobject]@{CloseCount=0}
    $dialog | Add-Member -MemberType ScriptMethod -Name Close -Value {$this.CloseCount++}
    [pscustomobject]@{
        Fields=$fields;Controls=$controls;Dialog=$dialog;Cancel=[bool]$Cancel
        Result=@{Value=$null};State=@{ViewingCleanupFailed=[bool]$Unsafe}
        Session=[pscustomobject]@{Completed=[bool]$Completed;ExitCode=0;Transport=[pscustomobject]@{DecisionReady=[pscustomobject]@{IsSet=[bool]$Decided}}}
        Response=[pscustomobject]@{state=$State;reasonCode='SyntheticSetupResult';protectionLevel='SyntheticProtection';fingerprint=('1'*64)}
        ProviderCalls=[Collections.Generic.List[object]]::new()
        DialogCalls=[Collections.Generic.List[object]]::new()
        Decisions=[Collections.Generic.List[object]]::new();CancellationCalls=0
    }
}

function Invoke-SetupHandlerFixture {
    param($Fixture,[scriptblock] $Confirm=$confirmHandler,[scriptblock] $Cancel=$cancelHandler,[scriptblock] $Setup=$setupHandler)
    $fields=$Fixture.Fields
    $result=$Fixture.Result
    $dialog=$Fixture.Dialog
    $controls=$Fixture.Controls
    $state=$Fixture.State
    $session=$Fixture.Session
    $window=[pscustomobject]@{FixtureOwner=$true}
    function New-RecipientProfileSetup {
        param([string] $Label,[string] $OutputPath,[switch] $ConfirmSetup)
        $Fixture.ProviderCalls.Add([pscustomobject]@{Label=$Label;OutputPath=$OutputPath;Confirmed=[bool]$ConfirmSetup})
        $Fixture.Response
    }
    function Import-RecipientProfile { throw 'Unexpected recipient selection provider in setup fixture.' }
    function Show-StatusDeskRecipientDialog {
        param($Owner,[string] $Purpose)
        $Fixture.DialogCalls.Add([pscustomobject]@{Owner=$Owner;Purpose=$Purpose})
        if ($Purpose -cne 'Setup') { throw 'Setup handler contract: actual outer action must select Purpose Setup' }
        if ($Fixture.Cancel) { & $Cancel } else { & $Confirm }
        $result.Value
    }
    function Request-StatusDeskCancellation { param($Session) $Fixture.CancellationCalls++ }
    function Set-StatusDeskDecision {
        param($Session,[bool] $Approve,[string] $PlanDigest)
        $Fixture.Decisions.Add([pscustomobject]@{Approve=$Approve;PlanDigest=$PlanDigest})
    }
    & $Setup
}

function Assert-SetupFixtureResult {
    param($Fixture,[ValidateSet('Cancel','Missing','Created','Failed','CleanupIncomplete','Guard')] [string] $Expected)
    if ($Expected -eq 'Guard') {
        Assert-SetupContract ($Fixture.DialogCalls.Count -eq 0 -and $Fixture.ProviderCalls.Count -eq 0) 'unsafe, disabled or already-decided action cannot open setup'
        Assert-SetupContract ($null -eq $Fixture.Result.Value) 'guard cannot return a setup result'
        return
    }
    Assert-SetupContract ($Fixture.DialogCalls.Count -eq 1 -and $Fixture.DialogCalls[0].Purpose -ceq 'Setup' -and
        $Fixture.DialogCalls[0].Owner.FixtureOwner) 'actual outer handler forwards its owner and Setup purpose once'
    if ($Expected -in @('Cancel','Missing')) {
        Assert-SetupContract ($Fixture.ProviderCalls.Count -eq 0 -and $null -eq $Fixture.Result.Value) 'cancel and missing input cannot call setup provider'
        if ($Expected -eq 'Cancel') { Assert-SetupContract ($Fixture.Dialog.CloseCount -eq 1) 'cancel closes the dialog once' }
        else { Assert-SetupContract ($Fixture.Fields.RecipientStatus.Text -ceq 'Provide both fields before confirming.') 'missing input has actionable guidance' }
    }
    else {
        Assert-SetupContract ($Fixture.ProviderCalls.Count -eq 1) 'one explicit confirmation calls the setup provider once'
        $call=$Fixture.ProviderCalls[0]
        Assert-SetupContract ($call.Label -ceq $Fixture.Fields.Fingerprint.Text -and $call.OutputPath -ceq $Fixture.Fields.ProfilePath.Text -and $call.Confirmed) 'provider receives both exact inputs and explicit setup confirmation'
        Assert-SetupContract ([object]::ReferenceEquals($Fixture.Response,$Fixture.Result.Value)) 'actual provider result is retained without substituting success'
        if ($Expected -eq 'Created') {
            Assert-SetupContract (-not $Fixture.Fields.ConfirmRecipient.IsEnabled) 'successful creation disables duplicate confirmation'
            Assert-SetupContract ($Fixture.Fields.RecipientStatus.Text.Contains('Synthetic round trip verified.') -and
                $Fixture.Fields.RecipientStatus.Text.Contains($Fixture.Response.protectionLevel) -and
                $Fixture.Fields.RecipientStatus.Text.Contains($Fixture.Response.fingerprint) -and
                $Fixture.Fields.RecipientStatus.Text.Contains('Share only the public profile') -and
                $Fixture.Fields.RecipientStatus.Text.Contains('Retain the private key')) 'creation presents returned round-trip/protection/fingerprint and key retention guidance'
        }
        else {
            Assert-SetupContract ($Fixture.Fields.RecipientStatus.Text.Contains('No assessment started.') -and
                $Fixture.Fields.RecipientStatus.Text.Contains($Fixture.Response.reasonCode)) 'setup failure remains visible without claiming assessment started'
        }
        if ($Expected -eq 'Failed') { Assert-SetupContract ($Fixture.Fields.ConfirmRecipient.IsEnabled -and -not $Fixture.State.ViewingCleanupFailed) 'ordinary setup refusal permits correction without claiming cleanup uncertainty' }
    }
    if ($Expected -eq 'CleanupIncomplete') {
        Assert-SetupContract (-not $Fixture.Fields.ConfirmRecipient.IsEnabled) 'uncertain cleanup disables inner confirmation'
        Assert-SetupContract ($Fixture.State.ViewingCleanupFailed -and $Fixture.Session.ExitCode -eq 60) 'actual outer action preserves unsafe cleanup disposition'
        foreach ($name in @('Approve','Decline','Cancel','SelectRecipient','SetupRecipient','OpenExisting','OpenReport','SaveHtml','ChangeChoices','Retry')) {
            Assert-SetupContract (-not $Fixture.Controls[$name].IsEnabled) ('cleanup uncertainty blocks '+$name)
        }
        Assert-SetupContract ($Fixture.Controls.Status.Text -ceq 'CleanupIncomplete — new work blocked') 'cleanup failure is explicit in status'
        $expectedCalls=if ($Fixture.Session.Completed) {0} else {1}
        Assert-SetupContract ($Fixture.CancellationCalls -eq $expectedCalls -and $Fixture.Decisions.Count -eq $expectedCalls) 'only an active session receives cancellation and decline'
        if ($expectedCalls) { Assert-SetupContract (-not $Fixture.Decisions[0].Approve -and $Fixture.Decisions[0].PlanDigest -ceq 'cleanup-failed') 'cleanup cannot grant assessment approval' }
    }
    else {
        Assert-SetupContract ($Fixture.CancellationCalls -eq 0 -and $Fixture.Decisions.Count -eq 0 -and $Fixture.Session.ExitCode -eq 0) 'ordinary setup cannot approve or cancel assessment work'
    }
}

$cases=@(
    @{Expected='Cancel';Inputs=@{Cancel=$true}},
    @{Expected='Missing';Inputs=@{Label=''}},
    @{Expected='Missing';Inputs=@{Destination=' '}},
    @{Expected='Created';Inputs=@{}},
    @{Expected='Failed';Inputs=@{State='Failed'}},
    @{Expected='CleanupIncomplete';Inputs=@{State='CleanupIncomplete'}},
    @{Expected='CleanupIncomplete';Inputs=@{State='CleanupIncomplete';Completed=$true}},
    @{Expected='Guard';Inputs=@{Unsafe=$true}},
    @{Expected='Guard';Inputs=@{Disabled=$true}},
    @{Expected='Guard';Inputs=@{Decided=$true}},
    @{Expected='Created';Inputs=@{Completed=$true;Decided=$true}}
)
foreach ($case in $cases) {
    $inputs=$case.Inputs
    $fixture=New-SetupHandlerFixture @inputs
    Invoke-SetupHandlerFixture $fixture
    Assert-SetupFixtureResult $fixture $case.Expected
}

# Mutants are confined to these in-memory callback copies. Each must be rejected
# by the same behavioral controls used above; production source is never edited.
$mutants=@(
    @{Name='missing field refusal';Expected='Missing';Inputs=@{Label=''};Confirm=$confirmHandler.ToString().Replace(";return",'')},
    @{Name='explicit setup confirmation';Expected='Created';Inputs=@{};Confirm=$confirmHandler.ToString().Replace(' -ConfirmSetup','')},
    @{Name='Setup purpose forwarding';Expected='Created';Inputs=@{};Setup=$setupHandler.ToString().Replace('-Purpose Setup','-Purpose Selection')},
    @{Name='cleanup admission blocking';Expected='CleanupIncomplete';Inputs=@{State='CleanupIncomplete'};Setup=$setupHandler.ToString().Replace('Stop-StatusDeskForCleanupFailure -State $state -Controls $controls -Session $session','$null=$null')},
    @{Name='unsafe action refusal';Expected='Guard';Inputs=@{Unsafe=$true};Setup=$setupHandler.ToString().Replace('$state.ViewingCleanupFailed -or ','')},
    @{Name='cancel closes dialog';Expected='Cancel';Inputs=@{Cancel=$true};Cancel=$cancelHandler.ToString().Replace('$dialog.Close()','$null=$null')}
)
foreach ($mutant in $mutants) {
    $inputs=$mutant.Inputs
    $fixture=New-SetupHandlerFixture @inputs
    $arguments=@{Fixture=$fixture}
    foreach ($name in @('Confirm','Setup','Cancel')) {
        if ($mutant.ContainsKey($name)) {
            $original=Get-Variable -Name ($name.ToLowerInvariant()+'Handler') -ValueOnly
            Assert-SetupContract ($mutant[$name] -cne $original.ToString()) ('mutation changes '+$mutant.Name)
            $arguments[$name]=[scriptblock]::Create($mutant[$name])
        }
    }
    $failure=$null
    try { Invoke-SetupHandlerFixture @arguments; Assert-SetupFixtureResult $fixture $mutant.Expected }
    catch { $failure=$_ }
    Assert-SetupContract ($null -ne $failure -and $failure.Exception.Message.StartsWith('Setup handler contract:')) ('behavioral controls reject '+$mutant.Name)
}
Write-Output ('PASS: Status desk recipient setup handlers; '+$cases.Count+' cases, '+$mutants.Count+' defect sensitivity controls, '+$checks+' assertions; pure controlled providers only.')
