[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Actual selection callbacks/continuation with explicit recording controls and
# providers. No WPF, chooser, STA child, build, certificate/key or process query.
$sourcePath=Join-Path (Split-Path $PSScriptRoot) 'src/StatusDesk.ps1'
$tokens=$null;$errors=$null
$sourceAst=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Recipient selection source must parse.'}
$selectionCounter=@{Checks=0}
function Assert-SelectionControl {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw ('Recipient selection control: '+$Message)}
    $selectionCounter.Checks++
}
function Get-SelectionCallback {
    param([string]$Function,[string]$Receiver)
    $definition=@($sourceAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Function},$true))
    Assert-SelectionControl ($definition.Count -eq 1) ('unique actual function '+$Function)
    $calls=@($definition[0].Body.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Expression.Extent.Text -ceq $Receiver -and $node.Member.Value -ceq 'Add_Click'},$true))
    Assert-SelectionControl ($calls.Count -eq 1 -and $calls[0].Arguments[0] -is [Management.Automation.Language.ScriptBlockExpressionAst]) ('unique actual callback '+$Receiver)
    $calls[0].Arguments[0].ScriptBlock.GetScriptBlock()
}
$fixtureTokens=$null;$fixtureErrors=$null
$fixtureAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'StatusDeskRecipientSelection.Tests.ps1'),[ref]$fixtureTokens,[ref]$fixtureErrors)
Assert-SelectionControl ($fixtureErrors.Count -eq 0 -and ($fixtureAst.ParamBlock.Parameters.Name.VariablePath.UserPath -join '|') -ceq 'StaChild|CandidatePath|PreparedManifestPath|PreparedManifestSha256') 'Actual GUI caller retains the existing STA child and exact prepared triple.'
$originalDriver=@($fixtureAst.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Expression.Extent.Text -ceq '$driver' -and $node.Member.Value -ceq 'Add_Tick'},$true))
$originalTick=@'
$driver.Add_Tick({
        foreach($source in @([System.Windows.PresentationSource]::CurrentSources)) {
            $window=$source.RootVisual
            if($watch.Elapsed.TotalSeconds -gt 20 -and $window -is [System.Windows.Window]){$state.TimedOut=$true;$window.Close();continue}
            if($window -isnot [System.Windows.Window] -or $window.Title -ne 'WIN-PCInfo — Recipient selection'){continue}
            $window.FindName('ProfilePath').Text=$setup.profilePath
            $window.FindName('Fingerprint').Text=if($state.Rejected){$setup.fingerprint}else{'0'*64}
            $window.FindName('ConfirmRecipient').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            if(-not $state.Rejected){$state.Rejected=$window.FindName('RecipientStatus').Text.Contains('RECIPIENT.FINGERPRINT_MISMATCH')}
            else{$state.Selected=$true}
        }
    }.GetNewClosure())
'@
Assert-SelectionControl ($originalDriver.Count -eq 1 -and $originalDriver[0].Extent.Text.Replace("`r`n","`n") -ceq $originalTick.Replace("`r`n","`n")) 'Original real-dialog wrong→valid driver is unchanged.'
$originalAssertions=@'
Assert-Equal $false $state.TimedOut 'the controlled recipient dialog finishes within its test deadline'
Assert-Equal $true $state.Rejected 'incorrect fingerprint keeps the selection dialog open'
Assert-Equal $true $state.Selected 'operator confirms the fingerprint before selection'
Assert-Equal 'Profile' $selection.mode 'GUI selects exactly one admitted profile'
Assert-Equal $setup.fingerprint $selection.fingerprintConfirmation 'the confirmed identity enters the subsequent frozen request'
'@
$fixtureAssertions=@($fixtureAst.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Assert-Equal'},$true) | Select-Object -First 5)
Assert-SelectionControl (($fixtureAssertions.Extent.Text -join "`n").Replace("`r`n","`n") -ceq $originalAssertions.Replace("`r`n","`n")) 'All original five wrong→valid assertions are preserved exactly.'
$additionalCases=@($fixtureAst.FindAll({param($node) $node -is [Management.Automation.Language.ForEachStatementAst] -and $node.Variable.VariablePath.UserPath -ceq 'case'},$true))
Assert-SelectionControl ($additionalCases.Count -eq 1) 'Actual fixture has one bounded additional dialog campaign.'
$setup=[pscustomobject]@{profilePath='DisclosedStaticProfile';fingerprint=('1'*64)};$root='DisclosedStaticRoot'
$malformedPath=Join-Path $root 'malformed.recipient.json'
$draftCases=@(& ([scriptblock]::Create($additionalCases[0].Condition.Extent.Text)))
Assert-SelectionControl (($draftCases.Name -join '|') -ceq 'EmptyProfile|EmptyFingerprint|BothEmpty|MissingProfile|MalformedProfile|MalformedFingerprint|Cancel|NoRecipient|BrowseCancel') 'Native draft binds exactly the nine approved existing-dialog branches.'
$confirm=Get-SelectionCallback 'Show-StatusDeskRecipientDialog' '$fields.ConfirmRecipient'
$cancel=Get-SelectionCallback 'Show-StatusDeskRecipientDialog' '$fields.CancelRecipient'
$none=Get-SelectionCallback 'Show-StatusDeskRecipientDialog' '$fields.NoRecipient'
$browseOriginal=Get-SelectionCallback 'Show-StatusDeskRecipientDialog' '$fields.Browse'
$pickerFactory='[Microsoft.Win32.OpenFileDialog]::new()'
Assert-SelectionControl ($browseOriginal.ToString().Contains($pickerFactory)) 'Browse factory substitution binds the existing selection chooser only.'
$browse=[scriptblock]::Create($browseOriginal.ToString().Replace($pickerFactory,'(New-SelectionPickerFixture)'))
$select=Get-SelectionCallback 'Invoke-StatusDesk' '$controls.SelectRecipient'
$desk=@($sourceAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-StatusDesk'},$true))[0]
$continuations=@($desk.Body.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.StartsWith('if ($null -ne $state.NextChoices -or $null -ne $state.NextSelection -or $state.RetryRequested)')})
Assert-SelectionControl ($continuations.Count -eq 1) 'Fresh preparation uses the actual unique request-cloning continuation.'
$continuation=[scriptblock]::Create($continuations[0].Extent.Text)
$textDefinition=@($sourceAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-StatusDeskPreparationText'},$true))
Assert-SelectionControl ($textDefinition.Count -eq 1) 'Protection guidance uses the actual preparation text function.'
. ([scriptblock]::Create($textDefinition[0].Extent.Text))
function New-SelectionControlFixture {
    param([string]$Case)
    $dialog=[pscustomobject]@{CloseCount=0}
    $dialog | Add-Member -MemberType ScriptMethod -Name Close -Value {$this.CloseCount++}
    $window=[pscustomobject]@{CloseCount=0;OwnerMarker='PureOwner'}
    $window | Add-Member -MemberType ScriptMethod -Name Close -Value {$this.CloseCount++}
    $certificate=[pscustomobject]@{DisposeCount=0}
    $certificate | Add-Member -MemberType ScriptMethod -Name Dispose -Value {$this.DisposeCount++}
    $fields=@{ProfilePath=[pscustomobject]@{Text='synthetic.recipient.json'};Fingerprint=[pscustomobject]@{Text=('1'*64)};RecipientStatus=[pscustomobject]@{Text=''}}
    $response=[pscustomobject]@{state='Approved';reasonCode='RECIPIENT.PROFILE_APPROVED';fingerprint=('1'*64);certificate=$certificate;label='Synthetic approved recipient';protectionLevel='WindowsUserBound'}
    switch($Case){
        'EmptyProfile' {$fields.ProfilePath.Text=''}
        'EmptyFingerprint' {$fields.Fingerprint.Text=''}
        'BothEmpty' {$fields.ProfilePath.Text='';$fields.Fingerprint.Text=''}
        'MissingProfile' {$fields.ProfilePath.Text='missing.recipient.json';$response.state='Rejected';$response.reasonCode='RECIPIENT.PROFILE_INVALID'}
        'MalformedProfile' {$fields.ProfilePath.Text='malformed.recipient.json';$response.state='Rejected';$response.reasonCode='RECIPIENT.PROFILE_INVALID'}
        'MalformedFingerprint' {$fields.Fingerprint.Text='invalid';$response.state='Rejected';$response.reasonCode='RECIPIENT.FINGERPRINT_MISMATCH'}
        'WrongFingerprint' {$fields.Fingerprint.Text=('0'*64);$response.state='Rejected';$response.reasonCode='RECIPIENT.FINGERPRINT_MISMATCH'}
    }
    if($Case -in @('EmptyProfile','EmptyFingerprint','BothEmpty')){$response.state='Rejected';$response.reasonCode='RECIPIENT.PROFILE_INVALID'}
    [pscustomobject]@{Case=$Case;Fields=$fields;Dialog=$dialog;Window=$window;Certificate=$certificate;Response=$response;Result=@{Value=$null};
        State=@{ViewingCleanupFailed=($Case -eq 'Unsafe');NextSelection=$null;NextChoices=$null;RetryRequested=$false};Controls=@{SelectRecipient=[pscustomobject]@{IsEnabled=($Case -ne 'Disabled')}};
        Session=[pscustomobject]@{Completed=($Case -eq 'Completed');Transport=[pscustomobject]@{DecisionReady=[pscustomobject]@{IsSet=($Case -in @('Decided','Completed'))}}};
        ProviderCalls=[Collections.Generic.List[object]]::new();DialogCalls=[Collections.Generic.List[object]]::new();PickerCalls=[Collections.Generic.List[object]]::new();FreshCalls=[Collections.Generic.List[object]]::new();
        Request=[pscustomobject]@{recipientSelection=[pscustomobject]@{mode='Profile';profilePath='previous.recipient.json';fingerprintConfirmation=('2'*64)};automationChoices=[pscustomobject]@{allowStaleRecovery=$true}}}
}
function Invoke-SelectionControlFixture {
    param($Fixture,[scriptblock]$Confirm=$confirm,[scriptblock]$Cancel=$cancel,[scriptblock]$None=$none,[scriptblock]$Select=$select,[scriptblock]$Continuation=$continuation)
    $fields=$Fixture.Fields;$dialog=$Fixture.Dialog;$result=$Fixture.Result;$Purpose='Selection'
    $window=$Fixture.Window;$state=$Fixture.State;$controls=$Fixture.Controls;$session=$Fixture.Session
    $LaunchParameters=@{Request=$Fixture.Request;Marker='UnchangedLaunch'};$DefinitionInitializer={};$ViewReady={}
    function Import-RecipientProfile {
        param($LiteralPath,$ExpectedFingerprint,[switch]$ForNewPackage)
        $Fixture.ProviderCalls.Add([pscustomobject]@{path=$LiteralPath;fingerprint=$ExpectedFingerprint;newPackage=[bool]$ForNewPackage})
        $Fixture.Response
    }
    function New-RecipientProfileSetup {throw 'Recipient selection control: selection must never create identity.'}
    function New-SelectionPickerFixture {
        $picker=[pscustomobject]@{Filter='';FileName='UnusedCancelledPath';Fixture=$Fixture}
        $picker | Add-Member -MemberType ScriptMethod -Name ShowDialog -Value {param($Owner);$this.Fixture.PickerCalls.Add([pscustomobject]@{owner=$Owner;filter=$this.Filter});$false}
        $picker
    }
    function Show-StatusDeskRecipientDialog {
        param($Owner,$Purpose)
        $Fixture.DialogCalls.Add([pscustomobject]@{owner=$Owner;purpose=$Purpose})
        switch($Fixture.Case){
            'Cancel' {& $Cancel}
            'NoRecipient' {& $None}
            'BrowseCancel' {& $browse;& $Cancel}
            default {& $Confirm}
        }
        $result.Value
    }
    function Set-StatusDeskDecision {throw 'Recipient selection control: selection must not approve collection.'}
    function Invoke-StatusDesk {
        param($DefinitionInitializer,$LaunchParameters,$ViewReady)
        $Fixture.FreshCalls.Add([pscustomobject]@{definition=$DefinitionInitializer;launch=$LaunchParameters;ready=$ViewReady})
        'DisclosedFreshPreparation'
    }
    & $Select
    & $Continuation | Out-Null
}
function Assert-SelectionFixture {
    param($Fixture,[string]$OriginalRequest)
    $case=$Fixture.Case
    Assert-SelectionControl (($Fixture.Request | ConvertTo-Json -Depth 10 -Compress) -ceq $OriginalRequest) 'Selection never mutates the prior frozen request.'
    if($case -in @('Unsafe','Disabled','Decided')){
        Assert-SelectionControl ($Fixture.DialogCalls.Count -eq 0 -and $Fixture.ProviderCalls.Count -eq 0 -and $Fixture.FreshCalls.Count -eq 0) 'Unsafe, disabled or decided selection cannot open a dialog or new preparation.'
        return
    }
    Assert-SelectionControl ($Fixture.DialogCalls.Count -eq 1 -and $Fixture.DialogCalls[0].purpose -ceq 'Selection' -and [object]::ReferenceEquals($Fixture.DialogCalls[0].owner,$Fixture.Window)) 'The actual outer action forwards Selection purpose and exact owner.'
    $empty=$case -in @('EmptyProfile','EmptyFingerprint','BothEmpty')
    $cancelled=$case -in @('Cancel','BrowseCancel')
    $approved=$case -in @('Approved','Completed')
    $providerCount=if($empty -or $cancelled -or $case -eq 'NoRecipient'){0}else{1}
    Assert-SelectionControl ($Fixture.ProviderCalls.Count -eq $providerCount) 'Empty/cancel/no-recipient paths do not call a provider; nonempty confirmation calls exactly once.'
    if($providerCount){Assert-SelectionControl ($Fixture.ProviderCalls[0].path -ceq $Fixture.Fields.ProfilePath.Text -and $Fixture.ProviderCalls[0].fingerprint -ceq $Fixture.Fields.Fingerprint.Text -and $Fixture.ProviderCalls[0].newPackage) 'Admission receives exact inputs with new-package expiry semantics.'}
    if($empty){Assert-SelectionControl ($Fixture.Fields.RecipientStatus.Text -ceq 'Provide both fields before confirming.') 'Missing inputs retain actionable refusal.'}
    elseif(-not $cancelled -and -not $approved -and $case -ne 'NoRecipient'){Assert-SelectionControl ($Fixture.Fields.RecipientStatus.Text.Contains($Fixture.Response.reasonCode)) 'Rejected profile/fingerprint stays visible and unselected.'}
    $changed=$approved -or $case -eq 'NoRecipient'
    Assert-SelectionControl ($Fixture.Dialog.CloseCount -eq $(if($changed -or $cancelled){1}else{0}) -and $Fixture.Window.CloseCount -eq $(if($changed){1}else{0})) 'Only deliberate selection closes the parent; refusal stays open and cancel preserves its prior choice.'
    Assert-SelectionControl ($Fixture.Certificate.DisposeCount -eq $(if($approved){1}else{0})) 'Approved public-certificate handle is disposed exactly once.'
    Assert-SelectionControl ($Fixture.FreshCalls.Count -eq $(if($changed){1}else{0})) 'Only profile/no-recipient choice creates one fresh preparation.'
    if($changed){
        $next=$Fixture.FreshCalls[0].launch.Request
        Assert-SelectionControl (-not [object]::ReferenceEquals($next,$Fixture.Request) -and -not $next.automationChoices.allowStaleRecovery) 'Fresh preparation clones its request and clears recovery authority.'
        Assert-SelectionControl (-not $Fixture.Session.Transport.DecisionReady.IsSet -or $case -eq 'Completed') 'Selection does not grant the next assessment approval.'
        if($approved){Assert-SelectionControl ($next.recipientSelection.mode -ceq 'Profile' -and $next.recipientSelection.profilePath -ceq [IO.Path]::GetFullPath($Fixture.Fields.ProfilePath.Text) -and $next.recipientSelection.fingerprintConfirmation -ceq $Fixture.Response.fingerprint) 'Fresh preparation freezes the exact admitted profile/fingerprint.'}
        else{Assert-SelectionControl ($next.recipientSelection.mode -ceq 'None' -and $null -eq $next.recipientSelection.profilePath -and $null -eq $next.recipientSelection.fingerprintConfirmation) 'Explicit local-only choice clears both recipient operands.'}
    }else{Assert-SelectionControl ($null -eq $Fixture.State.NextSelection -and $null -eq $Fixture.Result.Value) 'Refusal/cancel cannot replace the previous recipient.'}
    if($case -eq 'BrowseCancel'){Assert-SelectionControl ($Fixture.PickerCalls.Count -eq 1 -and [object]::ReferenceEquals($Fixture.PickerCalls[0].owner,$Fixture.Dialog) -and $Fixture.Fields.ProfilePath.Text -ceq 'synthetic.recipient.json' -and $Fixture.Fields.Fingerprint.Text -ceq ('1'*64)) 'Cancelled Browse forwards its owner/filter and preserves both typed inputs.'}
}
$cases=@('EmptyProfile','EmptyFingerprint','BothEmpty','MissingProfile','MalformedProfile','MalformedFingerprint','WrongFingerprint','Approved','Cancel','NoRecipient','BrowseCancel','Unsafe','Disabled','Decided','Completed')
foreach($case in $cases){$fixture=New-SelectionControlFixture $case;$original=$fixture.Request | ConvertTo-Json -Depth 10 -Compress;Invoke-SelectionControlFixture $fixture;Assert-SelectionFixture $fixture $original}
# Actual preparation rendering, with a static plan only; this is not collected evidence.
$summary=[pscustomobject]@{readyForApproval=$true;planDigest='SyntheticFrozenDigest';plan=[pscustomobject]@{
    scope=[pscustomobject]@{profileName='Comprehensive Local Assessment';capabilities=@()};operations=@();network=[pscustomobject]@{behavior='LocalOnly';plannedRequests=@()};
    output=[pscustomobject]@{destination='SyntheticPrivateDestination';recipientProfile=[pscustomobject]@{mode='Profile';label='Synthetic approved recipient';protectionLevel='WindowsUserBound';fingerprint=('1'*64)}};
    dependencies=[pscustomobject]@{runtime='SyntheticRuntime'};estimates=[pscustomobject]@{durationMinutes=1;workspaceDiskMiB=1;protectedPackageDiskMiB=1};cleanup=[pscustomobject]@{staleRunRecovery=[pscustomobject]@{requested=$false}};limitations=@()}}
$guidance=Get-StatusDeskPreparationText $summary
Assert-SelectionControl ($guidance.Contains('WindowsUserBound') -and $guidance.Contains('Synthetic approved recipient') -and $guidance.Contains('Confirmed fingerprint: '+('1'*64)) -and $guidance.Contains('Approval applies only to plan SyntheticFrozenDigest.')) 'Displayed preparation keeps actual protection label, fingerprint and frozen approval binding.'
$mutants=@(
    @{Case='EmptyProfile';Name='missing-input refusal';Confirm=$confirm.ToString().Replace(';return','')},
    @{Case='Cancel';Name='cancel closes';Cancel=$cancel.ToString().Replace('$dialog.Close()','$null=$null')},
    @{Case='NoRecipient';Name='explicit no-recipient';None=$none.ToString().Replace("mode='None'","mode='Profile'")},
    @{Case='Approved';Name='new-package admission';Confirm=$confirm.ToString().Replace(' -ForNewPackage','')},
    @{Case='Approved';Name='certificate disposal';Confirm=$confirm.ToString().Replace('$admission.certificate.Dispose()','$null=$null')},
    @{Case='Unsafe';Name='unsafe outer guard';Select=$select.ToString().Replace('$state.ViewingCleanupFailed -or ','')},
    @{Case='NoRecipient';Name='frozen request clone';Continuation=$continuation.ToString().Replace('$LaunchParameters.Request | ConvertTo-Json -Depth 40 | ConvertFrom-Json -Depth 40','$LaunchParameters.Request')}
)
foreach($mutant in $mutants){
    $fixture=New-SelectionControlFixture $mutant.Case;$original=$fixture.Request | ConvertTo-Json -Depth 10 -Compress;$arguments=@{Fixture=$fixture}
    foreach($name in @('Confirm','Cancel','None','Select','Continuation')){if($mutant.ContainsKey($name)){$originalCallback=Get-Variable -Name $name -ValueOnly;Assert-SelectionControl ($mutant[$name] -cne $originalCallback.ToString()) ('mutation changes '+$mutant.Name);$arguments[$name]=[scriptblock]::Create($mutant[$name])}}
    $failure=$null;try{Invoke-SelectionControlFixture @arguments;Assert-SelectionFixture $fixture $original}catch{$failure=$_}
    Assert-SelectionControl ($null -ne $failure -and $failure.Exception.Message.StartsWith('Recipient selection control:')) ('same behavioral checks reject '+$mutant.Name)
}
Write-Output ('PASS: recipient selection actual callbacks/fresh preparation; '+$cases.Count+' cases, '+$mutants.Count+' defect sensitivity controls, '+$selectionCounter.Checks+' assertions; WPF/provider substitutions only, native GUI pending.')
