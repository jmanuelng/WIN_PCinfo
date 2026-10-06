[CmdletBinding()]
param([switch]$StaChild,
    [string] $CandidatePath = '', [string] $PreparedManifestPath = '', [string] $PreparedManifestSha256 = '')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidateUseError=$null
try {
if (-not $candidateContext.Prepared) {
    $PreparedManifestPath=Join-Path $candidateContext.OwnedDirectory 'prepared-test-candidate.json'
    [IO.File]::WriteAllText($PreparedManifestPath,((New-PreparedTestCandidateManifest -RepositoryRoot $repositoryRoot -CandidatePath $candidateContext.Path) | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    $PreparedManifestSha256=(Get-FileHash -LiteralPath $PreparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
if(-not $StaChild){
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-STA','-File',$PSCommandPath,'-StaChild',
        '-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
    if($LASTEXITCODE -ne 0){throw 'Status desk choices failed.'};return
}
$candidate=$candidateContext.Path
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
$window=New-StatusDeskWindow
foreach($name in @('ChangeChoices','Retry','Help','About')){
    Assert-Equal $true ($null -ne $window.FindName($name)) "$name is discoverable without console input"
}
Assert-Equal $false $window.FindName('Retry').IsEnabled 'retry cannot interrupt active preparation'
$request=Get-AutomationRequest -LiteralPath (Join-Path $PSScriptRoot 'fixtures/automation-request.json') -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$request.outputDestination=$repositoryRoot
$original=$request | ConvertTo-Json -Depth 40 -Compress
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$state=@{Seen=$false;Failed='';Ticks=0}
$driver.Add_Tick({
    try{
        $state.Ticks++
        foreach($source in @([System.Windows.PresentationSource]::CurrentSources)){
            $dialog=$source.RootVisual
            if($dialog -isnot [System.Windows.Window] -or $dialog.Title -ne 'WIN-PCInfo — Assessment choices'){continue}
            if($state.Ticks -gt 50){$state.Failed='Dialog did not finish';$dialog.Close();return}
            $dialog.FindName('NetworkChoice').SelectedIndex=1
            $dialog.FindName('OutputPath').Text=$repositoryRoot
            $state.Seen=$true
            $dialog.FindName('ConfirmChoices').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
        }
    }catch{$state.Failed=$_.Exception.Message}
}.GetNewClosure())
try{$driver.Start();$selection=Show-StatusDeskChoicesDialog -Request $request}
finally{$driver.Stop()}
Assert-Equal '' $state.Failed 'choices finish without a hidden prompt'
Assert-Equal $true $state.Seen 'generated choices dialog was exercised'
Assert-Equal 'MicrosoftConnectivityEnabled' $selection.networkBehavior 'the operator can select the second approved network behavior'
Assert-Equal $repositoryRoot $selection.outputDestination 'the operator can select the private output destination'
Assert-Equal $original ($request | ConvertTo-Json -Depth 40 -Compress) 'choices never mutate the already frozen request'
foreach($surface in @('Help','About')){
    $text=Get-StatusDeskHelpText -Surface $surface
    Assert-Equal $true ($text -match 'Choose.*Verify.*Prepare.*Run.*Interpret.*Troubleshoot.*Share') 'help exposes the complete runway'
    Assert-Equal $true ($text -match 'MIT' -and $text -match 'DCO' -and $text -match 'no SLA') 'passive discovery retains governance'
    Assert-Equal $true ($text -match 'CleanupIncomplete' -and $text -match 'private key') 'help explains recovery and key retention'
}
$heartbeat=Get-StatusDeskActivityText -Record ([pscustomobject]@{phase='RunControl';state='Heartbeat';messageId='controller.waiting-for-worker'})
Assert-Equal $true ($heartbeat -match 'Waiting for owned work' -and $heartbeat -match 'not source progress') 'heartbeat English does not imply collection progress'
Write-Output 'PASS: generated GUI choices and passive help are operable without console input.'
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEntry.Tests.ps1'),'-Choices',
    '-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
if($LASTEXITCODE -ne 0){throw 'Generated GUI choice replacement and retry failed.'}
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
