[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
. (Join-Path $root 'src/AzureValidationArmTransport.ps1')
. (Join-Path $root 'src/AzureValidationTerraform.ps1')
. (Join-Path $root 'src/AzureValidationTerraformInitialization.ps1')
$script:Assertions=0
function Assert-Namespace {param([bool]$Condition,[string]$Because) $script:Assertions++;if(-not $Condition){throw $Because}}
function Assert-NamespaceRefusal {param([scriptblock]$Action,[string]$Reason) $caught=$null;try{$null=& $Action}catch{$caught=$_.Exception};Assert-Namespace ($null -ne $caught -and $caught.Message -ceq $Reason) 'Native namespace did not retain the expected closed refusal.'}
$pins=@{}
foreach($role in @('Terraform','Provider','CliConfig')){
    $file=@{Terraform='terraform.exe';Provider='terraform-provider-azurerm_v4.37.0_x5.exe';CliConfig='round.tfrc'}[$role]
    $pins[$role]=@{Path=('C:\synthetic-private-tools\'+$file);Length=1L;Sha256=('0'*64)}
}
$state=[pscustomobject]@{Now=[DateTimeOffset]::Parse('2030-01-01T00:00:00Z');ClockReads=0;AdvanceAfter=0}
$clock={ $state.ClockReads++;if($state.AdvanceAfter -gt 0 -and $state.ClockReads -ge $state.AdvanceAfter){$state.Now=$state.Now.AddMinutes(6)};$state.Now}.GetNewClosure()
$channel=New-AzureValidationTerraformChannel -Pins $pins -DeadlineUtc $state.Now.AddMinutes(5) -UtcNow $clock -RunProcess {throw 'TEST.NATIVE_TERRAFORM_PROHIBITED'} -OpenPinnedFile {throw 'TEST.NATIVE_TOOL_OPEN_PROHIBITED'}
# Only this freshly owned scratch subtree is created, moved and removed.
$fixtureParent=[IO.Path]::GetFullPath((Join-Path $root '.test-output/terraform-namespace-native-unit'))
$fixture=[IO.Path]::GetFullPath((Join-Path $fixtureParent ([guid]::NewGuid().ToString('N'))))
if(-not $fixture.StartsWith($fixtureParent+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'TEST.FIXTURE_SCOPE_INVALID'}
$lease=$null
try{
    $null=[IO.Directory]::CreateDirectory($fixture)
    $source=Join-Path $fixture 'source'
    $data=Join-Path $fixture 'data'
    $null=[IO.Directory]::CreateDirectory($source);$null=[IO.Directory]::CreateDirectory($data)
    Assert-NamespaceRefusal {Assert-AzureTerraformDirectoryOnlyEntry -Directory $data -ExpectedName 'modules' -Channel $channel} 'VALIDATION.TOOLING_UNRESOLVED'
    $moduleRoot=Join-Path $data 'modules';$null=[IO.Directory]::CreateDirectory($moduleRoot)
    Assert-AzureTerraformDirectoryOnlyEntry -Directory $data -ExpectedName 'modules' -Channel $channel
    Assert-Namespace $true 'Exact single data child refused.'
    [IO.File]::WriteAllText((Join-Path $data 'unapproved.json'),'synthetic')
    Assert-NamespaceRefusal {Assert-AzureTerraformDirectoryOnlyEntry -Directory $data -ExpectedName 'modules' -Channel $channel} 'VALIDATION.TOOLING_UNRESOLVED'
    [IO.File]::Delete((Join-Path $data 'unapproved.json'))
    Assert-Namespace (@(Get-AzureTerraformInitializationFiles -Root $source -Channel $channel).Count -eq 0) 'Empty source enumeration was fabricated.'
    $unexpected=Join-Path $source 'unknown-empty-directory'
    $null=[IO.Directory]::CreateDirectory($unexpected)
    Assert-NamespaceRefusal {Get-AzureTerraformInitializationFiles -Root $source -Channel $channel} 'VALIDATION.TOOLING_UNRESOLVED'
    [IO.Directory]::Delete($unexpected)
    foreach($relative in (Get-AzureTerraformReviewedTemplateHashes).Keys){
        $path=Join-Path $source $relative;$null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        [IO.File]::WriteAllText($path,'synthetic enumeration only')
    }
    Assert-Namespace (@(Get-AzureTerraformInitializationFiles -Root $source -Channel $channel).Count -eq 14) 'Reviewed source directory graph was not enumerated completely.'
    for($i=0;$i -lt 65;$i++){[IO.File]::WriteAllText((Join-Path $source ("unreviewed-$i.txt")),'synthetic')}
    Assert-NamespaceRefusal {Get-AzureTerraformInitializationFiles -Root $source -Channel $channel} 'VALIDATION.TOOLING_UNRESOLVED'
    for($i=0;$i -lt 65;$i++){[IO.File]::Delete((Join-Path $source ("unreviewed-$i.txt")))}
    $state.ClockReads=0;$state.AdvanceAfter=3
    Assert-NamespaceRefusal {Get-AzureTerraformInitializationFiles -Root $source -Channel $channel} 'VALIDATION.ROUND_INTERRUPTED'
    Assert-Namespace ($state.ClockReads -eq 3) 'Source enumeration continued after interruption.'
    $state.Now=[DateTimeOffset]::Parse('2030-01-01T00:00:00Z');$state.AdvanceAfter=0
    Initialize-AzureTerraformFrozenNamespaceType
    $lease=[WinPCInfo.AzureTerraform.FrozenSourceNamespace]::HoldAncestors($source)
    $lease.HoldAdditionalAncestors($data)
    $lease.MarkValidated()
    Assert-Namespace $lease.Verified 'Live ancestor lease did not validate.'
    foreach($directory in @($source,$data)){
        $blocked=$false
        try{[IO.Directory]::Move($directory,$directory+'-moved')}catch [IO.IOException]{$blocked=$true}catch [UnauthorizedAccessException]{$blocked=$true}
        Assert-Namespace ($blocked -and [IO.Directory]::Exists($directory) -and -not [IO.Directory]::Exists($directory+'-moved')) 'Held source/data ancestor allowed namespace rebinding.'
    }
    $writableChild=Join-Path $data 'child-write.json'
    [IO.File]::WriteAllText($writableChild,'synthetic child write')
    Assert-Namespace ([IO.File]::ReadAllText($writableChild) -ceq 'synthetic child write') 'Ancestor write-share exclusion blocked ordinary owned child-file writes.'
    [IO.File]::Delete($writableChild)
    $lease.Dispose();$lease=$null
    [IO.Directory]::Move($source,$source+'-moved');[IO.Directory]::Move($data,$data+'-moved')
    Assert-Namespace ([IO.Directory]::Exists($source+'-moved') -and [IO.Directory]::Exists($data+'-moved')) 'Closed ancestor handles still blocked exact-owned moves.'
    [IO.Directory]::Move($source+'-moved',$source);[IO.Directory]::Move($data+'-moved',$data)
    # Root-first no-follow acquisition refuses an owned local junction in
    # either directory or file-pin paths. No remote target is contacted.
    $destination=Join-Path $fixture 'junction-destination'
    $null=[IO.Directory]::CreateDirectory((Join-Path $destination 'child'))
    [IO.File]::WriteAllText((Join-Path $destination 'child/terraform.exe'),'synthetic')
    $junction=Join-Path $fixture 'junction'
    $null=New-Item -ItemType Junction -Path $junction -Target $destination
    try{
        $reparseFailure=$null
        try{$lease=[WinPCInfo.AzureTerraform.FrozenSourceNamespace]::HoldAncestors((Join-Path $junction 'child'))}catch{$reparseFailure=$_.Exception}
        if($null -ne $lease){$lease.Dispose();$lease=$null}
        Assert-Namespace ($null -ne $reparseFailure) 'Native namespace followed a local junction ancestor.'
        $reparseFailure=$null;$pinned=$null
        try{$pinned=Open-AzureTerraformPinnedFile -Path (Join-Path $junction 'child/terraform.exe')}catch{$reparseFailure=$_.Exception}
        if($null -ne $pinned){$pinned.Dispose()}
        Assert-Namespace ($null -ne $reparseFailure) 'Default file opener followed a local junction ancestor.'
    }finally{[IO.Directory]::Delete($junction)}
    # Default opener retains parent and exact file handles together.
    $pinDir=Join-Path $fixture 'pinned';$null=[IO.Directory]::CreateDirectory($pinDir)
    $pinPath=Join-Path $pinDir 'terraform.exe'
    [IO.File]::WriteAllText($pinPath,'synthetic pinned bytes')
    $pinned=Open-AzureTerraformPinnedFile -Path $pinPath
    try{
        Assert-Namespace ($pinned.CanRead -and $pinned.CanSeek -and -not $pinned.CanWrite -and $pinned.Length -eq 22) 'Default pinned stream lost its read/seek contract.'
        $blocked=$false
        try{[IO.Directory]::Move($pinDir,$pinDir+'-moved')}catch [IO.IOException]{$blocked=$true}
        Assert-Namespace ($blocked -and [IO.Directory]::Exists($pinDir)) 'Default pinned stream allowed its parent namespace to move.'
        $blocked=$false
        try{[IO.File]::WriteAllText($pinPath,'unapproved replacement')}catch [IO.IOException]{$blocked=$true}
        Assert-Namespace $blocked 'Default pinned stream allowed pinned content modification.'
    }finally{$pinned.Dispose()}
    [IO.Directory]::Move($pinDir,$pinDir+'-released')
    Assert-Namespace ([IO.Directory]::Exists($pinDir+'-released')) 'Default pinned stream did not release parent namespace.'
    # Missing SYSTEM-owned source prerequisite refuses; do not establish
    # new privileged owners/ACLs or live authority during this local check.
    Assert-NamespaceRefusal {Lock-AzureTerraformFrozenSourceNamespace -Root $source -Channel $channel -DataDirectory $data} 'VALIDATION.TOOLING_UNRESOLVED'
    [IO.Directory]::Move($source,$source+'-after-refusal');[IO.Directory]::Move($data,$data+'-after-refusal')
    Assert-Namespace $true 'Default source-guard refusal leaked ancestor leases.'
}
finally{
    if($null -ne $lease){$lease.Dispose()}
    $resolved=[IO.Path]::GetFullPath($fixture)
    if(-not $resolved.StartsWith($fixtureParent+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'TEST.FIXTURE_SCOPE_INVALID'}
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
[ordered]@{recordType='win-pcinfo.local-namespace-boundary-tests';result='Pass';assertions=$script:Assertions;nonQualifying=$true;nativeTerraformRequests=0;scope='Exact-owned scratch traversal and ancestor handles only; no privileged source setup, CLI or Azure'}|ConvertTo-Json -Compress|Write-Output
