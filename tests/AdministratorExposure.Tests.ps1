[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/AdministratorExposure.ps1')

$policy = Get-AdministratorExposurePolicy -ConvertFromJsonCommand (
    Get-Command ConvertFrom-Json -CommandType Cmdlet
)
$expected = @{
    LocalPrincipal = @{ state='Complete'; count=2; kinds='User|User'; origins='Local|Local' }
    DomainPrincipal = @{ state='Complete'; count=2; kinds='Group|User'; origins='Domain|Domain' }
    NestedGroup = @{ state='Complete'; count=2; kinds='Group|User'; origins='Domain|Local' }
    UnresolvedSid = @{ state='Complete'; count=2; kinds='Unknown|User'; origins='Unresolved|Local' }
    DuplicateMembership = @{ state='Complete'; count=2; kinds='User|User'; origins='Domain|Local' }
    AlternateAdministrator = @{ state='Complete'; count=2; kinds='User|User'; origins='Local|Local' }
    Denied = @{ state='Denied'; count=0; kinds=''; origins='' }
    Partial = @{ state='Partial'; count=2; kinds='Group|User'; origins='Domain|Local' }
    NonEnglish = @{ state='Complete'; count=2; kinds='Group|User'; origins='Domain|Local' }
    ElevationDenied = @{ state='Denied'; count=0; kinds=''; origins='' }
}

foreach ($scenario in @($policy.validationScenarios)) {
    $fixturePath = Join-Path $PSScriptRoot "fixtures/administrator-$($scenario.ToLowerInvariant()).json"
    $selected = Read-AdministratorExposureFixture -LiteralPath $fixturePath `
        -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet) -Policy $policy
    Assert-Equal $scenario $selected 'the fixture selects only a release-owned scenario'
    $result = Invoke-AdministratorExposureCollection -Policy $policy -ValidationScenario $selected
    Assert-Equal $expected[$scenario].state $result.payload.enumerationState `
        "$scenario preserves complete, partial, and denied enumeration"
    Assert-Equal $expected[$scenario].count @($result.payload.directMembers).Count `
        "$scenario preserves only bounded direct membership"
    Assert-Equal $expected[$scenario].kinds (@($result.payload.directMembers | ForEach-Object principalKind) -join '|') `
        "$scenario keeps structured principal kinds"
    Assert-Equal $expected[$scenario].origins (@($result.payload.directMembers | ForEach-Object origin) -join '|') `
        "$scenario keeps locale-independent local/domain/unresolved origin"
    Assert-Equal $true (Test-AdministratorExposureCollectorPayload -Payload $result.payload -Policy $policy) `
        "$scenario satisfies the closed collector payload"
}

$duplicate = Invoke-AdministratorExposureCollection -Policy $policy -ValidationScenario DuplicateMembership
Assert-Equal 2 @($duplicate.payload.directMembers).Count `
    'duplicate source membership is de-duplicated by SID'
Assert-Equal 2 @($duplicate.payload.directMembers.sid | Sort-Object -Unique).Count `
    'each stable principal SID occurs once'

$nested = Invoke-AdministratorExposureCollection -Policy $policy -ValidationScenario NestedGroup
Assert-Equal 'DirectMembersOnly' $nested.membershipSemantics `
    'a nested group remains one observed direct member and is never expanded'

$alternate = Invoke-AdministratorExposureCollection -Policy $policy -ValidationScenario AlternateAdministrator
Assert-Equal 'AlternateAdministrator' $alternate.processRelationship `
    'the elevated worker remains separate from the Assessment User Context'
Assert-Equal 'subject:assessment-user:primary' $alternate.assessmentUserContext `
    'alternate elevation cannot replace the Assessment User Context'
Assert-Equal 'protector:initiating-windows-user' $alternate.localPackageProtector `
    'alternate elevation cannot replace the Local Package Protector'

foreach ($scenario in @('Denied','ElevationDenied')) {
    $failed = Invoke-AdministratorExposureCollection -Policy $policy -ValidationScenario $scenario
    Assert-Equal 0 @($failed.payload.directMembers).Count `
        "$scenario cannot fabricate an empty Administrators group"
    Assert-Equal $false ([bool]$failed.payload.enumerationComplete) `
        "$scenario reports bounded missing coverage"
}

$invalidDenied=(Invoke-AdministratorExposureCollection -Policy $policy -ValidationScenario Denied).payload
$invalidDenied.directMembers=@(
    (New-AdministratorExposureSyntheticMember -Sid 'S-1-5-21-1-2-3-1001' `
        -AccountName $null -Kind Unknown -Origin Unresolved)
)
$invalidDenied.sourceReturnedEntries=1
Assert-Equal $false (Test-AdministratorExposureCollectorPayload -Payload $invalidDenied -Policy $policy) `
    'a denied source cannot smuggle a member or masquerade as an empty complete group'

$public = New-AdministratorExposurePublicProjection `
    -CollectorResult (Invoke-AdministratorExposureCollection -Policy $policy -ValidationScenario NonEnglish)
$publicJson = $public | ConvertTo-Json -Compress -Depth 10
if ($publicJson -match '(?i)S-1-5-|SYNTHETIC\\|DOMAINE|Administrateurs|Administrator') {
    throw 'The public projection leaked a Restricted principal identity or localized account text.'
}
Assert-Equal 2 $public.directMemberCount 'the public projection exposes only a safe aggregate count'

Write-Output 'PASS: Administrator Exposure fixtures preserve direct SID membership, context, coverage, and privacy.'
