[CmdletBinding()]
param(
    [ValidateSet('Coverage','Cultures','Safety','Workers','Sources')] [string] $Mode = 'Safety',
    [Parameter(Mandatory)] [string] $ResultDirectory,
    [string] $CaseFilter = '',
    [string] $CandidatePath = '', [string] $PreparedManifestPath = '', [string] $PreparedManifestSha256 = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidate=$candidateContext.Path
$candidateUseError=$null
try {
if (-not $candidateContext.Prepared) {
    $PreparedManifestPath=Join-Path $candidateContext.OwnedDirectory 'prepared-test-candidate.json'
    [IO.File]::WriteAllText($PreparedManifestPath,((New-PreparedTestCandidateManifest -RepositoryRoot $repositoryRoot -CandidatePath $candidate) | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    $PreparedManifestSha256=(Get-FileHash -LiteralPath $PreparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
$hostPath = Resolve-TestRuntime -ApplicationPath $candidate
$windowsPowerShellPath=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/powershell.exe'
$provenance = [ordered]@{
    sourceRevision = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    candidateSha256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
    candidateBytes = (Get-Item -LiteralPath $candidate).Length
    powerShell = $PSVersionTable.PSVersion.ToString(); dotNet = [Environment]::Version.ToString()
    architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    windowsVersion = [Environment]::OSVersion.Version.ToString()
    runtime = [ordered]@{ file=[IO.Path]::GetFileName($hostPath); sha256=(Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash.ToLowerInvariant() }
    softwareWorkerRuntime = [ordered]@{ file='powershell.exe'; version=(Get-Item -LiteralPath $windowsPowerShellPath).VersionInfo.FileVersion; sha256=(Get-FileHash -LiteralPath $windowsPowerShellPath -Algorithm SHA256).Hash.ToLowerInvariant() }
    inputs = @(foreach ($file in @('Invoke-AssessmentSafetyQualification.ps1','StatusDeskEngine.Tests.ps1','QualificationWorkspaceSampling.ps1',
        'AssessmentQualificationSupport.ps1','AdditionalScopeSourceAdapters.ps1','TestHarness.ps1','QualificationCleanup.ps1',
        'ReadinessSourceAdapters.ps1','IdentitySourceAdapters.ps1','PolicySourceAdapters.ps1','SecuritySourceAdapters.ps1',
        'PlatformSourceAdapters.ps1','RemoteSourceAdapters.ps1','SoftwareSourceAdapters.ps1','ResourceSourceAdapters.ps1',
        'NetworkSourceAdapters.ps1','CertificateSourceAdapters.ps1','ConnectivitySourceAdapters.ps1',
        'SoftwareSourceBoundary.ps1','ResourceSourceBoundary.ps1',
        'fixtures/automation-request.json','fixtures/assessment-safety-selection.json','fixtures/assessment-additional-sources.json')) {
        [ordered]@{ file=$file; sha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $file) -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
}
$null = [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($ResultDirectory))
$cases = [Collections.Generic.List[object]]::new()
if ($Mode -eq 'Coverage') {
    $selection = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/assessment-safety-selection.json') -Raw | ConvertFrom-Json
    foreach ($family in $selection) {
        foreach ($scenario in $family.scenarios) {
            $cases.Add(@{ id="$($family.family)-$scenario"; arguments=@("-$($family.family)SourceScenario", $scenario) })
        }
    }
}
elseif ($Mode -eq 'Sources') {
    $selection=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/assessment-additional-sources.json') -Raw | ConvertFrom-Json
    foreach ($case in $selection) {
        $cases.Add(@{id=$case.id;arguments=@("-$($case.family)SourceScenario",$case.scenario,'-QualificationSourceCase',$case.id)})
    }
}
elseif ($Mode -eq 'Cultures') {
    $sources = [ordered]@{
        Readiness='Complete'; Identity='SystemAbsent'; Policy='MdmWindows11'; Security='Active'
        Platform='Running'; Remote='Configured'; Software='Complete'; Resource='Complete'
        Network='Complete'; Certificate='ValidTrusted'; Connectivity='Direct'
    }
    foreach ($culture in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')) {
        foreach ($family in $sources.Keys) {
            $cases.Add(@{ id="$family-$culture"; arguments=@("-$($family)SourceScenario", $sources[$family], '-QualificationCulture', $culture) })
        }
    }
}
elseif ($Mode -eq 'Workers') {
    foreach($fault in @('PrivilegeTimeout','PrivilegeLoss','PrivilegePostStartLoss','SystemCancel','SystemTimeout','SystemLoss')) {
        $cases.Add(@{id=$fault;arguments=@('-QualificationPlanFault',$fault)})
    }
    foreach ($family in @('Software','Resource','Network','Certificate','IdentityRegistration','IdentityWorkSchool')) {
        foreach ($fault in @('Cancel','Timeout','Loss')) {
            $scenario = if($family -eq 'Certificate'){'ValidTrusted'}elseif($family -like 'Identity*'){'Registered'}else{'Complete'}
            $sourceFamily=if($family -like 'Identity*'){'Identity'}else{$family}
            $cases.Add(@{ id="$family-$fault"; arguments=@("-$($sourceFamily)SourceScenario",$scenario,
                '-QualificationWorkerFamily',$family,'-QualificationWorkerFault',$fault) })
        }
    }
}
else {
    $cases.Add(@{id='PrivilegeDenied';arguments=@('-PrivilegeOutcome','ElevationDenied')})
    $cases.Add(@{id='PrivilegeCancelled';arguments=@('-CancelDuringPrivilege')})
    foreach ($stage in @('Identity','Resource','Network','Software','Certificate','Connectivity')) {
        $cases.Add(@{ id="Cancel-$stage"; arguments=@('-QualificationCancelAfter', $stage) })
    }
    foreach ($boundary in @('Identity','Resource','Network','Software','Certificate','Connectivity','Firmware','Administrator','Policy','System')) {
        $cases.Add(@{ id="Prohibited-$boundary"; arguments=@('-QualificationProhibited', $boundary) })
    }
}
$results = [Collections.Generic.List[object]]::new()
$failedCase=$null
$qualificationCaseError=$null
try {
    foreach ($case in $cases) {
        if ($CaseFilter -and $case.id -notlike $CaseFilter) { continue }
        $failedCase=$case.id
        $resultPath = Join-Path ([IO.Path]::GetFullPath($ResultDirectory)) "$($case.id).json"
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $arguments = @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'), '-QualificationPath', $resultPath,
            '-CandidatePath',$candidate,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256) + $case.arguments
        Invoke-QualificationTestProcess -HostPath $hostPath -Arguments $arguments
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        $results.Add([ordered]@{ id=$case.id; elapsedMilliseconds=$watch.ElapsedMilliseconds; evidence=$result })
        Write-Output "PASS: $Mode/$($case.id) in $($watch.ElapsedMilliseconds) ms."
        $failedCase=$null
    }
    if ($results.Count -eq 0) { throw 'Qualification selection matched no cases.' }
}
catch { $qualificationCaseError=$_ }
finally {
    Complete-QualificationHarness -BodyError $qualificationCaseError -RetainEvidence {
    $summaryPath = Join-Path ([IO.Path]::GetFullPath($ResultDirectory)) "$Mode-summary.json"
    [IO.File]::WriteAllText($summaryPath, ([ordered]@{ provenance=$provenance; failedCase=$failedCase; results=$results.ToArray() } | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    }
}
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
