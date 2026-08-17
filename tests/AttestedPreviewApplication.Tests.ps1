[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Set-ZipEntryBytes {
    param(
        [Parameter(Mandatory)] [string] $ZipPath,
        [Parameter(Mandatory)] [string] $EntryName,
        [Parameter(Mandatory)] [byte[]] $Bytes
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::Open($ZipPath, 'Update')
    try {
        $existing = $archive.GetEntry($EntryName)
        if ($null -ne $existing) {
            $existing.Delete()
        }
        $created = $archive.CreateEntry($EntryName, [System.IO.Compression.CompressionLevel]::NoCompression)
        $stream = $created.Open()
        try {
            $stream.Write($Bytes, 0, $Bytes.Length)
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Get-ZipEntryBytes {
    param(
        [Parameter(Mandatory)] [string] $ZipPath,
        [Parameter(Mandatory)] [string] $EntryName
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entry = $archive.GetEntry($EntryName)
        $stream = $entry.Open()
        try {
            $memory = [System.IO.MemoryStream]::new()
            $stream.CopyTo($memory)
            , [byte[]] $memory.ToArray()
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
}

$workRoot = Join-Path $repositoryRoot '.test-output/attested-preview-application'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force

$appPath = Join-Path $workRoot 'WIN-PCInfo.ps1'
$build = & (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $appPath
$zipPath = Join-Path $workRoot ([string] $build.portablePackage.archiveFileName)
$bundle = & (Join-Path $repositoryRoot 'build/Attest-Preview.ps1') `
    -FallbackReason 'ArtifactSigningNotOperational' `
    -CandidateArchivePath $zipPath `
    -OutputDirectory (Join-Path $workRoot 'bundle')
$archiveRoot = [string] $build.portablePackage.unpackedRootName

$verified = Invoke-GeneratedApplication -CandidatePath $appPath -Arguments @(
    '-Workflow', 'VerifyAttestation',
    '-AttestationBundlePath', $bundle.bundleDirectory,
    '-CandidateArchivePath', $zipPath
)
Assert-Equal 0 $verified.ExitCode 'clean Attested Preview verification succeeds'
Assert-Equal 'win-pcinfo.limited-trust-warning' $verified.Records[0].recordType `
    'the operator sees the unsigned limited-trust warning before any other record'
Assert-Equal $true ($verified.Records[0].title -match 'UNSIGNED LIMITED-TRUST WARNING') `
    'the warning banner is unmistakable'
Assert-Equal $false $verified.Records[0].trusted 'the warning is not Trusted'
Assert-Equal $false $verified.Records[0].signed 'the warning is not signed'
Assert-Equal $false $verified.Records[0].supported 'the warning is not Supported'
Assert-Equal $false $verified.Records[0].satisfiesStableSigningGate `
    'the warning cannot satisfy the Stable signing gate'

$record = @($verified.Records | Where-Object recordType -eq 'win-pcinfo.attested-preview-verification')
$terminal = @($verified.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
Assert-Equal 1 $record.Count 'verification emits one attestation record'
Assert-Equal 'Verified' $record[0].state 'the clean bundle is Verified'
Assert-Equal 'ATTESTATION.VERIFIED' $record[0].reasonCode 'the verified reason is stable'
Assert-Equal 'AttestedPreview' $record[0].trustClass 'verification restates Attested Preview'
Assert-Equal $true $record[0].unsigned 'verification restates unsigned'
Assert-Equal $true $record[0].limitedTrust 'verification restates limited-trust'
Assert-Equal $false $record[0].signed 'verification is not signed'
Assert-Equal $false $record[0].trusted 'verification is not Trusted'
Assert-Equal $false $record[0].supported 'verification is not Supported'
Assert-Equal $false $record[0].satisfiesStableSigningGate `
    'verification cannot satisfy the Stable signing gate'
Assert-Equal 'None' $record[0].supportClaim 'verification makes no support claim'
Assert-Equal $build.portablePackageIdentity.sha256 $record[0].candidateSha256 `
    'verification restates the exact candidate digest'
Assert-Equal $build.generatedContentIdentity.sha256 $record[0].generatedApplicationSha256 `
    'verification restates the generated application digest'
Assert-Equal $build.portablePackage.sourceRevisionSha256 $record[0].sourceRevisionSha256 `
    'verification restates the source revision'
Assert-Equal $true $record[0].eligibleForLaterSmokeOrValidation `
    'only the exact verified candidate may proceed to later smoke or validation'
Assert-Equal $false $record[0].collectionStarted 'verification never starts collection'
Assert-Equal $false ($record[0].PSObject.Properties.Name -contains 'bundlePath') `
    'verification does not expose a local bundle path'
Assert-Equal $false ($record[0].PSObject.Properties.Name -contains 'archivePath') `
    'verification does not expose a local archive path'
Assert-Equal 1 $terminal.Count 'verification ends with one terminal record'
Assert-Equal 'Completed' $terminal[0].outcome 'verified attestation is Completed'
Assert-Equal 'ATTESTATION.VERIFIED' $terminal[0].reasonCode 'the terminal uses the verified reason'
Assert-Equal $true ($record[0].guidance.nextStep -match 'unsigned') `
    'verified guidance keeps the limited-trust reminder'

$missing = Invoke-GeneratedApplication -CandidatePath $appPath -Arguments @(
    '-Workflow', 'VerifyAttestation'
)
Assert-Equal 20 $missing.ExitCode 'missing attestation inputs fail closed'
Assert-Equal 'win-pcinfo.limited-trust-warning' $missing.Records[0].recordType `
    'the warning still appears when inputs are missing'
Assert-Equal 'NotStarted' $missing.Records[-1].outcome 'missing inputs stay NotStarted'
Assert-Equal 'ATTESTATION.INPUT_INVALID' $missing.Records[-1].reasonCode `
    'missing inputs use the stable input reason'
Assert-Equal $false $missing.Records[-1].collectionStarted 'missing inputs never start collection'

$mutations = @(
    @{
        Class = 'application'
        Reason = 'ATTESTATION.APPLICATION_ALTERED'
        Action = {
            param($Zip, $AttestationPath)
            $entry = "$archiveRoot/WIN-PCInfo.ps1"
            $original = Get-ZipEntryBytes -ZipPath $Zip -EntryName $entry
            $tampered = [byte[]]::new($original.Length + 1)
            [System.Buffer]::BlockCopy($original, 0, $tampered, 0, $original.Length)
            $tampered[$tampered.Length - 1] = 0x0A
            Set-ZipEntryBytes -ZipPath $Zip -EntryName $entry -Bytes $tampered
        }
    }
    @{
        Class = 'resource'
        Reason = 'ATTESTATION.RESOURCE_ALTERED'
        Action = {
            param($Zip, $AttestationPath)
            $entry = "$archiveRoot/schemas/assessment-record.schema.json"
            $original = Get-ZipEntryBytes -ZipPath $Zip -EntryName $entry
            $tampered = [byte[]]::new($original.Length)
            [System.Buffer]::BlockCopy($original, 0, $tampered, 0, $original.Length)
            $tampered[[Math]::Min(32, $tampered.Length - 1)] =
                [byte] (($tampered[[Math]::Min(32, $tampered.Length - 1)] + 1) -band 0xFF)
            Set-ZipEntryBytes -ZipPath $Zip -EntryName $entry -Bytes $tampered
        }
    }
    @{
        Class = 'manifest'
        Reason = 'ATTESTATION.MANIFEST_ALTERED'
        Action = {
            param($Zip, $AttestationPath)
            $entry = "$archiveRoot/package-manifest.json"
            $original = Get-ZipEntryBytes -ZipPath $Zip -EntryName $entry
            $tampered = [byte[]]::new($original.Length)
            [System.Buffer]::BlockCopy($original, 0, $tampered, 0, $original.Length)
            $tampered[[Math]::Min(16, $tampered.Length - 1)] =
                [byte] (($tampered[[Math]::Min(16, $tampered.Length - 1)] + 1) -band 0xFF)
            Set-ZipEntryBytes -ZipPath $Zip -EntryName $entry -Bytes $tampered
        }
    }
    @{
        Class = 'checksum'
        Reason = 'ATTESTATION.CHECKSUM_ALTERED'
        Action = {
            param($Zip, $AttestationPath)
            $entry = "$archiveRoot/checksums.sha256"
            $original = Get-ZipEntryBytes -ZipPath $Zip -EntryName $entry
            $tampered = [byte[]]::new($original.Length)
            [System.Buffer]::BlockCopy($original, 0, $tampered, 0, $original.Length)
            $tampered[0] = [byte] (($tampered[0] + 1) -band 0xFF)
            Set-ZipEntryBytes -ZipPath $Zip -EntryName $entry -Bytes $tampered
        }
    }
    @{
        Class = 'provenance'
        Reason = 'ATTESTATION.PROVENANCE_ALTERED'
        Action = {
            param($Zip, $AttestationPath)
            $entry = "$archiveRoot/provenance.json"
            $original = Get-ZipEntryBytes -ZipPath $Zip -EntryName $entry
            $tampered = [byte[]]::new($original.Length)
            [System.Buffer]::BlockCopy($original, 0, $tampered, 0, $original.Length)
            $tampered[[Math]::Min(20, $tampered.Length - 1)] =
                [byte] (($tampered[[Math]::Min(20, $tampered.Length - 1)] + 1) -band 0xFF)
            Set-ZipEntryBytes -ZipPath $Zip -EntryName $entry -Bytes $tampered
        }
    }
    @{
        Class = 'source-revision'
        Reason = 'ATTESTATION.SOURCE_REVISION_ALTERED'
        Action = {
            param($Zip, $AttestationPath)
            $attestation = Get-Content -LiteralPath $AttestationPath -Raw | ConvertFrom-Json -Depth 20
            $attestation.sourceRevision.sha256 = '0' * 64
            $json = $attestation | ConvertTo-Json -Compress -Depth 40
            [System.IO.File]::WriteAllBytes(
                $AttestationPath,
                [System.Text.UTF8Encoding]::new($false).GetBytes($json)
            )
        }
    }
    @{
        Class = 'dependency-inventory'
        Reason = 'ATTESTATION.DEPENDENCY_INVENTORY_ALTERED'
        Action = {
            param($Zip, $AttestationPath)
            $entry = "$archiveRoot/dependency-inventory.json"
            $original = Get-ZipEntryBytes -ZipPath $Zip -EntryName $entry
            $tampered = [byte[]]::new($original.Length)
            [System.Buffer]::BlockCopy($original, 0, $tampered, 0, $original.Length)
            $tampered[[Math]::Min(24, $tampered.Length - 1)] =
                [byte] (($tampered[[Math]::Min(24, $tampered.Length - 1)] + 1) -band 0xFF)
            Set-ZipEntryBytes -ZipPath $Zip -EntryName $entry -Bytes $tampered
        }
    }
)

foreach ($mutation in $mutations) {
    $mutationRoot = Join-Path $workRoot "mutate-$($mutation.Class)"
    $null = New-Item -ItemType Directory -Path $mutationRoot -Force
    $mutatedZip = Join-Path $mutationRoot ([string] $build.portablePackage.archiveFileName)
    Copy-Item -LiteralPath $zipPath -Destination $mutatedZip
    $mutatedBundle = Join-Path $mutationRoot 'bundle'
    Copy-Item -LiteralPath $bundle.bundleDirectory -Destination $mutatedBundle -Recurse
    $mutatedAttestation = Join-Path $mutatedBundle 'attestation.json'
    & $mutation.Action $mutatedZip $mutatedAttestation

    $verify = Invoke-GeneratedApplication -CandidatePath $appPath -Arguments @(
        '-Workflow', 'VerifyAttestation',
        '-AttestationBundlePath', $mutatedBundle,
        '-CandidateArchivePath', $mutatedZip
    )
    Assert-Equal 20 $verify.ExitCode "mutating $($mutation.Class) fails attestation verification"
    Assert-Equal 'win-pcinfo.limited-trust-warning' $verify.Records[0].recordType `
        "mutating $($mutation.Class) still shows the limited-trust warning"
    Assert-Equal 'NotStarted' $verify.Records[-1].outcome `
        "mutating $($mutation.Class) stays NotStarted"
    Assert-Equal $mutation.Reason $verify.Records[-1].reasonCode `
        "mutating $($mutation.Class) has a typed rejection"
    $rejected = @($verify.Records | Where-Object recordType -eq 'win-pcinfo.attested-preview-verification')
    Assert-Equal 1 $rejected.Count "mutating $($mutation.Class) emits a rejection record"
    Assert-Equal 'Rejected' $rejected[0].state "mutating $($mutation.Class) is Rejected"
    Assert-Equal $false $rejected[0].eligibleForLaterSmokeOrValidation `
        "mutating $($mutation.Class) cannot proceed to later smoke or validation"
    Assert-Equal $false $verify.Records[-1].collectionStarted `
        "mutating $($mutation.Class) never starts collection"

    $fixture = Invoke-GeneratedApplication -CandidatePath $appPath -Arguments @(
        '-Workflow', 'VerifyAttestation',
        '-AttestationBundlePath', $mutatedBundle,
        '-CandidateArchivePath', $mutatedZip,
        '-Mode', 'Automation',
        '-RequestPath', (Join-Path $PSScriptRoot 'fixtures/automation-request.json'),
        '-AcceptPreparation',
        '-PreparationFixturePath', (Join-Path $PSScriptRoot 'fixtures/preparation-ready.json')
    )
    Assert-Equal 20 $fixture.ExitCode "a preparation fixture cannot override a mutated $($mutation.Class)"
    Assert-Equal $mutation.Reason $fixture.Records[-1].reasonCode `
        "fixtures cannot authenticate a mutated $($mutation.Class)"
}

$missingEntryRoot = Join-Path $workRoot 'mutate-missing-inventory'
$null = New-Item -ItemType Directory -Path $missingEntryRoot -Force
$missingZip = Join-Path $missingEntryRoot ([string] $build.portablePackage.archiveFileName)
Copy-Item -LiteralPath $zipPath -Destination $missingZip
Add-Type -AssemblyName System.IO.Compression.FileSystem
$missingArchive = [System.IO.Compression.ZipFile]::Open($missingZip, 'Update')
try {
    $missingArchive.GetEntry("$archiveRoot/dependency-inventory.json").Delete()
}
finally {
    $missingArchive.Dispose()
}
$missingBundle = Join-Path $missingEntryRoot 'bundle'
Copy-Item -LiteralPath $bundle.bundleDirectory -Destination $missingBundle -Recurse
$missingResult = Invoke-GeneratedApplication -CandidatePath $appPath -Arguments @(
    '-Workflow', 'VerifyAttestation',
    '-AttestationBundlePath', $missingBundle,
    '-CandidateArchivePath', $missingZip
)
Assert-Equal 20 $missingResult.ExitCode 'a missing bound input fails closed'
Assert-Equal 'ATTESTATION.MISSING_INPUT' $missingResult.Records[-1].reasonCode `
    'a missing bound input has a typed missing reason'

foreach ($fixtureName in @(
    'attestation-forbidden-trusted.json',
    'attestation-convenience-fallback.json',
    'attestation-stable-signing-true.json'
)) {
    $fixtureRoot = Join-Path $workRoot ("fixture-" + [System.IO.Path]::GetFileNameWithoutExtension($fixtureName))
    $null = New-Item -ItemType Directory -Path $fixtureRoot -Force
    $fixtureZip = Join-Path $fixtureRoot ([string] $build.portablePackage.archiveFileName)
    Copy-Item -LiteralPath $zipPath -Destination $fixtureZip
    $fixtureBundle = Join-Path $fixtureRoot 'bundle'
    Copy-Item -LiteralPath $bundle.bundleDirectory -Destination $fixtureBundle -Recurse
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "fixtures/$fixtureName") `
        -Destination (Join-Path $fixtureBundle 'attestation.json') -Force
    $expectedReason = if ($fixtureName -eq 'attestation-convenience-fallback.json') {
        'ATTESTATION.FALLBACK_REASON_INVALID'
    }
    elseif ($fixtureName -eq 'attestation-stable-signing-true.json') {
        'ATTESTATION.STABLE_SIGNING_UNSATISFIED'
    }
    else {
        'ATTESTATION.FORBIDDEN_CLAIM'
    }
    $fixtureResult = Invoke-GeneratedApplication -CandidatePath $appPath -Arguments @(
        '-Workflow', 'VerifyAttestation',
        '-AttestationBundlePath', $fixtureBundle,
        '-CandidateArchivePath', $fixtureZip
    )
    Assert-Equal 20 $fixtureResult.ExitCode "$fixtureName is rejected"
    Assert-Equal $expectedReason $fixtureResult.Records[-1].reasonCode `
        "$fixtureName has the typed claim or governance rejection"
    $rejected = @($fixtureResult.Records | Where-Object recordType -eq 'win-pcinfo.attested-preview-verification')
    Assert-Equal $false $rejected[0].eligibleForLaterSmokeOrValidation `
        "$fixtureName cannot proceed to later smoke or validation"
    Assert-Equal $false $rejected[0].satisfiesStableSigningGate `
        "$fixtureName still cannot satisfy the Stable signing gate"
}

$docs = @(
    Get-Content -LiteralPath (Join-Path $repositoryRoot 'docs/attested-preview.md') -Raw
    Get-Content -LiteralPath (Join-Path $repositoryRoot 'docs/guided-runway.md') -Raw
)
$corpus = $docs -join "`n"
Assert-Equal $true ($corpus -match 'UNSIGNED LIMITED-TRUST WARNING') `
    'release documentation repeats the unmistakable warning'
Assert-Equal $true (($corpus -match 'never') -and ($corpus -match 'convenience')) `
    'release documentation forbids convenience fallback'
Assert-Equal $true ($corpus -match 'cannot satisfy the Stable signing gate') `
    'release documentation refuses the Stable signing gate'
Assert-Equal $false ($corpus -match 'Authenticode signing is complete') `
    'documentation does not claim signing is complete'
Assert-Equal $false ($corpus -match 'this release is Supported') `
    'documentation does not claim the release is Supported'

Write-Output 'PASS: Attested Preview verification warns, binds the candidate, and rejects every tamper class.'
