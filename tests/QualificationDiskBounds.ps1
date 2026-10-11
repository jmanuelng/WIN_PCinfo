Set-StrictMode -Version Latest

function Add-QualificationDiskReservation {
    param([string] $Path, [long] $Bytes, [string] $Kind)
    $ledger=$script:QualificationDiskLedger
    $full=[IO.Path]::GetFullPath($Path)
    if($Bytes -lt 0 -or -not $full.StartsWith($ledger.Root,[StringComparison]::OrdinalIgnoreCase)) {
        $ledger.Valid=$false
        throw 'Qualification disk reservation is outside its admitted scope.'
    }
    [Threading.Monitor]::Enter($ledger.SyncRoot)
    try {
        if($Bytes -gt [long]::MaxValue-$ledger.TotalBytes){$ledger.Valid=$false;throw 'Qualification disk bound overflow.'}
        $ledger.TotalBytes=[long]$ledger.TotalBytes+$Bytes
        $ledger.Claims[$full]=$true
        if(-not $ledger.Counts.ContainsKey($Kind)){$ledger.Counts[$Kind]=[ordered]@{writes=0L;bytes=0L}}
        $ledger.Counts[$Kind].writes++
        $ledger.Counts[$Kind].bytes+=$Bytes
    } finally {[Threading.Monitor]::Exit($ledger.SyncRoot)}
}

function Assert-QualificationDiskReservation {
    param([string] $Path)
    $ledger=$script:QualificationDiskLedger
    if(-not $ledger.Claims.ContainsKey([IO.Path]::GetFullPath($Path))){
        $ledger.Valid=$false
        throw 'Qualification encountered an unaccounted owned-file writer.'
    }
}

function Get-QualificationScriptIdentity {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    $text=[IO.File]::ReadAllText($LiteralPath,[Text.UTF8Encoding]::new($false,$true))
    $cr=[string][char]13; $lf=[string][char]10
    $canonical=$text.Replace($cr+$lf,$lf).Replace($cr,$lf)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical))).ToLowerInvariant()
}

function Assert-QualificationInventoryObject {
    param($Value, [string[]] $Keys)
    if ($Value -isnot [Collections.IDictionary] -or $Value.Count -ne $Keys.Count) {
        throw 'Qualification inventory object is not closed.'
    }
    foreach ($key in $Keys) {
        if (@($Value.Keys | Where-Object { $_ -is [string] -and $_ -ceq $key }).Count -ne 1) {
            throw 'Qualification inventory property is missing or changed.'
        }
    }
}

function Get-QualificationInventoryInputPaths {
    # These are the original twenty controlled application adapters. Executor
    # evidence is bound separately and never added to application reservations.
    @(
        'tests/AssessmentQualificationSupport.ps1', 'tests/SoftwareReportAssertions.ps1',
        'tests/TestHarness.ps1', 'tests/AdditionalScopeSourceAdapters.ps1',
        'tests/CertificateSourceAdapters.ps1', 'tests/ConnectivitySourceAdapters.ps1',
        'tests/IdentitySourceAdapters.ps1', 'tests/NetworkSourceAdapters.ps1',
        'tests/PlatformSourceAdapters.ps1', 'tests/PolicySourceAdapters.ps1',
        'tests/ReadinessSourceAdapters.ps1', 'tests/RemoteSourceAdapters.ps1',
        'tests/ResourceSourceAdapters.ps1', 'tests/ResourceSourceBoundary.ps1',
        'tests/SecuritySourceAdapters.ps1', 'tests/SoftwareSourceAdapters.ps1',
        'tests/SoftwareSourceBoundary.ps1', 'tests/QualificationDiskBounds.ps1',
        'tests/QualificationWorkspaceSampling.ps1', 'tests/QualificationRecoveryFixtureProof.ps1'
    )
}

function Get-QualificationInventoryExecutorPaths {
    @(
        'tests/GeneratedApplicationNative.ps1', 'tests/GeneratedApplicationNativeSupervisor.cs',
        'tests/QualificationCleanup.ps1', 'tests/QualificationCaseAdmission.ps1',
        'tests/Invoke-TestFile.ps1', 'tests/Invoke-QualificationCase.ps1',
        'tests/Invoke-FocusedTest.ps1', 'tests/Run-Tests.ps1',
        'tests/QualificationFixtureProcess.ps1', 'tests/QualificationCapabilityProcess.ps1',
        'tests/QualificationInlineRepresentation.ps1', 'tests/QualificationRecipientViewingInterruption.ps1',
        'tests/QualificationResourceBounds.ps1', 'tests/Invoke-AssessmentSafetyQualification.ps1',
        'tests/QualificationInputLauncher.ps1'
    )
}

function Get-QualificationInventoryPathAttributes {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    [IO.File]::GetAttributes($LiteralPath)
}

function Assert-QualificationInventoryPhysicalFile {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    $path=[IO.Path]::GetFullPath($LiteralPath)
    if (-not [IO.File]::Exists($path)) { throw 'Qualification inventory physical input is missing.' }
    $ancestor=$path
    while (-not [string]::IsNullOrEmpty($ancestor)) {
        if ((Get-QualificationInventoryPathAttributes -LiteralPath $ancestor) -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Qualification inventory physical input traverses a reparse point.'
        }
        $ancestor=[IO.Path]::GetDirectoryName($ancestor)
    }
}

function Get-QualificationInventoryInputEvidence {
    param($Entries, [string[]] $ExpectedPaths, [string] $RepositoryRoot)
    if ($Entries -isnot [object[]] -or $Entries.Count -ne $ExpectedPaths.Count) {
        throw 'Qualification inventory input set is not closed.'
    }
    $records=[Collections.Generic.List[object]]::new()
    for ($index=0; $index -lt $ExpectedPaths.Count; $index++) {
        $entry=$Entries[$index]
        Assert-QualificationInventoryObject -Value $entry -Keys @('path','sha256')
        if ($entry.path -isnot [string] -or $entry.path -cne $ExpectedPaths[$index] -or
            $entry.sha256 -isnot [string] -or $entry.sha256 -cnotmatch '\A[0-9a-f]{64}\z') {
            throw 'Qualification inventory input path or digest is malformed or changed.'
        }
        $path=[IO.Path]::GetFullPath((Join-Path $RepositoryRoot $entry.path))
        Assert-QualificationInventoryPhysicalFile -LiteralPath $path
        $canonical=Get-QualificationScriptIdentity -LiteralPath $path
        if ($entry.sha256 -cne $canonical) { throw 'Qualification inventory input digest does not match its source.' }
        $records.Add([ordered]@{path=$entry.path;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()})
    }
    $records.ToArray()
}

function Assert-QualificationResourceInventoryBinding {
    param(
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter(Mandatory)] [string] $HarnessPath,
        [string] $RepositoryRoot=(Split-Path -Parent $PSScriptRoot)
    )
    $RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $manifestPath=Join-Path $RepositoryRoot 'tests/qualification-resource-writers.json'
    $operands=[ordered]@{candidateIdentityKind='RawByteSha256';harnessIdentityKind='CanonicalUtf8LfSha256';
        declaredCandidateSha256=$null;actualCandidateSha256=$null;declaredHarnessSha256=$null;actualHarnessSha256=$null}
    try {
        if (-not [IO.Directory]::Exists($RepositoryRoot) -or
            ([IO.File]::GetAttributes($RepositoryRoot) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Qualification inventory repository is missing or ambiguous.'
        }
        Assert-QualificationInventoryPhysicalFile -LiteralPath $manifestPath
        $manifest=[IO.File]::ReadAllText($manifestPath,[Text.UTF8Encoding]::new($false,$true)) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        Assert-QualificationInventoryObject -Value $manifest -Keys @(
            'kind','version','candidateSha256','harnessSha256','scope','writers','emptyCreators','excluded',
            'inputs','sourceIdentityKind','privilegedFaultWitnesses','bindingContract','executorInputScope','executorInputs'
        )
        $expectedMetadata=[ordered]@{
            kind='ControlledAssessmentClosedDiskWriterInventory';version='1.2.0';
            scope='OrdinaryControlledAssessmentWpfViewingAndFinitePrivilegedFaultWitnesses';sourceIdentityKind='CanonicalUtf8LfSha256';
            bindingContract='win-pcinfo.qualification-resource-inputs/1.0.0';
            executorInputScope='ExternalQualificationExecutionAndRetentionOutsideMeasuredApplicationWorkspace';
            excluded='Maintainer signing, publication, qualification, Azure and explicit product validation-fixture writers are outside this ordinary assessment path. RecoveryDestination and InterruptHandoffPath configurations remain inadmissible; only the three closed finite privileged fault witnesses below are admitted.'
        }
        foreach ($key in $expectedMetadata.Keys) {
            if ($manifest[$key] -isnot [string] -or $manifest[$key] -cne $expectedMetadata[$key]) {
                throw 'Qualification inventory metadata or scope is not admitted.'
            }
        }
        foreach ($key in @('candidateSha256','harnessSha256')) {
            if ($manifest[$key] -isnot [string] -or $manifest[$key] -cnotmatch '\A[0-9a-f]{64}\z') {
                throw 'Qualification inventory operand digest is malformed.'
            }
        }
        $operands.declaredCandidateSha256=$manifest.candidateSha256
        $operands.declaredHarnessSha256=$manifest.harnessSha256
        if ([IO.Path]::GetFullPath($HarnessPath) -cne [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'tests/StatusDeskEngine.Tests.ps1'))) {
            throw 'Qualification candidate or exact canonical harness file is missing or ambiguous.'
        }
        Assert-QualificationInventoryPhysicalFile -LiteralPath $CandidatePath
        Assert-QualificationInventoryPhysicalFile -LiteralPath $HarnessPath
        # Observe both operands before either comparison. The private exception
        # data exposes which comparison failed without printing raw evidence.
        $operands.actualCandidateSha256=(Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $operands.actualHarnessSha256=Get-QualificationScriptIdentity -LiteralPath $HarnessPath
        if ($operands.declaredCandidateSha256 -cne $operands.actualCandidateSha256) {
            throw 'Qualification inventory candidate raw-byte digest does not match.'
        }
        if ($operands.declaredHarnessSha256 -cne $operands.actualHarnessSha256) {
            throw 'Qualification inventory canonical harness digest does not match.'
        }
        $expectedWriters=@('Write-RunRecoveryJournal','Write-RegisteredEvidenceArtifact','Write-ProtectedPackageEnvelope',
            'Write-RecipientProfileDocument','Export-RestrictedAssessmentReport')
        $expectedEmpty=@('New-RegisteredEvidenceArtifact','New-EvidenceWorkspaceOwnedWriteStream')
        foreach ($pair in @(@{key='writers';expected=$expectedWriters},@{key='emptyCreators';expected=$expectedEmpty})) {
            $entries=$manifest[$pair.key]
            if ($entries -isnot [object[]] -or $entries.Count -ne $pair.expected.Count) { throw 'Qualification writer inventory is not closed.' }
            for ($index=0; $index -lt $entries.Count; $index++) {
                if ($entries[$index] -isnot [string] -or $entries[$index] -cne $pair.expected[$index]) { throw 'Qualification writer inventory changed.' }
            }
        }
        if ($manifest.privilegedFaultWitnesses -isnot [object[]]) { throw 'Qualification witness inventory is not an array.' }
        foreach ($entry in $manifest.privilegedFaultWitnesses) {
            Assert-QualificationInventoryObject -Value $entry -Keys @('fault','relativePath','content','encodingBound','maximumLaunches','reservationBytes')
            foreach ($key in @('fault','relativePath','content','encodingBound')) {
                if ($entry[$key] -isnot [string]) { throw 'Qualification witness identity must be a string.' }
            }
        }
        # Reuse the original descriptor owner for exact count, values and bounds.
        $null=New-QualificationWitnessDescriptor -Fault '' -Root $RepositoryRoot -Manifest $manifest
        $actualSources=@(Get-QualificationInventoryInputEvidence -Entries $manifest.inputs -ExpectedPaths (Get-QualificationInventoryInputPaths) -RepositoryRoot $RepositoryRoot)
        $actualExecutors=@(Get-QualificationInventoryInputEvidence -Entries $manifest.executorInputs -ExpectedPaths (Get-QualificationInventoryExecutorPaths) -RepositoryRoot $RepositoryRoot)
        [pscustomobject]@{Manifest=$manifest;Operands=$operands;SourceInputs=$actualSources;ExecutorInputs=$actualExecutors}
    } catch {
        $_.Exception.Data['QualificationInventoryOperands']=$operands
        throw
    }
}

function New-QualificationWitnessDescriptor {
    param([string] $Fault, [string] $Root, $Manifest)
    $expected=@(
        @{fault='PrivilegePreStartCancel';relativePath='synthetic-pre-start-hello.txt';content='SyntheticBeforeWorkerHello'}
        @{fault='PrivilegePreStartTimeout';relativePath='synthetic-pre-start-hello.txt';content='SyntheticBeforeWorkerHello'}
        @{fault='PrivilegePostStartLoss';relativePath='synthetic-post-start.txt';content='SyntheticFirmwareReturned'}
    )
    if ($Manifest.version -cne '1.2.0' -or
        $Manifest.scope -cne 'OrdinaryControlledAssessmentWpfViewingAndFinitePrivilegedFaultWitnesses') {
        throw 'Qualification witness inventory version or scope is not admitted.'
    }
    $descriptors=@($Manifest.privilegedFaultWitnesses)
    if ($descriptors.Count -ne $expected.Count) { throw 'Qualification witness inventory is not closed.' }
    foreach ($item in $expected) {
        $matches=@($descriptors | Where-Object fault -CEQ $item.fault)
        if ($matches.Count -ne 1) { throw 'Qualification witness descriptor is not unique.' }
        $entry=$matches[0]
        $bytes=[Text.Encoding]::UTF8.GetByteCount($item.content)+3L
        if ($entry.relativePath -cne $item.relativePath -or $entry.content -cne $item.content -or
            $entry.encodingBound -cne 'Utf8IncludingOptionalThreeByteBom' -or
            ($entry.maximumLaunches -isnot [int] -and $entry.maximumLaunches -isnot [long]) -or
            $entry.maximumLaunches -ne 1 -or
            ($entry.reservationBytes -isnot [int] -and $entry.reservationBytes -isnot [long]) -or
            $entry.reservationBytes -ne $bytes) { throw 'Qualification witness descriptor changed.' }
    }
    if (-not $Fault) { return $null }
    $selected=@($expected | Where-Object fault -CEQ $Fault)
    if ($selected.Count -ne 1) { throw 'Qualification witness fault is not admitted.' }
    $path=[IO.Path]::GetFullPath((Join-Path $Root $selected[0].relativePath))
    [ordered]@{Fault=$Fault;Path=$path;Content=$selected[0].content;
        ReservationBytes=([Text.Encoding]::UTF8.GetByteCount($selected[0].content)+3L);LaunchAdmissions=0L}
}

function Invoke-QualificationWitnessAdmission {
    param([string] $TemplateSource, [string] $LaunchSource, [string] $ConfigurationLiteral)
    $ledger=$script:QualificationDiskLedger
    [Threading.Monitor]::Enter($ledger.SyncRoot)
    try {
        $witness=$ledger.Witness
        if ($null -eq $witness -or
            ($witness.LaunchAdmissions -isnot [int] -and $witness.LaunchAdmissions -isnot [long]) -or
            $witness.LaunchAdmissions -ne 0 -or -not $ledger.Valid) {
            throw 'Qualification witness launch is absent, repeated, or invalid.'
        }
        $preStart=$witness.Fault -cin @('PrivilegePreStartCancel','PrivilegePreStartTimeout')
        if (-not $preStart -and $witness.Fault -cne 'PrivilegePostStartLoss') {
            throw 'Qualification witness launch mode changed.'
        }
        $relative=if ($preStart) { 'synthetic-pre-start-hello.txt' } else { 'synthetic-post-start.txt' }
        $content=if ($preStart) { 'SyntheticBeforeWorkerHello' } else { 'SyntheticFirmwareReturned' }
        $path=[IO.Path]::GetFullPath((Join-Path $ledger.Root $relative))
        $bytes=[Text.Encoding]::UTF8.GetByteCount($content)+3L
        if ($witness.Path -cne $path -or $witness.Content -cne $content -or
            ($witness.ReservationBytes -isnot [int] -and $witness.ReservationBytes -isnot [long]) -or
            $witness.ReservationBytes -ne $bytes -or
            -not $path.StartsWith($ledger.Root,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Qualification witness launch descriptor changed.'
        }
        $generator=if ($preStart) { 'Get-PreStartOriginalPrivilegeWorkerSource' } else { 'Get-LossOriginalPrivilegeWorkerSource' }
        $generatorCommand=Get-Command -Name $generator -CommandType Function -ErrorAction Stop
        $original=& $generatorCommand
        $write='[IO.File]::WriteAllText('''+$path.Replace("'","''")+''','''+$content+''')'
        if ($preStart) {
            $hello='Write-Frame -Stream $pipe -Json $hello -MaximumBytes $maximumBytes -Token $tokenSource.Token'
            if ([regex]::Matches($original,[regex]::Escape($hello)).Count -ne 1) {
                throw 'Qualification witness hello anchor changed.'
            }
            $expected=$original.Replace($hello,$write+'; [Threading.Thread]::Sleep(30000); '+$hello)
        } else {
            $early='if ($configuration.workerFault -eq ''ExitAfterHello'') { exit 71 }'
            $collected='New-SyntheticFirmwareResult -Scenario ([string]$configuration.firmwareScenario)'
            foreach ($anchor in @($early,$collected)) {
                if ([regex]::Matches($original,[regex]::Escape($anchor)).Count -ne 1) {
                    throw 'Qualification witness post-start anchor changed.'
                }
            }
            $expected=$original.Replace($early,'').Replace($collected,'$null = '+$collected+'; '+$write+'; exit 71')
        }
        $lf=[string][char]10; $cr=[string][char]13
        $expected=$expected.Replace($cr+$lf,$lf).Replace($cr,$lf)
        $marker='__PRIVILEGED_WORKER_CONFIGURATION__'
        if ([regex]::Matches($expected,[regex]::Escape($marker)).Count -ne 1 -or
            -not [StringComparer]::Ordinal.Equals($expected,$TemplateSource) -or
            -not [StringComparer]::Ordinal.Equals($expected.Replace($marker,$ConfigurationLiteral),$LaunchSource)) {
            throw 'Qualification witness emitted worker source changed.'
        }
        # Reserve before the one admitted launch, even if launch or the write
        # later fails. Source generation and policy digest calls have no writes.
        $witness.LaunchAdmissions=1L
        Add-QualificationDiskReservation -Path $path -Bytes $bytes -Kind PrivilegedFaultWitness
    } catch {
        # A product fault reducer may map this exception to expected worker loss.
        # The independently checked ledger must still disqualify that evidence.
        $ledger.Valid=$false
        throw
    } finally { [Threading.Monitor]::Exit($ledger.SyncRoot) }
}

function Get-QualificationFunctionDefinition {
    param([Parameter(Mandatory)] [string] $Name)
    $commands=@(Get-Command -Name $Name -CommandType Function -ErrorAction Stop)
    if($commands.Count-ne1-or$commands[0].Name-cne$Name){throw 'Qualification function identity is not exact.'}
    $node=$commands[0].ScriptBlock.Ast
    if($node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq$Name){
        return $node.Extent.Text
    }
    if($node.Parent-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Parent.Name-ceq$Name){
        return $node.Parent.Extent.Text
    }
    throw 'Qualification function AST ownership is not admitted.'
}

function New-QualificationDiskInstrumentation {
    param([string] $ModuleText,[string] $Root,[string] $CandidatePath,[string] $HarnessPath, [string] $WitnessFault = '')
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $binding=Assert-QualificationResourceInventoryBinding -CandidatePath $CandidatePath -HarnessPath $HarnessPath -RepositoryRoot $repositoryRoot
    $manifest=$binding.Manifest
    $actualSourceInputs=[Collections.Generic.List[object]]::new()
    $actualSourceInputs.Add([ordered]@{path='tests/StatusDeskEngine.Tests.ps1';sha256=(Get-FileHash -LiteralPath $HarnessPath -Algorithm SHA256).Hash.ToLowerInvariant()})
    foreach ($input in $binding.SourceInputs) { $actualSourceInputs.Add($input) }
    $fullRoot=[IO.Path]::GetFullPath($Root)
    if([IO.File]::Exists($fullRoot) -or
        ([IO.Directory]::Exists($fullRoot) -and [IO.Directory]::EnumerateFileSystemEntries($fullRoot).GetEnumerator().MoveNext())){
        throw 'Qualification requires a new or verified empty owned output root.'
    }
    if([IO.Directory]::Exists($fullRoot) -and ([IO.File]::GetAttributes($fullRoot) -band [IO.FileAttributes]::ReparsePoint)-ne0){
        throw 'Qualification refuses an output root with a reparse point.'
    }
    $witness=New-QualificationWitnessDescriptor -Fault $WitnessFault -Root $fullRoot -Manifest $manifest
    $ledger=[hashtable]::Synchronized(@{Root=$fullRoot+[IO.Path]::DirectorySeparatorChar;TotalBytes=0L;Valid=$true;Claims=@{};Counts=@{};Witness=$witness})
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($ModuleText,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Qualification writer source does not parse.'}
    $controllerDefinitions=[Collections.Generic.List[string]]::new()
    $originalDefinitions=[Collections.Generic.List[string]]::new()
    $rules=@(
        @{name='Write-RunRecoveryJournal';anchor='$stream.Write($bytes, 0, $bytes.Length)';reservation='Add-QualificationDiskReservation -Path $temporaryPath -Bytes $bytes.Length -Kind Journal'}
        @{name='Write-RegisteredEvidenceArtifact';anchor='$stream.Write($Content, 0, $Content.Length)';reservation='Add-QualificationDiskReservation -Path ([string]$artifact[0].path) -Bytes $Content.Length -Kind RegisteredArtifact'}
        @{name='Write-ProtectedPackageEnvelope';anchor='$stream = New-EvidenceWorkspaceOwnedWriteStream -LiteralPath $LiteralPath';reservation='Add-QualificationDiskReservation -Path $LiteralPath -Bytes ([Text.Encoding]::ASCII.GetByteCount([string]$policy.envelope.magic)+4L+$headerBytes.Length+$Plaintext.Length+40L*$chunkCount) -Kind ProtectedPackage'}
        @{name='Write-RecipientProfileDocument';anchor='$stream = New-EvidenceWorkspaceOwnedWriteStream -LiteralPath $temporaryPath';reservation='Add-QualificationDiskReservation -Path $temporaryPath -Bytes $bytes.Length -Kind RecipientProfile'}
        @{name='Export-RestrictedAssessmentReport';anchor='$stream = New-EvidenceWorkspaceOwnedWriteStream -LiteralPath $partialPath';reservation='Add-QualificationDiskReservation -Path $partialPath -Bytes ([long]$bannerBytes.Length+$reportBytes.Length) -Kind RestrictedExport'}
        @{name='New-EvidenceWorkspaceOwnedWriteStream';anchor='Initialize-EvidenceWorkspaceNative';reservation='Assert-QualificationDiskReservation -Path $LiteralPath'}
    )
    foreach($rule in $rules){
        $matches=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $rule.name}.GetNewClosure(),$false))
        if($matches.Count-ne1){throw 'Qualification writer function is not unique.'}
        $original=$matches[0].Extent.Text
        $originalDefinitions.Add($original)
        if([regex]::Matches($original,[regex]::Escape($rule.anchor)).Count-ne1){throw 'Qualification writer mutation anchor changed.'}
        $changed=$original.Replace($rule.anchor,$rule.reservation+'; '+$rule.anchor)
        $ModuleText=$ModuleText.Replace($original,$changed)
        $controllerDefinitions.Add($changed)
    }
    if ($null -ne $witness) {
        $controllers=@($ast.FindAll({param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-ControlledPrivilegedCollectionPlan'
        },$false))
        if ($controllers.Count -ne 1) { throw 'Qualification witness controller is not unique.' }
        $originalController=$controllers[0].Extent.Text
        $launch='try { $worker = [System.Diagnostics.Process]::Start($startInfo) }'
        if ([regex]::Matches($originalController,[regex]::Escape($launch)).Count -ne 1) {
            throw 'Qualification witness process launch anchor changed.'
        }
        $admission='Invoke-QualificationWitnessAdmission -TemplateSource $workerSource -LaunchSource $launchWorkerSource -ConfigurationLiteral $configurationLiteral; '
        $ModuleText=$ModuleText.Replace($originalController,$originalController.Replace($launch,$admission+$launch))
    }
    foreach($name in @('Add-QualificationDiskReservation','Assert-QualificationDiskReservation','Invoke-QualificationWitnessAdmission')){
        $definition=Get-QualificationFunctionDefinition -Name $name
        $controllerDefinitions.Add($definition)
        $ModuleText+=[Environment]::NewLine+$definition
    }
    # A test-only extra argument shares one synchronized ledger between the
    # controller's viewing writer and the ordinary worker's assessment writers.
    $start=Get-QualificationFunctionDefinition -Name 'Initialize-StatusDeskWorker'
    foreach($anchor in @('param($Definitions, $ParameterJson, $Transport)', '.AddArgument($transport)', '. $Definitions')){
        if([regex]::Matches($start,[regex]::Escape($anchor)).Count-ne1){throw 'Qualification shared-ledger launch seam changed.'}
    }
    $start=$start.Replace('param($Definitions, $ParameterJson, $Transport)','param($Definitions, $ParameterJson, $Transport, $DiskLedger)').
        Replace('.AddArgument($transport)','.AddArgument($transport).AddArgument($script:QualificationDiskLedger)').
        Replace('. $Definitions','$script:QualificationDiskLedger=$DiskLedger; . $Definitions')
    # Parse the final controlled worker only after all reservations, witness
    # admission and helpers have been inserted. The earlier inventory AST is
    # deliberately not reused: its definitions would bypass instrumentation.
    # This setup parse remains included in native lifetime resource budgets.
    $ast=$null; $tokens=$null; $errors=$null
    $controlledAst=[Management.Automation.Language.Parser]::ParseInput($ModuleText,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Final controlled qualification definitions do not parse.'}
    $definitionInitializer=$controlledAst.GetScriptBlock()
    # Derive every writer and launch seam before creating the owned root.
    $null=[IO.Directory]::CreateDirectory($fullRoot)
    [pscustomobject]@{ModuleText=$ModuleText;DefinitionInitializer=$definitionInitializer;ControllerDefinitions=($controllerDefinitions -join [Environment]::NewLine);
        ControllerOriginalDefinitions=($originalDefinitions -join [Environment]::NewLine);ControllerWorker=$start;Ledger=$ledger;actualSourceInputs=$actualSourceInputs.ToArray();actualExecutorInputs=$binding.ExecutorInputs;inventoryOperands=$binding.Operands;sourceIdentityKind=$manifest.sourceIdentityKind;instrumentationSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'QualificationDiskBounds.ps1') -Algorithm SHA256).Hash.ToLowerInvariant();inventorySha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'qualification-resource-writers.json')).Hash.ToLowerInvariant()}
}
