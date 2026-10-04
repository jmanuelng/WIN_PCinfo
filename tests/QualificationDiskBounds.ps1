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
    $manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'qualification-resource-writers.json') -Raw|ConvertFrom-Json
    if($manifest.sourceIdentityKind-cne'CanonicalUtf8LfSha256' -or
        $manifest.candidateSha256-ne(Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $manifest.harnessSha256-ne(Get-QualificationScriptIdentity -LiteralPath $HarnessPath)){
        throw 'Qualification write inventory does not match this exact candidate and harness.'
    }
    $actualSourceInputs=[Collections.Generic.List[object]]::new()
    $actualSourceInputs.Add([ordered]@{path='tests/StatusDeskEngine.Tests.ps1';sha256=(Get-FileHash -LiteralPath $HarnessPath -Algorithm SHA256).Hash.ToLowerInvariant()})
    foreach($input in $manifest.inputs){
        $inputPath=Join-Path $repositoryRoot $input.path
        if($input.sha256-ne(Get-QualificationScriptIdentity -LiteralPath $inputPath)){
            throw 'Qualification write inventory does not match a controlled adapter.'
        }
        $actualSourceInputs.Add([ordered]@{path=[string]$input.path;sha256=(Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant()})
    }
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
    $start=Get-QualificationFunctionDefinition -Name 'Start-StatusDeskSession'
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
        ControllerOriginalDefinitions=($originalDefinitions -join [Environment]::NewLine);ControllerStart=$start;Ledger=$ledger;actualSourceInputs=$actualSourceInputs.ToArray();sourceIdentityKind=$manifest.sourceIdentityKind;instrumentationSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'QualificationDiskBounds.ps1') -Algorithm SHA256).Hash.ToLowerInvariant();inventorySha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'qualification-resource-writers.json')).Hash.ToLowerInvariant()}
}
