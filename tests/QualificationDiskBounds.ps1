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

function New-QualificationDiskInstrumentation {
    param([string] $ModuleText,[string] $Root,[string] $CandidatePath,[string] $HarnessPath)
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
    $ledger=[hashtable]::Synchronized(@{Root=$fullRoot+[IO.Path]::DirectorySeparatorChar;TotalBytes=0L;Valid=$true;Claims=@{};Counts=@{}})
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
    foreach($name in @('Add-QualificationDiskReservation','Assert-QualificationDiskReservation')){
        $definition=(Get-Command $name -CommandType Function).ScriptBlock.Ast.Parent.Extent.Text
        $controllerDefinitions.Add($definition)
        $ModuleText+=[Environment]::NewLine+$definition
    }
    # A test-only extra argument shares one synchronized ledger between the
    # controller's viewing writer and the ordinary worker's assessment writers.
    $start=(Get-Command Start-StatusDeskSession -CommandType Function).ScriptBlock.Ast.Parent.Extent.Text
    foreach($anchor in @('param($Definitions, $ParameterJson, $Transport)', '.AddArgument($transport)', '. ([scriptblock]::Create($Definitions))')){
        if([regex]::Matches($start,[regex]::Escape($anchor)).Count-ne1){throw 'Qualification shared-ledger launch seam changed.'}
    }
    $start=$start.Replace('param($Definitions, $ParameterJson, $Transport)','param($Definitions, $ParameterJson, $Transport, $DiskLedger)').
        Replace('.AddArgument($transport)','.AddArgument($transport).AddArgument($script:QualificationDiskLedger)').
        Replace('. ([scriptblock]::Create($Definitions))','$script:QualificationDiskLedger=$DiskLedger; . ([scriptblock]::Create($Definitions))')
    # Derive every writer and launch seam before creating the owned root.
    $null=[IO.Directory]::CreateDirectory($fullRoot)
    [pscustomobject]@{ModuleText=$ModuleText;ControllerDefinitions=($controllerDefinitions -join [Environment]::NewLine);
        ControllerOriginalDefinitions=($originalDefinitions -join [Environment]::NewLine);ControllerStart=$start;Ledger=$ledger;actualSourceInputs=$actualSourceInputs.ToArray();sourceIdentityKind=$manifest.sourceIdentityKind;instrumentationSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'QualificationDiskBounds.ps1') -Algorithm SHA256).Hash.ToLowerInvariant();inventorySha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'qualification-resource-writers.json')).Hash.ToLowerInvariant()}
}
