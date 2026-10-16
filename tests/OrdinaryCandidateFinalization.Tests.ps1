[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$fixture=Join-Path $repositoryRoot ('.test-output/ordinary-finalization-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($fixture)
$previousSpy=Get-Variable OrdinaryFinalizationSpy -Scope Global -ErrorAction SilentlyContinue
$previousCounter=Get-Variable OrdinaryFinalizationCounter -Scope Global -ErrorAction SilentlyContinue
$checks=0
function Get-FinalizationSyntax([string]$Text) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Ordinary finalization fixture does not parse.'}
    $ast
}
function Get-FinalizationMessageSites($Body) {
    @($Body.FindAll({param($node)
        ($node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName()-ceq 'Write-Output' -and $node.CommandElements.Count-eq 2 -and
            $node.CommandElements[1].Value-clike 'PASS:*') -or
        ($node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and
            $node.Expression.Extent.Text-ceq '$candidateSuccessMessages' -and $node.Member.Extent.Text-ceq 'Add' -and
            $node.Arguments.Count-eq 1 -and $node.Arguments[0].Value-clike 'PASS:*')
    },$true))
}
function Assert-FinalizationMessageOperand($Operand) {
    if($Operand -is [Management.Automation.Language.StringConstantExpressionAst]){return 'Literal'}
    if($Operand -isnot [Management.Automation.Language.ExpandableStringExpressionAst]){throw 'Success message operand is outside the closed replay contract.'}
    $kind='Literal'
    foreach($expression in $Operand.NestedExpressions){
        if($expression -is [Management.Automation.Language.VariableExpressionAst] -and
            $expression.VariablePath.UserPath -cin @('name','culture')){
            $current=if($expression.VariablePath.UserPath-ceq 'name'){'Name'}else{'Culture'}
        }
        elseif($expression -is [Management.Automation.Language.SubExpressionAst] -and
            $expression.Extent.Text-ceq '$($matrix.Count)'){
            # Exact AST spelling admits one non-static matrix Count member;
            # every other subexpression/command/assignment/invocation refuses.
            $current='Matrix'
        }
        else {throw 'Success message interpolation contains an unadmitted expression.'}
        if($kind-cne 'Literal' -and $kind-cne $current){throw 'Success message mixes identity profiles.'}
        $kind=$current
    }
    $kind
}
function Get-FinalizationConditionExpression($Pipeline) {
    if($Pipeline -isnot [Management.Automation.Language.PipelineAst] -or $Pipeline.Background -or
        $Pipeline.PipelineElements.Count-ne 1 -or
        $Pipeline.PipelineElements[0] -isnot [Management.Automation.Language.CommandExpressionAst] -or
        $Pipeline.PipelineElements[0].Redirections.Count-ne 0){throw 'Identity loop is outside the closed expression contract.'}
    $Pipeline.PipelineElements[0].Expression
}
function Get-FinalizationArrayExpression($Array) {
    if($Array -isnot [Management.Automation.Language.ArrayExpressionAst] -or
        $Array.SubExpression.Statements.Count-ne 1 -or
        ($null-ne $Array.SubExpression.Traps -and $Array.SubExpression.Traps.Count-ne 0)){throw 'Identity loop must use one closed array expression.'}
    Get-FinalizationConditionExpression $Array.SubExpression.Statements[0]
}
function Get-FinalizationLiteralValues($Array,[switch]$Culture) {
    $expression=Get-FinalizationArrayExpression $Array
    $elements=if($expression -is [Management.Automation.Language.ArrayLiteralAst]){$expression.Elements}else{@($expression)}
    foreach($element in $elements){
        if($element -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'Identity array contains a non-literal expression.'}
        $pattern=if($Culture){'^[A-Za-z]{2,3}-[A-Za-z0-9]{2,8}$'}else{'^[A-Za-z][A-Za-z0-9-]*$'}
        if([string]$element.Value -cnotmatch $pattern){throw 'Identity literal is outside the closed named identity contract.'}
        [string]$element.Value
    }
}
function Assert-FinalizationOwnerSyntax($Ast,$Open,$Outer) {
    $statements=@($Ast.EndBlock.Statements)
    $index=[array]::IndexOf($statements,$Open)
    $retained=@($statements|Select-Object -Skip $index)
    if($index-lt 0 -or $retained.Count-ne 6 -or $retained[4]-ne $Outer){throw 'Reader retained prefix/suffix contains unexpected executable statements.'}
    $normalized=@($retained|ForEach-Object {$_.Extent.Text -replace '[\s`]+',''})
    if($normalized[0]-cne '$candidateContext=Open-TestCandidate-RepositoryRoot$repositoryRoot-CandidatePath$CandidatePath-PreparedManifestPath$PreparedManifestPath-PreparedManifestSha256$PreparedManifestSha256' -or
        $normalized[1]-cnotmatch '^\$(candidate|candidatePath|application)=\$candidateContext\.Path$' -or
        $normalized[2]-cne '$candidateSuccessMessages=[Collections.Generic.List[string]]::new()' -or
        $normalized[3]-cne '$candidateUseError=$null' -or
        $Outer.CatchClauses.Count-ne 1 -or
        ($Outer.CatchClauses[0].Extent.Text -replace '[\s`]+','')-cne 'catch{$candidateUseError=$_}' -or
        $null-eq $Outer.Finally -or
        ($Outer.Finally.Extent.Text -replace '[\s`]+','')-cne '{Close-TestCandidate-Candidate$candidateContext-BodyError$candidateUseError}' -or
        $normalized[5]-cne 'foreach($candidateSuccessMessagein$candidateSuccessMessages){Write-Output$candidateSuccessMessage}'){
        throw 'Reader retained owner statements are outside the inert closed replay contract.'
    }
}
function Get-FinalizationReplay($Ast,$Outer) {
    # Disclosed substitution: only success message operands and the actual
    # inert culture/case identity loops execute. Provider, crypto, application,
    # protocol and cleanup workload assertions remain in their owning tests.
    $replay=[Collections.Generic.List[string]]::new()
    $expected=[Collections.Generic.List[string]]::new()
    $sites=@(Get-FinalizationMessageSites $Outer.Body)
    if($sites.Count-eq 0){throw 'Owning reader has no success message sites.'}
    foreach($site in $sites){
        $operand=if($site -is [Management.Automation.Language.CommandAst]){$site.CommandElements[1]}else{$site.Arguments[0]}
        # Validate EVERY operand before any branch evaluates a payload.
        $kind=Assert-FinalizationMessageOperand $operand
        $payload=$operand.Extent.Text
        if($kind -cin @('Culture','Name')){
            $variable=if($kind-ceq 'Culture'){'culture'}else{'name'}
            $loops=@($Ast.FindAll({param($node)$node -is [Management.Automation.Language.ForEachStatementAst] -and $node.Variable.VariablePath.UserPath-ceq $variable},$true))
            if($loops.Count-ne 1){throw 'Success message identity loop is not unique.'}
            if($variable-ceq 'name'){
                $assignments=@($Ast.FindAll({param($node)$node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text-ceq '$cases'},$true))
                if($assignments.Count-ne 1){throw 'Success cases declaration is not unique.'}
                $tables=@($assignments[0].FindAll({param($node)$node -is [Management.Automation.Language.HashtableAst]},$false))
                if($tables.Count-ne 1){throw 'Success cases declaration changed shape.'}
                $cases=[ordered]@{}
                foreach($pair in $tables[0].KeyValuePairs){
                    if($pair.Item1 -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
                        [string]$pair.Item1.Value-cnotmatch '^[A-Za-z][A-Za-z0-9-]*$' -or $cases.Contains([string]$pair.Item1.Value)){
                        throw 'Success case key is not a unique closed named literal.'
                    }
                    $cases[[string]$pair.Item1.Value]=$null
                }
                # Only validated named literals enter generated fixture text.
                $setup='$cases=[ordered]@{'+(@($cases.Keys|ForEach-Object {"'$_'=0"})-join ';')+'}'
                $replay.Add($setup)
            }
            $condition=$loops[0].Condition
            $expression=Get-FinalizationConditionExpression $condition
            if($kind-ceq 'Culture'){$identities=@(Get-FinalizationLiteralValues $expression -Culture)}
            else {
                if($expression -isnot [Management.Automation.Language.BinaryExpressionAst] -or
                    $expression.Operator-ne [Management.Automation.Language.TokenKind]::Plus){throw 'Case identity loop must append one literal array to its declared keys.'}
                $keys=Get-FinalizationArrayExpression $expression.Left
                if($keys -isnot [Management.Automation.Language.MemberExpressionAst] -or
                    $keys -is [Management.Automation.Language.InvokeMemberExpressionAst] -or
                    $keys.Static -or $keys.Extent.Text-cne '$cases.Keys'){throw 'Case identity loop uses an unadmitted member.'}
                $identities=@($cases.Keys)+@(Get-FinalizationLiteralValues $expression.Right)
            }
            foreach($identity in $identities){
                if($variable-ceq 'culture'){$culture=$identity}else{$name=$identity}
                $expected.Add([string](& ([scriptblock]::Create($payload))))
            }
            $replay.Add('foreach($'+$variable+' in '+$condition.Extent.Text+'){'+$site.Extent.Text+'}')
        }
        elseif($kind-ceq 'Matrix'){
            $assignments=@($Ast.FindAll({param($node)$node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text-ceq '$matrix'},$true))
            if($assignments.Count-ne 1){throw 'Success runtime matrix declaration is not unique.'}
            $arrays=@($assignments[0].FindAll({param($node)$node -is [Management.Automation.Language.ArrayExpressionAst]},$false))
            if($arrays.Count-ne 1){throw 'Success runtime matrix declaration changed shape.'}
            $count=$arrays[0].SubExpression.Statements.Count
            $matrix=@(1..$count)
            $expected.Add([string](& ([scriptblock]::Create($payload))))
            $replay.Add('$matrix=@(1..'+$count+')')
            $replay.Add($site.Extent.Text)
        }
        else {
            $expected.Add([string]$operand.Value)
            $replay.Add($site.Extent.Text)
        }
    }
    [pscustomobject]@{Body=($replay-join "`n");Expected=$expected.ToArray()}
}
function Invoke-FinalizationSyntaxControls {
    # Harmless mutation fixtures prove refusal before evaluating message or
    # loop syntax; these controls perform no provider/native/product work.
    $namePrefix='$cases=[ordered]@{one=0;two=0};'
    $matrixPrefix='$matrix=@(@{Name=''one''},@{Name=''two''});'
    $controls=[ordered]@{
        NameLiteral=@($namePrefix,'@($cases.Keys)+@(''three'')','name','"PASS: $name."',$false)
        CultureLiteral=@('','@(''en-US'',''ja-JP'')','culture','"PASS: $culture."',$false)
        MatrixCount=@($matrixPrefix,'$null','unused','"PASS: $($matrix.Count) fixtures."',$false)
        NameCounter=@($namePrefix,'@($cases.Keys)+@(''three'')','name','"PASS: $name $($global:OrdinaryFinalizationCounter++)."',$true)
        CultureCounter=@('','@(''en-US'',''ja-JP'')','culture','"PASS: $culture $($global:OrdinaryFinalizationCounter++)."',$true)
        MatrixCounter=@($matrixPrefix,'$null','unused','"PASS: $($matrix.Count) $($global:OrdinaryFinalizationCounter++)."',$true)
        NameLoopCounter=@($namePrefix,'@($cases.Keys)+@($($global:OrdinaryFinalizationCounter++))','name','"PASS: $name."',$true)
        CultureLoopCounter=@('','@(''en-US'',$($global:OrdinaryFinalizationCounter++))','culture','"PASS: $culture."',$true)
        Assignment=@($namePrefix,'@($cases.Keys)+@(''three'')','name','"PASS: $name $($global:OrdinaryFinalizationCounter=9)."',$true)
        Command=@($namePrefix,'@($cases.Keys)+@(''three'')','name','"PASS: $name $(Write-Output ''unexpected-operation'')."',$true)
        CultureCast=@('','@([string]''en-US'')','culture','"PASS: $culture."',$true)
        KeyInjection=@('$cases=[ordered]@{''one''''=0};$global:OrdinaryFinalizationCounter++;#''=0};','@($cases.Keys)+@(''three'')','name','"PASS: $name."',$true)
        LiteralDollarName=@('','$null','unused','''PASS: literal $name.''',$false)
    }
    foreach($control in $controls.GetEnumerator()){
        $value=$control.Value
        $body=if($value[2]-ceq 'unused'){'$candidateSuccessMessages.Add('+$value[3]+')'}else{
            'foreach($'+$value[2]+' in '+$value[1]+'){$candidateSuccessMessages.Add('+$value[3]+')}'
        }
        $ast=Get-FinalizationSyntax ($value[0]+'try{'+$body+'}finally{}')
        $outer=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[0]
        $global:OrdinaryFinalizationCounter=0;$refused=$false
        try {$null=Get-FinalizationReplay -Ast $ast -Outer $outer} catch {$refused=$true}
        if($refused-ne [bool]$value[4] -or $global:OrdinaryFinalizationCounter-ne 0){throw "$($control.Key) replay syntax was evaluated or incorrectly admitted/refused."}
    }
    $controls.Count
}
try {
    $checks+=Invoke-FinalizationSyntaxControls
    foreach($file in @('LocalProtectorPreparation.Tests.ps1','SystemCollectionPlanApplication.Tests.ps1',
        'ProtectedPackageBufferSafety.Tests.ps1','ProtectedPackageRecordSafety.Tests.ps1',
        'PrivilegedExecutionPhase.Tests.ps1','ProtectedPackageApplication.Tests.ps1',
        'RuntimeInventory.Tests.ps1','RuntimeMatrix.Tests.ps1')){
        $text=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $file))
        $ast=Get-FinalizationSyntax $text
        $outer=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
        $open=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text-ceq '$candidateContext'})
        if($outer.Count-ne 1 -or $open.Count-ne 1){throw 'Ordinary reader candidate ownership wrapper changed.'}
        Assert-FinalizationOwnerSyntax -Ast $ast -Open $open[0] -Outer $outer[0]
        foreach($unsafeOwner in @(
            ($text+"`n`$global:OrdinaryFinalizationCounter++"),
            $text.Replace('$candidateUseError=$null','$candidateUseError=$null; $global:OrdinaryFinalizationCounter++')
        )){
            $ownerAst=Get-FinalizationSyntax $unsafeOwner
            $ownerOpen=@($ownerAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text-ceq '$candidateContext'})[0]
            $ownerOuter=@($ownerAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[0]
            $global:OrdinaryFinalizationCounter=0;$refused=$false
            try {Assert-FinalizationOwnerSyntax -Ast $ownerAst -Open $ownerOpen -Outer $ownerOuter} catch {$refused=$true}
            if(-not $refused -or $global:OrdinaryFinalizationCounter-ne 0){throw 'Unexpected retained owner operation reached the inert replay contract.'}
            $checks++
        }
        $replay=Get-FinalizationReplay -Ast $ast -Outer $outer[0]
        $prefix=@'
param([string]$CandidatePath,[string]$PreparedManifestPath,[string]$PreparedManifestSha256)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=$PSScriptRoot
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $global:OrdinaryFinalizationSpy.Opens++
    if($CandidatePath-cne 'inert-candidate' -or $PreparedManifestPath-cne 'inert-manifest' -or $PreparedManifestSha256-cne ('a'*64)){throw 'Actual owner dropped explicit prepared inputs.'}
    [pscustomobject]@{Path=$CandidatePath}
}
function Close-TestCandidate {
    param($Candidate,[AllowNull()][Management.Automation.ErrorRecord]$BodyError)
    $global:OrdinaryFinalizationSpy.Closes++
    $global:OrdinaryFinalizationSpy.BodyError=$BodyError
    $global:OrdinaryFinalizationSpy.Events.Add('Close')
    if($global:OrdinaryFinalizationSpy.CloseError){throw $global:OrdinaryFinalizationSpy.CloseError}
    if($BodyError){throw $BodyError}
}
'@
        # Preserve the ACTUAL Open, candidate assignment, catch/finally and
        # after-finalizer suffix. Only the original owning body is substituted.
        $source=$prefix+"`n"+$text.Substring($open[0].Extent.StartOffset,$outer[0].Body.Extent.StartOffset-$open[0].Extent.StartOffset)+
            "{`n"+$replay.Body+"`n}"+$text.Substring($outer[0].Body.Extent.EndOffset)
        $variants=[ordered]@{
            Actual=$source
            EarlyFlush=$source.Replace('Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError',
                'foreach ($candidateSuccessMessage in $candidateSuccessMessages) { Write-Output $candidateSuccessMessage }; Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError')
            WriteOutputBeforeClose=$source.Replace("{`n"+$replay.Body+"`n}","{`nWrite-Output 'PASS: injected premature success.'`n"+$replay.Body+"`n}")
        }
        foreach($variant in $variants.GetEnumerator()){
            if($variant.Key-cne 'Actual' -and $variant.Value-ceq $source){throw 'Finalization mutant did not change its target.'}
            $null=Get-FinalizationSyntax $variant.Value
            $caller=Join-Path $fixture ($variant.Key+'-'+$file)
            [IO.File]::WriteAllText($caller,$variant.Value,[Text.UTF8Encoding]::new($false))
            foreach($closeFails in @($false,$true)){
                $failure=if($closeFails){[InvalidOperationException]::new('Disclosed candidate-only Close failure.')}else{$null}
                if($failure){$failure.Data['OwnedCleanupUnverified']=$true}
                $global:OrdinaryFinalizationSpy=@{Opens=0;Closes=0;BodyError=$null;CloseError=$failure;Events=[Collections.Generic.List[string]]::new()}
                $output=[Collections.Generic.List[string]]::new();$caught=$null
                try { & $caller -CandidatePath inert-candidate -PreparedManifestPath inert-manifest -PreparedManifestSha256 ('a'*64)|
                    ForEach-Object {$output.Add([string]$_);$global:OrdinaryFinalizationSpy.Events.Add('Output')} }
                catch {$caught=$_}
                $spy=$global:OrdinaryFinalizationSpy
                $accepted=$spy.Opens-eq 1 -and $spy.Closes-eq 1 -and $null-eq $spy.BodyError
                if($closeFails){$accepted=$accepted -and $output.Count-eq 0 -and $null-ne $caught -and
                    [object]::ReferenceEquals($caught.Exception,$failure) -and $caught.Exception.Data['OwnedCleanupUnverified']-eq $true}
                else {$accepted=$accepted -and $null-eq $caught -and ($output-join "`0")-ceq ($replay.Expected-join "`0") -and $spy.Events[0]-ceq 'Close'}
                if(($variant.Key-ceq 'Actual') -ne $accepted){throw "$file/$($variant.Key)/closeFails=$closeFails did not distinguish premature success from verified finalization."}
                $checks++
            }
        }
    }
}
finally {
    if($previousSpy){$global:OrdinaryFinalizationSpy=$previousSpy.Value}else{Remove-Variable OrdinaryFinalizationSpy -Scope Global -ErrorAction SilentlyContinue}
    if($previousCounter){$global:OrdinaryFinalizationCounter=$previousCounter.Value}else{Remove-Variable OrdinaryFinalizationCounter -Scope Global -ErrorAction SilentlyContinue}
    $parent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))
    if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($fixture))-ine $parent){throw 'Ordinary finalization fixture cleanup escaped its root.'}
    if([IO.Directory]::Exists($fixture)){[IO.Directory]::Delete($fixture,$true)}
}
Write-Output "PASS: $checks ordinary candidate success/finalization and premature-output sensitivity controls (inert body and recording owner substitutes)."
