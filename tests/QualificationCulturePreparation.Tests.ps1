[CmdletBinding()]
param(
    [string] $RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string] $SupportPath,
    [string] $ReferencePath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $RepositoryRoot 'tests/TestHarness.ps1')
. (Join-Path $RepositoryRoot 'tests/IdentitySourceAdapters.ps1')
. (Join-Path $RepositoryRoot 'tests/ReadinessSourceAdapters.ps1')
if (-not $SupportPath) { $SupportPath=Join-Path $RepositoryRoot 'tests/AssessmentQualificationSupport.ps1' }
if (-not $ReferencePath) { $ReferencePath=Join-Path $RepositoryRoot 'tests/fixtures/QualificationCultureReference.ps1' }

function New-CultureTransformationProbe {
    param([string] $Path,[string] $Name,[string[]] $Functions)
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    Assert-Equal 0 $errors.Count 'actual transformation source parses'
    $definitions=foreach($function in $Functions) {
        $nodes=@($ast.FindAll({param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $function
        }.GetNewClosure(),$false))
        Assert-Equal 1 $nodes.Count 'each actual transformation function is unique'
        $nodes[0].Extent.Text
    }
    $source=$definitions -join "`n"
    $probeAst=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    # Count the actual host parser calls, without changing their inputs or the
    # generated worker source embedded in here-strings.
    $parses=@($probeAst.FindAll({param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static -and
        $node.Expression.Extent.Text -ceq '[Management.Automation.Language.Parser]' -and
        $node.Member.Extent.Text -ceq 'ParseInput'
    },$true))
    foreach($parse in @($parses | Sort-Object {$_.Extent.StartOffset} -Descending)) {
        $statement=$parse.Parent
        while($null -ne $statement -and $statement -isnot [Management.Automation.Language.AssignmentStatementAst]) {
            $statement=$statement.Parent
        }
        Assert-Equal $true ($null -ne $statement) 'actual parser invocation has an assignment boundary'
        $source=$source.Insert($statement.Extent.StartOffset,'$script:CultureHostParses++; ')
    }
    New-Module -Name $Name -ScriptBlock ([scriptblock]::Create($source))
}
function Invoke-CultureTransformationProbe {
    param($Module,[string] $Source,[string] $Culture)
    & $Module {
        param($InputText,$RequestedCulture)
        $script:CultureHostParses=0
        $output=Add-QualificationCulture -ModuleText $InputText -Culture $RequestedCulture
        @{Text=$output;ParseCount=$script:CultureHostParses}
    } $Source $Culture
}

$common=@('Rename-QualificationFunction','Edit-QualificationEmbeddedCertificateSource','Add-QualificationCulture')
$reference=New-CultureTransformationProbe -Path $ReferencePath -Name CultureReference -Functions $common
$actualFunctions=$common
if ([IO.File]::ReadAllText($SupportPath).Contains('function Rename-QualificationOriginalDefinitions')) {
    $actualFunctions+= 'Rename-QualificationOriginalDefinitions'
}
$actual=New-CultureTransformationProbe -Path $SupportPath -Name CultureActual -Functions $actualFunctions
try {
    $candidate=Join-Path $RepositoryRoot 'artifacts/WIN-PCInfo.ps1'
    if (-not [IO.File]::Exists($candidate)) { & (Join-Path $RepositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null }
    $regions=[regex]::Matches([IO.File]::ReadAllText($candidate),
        '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
    Assert-Equal $true ($regions.Count -gt 0) 'regression uses actual generated module regions'
    $base=($regions | ForEach-Object {$_.Groups[2].Value}) -join "`n"
    $regions=$null
    $productModule=$base
    # Apply the actual collector renames and wrapper literal from the engine
    # harness, rather than reimplementing its setup in a second test.
    $tokens=$null; $errors=$null
    $harness=[Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $RepositoryRoot 'tests/StatusDeskEngine.Tests.ps1'),[ref]$tokens,[ref]$errors)
    $names=@($harness.FindAll({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$names' -and $node.Right.Extent.Text.Contains("'IdentityEnrollmentCollection'")
    },$false))
    Assert-Equal 1 $names.Count 'actual collector name inventory is unique'
    . ([scriptblock]::Create($names[0].Extent.Text))
    $renames=@($harness.FindAll({param($node)
        $node -is [Management.Automation.Language.ForEachStatementAst] -and
        $node.Condition.Extent.Text -ceq '$names'
    },$false))
    Assert-Equal 1 $renames.Count 'actual collector rename loop is unique'
    $wrappers=@($harness.FindAll({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$moduleText' -and
        $node.Right.Extent.Text.Contains('function Invoke-IdentityEnrollmentCollection { param')
    },$false))
    Assert-Equal 1 $wrappers.Count 'actual controlled wrapper literal is unique'
    $moduleText=$base
    . ([scriptblock]::Create($renames[0].Extent.Text))
    . ([scriptblock]::Create($wrappers[0].Extent.Text))
    $base=$moduleText
    $contexts=[ordered]@{
        Default=$base
        SystemAbsent=(Add-ControlledIdentitySources -ModuleText $base -Scenario SystemAbsent)
        EntraJoined=(Add-ControlledIdentitySources -ModuleText $base -Scenario EntraJoined)
        AdminEmpty=(Add-ControlledIdentitySources -ModuleText $base -Scenario AdminEmpty)
        Readiness=(Add-ControlledReadinessSources -ModuleText $base -Scenario Complete)
    }
    # The actual certificate adapter needs source generators from the product.
    # Load definitions in an isolated module and generate controlled source;
    # never invoke a store read, collector, worker, or assessment.
    $certificateSeed=New-Module -Name CultureCertificateSeed -ScriptBlock {
        param($ProductText,$ControlledText,$AdapterPath)
        . ([scriptblock]::Create($ProductText))
        . $AdapterPath
        $script:Seed=Add-ControlledCertificateSources -ModuleText $ControlledText -Scenario ValidTrusted
    } -ArgumentList $productModule,$base,(Join-Path $RepositoryRoot 'tests/CertificateSourceAdapters.ps1')
    try { $contexts.Certificate=& $certificateSeed { $script:Seed } }
    finally { Remove-Module -ModuleInfo $certificateSeed -Force }
    $comparisons=0
    foreach($context in $contexts.GetEnumerator()) {
        foreach($culture in @('en-US','tr-TR','ar-SA','ja-JP','es-MX')) {
            $expected=Invoke-CultureTransformationProbe -Module $reference -Source $context.Value -Culture $culture
            $observed=Invoke-CultureTransformationProbe -Module $actual -Source $context.Value -Culture $culture
            Assert-Equal $true ([string]::Equals($expected.Text,$observed.Text,[StringComparison]::Ordinal)) "$($context.Key)/$culture transformed source is byte-identical to the frozen original"
            Assert-Equal $true ($expected.ParseCount -gt 1) 'reference exposes repeated full-module parsing at the actual call site'
            # Certificate embedding retains its two existing parser calls;
            # the original-definition rename phase itself is always one.
            $expectedCount=if($context.Key -ceq 'Certificate'){3}else{1}
            Assert-Equal $expectedCount $observed.ParseCount "$($context.Key)/$culture prepares all original definitions with one rename-phase host parse"
            $comparisons++
        }
    }
    # Exercise boundary and refusal behavior without executing any generated
    # worker or collector. Appended public wrappers must remain public.
    & $actual {
        $original='function Alpha { function Alpha { 1 }; 2 }; function Beta { 3 }'
        $tail='; function Alpha { 4 }; function Beta { 5 }'
        $map=[ordered]@{Alpha='Original-Alpha';Beta='Original-Beta'}
        $result=Rename-QualificationOriginalDefinitions -Source ($original+$tail) -OriginalDefinitionLength $original.Length -Renames $map
        if($result -cne 'function Original-Alpha { function Original-Alpha { 1 }; 2 }; function Original-Beta { 3 }; function Alpha { 4 }; function Beta { 5 }') {
            throw 'Nested original definitions or appended public wrappers changed.'
        }
        foreach($case in @(
            @{Source='function Alpha {';Length=16;Map=@{Alpha='Original-Alpha'}},
            @{Source='function Alpha { 1 }';Length=20;Map=@{Absent='Original-Absent'}},
            @{Source='function Alpha { 1 }';Length=10;Map=@{Alpha='Original-Alpha'}},
            @{Source='function Alpha { 1 }';Length=21;Map=@{Alpha='Original-Alpha'}},
            @{Source='function Alpha { 1 }';Length=20;Map=@{'Alpha; x'='Original-Alpha'}}
        )) {
            $refused=$false
            try { $null=Rename-QualificationOriginalDefinitions -Source $case.Source -OriginalDefinitionLength $case.Length -Renames $case.Map }
            catch { $refused=$true }
            if(-not $refused){throw 'Malformed, missing, or out-of-bound original definitions were admitted.'}
        }
    }
    Write-Output "PASS: Culture preparation preserves $comparisons actual-source transformations and uses one rename-phase full-module parse (certificate embedding retains its two existing parses)."
}
finally {
    Remove-Module -ModuleInfo $reference,$actual -Force -ErrorAction SilentlyContinue
}