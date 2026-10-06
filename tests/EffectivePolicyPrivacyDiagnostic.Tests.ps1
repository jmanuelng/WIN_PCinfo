[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot 'EffectivePolicyApplication.Tests.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Policy application test does not parse.' }
$definition=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-EffectivePolicyPrivacyDiagnostic'
},$true))
if ($definition.Count -ne 1) { throw 'Private diagnostic definition is not unique.' }
. ([scriptblock]::Create($definition[0].Extent.Text))
$patterns=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value.StartsWith('(?i)6ac1786c|')
},$true))
if ($patterns.Count -ne 1) { throw 'Policy privacy assertion pattern is not unique.' }
$pattern=$patterns[0].Value
$safe='{"recordType":"win-pcinfo.effective-policy-validation","appliedPolicyCount":1,"auditCatalogCount":2,"policyIdentifiersPublished":false}'
$unsafe='{"recordType":"synthetic.public-record","nested":{"items":["safe","LocalGPO"]},"port":5985}'
$stdout=$safe+"`r`n"+$unsafe+"`r`n"
$diagnostic=Get-EffectivePolicyPrivacyDiagnostic -Scenario 'SyntheticDiagnosticControl' -StandardOutput $stdout -Pattern $pattern
if ($diagnostic.matchingPublicRecords.Count -ne 1) { throw 'Only the matching public record should be captured.' }
$record=$diagnostic.matchingPublicRecords[0]
if ($record.recordOrdinal -ne 1 -or $record.recordType -cne 'synthetic.public-record' -or $record.rawPublicRecord -cne $unsafe) {
    throw 'Diagnostic does not retain its exact producing public record.'
}
if (($record.exactMatches.value -join ',') -cne 'LocalGPO,5985') { throw 'Diagnostic changed the original assertion matches.' }
if (($record.propertyPaths.path -join ',') -cne '$["nested"]["items"][1],$["port"]') { throw 'Diagnostic did not locate nested and numeric property paths.' }
foreach ($match in $record.exactMatches) {
    if ($stdout.Substring($match.stdoutOffset,$match.length) -cne $match.value) { throw 'Diagnostic match offset does not bind the original stdout.' }
}
$clean=Get-EffectivePolicyPrivacyDiagnostic -Scenario 'SyntheticSafeControl' -StandardOutput $safe -Pattern $pattern
if ($clean.matchingPublicRecords.Count) { throw 'Safe coverage and count fields became a privacy match.' }
$name='{"recordType":"synthetic.public-record","PolicyXml":"safe"}'
$named=Get-EffectivePolicyPrivacyDiagnostic -Scenario 'SyntheticPropertyNameControl' -StandardOutput $name -Pattern $pattern
if ($named.matchingPublicRecords[0].propertyPaths[0].kind -cne 'PropertyName' -or
    $named.matchingPublicRecords[0].propertyPaths[0].path -cne '$["PolicyXml"]') { throw 'Matching property names must be identified distinctly.' }
Write-Output 'PASS: private privacy diagnostic preserves exact matches, producing records, nested property paths and stdout offsets; safe coverage and counts remain unmatched.'
