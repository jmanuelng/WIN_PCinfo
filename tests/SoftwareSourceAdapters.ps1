Set-StrictMode -Version Latest

# Substitute only Windows identity, registry, MSI native calls and WinRT objects.
# The release worker still runs under its real Job Object/byte/time/cleanup bounds.
function Add-ControlledSoftwareSources {
    param([string]$ModuleText,[string]$Scenario)
    $ModuleText=$ModuleText.Replace('Invoke-ControlledSoftwareInventoryCollection -Policy $Policy -ValidationScenario Empty }',
        'Invoke-ControlledSoftwareInventoryCollection -Policy $Policy -Live -AssessmentUserSid ''S-1-5-21-100-200-300-1001'' }')
    $ModuleText=$ModuleText.Replace('function Get-SoftwareInventoryLiveSource {','function Get-OriginalSoftwareInventoryLiveSource {')
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($ModuleText,[ref]$tokens,[ref]$errors)
    $collector=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-ControlledSoftwareInventoryCollection'},$false)
    $text=$collector.Extent.Text.Replace('[Security.Principal.WindowsIdentity]::GetCurrent()', '(Get-ControlledSoftwareIdentity)')
    $text=$text.Replace('[Security.Principal.WindowsPrincipal]::new($identity)', '(Get-ControlledSoftwarePrincipal)')
    $ModuleText=$ModuleText.Replace($collector.Extent.Text,$text)
    if($Scenario -in @('Composite','Ambiguous','OrderReversed','Withdrawn','LogicalFailure')){
        # Test-owned release data enters before the real catalog admission path.
        # Both data and expected digest change together only in this test module.
        $pattern='(?m)^\$script:SoftwareRecognitionCatalogBase64 = ''([^'']+)'''
        $match=[regex]::Match($ModuleText,$pattern)
        if(-not $match.Success){throw 'Catalog resource boundary changed.'}
        $catalog=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($match.Groups[1].Value))|ConvertFrom-Json -Depth 30
        if($Scenario -eq 'Composite'){
            $catalog.families[0].matchers+= [pscustomobject]@{
                matcherId='matcher:synthetic.registration';type='CompositeRegistration';registrationContext='Machine';registryView='Registry32'
                fields=[pscustomobject]@{registrationId='Synthetic.A';displayName='注册应用';publisher='Synthetic Publisher'}
            }
        }
        elseif($Scenario -in @('Ambiguous','OrderReversed')){
            $family=$catalog.families[0]|ConvertTo-Json -Depth 20|ConvertFrom-Json -Depth 20
            $family.familyId='family:synthetic.conflict';$family.matchers[0].matcherId='matcher:synthetic.conflict'
            $catalog.families+= $family
            if($Scenario -eq 'OrderReversed'){[array]::Reverse($catalog.families)}
        }
        elseif($Scenario -eq 'Withdrawn'){
            $catalog.families[0].lifecycle.state='withdrawn';$catalog.families[0].lifecycle.reason='Synthetic withdrawal fixture.';$catalog.families[0].matchers=@()
        }
        $json=if($Scenario -eq 'LogicalFailure'){'{malformed synthetic catalog'}else{$catalog|ConvertTo-Json -Depth 30 -Compress}
        $bytes=[Text.Encoding]::UTF8.GetBytes($json)
        $ModuleText=$ModuleText.Replace($match.Value,('$script:SoftwareRecognitionCatalogBase64 = '''+[Convert]::ToBase64String($bytes)+''''))
        $ModuleText=[regex]::Replace($ModuleText,'(?m)^\$script:SoftwareRecognitionCatalogDigest = ''[^'']+''',
            ('$script:SoftwareRecognitionCatalogDigest = '''+[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()+''''))
    }
    $adapter=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'SoftwareSourceBoundary.ps1'))
    $ModuleText + "`n" + $adapter.Replace('__SOFTWARE_CASE__',$Scenario)
}

function Assert-SoftwareSourceReport {
    param($Record,[string]$Html,[string]$Scenario)
    $observations=@($Record.observations|Where-Object fieldId -like 'field:software.*')
    $coverage=@($Record.coverage|Where-Object scopeId -like 'scope:software.*')
    if($Scenario -eq 'AlternateAdministrator'){
        Assert-Equal 8 @($coverage|Where-Object state -eq Denied).Count 'alternate administrator never substitutes its software'
        Assert-Equal 0 $observations.Count 'denied context creates no absence or identities'
        return
    }
    $msi=@($observations|Where-Object { $_.fieldId -eq 'field:software.msi.product-code' -and $_.valueState -eq 'ObservedValue' })
    $expectedMsi=if($Scenario -in @('MsiDenied','MsiCompilerDenied')){0}else{3}
    Assert-Equal $expectedMsi $msi.Count 'machine, managed and unmanaged MSI survive the documented SUCCESS sizing probe'
    if($expectedMsi){
        Assert-Equal 3 @($observations|Where-Object { $_.fieldId -eq 'field:software.msi.version' -and $_.value -eq 'release-2026+任意' }).Count 'MSI provider version text survives record and package'
    }
    $registry=@($observations|Where-Object { $_.fieldId -eq 'field:software.registry.registration-id' -and $_.valueState -eq 'ObservedValue' })
    Assert-Equal $(if($Scenario -eq 'DeniedUser'){4}else{8}) $registry.Count 'duplicates and explicit user/machine views remain distinct'
    $packages=@($observations|Where-Object { $_.fieldId -eq 'field:software.msix.package-full-name' -and $_.valueState -eq 'ObservedValue' })
    Assert-Equal $(if($Scenario -eq 'DeniedAllUsers'){5}else{10}) $packages.Count 'all five package types survive independent package scopes'
    Assert-Equal 'Bundle|Framework|Main|Optional|Resource' ((@($observations|Where-Object fieldId -eq 'field:software.msix.package-type'|ForEach-Object value|Sort-Object -Unique))-join '|') 'package type flags are preserved rather than flattened to applications'
    if($Scenario -in @('Complete','Composite','Ambiguous','OrderReversed','Withdrawn','LogicalFailure')){
        Assert-Equal 8 @($coverage|Where-Object state -eq Complete).Count 'every selected source executes before claiming complete inventory coverage'
    }
    $annotations=@($Record.softwareRecognition)
    Assert-Equal ($msi.Count+$registry.Count+$packages.Count) $annotations.Count 'recognition annotates each preserved identity'
    $exact=if($Scenario -eq 'DeniedAllUsers'){1}elseif($Scenario -in @('Ambiguous','OrderReversed','Withdrawn','LogicalFailure')){0}else{2}
    Assert-Equal $exact @($annotations|Where-Object outcome -eq RecognizedExact).Count 'exact release PFN recognizes only the exact package'
    if($Scenario -eq 'LogicalFailure'){
        Assert-Equal 21 @($annotations|Where-Object outcome -eq NotEvaluated).Count 'logical catalog failure preserves all source inventory with explicit unevaluated annotations'
    }else{Assert-Equal $true (@($annotations|Where-Object outcome -eq Unrecognized).Count -gt 0) 'near PFN and unknown software remain ordinary inventory'}
    if($Scenario -eq 'Composite'){Assert-Equal 1 @($annotations|Where-Object outcome -eq RecognizedComposite).Count 'exact Unicode composite requires the declared view and context'}
    if($Scenario -in @('Ambiguous','OrderReversed')){
        $ambiguous=@($annotations|Where-Object outcome -eq Ambiguous)
        Assert-Equal 2 $ambiguous.Count 'conflicting identity is ambiguous in either catalog order'
        Assert-Equal 0 @($ambiguous|ForEach-Object roles).Count 'ambiguity assigns no arbitrary migration roles'
    }
    if($Scenario -eq 'Withdrawn'){Assert-Equal 21 @($annotations|Where-Object outcome -eq Unrecognized).Count 'withdrawn catalog identity cannot recognize current inventory'}
    Assert-Equal $true ($Html.Contains('注册应用') -and $Html.Contains('release-2026+任意')) 'protected HTML preserves Unicode names and arbitrary versions'
    if($Scenario -eq 'DeniedUser'){Assert-Equal 2 @($coverage|Where-Object { $_.scopeId -like 'scope:software.registry.assessment-user.*' -and $_.state -eq 'Denied' }).Count 'inaccessible user registry views are explicitly denied'}
    if($Scenario -eq 'DeniedAllUsers'){Assert-Equal 'Denied' ($coverage|Where-Object scopeId -eq 'scope:software.msix.machine').state 'all-user package denial does not erase current-user packages'}
    if($Scenario -in @('MsiDenied','MsiCompilerDenied')){Assert-Equal 2 @($coverage|Where-Object { $_.scopeId -like 'scope:software.msi.*' -and $_.state -eq 'Denied' }).Count 'MSI source denial remains confined to MSI scopes'}
}
