# Frozen source from 04dd1aa84077e6d5f64d0c491caaaf188db78c33; differential oracle only.
# Original support SHA256 1f84f5f793775ce41fd2ad067bf0bb672ee845e23468e543325f2ced99f0fa86.
function Rename-QualificationFunction {
    param([string] $Source, [string] $Name, [string] $Replacement)
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($Source,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Controlled module did not parse.'}
    $definitions=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name},$true)
    if($definitions.Count -eq 0){throw "Controlled function $Name is missing."}
    foreach($node in @($definitions|Sort-Object {$_.Extent.StartOffset} -Descending)){
        $offset=$node.Extent.StartOffset+$node.Extent.Text.IndexOf($Name,[StringComparison]::Ordinal)
        $Source=$Source.Remove($offset,$Name.Length).Insert($offset,$Replacement)
    }
    $Source
}

function Edit-QualificationEmbeddedCertificateSource {
    param([string] $ModuleText,
        [ValidateSet('Edit-AdditionalScopeSource','Set-QualificationSourceCulture')] [string] $SourceEditor,
        [switch] $TrackAdditionalSource)
    # The existing certificate adapter embeds controlled source before the
    # module starts. Apply the same source edits at its invocation boundary.
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($ModuleText,[ref]$tokens,[ref]$errors)
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-BoundedCertificateTrustSnapshot'},$false)
    if($null -eq $node){throw 'Controlled certificate snapshot is absent.'}
    $matches=[regex]::Matches($node.Extent.Text,"\[Text.Encoding\]::UTF8.GetString\(\[Convert\]::FromBase64String\('([A-Za-z0-9+/=]+)'\)\)")
    if($matches.Count -ne 1){throw 'Controlled certificate source is not unique.'}
    $wrapper=$node.Extent.Text.Replace($matches[0].Value,'('+$SourceEditor+' -Source ('+$matches[0].Value+'))')
    if($TrackAdditionalSource){$wrapper=$wrapper.Replace('$script:StatusDeskTransport.State.CertificateSourceExecuted=$true',
        '$script:StatusDeskTransport.State.AdditionalSourceBuilt=$true; $script:StatusDeskTransport.State.CertificateSourceExecuted=$true')}
    $ModuleText=Rename-QualificationFunction -Source $ModuleText -Name Invoke-BoundedCertificateTrustSnapshot -Replacement "$SourceEditor-OriginalCertificateSnapshot"
    $ModuleText+"`n"+$wrapper
}

function Add-QualificationCulture {
    param([string] $ModuleText, [string] $Culture)
    if ($ModuleText.Contains('function Initialize-UnusedIdentityEnrollmentNativeSource')) {
        # The initializer is serialized into each real bounded child process.
        $ModuleText=$ModuleText.Replace('function Initialize-IdentityEnrollmentNativeSource {',
            "function Initialize-IdentityEnrollmentNativeSource {`n[Globalization.CultureInfo]::CurrentCulture='$Culture'; [Globalization.CultureInfo]::CurrentUICulture='$Culture'")
        $ModuleText=$ModuleText.Replace('public string DomainName=null,',
            'public string QualificationCulture=System.Globalization.CultureInfo.CurrentCulture.Name, QualificationUICulture=System.Globalization.CultureInfo.CurrentUICulture.Name; public string DomainName=null,')
        $ModuleText=Rename-QualificationFunction -Source $ModuleText -Name Invoke-BoundedIdentityNativeSnapshot -Replacement Invoke-CultureOriginalIdentitySnapshot
        $ModuleText+=@'

function Invoke-BoundedIdentityNativeSnapshot {
    param($Policy,$CollectorIndex,$Mode)
    $result=Invoke-CultureOriginalIdentitySnapshot @PSBoundParameters
    if($result.succeeded) {
        if(-not $script:StatusDeskTransport.State.ContainsKey('ObservedIdentityCultures')){$script:StatusDeskTransport.State.ObservedIdentityCultures=[Collections.Generic.List[object]]::new()}
        $script:StatusDeskTransport.State.ObservedIdentityCultures.Add(@{mode=$Mode;culture=$result.snapshot.QualificationCulture;uiCulture=$result.snapshot.QualificationUICulture})
    }
    $result
}
'@
    }
    $ModuleText += @'

[Globalization.CultureInfo]::CurrentCulture = '__CULTURE__'
[Globalization.CultureInfo]::CurrentUICulture = '__CULTURE__'
[Globalization.CultureInfo]::DefaultThreadCurrentCulture = '__CULTURE__'
[Globalization.CultureInfo]::DefaultThreadCurrentUICulture = '__CULTURE__'
function Set-QualificationSourceCulture {
    param([string] $Source)
    # This changes only culture at the existing controlled OS-source seam.
    # Remove fixed cultures in existing test prefixes, then apply both cultures
    # after any native worker param block so transport syntax is unchanged.
    $Source = [regex]::Replace($Source, '(?m)^\[(?:Threading\.Thread|Globalization\.CultureInfo)\]::(?:CurrentThread\.)?Current(?:UI)?Culture\s*=.*$', '')
    # Record the executing source culture in its existing locale field.
    $Source=[regex]::Replace($Source,"sourceLocale\s*=\s*'und'",'sourceLocale=[Globalization.CultureInfo]::CurrentCulture.Name')
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($Source,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Controlled source did not parse for culture qualification.' }
    # SYSTEM has no locale wire field. Its controlled CIM call must execute in
    # both requested cultures; the ordinary source/report checks require success.
    foreach($node in @($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-CimInstance'},$true)|Sort-Object {$_.Extent.StartOffset} -Descending)) {
        $body=$node.Body
        $entry=if($null -ne $body.ParamBlock){$body.ParamBlock.Extent.EndOffset}else{$body.Extent.StartOffset+1}
        $Source=$Source.Insert($entry,"`nif([Globalization.CultureInfo]::CurrentCulture.Name -ne '__CULTURE__' -or [Globalization.CultureInfo]::CurrentUICulture.Name -ne '__CULTURE__'){throw 'Controlled OS source culture mismatch.'}`n")
    }
    $offset=if($null -ne $ast.ParamBlock){$ast.ParamBlock.Extent.EndOffset}else{0}
    $Source.Insert($offset, "`n[Globalization.CultureInfo]::CurrentCulture='__CULTURE__'; [Globalization.CultureInfo]::CurrentUICulture='__CULTURE__'`n")
}
'@.Replace('__CULTURE__', $Culture)
    foreach ($name in @('Get-SyntheticCollectorScriptBytes', 'Get-PrivilegedCollectionWorkerSource',
        'Get-SystemCollectionWorkerSource', 'Get-SoftwareInventoryLiveSource', 'Get-ResourceDependenciesLiveSource', 'Get-NetworkTopologyLiveSource')) {
        if ($name -eq 'Get-SystemCollectionWorkerSource' -and $ModuleText -notmatch 'function Get-ControlledOriginalIdentitySystemPolicy') { continue }
        if ($name -eq 'Get-PrivilegedCollectionWorkerSource' -and $ModuleText -notmatch 'payloadSha256\s*=\s*Get-PrivilegedCollectionPlanSha256') { continue }
        if ($name -eq 'Get-SyntheticCollectorScriptBytes' -and $ModuleText -notmatch 'function Get-ControlledOriginalCollectorScriptBytes') { continue }
        $ModuleText = Rename-QualificationFunction -Source $ModuleText -Name $name -Replacement "QualificationOriginal-$name"
        $ModuleText += @'

function __NAME__ {
    $value = QualificationOriginal-__NAME__ @args
    $isBytes = $value -is [array]
    $text = if ($isBytes) { [Text.Encoding]::UTF8.GetString([byte[]] $value) } else { [string] $value }
    $text = Set-QualificationSourceCulture -Source $text
    if ($isBytes) { ,[Text.Encoding]::UTF8.GetBytes($text) } else { $text }
}
'@.Replace('__NAME__', $name)
    }
    if($ModuleText.Contains('$script:StatusDeskTransport.State.CertificateSourceExecuted=$true')) {
        $ModuleText=Edit-QualificationEmbeddedCertificateSource -ModuleText $ModuleText -SourceEditor Set-QualificationSourceCulture
    }
    $ModuleText
}
