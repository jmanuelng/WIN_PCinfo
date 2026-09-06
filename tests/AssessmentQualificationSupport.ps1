Set-StrictMode -Version Latest

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

function Add-QualificationProhibitedPayload {
    param([string] $ModuleText, [string] $Boundary)
    if ($Boundary -eq 'System') {
        . (Join-Path $PSScriptRoot 'IdentitySourceAdapters.ps1')
        $ModuleText=Add-ControlledSystemEnrollmentSources -ModuleText $ModuleText -Scenario SystemAbsent
        $ModuleText=Rename-QualificationFunction -Source $ModuleText -Name Get-SystemCollectionWorkerSource -Replacement Get-ProhibitedOriginalSystemSource
        return $ModuleText + @'

function Get-SystemCollectionWorkerSource {
    $source=Get-ProhibitedOriginalSystemSource
    $before='Write-SystemFrame -Stream $pipe -Json ($result |'
    if (-not $source.Contains($before)) { throw 'Controlled SYSTEM result boundary is absent.' }
    $source.Replace($before, '$result | Add-Member -NotePropertyName password -NotePropertyValue ''Synthetic-154-秘密-İ-🔒''; Write-SystemFrame -Stream $pipe -Json ($result |')
}
'@
    }
    $map = @{
        Identity=@('IdentityEnrollment','payload'); Resource=@('ResourceDependencies','payload')
        Network=@('NetworkTopology','payload'); Software=@('SoftwareInventory','payload')
        Certificate=@('CertificateTrust','payload'); Connectivity=@('MicrosoftConnectivity','payload')
        Firmware=@('Privileged','PrivateFirmwareCollectorResult.payload')
        Administrator=@('Privileged','PrivateAdministratorCollectorResult.payload')
        Policy=@('Privileged','PrivateEffectivePolicyCollectorResult.payload')
    }
    $name = 'Invoke-' + $map[$Boundary][0] + $(if($map[$Boundary][0] -eq 'Privileged'){'CollectionPlan'}else{'Collection'})
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($ModuleText,[ref]$tokens,[ref]$errors)
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$false)
    if ($null -eq $node) { throw 'Controlled collector boundary is missing.' }
    $ModuleText=$ModuleText.Replace("function $name {", "function QualificationOriginal-$name {")
    $ModuleText += @'

function __NAME__ {
    __PARAMS__
    $result=QualificationOriginal-__NAME__ @PSBoundParameters
    $target=$result.__PAYLOAD__
    if($null -eq $target){throw 'Controlled prohibited-input boundary was not reached.'}
    $script:StatusDeskTransport.State.ProhibitedBoundaryReached=$true
    if ($target -is [Collections.IDictionary]) { $target['password'] = 'Synthetic-154-秘密-İ-🔒' }
    else { $target | Add-Member -NotePropertyName password -NotePropertyValue 'Synthetic-154-秘密-İ-🔒' -Force }
    $result
}
'@.Replace('__NAME__',$name).Replace('__PARAMS__',$node.Body.ParamBlock.Extent.Text).Replace('__PAYLOAD__',$map[$Boundary][1])
    $ModuleText
}

function Assert-QualificationMarkerAbsent {
    param([string] $Text, [string] $Marker = 'Synthetic-154-秘密-İ-🔒')
    $bytes = [Text.Encoding]::UTF8.GetBytes($marker)
    $variants = @($marker, $marker.ToUpperInvariant(), $marker.ToLowerInvariant(),
        [Convert]::ToBase64String($bytes), [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($marker)),
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)),
        [Convert]::ToHexString([Security.Cryptography.SHA1]::HashData($bytes)),
        [Convert]::ToHexString([Security.Cryptography.SHA512]::HashData($bytes)),
        [Net.WebUtility]::HtmlEncode($marker), [Uri]::EscapeDataString($marker))
    foreach ($variant in $variants) {
        Assert-Equal $false ($Text.IndexOf($variant, [StringComparison]::OrdinalIgnoreCase) -ge 0) 'prohibited marker and declared transforms do not cross a retained/public boundary'
    }
}

function Add-QualificationWorkerFault {
    param([string] $ModuleText, [string] $Family, [string] $Fault)
    if ($Family -like 'Identity*') {
        $mode=if($Family -eq 'IdentityRegistration'){'RegistrationUser'}else{'WorkSchool'}
        $before='var result=new NativeSnapshot(); string scenario='
        if (-not $ModuleText.Contains($before)) { throw 'Controlled identity native source is absent.' }
        $action=if($Fault -eq 'Loss'){'throw new System.InvalidOperationException();'}else{'System.Threading.Thread.Sleep(30000);'}
        $ModuleText=$ModuleText.Replace($before,('if(mode=="'+$mode+'"){'+$action+'} '+$before))
        $ModuleText=Rename-QualificationFunction -Source $ModuleText -Name Invoke-BoundedIdentityNativeSnapshot -Replacement Invoke-OriginalQualificationIdentitySnapshot
        return $ModuleText + @'

function Invoke-BoundedIdentityNativeSnapshot {
    param($Policy,$CollectorIndex,$Mode)
    if(-not $script:StatusDeskTransport.State.ContainsKey('QualificationIdentityModes')){$script:StatusDeskTransport.State.QualificationIdentityModes=[Collections.Generic.List[string]]::new()}
    $script:StatusDeskTransport.State.QualificationIdentityModes.Add($Mode)
    $Policy.collectors[$CollectorIndex].deadlineMilliseconds=4000
    if($Mode -eq '__MODE__' -and '__FAULT__' -eq 'Cancel'){$script:StatusDeskTransport.Cancellation.CancelAfter(2000)}
    $result=Invoke-OriginalQualificationIdentitySnapshot -Policy $Policy -CollectorIndex $CollectorIndex -Mode $Mode
    if($Mode -eq '__MODE__'){$script:StatusDeskTransport.State.QualificationWorkerReason=$result.reasonCode}
    $result
}
'@.Replace('__MODE__',$mode).Replace('__FAULT__',$Fault)
    }
    $stem = @{ Software='SoftwareInventory'; Resource='ResourceDependencies'; Network='NetworkTopology'; Certificate='CertificateTrust' }[$Family]
    # Use the real generated NativeRunner/Job Object and snapshot admission.
    # Only the OS source program is replaced by an inert controlled worker.
    if ($Family -in @('Network','Certificate')) {
        $ModuleText=$ModuleText.Replace("function Invoke-Bounded$($stem)Snapshot {", "function Unused-Controlled$($stem)Snapshot {")
        $ModuleText=$ModuleText.Replace("function Invoke-Unused$($stem)Snapshot {", "function Invoke-Bounded$($stem)Snapshot {")
    }
    $ModuleText=$ModuleText.Replace("function Get-$($stem)LiveSource {", "function Unused-Qualification$($stem)LiveSource {")
    $ModuleText += "`nfunction Get-$($stem)LiveSource { param(`$Policy) '" + $(if($Fault -eq 'Loss'){'exit 7'}else{'[Threading.Thread]::Sleep(30000)'}) + "' }`n"
    $ModuleText=$ModuleText.Replace("function Invoke-Bounded$($stem)Snapshot {", "function Original-Qualification$($stem)Snapshot {")
    $ModuleText += @'

function Invoke-Bounded__STEM__Snapshot {
    param($Policy,$AssessmentUserSid)
    $Policy.collector.deadlineMilliseconds=4000
    if('__FAULT__' -eq 'Cancel'){$script:StatusDeskTransport.Cancellation.CancelAfter(2000)}
    $snapshot=Original-Qualification__STEM__Snapshot -Policy $Policy -AssessmentUserSid $AssessmentUserSid
    $script:StatusDeskTransport.State.QualificationWorkerReason=$snapshot.reasonCode
    $snapshot
}
'@.Replace('__STEM__',$stem).Replace('__FAULT__',$Fault)
    $ModuleText
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

function Assert-QualificationScopeScheduling {
    param($Record, [string] $CancelledAfter)
    $stages = @('Identity','Resource','Network','Software','Certificate','Connectivity')
    $prefixes = @('', 'scope:resource.', 'scope:network.', 'scope:software.', 'scope:certificate.', 'scope:connectivity.')
    $stoppedIndex = [array]::IndexOf($stages, $CancelledAfter)
    for ($index = $stoppedIndex + 1; $index -lt $stages.Count; $index++) {
        foreach ($scope in @($Record.coverage | Where-Object { $_.scopeId.StartsWith($prefixes[$index], [StringComparison]::Ordinal) })) {
            Assert-Equal 'NotAttempted' $scope.state 'cancellation prevents later selected scopes from claiming an attempt'
            Assert-Equal 0 @($scope.observationIds).Count 'an unscheduled scope carries no observations'
            Assert-Equal 0 @($Record.collectorResults | Where-Object { $scope.coverageId -in $_.coverageIds }).Count 'unscheduled scope has no collector envelope'
        }
    }
}
