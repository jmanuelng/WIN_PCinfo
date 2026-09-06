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

function Add-QualificationProhibitedPayload {
    param([string] $ModuleText, [string] $Boundary)
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
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($Source,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Controlled source did not parse for culture qualification.' }
    $offset=if($null -ne $ast.ParamBlock){$ast.ParamBlock.Extent.EndOffset}else{0}
    $Source.Insert($offset, "`n[Globalization.CultureInfo]::CurrentCulture='__CULTURE__'; [Globalization.CultureInfo]::CurrentUICulture='__CULTURE__'`n")
}
'@.Replace('__CULTURE__', $Culture)
    foreach ($name in @('Get-SyntheticCollectorScriptBytes', 'Get-PrivilegedCollectionWorkerSource',
        'Get-SystemCollectionWorkerSource', 'Get-SoftwareInventoryLiveSource', 'Get-ResourceDependenciesLiveSource')) {
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
