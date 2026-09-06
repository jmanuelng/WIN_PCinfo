Set-StrictMode -Version Latest

function Set-SoftwareReportTestValues {
    param($Entries,[string]$Scenario)
    if($Scenario -eq 'Maximum'){return}
    $index=0
    foreach($entry in $Entries){
        foreach($property in @('displayName','version','publisher')){
            if($null -eq $entry.$property){continue}
            $length=[Text.Encoding]::UTF8.GetByteCount([string]$entry.$property)
            $prefix="$index/$property/日本<&`"/"
            $remaining=$length-[Text.Encoding]::UTF8.GetByteCount($prefix)
            $fill=if($Scenario -eq 'EscapedOverflow'){'&'}else{[string][char](65+($index%26))}
            $entry.$property=$prefix+($fill*$remaining)
        }
        $index++
    }
}

function Expand-SoftwareReportText {
    param([string]$Html)
    $suffixes = @{}
    foreach ($match in [regex]::Matches($Html, '(?s)<li id="st(\d+)"><code>(.*?)</code>')) {
        $suffixes[$match.Groups[1].Value] = $match.Groups[2].Value
    }
    # Decode only the explicitly declared text suffix links. Compare the full
    # reconstructed values against every protected canonical registration.
    [regex]::Replace($Html, '<a href="#st(\d+)">\[suffix \d+\]</a>', {
        param($match)
        Assert-Equal $true $suffixes.ContainsKey($match.Groups[1].Value) 'every suffix resolves to exact retained text'
        $suffixes[$match.Groups[1].Value]
    })
}

function Assert-SoftwareReportEvidence {
    param($Record,[string]$Html)
    $expandedHtml = Expand-SoftwareReportText -Html $Html
    Assert-Equal 128 @($Record.subjects|Where-Object kind -eq Application).Count 'all registrations survive protected reopening'
    Assert-Equal 8 @($Record.coverage|Where-Object { $_.scopeId -like 'scope:software.*' -and $_.state -eq 'Complete' }).Count 'all software source scopes remain Complete'
    Assert-Equal 128 @($Record.softwareRecognition|Where-Object outcome -eq Unrecognized).Count 'recognition remains conservative for every registration'
    $software=[regex]::Match($expandedHtml,'(?s)<summary>Restricted installed-software evidence</summary>(.*?)</details>').Groups[1].Value
    $rows=@(foreach($table in [regex]::Matches($software,'(?s)<table><caption>(.*?)</caption>.*?<tbody>(.*?)</table>')){
        $prefix=[regex]::Match($table.Groups[1].Value,'Field prefix: ([^ ]+)').Groups[1].Value
        $metadata=@{}
        foreach($item in [regex]::Matches($table.Groups[1].Value,'(?s)<dt>([^<]*)<dd>(.*?)(?=<dt>|</dl>)')){
            $metadata[$prefix+$item.Groups[1].Value]=[Net.WebUtility]::HtmlDecode($item.Groups[2].Value)
        }
        $fields=@([regex]::Matches($table.Value,'<th scope="col">([^<]*)')|ForEach-Object {$prefix+$_.Groups[1].Value})
        foreach($row in [regex]::Matches($table.Groups[2].Value,'(?s)<tr>(<td(?: id="o\d+")?>.*?)(?=<tr>|$)')){
            $cells=@([regex]::Matches($row.Groups[1].Value,'(?s)<td(?: id="o\d+")?>(.*?)(?=<td|$)')|ForEach-Object {[Net.WebUtility]::HtmlDecode($_.Groups[1].Value)})
            Assert-Equal $fields.Count $cells.Count 'each software value has its own declared column'
            $values=$metadata.Clone()
            for($index=0;$index -lt $fields.Count;$index++){$values[$fields[$index]]=$cells[$index]}
            [pscustomobject]@{identity=$cells[0];values=$values}
        }
    })
    Assert-Equal 128 $rows.Count 'the report keeps one separate row per registration, including duplicate values'
    foreach($subject in @($Record.subjects|Where-Object kind -eq Application)){
        $observations=@($Record.observations|Where-Object { $_.subjectId -eq $subject.subjectId -and $_.fieldId -ne 'field:software.msix.package-full-name' })
        $identity=[string]$observations[0].value
        $row=@($rows|Where-Object identity -CEQ $identity)
        Assert-Equal 1 $row.Count 'each source identity resolves to its own report row'
        foreach($observation in $observations){
            $expected=if($observation.valueState -eq 'ObservedValue'){[string]$observation.value}else{[string]$observation.valueState}
            Assert-Equal $expected $row[0].values[[string]$observation.fieldId] 'identity-associated named fields preserve exact provider text and explicit unknown states'
        }
    }
    Assert-Equal $false ($Html -match '<script\b') 'the complete evidence report remains usable without scripts'
    $securityRows=[regex]::Matches($Html,'<tr><td>([^<]*)<td(?: id="o\d+")?>([^<]*)<td>([^<]*)<td><a href="#ss(\d+)">')
    Assert-Equal $true ($securityRows.Count -gt 0) 'the compact security table retains observable evidence'
    foreach($row in $securityRows){
        $id=[Net.WebUtility]::HtmlDecode($row.Groups[3].Value)
        $idParts = [regex]::Match($Html, 'Prefix: <code>([^<]*)</code>; suffix: <code>([^<]*)</code>')
        if ($idParts.Success) {
            $id = if ($id.StartsWith('Full: ', [StringComparison]::Ordinal)) { $id.Substring(6) } else {
                [Net.WebUtility]::HtmlDecode($idParts.Groups[1].Value) + $id + [Net.WebUtility]::HtmlDecode($idParts.Groups[2].Value)
            }
        }
        $observation=@($Record.observations|Where-Object observationId -CEQ $id)[0]
        $field = [Net.WebUtility]::HtmlDecode($row.Groups[1].Value)
        if ($Html.Contains('Field prefix: field:policy.')) {
            $field = if ($field.StartsWith('Full: ', [StringComparison]::Ordinal)) { $field.Substring(6) } else { 'field:policy.' + $field }
        }
        Assert-Equal ([string]$observation.fieldId) $field 'security observation IDs still identify the exact field'
        if($observation.valueState -eq 'ObservedValue'){
            Assert-Equal ([string]$observation.value) ([Net.WebUtility]::HtmlDecode($row.Groups[2].Value)) 'compact security rows preserve observed values'
        }
        $origin=@($Record.provenance|Where-Object provenanceId -CEQ $observation.provenanceId)[0]
        $source=[regex]::Match($Html,'<li id="ss'+$row.Groups[4].Value+'">Source \d+: ([^<]*); <a href="#sc(\d+)">')
        Assert-Equal ([string]$origin.sourceId) ([Net.WebUtility]::HtmlDecode($source.Groups[1].Value)) 'shared source links resolve the original provenance'
        $context=[regex]::Match($Html,'<li id="sc'+$source.Groups[2].Value+'">Context \d+<br>Subject: ([^<]*)<br>Execution context: ([^<]*)<br>Collected: ([^<]*)<br>Source locale: ([^<]*)')
        Assert-Equal ([string]$observation.subjectId) ([Net.WebUtility]::HtmlDecode($context.Groups[1].Value)) 'shared contexts preserve the exact subject'
        Assert-Equal ([string]$origin.executionContext) ([Net.WebUtility]::HtmlDecode($context.Groups[2].Value)) 'shared contexts preserve execution context'
        Assert-Equal ([DateTimeOffset]$origin.collectedAt) ([DateTimeOffset]$context.Groups[3].Value) 'shared contexts preserve collection time through JSON reopening'
        Assert-Equal ([string]$origin.sourceLocale) ([Net.WebUtility]::HtmlDecode($context.Groups[4].Value)) 'shared contexts preserve source locale'
    }
    foreach($link in [regex]::Matches($Html,'href="(#[^"]*recommendation[^"]*)"')){
        Assert-Equal $true $Html.Contains('id="'+$link.Groups[1].Value.Substring(1)+'"') 'overview recommendation links resolve retained migration details'
    }
}
