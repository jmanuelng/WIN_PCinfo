[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/DeviceReadiness.ps1')
# Independent reference: the previously delivered sequence of exact replacements.
function Invoke-LegacyReportAnchorTransform {
    param([string]$Html,[Collections.Generic.Dictionary[string,string]]$Anchors,[switch]$IncludeFragmentLinks)
    foreach($key in $Anchors.Keys){
        $Html=$Html.Replace('id="'+$key+'"','id="'+$Anchors[$key]+'"')
        if($IncludeFragmentLinks){$Html=$Html.Replace('href="#'+$key+'"','href="#'+$Anchors[$key]+'"')}
    }
    $Html
}
$anchors=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$anchors.Add('observation:case:a','o0');$anchors.Add('observation:case:A','o1')
$anchors.Add('observation:case:b','o2');$anchors.Add('recommendation:case:a','r0')
$anchors.Add('observation:with space','o4');$anchors.Add('recommendation:case:b','r1');$anchors.Add('observation:encoded:&quot;','o3')
$cases=@(
    '<span id="observation:with space">Space in supplied map</span>',
    '', '<main id="unrelated"><a href="#unrelated">Unknown</a></main>',
    '<td id="observation:case:a">same</td><td id="observation:case:A">same</td>',
    '<a href="#recommendation:case:a">Link</a><li id="recommendation:case:a">Target</li>',
    '<td id="observation:case:b">1</td><td id="observation:case:b">2</td>',
    '<li id="recommendation:case:a">First</li><li id="recommendation:case:a">Duplicate</li><a href="#recommendation:case:a">Repeated</a>',
    '<p>&lt;span id=&quot;observation:case:a&quot;&gt;escaped value&lt;/span&gt;</p>',
    '<span id="observation:encoded:&quot;">Encoded key</span>',
    'prefixid="recommendation:case:b" suffixhref="#recommendation:case:b"',
    '<p ID="observation:case:a">Capital attribute</p><a href="#observation:case:a">Observation link</a>',
    ('<div id="observation:case:a"><a href="#recommendation:case:b">日本 العربية &amp;</a></div>'*2048)
)
foreach($links in @($false,$true)){
    foreach($html in $cases){
        $expected=Invoke-LegacyReportAnchorTransform -Html $html -Anchors $anchors -IncludeFragmentLinks:$links
        $actual=Convert-AssessmentReportAnchorIds -Html $html -Anchors $anchors -IncludeFragmentLinks:$links
        Assert-Equal $expected $actual 'one-pass markup transformation preserves the prior complete byte sequence'
    }
}
$invalid=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$invalid.Add('first','second');$invalid.Add('second','third')
$rejected=$false
try{$null=Convert-AssessmentReportAnchorIds -Html '<b id="first">' -Anchors $invalid}catch{$rejected=$true}
Assert-Equal $true $rejected 'overlapping source and destination names cannot silently change sequential-replacement semantics'
Write-Output 'PASS: one-pass report anchors equal the independent legacy transform across 24 empty, escaped, case-sensitive, repeated, multilingual and maximum corpus cases.'
