Set-StrictMode -Version Latest

function New-FormatContractRecord {
    $record = Get-Content (Join-Path $PSScriptRoot 'fixtures/contract-positive.json') -Raw |
        ConvertFrom-Json -Depth 30 -DateKind String
    $record.requiredFeatures += 'software-recognition-annotations'
    $record.subjects += [pscustomobject]@{ subjectId='subject:software:1'; kind='Application' }
    $record | Add-Member softwareRecognition @([pscustomobject]@{
        annotationId='annotation:synthetic:1'; subjectId='subject:software:1'
        outcome='RecognizedExact'; familyId='family:synthetic'; familyLabel='Synthetic 界 😀'
        roles=@('Browser'); matcherIds=@('matcher:synthetic'); matcherTypes=@('ExactMsiProductCode')
        matchStrengthExplanation='Synthetic exact identity'; reasonCode=$null
        catalogRevision=1; catalogRelease='2.0.0-preview.1'; catalogDigest=('a'*64)
        provenance=@([pscustomobject]@{
            sourceType='PrimaryPublisherDocumentation'; owner='Synthetic'; reviewer='Synthetic'
            url='https://example.invalid/%E7%95%8C?q=one%20two#fragment'; verifiedOn='2000-02-29'
            pinnedCommit=$null; manifestPath=$null
        })
    })
    $record
}

function Set-FormatContractValue {
    param($Record, [string]$Field, [string]$Value)
    switch ($Field) {
        collectedAt { $Record.provenance[0].collectedAt=$Value }
        startedAt { $Record.collectorResults[0].startedAt=$Value }
        completedAt { $Record.collectorResults[0].completedAt=$Value }
        verifiedOn { $Record.softwareRecognition[0].provenance[0].verifiedOn=$Value }
        url { $Record.softwareRecognition[0].provenance[0].url=$Value }
    }
}
