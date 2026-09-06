[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/CertificateTrust.ps1')
. (Join-Path $PSScriptRoot 'CertificateSourceAdapters.ps1')
$originalCulture=[Globalization.CultureInfo]::CurrentCulture
$originalUICulture=[Globalization.CultureInfo]::CurrentUICulture
try {
    $policy=Get-CertificateTrustPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)
    $source=Get-ControlledCertificateSource -Source (Get-CertificateTrustLiveSource -Policy $policy) -Scenario ValidTrusted
    # Pin only the OS double's dates. JSON date recognition, source admission
    # and canonical evidence assembly are the production implementations.
    $source=$source.Replace('[DateTimeOffset]::UtcNow.AddYears(-1).UtcDateTime','[DateTime]::new(2025,9,6,12,34,56,[DateTimeKind]::Utc)').Replace('[DateTimeOffset]::UtcNow.AddYears(1).UtcDateTime','[DateTime]::new(2027,9,6,12,34,56,[DateTimeKind]::Utc)')
    foreach($culture in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')) {
        [Globalization.CultureInfo]::CurrentCulture=$culture
        [Globalization.CultureInfo]::CurrentUICulture=$culture
        $payload=(& ([scriptblock]::Create($source)))|ConvertFrom-Json
        Assert-Equal $true ($payload.candidates[0].notBefore -is [DateTime]) 'the source JSON crosses the actual date-recognition boundary'
        Assert-Equal $true (Test-CertificateTrustPayload $payload $policy) "$culture admits valid certificate timestamps"
        $record=[pscustomobject]@{
            run=[pscustomobject]@{runId='run:synthetic-certificate-culture';evidenceProfileId='profile:device-firmware-identity-administrator-policy-software-resource-and-network-readiness';outcome='Completed'}
            subjects=@();observations=@();provenance=@();coverage=@();diagnostics=@();collectorResults=@()
        }
        $result=[pscustomobject]@{cleanupVerified=$true;payload=$payload;envelope=[pscustomobject]@{executionContext='StandardUser';startedAt='2026-09-06T00:00:00Z';completedAt='2026-09-06T00:00:01Z'}}
        $record=Add-CertificateTrustEvidenceRecord $record $result $policy
        $timestamps=@($record.observations|Where-Object fieldId -in @('field:certificate.not-before','field:certificate.not-after'))
        Assert-Equal 10 $timestamps.Count 'all five source certificates contribute both validity timestamps'
        foreach($observation in $timestamps) {
            $expected=if($observation.fieldId -eq 'field:certificate.not-before'){'UTC 2025-09-06 12:34:56'}else{'UTC 2027-09-06 12:34:56'}
            Assert-Equal $expected $observation.value "$culture preserves the same Gregorian UTC instant in canonical evidence"
        }
        $payload.candidates[0].notAfter='not-a-date'
        Assert-Equal $false (Test-CertificateTrustPayload $payload $policy) "$culture still refuses malformed timestamps"
        $payload.candidates[0].notAfter='2000-01-01T00:00:00Z'
        Assert-Equal $false (Test-CertificateTrustPayload $payload $policy) "$culture still refuses reversed validity intervals"
    }
}
finally {
    [Globalization.CultureInfo]::CurrentCulture=$originalCulture
    [Globalization.CultureInfo]::CurrentUICulture=$originalUICulture
}
Write-Output 'PASS: certificate JSON timestamps retain invariant admission and Gregorian UTC evidence in all five cultures.'
