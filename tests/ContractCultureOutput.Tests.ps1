[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'AssessmentQualificationSupport.ps1')
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$hostPath = Resolve-WinPCInfoRuntime -ApplicationPath $candidate
$root = Join-Path $repositoryRoot ('.test-output/contract-cultures-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
try {
    $record = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/contract-positive.json') -Raw | ConvertFrom-Json -Depth 30
    $record.observations[0].value = 'Español | 日本語 | العربية | İı | 🔒 | é | "quoted"'
    $positive = Join-Path $root 'unicode.json'
    [IO.File]::WriteAllText($positive, ($record | ConvertTo-Json -Depth 30 -Compress), [Text.UTF8Encoding]::new($false))
    $record.observations[0] | Add-Member -NotePropertyName password -NotePropertyValue 'Synthetic-154-秘密-İ-🔒'
    $negative = Join-Path $root 'prohibited.json'
    [IO.File]::WriteAllText($negative, ($record | ConvertTo-Json -Depth 30 -Compress), [Text.UTF8Encoding]::new($false))
    foreach ($culture in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')) {
        $bootstrap = Join-Path $root 'culture-host.ps1'
        $source = @'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Globalization.CultureInfo]::CurrentCulture = '__CULTURE__'
[Globalization.CultureInfo]::CurrentUICulture = '__CULTURE__'
$application = $args[0]
$applicationArguments = $args[1..($args.Count-1)]
& $application @applicationArguments
exit $LASTEXITCODE
'@.Replace('__CULTURE__', $culture)
        [IO.File]::WriteAllText($bootstrap, $source, [Text.UTF8Encoding]::new($false))
        foreach ($fixture in @($positive, $negative)) {
            $run = Invoke-GeneratedApplication -CandidatePath $bootstrap -PowerShellPath $hostPath -Arguments @(
                $candidate, '-Mode','Automation','-RequestPath',(Join-Path $PSScriptRoot 'fixtures/automation-request.json'),
                '-AcceptPreparation','-PreparationFixturePath',(Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'),
                '-ContractFixturePath',$fixture)
            Assert-Equal '' $run.StandardError 'redirected stderr carries no diagnostic or ANSI text'
            Assert-Equal $false $run.StandardOutput.Contains([string][char]27) 'redirected stdout contains no ANSI escape sequence'
            Assert-QualificationMarkerAbsent -Text ($run.StandardOutput + $run.StandardError)
            $validation = @($run.Records | Where-Object recordType -eq 'win-pcinfo.contract-validation')
            Assert-Equal 1 $validation.Count 'redirected UTF-8 JSON has exactly one validator result'
            Assert-Equal ($fixture -eq $positive) $validation[0].accepted 'Unicode data and prohibited input retain their culture-independent admission result'
            Assert-Equal 1 @($run.Records | Where-Object recordType -eq 'win-pcinfo.terminal').Count 'each culture reaches one truthful terminal'
            Assert-Equal $false $run.Records[-1].collectionStarted 'controlled contract qualification cannot authorize collection'
        }
        Write-Output "PASS: $culture redirected UTF-8/Unicode JSON, ANSI exclusion and prohibited-marker transforms."
    }
}
finally {
    $resolved = [IO.Path]::GetFullPath($root)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))) { throw 'Culture test cleanup escaped its parent.' }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved, $true) }
}
