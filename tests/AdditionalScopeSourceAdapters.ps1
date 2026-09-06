Set-StrictMode -Version Latest

# Closed, repository-owned OS fault fixtures. The source reducers, authenticated
# worker protocol, ordinary scheduler, record admission and package/report stay
# active. A missing named double refuses execution instead of using Windows.
function Add-AdditionalScopeSource {
    param([string] $ModuleText, $Case)
    if($Case.PSObject.Properties['moduleReplacements']) {
        foreach($replacement in $Case.moduleReplacements) {
            if(-not $ModuleText.Contains([string]$replacement.before)){throw 'Controlled collector input boundary is absent.'}
            $ModuleText=$ModuleText.Replace([string]$replacement.before,[string]$replacement.after)
        }
    }
    $provider = [string]$Case.provider
    $isCertificate = $provider -eq 'Get-ControlledCertificateSource'
    if(-not $isCertificate) {
        $ModuleText = Rename-QualificationFunction -Source $ModuleText -Name $provider -Replacement "ScopeOriginal-$provider"
    }
    $fixture = ($Case | ConvertTo-Json -Depth 12 -Compress).Replace("'", "''")
    $ModuleText += "`n`$script:AdditionalScopeFixture = ConvertFrom-Json -InputObject '$fixture'`n"
    $ModuleText += @'

function Edit-AdditionalScopeSource {
    param([string] $Source)
    $Source=$Source.Replace("`r`n","`n").Replace("`r","`n")
    foreach ($fault in $script:AdditionalScopeFixture.functionFaults) {
        $tokens=$null; $errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($Source,[ref]$tokens,[ref]$errors)
        if ($errors.Count) { throw 'Controlled scope source does not parse.' }
        $matches=@($ast.FindAll({param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $fault.name
        }, $true))
        if ($matches.Count -ne 1) { throw "Controlled scope double is not unique: $($fault.name)" }
        $body=$matches[0].Body
        $offset=if($null -ne $body.ParamBlock){$body.ParamBlock.Extent.EndOffset}else{$body.Extent.StartOffset+1}
        $Source=$Source.Insert($offset, "`n$($fault.code)`n")
    }
    foreach ($replacement in $script:AdditionalScopeFixture.replacements) {
        if (-not $Source.Contains([string]$replacement.before)) { throw 'Controlled scope replacement anchor is absent.' }
        $Source=$Source.Replace([string]$replacement.before,[string]$replacement.after)
    }
    $Source
}
'@
    if($isCertificate){return Edit-QualificationEmbeddedCertificateSource -ModuleText $ModuleText -SourceEditor Edit-AdditionalScopeSource -TrackAdditionalSource}
    $ModuleText += @'

function __PROVIDER__ {
    $script:StatusDeskTransport.State.AdditionalSourceBuilt=$true
    $source=ScopeOriginal-__PROVIDER__ @args
    $isBytes=$source -is [array]
    if($isBytes){$source=[Text.Encoding]::UTF8.GetString([byte[]]$source)}
    $edited=Edit-AdditionalScopeSource -Source $source
    if($isBytes){,[Text.Encoding]::UTF8.GetBytes($edited)}else{$edited}
}
'@.Replace('__PROVIDER__',$provider)
    $ModuleText
}

function Assert-AdditionalScopeSource {
    param($Record, [string] $Html, $Case, $State)
    if($Case.id -like '*-ContextUnavailable' -or $Case.id -eq 'Network-ContextDenied') {
        Assert-Equal $false $State.ContainsKey('AdditionalSourceBuilt') 'an unavailable or prohibited Assessment User context stops before entering the OS source'
    }
    foreach ($expectation in $Case.expected) {
        $scopes=@($Record.coverage | Where-Object scopeId -Like $expectation.pattern)
        Assert-Equal $expectation.count $scopes.Count 'the fault expectation names its exact selected scope set'
        foreach ($scope in $scopes) {
            Assert-Equal $expectation.state $scope.state "$($Case.id): actual source disposition for $($scope.scopeId)"
            if ($scope.state -ne 'Complete') {
                Assert-Equal $true ([bool]$scope.reasonCode) 'a source gap retains its stable diagnostic reason'
                Assert-Equal $true $Html.Contains($scope.reasonCode) 'the protected report explains the source gap'
            }
        }
    }
}
