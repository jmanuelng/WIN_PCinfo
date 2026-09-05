$script:ResourceDependenciesPolicyBase64 = '__RESOURCE_DEPENDENCIES_POLICY_BASE64__'
$script:ResourceDependenciesPolicyDigest = '__RESOURCE_DEPENDENCIES_POLICY_SHA256__'

function Get-ResourceDependenciesSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-ResourceDependenciesPolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    if($script:ResourceDependenciesPolicyBase64 -eq ('__RESOURCE_DEPENDENCIES_' + 'POLICY_BASE64__')){
        $path=Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-resource-dependencies.json'
        $text=[IO.File]::ReadAllText($path,[Text.UTF8Encoding]::new($false,$true)).Replace("`r`n","`n").Replace("`r","`n")
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes($text)
        $expectedDigest=Get-ResourceDependenciesSha256 -Bytes $bytes
    }else{
        $bytes=[Convert]::FromBase64String($script:ResourceDependenciesPolicyBase64)
        $expectedDigest=$script:ResourceDependenciesPolicyDigest
    }
    if((Get-ResourceDependenciesSha256 -Bytes $bytes) -ne $expectedDigest){
        throw 'The embedded Resource Dependencies policy failed integrity validation.'
    }
    $policy=& $ConvertFromJsonCommand -InputObject (
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    ) -Depth 30 -ErrorAction Stop
    if($policy.kind -ne 'win-pcinfo.resource-dependencies-policy' -or
        $policy.contractVersion -ne '1.0.0' -or
        $policy.policyId -ne 'win-pcinfo.resource-dependencies/1.0.0' -or
        @($policy.layers).Count -ne 2 -or @($policy.sourceCatalog).Count -ne 5 -or
        @($policy.peripheralClassCatalog).Count -ne 8 -or @($policy.scopes).Count -ne 5 -or
        @($policy.rules).Count -ne 3 -or @($policy.recommendations).Count -ne 2 -or
        @($policy.validationScenarios).Count -ne 14){
        throw 'The Resource Dependencies policy is not semantically closed.'
    }
    $policy
}

function Read-ResourceDependenciesFixture {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)]$ConvertFromJsonCommand,
        [Parameter(Mandatory)]$Policy
    )
    try{
        $bytes=[IO.File]::ReadAllBytes([IO.Path]::GetFullPath($LiteralPath))
        if($bytes.Length -lt 1 -or $bytes.Length -gt 512){throw 'Fixture size is invalid.'}
        $json=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        $document=[Text.Json.JsonDocument]::Parse($json)
        try{
            $names=@($document.RootElement.EnumerateObject()|ForEach-Object Name)
            if($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
                (@($names|Sort-Object)-join '|') -ne 'contractVersion|scenario'){
                throw 'Fixture shape is invalid.'
            }
        }finally{$document.Dispose()}
        $fixture=& $ConvertFromJsonCommand -InputObject $json -Depth 5 -ErrorAction Stop
        if($fixture.contractVersion -ne '1.0.0' -or
            [string]$fixture.scenario -notin @($Policy.validationScenarios)){
            throw 'Fixture scenario is not release-owned.'
        }
        [string]$fixture.scenario
    }catch{
        throw [InvalidOperationException]::new(
            'The synthetic Resource Dependencies fixture is invalid.',$_.Exception
        )
    }
}

function New-ResourceDependencyScopeState {
    param([Parameter(Mandatory)][string]$ScopeId,[string]$State='Complete',[string]$ReasonCode='')
    [pscustomobject][ordered]@{scopeId=$ScopeId;state=$State;reasonCode=$ReasonCode}
}

function New-ResourceDependenciesSyntheticPayload {
    param([Parameter(Mandatory)][string]$Scenario,[Parameter(Mandatory)]$Policy)

    $mapped=@();$unc=@();$printers=@();$drivers=@();$peripherals=@()
    $sourceLocale='und';$relationship='SameUser';$observedContext='Synthetic'
    $state='Complete';$reason=''
    $mappedItem=[pscustomobject][ordered]@{
        localName='R:';remoteEndpoint='\\synthetic-file\migration';connectionState='Connected'
        providerName='Microsoft Windows Network'
    }
    $uncItem=[pscustomobject][ordered]@{
        remoteEndpoint='\\synthetic-file\department';connectionState='Connected'
        providerName='Microsoft Windows Network'
    }
    $printerItem=[pscustomobject][ordered]@{
        name='Synthetic Office Printer';portName='SYNTHETIC-PORT:'
        driverName='Synthetic Universal Driver';network=$true;default=$false;offline=$false
    }
    $driverItem=[pscustomobject][ordered]@{
        name='Synthetic Universal Driver';manufacturer='Synthetic Vendor'
        version='1.0.0.0';infName='synthetic-printer.inf'
    }
    $peripheralItem=[pscustomobject][ordered]@{
        class='USB';name='Synthetic Dock';manufacturer='Synthetic Vendor'
        driverProvider='Synthetic Provider';driverVersion='2.0.0.0'
        driverInfName='synthetic-device.inf';driverSigned=$true
    }
    switch($Scenario){
        'MappedDrive'{$mapped=@($mappedItem)}
        'DisconnectedDrive'{
            $mapped=@([pscustomobject][ordered]@{
                localName='S:';remoteEndpoint='\\synthetic-file\archive'
                connectionState='Disconnected';providerName='Microsoft Windows Network'
            })
        }
        'UncResource'{$unc=@($uncItem)}
        'Printers'{
            $printers=@($printerItem,[pscustomobject][ordered]@{
                name='Synthetic Local Printer';portName='SYNTHETIC-LOCAL:'
                driverName='Synthetic Local Driver';network=$false;default=$true;offline=$false
            })
            $drivers=@($driverItem,[pscustomobject][ordered]@{
                name='Synthetic Local Driver';manufacturer='Synthetic Vendor'
                version='1.0.0.1';infName='synthetic-local.inf'
            })
        }
        'PortsAndDrivers'{$printers=@($printerItem);$drivers=@($driverItem)}
        'Peripherals'{
            $peripherals=@(
                $peripheralItem,
                [pscustomobject][ordered]@{class='HIDClass';name='Synthetic Keyboard';manufacturer='Synthetic Vendor';driverProvider='Synthetic Provider';driverVersion='2.0.0.1';driverInfName='synthetic-hid.inf';driverSigned=$true},
                [pscustomobject][ordered]@{class='Bluetooth';name='Synthetic Headset';manufacturer='Synthetic Vendor';driverProvider='Synthetic Provider';driverVersion='2.0.0.2';driverInfName='synthetic-bt.inf';driverSigned=$true}
            )
        }
        'Empty'{}
        'Denied'{$state='Denied';$reason='RESOURCE.SOURCE_ACCESS_DENIED'}
        'Partial'{
            $state='Partial';$reason='RESOURCE.EVIDENCE_BOUND_EXCEEDED'
            $mapped=@(0..7|ForEach-Object {[pscustomobject][ordered]@{localName="$([char](82+$_)):";remoteEndpoint="\\synthetic-file\bounded-$($_+1)";connectionState='Connected';providerName='Microsoft Windows Network'}})
            $unc=@(0..7|ForEach-Object {[pscustomobject][ordered]@{remoteEndpoint="\\synthetic-file\unc-$($_+1)";connectionState='Connected';providerName='Microsoft Windows Network'}})
            $printers=@(0..7|ForEach-Object {[pscustomobject][ordered]@{name="Synthetic Printer $($_+1)";portName="SYNTHETIC-$($_+1):";driverName="Synthetic Driver $($_+1)";network=$true;default=$false;offline=$false}})
            $drivers=@(0..7|ForEach-Object {[pscustomobject][ordered]@{name="Synthetic Driver $($_+1)";manufacturer='Synthetic Vendor';version="1.0.0.$_";infName="synthetic-$_.inf"}})
            $peripherals=@(0..7|ForEach-Object {[pscustomobject][ordered]@{class='USB';name="Synthetic Peripheral $($_+1)";manufacturer='Synthetic Vendor';driverProvider='Synthetic Provider';driverVersion="2.0.0.$_";driverInfName="synthetic-device-$_.inf";driverSigned=$true}})
        }
        'Duplicates'{
            # Duplicate provider rows are intentional here. The exported copy
            # boundary must normalize them before evidence subjects are built.
            $mapped=@($mappedItem,$mappedItem);$unc=@($uncItem,$uncItem)
            $printers=@($printerItem,$printerItem);$drivers=@($driverItem,$driverItem)
            $peripherals=@($peripheralItem,$peripheralItem)
        }
        'LongUnicode'{
            $mapped=@([pscustomobject][ordered]@{localName='Ü:';remoteEndpoint='\\synthetic-file\迁移-Δοκιμή-équipe';connectionState='Connected';providerName='Réseau Windows'})
            $printers=@([pscustomobject][ordered]@{name='Imprimante-東京-Δοκιμή';portName='PORT-É:';driverName='Pilote-统一';network=$true;default=$false;offline=$false})
            $drivers=@([pscustomobject][ordered]@{name='Pilote-统一';manufacturer='Fabricant-É';version='3.0.0.0';infName='pilote-unicode.inf'})
            $peripherals=@([pscustomobject][ordered]@{class='USB';name='Périphérique-東京';manufacturer='Fabricant-É';driverProvider='Fournisseur-Δ';driverVersion='3.0.0.1';driverInfName='unicode-device.inf';driverSigned=$true})
        }
        'AlternateAdministrator'{$relationship='AlternateAdministrator';$observedContext='Administrator';$state='Denied';$reason='RESOURCE.ASSESSMENT_USER_CONTEXT_REQUIRED'}
        'LocalSystem'{$relationship='ProhibitedSystemContext';$observedContext='LocalSystem';$state='Denied';$reason='RESOURCE.ASSESSMENT_USER_CONTEXT_REQUIRED'}
        'NonEnglish'{
            $sourceLocale='fr-FR';$mapped=@([pscustomobject][ordered]@{localName='T:';remoteEndpoint='\\synthetic-file\équipe';connectionState='Connected';providerName='Réseau Windows'})
            $printers=@([pscustomobject][ordered]@{name='Imprimante Étage';portName='PORT-É:';driverName='Pilote Français';network=$true;default=$true;offline=$false})
            $drivers=@([pscustomobject][ordered]@{name='Pilote Français';manufacturer='Fabricant';version='4.0.0.0';infName='francais.inf'})
            $peripherals=@([pscustomobject][ordered]@{class='Mouse';name='Souris ergonomique';manufacturer='Fabricant';driverProvider='Fournisseur';driverVersion='4.0.0.1';driverInfName='souris.inf';driverSigned=$true})
        }
        default{throw 'The Resource Dependencies scenario is not release-owned.'}
    }
    [pscustomobject][ordered]@{
        sourceLocale=$sourceLocale;assessmentUserContextVerified=($relationship -eq 'SameUser')
        processRelationship=$relationship;mappedDrives=@($mapped);uncConnections=@($unc)
        printers=@($printers);printerDrivers=@($drivers);peripherals=@($peripherals)
        scopeStates=@($Policy.scopes|ForEach-Object {
            New-ResourceDependencyScopeState -ScopeId ([string]$_.scopeId) -State $state -ReasonCode $reason
        });executionContext=$observedContext
    }
}

function Test-ResourceDependencyObjectShape {
    param($Value,[string[]]$Names)
    $null -ne $Value -and (@($Value.PSObject.Properties.Name|Sort-Object)-join '|') -eq (@($Names|Sort-Object)-join '|')
}

function Test-ResourceDependencyString {
    param($Value,[int]$MaximumBytes,[switch]$AllowNull)
    if($null -eq $Value){return [bool]$AllowNull}
    if($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)){return $false}
    [Text.UTF8Encoding]::new($false).GetByteCount([string]$Value) -le $MaximumBytes
}

function Test-ResourceDependenciesCollectorPayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)]$Policy)
    try{
        if(-not (Test-ResourceDependencyObjectShape $Payload @('sourceLocale','assessmentUserContextVerified','processRelationship','mappedDrives','uncConnections','printers','printerDrivers','peripherals','scopeStates','executionContext'))){return $false}
        if($Payload.assessmentUserContextVerified -isnot [bool] -or
            [string]$Payload.processRelationship -notin @('SameUser','AlternateAdministrator','ElevatedAssessmentUser','DifferentStandardUser','ProhibitedSystemContext','Unavailable') -or
            [string]$Payload.executionContext -notin @('Synthetic','StandardUser','Administrator','LocalSystem') -or
            -not (Test-ResourceDependencyString $Payload.sourceLocale 35)){return $false}
        if([bool]$Payload.assessmentUserContextVerified){
            if([string]$Payload.processRelationship -ne 'SameUser' -or
                [string]$Payload.executionContext -notin @('Synthetic','StandardUser')){return $false}
        }else{
            $expectedContext=switch([string]$Payload.processRelationship){
                'AlternateAdministrator'{'Administrator'}
                'ElevatedAssessmentUser'{'Administrator'}
                'DifferentStandardUser'{'StandardUser'}
                'ProhibitedSystemContext'{'LocalSystem'}
                'Unavailable'{'StandardUser'}
                default{return $false}
            }
            if([string]$Payload.executionContext -ne $expectedContext){return $false}
        }
        $collections=@(
            @{value=@($Payload.mappedDrives);maximum=[int]$Policy.collector.maximumMappedDrives},
            @{value=@($Payload.uncConnections);maximum=[int]$Policy.collector.maximumUncConnections},
            @{value=@($Payload.printers);maximum=[int]$Policy.collector.maximumPrinters},
            @{value=@($Payload.printerDrivers);maximum=[int]$Policy.collector.maximumPrinterDrivers},
            @{value=@($Payload.peripherals);maximum=[int]$Policy.collector.maximumPeripherals}
        )
        if(@($collections|Where-Object {$_.value.Count -gt $_.maximum}).Count -gt 0){return $false}
        foreach($item in @($Payload.mappedDrives)){
            if(-not (Test-ResourceDependencyObjectShape $item @('localName','remoteEndpoint','connectionState','providerName')) -or
                -not (Test-ResourceDependencyString $item.localName 8) -or
                -not (Test-ResourceDependencyString $item.remoteEndpoint 512) -or
                [string]$item.remoteEndpoint -notmatch '^\\\\[^\\]+\\[^\\]+' -or
                [string]$item.connectionState -notin @('Connected','Disconnected','Unavailable') -or
                -not (Test-ResourceDependencyString $item.providerName 128 -AllowNull)){return $false}
        }
        foreach($item in @($Payload.uncConnections)){
            if(-not (Test-ResourceDependencyObjectShape $item @('remoteEndpoint','connectionState','providerName')) -or
                -not (Test-ResourceDependencyString $item.remoteEndpoint 512) -or
                [string]$item.remoteEndpoint -notmatch '^\\\\[^\\]+\\[^\\]+' -or
                [string]$item.connectionState -notin @('Connected','Disconnected','Unavailable') -or
                -not (Test-ResourceDependencyString $item.providerName 128 -AllowNull)){return $false}
        }
        foreach($item in @($Payload.printers)){
            if(-not (Test-ResourceDependencyObjectShape $item @('name','portName','driverName','network','default','offline')) -or
                -not (Test-ResourceDependencyString $item.name 512) -or -not (Test-ResourceDependencyString $item.portName 512) -or
                -not (Test-ResourceDependencyString $item.driverName 512) -or $item.network -isnot [bool] -or
                $item.default -isnot [bool] -or $item.offline -isnot [bool]){return $false}
        }
        foreach($item in @($Payload.printerDrivers)){
            if(-not (Test-ResourceDependencyObjectShape $item @('name','manufacturer','version','infName')) -or
                -not (Test-ResourceDependencyString $item.name 512) -or
                -not (Test-ResourceDependencyString $item.manufacturer 512 -AllowNull) -or
                -not (Test-ResourceDependencyString $item.version 128 -AllowNull) -or
                -not (Test-ResourceDependencyString $item.infName 260 -AllowNull)){return $false}
        }
        foreach($item in @($Payload.peripherals)){
            if(-not (Test-ResourceDependencyObjectShape $item @('class','name','manufacturer','driverProvider','driverVersion','driverInfName','driverSigned')) -or
                [string]$item.class -notin @($Policy.peripheralClassCatalog) -or
                -not (Test-ResourceDependencyString $item.name 512) -or
                -not (Test-ResourceDependencyString $item.manufacturer 512 -AllowNull) -or
                -not (Test-ResourceDependencyString $item.driverProvider 512 -AllowNull) -or
                -not (Test-ResourceDependencyString $item.driverVersion 128 -AllowNull) -or
                -not (Test-ResourceDependencyString $item.driverInfName 260 -AllowNull) -or
                $item.driverSigned -isnot [bool]){return $false}
        }
        if(@($Payload.scopeStates).Count -ne @($Policy.scopes).Count){return $false}
        $expected=@($Policy.scopes.scopeId|Sort-Object);$actual=@($Payload.scopeStates.scopeId|Sort-Object)
        if(($expected-join '|') -ne ($actual-join '|')){return $false}
        foreach($scope in @($Payload.scopeStates)){
            if(-not (Test-ResourceDependencyObjectShape $scope @('scopeId','state','reasonCode')) -or
                [string]$scope.state -notin @('Complete','Partial','Unavailable','Denied','Malformed','TimedOut','Cancelled','Failed') -or
                ($scope.state -eq 'Complete' -and -not [string]::IsNullOrEmpty([string]$scope.reasonCode)) -or
                ($scope.state -ne 'Complete' -and [string]::IsNullOrWhiteSpace([string]$scope.reasonCode))){return $false}
        }
        if(-not [bool]$Payload.assessmentUserContextVerified -and
            (@($Payload.mappedDrives).Count+@($Payload.uncConnections).Count+@($Payload.printers).Count+@($Payload.printerDrivers).Count+@($Payload.peripherals).Count -gt 0 -or
            @($Payload.scopeStates|Where-Object state -eq 'Complete').Count -gt 0)){return $false}
        return $true
    }catch{return $false}
}

function Copy-ResourceDependenciesCollectorPayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)]$Policy)
    if(-not (Test-ResourceDependenciesCollectorPayload -Payload $Payload -Policy $Policy)){
        throw 'The Resource Dependencies collector payload is outside the frozen contract.'
    }
    # Re-project every allowed primitive. This trust boundary intentionally
    # refuses object reuse so a collector cannot smuggle an undeclared property
    # such as a credential, print job, PnP identifier, or device serial into evidence.
    [pscustomobject][ordered]@{
        sourceLocale=[string]$Payload.sourceLocale
        assessmentUserContextVerified=[bool]$Payload.assessmentUserContextVerified
        processRelationship=[string]$Payload.processRelationship
        mappedDrives=@($Payload.mappedDrives|Sort-Object localName -Unique|ForEach-Object {[pscustomobject][ordered]@{localName=[string]$_.localName;remoteEndpoint=[string]$_.remoteEndpoint;connectionState=[string]$_.connectionState;providerName=if($null -eq $_.providerName){$null}else{[string]$_.providerName}}})
        uncConnections=@($Payload.uncConnections|Sort-Object remoteEndpoint -Unique|ForEach-Object {[pscustomobject][ordered]@{remoteEndpoint=[string]$_.remoteEndpoint;connectionState=[string]$_.connectionState;providerName=if($null -eq $_.providerName){$null}else{[string]$_.providerName}}})
        printers=@($Payload.printers|Sort-Object name -Unique|ForEach-Object {[pscustomobject][ordered]@{name=[string]$_.name;portName=[string]$_.portName;driverName=[string]$_.driverName;network=[bool]$_.network;default=[bool]$_.default;offline=[bool]$_.offline}})
        printerDrivers=@($Payload.printerDrivers|Sort-Object name -Unique|ForEach-Object {[pscustomobject][ordered]@{name=[string]$_.name;manufacturer=if($null -eq $_.manufacturer){$null}else{[string]$_.manufacturer};version=if($null -eq $_.version){$null}else{[string]$_.version};infName=if($null -eq $_.infName){$null}else{[string]$_.infName}}})
        peripherals=@($Payload.peripherals|Sort-Object class,name,driverVersion -Unique|ForEach-Object {[pscustomobject][ordered]@{class=[string]$_.class;name=[string]$_.name;manufacturer=if($null -eq $_.manufacturer){$null}else{[string]$_.manufacturer};driverProvider=if($null -eq $_.driverProvider){$null}else{[string]$_.driverProvider};driverVersion=if($null -eq $_.driverVersion){$null}else{[string]$_.driverVersion};driverInfName=if($null -eq $_.driverInfName){$null}else{[string]$_.driverInfName};driverSigned=[bool]$_.driverSigned}})
        scopeStates=@($Payload.scopeStates|ForEach-Object {[pscustomobject][ordered]@{scopeId=[string]$_.scopeId;state=[string]$_.state;reasonCode=[string]$_.reasonCode}})
        executionContext=[string]$Payload.executionContext
    }
}

function ConvertTo-ResourceDependencyAttemptPayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)]$Policy)
    if(Test-ResourceDependenciesCollectorPayload -Payload $Payload -Policy $Policy){
        return Copy-ResourceDependenciesCollectorPayload -Payload $Payload -Policy $Policy
    }
    # Provider strings and shapes cross an untrusted process boundary. Validate
    # each independently queried category so one drifting provider cannot erase
    # valid evidence from its siblings. The empty candidate first proves the
    # shared context and scope-state envelope; if that is corrupt, no category
    # is trustworthy and the whole attempt fails closed.
    if(-not (Test-ResourceDependencyObjectShape $Payload @(
        'sourceLocale','assessmentUserContextVerified','processRelationship','mappedDrives',
        'uncConnections','printers','printerDrivers','peripherals','scopeStates','executionContext'
    ))){
        return New-ResourceDependencyGapPayload -Policy $Policy -State 'Malformed' `
            -ReasonCode 'RESOURCE.SOURCE_PAYLOAD_MALFORMED' -Relationship 'SameUser' `
            -ObservedContext 'StandardUser'
    }
    function New-Candidate([string]$CollectionName,$CollectionValue){
        $candidate=[ordered]@{
            sourceLocale=$Payload.sourceLocale
            assessmentUserContextVerified=$Payload.assessmentUserContextVerified
            processRelationship=$Payload.processRelationship
            mappedDrives=@();uncConnections=@();printers=@();printerDrivers=@();peripherals=@()
            scopeStates=$Payload.scopeStates;executionContext=$Payload.executionContext
        }
        if($CollectionName){$candidate[$CollectionName]=@($CollectionValue)}
        [pscustomobject]$candidate
    }
    $emptyCandidate=New-Candidate '' @()
    if(-not (Test-ResourceDependenciesCollectorPayload -Payload $emptyCandidate -Policy $Policy)){
        return New-ResourceDependencyGapPayload -Policy $Policy -State 'Malformed' `
            -ReasonCode 'RESOURCE.SOURCE_PAYLOAD_MALFORMED' -Relationship 'SameUser' `
            -ObservedContext 'StandardUser'
    }
    $result=Copy-ResourceDependenciesCollectorPayload -Payload $emptyCandidate -Policy $Policy
    foreach($definition in @(
        @('mappedDrives','scope:resource.mapped-drives'),
        @('uncConnections','scope:resource.unc-connections'),
        @('printers','scope:resource.printers'),
        @('printerDrivers','scope:resource.printer-drivers'),
        @('peripherals','scope:resource.common-peripherals')
    )){
        $candidate=New-Candidate $definition[0] $Payload.($definition[0])
        if(Test-ResourceDependenciesCollectorPayload -Payload $candidate -Policy $Policy){
            $normalized=Copy-ResourceDependenciesCollectorPayload -Payload $candidate -Policy $Policy
            $result.($definition[0])=@($normalized.($definition[0]))
        }else{
            $scope=@($result.scopeStates|Where-Object scopeId -eq $definition[1])[0]
            $scope.state='Malformed';$scope.reasonCode='RESOURCE.SOURCE_PAYLOAD_MALFORMED'
        }
    }
    $result
}

function Invoke-ResourceDependenciesCollection {
    param(
        [Parameter(Mandatory)]$Policy,
        [Parameter()][string]$ValidationScenario,
        [Parameter()][switch]$Live,
        [Parameter()][string]$AssessmentUserSid,
        [Parameter()][ValidateSet('','Administrator','LocalSystem','AlternateUser')][string]$ProcessContextOverride=''
    )
    if($Live){
        $startedAt=[DateTimeOffset]::UtcNow
        if(-not (Test-ResourceDependencySid -Value $AssessmentUserSid)){
            $payload=New-ResourceDependencyGapPayload -Policy $Policy -State 'Unavailable' `
                -ReasonCode 'RESOURCE.ASSESSMENT_USER_CONTEXT_UNAVAILABLE' `
                -Relationship 'Unavailable' -ObservedContext 'StandardUser'
            return [pscustomobject][ordered]@{state='Completed';reasonCode='RESOURCE.ASSESSMENT_USER_CONTEXT_UNAVAILABLE';payload=$payload;envelope=[pscustomobject][ordered]@{startedAt=$startedAt.ToString('o');completedAt=([DateTimeOffset]::UtcNow).ToString('o');executionContext='StandardUser';attempts=1};cleanupVerified=$true}
        }
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=[Security.Principal.WindowsPrincipal]::new($identity)
        $processSid=[string]$identity.User.Value
        $isAdministrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if($ProcessContextOverride){
            switch($ProcessContextOverride){
                'LocalSystem'{$processSid='S-1-5-18';$isAdministrator=$true}
                'Administrator'{$processSid=$AssessmentUserSid;$isAdministrator=$true}
                'AlternateUser'{$processSid='S-1-5-21-9-8-7-1002';$isAdministrator=$false}
            }
        }
        $disposition=Get-ResourceDependencyProcessDisposition -ProcessSid $processSid `
            -AssessmentUserSid $AssessmentUserSid -IsAdministrator $isAdministrator
        if($null -ne $disposition){
            $payload=New-ResourceDependencyGapPayload -Policy $Policy -State 'Denied' `
                -ReasonCode 'RESOURCE.ASSESSMENT_USER_CONTEXT_REQUIRED' `
                -Relationship ([string]$disposition.relationship) `
                -ObservedContext ([string]$disposition.executionContext)
            return [pscustomobject][ordered]@{state='Completed';reasonCode='RESOURCE.ASSESSMENT_USER_CONTEXT_REQUIRED';payload=$payload;envelope=[pscustomobject][ordered]@{startedAt=$startedAt.ToString('o');completedAt=([DateTimeOffset]::UtcNow).ToString('o');executionContext=[string]$disposition.executionContext;attempts=1};cleanupVerified=$true}
        }
        $attempt=Invoke-BoundedResourceDependenciesSnapshot -Policy $Policy `
            -AssessmentUserSid $AssessmentUserSid
        if([bool]$attempt.succeeded){
            $payload=ConvertTo-ResourceDependencyAttemptPayload -Payload $attempt.payload -Policy $Policy
            return [pscustomobject][ordered]@{state='Completed';reasonCode='RESOURCE.COLLECTION_COMPLETED';payload=$payload;envelope=[pscustomobject][ordered]@{startedAt=([DateTimeOffset]$attempt.startedAt).ToString('o');completedAt=([DateTimeOffset]$attempt.completedAt).ToString('o');executionContext='StandardUser';attempts=1};cleanupVerified=$true}
        }
        $state=if([string]$attempt.reasonCode -match 'TIMEOUT'){'TimedOut'}
            elseif([string]$attempt.reasonCode -match 'CANCEL'){'Cancelled'}
            elseif([string]$attempt.reasonCode -match 'DENIED'){'Denied'}else{'Failed'}
        $payload=New-ResourceDependencyGapPayload -Policy $Policy -State $state `
            -ReasonCode ([string]$attempt.reasonCode) -Relationship 'SameUser' `
            -ObservedContext 'StandardUser'
        return [pscustomobject][ordered]@{state='Completed';reasonCode=[string]$attempt.reasonCode;payload=$payload;envelope=[pscustomobject][ordered]@{startedAt=([DateTimeOffset]$attempt.startedAt).ToString('o');completedAt=([DateTimeOffset]$attempt.completedAt).ToString('o');executionContext='StandardUser';attempts=1};cleanupVerified=$true}
    }
    if([string]$ValidationScenario -notin @($Policy.validationScenarios)){
        throw 'The Resource Dependencies validation scenario is not release-owned.'
    }
    $startedAt=[DateTimeOffset]::UtcNow
    $payload=Copy-ResourceDependenciesCollectorPayload -Payload (
        New-ResourceDependenciesSyntheticPayload -Scenario $ValidationScenario -Policy $Policy
    ) -Policy $Policy
    $completedAt=[DateTimeOffset]::UtcNow
    [pscustomobject][ordered]@{
        state='Completed';reasonCode='RESOURCE.COLLECTION_COMPLETED';payload=$payload
        envelope=[pscustomobject][ordered]@{
            startedAt=$startedAt.ToString('o');completedAt=$completedAt.ToString('o')
            executionContext=[string]$payload.executionContext;attempts=1
        }
        cleanupVerified=$true
    }
}

function New-ResourceDependenciesPublicProjection {
    param([Parameter(Mandatory)]$CollectorResult,[Parameter(Mandatory)]$Policy)
    $payload=$CollectorResult.payload
    [pscustomobject][ordered]@{
        recordType='win-pcinfo.resource-dependencies-validation';contractVersion='1.0.0'
        userResourceCoverage=Get-ResourceDependencyLayerState -ScopeStates $payload.scopeStates -ScopeIds @($Policy.layers[0].scopeIds)
        peripheralCoverage=Get-ResourceDependencyLayerState -ScopeStates $payload.scopeStates -ScopeIds @($Policy.layers[1].scopeIds)
        mappedDriveCount=@($payload.mappedDrives).Count;uncConnectionCount=@($payload.uncConnections).Count
        printerCount=@($payload.printers).Count;printerDriverCount=@($payload.printerDrivers).Count
        peripheralCount=@($payload.peripherals).Count;assessmentUserContextVerified=[bool]$payload.assessmentUserContextVerified
        processRelationship=[string]$payload.processRelationship;resourceIdentifiersPublished=$false
        deviceIdentifiersCollected=$false;shareContentsEnumerated=$false;printJobsEnumerated=$false
        storedCredentialsCollected=$false;wifiKeysCollected=$false;deviceStateChanged=$false
    }
}

function Get-ResourceDependencyLayerState {
    param([Parameter(Mandatory)]$ScopeStates,[Parameter(Mandatory)][string[]]$ScopeIds)
    $states=@($ScopeStates|Where-Object scopeId -in $ScopeIds|ForEach-Object state|Sort-Object -Unique)
    if($states.Count -eq 1){return [string]$states[0]}
    if('Denied' -in $states){return 'Denied'}
    if('Unavailable' -in $states){return 'Unavailable'}
    'Partial'
}

function Test-ResourceDependencySid {
    param([Parameter(Mandatory)][string]$Value)
    try{
        if([Text.Encoding]::UTF8.GetByteCount($Value) -gt 184){return $false}
        $sid=[Security.Principal.SecurityIdentifier]::new($Value)
        [string]::Equals($sid.Value,$Value,[StringComparison]::Ordinal)
    }catch{$false}
}

function Get-ResourceDependencyProcessDisposition {
    param(
        [Parameter(Mandatory)][string]$ProcessSid,
        [Parameter(Mandatory)][string]$AssessmentUserSid,
        [Parameter(Mandatory)][bool]$IsAdministrator
    )
    if($ProcessSid -eq 'S-1-5-18'){
        return [pscustomobject]@{relationship='ProhibitedSystemContext';executionContext='LocalSystem'}
    }
    if($IsAdministrator){
        $relationship=if([string]::Equals($ProcessSid,$AssessmentUserSid,[StringComparison]::OrdinalIgnoreCase)){
            'ElevatedAssessmentUser'
        }else{'AlternateAdministrator'}
        return [pscustomobject]@{relationship=$relationship;executionContext='Administrator'}
    }
    if(-not [string]::Equals($ProcessSid,$AssessmentUserSid,[StringComparison]::OrdinalIgnoreCase)){
        return [pscustomobject]@{relationship='DifferentStandardUser';executionContext='StandardUser'}
    }
    $null
}

function New-ResourceDependencyGapPayload {
    param(
        [Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$ReasonCode,[Parameter(Mandatory)][string]$Relationship,
        [Parameter(Mandatory)][string]$ObservedContext
    )
    [pscustomobject][ordered]@{
        sourceLocale='und';assessmentUserContextVerified=($Relationship -eq 'SameUser');processRelationship=$Relationship
        mappedDrives=@();uncConnections=@();printers=@();printerDrivers=@();peripherals=@()
        scopeStates=@($Policy.scopes|ForEach-Object {
            New-ResourceDependencyScopeState -ScopeId ([string]$_.scopeId) -State $State -ReasonCode $ReasonCode
        });executionContext=$ObservedContext
    }
}

function Get-ResourceDependenciesLiveSource {
    # This is release-owned source, not a caller-provided command. It requests
    # only explicitly cataloged metadata. In particular it never requests a
    # username, credential, print job, share child, PnP identifier, or serial.
    # The child also repeats the SID and token checks so changing the parent
    # object after validation cannot make an elevated or different user appear
    # to be the Assessment User Context.
@'
$ErrorActionPreference='Stop'
function New-Scope([string]$id){[pscustomobject][ordered]@{scopeId=$id;state='Complete';reasonCode=''}}
function Set-Scope([object[]]$scopes,[string]$id,[string]$state,[string]$reason){
    $item=@($scopes|Where-Object scopeId -eq $id)[0]
    if($item.state -eq 'Complete' -or $state -in @('Denied','Failed','Malformed')){
        $item.state=$state;$item.reasonCode=$reason
    }
}
function Get-FailureState([Exception]$exception){
    if($exception -is [UnauthorizedAccessException] -or $exception.HResult -eq -2147024891){'Denied'}else{'Failed'}
}
function Get-FailureReason([string]$state){if($state -eq 'Denied'){'RESOURCE.SOURCE_ACCESS_DENIED'}else{'RESOURCE.SOURCE_FAILED'}}
function Add-BoundedUnique(
    [Collections.Generic.Dictionary[string,object]]$set,[string]$key,[object]$value,
    [int]$maximum,[object[]]$scopes,[string]$scopeId,[bool]$replace
){
    if($set.ContainsKey($key)){if($replace){$set[$key]=$value};return}
    if($set.Count -ge $maximum){Set-Scope $scopes $scopeId 'Partial' 'RESOURCE.EVIDENCE_BOUND_EXCEEDED';return}
    $set[$key]=$value
}
function Get-CanonicalLocalName([string]$value){
    $trimmed=$value.Trim().TrimEnd(':')
    if($trimmed -notmatch '^[A-Za-z]$'){return $null}
    "$($trimmed.ToUpperInvariant()):"
}
$utf8=[Text.UTF8Encoding]::new($false,$true)
$expectedSid=[string]$env:WINPCINFO_RESOURCE_ASSESSMENT_SID
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$actualSid=[string]$identity.User.Value
if($actualSid -eq 'S-1-5-18' -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    -not [string]::Equals($actualSid,$expectedSid,[StringComparison]::OrdinalIgnoreCase)){
    throw 'The child process is not the verified Assessment User Context.'
}
$maximumMapped=[int]$env:WINPCINFO_RESOURCE_MAX_MAPPED
$maximumUnc=[int]$env:WINPCINFO_RESOURCE_MAX_UNC
$maximumPrinters=[int]$env:WINPCINFO_RESOURCE_MAX_PRINTERS
$maximumDrivers=[int]$env:WINPCINFO_RESOURCE_MAX_DRIVERS
$maximumPeripherals=[int]$env:WINPCINFO_RESOURCE_MAX_PERIPHERALS
$classCatalog=@([string]$env:WINPCINFO_RESOURCE_CLASSES -split '\|')
$scopes=@(
    New-Scope 'scope:resource.mapped-drives',New-Scope 'scope:resource.unc-connections',
    New-Scope 'scope:resource.printers',New-Scope 'scope:resource.printer-drivers',
    New-Scope 'scope:resource.common-peripherals'
)
$mappedSet=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
try{
    $networkKey=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Network',$false)
    try{
        $names=if($null -eq $networkKey){@()}else{@($networkKey.GetSubKeyNames()|Sort-Object -Unique)}
        foreach($name in $names){
            $localName=Get-CanonicalLocalName ([string]$name)
            if($null -eq $localName){Set-Scope $scopes 'scope:resource.mapped-drives' 'Partial' 'RESOURCE.MAPPED_DRIVE_MALFORMED';continue}
            $driveKey=$networkKey.OpenSubKey([string]$name,$false)
            try{
                $remote=$driveKey.GetValue('RemotePath',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $provider=$driveKey.GetValue('ProviderName',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if($remote -isnot [string] -or [string]$remote -notmatch '^\\\\[^\\]+\\[^\\]+'){
                    Set-Scope $scopes 'scope:resource.mapped-drives' 'Partial' 'RESOURCE.MAPPED_DRIVE_MALFORMED';continue
                }
                Add-BoundedUnique $mappedSet $localName ([pscustomobject][ordered]@{
                    localName=$localName;remoteEndpoint=[string]$remote
                    connectionState='Unavailable';providerName=if($provider -is [string]){[string]$provider}else{$null}
                }) $maximumMapped $scopes 'scope:resource.mapped-drives' $false
            }finally{if($null -ne $driveKey){$driveKey.Dispose()}}
        }
    }finally{if($null -ne $networkKey){$networkKey.Dispose()}}
}catch{$state=Get-FailureState $_.Exception;Set-Scope $scopes 'scope:resource.mapped-drives' $state (Get-FailureReason $state)}

$uncSet=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
try{
    $null=Get-CimInstance -ClassName Win32_NetworkConnection -Property LocalName,RemoteName,ConnectionState,ProviderName -ErrorAction Stop | ForEach-Object {
        $row=$_
        $rawLocal=[string]$row.LocalName
        $local=Get-CanonicalLocalName $rawLocal
        if(-not [string]::IsNullOrWhiteSpace($rawLocal) -and $null -eq $local){
            Set-Scope $scopes 'scope:resource.mapped-drives' 'Partial' 'RESOURCE.MAPPED_DRIVE_MALFORMED';return
        }
        $targetScope=if($null -eq $local){'scope:resource.unc-connections'}else{'scope:resource.mapped-drives'}
        if($row.RemoteName -isnot [string] -or [string]$row.RemoteName -notmatch '^\\\\[^\\]+\\[^\\]+'){
            $reason=if($null -eq $local){'RESOURCE.UNC_CONNECTION_MALFORMED'}else{'RESOURCE.MAPPED_DRIVE_MALFORMED'}
            Set-Scope $scopes $targetScope 'Partial' $reason;return
        }
        $state=if([string]$row.ConnectionState -eq 'Connected'){'Connected'}elseif([string]$row.ConnectionState -eq 'Disconnected'){'Disconnected'}else{'Unavailable'}
        if($null -ne $local){
            # A live network row is authoritative for the same local designator. Replacing the
            # registry-only definition avoids presenting a remembered mapping as disconnected.
            Add-BoundedUnique $mappedSet $local ([pscustomobject][ordered]@{
                localName=$local;remoteEndpoint=[string]$row.RemoteName;connectionState=$state
                providerName=if($row.ProviderName -is [string]){[string]$row.ProviderName}else{$null}
            }) $maximumMapped $scopes 'scope:resource.mapped-drives' $true
        }else{
            Add-BoundedUnique $uncSet ([string]$row.RemoteName) ([pscustomobject][ordered]@{
                remoteEndpoint=[string]$row.RemoteName;connectionState=$state
                providerName=if($row.ProviderName -is [string]){[string]$row.ProviderName}else{$null}
            }) $maximumUnc $scopes 'scope:resource.unc-connections' $false
        }
    }
}catch{
    $state=Get-FailureState $_.Exception;Set-Scope $scopes 'scope:resource.unc-connections' $state (Get-FailureReason $state)
    Set-Scope $scopes 'scope:resource.mapped-drives' 'Partial' 'RESOURCE.CONNECTION_STATE_UNAVAILABLE'
}
$mapped=@($mappedSet.Values|Sort-Object localName,remoteEndpoint)
$unc=@($uncSet.Values|Sort-Object remoteEndpoint)

$printerSet=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
try{
    $null=Get-CimInstance -ClassName Win32_Printer -Property Name,PortName,DriverName,Network,Local,Default,WorkOffline -ErrorAction Stop | ForEach-Object {
        $row=$_
        if($row.Name -isnot [string] -or $row.PortName -isnot [string] -or $row.DriverName -isnot [string] -or
            $null -eq $row.Network -or $null -eq $row.Default -or $null -eq $row.WorkOffline){
            Set-Scope $scopes 'scope:resource.printers' 'Partial' 'RESOURCE.PRINTER_MALFORMED';return
        }
        Add-BoundedUnique $printerSet ([string]$row.Name) ([pscustomobject][ordered]@{
            name=[string]$row.Name;portName=[string]$row.PortName;driverName=[string]$row.DriverName
            network=[bool]$row.Network;default=[bool]$row.Default;offline=[bool]$row.WorkOffline
        }) $maximumPrinters $scopes 'scope:resource.printers' $false
    }
}catch{$state=Get-FailureState $_.Exception;Set-Scope $scopes 'scope:resource.printers' $state (Get-FailureReason $state)}
$printers=@($printerSet.Values|Sort-Object name)

$driverSet=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
try{
    $null=Get-CimInstance -ClassName Win32_PrinterDriver -Property Name,Manufacturer,DriverVersion,InfName -ErrorAction Stop | ForEach-Object {
        $row=$_
        if($row.Name -isnot [string]){Set-Scope $scopes 'scope:resource.printer-drivers' 'Partial' 'RESOURCE.PRINTER_DRIVER_MALFORMED';return}
        Add-BoundedUnique $driverSet ([string]$row.Name) ([pscustomobject][ordered]@{
            name=[string]$row.Name;manufacturer=if($row.Manufacturer -is [string]){[string]$row.Manufacturer}else{$null}
            version=if($null -eq $row.DriverVersion){$null}else{[Convert]::ToString($row.DriverVersion,[Globalization.CultureInfo]::InvariantCulture)}
            infName=if($row.InfName -is [string]){[string]$row.InfName}else{$null}
        }) $maximumDrivers $scopes 'scope:resource.printer-drivers' $false
    }
}catch{$state=Get-FailureState $_.Exception;Set-Scope $scopes 'scope:resource.printer-drivers' $state (Get-FailureReason $state)}
$drivers=@($driverSet.Values|Sort-Object name)

$peripheralSet=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
try{
    $null=Get-CimInstance -ClassName Win32_PnPSignedDriver -Property DeviceClass,DeviceName,Manufacturer,DriverProviderName,DriverVersion,InfName,IsSigned -ErrorAction Stop |
        Where-Object {[string]$_.DeviceClass -in $classCatalog} | ForEach-Object {
        $row=$_
        if($row.DeviceName -isnot [string] -or [string]$row.DeviceClass -notin $classCatalog -or $null -eq $row.IsSigned){
            Set-Scope $scopes 'scope:resource.common-peripherals' 'Partial' 'RESOURCE.PERIPHERAL_MALFORMED';return
        }
        $key="$([string]$row.DeviceClass)|$([string]$row.DeviceName)|$([string]$row.DriverVersion)"
        Add-BoundedUnique $peripheralSet $key ([pscustomobject][ordered]@{
            class=[string]$row.DeviceClass;name=[string]$row.DeviceName
            manufacturer=if($row.Manufacturer -is [string]){[string]$row.Manufacturer}else{$null}
            driverProvider=if($row.DriverProviderName -is [string]){[string]$row.DriverProviderName}else{$null}
            driverVersion=if($row.DriverVersion -is [string]){[string]$row.DriverVersion}else{$null}
            driverInfName=if($row.InfName -is [string]){[string]$row.InfName}else{$null}
            driverSigned=[bool]$row.IsSigned
        }) $maximumPeripherals $scopes 'scope:resource.common-peripherals' $false
    }
}catch{$state=Get-FailureState $_.Exception;Set-Scope $scopes 'scope:resource.common-peripherals' $state (Get-FailureReason $state)}
$peripherals=@($peripheralSet.Values|Sort-Object class,name,driverVersion)
$payload=[pscustomobject][ordered]@{
    sourceLocale='und';assessmentUserContextVerified=$true;processRelationship='SameUser'
    mappedDrives=@($mapped);uncConnections=@($unc);printers=@($printers);printerDrivers=@($drivers)
    peripherals=@($peripherals);scopeStates=@($scopes);executionContext='StandardUser'
}
$xml=[Management.Automation.PSSerializer]::Serialize($payload,8)
[Console]::Out.Write([Convert]::ToBase64String($utf8.GetBytes($xml)))
'@
}

function Invoke-BoundedResourceDependenciesSnapshot {
    param([Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string]$AssessmentUserSid)
    Initialize-ProcessSupervisorNativeType
    $collector=$Policy.collector;$maximumMilliseconds=[int]$collector.deadlineMilliseconds
    $terminationMilliseconds=[Math]::Min(1000,[Math]::Max(1,[Math]::Floor($maximumMilliseconds/4)))
    $activeMilliseconds=[Math]::Max(1,$maximumMilliseconds-$terminationMilliseconds)
    $source=Get-ResourceDependenciesLiveSource
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
    $startedAt=[DateTimeOffset]::UtcNow
    $executable=[IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
    if(-not [IO.File]::Exists($executable) -or -not [string]::Equals(
        $executable,[Environment]::ProcessPath,[StringComparison]::OrdinalIgnoreCase)){
        return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode='RESOURCE.BOUNDARY_UNAVAILABLE';native=$null;startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow}
    }
    $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $environment['SystemRoot']=[Environment]::GetFolderPath('Windows')
    $environment['WINPCINFO_RESOURCE_ASSESSMENT_SID']=$AssessmentUserSid
    $environment['WINPCINFO_RESOURCE_MAX_MAPPED']=[string]$collector.maximumMappedDrives
    $environment['WINPCINFO_RESOURCE_MAX_UNC']=[string]$collector.maximumUncConnections
    $environment['WINPCINFO_RESOURCE_MAX_PRINTERS']=[string]$collector.maximumPrinters
    $environment['WINPCINFO_RESOURCE_MAX_DRIVERS']=[string]$collector.maximumPrinterDrivers
    $environment['WINPCINFO_RESOURCE_MAX_PERIPHERALS']=[string]$collector.maximumPeripherals
    $environment['WINPCINFO_RESOURCE_CLASSES']=@($Policy.peripheralClassCatalog)-join '|'
    $eventName="Local\WINPCInfo-ResourceDependencies-$([Guid]::NewGuid().ToString('N'))"
    [bool]$created=$false;$event=$null
    try{
        $event=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$eventName,[ref]$created)
        if(-not $created){return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode='RESOURCE.BOUNDARY_UNAVAILABLE';native=$null;startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow}}
        $native=[WinPCInfo.ProcessSupervisor.NativeRunner]::Run(
            $executable,@('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded),
            $PSHOME,$environment,$activeMilliseconds,[int]$collector.resultMaximumUtf8Bytes,4096,
            (Get-AssessmentCancellationToken),$event,1,$terminationMilliseconds,$false
        )
        if($native.Started -and -not [bool]$native.CompleteOwnedTreeAbsent){
            $exception=[InvalidOperationException]::new('The Resource Dependencies worker tree could not be proved absent.')
            $exception.Data['ReasonCode']='RESOURCE.COLLECTOR_CLEANUP_INCOMPLETE';throw $exception
        }
        if(-not $native.Started -or $native.FailureStage -ne [WinPCInfo.ProcessSupervisor.NativeFailureStage]::None -or
            $native.ExitCode -ne 0 -or $native.StandardOutputExceeded -or $native.StandardErrorExceeded -or
            $native.StandardErrorBytes -ne 0){
            $reason=Get-NativeSupervisorReasonCode -NativeResult $native
            if([string]::IsNullOrWhiteSpace($reason)){$reason='RESOURCE.SOURCE_FAILED'}
            return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode=$reason;native=$native;startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow}
        }
        $base64=[Text.UTF8Encoding]::new($false,$true).GetString($native.StandardOutput)
        $xml=[Text.UTF8Encoding]::new($false,$true).GetString([Convert]::FromBase64String($base64))
        [pscustomobject]@{succeeded=$true;payload=[Management.Automation.PSSerializer]::Deserialize($xml);reasonCode='';native=$native;startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow}
    }catch{
        if($_.Exception.Data['ReasonCode']){throw}
        [pscustomobject]@{succeeded=$false;payload=$null;reasonCode='RESOURCE.SOURCE_FAILED';native=$null;startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow}
    }finally{if($null -ne $event){$event.Dispose()}}
}

function Get-ResourceDependencySourceId {
    param([Parameter(Mandatory)][string]$FieldId)
    if($FieldId -like 'field:resource.mapped-drive.*'){'source:windows.local.mapped-resource-correlation'}
    elseif($FieldId -like 'field:resource.share.*' -or $FieldId -eq 'field:resource.connection-state' -or $FieldId -eq 'field:resource.provider-name'){'source:windows.cim.network-connections'}
    elseif($FieldId -like 'field:resource.printer.*' -or $FieldId -like 'field:resource.printer-driver.*'){'source:windows.cim.printers-and-drivers'}
    elseif($FieldId -like 'field:resource.peripheral.*'){'source:windows.cim.common-peripheral-drivers'}
    else{throw "No Resource Dependency source owns $FieldId."}
}

function Add-ResourceDependenciesEvidenceRecord {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$CollectorResult,[Parameter(Mandatory)]$Policy)
    if([string]$Record.run.evidenceProfileId -ne 'profile:device-firmware-identity-administrator-and-policy-readiness'){
        throw 'Resource Dependency evidence requires the accepted policy-ready evidence profile.'
    }
    if(@($Record.findings|Where-Object ruleId -in @($Policy.rules.ruleId)).Count -ne 0){
        throw 'Resource Dependency source evidence cannot be added after its Rule Evaluations.'
    }
    if(-not [bool]$CollectorResult.cleanupVerified -or
        -not (Test-ResourceDependenciesCollectorPayload -Payload $CollectorResult.payload -Policy $Policy)){
        throw 'Resource Dependency evidence requires a closed, cleanup-verified collector result.'
    }
    $runId=[string]$Record.run.runId;$payload=$CollectorResult.payload;$collector=$Policy.collector
    $collectedAt=[string]$CollectorResult.envelope.completedAt
    $observedContext=[string]$CollectorResult.envelope.executionContext
    $observations=[Collections.Generic.List[object]]::new();$provenance=[Collections.Generic.List[object]]::new()
    $subjects=[Collections.Generic.List[object]]::new()
    $scopeStateById=@{};foreach($scopeState in @($payload.scopeStates)){$scopeStateById[[string]$scopeState.scopeId]=[string]$scopeState.state}
    $scopeIds=@{};foreach($scope in $Policy.scopes){$scopeIds[[string]$scope.scopeId]=[Collections.Generic.List[string]]::new()}
    $envelopeSubjects=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $null=$envelopeSubjects.Add('subject:device:primary');$null=$envelopeSubjects.Add('subject:assessment-user:primary')
    function Add-ResourceObservation {
        param([string]$ScopeId,[string]$Suffix,[string]$FieldId,[string]$SubjectId,$Value,[string]$ValueState='ObservedValue')
        $observationId="observation:resource-$Suffix`:$runId";$provenanceId="provenance:resource-$Suffix`:$runId"
        $observation=[ordered]@{observationId=$observationId;fieldId=$FieldId;subjectId=$SubjectId;provenanceId=$provenanceId;valueState=$ValueState}
        if($ValueState -eq 'ObservedValue'){$observation.value=$Value}
        $observations.Add([pscustomobject]$observation)
        $provenance.Add([pscustomobject][ordered]@{provenanceId=$provenanceId;fieldId=$FieldId;subjectId=$SubjectId;sourceId=Get-ResourceDependencySourceId -FieldId $FieldId;collectorId=[string]$collector.collectorId;collectorVersion=[string]$collector.collectorVersion;executionContext=$observedContext;collectedAt=$collectedAt;sourceLocale=[string]$payload.sourceLocale})
        $scopeIds[$ScopeId].Add($observationId);$null=$envelopeSubjects.Add($SubjectId)
    }
    function Add-ResourceValue {
        param([string]$ScopeId,[string]$Suffix,[string]$FieldId,[string]$SubjectId,$Value)
        if($null -eq $Value){Add-ResourceObservation $ScopeId $Suffix $FieldId $SubjectId $null 'SourceReportedUnknown'}
        else{Add-ResourceObservation $ScopeId $Suffix $FieldId $SubjectId $Value}
    }
    $index=0
    foreach($item in @($payload.mappedDrives|Where-Object {$scopeStateById['scope:resource.mapped-drives'] -in @('Complete','Partial')})){
        $subjectId="subject:mapped-drive:$index";$subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='Interface'})
        Add-ResourceValue 'scope:resource.mapped-drives' "mapped-$index-local" 'field:resource.mapped-drive.local-name' $subjectId $item.localName
        Add-ResourceValue 'scope:resource.mapped-drives' "mapped-$index-endpoint" 'field:resource.mapped-drive.remote-endpoint' $subjectId $item.remoteEndpoint
        Add-ResourceValue 'scope:resource.mapped-drives' "mapped-$index-state" 'field:resource.mapped-drive.connection-state' $subjectId $item.connectionState
        Add-ResourceValue 'scope:resource.mapped-drives' "mapped-$index-provider" 'field:resource.mapped-drive.provider-name' $subjectId $item.providerName
        $index++
    }
    $index=0
    foreach($item in @($payload.uncConnections|Where-Object {$scopeStateById['scope:resource.unc-connections'] -in @('Complete','Partial')})){
        $subjectId="subject:unc-resource:$index";$subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='Interface'})
        Add-ResourceValue 'scope:resource.unc-connections' "unc-$index-endpoint" 'field:resource.share.endpoint' $subjectId $item.remoteEndpoint
        Add-ResourceValue 'scope:resource.unc-connections' "unc-$index-state" 'field:resource.connection-state' $subjectId $item.connectionState
        Add-ResourceValue 'scope:resource.unc-connections' "unc-$index-provider" 'field:resource.provider-name' $subjectId $item.providerName
        $index++
    }
    $index=0
    foreach($item in @($payload.printers|Where-Object {$scopeStateById['scope:resource.printers'] -in @('Complete','Partial')})){
        $subjectId="subject:printer:$index";$subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='Interface'})
        foreach($definition in @(
            @('name','field:resource.printer.name'),@('portName','field:resource.printer.port-name'),
            @('driverName','field:resource.printer.driver-name'),@('network','field:resource.printer.network'),
            @('default','field:resource.printer.default'),@('offline','field:resource.printer.offline')
        )){Add-ResourceValue 'scope:resource.printers' "printer-$index-$($definition[0])" $definition[1] $subjectId $item.($definition[0])}
        $index++
    }
    $index=0
    foreach($item in @($payload.printerDrivers|Where-Object {$scopeStateById['scope:resource.printer-drivers'] -in @('Complete','Partial')})){
        $subjectId="subject:printer-driver:$index";$subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='Application'})
        foreach($definition in @(
            @('name','field:resource.printer-driver.name'),@('manufacturer','field:resource.printer-driver.manufacturer'),
            @('version','field:resource.printer-driver.version'),@('infName','field:resource.printer-driver.inf-name')
        )){Add-ResourceValue 'scope:resource.printer-drivers' "printer-driver-$index-$($definition[0])" $definition[1] $subjectId $item.($definition[0])}
        $index++
    }
    $index=0
    foreach($item in @($payload.peripherals|Where-Object {$scopeStateById['scope:resource.common-peripherals'] -in @('Complete','Partial')})){
        $subjectId="subject:peripheral:$index";$subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='Interface'})
        foreach($definition in @(
            @('class','field:resource.peripheral.class'),@('name','field:resource.peripheral.name'),
            @('manufacturer','field:resource.peripheral.manufacturer'),@('driverProvider','field:resource.peripheral.driver-provider'),
            @('driverVersion','field:resource.peripheral.driver-version'),@('driverInfName','field:resource.peripheral.driver-inf-name'),
            @('driverSigned','field:resource.peripheral.driver-signed')
        )){Add-ResourceValue 'scope:resource.common-peripherals' "peripheral-$index-$($definition[0])" $definition[1] $subjectId $item.($definition[0])}
        $index++
    }
    # An empty array is evidence of absence only for a Complete scope. Close
    # each defined field explicitly so downstream rules cannot confuse a
    # denied or partial source with a successful empty inventory.
    foreach($scope in $Policy.scopes){
        $state=@($payload.scopeStates|Where-Object scopeId -eq $scope.scopeId)[0]
        if($state.state -eq 'Complete' -and $scopeIds[[string]$scope.scopeId].Count -eq 0){
            $subjectId=if([string]$scope.scopeId -in @('scope:resource.mapped-drives','scope:resource.unc-connections','scope:resource.printers')){'subject:assessment-user:primary'}else{'subject:device:primary'}
            $fieldIndex=0;foreach($fieldId in $scope.fieldIds){
                Add-ResourceObservation ([string]$scope.scopeId) "absent-$(([string]$scope.scopeId).Split('.')[-1])-$fieldIndex" ([string]$fieldId) $subjectId $null 'ObservedAbsent';$fieldIndex++
            }
        }
    }
    $coverage=[Collections.Generic.List[object]]::new();$diagnostics=[Collections.Generic.List[object]]::new()
    foreach($scopeState in $payload.scopeStates){
        $suffix=([string]$scopeState.scopeId).Substring('scope:resource.'.Length).Replace('.','-')
        $coverageId="coverage:resource-$suffix`:$runId";$entry=[ordered]@{coverageId=$coverageId;scopeId=[string]$scopeState.scopeId;state=[string]$scopeState.state;observationIds=@($scopeIds[[string]$scopeState.scopeId]);diagnosticIds=@()}
        if($scopeState.state -ne 'Complete'){
            $diagnosticId="diagnostic:resource-$suffix`:$runId";$entry.reasonCode=[string]$scopeState.reasonCode;$entry.diagnosticIds=@($diagnosticId)
            $diagnostics.Add([pscustomobject][ordered]@{diagnosticId=$diagnosticId;scopeId=[string]$scopeState.scopeId;phase='Collection';reasonCode=[string]$scopeState.reasonCode;operatorMessageId='resource-dependencies.collection.incomplete'})
        }
        $coverage.Add([pscustomobject]$entry)
    }
    $Record.subjects=@($Record.subjects)+@($subjects);$Record.observations=@($Record.observations)+@($observations)
    $Record.provenance=@($Record.provenance)+@($provenance);$Record.coverage=@($Record.coverage)+@($coverage)
    $Record.diagnostics=@($Record.diagnostics)+@($diagnostics)
    $Record.collectorResults=@($Record.collectorResults)+[pscustomobject][ordered]@{
        envelopeId="envelope:resource-dependencies:$runId";collectorId=[string]$collector.collectorId
        collectorVersion=[string]$collector.collectorVersion;operationId=[string]$collector.operationId
        intendedScopeIds=@($Policy.scopes.scopeId);subjectIds=@($envelopeSubjects)
        startedAt=[string]$CollectorResult.envelope.startedAt;completedAt=$collectedAt
        executionContext=$observedContext;attempts=1
        observationIds=@($observations|ForEach-Object observationId)
        coverageIds=@($coverage|ForEach-Object coverageId)
        diagnosticIds=@($diagnostics|ForEach-Object diagnosticId)
    }
    $Record.run.evidenceProfileId=[string]$Policy.evidenceProfileId
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne Complete).Count -eq 0){'Completed'}else{'CompletedWithGaps'}
    $Record
}

function Invoke-ResourceDependencyRule {
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][int]$InputObservationCount,
        [Parameter(Mandatory)][scriptblock]$Evaluation
    )
    $watch=[Diagnostics.Stopwatch]::StartNew();$results=@(& $Evaluation);$watch.Stop()
    if($InputObservationCount -gt [int]$Rule.maximumInputObservations -or
        $watch.ElapsedMilliseconds -gt [int]$Rule.deadlineMilliseconds -or $results.Count -ne 1 -or
        [string]$results[0].outcome -notin @('ExpectedCondition','NeedsAttention','Informational','Indeterminate')){
        throw "The release-owned $($Rule.operationId) rule violated its finite result contract."
    }
    $results[0]
}

function Complete-ValidatedResourceDependenciesAssessmentRecord {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$Policy,[Parameter(Mandatory)]$ContractValidation)
    if(-not [bool]$ContractValidation.accepted -or $ContractValidation.reasonCode -ne 'CONTRACT.ACCEPTED' -or
        [string]$Record.run.evidenceProfileId -ne [string]$Policy.evidenceProfileId -or
        @($Record.findings|Where-Object ruleId -in @($Policy.rules.ruleId)).Count -ne 0){
        throw 'Resource Dependency rules require an accepted source-only combined record.'
    }
    $rules=@{};foreach($rule in $Policy.rules){$rules[[string]$rule.findingKind]=$rule}
    $userScopeIds=@($Policy.layers|Where-Object layerId -eq UserResourceDependencies)[0].scopeIds
    $peripheralScopeIds=@($Policy.layers|Where-Object layerId -eq PeripheralDependencies)[0].scopeIds
    $userCoverage=@($Record.coverage|Where-Object scopeId -in $userScopeIds)
    $peripheralCoverage=@($Record.coverage|Where-Object scopeId -in $peripheralScopeIds)
    $userObservations=@($Record.observations|Where-Object {$_.fieldId -like 'field:resource.mapped-*' -or $_.fieldId -like 'field:resource.share.*' -or $_.fieldId -eq 'field:resource.connection-state' -or $_.fieldId -eq 'field:resource.provider-name' -or $_.fieldId -like 'field:resource.printer.*'})
    $peripheralObservations=@($Record.observations|Where-Object {$_.fieldId -like 'field:resource.peripheral.*' -or $_.fieldId -like 'field:resource.printer-driver.*'})
    $coverageObservations=@($userObservations+$peripheralObservations)
    $userResult=Invoke-ResourceDependencyRule -Rule $rules['user-resource-migration-dependencies'] -InputObservationCount $userObservations.Count -Evaluation {
        if(@($userCoverage|Where-Object state -ne Complete).Count -gt 0){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.USER_RESOURCE_EVIDENCE_INCOMPLETE'}}
        elseif(@($userObservations|Where-Object valueState -eq ObservedValue).Count -gt 0){[pscustomobject]@{outcome='NeedsAttention'}}
        else{[pscustomobject]@{outcome='Informational'}}
    }
    $peripheralResult=Invoke-ResourceDependencyRule -Rule $rules['peripheral-migration-dependencies'] -InputObservationCount $peripheralObservations.Count -Evaluation {
        if(@($peripheralCoverage|Where-Object state -ne Complete).Count -gt 0){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.PERIPHERAL_EVIDENCE_INCOMPLETE'}}
        elseif(@($peripheralObservations|Where-Object valueState -eq ObservedValue).Count -gt 0){[pscustomobject]@{outcome='NeedsAttention'}}
        else{[pscustomobject]@{outcome='Informational'}}
    }
    $coverageResult=Invoke-ResourceDependencyRule -Rule $rules['resource-dependency-coverage'] -InputObservationCount $coverageObservations.Count -Evaluation {
        if(@($Record.coverage|Where-Object {$_.scopeId -in @($Policy.scopes.scopeId) -and $_.state -ne 'Complete'}).Count -gt 0){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.RESOURCE_DEPENDENCY_EVIDENCE_INCOMPLETE'}}
        else{[pscustomobject]@{outcome='Informational'}}
    }
    $definitions=@(
        @{kind='user-resource-migration-dependencies';target='subject:assessment-user:primary';result=$userResult;observations=$userObservations},
        @{kind='peripheral-migration-dependencies';target='subject:device:primary';result=$peripheralResult;observations=$peripheralObservations},
        @{kind='resource-dependency-coverage';target='subject:device:primary';result=$coverageResult;observations=$coverageObservations}
    )
    foreach($definition in $definitions){
        $rule=$rules[$definition.kind];$findingId="finding:$($definition.kind):$($Record.run.runId)"
        $finding=[ordered]@{findingId=$findingId;ruleId=[string]$rule.ruleId;targetSubjectId=[string]$definition.target;outcome=[string]$definition.result.outcome;evidenceReferences=@($definition.observations|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})}
        if($definition.result.PSObject.Properties['reasonCode']){$finding.reasonCode=[string]$definition.result.reasonCode}
        $Record.findings=@($Record.findings)+[pscustomobject]$finding
        if($definition.kind -ne 'resource-dependency-coverage' -and $definition.result.outcome -in @('NeedsAttention','Indeterminate')){
            $recommendation=@($Policy.recommendations|Where-Object findingKind -eq $definition.kind)[0]
            $Record.recommendations=@($Record.recommendations)+[pscustomobject][ordered]@{recommendationId="recommendation:$($definition.kind):$($Record.run.runId)";definitionId=[string]$recommendation.definitionId;kind='AssessmentRecommendation';findingIds=@($findingId)}
        }
    }
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne Complete).Count -eq 0){'Completed'}else{'CompletedWithGaps'}
    $Record
}
