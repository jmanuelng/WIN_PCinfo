$script:SoftwareInventoryPolicyBase64 = '__SOFTWARE_INVENTORY_POLICY_BASE64__'
$script:SoftwareInventoryPolicyDigest = '__SOFTWARE_INVENTORY_POLICY_SHA256__'

function Get-SoftwareInventorySha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-SoftwareInventoryPolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    # Build replaces the complete placeholder token. Constructing the development
    # sentinel in two parts keeps that comparison stable in the generated file,
    # so a standalone artifact must use its embedded, digest-bound policy.
    $developmentSentinel = '__SOFTWARE_INVENTORY_' + 'POLICY_BASE64__'
    if ($script:SoftwareInventoryPolicyBase64 -eq $developmentSentinel) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-software-inventory.json'
        $text = [IO.File]::ReadAllText(
            $path, [Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
        $expectedDigest = Get-SoftwareInventorySha256 -Bytes $bytes
    }
    else {
        $bytes = [Convert]::FromBase64String($script:SoftwareInventoryPolicyBase64)
        $expectedDigest = $script:SoftwareInventoryPolicyDigest
    }
    if ((Get-SoftwareInventorySha256 -Bytes $bytes) -ne $expectedDigest) {
        throw 'The embedded Software Inventory policy failed integrity validation.'
    }
    $policy = & $ConvertFromJsonCommand -InputObject (
        [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 30 -ErrorAction Stop
    if ($policy.kind -ne 'win-pcinfo.software-inventory-policy' -or
        $policy.contractVersion -ne '1.0.0' -or
        $policy.policyId -ne 'win-pcinfo.software-inventory/1.0.0' -or
        @($policy.registryViews).Count -ne 2 -or
        @($policy.registrationContexts).Count -ne 2 -or
        @($policy.sourceCatalog).Count -ne 3 -or
        [int]$policy.collector.maximumTotalEntries -ne 128 -or
        @($policy.scopes).Count -ne 8 -or
        @($policy.rules).Count -ne 3 -or
        @($policy.validationScenarios).Count -ne 16) {
        throw 'The Software Inventory policy is not semantically closed.'
    }
    $policy
}

function Read-SoftwareInventoryFixture {
    param([Parameter(Mandatory)][string]$LiteralPath,[Parameter(Mandatory)]$ConvertFromJsonCommand,[Parameter(Mandatory)]$Policy)
    try{
        $bytes=[IO.File]::ReadAllBytes([IO.Path]::GetFullPath($LiteralPath))
        if($bytes.Length -lt 1 -or $bytes.Length -gt 512){throw 'Fixture size is invalid.'}
        $json=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);$document=[Text.Json.JsonDocument]::Parse($json)
        try{$names=@($document.RootElement.EnumerateObject()|ForEach-Object Name);$shape=(@($names|Sort-Object)-join '|');if($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or $shape -notin @('contractVersion|scenario','contractVersion|recognitionScenario|scenario')){throw 'Fixture shape is invalid.'}}finally{$document.Dispose()}
        $fixture=& $ConvertFromJsonCommand -InputObject $json -Depth 5 -ErrorAction Stop
        $recognitionScenario=if($fixture.PSObject.Properties['recognitionScenario']){[string]$fixture.recognitionScenario}else{'Evaluate'}
        if($fixture.contractVersion -ne '1.0.0' -or [string]$fixture.scenario -notin @($Policy.validationScenarios) -or $recognitionScenario -notin @('Evaluate','LogicalFailure')){throw 'Fixture scenario is not release-owned.'}
        [pscustomobject][ordered]@{inventoryScenario=[string]$fixture.scenario;recognitionScenario=$recognitionScenario}
    }catch{throw [InvalidOperationException]::new('The Software Inventory fixture is invalid.', $_.Exception)}
}

function New-SoftwareInventoryScopeState {
    param(
        [Parameter(Mandatory)] [string] $ScopeId,
        [string] $State = 'Complete',
        [string] $ReasonCode = ''
    )
    [pscustomobject][ordered]@{
        scopeId = $ScopeId
        state = $State
        reasonCode = $ReasonCode
    }
}

function New-SoftwareInventoryEntry {
    param(
        [Parameter(Mandatory)] [string] $ScopeId,
        [Parameter(Mandatory)] [string] $SourceKind,
        [Parameter(Mandatory)] [string] $RegistrationId,
        [AllowNull()] $ProductCode = $null,
        [AllowNull()] $PackageFamilyName = $null,
        [AllowNull()] $PackageFullName = $null,
        [AllowNull()] $DisplayName = $null,
        [AllowNull()] $Version = $null,
        [AllowNull()] $Publisher = $null,
        [AllowNull()] $PublisherId = $null,
        [AllowNull()] $SystemComponent = $null,
        [Parameter(Mandatory)] [string] $RegistrationContext,
        [Parameter(Mandatory)] [string] $RegistryView,
        [Parameter(Mandatory)] [string] $InstallerState,
        [Parameter(Mandatory)] [string] $PackageType,
        [Parameter(Mandatory)] [string] $Architecture
    )
    [pscustomobject][ordered]@{
        scopeId = $ScopeId
        sourceKind = $SourceKind
        registrationId = $RegistrationId
        productCode = $ProductCode
        packageFamilyName = $PackageFamilyName
        packageFullName = $PackageFullName
        displayName = $DisplayName
        version = $Version
        publisher = $Publisher
        publisherId = $PublisherId
        systemComponent = $SystemComponent
        registrationContext = $RegistrationContext
        registryView = $RegistryView
        installerState = $InstallerState
        packageType = $PackageType
        architecture = $Architecture
    }
}

function ConvertFrom-SoftwareInventoryAdapterRow {
    param([Parameter(Mandatory)] $Row)
    $kind=[string]$Row.adapterKind
    switch ($kind) {
        'Registry' {
            if (-not (Test-SoftwareInventoryObjectShape $Row @('adapterKind','scopeId','registrationKeyName','registrationContext','registryView','displayName','version','publisher','windowsInstaller','systemComponent'))) { throw 'Registry adapter shape is invalid.' }
            if(-not (Test-SoftwareInventoryText $Row.registrationKeyName 256) -or [string]::IsNullOrWhiteSpace([string]$Row.registrationKeyName) -or
                -not (Test-SoftwareInventoryText $Row.displayName 512 -AllowNull) -or -not (Test-SoftwareInventoryText $Row.version 256 -AllowNull) -or
                -not (Test-SoftwareInventoryText $Row.publisher 512 -AllowNull) -or
                ($null -ne $Row.windowsInstaller -and ($Row.windowsInstaller -isnot [int] -and $Row.windowsInstaller -isnot [long])) -or
                ($null -ne $Row.windowsInstaller -and [int]$Row.windowsInstaller -notin @(0,1)) -or
                ($null -ne $Row.systemComponent -and ($Row.systemComponent -isnot [int] -and $Row.systemComponent -isnot [long])) -or
                ($null -ne $Row.systemComponent -and [int]$Row.systemComponent -notin @(0,1))){throw 'Registry adapter primitives are invalid.'}
            $context=[string]$Row.registrationContext;$view=[string]$Row.registryView
            $scopeId=if($context -eq 'Machine'){"scope:software.registry.machine.$($view.Substring(8))"}else{"scope:software.registry.assessment-user.$($view.Substring(8))"}
            if($context -notin @('Machine','AssessmentUser') -or $view -notin @('Registry32','Registry64') -or [string]$Row.scopeId -ne $scopeId){throw 'Registry adapter context is invalid.'}
            return New-SoftwareInventoryEntry -ScopeId $scopeId -SourceKind Registry `
                -RegistrationId ([string]$Row.registrationKeyName) `
                -DisplayName $Row.displayName -Version $Row.version -Publisher $Row.publisher `
                -SystemComponent $(if($null -eq $Row.systemComponent){$null}else{[int]$Row.systemComponent -eq 1}) `
                -RegistrationContext $context -RegistryView $view -InstallerState Registered `
                -PackageType $(if($null -ne $Row.windowsInstaller -and [int]$Row.windowsInstaller -eq 1){'MsiRegistration'}else{'DesktopRegistration'}) -Architecture None
        }
        'Msi' {
            if (-not (Test-SoftwareInventoryObjectShape $Row @('adapterKind','scopeId','productCode','installContext','stateCode','displayName','version','publisher'))) { throw 'MSI adapter shape is invalid.' }
            if(-not (Test-SoftwareInventoryText $Row.productCode 38) -or [string]$Row.productCode -notmatch '^\{[0-9A-Fa-f-]{36}\}$' -or
                ($Row.installContext -isnot [int] -and $Row.installContext -isnot [long]) -or $Row.stateCode -isnot [string] -or
                -not (Test-SoftwareInventoryText $Row.displayName 512 -AllowNull) -or -not (Test-SoftwareInventoryText $Row.version 256 -AllowNull) -or
                -not (Test-SoftwareInventoryText $Row.publisher 512 -AllowNull)){throw 'MSI adapter primitives are invalid.'}
            $contextCode=[int]$Row.installContext;$stateCode=[string]$Row.stateCode
            $context=switch($contextCode){1{'AssessmentUserManaged'};2{'AssessmentUserUnmanaged'};4{'Machine'};default{throw 'MSI context is invalid.'}}
            $scopeId=if($contextCode -eq 4){'scope:software.msi.machine'}else{'scope:software.msi.assessment-user'}
            if([string]$Row.scopeId -ne $scopeId -or $stateCode -notin @('1','5')){throw 'MSI adapter state is invalid.'}
            return New-SoftwareInventoryEntry -ScopeId $scopeId -SourceKind Msi `
                -RegistrationId ([string]$Row.productCode) `
                -ProductCode ([string]$Row.productCode) -DisplayName $Row.displayName `
                -Version $Row.version -Publisher $Row.publisher -RegistrationContext $context `
                -RegistryView None -InstallerState $(if($stateCode -eq '5'){'Installed'}else{'Advertised'}) `
                -PackageType MsiProduct -Architecture None
        }
        'Msix' {
            if (-not (Test-SoftwareInventoryObjectShape $Row @('adapterKind','scopeId','queryContext','packageFamilyName','packageFullName','displayName','publisherId','versionMajor','versionMinor','versionBuild','versionRevision','architecture','isBundle','isFramework','isResource','isOptional','statusOk'))) { throw 'Package adapter shape is invalid.' }
            foreach($textCheck in @(@($Row.packageFamilyName,256),@($Row.packageFullName,512),@($Row.displayName,512),@($Row.publisherId,256))){if(-not (Test-SoftwareInventoryText $textCheck[0] $textCheck[1]) -or [string]::IsNullOrWhiteSpace([string]$textCheck[0])){throw 'Package adapter text is invalid.'}}
            foreach($number in @($Row.versionMajor,$Row.versionMinor,$Row.versionBuild,$Row.versionRevision)){if(($number -isnot [int] -and $number -isnot [long]) -or [long]$number -lt 0 -or [long]$number -gt 65535){throw 'Package adapter version is invalid.'}}
            foreach($flag in @($Row.isBundle,$Row.isFramework,$Row.isResource,$Row.isOptional,$Row.statusOk)){if($flag -isnot [bool]){throw 'Package adapter flag is invalid.'}}
            $context=[string]$Row.queryContext;$scopeId=if($context -eq 'AssessmentUser'){'scope:software.msix.assessment-user'}elseif($context -eq 'MachineAllUsers'){'scope:software.msix.machine'}else{throw 'Package context is invalid.'}
            if([string]$Row.scopeId -ne $scopeId){throw 'Package scope is invalid.'}
            $type=if([bool]$Row.isBundle){'Bundle'}elseif([bool]$Row.isFramework){'Framework'}elseif([bool]$Row.isResource){'Resource'}elseif([bool]$Row.isOptional){'Optional'}else{'Main'}
            $architecture=switch([string]$Row.architecture){'X86'{'x86'};'X64'{'x64'};'Arm'{'Arm'};'Arm64'{'Arm64'};'Neutral'{'Neutral'};default{'Unknown'}}
            $version="$([int]$Row.versionMajor).$([int]$Row.versionMinor).$([int]$Row.versionBuild).$([int]$Row.versionRevision)"
            return New-SoftwareInventoryEntry -ScopeId $scopeId -SourceKind Msix `
                -RegistrationId ([string]$Row.packageFullName) `
                -PackageFamilyName ([string]$Row.packageFamilyName) -PackageFullName ([string]$Row.packageFullName) `
                -DisplayName $Row.displayName -Version $version -PublisherId $Row.publisherId `
                -RegistrationContext $context -RegistryView None `
                -InstallerState $(if([bool]$Row.statusOk){'StatusOk'}else{'StatusNotOk'}) `
                -PackageType $type -Architecture $architecture
        }
        default { throw 'The source adapter kind is not release-owned.' }
    }
}

function ConvertFrom-SoftwareInventoryAdapterPayload {
    param([Parameter(Mandatory)] $Payload,[Parameter(Mandatory)] $Policy)
    if(-not (Test-SoftwareInventoryObjectShape $Payload @('assessmentUserContextVerified','processRelationship','observedExecutionContext','sourceLocale','scopeStates','adapterRows'))){throw 'The source adapter payload shape is invalid.'}
    $entries=[Collections.Generic.List[object]]::new()
    foreach($row in @($Payload.adapterRows)){
        try{$entries.Add((ConvertFrom-SoftwareInventoryAdapterRow -Row $row))}
        catch{
            $scope=$Payload.scopeStates|Where-Object scopeId -eq ([string]$row.scopeId)|Select-Object -First 1
            $ambiguousIdentity = $null -eq $scope -or
                $_.Exception.Message -match '(context|scope|state) is invalid'
            if(-not $ambiguousIdentity){$scope.state='Malformed';$scope.reasonCode='SOFTWARE.SOURCE_ENTRY_MALFORMED'}
            else{foreach($candidate in @($Payload.scopeStates)){if($candidate.state -eq 'Complete'){$candidate.state='Malformed';$candidate.reasonCode='SOFTWARE.SOURCE_PAYLOAD_MALFORMED'}}}
        }
    }
    [pscustomobject][ordered]@{
        assessmentUserContextVerified=[bool]$Payload.assessmentUserContextVerified
        processRelationship=[string]$Payload.processRelationship
        observedExecutionContext=[string]$Payload.observedExecutionContext
        sourceLocale=[string]$Payload.sourceLocale
        scopeStates=@($Payload.scopeStates);entries=@($entries)
    }
}

function New-SoftwareInventorySyntheticPayload {
    param(
        [Parameter(Mandatory)] [string] $Scenario,
        [Parameter(Mandatory)] $Policy
    )
    if ($Scenario -notin @($Policy.validationScenarios)) {
        throw 'The Software Inventory validation scenario is not release-owned.'
    }
    $scopeStates = @(
        foreach ($scope in @($Policy.scopes)) {
            New-SoftwareInventoryScopeState -ScopeId ([string] $scope.scopeId)
        }
    )
    $entries = [Collections.Generic.List[object]]::new()
    $newRegistry = {
        param($scope, $id, $name, $version, $publisher, $context, $view)
        New-SoftwareInventoryEntry -ScopeId $scope -SourceKind Registry `
            -RegistrationId $id -DisplayName $name -Version $version `
            -Publisher $publisher -RegistrationContext $context `
            -RegistryView $view -InstallerState Registered `
            -PackageType DesktopRegistration -Architecture None `
            -SystemComponent $false
    }
    $newMsi = {
        param($scope, $code, $name, $version, $publisher, $context, $state)
        New-SoftwareInventoryEntry -ScopeId $scope -SourceKind Msi `
            -RegistrationId "msi:${context}:$code" -ProductCode $code `
            -DisplayName $name -Version $version -Publisher $publisher `
            -RegistrationContext $context -RegistryView None `
            -InstallerState $state -PackageType MsiProduct -Architecture None
    }
    $newMsix = {
        param($scope, $identity, $name, $version, $publisherId, $context, $type, $architecture)
        New-SoftwareInventoryEntry -ScopeId $scope -SourceKind Msix `
            -RegistrationId "msix:${context}:$identity" `
            -PackageFamilyName "$name`_synthetic" -PackageFullName $identity `
            -DisplayName $name -Version $version -PublisherId $publisherId `
            -RegistrationContext $context -RegistryView None `
            -InstallerState StatusOk -PackageType $type -Architecture $architecture
    }
    $maxText = {
        param([string]$Prefix,[int]$Maximum,[char]$Fill)
        if($Prefix.Length -gt $Maximum){throw 'A synthetic maximum prefix exceeded its field bound.'}
        $Prefix + ([string]$Fill * ($Maximum - $Prefix.Length))
    }
    $machine32 = 'scope:software.registry.machine.32'
    $machine64 = 'scope:software.registry.machine.64'
    $user32 = 'scope:software.registry.assessment-user.32'
    $user64 = 'scope:software.registry.assessment-user.64'
    $msiMachine = 'scope:software.msi.machine'
    $msiUser = 'scope:software.msi.assessment-user'
    $msixUser = 'scope:software.msix.assessment-user'
    $msixMachine = 'scope:software.msix.machine'

    switch ($Scenario) {
        'RegistryViews' {
            $entries.Add((& $newRegistry $machine32 'reg:m32:a' 'Machine 32' '1.0' 'Publisher A' Machine Registry32))
            $entries.Add((& $newRegistry $machine64 'reg:m64:a' 'Machine 64' '2.0' 'Publisher B' Machine Registry64))
            $entries.Add((& $newRegistry $user32 'reg:u32:a' 'User 32' '3.0' 'Publisher C' AssessmentUser Registry32))
            $entries.Add((& $newRegistry $user64 'reg:u64:a' 'User 64' '4.0' 'Publisher D' AssessmentUser Registry64))
        }
        'UserAndMachine' {
            $entries.Add((& $newRegistry $machine64 'reg:m64:a' 'Desktop Machine' '1' 'Publisher A' Machine Registry64))
            $entries.Add((& $newRegistry $user64 'reg:u64:a' 'Desktop User' '2' 'Publisher B' AssessmentUser Registry64))
            $entries.Add((& $newMsi $msiMachine '{00000000-0000-0000-0000-000000000001}' 'MSI Machine' '2026' 'Publisher C' Machine Installed))
            $entries.Add((& $newMsi $msiUser '{00000000-0000-0000-0000-000000000002}' 'MSI User' '2026.1' 'Publisher D' AssessmentUserManaged Installed))
            $entries.Add((& $newMsix $msixUser 'Synthetic.User_1.0.0.0_x64__synthetic' 'Synthetic.User' '1.0.0.0' 'synthetic' AssessmentUser Main x64))
            $entries.Add((& $newMsix $msixMachine 'Synthetic.Machine_1.0.0.0_neutral__synthetic' 'Synthetic.Machine' '1.0.0.0' 'synthetic' MachineAllUsers Main Neutral))
        }
        'MsiStates' {
            $entries.Add((& $newMsi $msiMachine '{00000000-0000-0000-0000-000000000010}' 'Installed MSI' '1.0' 'Publisher' Machine Installed))
            $entries.Add((& $newMsi $msiUser '{00000000-0000-0000-0000-000000000011}' 'Advertised MSI' 'build-11' 'Publisher' AssessmentUserUnmanaged Advertised))
        }
        'PackageTypes' {
            $index = 0
            foreach ($type in @('Main', 'Bundle', 'Framework', 'Resource', 'Optional')) {
                $index++
                if($type -eq 'Main'){
                    $entries.Add((New-SoftwareInventoryEntry -ScopeId $msixUser -SourceKind Msix `
                        -RegistrationId 'msix:AssessmentUser:Microsoft.CompanyPortal_1.2.3.1_neutral__8wekyb3d8bbwe' `
                        -PackageFamilyName 'Microsoft.CompanyPortal_8wekyb3d8bbwe' `
                        -PackageFullName 'Microsoft.CompanyPortal_1.2.3.1_neutral__8wekyb3d8bbwe' `
                        -DisplayName 'Portal de empresa' -Version '1.2.3.1' `
                        -PublisherId '8wekyb3d8bbwe' -RegistrationContext AssessmentUser `
                        -RegistryView None -InstallerState StatusOk -PackageType Main -Architecture Neutral))
                }else{
                    $entries.Add((& $newMsix $msixUser "Synthetic.$type`_1.2.3.$index`_neutral__synthetic" "Synthetic.$type" "1.2.3.$index" 'synthetic' AssessmentUser $type Neutral))
                }
            }
        }
        'Duplicates' {
            $entries.Add((& $newRegistry $machine32 'reg:m32:duplicate-a' 'Same Product' 'one' 'Same Publisher' Machine Registry32))
            $entries.Add((& $newRegistry $machine64 'reg:m64:duplicate-b' 'Same Product' 'one' 'Same Publisher' Machine Registry64))
            $entries.Add((& $newMsi $msiMachine '{00000000-0000-0000-0000-000000000020}' 'Same Product' 'one' 'Same Publisher' Machine Installed))
        }
        'ArbitraryVersions' {
            $entries.Add((& $newRegistry $machine64 'reg:m64:version-a' 'Version A' 'release-2026.08+hotfix' 'Publisher' Machine Registry64))
            $entries.Add((& $newRegistry $user64 'reg:u64:version-b' 'Version B' 'vNext-preview_α' 'Publisher' AssessmentUser Registry64))
        }
        'Malformed' {
            $entries.Add((& $newRegistry $machine64 'reg:m64:malformed' ('x' * 600) '1' 'Publisher' Machine Registry64))
        }
        'Oversize' {
            foreach ($index in 1..65) {
                $entries.Add((& $newRegistry $machine64 "reg:m64:$index" "Product $index" "$index" 'Publisher' Machine Registry64))
            }
        }
        'AggregateMaximum' {
            foreach($index in 1..16){
                $entries.Add((& $newRegistry $machine32 (&$maxText "reg:m32:max-$index`:" 256 'r') (&$maxText "Machine32-$index`:" 512 'n') (&$maxText "$index`:" 256 'v') (&$maxText "Publisher-$index`:" 512 'p') Machine Registry32))
                $entries.Add((& $newRegistry $machine64 (&$maxText "reg:m64:max-$index`:" 256 'r') (&$maxText "Machine64-$index`:" 512 'n') (&$maxText "$index`:" 256 'v') (&$maxText "Publisher-$index`:" 512 'p') Machine Registry64))
                $entries.Add((& $newRegistry $user32 (&$maxText "reg:u32:max-$index`:" 256 'r') (&$maxText "User32-$index`:" 512 'n') (&$maxText "$index`:" 256 'v') (&$maxText "Publisher-$index`:" 512 'p') AssessmentUser Registry32))
                $entries.Add((& $newRegistry $user64 (&$maxText "reg:u64:max-$index`:" 256 'r') (&$maxText "User64-$index`:" 512 'n') (&$maxText "$index`:" 256 'v') (&$maxText "Publisher-$index`:" 512 'p') AssessmentUser Registry64))
                $codeMachine=('{'+'00000000-0000-0000-0001-'+$index.ToString('000000000000')+'}')
                $codeUser=('{'+'00000000-0000-0000-0002-'+$index.ToString('000000000000')+'}')
                $entries.Add((New-SoftwareInventoryEntry -ScopeId $msiMachine -SourceKind Msi -RegistrationId (&$maxText "msi:machine:$index`:" 256 'i') -ProductCode $codeMachine -DisplayName (&$maxText "MSI-Machine-$index`:" 512 'n') -Version (&$maxText "$index`:" 256 'v') -Publisher (&$maxText "Publisher-$index`:" 512 'p') -RegistrationContext Machine -RegistryView None -InstallerState Installed -PackageType MsiProduct -Architecture None))
                $entries.Add((New-SoftwareInventoryEntry -ScopeId $msiUser -SourceKind Msi -RegistrationId (&$maxText "msi:user:$index`:" 256 'i') -ProductCode $codeUser -DisplayName (&$maxText "MSI-User-$index`:" 512 'n') -Version (&$maxText "$index`:" 256 'v') -Publisher (&$maxText "Publisher-$index`:" 512 'p') -RegistrationContext AssessmentUserManaged -RegistryView None -InstallerState Advertised -PackageType MsiProduct -Architecture None))
                foreach($msix in @(
                    @{scope=$msixUser;context='AssessmentUser';architecture='x64';prefix="User-$index"},
                    @{scope=$msixMachine;context='MachineAllUsers';architecture='Neutral';prefix="Machine-$index"}
                )){
                    $entries.Add((New-SoftwareInventoryEntry -ScopeId $msix.scope -SourceKind Msix -RegistrationId (&$maxText "msix:$($msix.prefix):" 256 'i') -PackageFamilyName (&$maxText "family:$($msix.prefix):" 256 'f') -PackageFullName (&$maxText "full:$($msix.prefix):" 512 'q') -DisplayName (&$maxText "display:$($msix.prefix):" 512 'n') -Version (&$maxText "$index`:" 256 'v') -PublisherId (&$maxText "publisher:$($msix.prefix):" 256 'p') -RegistrationContext $msix.context -RegistryView None -InstallerState StatusOk -PackageType Main -Architecture $msix.architecture))
                }
            }
        }
        'DeniedAllUsers' {
            $state = @($scopeStates | Where-Object scopeId -eq $msixMachine)[0]
            $state.state = 'Denied'; $state.reasonCode = 'SOFTWARE.ALL_USERS_ACCESS_DENIED'
        }
        'DeniedUser' {
            foreach ($scopeId in @($user32, $user64, $msiUser, $msixUser)) {
                $state = @($scopeStates | Where-Object scopeId -eq $scopeId)[0]
                $state.state = 'Denied'; $state.reasonCode = 'SOFTWARE.ASSESSMENT_USER_ACCESS_DENIED'
            }
        }
        'Unicode' {
            $entries.Add((& $newRegistry $machine64 'reg:m64:unicode' '应用程序 Ω' '版本-二' 'Éditeur 東京' Machine Registry64))
            $entries.Add((& $newMsi $msiUser '{00000000-0000-0000-0000-000000000030}' 'Aplicación ñ' '版本-三' 'Издатель' AssessmentUserManaged Installed))
            $entries.Add((& $newMsix $msixUser 'Synthetic.Unicode_1.0.0.0_neutral__synthetic' 'パッケージ' '1.0.0.0' '発行元' AssessmentUser Main Neutral))
        }
        'AlternateAdministrator' {
            foreach ($state in $scopeStates) {
                $state.state = 'Denied'; $state.reasonCode = 'SOFTWARE.ASSESSMENT_USER_CONTEXT_MISMATCH'
            }
        }
        'LocalSystem' {
            foreach ($state in $scopeStates) {
                $state.state = 'Denied'; $state.reasonCode = 'SOFTWARE.SYSTEM_CONTEXT_PROHIBITED'
            }
        }
        'Partial' {
            $entries.Add((& $newRegistry $machine64 'reg:m64:partial' 'Retained Product' '1' 'Publisher' Machine Registry64))
            foreach ($scopeId in @($machine64, $msixMachine)) {
                $state = @($scopeStates | Where-Object scopeId -eq $scopeId)[0]
                $state.state = 'Partial'; $state.reasonCode = 'SOFTWARE.EVIDENCE_BOUND_EXCEEDED'
            }
        }
    }
    $contextAllowed = $Scenario -notin @('AlternateAdministrator', 'LocalSystem')
    [pscustomobject][ordered]@{
        assessmentUserContextVerified = $contextAllowed
        processRelationship = if ($Scenario -eq 'AlternateAdministrator') {'AlternateAdministrator'}
            elseif ($Scenario -eq 'LocalSystem') {'ProhibitedSystemContext'} else {'SameUser'}
        observedExecutionContext = if ($Scenario -eq 'AlternateAdministrator') {'Administrator'}
            elseif ($Scenario -eq 'LocalSystem') {'LocalSystem'} else {'Synthetic'}
        sourceLocale = if ($Scenario -eq 'Unicode') {'ja-JP'} else {'und'}
        scopeStates = @($scopeStates)
        entries = @($entries)
    }
}

function Test-SoftwareInventoryObjectShape {
    param($Value, [string[]] $Names)
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    (@($Names | Sort-Object) -join '|') -ceq ($actual -join '|')
}

function Test-SoftwareInventoryText {
    param($Value, [int] $Maximum, [switch] $AllowNull)
    if ($null -eq $Value) { return [bool]$AllowNull }
    if ($Value -isnot [string]) { return $false }
    [Text.Encoding]::UTF8.GetByteCount([string]$Value) -le $Maximum
}

function Test-SoftwareInventoryEntry {
    param($Entry, $Policy)
    $names = @('scopeId','sourceKind','registrationId','productCode','packageFamilyName',
        'packageFullName','displayName','version','publisher','publisherId','systemComponent',
        'registrationContext','registryView','installerState','packageType','architecture')
    if (-not (Test-SoftwareInventoryObjectShape $Entry $names)) { return $false }
    if ([string]$Entry.scopeId -notin @($Policy.scopes.scopeId) -or
        [string]$Entry.sourceKind -notin @('Registry','Msi','Msix') -or
        -not (Test-SoftwareInventoryText $Entry.registrationId 512) -or
        [string]::IsNullOrWhiteSpace([string]$Entry.registrationId) -or
        -not (Test-SoftwareInventoryText $Entry.productCode 64 -AllowNull) -or
        -not (Test-SoftwareInventoryText $Entry.packageFamilyName 256 -AllowNull) -or
        -not (Test-SoftwareInventoryText $Entry.packageFullName 512 -AllowNull) -or
        -not (Test-SoftwareInventoryText $Entry.displayName 512 -AllowNull) -or
        -not (Test-SoftwareInventoryText $Entry.version 256 -AllowNull) -or
        -not (Test-SoftwareInventoryText $Entry.publisher 512 -AllowNull) -or
        -not (Test-SoftwareInventoryText $Entry.publisherId 256 -AllowNull) -or
        ($null -ne $Entry.systemComponent -and $Entry.systemComponent -isnot [bool]) -or
        [string]$Entry.registrationContext -notin @('Machine','AssessmentUser',
            'AssessmentUserManaged','AssessmentUserUnmanaged','MachineAllUsers') -or
        [string]$Entry.registryView -notin @('Registry32','Registry64','None') -or
        [string]$Entry.installerState -notin @('Registered','Installed','Advertised','StatusOk','StatusNotOk') -or
        [string]$Entry.packageType -notin @('DesktopRegistration','MsiRegistration','MsiProduct','Main','Bundle','Framework','Resource','Optional') -or
        [string]$Entry.architecture -notin @('None','x86','x64','Arm','Arm64','Neutral','Unknown')) {
        return $false
    }
    if ($null -ne $Entry.productCode -and
        [string]$Entry.productCode -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { return $false }
    Test-SoftwareInventoryEntryTuple -Entry $Entry
}

function Test-SoftwareInventoryEntryTuple {
    param([Parameter(Mandatory)] $Entry)
    $scopeId=[string]$Entry.scopeId
    $sourceKind=[string]$Entry.sourceKind
    $context=[string]$Entry.registrationContext
    $view=[string]$Entry.registryView
    $state=[string]$Entry.installerState
    $type=[string]$Entry.packageType
    $architecture=[string]$Entry.architecture
    $registryTuple = $sourceKind -eq 'Registry' -and $state -eq 'Registered' -and
        $type -in @('DesktopRegistration','MsiRegistration') -and $architecture -eq 'None' -and
        $null -eq $Entry.productCode -and $null -eq $Entry.packageFamilyName -and
        $null -eq $Entry.packageFullName -and $null -eq $Entry.publisherId
    switch ($scopeId) {
        'scope:software.registry.machine.32' { return $registryTuple -and $context -eq 'Machine' -and $view -eq 'Registry32' }
        'scope:software.registry.machine.64' { return $registryTuple -and $context -eq 'Machine' -and $view -eq 'Registry64' }
        'scope:software.registry.assessment-user.32' { return $registryTuple -and $context -eq 'AssessmentUser' -and $view -eq 'Registry32' }
        'scope:software.registry.assessment-user.64' { return $registryTuple -and $context -eq 'AssessmentUser' -and $view -eq 'Registry64' }
    }
    $msiTuple = $sourceKind -eq 'Msi' -and $null -ne $Entry.productCode -and
        $view -eq 'None' -and $state -in @('Installed','Advertised') -and
        $type -eq 'MsiProduct' -and $architecture -eq 'None' -and
        $null -eq $Entry.packageFamilyName -and $null -eq $Entry.packageFullName -and
        $null -eq $Entry.publisherId -and $null -eq $Entry.systemComponent
    switch ($scopeId) {
        'scope:software.msi.machine' { return $msiTuple -and $context -eq 'Machine' }
        'scope:software.msi.assessment-user' { return $msiTuple -and $context -in @('AssessmentUserManaged','AssessmentUserUnmanaged') }
    }
    $msixTuple = $sourceKind -eq 'Msix' -and $null -eq $Entry.productCode -and
        -not [string]::IsNullOrWhiteSpace([string]$Entry.packageFamilyName) -and
        -not [string]::IsNullOrWhiteSpace([string]$Entry.packageFullName) -and
        $view -eq 'None' -and $state -in @('StatusOk','StatusNotOk') -and
        $type -in @('Main','Bundle','Framework','Resource','Optional') -and
        $architecture -in @('x86','x64','Arm','Arm64','Neutral','Unknown') -and
        $null -eq $Entry.publisher -and $null -eq $Entry.systemComponent
    switch ($scopeId) {
        'scope:software.msix.assessment-user' { return $msixTuple -and $context -eq 'AssessmentUser' }
        'scope:software.msix.machine' { return $msixTuple -and $context -eq 'MachineAllUsers' }
        default { return $false }
    }
}

function Test-SoftwareInventoryCollectorPayload {
    param([Parameter(Mandatory)] $Payload, [Parameter(Mandatory)] $Policy)
    $names = @('assessmentUserContextVerified','processRelationship',
        'observedExecutionContext','sourceLocale','scopeStates','entries')
    if (-not (Test-SoftwareInventoryObjectShape $Payload $names) -or
        $Payload.assessmentUserContextVerified -isnot [bool] -or
        [string]$Payload.processRelationship -notin @('SameUser','AlternateAdministrator',
            'DifferentStandardUser','ElevatedAssessmentUser','ProhibitedSystemContext','Unavailable') -or
        [string]$Payload.observedExecutionContext -notin @('StandardUser','Synthetic',
            'Administrator','LocalSystem','Unavailable') -or
        -not (Test-SoftwareInventoryText $Payload.sourceLocale 32) -or
        @($Payload.scopeStates).Count -ne @($Policy.scopes).Count) { return $false }
    $verifiedTuple = $Payload.assessmentUserContextVerified -and
        [string]$Payload.processRelationship -eq 'SameUser' -and
        [string]$Payload.observedExecutionContext -in @('StandardUser','Synthetic')
    if ($Payload.assessmentUserContextVerified -ne $verifiedTuple) { return $false }
    $scopeIds = @($Payload.scopeStates.scopeId)
    if (@($scopeIds | Sort-Object -Unique).Count -ne @($Policy.scopes).Count -or
        @($Policy.scopes.scopeId | Where-Object {$_ -notin $scopeIds}).Count -gt 0) { return $false }
    foreach ($scope in @($Payload.scopeStates)) {
        if (-not (Test-SoftwareInventoryObjectShape $scope @('scopeId','state','reasonCode')) -or
            [string]$scope.state -notin @('Complete','Partial','Unavailable','Denied',
                'Malformed','TimedOut','Cancelled','Failed','NotAttempted','NotApplicable') -or
            -not (Test-SoftwareInventoryText $scope.reasonCode 128)) { return $false }
        if (([string]$scope.state -eq 'Complete') -ne
            [string]::IsNullOrEmpty([string]$scope.reasonCode)) { return $false }
    }
    foreach ($entry in @($Payload.entries)) {
        if (-not (Test-SoftwareInventoryEntry -Entry $entry -Policy $Policy)) { return $false }
    }
    foreach ($scopeId in @($Policy.scopes.scopeId)) {
        if (@($Payload.entries | Where-Object scopeId -eq $scopeId).Count -gt
            [int]$Policy.collector.maximumEntriesPerScope) { return $false }
    }
    if (@($Payload.entries).Count -gt [int]$Policy.collector.maximumTotalEntries) { return $false }
    if (-not $verifiedTuple -and (@($Payload.entries).Count -gt 0 -or
        @($Payload.scopeStates | Where-Object state -eq 'Complete').Count -gt 0)) { return $false }
    $true
}

function ConvertTo-SoftwareInventoryAttemptPayload {
    param([Parameter(Mandatory)] $Payload, [Parameter(Mandatory)] $Policy)
    $scopeStates = @(
        foreach ($definition in @($Policy.scopes)) {
            $source = @($Payload.scopeStates | Where-Object scopeId -eq $definition.scopeId)[0]
            if ($null -eq $source) {
                New-SoftwareInventoryScopeState -ScopeId $definition.scopeId `
                    -State Malformed -ReasonCode 'SOFTWARE.SOURCE_PAYLOAD_MALFORMED'
            }
            else {
                New-SoftwareInventoryScopeState -ScopeId $definition.scopeId `
                    -State ([string]$source.state) -ReasonCode ([string]$source.reasonCode)
            }
        }
    )
    $entries = [Collections.Generic.List[object]]::new()
    $counts = @{}
    foreach ($entry in @($Payload.entries)) {
        $scopeId = [string]$entry.scopeId
        $scope = @($scopeStates | Where-Object scopeId -eq $scopeId)[0]
        if ($null -eq $scope -or -not (Test-SoftwareInventoryEntry -Entry $entry -Policy $Policy)) {
            if ($null -ne $scope) {
                $scope.state = 'Malformed'; $scope.reasonCode = 'SOFTWARE.SOURCE_ENTRY_MALFORMED'
            }
            continue
        }
        if (-not $counts.ContainsKey($scopeId)) { $counts[$scopeId] = 0 }
        if ($counts[$scopeId] -ge [int]$Policy.collector.maximumEntriesPerScope) {
            $scope.state = 'Partial'; $scope.reasonCode = 'SOFTWARE.EVIDENCE_BOUND_EXCEEDED'
            continue
        }
        if ($entries.Count -ge [int]$Policy.collector.maximumTotalEntries) {
            $scope.state = 'Partial'; $scope.reasonCode = 'SOFTWARE.TOTAL_EVIDENCE_BOUND_EXCEEDED'
            continue
        }
        $counts[$scopeId]++
        $entryParameters = @{
            ScopeId=[string]$entry.scopeId; SourceKind=[string]$entry.sourceKind
            RegistrationId=[string]$entry.registrationId; ProductCode=$entry.productCode
            PackageFamilyName=$entry.packageFamilyName; PackageFullName=$entry.packageFullName
            DisplayName=$entry.displayName; Version=$entry.version; Publisher=$entry.publisher
            PublisherId=$entry.publisherId; SystemComponent=$entry.systemComponent
            RegistrationContext=[string]$entry.registrationContext
            RegistryView=[string]$entry.registryView; InstallerState=[string]$entry.installerState
            PackageType=[string]$entry.packageType; Architecture=[string]$entry.architecture
        }
        $entries.Add((New-SoftwareInventoryEntry @entryParameters))
    }
    [pscustomobject][ordered]@{
        assessmentUserContextVerified = [bool]$Payload.assessmentUserContextVerified
        processRelationship = [string]$Payload.processRelationship
        observedExecutionContext = [string]$Payload.observedExecutionContext
        sourceLocale = [string]$Payload.sourceLocale
        scopeStates = @($scopeStates)
        entries = @($entries)
    }
}

function Test-SoftwareInventorySid {
    param([Parameter(Mandatory)] [string] $Value)
    try {
        if ([Text.Encoding]::UTF8.GetByteCount($Value) -gt 184) { return $false }
        $sid = [Security.Principal.SecurityIdentifier]::new($Value)
        [string]::Equals($sid.Value, $Value, [StringComparison]::Ordinal)
    }
    catch { $false }
}

function Get-SoftwareInventoryProcessDisposition {
    param(
        [Parameter(Mandatory)] [string] $ProcessSid,
        [Parameter(Mandatory)] [string] $AssessmentUserSid,
        [Parameter(Mandatory)] [bool] $IsAdministrator
    )
    if ($ProcessSid -eq 'S-1-5-18') {
        return [pscustomobject]@{
            relationship = 'ProhibitedSystemContext'; executionContext = 'LocalSystem'
        }
    }
    if ($IsAdministrator) {
        $relationship = if ([string]::Equals(
            $ProcessSid, $AssessmentUserSid, [StringComparison]::OrdinalIgnoreCase
        )) {'ElevatedAssessmentUser'} else {'AlternateAdministrator'}
        return [pscustomobject]@{
            relationship = $relationship; executionContext = 'Administrator'
        }
    }
    if (-not [string]::Equals(
        $ProcessSid, $AssessmentUserSid, [StringComparison]::OrdinalIgnoreCase
    )) {
        return [pscustomobject]@{
            relationship = 'DifferentStandardUser'; executionContext = 'StandardUser'
        }
    }
    $null
}

function New-SoftwareInventoryGapPayload {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [string] $Relationship,
        [Parameter(Mandatory)] [string] $ObservedContext
    )
    [pscustomobject][ordered]@{
        assessmentUserContextVerified = $Relationship -eq 'SameUser'
        processRelationship = $Relationship
        observedExecutionContext = $ObservedContext
        sourceLocale = 'und'
        scopeStates = @($Policy.scopes | ForEach-Object {
            New-SoftwareInventoryScopeState -ScopeId ([string]$_.scopeId) `
                -State $State -ReasonCode $ReasonCode
        })
        entries = @()
    }
}

function Get-SoftwareInventoryLiveSource {
    # Threat: broad inventory tools can activate provider behavior, inspect paths,
    # or accidentally read another person's profile. This child instead calls only
    # release-declared read interfaces. It repeats the canonical SID/non-elevation
    # check before opening CurrentUser so the parent cannot substitute an alternate
    # administrator or SYSTEM token after approval. Each source has an independent
    # Evidence Scope; access denial or malformed data narrows coverage and never
    # becomes a negative observation. The coordinator treats the child output as
    # untrusted until the exact-property and primitive validator re-projects it.
@'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
function New-Scope([string]$id){[pscustomobject][ordered]@{scopeId=$id;state='Complete';reasonCode=''}}
function Set-Scope($scopes,[string]$id,[string]$state,[string]$reason){
    $scope=@($scopes|Where-Object scopeId -eq $id)[0]
    if($scope.state -eq 'Complete' -or $state -in @('Denied','Failed','Malformed')){
        $scope.state=$state;$scope.reasonCode=$reason
    }
}
function Failure-State([Exception]$exception){
    $current=$exception
    while($null -ne $current){
        if($current -is [UnauthorizedAccessException] -or $current.HResult -eq -2147024891){return 'Denied'}
        $current=$current.InnerException
    }
    'Failed'
}
function Add-Entry($entries,$counts,$entry,[int]$maximum,$scopes){
    $scopeId=[string]$entry.scopeId
    if(-not $counts.ContainsKey($scopeId)){$counts[$scopeId]=0}
    if($counts[$scopeId] -ge $maximum){
        Set-Scope $scopes $scopeId 'Partial' 'SOFTWARE.EVIDENCE_BOUND_EXCEEDED';return
    }
    if($entries.Count -ge $maximumTotal){
        Set-Scope $scopes $scopeId 'Partial' 'SOFTWARE.TOTAL_EVIDENCE_BOUND_EXCEEDED';return
    }
    $counts[$scopeId]++;$entries.Add($entry)
}
function Text-Or-Null($value){if($value -is [string]){[string]$value}else{$null}}
$expectedSid=[string]$env:WINPCINFO_SOFTWARE_ASSESSMENT_SID
$maximum=[int]$env:WINPCINFO_SOFTWARE_MAXIMUM
$maximumTotal=[int]$env:WINPCINFO_SOFTWARE_MAXIMUM_TOTAL
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$actualSid=[string]$identity.User.Value
if($actualSid -eq 'S-1-5-18' -or
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    -not [string]::Equals($actualSid,$expectedSid,[StringComparison]::OrdinalIgnoreCase)){
    throw 'The child process is not the verified Assessment User Context.'
}
$scopeIds=@(
    'scope:software.registry.machine.32','scope:software.registry.machine.64',
    'scope:software.registry.assessment-user.32','scope:software.registry.assessment-user.64',
    'scope:software.msi.machine','scope:software.msi.assessment-user',
    'scope:software.msix.assessment-user','scope:software.msix.machine'
)
$scopes=@($scopeIds|ForEach-Object {New-Scope $_})
$entries=[Collections.Generic.List[object]]::new();$counts=@{}
$uninstallKey='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
foreach($context in @('Machine','AssessmentUser')){
    foreach($viewName in @('Registry32','Registry64')){
        $scopeId="scope:software.registry.$($context.ToLowerInvariant()).$($viewName.Substring(8))"
        if($context -eq 'AssessmentUser'){$scopeId=$scopeId.Replace('.assessmentuser.','.assessment-user.')}
        if($viewName -eq 'Registry64' -and -not [Environment]::Is64BitOperatingSystem){
            Set-Scope $scopes $scopeId 'NotApplicable' 'SOFTWARE.REGISTRY_VIEW_NOT_APPLICABLE';continue
        }
        $baseKey=$null;$root=$null
        try{
            $hive=if($context -eq 'Machine'){[Microsoft.Win32.RegistryHive]::LocalMachine}else{[Microsoft.Win32.RegistryHive]::CurrentUser}
            $view=[Microsoft.Win32.RegistryView]::$viewName
            $baseKey=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
            $root=$baseKey.OpenSubKey($uninstallKey,$false)
            $names=if($null -eq $root){@()}else{@($root.GetSubKeyNames()|Sort-Object)}
            foreach($name in $names){
                $key=$null
                try{
                    $key=$root.OpenSubKey([string]$name,$false)
                    if($null -eq $key){Set-Scope $scopes $scopeId 'Partial' 'SOFTWARE.REGISTRATION_UNAVAILABLE';continue}
                    $displayName=$key.GetValue('DisplayName',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $version=$key.GetValue('DisplayVersion',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $publisher=$key.GetValue('Publisher',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $windowsInstaller=$key.GetValue('WindowsInstaller',$null)
                    $systemComponent=$key.GetValue('SystemComponent',$null)
                    if(($null -ne $displayName -and $displayName -isnot [string]) -or
                        ($null -ne $version -and $version -isnot [string]) -or
                        ($null -ne $publisher -and $publisher -isnot [string]) -or
                        ($null -ne $windowsInstaller -and $windowsInstaller -isnot [int]) -or
                        ($null -ne $systemComponent -and $systemComponent -isnot [int])){
                        Set-Scope $scopes $scopeId 'Partial' 'SOFTWARE.REGISTRATION_MALFORMED';continue
                    }
                    Add-Entry $entries $counts ([pscustomobject][ordered]@{
                        adapterKind='Registry';scopeId=$scopeId;registrationKeyName=[string]$name
                        registrationContext=$context;registryView=$viewName
                        displayName=Text-Or-Null $displayName;version=Text-Or-Null $version
                        publisher=Text-Or-Null $publisher;windowsInstaller=$windowsInstaller
                        systemComponent=$systemComponent
                    }) $maximum $scopes
                }catch{Set-Scope $scopes $scopeId 'Partial' 'SOFTWARE.REGISTRATION_UNAVAILABLE'}
                finally{if($null -ne $key){$key.Dispose()}}
            }
        }catch{$state=Failure-State $_.Exception;Set-Scope $scopes $scopeId $state 'SOFTWARE.REGISTRY_SOURCE_FAILED'}
        finally{if($null -ne $root){$root.Dispose()};if($null -ne $baseKey){$baseKey.Dispose()}}
    }
}

if(-not ('WinPCInfo.SoftwareInventory.InstallerReader' -as [type])){
      $null=Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace WinPCInfo.SoftwareInventory {
  public sealed class InstallerValue { public string productCode; public int context; public string state; public string name; public string version; public string publisher; }
  public sealed class InstallerResult { public InstallerValue[] rows; public bool exceeded; public bool malformed; public bool unavailable; }
  public static class InstallerReader {
    // These values are the public MSIINSTALLCONTEXT values and documented MSI
    // product-state strings. We call only enumeration/property APIs: no configure,
    // reinstall, provide-component, or consistency operation is imported, so this
    // adapter has no native path that could activate Windows Installer repair.
    const int UserManaged=1,UserUnmanaged=2,Machine=4,NoMoreItems=259,MoreData=234,UnknownProperty=1608;
    [DllImport("msi.dll",CharSet=CharSet.Unicode)] static extern int MsiEnumProductsExW(string product,string user,int contexts,int index,StringBuilder code,out int installedContext,StringBuilder sid,ref int sidLength);
    [DllImport("msi.dll",CharSet=CharSet.Unicode)] static extern int MsiGetProductInfoExW(string code,string user,int context,string property,StringBuilder value,ref int length);
    // A null user SID has documented source semantics: machine queries use the
    // machine context and user queries use the caller represented by the returned
    // product context. The caller separately verifies each returned non-empty SID
    // against the approved Assessment User before admitting the row.
    static string Get(string code,int context,string property){int length=0;int result=MsiGetProductInfoExW(code,null,context,property,null,ref length);if(result==UnknownProperty)return null;if(result==0&&length==0)return "";if(result!=MoreData)throw new Win32Exception(result);length++;var value=new StringBuilder(length);result=MsiGetProductInfoExW(code,null,context,property,value,ref length);if(result==UnknownProperty)return null;if(result!=0)throw new Win32Exception(result);return value.ToString();}
    static InstallerResult ReadContext(string expectedSid,int contexts,bool expectMachine,int maximum){
      var result=new InstallerResult();var values=new List<InstallerValue>();
      for(int index=0;;index++){var code=new StringBuilder(39);var sid=new StringBuilder(185);int sidLength=184,context;int call=MsiEnumProductsExW(null,null,contexts,index,code,out context,sid,ref sidLength);if(call==NoMoreItems)break;if(call!=0)throw new Win32Exception(call);bool machine=context==Machine;bool user=context==UserManaged||context==UserUnmanaged;if((expectMachine&&!machine)||(!expectMachine&&!user)){result.malformed=true;continue;}string returnedSid=sid.ToString();if(user&&returnedSid.Length>0&&!String.Equals(returnedSid,expectedSid,StringComparison.OrdinalIgnoreCase)){result.malformed=true;continue;}if(values.Count>=maximum){result.exceeded=true;continue;}try{string state=Get(code.ToString(),context,"State");if(state!="1"&&state!="5"){result.malformed=true;continue;}values.Add(new InstallerValue{productCode=code.ToString(),context=context,state=state,name=Get(code.ToString(),context,"ProductName"),version=Get(code.ToString(),context,"VersionString"),publisher=Get(code.ToString(),context,"Publisher")});}catch(Win32Exception){result.unavailable=true;}}
      result.rows=values.ToArray();return result;
    }
    public static InstallerResult ReadMachine(int maximum){return ReadContext("",Machine,true,maximum);}
    public static InstallerResult ReadUser(string expectedSid,int maximum){return ReadContext(expectedSid,UserManaged|UserUnmanaged,false,maximum);}
  }
}
"@
}
foreach($msiContext in @('Machine','AssessmentUser')){
      $scopeId=if($msiContext -eq 'Machine'){'scope:software.msi.machine'}else{'scope:software.msi.assessment-user'}
      try{
        $result=if($msiContext -eq 'Machine'){
          [WinPCInfo.SoftwareInventory.InstallerReader]::ReadMachine($maximum)
        }else{[WinPCInfo.SoftwareInventory.InstallerReader]::ReadUser($expectedSid,$maximum)}
        foreach($row in $result.rows){
            Add-Entry $entries $counts ([pscustomobject][ordered]@{
              adapterKind='Msi';scopeId=$scopeId;productCode=[string]$row.productCode
              installContext=[int]$row.context;stateCode=[string]$row.state
              displayName=Text-Or-Null $row.name;version=Text-Or-Null $row.version
              publisher=Text-Or-Null $row.publisher
            }) $maximum $scopes
        }
        if($result.exceeded){Set-Scope $scopes $scopeId 'Partial' 'SOFTWARE.EVIDENCE_BOUND_EXCEEDED'}
        if($result.malformed){Set-Scope $scopes $scopeId 'Partial' 'SOFTWARE.INSTALLER_ENTRY_MALFORMED'}
        if($result.unavailable){Set-Scope $scopes $scopeId 'Partial' 'SOFTWARE.INSTALLER_ENTRY_UNAVAILABLE'}
      }catch{$state=Failure-State $_.Exception;Set-Scope $scopes $scopeId $state 'SOFTWARE.INSTALLER_SOURCE_FAILED'}
}

function Add-PackageRows($packages,[string]$scopeId,[string]$context){
    # PackageManager returns structured identity/status objects without opening a
    # package path or manifest. FindPackagesForUser('') is the already verified
    # Assessment User; FindPackages() is the distinct all-user query and may be
    # denied to a standard token. Each query has its own scope, so all-user denial
    # cannot erase successful user evidence or become observed absence. Boolean
    # package flags are retained as raw adapter facts and normalized only after the
    # coordinator revalidates the child payload.
    foreach($package in $packages){
        try{
            $id=$package.Id;$version=$id.Version
            $optional=$false;try{$optional=[bool]$package.IsOptional}catch{}
            $architecture=switch([string]$id.Architecture){'X86'{'x86'};'X64'{'x64'};'Arm'{'Arm'};'Arm64'{'Arm64'};'Neutral'{'Neutral'};default{'Unknown'}}
            Add-Entry $entries $counts ([pscustomobject][ordered]@{
                adapterKind='Msix';scopeId=$scopeId;queryContext=$context
                packageFamilyName=[string]$id.FamilyName;packageFullName=[string]$id.FullName
                displayName=[string]$id.Name;publisherId=[string]$id.PublisherId
                versionMajor=[int]$version.Major;versionMinor=[int]$version.Minor
                versionBuild=[int]$version.Build;versionRevision=[int]$version.Revision
                architecture=[string]$id.Architecture;isBundle=[bool]$package.IsBundle
                isFramework=[bool]$package.IsFramework;isResource=[bool]$package.IsResourcePackage
                isOptional=$optional;statusOk=[bool]$package.Status.VerifyIsOK()
            }) $maximum $scopes
        }catch{Set-Scope $scopes $scopeId 'Partial' 'SOFTWARE.PACKAGE_ENTRY_MALFORMED'}
    }
}
try{
    $manager=[Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime]::new()
    Add-PackageRows ($manager.FindPackagesForUser('')) 'scope:software.msix.assessment-user' 'AssessmentUser'
}catch{$state=Failure-State $_.Exception;Set-Scope $scopes 'scope:software.msix.assessment-user' $state 'SOFTWARE.PACKAGE_USER_SOURCE_FAILED'}
try{
    $manager=[Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime]::new()
    Add-PackageRows ($manager.FindPackages()) 'scope:software.msix.machine' 'MachineAllUsers'
}catch{$state=Failure-State $_.Exception;Set-Scope $scopes 'scope:software.msix.machine' $state 'SOFTWARE.PACKAGE_ALL_USERS_SOURCE_FAILED'}

$payload=[pscustomobject][ordered]@{
    assessmentUserContextVerified=$true;processRelationship='SameUser';observedExecutionContext='StandardUser'
    sourceLocale='und';scopeStates=@($scopes);adapterRows=@($entries)
}
[Console]::Out.Write(($payload|ConvertTo-Json -Compress -Depth 6))
'@
}

function ConvertTo-SoftwareInventoryEncodedCommand {
    param([Parameter(Mandatory)] [string] $Source)
    $input = [IO.MemoryStream]::new([Text.UTF8Encoding]::new($false).GetBytes($Source))
    $output = [IO.MemoryStream]::new()
    try {
        $gzip = [IO.Compression.GZipStream]::new(
            $output, [IO.Compression.CompressionLevel]::Optimal, $true
        )
        try { $input.CopyTo($gzip) } finally { $gzip.Dispose() }
        $payload = [Convert]::ToBase64String($output.ToArray())
    }
    finally { $input.Dispose(); $output.Dispose() }
    $bootstrap = '$b=[Convert]::FromBase64String(''' + $payload +
        ''');$m=[IO.MemoryStream]::new($b);$g=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);$r=[IO.StreamReader]::new($g,[Text.Encoding]::UTF8);try{&([scriptblock]::Create($r.ReadToEnd()))}finally{$r.Dispose();$g.Dispose();$m.Dispose()}'
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
}

function Invoke-BoundedSoftwareInventorySnapshot {
    param([Parameter(Mandatory)] $Policy, [Parameter(Mandatory)] [string] $AssessmentUserSid)
    # The release-owned source is compressed into the command line so no writable
    # script path exists between validation and launch. NativeRunner starts only
    # the active host inside a Job Object, bounds output and time, and must prove
    # the whole tree absent. A timeout is useful coverage evidence; uncertain tree
    # cleanup is a run-level cleanup failure and is never downgraded to a gap.
    Initialize-ProcessSupervisorNativeType
    $collector = $Policy.collector
    $terminationMilliseconds = 1000
    $activeMilliseconds = [Math]::Max(
        1, [int]$collector.deadlineMilliseconds - $terminationMilliseconds
    )
    $startedAt = [DateTimeOffset]::UtcNow
    $windowsDirectory = [Environment]::GetFolderPath('Windows')
    $executable = [IO.Path]::GetFullPath((Join-Path $windowsDirectory `
        'System32\WindowsPowerShell\v1.0\powershell.exe'))
    if (-not [IO.File]::Exists($executable)) {
        return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode='SOFTWARE.BOUNDARY_UNAVAILABLE';startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow}
    }
    $environment = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $environment['SystemRoot'] = $windowsDirectory
    $environment['WINPCINFO_SOFTWARE_ASSESSMENT_SID'] = $AssessmentUserSid
    $environment['WINPCINFO_SOFTWARE_MAXIMUM'] = [string]$collector.maximumEntriesPerScope
    $environment['WINPCINFO_SOFTWARE_MAXIMUM_TOTAL'] = [string]$collector.maximumTotalEntries
    $environment['POWERSHELL_TELEMETRY_OPTOUT'] = '1'
    $environment['POWERSHELL_UPDATECHECK'] = 'Off'
    $environment['POWERSHELL_DIAGNOSTICS_OPTOUT'] = '1'
    $environment['DOTNET_CLI_TELEMETRY_OPTOUT'] = '1'
    # Windows PowerShell's in-box C# compiler writes transient compiler files.
    # Give it one unpredictable, coordinator-owned directory rather than the
    # ambient shared temp root. This directory never holds assessment evidence;
    # it is removed and verified absent after the Job Object proves the worker
    # tree gone. Cleanup uncertainty is surfaced as CleanupIncomplete.
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $compilerBoundary = [IO.Path]::GetFullPath((Join-Path $temporaryRoot `
        "WINPCInfo-SoftwareInventory-$([Guid]::NewGuid().ToString('N'))"))
    if (-not $compilerBoundary.StartsWith(
        $temporaryRoot, [StringComparison]::OrdinalIgnoreCase
    )) { throw 'The Software Inventory compiler boundary escaped the temp root.' }
    $null = [IO.Directory]::CreateDirectory($compilerBoundary)
    $environment['TEMP'] = $compilerBoundary
    $environment['TMP'] = $compilerBoundary
    $encoded = ConvertTo-SoftwareInventoryEncodedCommand -Source (Get-SoftwareInventoryLiveSource)
    $eventName = "Local\WINPCInfo-SoftwareInventory-$([Guid]::NewGuid().ToString('N'))"
    [bool]$created = $false; $event = $null
    try {
        $event = [Threading.EventWaitHandle]::new(
            $false, [Threading.EventResetMode]::ManualReset, $eventName, [ref]$created
        )
        if (-not $created) { throw 'Event ownership failed.' }
        $native = [WinPCInfo.ProcessSupervisor.NativeRunner]::Run(
            $executable, @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded),
            (Split-Path -Parent $executable), $environment, $activeMilliseconds,
            [int]$collector.resultMaximumUtf8Bytes, 4096,
            [Threading.CancellationToken]::None, $event, 1,
            $terminationMilliseconds, $false
        )
        if ($native.Started -and -not $native.CompleteOwnedTreeAbsent) {
            $exception = [InvalidOperationException]::new(
                'The Software Inventory worker tree could not be proved absent.'
            )
            $exception.Data['ReasonCode'] = 'SOFTWARE.COLLECTOR_CLEANUP_INCOMPLETE'
            throw $exception
        }
        if (-not $native.Started -or
            $native.FailureStage -ne [WinPCInfo.ProcessSupervisor.NativeFailureStage]::None -or
            $native.ExitCode -ne 0 -or $native.StandardOutputExceeded -or
            $native.StandardErrorBytes -ne 0) {
            $reason = Get-NativeSupervisorReasonCode -NativeResult $native
            if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'SOFTWARE.SOURCE_FAILED' }
            return [pscustomobject]@{succeeded=$false;payload=$null;reasonCode=$reason;native=$native;startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow}
        }
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($native.StandardOutput)
        $payload = $json | ConvertFrom-Json -Depth 8 -ErrorAction Stop
        [pscustomobject]@{succeeded=$true;payload=$payload;reasonCode='';native=$native;startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow}
    }
    catch {
        if ($_.Exception.Data['ReasonCode']) { throw }
        [pscustomobject]@{succeeded=$false;payload=$null;reasonCode='SOFTWARE.SOURCE_FAILED';startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow}
    }
    finally {
        if ($null -ne $event) { $event.Dispose() }
        try {
            if ([IO.Directory]::Exists($compilerBoundary)) {
                [IO.Directory]::Delete($compilerBoundary, $true)
            }
        }
        catch {
            $cleanupException = [InvalidOperationException]::new(
                'The Software Inventory compiler boundary could not be removed.',
                $_.Exception
            )
            $cleanupException.Data['ReasonCode'] = 'SOFTWARE.COLLECTOR_CLEANUP_INCOMPLETE'
            throw $cleanupException
        }
        if ([IO.Directory]::Exists($compilerBoundary)) {
            $cleanupException = [InvalidOperationException]::new(
                'The Software Inventory compiler boundary remains after cleanup.'
            )
            $cleanupException.Data['ReasonCode'] = 'SOFTWARE.COLLECTOR_CLEANUP_INCOMPLETE'
            throw $cleanupException
        }
    }
}

function Invoke-SoftwareInventoryCollection {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter()] [string] $ValidationScenario,
        [Parameter()] [switch] $Live,
        [Parameter()] [string] $AssessmentUserSid,
        [Parameter()] [ValidateSet('LocalSystem','Administrator','DifferentStandardUser')] [string] $ProcessContextOverride
    )
    $started = [DateTimeOffset]::UtcNow
    if (-not $Live) {
        if ([string]::IsNullOrWhiteSpace($ValidationScenario)) {
            throw 'A release-owned validation scenario is required.'
        }
        $raw = New-SoftwareInventorySyntheticPayload -Scenario $ValidationScenario -Policy $Policy
        $completed = [DateTimeOffset]::UtcNow
    }
    else {
        if (-not (Test-SoftwareInventorySid $AssessmentUserSid)) {
            $raw = New-SoftwareInventoryGapPayload -Policy $Policy -State Unavailable `
                -ReasonCode 'SOFTWARE.ASSESSMENT_USER_CONTEXT_UNAVAILABLE' `
                -Relationship Unavailable -ObservedContext Unavailable
            $completed = [DateTimeOffset]::UtcNow
        }
        else {
            if ($ProcessContextOverride) {
                $processSid = if ($ProcessContextOverride -eq 'LocalSystem') {'S-1-5-18'}
                    elseif ($ProcessContextOverride -eq 'DifferentStandardUser') {'S-1-5-21-1-2-3-9999'}
                    else {$AssessmentUserSid}
                $isAdministrator = $ProcessContextOverride -in @('LocalSystem','Administrator')
            }
            else {
                $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
                $processSid = [string]$identity.User.Value
                $principal = [Security.Principal.WindowsPrincipal]::new($identity)
                $isAdministrator = $principal.IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator
                )
            }
            $disposition = Get-SoftwareInventoryProcessDisposition `
                -ProcessSid $processSid -AssessmentUserSid $AssessmentUserSid `
                -IsAdministrator $isAdministrator
            if ($null -ne $disposition) {
                $raw = New-SoftwareInventoryGapPayload -Policy $Policy -State Denied `
                    -ReasonCode 'SOFTWARE.ASSESSMENT_USER_CONTEXT_MISMATCH' `
                    -Relationship $disposition.relationship `
                    -ObservedContext $disposition.executionContext
                $completed = [DateTimeOffset]::UtcNow
            }
            else {
                $snapshot = Invoke-BoundedSoftwareInventorySnapshot `
                    -Policy $Policy -AssessmentUserSid $AssessmentUserSid
                $completed = $snapshot.completedAt
                if ($snapshot.succeeded) {
                    $raw = ConvertFrom-SoftwareInventoryAdapterPayload `
                        -Payload $snapshot.payload -Policy $Policy
                }
                else {
                    $state = if ($snapshot.reasonCode -eq 'PROCESS.TIMED_OUT') {'TimedOut'}
                        elseif ($snapshot.reasonCode -eq 'PROCESS.CANCELLED') {'Cancelled'}
                        else {'Failed'}
                    $raw = New-SoftwareInventoryGapPayload -Policy $Policy -State $state `
                        -ReasonCode ([string]$snapshot.reasonCode) -Relationship SameUser `
                        -ObservedContext StandardUser
                }
            }
        }
    }
    $payload = ConvertTo-SoftwareInventoryAttemptPayload -Payload $raw -Policy $Policy
    if (-not (Test-SoftwareInventoryCollectorPayload -Payload $payload -Policy $Policy)) {
        throw 'The Software Inventory collector payload failed its closed contract.'
    }
    [pscustomobject][ordered]@{
        state = if (@($payload.scopeStates | Where-Object state -ne 'Complete').Count) {'CompletedWithGaps'} else {'Completed'}
        reasonCode = if (@($payload.scopeStates | Where-Object state -ne 'Complete').Count) {'SOFTWARE.COLLECTION_GAPS'} else {'SOFTWARE.COLLECTION_COMPLETED'}
        validationFixture = -not $Live
        cleanupVerified = $true
        envelope = [pscustomobject][ordered]@{
            startedAt = $started.ToString('o'); completedAt = $completed.ToString('o'); attempts = 1
            executionContext = if($Live){'StandardUser'}else{'Synthetic'}
        }
        payload = $payload
    }
}

function New-SoftwareInventoryPublicProjection {
    param([Parameter(Mandatory)] $CollectorResult)
    $payload = $CollectorResult.payload
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.software-inventory-validation'
        contractVersion = '1.0.0'
        state = [string]$CollectorResult.state
        completeScopeCount = @($payload.scopeStates | Where-Object state -eq 'Complete').Count
        incompleteScopeCount = @($payload.scopeStates | Where-Object state -ne 'Complete').Count
        registrationCount = @($payload.entries).Count
        registryCount = @($payload.entries | Where-Object sourceKind -eq 'Registry').Count
        msiCount = @($payload.entries | Where-Object sourceKind -eq 'Msi').Count
        msixCount = @($payload.entries | Where-Object sourceKind -eq 'Msix').Count
        softwareIdentitiesPublished = $false
        displayNamesOrPublishersPublished = $false
        pathsOrHashesCollected = $false
        licenseMaterialCollected = $false
        binaryInspectionPerformed = $false
        consistencyActionInvoked = $false
        networkAccessPerformed = $false
        deviceStateChanged = $false
    }
}

function Add-SoftwareInventoryEvidenceRecord {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$CollectorResult,[Parameter(Mandatory)]$Policy)
    if([string]$Record.run.evidenceProfileId -ne 'profile:device-firmware-identity-administrator-policy-resource-and-network-readiness'){
        throw 'Software Inventory evidence requires the accepted network-ready evidence profile.'
    }
    if(@($Record.findings|Where-Object ruleId -in @($Policy.rules.ruleId)).Count -ne 0){
        throw 'Software Inventory source evidence cannot be added after its Rule Evaluations.'
    }
    if(-not [bool]$CollectorResult.cleanupVerified -or
        -not (Test-SoftwareInventoryCollectorPayload -Payload $CollectorResult.payload -Policy $Policy)){
        throw 'Software Inventory evidence requires a closed, cleanup-verified collector result.'
    }
    $runId=[string]$Record.run.runId;$payload=$CollectorResult.payload;$collector=$Policy.collector
    $collectedAt=[string]$CollectorResult.envelope.completedAt;$context=[string]$CollectorResult.envelope.executionContext
    $observations=[Collections.Generic.List[object]]::new();$provenance=[Collections.Generic.List[object]]::new()
    $subjects=[Collections.Generic.List[object]]::new();$envelopeSubjects=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $null=$envelopeSubjects.Add('subject:device:primary');$null=$envelopeSubjects.Add('subject:assessment-user:primary')
    $scopeObservationIds=@{};foreach($scope in $Policy.scopes){$scopeObservationIds[[string]$scope.scopeId]=[Collections.Generic.List[string]]::new()}
    $scopeStateById=@{};foreach($state in $payload.scopeStates){$scopeStateById[[string]$state.scopeId]=[string]$state.state}
    $scopeById=@{};foreach($scope in $Policy.scopes){$scopeById[[string]$scope.scopeId]=$scope}
    function Add-SoftwareObservation {
        param([string]$ScopeId,[string]$Suffix,[string]$FieldId,[string]$SubjectId,$Value,[string]$ValueState='ObservedValue')
        $observationId="observation:software-$Suffix`:$runId";$provenanceId="provenance:software-$Suffix`:$runId"
        $entry=[ordered]@{observationId=$observationId;fieldId=$FieldId;subjectId=$SubjectId;provenanceId=$provenanceId;valueState=$ValueState}
        if($ValueState -eq 'ObservedValue'){$entry.value=$Value}
        $observations.Add([pscustomobject]$entry)
        $sourceId=[string]$scopeById[$ScopeId].sourceId
        $provenance.Add([pscustomobject][ordered]@{provenanceId=$provenanceId;fieldId=$FieldId;subjectId=$SubjectId;sourceId=$sourceId;collectorId=[string]$collector.collectorId;collectorVersion=[string]$collector.collectorVersion;executionContext=$context;collectedAt=$collectedAt;sourceLocale=[string]$payload.sourceLocale})
        $scopeObservationIds[$ScopeId].Add($observationId);$null=$envelopeSubjects.Add($SubjectId)
    }
    function Add-SoftwareValue {
        param([string]$ScopeId,[string]$Suffix,[string]$FieldId,[string]$SubjectId,$Value)
        if($null -eq $Value){Add-SoftwareObservation $ScopeId $Suffix $FieldId $SubjectId $null 'SourceReportedUnknown'}
        else{Add-SoftwareObservation $ScopeId $Suffix $FieldId $SubjectId $Value}
    }
    $fieldBySource=@{
        Registry=[ordered]@{registrationId='field:software.registry.registration-id';displayName='field:software.registry.display-name';version='field:software.registry.version';publisher='field:software.registry.publisher';registrationContext='field:software.registry.registration-context';registryView='field:software.registry.registry-view';installerState='field:software.registry.installer-state';packageType='field:software.registry.package-type'}
        Msi=[ordered]@{productCode='field:software.msi.product-code';displayName='field:software.msi.display-name';version='field:software.msi.version';publisher='field:software.msi.publisher';registrationContext='field:software.msi.registration-context';installerState='field:software.msi.installer-state';packageType='field:software.msi.package-type'}
        Msix=[ordered]@{packageFamilyName='field:software.msix.package-family-name';packageFullName='field:software.msix.package-full-name';displayName='field:software.msix.display-name';version='field:software.msix.version';publisherId='field:software.msix.publisher-id';registrationContext='field:software.msix.registration-context';installerState='field:software.msix.installer-state';packageType='field:software.msix.package-type';architecture='field:software.msix.architecture'}
    }
    $index=0
    foreach($software in @($payload.entries)){
        $scopeId=[string]$software.scopeId
        if($scopeStateById[$scopeId] -notin @('Complete','Partial')){continue}
        $subjectId="subject:software:$index";$subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='Application'})
        $fieldByProperty=$fieldBySource[[string]$software.sourceKind]
        foreach($property in $fieldByProperty.Keys){
            $fieldId=[string]$fieldByProperty[$property]
            if($fieldId -in @($scopeById[$scopeId].fieldIds)){
                Add-SoftwareValue $scopeId "$index-$property" $fieldId $subjectId $software.$property
            }
        }
        $index++
    }
    foreach($scope in $Policy.scopes){
        $scopeId=[string]$scope.scopeId
        if($scopeStateById[$scopeId] -eq 'Complete' -and $scopeObservationIds[$scopeId].Count -eq 0){
            $subjectId=if($scopeId -like '*.assessment-user*'){'subject:assessment-user:primary'}else{'subject:device:primary'}
            $fieldIndex=0;foreach($fieldId in $scope.fieldIds){
                $scopeSuffix=$scopeId.Substring('scope:software.'.Length).Replace('.','-')
                Add-SoftwareObservation $scopeId "absent-$scopeSuffix-$fieldIndex" ([string]$fieldId) $subjectId $null 'ObservedAbsent';$fieldIndex++
            }
        }
    }
    $coverage=[Collections.Generic.List[object]]::new();$diagnostics=[Collections.Generic.List[object]]::new()
    foreach($scopeState in $payload.scopeStates){
        $scopeId=[string]$scopeState.scopeId;$suffix=$scopeId.Substring('scope:software.'.Length).Replace('.','-')
        $coverageId="coverage:software-$suffix`:$runId";$coverageEntry=[ordered]@{coverageId=$coverageId;scopeId=$scopeId;state=[string]$scopeState.state;observationIds=@($scopeObservationIds[$scopeId]);diagnosticIds=@()}
        if($scopeState.state -ne 'Complete'){
            $diagnosticId="diagnostic:software-$suffix`:$runId";$coverageEntry.reasonCode=[string]$scopeState.reasonCode;$coverageEntry.diagnosticIds=@($diagnosticId)
            $diagnostics.Add([pscustomobject][ordered]@{diagnosticId=$diagnosticId;scopeId=$scopeId;phase='Collection';reasonCode=[string]$scopeState.reasonCode;operatorMessageId='software-inventory.collection.incomplete'})
        }
        $coverage.Add([pscustomobject]$coverageEntry)
    }
    $Record.subjects=@($Record.subjects)+@($subjects);$Record.observations=@($Record.observations)+@($observations)
    $Record.provenance=@($Record.provenance)+@($provenance);$Record.coverage=@($Record.coverage)+@($coverage)
    $Record.diagnostics=@($Record.diagnostics)+@($diagnostics)
    $Record.collectorResults=@($Record.collectorResults)+[pscustomobject][ordered]@{envelopeId="envelope:software-inventory:$runId";collectorId=[string]$collector.collectorId;collectorVersion=[string]$collector.collectorVersion;operationId=[string]$collector.operationId;intendedScopeIds=@($Policy.scopes.scopeId);subjectIds=@($envelopeSubjects);startedAt=[string]$CollectorResult.envelope.startedAt;completedAt=$collectedAt;executionContext=$context;attempts=1;observationIds=@($observations|ForEach-Object observationId);coverageIds=@($coverage|ForEach-Object coverageId);diagnosticIds=@($diagnostics|ForEach-Object diagnosticId)}
    $Record.run.evidenceProfileId=[string]$Policy.evidenceProfileId
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne Complete).Count -eq 0){'Completed'}else{'CompletedWithGaps'}
    $Record
}

function Invoke-SoftwareInventoryRule {
    param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)][int]$InputObservationCount,[Parameter(Mandatory)][scriptblock]$Evaluation)
    $watch=[Diagnostics.Stopwatch]::StartNew();$results=@(& $Evaluation);$watch.Stop()
    if($InputObservationCount -gt [int]$Rule.maximumInputObservations -or $watch.ElapsedMilliseconds -gt [int]$Rule.deadlineMilliseconds -or $results.Count -ne 1 -or [string]$results[0].outcome -notin @('NeedsAttention','Informational','Indeterminate')){throw "The release-owned $($Rule.operationId) rule violated its finite result contract."}
    $results[0]
}

function Complete-ValidatedSoftwareInventoryAssessmentRecord {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$Policy,[Parameter(Mandatory)]$ContractValidation)
    if(-not [bool]$ContractValidation.accepted -or $ContractValidation.reasonCode -ne 'CONTRACT.ACCEPTED' -or [string]$Record.run.evidenceProfileId -ne [string]$Policy.evidenceProfileId -or @($Record.findings|Where-Object ruleId -in @($Policy.rules.ruleId)).Count -ne 0){throw 'Software Inventory rules require an accepted source-only combined record.'}
    $rules=@{};foreach($rule in $Policy.rules){$rules[[string]$rule.findingKind]=$rule}
    $machineScopes=@($Policy.scopes|Where-Object {$_.scopeId -like '*.machine*'}|ForEach-Object scopeId)
    $userScopes=@($Policy.scopes|Where-Object {$_.scopeId -like '*.assessment-user*'}|ForEach-Object scopeId)
    $machineCoverage=@($Record.coverage|Where-Object scopeId -in $machineScopes);$userCoverage=@($Record.coverage|Where-Object scopeId -in $userScopes)
    $softwareObservations=@($Record.observations|Where-Object fieldId -like 'field:software.*')
    $machineObservationIds=@($machineCoverage|ForEach-Object {@($_.observationIds)})
    $userObservationIds=@($userCoverage|ForEach-Object {@($_.observationIds)})
    $machineObservations=@($softwareObservations|Where-Object {$_.observationId -in $machineObservationIds})
    $userObservations=@($softwareObservations|Where-Object {$_.observationId -in $userObservationIds})
    $machineResult=Invoke-SoftwareInventoryRule $rules['machine-software-inventory'] $machineObservations.Count {if(@($machineCoverage|Where-Object state -ne Complete).Count){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.MACHINE_SOFTWARE_EVIDENCE_INCOMPLETE'}}elseif(@($machineObservations|Where-Object valueState -eq ObservedValue).Count){[pscustomobject]@{outcome='NeedsAttention'}}else{[pscustomobject]@{outcome='Informational'}}}
    $userResult=Invoke-SoftwareInventoryRule $rules['assessment-user-software-inventory'] $userObservations.Count {if(@($userCoverage|Where-Object state -ne Complete).Count){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.USER_SOFTWARE_EVIDENCE_INCOMPLETE'}}elseif(@($userObservations|Where-Object valueState -eq ObservedValue).Count){[pscustomobject]@{outcome='NeedsAttention'}}else{[pscustomobject]@{outcome='Informational'}}}
    $coverageResult=Invoke-SoftwareInventoryRule $rules['software-inventory-coverage'] $softwareObservations.Count {if(@($Record.coverage|Where-Object {$_.scopeId -in @($Policy.scopes.scopeId) -and $_.state -ne 'Complete'}).Count -gt 0){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.SOFTWARE_EVIDENCE_INCOMPLETE'}}else{[pscustomobject]@{outcome='Informational'}}}
    foreach($definition in @(@{kind='machine-software-inventory';target='subject:device:primary';result=$machineResult;observations=$machineObservations},@{kind='assessment-user-software-inventory';target='subject:assessment-user:primary';result=$userResult;observations=$userObservations},@{kind='software-inventory-coverage';target='subject:device:primary';result=$coverageResult;observations=$softwareObservations})){
        $rule=$rules[$definition.kind];$findingId="finding:$($definition.kind):$($Record.run.runId)";$finding=[ordered]@{findingId=$findingId;ruleId=[string]$rule.ruleId;targetSubjectId=[string]$definition.target;outcome=[string]$definition.result.outcome;evidenceReferences=@($definition.observations|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})}
        if($definition.result.PSObject.Properties['reasonCode']){$finding.reasonCode=[string]$definition.result.reasonCode};$Record.findings=@($Record.findings)+[pscustomobject]$finding
        if($definition.kind -ne 'software-inventory-coverage' -and $definition.result.outcome -in @('NeedsAttention','Indeterminate')){$recommendation=@($Policy.recommendations|Where-Object findingKind -eq $definition.kind)[0];$Record.recommendations=@($Record.recommendations)+[pscustomobject][ordered]@{recommendationId="recommendation:$($definition.kind):$($Record.run.runId)";definitionId=[string]$recommendation.definitionId;kind='AssessmentRecommendation';findingIds=@($findingId)}}
    }
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne Complete).Count -eq 0){'Completed'}else{'CompletedWithGaps'};$Record
}
