function Test-Utf8RuntimeBehavior {
    try {
        # Evidence will eventually cross JSON and package boundaries. A strict
        # decoder prevents malformed byte sequences from being silently replaced
        # with U+FFFD, which could change identifiers or conceal forbidden data.
        $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $sample = 'WIN-PCInfo: Español 日本語 العربية'
        $roundTrip = $strictUtf8.GetString($strictUtf8.GetBytes($sample))
        if ($roundTrip -ne $sample) { return $false }

        # Validate the .NET JSON path used by the contract boundary rather than
        # proving only a private encoder instance. JsonDocument preserves the
        # Unicode scalar values without relying on localized display text.
        $json = [System.Text.Json.JsonSerializer]::Serialize($sample, [string])
        $document = [System.Text.Json.JsonDocument]::Parse($json)
        try {
            if ($document.RootElement.GetString() -ne $sample) { return $false }
        }
        finally {
            $document.Dispose()
        }
        if ([System.Console]::OutputEncoding.CodePage -ne 65001) { return $false }

        try {
            $null = $strictUtf8.GetString([byte[]] @(0xC3, 0x28))
            return $false
        }
        catch {
            if ($_.Exception.InnerException -is [System.Text.DecoderFallbackException]) {
                return $true
            }
            return $false
        }
    }
    catch {
        return $false
    }
}

function Test-CryptographyRuntimeBehavior {
    try {
        # The check uses only fixed synthetic bytes. AES-GCM availability is a
        # safety prerequisite for a later package slice; this check creates no
        # key material that could protect real evidence and persists nothing.
        $shaInput = [System.Text.Encoding]::ASCII.GetBytes('abc')
        $shaActual = [System.Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($shaInput)
        ).ToLowerInvariant()
        if ($shaActual -ne 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') {
            return $false
        }

        $key = [byte[]] (0..31)
        $nonce = [byte[]] (0..11)
        $plainText = [System.Text.Encoding]::UTF8.GetBytes('WIN-PCInfo synthetic probe')
        $cipherText = [byte[]]::new($plainText.Length)
        $tag = [byte[]]::new(16)
        $recovered = [byte[]]::new($plainText.Length)
        $aes = [System.Security.Cryptography.AesGcm]::new($key, 16)
        try {
            $aes.Encrypt($nonce, $plainText, $cipherText, $tag)
            $aes.Decrypt($nonce, $cipherText, $tag, $recovered)
        }
        finally {
            $aes.Dispose()
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($key)
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($plainText)
        }

        $expected = [System.Text.Encoding]::UTF8.GetBytes('WIN-PCInfo synthetic probe')
        return [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($recovered, $expected)
    }
    catch {
        return $false
    }
}

function Get-BuiltInModuleCompatibilityFacts {
    try {
        # A profile or PSModulePath entry could shadow a required command with
        # attacker-controlled code. Load only the literal manifests in PSHOME,
        # verify their Authenticode signatures through the literal built-in
        # Security module, and inspect the commands exported by those exact
        # module objects. Trust is limited to Windows Authenticode validation and
        # the installed PowerShell distribution; any ambiguity fails closed.
        $moduleRoot = [System.IO.Path]::GetFullPath((Join-Path $PSHOME 'Modules'))
        $manifests = [ordered]@{
            'Microsoft.PowerShell.Security' = Join-Path $moduleRoot 'Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1'
            'Microsoft.PowerShell.Utility' = Join-Path $moduleRoot 'Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1'
            'Microsoft.PowerShell.Management' = Join-Path $moduleRoot 'Microsoft.PowerShell.Management/Microsoft.PowerShell.Management.psd1'
        }

        $modules = [ordered]@{}
        foreach ($moduleName in $manifests.Keys) {
            $module = Import-Module -Name $manifests[$moduleName] -PassThru -Force -ErrorAction Stop
            $resolvedManifest = [System.IO.Path]::GetFullPath($manifests[$moduleName])
            if ($module.Name -ne $moduleName -or [System.IO.Path]::GetFullPath($module.Path) -ne $resolvedManifest) {
                throw "Built-in module identity mismatch: $moduleName"
            }
            $modules[$moduleName] = $module
        }

        $signatureCommand = $modules['Microsoft.PowerShell.Security'].ExportedCommands['Get-AuthenticodeSignature']
        if ($null -eq $signatureCommand -or $signatureCommand.CommandType -ne 'Cmdlet') {
            throw 'The trusted Authenticode command is unavailable.'
        }
        foreach ($manifestPath in $manifests.Values) {
            $signature = & $signatureCommand -LiteralPath $manifestPath -ErrorAction Stop
            if ([string] $signature.Status -ne 'Valid' -or
                $null -eq $signature.SignerCertificate -or
                $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') {
                throw "Built-in module signature is not valid: $manifestPath"
            }
        }

        $requiredExports = [ordered]@{
            'Microsoft.PowerShell.Utility' = @('ConvertFrom-Json', 'ConvertTo-Json', 'Test-Json')
            'Microsoft.PowerShell.Management' = @('Start-Process', 'Stop-Process', 'Wait-Process')
        }
        foreach ($moduleName in $requiredExports.Keys) {
            foreach ($commandName in $requiredExports[$moduleName]) {
                $command = $modules[$moduleName].ExportedCommands[$commandName]
                if ($null -eq $command -or $command.CommandType -ne 'Cmdlet' -or $command.ModuleName -ne $moduleName) {
                    throw "Required built-in command identity mismatch: $moduleName\$commandName"
                }
            }
        }

        $coreCommandsAvailable = $true
        foreach ($commandName in @('Get-Command', 'Import-Module')) {
            $command = $ExecutionContext.InvokeCommand.GetCommand(
                $commandName,
                [System.Management.Automation.CommandTypes]::Cmdlet
            )
            if ($null -eq $command -or $command.Source -ne 'Microsoft.PowerShell.Core') {
                $coreCommandsAvailable = $false
            }
        }

        return [pscustomobject]@{
            requiredCommands = $coreCommandsAvailable
            validatorProvenance = $true
            moduleLoading = $true
        }
    }
    catch {
        return [pscustomobject]@{
            requiredCommands = $false
            validatorProvenance = $false
            moduleLoading = $false
        }
    }
}

function Test-ProcessControlBehavior {
    $process = $null
    $terminationProcess = $null
    try {
        # Later collectors may launch approved Windows tools. The coordinator
        # must be able to pass literal arguments, observe a real exit code, bound
        # the wait, and terminate the child tree. If any guarantee is missing,
        # eligibility fails before collection instead of accepting orphan risk.
        $executable = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $executable
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 17')) {
            $null = $startInfo.ArgumentList.Add($argument)
        }

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { return $false }
        if (-not $process.WaitForExit(5000)) {
            $process.Kill($true)
            $process.WaitForExit()
            return $false
        }
        if ($process.ExitCode -ne 17) { return $false }

        $terminationStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $terminationStartInfo.FileName = $executable
        $terminationStartInfo.UseShellExecute = $false
        $terminationStartInfo.RedirectStandardOutput = $true
        $terminationStartInfo.RedirectStandardError = $true
        foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
            '[System.Threading.Thread]::Sleep(30000)'
        )) {
            $null = $terminationStartInfo.ArgumentList.Add($argument)
        }
        $terminationProcess = [System.Diagnostics.Process]::new()
        $terminationProcess.StartInfo = $terminationStartInfo
        if (-not $terminationProcess.Start()) { return $false }
        if ($terminationProcess.WaitForExit(200)) { return $false }
        $terminationProcess.Kill($true)
        return $terminationProcess.WaitForExit(5000) -and $terminationProcess.HasExited
    }
    catch {
        if ($null -ne $process -and -not $process.HasExited) {
            try { $process.Kill(); $process.WaitForExit() } catch { }
        }
        if ($null -ne $terminationProcess -and -not $terminationProcess.HasExited) {
            try { $terminationProcess.Kill(); $terminationProcess.WaitForExit() } catch { }
        }
        return $false
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
        if ($null -ne $terminationProcess) { $terminationProcess.Dispose() }
    }
}

function Get-RuntimeCompatibilityPolicy {
    # This exact policy implements the governing decision that any stable 7.x
    # host at or above 7.6 may attempt compatibility checks. Eligibility is not
    # a support claim; release evidence separately records exact tested patches.
    [pscustomobject][ordered]@{
        policyId = 'win-pcinfo.runtime-compatibility/1.0.0'
        edition = 'Core'
        stableOnly = $true
        minimumVersion = [version] '7.6.0'
        maximumVersionExclusive = [version] '8.0.0'
        architectures = @('X64', 'X86', 'Arm64')
    }
}

function Get-ActiveRuntimeFacts {
    $version = $PSVersionTable.PSVersion
    $facts = [ordered]@{
        hostPresent = $true
        psEdition = [string] $PSVersionTable.PSEdition
        version = [string] $version
        prereleaseLabel = if ($version.PSObject.Properties['PreReleaseLabel']) { [string] $version.PreReleaseLabel } else { $null }
        architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        requiredCommands = $false
        validatorProvenance = $false
        encoding = $false
        cryptography = $false
        moduleLoading = $false
        processControl = $false
    }

    $policy = Get-RuntimeCompatibilityPolicy
    $isStable = [string]::IsNullOrEmpty([string] $facts.prereleaseLabel) -and $facts.version -notmatch '-'
    try { $parsedVersion = [version] $facts.version } catch { $parsedVersion = $null }
    if ($facts.psEdition -ne $policy.edition -or -not $isStable -or $null -eq $parsedVersion -or
        $parsedVersion -lt $policy.minimumVersion -or $parsedVersion -ge $policy.maximumVersionExclusive -or
        $facts.architecture -notin $policy.architectures) {
        return [pscustomobject] $facts
    }

    $moduleFacts = Get-BuiltInModuleCompatibilityFacts
    $facts.requiredCommands = $moduleFacts.requiredCommands
    $facts.validatorProvenance = $moduleFacts.validatorProvenance
    $facts.moduleLoading = $moduleFacts.moduleLoading
    $facts.encoding = Test-Utf8RuntimeBehavior
    $facts.cryptography = Test-CryptographyRuntimeBehavior
    $facts.processControl = Test-ProcessControlBehavior
    [pscustomobject] $facts
}

function Read-RuntimeFixture {
    param([Parameter(Mandatory)] [string] $LiteralPath)

    $fixtureText = [System.IO.File]::ReadAllText(
        [System.IO.Path]::GetFullPath($LiteralPath),
        [System.Text.UTF8Encoding]::new($false, $true)
    )
    $fixtureText | ConvertFrom-Json
}

function Test-RuntimeCompatibility {
    param([Parameter(Mandatory)] $Facts)

    $policy = Get-RuntimeCompatibilityPolicy

    $reasonCode = if (-not $Facts.hostPresent) {
        'RUNTIME.HOST_MISSING'
    }
    elseif ($Facts.psEdition -ne $policy.edition) {
        'RUNTIME.EDITION_UNSUPPORTED'
    }
    elseif (-not [string]::IsNullOrEmpty([string] $Facts.prereleaseLabel) -or [string] $Facts.version -match '-') {
        'RUNTIME.PRERELEASE_UNSUPPORTED'
    }
    else {
        try { $parsedVersion = [version] ([string] $Facts.version) }
        catch { $parsedVersion = $null }

        if ($null -eq $parsedVersion) { 'RUNTIME.VERSION_INVALID' }
        elseif ($parsedVersion -ge $policy.maximumVersionExclusive -or $parsedVersion.Major -ne 7) { 'RUNTIME.MAJOR_UNSUPPORTED' }
        elseif ($parsedVersion -lt $policy.minimumVersion) { 'RUNTIME.VERSION_TOO_OLD' }
        elseif ([string] $Facts.architecture -notin $policy.architectures) { 'RUNTIME.ARCHITECTURE_UNSUPPORTED' }
        elseif (-not $Facts.requiredCommands) { 'RUNTIME.REQUIRED_COMMAND_MISSING' }
        elseif (-not $Facts.validatorProvenance) { 'RUNTIME.VALIDATOR_PROVENANCE_INVALID' }
        elseif (-not $Facts.encoding) { 'RUNTIME.ENCODING_INCOMPATIBLE' }
        elseif (-not $Facts.cryptography) { 'RUNTIME.CRYPTOGRAPHY_INCOMPATIBLE' }
        elseif (-not $Facts.moduleLoading) { 'RUNTIME.MODULE_LOADING_INCOMPATIBLE' }
        elseif (-not $Facts.processControl) { 'RUNTIME.PROCESS_CONTROL_INCOMPATIBLE' }
        else { 'RUNTIME.ELIGIBLE' }
    }

    [pscustomobject][ordered]@{
        Eligible = $reasonCode -eq 'RUNTIME.ELIGIBLE'
        ReasonCode = $reasonCode
        PolicyId = $policy.policyId
    }
}
