function Test-Utf8RuntimeBehavior {
    try {
        # Evidence will eventually cross JSON and package boundaries. A strict
        # decoder prevents malformed byte sequences from being silently replaced
        # with U+FFFD, which could change identifiers or conceal forbidden data.
        $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $sample = 'WIN-PCInfo: Español 日本語 العربية'
        $roundTrip = $strictUtf8.GetString($strictUtf8.GetBytes($sample))
        if ($roundTrip -ne $sample) { return $false }

        try {
            $null = $strictUtf8.GetString([byte[]] @(0xC3, 0x28))
            return $false
        }
        catch [System.Text.DecoderFallbackException] {
            return $true
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

function Test-ValidatorProvenance {
    try {
        # A profile or module-path shadow could replace Test-Json with attacker
        # code. Resolve the module-qualified cmdlet and require its signed-in-box
        # module location under the active runtime's literal PSHOME tree.
        $validator = Get-Command 'Microsoft.PowerShell.Utility\Test-Json' -CommandType Cmdlet -ErrorAction Stop
        $moduleRoot = [System.IO.Path]::GetFullPath((Join-Path $PSHOME 'Modules'))
        $modulePath = [System.IO.Path]::GetFullPath($validator.Module.Path)
        return $validator.Source -eq 'Microsoft.PowerShell.Utility' -and
            $modulePath.StartsWith($moduleRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Test-LiteralModuleLoading {
    try {
        # Floating PSModulePath discovery is not a trust decision. Importing the
        # exact built-in manifest proves that future modules can be loaded from a
        # verified literal path and fail closed when that path is unavailable.
        $manifestPath = Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1'
        $module = Import-Module -Name $manifestPath -PassThru -ErrorAction Stop
        return [System.IO.Path]::GetFullPath($module.Path) -eq [System.IO.Path]::GetFullPath($manifestPath)
    }
    catch {
        return $false
    }
}

function Test-ProcessControlBehavior {
    $process = $null
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
        return $process.ExitCode -eq 17
    }
    catch {
        if ($null -ne $process -and -not $process.HasExited) {
            try { $process.Kill($true); $process.WaitForExit() } catch { }
        }
        return $false
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Get-ActiveRuntimeFacts {
    $requiredCommandNames = @(
        'ConvertFrom-Json', 'ConvertTo-Json', 'Get-Command', 'Import-Module',
        'Start-Process', 'Stop-Process', 'Wait-Process', 'Test-Json'
    )
    $commandsAvailable = $true
    foreach ($commandName in $requiredCommandNames) {
        if ($null -eq (Get-Command $commandName -CommandType Cmdlet -ErrorAction SilentlyContinue)) {
            $commandsAvailable = $false
            break
        }
    }

    $version = $PSVersionTable.PSVersion
    [pscustomobject][ordered]@{
        hostPresent = $true
        psEdition = [string] $PSVersionTable.PSEdition
        version = [string] $version
        prereleaseLabel = if ($version.PSObject.Properties['PreReleaseLabel']) { [string] $version.PreReleaseLabel } else { $null }
        architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        requiredCommands = $commandsAvailable
        validatorProvenance = Test-ValidatorProvenance
        encoding = Test-Utf8RuntimeBehavior
        cryptography = Test-CryptographyRuntimeBehavior
        moduleLoading = Test-LiteralModuleLoading
        processControl = Test-ProcessControlBehavior
    }
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

    $reasonCode = if (-not $Facts.hostPresent) {
        'RUNTIME.HOST_MISSING'
    }
    elseif ($Facts.psEdition -ne 'Core') {
        'RUNTIME.EDITION_UNSUPPORTED'
    }
    elseif (-not [string]::IsNullOrEmpty([string] $Facts.prereleaseLabel) -or [string] $Facts.version -match '-') {
        'RUNTIME.PRERELEASE_UNSUPPORTED'
    }
    else {
        try { $parsedVersion = [version] ([string] $Facts.version) }
        catch { $parsedVersion = $null }

        if ($null -eq $parsedVersion) { 'RUNTIME.VERSION_INVALID' }
        elseif ($parsedVersion.Major -ne 7) { 'RUNTIME.MAJOR_UNSUPPORTED' }
        elseif ($parsedVersion -lt [version] '7.6.0') { 'RUNTIME.VERSION_TOO_OLD' }
        elseif ([string] $Facts.architecture -notin @('X64', 'X86', 'Arm64')) { 'RUNTIME.ARCHITECTURE_UNSUPPORTED' }
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
    }
}
