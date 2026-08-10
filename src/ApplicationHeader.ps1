[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Guided', 'Automation')]
    [string] $Mode = 'Guided',

    [Parameter()]
    [string] $RequestPath,

    # This validation-only input exercises the generated artifact against
    # synthetic host descriptions. It never authorizes collection, even when
    # the described runtime is eligible.
    [Parameter(DontShow)]
    [string] $RuntimeFixturePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
