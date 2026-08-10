[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Guided', 'Automation')]
    [string] $Mode = 'Guided',

    [Parameter()]
    [string] $RequestPath,

    # Automation approval is deliberately separate from the versioned request.
    # Its absence is an explicit decline and can never be inferred from fields
    # that were supplied before the Preparation Summary was produced.
    [Parameter()]
    [switch] $AcceptPreparation,

    # This validation-only input exercises the generated artifact against
    # synthetic host descriptions. It never authorizes collection, even when
    # the described runtime is eligible.
    [Parameter(DontShow)]
    [string] $RuntimeFixturePath,

    # Synthetic validation facts can force fail-closed preparation paths but
    # cannot add scope, authority, network access, or permission to collect.
    [Parameter(DontShow)]
    [string] $PreparationFixturePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
