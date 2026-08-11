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
    [string] $PreparationFixturePath,

    # This input is reserved for synthetic contract conformance fixtures. Its
    # presence marks the invocation validation-only and can never authorize a
    # collector, real Assessment Record, or Product Capability claim.
    [Parameter(DontShow)]
    [string] $ContractFixturePath,

    # A release-owned synthetic lifecycle scenario may exercise the approved
    # synthetic collector, but it cannot select commands, paths, device evidence,
    # or a production package finalizer. The terminal remains visibly fixture-only.
    [Parameter(DontShow)]
    [string] $RunFixturePath,

    # Release-owned scenarios exercise the immutable Privileged Collection Plan
    # without displaying a real UAC prompt. A fixture can only reduce trust or
    # select one published synthetic fault; it cannot provide worker content,
    # operations, executable paths, identities, or evidence.
    [Parameter(DontShow)]
    [string] $PrivilegedCollectionFixturePath,

    # The generated artifact accepts only one release-owned SYSTEM validation
    # scenario name. It cannot provide an operation, parameter, executable,
    # script, command, identity, credential, evidence value, or task name.
    [Parameter(DontShow)]
    [string] $SystemCollectionFixturePath,

    # A release-owned workspace/recovery scenario may select one synthetic
    # fault only. It cannot supply a destination, cleanup target, identity,
    # journal field, evidence value, process, command, or Windows Feature.
    [Parameter(DontShow)]
    [string] $EvidenceWorkspaceFixturePath,

    # A package fixture selects one release-owned cryptographic or viewing
    # scenario. It cannot supply plaintext, keys, identities, paths, or metadata.
    [Parameter(DontShow)]
    [string] $ProtectedPackageFixturePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
