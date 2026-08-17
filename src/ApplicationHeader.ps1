[CmdletBinding()]
param(
    # Help and About are intentional discovery surfaces, not assessment steps.
    # The threat is turning every run into a feedback or telemetry prompt. The
    # mechanism is a closed Workflow set: those routes are emitted only when
    # the operator passes Help or About. The trust assumption is that opening
    # Help is a deliberate local choice. Safe failure is to keep Assessment
    # silent about repository and reporting routes.
    [Parameter()]
    [ValidateSet('Assessment', 'RecipientProfileSetup', 'RestrictedReportExport', 'Help', 'About')]
    [string] $Workflow = 'Assessment',

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

    # Guided assessment selection requires both the local public profile path
    # and the fingerprint confirmed through the operator's trusted relationship.
    # Supplying neither chooses zero recipients; supplying only one fails closed.
    [Parameter()]
    [string] $AssessmentRecipientProfilePath,

    [Parameter()]
    [string] $AssessmentRecipientFingerprintConfirmation,

    # Recipient setup is a separate, deliberate consultant workflow. The
    # confirmation switch is never inferred from assessment approval. A trusted
    # release creates one persistent non-exportable Current User identity only
    # when all three setup inputs are supplied together.
    [Parameter()]
    [string] $RecipientProfileOutputPath,

    [Parameter()]
    [string] $RecipientLabel,

    [Parameter()]
    [switch] $ConfirmRecipientSetup,

    # Restricted Report Export is also separate from an Assessment Run. It can
    # open one completed package and write one warned HTML artifact; no argument
    # can request another inner artifact, upload, retention, or background work.
    [Parameter()]
    [string] $ProtectedPackagePath,

    [Parameter()]
    [string] $RestrictedReportOutputPath,

    [Parameter()]
    [string] $RestrictedReportWarningAcknowledgment,

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
    [string] $ProtectedPackageFixturePath,

    # A sharing fixture selects one release-owned recipient/profile/export
    # scenario. It cannot supply a certificate, key, fingerprint, profile,
    # package, report, path, warning text, or persistent Windows identity.
    [Parameter(DontShow)]
    [string] $RecipientSharingFixturePath,

    # A Device Readiness fixture selects one release-owned adapter scenario.
    # It cannot provide device evidence, a query, command, path, or authority.
    [Parameter(DontShow)]
    [string] $DeviceReadinessFixturePath,

    # An Identity and Enrollment fixture selects one release-owned source and
    # process-context scenario. It cannot supply an identifier, account, tenant,
    # domain, device, command, source path, credential, or collection authority.
    [Parameter(DontShow)]
    [string] $IdentityEnrollmentFixturePath,

    # A Local Administrator Exposure fixture selects one release-owned SID and
    # context scenario. It cannot provide a group name, SID, account, member,
    # credential, command, path, collector, or authority.
    [Parameter(DontShow)]
    [string] $AdministratorExposureFixturePath,

    # An Effective Policy fixture selects one release-owned policy-source
    # scenario. It cannot provide policy identifiers, links, settings, SIDs,
    # registry values, commands, source paths, credentials, or authority.
    [Parameter(DontShow)]
    [string] $EffectivePolicyFixturePath,

    # A Resource Dependencies fixture selects one release-owned user-resource
    # and peripheral scenario. It cannot supply a resource, endpoint, device,
    # driver, credential, command, source path, or collection authority.
    [Parameter(DontShow)]
    [string] $ResourceDependenciesFixturePath,

    # A Network Topology fixture selects one release-owned local source shape.
    # It cannot provide an address, adapter, route, resolver, proxy, component,
    # connection, command, network permission, or collection authority.
    [Parameter(DontShow)]
    [string] $NetworkTopologyFixturePath,

    # Internal release-validation seam. The fixture contains only a scenario
    # name; software identities remain inside the protected package.
    [Parameter(DontShow)]
    [string] $SoftwareInventoryFixturePath,

    # Internal release-validation seam. The fixture selects one frozen
    # certificate scenario; it cannot carry a certificate, fingerprint, key,
    # password, store path, trust change, command, or collection authority.
    [Parameter(DontShow)]
    [string] $CertificateTrustFixturePath,

    # Internal release-validation seam. The fixture selects only one frozen
    # connectivity scenario and cannot supply a host, request, or credential.
    [Parameter(DontShow)]
    [string] $MicrosoftConnectivityFixturePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
