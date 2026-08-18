[CmdletBinding()]
param(
    # Help and About are intentional discovery surfaces, not assessment steps.
    # The threat is turning every run into a feedback or telemetry prompt. The
    # mechanism is a closed Workflow set: those routes are emitted only when
    # the operator passes Help or About. The trust assumption is that opening
    # Help is a deliberate local choice. Safe failure is to keep Assessment
    # silent about repository and reporting routes.
    [Parameter()]
    # Verify is first-run package authentication. The threat is treating an
    # adjacent schema or helper as trusted because it sits next to the
    # application. The mechanism is the embedded governing-resource table.
    # The trust assumption is that those bytes came from the deterministic
    # build. Safe failure is NotStarted with no integrity override.
    # VerifyAttestation is the governed unsigned Preview fallback check.
    # The threat is treating checksums as Authenticode, or selecting the
    # fallback for convenience. The mechanism is an exact-candidate
    # attestation that cannot claim Trusted, signed, or Supported. The
    # trust assumption is SHA-256 binding of the reviewed portable
    # candidate, not Windows Authenticode. Safe failure is NotStarted
    # with a typed attestation reason and no bypass.
    # SignAndVerifyCandidate is the governed Signing Boundary. The threat
    # is signing the wrong digest or treating a synthetic session as a
    # Trusted release. The mechanism is exact-digest eligibility plus
    # fail-closed verification. The trust assumption is that the request
    # is synthetic and live Azure setup is absent. Safe failure is
    # NotStarted with no Trusted label.
    # RunValidationRound is the maintainer controller for one to four
    # private Windows 11 clients. The threat is leaving residue, admitting
    # a fifth live VM, or treating a controller tracer as qualifying
    # Preview evidence. The mechanism is an exclusive lease, cleanup-first
    # admission, VM Agent control, irreversible Round Cleanup Mode, and
    # independent absence checks. The trust assumption is the approved
    # managed identity. Safe failure is NotStarted, or CleanupIncomplete
    # while residue remains.
    # RecoverValidationRound is the Azure-resident cleanup worker. The
    # threat is being unable to finish teardown after host loss. The
    # mechanism is the private Round Recovery Record without the
    # initiating process or its local files. Safe failure is
    # CleanupIncomplete while any exact owned target remains.
    [ValidateSet('Assessment', 'RecipientProfileSetup', 'RestrictedReportExport', 'Help', 'About', 'Verify', 'VerifyAttestation', 'AdmitValidationRound', 'RunValidationRound', 'RecoverValidationRound', 'EvaluateReleaseGates', 'SignAndVerifyCandidate')]
    [string] $Workflow = 'Assessment',

    # These paths exist only to locate the sidecar bundle and the unchanged
    # candidate zip. They are never copied into verification records.
    [Parameter()]
    [string] $AttestationBundlePath,

    [Parameter()]
    [string] $CandidateArchivePath,

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
    [string] $MicrosoftConnectivityFixturePath,

    # AdmitValidationRound is a maintainer offline gate. The threat is writing
    # a rendered plan into the repository or contacting Azure from an
    # assessment host. The mechanism is a synthetic request plus an already
    # marked private workspace. The trust assumption is that the operator
    # chose a folder outside this checkout. Safe failure is NotStarted with
    # no Terraform or Azure process.
    [Parameter()]
    [string] $ValidationRoundRequestPath,

    [Parameter()]
    [string] $ValidationPrivateWorkspacePath,

    # RunValidationRound is a maintainer controller. The threat is treating
    # a synthetic fixture as live Azure, or leaking a bootstrap password
    # through guest control. The mechanism is a closed scenario name plus
    # the same marked private workspace as admission. The trust assumption
    # is that live Azure uses the approved managed identity. Safe failure
    # is NotStarted with no create. RecoverValidationRound reuses the
    # same fixture and private-workspace parameters and does not need
    # the original request or local recovery journal.
    [Parameter(DontShow)]
    [string] $ValidationRoundFixturePath,

    # EvaluateReleaseGates is a maintainer offline gate. The threat is treating
    # a synthetic pack, a waived failure, or the unsigned generated script as a
    # published Preview or Supported release. The mechanism is exact-candidate
    # binding plus a public identifier-free projection. The trust assumption is
    # that the pack is synthetic and that these bytes are the candidate. Safe
    # failure is NotStarted, or an evaluated denial that cannot authorize
    # publication.
    [Parameter()]
    [string] $ReleaseEvidencePackPath,

    [Parameter()]
    [string] $ReleaseGateWorkspacePath,

    # SignAndVerifyCandidate is a maintainer Signing Boundary. The threat is
    # signing the wrong digest, leaving a standing role, or contacting Azure
    # from an assessment host. The mechanism is a synthetic request plus an
    # already marked private workspace. The trust assumption is that live
    # Artifact Signing setup authority is absent. Safe failure is NotStarted
    # with no Trusted label and the session capability removed.
    [Parameter()]
    [string] $SigningSessionRequestPath,

    [Parameter()]
    [string] $SigningWorkspacePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
