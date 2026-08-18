# Consultant Workbench

This workbench is the consultant-oriented companion to the [Guided Runway](guided-runway.md). It points to the operational documents that match the behavior implemented in this repository. It does not add a second product mode and does not create a Preview or Supported claim.

## Start here

1. Read the [Guided Runway](guided-runway.md) for purpose, the learning and consulting boundary, prerequisites, terminology, and the Choose through Share path.
2. Open Help or About only when you want repository, feedback, contribution, or private vulnerability-reporting routes.
3. Use the [synthetic interpretation examples](examples/synthetic-interpretation.md) before you read a real report.

## Assessment spine

- [Runtime prerequisites and safe launch](runtime-prerequisites.md)
- [Portable distribution and first-run](portable-distribution.md)
- [Attested Preview trust bundle](attested-preview.md)
- [Preparation Summary and approval](preparation-summary.md)
- [Assessment Run lifecycle](run-lifecycle.md)
- [Process Supervisor](process-supervisor.md)
- [Privileged Collection Plan](privileged-collection-plan.md)
- [SYSTEM Collection Sub-plan](system-collection-sub-plan.md)
- [Evidence Workspace and Stale-run Recovery](evidence-workspace-recovery.md)
- [Protected Evidence Packages and viewing](protected-evidence-package.md)
- [Recipient Profiles and restricted report export](recipient-sharing.md)
- [Comprehensive Local Assessment report](comprehensive-local-assessment-report.md)
- [Cross-domain findings and cautious Microsoft Zero Trust migration guidance](cross-domain-findings-and-migration-guidance.md)

## Evidence areas

- [Device, Windows, activation, form, virtualization, and power context](device-windows-readiness.md)
- [Firmware, Secure Boot, and TPM readiness](firmware-readiness.md)
- [Registration, join, and enrollment context](identity-enrollment.md)
- [Local administrator exposure and execution context](local-administrator-exposure.md)
- [Applied Group Policy and local security policy](effective-policy-assessment.md)
- [Safe Software Inventory](software-inventory.md)
- [Software Recognition annotations](software-recognition.md)
- [User resources and peripheral migration dependencies](resource-peripheral-dependencies.md)
- [Local network topology and Local Only](network-topology-and-local-only.md)
- [Microsoft service connectivity and enrollment discovery](microsoft-connectivity-and-enrollment-dns.md)
- [Purpose-bound certificates and local trust](certificate-trust.md)

## Planning and claim documents

These documents explain intended release scope. They are not a support claim for a specific machine.

- [WIN-PCInfo 2.0.0-preview.1 scope](spec/releases/2.0.0-preview.1.md)
- [Capability ledger](spec/capability-ledger.md)
- [Stable 2.0.0 supported-device matrix](spec/releases/2.0.0-supported-device-matrix.md)

## Maintainer validation admission

- [Offline Azure validation admission](azure-validation-admission.md) admits a synthetic one-to-four-client round plan into a private workspace without contacting Azure. Completing that gate does not deliver `CAP-0028` or create a Preview or Supported claim.
- [One fresh Azure validation round](azure-validation-round.md) walks one to four private Windows 11 clients through synthetic VM Agent control, exclusive-lease admission, cancellation and expiry recovery, and Zero Round Residue. Live create stays `NotStarted` on this host. Completing that controller does not deliver `CAP-0028` or create a Preview or Supported claim.
- [Automated release gates and evidence manifests](release-gates.md) evaluate a synthetic evidence pack, derive the Preview Capability Matrix, and emit promotion-denial inputs. Completing that gate does not deliver `CAP-0030` or create a Preview or Supported claim.
- [Signing Boundary](signing-boundary.md) signs a frozen eligible candidate only after release gates and human digest confirmation, verifies the signature contract, finalizes the outer package, and smoke-runs Help. Completing that workflow does not deliver `CAP-0025` or create a Trusted, Preview, or Supported claim.
- [Qualify the exact Preview candidate](preview-qualification.md) binds the frozen signed or attested distributable, walks the complete Preview.1 scenario plan, and emits an identifier-free approval or denial packet. Completing that workflow does not deliver `CAP-0027` or create a Preview or Supported claim.
- [Publish the approved Preview.1 release](preview-publication.md) binds the candidate digest, stages synthetic stand-ins for the required public assets, previews the GitHub release record, requires human confirmation of the candidate digest, and independently verifies a one-time synthetic publish. Completing that workflow does not deliver `CAP-0026`, create a live GitHub release, or create a Preview or Supported claim.

## Privacy-safe field notes

If you later want to contribute a privacy-sanitized Field Validation attestation, follow [Field Validation](field-validation.md). That human process is optional, requires deliberate consent, and is not a product workflow. Ordinary assessment use never becomes validation evidence automatically.
