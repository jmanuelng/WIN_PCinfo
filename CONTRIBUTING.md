# Contributing

Contributions are welcome when they preserve the public privacy boundary and the implemented safety contracts.

## Rules

- The repository is MIT licensed, as stated in [README.md](README.md#license).
- Commits should follow the Developer Certificate of Origin (DCO).
- Do not commit Assessment Records, Protected Evidence Packages, Recipient Profiles, fingerprints, Terraform state, rendered Terraform values, Azure identifiers, credentials, or other Restricted Diagnostic Evidence.
- Offline Azure validation admission is documented in [docs/azure-validation-admission.md](docs/azure-validation-admission.md). Use only a marked private workspace outside this repository. The gate does not contact Azure and does not deliver `CAP-0028`.
- One fresh Azure validation round is documented in [docs/azure-validation-round.md](docs/azure-validation-round.md). Use only a marked private workspace. Live Azure stays `NotStarted` without the approved managed identity and without acquired pinned tooling. Completing a controller tracer does not deliver `CAP-0028`.
- Automated release gates are documented in [docs/release-gates.md](docs/release-gates.md). Use only synthetic, identifier-free evidence packs. The gate cannot waive missing evidence and does not deliver `CAP-0030`.
- Do not add floating dependencies or install tools on an assessed device.
- Public documentation must stay beginner-friendly and must not claim deferred behavior as implemented.

## How to propose a change

1. Open a public issue for a defect or improvement that can be discussed without private evidence.
2. Keep pull requests narrow and include tests for the observable seam you change.
3. Run `pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1` before you ask for review.

Security-sensitive reports use [SECURITY.md](SECURITY.md), not this public channel.

## Governance

The project is maintainer led. Required checks apply to maintainer and community changes. Maintenance is best effort. There is no SLA, response deadline, or support contract.

The in-product Help and About workflows expose these routes only when someone opens them. Assessment runs do not prompt for contributions or feedback.
