# Cross-domain findings and cautious Microsoft Zero Trust migration guidance

This preview slice does not collect new device facts. It reuses the validated Assessment Record that earlier slices already admitted, then applies one closed release policy to derive cross-domain findings, tenant-side discovery tasks, and an ordered advisory migration path. The rules are pure: they cannot invoke collectors, launch a process, contact Microsoft, refresh policy, or change the device.

## What the guidance layer adds

The release-owned policy combines four kinds of already-validated evidence:

1. Identity foundation: Assessment User Context, device registration, and work-or-school enrollment findings.
2. Management-plane prerequisites: generic Microsoft connectivity, TLS-inspection interpretation, certificate/trust findings, and Local Only coverage.
3. Dependency transition: local-administrator exposure plus observed software, resource, and peripheral dependencies.
4. Policy modernization: applied policy evidence, configured policy signals, Policy CSP result signals, and observed policy conflicts.

Those four findings feed one final `zero-trust-path` finding. The final finding is intentionally cautious. A missing or incomplete prerequisite stays `Indeterminate`; an observed blocker stays `NeedsAttention`; and the app never turns mixed evidence into a score, compliance verdict, fixed schedule, or automatic remediation plan.

## Ordered path and priorities

The ordered path is frozen in the release policy and always uses three explicit priority tiers:

- `ImmediateReview`: confirm the intended cloud identity target, then review connectivity, DNS, TLS, and certificate prerequisites.
- `PlanNext`: review software/resource/privilege dependencies and translate validated local policy into an approved cloud-management baseline.
- `ConsiderLater`: stage compliant-device access, device risk, and advanced endpoint data-protection work only after earlier steps are understood.

Each recommendation carries its purpose, prerequisites, caution, responsible role, verification expectation, authoritative Microsoft references, and typed `Requires`, `Enables`, or `ConflictsWith` relationships. The app never converts those priorities into a hidden score or a calendar date.

## Tenant-side discovery tasks

Some facts cannot be proven from one endpoint. When that happens, WIN-PCInfo emits an explicit `TenantSideDiscoveryTask` instead of fabricating cloud evidence. In Preview.1 those tasks cover:

- the approved Conditional Access and compliant-device target,
- the approved advanced security and data-protection scope, and
- when needed, the tenant-specific enrollment DNS, proxy, and certificate-path design.

These tasks name the required role and the safe expected result, but they do not publish tenant identifiers, policy values, proxy details, certificate fingerprints, or other Restricted Diagnostic Evidence.

## Privacy and limits

The cross-domain layer copies only evidence references that already exist in the canonical Assessment Record. It does not duplicate sensitive values into the public report section or contract projections. Public output contains finding outcomes, fixed counts, priority tiers, booleans, and stable identifiers only.

This guidance is advisory. It does not prove tenant assignment, Intune onboarding, Conditional Access scope, Defender for Endpoint onboarding, compliance state, or future rollout success. Those decisions still belong to the responsible tenant administrators and security owners in their approved Microsoft administration boundaries.

The release policy is defined in [`docs/spec/releases/2.0.0-preview.1-cross-domain-guidance.json`](spec/releases/2.0.0-preview.1-cross-domain-guidance.json), validated by [`schemas/cross-domain-guidance.schema.json`](../schemas/cross-domain-guidance.schema.json), and reviewed against the Microsoft Zero Trust and Intune planning sources embedded in that policy on August 16, 2026.

## Reproduce the validation seam

Repository maintainers can rerun the focused checks with:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/CrossDomainGuidance.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/CrossDomainGuidanceApplication.Tests.ps1
```

The fixtures are synthetic. They prove the release-owned rule behavior and generated-application seam only; they do not claim facts about the machine that runs the tests.
