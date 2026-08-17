# Synthetic interpretation examples

These worked examples are wholly synthetic. They use release-owned labels only. They are not observations about the computer that displays this page, and they contain no tenant, subscription, device, or host-network facts.

Use them to practice reading a report before you look at real Restricted Diagnostic Evidence.

## Example: missing evidence

A synthetic Local Only run records Microsoft connectivity coverage as `NotAttempted` with reason `FINDING.NETWORK_REQUESTS_NOT_ATTEMPTED`.

How to read it:

- The application did not try the Microsoft endpoints. That is the approved Local Only behavior.
- Missing connectivity evidence is not proof that Microsoft services are reachable or blocked.
- Unrelated local scopes, such as software inventory, remain readable.

Safe next step: if you needed those checks, start a new request with `MicrosoftConnectivityEnabled` after you approve that network behavior.

## Example: Indeterminate finding

A synthetic firmware finding is `Indeterminate` because Secure Boot coverage is `Unavailable`. The report does not say Secure Boot is off.

How to read it:

- The rule lacked admitted context, so it refused both a pass and a fail.
- Indeterminate is honest incompleteness, not a hidden severity.
- A later complete observation could change the finding. Guessing would not.

Safe next step: review the coverage reason. If elevation was denied, the privileged firmware scope may be unavailable. Do not treat the gap as noncompliance.

## Example: Tenant-side Discovery Task

A synthetic identity section includes a Tenant-side Discovery Task: confirm the approved Conditional Access and compliant-device target in the tenant’s own administration boundary.

How to read it:

- One endpoint cannot see tenant assignments, Intune intent, or organization-wide policy.
- The task names a role and an expected review, not a tenant identifier and not a configuration value.
- Completing the task happens outside WIN-PCInfo.

Safe next step: give the task to the responsible tenant administrator. Do not paste Restricted identity values into a public tracker.

## Example: restricted sharing

A synthetic Completion Summary says the package is available to the initiating Windows user only. Recipient access is `None`. Result-sharing guidance says encrypted private transfer is unavailable and public destinations are prohibited.

How to read it:

- Copying the `.winpcinfo` file does not give another person access.
- You still must never attach the package, the report, or a Restricted Report Export to a public issue.
- Adding a consultant later is not implemented. Choose zero or one recipient before collection, or keep the result local.

Safe next step: keep the synthetic lesson, delete any practice export, and never publish Restricted Diagnostic Evidence.
