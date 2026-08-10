# Issue #44 validation evidence

This public-safe evidence describes synthetic validation only. It contains no real device, user, task, process, tenant, package, Recipient Profile, certificate, or assessment identifier.

## Contract evidence

- `docs/spec/releases/2.0.0-preview.1-system-collection-plan.json` fixes the one SYSTEM operation, Windows source, authority proof, parameter contract, activation mechanism, pipe, Job Object, privacy exclusions, deadlines, cleanup, and nine validation scenarios.
- `schemas/system-collection-plan.schema.json` closes every policy object and array.
- The SYSTEM policy declares the Boolean provider-presence field, its one Evidence Scope, and the release-owned collector. The generated application emits the same normal Collector Result Envelope shape used by other collectors without changing the earlier lifecycle fixture's globally closed Assessment Contract Set.

## Synthetic scenario matrix

| Scenario | Expected SYSTEM result | Expected coverage and behavior |
| --- | --- | --- |
| SyntheticSuccess | `Completed` | `Complete`; envelope context is `Synthetic`; safe work continues |
| UnknownOperation | `IntegrityFailed` | `NotAttempted`; no activation; scheduling closes |
| InvalidParameters | `IntegrityFailed` | `NotAttempted`; command-shaped extra field rejected; scheduling closes |
| ActivationFailure | `Unavailable` | `Unavailable`; safe work continues |
| WorkerLost | `Failed` | `Failed`; owned tree absent; safe work continues |
| Cancellation | `Cancelled` | `Cancelled`; scheduling closes; bounded tree termination |
| Timeout | `TimedOut` | `TimedOut`; bounded tree termination; safe work continues |
| Denied | `Unavailable` | `Denied`; no activation residue; safe work continues |
| AbnormalCleanup | `Completed` | a real named kernel IPC object survives the first attempt, is removed by one bounded retry, and cannot be reopened |

The generated application repeats the complete matrix after request validation and Preparation approval. It emits one SYSTEM phase record, one matching terminal result, the normal envelope, exact synthetic provenance, scoped coverage, and verified cleanup. The successful case additionally emits a normal Assessment Record that passes the shared Draft 2020-12 schema and semantic reference, coverage, graph, type, and bound checks. The same schema admits real `LocalSystem` provenance, but the coordinator uses it only after SID `S-1-5-18` and peer identity are proven. Useful synthetic work still ends `IntegrityFailed` at the later package gate because issue #44 does not implement a Protected Evidence Package.

Focused security checks also prove that malformed authenticated result content closes run integrity instead of becoming worker loss, a pre-identity live failure reports `NotStarted`, and deleting a simulated pre-Job task registration cannot hide its still-running captured engine process.

## Commands

```powershell
pwsh -NoLogo -NoProfile -File ./tests/SystemCollectionPlanPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SystemCollectionPlan.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SystemCollectionPlanApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AssessmentContractSet.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ContractValidator.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

The complete repository suite also verifies deterministic embedding and prevents regressions in Preparation, administrator privilege, process supervision, Assessment Run lifecycle, evidence contracts, runtime gating, and Windows PowerShell fail-closed behavior.

## Environmental limitation

No approved disposable or controlled Windows client was available. The test suite therefore does not display UAC, create a real scheduled task, obtain a LocalSystem token, or query a real MDM WMI Bridge provider. Every result is marked `SyntheticUnelevated` and carries `SYSTEM.LIVE_ACTIVATION_VALIDATION_UNAVAILABLE`. This ticket provides the live fixed activation implementation but does not claim it has passed controlled-client validation or created a Preview/Supported capability claim.
