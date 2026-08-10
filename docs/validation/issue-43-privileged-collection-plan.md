# Issue #43 Privileged Collection Plan validation

This evidence is synthetic and identifier-free. It proves the exported privilege security contract and generated-application integration without approving UAC, collecting a real device, exposing an account, or producing a Protected Evidence Package.

## Acceptance traceability

| Requirement | Public-safe evidence |
| --- | --- |
| At most one UAC; none when already elevated | `PrivilegedCollectionPlan.Tests.ps1` proves policy counts `1` and `0`; `PrivilegedCollectionPlanApplication.Tests.ps1` repeats both through the generated application. Each result identifies this as synthetic unelevated evidence, not a recorded UAC interaction. |
| Immutable IDs and typed parameters only | `PrivilegedCollectionPlanPolicy.Tests.ps1` binds the four IDs to the Preparation Plan; the worker accepts an exact ordered set with closed empty objects. A real post-approval mutation fails before UAC. |
| One-instance, bounded, ACL/nonce/schema protected channel | The policy fixes one instance, 16 KiB frames, 32-byte nonce, and initiating-user/Administrators ACL. The exported wrong-client fixture exercises kernel PID rejection. |
| Mutual peer and artifact identity | Both peers query the process attached to their pipe handle and hash the actual PowerShell image; the release policy binds the canonical worker template digest. |
| Prohibited channel content absent | Tests inspect the sanitized result; the worker protocol has closed message shapes containing only protocol, nonce/digest, fixed operation IDs, empty typed parameters, and status. A focused hostile operation result with an extra `assessmentEvidence` property is rejected. |
| Alternate administrator preserves ownership roles | The alternate-admin fixture keeps the original synthetic Assessment User Context and Local Package Protector while reporting only the relationship. |
| Denial continues safe work | Generated denial returns `Unavailable` privileged coverage and `Complete` safe standard-user synthetic coverage with one terminal result. |
| Complete cleanup | Every scenario verifies the coordinator-owned Job Object is empty, the hostile fixture process and named pipe are absent, and no staging exists before return. The retained pre-elevation Job handle is the termination boundary across UAC integrity levels. |
| Beginner comments and documentation | `src/PrivilegedCollectionPlan.ps1` explains UAC, ACLs, nonces, pipe peer PIDs, Authenticode/digests, Job Objects, privacy, threats, assumptions, and fail-closed behavior; `docs/privileged-collection-plan.md` teaches the same behavior. |

## Synthetic matrix

| Scenario | Privilege result | Key proof |
| --- | --- | --- |
| Accepted elevation | `Completed` | Synthetic policy count is one; four operations share one phase. |
| Already elevated | `Completed` | Synthetic policy count is zero. |
| Alternate administrator | `Completed` | Synthetic coordinator-owned user/protector identities remain unchanged. |
| Elevation denied | `Unavailable` | Synthetic denial has no retry; standard synthetic collection continues. |
| Wrong pipe client | `IntegrityFailed` | Kernel client PID differs from the owned worker and is rejected. |
| Altered plan | `IntegrityFailed` | Full approved-plan digest mismatch stops before launch. |
| Lost worker | `IntegrityFailed` | EOF cannot become partial success; cleanup remains verified. |
| Timeout | `TimedOut` | Finite operation deadline followed by bounded hard stop. |
| Cancellation | `Cancelled` | Cancellation closes scheduling and terminates the worker within the public test bound. |

Generated accepted/denied results end as `IntegrityFailed` only because issue #46 has not delivered the real Protected Evidence Package finalizer. Useful synthetic collection is still shown in coverage; it is never mislabeled `Completed` without a verified package.

## Typed live-validation limitation

The opening checkpoint authorized live elevation only if a supported disposable or controlled Windows client already existed. None was available in this environment. Live UAC acceptance, alternate credentials, and dialog denial therefore remain `NotStarted` for validation with reason `PRIVILEGE.LIVE_ELEVATION_VALIDATION_UNAVAILABLE`; remediation is to repeat the scenarios on an approved controlled client. This limitation is emitted in every synthetic privilege record. It does not weaken the production path: the live runner still uses Windows `runas` once, observes native denial `1223`, and uses its pre-elevation Job handle for bounded tree termination.

## Commands

```powershell
pwsh -NoLogo -NoProfile -File ./tests/PrivilegedCollectionPlanPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/PrivilegedCollectionPlan.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/PrivilegedCollectionPlanApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

The focused matrix validates nine scenarios at the exported seam and again through the generated application. The complete repository suite verifies deterministic embedding and prevents regressions in Preparation, process supervision, lifecycle, contracts, runtime gating, and Windows PowerShell fail-closed behavior.
