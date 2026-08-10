# Issue #43 privilege-boundary validation

This evidence is synthetic and identifier-free. It proves the exported privilege security contract and generated-application integration without approving UAC, collecting a real device, exposing an account, or producing a Protected Evidence Package.

## Acceptance traceability

| Requirement | Public-safe evidence |
| --- | --- |
| At most one UAC; none when already elevated | `PrivilegedPlan.Tests.ps1` proves counts `1` and `0`; `PrivilegedPlanApplication.Tests.ps1` repeats both through the generated application. |
| Frozen IDs and typed parameters only | `PrivilegedPlanPolicy.Tests.ps1` binds the four IDs to the Preparation Plan; the worker accepts an exact ordered set with closed empty objects. A real post-approval mutation fails before UAC. |
| One-instance, bounded, ACL/nonce/schema protected channel | The policy fixes one instance, 16 KiB frames, 32-byte nonce, and initiating-user/Administrators ACL. The exported wrong-client fixture exercises kernel PID rejection. |
| Mutual peer and artifact identity | Both peers query the process attached to their pipe handle and hash the actual PowerShell image; the release policy binds the canonical worker template digest. |
| Prohibited channel content absent | Tests inspect the sanitized result; the worker protocol has closed message shapes containing only protocol, nonce/digest, fixed operation IDs, empty typed parameters, and status. |
| Alternate administrator preserves ownership roles | The alternate-admin fixture keeps the original synthetic Assessment User Context and Local Package Protector while reporting only the relationship. |
| Denial continues safe work | Generated denial returns `Unavailable` privileged coverage and `Complete` safe standard-user synthetic coverage with one terminal result. |
| Complete cleanup | Every scenario verifies the worker/root, worker-owned Job, hostile fixture process, named pipe, and nonexistent staging absent before return. |
| Beginner comments and documentation | `src/PrivilegedPlan.ps1` explains UAC, ACLs, nonces, pipe peer PIDs, Authenticode/digests, Job Objects, privacy, threats, assumptions, and fail-closed behavior; `docs/privileged-plan.md` teaches the same behavior. |

## Synthetic matrix

| Scenario | Privilege result | Key proof |
| --- | --- | --- |
| Accepted elevation | `Completed` | One simulated UAC interaction; four operations share one phase. |
| Already elevated | `Completed` | Zero UAC interactions. |
| Alternate administrator | `Completed` | Coordinator-owned user/protector identities remain unchanged. |
| Elevation denied | `Unavailable` | No retry; standard synthetic collection continues. |
| Wrong pipe client | `IntegrityFailed` | Kernel client PID differs from the owned worker and is rejected. |
| Altered plan | `IntegrityFailed` | Full approved-plan digest mismatch stops before launch. |
| Lost worker | `IntegrityFailed` | EOF cannot become partial success; cleanup remains verified. |
| Timeout | `TimedOut` | Finite operation deadline followed by bounded hard stop. |
| Cancellation | `Cancelled` | Cancellation closes scheduling and terminates the worker within the public test bound. |

Generated accepted/denied results end as `IntegrityFailed` only because issue #46 has not delivered the real Protected Evidence Package finalizer. Useful synthetic collection is still shown in coverage; it is never mislabeled `Completed` without a verified package.

## Commands

```powershell
pwsh -NoLogo -NoProfile -File ./tests/PrivilegedPlanPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/PrivilegedPlan.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/PrivilegedPlanApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

The focused matrix validates nine scenarios at the exported seam and again through the generated application. The complete repository suite verifies deterministic embedding and prevents regressions in Preparation, process supervision, lifecycle, contracts, runtime gating, and Windows PowerShell fail-closed behavior.
