# Qualification cleanup safety (#187)

The saved #158 checkpoint allowed retention and sampling exceptions in `finally`
to bypass owned worker cancellation, mutex disposal and workspace removal.
The continuation preserves that checkpoint and integrates current main separately.
The repair comparison starts at `60d883ce716496dddadfe0b83360ae93691b4da9`.

## Focused failure loop

`pwsh -NoLogo -NoProfile -File tests/QualificationCleanup.Tests.ps1` initially
failed in less than one second: `Expected 'False' but received 'True': retention
failure still removes its owned test workspace`. The fixture opened a directory
as a file to provoke real write access denial in the actual Status desk harness
finalization block. A separate wrapper fixture reproduced the same skipped
cleanup in the assessment-safety wrapper before its correction.

The final loop replays each harness's actual terminal try/catch/finally boundary,
substituting its assessment body and controlled worker adapter. It starts no
generated application and performs no live assessment. It verifies cancellation,
completion, synthetic-lock disposal, owned-mutex release/disposal and workspace
absence despite write, sampler and serialization failures. It verifies that body,
evidence and cleanup failures remain inspectable together. An unverified worker
preserves its workspace and creates a durable stop signal; the regression removes
that signal only after disposing its controlled handles and verifying absence.
The two qualification wrappers retain evidence without bypassing cleanup when
copying fails. The existing sampler regression still rejects access denial.

`pwsh -NoLogo -NoProfile -File tests/RegressionHarness.Tests.ps1` also reproduced
execution of a second test after unverified cleanup. After correction it verifies
that ordinary assertion failures still execute the remaining files, while an
unverified cleanup stops execution and explicitly inventories remaining files as
`Blocked`. The inter-process marker is identifier-free and stays in ignored test
output. It must not be removed until the preserved owned state is verified safe.

Both focused commands pass after correction; `git diff --check` passes. The shared
finalizer attempts all independent cleanup actions and aggregates failures rather
than masking them. Cleanup evidence is updated only after cleanup succeeds.
WPF exceptions recover the exact session captured by ViewReady before cleanup.
Qualification provenance includes the new helper identity.

## Qualification boundary

These are synthetic harness checks on the build host. Independent Standards and
Spec reviews are required before generated application tests resume. The complete
current application gate remains pending; the historical #158 failed gate stays
failed. No Windows client live assessment, signing, trust mutation, Azure run,
tester distribution or GitHub Actions execution is claimed by this repair.
