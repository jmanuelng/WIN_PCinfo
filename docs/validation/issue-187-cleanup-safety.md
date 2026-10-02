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

## Independent review and corrections

### Standards

The first frozen review (`fb2e570`) found one P1: a failed stop-marker write
could let the suite continue. The runner now preserves unsafe state from caught
exceptions independently of file persistence, and recognizes a marker-directory
collision as blocked. A native child emits a fixed identifier-free unsafe-cleanup
signal; its caller propagates that signal as exception data before handling an exit
code. Wrappers preserve unsafe child workspaces even without a readable marker.
The case controller also retains an original failure alongside summary-write
failure. The marker remains a durable safeguard where persistence is available.

### Spec

The first frozen review found the same P1 and one P2: the helper scope hid the
caller's HTML variable, recording zero bytes. The harness now captures that exact
variable in its original scope and measures it within protected retention.

Both review findings have independent RED/GREEN regressions: marker write denial
initially allowed the second file to execute; native cleanup state initially lost
its unsafe flag; and report-size evidence initially recorded 0 instead of the
known 16-byte fixture. Corrected focused checks pass, including explicit recovery
retention and native-process propagation without any marker file or directory.
The second frozen review (`6f517e4`) found one P1 on each axis: other native Status
desk callers did not yet propagate the unsafe-cleanup signal. All native source,
report, GUI, cancellation, lock and deliberate recovery callers now use the shared
process helper. Recovery's independently supervised child uses the same output
result guard; its parent finalization retains unsafe child state and aggregates
cleanup failures. The same-process post-start-loss caller already preserves the
exception object and does not need a native conversion.

A new RED/GREEN regression executes the actual certificate wrapper and suite
runner with only build/runtime discovery and the child assessment substituted.
The child provokes a real marker-write failure without a marker file/directory;
the original wrapper allowed the next file to execute, while the corrected wrapper
blocks it. Successful native cases still execute subsequent files. Recovery parent
finalization is separately replayed with an unsafe child error and preserves its
workspace and original error. Both focused commands pass, in about ten and three
seconds respectively, without executing an application candidate.

Final independent re-review is pending. Findings in the initial review: Standards
1 (worst P1), Spec 2 (worst P1); neither axis is combined with the other.

## Qualification boundary

These are synthetic harness checks on the build host. Independent Standards and
Spec reviews are required before generated application tests resume. The complete
current application gate remains pending; the historical #158 failed gate stays
failed. No Windows client live assessment, signing, trust mutation, Azure run,
tester distribution or GitHub Actions execution is claimed by this repair.
