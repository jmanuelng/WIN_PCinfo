# WinRM listener enumeration correction (#145)

Starting commit and Code Review fixed point:
`21ff92c1007c34a9ddcc3aceb8cc5798e24c0f7a`.
Source correction (DCO signed):
`f2b7aceecf2e0c627c503f1b2ca3b6632761645e`.

This bounded correction addresses the subsequent Standards P2 finding: checking
SubKeyCount before GetSubKeyNames cannot prevent unbounded collection when the
key grows during enumeration. The prior source-mapping research and resolved
certificate/listener source findings remain recorded in
[source proof](issue-145-winrm-source-proof.md) and
[earlier correction evidence](issue-145-correction-evidence.md).

The worker now uses RegEnumKeyExW with one 256-character buffer and indices
0 through 32. It retains at most 32 names; index 32 is only an overflow probe.
There is no bulk name allocation, retry or larger buffer. Known count overflow
and a successful overflow probe return Constrained. Native denial, disappearance,
oversized names and malformed returned lengths preserve explicit incomplete
outcomes. A full readable collection still reports Partial; concurrent changes
can reorder or remove records, so no consistent live snapshot is inferred.
The existing fixed four-byte RegGetValueW path is unchanged.

## Retained regression and affected checks

Implement, TDD and Code Review were invoked at the already-approved generated
assessment seam. ListenerGrowth starts with a count of one and an inexhaustible
indexed source. RED failed closed worker admission when the old bulk operation
was detected. GREEN uses the actual production native-call arguments: the
controlled adapter checks the same 256-character buffer identity and capacity,
sequential indices, the 32-plus-one ceiling, handle and null optional arguments.
The growth and exact-limit cases require precisely 33 calls. No large fixture
array, live registry query or replacement production enumeration loop is used.
The adapter refuses a missing or changed native call boundary.

PowerShell 7.6.5 x64; generated tests were serialized. All twelve affected
generated cases passed in 21.7–22.5 seconds each:

```powershell
pwsh -NoProfile -Command '& ./tests/RemoteSourceApplication.Tests.ps1 -Scenario ListenerGrowth,ListenerLimit,ListenerEnumDenied,ListenerEnumAbsent,ListenerNameOversize,ListenerNameBadLength,ListenerEmpty,ListenerBound,ListenerUnknown,ListenerMultiple,ListenerDisabled,DwordBound'
pwsh -NoProfile -File tests/PrivilegedCollectionPlanPolicy.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicyPrivilegedCollector.Tests.ps1
```

The focused checks passed the exact worker digest, closed payload admission,
native declaration compilation, canonical/report outcomes, protected reopening
and owned viewing cleanup. All affected PowerShell files also parsed. The
canonical worker SHA-256 is
`f3dbaed4ca547bc0bddc09d8b947600a77192736f30980fe0613a44ce3b87610`;
the released privilege policy was rebound to these exact bytes. Generated source
adapters bind their own instrumented worker digest; they do not bypass admission.

Three synthetic, high-entropy configured samples of the production inline
launch encoder measured 18,898, 18,884 and 18,916 characters under the unchanged
32,500 ceiling. They were encoded only, never executed as live collectors.
An initial ad hoc check used the separate EncodedCommand helper, which refused
the full privilege template at its existing compressed bound. The privilege
coordinator uses InlineCommand; its actual controlled launches and measurements
above passed. No encoder or limit was changed.

No full-suite run is claimed: the user's per-ticket
cadence reserves integrated regression for #158/final. The earlier 27-scenario
matrix and source proof retain their original revision attribution; this
correction does not repeat unchanged source discovery or the full matrix.

## Exact unsigned candidate and cleanup

`pwsh -NoProfile -File tests/BuildDeterminism.Tests.ps1` passed at source
`f2b7aceecf2e0c627c503f1b2ca3b6632761645e`, including independent output
directories, canonical line endings and standalone embedded-resource checks.

- Generated candidate SHA-256:
  `a25724b3576edd5bbd865dcd2a966d69f6b62371c5956e7d44f49f5dc8156cc5`.
- Candidate size: 3,261,676 bytes.
- Content-tree provenance SHA-256:
  `84efa48f4857a6fdf919c4bb7b1ab0f9495ad57d957087962772ac03ddd3577a`.

The two deterministic outputs and the application test candidate have the same
digest. Documentation-only delivery commits do not change this candidate.
Unsigned build artifacts remain ignored local output. Each generated test
waited for its owned worker to finish, verified package/viewing cleanup, resolved
its unique test directory under `.test-output`, and removed only that directory.
No `status-desk-*` test directories remained after this run. Existing unrelated
test/build resources were preserved. No live assessment, registry/device query,
UAC, certificate/trust change, signing, cloud action or private #160 work occurred.

## Review and remaining ownership

Code Review command:
`git diff 21ff92c1007c34a9ddcc3aceb8cc5798e24c0f7a...HEAD`.
The fixed point resolves, the three-dot source diff is nonempty, and the DCO
source commit is listed above. Use
`git log 21ff92c1007c34a9ddcc3aceb8cc5798e24c0f7a..HEAD --oneline`
for the source and documentation handoff commits.
Spec source: current #145 body/comments and relevant #134/#37/#158 allocation.
Standards sources: original checkout AGENTS.md, docs/agents instructions and
CONTEXT.md; integration `.sandcastle/CODING_STANDARDS.md`, CONTRIBUTING.md and
Code Review's complete smell baseline. No relevant integration ADR exists.

**Standards: pending fresh affected root review. Spec: pending fresh affected
root review.** Known retained nested slots require the documented sequential
root dispatch after this worker ends. Earlier review results do not substitute
for these affected reviews. Root owns GitHub delivery, the requirement register
and #145 closure. #161 live source comparisons, genuine privilege, integrated
regression and release gates retain their existing owners and pending status.
