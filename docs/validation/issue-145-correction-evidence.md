# WinRM source correction checkpoint (#145)

This is the earlier source checkpoint. The subsequent Standards enumeration
finding and current candidate are recorded in the
[bounded enumeration correction](issue-145-enumeration-bound.md).

Starting commit and Code Review fixed point:
`77fdb5fc7753213447862c5d3ab4efb7bd3ca73a`.
Source commits, both DCO signed:

- `753d7385864b994a9f3e6b1417ae0dff736b233b`: executing certificate/listener
  configuration sources, canonical/report projection and source identities.
- `7ce0a580bafe5bc47093e728b0facfd14bd0eaca`: typed four-byte registry reads and
  Boolean range enforcement, with retained source regressions.

This corrects the two earlier source-review blockers: all four mandatory WinRM
fields now have executing request-free sources. The
[primary source trace](issue-145-winrm-source-proof.md) establishes the explicit
normal Registry64 HKLM configuration mapping. No field was removed or replaced
with an unexecuted placeholder. Independent review is still required before
implementation closure; controlled validation is not live acceptance.

Certificate authentication observes only explicit DWORD 0/1. Listener state is
an aggregate of explicit enabled values in at most 32 direct local records;
transport/port survive only when shared by all records. Differing endpoints
cannot become an arbitrary single endpoint. Listener coverage remains Partial
because policy-created, compatibility/default expansion, overrides, freshness
and actual listening remain unobserved. Empty/missing storage is unknown, never
false authentication or proven absent listeners. These are Configured Policy
Signals; WinRM service runtime remains separate.

## Focused validation

PowerShell 7.6.5 x64; generated assessments serialized. No full suite was run,
following the user's per-ticket cadence override. #158/final owns integrated
regression; the [private comparison handoff](issue-145-readonly-comparison.md)
keeps #161 live Windows 10/11, observer and actual-environment validation pending.

The initial certificate and listener regressions failed at the generated public
seam with the prior Partial authentication and Constrained listener placeholders.
Both then passed with source-derived values, canonical provenance/coverage,
source-linked HTML, encrypted reopening and verified viewing cleanup.

At `753d738`, all 24 retained source scenarios passed, including custom HTTP
port 47099, HTTPS, disabled/mixed records, absent/denied/malformed/unsupported/
unavailable data, partial inputs, unknown context, Windows 10 guidance and tr-TR.
Cases took 20.8–23.4 seconds. These are synthetic contexts, not live OS/locale
compatibility evidence. Policy catalog, exact worker digest, payload admission,
canonical contracts and the deterministic build also passed.

Self-review then established the service's 0–1 Boolean bounds before GetBool.
`BooleanRange` failed when DWORD 2 became true and passed after correction.
`DwordBound` failed when the controlled API detected an unbounded GetValue read;
the final path uses RegGetValueW with DWORD-only/Registry64/zero-on-failure flags
and a fixed four-byte buffer. Oversized/type-mismatched replies are rejected,
without buffer expansion or fetching a wrongly typed blob. The adapter replaces
only the native call expression and checks its real flags, hive and byte count;
a changed/missing boundary fails closed rather than reaching the device.

At final source `7ce0a580`, these affected checks passed:

```powershell
pwsh -NoProfile -Command '& ./tests/RemoteSourceApplication.Tests.ps1 -Scenario DwordBound,DwordOversize,BooleanRange,CertificateKind,CertificateAbsent,RegistryDenied,ListenerMultiple,Configured,CertificateFalse,ListenerDisabled,ListenerMissing'
pwsh -NoProfile -File tests/RemoteSourceApplication.Tests.ps1 -Scenario Stopped
pwsh -NoProfile -File tests/PrivilegedCollectionPlanPolicy.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicyPrivilegedCollector.Tests.ps1
pwsh -NoProfile -File tests/BuildDeterminism.Tests.ps1
```

The 12 final generated cases took 21.3–22.2 seconds and include explicit stopped
WinRM runtime coexisting with enabled configured records. The earlier policy
catalog, EffectivePolicy and EffectivePolicyContract passes remain applicable:
the later correction changes only the new source's input validation/read bound.
The default retained source matrix now contains 27 scenarios; unchanged cases
were not rerun after the bounded corrections.

The affected maximum software-report workload passed at `753d738`: 259,527 HTML
bytes, protected reopening, deliberate export and cleanup. The later DWORD
correction changes neither renderer nor that valid fixture's report bytes, so
the unchanged maximum matrix was not repeated. A temporary adapter argument
replacement error initially caused a timeout, and an overlong source-description
string was refused by the existing 192-character schema bound; both were fixed
before the passing checkpoints, without changing production limits.

## Exact final unsigned candidate

- Candidate SHA-256:
  `eb1f4277eae5b8a2c1683aadbf005ff7dd751d66aa6455af139a14e385af2c5a`.
- Candidate size: 3,260,030 bytes.
- Content-tree provenance SHA-256:
  `2315b6be7af10933edd616409a59cc54ce9c4aeee1047fd7731a0256805c3828`.
- Canonical composed-worker SHA-256:
  `204e9134334e9c81d17700405a9093461bca4ba3779d5c96735162b166e91dc8`.
- Three high-entropy synthetic configured-worker samples: 18,770, 18,760 and
  18,760 characters against the unchanged 32,500-character launch ceiling.
  Samples were encoded only, never executed as live collectors.

BuildDeterminism reproduced the candidate in separate output directories and
validated standalone embedded resources. Generated unsigned artifacts remain
ignored local build output. Synthetic package/viewing tests verified their owned
cleanup. No assessment, registry configuration, certificate mapping, credential,
trust/signing, live UAC, cloud, publication or private #160 operation occurred.

## Independent review handoff

Code Review was invoked. The fixed point resolves, the three-dot diff is
nonempty, and the source commits are listed above. Review command:
`git diff 77fdb5fc7753213447862c5d3ab4efb7bd3ca73a...HEAD`.
Spec source: current #145 body/comments plus normative #134/#37 and #158
allocation supplied by root. Standards sources: original checkout AGENTS.md,
docs/agents instructions and CONTEXT.md; integration
`.sandcastle/CODING_STANDARDS.md` and `CONTRIBUTING.md`; Code Review's smell
baseline. No relevant ADR directory exists in the integration checkout.

**Standards: pending fresh root review. Spec: pending fresh root review.**
Known retained nested slots require the documented root dispatch after this
worker ends; no prior reviewer context or prior pass substitutes for either axis.
No known source correction remains at this checkpoint, subject to those reviews.
Root owns review findings, requirement register, delivery and #145 closure.
Integrated/full, live observer, genuine privilege and release gates remain
pending with their existing owners and are not waived by this checkpoint.
