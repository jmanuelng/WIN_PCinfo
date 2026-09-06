# Update and remote-configuration checkpoint (#145)

Starting/fixed review point: `19b45d6c84b22ff4006d78454b514c2baf0f6714`.
Source checkpoint: `32be5665e52785dc6aaab0fac32449f871083f16` (DCO signed).
Dependencies #137/#139 were CLOSED; #144 was incorporated at the exact starting
tree. This is controlled-source implementation evidence, **not live acceptance**.

## Status and remaining requirements

Windows Update/WUfB, RDP, SMB and selected legacy-authentication sources now
execute through the generated engine, typed payload admission, canonical
observations/provenance/coverage, advisory rules, encrypted package reopening and
source-linked HTML. WinRM has useful request-free Service policy and service
state evidence, with four explicit unimplemented fields:

`field:policy.winrm.auth-certificate`, `field:policy.winrm.listener-state`,
`field:policy.winrm.listener-transport`, `field:policy.winrm.listener-port`.

No listener/certificate-auth source executed. These are implementation/source
limitations, not environmental absence. Honest Partial/Constrained coverage does
not waive their required-field status. **#145 closure remains pending the fresh
Spec review's completeness assessment and any required implementation.** Both
independent review axes also remain pending as recorded below.

The exact private #161 comparison plan is
[issue-145-readonly-comparison.md](issue-145-readonly-comparison.md). It documents
the missing-source next action and keeps manual request-bearing comparisons
separate from the product's Local Only observer gate.

## Repairs and source boundaries

- Read-only inbox module metadata confirmed that both SMB configuration
  operations are CDXML Functions. Fixed native inbox manifest imports replace
  cmdlet-only discovery, preserving the existing closed operation set and
  avoiding implicit Windows PowerShell 5.1 compatibility processes. DISM's exact
  SMB1Protocol read is pinned to its inbox manifest too.
- Registry absence survives nullable normalization and typed admission as
  ObservedAbsent for update and legacy-auth fields. Feature/quality deferral and
  LAN Manager bounds are enforced at admission. Each legacy-auth scope reflects
  its own fields instead of misattributing LM errors to the NTLM mask scope.
- RDP selects only RDP-Tcp and separates connection configuration, service
  runtime, authentication and listener configuration. Malformed values remain
  Malformed; a configured disabled listener is not confused with missing data.
  Service and optional-feature states use finite stable vocabularies.
- WSMan provider reads were removed: localhost management sessions can make
  requests. Five documented WinRM Service policy-registry mappings are read
  without defaults, service changes, listener probes or WSMan calls. Four usable
  auth signals remain distinct from the missing certificate-auth field.
- Partial SMB/auth values are retained without coercing missing Boolean fields
  to false. Complete remote groups must carry every declared field; failed
  groups cannot donate values. Independent malformed/denied/unsupported/partial
  coverage survives package validation and HTML.
- Configured RDP, WinRM and SMB scopes are in Configured Policy Signals;
  service runtime and SMB1 feature state stay separate. The HTML's
  `update-remote-auth/1.0.0` guidance distinguishes Windows 10, Windows 11 and
  unknown/out-of-catalog context, potentially stale configuration, ignored
  legacy SMB signing flags and unproven policy/traffic/enforcement intent.

No device assessment, settings/service change, real UAC, trust/certificate
mutation, signing, key export, cloud operation or GitHub mutation was performed.
OS calls in the selected source blocks are replaced only at controlled test
boundaries. The generated scheduler, collector channel, contract validation,
rules, renderer, encryption, reopening and owned cleanup execute normally.

## Focused validation

The approved per-ticket gate is focused; `tests/Run-Tests.ps1` was not run.
Full integrated regression remains #158/final. PowerShell 7.6.5 x64 was used.

At `32be566`, these focused checks passed:

```powershell
pwsh -NoProfile -File tests/EffectivePolicyPolicy.Tests.ps1
pwsh -NoProfile -File tests/PrivilegedCollectionPlanPolicy.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicy.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicyContract.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicyPrivilegedCollector.Tests.ps1
pwsh -NoProfile -File tests/PrivilegedInlineRepresentation.Tests.ps1
pwsh -NoProfile -File tests/BuildDeterminism.Tests.ps1
```

The retained red-green cases first rejected SMB function discovery,
malformed RDP configuration, missing report family sections,
partial Boolean projection and inconsistent complete-source admission. The
no-request WinRM fixture failed against the old WSMan path before the finite
registry source replaced it. An adapter-only cast/composition error was repaired
and is not reported as a product defect. Exact worker digest drift was refused
until the reviewed canonical source identity was refreshed. Historical failures
are retained here, not waived.

Revision-specific matrix and correction results are recorded in the completion
addendum. Generated tests are serialized, including package/viewing cleanup.

## Candidate checkpoint

At `32be566`, deterministic unsigned candidate SHA-256 is
`a73230eb4a6273567ac8efdd1be53f43d851c664fbe23ada18e7618aa1004d6e`,
3,212,510 bytes. Content-tree provenance SHA-256 is
`7328f0946c952a30c524e3a93fdf682bedc6352ccebcee7c89ef949054f3eb8f`.
The canonical composed-worker SHA-256 is
`c4a7f979bd0dd41576d61a6ca1b5bd33e73e9a8c9842b8c54d81c05fb7960c57`.

Three high-entropy synthetic configurations measured 18,298, 18,286 and 18,290
characters against the unchanged 32,500-character launch ceiling. Existing
Process and ShellExecute (without runas) checks, padding/oversize refusal and
five-culture transport passed. No genuine UAC result is inferred. The nested
SYSTEM contract and all source/admission, ownership and size bounds remain.

Ignored build output stays local; generated synthetic packages/viewing sessions
verify their owned cleanup. A conclusively owned temporary debug script was
removed. No assessment, private identifier, key or recipient artifact is
committed. The frozen private #160 candidate/signature/recipient remain separate.

## Independent reviews and next ownership

**Standards:** not started. One fresh-agent creation attempt failed with
`agent thread limit reached`; no unchanged retry or prior-ticket reviewer was
reused. Root orchestration must dispatch this axis against the exact fixed point.

**Spec:** not started for the same retained-thread capacity limit. Root must
dispatch an independent fresh axis and explicitly assess all four missing WinRM
fields against #145/#134/#37 and the frozen Preview definition. No acceptance
waiver is inferred from honest coverage or test success.

Root owns requirement-register updates, any push/PR/merge/closure and the next
safe ticket. #151 owns integrated report acceptance; #154/#158 own remaining
safety/full regression; #161 owns exact-candidate live comparisons, real UAC,
non-English Windows, observer and end-to-end acceptance. Historical #138 working
set excess of 662–755 MiB against provisional 512 MiB remains unwaived. The
September 6 handoff cutoff is before September 7 00:00 CDT / 05:00 UTC and changes
none of these obligations.

## Final source correction and handoff evidence

Final source revision: `959a7024b43685373ddf0097fb7c37a969d50393`, following
`32be566`. Both commits carry DCO sign-off. The final evidence-only commit does
not change the candidate. Fresh independent Standards/Spec reviews remain
unstarted; this handoff is not a claim that either axis passed.

At `32be566`, the complete 11-scenario generated matrix passed in one serialized
run: Configured, Absent, Denied, Unsupported, Malformed, Partial, Unavailable,
UnknownContext, Windows10, Stopped and tr-TR. Cases took 21.0–22.2 seconds.
UnknownContext uses an out-of-catalog future build, preserving unknown guidance
instead of inheriting Windows 10/11 applicability. This does not prove real
non-English Windows behavior.

The added RegistryDenied regression then failed as expected: a synthetic method
wrapped UnauthorizedAccessException and the source reported Failed. At `959a702`,
an eight-exception bounded type-based classification chain preserves the inner
Denied result without parsing messages. RegistryDenied and ordinary Denied both
passed through generated collection, package reopening, coverage and HTML (21.6
and 21.0 seconds). The default retained matrix now includes RegistryDenied.

```powershell
pwsh -NoProfile -File tests/RemoteSourceApplication.Tests.ps1
# Previous line: all 11 cases at 32be566 before RegistryDenied was added.
pwsh -NoProfile -Command '& ./tests/RemoteSourceApplication.Tests.ps1 -Scenario RegistryDenied,Denied'
# Previous line: affected generated regressions at final source 959a702.
```

Final unsigned candidate: 3,212,962 bytes; SHA-256
`405f39b0052e30be190239741e214bee0cecc2c5f3a6b5d03ccdd1451133ad65`.
Content-tree provenance SHA-256:
`39b0f6e96c71fae1ad9610f8886e1af08e131061e5a79653dcf13998aa1b8a8b`.
Final canonical composed-worker SHA-256:
`8aa212f0bb2311b7bdee06a83e0e731bfc50edc1afbb30a8bbe22e34ec8a41a1`.
SYSTEM source remains
`4e854dec2f52e8095e3ca76a119638352c189b5ef108f5a18f02092d23eacc81`.
Three final high-entropy configured launch samples measured 18,338, 18,320 and
18,322 characters against the unchanged 32,500 limit. No size increase, generic
query channel or change of ownership/admission was introduced.

At final source `959a702`, the following affected checks passed, serialized:

```powershell
pwsh -NoProfile -File tests/PrivilegedCollectionPlanPolicy.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicyPrivilegedCollector.Tests.ps1
pwsh -NoProfile -Command '& ./tests/PlatformSourceApplication.Tests.ps1 -Scenario Denied,Unavailable'
pwsh -NoProfile -File tests/BuildDeterminism.Tests.ps1
```

The shared failure-classifier regression preserved platform Denied and
Unavailable states through generated protected reports (20.9 and 21.4 seconds).
Deterministic build independently reproduced the final `405f39b0…` candidate.
No whole-suite, live, signing, observer or missing-field acceptance result is
inferred. Source and focused checks are committed; root should run fresh reviews
before treating this checkpoint as review-approved or deciding #145 closure.

## Orchestrator independent review result

Fresh root reviewers inspected `19b45d6c84b22ff4006d78454b514c2baf0f6714...a0935fa7fff25bd583541624d9d46accde6af49a` after the clean worker checkpoint released an active slot. The earlier unstarted status above is historical. Neither reviewer reran tests or changed sources.

**Standards:** zero documented-standard violations; one nonblocking possible Duplicated Code judgment for the mirrored SMB client/server normalization loops (`src/PrivilegedCollectionPlan.ps1` around lines2040/2071). Separate source calls and explicit reason codes remain appropriate; optional extraction is not an acceptance blocker.

**Spec:** two P1 implementation blockers remain. Certificate authentication has no executing request-free source. Effective WinRM listener state, transport and port likewise have no executing source. All four fields remain normative in the frozen CAP-0008 contract. Service state and policy settings cannot establish listener configuration; honest Constrained/Partial coverage and the #161 handoff do not satisfy implementation closure. No additional scope creep or independently established defect was identified.

**Disposition:** #145 stays OPEN and incomplete. Its safe source repairs are committed and focused-tested but have not been delivered at this checkpoint. Root may continue independent #146/#147 work; neither depends on #145. A bounded fresh #145 continuation must implement the missing sources, refresh affected exact-candidate tests/evidence and obtain affected reviews before closure. No live collection, requirement waiver or fixture substitution is authorized by this review. This review-record addition changes documentation only; source and candidate bytes recorded above are unchanged.
