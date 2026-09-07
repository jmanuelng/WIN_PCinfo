# #154 automated qualification

Assigned specification: [#154](https://github.com/jmanuelng/WIN_PCinfo/issues/154),
with the approved #134/#37 specifications and #158 allocation. This continuation
supersedes the outstanding automated work in
[the earlier qualification audit](issue-154-qualification-audit.md), while
preserving that audit and the package-admission checkpoint as historical evidence.

**Automated qualification passed. Standards and Spec review are both pending.**
This is an implementation/review checkpoint, not application or release acceptance.

| #154 criterion | Automated disposition and evidence |
| --- | --- |
| Exact Draft 2020-12 validator and semantic contracts | Pass: 573 official cases, 177 justified exclusions, zero failures/fetches; generated contract and semantic-matrix checks retain duplicate/I-JSON/reference/graph/version/feature/privacy/bound negatives. |
| Every applicable selected-scope state and honest run semantics | Pass: 99 selected scopes, 676 executed applicable scope/state pairs, 611 explicitly excluded combinations; 343 complete generated cases and zero missing/unexpected states. |
| Crypto, protectors, buffers and no persistent plaintext archive | Pass: retained known-answer, key/nonce/AAD/chunk/finalization and DPAPI/recipient tests; new exceptional-buffer observations qualify the bounded ownership repairs. |
| Invalid, incompatible, oversized/interrupted packages and context/profile contracts | Pass: eleven incompatible records inside authenticated packages are refused before final naming/viewing; affected package/protector/viewing regressions pass. Unchanged prior alias/framing qualification is preserved. |
| Prohibited material, public output, cleanup and five cultures/Unicode | Pass: selected collector boundaries refuse secret-bearing inputs; marker-only retained evidence, declared transforms, owned cleanup, 55 source/culture cases and current redirected Unicode/ANSI checks pass. |

Live context/provider/non-English Windows acceptance remains Pending in #161/#162.
Root must obtain both fresh affected review axes before delivery or ticket closure.

## Identity and method

- Exact starting revision and review fixed point:
  `37482d15ee366e5b51e686cc9f4180f1ffb53fa2`.
- Product repair checkpoint: `f879ed73bdf2e1211d7432d664552b539cb7bed0`.
- Current product source: `3b33754730fc6c4f92af742ba3ded83fb891c7ba`.
- Final worker qualification test source: `2a9f71fd7a09045c556eda5430d32f8feb8c56f1`.
- Generated unsigned candidate: SHA-256
  `1c2e77746a5714ff01206868e1c39027a83e12ae5b3b86ea60c1387797466a49`,
  3,312,123 bytes. Test/document-only commits preserve these candidate bytes.
- Installed host: `C:/Program Files/PowerShell/7/pwsh.exe`, PowerShell 7.6.5,
  .NET 10.0.11, X64, Windows. No installation or runtime repair occurred.

The ordinary generated coordinator, contract admission, rules, report, package
encryption/reopening and cleanup execute against repository-owned OS doubles.
Existing source adapters are reused. Network/certificate source reducers use
their existing in-process adapters; their timeout/cancel/loss checks separately
run the actual bounded native worker. Identity, software, resource, privileged
and SYSTEM worker tests retain their applicable process/protocol boundaries.
No controlled context/provider result is a live Windows acceptance claim.

The new retained gates are `OfficialSchemaQualification.Tests.ps1`,
`AssessmentSafetyQualification.Tests.ps1`, `ProtectedPackageBufferSafety.Tests.ps1`,
`ProtectedPackageRecordSafety.Tests.ps1`, `DeviceProhibitedMaterial.Tests.ps1`,
`ContractCultureOutput.Tests.ps1`, and `CertificateCulture.Tests.ps1`.
The 195 existing source scenarios remain
retained by their original eleven `*SourceApplication.Tests.ps1` entry points;
the qualification runner adds exact scope and output evidence to those scenarios.
The full `tests/Run-Tests.ps1` gate is deliberately **NotRun**, assigned to #158.

The [baseline focused regression results](issue-154-focused-results.json) contain
**27 passing test files**, 708.736 seconds total, on candidate
`2f471e321de719de02a902633e637f6395a0476d5545a2d924f914eec52d1181`
(3,311,711 bytes). The two package files ran at
`f879ed73bdf2e1211d7432d664552b539cb7bed0`; the remaining 25 ran at
`9eee5ad65ed0ac799e84a93a53e552dc98c75742`, after a test-only buffer cleanup
correction. The changed file was rerun; unchanged passing files were not looped.
The later certificate timestamp repair leaves validator, crypto, recipient and
lifecycle implementations and their inputs unchanged. Those results retain
their stated baseline identity. Affected certificate/report checks are refreshed
separately on the current candidate; earlier generated-application results are
not relabeled with its new digest. Entry-file and unaffected implementation
hashes are checked before preserving baseline results.
The two baseline `ComprehensiveReport*` entries and `ContractCultureOutput` are
superseded by current candidate checks. The remaining 24 qualify unchanged
boundaries with their recorded source/candidate identities.
The [current certificate/report results](issue-154-certificate-results.json)
record nine passing files, including the retained `CertificateCulture.Tests.ps1`.
Their total elapsed time is 285.937 seconds.
Its pinned September 6 timestamp first failed under es-MX by becoming June 9;
the generated ar-SA case independently failed certificate admission. After the
invariant conversion repair, the focused five-culture regression and the
original ar-SA generated case pass. All selected generated qualification modes
are refreshed because this repair changed candidate bytes.
Each listed file ran as `pwsh -NoLogo -NoProfile -File <test path>` using
the explicit installed host; the result records its exit code and elapsed time.

The [current redirected-output result](issue-154-output-results.json) separately
refreshes `ContractCultureOutput.Tests.ps1` on the current candidate: ten positive/
negative executions across all five cultures, including Unicode, sanitized JSON,
empty stderr and ANSI exclusion, in 32.599 seconds. This supersedes its baseline
execution.

The [exact scope/state map](issue-154-scope-results.json) records all case identities,
stable scope reasons, source boundaries, input/runtime hashes and original result
summary digests. Elapsed values below sum the completed passing case timers.
The total is 7,976.383 seconds. Final continuity checks verify 25 pinned official
inputs, four schemas, four loaded validator assemblies, all 36 baseline/current
certificate test-entry hashes, and syntax for all 27 changed PowerShell files.
These continuity and syntax checks are explicitly separate from test execution.

| Generated qualification mode | Passing cases | Elapsed seconds |
| --- | ---: | ---: |
| Existing source scenarios | 195 | 4,520.229 |
| Additional applicable source/prerequisite cases | 52 | 1,204.001 |
| Eleven source families in five cultures | 55 | 1,441.434 |
| Scheduling, privilege denial and prohibited inputs | 18 | 298.970 |
| Actual worker interruption/loss | 23 | 511.749 |

Qualification commands (each under the explicit installed host above):

```powershell
& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File tests/Invoke-AssessmentSafetyQualification.ps1 -Mode Coverage -ResultDirectory .test-output/issue-154-final-qualified/coverage
& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File tests/Invoke-AssessmentSafetyQualification.ps1 -Mode Sources -ResultDirectory .test-output/issue-154-final-qualified/sources
& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File tests/Invoke-AssessmentSafetyQualification.ps1 -Mode Cultures -ResultDirectory .test-output/issue-154-final-qualified/cultures
& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File tests/Invoke-AssessmentSafetyQualification.ps1 -Mode Safety -ResultDirectory .test-output/issue-154-final-qualified/safety
& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File tests/Invoke-AssessmentSafetyQualification.ps1 -Mode Workers -ResultDirectory .test-output/issue-154-worker-qualified
& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File tests/Invoke-AssessmentSafetyQualification.ps1 -Mode Workers -CaseFilter '[RNCI]*' -ResultDirectory .test-output/issue-154-worker-qualified-tail
```

The runner records a case as passing only after the complete application test
returns exit 0. An individual projection written before a later assertion is
not a pass; only entries added to the summary's results after exit 0 count.
The first worker batch completed eight cases, then stopped on a Resource-Cancel
report assertion. That failed case is excluded. The remaining fifteen cases
passed with the corrected assertion; their union contains all 23 unique cases.
The first batch's source, input hashes, original failed-case identity and eight
completed results remain explicit in the evidence.

The four initial modes ran at product source `3b33754`. Worker cases first ran
at `845fb3ce4a2d364f645e12c99f98c14c6463ac7f`, after two changes restricted to
the privileged-fault test branch. The remaining worker cases ran at `2a9f71f`,
whose only further change is the Resource-Cancel report assertion guard.
Text comparison excluding those exact conditional branches reproduces the
prior harness; all other recorded input bytes match. Earlier credited cases
cannot select the changed branches. Candidate and runtime identities match
across every batch. No earlier result is relabeled with a later source SHA.

## Official validator qualification

[The detailed official result](issue-154-official-results.json) records
**573 Pass, 0 Fail, 177 justified NotApplicable**, 377 ms, with zero external
document fetches. Counts are supported by exact group/case identities, selected
schemas/data, expected outcomes and explicit reasons for every excluded group.

```powershell
& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File tests/Invoke-OfficialSchemaQualification.ps1 -ResultPath .test-output/issue-154-official-results.json
```

The 24 approved Draft 2020-12 fixture families and MIT license are unchanged
upstream bytes from commit `c9510e3bf8a896c3cba4e08509cf752b4f30dff8`, draft tree
`db5782b10c73f2eee7bd3c9a0c57cfe24390e9b9`, license blob
`c28adbadd9114a30a302fef37c3d14f490645c1c`. Their manifest verifies byte counts,
SHA-256 and Git blob identities. No corpus reacquisition occurred.

The runner invokes the installed `Microsoft.PowerShell.Utility\Test-Json` with
the product's actual configuration and no validator options. It passes raw
`JsonElement.GetRawText()` values, so PowerShell numeric/date/array coercion
cannot alter official inputs. Loading errors and exceptions cannot count as
ordinary invalid-instance passes. A temporary failing fetch callback observes
offline resolution and is restored afterward.

Selected groups cover release-used Boolean schemas, local/escaped/chained/
recursive references, adjacent reference keywords, embedded identities,
objects, applicators, conditions, dependencies, tuple/items, bounds, uniqueness
and Unicode/pattern behavior. The actual configuration treats `format` as
annotation: all 21 official date/date-time/URI cases run, including invalid
strings expected to remain valid annotations. This makes no format-assertion
claim. Domain semantics and I-JSON are tested separately through contract and
authenticated-package boundaries.

The recorded run was reused only after checking identical runner, selection,
all 25 pinned inputs, four release schemas, loaded validator assemblies and
runtime. The product validator and these inputs did not change during the
subsequent source repairs. The old preliminary WIP count was not reused as
qualification. Schema hashes in this result are canonical UTF-8/LF; the earlier
audit's raw checkout hashes included different line endings.

Published official-result JSON normalizes line endings only. The original official
runner result's SHA-256 is
`a9d0f1a9518f59e0187b82a66875367848f417b145b9b717ff80291550ab9cab`;
the scope evidence retains the original completed summary hashes. This text
normalization changes no input, expected outcome, result or qualification run.

## Bounded repairs and regression evidence

Each product repair followed an observed failing case at its public/generated
boundary. These are distinct from new cases that already passed and corrections
to stale test expectations.

| Trigger | Observed failure | Resulting behavior |
| --- | --- | --- |
| Authenticated incompatible record and exceptional package writes | Boxed-byte copies and owned stream backing buffers survived the intended clearing path. | Package readers return clearable byte arrays; owned archive/manifest/artifact and stream buffers are cleared on failure; successful artifact buffers transfer explicitly to the caller. |
| Recipient content-key unwrap | A pipeline-enumerated object array required a new byte-array copy. | RSA unwrap transfers one byte array suitable for caller clearing. |
| Cancellation after later source stages | Some later selected scopes disappeared from the comprehensive record. | All 99 selected scopes remain; unscheduled scopes are NotAttempted with no observations or collector envelope. |
| Actual native timeout/cancellation | Several source adapters lost the supervisor's actual reason and reported a different state. | Software/resource/network/certificate and both identity workers preserve their applicable timeout/cancel/failure dispositions. Cancellation stops the later work/school identity call. |
| SYSTEM timeout, cancellation or worker loss before admitted evidence | Eight field scopes retained their initial Unavailable placeholders. | All nine scopes in the attempted SYSTEM operation retain the actual attempt disposition. |
| Empty Assessment User SID | Software/resource SID parameter binding threw before the intended unavailable-context branch. | Missing context becomes explicit Unavailable coverage without entering the OS source. |
| Remote-policy timeout | Update/legacy signals emitted TimedOut, but internal admission rejected that state. | The two signal checks admit that existing source outcome while still forbidding a retained value on failure. |
| Valid marker-only record with no evidence references | Report rendering failed under strict mode. | Empty reference collections render safely without inventing observations. |
| JSON-recognized certificate timestamps under non-English cultures | ar-SA rejected Gregorian date text; es-MX silently changed September 6 to June 9 in canonical evidence. | Timestamp admission and UTC evidence rendering use invariant parsing and Gregorian formatting, preserving the same instant in all five cultures. |

The existing policy expectation was corrected to preserve the current AppLocker
CSP gap and Indeterminate conflict guidance. The resource report expectation now
uses the released canonical observation anchors. Neither was an observed product
regression. A new test's cleanup also needed typed byte-array variables; its
failed owned fixture was identified by exact path, creation interval and sole
protected-package contents, then removed after resolved-path/reparse checks.

Three worker-test corrections are also distinguished from product defects.
The standalone 10-second privileged timeout fault was shorter than the combined
17.75-second privilege/SYSTEM budget. The controlled source now waits 30 seconds,
and the real supervisor reaches TimedOut with verified cleanup. LostWorker exits
after hello, before receiving a plan: assertions preserve protocol
IntegrityFailed/PRIVILEGE.WORKER_LOST separately from run NotStarted/20, with
zero admitted operations. Resource-Cancel stops before network scheduling, so
its report uses the same early-cancellation assertion as cancellation immediately
after that stage. Exact NotAttempted coverage and lack of unscheduled observations
remain asserted. Temporary diagnostic instrumentation was removed.

## Scope/state applicability

The selected comprehensive profile is filtered from Contract Set 1.13.0 by its
exact profile ID: **99 of 104** declared scopes. A successful case's other
synthetic dependency scopes do not establish source execution for those scopes.
The evidence map credits the owning source, an explicitly asserted prerequisite
or authorization branch, actual scheduler behavior, or a named exported attempt.
Its `notApplicableStates` entries explain excluded source/state combinations;
they are not emitted coverage rows. An actual `NotApplicable` coverage value
has its own executed witness like every other applicable state.

| Scope cohort | Count | Applicability distinctions |
| --- | ---: | --- |
| Device context | 1 | Source access/cardinality gaps are Partial; failed admitted attempts can be Malformed, Constrained, TimedOut or Cancelled. A declared unavailable signal is Unavailable. Prohibited input and worker loss refuse the ordinary comprehensive report. Marker-only ProhibitedMaterialBlocked records remain qualified at the approved fixture/contract/package boundary. |
| Firmware | 3 | Complete, Denied, Unsupported, Malformed and Failed are source outcomes; denied privilege leaves the three sources Unavailable. Missing TPM is observed absence; legacy-BIOS Secure Boot inapplicability is distinct from a collection success. An interrupted front-loaded privilege protocol with no authenticated result creates no per-source report. |
| Identity and direct administrators | 4 | Identity preserves native failure/timeout/cancel and prerequisite availability. Work/school becomes NotAttempted when cancellation prevents its scheduling. Administrator source failures are Denied/Malformed/Failed; bounded enumeration is Partial. |
| SYSTEM provider, MDM fields and AppLocker CSP | 9 | Provider absence or denial can suppress dependent queries; their reasons are retained. Build applicability, malformed field values and CSP collections have separate dispositions. Whole-attempt failures cover all nine fields; a cancellation with no final record is recorded as attempt evidence. |
| Applied/local-security policy | 15 | User-context guards apply only to the user RSoP scopes. RSoP bounds are Partial; malformed links/settings affect their own scopes. Local user-right failures aggregate to Partial. Typed SAM/audit failures do not invent a Malformed or successful-empty result. |
| Defender, SmartScreen, firewall and Security Center | 10 | Missing, malformed, unsupported and denied sources remain distinct. Multiple/bounded provider registrations are Partial. Source field gaps are not disabled-control observations. |
| BitLocker, VBS, WDAC and GP AppLocker | 5 | Source partiality, typed failures and timeout are retained. Empty WDAC inventory can be Complete; nonempty inventory remains Partial because deployment-channel attribution is unknown. Bounded GP collections are Partial. |
| Update, legacy authentication, RDP, WinRM and SMB | 16 | Compound signal gaps can be Partial. WinRM listener registry evidence remains Partial, with Constrained on bounds; it does not prove the complete effective listener set. A timeout signal is not a successful observation. |
| Software | 8 | Bounds/malformed entries and worker/context failures have distinct coverage. Only the two 64-bit registry scopes become NotApplicable on a 32-bit source. |
| Resources | 5 | Cached/partial printer evidence cannot qualify complete migration guidance; a controlled local-printer source separately exercises Complete. Row/bound failures are Partial. |
| Local network | 9 | Security-component inventory is Unsupported in the approved offline source. Context/worker failures can affect all nine. Proxy malformation is distinct from list partiality; Local Only makes no connectivity requests. |
| Certificate purposes | 6 | Four attributable purposes have bounded/partial/store-gap outcomes. Two purposes without approved attribution are NotApplicable; whole-context/worker refusal remains distinct. Trust/validity findings are not coverage states. |
| Microsoft connectivity | 8 | Completed or failed protocol observations reduce to Complete or Partial coverage; Local Only and unscheduled work are NotAttempted. Failed/TimedOut protocol values do not become invented scope timeouts. |

An unobserved state is not automatically NotApplicable. The exact-scope map
links all 676 applicable pairs to executed witnesses and attaches source/
scheduling reasons to the other 611 combinations. Both `unqualified` and
`unexpected` are empty. No source-only assertion is counted as execution.

## Safety, culture and live allocation

The package negatives place eleven incompatible Assessment Records inside valid
authenticated archives with matching artifact digests. Creation refuses final
naming; reading exposes no artifacts; viewing creates no artifact or recovery
journal. The existing alias-admission repair and nine framing negatives are
unchanged and were not duplicated. Affected crypto/protector/write/view/negative
checks were run because buffer ownership changed.

The passing `ProtectedPackage.Tests.ps1` checks the fixed independent
AES-256-GCM ciphertext/tag vector, fresh underlying 256-bit keys and nonce
prefixes, deterministic inner contents and actual local DPAPI reopening.
`ProtectedPackageNegative.Tests.ps1` covers exact and exceeded artifact/archive
bounds, chunk nonce uniqueness, authenticated invalid archives and digests,
truncation and controlled wrong-user/device refusal. Recipient tests exercise
RSA-OAEP-SHA-256, historical opening, missing keys, supported key sizes and
software/hardware protection labels through the declared synthetic provider
contracts. Those provider labels do not establish a live hardware key boundary.

Buffer observations hold references to actual allocated arrays and stream
backing buffers while leaving validator/crypto implementations active. They
cover setup, interrupted-write, disk-exhaustion, post-encryption chunk failure,
authentication failure, incompatible-record admission and successful caller
transfer/disposal. This is controlled managed-buffer evidence, not forensic
erasure or removal of immutable strings/runtime-internal copies.

Prohibited-input checks cover device, identity, resource, network, software,
certificate, connectivity, firmware, administrator, policy and SYSTEM routes.
They check the literal marker, invariant case variants, UTF-8/UTF-16 Base64,
UTF-8 SHA-1/SHA-256/SHA-512 hex, HTML and URI encoding at the applicable public
and retained boundaries. These are declared tested transforms, not every
possible transformation. Only false-retained/false-hashed marker records pass
the separate marker contract/report/package test. Unknown secret-bearing
payloads cannot become successful comprehensive reports.

Culture qualification uses en-US, es-MX, tr-TR, ja-JP and ar-SA. The source
harness configures executing controlled sources, observes both cultures inside
the two actual identity children, and guards the actual controlled SYSTEM CIM
call. Other source locales survive canonical packaging where a locale field
exists. Separate generated automation checks use real redirected UTF-8 JSON,
Unicode input, exact result/terminal counts, empty stderr and explicit ANSI ESC
exclusion. Report tests retain Unicode escaping, supplementary characters and
deterministic rendering under the five cultures.

Live wrong-user/device, hardware/software-provider and non-English Windows
sessions remain **Pending in #161/#162**. Full integrated regression remains
with #158, including the historical #138 512-MiB budget concern allocated to
#158/#161. No live assessment, UAC, installed key/trust mutation, signing, cloud
or private #160 operation occurred. Root owns the requirement-register update,
independent review, delivery and all GitHub mutations.

## Independent review handoff

Implement, TDD and Code Review were invoked. The user assigns the two fresh,
independent affected-diff reviews to root's separate CLI sessions. Neither axis
is waived or replaced by this worker's qualification: **Standards Pending;
Spec Pending**. Earlier reviews qualify only their unchanged historical diffs.

```text
git diff 37482d15ee366e5b51e686cc9f4180f1ffb53fa2...HEAD
git log 37482d15ee366e5b51e686cc9f4180f1ffb53fa2..HEAD --format=full
```

The assigned specification source is the supplied current #154 issue snapshot,
with approved #134/#37 and #158 allocation snapshots. Standards sources are the
original checkout's `AGENTS.md`, `CONTEXT.md` and
`docs/agents/{issue-tracker,triage-labels,domain}.md`, this integration checkout's
`CONTRIBUTING.md` and `.sandcastle/CODING_STANDARDS.md`, relevant ADRs, and the
Code Review skill's smell baseline. The user's focused-test override assigns
the full repository gate to #158. No push, PR or issue mutation is authorized
from this checkpoint.
