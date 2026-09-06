# Platform protection source execution (#144)

Fixed starting point: `a61e7ede9c88bbd384b22a0edcbe2e2f9d76146e`.
Implementation begins at `4790bd18` on the existing integration branch. Native
dependencies #137 and #139 were CLOSED; the preceding #143 seams are retained.
This is controlled-source implementation evidence. Live device acceptance,
genuine UAC, native inbox module compatibility and private comparisons are
**Pending #161**. No live platform source, security setting/service change,
certificate/trust operation, signing or cloud operation was performed.

## Source changes and bounded interpretation

- BitLocker reads the operating-system drive through `Win32_EncryptableVolume`
  and four read-only status methods. Ten fixed `GetKeyProtectors` type filters
  produce at most eight type/count groups, with at most 32 entries per group.
  Identifiers are discarded. Static inspection of the inbox BitLocker module
  showed that `Get-BitLockerVolume` retrieves numerical recovery passwords
  internally, so that command is excluded. The documented not-activated result
  from `GetKeyProtectors` becomes an empty protector set; failed status fields
  remain gaps. Local protection does not establish escrow or physical attestation.
- Four fixed `Win32_DeviceGuard` properties preserve configured versus running
  VBS, Credential Guard, memory integrity and user-mode code integrity. Missing
  fields have no invented absent/disabled observation; malformed values clear
  the affected source and retain honest coverage.
- WDAC uses only the fixed System32 `CiTool.exe -lp -json` interface on builds
  22621 and later. Listing is limited to two seconds and 65,536 UTF-8 bytes,
  with strict decoding and verified child termination. At most eight policy
  summaries cross the existing result boundary. `IsEnforced` means activated,
  not proof that deny rules replace audit behavior. Deployment channel remains
  Unknown with Partial coverage because this interface does not establish it.
- AppLocker GP uses the fixed inbox `Get-AppLockerPolicy -Effective` operation.
  CSP uses only `EnforcementMode` from five release-owned local-system WMI Bridge
  classes in the existing upfront SYSTEM phase. No Policy XML, CodeIntegrity or
  enterprise-data-protection payload is requested. The closed result admits at
  most five unique type/mode summaries and eight source instances per class.
  Missing modes, unsupported classes and disagreeing grouping modes stay gaps;
  distinct GP/CSP observations never select a deployment winner. The canonical
  CSP scope and provenance belong to the SYSTEM collector.
- The protected HTML includes these source-linked fields, configured/current
  distinctions and coverage reasons. Existing rule definitions, encrypted
  packaging, initiating-user ownership, protected reopening and cleanup remain
  the application boundary exercised by generated tests.

Primary interface documentation and precise per-family private checks are in
[the #161 read-only comparison handoff](issue-144-readonly-comparison.md).

## Existing inline transport adaptation

Adding even the first source block exceeded the prior near-limit launch
(#143: 32,457/32,500 characters). The existing Brotli/base64 representation now
packs each pair of base64 symbols into one fixed BMP character, U+4000–U+5080.
The decoder checks that alphabet and reconstructs the same Brotli bytes before
strict UTF-8 decoding. The 32,500-character guard remains unchanged. There is no
new broker, command channel, file, privilege interaction or caller-supplied
operation. Worker source/digest admission, authenticated one-use transport,
result bounds and owned Job/process cleanup remain mandatory.

The encoding test first failed with a 25,000-byte high-entropy synthetic literal
under the previous representation, then passed exact hash roundtrip through an
actual Windows child process. Padding cases, invalid alphabet, oversized source,
quotes/Unicode and five cultures are checked. A real controlled ShellExecute
launch also passes without `runas`; this proves parser/argument behavior only,
not elevation. Genuine standard-user UAC and already-elevated acceptance remain
#161 obligations. The configured composition check preserves nested SYSTEM
source bytes and measures the unchanged launch ceiling.

## Test method and observed results

Installed PowerShell Core 7.6.5 X64, shared UTF-8 harness, serial generated runs.
The platform adapter replaces only selected OS/API boundaries in generated
worker source; canonical admission, normalization, rules, protected package,
record/HTML reopening and cleanup execute normally. Other capability families
use synthetic prerequisite evidence. The adapters are not shipped in the app.

The initial source matrix passed seventeen cases: Running, Configured,
VbsPartial, VbsMalformed, BitLockerPartial, ProtectorBound, GpMalformed, WdacOld,
WdacMalformed, WdacBound, CspDenied, CspMissing, CspMalformed, CspConflict, Denied,
Unsupported and Unavailable. Individual cases took 21.5–31.4 seconds. A retained
Unencrypted test then failed on the not-activated protector return code and
passed after its documented empty-state handling (22.3 seconds).

The native CiTool boundary test exposed an extra `VoidTaskResult` on the success
pipeline; discarding the async wait return repaired the exact JSON result. Real
controlled children verify valid output, oversized output, denied exit, timeout,
invalid UTF-8 and absence after cleanup. No CiTool process was executed.

The SYSTEM scope test failed until its separate CSP scope was added to the
release policy and schema. A later cosmetic worker-source edit caused the exact
digest gate to reject the privileged fixture; refreshing the reviewed digest
restored the policy test and complete bounded worker regression. These are
retained red-green evidence, not waived failures.

Final source revision, focused commands/results, candidate hashes and separate
independent review outcomes appear in the completion addendum below.

## Requirement-register contribution

Root orchestration owns the shared #134 register; this file does not edit it.

| Requirement | Implemented evidence | Next owner |
| --- | --- | --- |
| #37 stories 32,36,38; CAP-0008; release-required CMP-0008/CMP-0020 platform fields | Four selected source families through canonical evidence and protected HTML | #161 per-family real comparisons |
| #37 stories 49–54 | Conservative advisory findings and discovery tasks; channel conflict and missing evidence remain distinct | #151 integrated report; #161 acceptance |
| #37 stories 66–67 | No recovery material, policy bodies or protector IDs retained; fixed SYSTEM contract and source projection; protected ownership/cleanup | #154 safety gates; #158 integrated gate; #161 live protection |
| #37 story 69 | Locale-neutral typed fields and five-culture Unicode transport regression | #161 real non-English Windows |
| #134 GUI stories 19–24 | Generated ordinary Status desk through report completion using controlled sources | #153 operability; #158 exact candidate; #161 complete live workflow |
| #37 sub-objectives 5,8,9 | Focused implementation evidence only | #158 full regression/resource checks; #161 delivered-app acceptance; #162–164 release gates |

The user explicitly reserves the full repository suite for #158/final; it is not
claimed here. Historical #138 working-set excess remains unwaived. The frozen
private #160 candidate and its authority are separate from these evolving bytes;
live #160 remains Blocked. September 6 handoff means before September 7 00:00 CDT
/ 05:00 UTC and changes no outstanding acceptance requirement.

## Reviewed implementation checkpoint (Spec review pending)

Source checkpoint: `427e415130bbcbf93cdfb54aafc1aeb034837a48`.
Commits are `4790bd18c573361d9d4af90a3bdddbe993fe3710` (source wiring,
closed SYSTEM contract, transport and tests) and `427e415` (exact composed worker
identity refresh). The subsequent evidence-only commit does not change candidate
bytes. **This checkpoint is not ticket completion: independent Spec review is
pending.** The orchestration agent will run that fresh axis after this worker
returns, because the retained-agent slot limit prevented its creation here.

Focused checks passed, with commands relative to the integration checkout:

```powershell
pwsh -NoProfile -File tests/SystemCollectionPlanPolicy.Tests.ps1
pwsh -NoProfile -File tests/PrivilegedCollectionPlanPolicy.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicyPolicy.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicy.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicyContract.Tests.ps1
pwsh -NoProfile -File tests/SystemAppLockerContract.Tests.ps1
pwsh -NoProfile -File tests/CiToolSourceBoundary.Tests.ps1
pwsh -NoProfile -File tests/PrivilegedInlineRepresentation.Tests.ps1
pwsh -NoProfile -File tests/SystemCollectionPlan.Tests.ps1
pwsh -NoProfile -File tests/SystemBrokerAdmission.Tests.ps1
pwsh -NoProfile -File tests/EffectivePolicyPrivilegedCollector.Tests.ps1
pwsh -NoProfile -Command '& ./tests/EffectivePolicyApplication.Tests.ps1 -Scenario Workgroup,BitLockerEncrypted,BitLockerUnencrypted,BitLockerUnknown,VbsConfiguredNotRunning,VbsCredentialGuardRunning,WdacWindows11Policies,WdacWindows10Unsupported,AppLockerGpOnly,AppLockerCspOnly,AppLockerGpCspConflict,AppLockerChannelIncomplete'
pwsh -NoProfile -Command '& ./tests/PlatformSourceApplication.Tests.ps1 -Scenario Running,Unencrypted,VbsPartial,CspDenied'
pwsh -NoProfile -File tests/BuildDeterminism.Tests.ps1
pwsh -NoProfile -File tests/PolicyUserContextNativeSource.Tests.ps1
git diff --check a61e7ede9c88bbd384b22a0edcbe2e2f9d76146e...HEAD
```

The initial seventeen-case matrix plus Unencrypted are described above. At the
final source checkpoint, the four affected generated source reruns took 22.6,
22.0, 22.0 and 21.8 seconds respectively. The twenty-case SYSTEM lifecycle gate
passed in 16.6 seconds, closed broker refusal in 0.9 seconds, and the privileged
fixture/admission regression in 55.6 seconds. Its existing exclusion of
`DeniedSystem` remains explicit; this does not claim that separate scenario was
run. Independent SYSTEM denial/lifecycle and generated CspDenied were run.

Deterministic builds in separate output directories produced identical unsigned
UTF-8 BOM/CRLF scripts and passed the existing standalone generated seams.
`artifacts/WIN-PCInfo.ps1` is **3,204,787 bytes**, SHA-256
`78d90d6bcae5dfd0f1ee49809aa2774081c3b06b5db9e4ea103fb1ef8281b104`.
It matches `.test-output/build-determinism/first/WIN-PCInfo.ps1` and is not signed
or accepted for live use. Build artifacts remain ignored, local test output;
generated assessments verified their owned package/viewing cleanup. No real
evidence, key, certificate or recipient object is committed.

Final configured high-entropy composition samples measured **18,264/32,500
characters**. The nested SYSTEM source and native user-context compilation/parser
checks passed. Exact canonical worker SHA-256 identities are:

- Administrator/composed worker: `ba7e557f40fa1d5ec4fa66157340d86084c2b6610fc19c6a3ee1a8cd201fa468`.
- SYSTEM worker: `4e854dec2f52e8095e3ca76a119638352c189b5ef108f5a18f02092d23eacc81`.

**Standards axis:** independent review against the fixed starting point found
zero documented-standard violations. One nonblocking Primitive Obsession
judgment concerns numeric scope positions (`@(41)` / `@(41,42)`), an existing
pattern whose names could be mapped in a future cohesive catalog change. The
review checked the closed SYSTEM result and fixed Unicode alphabet/bound, ran
no tests or live operations, and acknowledged the user's focused-gate override.

**Spec axis:** pending fresh independent review; no pass is inferred from the
Standards result. Review the complete fixed-point diff and issue #144, including
the finite SYSTEM catalog, no-recovery BitLocker source choice, source semantics,
transport representation, controlled process limits and truthful #161 handoff.
