# Identity, enrollment and administrator evidence (#141)

Implementation starts at `9abfb1e17c2d3c9d9f7c633cfa31d284b8808ec7` on the
integration branch. Dependencies #137 and #139 are closed; #140 is integrated.
This record concerns controlled-source implementation acceptance. No live
assessment, UAC, SYSTEM task, signing, trust change, directory query or tenant
authentication was performed. Private source comparisons remain pending #161.

## Repairs and evidence boundaries

- Work-account admission requires the querying process to match the verified
  Assessment User SID and logon session. Missing verification skips the
  user-scoped attempt with an explicit reason. A second session check prevents
  changed or denied context from supplying account evidence.
- The default Entra join query can return a device join instead of separate
  work accounts. That case retains the device join but leaves work-account
  coverage unavailable. Successful no-join results are distinct from denial,
  unknown join types, API failure and malformed results. Missing identifiers
  remain unknown rather than becoming empty strings or false absence.
- Local administrator lookup/query exceptions produce a scoped failure while
  preserving unrelated privileged evidence. Direct SID membership remains
  bounded to eight entries, with explicit Partial coverage; no nested expansion
  or domain-capable account-name resolution was added. Unresolved names are
  unknown. A healthy or empty complete group produces informational advice.
  Complete zero-member coverage requires an observed count of zero and complete
  enumeration. Its exact field set excludes principal fields; retained member
  evidence cannot masquerade as an empty group.
- SYSTEM MDM provider access denial survives the closed worker protocol as
  Denied, separately from Unavailable and observed provider absence. Dependent
  policy fields inherit that prerequisite state; no new policy query was added.
- Six Tenant-side Discovery Tasks cover tenant assignment, compliance,
  licensing, enrollment intent, approved administrator context and recovery
  escrow. The administrator task also links to the direct-membership finding.
  No local observation asserts these organization facts or contains recovery
  material. HTML explains device-default account ambiguity and SYSTEM limits.

The source semantics follow Microsoft's [NetGetAadJoinInformation contract](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation):
the returned default can describe the joined device or one current-user work
account, and a null result can represent no join. This is not a complete account
inventory or proof of enrollment. WTS/LSA verification remains local, with no
directory translation; measured Local Only attribution remains #148/#161.
The documented [DSREG join enum](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/ne-lmjoin-dsreg_join_type)
assigns zero to Unknown. The corrective Spec review caught the initial mapping
of a present zero-valued structure to None. Both source mappings now preserve
Unknown, while only an absent structure proves no default join. The controlled
enum-zero case failed with Complete coverage before the correction and passes
with Unavailable coverage and an Indeterminate rule afterward.

## Focused validation

Tests use installed PowerShell Core 7.6.5 X64 through the shared harness. The
new `tests/IdentitySourceApplication.Tests.ps1` runs the generated Comprehensive
engine with test-only OS adapters. They replace native snapshot reads, the
NetAPI membership boundary and the SYSTEM provider read, including the embedded
activation broker's exact source digest. The real scheduler, frozen privilege
plan, supervised workers, authenticated protocol, contracts, rules, encryption,
protected reopening, offline HTML, Completion Summary and cleanup remain active.
No adapter or source override is exposed by the distributed application's CLI.

Observed red cases include separate-user work-account substitution, device-join
false negative, unknown native join enums interpreted as informational,
successful no-join reported malformed, administrator query exception aborting
the privileged phase, SID-only unresolved names reported absent, SYSTEM denial
reported unavailable, and missing scoped administrator/escrow tasks. Each has a
retained generated-application regression. During fixture development, an
unreachable C# branch and unrefreshed worker digests caused test/setup failures;
those were corrected without weakening admission. They are not source successes.

The source matrix covers 24 named scenarios. The first 19 cases passed at
`1f35c700dd7c7c168cbfd6724839bb71858f0dd8`; the subsequent observed-empty-group
case exposed a validator failure. After that repair and the enum-zero review
correction, 10 affected or remaining cases passed at
`8993440c41bd8a1e1414df5730cd0d808a6ee9cf`: UnknownJoin, Workgroup, NoJoinSuccess,
Registered, EntraJoined, AdminEmpty, AdminPartial, SystemDenied,
SystemUnavailable and SystemAbsent (22.4–24.5 seconds each). This is a passing
24-scenario coverage set with targeted corrective regression, not a claim that
all 24 were rerun against one unchanged source revision.

The whole repository suite remains reserved for #158/final integration under
the latest user test-cadence override. Completed focused gates are:

| Gate | Result |
| --- | --- |
| IdentitySourceApplication | All 24 named scenarios have passing controlled-source evidence, with the corrective-run distinction above. Covers workgroup/domain/registered/Entra, denied/unavailable/malformed/missing native data, changed/different session and user, administrator/SYSTEM context, bounded/empty/denied administrator enumeration, and SYSTEM denied/unavailable/absent provider. |
| IdentityEnrollmentPolicy, AdministratorExposurePolicy, PrivilegedCollectionPlanPolicy, SystemCollectionPlanPolicy | Pass; closed release definitions, source/worker identities, authority and field/task bounds. |
| IdentityEnrollmentContract, AdministratorExposure | Pass; native snapshot normalization and direct-membership semantics. |
| ContractValidator | Pass; generated record admission and malformed encoding, JSON, depth, size, numeric, version, feature, privacy, reference, cycle, coverage and field-bound rejections. |
| ContractSemanticMatrix | Pass; 18 semantic state/reference/incomplete-record negatives and locale handling. |
| IdentityEnrollmentRecord | Pass, 5.8 seconds; canonical subjects, observations, provenance, findings and six scoped tasks. |
| AdministratorExposureContract | Pass, 6.4 seconds; canonical direct-membership record and contradictory zero-count rejection. |
| IdentityEnrollmentApplication | Pass, 13 existing generated application scenarios, 130.8 seconds; Automation output, context coverage, protected package/report verification, identifier omission and cleanup. |
| SystemCollectionPlan | Pass, 20 controlled protocol, provenance, confinement, lifecycle and cleanup cases, 16.7 seconds. |
| BuildDeterminism | Pass, 51.0 seconds; exact provenance, different output directories and checkout-text consistency. |
| Parser/type boundary | All 14 changed PowerShell files and the final generated candidate parse. Actual native C# compiles without calling Windows sources. Runtime contract tests above check typed evidence. |
| Diff/source bound | Whitespace check passes. Compact device source remains 11,254 bytes within the unchanged 11,264-byte bound. |

The live portion of `IdentityEnrollmentNativeSource.Tests.ps1` was deliberately
not executed. The replacement evidence is controlled source adapters plus
native compilation, not a live Windows-source claim. Durations include test,
build and control overhead; they are not performance-budget acceptance. The
Comprehensive cases exercised protected reopening and removed their exact owned
run workspaces. Only ignored synthetic test/build outputs remain for local
audit; no unrelated artifacts or private candidate were modified.

Exact unsigned candidate from source commit
`8993440c41bd8a1e1414df5730cd0d808a6ee9cf`:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| WIN-PCInfo.ps1 | 3,098,810 | `e589901a6ea85d599a5de49fdd84260b76a27398f3fc556a91003d196be1da81` |
| WIN-PCInfo-2.0.0-preview.1-portable.zip | 4,612,763 | `b017f10d6d40b8f6756d07c60e238ba26ec87e65eddb2adb7f0df3b07721bfd7` |

Both artifacts match both independent deterministic-build copies by SHA-256.
The package content-tree identity is
`0e5769480df40eca293094fd61927660909c0b3bd4217c1f54576b0b77f251aa`.
These changed-source digests supersede historical unsigned ticket candidates;
they do not renew live, signing, trust or release evidence. The final completion
commit only updates this evidence and does not change application resources.

## Standards review

The independent Standards reviewer examined the diff from the fixed start
through the implementation and corrective commits: zero documented-standard
breaches and zero blocking findings. Three nonblocking heuristic judgments
remain: possible duplication of the before/after SID/session predicate,
test-only privileged policy digest refresh, and the two native join mappings.
The separate phase checks and small source mappings remain explicit; no shared
abstraction or broader rewrite was needed for this slice.
Final evidence-only review found zero new Standards findings.

## Spec review

The independent Spec reviewer initially found one blocking P2: a present
documented enum-zero join structure was interpreted as no join. Corrective
review at `8993440c41bd8a1e1414df5730cd0d808a6ee9cf` found zero remaining
code findings, verified the enum distinction and narrow observed-empty-group
validator correction, and found no scope creep. Private source comparison,
final integrated acceptance and measured resource gates remain pending their
assigned tickets, not waived by these reviews.
Final evidence-only review found zero Spec findings or blockers.

## Requirement register contribution and next owners

| Requirement | Contribution | Remaining owner |
| --- | --- | --- |
| #37 stories 29–30; CAP-0005–0007, CAP-0016 | Actual identity/context, administrator and SYSTEM source paths through the generated protected report | #161 private source comparison and real contexts |
| #37 stories 49–54 | Distinct observation/coverage/finding semantics; linked advisory interpretation and scoped tenant tasks | #151 full cross-domain report review; #158 integrated regression; #161 human usefulness |
| #37 stories 58, 66–67, 69 | Existing initiating-user protection and one privileged phase retained; no directory resolution/secret collection added; synthetic Unicode and denied contexts | #161 real alternate-admin/SYSTEM, locale, protection and cleanup |
| #134 GUI stories 12, 19–25; CMP-0005–0007, CMP-0018–0019, CMP-0032–0033, CMP-0045 | Source-adapter-to-record/package/HTML/Completion Summary contribution | Shared components remain allocated to their other owning tickets; #153/#158/#161 complete UI and acceptance |
| User-target privileged RSOP identity | Existing coordinator SID precedes the later WTS/LSA Assessment User verification | #142 owns source-specific user-policy context repair, preserving #139 one-UAC ordering |
| Exact private acceptance and resource budgets | No live claim; no waiver of historical #138 working-set excess | #158 final candidate/integrated gate; #161 complete delivered-app measurements |

The [unexecuted private procedure](issue-141-readonly-comparison.md) names the
source and context comparisons for #161. Parent #134/#37 remain untouched.
September 6 remains the private handoff target; synthetic acceptance is neither
the real GUI-to-HTML milestone nor release qualification/publication.

### Precise #142 policy context handoff

Code inspection found that `src/DeviceReadiness.ps1:2360` reads the coordinator
token and passes its non-admin, non-SYSTEM SID to the privileged plan at line
2371, before later WTS/LSA Assessment User verification. The serialized value
reaches `Get-LiveEffectivePolicyResult` in
`src/PrivilegedCollectionPlan.ps1:2129`; lines 1280–1305 use it to select
`root/RSOP/User/<SID>` or mark user policy unavailable. A different non-admin
coordinator can therefore select its own cached user policy, and an elevated
coordinator supplies an empty SID even when an Assessment User might later be
verified. This finding is inspected source behavior, not a controlled RSOP
reproduction or live observation. #142 owns the source-specific context repair
and its controlled tests, preserving #139's privilege-before-collection and
single-UAC ordering. No policy-source repair was added to #141.
