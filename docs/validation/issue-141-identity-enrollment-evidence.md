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

At the implementation commit, the 24-case source matrix and remaining focused
regressions are in progress. Identity, administrator, privileged and SYSTEM
release-policy checks and changed PowerShell parser checks pass. Final outcomes,
candidate digests and the separate Standards/Spec reports will be recorded in
the evidence completion commit. The whole repository suite is deliberately
reserved for #158/final integration under the latest user test-cadence override.

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
