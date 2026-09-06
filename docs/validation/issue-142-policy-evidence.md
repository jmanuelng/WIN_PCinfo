# Policy source and context implementation (#142)

Starting point: `6d5a753b786dfef928030d5f05ff50342dd936eb`. Dependencies #137
and #139 were merged before implementation; #141 is now merged. The work is
controlled-source implementation acceptance only. No live assessment, UAC,
SYSTEM task, policy change, directory call, signing or trust change was performed.

The repair uses the existing three policy layers, finite release source catalogs,
typed contracts, findings, encrypted package and HTML. It normalizes the cached
user RSoP SID namespace, verifies the requesting SID/session with local WTS/LSA
inside the already authorized privilege phase, and rechecks context after user
RSoP. Mismatched, changed, absent and denied user contexts retain scoped gaps
while computer policy proceeds. CIM references are read by exact class/key;
textual WMI references are parsed exactly. A policy with a similar ID cannot
donate its link or precedence, and a scope reference's display text is not its ID.

The worker reuses only the local portion of the identity native implementation.
The build projects reviewed source into the integrity-bound candidate resource; distributed
execution loads no external code file. The first whole-privilege regression caught
an exceeded Windows command-line limit. Source composition now compresses the
SYSTEM worker once together with its caller. An exact-source regression proves
that the outer launch minifier preserves the nested worker bytes. The launch bound remains unchanged.

Microsoft's [RSOP_GPO definition](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-gpo)
distinguishes the policy container key from its GUID and applicability. The
[RSOP_GPLink definition](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-gplink)
declares GPO/SOM references and applied order. The
[RSOP_PolicySetting definition](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-policysetting)
defines setting identity and precedence. The existing release guidance and
Windows 10/11 CSP catalog versions remain in force; the repair does not infer
tenant intent or expand the source catalog.

## Validation record

Tests use installed PowerShell Core 7.6.5 X64 and the shared test harness.
`PolicySourceApplication.Tests.ps1` substitutes OS boundaries in the generated
Comprehensive engine. Actual RSoP, SAM, audit, direct-right and security-option
normalization, supervised privileged/SYSTEM protocol, contracts, rule evaluation,
encryption, reopening, offline HTML and owned cleanup remain active. Other
capability owners retain synthetic prerequisite coverage. The test adapter is
not shipped as an application CLI or authorized live source.

Observed red cases: wrong user namespace; mismatched verified SID; user changing
during RSoP; substring link contamination; CIM scope display text in evidence; malformed references reported absent; and
a later identity result relabeling the earlier user policy. The final source
matrix also reproduced a denied CSP result query reported as Unavailable.
The correction preserves Denied with `POLICY.MDM_RESULT_QUERY_DENIED`, separate
from provider-discovery denial, through the closed SYSTEM validator and report.
Each has retained generated-record/report regression coverage. Test development
also caught setup-only anchor, fixture-marker, synthetic field-name and diagnostic
capture failures; they are not passed collection evidence. An intermediate
CSP correction used a provider-denial reason for a result-query failure and was
correctly rejected by the state-machine validator; the final distinct reason
preserves that rejection boundary. An overlapping
test invocation was correctly rejected by the active-run lock and is rerun
serially, without weakening the lock.

The 21 generated source scenarios passed: UserNamespace, ContextMismatch,
ContextDenied, ContextUnavailable, ContextChanged, DifferentSession,
ReferenceCollision, CimReference, SecurityDenied, SecurityAbsent, RightsBound,
MdmConflict, MdmWindows11, MdmDenied, MdmAbsent, MdmUnsupportedBuild,
MdmMissingProperty, MdmUnavailable, DomainPrecedence, MalformedReference and
LateIdentityChange. The first 13 passed at `38753e8`; the remaining eight passed
with the CSP correction subsequently committed as
`be67db049b41840ba1e9e53640a0f87f7ca1c065`. Per-case elapsed times were
21.2–23.4 seconds, including build and test overhead.

The following focused gates passed at the final application source commit
`be67db049b41840ba1e9e53640a0f87f7ca1c065`:

| Gate | Result |
| --- | --- |
| PolicyUserContextNativeSource | Native projection compiles without calls; source excludes directory-capable APIs; exact nested SYSTEM source survives launch minimization; eight fully configured launch samples passed, maximum 31,937 of 32,500 characters (2.4 s) |
| EffectivePolicyPolicy / PrivilegedCollectionPlanPolicy / SystemCollectionPlanPolicy | Closed catalogs, authority, scopes, bounds and exact payload digests pass (0.1 s each) |
| EffectivePolicy | Three-layer fixture semantics and privacy pass (2.2 s) |
| EffectivePolicyContract | Canonical record, coverage and bounded interpretation pass (29.7 s) |
| EffectivePolicyPrivilegedCollector | Closed privileged projection and fixture matrix pass (49.3 s) |
| PrivilegedCollectionPlan | All nine ownership, integrity, deadline, cancellation and cleanup scenarios pass (15.3 s) |
| SystemCollectionPlan | All twenty catalog, provenance, confinement, lifecycle and cleanup scenarios pass (16.2 s) |
| DeviceReadinessPolicy | Unchanged compact collector remains within 11,264-byte bound (0.7 s) |
| BuildDeterminism | Independent directories, line-ending normalization, embedded resources and standalone application checks pass (50.3 s) |
| StatusDeskEngine MdmDenied | Final result-denial reason and protected HTML assertions pass (21.1 s) |
| StatusDeskEngine RequireFrontLoadedPrivilege + AlternateAdministrator | Actual ordinary engine retains privilege-before-collection and initiating-user protected reopening under controlled alternate administration (15.6 s) |
| Syntax / oversized launch guard | Every changed PowerShell source/test/build file parses; an oversized high-entropy source is rejected before launch |

The unchanged IdentityEnrollmentPolicy gate also passed on `38753e8`. Live
native identity tests were not run. The existing generated policy fixture runner
passed Workgroup, Domain, UserAndComputerRsop, MissingRsop and StaleRegistry,
then exposed an outdated DeniedAdministrator expectation: after denied UAC the
frozen #139 path starts no SYSTEM operation, so the MDM finding is Indeterminate,
not Informational. Test-only commit `71f5edf` aligns this expectation and adds
an optional scenario filter for focused runs. The six remaining selected policy
cases passed in 72.9 seconds: DeniedAdministrator, DeniedSystem, NonEnglish,
AppliedOrderConflict, PartialChannel and NonMdm. Their generated validated
records, findings, privacy, encrypted packages and cleanup assertions all passed.
The changed selection runner also parses. Other capability fixture cases in that runner
are deferred to their owners/integrated regression rather than replayed here.

Exact unsigned candidate from application source commit `be67db0`:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| WIN-PCInfo.ps1 | 3,154,908 | `6eb9ad40d610821ace4ba4706a6632fbce797e6ea0895d8316a8e587b6daf525` |
| WIN-PCInfo-2.0.0-preview.1-portable.zip | 4,668,998 | `74211ce1ee65d327472c252f0670b50676dee97230996b7f067fe5a10b982ce2` |

Both artifacts match both deterministic-build copies by SHA-256. The package
content-tree identity is
`d9178e3a52d58cce4a4632f7aedb5bf539d0ef2127de75087c30346a0c308cea`.
The final evidence-only commit changes no application resource. These unsigned
candidate identities supersede earlier ticket candidates without renewing live,
signing, trust or release evidence. Controlled Comprehensive runs reopened the
protected report and verified owned cleanup; ignored synthetic build outputs
remain available locally. The separate frozen private #160 candidate is untouched.

Whole-repository regression remains reserved for #158/final under the user's
test-cadence override. No test duration or source-size pass establishes the real
application resource budgets. Historical #138 working-set measurements of
662–755 MiB remain above the provisional 512 MiB bound and are not waived.

## Standards review

Independent review of `6d5a753...38753e8`: zero hard violations and one
nonblocking judgment, possible Shotgun Surgery at the exact-text projector in
`Get-PolicyUserContextSource`. Future identity-source refactoring may need a
coordinated projector change; a composable shared WTS/LSA source unit could
reduce that coupling. The current checked anchors fail closed, and native
compilation plus exact nested-source preservation are tested. A broader
abstraction was not needed for this bounded repair.

Affected correction review of `38753e8..be67db0`: zero hard violations and zero
new judgments. Stable source-specific denial reasons, the finite validator
allowlist and test-only diagnostics preserve repository standards.
Final affected test/evidence review of `be67db0..71f5edf` and this evidence
found zero hard violations, zero new judgments and no actionable corrections.
The reviewer independently matched the current artifact sizes and SHA-256 values.

## Spec review

Independent review of `6d5a753...38753e8` found zero actionable findings,
missing implementation or scope creep in #142's bounded contribution.
Affected correction review of `38753e8..be67db0` also found zero actionable
findings. The denial repair preserves explicit coverage with a stable reason.
Both reviews leave live #161 comparisons and integrated #158 acceptance pending;
neither reviewer performed a live operation or presumed pending tests passed.
Final affected test/evidence review found zero actionable corrections and
required the six pending fixture results before closure; those subsequently
passed as recorded above. No additional code correction was needed.

## Requirement register contribution

| Requirement | Implementation contribution | Next owner |
| --- | --- | --- |
| #37 stories 31–34,38; CAP-0008, CAP-0016; CMP-0008, CMP-0020 | Local/Domain GP identity, exact references/precedence, local security and bounded SYSTEM CSP through the protected report | #161 private source/context comparisons |
| #37 stories 49–54,69; #134 GUI stories 19–24; CMP-0032, CMP-0033, CMP-0045 | Separate evidence layers, scoped gaps, advisory conflicts and tenant-side unknowns through contracts, findings and HTML | #151 cross-domain report; #158 integrated regression; #161 delivered-app acceptance |
| #37 sub-objectives 5,8,9 and full release scope | Existing safety, finite catalogs and required shared-component obligations retained; CMP-0061 remains deferred | Remaining capability owners and #158/#161 |
| One-UAC ownership, Local Only and quality budgets | Privilege-before-collection and initiating-user package ownership retained; no remote identity resolution or mutation added | #148/#161 real attribution/context; #158/#161 exact final candidate and resource budgets |

The [private source checklist](issue-142-readonly-comparison.md) is pending #161.
Parent #134/#37 are unchanged. September 6 remains the complete private handoff
target. Synthetic implementation acceptance is neither the real GUI-to-HTML
milestone nor application/release acceptance, signing approval or publication.
