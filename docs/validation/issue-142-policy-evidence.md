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
a later identity result relabeling the earlier user policy.
Each has retained generated-record/report regression coverage. Test development
also caught setup-only anchor, fixture-marker, synthetic field-name and launch
composition failures; they are not passed collection evidence. An overlapping
test invocation was correctly rejected by the active-run lock and is rerun
serially, without weakening the lock.

Focused gate results, exact candidate digests and independent review dispositions
are recorded below after final validation. Whole-repository regression is reserved
for #158/final under the user's test-cadence override.

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
