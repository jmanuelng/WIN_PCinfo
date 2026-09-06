# Private policy/source comparison for #161

This procedure is unexecuted. #161 owns the exact personally signed candidate,
the authorized device/session cases and the approved private destination outside
the repository. This checklist grants no live collection, UAC, policy changes,
signing, trust changes, authentication or network authority. September 6 remains
the private handoff target. Public qualification and the full #37 scope remain
separate obligations.

1. Record candidate SHA-256, source revision, installed runtime, Windows
   build, profile, network behavior, frozen administrator/SYSTEM plan and local
   package protection scope privately. Approve the existing complete Preparation
   Summary once. Preserve the initiating user's protection under alternate-admin
   elevation. No tool or Windows Feature is installed during assessment.
2. Use available, authorized workgroup/domain and MDM/non-MDM Windows 10/11
   clients. Do not join, enroll, switch policy, refresh GP or manufacture a
   missing/denied source merely to create a test case. Missing environments are
   Blocked or pending, never Passed by a fixture.
3. Compare the following finite read-only sources close to collection time.
   Record selected fields and return dispositions only; no policy dumps,
   recursive group expansion, directory translation or remote organization query.

| Source/context | Required comparison |
| --- | --- |
| Local WTS/LSA active session | Confirm the requesting SID and coordinator session agree with the unique active Assessment User before and after user RSoP. Different, ambiguous, denied or changing context must not substitute the coordinator or alternate administrator. |
| Cached `root/RSOP/User/S_...` and `root/RSOP/Computer` | Compare cataloged `RSOP_GPO` identity/applicability, exact `RSOP_GPLink` GPO/SOM references and `RSOP_RegistryPolicySetting` object identity/precedence. Confirm user and computer targets, Local versus Domain origins, disabled links and missing classes remain distinguishable. An empty successful query differs from denial/missing namespace. |
| Local SAM NetAPI levels 0 and 3 | Compare password and lockout fields independently. These describe local accounts only; they do not establish domain-account policy. One failed level must preserve the other. |
| Three Audit API subcategories and three direct LSA rights | Compare the versioned finite catalog. Keep direct SIDs private, never expand assigned groups, and retain Partial coverage above eight principals. Denied audit/rights are coverage gaps. |
| Three security-option registry signals | Compare exact catalog values and missing values. Registry configuration has Unproven attribution; neither current values nor a stale upstream signal establishes applied organizational GP, CSP assignment or enforcement. |
| Frozen SYSTEM MDM Bridge result operation | Compare the provider prerequisite, build-selected Windows 10/11 catalog, three fixed Policy/Result nodes and seven fields. Administrator access alone is insufficient. Missing build, provider, class, node, property, wrong context and denial must have their own scope/reason. No tenant intent is inferred. |
| Conflicting sources | Compare observed GP setting precedence separately from registry/CSP disagreements. Confirm conflicts are advisory NeedsAttention with linked evidence and tenant-side assignment/precedence questions. Missing evidence must remain Indeterminate. MDMWinsOverGP must not become a blanket winner for every setting/channel. |
| Final record/package/HTML | Trace observations, provenance, coverage, findings and recommendations through validated records, initiating-user encrypted packaging, protected reopening and readable offline HTML. Applied Policy Evidence, Configured Policy Signals and Current Control State must remain separately labeled. Confirm exact-value links and explained limitations, without public identifiers. |

Record expected/observed values privately, source/context/version, elapsed time,
result as Pass/Fail/Blocked or justified NotApplicable, and cleanup disposition.
Retain recoverable protected evidence if cleanup cannot be proven. Report only
sanitized outcomes/counts publicly. No LGPO, RSAT, PsExec, Windows Feature
installation, policy mutation or live tool acquisition is part of this procedure.
Measured Local Only attribution remains #148/#161; final integrated regression
and exact-candidate resource acceptance remain #158/#161. Short synthetic passes
do not waive the historical #138 working-set excess or prove live performance.
