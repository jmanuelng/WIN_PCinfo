# Issue 51 validation projection

This public projection contains release-owned contracts and identifier-free synthetic/native validation outcomes only. It contains no account, domain, tenant, device, session, recipient, path, package, or real Assessment Record value.

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Frozen authority | Three collectors, four Evidence Scopes, three Rule Evaluations, and four Tenant-side Discovery Task definitions validate against the release schema and immutable Preparation Plan. |
| Structured sources | The read-only native boundary uses `NetGetJoinInformation`, `NetGetAadJoinInformation` (`S_FALSE` means absent; `S_OK` requires a non-null structure), Terminal Services, and local LSA logon-session APIs; no localized command output, domain-capable name lookup, or tenant authentication is used. |
| Hard rule bounds | Three fixed rule evaluators run in supervisor-owned Microsoft-signed children; a forced 30-second stall is terminated at the frozen two-second deadline with complete tree absence. |
| Context separation | The live source requires complete WTS active-session enumeration plus a matching SID from local LSA logon-session data, compares that SID to the process token only for a relationship, rejects elevated/SYSTEM source execution, and keeps the privileged and SYSTEM collectors separate. Synthetic boundary cases prove explicit gaps. |
| Privacy | All eleven new values are Restricted; generated public output is checked for synthetic account, domain, tenant, and device markers. |
| Canonical evidence | The additive Contract Set 1.2 profile validates two subjects, eight scopes, 36 observations for the complete case, ten findings, and bounded discovery references. |
| Generated application | Thirteen closed cases exercise Preparation, device/firmware prerequisites, identity/SYSTEM sources, record, report, package reopen, terminal result, and verified cleanup. |
| Live shape | One unelevated read-only local probe validates the native payload and emits only an identifier-free PASS result; it is not a managed-environment support claim. |

No fixture can supply an identifier, command, script, executable, source path, credential, network permission, elevation authority, or device mutation. Missing, malformed, denied, and prohibited process contexts remain explicit coverage gaps.
