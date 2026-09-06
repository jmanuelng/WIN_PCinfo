# Approved Microsoft connectivity implementation (#150)

Starting revision: `6ba3a8f88ddb9d9038024bf0bb68d8d69146b56e`. Final application
revision: `77f3f35841f17ae155588fc59b024e44c67c68c3`. All native
blockers are merged and closed; #149 merged during this slice through PR #175,
merge `548696d3122b47293ba628a628dc4aad8ab02485`. This slice uses controlled
protocol and local-context adapters only. No live assessment, endpoint probe,
certificate/key creation, trust modification, UAC, observer activation, cloud
operation, signing or publication is authorized or represented by these results.

The existing Comprehensive engine, three generic endpoint catalog, eight protocol
scopes, typed record, rules, encryption and report remain in use. Preparation
freezes the full release policy and a private local resolver/static-proxy snapshot;
the public plan binds that snapshot with a per-preparation nonce and digest. The
GUI lists each exact target, protocol, port and HEAD URI with the request, time,
redirect and credential limits. Raw proxy and resolver identifiers remain worker
private. Local Only captures no connectivity context and invokes no protocol.

Every new logical protocol hop compares the policy against the embedded allowlist
and rechecks visible active-interface DNS configuration and current-user static
proxy routes, including resolver order. Changed/unavailable context suppresses new work. PAC/WPAD is not
evaluated, and malformed proxy flag/types/connection blobs fail closed. The
Windows connection-settings byte array is preserved so its automatic-discovery
flags can actually be checked. HTTP uses the frozen explicit static proxy or
direct selection. It cannot consult automatic proxy discovery after approval.

Direct TCP follows successful DNS, direct TLS follows successful TCP, and direct
HTTP follows successful TLS. A configured static proxy may still complete HTTP
when the direct path is blocked; that preserves useful proxy evidence while TLS
inspection remains Indeterminate. HTTP 401/403/407/429 is Blocked, other non-2xx
non-redirect responses are Failed, and redirects are rejected without another
request. Bounded exception unwrapping retains timeout and socket-denial states.
HTTP-path CertificateChainInvalid and TlsAuthenticationFailed preserve distinct
certificate-chain and other TLS authentication failures without overwriting the
direct-path fields. An uncaptured HTTP certificate remains null, preventing a
transport failure from becoming a whole-payload invalid empty fingerprint.
No failure is expanded into an unrelated local-scope failure.

The unchanged limits allow at most 12 logical protocol attempts, 5 seconds per
phase within a 45-second collector window, eight retained DNS addresses/elements,
32 HTTP header entries, 16 KiB response headers, zero response-body bytes and zero
redirects. Context-check time is deducted before dispatch. Windows owns delegated
name resolution and transport internals: this count is not a packet count or a
measured zero-egress result. Visible DNS/proxy snapshot checks do not claim a
complete freeze of NRPT, DoH, WinHTTP/service settings or all Windows routing
policy. Generic enrollment/registration targets do not prove tenant CNAMEs,
authorization, onboarding or regional service health.

The production observation reducer yields Suspected for differing completed
paths, NotObservedWithinCompletedTests for matching completed paths, and
Indeterminate for incomplete evidence. Confirmed remains supported by the
existing controlled record/fixture with independent proxy-policy corroboration;
the actual source does not invent such corroboration from certificate differences.

## Controlled validation

Installed PowerShell Core 7.6.5 X64 runs the existing generated-app harness.
ConnectivitySourceApplication executes the actual preparation, ordinary scheduler
and connectivity reducer with DNS/TCP/TLS/HTTP and local-context boundary adapters.
It validates the canonical protected record, eight scopes, advisory findings,
reopened HTML and owned cleanup. There is no shipped adapter CLI and no fixture
authorization for real network work. ConnectivityHttpBoundary executes the actual
HTTP phase with controlled .NET transport objects; ConnectivityContextBoundary
executes the actual current-user proxy parser with controlled registry objects.

Red cases observed: enabled preparation lacked bound resolver/proxy context;
HTTP 407 was reported Succeeded; wrapped timeout became Failed; malformed proxy
flags authorized direct traffic. The corresponding behavioral regressions pass.
Spec review added red cases for resolver-priority changes retaining the same
digest and proxy-path certificate rejection losing its cause; both now pass.
The generated proxy case exposed the null-fingerprint bug, also fixed test-first.
A test-only byte-array adapter and an implementation rename temporarily failed;
both were corrected before acceptance. A build during a policy/schema edit
correctly rejected the intermediate incomplete schema; the closed schema was
updated before subsequent generated cases. These are not live evidence.

| Gate | Status |
| --- | --- |
| ConnectivitySourceApplication | Pass: all 16 scenarios across initial/correction runs: Direct, WindowsProxy, ProxyOnly, Suspected, Blocked, Partial, DnsFailure, Timeout, InvalidChain, Redirect, ProxyBlocked, AutomaticProxy, ContextChanged, LocalOnly, ProxyInvalidChain, ProxyTlsFailure; 21.3–23.0 seconds per case. Final proxy failures and ContextChanged passed after corrections |
| ConnectivityHttpBoundary | Pass: nine actual-phase cases: 407, invalid chain, other TLS authentication rejection, 204, 302, 307, 503, timeout, oversized headers; one send only; no credentials/cookies/body/redirect/downloads; null fingerprint and transport/response disposal |
| ConnectivityContextBoundary | Pass: malformed flag/type/blob, PAC URL, WPAD bit and static proxy; all owned registry objects disposed; actual resolver reducer detects reversed server order |
| SchemaContracts / PreparationSummary | Pass: both network modes, closed preparation plan and accepted/declined request parity |
| StatusDeskEngine enabled decline | Pass: no protocol entry or package before/after declined consent |
| MicrosoftConnectivity / MicrosoftConnectivityPolicy / LocalOnlyRequestBoundary | Pass: existing fixture semantics and instrumented LocalOnly no-request branch |
| MicrosoftConnectivityApplication | Pass: all 14 existing fixtures plus LocalOnly collapse; canonical record, report, encrypted package reopening and cleanup. Confirmed is controlled fixture evidence only |
| MicrosoftConnectivityContract | Pass: canonical typed source evidence, coverage, traceable interpretation and earlier resource/network/software dependency contracts |
| BuildDeterminism | Pass on final application revision: two output directories, LF/CRLF source mirrors, exact provenance, relocated device/software/certificate application execution |
| Changed executable syntax / diff whitespace | Pass before and after review corrections |
| Whole repository regression / live acceptance | Pending #158/#161/#162 under the user's focused per-ticket test cadence |

No shared privileged/SYSTEM composition or existing inline limits were edited.
Synthetic packages and plaintext viewing use verified owned cleanup. Ignored
unsigned build outputs are retained locally; no private real records are published.

An initial BuildDeterminism relocated-device assertion failed while another
generated assessment test was active. The same source passed a serialized rerun;
the final corrected source also passed serialized. The initial terminal details
were not retained, so shared run-lock contention is a likely cause, not a proven
diagnosis. Generated assessments must be serialized; deterministic construction
does not waive the single-active-run boundary.

Exact unsigned candidates from `77f3f35`:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| WIN-PCInfo.ps1 | 3,173,342 | `07f4d669f08556d23149897e3f86b4c9912198fd68b3ef9ec98820c34ab1527c` |
| WIN-PCInfo-2.0.0-preview.1-portable.zip | 4,696,499 | `93934dc2098a62446f4a1e6340cf91307621ae16c45965f91ec1bc8f097d667b` |

Both match both independent deterministic-build copies in length and digest.
Validation documents are excluded from the portable content tree; this final
evidence-only edit does not change the recorded application/package bytes.

## Standards review

Independent fixed-point review `6ba3a8f...9114d42`: zero hard documented-standard
violations; one nonblocking possible Duplicated Code judgment for repeated
per-protocol context/deadline guards. It is retained as an explicit judgment;
the separate direct/proxy prerequisites remain visible. Correction review
`9114d42...77f3f35`: zero hard violations or new actionable smell findings.
Both controlled context/HTTP boundary tests passed independently. No review
performed a live operation or modified source.

## Spec review

Fresh independent review found two actionable issues: DNS priority was hidden by
sorting, and proxy-path TLS/chain failure lost attribution. Both were corrected
and independently re-reviewed at `77f3f35`, with zero residual actionable
findings or scope creep. Both permitted boundary tests passed independently.
A retained-agent capacity limit prevented parallel reviewer creation, so the
axes and correction reviews ran serially. No prior-ticket review context was
reused and neither axis was omitted. Whole-repository and live gates remain
pending as listed above.

## Requirement register contribution and next owners

| Requirement | Implementation disposition | Next owner |
| --- | --- | --- |
| #37 stories 22–26, 45–46, 48–54, 66–67, 69; CAP-0012/CAP-0013; #134 GUI stories 5, 7–8, 19–24 | Controlled implementation coverage as above; exact-context consent, scoped connectivity evidence, conservative interpretation and protection retained | #158 aggregates this contribution and full integration; #151 owns broader report follow-up |
| Real Local Only and Microsoft Connectivity Enabled runs | Pending; use the same Comprehensive profile, exact generated personally admitted candidate, upfront consent, context display, both direct/static proxy where available, denial/partial/timeout/redirect and private report checks | #161, with observer attribution still Blocked as recorded by #148/#160 |
| Fresh-client network scenarios | Pending; both product modes, restricted/full-outbound validation controls, configured proxy and TLS-inspection scenarios, non-English client, private artifacts and verified cleanup | #162 |
| Live TLS inspection confirmation | Pending independent attributable policy/path evidence; differing certificates alone cannot confirm inspection | #161/#162 |
| Exact candidate signing, release and acceptance | Pending, no future-source signature inferred; the separate frozen #160 candidate is untouched | #155/#158/#161/#163/#164 |
| Real quality/resource acceptance | Pending; historical #138 working-set excess and mandatory real quality gates remain unwaived | #158/#161 |

September 6 remains the private handoff target. Controlled implementation closure
does not establish a real assessment milestone, full application acceptance, a
qualifying Azure round, release qualification or completion of #134/#37.
