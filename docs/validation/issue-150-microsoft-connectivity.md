# Approved Microsoft connectivity implementation (#150)

Starting revision: `6ba3a8f88ddb9d9038024bf0bb68d8d69146b56e`. All native
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
proxy routes. Changed/unavailable context suppresses new work. PAC/WPAD is not
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
A test-only byte-array adapter and an implementation rename temporarily failed;
both were corrected before acceptance. A build during a policy/schema edit
correctly rejected the intermediate incomplete schema; the closed schema was
updated before subsequent generated cases. These are not live evidence.

| Gate | Status |
| --- | --- |
| ConnectivitySourceApplication | Pass: Direct, WindowsProxy, ProxyOnly, Suspected, Blocked, Partial, DnsFailure, Timeout, InvalidChain, Redirect, ProxyBlocked, AutomaticProxy, ContextChanged, LocalOnly; approximately 21–23 seconds per case |
| ConnectivityHttpBoundary | Pass: 407, 204, 302, 307, 503, timeout, oversized headers; one send only; no credentials/cookies/body/redirect/downloads; transport/response disposal |
| ConnectivityContextBoundary | Pass: malformed flag/type/blob, PAC URL, WPAD bit and static proxy; all owned registry objects disposed |
| SchemaContracts / PreparationSummary | Pass: both network modes, closed preparation plan and accepted/declined request parity |
| StatusDeskEngine enabled decline | Pass: no protocol entry or package before/after declined consent |
| MicrosoftConnectivity / MicrosoftConnectivityPolicy / LocalOnlyRequestBoundary | Pass: existing fixture semantics and instrumented LocalOnly no-request branch |
| Existing generated fixture matrix / final build evidence / independent reviews | Pending final execution and review below |
| Whole repository regression / live acceptance | Pending #158/#161/#162 under the user's focused per-ticket test cadence |

No shared privileged/SYSTEM composition or existing inline limits were edited.
Synthetic packages and plaintext viewing use verified owned cleanup. Ignored
unsigned build outputs are retained locally; no private real records are published.

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
