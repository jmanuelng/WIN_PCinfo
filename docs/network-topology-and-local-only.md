# Local network topology and Local Only

This preview slice records a bounded view of local Windows network configuration after the operator approves the Preparation Summary. The worker reads adapters, configured IP addresses and resolvers through `System.Net.NetworkInformation`; connected profiles through Network List Manager; IPv4 and IPv6 routes through IP Helper; Current User proxy and bounded RAS phonebook settings through read-only local files/registry; and existing TCP endpoints through the local IP tables. It does not activate the PowerShell networking modules or CIM providers that failed isolated Local Only validation. Windows Security Center inventory has no approved provably offline live interface in this release, so that scope is reported `Unsupported` instead of activating its provider.

Each source has a fixed property list, an eight-item ceiling per Evidence Scope, one 30-second attempt, compact UTF-8 JSON transport, a 256 KiB fail-safe process-output ceiling, and verified Job Object cleanup. The transport limit is derived rather than calibrated from one machine: at most 28,672 admitted UTF-8 string bytes, multiplied by JSON's worst six-byte control-character escape, plus 32,768 bytes for fixed property names, numeric primitives, arrays, and framing gives 204,800 bytes; the release rounds that once to the next power of two, 262,144 bytes. An exact-bound valid JSON fixture passes and a one-byte-over valid fixture fails before parsing or evidence admission.

## What Local Only proves

`LocalOnly` means the assessment makes zero DNS, TCP, TLS, HTTP, catalog, update, and telemetry requests. The collector reads already-local state only. It never resolves a name, opens a socket, connects a VPN, contacts a proxy, refreshes a profile, enumerates packet payloads, or captures traffic. Three future network-dependent scopes—Microsoft management connectivity, enrollment DNS, and TLS trust—remain `NotAttempted` with `NETWORK.LOCAL_ONLY_NOT_ATTEMPTED`. That state is not success, failure, absence, or a hidden probe.

Local configuration cannot prove external reachability, authorization, service health, certificate trust, tenant assignment, or Microsoft endpoint availability. To request those facts, start a new Preparation Summary using the separately approved Microsoft Connectivity Enabled mode; approval for Local Only cannot be widened after collection starts.

## Reading the report

The report distinguishes local-source coverage from network-dependent coverage. Complete means the cataloged local source completed within its bound. Partial, Denied, Malformed, Unavailable, TimedOut, Cancelled, or Failed identifies the affected scope without discarding successful unrelated scopes. An empty Complete scope can establish that the cataloged local source returned no items; an incomplete scope cannot establish absence.

Adapter, profile, address, route, resolver, proxy, VPN, product-registration, and connection values are Restricted Diagnostic Evidence. Exact values remain only in the encrypted report and canonical Assessment Record. Public progress, validation, and terminal records contain counts, state names, stable reason codes, and booleans only. The collector excludes MAC addresses, interface GUIDs, process IDs, packet contents, Wi-Fi keys, stored credentials, proxy credentials, VPN credentials, and traffic payloads.

VPN and security-product names are inventory facts only. Their presence, name, or Windows registration state does not prove that they are healthy, approved, configured correctly, enforcing policy, or suitable for a target environment.

## Safety and troubleshooting

WIN-PCInfo does not enable, disable, connect, disconnect, reset, renew, repair, flush, add, delete, or otherwise change adapters, routes, addresses, resolvers, proxies, VPNs, firewall settings, connection profiles, or network services. A denied, unsupported, malformed, bounded, or failed source remains an explicit coverage gap. Current User RAS registration can report its configured endpoint and strategy, but the approved offline phonebook source cannot prove current connection status; that field remains source-reported unknown. Retry only after confirming the approved Assessment User Context and local permissions; do not weaken network controls or disclose the encrypted evidence publicly merely to obtain Complete coverage.

Repository maintainers can reproduce the focused and generated checks with:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/NetworkTopologyPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/NetworkTopology.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/NetworkTopologyNativeSource.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/NetworkTopologyContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/NetworkTopologyApplication.Tests.ps1
```

The fixtures are synthetic and do not claim facts about the test computer. See [issue #61 validation evidence](validation/issue-61-network-topology.md) for the public-safe evidence projection.
