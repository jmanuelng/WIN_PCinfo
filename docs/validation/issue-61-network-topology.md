# Issue 61 validation: network topology and Local Only

This public-safe projection records release-owned contracts, synthetic validation, and a sanitized live outbound-trace validation. It contains no real adapter, address, route, resolver, proxy, VPN, product, connection, process, user, device, or organization identifier.

## Evidence

- The policy/schema tests close every collector, rule, and deferred probe over exact operation, source, execution context, privilege, network behavior, executable, dependency, side-effect, attempt, deadline, output, evidence, and cleanup bounds.
- The native-source test rejects DNS, socket, web, catalog, update, telemetry, packet-capture, credential, and network-configuration APIs. It also verifies that the source projects only the frozen local Windows properties and streams through the eight-item boundaries.
- Fourteen generated-artifact cases cover multiple adapters, IPv4/IPv6, disconnected profiles, active routes, resolver sets, proxy configuration, VPN/security registrations, existing connections, empty sources, malformed and denied sources, bounded partial results, explicit Local Only, and Unicode/non-English values.
- Every generated case reports `outboundRequestCount = 0`; all three network-dependent scopes remain `NotAttempted`; the canonical Assessment Record and beginner report validate; the Protected Evidence Package is created and reopened; and every validation-owned package/workspace is verified absent before the terminal record.
- Public-output assertions reject every seeded address/name family and publish only counts and typed states. Product names never become health or approval findings.

## Preliminary PID-correlated live trace

The issue owner explicitly authorized the previously blocked read-only elevated trace boundary. A bounded 16 MiB circular ETW session enabled only `Microsoft-Windows-Kernel-Network`, `Microsoft-Windows-TCPIP`, `Microsoft-Windows-Winsock-Sockets`, `Microsoft-Windows-Winsock-NameResolution`, and `Microsoft-Windows-DNS-Client`. The session was armed before either validation process began.

A dedicated standard-user loopback socket process ran first as a positive control. The observer correlated 243 events to that process, including Kernel Network send/connect activity, proving that process correlation and the relevant network providers were active. The exact release-owned Local Only collector then completed in 3,123 ms under its 5,000 ms deadline, passed the closed payload validator, reported zero outbound requests, and returned only after its Job-owned process tree was proved absent. The observer remained active for a final 250 ms after that proof.

The independent observer found zero directly collector-correlated DNS, name-resolution, Winsock, Kernel Network send/connect, or packet activity. Thirteen collector-correlated TCP/IP records were limited to event IDs 1066, 1319, and 1320; the installed Microsoft provider manifest identifies those as timer expiry, timer reschedule, and timer-fired bookkeeping rather than network requests. This establishes no directly PID-attributed collector traffic, but it is not the closure assertion: CIM, CDXML, and service-backed providers could delegate work to a Windows service with another PID.

The raw ETL, decoded CSV, provider list, process-correlation markers, and synchronization markers were deleted immediately after sanitization. A post-run boundary check found zero transient trace artifacts. The retained evidence contains only provider/event classifications and aggregate counts; it contains no process ID, endpoint, packet, address, name, or local topology value.

## Open closure evidence blocker

The remaining closure assertion must cover delegated Windows-service activity as well as the collector process. The proposed stronger validation uses two separate, bounded 16 MiB system-wide ETW sessions: an immediately preceding loopback-only calibration and a collector-only measurement window. The measurement accepts only zero total DNS, Winsock name-resolution/socket, and Kernel Network send/connect events across every process before, during, and after the collector attempt. Raw ETL/CSV material would be deleted immediately and only sanitized aggregate event classifications retained.

That trace can transiently contain unrelated applications' private network metadata. It is materially broader than the approved collector-PID trace and therefore requires explicit authorization before execution. Windows Sandbox is not currently available on this host, and enabling or installing it is not authorized. Until the maintainer explicitly approves this bounded system-wide trace (or supplies an already-approved disposable isolated Windows environment), issue #61 and PR #94 remain open and unmerged.

## Threat model and security review

This slice is a Security-sensitive Change because it crosses process, network, privacy, canonical-record, report, and package boundaries. The review traced these threats to code and tests:

- **Unapproved network activity:** a local provider might hide a name resolution or connection. The release catalog therefore admits only configuration/state interfaces; the source-safety test rejects DNS-resolution, socket, web, update, catalog, telemetry, and connectivity commands. The generated request count must remain empty and the three dependent scopes remain `NotAttempted`.
- **Wrong user or elevated context:** Current User proxy/VPN/profile state could describe the operator, alternate administrator, or SYSTEM instead of the Assessment User. The coordinator passes only the previously verified canonical SID; the child independently compares its actual SID and rejects elevated, different-user, and SYSTEM contexts before reading a source.
- **Arbitrary code or process escape:** a fixture or worker could try to choose script/executable content or survive cancellation. Only release-embedded source is encoded, the active Microsoft-signed PowerShell host is selected by the coordinator, and the Process Supervisor assigns the suspended child to a kill-on-close Job Object. Deadline or tree-absence uncertainty becomes typed cleanup failure and prevents normal packaging.
- **Untrusted worker output:** serialized output could smuggle extra properties, wrong primitive types, excessive items, secret material, or false Complete coverage. The coordinator applies exact shape, type, byte, count, context, and scope invariants, then copies admitted primitives into new coordinator-owned objects before canonical validation.
- **Privacy leakage:** exact addresses, endpoints, adapter/profile/product names, and configuration values could reach public stdout. These values are Restricted and remain inside the protected Assessment Record/report; generated tests reject seeded identifier families from progress, validation, completion, and terminal projections.
- **Misleading inference or mutation:** product registrations could be presented as health/approval, or observation could alter the network. Rules remain advisory, health inference is explicitly false, all write/prompt/install/download/self-elevation flags are frozen false, and source tests reject configuration-changing and packet-capture APIs.

The trust assumptions are Windows access-control enforcement, the already-verified Assessment User SID, the active Microsoft-signed PowerShell host, the Process Supervisor's Windows Job Object implementation, and the release-embedded policy/digest. Safe failure is explicit: an unavailable, denied, malformed, bounded, timed-out, failed, or cleanup-uncertain source cannot become a Complete absence claim; unrelated accepted scopes remain separately represented, and cleanup uncertainty prevents ordinary completion.

The independent Standards and Spec review required by the implementation workflow is recorded in the issue/PR closure trail. It verifies these threat mappings, public/private classification, and Local Only behavior against `CONTEXT.md` and issue #61 before merge.

Run `pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1` for the complete repository gate. The deterministic build evidence reports the generated artifact digest without publishing the ignored artifact itself.
