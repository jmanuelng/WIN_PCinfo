# Issue 61 validation: network topology and Local Only

This public-safe projection records release-owned contracts and synthetic validation. It contains no real adapter, address, route, resolver, proxy, VPN, product, connection, user, device, or organization identifier.

## Evidence

- The policy/schema tests close every collector, rule, and deferred probe over exact operation, source, execution context, privilege, network behavior, executable, dependency, side-effect, attempt, deadline, output, evidence, and cleanup bounds.
- The native-source test rejects DNS, socket, web, catalog, update, telemetry, packet-capture, credential, and network-configuration APIs. It also verifies that the source projects only the frozen local Windows properties and streams through the eight-item boundaries.
- Fourteen generated-artifact cases cover multiple adapters, IPv4/IPv6, disconnected profiles, active routes, resolver sets, proxy configuration, VPN/security registrations, existing connections, empty sources, malformed and denied sources, bounded partial results, explicit Local Only, and Unicode/non-English values.
- Every generated case reports `outboundRequestCount = 0`; all three network-dependent scopes remain `NotAttempted`; the canonical Assessment Record and beginner report validate; the Protected Evidence Package is created and reopened; and every validation-owned package/workspace is verified absent before the terminal record.
- Public-output assertions reject every seeded address/name family and publish only counts and typed states. Product names never become health or approval findings.

## Threat model and security review

This slice is a Security-sensitive Change because it crosses process, network, privacy, canonical-record, report, and package boundaries. The review traced these threats to code and tests:

- **Unapproved network activity:** a local provider might hide a name resolution or connection. The release catalog therefore admits only configuration/state interfaces; the source-safety test rejects DNS-resolution, socket, web, update, catalog, telemetry, and connectivity commands. The generated request count must remain empty and the three dependent scopes remain `NotAttempted`.

## Open closure evidence blocker

The issue requires an independent outbound-capture assertion before, during, and after the real local-source attempt. That evidence is `NotStarted` in this standard-user developer session. Windows PktMon and ETW/Winsock trace-session activation both return access denied; Windows Filtering Platform net-event subscription requires `FWPM_ACTRL_SUBSCRIBE`, which is not granted by the ticket's explicit `Elevation: None` authorization. Polling owner tables or trusting the collector's own counter would not capture short-lived DNS/socket attempts and is not accepted as closure evidence. No capture provider, firewall rule, network configuration, or privilege was changed.

To close this evidence gap, run the live local-source attempt under a pre-authorized read-only event-level capture boundary on a disposable validation host/profile, or explicitly authorize the minimal tracing privilege needed to arm such a boundary before the process starts. Until then, issue #61 and its pull request remain open and unmerged even though the implementation and non-capture tests pass.
- **Wrong user or elevated context:** Current User proxy/VPN/profile state could describe the operator, alternate administrator, or SYSTEM instead of the Assessment User. The coordinator passes only the previously verified canonical SID; the child independently compares its actual SID and rejects elevated, different-user, and SYSTEM contexts before reading a source.
- **Arbitrary code or process escape:** a fixture or worker could try to choose script/executable content or survive cancellation. Only release-embedded source is encoded, the active Microsoft-signed PowerShell host is selected by the coordinator, and the Process Supervisor assigns the suspended child to a kill-on-close Job Object. Deadline or tree-absence uncertainty becomes typed cleanup failure and prevents normal packaging.
- **Untrusted worker output:** serialized output could smuggle extra properties, wrong primitive types, excessive items, secret material, or false Complete coverage. The coordinator applies exact shape, type, byte, count, context, and scope invariants, then copies admitted primitives into new coordinator-owned objects before canonical validation.
- **Privacy leakage:** exact addresses, endpoints, adapter/profile/product names, and configuration values could reach public stdout. These values are Restricted and remain inside the protected Assessment Record/report; generated tests reject seeded identifier families from progress, validation, completion, and terminal projections.
- **Misleading inference or mutation:** product registrations could be presented as health/approval, or observation could alter the network. Rules remain advisory, health inference is explicitly false, all write/prompt/install/download/self-elevation flags are frozen false, and source tests reject configuration-changing and packet-capture APIs.

The trust assumptions are Windows access-control enforcement, the already-verified Assessment User SID, the active Microsoft-signed PowerShell host, the Process Supervisor's Windows Job Object implementation, and the release-embedded policy/digest. Safe failure is explicit: an unavailable, denied, malformed, bounded, timed-out, failed, or cleanup-uncertain source cannot become a Complete absence claim; unrelated accepted scopes remain separately represented, and cleanup uncertainty prevents ordinary completion.

The independent Standards and Spec review required by the implementation workflow is recorded in the issue/PR closure trail. It verifies these threat mappings, public/private classification, and Local Only behavior against `CONTEXT.md` and issue #61 before merge.

Run `pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1` for the complete repository gate. The deterministic build evidence reports the generated artifact digest without publishing the ignored artifact itself.
