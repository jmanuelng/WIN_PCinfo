# Issue #160 bounded observer preparation

Status: **Blocked before activation**. This is a finite proposed procedure, not
approval or live evidence. It continues [the earlier preparation record](issue-160-session-preparation.md)
for [#160](https://github.com/jmanuelng/WIN_PCinfo/issues/160). Starting source and
Code Review fixed point: `43797b80b9af8be8e5ac15f8f2c66c962b53188b`.
The existing private signed candidate, separate recipient, keys, trust and
protected evidence remain unchanged. Completed private signing/setup checks must
not be repeated. Actual desktop preparation, recipient confirmation, assessment
consent, observation and the GUI-to-report milestone remain pending. The private
handoff remains incomplete and due by end of September 6, America/Chicago
(before September 7 at 00:00 CDT / 05:00 UTC), following the user's EOD
clarification. #161 owns complete acceptance; this deadline grants no live authority.

## Preparation blockers and next action

1. **WPR finalization adds data beyond the three selected providers.** Microsoft
   documents that `-stop` merges automatically and inserts image identifiers and
   system information. The installed CLI does not offer `-mergeonly` on `-stop`;
   that switch belongs to a separate `-merge` command. `-skipPdbGen` suppresses PDB
   generation, not this metadata. The exact injected field set has not been
   bounded against the command-line/secret exclusions. Do not activate on a claim
   that the WPR profile describes all saved data. Next action: establish the
   installed finalization field boundary through read-only documentation/source
   evidence, or prepare a separately reviewed minimal save method. Do not silently
   add permission for command-line recording, extra providers or unrestricted
   metadata. This blocker precedes a calibration approval request.
2. **The finite timing below requires continuous supervision.** It contains no
   automatic watchdog and cannot guarantee that Windows obeys a stop request.
   If unattended operation or an enforced wall-time ceiling is required, this
   procedure is insufficient: first implement only a bounded stopping helper at
   its public command/time boundary with controlled red/green tests. A file-size
   cap is not that helper. No helper is introduced by this documentation change.
3. **Attribution is unproved.** The loopback controls below are candidates for
   approved calibration, not passed controls. Their failed attempts might not
   emit the selected events or exercise DNS service delegation. No success
   traffic, arbitrary service delegation or all-protocol coverage is established.
   A control that lacks the necessary events leaves coverage Blocked. The exact
   frozen candidate's source/call-surface review must also close any uncovered
   request paths before a no-assessment-request claim; #148 controlled results do
   not replace that live evidence.

The finalization finding follows Microsoft's [WPR start/stop explanation](https://devblogs.microsoft.com/performance-diagnostics/wpr-start-and-stop-commands/).
The separate save/merge switches are documented in [WPR command-line options](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options).
No claim is made that command lines were actually captured; no capture ran.

## Exact proposed scope

The private profile named `observer160-proposed.wprp` has SHA-256
`9ee4c7744269a0a24a88a9ae241a9a149cedea0d7d30e8b5df65963ffb2c1350`.
It remains an unapproved operational input outside tracked source. Installed WPR
10.0.26100 parses `WINPCInfo160Proposed.Verbose.File` and the following filters.
Recheck these exact bytes and installed event versions before any approved run;
a mismatch blocks execution rather than selecting a built-in fallback profile.

| Provider | Admission |
| --- | --- |
| Kernel-Process `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716` | Level 4, keyword `0x10`, events 1/2/15, start capture-state `0x10` |
| Kernel-Network `7dd42a49-5329-4832-8dfd-43d979153a88` | Level 4, keywords `0x30`, events 10–18, 26–32, 34, 42, 43, 49, 58, 59 |
| DNS-Client `1c95126e-7eea-49a9-a3fe-a378b03ddb4d` | Level 4, only events 3006 and 3010 |

All providers are Strict; extra Stack/SID/TSID flags are false. There is no
image-load/thread/stack/sample provider, packet payload or whole DNS-provider
capture. The installed selected process templates omit CommandLine. DNS 3010
version 1 has ClientPID; version 0 does not qualify delegated client attribution.
Capture-state effectiveness and actual event versions still need calibration.
Included-event filters are described by Microsoft's [EventFilters schema](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/eventfilters).

Capture is intrinsically **host-wide restricted metadata**: unrelated process
images, lifetimes, parents, sessions and mandatory labels; socket endpoints,
sizes/timings and connection failures; DNS names, query types/options, server and
interface metadata. Filtering after capture does not make unrelated data
uncaptured. Finalization metadata is an additional unresolved boundary above.
This scope needs actual observer approval independently from signing and product
assessment approval. No external canary, external request, audit/firewall/service
change, driver, dependency installation, trust change or key operation is proposed.

The collector uses 64 KiB x 128 buffers (8 MiB) and a 128 MiB Sequential maximum.
Microsoft describes stopping sequential file capture at [MaximumFileSize](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/maximumfilesize).
That is a configured ceiling, not a measured disk bound on temporary plus merged
files, a wall-time limit, or proof that providers have been disabled. Reaching
the cap, disk exhaustion or any incomplete interval invalidates a negative claim.
Do not switch to circular mode, restart capture or increase the cap mid-session.

## Private binding before an approval request

The orchestrator binds these placeholders in the existing private session packet;
never publish their values or dump `ownership-and-inputs.json`:

- `$wpr`: literal installed System32 executable; privately record file identity,
  version, architecture and unchanged policy admission. Use no PATH substitute.
- `$profile`: exact profile above, copied to the reconciled private session only
  after confirming source bytes and destination ownership. Do not embed it in or
  rebuild the signed candidate.
- `$instance`: one unused `WINPCInfo160-` plus random GUID name for one interval.
  Register intent, initiating identity and UTC before starting. A name alone is
  not ownership: bind the actual collector name and start identity after start.
- `$temporary` and `$etl`: respectively a new empty `observer/<instance>/temp`
  directory and absent `observer/<instance>/recording.etl` under the existing
  private root. Bind exact literal resolved paths, reject UNC/reparse traversal,
  pre-existing contents and unrelated ownership. Do not use default WPR storage.
- `$journal`: the private interval record, including supervisor, consent,
  start/stop command UTC and monotonic times, actual session/collector identity,
  control process identities, private output inventory and recovery disposition.

Reconcile the private root against the authoritative ownership record, current
initiating user and ancestor/descendant reparse checks. Check owner and complete
ACL readback on every new output directory and resulting file. Preserve the
recorded managed-sandbox read principal; do not claim only user/SYSTEM access.
Refuse broader or unexpected access, sync/publication exposure or an owner change.
No real paths, account/device/network/certificate identifiers or ETL enter Git.
Temporary plus final storage needs a separate approved reserve and free-space
check; the 128 MiB collector maximum alone does not establish that reserve.

## Finite supervised sequence, conditional on clearing blockers

This sequence is not executable authorization. Two pre-opened observer consoles
use the same approved observer privilege and privately bound instance. One runs
the operation; the other remains available for stop/status/recovery. The
Assessment Operator uses the ordinary candidate GUI under its separately frozen
product privilege plan. Pause unrelated AFK tests at a clean boundary throughout
the interval. Do not run an unattended capture or add an elevation/task/service
to manufacture supervision.

1. Before start, inspect `& $wpr -status profiles collectors -details -instancename $instance`
   privately. Require an unambiguously unused instance, not merely a nonzero
   exit code; denied/unrecognized status is Blocked. Verify read-only global ETW
   session inventory is available for later comparison, recording only relevant
   owned identities privately. Do not adopt or stop pre-existing sessions.
2. Arm a visible monotonic stopwatch in the supervisor console immediately
   before issuing start. Record UTC as well. One **180-second calibration**
   interval is proposed first; the candidate must not launch in calibration.
   Only after its evidence is reviewed may one separately approved
   **4,200-second candidate** interval be used, starting before portable launch.
   These are stop-request deadlines measured from before the start attempt, not
   from when start returns. A start command still unresolved at 15 seconds ends
   the attempt and enters owned-session reconciliation; do not start controls.
3. Proposed start command:
   `& $wpr -start "${profile}!WINPCInfo160Proposed.Verbose" -filemode -recordtempto $temporary -instancename $instance`.
   Inspect the instance-scoped status immediately. Record actual collector
   identity, profile, interval and output paths. Only a successful start plus
   ownership reconciliation permits controls or candidate launch. A partial
   failure is not proof that no session exists; inspect and cancel only an
   unequivocally owned instance.
4. Run the calibration controls below within seconds 15–60. At seconds 60 and
   150 inspect scoped status/loss/cap state. Stop immediately on loss, unexpected
   provider/field scope, ownership ambiguity, control escape or observer failure.
   For a later candidate interval, require launch by second 120 and inspect
   status at least once per minute. Record preparation/decline, then the separate
   frozen-plan/recipient approval, real collection, terminal, protected report
   open/close and owned cleanup boundaries. If mandatory work cannot finish
   inside this interval, stop on time and leave the uncovered result Blocked;
   extending observation requires new concrete authority, not automatic retry.
5. Request stop as soon as the required interval completes, or at its deadline,
   whichever is first. The proposed command, **blocked on finalization scope**,
   is `& $wpr -stop $etl -skipPdbGen -instancename $instance`.
   Record stop-request and actual session-end times separately. A console that
   remains busy may be merging after recording ended; do not equate CLI duration
   to observed collection time or assume either ended.
6. At 15 seconds after a stop request, use the second console's scoped status and
   independently match the registered ETW collector. If recording remains active
   and ownership is conclusive, issue exactly
   `& $wpr -cancel -instancename $instance`. Cancel can discard unsaved recording;
   preserving evidence must not keep collection running past its scope. If start
   or stop was ambiguous, reconcile before cancel; never compensate with global
   stop/cancel. After another 15 seconds, unresolved absence/ownership is
   **CleanupIncomplete** and needs immediate supervised recovery of only the
   recorded instance. Do not launch another trace or assessment. There is no
   promise of hard stop during host/supervisor failure, suspension or OS refusal.
7. Verify both WPR instance inactivity and absence of the registered collector
   in an independent read-only ETW session query. Capture final loss and interval
   evidence before disposing anything. WPR returning exit 0, a missing CLI
   process, or an ETL existing is insufficient proof of session absence. Do not
   parse localized status prose into an automated success result.

Every relevant WPR command ends with `-instancename $instance`, as installed
advanced help requires. There is deliberately no global stop or cancel command
in this procedure. Standard output/errors stay in the private packet, with no
unbounded shell transcript or command-line inventory.

## Loopback-only candidate controls

No control has run. The orchestrator must bind literal installed executable
identities and record parent PID, child PID, creation/end time and image for each
attempt. Both controls use existing Windows components, finite native command
options and continuous supervision; if a child remains after 15 seconds, stop
only its conclusively owned process tree and mark calibration Blocked. Neither
control's exit code is a capture success criterion.

| Control | Exact proposed attempt and required evidence |
| --- | --- |
| Native child and direct TCP attempt | After confirming no local listener on TCP 9, run installed `curl.exe -q --noproxy "*" --connect-timeout 2 --max-time 2 --max-redirs 0 --output NUL http://127.0.0.1:9/`. `-q` is first to suppress user curl configuration. Numeric loopback, no proxy, no redirects, no TLS and no DNS. Expect refusal plus attributable selected connection/failure events and complete process lifetime; if the events do not appear, this control fails calibration. It does not qualify successful TCP transfer. |
| DNS client attempt | After confirming no local UDP/TCP 53 listener, launch one installed Windows PowerShell child with `-NoLogo -NoProfile -NonInteractive -Command "Resolve-DnsName -Name winpcinfo160-control.invalid. -Type A -Server 127.0.0.1 -DnsOnly -NoHostsFile -NoRecursion -QuickTimeout"`. Expect a local failed DNS attempt, exact query type/name, and selected DNS plus network metadata. Require 3010 version 1 ClientPID to bind to that child's lifetime and actual service/client evidence to qualify delegation. If direct-client execution, cache behavior, missing service activity or version 0 prevents that, delegated coverage stays Blocked. Never remove the explicit server or enable fallback to make an event appear. |

Use fresh process identities for two attempts of each control inside the one
calibration interval; do not force PID reuse. Closed ports are a precondition,
not authority to contact an unrelated local service. Recheck immediately before
each attempt; any new listener or unexpected destination aborts calibration.
No listener, DNS zone, hosts entry, proxy, firewall rule or service is created.
Microsoft documents the explicit server and DNS-only options in
[Resolve-DnsName](https://learn.microsoft.com/en-us/powershell/module/dnsclient/resolve-dnsname?view=windowsserver2025-ps).

These are **failed-request candidate controls**. They do not prove successful
traffic visibility, guaranteed service delegation, IPv6, ICMP/raw/link-layer
coverage or every request API failure. The deliberately limited controls cannot
be treated as a complete no-egress calibration. In the candidate interval use
only separately approved bracketing controls, with disjoint registered process
lifetimes; keep their traffic classified as control traffic without deleting it
from the original trace. Report/browser/service activity needs its own causal
attribution and cannot be erased as background noise merely to produce zero.

## Evidence acceptance and cleanup

Before any negative conclusion, reconcile every provider GUID/event ID/version
against its installed template, including payload PID versus header emitter PID.
Bind process identity to PID **and creation time/lifetime**, parent lifetime and
image; PID-only joins and event proximity are insufficient. Start capture-state
must cover existing service/browser processes; child, privileged and SYSTEM
workers require complete causal ownership from the frozen application records.
Unknown lifetime, PID reuse ambiguity, unresolved delegation or a missing worker
keeps the relevant claim Blocked.

Require successful controls, interval start before the first relevant candidate
action, interval end after report close/cleanup, no gaps/early cap stop, final
ETL/header/collector loss counts all zero, and a decoder able to account for all
selected events. Before activation, identify the installed read-only ETL decoder
and how it will report header loss plus versions; if unavailable, stop preparation
without installing tooling. Pre-stop zero loss alone cannot prove final zero
loss. An unreadable trace, unknown schema, missing counter or unaccounted event
cannot become zero. Retain factual observations separately from coverage and
interpretation; a Pass for syntactic profile admission is not a live Pass.

Register actual output files privately after ACL/path readback, hash retained
evidence, and record stop/absence/child cleanup outcomes. Preserve the original
trace, protected package, recovery records, recipient keys and required trust
until approved retention-safe disposal. Never delete an uncertain directory or
clear shared WPR caches. Later approved trace deletion uses only exact inventoried
paths under the reconciled private interval root after session absence, resolved
containment and no reparse traversal are verified. Use literal PowerShell paths
end-to-end; verify absence and retain the disposition record. No forensic-erasure
claim, certificate cleanup or package removal belongs to this continuation.

## Validation of this continuation

Implement and TDD applicability: documentation only, no executable helper,
product change, trace activation, control attempt or assessment. Behavioral
red/green and runtime tests are NotApplicable. Focused checks are exact profile
SHA-256, installed read-only `-profiles`/`-profiledetails`, command-help review,
primary documentation cross-checks and `git diff --check`. Neither actual stop
behavior nor attribution, finalization fields, final ETL loss decoding or private
output creation passed. The full suite is not rerun for this documentation slice
under the user's focused-test cadence; integrated #158/#161 gates remain pending.

Two fresh independent Code Review axes examine this continuation against the
fixed point above; results are handed to the orchestrator separately. #160 stays
open. The original candidate remains frozen. Historical #138 synthetic working
set of 662–755 MiB still exceeds the provisional 512 MiB budget; this observer
preparation neither resolves nor waives the #158/#161 performance obligation.
