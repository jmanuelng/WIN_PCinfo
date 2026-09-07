# #161 observer preparation: bounded method and remaining blocker

**Blocked before activation. No trace, calibration, canary, session query,
stop/cancel, private binding, decoding or live assessment was performed.** Root
owns those operations and their concrete approvals. This is a finite review of
the existing [#160 procedure](issue-160-observer-procedure.md) and the supplied
`observer160-raw-stop-lead.md`; that lead remains an unverified hypothesis.
No observer framework or executable controller is introduced.

## What the bounded read-only check establishes

On September 7, 2026 UTC, the worker read installed `wpr -help stop`,
`logman stop /?` and `tracerpt /?`, plus the primary references below. These help
commands did not select, inventory or operate a trace session. Installed help
identifies Logman 10.0.26100.1150 and TraceRpt 10.0.26100.5074. Root must bind the
actual executable identities privately before any later execution.

| Boundary | Supported fact | What remains unproved |
| --- | --- | --- |
| WPR save | Installed help says stop merges. The documented `-mergeonly` belongs to the separate merge operation; `-skipPdbGen` suppresses PDB generation. | No documented installed stop switch establishes a selected-events-only save. The exact additional saved metadata is not established by a provider filter. [WPR options](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options) |
| Direct named native stop | `logman stop <name> -ets` addresses an ETW session directly without creating/scheduling a saved collector set. | The name must be the actual owned ETW collector, not a guessed WPR profile/instance. Documentation does not establish WPR/native-stop interoperability, final file retention and bookkeeping cleanup as a combined supported transaction. [Logman start/stop](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman-start-stop) |
| Native session lifecycle | ControlTrace can query or stop an identified session; file-mode buffers normally flush at session close. More-data can follow a completed stop; active-connections can mean stop is still progressing. | A CLI exit code is not absence, loss or finalization proof. These API facts do not prove Logman's internal call path or WPR state reconciliation. [ControlTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew) |
| Raw ETL header | Defined metadata includes OS build, processor count/speed, clock/timing/time zone, session/log path, buffer/mode/file bounds and loss fields. The first event contains the header; an unclosed file can have zero EndTime. | Header documentation is not an exhaustive list of automatically emitted records. Pointer-size/version-aware decoding and all saved metadata still need an admitted boundary. [TRACE_LOGFILE_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header) |
| Installed decoder | TraceRpt supports ETL XML output and a summary. Installed help also exposes raw timestamps and interpreted structures. | Exact selected event versions, header/collector loss reconciliation, complete fields and unreadable-event accounting have not been calibrated. No best-effort `-lr`, symbol server, provider-image fetch or default output location is admitted. [TraceRpt](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracerpt) |

The additional WPR Cancel and instance-name references in the lead could not be
retrieved in this bounded check (fetch refusal/403). Installed help still exposes
`-instancename`; no new guarantee about bookkeeping cleanup is inferred. Research
stops here: repeated searches cannot supply actual calibration evidence.

## Concrete conditional method for root's preparation

Retain the existing profile's exact SHA-256
`9ee4c7744269a0a24a88a9ae241a9a149cedea0d7d30e8b5df65963ffb2c1350`,
selected process/network/DNS event IDs and versions, Strict providers, disabled
stack/SID/TSID additions, 64 KiB × 128 buffers and 128 MiB Sequential file ceiling.
This is host-wide restricted metadata, including unrelated process lifetimes,
images and network/DNS identities. Post-filtering does not undo collection.
The cap is neither a wall-time stop nor a total temporary-plus-final disk budget.

Before an activation proposal, root privately reconciles the existing session
inventory, initiating authority and new empty no-reparse output directory with
complete ACL readback. Bind exact installed tools, the profile bytes, one unused
instance, actual ETW collector name/GUID, start identity/time, raw output path,
decoder outputs, supervisor and recovery ownership. A unique-looking name alone
does not establish ownership. Do not print these private bindings publicly.

The proposed calibration remains **one 180-second interval**, with no candidate
launch. The later candidate interval remains separately approved and at most
**4,200 seconds**, starting before launch and covering report close/cleanup.
Both deadlines run from immediately before start, even if start stalls. Use the
existing two continuously supervised consoles; start unresolved at 15 seconds
enters owned-session reconciliation. No unattended trace or new watchdog is added.

During a future approved calibration, retain the existing two attempts each of
the bounded numeric-loopback curl failure and DNS-only explicit-loopback resolver
failure. Verify the selected ports have no listener before each attempt. Register
each control's process identity/lifetime and expected selected events privately.
No listener, external canary, network setting, firewall/audit rule or dependency
is created. Controls stop within their existing native limits; an owned surviving
child at 15 seconds is a failed calibration and needs exact-tree cleanup.

The raw-stop hypothesis would replace WPR's merge save only after root establishes
the complete saved metadata and lifecycle boundary: directly stop the **recorded
actual collector** using installed Logman, prove it absent independently, verify
the raw ETL is finalized and loss accounting is complete, preserve the owned raw
file, then reconcile only that WPR instance's bookkeeping. This sequence is
**not activation-ready**. In particular, WPR cancel may discard recording data;
do not assume a copy before stop is complete or that cancel preserves raw files.
Never globally stop/cancel, clear caches, adopt an existing trace or guess a logger.

For whichever save method becomes qualified, request stop at interval completion
or deadline, whichever comes first. Record requested and observed end separately.
At 15 seconds after stop, the independent supervisor checks exact scoped state
and the recorded ETW collector; perform only already-approved, conclusively owned
recovery. Another 15 seconds without verified absence is **CleanupIncomplete**.
Stop new traces/assessments and preserve the journal. This finite supervised
escalation does not promise an OS-enforced hard stop during suspension, denial,
host failure or loss of the supervisor. A strict unattended-stop requirement is
therefore still blocked, not satisfied by this method.

## Loss, attribution and acceptance boundaries

Before a negative request claim, require the full interval, successful bracketing
controls, zero final event/buffer loss, no cap/disk truncation, valid final times,
complete decoding and agreement of provider GUID/event ID/version with the
installed templates. Unknown loss or an unaccounted event is not zero. Preserve
original restricted evidence and its hashes; never delete inconvenient records.

Join process identity by PID **and creation/lifetime**, parent lifetime and image,
including launcher, generated workers, privileged/SYSTEM work and existing
browser/services. Header emitter PID and payload client PID are different facts.
DNS 3010 version 1 ClientPID is required for the proposed DNS-client association;
version 0, missing lifetime, PID reuse ambiguity or unproved delegation remains
Blocked. Capture-state coverage for pre-existing processes also remains unproved.

The failed loopback controls cannot establish successful traffic visibility,
arbitrary service delegation, IPv6, ICMP/raw/link-layer coverage or every request
API. Root needs a candidate-specific source/call-surface comparison to determine
which uncovered paths matter. Do not relabel browser/service events as background
solely to obtain zero. Both observer and live source acceptance retain these gaps.

After verified session/control absence, inventory final files, enforce the private
ACL/path boundary, and record retained evidence and cleanup. Later deletion uses
only literal inventoried owned targets after resolved containment/no-reparse checks.
Retain protected packages, needed recipient keys and unresolved recovery evidence.
Do not modify trust or private #160 artifacts as observer cleanup.

## Precise blocker and next owner

**OBS-158-1, owner root/#160:** no established complete automatically saved metadata
boundary and no supported, verified WPR/native-stop/raw-file/bookkeeping sequence.
Root must resolve those facts before proposing activation. If existing supported
tools cannot establish them, report this blocker rather than constructing a new
observer framework or broadening capture. **OBS-158-2, owner #160/#161:** actual
loss/decoder/lifetime/delegation calibration and exact-candidate interval coverage
are NotStarted and require separately authorized execution after OBS-158-1 clears.

These blockers prevent measured Local Only zero-request acceptance. They do not
invalidate correctly scoped synthetic source tests, and those tests do not close
the blockers. The first real milestone and final eight live checks remain pending.
