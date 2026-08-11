# Process Supervisor

WIN-PCInfo uses one Process Supervisor whenever an Approved Collector Executable must run outside the main PowerShell process. It now supervises both the original synthetic safety probe and the narrow Device Readiness collector. That slice still does not by itself create a Preview/Supported claim.

## Why a supervisor is necessary

Starting a process is easy. Starting only reviewed code, bounding everything it can do through the launch channel, stopping its descendants, and reporting failure honestly are the difficult parts. A direct `Start-Process`, shell command, plug-in path, or collector-selected script would bypass those controls, so collectors receive no executable, command, script, argument, environment, working-directory, timeout, or output-limit parameter.

The exported interface accepts only a release-defined operation ID and, when needed, a cancellation token. The hidden validation parameter accepts only eight published scenario names and cannot carry evidence or commands:

```powershell
$result = Invoke-ApprovedCollectorProcess `
    -OperationId 'op:synthetic.windows.os.success' `
    -CancellationToken $cancellationToken
```

The result contains a Collector Result Envelope, normalized observations, Evidence Coverage State, stable diagnostics, and sanitized process accounting. It never returns raw standard output, raw standard error, executable paths, working paths, native error text, or environment values.

## What the release fixes in advance

The schema-validated [Approved Collector Catalog](spec/releases/2.0.0-preview.1-approved-collectors.json) fixes:

- the collector and operation identities;
- resolution to the literal active `pwsh.exe` under `PSHOME` and a valid Microsoft Authenticode signer;
- the exact embedded collector-payload digest and fixed `-EncodedCommand` argument vector;
- a replacement four-variable environment instead of parent-environment inheritance;
- the validated active `PSHOME` as a non-writing working boundary;
- a five-second operation deadline, per-operation stdout bounds (4 KiB for the original probe and 8 KiB for Device Readiness), a 4 KiB stderr bound, and a 750 ms cooperative-cancellation grace interval;
- a two-second hard-termination verification bound; and
- suspended startup, mandatory Windows Job Object assignment, kill-on-close behavior, and `NotStarted` when Job assignment is incompatible.

The deterministic build validates this catalog against [its Draft 2020-12 schema](../schemas/approved-collector-catalog.schema.json), embeds the exact canonical bytes in the generated application, and records both resources in the application manifest. The supervisor verifies the embedded digest before policy can influence a launch.

## Process-tree control

The supervisor calls the Windows process API with `CREATE_SUSPENDED`. While the new process cannot execute, it creates and configures a run-owned Job Object, assigns the process, and only then resumes the first thread. This order closes the ordinary spawn-to-assignment race in which a fast collector could create an unowned child.

Every compatible descendant inherits Job membership. When the root finishes, times out, is cancelled, or exceeds an output bound, the supervisor terminates any remaining Job members and queries kernel Job accounting until the active-process count reaches zero. Closing the Job also has kill-on-close protection.

If Job assignment is incompatible, the safe fallback is no execution: the still-suspended candidate is terminated and the envelope reports `PROCESS.JOB_INCOMPATIBLE`, `NotStarted`, and `IncompatibleNoLaunch`. WIN-PCInfo does not fall back to root-only termination or claim tree control it does not have.

## Cancellation and deadlines

Cancellation signals a run-unique named Windows event whose name is supplied through the fixed environment contract. The synthetic collector may only open that event. If it exits within 750 ms, the result records cooperative cancellation. If it ignores the event, the supervisor terminates the complete Job Object and records hard cancellation. Every wait after a termination request is bounded by two seconds; failure to prove absence becomes `PROCESS.TERMINATION_INCOMPLETE` rather than an infinite wait or a false cleanup claim. Both ordinary cancellation paths acknowledge within the parent specification's two-second budget and return only after cleanup verification.

A deadline is independent of cancellation. Deadline expiry immediately terminates the Job and produces `TimedOut` coverage with `PROCESS.DEADLINE_EXCEEDED`.

## Untrusted output and privacy

Authenticode verifies executable provenance, not live output. Stdout and stderr are drained concurrently into separately capped buffers so one full pipe cannot deadlock the other. Passing either cap terminates the Job and produces `PROCESS.OUTPUT_LIMIT_EXCEEDED`.

Only an approved success payload is decoded as strict UTF-8 and checked against its fixed JSON shape. Device Readiness accepts exactly eight bounded properties, or the one-property unavailable shape. Raw pipe text is never copied into progress or diagnostics, and it is not hashed: unexpected Prohibited Secret Material must not gain a second representation through a digest. Retained buffers are zeroed after normalization or failure handling as best-effort memory hygiene, without making a forensic secure-erasure claim.

## Files and other residue

The supervisor creates no script file or working directory. The digest-verified release source is encoded directly into the fixed PowerShell argument, closing the validate-then-execute file-replacement window. The active `PSHOME` is validated as the working directory and treated as non-writing. The run-unique cancellation event disappears when the last owned handle closes. No scheduled task, service, persistent process, marker, log, or lock is created. Every success, rejection, overflow, timeout, cancellation, child-process, and incompatibility fixture verifies the owned process tree and named event absent before return.

For the public-safe validation matrix and commands, see [Issue #41 validation evidence](validation/issue-41-process-supervisor.md).
