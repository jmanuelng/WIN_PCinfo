# Frozen Administrator plan

WIN-PCInfo now has a narrow Privileged Plan Runner that can execute the four Administrator operations already shown in the approved Preparation Summary as one contiguous phase. This is a security tracer bullet: the operations return synthetic status only. They do not collect real device evidence, deliver a Product Capability, or make Preview/Supported claims.

The generated application exposes the same contract through hidden synthetic validation fixtures. Ordinary generated execution still cannot reach real collection because Local Package Protector and final package work belongs to later slices. A local development build is also unsigned and therefore fails Preparation integrity before collection. These limitations prevent this security test from becoming an accidental product-completion claim.

## What happens at elevation

Preparation remains in the standard-user coordinator. It owns consent, the Assessment User Context, the Local Package Protector, the Assessment Run lifecycle, and eventual package finalization.

After approval:

1. The coordinator verifies the full Preparation Plan digest and extracts exactly four `Administrator` operations. A mismatch stops before UAC.
2. If the coordinator already has an eligible Administrator token, it launches the worker directly and requests no elevation.
3. Otherwise it uses Windows `runas` once. There is no retry and no second product prompt.
4. The elevated worker joins its own kill-on-close Windows Job Object before connecting or receiving the plan.
5. Both processes verify the other process and PowerShell artifact through the connected named-pipe handle.
6. The worker validates the nonce, plan digest, exact ordered operation IDs, and closed empty parameter objects. It runs all four in one phase and returns only operation status.
7. Both processes close the one-use pipe. The worker Job handle closes, the coordinator verifies its owned processes absent, and standard-user work may continue.

If the operator denies UAC, all four privileged operations become explicitly `Unavailable` with `PRIVILEGE.ELEVATION_DENIED`. Safe standard-user work continues and WIN-PCInfo never asks again.

## Why an alternate administrator does not become the assessed user

Windows may let the operator enter a different administrator account in the UAC dialog. That account is only the **privileged worker principal**. The coordinator never sends the Assessment User Context or Local Package Protector through the privilege channel, so the worker cannot substitute its own account for either role. The sanitized result describes only the relationship `AlternateAdministrator`; it does not publish an account name or SID.

## The local channel, in beginner terms

A Windows named pipe is a short-lived local connection, not a file and not a network listener. WIN-PCInfo creates a new unpredictable pipe for each run and allows one client only.

The pipe has several independent checks:

- **ACL:** Windows grants access only to the initiating user and local Administrators. This permits a deliberately selected alternate administrator while excluding ordinary unrelated users.
- **Nonce:** 32 random bytes bind every message to this one run. Replayed or misdirected messages fail validation.
- **Kernel peer PID:** each side asks Windows which process is attached to its pipe handle. A PID written inside JSON is never trusted by itself.
- **Artifact identity:** the coordinator validates Microsoft-signed `pwsh.exe`, hashes the actual peer image, and verifies the exact release-owned worker template digest. The worker independently hashes the coordinator image.
- **Framing:** every UTF-8 JSON message has a four-byte length prefix and a 16 KiB maximum. Duplicate, extra, missing, oversized, malformed, or out-of-order fields fail closed.
- **One purpose:** the worker accepts no executable path, script, command, credential, environment value, evidence object, or open-ended parameter bag.

The pipe name and nonce are anti-confusion values, not passwords. The design trusts Windows ACL, pipe-peer, process, Job Object, UAC, and Authenticode behavior, plus the reviewed release worker source. If any trust check is unavailable or inconsistent, no operation is accepted.

## What may cross

Coordinator to worker:

- protocol version;
- random run nonce;
- approved Preparation Plan digest; and
- the four release-owned operation IDs, each with a closed empty typed parameter object.

Worker to coordinator:

- protocol version and the same nonce/digest;
- sanitized peer/artifact proof; and
- `Completed` status for each synthetic operation in one phase.

Assessment evidence, user identity facts, package-protector facts, raw errors, paths, credentials, secrets, script text, and command text never cross the pipe.

## Cancellation, deadlines, and cleanup

Connection and operation waits are finite. One cancellation closes scheduling; if the trusted worker does not finish during the 750 ms grace, the coordinator requests whole-tree termination and waits at most two seconds for the root to disappear. The worker's private kill-on-close Job Object ensures any descendant inherits the same lifetime. This slice's approved operations contain no child-process or file-creation behavior, so the worker root is the complete planned tree and there is no staging directory to remove.

Timeout, cancellation, worker loss, wrong-client connection, and altered-plan fixtures all return typed sanitized results. Raw PowerShell or native error text never enters progress, evidence, or terminal output.

See [issue #43 validation evidence](validation/issue-43-privileged-plan.md) for the public-safe test matrix and commands.
