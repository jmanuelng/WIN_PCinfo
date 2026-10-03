# #154 blocking Spec-review corrections

Only the two blocking findings from the independent review of
`37482d15ee366e5b51e686cc9f4180f1ffb53fa2...8a2663ebf58133a2a6fb7d0602ada215b24c748e`
are addressed here. The earlier Standards axis found zero issues. Those reviews
do not qualify these changed bytes. **Fresh affected Standards and Spec reviews
are both Pending, owned by root. #154 remains Open.**

## Exact identities

- Clean starting HEAD and Code Review fixed point:
  `8a2663ebf58133a2a6fb7d0602ada215b24c748e`.
- Branch: `codex/spec134-afk-batch`.
- First format correction: `72d3fd7aa4b2185ae131543b85fd807966b83d64`.
- Privileged execution correction: `23265f720f5722d4f1babb43288d7cd65cac1a1f`.
- Package round-trip test checkpoint: `f340cc1f797f5d23ecfa3b354b205e000cb3f90c`.
- Final product and test checkpoint, including the affected SYSTEM wire fix:
  `447c73041f3f5e9ce249856555694447c3519e53`.
- Corrected unsigned generated candidate SHA-256:
  `262f069f9d228c1636f84165846b9996bf257993f0900f423e9154166467a86e`,
  **3,319,490 bytes**. Documentation-only delivery commits preserve these bytes;
  the final commit identity is reported in the worker handoff.
- Installed test host: `C:/Program Files/PowerShell/7/pwsh.exe`, Core 7.6.5,
  .NET 10.0.11, X64. No software, dependency or runtime was installed.

## Semantic format correction

The Assessment Record schema declares exactly three format keywords, governing
five paths. The shared semantic pass now enforces all five after schema admission:

| Format | Assessment Record paths |
| --- | --- |
| `date-time` | `provenance[].collectedAt`, `collectorResults[].startedAt`, `collectorResults[].completedAt` |
| `date` | `softwareRecognition[].provenance[].verifiedOn` |
| `uri` | `softwareRecognition[].provenance[].url`, also subject to the existing `^https://` schema pattern |

The audit also checked the other three schemas in the existing official
qualification selection: Contract Set, protected envelope and package manifest
declare no additional string-format keywords. Other schema roots retain their
own admission boundaries; this correction introduces no general schema walker
or replacement validator.

The implementation follows [RFC 3339 sections 5.6–5.7](https://www.rfc-editor.org/rfc/rfc3339#section-5.6)
and [RFC 3986 sections 2–3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3).
Gregorian calendar checks and ASCII syntax preserve year 0000, valid leap days,
lowercase `t`/`z`, arbitrary bounded fractional precision, numeric offsets and
offset-adjusted UTC month-end leap-second positions. It does not fetch a
changing leap-second announcement table or introduce interval-order rules.
URI checks preserve generic syntax, escaped Unicode, IPv6, IPvFuture and numeric
ports without adding reachability, DNS, publisher or port-range policy.
Raw Unicode remains legitimate record data; URI characters needing encoding
must be percent-encoded. Invalid syntax returns only `CONTRACT.FORMAT_INVALID`.

`ConvertFrom-Json -DateKind String` preserves the wire representation for the
semantic pass. The existing SYSTEM record boundary now evaluates the same
serialized representation that passed its schema, including when its caller
holds typed `DateTime` values. This prevents culture-dependent string coercion.

The installed official validator's [format annotation behavior](https://json-schema.org/draft/2020-12/json-schema-validation#section-7)
is unchanged. Official annotation cases do not establish semantic acceptance.
The separate exported-validator regression executes **470 format cases** across
en-US, es-MX, tr-TR, ja-JP and ar-SA. Package tests preserve legitimate format
and Unicode bytes in all five cultures, then reject five malformed-format
records alongside the eleven retained incompatible-record cases. Hostile
archives have correct ciphertext authentication and matching artifact digests.
Creation refuses final naming; reopening exposes no decrypted artifacts;
viewing creates no artifact or journal; owned cleanup and managed-buffer checks
remain enforced. No forensic-erasure claim is made.

## Privileged execution correction

After validating the complete frozen plan, the owned worker sends one bounded
`ExecutionStarted` frame. The existing pipe peer/process/artifact checks precede
it; its closed fields bind kind, version, nonce, plan digest and phase identity.
Only that admitted transition sets `executionStarted`. The final result must
retain the same phase identity. No operation, command, parameter, authority or
evidence envelope is invented by the transition. EOF has a typed failure path.
The release policy pins the changed canonical worker payload digest.

| Controlled boundary | Required observed result |
| --- | --- |
| Worker loss after hello, before plan receipt | Protocol `IntegrityFailed/PRIVILEGE.WORKER_LOST`; assessment `NotStarted/20`, collection false |
| Worker loss after synthetic firmware collection returns, before final envelopes | Protocol `IntegrityFailed/PRIVILEGE.WORKER_LOST`; assessment `IntegrityFailed/50`, collection true |
| Worker exceeds the combined deadline | `TimedOut/40`; the retained 30-second fault exceeds the 17.75-second combined budget |
| Operator cancellation during privileged work | `Cancelled/30`, verified owned cleanup |

Both loss cases retain zero admitted operations, no SYSTEM scheduling and no
package. The post-start test executes the actual controlled worker and writes
only a fixed synthetic witness after its firmware reducer returns, before
exiting. The witness is removed with its conclusively owned test directory.
Eleven protocol cases cover identity/shape rejection, pre/post-start loss,
final-phase consistency and success. Actual loss is also tested without a
scenario-specific failure-reason substitution. All work is unelevated and
synthetic; there are no real device reads or UAC operations.

## RED/GREEN and affected qualification

| Observed failure, preserved | Correction and retained witness |
| --- | --- |
| On start product bytes, `ContractFormats.Tests.ps1` expected `CONTRACT.FORMAT_INVALID` for `not-a-time` but received `CONTRACT.ACCEPTED`. | Shared semantic format enforcement; exported format matrix. |
| On start product bytes, package record test expected `IntegrityFailed` but creation returned `Verified` for a malformed provenance timestamp. | Shared admission refuses malformed formats before naming, authenticated reopening and viewing. |
| On product `72d3fd7…`, controlled firmware returned and its worker died, but the assessment reported `NotStarted` instead of `IntegrityFailed`. | Authenticated execution transition; retained generated Status desk post-start loss test. |
| First affected run at `f340cc1…`, candidate `3052ec01d9f2c90957c1d9d671b6b0820bf6abec9ef9af888a84b8b080cf4468` (3,319,155 bytes): 15 checks passed, then SYSTEM's valid typed timestamp round trip failed with `CONTRACT.FORMAT_INVALID`. Remaining checks did not run. | Commit `447c730…` aligns SYSTEM schema and semantics on canonical JSON; the existing boundary test now covers all five cultures. |

**All 25 final affected checks passed**, in **565.410 seconds**, against the
exact corrected product/test checkpoint above. The
[machine-readable evidence](issue-154-review-corrections-results.json) records
the serialized command inventory, timings, exit codes, log/test hashes, build
inputs, 12 passing changed/generated PowerShell syntax checks, the exact test
tree and all 493 tracked test/input fingerprints. Native helper compilation and
typed protocol execution pass through the privilege and SYSTEM checks.

The final round includes exported validator and semantic-matrix tests,
protected record admission/viewing/buffers, redirected Unicode/ANSI output,
certificate cultures, privilege policy/protocol/generated application,
contiguous SYSTEM execution, three privileged collector projections,
post-start/early-loss/deadline/cancellation and ordinary controlled assessment,
inline worker representation and deterministic builds. The pinned official
selection was freshly rerun: **573 Pass, 177 justified NotApplicable, zero Fail,
zero external fetches**. All four installed validator assembly hashes match
the recorded toolchain. Candidate bytes remain unchanged after every check.

## Review and remaining qualification

Implement, TDD and Code Review were invoked. Existing seams and GUI/certificate
choices were already authorized. The fixed point resolves, the three-dot diff
is nonempty, and all correction commits carry DCO sign-offs. Root owns both
fresh independent affected review axes; no retained app-agent slots were used.

```text
git diff 8a2663ebf58133a2a6fb7d0602ada215b24c748e...HEAD
git log 8a2663ebf58133a2a6fb7d0602ada215b24c748e..HEAD --format=full
```

Assigned spec: supplied current `issues/154.json` (Open, orchestrator claim),
with normative #134/#37 and #158 allocation snapshots. Its dependencies
#137/#138/#152/#179 are Closed in the supplied snapshot. Standards sources:
original-checkout `AGENTS.md`, `CONTEXT.md` and
`docs/agents/{issue-tracker,triage-labels,domain}.md`; integration
`CONTRIBUTING.md`, `.sandcastle/CODING_STANDARDS.md`; the Code Review skill's
twelve smell heuristics. Neither checkout has relevant ADR files. The user's
focused-test override reserves `tests/Run-Tests.ps1` for #158/final.

After the affected reviews, root must refresh affected exact-candidate
generated qualification, including the source, additional-scope, culture,
safety and interruption modes of `Invoke-AssessmentSafetyQualification.ps1`,
their scope/state map and the retained post-start regression. The previous
343-case/676-pair/99-scope result is **historical**, tied to product `3b337547…`,
test `2a9f71fd…` and candidate `1c2e77746a5714ff01206868e1c39027a83e12ae5b3b86ea60c1387797466a49`
(3,312,123 bytes). It is not a pass for either correction candidate. All earlier
failures and identities remain in [the historical qualification](issue-154-automated-qualification.md).
No unchanged evidence is relabeled as current execution.

Full repository regression remains NotRun here, assigned to #158/final.
Independent live gates #160–#164 remain Pending. The held private signed
variant, keys, trust and profiles were not accessed or changed. Changed bytes
have no inherited signing approval. Root owns ledger updates and all GitHub
mutations. No push, PR, merge, closure, publication or public upload occurred.
The September 7 05:00 UTC cutoff is unchanged; required refreshed qualification,
independent reviews and live acceptance remain schedule risks, never waivers.
At the September 7 01:11 UTC evidence checkpoint, the cutoff had not passed;
approximately 3 hours 49 minutes remained. No complete private-handoff or
release-acceptance claim follows from these automated corrections.
