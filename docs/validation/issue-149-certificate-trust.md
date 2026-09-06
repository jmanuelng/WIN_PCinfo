# Purpose-bound certificate implementation (#149)

Starting revision: `a5df6b5b021333ffd658b51fbc4137e5bfab621e`. The #137 blocker
is merged, and #148 was merged during this slice. This evidence is exclusively
controlled and synthetic. No real certificate store was read, live assessment
run, key accessed/exported, certificate created, trust modified, candidate signed,
observer activated or release published by this slice.

The existing generated certificate collector, twelve-field contract, purpose
policy, advisory rules, protected package and report remain in use. The actual
source now stops metadata/chain processing after eight matching candidates per
purpose, including malformed matches; a ninth match retains Constrained coverage
instead of processing every match and truncating only afterward. All certificate
objects from the worker-local Windows store snapshot are disposed, including
unselected objects. No unrestricted inventory is emitted. The unchanged 30-second
worker deadline and 131,072-byte output bound remain in force; this does not bound
the memory Windows uses to materialize its store snapshot.

Well-formed certificates without EKU are excluded from purpose selection rather
than reported as malformed. Native E_ACCESSDENIED, UnauthorizedAccessException and
SecurityException retain Denied coverage through bounded exception unwrapping;
other store failures remain Unavailable. Partial multi-store access retains
successful candidates and a scoped reason. Admission rejects contradictory
incomplete/unevaluated chain trust, alternate-user observations, successful
candidates under denied/unexamined scopes and reversed date intervals.

The HTML identifies the selected user/machine stores and coverage reason beside
each purpose, preserves Restricted candidate metadata, and separates assessment
observations from signing trust and Package Recipient setup. Purpose ownership,
remote acceptance, revocation and key-exportability remain unproven unless the
existing permitted observation supports them. TLS inspection and service purposes
without approved attributable targets remain NotApplicable. Both approved network
behaviors, recipient/signing paths, native privileged/SYSTEM sources, exact nested
worker bytes and their limits are unchanged.

## Controlled validation

Installed PowerShell Core 7.6.5 X64 runs the existing harness. The new test adapter
executes the actual generated store-selection/reduction and chain-policy source,
replacing only Windows identity/store/chain APIs and the snapshot transport in
test memory. The ordinary Comprehensive scheduler, canonical validation, advisory
rules, encryption, package reopening, HTML and protected viewing execute normally.
Other capability sources use existing controlled adapters. There is no shipped
adapter CLI and no fixture authorization for live collection. These tests do not
measure Windows store behavior, native worker attribution or actual egress.

Observed red cases: chain work continued beyond the candidate limit; malformed
matches bypassed the processing budget; absent EKU became Malformed; a native
cryptographic access denial became Unavailable; contradictory chain/context/scope
and date payloads were admitted; HTML omitted explicit setup separation and
selected store context. Corresponding regressions now pass. A test-only
ScriptMethod added an extra RuntimeException wrapper to synthetic store denial;
the adapter was corrected to throw directly at the Open API boundary. That
harness correction is not a product or live-device result.

| Focused gate | Status |
| --- | --- |
| CertificateSourceApplication | Pass: all 14 scenarios across the initial and affected correction runs; 21.4–31.5 seconds per case. Includes bounded/malformed-bound, missing EKU, validity/trust/chain states, multiple candidates, typed/native denial, partial/absent and alternate-admin contexts; exact 12 fields, provenance, per-purpose advisory references, reopened HTML and owned cleanup |
| CertificateSourceBounds | Pass: malformed matches consume the bound, seven candidates per purpose survive, 48 snapshot objects / four stores / 32 chains dispose; native cryptographic access denial is Denied |
| CertificateTrustAdmission | Pass: incomplete-but-trusted, alternate-admin observations, denied-scope candidates and reversed validity intervals are rejected |
| CertificateTrust / CertificateTrustPolicy | Pass: existing twelve scenario reducers, privacy negatives, scoped rules and unchanged finite offline policy |
| CertificateTrustNativeSource / LocalOnlyRequestBoundary | Pass: actual source parsing/safety and unchanged NoCheck/download-disable checks, including fail-closed missing capability and zero LocalOnly request-adapter dispatch |
| Existing generated CertificateTrustApplication / final deterministic candidate | Pending final focused execution and artifact digest capture |
| Whole repository regression / live acceptance | Pending #158/#161 under the user's focused per-ticket test cadence |

Generated synthetic assessment packages and plaintext viewing are removed through
the existing verified owned-cleanup harness. Ignored local build outputs remain
available for review. No private identities or real assessment artifacts enter
public evidence. Exact final candidate identity and independent review outcomes
will be recorded here before ticket handoff.

## Requirement register contribution

| Requirement | Implementation disposition | Next owner |
| --- | --- | --- |
| #37 story 47; CAP-0014; CMP-0014 and certificate portion of CMP-0023 | Controlled purpose-selected user/machine source, bounds, metadata, advisory findings, package and HTML repaired and under focused validation | #161 private real source comparison; #158 integrated acceptance |
| #37 stories 49–54,66–67,69; #134 GUI stories 19–21,24 | Bounded #149 contribution: scoped missing evidence and references, privacy, stable values, unchanged preparation and protected workflow | #151 broader report/recommendation work; #158/#161 full integration/locale/GUI acceptance |
| Local Only implicit chain/revocation/assessment requests | Controlled call boundaries pass; live zero-egress conclusion remains Blocked by delegated DNS/service attribution method | #160/#161 approved minimized observer method; #150 enabled connectivity |
| Validity, trust, incomplete chains, multiple/absent purposes, denial, virtual and alternate-admin contexts on actual devices | NotStarted for this slice; synthetic evidence does not establish real acceptance | #161 private comparison checklist |
| Full #37 sub-objectives 7–9 / #134 delivery and quality gates | Pending complete application and release acceptance; CMP-0061 remains deferred | #158/#161 and #162–#164 release owners |

The orchestrator carries this contribution into the shared #134 requirement
register through the merged evidence and durable orchestration ledger; #158 owns
aggregation. Parent #37/#134 remain unchanged. The
[private comparison criteria](issue-149-readonly-comparison.md) retain live gates
without public certificate identities. The separate signed private #160 candidate
is untouched; changed application bytes cannot inherit its signatures. Historical
#138 working-set measurements of 662–755 MiB exceed the provisional 512 MiB budget;
no focused certificate test waives that acceptance requirement. September 6
remains the complete private handoff target.
