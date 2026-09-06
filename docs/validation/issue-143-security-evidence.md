# Security-control source execution (#143)

Fixed starting point: `89533db43d22256bdec59cc81590077a42359ec7`.
Native blockers #137 and #139 were merged/CLOSED before this work. This is
controlled-source implementation evidence only; actual device acceptance is
pending #161. No live assessment, security setting/service change, UAC, actual
SYSTEM task, certificate/trust operation, signing, network observation or cloud
operation is authorized or performed by this slice.

## Repairs and source basis

The existing generated Comprehensive engine, privilege protocol, scope catalog,
contract validator, rules, encrypted packaging and protected reopening are reused.
The new tests replace Windows API/module boundaries inside the generated worker;
other capability families retain synthetic prerequisite coverage. No test adapter
or fixture command is added to the delivered application.

- Windows inbox Defender and NetSecurity manifests export the three relevant
  operations as CDXML functions. Compiled-cmdlet-only discovery skipped them.
  Discovery now imports only the fixed inbox manifest beneath Windows System32
  and selects the declared exported operation, without ambient module search.
- The worker and release catalog ordered the same scopes differently. Admission
  now requires the exact set and multiplicity, and copying restores catalog order.
  Scope identity, bounds and field validation remain mandatory.
- Null/missing runtime properties retain Partial coverage without invented
  booleans. Malformed runtime data is cleared and scoped as Malformed; independent
  sources survive. Empty and ambiguous Defender result sets are explicit gaps.
- Firewall missing properties remain local to the affected profile. Present null
  ASR preference arrays represent an empty configured result; missing properties,
  unequal arrays, malformed entries and the sixteen-rule bound remain distinct.
- The constraint rule recognizes the documented `Passive Mode` and
  `SxS Passive Mode` values while retaining the observed mode. Microsoft describes
  these separately from normal active mode and EDR Block Mode in its
  [Defender Antivirus overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows).
  The rule does not derive tenant enrollment or primary-provider authority from
  a mode alone. Existing versioned advisory definitions remain applicable.
- The HTML previously omitted these security observations despite retaining them
  in the record. A bounded security section now shows all released Defender,
  Firewall, ASR, network protection, SmartScreen and tamper fields, scope reasons,
  configured/current labels, and individual evidence/provenance references.
  Provider registration/category health remain separate from runtime protection.

## Validation method and status

Use installed PowerShell Core 7.6.5 X64 and the shared UTF-8 harness. Generated
assessments run serially. Commands are relative to the integration checkout:

```powershell
pwsh -NoLogo -NoProfile -File tests/SecuritySourceApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File tests/EffectivePolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File tests/EffectivePolicyContract.Tests.ps1
pwsh -NoLogo -NoProfile -File tests/EffectivePolicyPrivilegedCollector.Tests.ps1
pwsh -NoLogo -NoProfile -File tests/PrivilegedCollectionPlanPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File tests/PolicyUserContextNativeSource.Tests.ps1
```

The source matrix includes Active, Passive, Unsupported inbox modules, Denied,
Unavailable, NullRuntime, MalformedRuntime, FirewallPartial, AsrEmpty, AsrBound,
AsrMismatch, NetworkMissing, SmartScreenMissing, SmartScreenMalformed, and
en-US/es-MX/tr-TR/ja-JP/ar-SA structured-source cultures. Every case uses actual
normalization, record validation, advisory rules, package verification, HTML,
registered viewing and owned cleanup. UTF-8 provider names are synthetic.

Observed red cases included skipped CDXML functions, scope-order rejection,
payload-wide rejection after missing/malformed runtime and Firewall properties,
null ASR arrays treated as malformed, documented passive mode not recognized,
empty source results reported only as partial fields, and omitted security HTML.
Test setup initially used catalog indices in a worker with a different scope order;
that setup failure is not source evidence. The controlled payload now follows
the worker's actual index layout before public admission/canonicalization.

The configured command-size guard initially failed after new source handling.
Redundant discovery/projection code and exception prose were reduced; no limit
was raised. The latest pre-review eight configured samples reached 32453 of
32500 characters. The actual guarded launcher still refuses an oversized launch;
future shared-source changes must repeat the configured tests. Device source
and nested SYSTEM bytes remain independently bounded and preserved.

Final focused results, exact candidate hashes and independent reviews are recorded
in the completion addendum after execution. Until then this document is not a
claim that the final focused gate has passed.

The full suite remains unrun here under the user's per-ticket cadence override;
#158/final owns integrated regression. Historical #138 working-set excess remains
unresolved acceptance evidence, not a waiver. The privately signed frozen #160
candidate, its keys/recipient, and actual observation gates remain separate from
these evolving source bytes.

## Requirement-register contribution

Root orchestration owns the shared #134 register. This contribution does not
modify that ledger or close a live gate.

| Requirement | This slice | Next owner |
| --- | --- | --- |
| #37 stories 32,35,38; CAP-0008; released CMP-0008/CMP-0020 security fields | Source-backed six-family execution, conservative versioned interpretation and explicit configured/current distinctions | #161 private per-family comparisons |
| Stories 49–54 | Existing findings/discovery tasks retained; missing coverage remains Indeterminate; source-linked readable HTML without compliance/remediation claims | #151 cross-domain report, #161 acceptance |
| Stories 66–67 | Synthetic data only; no secret-adjacent preference properties cross the worker projection; protected record/report and cleanup reused | #154 safety negatives, #158 integrated gate, #161 live protection |
| Story 69 | Required five structured-source cultures and Unicode regression | #161 real non-English run |
| #134 GUI stories 19–24 and full workflow gates | Generated Status desk worker through real record/package/HTML, controlled OS boundaries | #153 operability, #158 exact candidate, #161 live workflow acceptance |
| #37 sub-objectives 5,8,9 and final acceptance | Focused implementation evidence only | #158 integrated measurements; #161 delivered-app validation; #162–164 release gates |

Per-family read-only steps are in [the #161 comparison handoff](issue-143-readonly-comparison.md).
September 6 delivery still means before September 7 00:00 CDT / 05:00 UTC;
deadline clarification changes no acceptance requirement.
