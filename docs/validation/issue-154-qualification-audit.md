# #154 qualification audit and authenticated framing checkpoint

Specification: [#154](https://github.com/jmanuelng/WIN_PCinfo/issues/154), with
the inherited [#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37) testing
decisions and [#134](https://github.com/jmanuelng/WIN_PCinfo/issues/134).
**Partial; #154 remains open.** This document advances the earlier
[package admission checkpoint](issue-154-package-admission-checkpoint.md).

Starting revision and Code Review fixed point:
`7f36c092f089ae1671f841f7dc98c2e404aceee1`.
New test source: `ec37eefad17f8c7db326c22b6943f5eab18ea019` (DCO signed).
No production code, release schema, build input or cryptographic engine changed.

## Newly executed qualification

On September 6, 2026, the installed PowerShell Core 7.6.5 X64 executed:

```powershell
pwsh -NoLogo -NoProfile -File tests/ProtectedPackageFraming.Tests.ps1
```

**Pass**, exit 0, 1.94 seconds. A synthetic package containing at least three
authenticated chunks first finalizes successfully. Nine independently mutated
copies then fail with `IntegrityFailed`, `verified=false`, no returned artifacts,
and refusal to create a viewing directory or recovery journal:

| Mutation | Property qualified |
| --- | --- |
| Leading whitespace in the header, with adjusted header byte length | The parsed header still passes structural admission and has identical values. Its exact bytes are authenticated as associated data. |
| First ciphertext byte | Ciphertext authentication is tested separately from tag corruption. |
| First frame's tag byte | Full-tag integrity is required. |
| Nonce byte | The declared nonce sequence cannot be changed. |
| Chunk index | Chunk placement is checked. |
| Plaintext length | Frame length cannot disagree with the declared envelope. |
| First two complete frames swapped | A valid collection of frames cannot be reordered. |
| Entire final chunk removed | Earlier authenticated chunks are insufficient for completion. |
| Byte appended after final frame | A valid prefix cannot admit trailing content. |

The unchanged canonical package reopens afterward. The unique synthetic test
directory is removed after checking its resolved parent; caller-owned plaintext
record/report buffers and returned positive artifacts are cleared. The test is
automatically discovered by `Run-Tests.ps1`. These were missing explicit
qualification cases for already-correct behavior: they passed on their first
execution, so there is no claimed red-to-green product repair.

The earlier alias correction remains source
`0d8aed50f57b9aad9b31195a7781b8d46781180e`, with its separately recorded passing
checks and independent reviews. Its unchanged matrices were not rerun.

The existing local generated application still hashes to
`03b56dd606dd443e200f24c1504598274f2e54f5619022eaf0c2ac13a94a0956`
(3,305,322 bytes as recorded by the preceding checkpoint). This continuation
checked the existing artifact's digest; it did not rebuild or repeat generated
application qualification. Test/document commits do not promote that candidate
to full current integrated acceptance. The #158/final full suite is **NotRun**.

## Exact structural validator identity

After invoking `Microsoft.PowerShell.Utility\Test-Json` in the installed runtime,
the loaded assemblies were inspected through `AppDomain.CurrentDomain.GetAssemblies()`;
file versions came from `FileVersionInfo`, and file hashes from `Get-FileHash`.
Runtime: PowerShell 7.6.5; .NET 10.0.11. SHA-256 identities:

| Loaded assembly | Assembly version / file version | SHA-256 |
| --- | --- | --- |
| Microsoft.PowerShell.Commands.Utility | 7.6.0.500 / 7.6.5.500 | `2f6201bb3caf4c08158be733e786dd85b11537694f7e6ab40356fc0727a3596f` |
| JsonSchema.Net | 7.0.0.0 / 7.4.0 | `879c8631777b621ff25e939f021f06dfb2745c3a98e8cd5a281f6eee9da77aa6` |
| JsonPointer.Net | 5.0.0.0 / 5.3.1 | `aefde47dbcb4e96a0280630138430e74d518e4eff79967377d05104b4c40707f` |
| Json.More | 2.0.0.0 / 2.1.1 | `95dd96afb294c5243f369b1f8510d5f70c15715746982470382362c0e88f1d4d` |

`RuntimeCompatibility.ps1` admits the Utility cmdlet provenance;
`ContractValidator.ps1` calls its supplied trusted `TestJsonCommand` with the
release-bound Assessment Record schema. Qualification must use this actual
cmdlet/configuration, not a separately installed validator bearing the same name.
Other runtime versions require their own evidence.

Schema keyword inventory was read recursively from schema-valued nodes,
including `$defs`, `properties`, applicators and dependent schemas. Property
names inside instance definitions were not counted as schema keywords.

| Release schema | SHA-256 |
| --- | --- |
| `assessment-record.schema.json` | `6d4558aad6ff39881080522995e1d6f2e7218d0c54ab6e1d4619e895a1bf3f68` |
| `assessment-contract-set.schema.json` | `18ce72ffdfb09c07f17ccdc73847bf382b6d1e9387576484c1a3e73769ac7f39` |
| `protected-package-envelope.schema.json` | `fd7d896512158d20ef9600ab7128bc5f2cf3cda0dd2fb573c744c01006266895` |
| `assessment-package-manifest.schema.json` | `bccd195f04d1fbe1c7de71859415b1ac9c09a0829920a38be344ea7c21abea5a` |

All four use `$schema`, `$id`, `title`, `type`, `properties`, `required`,
`additionalProperties`, `const`, `enum`, `pattern`, `minimum` and `maximum`.
Record/Contract Set/manifest additionally use `$defs`, `$ref`, `items`,
`minItems`, and `maxItems`. Record/Contract Set/envelope use `minLength` and
`maxLength`. Record and Contract Set use `uniqueItems`. Record/envelope/manifest
use `allOf`, `if` and `then`; envelope also uses `else`. Record alone uses
`anyOf`, `dependentSchemas` and `format`; manifest uses `prefixItems`.
Boolean subschemas are also applicable (for example, `additionalProperties:false`).

### Official-test applicability and input authority

The repository's two `prefixItems` probes in `AssessmentContractSet.Tests.ps1`
are useful dialect checks. They have no recorded official-suite case identity
and do not qualify the above keyword set. The historical #40 evidence cannot
establish exact current validator qualification. This is an **open evidence
requirement**, not an observed failure of JsonSchema.Net.

The [official JSON Schema Test Suite](https://github.com/json-schema-org/JSON-Schema-Test-Suite)
provides language-neutral cases grouped under each draft. Read-only upstream
metadata identified this proposed immutable input:

- Repository commit: `c9510e3bf8a896c3cba4e08509cf752b4f30dff8`.
- `tests/draft2020-12` Git tree SHA-1: `db5782b10c73f2eee7bd3c9a0c57cfe24390e9b9`.
- [License at that revision](https://github.com/json-schema-org/JSON-Schema-Test-Suite/blob/c9510e3bf8a896c3cba4e08509cf752b4f30dff8/LICENSE): MIT; Git blob SHA-1 `c28adbadd9114a30a302fef37c3d14f490645c1c`.
- Applicable file families: `boolean_schema`, `defs`, `ref`, `type`, `const`,
  `enum`, `properties`, `required`, `additionalProperties`, `allOf`, `anyOf`,
  `dependentSchemas`, `if-then-else`, `items`, `prefixItems`, `minimum`,
  `maximum`, `minItems`, `maxItems`, `minLength`, `maxLength`, `pattern`,
  `uniqueItems`, and `format` (each a `.json` file under that draft).

Next owner must select and record exact cases within these families for the
release-used combinations and offline local references, establish the actual
cmdlet's format assertion configuration, and include applicable Unicode/pattern
and format cases. `$id`/`$schema` resolution behavior is part of that selection;
`title` is annotation-only. Unused remote resolution, dynamic references and
other unused vocabularies must receive explicit applicability reasons, not a
whole-corpus obligation or silent pass. A hand-authored imitation is insufficient
to meet the explicit official-test requirement.

No corpus was downloaded, vendored, executed or installed. Metadata and license
identity were read only; the Git hashes above are not claimed SHA-256 download
checksums. The dispatch authorizes only already-approved pinned acquisitions,
and no approval for this corpus was supplied. Before acquiring it, root must
resolve that specific authority and preserve the exact pin/license, then record
acquired-byte SHA-256 and case selection. Independent repository qualification
can continue meanwhile. This is not a request for a new validator dependency.

## Coverage applicability: established boundary and remaining mapping

Contract Set 1.13.0 declares 104 scopes. Filtering `scopeDefinitions.profileIds`
for `profile:device-firmware-identity-administrator-policy-software-resource-network-certificate-and-microsoft-connectivity-readiness`
selects 99 definitions. These are definitions admitted by that profile, not a
claim that all 99 collectors ran in any particular execution. Count by the
declared collector set:

| Collector boundary | Scope definitions |
| --- | ---: |
| Device context / device-context classifier | 1 |
| Effective policy | 46 |
| Firmware security | 3 |
| Local-administrator direct membership | 1 |
| Local network topology | 9 |
| MDM device manageability | 9 |
| Microsoft connectivity | 8 |
| Purpose-bound certificate trust | 6 |
| Registration and user context | 2 |
| Resource dependencies | 5 |
| Software inventory | 8 |
| Work/school context | 1 |

The 104-definition catalog must not be substituted for actual selected-plan
coverage. Local Only versus approved Microsoft Connectivity, initiating-user
versus administrator/SYSTEM availability, Windows feature support, source
presence and collection lifecycle determine applicable states. In particular,
an unexecuted source cannot earn a successful empty observation; policy or OS
inapplicability must retain its defined reason. Cancellation and NotAttempted
belong to the orchestrator's actual scheduling boundary, not invented source
payload variants.

The following source audit resolves the collector-family entry points. Each
`*SourceApplication.Tests.ps1` below invokes the generated Status desk engine
with controlled OS boundaries; its sibling `*SourceAdapters.ps1` contains the
record/report assertions. These are concrete existing checks, not newly run
results. Exact per-case historical results are in the linked ticket evidence.

| Selected scopes / source family | Existing scenario entry points and applicability |
| --- | --- |
| Device context and three firmware scopes | [#140](issue-140-device-firmware-evidence.md), `ReadinessSourceApplication`: Complete, Denied, NullLicense, MixedUnknownLicense, Bounded, Absent, Unsupported, Malformed, Virtual, MicrosoftPhysical, FirmwareBounded, TimedOut, MalformedOutput, OversizeOutput, Cancelled. Missing activation is SourceReportedUnknown; bounded source output cannot become complete observations. Firmware rule NotApplicable on legacy BIOS must remain distinct from unsupported collection. |
| Registration/user/work-school, administrator membership, SYSTEM manageability | [#141](issue-141-identity-enrollment-evidence.md), `IdentitySourceApplication`: join/workgroup, separate user/session, UserDenied/UserUnavailable, WorkSchoolDenied, AadMalformed, UnknownJoin, AdminDenied/AdminUnavailable/AdminEmpty/AdminPartial, SystemDenied/SystemUnavailable/SystemAbsent. Administrator coverage is respectively Denied/Failed/Complete/Partial; only Complete yields Informational membership advice, otherwise Indeterminate. SID-only names are SourceReportedUnknown. SYSTEM discovery preserves Denied/Unavailable/Complete, with successful absence an observation. |
| Applied/local-security policy and MDM result scopes | [#142](issue-142-policy-evidence.md), `PolicySourceApplication`: namespace/context/session negatives, reference collisions, SecurityDenied/SecurityAbsent/RightsBound, MdmDenied/MdmAbsent/MdmUnsupportedBuild/MdmMissingProperty/MdmUnavailable, conflict and precedence. Local rights above the direct-principal bound are Partial. NonMdm and denied administrator/SYSTEM fixtures are retained by `EffectivePolicyApplication.Tests.ps1`; unexecuted privileged work cannot claim a successful empty policy. |
| Defender, firewall, ASR, SmartScreen | [#143](issue-143-security-evidence.md), `SecuritySourceApplication`: Active/Passive, Unsupported/ImportDenied/Denied/Unavailable, NullRuntime/MalformedRuntime, FirewallPartial, AsrEmpty/AsrBound/AsrMismatch, NetworkMissing, SmartScreenMissing/SmartScreenMalformed, CultureMode and explicit culture arguments. Null source values do not mean disabled controls. Missing providers, denied import and malformed payloads retain distinct scope reasons. |
| BitLocker, VBS, WDAC, GP/CSP AppLocker | [#144](issue-144-platform-evidence.md), `PlatformSourceApplication`: Running/Unencrypted/Configured, VbsPartial/VbsMalformed, BitLockerPartial/ProtectorBound, GpMalformed, WdacOld/WdacMalformed/WdacBound, CspDenied/CspMissing/CspMalformed/CspConflict, Denied/Unsupported/Unavailable. Old WDAC builds are Unsupported; policy inventory can remain Partial despite returned entries. GP/CSP channel disagreements do not choose a winner. |
| Update/legacy auth/RDP/WinRM/SMB policy scopes | [#145 final bound correction](issue-145-enumeration-bound.md), `RemoteSourceApplication`: Configured/Absent/Denied/RegistryDenied/Unsupported/Malformed/Partial/Unavailable; certificate-Boolean kind/range cases; listener missing/unknown/multiple/disabled/growth/limit/enumeration denial/name bounds. Readable local WinRM listener enumeration remains Partial because it does not establish all effective listeners. These corrected tests supersede historical placeholder evidence. |
| Eight software scopes | [#146](issue-146-software-source-flow.md), `SoftwareSourceApplication`: Complete executes all eight; AlternateAdministrator makes all eight Denied; DeniedUser affects the two user registry views; DeniedAllUsers affects machine MSIX; MsiDenied/MsiCompilerDenied affect both MSI scopes without erasing registry/package evidence. Recognition Composite/Ambiguous/Withdrawn/LogicalFailure belongs to interpretation, not invented inventory collection failure. |
| Five resource scopes | [#147](issue-147-resource-source-flow.md), `ResourceSourceApplication`: mapped drives Complete/Denied/Partial via RegistryDenied/ConnectionDenied/Oversize; UNC connections Complete/Denied; printers Partial/Denied; printer drivers Complete despite unrelated gaps; peripherals Complete/Partial/Failed via Maximum/PeripheralUnavailable. Cached remote printer details cannot qualify Complete migration guidance: finding stays Indeterminate. Unavailable remote port is SourceReportedUnknown, without contacting the printer. |
| Nine local network scopes | [#148](issue-148-local-topology.md), `NetworkSourceApplication`: adapters Complete/Denied/Partial (including MalformedInterface); proxy Complete/Malformed/Denied via MalformedProxy/ProxyOversize/ProxyDenied; routes remain Complete despite unrelated failures; security-components remains Unsupported with `NETWORK.SECURITY_COMPONENT_OFFLINE_SOURCE_UNAVAILABLE`. Local Only explicitly keeps connectivity TLS and enrollment DNS NotAttempted. Disconnected interfaces do not imply absent network configuration. |
| Six certificate purposes | [#149](issue-149-certificate-trust.md), `CertificateSourceApplication`: four attributable purposes Complete/Denied/Constrained, code-trust Partial when one selected store is denied; AlternateAdministrator denies all six. Two purposes without approved attribution remain NotApplicable. MissingEku/AbsentPurpose give Complete selection with no matching observation and NotApplicable findings. Expired/NotYetValid give NeedsAttention validity; Untrusted gives NeedsAttention trust; incomplete chain gives Indeterminate trust. Coverage gaps give Indeterminate findings and cannot borrow another purpose's references. |
| Eight connectivity scopes | [#150](issue-150-microsoft-connectivity.md), `ConnectivitySourceApplication`: Direct/WindowsProxy/ProxyOnly, Blocked/Partial/DnsFailure/Timeout, InvalidChain/Redirect/ProxyBlocked/AutomaticProxy/ContextChanged/LocalOnly, ProxyInvalidChain/ProxyTlsFailure. All eight scopes remain present. LocalOnly has zero protocol requests. A proxy TLS failure remains a path-specific observation; direct TLS NotAttempted must not be overwritten by proxy evidence. Failed/TimedOut protocol values are not automatically the same as coverage or run terminal states. |

Shared lifecycle applicability is established separately by
`RunLifecycle.Tests.ps1`: Cancelled/exit 30 and TimedOut/exit 40 retain matching
scope states, worker loss yields Failed coverage with IntegrityFailed/exit 50,
and failed package finalization emits no Assessment Record. Those tests use a
representative collector seam; they are not proof of every selected collector's
interruption propagation. `DeviceReadinessContract.Tests.ps1` separately
exercises ProhibitedMaterialBlocked with its required marker diagnostic.

**Remaining state qualification is now specific:** for the 99 selected
definitions, attach each exact scope to the relevant assertions above, fill
uncovered applicable source states, and prove orchestration propagation for
collectors not covered by the representative timeout/cancel/worker-loss cases.
Record justified inapplicability from each source/plan contract, including
conditional connectivity and privileged scheduling. The matrix resolves known
existing behavior; it does not assert unexamined state combinations passed.

## Existing evidence and exact remaining acceptance work

This table is a source audit, not a fresh run of the listed unchanged tests.
Reuse a recorded result only after establishing identical tested code, inputs,
toolchain and environment; historical candidate hashes are not current passes.

| Requirement | Established checks / remaining obligation |
| --- | --- |
| Wire, definitions and semantics | `ContractValidator.Tests.ps1` exercises duplicate properties, invalid UTF-8/Unicode, byte/depth/safe-integer bounds, incompatible major, unsupported feature, secret-bearing field, dangling reference, graph cycle, inconsistent coverage and field bounds through the generated application. `ContractSemanticMatrix.Tests.ps1` adds 18 ambiguous-reference, state, provenance, collector, scope and graph cases. Complete current applicability and exact-result linkage remain pending. |
| Observation/finding/diagnostic/run distinctions | Semantic matrix rejects observation-value conflicts, finding conflicts and invalid NotStarted/Cancelled/TimedOut/IntegrityFailed/CleanupIncomplete combinations. Report tests distinguish observed absence and source-reported unknown. This does not replace the 99-scope applicability map. |
| Crypto/protectors | Earlier checkpoint refreshes known-answer, fresh keys, nonce bounds, DPAPI reopen and synthetic wrong user/device. New framing test closes explicit AAD/order/final-chunk/trailing-content negatives. `RecipientProfile.Tests.ps1` covers synthetic hardware/software provider classification, public-only profiles, 3072 default/2048 minimum, wrong fingerprint and expired-new-package rejection. `ProtectedPackageRecipient.Tests.ps1` retains RSA-OAEP-SHA-256, additional local access and historical decryption. Live provider/context evidence remains #161/#162. |
| Controlled buffer clearing | Production package writer/reader has `finally` clearing of content keys, chunk plaintext, associated data and inner bytes. Tests clear owned plaintext and key buffers. This source audit is not proof of every exceptional allocation path; complete controllable-buffer failure-path evidence remains pending, without a forensic-erasure claim. |
| Invalid/incompatible/oversized/interrupted package | Negative, admission, write-failure, viewing and generated package tests cover archive/manifest/digest, historical bound and unknown format, size limits, interruption and verified finalization. Complete mapping of incompatible Assessment Record cases inside authenticated packages to refusal before final naming/viewing remains pending. Do not infer it solely from standalone validator rejection. |
| Marker-only secrets/public output | `DeviceReadinessContract.Tests.ps1` rejects a prohibited source payload and asserts marker `retained=false`, `hashed=false`. `ContractValidator.Tests.ps1` rejects a synthetic secret field and searches stdout for its literal. That stdout assertion alone does not prove exclusion of a transformed/hash value from every retained artifact. Complete controlled-marker tracing across selected input/output, diagnostics, package/report, progress and retention routes remains pending. |
| Cleanup ownership | Earlier #138/#152 recovery and package-view/write tests retain identity checks, cleanup-failure gates and ownership-safe refusal. The new nine negatives add no view/journal and preserve the canonical package. Do not treat that as a fresh run of all cleanup paths. |
| Five cultures and Unicode | `ComprehensiveReport.Tests.ps1` supplies explicit en-US/es-MX/tr-TR/ja-JP/ar-SA strings; `ReportContractAssertions.ps1` sets both cultures, compares deterministic UTF-8 rendering, and checks emoji/escaped-suffix reconstruction. `SecuritySourceApplication.Tests.ps1` permits explicit culture scenarios; its default list names the four non-English cultures, while #143 records the explicit five-culture run. `PrivilegedInlineRepresentation.Tests.ps1` loops all five for command representation. Report input/render and command-transport applicability is mapped; exact current all-source JSON/redirected-output evidence and a dedicated ANSI exclusion assertion were not established by this audit. Real non-English Windows is #161/#162. |

The public-output boundary has concrete existing checks beyond the single
contract marker: `ResourceDependenciesApplication.Tests.ps1` rejects synthetic
file/printer/peripheral/SID markers from stdout; `NetworkTopologyApplication.Tests.ps1`
rejects synthetic network ranges, adapter/profile/proxy and Unicode markers;
`CertificateTrustApplication.Tests.ps1` rejects certificate identity markers.
Each rejects nonempty stderr. `ProtectedPackageApplication.Tests.ps1` checks
one result/terminal, matching exit/package-finalized status, no exposed content,
no key/nonce/path identifiers in its public projection, and no new residue.
The Assessment Record marker schema admits only encountered/retained/hashed,
with the latter two fixed false; semantic validation requires such a marker
for ProhibitedMaterialBlocked. This resolves marker shape and named projection
coverage. The remaining privacy work is end-to-end retention/transform checking
for prohibited source inputs across other applicable collector families, not
retesting those unchanged projection assertions.

## Review and next owner

Implement, TDD and Code Review invoked. Code Review fixed point:
`7f36c092f089ae1671f841f7dc98c2e404aceee1`.
Review commands:

```text
git diff 7f36c092f089ae1671f841f7dc98c2e404aceee1...HEAD
git log 7f36c092f089ae1671f841f7dc98c2e404aceee1..HEAD --oneline
```

**Standards: Pending. Spec: Pending.** Root dispatches the two fresh independent
axes under the established retained-slot handoff. Standards sources: original
checkout `AGENTS.md`, `CONTEXT.md`, `docs/agents/{issue-tracker,triage-labels,domain}.md`;
integration `CONTRIBUTING.md`, `.sandcastle/CODING_STANDARDS.md`; Code Review smell
baseline. Assigned spec is #154 with #134/#37 and #158 allocation context.

Root retains #154 open, records this bounded progress, and arranges a fresh
continuation for the official-case qualification and remaining acceptance maps.
No issue/ledger, push, PR, merge, closure, live collection, UAC, trust, installed
key, signing, cloud or private #160 operation occurred. #158 full regression and
#161/#162 live acceptance remain distinct pending gates.
