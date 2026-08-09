# WinGet package-availability enrichment

This rulebook defines the optional WinGet enrichment of WIN-PCInfo software inventory. The governing decision is [Define opt-in WinGet package-availability assessment](https://github.com/jmanuelng/WIN_PCinfo/issues/36), part of the [WIN-PCInfo v2 product and release specification map](https://github.com/jmanuelng/WIN_PCinfo/issues/1).

The feature is deferred from `2.0.0-preview.1`. This document fixes its future contract so an implementation can be designed and validated without confusing package availability with software identity or deployment readiness.

## What this enrichment answers

When an operator opts in, WIN-PCInfo may ask one narrow question for discovered software:

> Did the verified Microsoft WinGet Community source report a potential package candidate during this Assessment Run?

The answer is a time-bound annotation on ordinary software inventory. It can help an Intune administrator identify one possible distribution lead for later investigation.

It does **not** establish that the application or package is:

- licensed, approved, safe, supported, current, or free of vulnerabilities;
- compatible with the assessed device or organization;
- ready for Microsoft Intune or another management service;
- suitable for silent installation, detection, update, removal, or replacement;
- the same product solely because a display name looks similar; or
- still present in WinGet after the recorded query time.

Ordinary software inventory and the release-bundled [Software Recognition Catalog](./software-recognition-catalog.md) remain independent. Failure or refusal of this enrichment never removes, changes, or hides collected inventory.

## Operator choice and network boundary

Package Availability is an optional checkbox within the software-inventory evaluation. It is off by default.

The Assessment Run Request records the choice before preparation. Automation must use an equally explicit option. Package Availability is incompatible with `Local Only`: the guided interface prevents the combination, while conflicting automation input returns `NotStarted` with correction guidance rather than silently widening network access or discarding requested work.

The single Preparation Summary explains that the authorized operation will:

1. run in the signed-in user's context;
2. verify and contact only the Microsoft WinGet Community source named `winget`;
3. refresh that source once;
4. accept that named source's agreement when required and explicitly approved;
5. use WinGet under the device's existing Windows and WinGet telemetry configuration; and
6. permit WinGet to retain its normally managed catalog cache.

The operator approves or declines the complete action once. Declining it produces `NotEvaluated` for the enrichment and does not stop other assessment work. WIN-PCInfo never changes WinGet settings, source-refresh intervals, source configuration, telemetry settings, Windows privacy settings, proxy settings, or security controls.

## Eligible WinGet environment

Preflight verifies all of the following before collection:

- an eligible, supported App Installer and WinGet deployment is available and registered for the signed-in user;
- the execution alias and required interfaces are usable in that user session;
- the exact source named `winget` matches the release-approved Microsoft source identity, type, and endpoint definition;
- the bundled structured client dependency is authentic, complete, and compatible; and
- the approved network action can run noninteractively within its bounds.

The feature never runs as `SYSTEM`, installs or repairs App Installer, enables an execution alias, resets a source, or modifies policy. Missing, old, unregistered, disabled, replaced, or policy-blocked WinGet prerequisites make only this enrichment `NotEvaluated` unless the failure proves the WIN-PCInfo release itself is altered.

Microsoft documents WinGet availability and common registration limitations in [Use the WinGet tool to install and manage applications](https://learn.microsoft.com/en-us/windows/package-manager/winget/) and [Troubleshooting WinGet](https://learn.microsoft.com/en-us/windows/package-manager/winget/troubleshooting).

## Exact source access and freshness

WIN-PCInfo targets only the verified source named `winget`. It never searches `msstore`, a custom source, or all configured sources for this feature.

During the approved preparation operation, the process supervisor invokes a bounded, noninteractive refresh of that named source. It evaluates stable process status and exit information only; localized command output is never parsed as evidence or control input. Source agreements are accepted only when that action was included in the approved Preparation Summary.

A successful, contemporaneous refresh is required before producing `CandidateObserved`, `AmbiguousCandidates`, or `NoCandidateObserved`. If freshness cannot be established, cached metadata is not used to make a current availability statement; the enrichment becomes `NotEvaluated` with a stable reason.

WIN-PCInfo does not retain a reusable copy of the WinGet catalog. The normal WinGet-managed cache may remain, as disclosed before approval. No WIN-PCInfo refresh service, scheduled task, background process, or catalog database is created.

Microsoft describes source commands in [winget source](https://learn.microsoft.com/en-us/windows/package-manager/winget/source) and its automatic source-update interval in [WinGet settings](https://learn.microsoft.com/en-us/windows/package-manager/winget/settings).

## Structured integration

The release carries one exact, unmodified `Microsoft.WinGet.Client` module package as a private dependency. WIN-PCInfo:

- preserves the module's complete official package layout, license, and notices;
- authenticates the containing WIN-PCInfo release and verifies every pinned dependency file;
- imports the module by its verified absolute manifest path, never by discovery through `PSModulePath`;
- records the exact module version and hashes in the dependency inventory, SBOM, and release provenance; and
- uses structured module objects constrained to the named `winget` source.

The `winget` command-line interface is used only for the consented named-source refresh. WIN-PCInfo never parses `winget list`, `search`, or other presentation-oriented table output. It does not install a PowerShell module from PowerShell Gallery during an Assessment Run.

The client module reports WinGet's structured correlation but does not expose every internal match criterion. The evidence therefore records `WinGetEngine` as the correlation basis and adds ProductCode or Package Family Name corroboration only when demonstrable from structured values. WIN-PCInfo never invents a hidden match reason. A more complex direct COM adapter is not required by this contract.

The WinGet project is MIT licensed; releases must retain the applicable [license](https://github.com/microsoft/winget-cli/blob/master/LICENSE) and [third-party notices](https://github.com/microsoft/winget-cli/blob/master/NOTICE).

## Evaluation scope and outcomes

Structured WinGet results are compared with all normalized installed-application observations inside the release-defined Package Availability scope, not only applications recognized by the Software Recognition Catalog.

Every in-scope application receives exactly one **Package Availability Outcome**:

| Outcome | Meaning |
| --- | --- |
| `CandidateObserved` | One structured candidate was reported by the verified, freshly updated source. |
| `AmbiguousCandidates` | More than one plausible structured candidate remains and WIN-PCInfo does not choose a winner. |
| `NoCandidateObserved` | The approved source and evaluation completed, but no candidate was reported for that application. This does not prove that no package exists elsewhere. |
| `NotEvaluated` | The application or enrichment could not be evaluated safely or completely; a stable reason is required. |

Release-defined exclusions such as updates, drivers, frameworks, resource packages, or observations without sufficient identity remain visible in ordinary inventory and receive `NotEvaluated` when they fall inside the declared accounting boundary. Catalog order, display-name similarity, or an unrestricted fuzzy search never chooses a candidate.

The beginner-facing wording for a positive result is:

> Package candidate found in the Microsoft WinGet Community source.

The report shows the query time and progressively discloses the candidate and correlation details. It does not shorten the statement to an unqualified “Available in WinGet.”

Installed and available version strings may be retained as restricted supporting evidence when WinGet supplies them. They do not produce an update, currency, security, or lifecycle conclusion in this feature.

## Evidence and privacy

Package Availability results are Restricted Diagnostic Evidence. For each evaluated application, the protected assessment retains only the declared, bounded fields required from this list:

- Package Availability Outcome and stable reason when applicable;
- verified source identity and source type;
- query time and successful-refresh time;
- App Installer, WinGet, and bundled client-module versions;
- candidate package identifier, name, and version strings when present;
- `WinGetEngine` correlation basis; and
- corroborating ProductCode or Package Family Name when safely demonstrated.

WIN-PCInfo does not retain command output, the downloaded source catalog, WinGet telemetry records, source credentials, unrelated source configuration, or other applications' metadata inside a subject's observation.

The Preparation Summary warns that WinGet contacts Microsoft, refreshes catalog metadata, and may send search, filter, or matched-package metadata through WinGet's own telemetry according to existing Windows privacy settings. WIN-PCInfo makes no narrower data-transmission promise and does not change those settings. The WinGet project publishes its behavior in its [privacy statement](https://github.com/microsoft/winget-cli/blob/master/PRIVACY.md).

Opening a completed report, Protected Evidence Package, or historical assessment never contacts WinGet. The recorded observation remains tied to its original source, refresh, and query times.

## Failure, cancellation, and time bounds

Package Availability is a confined optional enrichment:

- ordinary inventory, Software Recognition, and unrelated assessment work continue after an eligibility, agreement, refresh, network, matching, timeout, cancellation, or source failure;
- every affected application receives `NotEvaluated` with a stable reason;
- safely completed observations may remain in a partial result after cancellation or timeout;
- all remaining evaluations are accounted for rather than silently omitted; and
- owned processes are terminated and cleanup proceeds under the normal Assessment Run contract.

Three conditions remain run-level failures:

1. an altered or unauthenticated bundled module or governing resource returns `NotStarted` with no bypass;
2. a request that combines Package Availability with `Local Only` returns `NotStarted` with correction guidance; and
3. another existing release-integrity or security gate independently requires `NotStarted`.

The initial provisional hard ceiling for the entire optional phase is five minutes: no more than two minutes for source validation and refresh, followed by no more than three minutes for structured correlation. A later release may revise these versioned bounds only through benchmarking, impact review, documentation, and affected revalidation. No operation receives an unbounded timeout.

## Dependency and release governance

Changing the bundled Microsoft client module or another governed integration dependency requires a new WIN-PCInfo release. The change must update exact versions and hashes, license and notice material, SBOM, dependency provenance, impact assessment, affected automated tests, fresh-client evidence, and final signed-or-attested artifact validation.

WIN-PCInfo never selects a newer installed module or PowerShell Gallery version at runtime. A dependency update is best-effort project maintenance with no background updater, deadline, or independent hotfix channel.

## Delivery and validation gates

This enrichment is `CMP-0061`, an optional later-candidate Capability Component of `CAP-0009` Software and application migration inventory. It is not included in `2.0.0-preview.1` and has no later release target yet.

Before a future release enables it, deterministic and fresh-client validation must cover at least:

- latest-patched supported Windows 10 and Windows 11 scenarios;
- App Installer and WinGet missing, old, current, unregistered, and alias-disabled states, including first-sign-in registration delay;
- the signed-in standard-user context and proof that SYSTEM is not used;
- the exact source present, missing, replaced, renamed, policy-blocked, agreement-pending, and agreement-changed;
- `msstore` and custom sources configured while proving they are neither queried nor contacted;
- online, offline, proxy, DNS, TLS-inspection, timeout, stale-cache, missing-cache, and corrupt-cache paths;
- cancellation during refresh and correlation;
- non-English Windows systems, Unicode application data, and long, spaced, and non-ASCII release paths;
- another client-module version already installed or loaded, without dependency collision or `PSModulePath` mutation;
- ProductCode, Package Family Name, WinGet-engine, ambiguous, unmatched, excluded, and nonstandard-version cases;
- every Package Availability Outcome and stable failure reason;
- no WinGet setting, source configuration, telemetry setting, application, execution alias, or Windows policy change;
- no module installation, reusable catalog copy, background task, orphan process, or WIN-PCInfo residue; and
- continued ordinary inventory, recognition, reporting, packaging, completion, cancellation, and cleanup when enrichment fails.

Beginner documentation must explain how to opt in, what contacts Microsoft, what WinGet may retain or telemeter, what every outcome means, why a candidate is only an Intune distribution lead, and how to correct eligibility problems without resetting sources, changing telemetry, installing an application, or weakening security controls.

## Implementation handoff

Implementation must add the request field, guided checkbox, Preparation Summary disclosure, compatibility checks, verified private dependency adapter, named-source refresh operation, structured correlation, evidence-field definitions, semantic validation, report presentation, stable diagnostics, tests, release evidence, and beginner documentation described here.

Until all applicable gates pass for an exact release candidate, Package Availability remains deferred and ordinary software inventory remains fully usable without it.
