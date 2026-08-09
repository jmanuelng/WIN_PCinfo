# Software Recognition Catalog governance

Status: **planned for WIN-PCInfo 2.0.0-preview.1**. This rulebook defines how the catalog must behave; it does not contain the catalog entries or implement matching.

The governing decision is [Define Software Recognition Catalog governance](https://github.com/jmanuelng/WIN_PCinfo/issues/35), part of the [WIN-PCInfo v2 product and release specification map](https://github.com/jmanuelng/WIN_PCinfo/issues/1).

## Why the catalog exists

An installed-software list is useful, but a consultant may also need to recognize products that affect a Microsoft Zero Trust migration. For example, an endpoint-security product, VPN client, device-management agent, or remote-support tool can identify an important discovery or replacement conversation.

The **Software Recognition Catalog** is a deliberately small, release-bundled classification table. It adds conservative product-family and migration-role annotations to normalized software inventory. It is not a copy of WinGet, Patch My PC, Chocolatey, or another package catalog.

Ordinary software inventory is always authoritative for what WIN-PCInfo observed. Classification never replaces, hides, or changes that inventory.

## What recognition means

A recognition outcome is one of:

- `RecognizedExact`: one strong Windows package identity maps to one family.
- `RecognizedComposite`: one release-tested combination of registration fields maps to one family.
- `Ambiguous`: available evidence maps to more than one family or cannot safely distinguish them.
- `Unrecognized`: the release catalog contains no valid match for the observation.
- `NotEvaluated`: recognition could not run, while ordinary inventory remains available.

A recognized family may have more than one controlled migration role. Recognition does not establish compatibility, licensing, vulnerability, safety, current use, support, product health, Intune readiness, Defender readiness, replacement suitability, or successful deployment.

Unknown software is not suspicious merely because the catalog does not recognize it.

## Initial scope

Preview.1 has no catalog-size quota. A useful initial target is approximately 50 to 150 well-evidenced product families, and a smaller catalog is acceptable when the evidence does not justify more.

The initial controlled roles may cover:

- endpoint security, antivirus, or endpoint detection and response;
- device management;
- VPN or zero-trust network access;
- data-loss prevention;
- encryption;
- remote support;
- authentication or credential providers;
- browsers;
- patch or update agents;
- backup or recovery agents; and
- another explicitly reviewed migration dependency.

One family may carry multiple roles. Contributors cannot add free-form roles; a new or materially changed role updates the governed taxonomy and its tests.

## Approved evidence sources

Use the lightest reliable evidence in this order:

1. Windows-defined package identities or security-provider interfaces and primary publisher documentation.
2. Exact identity observed through a controlled fresh installation from the publisher's official distribution in a disposable validation VM, only when an important ambiguity cannot otherwise be resolved and licensing permits the test.
3. A selected WinGet Community Repository manifest at a pinned commit as secondary corroboration.

Patch My PC's public product list may be a human research lead, but its data is not copied or bundled without explicit permission and legal review. Chocolatey Community Repository data is not ingested without explicit written permission. Search snippets, marketing aggregators, weak community claims, and copied marketing descriptions are not catalog evidence.

Only minimal factual identifiers and provenance are retained. Third-party installers, icons, logos, descriptions, scripts, and marketing text are not stored in the repository or release. Applicable third-party notices travel with the release.

## Allowed matchers

Catalog entries are data, never executable logic. Allowed matchers are:

- exact MSIX Package Family Name;
- exact MSI ProductCode or UpgradeCode when safely available; and
- a release-tested composite of uninstall-registration fields with explicit registry view and user or machine context.

The catalog does not recognize software from display name alone, publisher alone, fuzzy or substring matching, unrestricted regular expressions, paths, executable names, processes, services, or arbitrary binary inspection.

A unique strong identity produces `RecognizedExact`. A unique fully satisfied composite produces `RecognizedComposite`. Any cross-family conflict produces `Ambiguous`; catalog order never chooses a winner. Product version remains ordinary inventory and affects matching only when a documented exact boundary is necessary to avoid a false match. Vendor version strings are not assumed to use semantic versioning.

## Minimal entry and snapshot model

Each family entry contains only:

- an immutable, never-reused family ID;
- a short English label;
- one or more controlled migration roles;
- typed matchers and their match strength;
- minimal authoritative source records;
- the releases in which the entry was added and reviewed; and
- an `active`, `superseded`, or `withdrawn` lifecycle state.

Source records identify the source type and owner, authoritative URL, verification date, reviewer, and any applicable pinned WinGet commit and manifest. A superseded or withdrawn family remains as a tombstone with a brief reason and replacement link. Historical assessment packages are never silently reclassified.

The published snapshot records a schema version, monotonically increasing catalog revision, owning WIN-PCInfo release, source revision, and exact digest. It has no independent update channel or semantic-version lifecycle. Every published addition, correction, or retirement ships in a new WIN-PCInfo release.

## Runtime and failure behavior

Software collection and normalization are independent from catalog loading and matching.

- A valid catalog is authenticated and validated before use.
- A catalog evaluation or logical-load failure is confined to recognition. Software remains ordinary inventory, recognition becomes `NotEvaluated`, the limitation is reported, and unrelated collection continues.
- A bundled catalog whose digest does not match the authenticated release manifest indicates release corruption or alteration. The Assessment Run returns `NotStarted` before collection, with no bypass.
- Unknown or ambiguous software never causes the Assessment Run to fail.
- The catalog never downloads an update, falls back to a latest version, or performs a live reputation lookup.

## Evidence and report presentation

Installed product identities, recognized families, migration roles, match details, and future package-availability results are Restricted Diagnostic Evidence by default.

The beginner report shows the observed application, recognized family and roles, and a plain-language explanation of match strength. Progressive technical detail may show the source registration, matcher type, catalog revision, and provenance. `Ambiguous`, `Unrecognized`, and `NotEvaluated` include a safe explanation and next step but are not warnings merely because recognition is incomplete.

Recognition is an annotation, not an Assessment Finding. Separate versioned rules decide whether available evidence supports an advisory finding or recommendation.

## Contributions and maintenance

The project maintainer is the accountable Catalog Owner and final release authority. Public additions and corrections may arrive through DCO-covered pull requests, but no contributor or vendor can approve its own entry or require inclusion.

A proposed entry includes:

- family and controlled roles;
- exact typed matchers;
- authoritative sources;
- sanitized positive and near-match negative fixtures;
- false-positive analysis;
- a licensing and redistribution statement; and
- the intended lifecycle change.

Automated checks and maintainer review are mandatory. There is no paid placement, preferred ranking, endorsement, completeness promise, response deadline, inclusion guarantee, or catalog-update service level.

Maintenance is best effort and event-driven: review occurs when a contribution arrives, a false match is reported, a relevant identity changes, or a release intentionally refreshes an area. WIN-PCInfo creates no timer, scheduled refresh, stale alarm, or background catalog task.

## Release verification

The release gate requires:

- strict catalog schema, size, depth, duplicate, and conflict validation;
- one positive and one near-match negative synthetic fixture for every matcher;
- shared ambiguity, unknown-product, catalog-order, Unicode, non-English, 32/64-bit, and user/machine-context tests;
- a catalog-load failure test proving ordinary inventory continues as `NotEvaluated`;
- an integrity-mismatch test proving the run returns `NotStarted`;
- affected Windows 10 and Windows 11 integration scenarios; and
- release-manifest provenance, digest, generated-artifact equivalence, and final signed or attested artifact smoke evidence.

Only affected catalog tests and scenarios need to rerun after an entry change, in addition to invariant release gates.

## WinGet package availability is separate

A changing WinGet source answers a different question: whether it currently reports a candidate package that an Intune administrator might investigate as one software-distribution strategy. It is not the Software Recognition Catalog.

Preview.1 does not perform that live check. A future separately consented capability must decide WinGet eligibility, named-source access, source agreements, refresh and telemetry behavior, structured correlation, privacy disclosure, time-bound evidence wording, failure states, and Windows validation. A future observation must never imply licensing, approval, compatibility, silent installation, correct detection rules, deployment success, or lasting package availability.

## Implementation handoff

Implementation must publish the catalog schema, controlled-role taxonomy, initial entries, synthetic fixtures, contributor checklist, review ownership, and release validation evidence under this rulebook. Those artifacts must remain small, data-only, authenticated, deterministic, and easy for a beginner to inspect.
