# Software Recognition annotations

WIN-PCInfo keeps its ordinary installed-software inventory exactly as observed. It may then add a separate **Software Recognition annotation** that maps a strong Windows identity to a small, reviewed product family and one or more migration roles.

Recognition is a navigation aid for a migration conversation. It is not an Assessment Finding and does not claim that software is compatible, healthy, safe, licensed, supported, approved, currently used, Intune-ready, Defender-ready, replaceable, or deployable.

## Reading an outcome

- `RecognizedExact` means one family matched an exact Package Family Name, MSI ProductCode, or MSI UpgradeCode.
- `RecognizedComposite` means one family matched every exact registration field in a reviewed composite, including its machine/user context and 32/64-bit registry view.
- `Ambiguous` means more than one family matched. WIN-PCInfo does not pick whichever entry appears first.
- `Unrecognized` means this release's small catalog has no valid match. This is not a warning and does not make the application suspicious.
- `NotEvaluated` means the catalog could not be applied safely. The ordinary installed-software observation remains available and authoritative.

The report first shows the observed application, then the outcome, family, migration roles, and a plain-language match explanation. Expand “Catalog revision and provenance” for matcher types and source links. Installed product identities and annotations are Restricted Diagnostic Evidence and stay inside the protected package by default.

## Conservative identity rules

Recognition accepts only exact Package Family Names, exact MSI codes, and explicit exact-field composites. A display name or publisher by itself is never identity. The evaluator does not use substrings, fuzzy matching, regular expressions, paths, executable names, processes, services, or binary inspection.

The catalog is bundled with one WIN-PCInfo release. Recognition is offline and performs no live WinGet, reputation, or catalog lookup. Preview.1's three-entry seed is intentionally incomplete; a future live WinGet package-availability observation is a separate, consent-controlled feature with different claim limits.

## Failure behavior

WIN-PCInfo authenticates the bundled catalog before any device collector starts. An altered catalog digest stops the run as `NotStarted` with no bypass. A catalog that is authentic but cannot be parsed or evaluated is confined to `NotEvaluated`; it does not erase collected inventory or stop unrelated assessment work.

Maintainers and contributors should use the [Software Recognition contributor checklist](software-recognition-contributing.md). The technical governance and exact release model are in [Software Recognition Catalog governance](spec/software-recognition-catalog.md).
