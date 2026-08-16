# Comprehensive Local Assessment report

The `assessment-report.html` file is the human-readable summary inside every WIN-PCInfo Protected Evidence Package. It is self-contained, uses no external scripts, styles, fonts, images, or service calls, and is intended for offline Microsoft Edge viewing or local print.

## What appears first

The report starts with an executive summary before any detailed evidence:

- `Outcome` states whether the run completed, completed with gaps, timed out, was cancelled, failed integrity checks, or ended with cleanup uncertainty.
- `Scope` states that the report is one Comprehensive Local Assessment across device, identity, privilege, policy, applications, dependencies, network, trust, and Microsoft connectivity observations.
- `Completeness` tells you whether the admitted evidence set was complete or recoverable-partial.
- `Limitations` lists the bounded places where local evidence cannot answer a tenant or organization question.
- `Prioritized advisory results` calls out the most important findings without collapsing them into a score.
- `Next steps` keeps product recommendations separate from Tenant-side Discovery Tasks.

After that summary, the report progressively discloses diagnostics, detailed observations, and provenance.

## How to read it

- `Observations` are bounded facts from Windows or a derived release-owned classifier.
- `Findings` are advisory interpretations of those admitted observations.
- `Severity` and `Confidence` stay attached to advisory results; they are not hidden inside prose.
- `Recommendations` are concrete next product-side review steps.
- `Tenant-side Discovery Tasks` are questions that require authorized cloud, policy, owner, or tenant follow-up outside the local evidence boundary.
- `Diagnostics` are typed reason codes for denied, missing, partial, malformed, timed-out, or otherwise incomplete evidence paths.

The report is not a compliance certificate, migration schedule, purchasing instruction, or automatic remediation plan.

## Navigation and print

- The document includes a skip link and internal navigation links for keyboard use.
- Focus indicators remain visible without relying on color alone.
- The report works with scripting disabled.
- Print styles are included for Letter and A4-friendly output. Detailed `details/summary` sections remain in the file for screen reading and can still be expanded before print when needed.

## Sharing

The HTML report inside the package is still Restricted Diagnostic Evidence. Normal sharing should use the encrypted Protected Evidence Package and the Completion Summary guidance. The separate Restricted Report Export workflow exists only for deliberate warned plaintext export and still requires private handling and deletion after use.
