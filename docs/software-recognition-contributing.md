# Software Recognition contributor checklist

The project maintainer is the Catalog Owner and final release authority. A contributor or vendor cannot approve its own entry, require inclusion, buy placement, or obtain a completeness or response-time promise.

Use this checklist for every addition, correction, supersession, or withdrawal:

- [ ] Keep the immutable family ID; never reuse an old ID for a different family.
- [ ] Choose only roles already present in the catalog's controlled taxonomy, or propose a separately reviewed taxonomy change.
- [ ] Use only an exact Package Family Name, exact MSI ProductCode/UpgradeCode, or exact registration-field composite with explicit user/machine context and registry view.
- [ ] Do not use display name or publisher alone, substring/fuzzy/regex matching, paths, executables, processes, services, or binary inspection.
- [ ] Cite primary publisher documentation where possible. A controlled fresh installation must be disposable and license-permitted. A WinGet manifest is secondary evidence and must pin its exact commit and manifest path.
- [ ] Add a sanitized positive fixture and a near-match negative fixture for every matcher, including relevant Unicode, context, and 32/64-bit boundaries.
- [ ] Explain false-positive risk and any possible cross-family collision; collisions must produce `Ambiguous` independent of catalog order.
- [ ] Confirm that only minimal factual identifiers and provenance are added. Do not add installers, scripts, icons, logos, screenshots, marketing descriptions, or copied third-party catalog data.
- [ ] Record the license/redistribution basis and whether any third-party asset or external catalog data is included.
- [ ] For `superseded` or `withdrawn`, remove all matchers, keep a reasoned tombstone, and add the replacement family ID when applicable.
- [ ] Increase the catalog revision for a published change and update the owning release/review fields.
- [ ] Run the focused matcher, catalog, contract, generated-application, determinism, and full repository gates.

Recognition remains an annotation. A catalog contribution must not add a finding, recommendation, compatibility promise, health/safety judgment, licensing conclusion, or package-availability claim.
