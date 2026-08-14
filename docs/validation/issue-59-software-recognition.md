# Issue #59 — Software Recognition Catalog validation

This public-safe evidence records data-only catalog and synthetic test results. It contains no real device inventory, user identity, tenant data, third-party installer, executable, binary content, logo, or licensed catalog export.

## Implemented boundary

The generated application authenticates the strict Preview.1 catalog before collection, then annotates each canonical Application subject without changing ordinary Software Inventory or creating an Assessment Finding. Exact PFN and MSI identity, contextual composite, ambiguity, unknown, and logical-failure outcomes are deterministic and catalog-order independent. The evaluator is offline and does not perform live WinGet or reputation lookup.

The initial seed contains three primary-source-backed Microsoft package-family identities. The build manifest authenticates both the snapshot and its Draft 2020-12 schema. The snapshot license review records that no third-party assets or unlicensed external catalog data are included.

## Focused evidence

The focused suites cover exact PFN, MSI ProductCode, MSI UpgradeCode from a strict read-only uninstall registration, Unicode composite, near-match rejection for every published PFN, user/machine and registry-view context, ordinal case-distinct cross-family ambiguity in both catalog orders, unknown software, malformed and strict-schema-invalid logical loads, duplicate IDs, forbidden matcher types, reasoned withdrawn tombstones, invalid active withdrawn matchers, bounded UTF-8 output, deterministic catalog-and-schema embedding, protected-package reopening, report language, and digest alteration before collection.

The generated positive fixture preserves five ordinary registrations, emits five annotations, recognizes one exact release-seed PFN, leaves four safely unrecognized, and creates no finding. The logical-failure fixture preserves the same five registrations and emits five `NotEvaluated` annotations. The digest-tamper fixture exits 20 as `NotStarted` with `SOFTWARE_RECOGNITION.INTEGRITY_FAILED` and `collectionStarted=false`.

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/SoftwareRecognition.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SoftwareRecognitionCatalog.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SoftwareRecognitionApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SoftwareInventoryContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AssessmentContractSet.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/BuildDeterminism.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

The final uninterrupted repository gate passed all 80 test files in 1,947.6 seconds. The normalized release-catalog SHA-256 is `e24f18f2f46ec7f20fa45a84791e7ebd3319856e1ac6f44851a1dc1020fb2150`; the deterministic generated-application SHA-256 is `637d135ed5fb8b959241f103170b7f9578a4b83ec7ba84cf2b22461daac566fb`; and its authenticated application-manifest digest is `ce14b9d91d39b1b04765daf711f0eded22ebb5b84df0749b18684b3b277a4852`.
