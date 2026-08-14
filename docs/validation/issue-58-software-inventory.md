# Issue #58 — Safe Software Inventory validation

This public-safe projection records release-owned contracts and synthetic validation. It contains no software registration identity, product code, package identity, display name, publisher, version, installation path, hash, license material, user SID, or raw provider diagnostic.

## Closed generated-application matrix

`tests/SoftwareInventoryApplication.Tests.ps1` builds the generated artifact and drives 16 exact scenarios through Preparation, collection, canonical validation, findings, beginner report, Protected Evidence Package reopening, terminal output, and verified fixture cleanup:

- explicit registry views;
- user and machine registrations;
- installed and advertised MSI states;
- main, bundle, framework, resource, and optional package types;
- duplicate display metadata with distinct source identities;
- arbitrary and Unicode version/provider text;
- malformed and over-ceiling source data;
- the 128-entry aggregate maximum distributed across all eight scopes;
- all-user package denial and Assessment User denial;
- empty sources;
- alternate-administrator and LocalSystem rejection; and
- source-local partial coverage.

All 16 generated cases pass. Public output exposes only counts, coverage/finding states, stable terminal facts, and false safety flags. Each case validates the Assessment Record, verifies the beginner report, reopens the protected record/report, and proves the validation boundary absent.

## Source and contract checks

The focused suites establish:

- the policy and preparation schema freeze the exact executable, source/property catalog, context, dependencies, one attempt, ten-second deadline, 1 MiB result ceiling, 64-entry scope ceiling, 128-entry aggregate ceiling, offline/no-write behavior, and cleanup contract;
- both uninstall registry views are explicit and read-only;
- MSI enumeration uses only inventory APIs and preserves installed/advertised context;
- Windows package identity/status projections preserve declared package types;
- `Win32_Product`, WMI/CIM software enumeration, consistency/repair actions, profile loading, paths, hashes, binary content, and license material are absent;
- contradictory Assessment User context tuples are rejected;
- per-source denial, malformation, and overflow preserve unrelated scopes;
- source identities—not names or publishers—preserve duplicates;
- Contract Set 1.7 validates the final additive profile and 2 MiB/6,144-item document bounds; and
- deterministic building binds the software module, schema, policy, and all prior resources.

The canonical MSI regression also proves that installed and advertised products remain separate application subjects. Empty 32-bit and 64-bit registry scopes use the release-declared two-occurrence-per-target field bound; MSI and MSIX fields retain one occurrence per application subject.

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/SoftwareInventoryPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SoftwareInventory.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SoftwareInventoryNativeSource.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SoftwareInventoryContract.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SoftwareInventoryApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AssessmentContractSet.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ContractValidator.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/BuildDeterminism.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

The final uninterrupted repository gate passed all 77 test files in 1,369.6 seconds. `BuildDeterminism.Tests.ps1` produced deterministic artifact SHA-256 `20e10143754864fd1bba5b6bf56934b57ecfcdd22ec703fb16c246cc7ba3d51a` with exact source and governing-resource provenance.
