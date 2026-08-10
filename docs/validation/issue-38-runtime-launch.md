# Issue 38 runtime-launch evidence

This is the public-safe validation projection for the runtime-launch tracer bullet. It contains only synthetic fixture names, stable contract values, and reproducible artifact facts. It contains no assessment evidence, machine identity, account, tenant, subscription, resource, network, credential, or private diagnostic data.

## Automated runtime matrix

`pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1` passed all five test files:

- Generated guided and automation launches normalized the equivalent request to the same SHA-256 request digest, used contract version `1.0.0`, and returned the same terminal outcome, stable reason, and exit code.
- Invalid automation requests covered an unknown security-relevant field, unsupported contract major, missing required field, and unsupported network mode. Each returned structured `NotStarted` / `20` before collection.
- The generated application exercised 14 synthetic runtime fixtures: eligible, a later stable 7.x patch, missing host, prerelease, wrong edition, wrong major, too old, wrong architecture, missing command, invalid validator provenance, incompatible encoding, incompatible cryptography, incompatible module loading, and incompatible process control.
- Every runtime fixture reported `collectionStarted: false`, created no new working-directory entry, preserved a pre-existing sentinel file byte-for-byte, and ended through the stable terminal contract. Source inspection confirms that the pre-eligibility path contains no collector, assessment-network, elevation, installation, or Windows Feature operation. Every ineligible fixture included the official Microsoft installation URL and a retry step.
- The live eligible-host launch exercised strict UTF-8 and JSON behavior, SHA-256 and AES-GCM, literal loading and Microsoft Authenticode validation of required built-in modules, exact command identities, normal child exit, and bounded hard child termination.
- The real generated artifact also ran under Windows PowerShell 5.1 and returned structured `RUNTIME.EDITION_UNSUPPORTED` / `NotStarted` / `20` with official guidance and no collection.
- Two builds to different output directories produced identical application bytes. UTF-8 BOM, CRLF-only line endings, build-tool identity, and all six modular source identities and SHA-256 digests were verified.

## Sanitized guided and automation transcript

Equivalent guided and automation launches emitted the same contract sequence. The automation launch used the synthetic request in `tests/fixtures/automation-request.json`. Time values below are normalized to one public-safe UTC value; the application emits the actual event time.

```json
{"recordType":"win-pcinfo.progress","contractVersion":"1.0.0","sequence":1,"phase":"RequestValidation","state":"Started","time":"2026-08-09T00:00:00.0000000+00:00","completion":{"completedUnits":0,"totalUnits":2,"unit":"LaunchGate"},"messageId":"request.validation.started"}
{"recordType":"win-pcinfo.progress","contractVersion":"1.0.0","sequence":2,"phase":"RequestValidation","state":"Succeeded","time":"2026-08-09T00:00:00.0000000+00:00","completion":{"completedUnits":1,"totalUnits":2,"unit":"LaunchGate"},"messageId":"request.validation.succeeded"}
{"recordType":"win-pcinfo.progress","contractVersion":"1.0.0","sequence":3,"phase":"RuntimeCompatibility","state":"Started","time":"2026-08-09T00:00:00.0000000+00:00","completion":{"completedUnits":1,"totalUnits":2,"unit":"LaunchGate"},"messageId":"runtime.check.started"}
{"recordType":"win-pcinfo.progress","contractVersion":"1.0.0","sequence":4,"phase":"RuntimeCompatibility","state":"Succeeded","time":"2026-08-09T00:00:00.0000000+00:00","completion":{"completedUnits":2,"totalUnits":2,"unit":"LaunchGate"},"messageId":"runtime.check.succeeded"}
{"recordType":"win-pcinfo.terminal","contractVersion":"1.0.0","outcome":"NotStarted","exitCode":20,"reasonCode":"SLICE.COLLECTION_NOT_IMPLEMENTED","phase":"Preparation","collectionStarted":false,"requestDigest":"8160a0c0259e18615e893e162beaafa26081dac72082e684e6c93eaa5c4a255a","validationFixture":false,"cleanup":{"required":false,"verified":true},"runtime":{"eligible":true,"reasonCode":"RUNTIME.ELIGIBLE","policyId":"win-pcinfo.runtime-compatibility/1.0.0"}}
```

The terminal outcome is intentionally `NotStarted`: the eligible runtime reached the preparation boundary, but this slice contains no assessment collector and makes no capability-delivery claim.

## Deterministic build evidence

- Build contract: `win-pcinfo.build-evidence/1.0.0`
- Generated application SHA-256: `9c08a08579272c6c7cf1ac5be17118d3b0d72f6e53a8c49a77223b87d5993ef1`
- Representation: UTF-8 with BOM and CRLF
- Tracked inputs: `src/ApplicationHeader.ps1`, `src/Contracts.ps1`, `src/RuntimeCompatibility.ps1`, `src/LaunchEngine.ps1`, `src/EntryAdapters.ps1`, and `src/ApplicationMain.ps1`
- Reproduction: `pwsh -NoLogo -NoProfile -File ./build/Build.ps1`

The generated application is ignored and is never hand-edited. Build output reports the exact build-tool and source-input digests so a reviewer can reproduce this artifact from tracked files.

## Acceptance trace

- Shared request, progress, terminal, and exit contracts: `src/Contracts.ps1`, `src/EntryAdapters.ps1`, `src/LaunchEngine.ps1`, `tests/TestHarness.ps1`, and `tests/LaunchContract.Tests.ps1`.
- Full runtime allowlist and stable failure guidance: `src/RuntimeCompatibility.ps1`, `src/Contracts.ps1`, and `tests/RuntimeMatrix.Tests.ps1`.
- Pre-collection side-effect boundary: `src/ApplicationMain.ps1`, `src/LaunchEngine.ps1`, and the isolated working-directory assertions in `tests/RuntimeMatrix.Tests.ps1`.
- Modular deterministic source-to-application build: `build/Build.ps1` and `tests/BuildDeterminism.Tests.ps1`.
- Beginner prerequisites and retry documentation: `README.md` and `docs/runtime-prerequisites.md`.
