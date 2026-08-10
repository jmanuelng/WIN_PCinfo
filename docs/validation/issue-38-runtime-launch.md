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
- Generated application SHA-256: `f714ff843d534b43aa2a1d651ada944d5dece6ed3ba1fd4893b40889d202ca48`
- Representation: UTF-8 with BOM and CRLF
- Tracked inputs: `src/ApplicationHeader.ps1`, `src/Contracts.ps1`, `src/RuntimeCompatibility.ps1`, `src/LaunchEngine.ps1`, `src/EntryAdapters.ps1`, and `src/ApplicationMain.ps1`
- Reproduction: `pwsh -NoLogo -NoProfile -File ./build/Build.ps1`

The generated application is ignored and is never hand-edited. Build output reports the exact build-tool and source-input digests so a reviewer can reproduce this artifact from tracked files.

## Security-sensitive change review

This runtime slice is a **Security-sensitive Change** because it establishes process, module, cryptographic, encoding, and generated-package boundaries. It is traced to the public [product threat model and security acceptance criteria](https://github.com/jmanuelng/WIN_PCinfo/issues/12), [modular architecture and dependency policy](https://github.com/jmanuelng/WIN_PCinfo/issues/10), parent implementation specification [#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37), and runtime ticket [#38](https://github.com/jmanuelng/WIN_PCinfo/issues/38).

The documented security review considered these public-safe threats and failure modes:

- **Profile or module-path shadowing:** required modules load only from literal `$PSHOME` manifests. Expected command identities, Microsoft Authenticode signatures on manifests and referenced binary payloads, and the `Test-Json` origin must agree. Request parsing, fixture parsing, request hashing, progress, and terminal serialization invoke the verified `CommandInfo` objects directly instead of ambient command names. Failure returns a distinct module-loading, command, or validator-provenance reason.
- **Malformed or ambiguous text:** strict UTF-8 rejects invalid byte sequences; the exact signed PowerShell JSON commands and the .NET JSON path round-trip multilingual text; standard output must be UTF-8. Failure stops before collection.
- **Unavailable or incompatible cryptography:** fixed synthetic SHA-256 and AES-GCM known behavior is exercised without real evidence or durable key material. Buffers are cleared where controllable; failure stops before collection.
- **Unbounded or orphaned child work:** the probe uses a literal current-host executable, literal arguments, redirected bounded channels, a finite wait, a known exit code, and a second child that must be hard-terminated within the deadline. Cleanup falls back to direct termination if the tree-aware operation fails.
- **Synthetic-fixture bypass:** fixture mode is always marked `validationFixture: true`, always returns `NotStarted`, and never authorizes collection even when a fixture describes an eligible host.
- **Self-attestation limit:** the local module check trusts the installed PowerShell Security cmdlet and Windows Authenticode. A running engine compromised deeply enough to falsify its own checks remains outside self-attestation; independent installation and release verification is required.

The initial two-axis code review identified incomplete domain contracts, provenance, Unicode serialization, hard process termination, evidence wording, and duplicated harness/build logic. Those findings were corrected and revalidated before publication; no security exception or weakened fallback was accepted.

## Acceptance trace

- Shared request, progress, terminal, and exit contracts: `src/Contracts.ps1`, `src/EntryAdapters.ps1`, `src/LaunchEngine.ps1`, `tests/TestHarness.ps1`, and `tests/LaunchContract.Tests.ps1`.
- Full runtime allowlist and stable failure guidance: `src/RuntimeCompatibility.ps1`, `src/Contracts.ps1`, and `tests/RuntimeMatrix.Tests.ps1`.
- Pre-collection side-effect boundary: `src/ApplicationMain.ps1`, `src/LaunchEngine.ps1`, and the isolated working-directory assertions in `tests/RuntimeMatrix.Tests.ps1`.
- Modular deterministic source-to-application build: `build/Build.ps1` and `tests/BuildDeterminism.Tests.ps1`.
- Beginner prerequisites and retry documentation: `README.md` and `docs/runtime-prerequisites.md`.
