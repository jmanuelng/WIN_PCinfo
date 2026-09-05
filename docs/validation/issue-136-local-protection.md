# Issue #136 local protection and personal certificate preparation

Scope: [#136](https://github.com/jmanuelng/WIN_PCinfo/issues/136), under
[#134](https://github.com/jmanuelng/WIN_PCinfo/issues/134) and
[#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37). Starting revision and
fixed review point: `85b8c5748cea65053476af61ddfc0c2f1b631cc3`.

This record covers automated implementation only. Live certificate creation,
trust changes, actual signing and assessment acceptance remain **Pending #160**.
The Status desk belongs to #137. No release or supported-capability claim follows
from these tests. The September 6 target is unchanged; a ready fixture or signing
procedure is not the first real GUI-to-HTML milestone.

## Requirement contribution to the #134 register

| Requirement | Implemented evidence | Disposition / next owner |
| --- | --- | --- |
| Initiating-user local protection readiness | Generated preparation performs one in-memory 32-byte CurrentUser wrap/unwrap through the existing package boundary, compares exact bytes, clears controllable buffers, and keeps collection behind consent. Provider denial, missing/changed/short recovery, empty and oversized wraps leave the prerequisite unresolved. | Automated Pass; actual intended-user/alternate-admin scenarios Pending #160 / #139 |
| Repeat-safe separate test identities | Private session procedure separates CurrentUser signing from non-exportable recipient encryption. Recipient setup now refuses an existing or unusable profile destination before creating a persistent identity; interrupted setup requires private ownership reconciliation. | Automated Pass for recipient preflight; signing identity creation/trust and repeat-session execution Pending #160 |
| Recipient round trip and access semantics | Existing setup/public-profile schema, TPM/software provider admission and cleanup, RSA-OAEP-SHA-256 round trip, fingerprint confirmation, expiry/new admission and historical opening contracts retained and regression checked. Same-machine recipient is explicitly not off-device recovery. | Automated Pass; real provider/non-exportability and both opening routes Pending #160; complete reopening UI #152 |
| Exact executable candidate and resources | New `Build.ps1 -SignedHelperPath` admits only Windows-valid Authenticode over this source's generated launcher, preserves its bytes, and embeds the signed helper digest before primary signing. Synthetic tests reject changed payload even under simulated Valid trust, invalid trust and changed governed helper bytes. Public Build rejects the synthetic signature. | Automated Pass; real helper/primary signatures and final private archive checks Pending #160; general release package/provenance #155 |
| Private inventory and safe retirement | Prepared guide records separate identities, exact trust additions and candidate identities; no private export; preserves recipient keys needed by retained packages; requires exact store and provider absence checks and retained opening capability before trust retirement. | Procedure prepared; real inventory/rollback/removal evidence Pending #160 / #161 |
| #37 stories 3, 7–8, 57–62, 66–68, 76–78; #134 stories 25–28, 32; CAP-0018, CAP-0020, CAP-0025 | This ticket contributes local-readiness, recipient-repeat and personal-signing prerequisite evidence to sub-objectives 2 and 10. It does not close all shared components or release obligations. | Orchestrator ledger receives these rows; aggregate component/story reconciliation remains #158 |

Shared CMP-0024, CMP-0026, CMP-0027, CMP-0029, CMP-0036, CMP-0045,
CMP-0047, CMP-0048, CMP-0052, CMP-0055 and CMP-0056 retain their other
owning tickets. CMP-0061 remains deferred. No requirement is waived by a private
test certificate or fixture pass.

## TDD and focused validation

Confirmed seams are generated Preparation Summary/terminal contracts, recipient
setup and package opening, and authenticated portable package generation and
verification. The new readiness test loads the generated module regions and
invokes the preparation contract with isolated OS protection adapters; it does
not claim a signed live process. Existing generated-application regressions cover
the actual public process, consent and trust boundaries. Synthetic signing adapters
exist at the build module boundary only; the shipped command has none.

- Readiness red: a successful provider round trip still left preparation
  unavailable (exit 1, 4.35 seconds). Green: ready summary, decline without
  collection, and all three controllable buffers cleared (4.64 seconds). The
  extended seven-case failure lane also passed.
- Signed-helper red: the build resource contract lacked `SignedHelperPath`
  (exit 1, 1.29 seconds). Green: fixed signed bytes carried into governed resources
  (1.72 seconds). Extended trust, changed-payload, actual package-verification and
  public-Build synthetic-signature rejection checks passed (6.38 seconds).
- Repeat-setup red: a second setup attempted another persistent identity before
  discovering the profile already existed (exit 1, 1.44 seconds). Green: no
  identity attempt, unchanged existing profile, and missing-parent refusal
  (1.36 seconds).

The focused lane runs each named file in a fresh already-installed PowerShell
Core 7.6.5 X64 process with `-NoLogo -NoProfile -File tests/<name>.Tests.ps1`.
All inputs are synthetic; no certificate store/trust mutation, real signing,
live assessment, key export, cloud call or installation is performed.

All 15 focused test files passed, exit 0, **238.02 seconds** total measured
test-process time:

| Test file (`tests/<name>.Tests.ps1`) | Seconds |
| --- | ---: |
| LocalProtectorPreparation | 4.98 |
| PersonalSigningPreparation | 5.19 |
| RecipientSetupRepeat | 1.28 |
| PreparationSummary | 13.75 |
| PreparationFailure | 21.55 |
| RecipientProfile | 1.70 |
| RecipientSelection | 19.49 |
| ProtectedPackage | 1.74 |
| ProtectedPackageRecipient | 2.16 |
| ProtectedPackageNegative | 3.13 |
| RecipientSharingApplication | 48.56 |
| SigningBoundary | 1.81 |
| SigningBoundaryApplication | 19.37 |
| BuildDeterminism | 48.86 |
| PortableDistributionApplication | 44.45 |

PowerShell parser checks for all eight changed executable/test files and
`git diff --check`: **Pass**. BuildDeterminism confirms equivalent source builds
in separate destinations retain identical generated bytes.

Exact unsigned candidate SHA-256:
`7a9cf1bd6d70b14039a72de0aa216f1d51b59cf05576b0891c017f0756b38d89`.
Exact unsigned portable ZIP SHA-256:
`5602166eff6c6a55f376118d1803f49ad96d451a43e7f8bd42cc89d714907303`.
These are synthetic-test/build identities, not personally signed or accepted
assessment artifacts. Validation-only evidence edits are excluded from the
generated package and do not change either identity.

The complete `tests/Run-Tests.ps1` gate is deliberately **Deferred**, per the
maintainer's latest instruction, to the first integrated GUI checkpoint, #158,
and final independent/CI gates. The earlier 123-file pass before this ticket is
historical dependency evidence and does not validate changed #136 code.

## Candidate and cleanup disposition

Generated unsigned application/archive and focused test output remain ignored
workspace artifacts. New test-specific temporary profile/package/signing copies
are removed only after resolving their paths under the owned test root. The
readiness probe creates no evidence directory or file. Existing generated fixture
tests retain their declared cleanup contracts. No real inventory, fingerprint,
Recipient Profile or restricted operational artifact enters source or public
evidence. Unrelated worktrees and retained user packages/keys are untouched.

## Prepared live gates

[#160](https://github.com/jmanuelng/WIN_PCinfo/issues/160) executes
[the personal certificate procedure](../personal-evaluation-certificates.md):
review the exact candidate; establish/reuse the dedicated signing identity and
narrow CurrentUser test trust; sign helper first, freeze and sign primary,
refresh outer metadata and verify the extracted final archive; reject altered
copies; establish/reuse the separately verified recipient; prove current-user
local and recipient access plus wrong-protector/corruption rejection; then perform
the real GUI preparation/decline and separately approved assessment after #137.
Keep alternate-admin/SYSTEM trust failures blocked rather than broadening trust.
Record genuine TPM versus software behavior, cleanup, signing expiry and recipient
historical-opening behavior privately. The guide also prepares exact inventory,
retention and retirement checks for #160/#161. These gates are **Pending**;
no actual candidate-specific authorization or acceptance is inferred here.
