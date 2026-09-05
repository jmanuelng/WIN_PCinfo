# Issue #135 runtime selection evidence

Scope: [#135](https://github.com/jmanuelng/WIN_PCinfo/issues/135), under
[#134](https://github.com/jmanuelng/WIN_PCinfo/issues/134) and
[#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37). Starting revision and
review fixed point: `6cecce6834a8e6ad3e916c9c3b1ba971d0b58aa5`.

Status: **Blocked**. The complete repository gate has not passed. A separately
confirmed static qualification-fixture expiry defect requires a fresh bounded
dependency repair; this record does not claim #135 closure or batch readiness.

## Requirement evidence

| Requirement | Method and observed result | Disposition / next owner |
| --- | --- | --- |
| One explicit eligible host despite multiple matches | Generated application launch with an injected OS inventory containing a missing path and duplicate installed-host matches reached `PREPARATION.DECLINED`, exit 20, runtime eligible, no collection. | Pass, automated |
| Exact stable Core 7.6-or-later 7.x policy and safety prerequisites | Shared selection runs the generated `CheckRuntime` workflow. RuntimeMatrix covers edition/version/architecture, module/validator provenance, encoding, cryptography and process-control rejection through generated application execution. | Pass, focused; whole gate blocked below |
| Portable entry admission and NoProfile/STA | Extracted generated helper covers absent hosts, missing application, altered signature, policy rejection and successful NoProfile/STA dispatch. RuntimeInventory separately executes ten distinct generated-application runtime negatives through synthetic OS adapters and the portable entry boundary. | Pass, automated |
| Real generated-artifact execution and retained entry semantics | Extracted package guided and automation validation invocations execute on the installed host, decline with the same terminal/exit semantics, and remain visibly synthetic. Existing portable Help relaunch, Windows PowerShell wrong-edition and LaunchContract tests pass. | Pass, automated |
| UTF-8 and bootstrap provenance | Test host retains its UTF-8 setup. Application initializes UTF-8 for detached launch. Bootstrap uses literal built-in manifests from its own PSHOME, avoiding the observed redirected Windows PowerShell / PowerShell 7 module-path conflict. | Pass, focused checks |
| Other generated-test children | Two lifecycle lock-owner children and three release Help-smoke launchers reuse the active explicit host. With multiple installed matches, all three smoke defaults failed while explicit-host calls passed; their minimal host correction preserves release/trust semantics. | Pass, focused module and generated signing/publication checks; qualification expiry blocker below |
| No fixture authority | Runtime-only workflow ignores fixture/preparation inputs and never starts assessment. Synthetic portable admission launches only validation requests. Shipped command exposes no signature/probe override. | Pass, automated |
| GUI and live acceptance | Launcher dispatches Gui; production adapter remains explicitly unavailable until #137. Personal signing, real double-click/preparation decline, policy/trust dialogs, actual GUI assessment and intended display/locale checks require live sessions. | Pending #137, #160 and #161 |

## TDD and validation record

- Red: multiple `pwsh` matches produced a string parameter binding failure before
  application execution (4.97 seconds). Green: generated preparation decline on
  one explicit host (7.01 seconds).
- Red: a missing first candidate prevented process start (4.49 seconds). Green:
  selection rejected it and the generated application reached preparation
  (8.84 seconds).
- Red: portable entry had no callable dispatch boundary. Green: extracted helper
  selected one host with explicit NoProfile/STA and preserved safe GUI-unavailable
  status. Extended negatives and actual generated guided/automation execution pass.
- Focused regression exposed inherited PSModulePath breaking Windows PowerShell's
  security command. Literal built-in module loading repaired it; redirected
  packaged Help now completes with exit 0. Full portable package authentication,
  Windows PowerShell rejection and guided/automation parity focused checks pass.
- PowerShell parser check and `git diff --check`: Pass.
- Initial full gate: environment/sandbox denial, exit 1 after 180.84 seconds,
  when AzureValidationAdmission attempted its existing synthetic public-workspace
  negative test. This is neither a product failure nor a passing gate. Earlier
  AdministratorExposure and AttestedPreview groups passed. The owned session
  was confirmed terminated before review corrections began.
- Corrected-code full gate attempt: exit 1 after 217.44 seconds at the build
  manifest regression, whose expected resource list omitted the two new launcher
  inputs. All preceding Azure groups passed. The owning-slice repair updates the
  expected manifest with both literal source paths; it changes no product bytes.
  Focused BuildDeterminism and PortableDistribution checks pass, confirming exact
  source provenance, complete inventory and unchanged deterministic identities.
- Subsequent gate: exit 1 after 1417.27 seconds at GuidedRunwayDocumentation's
  hard-coded original Workflow/Mode declaration strings. All preceding groups
  through firmware passed. The owning-slice test correction acknowledges
  CheckRuntime and the reserved Gui entry while retaining only Guided/Automation
  as documented implemented modes. It changes no product bytes.
- Full gate command: `& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File ./tests/Run-Tests.ps1` using
  the explicitly selected installed PowerShell Core 7.6.5 executable on Windows.
  No further complete run is started while the independently confirmed expiry
  blocker remains.
- Final focused lane: RuntimeSelection (including all three generated Help smoke
  defaults), RuntimeInventory, RuntimeMatrix (14 cases), PortableEntry,
  BuildDeterminism, PortableDistribution, PortableDistributionApplication,
  LaunchContract, WindowsPowerShellHost, RequestValidation (12 negatives), and
  PreparationSummary all passed under that same explicit host, exit 0.
  GuidedRunwayDocumentation, GuidedRunwayPolicy, and RunLifecycle also passed
  separately after their bounded corrections. The lifecycle regression first
  reproduced the concatenated executable path, then passed both live-owner and
  abandoned-owner child cases. Each of the three smoke defaults first failed
  while its explicit-host counterpart passed; all defaults passed after repair.

## Independent full-gate blocker

Reproduction: `& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File ./tests/PreviewQualificationApplication.Tests.ps1` on the same
explicit eligible host at the actual September 5, 2026 clock. The generated
application returns a completed qualification evaluation with `QUALIFY.DENIED`
and blocking reason `QUALIFY.EXPIRED`; the test expects `Approved`. Its static
complete fixture records evidence at `2026-08-01T00:00:00Z`, while the generated
workflow evaluates the real clock. The module test pins its clock to
`2026-08-17T00:00:00Z` and passes. The current evidence genuinely exceeds the
release age limit; the runtime fix correctly exposes this separate test defect.

`SigningBoundary.Tests.ps1`, `SigningBoundaryApplication.Tests.ps1`,
`PreviewQualification.Tests.ps1`, `PreviewPublication.Tests.ps1`, and
`PreviewPublicationApplication.Tests.ps1` pass after the explicit-host correction.
No timestamp was refreshed, expiration check relaxed, approval fabricated, or
test disabled. The orchestrator owns a fresh bounded dependency repair that must
retain real expiry gates and stale-evidence negatives. Full-suite acceptance
remains blocked until that repair and a new complete gate pass.

## Standards review

Initial independent review of `56c02a1`: no established hard violations; one
judgment call, **Duplicated Code**, in portable script encoding. The separate
encoding implementations disagreed about BOM presence and removed `@ec` from
the packaged CMD. The correction consolidates normalization/encoding with an
explicit BOM option. A regression executing packaged CMD Help reproduced the
shell error, then passed with the complete generated application. Independent
affected review of `56c02a1...551d9e5`: resolved, no new hard violations or
actionable smells. This review was read-only and did not run tests.
The separate `551d9e5...778c518` manifest/evidence review found no hard violations
or actionable smells; prior implementation review remains valid. The final
bounded smoke-host/test/evidence correction requires its affected review before
handoff.

## Spec review

Initial independent review of `56c02a1`: three findings; no scope creep.

1. Probe policy failures became missing runtime. The correction carries typed
   policy rejection through candidate selection and portable guidance. Red
   observed `RUNTIME.HOST_MISSING`; green preserves `LAUNCH.POLICY_REJECTED`.
2. GUI rejection duplicated and rewrote the terminal. The correction preserves
   the existing terminal and displays guidance separately. Regression evidence
   retains one CleanupIncomplete terminal, exit 50, collection started and
   cleanup unverified; guidance cannot invent a safe terminal.
3. Named candidate cases shared one unconditional rejection. Those placeholders
   were replaced by ten distinct real generated-application runtime negatives
   at the synthetic process boundary, plus executable signature rejection,
   policy-process rejection and actual later eligible-host execution. Every
   tested rejection retains its specific portable reason; a later real host
   reaches `RUNTIME.ELIGIBLE` without collection.

Focused regressions pass. Independent affected review of `56c02a1...551d9e5`:
all three findings resolved, no new missing requirements, incorrect behavior or
scope creep. The encoding correction's actual packaged CMD-to-application Help
test supplies generated-artifact evidence. This review was read-only and did not
run tests; final full-suite and live acceptance remain separate gates.
The separate `551d9e5...778c518` manifest/evidence review found no missing
requirements, incorrect behavior or scope creep. The final bounded
smoke-host/test/evidence correction requires its affected review before handoff.

## Artifact and live disposition

The 1417.27-second failed gate used application SHA-256
`3429cae575968863d22feeabab78406fd0f84a74e8c523792e3ca7754ba0d13e`
and portable archive SHA-256
`8e572510d1cea715ec36ceda0dc5f5e5db037c094fb72ca444231cde2dd00985`.
Those identities were superseded by the three bounded smoke-host corrections;
the partial gate is not evidence for the corrected artifact.

Final focused build identities (SHA-256):

| Artifact | Digest |
| --- | --- |
| `WIN-PCInfo.ps1` | `d834aee6eef1fb4daabcbea11d6e6be6001cac9d1a25fa7f53c22246b071b745` |
| `WIN-PCInfo-2.0.0-preview.1-portable.zip` | `b8ed77f78e4039b70a6c2a95f4e020a87fbb6c95fd165fd06b16b85cb7b2d57c` |
| Packaged `Start-WIN-PCInfo.ps1` | `91558432aa16a083ba997c2ae2c7bd4b1290743bd2db023bc1fa1d0a5d2d2abc` |
| Packaged `Start-WIN-PCInfo.cmd` | `2e3be44c64de234f14baadbd09f3e5de659599851903742006684aff79b278d6` |

Generated artifacts and synthetic test output remain ignored. PortableEntry
removes only its newly created extraction after checking its resolved workspace
ownership. No real assessment, certificate/trust mutation, installation, policy
change, elevation or external mutation was performed. Automated evidence is not
personal GUI acceptance, application readiness or release qualification.

The orchestrator owns the shared #134 register; this ticket-specific record
provides its requirement results and named live successors without duplicating
the complete #158 allocation register.
