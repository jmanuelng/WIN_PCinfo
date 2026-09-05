# Issue #135 runtime selection evidence

Scope: [#135](https://github.com/jmanuelng/WIN_PCinfo/issues/135), under
[#134](https://github.com/jmanuelng/WIN_PCinfo/issues/134) and
[#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37). Starting revision and
review fixed point: `6cecce6834a8e6ad3e916c9c3b1ba971d0b58aa5`.

## Requirement evidence

| Requirement | Method and observed result | Disposition / next owner |
| --- | --- | --- |
| One explicit eligible host despite multiple matches | Generated application launch with an injected OS inventory containing a missing path and duplicate installed-host matches reached `PREPARATION.DECLINED`, exit 20, runtime eligible, no collection. | Pass, automated |
| Exact stable Core 7.6-or-later 7.x policy and safety prerequisites | Shared selection runs the generated `CheckRuntime` workflow. Existing RuntimeMatrix covers edition/version/architecture, module/validator provenance, encoding, cryptography and process-control rejection through generated application execution. | Full gate pending |
| Portable entry admission and NoProfile/STA | Extracted generated helper exercised against synthetic absent/prerelease/incompatible/rejected inventories, missing application, altered signature, and policy rejection. Successful synthetic dispatch selects one executable with NoProfile/STA. | Pass, automated |
| Real generated-artifact execution and retained entry semantics | Extracted package guided and automation validation invocations execute on the installed host, decline with the same terminal/exit semantics, and remain visibly synthetic. Existing portable Help relaunch, Windows PowerShell wrong-edition and LaunchContract tests pass. | Pass, automated |
| UTF-8 and bootstrap provenance | Test host retains its UTF-8 setup. Application initializes UTF-8 for detached launch. Bootstrap uses literal built-in manifests from its own PSHOME, avoiding the observed redirected Windows PowerShell / PowerShell 7 module-path conflict. | Pass, focused checks |
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
- Full gate: running `pwsh.exe -NoLogo -NoProfile -File ./tests/Run-Tests.ps1` using
  the explicitly selected installed PowerShell Core 7.6.5 executable on Windows.
  Final result, elapsed time and candidate identities will be recorded below.

## Standards review

Pending independent review of the committed diff from the fixed point.

## Spec review

Pending independent review against issue #135 and relevant inherited contracts.

## Artifact and live disposition

Generated artifacts and synthetic test output remain ignored. PortableEntry
removes only its newly created extraction after checking its resolved workspace
ownership. No real assessment, certificate/trust mutation, installation, policy
change, elevation or external mutation was performed. Automated evidence is not
personal GUI acceptance, application readiness or release qualification.

The orchestrator owns the shared #134 register; this ticket-specific record
provides its requirement results and named live successors without duplicating
the complete #158 allocation register.
