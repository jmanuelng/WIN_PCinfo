# WIN-PCInfo coding standards

The repository's `AGENTS.md`, `CONTEXT.md`, relevant `docs/adr/` decisions,
and GitHub issue specification are authoritative. Surface conflicts instead of
silently overriding them.

## PowerShell

- Use PowerShell 7-compatible syntax and `Set-StrictMode -Version Latest` in
  executable modules and tests.
- Prefer explicit parameter validation, bounded inputs, stable codes, and
  deterministic output over implicit coercion or presentation text.
- Preserve the distinction between observations, coverage, diagnostics,
  findings, and recommendations defined in `CONTEXT.md`.
- Never weaken security controls, collect secret material, or turn absent or
  incomplete evidence into a successful negative claim.

## Testing

- Work test-first when behavior changes: demonstrate the failing case, make it
  pass, and retain the regression test.
- Run the focused test while iterating and the complete repository gate before
  delivery:

  `pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1`

- Keep build output deterministic and generated artifacts out of source
  control.

## Delivery

- Keep each issue change cohesive and traceable to its specification.
- Do not push, open or merge pull requests, or close issues from an agent
  phase. The Sandcastle orchestrator owns those transactional operations after
  implementation, review, and the full test gate complete.
