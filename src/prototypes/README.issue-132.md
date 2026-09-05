# Issue 132 GUI and report experience prototype

> **PROTOTYPE — synthetic decision evidence only.** This code does not collect device evidence, change Windows, contact a service, create an assessment package, or save a report.

Question: which PowerShell GUI and HTML report information hierarchy lets a beginner run a bounded assessment confidently while giving a consultant useful, honest evidence?

This is a new prototype surface because WIN-PCInfo has no existing GUI page in which to mount the variations. It deliberately offers three structurally different directions in one WPF window:

- **A — Guided journey:** a visible five-step route, plain-language preparation, and result actions in a separate rail.
- **B — Status desk:** a compact operating surface with persistent scope facts, an event timeline, and report actions beside the terminal state.
- **C — Focus first:** one large immediate decision with supporting rationale and technical state kept secondary.

Each direction opens a matching, self-contained HTML report sample. All report data is plainly synthetic, and each report includes a denied identity/enrollment source so incomplete evidence cannot look like a clean bill of health.

## Run

From the repository root on Windows:

```powershell
npm run prototype:gui-report
```

Use the bottom arrows or the Left/Right keys to switch direction. Pick a simulated outcome, start it, interact with the responsive window, cancel with the button or Escape, and inspect the report actions after a usable result. The private HTML action demonstrates its warning and writes no file.

For a noninteractive structure check:

```powershell
pwsh -NoLogo -NoProfile -STA -File ./src/prototypes/Issue132.GuiReportExperience.ps1 -ValidateOnly
```

## Decision prompts

1. Which direction would you trust a beginner to operate without a consultant beside them?
2. Which report gets a consultant to the important result fastest without hiding evidence or limitations?
3. Should `Open report` remain the primary completion action, with private HTML saving visibly secondary?
4. Which elements should be combined—for example, A's journey, B's timeline, or C's explanations?

The chosen direction must be rewritten and integrated through the production architecture. This prototype is intentionally not production-quality code and must not be merged into `main` as the application implementation.
