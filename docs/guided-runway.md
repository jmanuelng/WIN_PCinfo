# Guided Runway

This Guided Runway is the beginner path through the WIN-PCInfo behavior that is actually implemented today. It is instructional material. Completing these steps does not create a Preview or Supported capability claim.

Open Help or About only when you want the repository and feedback routes. An assessment run never asks for feedback.

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow Help
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow About
```

## What WIN-PCInfo is for

WIN-PCInfo is a local Windows assessment application. After you approve one Preparation Summary, it can collect a bounded Comprehensive Local Assessment from one Windows 10 or Windows 11 client, derive advisory findings, render a self-contained English HTML report, and protect those results in one encrypted Protected Evidence Package.

Use it to understand one device and to prepare a Microsoft Zero Trust migration conversation. It does not assess a tenant, prove compliance, deploy software, or change Windows security configuration.

## Learning and consulting boundary

WIN-PCInfo is a learning and consulting tool. Observations are bounded facts. Findings are advisory. Recommendations are next review steps. Tenant-side Discovery Tasks are questions that one device cannot answer. The product never produces a security score, compliance percentage, certification, incident declaration, or automatic remediation plan.

## Prerequisites

You need:

- an already installed stable PowerShell 7.6 or later 7.x host. WIN-PCInfo never installs, upgrades, downgrades, or repairs PowerShell;
- a local copy of this repository and permission to run `build/Build.ps1`;
- an existing local folder for later private results if you intend to keep a package.

See [Runtime prerequisites and safe launch](runtime-prerequisites.md) for the exact host checks.

A locally built `artifacts/WIN-PCInfo.ps1` is unsigned. Help and About work on that development artifact. Ordinary assessment collection does not: the application fails closed with `PREPARATION.INTEGRITY_FAILED` before it shows the Preparation Summary. Closed validation fixtures can exercise the generated path without claiming real device evidence.

## Terminology

| Term | Meaning |
| --- | --- |
| Observation | A bounded fact admitted from Windows or a release-owned classifier |
| Finding | An advisory interpretation of admitted observations |
| Indeterminate | The evidence is not enough to support a positive or negative finding |
| Coverage | Whether a scope was complete, partial, unavailable, denied, or not attempted |
| Tenant-side Discovery Task | A follow-up question that requires authorized cloud, policy, or owner work |
| Restricted Diagnostic Evidence | Private assessment detail that stays inside the protected package |
| Preparation Summary | The complete plan you review before any collection can start |
| Local Only | Approved network behavior that makes zero assessment network requests |
| Microsoft Connectivity Enabled | Approved network behavior that runs only the disclosed Microsoft checks |

## Safety reasoning

WIN-PCInfo front-loads authority. It checks the PowerShell host, the application integrity, disk and destination safety, the network choice, and any recipient choice before collection. After you approve the summary, it does not ask for more authority, install software, enable Windows Features, or change proxy, DNS, TLS, firewall, Defender, Group Policy, or enrollment settings.

One ordinary launch may request Windows elevation at most once. SYSTEM work exists only as one predefined read-only MDM provider-presence operation. Denied elevation does not stop safe standard-user collection; privileged scopes become unavailable.

If a check cannot be proved, the application fails closed. It does not invent a weaker path.

## Expected outcomes

Every accepted run ends with exactly one terminal outcome and matching exit code: `Completed` (`0`), `CompletedWithGaps` (`10`), `NotStarted` (`20`), `Cancelled` (`30`), `TimedOut` (`40`), `IntegrityFailed` (`50`), or `CleanupIncomplete` (`60`).

A safely completed or recoverable-partial run produces one Assessment Record, one beginner HTML report, and one Protected Evidence Package. The Completion Summary explains who can open the package and which public-sharing actions are prohibited.

## Limitations

One endpoint cannot prove tenant intent, Intune assignment, Defender for Endpoint onboarding, BitLocker recovery escrow, or organization-wide compliance. Missing evidence is a gap, not a hidden pass. Physical firmware attestation, real third-party security-product support, focused assessment profiles, authenticated Microsoft-cloud collection, the safe public feedback bundle, Community Validation as a product workflow, adoption and outcome measures, formal accessibility conformance, and WinGet package-availability enrichment are not implemented.

## Choose

For a delivered Personal Evaluation Build, use the exact private candidate and
instructions supplied for your authorized session. Extract the complete portable
bundle into a private local folder and double-click `Start-WIN-PCInfo.cmd`. Keep its
governing resources together. The launcher selects an eligible installed runtime
and opens the WPF Status desk; it does not install a runtime. A source build alone
is unsigned and cannot perform an ordinary assessment.

The Status desk exposes **Change network / output** before approval. Choose either
approved network behavior and a private results folder. The scope remains
Comprehensive Local Assessment. Changing choices stops the old preparation and
shows a new complete summary; approval never carries over. **Select recipient
before assessment** similarly replaces the selection with zero or one confirmed
recipient. Encrypted results are the default; plaintext HTML is a separate warned
action, not an output-mode default.

Choose whether WIN-PCInfo fits your purpose. Preview.1 exposes one Comprehensive Local Assessment. There is no capability picker.

Choose one network behavior before approval:

- `LocalOnly` makes zero assessment network requests.
- `MicrosoftConnectivityEnabled` runs only the disclosed DNS, TCP, TLS, and HTTP checks.

Choose zero or one consultant Recipient Profile before collection. The default is zero recipients.

Do not choose WIN-PCInfo if you need a compliance audit, tenant assessment, remediator, or fleet manager.

## Verify

The following trust questions stay separate. Passing one never proves the others.

### Verify before run

A private evaluator compares the supplied exact candidate digest and follows
[Personal evaluation certificates](personal-evaluation-certificates.md) with the
maintainer during the authorized session. Personal test signing and the separate
non-exportable Current User encryption certificate are distinct identities. Keep
machine paths, certificate identities, fingerprints and session records private.
Personal trust does not establish public publisher trust, Preview qualification,
or Supported status. Never weaken execution policy or add broad trust to get past
a rejection. After runtime or trust changes, close and launch the exact approved
candidate again; the retry button does not reauthenticate changed script bytes.

Build the generated application yourself and compare the build-evidence digest with the file you are about to launch:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
```

Review `src/` rather than editing `artifacts/WIN-PCInfo.ps1`. The generated file is reproducible and ignored.

The same build also writes an unsigned portable zip. That archive has a second precursor identity: the SHA-256 of the zip bytes. Extract it and run first-run verification through the generated application as described in [Portable distribution and first-run](portable-distribution.md). A missing or altered governing resource returns `NotStarted` with no integrity override.

This local development artifact is unsigned. That is an honest trust result, not a bypass. A later trusted Authenticode release is a separate publication path. The governed [Signing Boundary](signing-boundary.md) can exercise eligibility, synthetic signing, verification, final-package assembly, and session cleanup, but a synthetic session cannot authorize publication or satisfy the Stable signing gate. Live Azure Artifact Signing stays NotStarted until separate setup authority exists. The governed Attested Preview fallback is documented in [Attested Preview trust bundle](attested-preview.md) and remains unsigned, limited-trust, and unable to satisfy the Stable signing gate.

### Runtime integrity

Before assessment work, WIN-PCInfo checks that the active host is PowerShell Core, a stable 7.6-or-later 7.x version, and that required built-in commands, UTF-8 behavior, SHA-256, AES-256-GCM, and process control work. A failed check returns `NotStarted` with official Microsoft installation guidance. WIN-PCInfo never changes the runtime.

### Preview versus Stable

`Preview` and `Stable` are release-claim states. They are not created by running this repository copy. `Supported` is reserved for a future Stable release that has trusted signing and the required evidence. This instructional slice makes no Preview or Stable claim.

### Attested versus trusted

Trusted Authenticode publication remains unauthorized in this slice. The governed [Signing Boundary](signing-boundary.md) can sign and verify a frozen eligible candidate only after release gates and the exact human digest confirmation. A synthetic session cannot create a Trusted or Stable claim, and live Azure Artifact Signing stays NotStarted until separate setup authority exists. An Attested Preview is a governed unsigned fallback: it binds one exact portable candidate to checksums, the resource manifest, dependency inventory, SBOM, source revision, and build provenance. Verifying that fallback through `-Workflow VerifyAttestation` always shows an **UNSIGNED LIMITED-TRUST WARNING** as the first record before any later smoke or validation work. It is never Trusted, never signed, and never Supported, and it cannot satisfy the Stable signing gate. Fallback selection is allowed only when Artifact Signing is not operational or during a verified service incident, never for convenience. A local unsigned build without that governed selection is simply unsigned and does not inherit this warning. See [Attested Preview trust bundle](attested-preview.md).

### Capability matrices

The planning matrix lives in [WIN-PCInfo 2.0.0-preview.1 scope](spec/releases/2.0.0-preview.1.md) and the [capability ledger](spec/capability-ledger.md). Those documents describe intended Preview.1 scope. They are not a product-generated support claim for the machine you are reading this on.

### Support claims

This slice makes no support claim. Runnable is not Supported. An eligible PowerShell host is not a Supported Windows scenario. Microsoft lifecycle status is not a WIN-PCInfo support claim.

### Microsoft lifecycle

Microsoft’s own lifecycle, servicing channel, and edition status are independent facts. WIN-PCInfo may report Windows edition and build as observations. It does not block a run merely because Microsoft has a different lifecycle label, and it does not inherit Microsoft support.

## Prepare

In the GUI, read the entire preparation area, including unresolved prerequisites,
scope, network requests, output destination, recipient, privilege plan, estimates,
and cleanup. **Approve and start** authorizes only that plan. **Decline** starts
no assessment. **Help** and **About** are passive local reading surfaces, available
when requested; they never navigate, upload evidence or prompt for feedback.

Keyboard use: Tab and Shift+Tab move between controls; Alt plus an underlined
letter selects its control. Enter or Space activates a focused button. Scroll
the preparation and activity regions to read long text. The main window and
dialogs scroll on smaller displays. Actual keyboard, display scaling and beginner
acceptance remain the private [#161 session](https://github.com/jmanuelng/WIN_PCinfo/issues/161).
Automated control tests are not evidence that those live checks passed.

The following console path remains available independently:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Mode Guided
```

On a trusted artifact, the application prints one `win-pcinfo.preparation-summary` that lists scope, privileges, network behavior, estimated time and storage, protection, cleanup, and limitations. Read the whole summary. Type exactly `APPROVE` to continue. Any other input declines and stays `NotStarted`.

Automation uses the same plan and requires an explicit switch:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Mode Automation -RequestPath ./tests/fixtures/automation-request.json
```

Add `-AcceptPreparation` only after you have reviewed that request. The switch cannot repair an invalid request or an integrity failure.

On this unsigned development artifact, the same commands fail with `PREPARATION.INTEGRITY_FAILED` before the summary. That is the implemented verify-before-run gate.

## Run

In the GUI, phase/state activity and elapsed time describe work without inventing
a percentage. A waiting heartbeat means the controller is responsive, not that a
source returned evidence. **Cancel assessment** and closing an active window both
wait for owned workers and safe finalization. Keep the application open while it
reports cleanup attention. After verified cleanup, a failed preparation retains
its unresolved prerequisites. Use **Change network / output** or **Select recipient**
to correct the request; either action starts a fresh preparation for your approval.
You can deliberately choose no recipient if that is the intended sharing route.
**New preparation / retry** repeats the current choices after verified cleanup;
it never resumes collection.

After approval on a trusted artifact, the run continues without further prompts. You should see structured progress records, then packaging, then one terminal record.

Cancel with Ctrl+C. The application acknowledges cancellation, stops owned work, protects recoverable evidence when it is safe to do so, and verifies cleanup. Cancellation does not resume later.

If a previous run crashed, do not delete folders by guesswork. Recovery is cleanup-only. It never resumes collection. The GUI exposes **Recover owned residue** when registered assessment residue blocks the destination; review and approve its recovery-only plan. **Recover viewing residue** lets you deliberately select a folder to inspect registered viewing residue. Unrelated or ambiguous paths stay untouched. Guided console launch sets `allowStaleRecovery` to false. Automation can request `automationChoices.allowStaleRecovery` after ownership is identified. The exact safety rules are in [Evidence Workspace and Stale-run Recovery](evidence-workspace-recovery.md).

If viewing, export or recipient setup reports `CleanupIncomplete`, this invocation
blocks new assessment, setup, viewing and export even if later recovery succeeds.
Retain protected packages and recovery records; use deliberate recovery or close.
Start a fresh invocation only after owned cleanup is verified.

## Interpret

**Open report** is the primary completion action when a verified package is
available. **Close viewing** closes the restricted viewer and removes its owned
temporary HTML. A partial package can still be useful; read its terminal outcome
and coverage before using findings. No package or an integrity failure disables
report actions. The offline report supports keyboard links and expandable details;
use zoom and scroll as needed. Embedded-viewer and Microsoft Edge behavior require
the exact-candidate checks in #161; fixture reports do not establish live success.

Read the report in this order: outcome, scope, completeness, limitations, prioritized advisory results, then next steps. After that, open the detailed observations.

- Missing evidence is a coverage gap. It is not the same as “the setting is off.”
- An Indeterminate finding means the rule did not have enough admitted context. It is not a hidden failure.
- A Tenant-side Discovery Task is work for a tenant administrator or security owner. The local report cannot finish that work.

Wholly synthetic walkthroughs are in [Synthetic interpretation examples](examples/synthetic-interpretation.md).

The report is not a compliance certificate. Deeper report structure is in [Comprehensive Local Assessment report](comprehensive-local-assessment-report.md).

## Troubleshoot

| What you see | What it means | Safe next step |
| --- | --- | --- |
| `RUNTIME.*` | The PowerShell host is ineligible | Install stable PowerShell 7.6 or later 7.x from Microsoft yourself, then retry |
| `PREPARATION.INTEGRITY_FAILED` | The application is unsigned, the embedded definition is corrupt, or trust could not be proved | Use Help on this development build; do not add a “run anyway” switch |
| `PREPARATION.DECLINED` | You did not type `APPROVE`, or automation omitted `-AcceptPreparation` | Review the summary or request and decide again |
| `PREPARATION.PREREQUISITE_UNRESOLVED` | Disk, destination, protector, or recipient checks failed | Fix the disclosed prerequisite and start a new request |
| Elevation denied | Privileged scopes are unavailable | Continue reading the honest partial result |
| `Cancelled` | You stopped the run | Start a new run if you still need results |
| `CleanupIncomplete` | Owned residue could not be proved absent | Follow Stale-run Recovery; do not delete an unknown path |
| `IntegrityFailed` | Evidence or package checks failed | Keep the original package if investigation is authorized; do not open it with another tool |

## Share

Use **Reopen encrypted results** to select an existing `.winpcinfo` file, then
explicitly choose initiating Windows user/device access or the approved recipient
key in the Current User store. The recipient route never silently falls back to
local access. **Recipient setup** creates a separate persistent non-exportable key
and public profile only after deliberate confirmation and a synthetic round trip.
Confirm the fingerprint with the recipient through an independent trusted channel
before selecting the profile. A recipient cannot be added after package creation.

Keep the recipient private key while any retained package depends on it. Removing
it can permanently lose historical package access. The dedicated same-device test
key does not prove independent off-device recovery. Before deliberate removal,
verify another approved recipient can open retained packages, or decide to dispose
of those packages; then follow the exact private certificate removal procedure.
Never export private keys or remove unrelated certificates. Signing trust removal
and encryption-key retention are separate decisions.

**Save HTML for consultant** requires the displayed restricted-evidence warning
and a chosen private file destination. Transfer the encrypted package to its
already-approved recipient through your authorized private channel; use exported
HTML only when that deliberate fallback is appropriate. The application never
uploads or sends either file. Delete any exported plaintext after the review;
browser/cache absence and forensic erasure are not promised.

Keep the `.winpcinfo` package private. Never attach a package, Assessment Record, Recipient Profile, fingerprint, or exported HTML report to a public issue, Discussion, pull request, or CI log.

A consultant creates a Recipient Profile in a separate workflow, then confirms the fingerprint out of band before you select that profile:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow RecipientProfileSetup -RecipientProfileOutputPath C:\PrivateTransfer\consultant.recipient.json -RecipientLabel 'Authorized endpoint consultant' -ConfirmRecipientSetup
```

On an unsigned development artifact that command fails the trust gate before it creates an identity. That is intentional.

Package opening uses an Evidence Viewing Session. The session validates the whole package, writes only one requested artifact into a restricted temporary workspace, and removes that plaintext when you close the session. Details are in [Protected Evidence Packages and viewing](protected-evidence-package.md).

Restricted Report Export is a warned fallback. The HTML remains unencrypted Restricted Diagnostic Evidence. Read the warning, then use the exact acknowledgment:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow RestrictedReportExport -ProtectedPackagePath C:\PrivateResults\package-example.winpcinfo -RestrictedReportOutputPath C:\PrivateTransfer\restricted-report.html -RestrictedReportWarningAcknowledgment 'I UNDERSTAND THIS IS RESTRICTED DIAGNOSTIC EVIDENCE'
```

Delete the exported HTML after the private review. Ordinary deletion is not forensic erasure.

## Governance

The project is MIT licensed, DCO governed, and maintainer led. Contribution rules are in [CONTRIBUTING.md](../CONTRIBUTING.md). Private vulnerability reporting is in [SECURITY.md](../SECURITY.md). Those routes appear in Help and About only when you open those workflows.

Maintenance is best effort. There is no SLA, response deadline, remediation commitment, or support contract.

Consultants who want the deeper operational index should continue with the [Consultant Workbench](consultant-workbench.md).
