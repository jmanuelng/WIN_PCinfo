# Protected Evidence Packages and viewing

This tracer bullet proves that WIN-PCInfo can turn a validated synthetic Assessment Record and synthetic HTML report into one encrypted local package, reopen it, and reveal only one deliberately requested artifact. Ordinary v2 execution still stops after Preparation; this path is available only through release-owned validation fixtures and does not claim that a Product Capability or Preview Release is delivered.

## Start with the trust boundary

A Protected Evidence Package contains Restricted Diagnostic Evidence. Treat the `.winpcinfo` file as sensitive even though its contents are encrypted. Keep it on an eligible local Evidence Workspace and do not attach it to a public issue, discussion, or CI log.

The Local Package Protector is the Windows user who initiated the run. WIN-PCInfo generates a fresh random 256-bit content key for each package and asks Windows Data Protection API (DPAPI) to protect that key with `CurrentUser` scope. An alternate administrator does not become the protector. Copying the package to another Windows user or device normally makes the wrapped key unusable. This is local access protection, not proof of who authored the package and not durable public tamper evidence.

## What finalization does

1. WIN-PCInfo validates the Assessment Record against its exact Assessment Contract Set.
2. It creates a deterministic ZIP in memory. The ZIP contains exactly `assessment-record.json`, `assessment-report.html`, and `package-manifest.json`; no plaintext archive is written to disk.
3. The manifest records the product release, Contract Set, package policy, manifest contract, completeness, protection state, and the exact path, media type, byte length, and SHA-256 digest of each artifact. It explicitly makes no authorship or durable-tamper-evidence claim.
4. The in-memory ZIP is encrypted in 16 KiB AES-256-GCM chunks. Every chunk receives a unique 96-bit nonce and a full 128-bit tag. The closed header and each chunk's index, lengths, and nonce are authenticated as associated data.
5. Only provisional ciphertext is written. It is flushed to disk, closed, reopened with DPAPI, authenticated, decompressed in memory, and checked against the envelope schema, archive rules, manifest schema, digests, and Assessment Contract semantics.
6. Only after every check succeeds is the provisional file renamed with the final `.winpcinfo` suffix and registered for preservation in the Run Recovery Journal.

An interrupted write or storage failure removes incomplete ciphertext. Corruption, truncation, unsupported format, wrong protection context, malformed ZIP, invalid manifest, or failed digest produces `IntegrityFailed`; no artifact bytes are returned and no final package is reported.

## Open one artifact safely

An Evidence Viewing Session first validates the complete package. It then creates a new Evidence Workspace boundary whose protected Windows ACL grants access only to the initiating user and LocalSystem. Only the requested release-declared artifact is written there. The journal records the exact plaintext file, filesystem identity, owner process, and workspace so an interruption remains recoverable without recording evidence content.

Close the session as soon as the requested artifact is no longer needed. Close removes the plaintext file, clears controllable in-memory copies, removes the empty restricted boundary, verifies absence, and removes the journal last. Ordinary file deletion is not forensic secure erasure; storage and Windows may retain recoverable blocks. If close returns `CleanupIncomplete`, leave the journal and boundary undisturbed and use the deliberate cleanup-only recovery path.

## Troubleshooting

- `IntegrityFailed`: do not retry by weakening validation or extracting the archive with another tool. Preserve the original protected package if investigation is authorized, and create a new package from validated source evidence.
- Wrong user or device: return to the initiating Windows user's original device and profile. This slice has no recovery certificate or password bypass.
- Interrupted finalization: only a fully reopened final `.winpcinfo` file is a package. A `.partial` file is incomplete ciphertext and is removed by the owning operation.
- Viewing cleanup incomplete: do not delete an ambiguous path manually. Use the exact Run Recovery Journal through deliberate cleanup-only recovery.

The closed release policy is `docs/spec/releases/2.0.0-preview.1-protected-package.json`. The envelope and manifest schemas are `schemas/protected-package-envelope.schema.json` and `schemas/assessment-package-manifest.schema.json`.
