# Issue 46 validation evidence

This public-safe validation uses only synthetic markers and the generated unsigned development application. It contains no Assessment Package, Assessment Record, user/device identity, DPAPI blob, path, nonce, key, journal, or Restricted Diagnostic Evidence.

## Automated evidence

- `ProtectedPackagePolicy.Tests.ps1` validates the closed release policy.
- `ProtectedPackageContracts.Tests.ps1` validates emitted envelope headers and manifests against their public schemas.
- `ProtectedPackage.Tests.ps1` verifies the AES-256-GCM known-answer vector, fresh keys and nonce prefixes, deterministic inner bytes, ciphertext-only persistence, exact manifest digests, and successful DPAPI reopen.
- `ProtectedPackageNegative.Tests.ps1` verifies the maximum-size multi-chunk case, unique nonces, corruption, wrong-context key failure, truncation, unsupported format, malformed archive, and invalid manifest.
- `ProtectedPackageWriteFailure.Tests.ps1` verifies interrupted and exhausted writes leave no provisional or final package.
- `ProtectedPackageViewing.Tests.ps1` verifies one requested plaintext artifact, the protected ACL, exact interruption recovery ownership, verified close, and rejection before exposure.
- `ProtectedPackageApplication.Tests.ps1` invokes all ten closed scenarios through the generated application and verifies one sanitized result, one matching stable terminal outcome, and zero validation residue.
- `BuildDeterminism.Tests.ps1` binds the implementation, policy, and schemas into the deterministic application manifest.

Run all checks with:

```powershell
pwsh -NoLogo -NoProfile -File tests/Run-Tests.ps1
```

Passing these synthetic checks is implementation evidence for this tracer bullet only. It is not Client VM Validation, a supported-device claim, release evidence, or permission to publish a release.
