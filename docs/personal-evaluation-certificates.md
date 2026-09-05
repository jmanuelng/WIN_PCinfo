# Personal evaluation certificates and exact-candidate preparation

This is the prepared private-session procedure for [#160](https://github.com/jmanuelng/WIN_PCinfo/issues/160).
It creates two separate dedicated CurrentUser identities only during that authorized
session. Implementation tests do not create certificates, add trust, sign code, or
approve a real assessment. Personal test trust establishes no public publisher,
Preview, Supported, or release-qualification claim.

## Before changing anything

Use the initiating Windows user, the already installed eligible PowerShell, and an
approved private directory outside source control and public/synced destinations.
Keep the session inventory, certificate identifiers, Recipient Profile, signatures,
candidate hashes and detailed validation output there. Do not use a transcript in
the repository. No key, PFX, password, or recovery phrase is exported.

The private inventory records the source commit; exact unsigned and signed artifact
digests; each purpose; public certificate SHA-256 fingerprint and store thumbprint;
CurrentUser store location; provider/key name; validity; key non-exportability;
which exact trust entries this session added; profile digest; completed checks;
retained-package dependencies; and cleanup state. Provider/key names identify an
owned object for later removal, not exported key material. Record an intent before
each mutation and the exact resulting identity immediately afterward.

On restart, reconcile the inventory with those exact identities before doing
anything else. Reuse a valid dedicated signing identity and an existing verified
recipient/profile pair. Never select the first certificate matching a subject or
create another because a previous command's output was lost. Missing inventory,
multiple matches, incomplete cleanup, absent private keys or unexplained residue
means **Blocked** for setup until the owner reconciles it. Preserve existing keys
and packages. A fresh candidate uses a new private staging directory; never rerun
the build into a retained signed candidate directory.

## One-time dedicated signing identity

Confirm the unused dedicated identity and narrow trust scope in the session. With
the installed PKI command available, the prepared creation parameters are:

```powershell
$signingParameters = @{
    Type = 'CodeSigningCert'
    Subject = 'CN=WIN-PCInfo Personal Evaluation Test'
    CertStoreLocation = 'Cert:\CurrentUser\My'
    Provider = 'Microsoft Software Key Storage Provider'
    KeyAlgorithm = 'RSA'
    KeyLength = 3072
    KeyExportPolicy = 'NonExportable'
    KeyUsage = 'DigitalSignature'
    HashAlgorithm = 'SHA256'
    NotAfter = (Get-Date).AddMonths(3)
}
$signingCertificate = New-SelfSignedCertificate @signingParameters
```

Before use, verify the recorded exact certificate, Code Signing EKU
`1.3.6.1.5.5.7.3.3`, current validity, usable private key, non-exportability and
absence of CA issuance authority. If the command/provider is unavailable, stop;
do not install or repair tooling during this procedure. These parameters use
[Microsoft's certificate creation contract](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate?view=windowsserver2025-ps).

Trust only this dedicated signing certificate's public DER in the initiating
user's **Root** and **TrustedPublisher** stores on the evaluation machine. Record
whether each exact entry already existed; only newly added entries are owned for
rollback. Read both stores back by the exact fingerprint. Do not change execution
policy, use LocalMachine stores, distribute trust, or add the encryption certificate
to either trust store. Self-signed test trust and publisher selection follow
[PowerShell's signing guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing).
If another administrator or SYSTEM cannot validate a required worker under this
approved scope, record a blocker for #160; do not silently broaden trust.

## Freeze, sign and verify the portable candidate

Use two new private build directories. Variables below refer to session-reviewed
literal paths and the exact signing certificate from the private inventory.

1. Build the unsigned precursor with `build/Build.ps1 -OutputPath $stageAApplication`.
   Record the source revision, generated application and portable archive hashes,
   and the generated `Start-WIN-PCInfo.ps1` hash. Inventory all executable package
   resources. Currently the two PowerShell artifacts are the primary application
   and generated launcher. The CMD entry has no PowerShell Authenticode trailer;
   its exact bytes remain authenticated through the signed application's governing
   table and the package checks. Any new executable requires its own approved
   sign/verify treatment before this inventory is complete.
2. Confirm the exact unsigned launcher digest, then sign that generated launcher
   using `Set-AuthenticodeSignature -LiteralPath $stageAHelper -Certificate
   $signingCertificate -HashAlgorithm SHA256 -IncludeChain Signer`. Do not sign
   modular source instead. Require `Get-AuthenticodeSignature` to return **Valid**
   and the exact expected signer fingerprint. Record the signed launcher digest.
3. Build the final unsigned primary candidate into stage B with
   `build/Build.ps1 -OutputPath $stageBApplication -SignedHelperPath $stageAHelper`.
   This command admits only a Windows-valid signature over the exact launcher
   generated from this source, and embeds the signed helper's complete digest
   into the primary application. It keeps the helper's signed bytes unchanged.
   The default build remains an unsigned precursor. No signature adapter or
   synthetic trust switch is exposed by Build.ps1.
4. Freeze and confirm stage B's primary application digest before signing its
   copy in the unpacked stage B package. Use the same signing command with that
   exact application path. Require **Valid** and the expected signer again. Keep
   the unsigned source artifact and its identity separate. Signing replaces any
   existing signature, so a previously signed candidate is verified and reused,
   never silently re-signed. No timestamp service is contacted in this private
   procedure; expiry can therefore invalidate code admission. A later candidate
   needs a currently valid signature. See
   [Set-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature?view=powershell-7.6).
5. Refresh only the outer package manifest's `WIN-PCInfo.ps1` resource digest and
   byte length from the fixed signed primary. Preserve
   `unsignedGeneratedContentIdentity` and original precursor provenance as their
   historical input identities. Recompute `checksums.sha256` for every originally
   listed file, including the refreshed manifest. Never change any embedded
   governing resource or re-run Build over this signed package. Save a separate
   private personal-signing record linking source commit, unsigned precursor,
   signed helper, signed primary and final archive. It must explicitly say
   Personal Evaluation Build, no public qualification, no timestamp and no
   publication authorization; the precursor metadata is not signed-release
   provenance. General release packaging remains #155's responsibility.
6. Run the signed application inside the unpacked stage B package with
   `-Workflow Verify` and require `PACKAGE.VERIFIED`, exit 0. Verify both script
   signatures and all listed resource digests again. Archive these fixed bytes
   into a new private personal-evaluation archive; record its SHA-256, extract to
   another new private directory, and repeat verification there. The archive is
   a separate exact identity, not itself an Authenticode-signed script.
7. In disposable copies only, alter one primary-script byte and require signature
   rejection before collection; alter one helper/resource byte and require
   package-integrity rejection. Do not repair or authorize those copies. Any
   changed source/helper/resource requires the sequence and affected validation
   again, with fresh candidate-specific approval.

Only after all these checks may #160 proceed to real double-click GUI preparation,
decline without collection, then a separately approved assessment. The synthetic
`SignAndVerifyCandidate` release workflow is not a personal signing service and
cannot substitute for these Windows checks.

## One-time dedicated encryption recipient

Use the signed generated application's existing `RecipientProfileSetup` workflow,
separately from assessment, with a new private `-RecipientProfileOutputPath`, an
explicit `-RecipientLabel`, and `-ConfirmRecipientSetup`. Follow
[Recipient Profiles](recipient-sharing.md). Prefer the Microsoft Platform Crypto
Provider; retain its honest `UserAndDeviceBound` label only when operational.
The approved non-exportable software fallback is `WindowsUserBound`.

Require `Created`, `RECIPIENT.PROFILE_CREATED`, and
`syntheticRoundTripVerified: true`. Setup exports only the public Recipient Profile
after RSA-OAEP-SHA-256 encrypt/decrypt equality succeeds. It does not add certificate
trust. Verify the exact corresponding CurrentUser private-key identity and record
its provider/non-exportability privately. An existing output path is refused
before identity creation; successful repeated use imports the existing profile
and verifies its key, rather than invoking creation again. A race or failed setup
still follows the existing exact-identity cleanup protocol; `CleanupIncomplete`
blocks retries. After interruption, reconcile the inventory before creating a
new identity or deleting anything.

Compare the profile's SHA-256 fingerprint through the established trusted contact
with its owner and enter that confirmation before collection. The Preparation
Summary freezes zero or one recipient and its actual protection level. New-package
admission and packaging reject expired or not-yet-valid certificates. Historical
opening may succeed after recipient expiry when the matching private key remains
usable; missing or unrelated keys and corrupt packages must expose no plaintext.

CurrentUser DPAPI remains the initiating-user local access route. The recipient
is additional access, and a same-machine recipient is **not independent off-device
recovery**. Alternate-administrator elevation must not transfer local ownership.
In #160, verify synthetic package creation/opening through both routes, wrong
protector/corruption rejection and viewing cleanup before relying on real results.
Do not export private keys or claim recovery following loss of the necessary
Windows user/profile/device/key.

## Retention, rollback and exact removal

Keep retained encrypted packages and their inventory while they have an authorized
purpose. Never remove a recipient key while a retained package depends on it.
Expiry prevents new admission; it is not permission to delete a historical-opening
key. Before retiring test signing trust, preserve an independently trusted usable
application that can open retained packages under an authorized protector.

At approved retirement, inspect only the exact inventory identities. Remove the
owned signing public certificate from CurrentUser TrustedPublisher and Root;
preserve pre-existing entries. When no longer needed, remove the exact dedicated
signing certificate from CurrentUser My and delete its recorded CNG provider key.
For the encryption identity, first prove every dependent retained package has an
independently tested retained access route or has been deliberately disposed of;
only then remove its exact My certificate and corresponding CNG key. Certificate
store removal alone does not prove provider-key removal. Reopen each affected store
and check the exact thumbprint absent; use `CngKey.Exists` with the recorded key
name/provider to prove key absence. No subject wildcard, broad store sweep, or
private-key export is permitted. Retain the private recovery/ownership inventory
until all intended absence checks pass; unresolved residue is **CleanupIncomplete**.

Remove only conclusively owned staging copies and disposable negative-test files
after checking resolved paths lie inside the designated private session directory.
Preserve signed candidates and keys needed by retained packages. Delete deliberate
plaintext report exports when their purpose ends. Ordinary deletion is not a
forensic-erasure promise. Publish only sanitized pass/fail results and pending
gates, never the instantiated inventory or detailed signing/assessment output.
