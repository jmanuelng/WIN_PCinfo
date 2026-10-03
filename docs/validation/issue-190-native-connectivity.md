# Issue 190: native certificate rejection and typed connectivity failures

This bounded #134/#154/#158 repair addresses F158-6. Before editing, the full
native file reproduced **expected Failed, observed TlsAuthenticationFailed** for
HTTP certificate rejection. Historical gate evidence remains failed and intact.

## Diagnosis and correction

The approved source contract admits CertificateChainInvalid and
TlsAuthenticationFailed independently of generic Failed. The production HTTP
failure mapper gives an actually observed invalid chain its specific outcome;
otherwise bounded exception unwrapping recognizes TLS authentication failures.
HTTP response status, direct TLS evidence and proxy attribution remain separate.
No production behavior changes.

A tighter loopback probe found that the original server did not present a
certificate at all. The actual-user Windows transport rejected the ephemeral
server key before handshake; the sandbox's different wrapper produced the TLS
authentication state. Accepting either broad failure without certificate
observation would have falsely qualified a setup failure as trust rejection.
The strengthened real native regression first failed **Invalid versus
Unavailable** at the direct TLS chain assertion.

The Windows-only fixture now creates one random, exact-owned current-user CNG
RSA key with export policy None. It signs a ten-minute self-signed synthetic
loopback certificate without installing or trusting it and without exporting
private-key material. Normal platform validation rejects that certificate.
TLS must observe the exact synthetic certificate and return Invalid chain;
HTTP must observe the same certificate and return CertificateChainInvalid with
no success response status. Separate deterministic exception cases retain
TlsAuthenticationFailed and generic Failed without fabricating chain evidence.

The fixture shuts down its listener and accepted client, bounds worker completion
to three seconds, and preserves the key if a worker is still active. Once the
worker is absent, disposal deletes only the key object created by that fixture
and verifies the exact name is absent through the same provider. Every cleanup
error carries the unsafe flag. Constructor, body and disposal failures reach the
shared qualification finalizer, which preserves failure and blocks further work
when owned cleanup is unverified.

The use of a non-exportable key and exact-key deletion follows the documented
[CngExportPolicies.None](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cngexportpolicies?view=net-10.0)
and [CngKey.Delete](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cngkey.delete?view=net-10.0)
contracts. The host-specific handshake failure above is an observed result,
not a product qualification or a claim about every Windows TLS implementation.

## Qualification boundary

Test source `7009de092af9877bf56241332ad9fc2f332c6b2d`, reviewed against
`a208d2f`. Product source and candidate bytes remain unchanged from #188:
SHA-256 `6082704dbfaa8aa5432acd7db1ab41fd7799c8416cccf034fedfa01124a2d259`,
**3,319,524 bytes**. Native cryptographic fixture checks use the actual user;
they create no trusted certificate or real assessment evidence.

The complete native file passes, including the previously unreached static
proxy failure, bounded local DNS and loopback TCP checks. The selected static
proxy is loopback; production never falls back to direct Microsoft transport.
No real Microsoft endpoint assessment is performed. All six affected checks pass
serially: native, policy, source, contract, generated application and LocalOnly
request boundary. The generated file covers fourteen scenarios plus an enabled
fixture collapsed to zero Local Only requests. The LocalOnly boundary test also
proves zero request-capable adapter dispatch. Exact test/log identities and
observed results are retained in `issue-190-native-results.json`. The requirement
register advances only the scoped F158-6 retest checkpoint; all309 requirements
and historical/live/automated validation are preserved.

## Independent reviews

### Standards

No findings at the frozen source/base. No hard documented breaches or meaningful
baseline smells. The exact-owned key is non-exportable, the certificate is not
installed or trusted, and deletion is verified. Bounded cleanup propagates unsafe
state through the shared finalizer. Matching certificate hashes and strict
outcomes prevent setup failure from substituting for certificate rejection.
Diff whitespace check passes. Source review only; no execution or mutation.

### Spec

No findings at the same source/base. Exact certificate observation and invalid
chain are required; certificate, authentication and generic failures remain
distinct, without inferred HTTP success. Worker shutdown and exact key absence
are bounded and checked; unsafe cleanup blocks further execution. Previously
unreached proxy/DNS/TCP checks remain intact, with production endpoint and Local
Only behavior unchanged. Source review only; affected evidence and the final
integrated gate remain separate obligations.

Final findings: Standards 0, Spec 0. Final integrated and live qualification
remain pending. No signing, real trust setup, Azure run, tester distribution,
public release or GitHub Actions execution is claimed by this repair.
