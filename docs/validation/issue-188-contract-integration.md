# Issue 188: resource, preparation and privacy contract integration

This bounded repair addresses F158-1, F158-4 and F158-8 under #134, #154 and
#158. The historical failed gate in `issue-158-integrated-checkpoint.md` remains
failed. This record qualifies the affected synthetic seams; it does not replace
the final integrated gate or establish Windows client acceptance.

## Diagnosis and resulting behavior

The original AssessmentContractSet test failed actual Draft 2020-12 Test-Json
validation: #147 added two printer driver fields to the existing 262-field
inventory without updating its version/schema/test agreement. Contract Set
**1.14.0** now admits exactly **264** fields, preserving both new fields. The
263-field and 265-field negative cases fail validation. Generated combined records
and package manifests accept the new version while historical package versions
remain admitted. No evidence, transport, report, memory or time budget changes.

After inventory admission, the previously unreached collector assertion failed:
AppLocker CSP is intentionally collected through the SYSTEM MDM Bridge channel
under #144. The test now checks that exact collector independently of the
effective-policy collector used for the other five platform-protection scopes.

The original SchemaContracts generated-plan test failed its Microsoft
connectivity const. Fixing that exposed certificate guidance drift. A structural
comparison found stale recommendation metadata in five policy consts, plus
earlier approved effective-policy source/layer changes and #147 printer source
fields and rule-input cardinalities. Schema consts now agree exactly with the
existing release policy files. Policy files themselves retain their approved
definitions. The source-rule input counts account for the two retained fields;
this does not increase a collector or package byte ceiling.

Both LocalOnly and MicrosoftConnectivityEnabled generated plans pass actual
trusted Test-Json validation. Each executes all **36** immutable-operation
mutation negatives, including the original 29 previously unreached cases and
seven guidance/source mutations. Altered guidance, missing prerequisites,
references, roles and verification, changed printer properties, and a changed
policy source interface remain rejected.

DeviceReadinessApplication originally rejected two public software guidance
cautions containing the word "entitlement". The minimized actual output had no
manufacturer, model or processor marker leak. The privacy assertion allows only
the exact reviewed caution at the two named recommendation fields in the
Preparation Summary. All other output remains scanned. Seven injections into an
actual serialized generated validation record are rejected, including the exact
public caution at a different field. Altering the allowlisted caution to an
entitlement claim is also rejected. No production privacy boundary is bypassed.

## Qualification and identity

Source repair: `faa8f7062ba2945925b62a6243de590e96eb741a`, reviewed against
`f065037`. Candidate SHA-256:
`6082704dbfaa8aa5432acd7db1ab41fd7799c8416cccf034fedfa01124a2d259`,
**3,319,524 bytes**. Earlier candidate evidence is invalidated for this repair;
historical evidence remains unchanged.

All thirteen serial affected checks pass: AssessmentContractSet, SchemaContracts,
DeviceReadinessApplication, PreparationSummary, RequestValidation,
ProtectedPackageContracts, ProtectedPackageAdmission, ProtectedPackageApplication,
ResourceDependenciesPolicy, ResourceDependenciesContract, ContractValidator,
RecommendationDefinitions and OfficialSchemaQualification. The package application
test completes all ten scenarios with verified cleanup. The official installed
validator passes **573** selected cases, rejects no expected disposition, retains
**177** explicitly inapplicable cases, and performs **zero** external fetches.

Changed official schema pins were reviewed for applicability: the contract-set
const/version and exact inventory cardinality and the package version enum use
the same already-qualified JSON Schema keyword vocabulary. No selected official
case becomes inapplicable, no corpus or selection is changed, and old results are
not reused as evidence for the new pins. The preparation schema retains strict
const validation and its generated-plan mutation checks.

BuildDeterminism also passes, reproducing identical application bytes from LF and
CRLF input trees and verifying exact source/resource provenance and relocated
standalone execution. All fourteen affected checks pass. Sanitized test/log
identities, definition hashes and observed results are recorded separately in
`issue-188-contract-results.json`.

## Independent reviews

### Standards

No findings at the frozen source repair against the resolved base. No hard
documented breaches or meaningful baseline smells. The six changed preparation
constants exactly match their release-owned policies; version 1.14 consistently
reaches package admission and retains both printer fields. Privacy regressions
preserve restricted-marker rejection outside the two allowlisted guidance fields.
Schema pins change without new schema keywords. Diff whitespace check passes.
Source review only; no application execution or mutation.

### Spec

No findings at the same frozen source/base. All six affected preparation consts
match normative policies. Printer observation counts retain the existing
eight-registration ceiling; AppLocker CSP retains SYSTEM ownership. Both modes
exercise mutation negatives; privacy exempts only exact reviewed cautions at
their designated fields. Version propagation, schema pins and build resource
digests are coherent. Source review only; qualification documentation and the
final integrated gate remain separate obligations.

Final findings: Standards 0, Spec 0. The final full application gate remains
pending after #189–#192.
No live assessment, signing, trust mutation, Azure run, tester distribution,
public release or GitHub Actions execution is claimed by this repair.
