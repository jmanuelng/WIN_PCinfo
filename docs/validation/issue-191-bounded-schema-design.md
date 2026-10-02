# Issue 191: bounded canonical schema evaluation design

Status: implementation under local engineering validation. One fresh calibrated
controlled maximum assessment passes; repeat qualification and final integrated
review remain pending. No actual delivered-GUI, live acceptance or release claim.

The original unchanged maximum controlled Status desk workload exceeded the
frozen 512 MiB working-set ceiling. Its functional checks and owned cleanup passed.
The existing trusted Test-Json command allocates approximately 310 MB during
one maximum-record structural validation. Repeated isolated validation retains
stable managed memory after warm-up. Changing its output mode did not materially
reduce allocation; a smaller process heap cap rejected a valid record. Neither
approach is accepted.

The correction changes evaluation scheduling inside ContractValidator. Records
below 512 KiB retain whole-record evaluation; larger records use the equivalent
bounded schedule below. Both paths verify one Boolean result per command and
reject command errors. This threshold changes scheduling, never a record limit.
It keeps the trusted caller-supplied Test-Json command, its engine/options, the
canonical schema, every record item, all bounds, lexical checks, semantic checks,
and existing public reason codes. No dependency is acquired or backend replaced.

## Equivalence boundary

For the reviewed canonical schema:

`Canonical(record) = Skeleton(Project(record)) AND each original item schema accepts every corresponding original item.`

The temporary skeleton schema replaces only uniform items constraints of the
ten independent top-level arrays with true. Its input projection retains every
original property name and every non-split raw value; an admitted array retains
its exact cardinality with null placeholders. Wrong-type values, non-object
roots, unknown properties and absent optional properties remain unchanged.
Original type/count bounds, required properties and the closed object shape
remain enforced. requiredFeatures remains raw and wholly validated, including
its whole-array uniqueness. The projection avoids building a second complete
instance tree solely to check root shape and array cardinality.

Every present split array is then evaluated in batches of at most 64 items,
using its original item schema and unchanged definitions. Item-local conditions,
dependencies, types, field patterns and nested-array uniqueness remain intact.
Optional absence and empty arrays remain governed by the complete skeleton.
Raw JSON values preserve order and avoid PowerShell numeric/date coercion.
Original, projected and validated item counts and returned Boolean counts must
agree. Each batch has its own command invocation, requiring exactly one Boolean
result. Missing, duplicate, compensated or non-Boolean outputs reject the record.
Only the trusted command's normal `InvalidJsonAgainstSchemaDetailed` errors may
accompany a false schema decision; every other command error fails closed.
Derivation failures also reject the record. Semantic
checks run only after every structural pass accepts it and use the original
record. No projected record is reported or packaged. Original UTF-8, document
size, duplicate names, depth, string and numeric checks precede projection.

## Fail-closed admission

The qualified canonical UTF-8/LF schema identity is
`c550ad7fcb86bb6d476f4da18c431b1c432f833ab5bbe34bfb5d4f1e5d327351`.
Its authenticated resource digest must be verified by the existing boundary
before derivation. The optimized algorithm admits this exact reviewed shape;
a changed schema requires fresh review and qualification. It cannot silently
partition new root dependencies, cross-array references, contains, prefixItems,
unevaluatedItems, array-level conditions or uniqueness constraints.

The reviewed reference graph contains only local references into $defs and no
nested resource IDs, anchors or dynamic references. Derived wrappers carry the
same dialect and definitions. Their distinct deterministic derived IDs prevent
stale root registrations from substituting another component; local definition
reference closure makes the changed wrapper base URI irrelevant to assertions.
Canonical schema bytes and identifiers remain unchanged.

No successful-record result is cached. The plan is derived anew from the
verified canonical bytes. Batch reclamation operates on managed memory inside
the application process and does not trim the OS working set or change machine
configuration. First progress, heartbeat, cancellation, cleanup and all resource
ceilings remain unchanged.

## Required evidence before adoption

- Differential whole-record versus bounded evaluation on identical canonical
  positives and negatives, including every existing contract fixture.
- Required/property/type/count failures, nested duplicate IDs, recognition
  conditions, optional/empty arrays, explicit null/wrong types, case variants,
  unknown array properties, simultaneous failures, and invalid items at first/last and
  63/64/65 batch boundaries.
- Raw numeric/Unicode preservation, trusted command errors on different passes,
  incomplete/unexpected Boolean output, changed schema admission, and stale
  registry/offline reference behavior.
- Actual trusted Test-Json official Draft 2020-12 qualification remains engine
  provenance evidence. Arbitrary upstream schemas are outside this specialized
  canonical decomposition; they do not establish its equivalence.
- Fresh generated Software Maximum, Distinct, EscapedOverflow, FullReport Maximum
  and affected WPF execution, exact candidate/source identities, ownership and
  sampling-loss disposition, then independent Standards and Spec review.

Original failures remain Fail. Diagnostic prototypes cannot qualify an unchanged
candidate. Actual delivered-app and controlled-driver upper bounds remain
separately attributed; aggregate child-tree and eligible-client live acceptance
remain pending in the owning live gates. Three clean full-profile qualifying
measurements remain required before a release claim.

## Collection-stage buffer lifetime

The remaining maximum controlled WPF peak occurs before canonical record
construction. A retained stage probe locates accumulation across preparation
and collector validators; collecting only before record construction is too
late to lower that prior peak. The adopted correction reclaims inactive managed
allocations at the existing collection-stage admission boundary, before the
next source allocates. Cancellation is checked before and after this collection
through the existing stage functions. Scope, source values, bounds and machine
configuration remain unchanged. The diagnostic passes functional/cleanup
assertions and observes a 533,471,232-byte assessment working-set upper bound,
but is NotQualified because periodic private/workspace coverage is incomplete.

Sparse dispatcher samples remain diagnostic evidence. Credible controlled
qualification requires native lifetime private/working-set peaks covering
startup and a complete conservative owned-disk write bound; no baseline is
subtracted. Target-runtime native calibration now passes; independent advisory on the
measurement design passes. Final integrated review remains pending.
Original mixed-process and post-assessment driver failures remain Fail.

## Native lifetime counters and complete owned-write bounds

Controlled qualification now reads PROCESS_MEMORY_COUNTERS_EX through an exact
held process handle. Native lifetime peak private commit and working set cover
startup and allocations released between observations. No baseline is subtracted.
The helper validates the target pointer layout, structure byte count, native call
result and current/peak invariants. An isolated target-runtime calibration commits
and touches 256 MiB, releases the exact allocation, and demonstrates that lifetime
peaks retain the allocation after current memory falls. The .NET peak readings
agree within bracketed native readings. Calibration is bound to helper bytes,
runtime bytes and versions, Windows version and architecture, and expires after
24 hours. Invalid or absent calibration prevents controlled qualification. The consumer
reconstructs the complete retained proof: exact kind/Booleans, integral nonnegative
counters, pointer/structure layout, current-versus-peak invariants, monotonic peaks
across before/during/after/final bracket, allocation increase/release and both .NET
peaks inside that bracket. A retained success flag cannot waive these checks.
Twenty-three malformed-evidence negatives exercise that admission directly.

Periodic dispatcher samples retain counts, gaps and losses as diagnostics.
They do not establish strict private-memory or disk upper bounds. For the ordinary
controlled assessment plus WPF report-viewing path, an exact candidate/harness/
adapter/instrumentation inventory accounts for every owned byte increase before
mutation. Reservations include journal replacement overlap, registered HTML,
complete protected-envelope framing/ciphertext, recipient-profile writes and
restricted export bytes. Native owned-file creation requires a previously recorded reservation. This is
a reviewed closure over exact pinned source and adapters; the path-claim guard
does not independently detect arbitrary later writes to an already claimed path.
The cumulative bound never subtracts deleted or renamed bytes. Unknown writers,
changed input identities or changed mutation seams reject qualification.
Interruption and post-start witness configurations are outside this inventory.

The shared worker/controller ledger is frozen by value only after the complete
assessment and WPF viewing endpoint. Original writers are then restored so
independent post-assessment export and reopening assertions still execute.
Their separate full-driver memory failures remain Fail. Inventory setup is
inside unconditional finalization, and no output directory is created until
all writer and launch seams have been derived. Captured calibration, inventory
and instrumentation hashes are retained with every controlled measurement.

## Report anchor transformation

Maximum reports previously copied the complete HTML for each observation anchor
and twice for each recommendation anchor. The replacement uses one ordinal
mapping pass for observation IDs and another for recommendation IDs/fragments.
The original IDs are HTML-encoded; canonical and compact destination IDs are
disjoint. Unknown attributes and values remain unchanged. Observation shortening
still precedes the existing missing-row checks, and recommendation shortening
still follows them. No field, row, link, escaping rule or report limit is removed.

An independent legacy sequential-replacement differential passes 24 cases,
including empty input, repeated markup, case variants, spaces, encoded quotes,
Unicode, unknown attributes and a repeated maximum corpus. Real comprehensive
report determinism, locale, unknown-field and maximum-size assertions pass.

The first fresh calibrated generated maximum WPF assessment for candidate
24ab45dda69ee2a7cfd45985b27e39031e7f8c6f94cab5e0b2a54a830b0a9512
records 526,274,560 bytes lifetime peak working set, 358,871,040 bytes private
commit, and a 2,047,117-byte cumulative owned-write bound. Functional assertions
and cleanup pass. The full test driver subsequently peaks at 711,831,552 bytes
working set and remains Fail. This is controlled-source engineering evidence,
not actual delivered-GUI or aggregate-child measurement. Original failures,
failed diagnostic runs and pending eligible-client acceptance remain retained.

The subsequent thirteen-case controlled campaign passes three fresh maximum WPF
runs, Distinct, EscapedOverflow, accepted and denied FullReport, and six separate
active WPF actions. Maximum working sets are 525,078,528, 520,441,856 and
520,343,552 bytes; all native reads and cleanup checks pass. This campaign retains
the earlier calibration identity. Re-measurement under the stricter typed
calibration admission is in progress; final integrated qualification is pending.

## Checkout-stable inventory identities

The closed inventory pins canonical UTF-8/LF script identities, matching Git's
source representation, while retaining the actual tested-byte SHA-256 for every
harness/adapter/instrumentation input. Native calibration continues to pin exact
runtime/helper bytes and needs renewal after any such change. This avoids a false
inventory rejection after a clean Windows checkout converts LF to CRLF or
preserves a UTF-8 BOM. A logical source value change still invalidates the pin.
An independent LF/CRLF/BOM regression is RED before the identity helper and GREEN
after it; candidate drift, unknown writer and derivation failures still reject.

The stricter typed-calibration thirteen-case campaign also passes, including
three maximum WPF measurements of 520,957,952, 523,423,744 and 523,591,680 bytes
working set. The current final inventory-attribution campaign is being repeated
before freezing source for the full gate. Earlier identities and failures are
retained rather than overwritten.
