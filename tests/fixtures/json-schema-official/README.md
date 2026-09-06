# Official structural-validator qualification

These 24 fixture families and the MIT license are unchanged upstream bytes from
JSON-Schema-Test-Suite commit `c9510e3bf8a896c3cba4e08509cf752b4f30dff8`,
Draft 2020-12 tree `db5782b10c73f2eee7bd3c9a0c57cfe24390e9b9`.
`source-manifest.json` records the source, Git blob, SHA-256 and byte length of
each acquired file, including license blob
`c28adbadd9114a30a302fef37c3d14f490645c1c`. `.gitattributes` preserves their bytes.
Acquisition was explicitly approved for #154; no runtime or software is bundled.

`selection.json` identifies every group and every case by file/group/case index,
description and case count. A selected group runs all its official cases without
rewriting schemas or data. The selection contains 573 applicable cases and 177
explicitly excluded cases. It qualifies the release-used vocabulary inventoried
in `docs/validation/issue-154-qualification-audit.md`, not the whole dialect.

The retained `OfficialSchemaQualification.Tests.ps1` gate calls the installed
Microsoft PowerShell Utility `Test-Json` cmdlet with the same `-Json`, `-Schema`
and error-action configuration as the product. Raw `JsonElement.GetRawText()`
prevents PowerShell number, date, null and array coercion. Exceptions and schema
loading errors cannot count as expected invalid-instance results. The report
records the exact runtime and validator assembly identities and input hashes.

Four release schemas are pinned as canonical UTF-8/LF hashes. A change requires
reviewing keyword/case applicability. The group selection covers Boolean
schemas; local `$defs`/`$ref` including escaped, recursive and chained pointers;
adjacent reference keywords; embedded `$id` ordering; types, constants, enums,
objects, required fields, additional properties, applicators, conditionals,
dependencies, tuple/items, numeric/string/array bounds, uniqueness and patterns.
Unselected mixed-vocabulary groups name the unused keywords. Remote metaschema
validation, anchors, URNs and other unused identity combinations are excluded
explicitly. The engine's external-document fetch callback is replaced by a
failing counter for this test and restored afterward. Selected references must
resolve without fetching any document; the test does not install a resolver.

The ordinary Draft 2020-12 `format` vocabulary is annotation-only in this actual
cmdlet configuration. All 21 official cases for the release-used `date`,
`date-time` and `uri` formats run, including invalid strings expected to remain
valid annotations. This is no claim of format assertion. All 12 official pattern
cases and 14 minimum/maximum string-length cases run, including Unicode
semantics; the `const`/`enum` families additionally exercise escaped strings and
distinct Unicode representations. I-JSON and domain semantics are qualified at
the generated contract/package seams, independently of these structural cases.

Run `tests/Invoke-OfficialSchemaQualification.ps1 -ResultPath <owned-result.json>`
under the installed approved PowerShell host to retain the detailed synthetic
report, or run the `.Tests.ps1` gate for verification with owned-result cleanup.
