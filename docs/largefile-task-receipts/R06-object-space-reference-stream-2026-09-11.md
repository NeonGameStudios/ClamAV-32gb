# Task receipt: R06 object-space reference stream correction

Task ID / parent milestone: `R06` / `R00`

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`, starting commit `b4cde643fce085fa016338339830b2b28ff9a42a`; existing dirty working tree preserved; pre-receipt current-source manifest SHA-256 `487525d327c15e5063e65160243ae16c7bdad6347067b2de607ef3ffce1a7d48`.

Prerequisites verified: the vendored OneNote parser source and its object-space
mapping model were inspected. No remote runner, MCP-SSH, usage reset, banked
reset, GitHub workflow action, commit, or push was used. No host software was
installed.

Owned files and excluded shared files: owned the embedded-ink and note-tag
property-set helpers, the focused parser regression, the source guard, this
receipt, and the task ledger entry. Shared capability statuses and release
evidence records were not promoted.

Observed failing case and expected behavior: both nested property-set helpers
computed an object-space reference offset/count but sliced
`object.props.object_ids`. Object-space references must be taken from the
dedicated `object_space_ids` stream so ordinary object IDs cannot be returned
as object-space IDs or cause valid space references to disappear.

Changes made:

- Corrected embedded-ink and note-tag object-space extraction to use the
  parent object's `object_space_ids` stream.
- Added a parsed-property regression with distinct ordinary/object-space
  compact IDs; it requires the object-space value.
- Added source guards pinning the dedicated stream in both helpers and the
  regression name.

Commands, exits, logs and fixture/database hashes:

- Canonical `cargo test --manifest-path libclamav_rust/onenote_parser/Cargo.toml --locked --offline` remains blocked before compilation because the offline cache lacks `insta`.
- A disposable `/private/tmp` copy with only the unavailable test-only
  `insta` dependency removed compiled and ran the current parser library unit
  tests: `61 passed; 0 failed`.
- `sh tools/largefile_source_guards.sh`: exit 0; all 597 capability bindings
  passed.
- `python3 -B -m unittest discover -s tools -p '*_test.py'`: `147 passed`, `2
  expected skips`.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md`: exit 0.
- `git diff --check`: exit 0. The deterministic inventory comparison also
  passed.

Development tests passed: the isolated current-source parser library unit
profile passed 61/61, including
`object_space_reference_extraction_uses_object_space_stream`.

Full-size/certified evidence produced, or explicitly not run: not run. No
current-source full C/Rust consumer relink, materialized late-content fixture,
Linux x86-64 Release/sanitizer run, production-CVD/service run, or R04
qualification record exists for this slice.

Remaining failures / next slice: OneNote consumer compilation, materialized
late-content and full parser-quota evidence, certified Linux x86-64 execution,
and release qualification remain open. The seven R09 rows and the overall
release gate remain pending/blocked.

State: `development-verified`
