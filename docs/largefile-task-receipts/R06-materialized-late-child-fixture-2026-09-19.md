# Task receipt: R06 materialized late-child fixture — 2026-09-19

Task ID / parent milestone: `R06` / `R00`

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`

## Scope

Create a reproducible, fully allocated modern OneNote fixture whose real
embedded child is serialized beyond the former 256 MiB whole-input boundary,
then exercise it through the vendored reader-backed parser callback API.

## Implementation

- Added `tools/largefile_onenote_late_fixture.py`. It inserts a valid,
  unreferenced FSSHTTPB `ObjectDataBlob` before the existing data-element
  records, preserving the original modern section's IDs and references.
- Added a CMake-generated build fixture target,
  `tgt_largefile_onenote_late_fixture`, so the 256 MiB artifact is generated
  from the existing decrypted corpus and is never committed.
- Added the production-linked Check test
  `test_rust_onenote_reader_detects_materialized_late_child`, including the
  `OneNote.Reader.LateMZ` nested-child signature, temporary-byte cleanup
  assertions, and non-cacheable/incomplete failure checks.
- Added source guards for the generator, CMake target, and C test; refreshed
  the generated `docs/largefile-inventory.tsv`.

## Verification

Using the existing decrypted `clam.exe.webapp-export.one` corpus, the tool
created a fully allocated file of `268,487,770` bytes. The embedded `MZ`
marker was independently located at byte `268,468,815`, which is `33,359`
bytes beyond `268,435,456` (`256 MiB`). The vendored parser's public
`scan_section_reader` API streamed exactly one attachment, `clam.exe`, with
`544` bytes of output.

The generator was also run through its CLI help path, the fixture was checked
with the existing standalone Rust harness, `git diff --check` passed, the
capability manifest passed with 604 rows, the status snapshot passed, and the
full source-guard suite passed. The follow-up deterministic framing suite
passed 3/3 tests, covering the one-byte compact type encoding, package/first
element admission, and refusal to create a below-cap output.

## Qualification boundary

The new production-linked C test and CMake fixture wiring are source-verified
but have not yet run in a coherent current-source CMake build in this macOS
checkout: `cmake` is unavailable locally, and the retained remote staging
policy prevents treating an older Sonic1 checkout as this source revision.
Therefore no production-linked C pass, sanitizer pass, Sonic1 pass, or
capability promotion is claimed. The release gate remains blocked pending
that run and the roadmap's certified/full-size qualification evidence.

State: `development-verified`; reproducible physical late-child fixture and
standalone reader callback pass; production-linked execution remains pending.
