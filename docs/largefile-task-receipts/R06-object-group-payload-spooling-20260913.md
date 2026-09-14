# R06 OneNote object-group payload spooling receipt — 2026-09-13

## Scope

Keep stream-backed modern OneNote structural object payloads out of the
parser's in-memory `Vec<u8>` path. Attachment blobs already used the bounded
reader/spool abstraction; this slice applies the same behavior to inline
object-group binary items that hold metadata and object-property payloads.

## Observed gap

`BinaryItem::parse` decoded every stream-backed object-group binary item with
`read_vec_u64`. Although the individual materialization ceiling was enforced,
multiple structural payloads could remain resident as owned vectors while the
OneStore graph was built. That was weaker than the roadmap's bounded
reader/spool contract for a streaming modern input.

## Changes

- `BinaryItem` now stores `ReaderBlob` and reads through `Reader::read_blob`.
  Stream inputs therefore use private mode-0600 temporary spools written in
  bounded refill windows and charged through the supplied blob budget; slice
  inputs retain the compatibility memory behavior.
- `ObjectGroupData::Object` now owns the blob abstraction and validates its
  declared size through the blob length, without narrowing to `usize`.
- OneStore header and object-property parsing opens a bounded reader over the
  blob rather than borrowing an in-memory slice.
- Added a parser regression proving that a stream binary item uses the private
  spool path and preserves its payload bytes.

## Verification

- Existing disposable ARM64 Linux CMake `RelWithDebInfo` build cache was
  confirmed to carry `-fsanitize=address,undefined` for C and C++.
- `cmake --build /tmp/clamav-asan-current-20260912 --target check_clamav -j2`
  — exit 0; current consumer target rebuilt and linked.
- `cargo test --locked --offline --lib` in the current vendored parser — exit 0;
  78 passed, 0 failed, 0 ignored. This includes the new binary-item spool
  regression and all existing reader, OneStore, and parser boundary tests.
- Focused current-source ASan/UBSan `rust_onenote` consumer group — 4/4.
- Focused current-source ASan/UBSan `required_unsupported` consumer group —
  57/57.
- `git diff --check` — exit 0.

## Limits and next action

This is development verification only. It does not prove a fully materialized
large-file OneNote case, complete parser-owned aggregate memory accounting,
certified Linux x86-64 qualification, production-CVD/service behavior, or
release readiness. No capability was promoted. The next R06 proof remains an
independently generated valid modern fixture with late child content and
materialized edge evidence.

State: `development-verified`.
