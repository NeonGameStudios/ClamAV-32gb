# Task receipt: R06 modern OneNote parser boundary audit

Task ID / parent milestone: `R06` / `R00`

Scope: determine whether the pinned modern OneNote dependency provides a
reader/seek-backed parsing boundary suitable for inputs beyond the current
256 MiB whole-input cap. This receipt records the initial audit and the
follow-up bounded-reader implementation slices; it does not promote OneNote
to release qualification. The later scanner admission lift is recorded below.

Prerequisites verified:

- The canonical checkout and dirty working tree were preserved.
- At the initial audit, `libclamav_rust/src/scanners.rs` refused modern
  OneNote inputs above `FMap::WHOLE_INPUT_MAX` and returned `CL_ERESOURCE`.
- `libclamav_rust/src/onenote.rs` calls the pinned dependency's
  `Parser::parse_section_buffer(&[u8], &Path)` API for modern sections.
- `Cargo.lock` pins `onenote_parser` 0.3.1 to git commit
  `29c08532252b917543ff268284f926f30876bb79` on the
  `CLAM-2329-new-from-slice` branch.
- The cached dependency checkout also exposes `Parser::parse_section(&Path)`,
  but its implementation calls `read_to_end` into a `Vec<u8>` before parsing;
  it is therefore not a streaming substitute.

Observed blocker and expected behavior:

- The pinned `onenote_parser` source has no public reader/seek-backed section
  API. Its internal `Reader` is a wrapper around `&[u8]`, and the path API
  materializes the entire file. Raising `WHOLE_INPUT_MAX`, mapping a larger
  file, or switching to `parse_section` would violate the roadmap's bounded
  reader/spool requirement.
- An offline test of the cached dependency could not run because the local
  Cargo cache lacks the `insta` crate (`cargo test --offline` exit 101).
  No dependency was downloaded or installed.

Dependency ownership audit (2026-09-09 UTC):

- The pinned checkout at
  `/Users/claude/.cargo/git/checkouts/onenote.rs-83d1173891b1b328/29c0853`
  contains 10,071 lines across roughly 568 KiB of parser source. Its private
  reader wraps `&[u8]`, and the modern model owns extracted content in `Vec`
  fields, including embedded-file payloads. This confirms that a compliant
  reader-backed fork is a broad parser/API ownership change, not a local
  adapter around the existing public methods.
- The initial audit therefore kept the refusal in place rather than raising
  the cap, mapping a larger whole input, or introducing an unbounded `Vec`.

Conclusion of the initial audit: no modern parser implementation change was
made at that point. The subsequent bounded fork and reader-backed scanner work
are recorded below. Closing R06 still requires a current-source build and a
valid modern fixture with late-child evidence; the initial fail-visible refusal
has since been removed from the modern scanner.

Bounded legacy-reader regression (2026-09-09 UTC):

- Added `legacy_reader_handles_short_source_reads`, which limits every source
  read to three bytes and verifies that a valid legacy attachment is emitted
  completely with no abort. This protects the reader-backed path's short-read
  handling without initially relaxing the modern whole-input cap or allocating a larger
  parser buffer.
- The local unit harness remains green, but the Rust crate test profile was not
  run because the available toolchains lack the required cached test/dependency
  set. Local and Sonic1 formatter checks both stopped with exit 1 because the
  `rustfmt` component is not installed; no toolchain component was installed.
- An isolated Sonic1 `rustc --test` invocation against the existing cached
  OneNote parser and dependency artifacts compiled the overlaid module and ran
  all 13 existing OneNote module tests: 13 passed, 0 failed. The remote run
  used the pre-regression overlay; the newly added local short-read test was
  not attributed to that result because the SSH policy rejected uploading the
  private updated source payload.

The short-read regression is implementation-level development coverage only.
The modern reader-backed dependency boundary remains the blocking R06 issue.

The former modern whole-input refusal was covered by a Rust admission unit
`onenote_modern_parser_rejects_inputs_above_whole_input_cap`. A production C
fixture that called the full scanner with a shared OneNote magic prefix was
prototyped and discarded: the scanner must first stream the legacy fallback
over the declared extent, and the synthetic 256 MiB marker search exceeded
the test harness timeout before reaching the cap assertion. The Rust unit
keeps this boundary check deterministic without encoding that fallback scan
cost as a test timeout.

Current-source verification (2026-09-09 UTC):

- An architecture-matched x86-64 container relinked the current CMake
  `check_clamav` target successfully. The focused `cl_suite/rust_onenote`
  selection passed 2/2 with zero failures and errors.
- `sh tools/largefile_source_guards.sh` passed, the acceptance map/schema
  check passed for all 597 capabilities, `git diff --check` passed, and the
  tools suite passed 145 tests with two expected skips.

Bounded modern-reader implementation slice (2026-09-09 UTC):

- Vendored the audited `onenote_parser` 0.3.1 source at the pinned
  `29c0853` revision under `libclamav_rust/onenote_parser` and changed the
  production dependency to that path. The legacy slice API remains intact.
- Added a sequential parser reader with a 64 KiB refill window, short-read
  handling, typed I/O-error extraction, and a public
  `Parser::parse_section_reader` boundary. The parser's format-object model
  still owns declared payloads in `Vec` fields. Those reads now refill in
  64 KiB chunks and reject any individual parser-owned payload above the
  explicit 256 MiB materialization limit. This slice removes the whole-root
  `read_to_end`/temporary-file/contiguous-`mmap` path, but aggregate parser
  memory is not yet quota-accounted.
- The ClamAV scanner now restarts a bounded `FMapReader` after the legacy
  compatibility pass and calls `OneNote::scan_reader`. Attachment output
  continues through the existing quota-accounted temporary spool, callback
  stop, deadline, cleanup, and status-provenance paths. At this stage the
  scanner still returned `CL_ERESOURCE` above the explicit 256 MiB admission
  cap; that gate was removed in the later admission-lift slice below.
- The vendored parser's `tests/lib.rs` reader-equivalence case passes with
  deliberate three-byte source reads, and its logical 256 MiB-plus padded
  input case passes without materializing the padding. The current-source
  x86-64 CMake relink reached `100% Built target check_clamav`, and the
  focused `cl_suite/rust_onenote` run passed 2/2. Source guards and
  `git diff --check` also pass.

Bounded payload allocation refinement (2026-09-09 UTC):

- Declared payload buffers now grow with exact refill-sized reservations
  instead of reserving the entire declared length before the first source
  read. Allocation failure is a typed parser resource failure and remains
  fail-visible through the ClamAV FFI; the individual 256 MiB admission limit
  is unchanged.
- After this refinement, the vendored parser suite passed 13/13 unit tests,
  4/4 integration tests, and its one existing ignored doctest. A fresh
  current-source x86-64 CMake relink completed and `cl_suite/rust_onenote`
  passed 2/2. Aggregate parser-memory accounting, a materialized beyond-cap
  fixture, and full qualification remain open.

This is an implementation-level bounded-reader milestone, not the R06 Done
condition: a valid materialized modern input beyond the former cap, late-content proof,
quota/fault behavior, and full qualification evidence remain open.

Aggregate parser-materialization refinement (2026-09-09 UTC):

- The vendored reader now tracks the cumulative bytes of parser-owned payload
  buffers retained by the parsed section, in addition to the per-payload
  ceiling. The default aggregate budget is the same explicit 256 MiB bound;
  both slice and sequential-reader payload paths use fallible reservation and
  return the typed resource/allocation errors before a larger buffer is
  published.
- The parser suite after this change passed 14/14 unit tests, 4/4 integration
  tests, and its one existing ignored doctest. This verifies cumulative-limit,
  short-read, and logical beyond-former-cap reader behavior. A new C/Rust
  application relink and certified materialized-edge run remain required.
- The full `libclamav_rust` consumer crate also passed
  `cargo check --locked` in the same disposable x86-64 environment, including
  the updated OneNote scanner integration.

Bounded stream-window refinement (2026-09-09 UTC):

- The reader-backed parser now rejects a stream `read`/`peek` request larger
  than its configured materialization window before growing the internal
  buffer. Stream refill growth uses fallible reservation and maps allocation
  failure to the existing typed parser resource error. Slice-backed parsing
  remains unchanged because it borrows caller-owned bytes rather than growing
  a reader buffer.
- The focused regression covers rejection before any stream-buffer growth.
  Source guards, inventory freshness, and `git diff --check` pass. The fresh
  parser run passed 15 unit tests, 4 integration tests, and 1 ignored
  doctest. A native C relink was not claimed because the available x86
  disposable image lacks the Check headers. Rust crates were fetched only in
  the disposable container; no host dependency or tool was installed.

Count-driven collection safety refinement (2026-09-09 UTC):

- Added a typed collection budget and fallible incremental reservation helpers
  to the vendored reader. Explicit counts in compact ID arrays, object-property
  streams, property sets, and nested property-value sets are checked before
  reservation. End-marker collections in object groups, storage indexes and
  manifests, and the data-element package maps now reserve one entry at a time
  under the same budget.
- The focused parser run passed 17 unit tests, 4 integration tests, and 1
  ignored doctest, including a nested property-values oversized-count
  regression. Source guards, inventory freshness, snapshot validation, and
  `git diff --check` passed across all 597 capability entries.
- A fresh full `libclamav_rust` consumer check was attempted after the change,
  but Docker Desktop failed to start after disposable build-disk pressure; no
  consumer result is attributed to this slice. The prior successful consumer
  check remains recorded above. No host dependency or tool was installed.

Ink-path decoder safety refinement (2026-09-09 UTC):

- The multi-byte ink-path decoder now uses the same typed collection budget
  and fallible reservation before creating its decoded value vector. It also
  rejects truncated or over-wide varints and declared lengths that run past
  the materialized input, replacing malformed-input slice panics with explicit
  parser errors.
- The parser suite passed 20 unit tests, 4 integration tests, and 1 ignored
  doctest, including valid-zero, truncated-length, and truncated-varint
  decoder regressions. Source guards, inventory freshness, snapshot validation,
  and `git diff --check` passed. Docker remained unavailable for a fresh
  consumer-level compile, so that result is not claimed here.

Post-reader mapping-table safety refinement (2026-09-09 UTC):

- `MappingTable::from_entries` now returns the typed parser result and bounds
  its object/object-space maps and per-ID vectors under the 64 MiB collection
  budget, using fallible one-entry-at-a-time reservations before inserts and
  pushes. The object parser propagates limit and allocation failures.
- The focused parser run passed 20 unit tests, 4 integration tests, and 1
  ignored doctest. Source guards, inventory freshness, snapshot validation,
  and `git diff --check` passed. Docker remained unavailable for a fresh
  consumer-level compile; materialized late-content evidence and full parser
  quota remain open.

Legacy whole-file read safety refinement (2026-09-09 UTC):

- The vendored parser's path-based legacy APIs now validate file metadata
  against the materialization ceiling, use fallible reservation, and read in
  bounded chunks with a second limit check for files that grow after metadata
  inspection. This removes the unchecked metadata-to-`usize` cast and
  infallible `read_to_end` growth path.
- Source guards, inventory freshness, snapshot validation, and
  `git diff --check` pass. The reader-backed parser tests remain green at 20
  unit tests, 4 integration tests, and 1 ignored doctest. Docker remains
  unavailable for a fresh consumer-level compile; modern admission and full
  parser quota qualification remain open.

Derived property-vector safety refinement (2026-09-09 UTC):

- Byte-property copies now use fallible reservation. The `u16` and `u32`
  property-vector conversions reserve under the typed 64 MiB collection budget
  before pushing decoded values, so a large bounded payload cannot turn into an
  unchecked derived collection.
- The focused parser suite passed 21 unit tests, 4 integration tests, and 1
  ignored doctest, including the over-budget derived-vector regression. Source
  guards, inventory freshness, snapshot validation, and `git diff --check`
  pass. Docker remains unavailable for a fresh consumer-level compile; modern
  admission and full parser quota qualification remain open.

Modern scanner admission lift (2026-09-09 UTC):

- Removed the stale production `FMap::WHOLE_INPUT_MAX` admission refusal from
  the modern OneNote scanner. Modern sections now reach the bounded
  `FMapReader` path regardless of logical input length; whole-input APIs retain
  their own explicit cap where a borrowed slice is required.
- The existing logical-input-above-former-cap parser integration case remains
  green, and the focused parser suite passed 21 unit tests, 4 integration
  tests, and 1 ignored doctest. Source guards, inventory freshness, snapshot
  validation, and `git diff --check` pass. A fresh consumer-level compile and
  materialized late-content scanner fixture remain open; Docker is still
  unavailable.

Cache-only consumer-build follow-up (2026-09-09 UTC):

- Reused the existing host and parser Cargo caches in a disposable combined
  cache and ran the consumer check with `--locked --offline`. Cargo resolved
  the Rust graph and reached the host `openssl-sys` build script, which stopped
  because this macOS host has neither `pkg-config` nor discoverable OpenSSL
  development headers. No software was installed and no network access was
  used; a coherent consumer compile remains unverified on this host.

Derived OneStore/output collection safety refinement (2026-09-09 UTC):

- Added one bounded, fallible reservation path for parser-owned collections
  that are derived after the FSSHTTP/OneStore reader has materialized its
  source objects. TOC flattening, note-tag and ink-stroke outputs, decoded
  ink paths, object reference vectors, revision group maps, revision/object
  caches, and the OneStore object-space map now reserve against the same
  typed 64 MiB collection budget before growth. The TOC path also avoids the
  infallible iterator collections, and malformed ink dimensions/lengths now
  return parser errors instead of reaching division or slice panics.
- The focused parser run passed 21 unit tests, 4 integration tests, and 1
  ignored doctest. Source guards, inventory freshness, snapshot validation,
  and `git diff --check` remain required after the line-number refresh. The
  full consumer compile, materialized late-content fixture, and full parser
  quota qualification remain open; no host software, remote execution,
  usage reset, commit, push, or workflow action was used.

Shared reference-resolution safety refinement (2026-09-10 UTC):

- Object and object-space reference arrays now use bounded fallible output
  vectors. Reference-count aggregation detects arithmetic overflow, and the
  object-space resolver propagates missing mapping errors instead of silently
  dropping them through `flat_map`. Embedded-ink and note-tag property-set
  adapters use the same bounded path for their derived compact-ID vectors.
- An isolated offline parser-library check and its 21 unit tests passed after
  the change. The full workspace consumer build remains unavailable on this
  host because the cache-only attempt stops at missing OpenSSL development
  headers; integration snapshots, materialized late-content evidence, and
  full parser quota qualification remain open. No software, remote execution,
  usage reset, commit, push, or workflow action was used.

High-level parse-result collection safety refinement (2026-09-10 UTC):

- High-level outline, page, table, section, page-series, image, and UTF-16
  conversion paths now collect parser results through the shared bounded,
  fallible helper. This closes the remaining infallible `collect::<Result<_>>()`
  growth points in those materialized output paths without changing their
  error semantics.
- The isolated offline parser-library check and its 21 unit tests passed after
  the change. Source guards, inventory freshness, snapshot validation, and
  `git diff --check` passed across all 597 capability entries. The full
  consumer compile, materialized late-content fixture, integration snapshot
  rerun, and full parser quota qualification remain open; no software,
  remote execution, usage reset, commit, push, or workflow action was used.

Remaining parser collection safety refinement (2026-09-10 UTC):

- Replaced the final infallible parser collection sites in notebook loading,
  FSSHTTP object lookup, rich-text styles/embedded objects, table-derived
  vectors, outline indent distances, ink dimensions, number-list UTF-16
  output, and signed ink-path conversion with the shared bounded/fallible
  collection paths. Malformed non-aligned table-width and ink-dimension
  payloads now fail as parser errors rather than being silently truncated.
- The isolated offline parser-library check and its 21 unit tests passed after
  the change. The repository-wide source guards passed all 597 capability
  entries; inventory freshness, snapshot validation, and `git diff --check`
  also passed. Snapshot integration rerun, full consumer compilation,
  materialized late-content evidence, and full parser quota qualification
  remain open; no software, remote execution, usage reset, commit, push, or
  workflow action was used.

Format-width and UTF-16 fail-visible refinement (2026-09-10 UTC):

- UTF-16 conversion now rejects odd-width and invalid-surrogate payloads as
  parser errors instead of silently dropping a trailing byte or panicking on
  `unwrap()`. u16/u32 property vectors reject non-aligned payloads before
  conversion, and the conversion regressions are covered by two new unit
  tests.
- The isolated offline parser-library suite passed 23 unit tests. Source
  guards passed all 597 capability entries, and inventory freshness, snapshot
  validation, and `git diff --check` passed. Snapshot integration rerun, full
  consumer compilation, materialized late-content evidence, and full parser
  quota qualification remain open; no software, remote execution, usage
  reset, commit, push, or workflow action was used.

Checked rich-text reference refinement (2026-09-10 UTC):

- Rich-text embedded-object resolution now bounds the derived reference index
  before lookup and reports a malformed parser error when the style/object
  arrays disagree, eliminating an input-driven out-of-range panic.
- The isolated offline parser-library suite passed 23 unit tests. Source
  guards passed all 597 capability entries, and inventory freshness, snapshot
  validation, and `git diff --check` passed. Full consumer compilation,
  snapshot integration rerun, materialized late-content evidence, and full
  parser quota qualification remain open; no software, remote execution,
  usage reset, commit, push, or workflow action was used.

Reader-boundary disposable integration verification (2026-09-10 UTC):

- A disposable standalone test harness compiled the current vendored parser
  source and ran the two reader-boundary cases against the real
  `New Section 1.one` sample: three-byte short reads matched the buffer parser,
  and a 256 MiB-plus logical stream completed without materializing its
  padding. Both tests passed. The repository snapshot integration tests still
  remain unavailable because the host cache lacks `insta`.

Bounded raw property-vector copy refinement (2026-09-10 UTC):

- `one::property::simple::parse_vec` now reserves raw byte vectors through the
  shared bounded collection helper, keeping this property path under the typed
  64 MiB collection budget while preserving its existing payload-size check.
- The isolated offline parser-library suite passed 23 unit tests, and the
  disposable reader-boundary harness passed both integration cases after the
  change. Source guards passed all 597 capability entries; inventory
  freshness, snapshot validation, and `git diff --check` passed. Full consumer
  compilation remains blocked by the host's absent OpenSSL development
  headers; materialized late-content evidence, snapshot integration, and full
  parser quota qualification remain open. No software, remote execution,
  usage reset, commit, push, or workflow action was used.

Fail-closed malformed enum and path refinement (2026-09-10 UTC):

- Unknown note-tag shapes and object-group change frequencies now return typed
  malformed-data errors instead of panicking. Notebook, section, and
  section-group path metadata checks also return parser errors when required
  components are absent rather than using input-dependent `expect` calls.
- The isolated offline parser-library suite passed 25 unit tests, and the
  disposable reader-boundary harness passed both integration cases. Source
  guards passed all 597 capability entries; inventory freshness, snapshot
  validation, and `git diff --check` passed. Full consumer compilation remains
  blocked by the host's absent OpenSSL development headers; materialized
  late-content evidence, snapshot integration, and full parser quota
  qualification remain open. No software, remote execution, usage reset,
  commit, push, or workflow action was used.

Fail-closed reference-range and ink-shape refinement (2026-09-10 UTC):

- Object and object-space reference arrays now reject declared ranges that
  overflow or extend beyond their corresponding ID streams, and object
  references now report missing mapping entries instead of silently dropping
  them. Ink bounding-box vectors with a count other than four now return a
  malformed-data error instead of being silently ignored.
- Four direct malformed-range regressions were added. The isolated offline
  parser-library suite passed 29 unit tests, and the disposable
  reader-boundary harness passed both integration cases. Source guards passed
  all 597 capability entries; inventory freshness, snapshot validation, and
  `git diff --check` passed. Full consumer compilation remains blocked by the
  host's absent OpenSSL development headers; a direct offline consumer recheck
  also stops earlier because the locked `insta` crate is absent from the host
  cache. Materialized late-content evidence, snapshot integration, and full
  parser quota qualification remain open. No software, remote execution,
  usage reset, commit, push, or workflow action was used.

Checked OneNote recursion-boundary refinement (2026-09-10 UTC):

- The parser now exposes a shared checked recursion limit of 1024 levels.
  Recursive TOC traversal checks that limit, while OneStore revision traversal
  tracks visited revision IDs, rejects cycles, and reserves the visited set
  through the bounded collection helper. A typed `RecursionLimit` error is
  treated as a resource-limit failure for callers.
- The isolated offline parser-library suite passed 30 unit tests, and the
  disposable reader-boundary harness passed both integration cases. Source
  guards passed all 597 capability entries; inventory freshness, snapshot
  validation, and `git diff --check` passed. Full consumer compilation remains
  blocked by the host's absent OpenSSL development headers and missing locked
  `insta` cache entry; materialized late-content evidence, snapshot
  integration, and full parser quota qualification remain open. No software,
  remote execution, usage reset, commit, push, or workflow action was used.

Checked FSSHTTPB payload-width refinement (2026-09-10 UTC):

- Binary-item and data-element-fragment payloads now pass their format
  controlled `u64` sizes through a checked `read_vec_u64` conversion before
  materialization, and compact-u64's defensive fallback returns a typed
  malformed-data error instead of panicking.
- The isolated offline parser-library suite passed 31 unit tests, and the
  disposable reader-boundary harness passed both integration cases. Source
  guards passed all 597 capability entries; inventory freshness, snapshot
  validation, and `git diff --check` passed. Full consumer compilation remains
  blocked by the host's absent OpenSSL development headers and missing locked
  `insta` cache entry; materialized late-content evidence, snapshot
  integration, and full parser quota qualification remain open. No software,
  remote execution, usage reset, commit, push, or workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

OneNote byte-slice parser-error preservation refinement (2026-09-10 UTC):

- The public `scan_bytes` modern-parser attempt now preserves typed parser
  errors, including resource-limit failures, instead of collapsing every
  failure to generic `Parse`. A valid legacy marker still takes the legacy
  compatibility path; when no legacy record exists, the original modern
  failure is returned fail-visibly.
- The change is covered by source guards and the existing malformed modern
  fallback regression. The isolated parser-library suite remains 42/42 and
  the disposable reader-boundary harness remains 4/4. Full consumer
  compilation, materialized late-content evidence, snapshot integration, and
  full parser quota qualification remain open. No software, remote execution,
  usage reset, commit, push, or workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

Data Element Fragment completion-marker refinement (2026-09-10 UTC):

- Fragment parsing now requires the format-defined Data Element End marker
  after the opaque chunk. A focused regression rejects a truncated fragment
  with the marker removed, while the large-logical-offset chunk case remains
  valid.
- The isolated offline parser-library suite passed 42 unit tests, and the
  disposable reader-boundary harness passed all four cases. Source guards,
  inventory freshness, snapshot validation, and `git diff --check` passed after
  this source change. Full consumer compilation, materialized late-content
  evidence, snapshot integration, and full parser quota qualification remain
  open. No software, remote execution, usage reset, commit, push, or workflow
  action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

OneStore packaging identity/version compatibility refinement (2026-09-10 UTC):

- The packaging parser no longer requires `guidFile` to equal
  `guidLegacyFileVersion`. The format defines the former as the package-store
  identity and the latter as its version, so valid files may carry distinct
  GUIDs. The parser now independently validates the required fixed file-type
  and file-format GUIDs.
- A minimal packaging regression parses distinct identity/version GUIDs and
  rejects invalid fixed GUIDs. The isolated offline parser-library suite
  passed 41 unit tests, and the disposable reader-boundary harness passed all
  four cases. Source guards, inventory freshness, snapshot validation, and
  `git diff --check` remain required before handoff. Full consumer compilation,
  materialized late-content evidence, snapshot integration, and full parser
  quota qualification remain open. No software, remote execution, usage reset,
  commit, push, or workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

Bounded stream-window refinement (2026-09-10 UTC):

- Stream reads larger than the 64 KiB refill window now fail with a typed
  resource-limit error before buffer growth. This keeps the sequential reader
  boundary from regressing into a single large contiguous source window while
  preserving chunked payload materialization.
- The isolated offline parser-library suite passed 33 unit tests, and the
  disposable reader-boundary harness passed both integration cases. Source
  guards passed all 597 capability entries; inventory freshness, snapshot
  validation, and `git diff --check` passed. Full consumer compilation remains
  blocked by absent host OpenSSL development headers and the missing locked
  `insta` cache entry; materialized late-content evidence, snapshot
  integration, and full parser quota qualification remain open. No software,
  remote execution, usage reset, commit, push, or workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

OneStore property-vector width refinement (2026-09-10 UTC):

- The format's `u32` byte-vector length now passes through the checked
  `read_vec_u64` helper instead of being narrowed with `as usize` before
  materialization. A direct oversized-declaration regression covers the
  fail-visible resource-limit behavior.
- The isolated offline parser-library suite passed 32 unit tests, and the
  disposable reader-boundary harness passed both integration cases. Source
  guards passed all 597 capability entries; inventory freshness, snapshot
  validation, and `git diff --check` passed. Full consumer compilation remains
  blocked by absent host OpenSSL development headers and the missing locked
  `insta` cache entry; materialized late-content evidence, snapshot
  integration, and full parser quota qualification remain open. No software,
  remote execution, usage reset, commit, push, or workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

Reader fault-boundary disposable verification (2026-09-10 UTC):

- The standalone reader harness added deterministic mid-input truncation and
  source read-failure cases. All four reader-boundary cases passed: short
  reads match buffer parsing, logical input above the former cap completes,
  truncation is reported as an unexpected EOF, and an injected source error
  remains an I/O failure.
- This is development evidence only. Consumer compilation, materialized
  late-content evidence, snapshot integration, and full parser quota
  qualification remain open. No software, remote execution, usage reset,
  commit, push, or workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

Bounded embedded-data copy refinement (2026-09-10 UTC):

- Embedded-file, picture-container, and raw property-vector copies now use a
  shared fallible helper under the 64 MiB derived-data budget instead of plain
  `to_vec()` duplication.
- The isolated offline parser-library suite passed 34 unit tests, and the
  disposable reader-boundary harness passed all four cases. Source guards
  passed all 597 capability entries; inventory freshness, snapshot validation,
  and `git diff --check` passed. Full consumer compilation remains blocked by
  absent host OpenSSL development headers and the missing locked `insta` cache
  entry; materialized late-content evidence, snapshot integration, and full
  parser quota qualification remain open. No software, remote execution,
  usage reset, commit, push, or workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

Checked data-element-fragment chunk refinement (2026-09-10 UTC):

- `DataElementFragment` now validates the checked `offset + length` chunk
  range against the declared total data-element size and reads only the
  declared chunk length. This preserves large logical element coordinates
  without treating the total size as a contiguous allocation request, while
  malformed ranges remain fail-visible.
- The isolated offline parser-library suite passed 38 unit tests, including a
  fragment whose total logical size is above 256 MiB but whose declared chunk
  is one byte; the disposable reader-boundary harness passed all four cases.
  Source guards, inventory freshness, snapshot validation, and
  `git diff --check` passed after this source change. Full consumer
  compilation, materialized late-content evidence, snapshot integration, and
  full parser quota qualification remain open. No software, remote execution,
  usage reset, commit, push, or workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

Bounded Latin-1 property conversion refinement (2026-09-10 UTC):

- ASCII/Latin-1 property conversion now computes the resulting UTF-8 size,
  rejects output above the 64 MiB derived-data budget, and uses fallible string
  reservation before conversion. The existing byte-to-character behavior is
  preserved for the full Latin-1 range.
- The isolated offline parser-library suite passed 39 unit tests, and the
  disposable reader-boundary harness passed all four cases. Source guards,
  inventory freshness, snapshot validation, and `git diff --check` passed.
  Full consumer compilation, materialized late-content evidence, snapshot
  integration, and full parser quota qualification remain open. No software,
  remote execution, usage reset, commit, push, or workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

OneStore root and packaging-schema validation refinement (2026-09-10 UTC):

- The parser now validates the packaging cell-schema GUID against the two
  format-defined OneNote file types and rejects a mismatched schema before
  walking the store. The header-root Cell ID must match the MS-ONESTORE
  section value, and the data-root Cell ID must identify the required root
  object-space GUID; malformed roots are no longer allowed to redirect the
  parser to an arbitrary cell.
- The public byte-slice compatibility path now preserves typed parser errors
  through its legacy fallback decision, matching the scanner-facing path;
  absent a valid legacy marker, a resource or I/O failure is no longer
  collapsed to generic `Parse`.
- The standalone current-source parser harness passed 45/45 unit tests and
  4/4 reader-boundary tests. `sh tools/largefile_source_guards.sh` passed,
  inventory and snapshot checks are fresh, and `git diff --check` passed.
  The current workspace consumer check remains blocked before compilation by
  the missing offline `insta` cache entry (and the host lacks OpenSSL
  development headers); no software was installed.

These are parser correctness and fail-visible-boundary improvements only.
The full consumer build, materialized late-content fixture, snapshot
integration rerun, certified runner, and full parser quota qualification
remain open. No remote execution, Docker, usage reset, commit, push, or
GitHub workflow action was used.

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.

Byte-slice legacy-fallback and compact-width safety refinement (2026-09-10 UTC):

- The public `scan_bytes` and `from_bytes` compatibility APIs now enter the
  legacy extractor only for format/parse failures. Resource-limit, read,
  timeout, sink, and parser-panic failures remain fail-visible instead of
  being masked by a coincidental legacy marker in the input.
- The CompactU64 unit coverage now round-trips representative values through
  every supported 7-, 14-, 21-, 28-, 35-, 42-, 49-, and 64-bit encoding width;
  the former higher-width placeholder tests did not exercise their decoders.
- The standalone current-source parser harness passed 38/38 unit tests and
  4/4 reader-boundary tests. The acceptance-case suite passed. Consumer
  compilation remains blocked before compilation by the missing offline
  `insta` cache entry and absent host OpenSSL development headers; no
  software, remote execution, Docker, usage reset, commit, push, or GitHub
  workflow action was used.

These are fail-visible compatibility and parser-test refinements only. The
full consumer build, materialized late-content fixture, snapshot integration,
certified runner, and full parser quota qualification remain open.

Path/notebook sequential-reader refinement (2026-09-10 UTC):

- The public `Parser::parse_section` and `Parser::parse_notebook` APIs now
  feed opened files directly into the bounded sequential `Reader`, removing
  their former whole-file `Vec<u8>` admission and retaining the existing
  schema, filename, and section-group behavior. This closes the path-based
  library ingress gap without changing the explicit borrowed-slice API cap.
- The disposable current-source parser harness compiled the updated parser
  and passed 38/38 unit tests plus 4/4 reader-boundary tests. The full parser
  package check remains blocked before compilation by the missing offline
  `insta` cache entry; the host also lacks OpenSSL development headers. The
  full source/evidence guard passed all 597 capability entries, and inventory
  freshness, snapshot validation, and `git diff --check` passed.
- The repository parser integration suite now includes the same sparse-file
  control; its disposable no-`insta` equivalent passed independently.

This is an implementation/development-verification refinement only. A
materialized late-content fixture, full consumer build, snapshot integration,
certified runner, and full parser quota qualification remain open. No
software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.

Modern-reader current-source boundary verification (2026-09-11 UTC):

- A temporary manifest outside the repository compiled the current vendored
  OneNote parser offline with the existing dependency cache. The parser's
  library tests passed 61/61.
- A temporary integration harness passed 2/2 reader-boundary tests: a
  short-read source produced the same parse result as the buffer path, and a
  valid sample remained parseable through a logical reader length of
  `256 MiB + 1`, exercising the former admission boundary without
  materializing that size.
- The regular package test remains blocked by the uncached offline `insta`
  development dependency. This evidence does not claim consumer linkage,
  materialized late-content qualification, certified Linux x86-64 execution,
  or full parser quota qualification.

No software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.

Typed UTF-16 quota propagation refinement (2026-09-10 UTC):

- `simple::parse_string()` now preserves the vendored UTF-16 converter's
  typed collection and allocation-limit errors. Previously it converted every
  converter failure into generic malformed OneNote data, hiding a parser-owned
  quota refusal from the application boundary.
- The converter now has a bounded helper regression that confirms a collection
  limit remains resource-classified. The standalone current-source module
  harness passes 17/17; full parser-package compilation remains blocked by the
  missing offline `insta` cache entry, and consumer compilation remains blocked
  by unavailable host OpenSSL development headers.

This is an implementation/development-verification refinement only. It does
not promote the modern OneNote capability: materialized late-content evidence,
consumer integration, certified runner, and full parser quota qualification
remain open. No software, remote execution, Docker, usage reset, commit, push,
or GitHub workflow action was used.

Sequential-reader EINTR refinement (2026-09-10 UTC):

- The vendored OneNote `Reader` now retries `Interrupted` stream reads before
  growing or publishing its refill window. Genuine read errors and EOF remain
  fail-visible, while a signal interruption no longer becomes a spurious
  `CL_EREAD` at the scanner boundary.
- A focused `InterruptOnce` reader regression covers the retry path. The
  standalone current-source module harness remains 17/17; full parser-package
  compilation is still blocked by the missing offline `insta` cache entry and
  consumer compilation by unavailable host OpenSSL development headers.

This is an implementation/development-verification refinement only. The
materialized late-content case, consumer integration, certified runner, and
full parser quota qualification remain open. No software, remote execution,
Docker, usage reset, commit, push, or GitHub workflow action was used.

OneStore mapping identity refinement (2026-09-10 UTC):

- Storage-index cell and revision mappings, plus storage-manifest root
  declarations, are keyed sets in the current parser. Duplicate keys now fail
  closed with typed malformed FSSHTTPB data errors rather than replacing the
  first parsed record. Focused insertion regressions verify that the original
  value remains intact after a rejected duplicate.
- The standalone current-source parser harness passed 45/45 unit tests,
  4/4 reader-boundary tests, and the sparse path-streaming test. Full source
  guards, inventory freshness, snapshot validation, and `git diff --check`
  remain required before handoff. Consumer compilation is still blocked before
  compilation by the missing offline `insta` cache entry; the host also lacks
  OpenSSL development headers.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No software,
remote execution, Docker, usage reset, commit, push, or GitHub workflow action
was used.

Legacy reader-window arithmetic refinement (2026-09-10 UTC):

- Corrected `scan_legacy_reader()` to subtract the current scan start only once
  when computing the remaining declared input. The previous double subtraction
  could fail closed with `Error::Format` after the first 1 MiB scan window and
  prevent a later valid attachment marker from being considered.
- Added `legacy_reader_finds_marker_after_scan_window`, which places a valid
  attachment after the first full scan window and verifies complete sink output
  with no abort. Full consumer and certified parser qualification remain open.
- A disposable offline Cargo harness compiling the actual current
  `libclamav_rust/src/onenote.rs` against the vendored parser passed 17/17
  module tests, including the late-window case. Cursor advancement now uses
  checked addition so representational overflow remains fail-visible.

Nested reference-count traversal refinement (2026-09-10 UTC):

- OneStore object and object-space reference-offset accounting now traverses
  both `PropertyValues` arrays and child `PropertySet` nodes. The prior code
  ignored the latter even though PropertyID type `0x11` contains a child
  PropertySet, which can itself contain OID/OSID references.
- The traversal uses an explicit bounded worklist rather than recursive calls,
  and reserves each pending entry through the parser collection budget. This
  makes the post-parse offset walk safe for deeply nested property graphs.
- A 2048-level nested regression passed for both OID and OSID counting. The
  standalone current-source parser harness passed 52/52 unit tests; inventory
  freshness, source guards, and `git diff --check` passed as well.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No
software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.

Nested OneNote traversal depth hardening (2026-09-10 UTC):

- Outline groups and elements, table rows and cells, and content nested through
  table cells now carry the vendored parser's checked recursion depth. The
  shared bound covers the outline/table object-graph cycle rather than guarding
  only notebook TOC recursion, so cyclic or excessively nested content fails
  with the typed parser resource error before stack growth becomes unbounded.
- The source guard, inventory refresh, snapshot check, and full source gate are
  required follow-up checks. The offline Cargo check remains blocked before
  compilation by the missing `insta` cache entry; no consumer compile,
  materialized late-content qualification, software install, remote execution,
  Docker, usage reset, commit, push, or GitHub workflow action is claimed.

OneStore reference-count narrowing hardening (2026-09-10 UTC):

- Object and object-space predecessor reference counts now convert their
  decoded `u32` values to `usize` with `usize::try_from` before checked offset
  arithmetic. This removes the unchecked narrowing boundary on targets where
  `usize` is narrower and reports malformed data instead of deriving a wrapped
  offset.
- Focused regressions cover the maximum decoded count on the current target;
  the full source gate passed, including acceptance-map/schema controls and
  source guards. `cargo test --offline --manifest-path
  libclamav_rust/onenote_parser/Cargo.toml` remains blocked before compilation
  because the local cache has no `insta` package entry. No software, remote
  execution, Docker, usage reset, commit, push, or GitHub workflow action was
  used.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open.

Object-group declaration/data consistency refinement (2026-09-10 UTC):

- FSSHTTPB object-group parsing now validates that each declaration matches
  the corresponding object-data variant and that its declared object/cell
  reference counts match the parsed arrays. OneStore object-space assembly
  rejects duplicate `(object_id, partition_id)` keys instead of silently
  replacing an earlier record. These checks are fail-visible malformed-data
  handling and do not alter the advisory object-data-size field.
- The standalone current-source parser harness passed 41/41 unit tests,
  4/4 reader-boundary tests, and the sparse path-streaming test. Source
  guards, inventory freshness, snapshot validation, and `git diff --check`
  remain required before handoff. The full parser package check remains
  blocked before compilation by the missing offline `insta` cache entry; the
  host also lacks OpenSSL development headers.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No
software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.

Legacy-reader panic-boundary refinement (2026-09-10 UTC): the direct
`scan_legacy_reader` API now converts reader or attachment-sink panics into
`OneNoteParserPanic` and invokes the sink abort hook before returning. The
current-source module harness passes 20/20 tests, including a panicking seek
regression that verifies the sink is aborted; certified parser and full-size
qualification remain open.

Nested OneStore property-set recursion refinement (2026-09-10 UTC):

- Nested `PropertySet` and `PropertyValue` parsing now carries the same
  checked recursion budget used by other OneNote object traversal. The first
  deep regression showed that the former 1024-frame nominal limit could itself
  exhaust the parser test thread before the check ran, so the shared limit is
  128; valid documents retain ample nesting headroom while adversarial depth
  fails with the parser resource classification.
- The disposable current-source standalone parser harness passed 49/49 unit
  tests. Snapshot freshness, inventory freshness, `git diff --check`, and the
  full source guard passed. The repository package check remains blocked before
  compilation by the missing offline `insta` cache entry; the host also lacks
  OpenSSL development headers.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No
software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.

Packaging-reference binding refinement (2026-09-10 UTC):

- `parse_store` now resolves `package.storage_index` explicitly through the
  data-element package instead of taking the first value from a hash map. This
  makes a package containing multiple storage indexes deterministic and
  prevents the parser from using an index unrelated to the packaging header.
- A focused two-index lookup regression passed. Snapshot freshness, inventory
  freshness, `git diff --check`, and the full source guard passed after the
  change. The full parser package check remains blocked before compilation by
  the missing offline `insta` cache entry; the host also lacks OpenSSL
  development headers.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No
software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.

Notebook traversal failure-visibility refinement (2026-09-10 UTC):

- Notebook TOC traversal continues to skip a genuinely missing section path,
  preserving compatibility with stale entries left by deleted sections.
  Metadata failures other than `NotFound` now propagate, and existing TOC
  entries must resolve to a regular section file or directory; special files
  no longer fall through as an empty section group.
- The standalone current-source parser harness passed 48/48 unit tests after
  syncing the traversal change. Source guards and `git diff --check` remain
  required; consumer compilation, materialized late-content evidence,
  snapshot integration, certified runner, and full parser quota qualification
  remain open. No software, remote execution, Docker, usage reset, commit,
  push, or GitHub workflow action was used.

OneStore property-set identity refinement (2026-09-10 UTC):

- Property-set parsing now rejects duplicate property identifiers before
  inserting the second value. This prevents the property map from discarding
  an earlier value while retaining a misleading later index.
- The standalone current-source parser harness passed 43/43 unit tests,
  4/4 reader-boundary tests, and the sparse path-streaming test. The full
  parser package check remains blocked before compilation by the missing
  offline `insta` cache entry; the host also lacks OpenSSL development
  headers.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No
software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.

FSSHTTPB duplicate-identifier refinement (2026-09-10 UTC):

- All seven typed maps in `DataElementPackage` now use a fail-closed unique
  insertion helper. A repeated data-element identifier is rejected without
  replacing the first parsed value, preventing ambiguous package contents
  from reaching OneStore resolution.
- The standalone current-source parser harness passed 42/42 unit tests,
  4/4 reader-boundary tests, and the sparse path-streaming test. The full
  parser package check remains blocked before compilation by the missing
  offline `insta` cache entry; the host also lacks OpenSSL development
  headers.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No
software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.

Revision-root precedence refinement (2026-09-10 UTC):

- Revision manifests are traversed newest-to-base. Root merging now preserves a
  root already supplied by a newer revision, so a dependency revision cannot
  replace the current revision's root. Duplicate root roles in one revision
  manifest are rejected in accordance with the format's distinct-role rule.
- The standalone current-source parser harness passed 48/48 unit tests,
  4/4 reader-boundary tests, and the sparse path-streaming test. The full
  source guard, inventory freshness, snapshot validation, and `git diff --check`
  all pass in this checkout. Consumer compilation is still blocked before
  compilation by the missing offline `insta` cache entry; the host also lacks
  OpenSSL development headers.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No software,
remote execution, Docker, usage reset, commit, push, or GitHub workflow action
was used.

Revision-manifest group-reference identity refinement (2026-09-10 UTC):

- Duplicate object-group references now fail closed during FSSHTTPB parsing
  instead of being reprocessed. The focused regression preserves the first
  reference and rejects the duplicate.
- The standalone current-source parser harness passed 48/48 unit tests,
  4/4 reader-boundary tests, and the sparse path-streaming test. The full
  source guard, inventory freshness, snapshot validation, and `git diff --check`
  all pass in this checkout. Consumer compilation remains blocked before
  compilation by the missing offline `insta` cache entry; the host also lacks
  OpenSSL development headers.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No software,
remote execution, Docker, usage reset, commit, push, or GitHub workflow action
was used.

Storage-manifest mapping refinement (2026-09-10 UTC):

- OneStore now resolves the storage manifest through the storage-index
  manifest mapping instead of selecting an arbitrary first hash-map entry.
  Packages without that optional mapping remain accepted only when exactly one
  storage manifest is present; ambiguous manifests and multiple mappings fail
  closed.
- Focused regressions cover explicit mapping selection and ambiguous
  unmapped-manifest rejection. The standalone current-source parser harness
  passed 55/55 unit tests, and inventory freshness, source guards, and
  `git diff --check` passed.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No
software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.

Legacy-reader interruption refinement (2026-09-10 UTC):

- The legacy OneNote reader now retries `Interrupted` reads for its magic,
  scan-window, fixed-header, and streamed-payload reads. A resumable source
  interruption no longer becomes a permanent parser read failure.
- A focused injected-interruption regression passes in the current-source
  module harness. This is implementation/development evidence only; no fresh
  consumer binary, materialized late-content record, or certified parser
  qualification is claimed.

This refinement does not change the outer admission cap or qualification
status. No software, remote execution, Docker, usage reset, commit, push, or
GitHub workflow action was used.

Modern-reader panic-boundary refinement (2026-09-10 UTC):

- The scanner-facing `OneNote::scan_reader` entry point now contains panics
  raised by its source reader, pinned parser, or extraction callback and
  returns `OneNoteParserPanic`, matching the existing `scan_bytes` contract.
  A direct Rust consumer therefore receives a fail-closed error instead of an
  unwind; the C scanner's outer panic boundary remains a second defense.
- The standalone current-source OneNote module harness compiled offline and
  passed 19/19 tests, including an injected source-reader panic regression.

This is an implementation/development-verification refinement only. Consumer
compilation, materialized late-content evidence, snapshot integration,
certified runner, and full parser quota qualification remain open. No
software, remote execution, Docker, usage reset, commit, push, or GitHub
workflow action was used.
