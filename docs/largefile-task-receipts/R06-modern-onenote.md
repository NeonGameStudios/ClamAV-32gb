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

State: `reader-boundary-implemented; qualification-and-quota-work-open`;
release readiness remains blocked.
