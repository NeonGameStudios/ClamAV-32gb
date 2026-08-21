# Wishlist

## Current state — 2026-08-19

- The 32 GiB ingress policy, shared accounting/fail-closed controls, and
  capability manifest are implemented and source-guarded; release defaults
  remain gated on qualification.
- Large-mail phishing URL inspection now uses quota-accounted file-backed
  input, fmap HTML normalization, and 64 KiB chunked text-URL extraction; the
  former 100 KiB whole-message helper boundary is removed.
- Parser-specific limitations remain explicit unsupported results where a
  legacy ABI still requires a contiguous member or has an inherent format
  width. These are tracked in `docs/largefile-capabilities.tsv`.
- AutoIt EA05 decoded and stored members now use bounded output/temp spooling;
  EA06 script decompilation remains an explicit random-access boundary.
- HTML CSS data-URI images now decode through a 64 KiB reader into the shared
  temporary quota before nested scanning; oversized or incomplete extraction
  is fail-visible instead of using an unaccounted whole-image buffer.
- PNG large ancillary and IDAT chunks now skip their payload without a whole-
  chunk fmap mapping; only the fixed-size IHDR is borrowed.
- OLE2 summary-property metadata now reads only the bounded property table and
  bounded per-property windows instead of mapping the full attacker-declared
  property-set size; malformed/truncated windows remain fail-visible.
- PE import-hash inspection now reads fixed-size import descriptors on demand
  and validates the import-directory range without 32-bit addition wraparound.
- The PE resource-string heuristic now borrows at most the 8 KiB prefix its
  detector consumes, with subtraction-form resource range validation.
- EGG metadata extra fields now reject sizes above the individual-allocation
  ceiling explicitly, and encryption-header size subtraction is underflow-safe.
- AC exact-tail matching now has a >4 GiB offset regression that verifies the
  returned match coordinate remains 64-bit; production-signature qualification
  is still open.
- BM offset admission now rejects checked-addition wraparound before building
  its offset table; the >4 GiB match and near-`UINT64_MAX` regression paths
  are both covered.
- Byte-compare logical-signature matching now has a >4 GiB window regression;
  production-signature qualification remains open.
- Exact-size hash lookup now has a 5 GB regression across all four hash
  purposes; parser and fuzzy-image qualification remains open.
- PCRE subject admission now tests the lower `MaxContiguousSize` override;
  full-size execution and RSS qualification remains open.
- The public `cl_fmap_get_data()` range clamp now uses subtraction-form
  bounds, including a regression for a wrapping caller length.
- JavaScript normalization text-buffer growth now uses native-width checked
  capacity arithmetic instead of an `unsigned` capacity.
- JavaScript token-vector growth, token-range replacement, token appending, and
  adjacent string-literal folding now reject native-size arithmetic overflow
  before allocation or mutation; the existing concatenation regression remains
  covered by the tokenizer suite.
- RTF embedded-object probing now carries its two-byte header across 8 KiB
  reader boundaries instead of reading beyond a one-byte callback; the
  split-boundary regression is fail-visible and non-cacheable.
- Optional fuzzy-image matching now has an explicit unsupported boundary for
  images above the individual-allocation ceiling; it cannot silently skip the
  detector and report a clean scan.
- Logical bytecode dispatch now validates its context, table, one-based index,
  match arrays, and fmap before indexed pointer formation; a focused malformed
  dispatch regression is covered, while v1/v2 fixture and interpreter/JIT
  qualification remains open.
- YARA-compatible logical roots now charge one bounded fmap pass to shared
  matcher-work accounting and fail closed when that budget is exhausted; full
  production-rule and large-file qualification remains open.
- Logical signatures now validate referenced bytecode entries before indexed
  dereference and return a fail-visible parse result when metadata is stale or
  missing; full logical-expression and mixed-ABI qualification remains open.
- ISO9660 block and directory coordinates now use checked 64-bit arithmetic
  before fmap access, with overflow treated as incomplete; full ISO corpus and
  supported-build qualification remains open.
- UDF file entries now support bounded lists of recorded allocation extents,
  aggregating their logical and temporary budgets before one child scan;
  fragmented UDF corpus qualification remains open.
- HFS+ catalog node-size validation and catalog block coordinates now retain
  64-bit arithmetic through fmap admission; large-volume corpus qualification
  remains open.
- PDF Flate, RunLength, and LZW decoder output now retains native-width
  accounting and fails explicitly when the legacy 4 GiB decoder boundary is
  exceeded, instead of wrapping the decoded length or exposing a partial
  prefix.
- TIFF IFD traversal now keeps its working cursor native-width, preventing a
  malformed IFD near the 4 GiB coordinate boundary from wrapping back to the
  beginning of a larger file; the on-disk TIFF offsets remain 32-bit.
- ELF64 entrypoint and section coordinates now retain a native-width matcher
  view, while legacy bytecode metadata above 4 GiB is explicitly incomplete;
  checked program-header arithmetic and sparse-map regressions cover the
  boundary.
- The remaining milestone is a current-head Linux x86-64 build and the full
  Release/ASan/UBSan, parser-corpus, resource-budget, and production-database
  qualification on Sonic1.
- Public large-file limit setters now reject negative values without silently
  replacing the caller's resource policy with a default.
- TIFF IFD type-width multiplication and external-value range checks now use
  checked native-size arithmetic and remain fail-visible.
- GIF block, color-table, and extension range admission now uses checked
  subtraction-form bounds rather than wrapping offset-plus-length comparisons.
- HWP3 information-block bounds now use subtraction-form admission, and image
  payload headers reject short lengths before fixed-header subtraction.
- The service gate now directly exercises `SCANREPORT` through a Unix-socket
  length-prefixed protocol probe and validates its report against the fixture
  oracle; full release qualification remains open.
- ARJ header admission now validates the starting offset before subtraction-form
  range checks; parser-family and production-corpus qualification remain open.
- HTML normalized no-comment, no-tags, and JavaScript output open failures now
  remain fail-visible; parser-family and production-corpus qualification remain open.
- The mandatory service gate now directly exercises and oracle-validates all
  six structured clamd command families; full production qualification remains open.
- CAB/CHM fmap callbacks now reject unrepresentable or wrapping origin/seek
  coordinates before decoder reads; parser-family and production-corpus qualification remain open.
- PDF objects that have a confirmed header but no terminating `endobj` now
  increment invalid-object accounting and mark the scan incomplete/non-cacheable
  instead of allowing the retained truncated object to produce a clean result.
- ALZ quota crossings and decoder failures now discard partial member output
  before nested scanning; only complete extracted members are dispatched, while
  the archive remains explicitly incomplete when a limit or decoder error occurs.
- MSEXPAND now rejects decoder output that exceeds its declared decompressed size;
  add broader malformed-SZDD corpus coverage during parser qualification.
- OLE2/MSO zlib output-size prefixes are now enforced exactly; add malformed
  MSO stream corpus coverage during Office-parser qualification.
- ZWS/SWF compressed-input length fields are now enforced before LZMA setup; add
  broader malformed ZWS corpus coverage during media-parser qualification.
- HWPOLE2 declared payload length mismatches are now fail-closed; add malformed
  embedded-OLE2 corpus coverage during document-parser qualification.
- LHA/LZH member-limit and metadata callback failures now stop fail-closed;
  add malformed, oversized, callback, and multi-member corpus coverage during
  Rust-parser qualification.
- Legacy CPIO/TAR/RAR/EGG/ARJ/InstallShield metadata callback failures now
  propagate; add callback-fault and malformed archive corpus coverage.
- UNIX mbox bounce and BinHex attachment scans now propagate every non-clean
  result instead of checking only for `CL_VIRUS`; add mail-spool fault and
  malformed BinHex corpus coverage.
- PE import wildcard matches, Authenticode certificate alerts, and bytecode
  hook alert-append failures now remain fail-visible; add signature,
  callback/resource fault-injection and production PE/bytecode corpus coverage.
- AC all-matches signature alert-append failures now remain fail-visible; add
  callback/resource fault injection and production all-matches signature
  corpus coverage.
- BM all-matches signature alert-append failures now remain fail-visible; add
  callback/resource fault injection and production all-matches signature
  corpus coverage.
- Structured credit-card and SSN heuristic alert-append failures now remain
  fail-visible; add detector callback/resource fault injection and production
  structured-data corpus coverage.
- Legacy file-inspection, pre-scan, and post-scan callback alert results now
  propagate; add callback fault-injection coverage across library and front-end
  APIs.
- OLE2 VBA macro and encrypted-RAR heuristic alert results now propagate; add
  heuristic callback/resource fault injection and malformed OLE/RAR corpus
  coverage.

## Large-file validation and expansion progression

1. **Validate the current 32 GiB raw path on the local macOS host**
   - **In progress:** native macOS host-preflight capture added; local build
     tool availability and memory telemetry are being qualified.
   - Use the bare-metal 64 GB machine with one worker first.
   - Exercise sparse boundary fixtures and materialized inputs where practical.
   - Verify exact tail-marker detection, 32 GiB + 1 rejection, and the absence of
     false `OK` results.
   - Record RSS, virtual memory, I/O, page faults, scan time, temporary storage,
     build identity, and macOS-specific behavior.

2. **Compare local macOS results with Sonic1 Linux results**
   - Run equivalent raw workloads and configurations.
   - Preserve the platform differences in the evidence rather than treating the
     Linux runtime gate as proof of macOS behavior.

3. **Define a higher-memory deployment profile**
   - Establish a fixed resource budget that leaves headroom for the OS,
     signatures, parser scratch space, page cache, temporary storage, and
     concurrency.
   - Only then consider widening `MaxFileSize`, `MaxScanSize`,
     `StreamMaxLength`, and milter quotas toward a 50–100 GiB policy.
   - Add one-worker and measured-concurrency tests for the new boundary.

4. **Review parser-specific limits independently**
   - Decide which bounded paths should remain capped and which need
     windowed/streaming or higher-memory implementations.
   - Preserve fail-visible, non-clean behavior whenever a parser cannot inspect
     all required content.

5. **Complete legitimate service qualification**
   - Use the official ClamAV databases obtained through `freshclam`.
   - Test authorized real clean/infected files, materialized workloads,
     parser-expansion inputs, cold-cache behavior, daemon paths, and resource
     budgets.
