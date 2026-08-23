# Wishlist

## Current state — 2026-08-19

- The 32 GiB ingress policy, shared accounting/fail-closed controls, and
  capability manifest are implemented and source-guarded; release defaults
  remain gated on qualification.
- Direct framed clamd report probes now reuse the strict four-role service
  oracle parser instead of accepting a weaker role-only row; malformed
  detection/offset bindings fail before a protocol result can be recorded.
  Compiled report, production-CVD, and Sonic1 qualification remain open.
- Final clamd framed-report serialization now reconciles a later daemon-side
  non-success or detection status with a previously complete report, so close,
  aggregation, and transport-boundary failures cannot be published as clean.
  Compiled daemon and Sonic1 qualification remain open.
- Milter structured-report finalization now initializes the infected reply
  buffer and skips only the optional VirusAction event when its copied
  arguments cannot be allocated; the mandatory infected action remains
  fail-closed, and configured VirusAction allocation failure aborts startup.
  Compiled milter fault injection and one-request Sonic1 qualification remain
  open.
- Unknown logical-signature types now become explicit incomplete/non-cacheable
  matcher results, and bundled YARA execution preserves direct memory/resource
  exhaustion statuses instead of relabeling them as generic parse errors.
  Add focused compiled regressions and full logical/YARA qualification.
- Bytecode debug-node growth now uses checked native-size arithmetic, the
  individual-allocation ceiling, and zeroed extension state for safe malformed
  input cleanup; constant-table growth uses the same ceiling and rejects its
  terminal counter overflow. Add compiled malformed-loader and allocation
  fault-injection coverage.
- Bytecode VM stack/global pointer-registration tables now use bounded growth
  and stop execution with `CL_EMEM` when registration fails, rather than
  continuing with a zero pointer identifier. Add compiled interpreter fault
  injection and sanitizer coverage.
- Bytecode API hashset, buffer, decompressor, JavaScript-normalizer, and map
  tables now check `count + 1` and native-size multiplication before bounded
  reallocation. Add compiled API counter-overflow and allocation-fault
  coverage across interpreter/JIT variants.
- PDF, PE, ELF, Mach-O, and root-metadata bytecode hook-context allocation
  failures now mark required hook work incomplete before returning `CL_EMEM`;
  compiled hook fault injection, interpreter/JIT qualification, production
  executable corpora, and Sonic1 qualification remain open.
- AutoIt EA06 script decompilation now marks its bounded output-buffer
  allocation failure as incomplete before returning `CL_EMEM`; compiled fault
  injection, parser corpus, sanitizer, and Sonic1 qualification remain open.
- RTF parser stack growth and embedded-object state/description allocation
  failures now mark required inspection incomplete before returning `CL_EMEM`;
  compiled allocation fault injection, parser corpus, sanitizer, and Sonic1
  qualification remain open.
- OLE2 per-directory extraction-path allocation failures now mark the layer
  incomplete before returning `CL_EMEM`, matching the existing directory-create
  failure behavior; compiled Office fault injection, corpus, sanitizer, and
  Sonic1 qualification remain open.
- HWP3/HWP5 metadata object, converted-string, information-block, and record
  allocation failures now retain explicit incomplete reasons instead of relying
  on a generic parser unwind; compiled HWP fault injection, corpus, sanitizer,
  and Sonic1 qualification remain open.
- Trust-layer verdicts now commit only after evidence/metadata updates succeed;
  multi-layer trust reasons use the target layer's object ID, and allocation or
  metadata-update failures remain incomplete instead of returning directly from
  cleanup. Compiled trust-callback fault injection and Sonic1 qualification
  remain open.
- MHTML preclassification now bounds each comment value before the legacy
  in-memory XML reader, checks bounded tag searches, and rejects oversized
  metadata as an explicit resource-incomplete result; add compiled oversized-
  comment, sanitizer, and supported-build MHTML qualification.
- Mach-O 32-bit entry-point and section-alignment arithmetic now rejects
  native-coordinate wraparound; add compiled malformed-Mach-O, sanitizer, and
  parser-family qualification.
- Mach-O 32-bit and native-width section-table allocation failures now mark
  required executable inspection incomplete; add compiled allocation-fault,
  malformed-Mach-O, sanitizer, and parser-family qualification.
- Internal fmap hashing now checks `MaxScanTime` before and between bounded
  read windows, including matcher and cache callers; public no-context hash
  APIs retain legacy behavior; a focused timeout regression is registered, and
  compiled timeout qualification remains open.
- The CommuniGate MIME header-skip loop now checks `MaxScanTime` on every
  line and preserves incomplete fmap reads instead of silently continuing;
  compiled mailbox timeout qualification remains open.
- An opt-in `largefile_library_exact_32g` CTest now creates a sparse exact-
  32-GiB file, detects a marker in its final 64 bytes through
  `cl_scanfile_ex2()`, and verifies the structured report and full matcher
  accounting; the compiled Linux/Sonic1 execution remains open.
- The generated size/type/offset inventory has been refreshed from the current
  source tree and now remains reproducible through `tools/largefile_inventory.sh`;
  `largefile_source_guards.sh` now rejects any committed inventory drift, and
  the 162-entry capability manifest validates against the refreshed dispatch
  inventory.
- Sanitizer runtime qualification now rejects any native compile-database entry
  that lacks either ASan or UBSan, rather than accepting evidence because the
  flags appear in only one command; full Linux/Sonic1 sanitizer qualification
  remains open.
- Large-mail phishing URL inspection now uses quota-accounted file-backed
  input, fmap HTML normalization, and 64 KiB chunked text-URL extraction; the
  former 100 KiB whole-message helper boundary is removed.
- Parser-specific limitations remain explicit unsupported results where a
  legacy ABI still requires a contiguous member or has an inherent format
  width. These are tracked in `docs/largefile-capabilities.tsv`.
- RAR extraction now fails closed when UnRAR cannot provide the complete archive
  comment, reports bad-CRC member output, materializes no member output, or
  produces a non-regular/size-mismatched member; successful members are
  inspected through their validated descriptor while temporary bytes remain
  reserved. Backend-enabled RAR corpus and supported-build qualification remain
  open.
- The optional UnRAR backend now receives a deadline callback for member
  extraction and skip operations, preserving timeout as `CL_ETIMEOUT`; add
  compiled backend callback-injection and production RAR corpus qualification.
- 7-Zip member extraction now independently verifies the decoder-produced count
  and the materialized regular-file size against the declared member size before
  nested scanning; parser-family and supported-build qualification remain open.
- InstallShield MSI layers with unsupported control metadata now fail closed as
  non-cacheable `CL_EUNPACK`; valid-parser corpus and supported-build
  qualification remain open.
- InstallShield file records and resolved names are now released before nested
  CAB extraction, avoiding metadata fmap windows that span recursive scans;
  valid-parser corpus and supported-build qualification remain open.
- Encrypted PDF streams without a usable key or supported method now retain an
  explicit unsupported completion reason while raw matching continues; valid
  encrypted-PDF corpus and qualification remain open.
- PDF trailer-xref backing-read failures now remain explicit `CL_EREAD`
  incomplete results instead of being conflated with malformed xref structure;
  compiled trailer-fault, sanitizer, and production PDF corpus qualification
  remain open.
- PDFNG referenced-object reloads now reject objects at the individual
  contiguous-allocation ceiling instead of using an unbounded `calloc`; the
  parser marks the layer incomplete and raw matching remains authoritative.
- The PDF ARC4 helper now carries native `size_t` lengths, removing the final
  encrypted-stream truncation cast; the deliberate 1 GiB PDF decoder boundary
  and parser-family qualification remain open.
- PDF packed object references now reject object-number and generation-width
  overflow instead of aliasing another object; full malformed-reference corpus
  and parser-family qualification remain open.
- PDF raw and decoded stream output now re-checks the shared deadline after
  temporary admission and immediately before each write; add deterministic
  output-timeout injection and full PDF corpus qualification.
- PDF parser staging, extracted-object output, and normalized-content output now
  share post-admission and pre-write deadline checks; add deterministic staging
  timeout injection and full PDF corpus qualification.
- XLM BIFF data and OfficeArt drawing groups now use the shared bounded
  allocator with checked cumulative growth; allocation-ceiling and arithmetic
  failures remain explicit incomplete results.
- Shared base64 encode/decode helpers now use the individual-allocation
  ceiling, covering embedded MSXML binaries and metadata fallback paths before
  temporary staging begins.
- Bundled 7-Zip and NSIS decoder allocation callbacks now use checked shared
  allocation, including multiplication overflow checks for NSIS zlib state.
- NSIS member-table, raw-copy, compressed, and solid-stream traversal now
  honors the shared scan deadline and preserves fail-visible `CL_ETIMEOUT`;
  add compiled timeout-injection, decoder-state, sanitizer, and production
  NSIS corpus qualification.
- NSIS output staging now re-checks the shared deadline after temporary quota
  admission and before writing; add deterministic post-admission timeout
  injection and full NSIS corpus qualification.
- NSIS decoder initialization, fixed-header reads, temporary-output creation,
  and extracted-member rewind failures now mark the required layer incomplete;
  compiled decoder fault injection, malformed corpus, sanitizer, and Sonic1
  qualification remain open.
- AutoIt EA05/EA06 streamed output and EA06 script materialization now re-check
  the shared deadline after temporary admission and immediately before writes;
  add deterministic post-admission injection and complete AutoIt corpus
  qualification.
- TNEF attribute-string lengths now convert to `size_t` before the terminating
  byte, allocation, and read-coordinate arithmetic; the parser cannot wrap a
  maximum positive signed length.
- TNEF debug dumps now check the shared deadline immediately before each write
  and preserve debug-dump write failures; add deterministic debug-output fault
  injection and complete TNEF corpus qualification.
- CPIO member sizes and name padding now use native-width checked alignment;
  32-bit format fields cannot wrap archive coordinates at their padding edge.
- PE32 MEW, Upack, FSG, UPX, WWPack, and Aspack paths now reject checked
  32-bit size/coordinate additions that would wrap before allocation or
  unpacked scanning.
- PE UPX/FSG direct output and generic rebuilt-PE nested handoffs now re-check
  the shared deadline; add deterministic output-timeout injection and complete
  PE unpacker corpus qualification.
- The internal PE rebuilt-output writer now receives scan context from the
  legacy MEW, Upack, FSG, Petite, PEspin, yC, WWPack, NsPack, and Aspack paths;
  short writes and deadline expiry are fail-visible. Add compiled timeout and
  short-write injection across the full PE unpacker corpus.
- HFS+ inline compressed output above its 64 KiB decoder buffer is now an
  explicit resource-incomplete result, and supported output uses the shared
  allocation guard.
- HFS+ fork extraction now counts emitted blocks against the declared
  `totalBlocks` value instead of reading additional inline extents; add
  compiled malformed-fork and extent-overflow qualification.
- The bundled CAB/CHM adapter now bounds decoder-requested allocations with the
  shared individual-allocation ceiling.
- Bundled CAB/CHM libmspack callbacks now check the shared scan deadline during
  decoder reads, seeks, and writes and preserve timeout through archive open and
  extraction; a constructor-injected callback-timeout regression now covers both
  decoder-owned read boundaries, while production corpus qualification remains.
- Bundled CAB/CHM member temporary admission and nested-scan handoff now
  re-check the shared deadline outside decoder callbacks; add deterministic
  admission/handoff timeout injection and complete CAB/CHM corpus qualification.
- Bytecode output and shared MIME/fileblob spool paths now re-check the shared
  deadline after temporary admission and before writing; failed or short
  bytecode writes release their current reservation and block extraction of
  partial output; add post-admission timeout injection and complete
  bytecode/mail corpus qualification.
- MSPack decoder writes and bytecode output now perform a final deadline check
  after output-budget/accounting updates and immediately before materializing
  bytes; add deterministic expiry-window injection and complete CAB/CHM and
  bytecode corpus qualification.
- PCRE full-map and buffer subject matching now re-checks MaxScanTime after
  contiguous-subject admission and releases the reservation on expiry; add
  deterministic contiguous-PCRE timeout injection and complete PCRE corpus
  qualification.
- PCRE match-data allocation failures now mark the scan incomplete, and match
  or recursion-limit exhaustion returns `CL_ERESOURCE` instead of becoming a
  clean non-match; add compiled limit-exhaustion, allocation-fault, and
  production-regex qualification.
- Per-scan BM and PCRE offset tables now use the individual-allocation ceiling;
  BM setup and context-aware PCRE setup mark allocation failure before raw
  matching can be reported complete. Add compiled offset-setup fault injection
  and production-signature qualification.
- Shared in-memory blob growth now checks cumulative native-width sizes before
  page rounding, reallocation, and final length updates; requests beyond the
  1 GiB individual-allocation boundary fail explicitly instead of wrapping.
  Add compiled overflow/fault-injection coverage for legacy text/VBA blob
  callers and complete their parser-family qualification.
- The shared Rust temporary spool now re-checks `MaxScanTime` after any
  additional quota reservation and before `libc::write()`, releasing only the
  new reservation on expiry. Add compiled timeout injection for the generic
  reader, OneNote root, and Rust archive output paths.
- Generic Rust reader-to-spool errors now preserve `io::ErrorKind::TimedOut`
  as `CL_ETIMEOUT` instead of collapsing it to `CL_EREAD`; add a compiled CSS
  embedded-image timeout regression and complete Rust parser qualification.
- MSEXPAND, TAR, SIS, ISO9660, and UDF materialized-output paths now re-check
  the shared deadline at output boundaries; add deterministic post-admission
  timeout injection and complete archive/filesystem corpus qualification.
- OLE2 VBA, MSO-inflated, embedded, and encrypted stream outputs now re-check
  the shared deadline after admission and before writes; add deterministic
  post-admission injection and complete Office/VBA corpus qualification.
- VBA project, OLE10, and PowerPoint materialization now re-check the shared
  deadline after admission and immediately before writes; add deterministic
  post-admission injection and complete Office/PPT corpus qualification.
- Sanitizer runtime metadata now invokes the copied sanitizer scanner with the
  copied sanitizer dependency directory explicitly first in `LD_LIBRARY_PATH`,
  keeping provenance binding consistent with the actual workload; full
  sanitizer qualification remains a release gate.
- AutoIt EA05 decoded and stored members now use bounded output/temp spooling;
  EA06 parser entry, member traversal, compressed decoding, and script-token
  traversal now honor the shared scan deadline. EA06 non-script stored and
  compressed members now use bounded history/file-backed output; script
  decompilation remains an explicit random-access boundary.
- 7-Zip fmap input-read, output-write, and allocation failures now preserve
  their operational status instead of becoming generic parse errors; add
  compiled malformed/archive-corpus and sanitizer qualification.
- The Rust fmap adapter now rejects out-of-range `need_off()` windows before
  callback or slice formation, and its scanner-facing reader checks shared
  read/seek deadlines while preserving `CL_ETIMEOUT`; add compiled
  Rust/layout and parser-corpus qualification.
- Rust OneNote fixed-prefix truncation versus fmap read failure, and ALZ field
  read failures, now retain distinct non-clean statuses; add compiled Rust and
  parser-corpus qualification.
- OneNote legacy attachment sinks and bounded modern attachment callbacks now
  check the shared scan deadline before output admission, preserving timeout
  status even when attachment bytes are already resident; retain compiled
  timeout-injection and OneNote parser-family qualification.
- DMG trailer, XML, and streamed stripe fmap read failures now preserve
  `CL_EREAD` instead of becoming generic parse errors; add compiled DMG corpus
  and sanitizer qualification.
- HFS+ catalog-node fmap callback failures now preserve `CL_EREAD` and mark the
  layer incomplete; add compiled HFS+ node-read and corpus qualification.
- TIFF header and IFD fmap callback failures now preserve `CL_EREAD` while
  genuinely short structures remain parser errors; add compiled TIFF corpus
  qualification.
- HTML CSS data-URI images now decode through a 64 KiB reader into the shared
  temporary quota before nested scanning; oversized or incomplete extraction
  is fail-visible instead of using an unaccounted whole-image buffer.
- PNG large ancillary and IDAT chunks now skip their payload without a whole-
  chunk fmap mapping; only the fixed-size IHDR is borrowed.
- JPEG 2000 structural box admission now checks the shared deadline at parser
  entry and before each top-level box; add compiled timeout-injection and
  production image-corpus qualification.
- JPEG Photoshop 8BIM resource-header fmap callback failures now preserve
  `CL_EREAD` after an in-range boundary check; add compiled Photoshop-resource
  and production JPEG corpus qualification.
- JPEG APP13 Photoshop-marker probes now stay within the segment and preserve
  in-range fmap callback failures as `CL_EREAD`; add compiled marker-fault and
  production JPEG corpus qualification.
- JPEG Photoshop-resource and thumbnail traversal now stays inside its APP13
  segment; add compiled cross-segment boundary and thumbnail corpus coverage.
- OLE2 summary-property metadata now reads only the bounded property table and
  bounded per-property windows instead of mapping the full attacker-declared
  property-set size; malformed/truncated windows remain fail-visible.
- OLE2 encryption probing now reads a bounded native-width window at the
  encryption stream offset instead of indexing beyond the initial header view;
  add compiled encrypted-OLE2 and fault-injected read qualification.
- PE import-hash inspection now reads fixed-size import descriptors on demand
  and validates the import-directory range without 32-bit addition wraparound.
- The PE resource-string heuristic now borrows at most the 8 KiB prefix its
  detector consumes, with subtraction-form resource range validation.
- PE version-resource extraction now preserves resource-tree, entry, and
  payload read/coordinate failures as non-cacheable `CL_EREAD`/`CL_EFORMAT`
  results instead of silently omitting version metadata; compiled PE metadata
  corpus and callback-fault qualification remain open.
- The enabled PE Swizzor resource heuristic now propagates recursive resource
  read failures and malformed coordinates instead of treating them as an
  ignorable clean heuristic result; compiled Swizzor corpus and callback-fault
  qualification remain open.
- PE icon bitmap headers now use native-width map coordinates and reject
  declared header ranges that extend beyond the input; add compiled PE/icon
  corpus and sanitizer qualification.
- Embedded PE candidates above 4 GiB now undergo header admission through a
  bounded child fmap rooted at the native-width offset; add compiled embedded
  PE, production-database, and Sonic1 qualification.
- ZIP fixed local and central-directory header admission now distinguishes an
  in-range fmap backing-read failure (`CL_EREAD`) from an out-of-range or
  truncated coordinate (`CL_EPARSE`); add compiled ZIP callback-fault and
  parser-corpus qualification.
- EGG metadata extra fields now reject sizes above the individual-allocation
  ceiling explicitly, and encryption-header size subtraction is underflow-safe.
- EGG archive indexing, block metadata traversal, and streamed decoder loops now
  honor the shared scan deadline; add compiled timeout-injection and production
  EGG corpus qualification.
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
- RTF document and fmap-chunk traversal now honor the shared scan deadline;
  add compiled timeout-injection and long-document/object corpus qualification.
- Optional fuzzy-image matching now has an explicit unsupported boundary for
  images above the individual-allocation ceiling; it cannot silently skip the
  detector and report a clean scan.
- BMP and JPEG 2000 now have bounded structural header/box admission while
  other generic graphics without a parser remain raw-matchable but explicit
  incomplete results when image parsing is enabled; add full image parsers and
  production-corpus qualification before enabling deeper inspection.
- Logical bytecode dispatch now validates its context, table, one-based index,
  match arrays, and fmap before indexed pointer formation; a focused malformed
  dispatch regression is covered, while v1/v2 fixture and interpreter/JIT
  qualification remains open.
- Bytecode loader, interpreter, and VM buffers now use the shared
  individual-allocation ceiling, and hex-data decoding rejects checked-offset
  overflow before allocation or input traversal; ABI fixture and runtime
  qualification remain open.
- YARA-compatible logical roots now charge one bounded fmap pass to shared
  matcher-work accounting and fail closed when that budget is exhausted; full
  production-rule and large-file qualification remains open.
- Logical signatures now validate referenced bytecode entries before indexed
  dereference and return a fail-visible parse result when metadata is stale or
  missing; full logical-expression and mixed-ABI qualification remains open.
- ISO9660 block and directory coordinates now use checked 64-bit arithmetic
  before fmap access, with overflow treated as incomplete; full ISO corpus and
  supported-build qualification remains open.
- ISO9660 primary root-directory coordinates now receive the same checked
  extent-plus-attribute arithmetic as child records; add compiled root-overflow,
  sanitizer, and production ISO corpus qualification.
- ISO9660 directory blocks are now copied into a bounded 2 KiB buffer and
  released before recursive directory or file scans, preventing a directory
  fmap window from spanning nested work; full ISO corpus qualification remains
  open.
- UDF file entries now support bounded lists of recorded allocation extents,
  aggregating their logical and temporary budgets before one child scan;
  fragmented UDF corpus qualification remains open.
- UDF extraction now honors each file entry's declared logical `informationLength`,
  requires exact aggregate allocation accounting, and fails closed when the
  allocation list does not provide exactly the declared bytes; transformed
  `ext_ad` content remains explicitly unsupported; add compiled transformed-
  extent, read-fault, sanitizer, and production UDF corpus qualification.
- UDF generic volume descriptor identifiers now use equality checks and reject
  unsupported identifiers as incomplete; add valid/invalid descriptor corpus
  coverage and supported-build qualification.
- Align the active release, sanitizer, service, and macOS qualification gates
  on the roadmap's four-hour `MaxScanTime` deadline; preserve historical run
  records with their original configured deadlines.
- Keep the clamd INSTREAM quota boundary and its clients on one policy helper;
  zero `StreamMaxLength` now selects the bounded 32-GiB ceiling at both ends,
  with the daemon-side unit regression covered locally.
- Keep clamd INSTREAM buffered-chunk arithmetic subtraction-based and
  wrap-safe for malformed maximum-size protocol chunks; the helper and
  boundary regression are now source-guarded.
- HFS+ catalog node-size validation and catalog block coordinates now retain
  64-bit arithmetic through fmap admission; large-volume corpus qualification
  remains open.
- HFS+ resource-compression block-table counts now use checked native-width
  allocation/read sizing and fail with `CL_ERESOURCE` before a wrapped table
  can be allocated or read; compressed-resource corpus qualification remains
  open.
- HFS+ catalog, attribute-tree, fork, resource-table, and compressed-resource
  traversal now honor the shared scan deadline; add compiled timeout-injection
  and large-volume corpus qualification.
- HFS+ ordinary fork, inline compressed, and compressed-resource output paths
  now re-check the shared deadline after admission and before writes; add
  deterministic post-admission injection and complete HFS+ corpus qualification.
- CAB and CHM temporary-output creation failures now mark the layer incomplete
  before returning an allocation error, so a required member cannot be skipped
  after quota admission and still appear clean; compiled CAB/CHM corpus and
  Sonic1 qualification remain open.
- BinHex data/resource temporary-output creation failures now mark the layer
  incomplete before cleanup or return, with a focused invalid-directory
  regression; compiled BinHex corpus and Sonic1 qualification remain open.
- HWP/HWPML, HFS+, and OLE2 materialization helpers now mark direct temporary
  output allocation/open failures incomplete before returning; source gates
  cover the new reasons, while compiled document/filesystem fault injection,
  production corpora, and Sonic1 qualification remain open.
- RTF, SWF, InstallShield, and AutoIt temporary-directory/output setup and
  open failures now mark required parser work incomplete before returning;
  compiled fault injection, production corpora, and Sonic1 qualification
  remain open.
- HFS+ temporary-directory setup and InstallShield MSI/CAB staging allocation
  failures now mark required parser work incomplete before returning; compiled
  allocation-fault injection, production corpora, and Sonic1 qualification
  remain open.
- HFS+ volume-header and catalog-node working-buffer allocation failures now
  mark the required layer incomplete before returning `CL_EMEM`; add compiled
  allocation fault-injection and full HFS+ corpus qualification.
- HTML RFC2397, XDP, SIS, MSXML, OLE2, TAR, script-encoded HTML, PDF, TNEF,
  UUEncode, and mail temporary staging allocation/creation failures now mark
  required parser work incomplete before returning; compiled fault injection,
  production corpora, and Sonic1 qualification remain open.
- RAR extracted-member output-path allocation and bytecode output-file/
  normalized-JavaScript-directory setup failures now mark required work
  incomplete before returning; compiled backend/runtime fault injection,
  production corpora, and Sonic1 qualification remain open.
- UDF extracted-file and VBA project temporary-output creation failures now
  mark required work incomplete before returning; compiled allocation-fault
  injection, production Office/UDF corpora, and Sonic1 qualification remain
  open.
- PDF Flate, RunLength, and LZW decoder output now retains native-width
  accounting and fails explicitly when the legacy 4 GiB decoder boundary is
  exceeded, instead of wrapping the decoded length or exposing a partial
  prefix.
- PDF legacy filter input and Flate/RunLength/LZW growth now reject the shared
  1 GiB individual-allocation ceiling with explicit `CL_ERESOURCE`, and ASCII85
  expansion checks its prospective contiguous output before allocation; the
  legacy ASCII85, RunLength, Flate, ASCIIHex, LZW, and filter-chain traversal
  now honors the shared scan deadline; fully streaming PDF-filter conversion
  and large-corpus qualification remain open.
- Legacy PDF ASCII85, RunLength, Flate, ASCIIHex, and LZW output allocation,
  growth, final-resize, and decoder-initialization failures now mark required
  inspection incomplete before returning `CL_EMEM`; compiled fault injection,
  sanitizer, production PDF corpus, and Sonic1 qualification remain open.
- Unfiltered PDF streams now bypass the contiguous legacy decoder token and copy
  to extracted output in 64 KiB chunks with caller-owned `MaxTemporarySize`
  reservations; decoded filtered output is charged to the same shared budget,
  while filtered decoder input/growth remains explicitly bounded at the 1 GiB
  individual-allocation ceiling and full streaming filter conversion remains
  open.
- TIFF IFD traversal now keeps its working cursor native-width, preventing a
  malformed IFD near the 4 GiB coordinate boundary from wrapping back to the
  beginning of a larger file; the on-disk TIFF offsets remain 32-bit.
- JPEG required header, marker, segment-size, and Photoshop-resource reads now
  distinguish in-range fmap callback failures (`CL_EREAD`) from genuinely short
  structures; add callback-fault, sanitizer, and production JPEG corpus
  qualification.
- JPEG parser entry and Photoshop 8BIM resource traversal now honor the shared
  deadline in addition to the segment walk; add compiled timeout-injection and
  long-resource JPEG corpus qualification.
- GIF required signature, version, descriptor, block-label, extension, and
  image-data reads now distinguish in-range fmap callback failures (`CL_EREAD`)
  from genuinely short structures; add callback-fault, sanitizer, and
  production GIF corpus qualification.
- ISO9660 volume, secondary-descriptor, directory-block, and file-data reads
  now distinguish in-range fmap callback failures (`CL_EREAD`) from genuinely
  out-of-map/truncated ranges; add callback-fault, sanitizer, and production
  ISO9660 corpus qualification.
- ISO9660 volume, directory-entry, and file-extent traversal now honors the
  shared scan deadline; add compiled timeout-injection and large-directory
  corpus qualification.
- UDF generic and required volume-descriptor reads now distinguish in-range
  fmap callback failures (`CL_EREAD`) from short or out-of-map descriptors
  (`CL_EPARSE`); add callback-fault, sanitizer, and production UDF corpus
  qualification.
- SWF fixed metadata and compressed-input reads now distinguish in-range fmap
  callback failures (`CL_EREAD`) from short input/format errors; add callback-
  fault, sanitizer, and production SWF corpus qualification.
- SWF uncompressed tag traversal and CWS/ZWS decoder loops now honor the
  shared deadline with temporary-output cleanup; add compiled timeout-injection
  and long compressed/uncompressed SWF corpus qualification.
- SWF temporary-output writes now re-check the shared deadline after quota
  admission and immediately before each header or decoded-chunk write, release
  the current reservation on timeout or short write, and preserve the
  operational result; add deterministic output-timeout injection and full SWF
  corpus qualification.
- TNEF attribute, attachment-data, and debug-dump traversal now honor the
  shared scan deadline and preserve timeout as an incomplete, non-cacheable
  result; add compiled timeout-injection and long-attribute/attachment corpus
  qualification.
- TNEF attachment-title/output-blob allocation and attachment-data
  materialization failures now mark required attachment inspection incomplete;
  add compiled allocation fault injection, malformed attachment corpus,
  sanitizer, and Sonic1 qualification.
- Standalone and mail-embedded UUEncode decoding now checks the shared deadline
  before each input line and preserves timeout through mbox result handling;
  add compiled timeout-injection and long-attachment corpus qualification.
- UUEncode message-state/output-blob allocation and decoded attachment
  materialization failures now mark the required attachment incomplete, and
  unterminated/invalid attachments are explicit non-clean results; compiled
  allocation fault injection, corpus, sanitizer, and Sonic1 qualification
  remain open.
- ARJ compressed bit-window refills and stored-member reads now preserve
  in-range fmap callback failures as `CL_EREAD` instead of `CL_EFORMAT`; add
  callback-fault, sanitizer, and production ARJ corpus qualification.
- ARJ extracted members now must materialize as regular files whose size exactly
  matches the declared original size before nested scanning; add malformed
  output-size and filesystem-fault corpus qualification.
- ARJ header traversal, stored-member copying, and both decompression loops now
  honor the shared scan deadline and preserve fail-visible `CL_ETIMEOUT`; add
  compiled timeout-injection, decoder-state, sanitizer, and production ARJ
  corpus qualification.
- ARJ stored and decompressor output now re-checks the shared deadline
  immediately before writes, and ARJ temporary admission and nested handoff are
  explicit; add deterministic output-timeout injection and full ARJ corpus
  qualification.
- ARJ compressed and stored decoder-buffer allocation failures now mark the
  archive layer incomplete before returning `CL_EMEM`; add compiled decoder
  allocation fault-injection and full ARJ corpus qualification.
- CPIO fixed-header and member-name reads now distinguish in-range fmap
  callback failures (`CL_EREAD`) from impossible/truncated coordinates
  (`CL_EPARSE`) across all four legacy variants; add compiled callback-fault,
  sanitizer, and production CPIO corpus qualification.
- CPIO old, ODC, newc, and CRC member walks now check the shared deadline
  before each header read; add compiled timeout-injection and long-archive
  qualification.
- GZip, BZip2, and XZ streaming input now distinguish in-range fmap callback
  failures (`CL_EREAD`) from genuine premature EOF/decode failures; add
  compiled callback-fault, sanitizer, and production compressed-stream corpus
  qualification.
- GZip (including its legacy fallback), BZip2, and XZ now re-check the shared
  `MaxScanTime` deadline during decompression instead of allowing CPU-heavy
  streams with little output to bypass the scan deadline; add compiled timeout,
  sanitizer, and production compressed-stream qualification.
- The shared compressed-output reservation now checks the deadline before and
  after quota admission, and the GZip, BZip2, XZ, script-normalization, and
  CryptFF spool writers re-check it immediately before writing; add compiled
  output-timeout injection across those decoder families.
- Shared child-descriptor and force-to-disk nested-fmap paths now re-check the
  deadline after temporary admission, before materialized writes, and before
  nested handoff; EGG member output, per-chunk RAR staging, legacy VBA project
  output, and UTF-16 HTML output receive the same boundary checks. Add compiled
  timeout injection and parser-family corpus qualification.
- JavaScript normalization’s quota-backed flush now re-checks the shared
  deadline after each reservation and immediately before writing; add compiled
  HTML/bytecode normalization timeout injection and corpus qualification.
- BZip2 extraction now consumes concatenated streams and rejects decoder
  no-progress states while input remains; add compiled malformed-stream,
  sanitizer, and production BZip2 corpus qualification.
- Script normalization now carries the text normalizer's specific fmap read
  status, preserving in-range callback failures as `CL_EREAD` instead of
  generic parse errors; add compiled scanner-level callback-fault and
  production script corpus qualification.
- Script normalization now writes the complete generated view to a
  quota-accounted temporary fmap and scans it through the native-width matcher
  path, removing the obsolete 4-GiB buffer-ABI boundary; compiled timeout,
  cleanup, corpus, sanitizer, and Sonic1 qualification remain release gates.
- The mandatory service gate now binds `clamd`, `clamdscan`, `clamscan`, and
  milter workloads to the audited source/build manifest, compile graph,
  executable hashes, and resolved runtime dependency hashes; retain a real
  supported-Linux service run as the release gate.
- The milter now fails closed if its local temporary-file descriptor cannot be
  rewound before FILDES submission, preventing an indeterminate descriptor
  position from reaching clamd; compiled exact-edge milter qualification
  remains open.
- ELF64 entrypoint and section coordinates now retain a native-width matcher
  view, while legacy bytecode metadata above 4 GiB is explicitly incomplete;
  checked program-header arithmetic and sparse-map regressions cover the
  boundary.
- ELF required metadata reads now distinguish in-range fmap callback failures
  (`CL_EREAD`) from genuinely short headers (`CL_EPARSE`); add direct scanner,
  sanitizer, and production ELF corpus qualification.
- ELF executable inspection now checks the shared deadline before header
  admission, between metadata phases, and at each program/section-header
  traversal step; add compiled timeout-injection and large-metadata corpus
  qualification.
- Mach-O required metadata and universal-binary reads now distinguish in-range
  fmap callback failures (`CL_EREAD`) from genuinely short input (`CL_EPARSE`);
  add direct scanner, universal-binary, sanitizer, and production Mach-O corpus
  qualification.
- Mach-O load-command, section, universal-binary architecture, and nested
  member traversal now honor the shared deadline with cleanup and explicit
  timeout results; add compiled timeout-injection and large-metadata corpus
  qualification.
- UDF descriptor, empty-descriptor, file-index, allocation, and extracted-file
  traversal now honor the shared deadline with cleanup and explicit timeout
  propagation; add compiled timeout-injection and fragmented-volume corpus
  qualification.
- The remaining milestone is a current-head Linux x86-64 build and the full
  Release/ASan/UBSan, parser-corpus, resource-budget, and production-database
  qualification on Sonic1.
- Public large-file limit setters now reject negative values without silently
  replacing the caller's resource policy with a default.
- False-positive hash preparation and fmap read failures now preserve their
  underlying error through alert append, mark the scan incomplete, and prevent
  a required hash check from being treated as an ordinary detection path.
- False-positive trust-update errors and missing metadata trust reasons now
  remain fail-visible instead of producing a trusted verdict after a failed
  metadata operation.
- Modern and legacy callback trust-update failures now remain fail-visible and
  cannot be converted into `CL_VERIFIED` before evidence/metadata cleanup
  succeeds.
- On-access file preflight failures now remain visible to extra-scan callers;
  fanotify prevention still denies incomplete permission events.
- On-access structured-report parser, limit, and resource statuses now remain
  visible through the client return value instead of becoming clean or generic
  connection failures; add compiled fanotify and monitoring-mode integration
  coverage.
- The shared framed-report consumers now validate and preserve the report's
  numeric incomplete status through on-access and milter handling; detections
  remain authoritative when a multi-frame response also contains an incomplete
  result, while contradictory clean/error combinations fail closed. Add
  compiled multi-frame timeout/resource and exact milter-action qualification.
- Structured report producers now normalize sticky incomplete clean/trusted
  statuses to a specific non-clean `CL_EUNPACK`, `CL_EPARSE`, `CL_ERESOURCE`,
  `CL_BREAK`, or generic `CL_ERROR` result before serialization; unsupported
  daemon skips use `CL_EUNPACK`. Add compiled daemon skip and report-wire
  qualification.
- On-access requests that cannot be sent, including a file disappearing before
  open, now become explicit non-clean `CL_EOPEN`/write failures instead of a
  zero-length soft skip that could be labeled clean; compiled fanotify and
  monitoring-mode coverage remains open.
- On-access regular-file streams now reject post-stat growth in both ordinary
  and quarantine modes, preventing a clean prefix from being reported; add
  compiled file-mutation and monitoring-mode coverage.
- ZIP local/central filename, local-header discovery, EOCD, ZIP64 metadata, and
  data-descriptor read failures now remain `CL_EREAD` and non-cacheable instead
  of becoming clean members or triggering incomplete local-header fallback; add
  compiled archive-corpus coverage.
- ZIP local and central fixed-header views are now copied or reduced to scalar
  metadata before recursive decompression, so archive fmap locks do not span
  child scans; compiled ZIP corpus and supported-build qualification remain
  open.
- ZIP bounded member writers and ZipCrypto staging now re-check the shared
  deadline after temporary admission and immediately before materialized writes;
  add deterministic post-admission injection and complete ZIP corpus
  qualification.
- Windows memory scans no longer turn a failed descriptor scan into `OK`; the
  native Windows memory ingress remains outside the certified first-release
  platform boundary.
- Raw matcher hash-cache failures now remain incomplete and non-cacheable
  instead of being discarded after hash computation.
- TIFF IFD type-width multiplication and external-value range checks now use
  checked native-size arithmetic and remain fail-visible.
- TIFF IFD traversal now checks the shared scan deadline at each directory;
  add compiled timeout-injection and large-chain corpus qualification.
- GIF block, color-table, and extension range admission now uses checked
  subtraction-form bounds rather than wrapping offset-plus-length comparisons.
- GIF block, extension, and image-data traversal plus PNG chunk traversal now
  honor the shared scan deadline; add compiled timeout-injection and large-chain
  media corpus qualification.
- HWP3 information-block bounds now use subtraction-form admission, and image
  payload headers reject short lengths before fixed-header subtraction.
- The service gate now directly exercises `SCANREPORT` through a Unix-socket
  length-prefixed protocol probe and validates its report against the fixture
  oracle; full release qualification remains open.
- clamd large-file startup admission now compares against fixed historical
  100 MiB/400 MiB bypass thresholds, so enabling the 32/64 GiB defaults cannot
  skip the Linux x86-64 memory and temporary-space checks.
- Parallel MULTISCAN file workers now preserve unexpected scan failures and
  honor `ExitOnOOM` instead of reducing a fatal worker result to success.
- ARJ header admission now validates the starting offset before subtraction-form
  range checks; parser-family and production-corpus qualification remain open.
- HTML normalized no-comment, no-tags, and JavaScript output open failures now
  remain fail-visible; parser-family and production-corpus qualification remain open.
- HTML normalized no-comment, no-tags, JavaScript, and RFC2397 output now uses
  caller-owned chunk reservations against MaxTemporarySize through nested scans
  and cleanup; compiled quota-fault, sanitizer, and production HTML/MHTML corpus
  qualification remain open.
- HTML normalized and script-encoded output now re-checks the shared deadline
  before quota admission, after reservation, and immediately before writing;
  add deterministic output-timeout injection and full HTML/MHTML corpus
  qualification.
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
- ALZ stored, deflate, and BZip2 members now require the decoder-produced output
  count to equal the declared uncompressed member size before nested scanning;
  mismatches discard the member output and remain fail-visible. Add compiled
  Rust and malformed-archive corpus qualification.
- MSEXPAND now rejects decoder output that exceeds its declared decompressed size;
  add broader malformed-SZDD corpus coverage during parser qualification.
- MSEXPAND bitstream and back-reference traversal now honor the shared scan
  deadline; add compiled timeout-injection and long-output decoder corpus
  qualification.
- Streaming MSXML/XDP input, character, JSON, base64, and temporary-output
  traversal now honor the shared scan deadline; add compiled timeout-injection
  and large-embedded-payload corpus qualification.
- Legacy MSXML callback and base64 materialization now re-check the shared
  deadline after temporary admission, before writing, and before nested
  handoff; streaming MSXML output and nested handoffs receive the same
  post-admission boundary. Add deterministic timeout injection and compiled
  XML/OOXML/HWPML corpus qualification.
- Optional XDP `keeptmp` staging now honors the shared deadline and preserves
  read/write/resource failures; add compiled staging-failure qualification.
- XDP temporary-dump writes now re-check the shared deadline after quota
  admission; add deterministic post-admission timeout injection.
- HWP3 document-info, paragraph, font-table, and information-block traversal
  now honor the shared scan deadline; add compiled timeout-injection and large
  legacy-document corpus qualification.
- HWP raw-deflate and HWPML Base64 output now re-check the shared deadline
  before quota admission and before writing; add deterministic output-timeout
  injection and full HWP/HWPML corpus qualification.
- OLE2 property-tree, VBA/XLM, MSO-inflation, embedded-stream, and
  encrypted-stream traversal now honor the shared scan deadline; add compiled
  timeout-injection and large Office/VBA corpus qualification.
- XLM macro and extracted-image temporary-output boundaries now re-check the
  shared deadline before quota admission and before writing; retain deterministic
  timeout injection and complete Office/XLM corpus qualification.
- InstallShield MSI, embedded-file, and CAB output paths now re-check the shared
  deadline before admission and before writes; add deterministic timeout
  injection and complete InstallShield corpus qualification.
- Decompressed VBA modules now enter the 64-bit fmap matcher path, preserving
  full-map PCRE and logical/YARA evaluation instead of rejecting lengths above
  4 GiB at the legacy buffer-matcher ABI; the decompressor's contiguous
  individual-allocation ceiling remains an explicit unsupported boundary.
- 7-Zip member extraction now checks the shared deadline before and after each
  bounded streaming-output callback write and in fmap input read/seek
  callbacks, including long solid-folder decoder work, preserving
  `CL_ETIMEOUT` through decoder read errors; add compiled solid-archive
  timeout-injection and production corpus qualification.
- The bounded 7-Zip legacy whole-buffer fallback now routes its output through
  the same deadline-aware callback, so a fallback write cannot bypass timeout
  admission; retain legacy-fallback and solid-folder corpus qualification.
- OLE2/MSO zlib output-size prefixes are now enforced exactly; add malformed
  MSO stream corpus coverage during Office-parser qualification.
- ZWS/SWF compressed-input length fields are now enforced before LZMA setup; add
  broader malformed ZWS corpus coverage during media-parser qualification.
- HWPOLE2 declared payload length mismatches are now fail-closed; add malformed
  embedded-OLE2 corpus coverage during document-parser qualification.
- LHA/LZH member-limit and metadata callback failures now stop fail-closed;
  add malformed, oversized, callback, and multi-member corpus coverage during
  Rust-parser qualification.
- LHA/LZH decoder output now checks the shared scan deadline between bounded
  output chunks, covering decoders that emit data without another fmap read;
  retain compiled timeout-injection and parser-family qualification.
- Legacy CPIO/TAR/RAR/EGG/ARJ/InstallShield metadata callback failures now
  propagate; add callback-fault and malformed archive corpus coverage.
- TAR parser entry and member traversal now honor the shared scan deadline and
  preserve fail-visible `CL_ETIMEOUT`; add compiled timeout-injection,
  malformed archive, sanitizer, and production TAR corpus qualification.
- All CPIO legacy/newc header, name, padding, and member-data cursor advances
  now use checked native-width arithmetic; an overflow remains an explicit
  incomplete parse instead of wrapping to an attacker-selected earlier range.
  Add compiled coordinate-boundary and malformed CPIO corpus coverage.
- UNIX mbox bounce and BinHex attachment scans now propagate every non-clean
  result instead of checking only for `CL_VIRUS`; add mail-spool fault and
  malformed BinHex corpus coverage.
- BinHex byte decoding and run-length expansion now honor the shared scan
  deadline and preserve cleanup/non-cacheable timeout results; add compiled
  timeout-injection and long-encoded-attachment corpus qualification.
- BinHex data/resource fork output now re-checks the shared deadline after
  admission, before writes, and before nested handoff; add deterministic
  post-admission injection and complete BinHex corpus qualification.
- RTF embedded-object admission and materialized writes now re-check the shared
  deadline; add deterministic post-admission injection and complete RTF object
  corpus qualification.
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
- Unexpected statuses from deprecated pre-cache, file-inspection, pre-scan, and
  post-scan callbacks now remain fail-visible and non-cacheable instead of being
  normalized to a clean result; the public scan-map regression covers all four
  callback entry points.
- Modern pre-hash, pre-scan, and post-scan callbacks now preserve unexpected
  `CL_E*` returns as incomplete, non-cacheable results instead of continuing as
  clean; the public scan-map regression covers all three locations.
- OLE2 VBA macro and encrypted-RAR heuristic alert results now propagate; add
  heuristic callback/resource fault injection and malformed OLE/RAR corpus
  coverage.
- ELF broken-executable heuristic alert results now propagate callback,
  trusted, and operational statuses instead of preserving only `CL_VIRUS`; add
  ELF heuristic fault-injection and malformed-corpus coverage.
- ELF active program/section-header working-buffer allocation failures now
  mark required inspection incomplete before returning `CL_EMEM`; add compiled
  allocation fault-injection and executable-corpus qualification.
- Mach-O and universal-binary broken-executable heuristic alert results now
  propagate callback, trusted, and operational statuses; add Mach-O heuristic
  fault-injection and malformed-corpus coverage.
- Encrypted EGG heuristic alert results now propagate callback, trusted, and
  operational statuses; add EGG heuristic fault-injection and malformed-corpus
  coverage.
- Malformed-PE broken-executable heuristic alert results now propagate
  callback, trusted, and operational statuses; add PE heuristic fault-injection
  and malformed-corpus coverage.
- Extended-MBR partition-intersection alert results now stop traversal on every
  non-success status; add callback/resource fault-injection and malformed
  partition-image coverage.
- APM, GPT, and MBR parser entry points and partition-table/intersection walks
  now honor the shared scan deadline and preserve timeout as incomplete;
  add compiled partition-image corpus and timeout qualification.
- APM block coordinates and old-school partition scaling now use checked
  native-size conversion before fmap reads or nested scans; add compiled
  narrow-width/large-coordinate partition-image qualification.
- GPT sector-size auto-detection now uses bounded `fmap_readn()` probes and
  preserves an in-range backing-read failure as `CL_EREAD`; add compiled
  auto-detection fault-injection and partition-image qualification.
- APM, MBR, and GPT partition-intersection list allocation failures now mark
  the required walk incomplete before returning `CL_EMEM`; add allocation
  fault-injection and compiled partition-image qualification.
- Legacy clamd FILDES and INSTREAM command workers now preserve parser, limit,
  read, and format failures instead of normalizing them to successful command
  completion; add daemon IDSESSION and malformed/limit integration coverage.
- Structured clamd fallback reports now classify parser/format failures as
  malformed and dispatch, transport, and allocation failures as resource
  failures instead of labeling every non-detection error unsupported; the
  shared classifier unit test covers each fallback class, with compiled
  protocol execution still required.
- Structured clamd report serialization failures now emit a schema-shaped,
  explicitly incomplete resource report rather than a compact clean fallback;
  clients require a numeric verdict and successful status for `COMPLETE`, with
  the historical string-valued clean fallback rejected.
- The public structured report now classifies unsupported decoder and bytecode
  statuses consistently with clamd fallback reports; the library unit test
  covers all three statuses, with compiled execution still required.
- clamdscan stdin legacy results now keep `dsresult()`'s print status separate
  from its infection count and propagate daemon `ERROR` replies into the exit
  status; the service gate now schedules a pipe-backed stdin/INSTREAM case,
  with compiled execution still open.
- Buffer and fmap matcher callers now preserve every matcher error below
  `CL_TYPENO` instead of allowing a later matcher pass to hide resource,
  timeout, callback, or read failures; add matcher fault-injection and
  production signature-corpus coverage.
- PDF extracted-object bytecode hooks now fail closed when their fmap cannot
  be created and preserve post-dump hook errors; add bytecode fault injection
  and production PDF/bytecode corpus coverage.
- PE `BC_PE_ALL` and `BC_PE_UNPACKER` callers now preserve applicable hook
  setup, execution, and unpacked-layer failures instead of returning clean;
  add PE bytecode fault-injection and production corpus coverage.
- PE header and enabled import-table passes now stop on every non-success
  result instead of continuing with partial metadata; add PE read/memory fault
  injection and malformed production corpus coverage.
- Multipart/related mail roots now stay file-backed while preserving the
  HTML-first/text-fallback root selection and MHTML preclassification path;
  run the 65 MiB regression, sanitizer/RSS checks, and full MHTML corpus on
  supported Linux.
- OLE2 summary metadata failures now remain attached to the parser result
  instead of being discarded while embedded streams continue scanning; add
  metadata fault-injection coverage during Office-parser qualification.
- OLE2 AES password-derivation buffers now use the shared individual-allocation
  ceiling instead of plain `calloc()` for attacker-controlled salt lengths;
  encrypted Office corpus and supported-build qualification remain open.
- Sequential OOXML ZIP, script, and mail parser passes now preserve a specific
  earlier parser error while allowing later detection results; add compiled
  mixed-parser fault-injection coverage during parser qualification.
- TAR initial-header fmap read failures now remain fail-visible instead of
  being mistaken for exact EOF; add compiled TAR fault-injection and corpus
  coverage during parser qualification.
- ClamAV YARA rules now observe the active scan deadline during a single
  long-running logical rule; add compiled timeout, sanitizer, and production
  YARA corpus coverage.
- Bytecode VM watchdogs now clamp to a shorter active `MaxScanTime`, and
  logical/hook paths re-check the deadline after successful execution; add
  compiled interpreter/JIT timeout and production bytecode coverage.
- Applicable bytecode entries now fail closed when the runtime is disabled:
  `CL_EBYTECODE`, incomplete/non-cacheable; retain interpreter/LLVM and
  independently compiled fixture qualification as release gates.
- Mixed v1/v2 hook tables now skip only the incompatible legacy entry on
  >4-GiB layers so a later v2 hook can still run; retain mixed-ABI execution,
  detection, and incomplete-result qualification as a release gate.
- `clambc` now strictly parses numeric function/parameter arguments, fails
  closed for malformed or overflowing setup and runtime failures, and returns
  a nonzero process status so an independently compiled ABI-v2 fixture cannot
  be reported as a successful run after a tool/runtime error; retain
  interpreter/JIT qualification.
- The shared individual-allocation `calloc` guard now uses division-form
  admission before multiplication, so narrower `size_t` builds cannot wrap
  the requested element count into an apparently safe allocation size; the
  checked product is also reused for allocation-failure diagnostics.
- Legacy MSXML base64 embedded-data failures now fail closed as incomplete and
  non-cacheable instead of skipping the element; add compiled XML/OOXML corpus
  and sanitizer qualification.
- Confirmed XAR `<data>`/`<ea>` entries with invalid metadata no longer end the
  TOC walk as clean; add compiled malformed-XAR and production corpus coverage.
- XAR TOC XML/decoder, subdocument, gzip/LZMA member, and raw-member walks now
  honor the shared scan deadline with decoder and temporary-file cleanup; add
  compiled timeout-injection and long-member/TOC corpus qualification.
- Oversized MIME lines now fail closed instead of being split or skipped by the
  bounded legacy parser; add compiled long-header/body and production mail
  corpus coverage.
- MIME body-spool writes and bounded raw/encoded body exports now check the
  shared deadline before each write/read chunk; add compiled timeout injection
  during mail reassembly/export and production mail corpus coverage.
- DMG XML staging, partition reconstruction, and the shared bounded stripe
  writer now check the scan deadline, preserving `CL_ETIMEOUT`; add compiled
  DMG timeout-injection and production corpus qualification.
- DMG `blkx` metadata is now handled and released one callback at a time,
  removing whole-resource-fork heap retention; add compiled multi-block corpus,
  callback-timeout injection, sanitizer, and production DMG qualification.
- XAR’s shared temporary-output writer now checks the deadline after admission
  and immediately before TOC, subdocument, compressed-member, and raw-member
  spool writes while preserving short writes; add compiled XAR output-timeout
  injection and production corpus qualification.
- TNEF attribute headers now distinguish in-range fmap callback failures
  (`CL_EREAD`) from genuinely short headers (`CL_EPARSE`); add compiled
  callback-fault, exact-EOF, sanitizer, and production TNEF corpus coverage.
- Extend the standalone service-evidence verifier to recheck the copied oracle
  and every recorded workload input, structured report, process status, match
  signature/offset, and exact-edge milter outcome after the workload; compiled
  Linux/Sonic1 evidence remains required.
- RIFF header and chunk callback failures now preserve `CL_EREAD` instead of
  being flattened into truncation, while parser entry and chunk traversal
  honor the shared deadline and preserve `CL_ETIMEOUT`; add compiled
  callback/timeout-fault and production RIFF corpus qualification.
- CryptFF’s bounded decrypt-and-spool path now checks the shared deadline at
  parser entry and for each source chunk, preserving `CL_ETIMEOUT` through
  temporary-file cleanup; add compiled timeout-fault and production CryptFF
  corpus qualification.
- Structured-text detection now checks the shared deadline before each bounded
  fmap window and preserves `CL_ETIMEOUT` as an incomplete, non-cacheable
  result; add compiled large-text timeout and production structured-data
  corpus qualification.
- HTML normalization, script-encoded discovery/decoding, and UTF-16 conversion
  now check the shared deadline at bounded input boundaries and preserve
  `CL_ETIMEOUT` through normalized-output cleanup; add compiled HTML timeout,
  script-encoder, UTF-16, sanitizer, and production corpus qualification.
- Script normalization now checks the shared deadline at parser entry and in
  both file-backed and in-memory bounded-map paths, preserving `CL_ETIMEOUT`
  through matcher-buffer and temporary-output cleanup; add compiled large-script
  timeout and production corpus qualification.
- Old-format SIS metadata table, dependency-header, string, header, and
  language-table failures now remain incomplete/non-cacheable with distinct
  `CL_EREAD` versus `CL_EPARSE` results; add compiled callback-fault and
  production SIS corpus qualification. A focused in-range language-table
  callback regression now covers the `CL_EREAD` branch.
- Old-format SIS metadata and 9.x nested field traversal now honor the shared
  scan deadline and preserve fail-visible `CL_ETIMEOUT`; add compiled timeout,
  malformed-nesting, sanitizer, and production SIS corpus qualification.
- Python bytecode magic is now an explicit unsupported parser boundary:
  raw matching continues, but non-detection results are incomplete and
  non-cacheable until a bounded version-aware parser is implemented.
- GGUF, ONNX, and TensorFlow Lite model recognition is now an explicit
  unsupported parser boundary with raw matching preserved; add a bounded
  model parser and production corpus qualification before enabling deep
  model inspection.
- RAR and RAR SFX recognition, including confirmed embedded SFX candidates,
  now fails closed when the optional UnRAR backend is unavailable; complete
  backend-enabled parser and production corpus qualification remains
  required.
- SDB-enabled scans now retain the mandatory outer raw pass while performing
  a separate type-recognition-only pass after parsing; embedded SFX/archive
  candidates are no longer skipped merely because SDB signatures are loaded.
  Compiled embedded-SFX and production parser qualification remain open.
- File-type-recognition-only matcher passes now suppress hash and logical
  signature evaluation, preventing duplicate detector work after the
  SDB-enabled outer raw pass.

- clamd FILDES now returns a non-clean worker result when descriptor passing is
  unavailable after sending its explicit wire error; add a compiled
  no-FD-passing integration fixture before claiming that build variant.
- Runtime release evidence now preserves and hashes the release and sanitizer
  Rust archives, records the exact ENABLE_UNRAR disposition, copies enabled
  UnRAR interface/backend artifacts, and puts those artifacts first in the
  loader path; synthetic verifier controls reject missing or mismatched
  components. Authorized production-CVD and service qualification remain open.
- Service report evidence now requires detection-shaped reports to carry a
  non-clean verdict as well as the oracle's exact `last_alert`; a clean verdict
  paired with a matching alert is rejected by all report verifiers. Production
  CVD and Sonic1 qualification remain open.
- MIME/mbox raw line reads, materialized-header traversal, and disk-backed
  multipart/related traversal now honor the shared `MaxScanTime` deadline and
  preserve `CL_ETIMEOUT`; add compiled timeout injection and production mail
  corpus qualification.
- Mail `message/partial` identifier, spool, save, and reassembly-output
  allocation/materialization failures now mark the mail layer incomplete;
  add fault-injected partial-message coverage and production corpus
  qualification.

## Large-file validation and expansion progression

- `clamscan` stdin staging now shares the engine's `MaxTemporarySize` budget
  with parser spools and passes the staged byte count into the scan; the
  service gate now schedules exact-edge coverage for both `clamscan` and
  `clamdscan -`, with compiled temporary-budget evidence and the new
  path-helper regression's runtime execution still open; the Linux raw gate
  now requires both exact-32-GiB stdin detection at the final marker and the
  32-GiB-plus-one stdin rejection. Sonic1 remains unreachable during the
  latest bounded SSH-connect retry, so no Linux runtime result is claimed.

1. **Validate the current 32 GiB raw path on the local macOS host**
   - **Host preflight remains open:** the latest Darwin arm64 capture had
     5,323,248 KiB available against the 48 GiB minimum, no CMake or Ninja
     binary, and roughly 16 GiB of system memory; it is not large-file
     qualification evidence. Repeat on the 64 GB bare-metal host after the
     build toolchain is available.
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

- Matcher evaluation now merges target-specific and generic logical/YARA-root
  statuses. A target-root parser, bytecode, or resource failure cannot be
  overwritten by a later generic-root `CL_SUCCESS`; detections still take
  precedence. A focused two-root regression and source guards cover the
  fail-closed status contract, while full logical-signature and production
  qualification remain open.

- Bundled YARA execution statuses are now normalized before crossing the
  ClamAV error-code boundary. Interpreter stack overflow and other YARA
  execution failures are no longer vulnerable to numeric status collisions
  (including `CL_EMAXFILES`); required failures are incomplete and
  non-cacheable. A focused overflow regression covers the contract; full YARA
  corpus and production qualification remain open.

- ALZ now returns `CL_EMAXFILES` directly when member admission reaches the
  configured file-count limit, instead of relying only on the outer sticky
  incomplete state. A focused Rust helper regression covers the boundary;
  full ALZ corpus and production qualification remain open.

- ALZ finalization now returns `CL_EMAXSIZE` or `CL_EMAXFILES` directly for
  oversized, cumulative-size, or internally counted skipped members, rather
  than only recording a heuristic and returning success. Full ALZ limit-edge
  and production qualification remain open.
- ALZ extracted-member callbacks now check the shared scan deadline before
  reserving or writing each decoder-emitted chunk, preserving timeout status
  even when the decoder does not request another fmap window; compiled timeout
  injection and full ALZ qualification remain open.

- Keep `clamd_stream_limit()` as the single hard 32-GiB ingress ceiling for
  both daemon staging and client preflight, including integrations that pass a
  directly constructed option object; compiled service and Sonic1 evidence
  remain required.

- Preserve fail-closed file-count accounting at the established
  `cli_ctx.scannedfiles` native ceiling: an unlimited `MaxFiles=0` policy must
  return an incomplete resource result at `UINT32_MAX`, never wrap and admit a
  new object; production file-count qualification remains required.
- Keep structured report counters non-negative at saturation: use json-c's
  unsigned integer representation where available, and reject values above
  `INT64_MAX` on legacy json-c rather than serializing a negative metric; add
  compiled JSON-C-version and service fallback qualification.
- Structured report JSON now checks every json-c integer and string node
  allocation and returns `CL_EMEM` instead of serializing a partial report;
  add compiled allocation-fault and shared/static JSON-C qualification.
- Structured report metadata-string allocation failures are now sticky across
  report aggregation, force non-detection reports to `CL_EMEM` resource
  failure, and make JSON serialization fail closed; add fault-injected target,
  reason, alert, and directory-merge coverage.
- Mixed ABI bytecode hooks now continue after a v1 logical-match offset exceeds
  its 32-bit bridge, preserving the explicit incomplete/non-cacheable result
  while allowing a later v2 hook to use native offsets; retain mixed
  interpreter/JIT and production-bytecode qualification as a release gate.
- Widen ELF32 program/section table traversal cursors to native-width
  containing-file coordinates and derive ELF32 entry-point file offsets in
  native width while preserving the format's 32-bit fields; the synthetic
  >4 GiB-coordinate regression is registered, with compiled ELF corpus and
  supported-Linux qualification still required.
- Widen PE32 RVA-to-file translation and entry-point metadata to native-width
  containing-file coordinates while preserving format-defined 32-bit RVAs;
  legacy PE-specific and bytecode paths must fail closed above their ABI width,
  with compiled PE corpus and supported-Linux qualification still required.
- Preserve unsigned high-bit PE section-header fields in the native metadata
  view; classify legacy signed-coordinate PE-specific analysis as explicitly
  incomplete, and keep checked RVA-extent arithmetic from wrapping. The
  synthetic boundary regression is registered; compiled PE corpus, unpacker,
  sanitizer, and supported-Linux qualification remain required.
- Retain PE alignment-up extents and overlay starts in native width when a
  legal 32-bit section size rounds above 4 GiB; legacy PE hashing and
  inspection must return an explicit incomplete result rather than a narrowed
  partial view. The sparse logical-map boundary regression is registered;
  compiled PE corpus, unpacker, sanitizer, and supported-Linux qualification
  remain required.
- Keep ISO9660 long directory-name normalization bounded by the destination
  buffer and preserve its explicit incomplete/non-cacheable result; the
  synthetic 260-byte identifier regression is registered, with compiled ISO
  corpus, sanitizer, and parser-family qualification still required.

- Structured detection reports now carry an optional native-width
  `last_alert_offset` for retained root-level AC, BM, and PCRE matcher alerts;
  service qualification rejects a detection report that omits or mismatches
  the oracle offset. Parser, hash, callback, and child-layer detections remain
  offset-less until they have a stable coordinate contract; compiled report,
  service, and Sonic1 qualification remain open.

- Logical matcher evaluation now continues after non-critical parser, decoder,
  or bytecode failures while retaining the first incomplete status; detections
  and critical timeout/resource/I/O failures still halt evaluation. This keeps
  a required incomplete result fail-visible without suppressing an independent
  later logical detection. The focused regression is registered; compiled
  logical-signature, interpreter/JIT, sanitizer, and production qualification
  remain open.

- Target-specific raw matcher failures in buffer and fmap scans now remain
  fail-visible while non-critical failures continue into the independent
  generic raw pass; detections and critical timeout/resource/I/O failures still
  halt immediately. Static guards cover both raw ingress helpers; compiled
  fault-injection and production-signature qualification remain open.
- Buffer-ingress AC-data initialization now skips only a root with a
  non-critical setup failure, allowing the independent generic or target root
  to run while preserving the failure status; compiled fault-injection and
  production-signature qualification remain open.
- Raw matcher-root setup now isolates non-critical AC, BM, and PCRE offset
  preparation failures to the affected root, recomputes overlap from roots
  that are ready, and continues the independent raw matcher while preserving
  the setup status; critical memory, timeout, resource, and I/O failures still
  halt immediately. Static coverage is present; compiled fault-injection and
  production-signature qualification remain open.
- File-backed HTML phishing URL extraction now checks `MaxScanTime` before and
  after each bounded fmap window, so URL scanning cannot silently consume a
  large HTML body past the shared deadline; compiled HTML timeout injection
  and production qualification remain open.
- HTML phishing URL normalization, host construction, hash lookup, and
  temporary-copy allocation failures now mark the scan incomplete instead of
  being discarded or falling through as heuristic phishing detections; add
  allocation fault-injection and compiled URL-corpus qualification.
- RAR `keeptmp` archive-comment staging now uses bounded writes with shared
  deadline checks and fail-visible short-write handling; add compiled RAR
  comment-timeout and optional-backend corpus qualification.
- PDFNG referenced-object reloads now check `MaxScanTime` immediately before
  and after their bounded contiguous read; add compiled reload-timeout and
  broader PDFNG parser-loop qualification.
- Raw embedded-type dispatch now checks `MaxScanTime` before each candidate so
  a large matcher result list cannot delay parser admission; add compiled
  candidate-list timeout injection and production qualification.
- AC embedded-type match tracking allocation failure now marks the scan
  incomplete before returning `CL_EMEM`; add matcher allocation
  fault-injection and production-signature qualification.
- AC partial-signature offset tables, logical match-offset tracking, and AC or
  PCRE result-list allocation failures now mark the required matcher operation
  incomplete before returning `CL_EMEM`; add compiled fault-injection coverage
  for each list-growth boundary and production-signature qualification.
- AC matcher state initialization and file-type matcher setup now use the
  individual-allocation ceiling and mark allocation failures on the shared scan
  context; add fault-injected matcher-root setup and file-type detection
  coverage.
- Legacy PDF object-header and `endobj` searches now use overlapping 64 KiB
  windows with shared deadline checks; add compiled timeout injection,
  decoder-fault coverage, and production PDF qualification.
- Legacy PDF dictionary parsing now checks for a missing next token before
  pointer subtraction; add malformed-object and timeout regression coverage.
- Legacy PDF stream-boundary searches now use overlapping 64 KiB deadline
  windows; add compiled timeout and malformed-stream regression coverage.
- Legacy PDF `/Length`, JavaScript, `/XRef`, and trailer encryption searches
  now use deadline windows; make the dictionary helper and metadata tree
  searches context-aware and add compiled timeout coverage.
- PDF page-tree metadata searches now use deadline windows, `/Colors` passes
  the remaining length correctly, and URI delimiter scans check timeouts; add
  compiled metadata malformed-object and timeout coverage.
- The legacy PDF dictionary helper and large value decoders now receive scan
  context deadlines; migrate the compatibility context-free encryption helper
  and add compiled malformed-value and timeout coverage.
- The context-bearing encryption-object `/Standard` search now uses deadline
  windows; add compiled encrypted-PDF timeout and malformed-dictionary tests.
- Legacy PDF token scanning now checkpoints long comments, whitespace, and line
  endings; add compiled token-timeout and malformed-object coverage.
- Active PDF encryption crypt-filter parsing now supplies scan context while
  the public compatibility wrapper remains; add compiled malformed-filter and
  timeout coverage.
- Legacy PDF name normalization and JavaScript delimiter recovery now use
  deadline-aware searches; add compiled malformed-object and timeout coverage.
- Runtime evidence now clears inherited `LD_PRELOAD`/`LD_AUDIT` and records the
  loader-injection disposition; retain a hostile-environment gate in Linux
  release and sanitizer qualification.
- Service qualification applies the same loader-injection isolation to clamd
  and all frontends; retain hostile-environment service evidence coverage.
- PDFNG string, dictionary, array, and indirect-reference scans now checkpoint
  `MaxScanTime` at bounded progress intervals and discard partial parser
  structures on expiry; add compiled parser-loop timeout injection and full
  PDF corpus qualification.
- The runtime evidence gate now initializes its copied dependency directory
  before constructing the loader path under `set -u`; retain Linux release,
  sanitizer, service, and production-corpus qualification as release gates.
- Legacy UPX NRV2B/NRV2D/NRV2E bitstream, back-reference-copy, import-recovery,
  and PE-rebuild loops now receive the shared scan context and checkpoint
  `MaxScanTime`; add compiled UPX timeout injection and production PE corpus,
  sanitizer, and Sonic1 qualification.
- Legacy WWPack bitstream, large back-copy, block traversal, and section
  reconstruction loops now checkpoint the shared `MaxScanTime`; add compiled
  WWPack timeout injection, short-write coverage, and production PE corpus,
  sanitizer, and Sonic1 qualification.
- Legacy Aspack block-output and large back-copy loops now checkpoint the
  shared `MaxScanTime`; add compiled Aspack timeout injection, short-write
  coverage, and production PE corpus, sanitizer, and Sonic1 qualification.
- Legacy Upack output, LZMA back-copy, and call-fix loops now receive the
  shared scan context and checkpoint `MaxScanTime`; add compiled Upack timeout
  injection, production PE corpus, sanitizer, and Sonic1 qualification.
- FSG decompression and back-copy loops now use a context-aware decoder entry
  while retaining a compatibility wrapper for other packers; add compiled FSG
  timeout injection, multi-section corpus, sanitizer, and Sonic1 qualification.
- Non-LZMA MEW bitstream, back-copy, and section-traversal loops now use a
  context-aware decoder entry; add compiled MEW timeout injection and retain
  separate LZMA-path, production corpus, sanitizer, and Sonic1 qualification.
- MEW LZMA helper, output, copy, and call-fix loops now carry the shared scan
  context and checkpoint `MaxScanTime`; add compiled LZMA timeout injection,
  malformed packed-PE coverage, production corpus, sanitizer, and Sonic1
  qualification.
- Petite compressed-section output, import walks, and back-copy loops now
  checkpoint the shared `MaxScanTime`; add compiled Petite timeout injection,
  malformed-section coverage, sanitizer, and Sonic1 qualification.
- PEspin compressed-section handoffs now use the context-aware FSG decoder;
  add compiled PEspin timeout injection and retain separate emulation/XOR,
  production corpus, sanitizer, and Sonic1 qualification.
- yC emulator and section-decrypt loops now propagate distinct timeout results
  and checkpoint the shared `MaxScanTime`; add compiled yC timeout-injection,
  hostile jump-loop, production corpus, sanitizer, and Sonic1 qualification.
- Rust temporary-spool writes now use bounded 64 KiB chunks with a deadline
  check before each write, including large callback slices from Rust parsers;
  add deterministic short-write/timeout coverage and compiled Rust/Sonic1
  qualification.

## Scan-level temporary-directory setup failures — 2026-08-22

Top-level and recursive scans now mark required temporary-directory allocation
and creation failures as incomplete before unwinding. Cleanup only attempts to
remove a scan directory after its creation succeeded, preserving the original
resource reason and preventing a cleanup error from obscuring the admission
failure. Focused public-report and recursion-stack regressions are registered;
compiled fault injection, sanitizer, production-corpus, and Sonic1 qualification
remain open.

## INSTREAM client partial-stream boundary — 2026-08-22

- clamdscan INSTREAM submission now has one strict path: reject bytes beyond
  StreamMaxLength without sending a normal terminator, fail closed on ordinary
  and exact-limit read errors, and add compiled read-fault plus daemon-side
  partial-request qualification.

## Legacy FILDES client hard-ceiling preflight — 2026-08-22

- Public `send_fdpass*` wrappers now preflight known regular files through the
  shared checked helper and enforce the hard 32-GiB ceiling when daemon options
  are unavailable; add compiled FILDES and Sonic1 qualification for sparse
  exact-edge and over-limit inputs.

## MIME retained-node accounting — 2026-08-22

The legacy MIME line-list quota now charges each retained text node and the
ref-count byte used by `lineCreate()` in addition to line payload bytes. This
keeps many-short-line messages within the intended bounded representation, and
deduplicated blank separators no longer consume quota when no node is retained.
The source guards and non-clang regression gates remain the available local
evidence; allocation fault injection, sanitizer, production mail corpus, and
Sonic1 qualification remain open.
