# Wishlist

## HWPML missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null HWPML parser context, but mark a
  recognized HWPML layer with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `hwpml_map` regression passes and records the
  sticky reason. Keep full HWPML/XML corpus, sanitizer, materialized
  large-file, production-CVD, and Sonic1 qualification open.

## InstallShield missing-map confirmed-entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for null InstallShield parser contexts, but mark
  recognized MSI and legacy extraction layers with no input fmap incomplete
  and return `CL_EPARSE`; leave the weak MSI header-admission probe
  non-confirming.
- The isolated production-linked `ishield_map` regression passes for both
  confirmed entries. Keep full InstallShield/CAB corpus, sanitizer,
  materialized large-file, production-CVD, and Sonic1 qualification open.

## SIS missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null SIS parser context, but mark a recognized
  SIS layer with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `sis_map` regression passes and records the
  sticky reason. Keep full SIS corpus, sanitizer, materialized large-file,
  production-CVD, and Sonic1 qualification open.

## 7-Zip missing-map confirmed-entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null confirmed 7-Zip parser context, but mark a
  recognized layer with no input fmap incomplete and return `CL_EPARSE`; keep
  the weak header-admission probe non-confirming.
- The isolated production-linked `7z_map` regression passes and records the
  sticky reason. Keep full 7-Zip/BCJ2 corpus, sanitizer, materialized
  large-file, production-CVD, and Sonic1 qualification open.

## AutoIt missing-map confirmed-entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null confirmed AutoIt parser context, but mark
  a recognized AutoIt layer with no input fmap incomplete and return
  `CL_EPARSE`; leave the weak header-admission probe non-confirming.
- The isolated production-linked `autoit_map` regression passes and records
  the sticky reason. Keep full AutoIt corpus, sanitizer, materialized
  large-file, production-CVD, and Sonic1 qualification open.

## XDP missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null XDP parser context, but mark a recognized
  XDP layer with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `xdp_map` regression passes and records the
  sticky reason. Keep full XDP/XML corpus, sanitizer, materialized large-file,
  production-CVD, and Sonic1 qualification open.

## DMG missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null DMG parser context, but mark a recognized
  DMG layer with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `dmg_map` regression passes and records the
  sticky reason. Keep full DMG corpus, sanitizer, materialized large-file,
  production-CVD, and Sonic1 qualification open.

## MBR/GPT missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for null partition-parser contexts, but mark
  recognized MBR and GPT layers with no input fmap incomplete and return
  `CL_EPARSE`; cover both MBR entry points used by dispatch preflight and
  scanning.
- The isolated production-linked `partition_map` regression passes for both
  families. Keep complete partition corpus, sanitizer, materialized large-file,
  production-CVD, and Sonic1 qualification open.

## HWPOLE2 missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null HWPOLE2 parser context, but mark a
  recognized HWPOLE2 parser with no input fmap incomplete and return
  `CL_EPARSE`.
- The isolated production-linked `hwpole2_map` regression passes and records
  the sticky reason. Keep full HWPOLE2/OLE corpus, sanitizer, materialized
  large-file, production-CVD, and Sonic1 qualification open.

## APM missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null APM parser context, but mark a recognized
  APM parser with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `apm_map` regression passes and records the
  sticky reason. Keep full APM corpus, sanitizer, materialized large-file,
  production-CVD, and Sonic1 qualification open.

## HFS+ missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null HFS+ parser context, but mark a recognized
  HFS+ parser with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `hfs_map` regression passes and records the
  sticky reason. Keep full HFS+ corpus, sanitizer, materialized large-file,
  production-CVD, and Sonic1 qualification open.

## UDF missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null UDF parser context, but mark a recognized
  UDF parser with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `udf_map` regression passes and records the
  sticky reason. Keep full UDF corpus, width review, sanitizer, materialized
  large-file, production-CVD, and Sonic1 qualification open.

## ISO9660 missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null ISO parser context, but mark a recognized
  ISO parser with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `iso_map` regression passes and records the
  sticky reason. Keep full ISO/Joliet corpus, sanitizer, materialized
  large-file, production-CVD, and Sonic1 qualification open.

## CPIO fixed-width numeric fields — 2026-08-25

- Require exact-width octal ODC and hexadecimal newc/CRC name-size and
  file-size fields; reject malformed prefixes as incomplete `CL_EPARSE`
  instead of moving the archive cursor using a partial value.
- The production-linked `cpio_numeric` regression covers both fields in ODC
  and newc and verifies non-cacheability; retain complete CPIO corpus,
  sanitizer, materialized large-file, production-CVD, and Sonic1 qualification
  as release gates.

## OLE2 XLM/BIFF read-status preservation — 2026-08-24

- Preserve an operational WorkBook-sector read failure through the XLM/BIFF
  walker and OLE2 property enumeration as `CL_EREAD`; do not collapse it to a
  generic parse result.
- A focused fixture-backed regression covers the injected sector fault and
  non-cacheability. Complete OLE2 corpus, sanitizer, and parser-family
  qualification remain open.

## XZ trailing-stream admission — 2026-08-24

- Do not dispatch a clean XZ output when the first decoder stream ends while
  buffered or unrequested trailing input remains; return explicit incomplete
  `CL_EUNPACK` and preserve non-cacheability.
- The focused regression concatenates two valid XZ streams. Keep complete XZ
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD, and Sonic1 qualification open.

## Rust current-layer fmap boundary — 2026-08-24

- Reject a missing or zero-length recursion stack and an out-of-range current
  recursion level before Rust forms or indexes the raw scan-layer slice.
- Focused Rust unit regressions and source guards cover the two malformed
  context states. Keep ALZ, LHA/LZH, and OneNote parser-family corpus,
  production-linked, sanitizer, certified Linux x86-64, materialized
large-file, and Sonic1 qualification open.

## Rust parser current-fmap status mapping — 2026-08-24

- Preserve `CL_ENULLARG` for a null Rust parser context, `CL_EPARSE` for a
  malformed current layer, and `CL_EREAD` for an in-range fmap callback fault
  instead of collapsing all three into generic `CL_ERROR`.
- Add focused Rust status-class regressions and keep ALZ, LHA/LZH, and OneNote
  parser-family corpus, production-linked, sanitizer, certified Linux x86-64,
  materialized large-file, and Sonic1 qualification open.

## CAB/CHM missing-map entry hardening — 2026-08-24

- Reject missing input fmaps before CAB header admission, CAB extraction, or
  CHM extraction reaches the MSPack adapter; return explicit incomplete
  `CL_EPARSE` results and preserve non-cacheability.
- Add direct entry-point regression coverage for CAB header, CAB scan, and CHM
  scan. Keep complete CAB/CHM production corpus, sanitizer, materialized
  large-member, certified Linux x86-64, and Sonic1 qualification open.

## Masked ZIP-SFX central-directory admission — 2026-08-24

- Require a masked ZIP-SFX local header to be confirmed by a bounded EOCD and
  central record that references local-header offset zero. Confirmed candidates
  carry a central-directory layer attribute and use the full ZIP catalogue;
  ordinary embedded local records retain single-member dispatch.
- The focused production-linked GCC case passes 2/2 with exact child-only
  detection, layer-attribute observation, malformed-central rejection, and an
  injected in-range central-record read failure classified as `CL_EREAD`.
- Add complete ZIP/SFX corpus, ZIP64 and multi-entry cases, sanitizer and
  materialized large-file runs, certified Linux x86-64 execution, production
  CVDs, and Sonic1 qualification before marking the ZIP/SFX family complete.

## Bounded UTF-16 HTML normalization — 2026-08-24

- UTF-16 HTML now uses strict bounded UTF-16-to-UTF-8 conversion with explicit
  endian admission, cross-window surrogate state, and exact decoded-output
  temporary accounting before the normalized HTML child scan.
- The focused Linux ARM64 GCC encoding case passes 2/2 and covers LE/BE with
  and without BOMs, a surrogate split at the 4 KiB boundary, decoded-child
  detection, reservation release, and exact malformed-input reasons.
- Add production HTML corpus, ASan/UBSan, Linux x86-64, materialized large-file,
  and Sonic1 evidence before parser-family qualification.

## Encoded-text script normalization — 2026-08-24

- UTF-16LE/BE script text now uses bounded streaming UTF-8 conversion before
  normalized matching, with explicit BOM, odd-length, byte-order, and
  cross-window surrogate handling.
- UTF-8 script text is validated incrementally; overlong, truncated,
  surrogate, and out-of-range sequences stay fail-visible and non-cacheable.
- The focused Linux ARM64 GCC case passes all three encoding branches and
  malformed/cross-window oracles. Production corpora, ASan/UBSan, Linux
  x86-64, and Sonic1 qualification remain gates.

## PE32+ common inspection and narrower x86 boundary — 2026-08-24

- PE32+ now completes section hashing, overlay inspection, `BC_PE_ALL`, and
  native 64-bit import-table metadata/hash traversal after raw matching.
- The remaining PE32/x86 heuristics and unpackers stay fail-visible and
  non-cacheable instead of being misrepresented as architecture-neutral.
- A deterministic focused Linux ARM64 GCC regression passes common import
  metadata and injected 64-bit-thunk read failure. Production PE32+ corpora,
  Linux x86-64, ASan/UBSan, and Sonic1 runs remain qualification gates.

## Daemon host file and temporary-filesystem admission — 2026-08-24

- Certified large-file daemon startup now requires `RLIMIT_FSIZE` to represent
  the maximum configured ingress and rejects unmeasurable limits instead of
  warning and continuing. Linux temporary staging also rejects tmpfs and ramfs
  so the 48-GiB memory and 68-GiB disk-capacity floors cannot describe the same RAM.
  Deterministic GCC and ASan/UBSan policy tests pass locally; a current-source
  Linux x86-64 daemon startup matrix and Sonic1 resource evidence remain gates.
- The certified startup profile now rejects `MaxThreads` values other than 1;
  admission budgets one active scan and requires additional requests to stay
  queued without staging. Multi-worker admission remains outside the first
  release profile until resources are measured and reserved per active worker.
- Linux admission now resolves the daemon's real cgroup membership and mount,
  then uses the smallest finite v1/v2 ancestor headroom. Synthetic nested,
  hybrid-controller, multiple-mount, and current-container probes pass locally;
  current-source Sonic1 startup under its actual service/container placement
  remains a release gate.

## Zero-valued front-end admission limits — 2026-08-23

- Daemon startup admission now treats explicit `StreamMaxLength=0` and
  `OnAccessMaxFileSize=0` as their documented 32-GiB ceilings before sizing
  memory and temporary-space requirements. A focused regression prevents
  lower `MaxFileSize` settings from bypassing those checks; runtime resource
  and Sonic1 qualification remain release gates.

## Shared clamd client stream EINTR handling — 2026-08-23

- Legacy clamd client stream staging now retries signal-interrupted source
  reads for both ordinary chunks and the byte-over-limit sentinel probe,
  while real read failures remain fail-closed. Compiled nonblocking/fault
  injection and Sonic1 qualification remain release gates.

## Milter large-stream transport width and interruption handling — 2026-08-23

- Milter socket progress now retains the native `ssize_t` result width for
  multi-gigabyte stream chunks and retries `EINTR` at send/receive boundaries
  instead of failing a valid request. Compiled transport fault injection,
  sanitizer, and Sonic1 qualification remain release gates.

## On-access source-read status propagation — 2026-08-23

- Local read failures while staging an on-access INSTREAM request now preserve
  `CL_EREAD` through the protocol/client boundary instead of being relabeled
  as a generic write failure. Compiled on-access fault injection and Sonic1
  qualification remain release gates.

## Authenticode certificate-header read classification — 2026-08-23

- Mark confirmed PE security-directory certificate-header range failures
  incomplete and non-cacheable, distinguishing `CL_EREAD` for in-range fmap
  callback failures from `CL_EPARSE` for truncation; retain PE corpus,
  sanitizer, and Sonic1 qualification as release gates.

## Runtime dependency immutability evidence — 2026-08-23

- The mandatory service qualification now records and canonicalizes the
  runtime dependency path/hash set both before and after the workload. The
  verifier requires the sets to match and the summary to carry an explicit
  service_runtime_dependencies_unchanged=pass marker. The synthetic service
  evidence regression tampers with the after-manifest and requires rejection.
  Real production-CVD, sanitizer, and Sonic1 execution remain open.

## PCRE man-page platform ceiling — 2026-08-23

- Corrected `clamd.conf` documentation so `PCREMaxFileSize` describes the
  implemented 32 GiB anonymous-map ceiling on qualifying 64-bit builds and
  the 1 GiB fallback elsewhere; the build-profile-dependent default is now
  explicit. Generated-man-page qualification remains a release gate.

## JPEG exploit-probe read classification — 2026-08-23

- The JPEG MS04-028 comment-marker probe now preserves an in-range fmap
  callback failure as `CL_EREAD` instead of silently treating the probe as a
  non-match. A one-shot callback-fault regression covers the distinction;
  compiled media corpus, sanitizer, and Sonic1 qualification remain release
  gates.

## Bytecode JavaScript-normalizer limit cleanup — 2026-08-23

- JavaScript-normalizer API limit failures now release the borrowed input
  window before returning the legacy failure sentinel; the shared limit
  checker already records the MaxFiles boundary as incomplete. A focused
  regression covers the boundary and confirms the input pipe is drained;
  independently compiled interpreter/JIT, sanitizer, and Sonic1 qualification
  remain release gates.

## Legacy bytecode coordinate narrowing — 2026-08-23

- Legacy `seek`, `file_find`, and PDF-offset results now fail visibly when a
  valid native coordinate exceeds `INT32_MAX`, instead of returning the v1
  `-1` sentinel without an incomplete/non-cacheable status. Retain independently
  compiled v1/v2 fixture and interpreter/JIT qualification as release gates.

## PE icon alpha-mask read failures — 2026-08-23

- A 32-bit PE icon's required alpha-mask window now fails closed when its
  in-range fmap read fails. The previous fallback could hide an in-range
  callback failure, while the documented out-of-range malformed-icon fallback
  remains available; a focused callback regression verifies `CL_EREAD`, the
  incomplete reason, and non-cacheability.
  Compiled PE/icon corpus, sanitizer, and Sonic1 qualification remain open.

## Raw matching of short non-empty layers — 2026-08-23

- Removed the historical five-byte early exits from root, descriptor-child, and
  nested-fmap scan paths. Empty inputs still complete without a matcher pass,
  while every non-empty layer now reaches the outer raw matcher, including
  one-byte and other sub-five-byte content. A focused one-byte signature
  regression and source guards cover the contract; full compiled and
  production-signature qualification remains open.

## MSXML fmap callback failure classification — 2026-08-23

- Preserve an in-range MSXML fmap callback failure as `CL_EREAD` instead of
  allowing libxml2 to collapse it into generic malformed-XML status. The
  adapter now records callback failure through reader initialization and
  parsing, with focused non-cacheable coverage; compiled MSXML/HWPML corpus,
  sanitizer, and Sonic1 qualification remain open.

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
- Mach-O load-command admission now enforces the declared command-table and
  per-command boundaries across segment, section, and thread-state payloads;
  add compiled malformed-command corpus, sanitizer, and parser-family
  qualification.
- TIFF direct parser missing-map admission now returns `CL_EPARSE` with a
  sticky incomplete result; add compiled TIFF corpus, sanitizer, and
  parser-family qualification.
- ELF metadata-only parser admission now rejects missing maps and null output
  metadata before dereference; add compiled ELF corpus, sanitizer, and
  parser-family qualification.
- TNEF direct parser admission now distinguishes null context from missing
  recognized input fmap and returns a sticky incomplete parse for the latter;
  add compiled TNEF corpus, sanitizer, and parser-family qualification.
- BMP and JPEG 2000 direct entries now distinguish null context from missing
  recognized input fmap and return parser-specific incomplete parses; add
  compiled graphics corpus, sanitizer, and parser-family qualification.
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
  the 179-entry capability manifest validates against the refreshed dispatch
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
- The Rust fmap adapter now distinguishes an in-range `need()` callback failure
  from genuine EOF and preserves it as `CL_EREAD` through scanner-facing Rust
  readers; LHA/LZH construction, member-read, and next-header errors preserve
  the same distinction through `delharc`; add compiled callback-fault and
  parser-corpus qualification.
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
- EGG skippable and fixed metadata extra fields validate oversized spans
  without mapping them contiguously. Scanner-aware filename and archive/file
  comment metadata now uses bounded source ranges, direct fmap scans, and
  fixed-window codepage conversion; only the public legacy contiguous-string
  API retains the individual-allocation ceiling, and encryption size
  subtraction remains underflow-safe.
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
  purposes, extended to exact 32 GiB and 32 GiB plus one byte; parser and
  fuzzy-image qualification remains open.
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
- Bytecode file search now preserves `needle_length - 1` bytes between 4 KiB
  input windows, including a split signature above 4 GiB. The loader enforces
  format-8-only APIs/globals, `clambc` initializes native matcher offsets, and
  exact scan-option queries no longer accept partial or embedded-NUL names; an
  independently compiled format-8 fixture plus interpreter/JIT and Sonic1
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
- Optional XDP `keeptmp` staging now holds the complete cumulative dump
  reservation through streaming XML/Base64 inspection, so retained input and
  decoded children cannot independently reuse the same temporary quota. The
  focused GCC case passes cumulative, overlapping-output, timeout, rollback,
  and partial-cleanup oracles.
- Add production XDP corpus, ASan/UBSan, Linux x86-64, materialized large-file,
  and Sonic1 qualification; the current Sonic1 SSH service was unreachable.
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
  4 GiB at the legacy buffer-matcher ABI. Module bodies now use fixed-window
  decompression, persistent codepage state, cross-window normalization, and
  transactional quota-accounted output; project-directory metadata and the
  legacy whole-module callback retain explicit 1 GiB contiguous boundaries.
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
- The shared Rust decoder spool now retries signal-interrupted `write()` calls
  and treats zero-byte or other failed writes as explicit incomplete output;
  add compiled EINTR/short-write injection and retain LHA/ALZ/OneNote corpus,
  sanitizer, and parser-family qualification.
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
- Confirmed XAR TOC metadata and XML-reader failures now retain sticky
  incomplete state through the direct parser entry; add broader malformed-TOC
  and XML fault-injection coverage.
- Confirmed RIFF parser entry now treats a missing input fmap as an explicit
  incomplete parse instead of `CL_ENULLARG`; add compiled RIFF corpus and
  sanitizer qualification.
- RTF direct parser admission now rejects a missing input fmap as an explicit
  incomplete parse; add compiled RTF/OLE corpus and sanitizer qualification.
- CHM direct MSPack admission now checks the null context before initializing
  its fmap wrapper; add compiled CHM corpus and sanitizer qualification.
- Legacy MSXML direct admission now rejects a recognized layer with no input
  fmap as an explicit incomplete parse; add compiled XML/OOXML and sanitizer
  qualification.
- OLE2 extraction now rejects a recognized layer with no input fmap as an
  explicit incomplete parse; add compiled OLE2 corpus and sanitizer
  qualification.
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

## On-access FILDES hard-ceiling preflight — 2026-08-22

The on-access protocol's descriptor-passing path now rechecks the opened
regular file against a defensive 32-GiB ceiling before
sending `FILDESREPORT`. Direct-context callers therefore cannot bypass the
scan-thread preflight; stat and over-limit failures preserve non-clean status
without sending a partial request. Compiled on-access fault-injection and
Sonic1 qualification remain open.

## On-access stream rewind failure — 2026-08-22

Regular-file on-access streams now require a successful rewind before the
`INSTREAMREPORT` command is sent. A failed `lseek` returns `CL_ESEEK` without
submitting a scan for a stale descriptor position; non-seekable non-regular
inputs retain their existing streaming behavior. Compiled read/seek fault
injection and Sonic1 qualification remain open.

## On-access configured-limit parity — 2026-08-22

Direct on-access client calls now combine `StreamMaxLength` with
`OnAccessMaxFileSize` before action setup, path submission, streaming, or
FILDES transfer. This keeps the local option from being bypassed when the
scan-thread preflight is not the caller, while retaining the protocol-level
32-GiB defensive check. Compiled option-parity/fault-injection and Sonic1
qualification remain open.

## RTF split reserved-field accounting — 2026-08-23

- Preserve partial progress when an embedded RTF object’s eight-byte reserved
  field crosses an 8 KiB fmap chunk boundary, keeping the payload-size field
  aligned; retain the focused boundary regression, compiled RTF/OLE corpus,
  sanitizer, and Sonic1 qualification as release gates.

## ELF fixed-range truncation classification — 2026-08-22

- Preflight the complete range of every fixed-size ELF metadata request before
  calling the fmap callback, so a truncated header cannot be reported as an
  operational callback failure; retain `CL_EREAD` for fully in-range callback
  failures. Add compiled scanner, sanitizer, production ELF-corpus, and Sonic1
qualification.

## Fixed-range parser truncation classification — 2026-08-22

- Preflight fixed-size Mach-O, TIFF, and TNEF metadata reads before callback
  admission, preserving parse results for genuinely short structures and
  `CL_EREAD` for fully in-range callback failures; retain compiled scanner,
sanitizer, production-corpus, and Sonic1 qualification as release gates.

## GIF/PNG fixed-range truncation classification — 2026-08-22

- Preflight fixed-size GIF fields and PNG chunk metadata before callback
  admission, preserving parse results for truncated structures and `CL_EREAD`
  for fully in-range callback failures; retain compiled scanner, sanitizer,
  production media-corpus, and Sonic1 qualification as release gates.

## JPEG fixed-range truncation classification — 2026-08-22

- Preflight fixed-size JPEG header, marker, segment-size, Photoshop-marker,
  and resource-size reads before callback admission, preserving parse results
  for truncated structures and `CL_EREAD` for fully in-range callback
  failures; retain compiled scanner, sanitizer, production media-corpus, and
  Sonic1 qualification as release gates.

## BMP/JP2/APM fixed-range truncation classification — 2026-08-22

- Preflight fixed-size BMP, JPEG 2000, and APM metadata reads before callback
  admission, preserving parse/format results for truncated structures and
  `CL_EREAD` for fully in-range callback failures; retain compiled scanner,
  sanitizer, production media-corpus, and Sonic1 qualification as release
  gates.

## HWP3 fixed-section truncation classification — 2026-08-22

- Preflight fixed-size HWP3 document-info and metadata-enabled summary reads
  before callback admission, preserving parse results for truncated sections
  and `CL_EREAD` for fully in-range callback failures; retain compiled
  scanner, sanitizer, production document-corpus, and Sonic1 qualification as
  release gates.

## UDF declared-partition extent accounting — 2026-08-23

- Bound UDF allocation extents by the declared partition length before fmap
  access, retaining the out-of-partition fixture, compiled fragmented-UDF
  corpus, sanitizer, width review, and Sonic1 qualification as release gates.

## SIS fixed-header truncation classification — 2026-08-22

- Preflight the fixed 16-byte SIS UID header before callback admission,
  preserving parse results for truncated packages and `CL_EREAD` for fully
  in-range header callback failures; retain compiled scanner, sanitizer, SIS
  corpus, and Sonic1 qualification as release gates.

## XAR fixed-header read classification — 2026-08-22

- Preflight the fixed XAR header before callback admission, preserving parse
  results for truncated headers and `CL_EREAD` for fully in-range callback
  failures; retain compiled scanner, sanitizer, production XAR corpus, and
  Sonic1 qualification as release gates.

## ARJ signature truncation classification — 2026-08-22

- Preflight the fixed two-byte ARJ signature before callback admission,
  preserving parse results for one-byte candidates and `CL_EREAD` for fully
  in-range signature callback failures; retain compiled scanner, sanitizer,
  production ARJ corpus, and Sonic1 qualification as release gates.

## HWP3 content-table truncation classification — 2026-08-22

- Preflight HWP3 content-stream font and style table count reads before
  callback admission, preserving parse results for one-byte prefixes and
  `CL_EREAD` for fully in-range callback failures; retain compiled scanner,
  sanitizer, production HWP3 corpus, and Sonic1 qualification as release
  gates.

## HWP3 paragraph-header truncation classification — 2026-08-22

- Preflight HWP3 paragraph metadata reads before callback admission,
  preserving parse results for short character-count prefixes and `CL_EREAD`
  for fully in-range callback failures; retain compiled scanner, sanitizer,
  production HWP3 corpus, and Sonic1 qualification as release gates.

## HWP3 information-block header truncation classification — 2026-08-22

- Preflight HWP3 information-block ID and length reads before callback
  admission, preserving parse results for short headers and `CL_EREAD` for
  fully in-range callback failures; retain compiled scanner, sanitizer,
  production HWP3 corpus, and Sonic1 qualification as release gates.

## HWP3 paragraph-payload fixed-read classification — 2026-08-22

- Preflight HWP3 paragraph content, special-character length, box, and
  drawing fields before callback admission, preserving parse results for short
  payload prefixes and `CL_EREAD` for fully in-range callback failures; retain
  compiled scanner, sanitizer, production HWP3 corpus, and Sonic1
qualification as release gates.


## Shared fixed-range reader and PE fixed-metadata classification — 2026-08-22

- Add and adopt `fmap_readn_full()` for fixed-range admission, preserving
  parse results for short ranges and `CL_EREAD` for fully in-range callback
  failures; apply it to PE fixed headers, directories, sections, certificate
  headers, import descriptors, and 32/64-bit thunk entries. Retain compiled
  scanner, sanitizer, production PE corpus, and Sonic1 qualification as
  release gates.

## SIS fixed metadata range classification — 2026-08-22

- Preflight SIS UID, main metadata, name-table, and dependency-header reads
  before callback admission, preserving parse results for short ranges and
  `CL_EREAD` for fully in-range callback failures; retain compiled scanner,
  sanitizer, production SIS corpus, and Sonic1 qualification as release gates.

## HWPOLE2 fixed-prefix range classification — 2026-08-22

- Preflight the fixed HWPOLE2 32-bit payload-size prefix, preserving parse
  results for short headers and `CL_EREAD` for fully in-range callback
  failures; retain the native 32-bit payload-size boundary and compiled
 scanner, sanitizer, production HWP corpus, and Sonic1 qualification as
 release gates.

## TNEF attachment-range admission — 2026-08-22

- Preflight declared TNEF attachment payloads before materialization,
  preserving parse results for out-of-range data and `CL_EREAD` for fully
  in-range callback failures; retain compiled scanner, sanitizer, production
  TNEF corpus, and Sonic1 qualification as release gates.

## UUEncode mid-attachment read classification — 2026-08-22

- Preserve `CL_EREAD` for fmap line-read failures after UUEncode admission in
  standalone and embedded-mail paths, while retaining parse/incomplete results
  for malformed or unterminated attachments; retain compiled scanner,
  sanitizer, production UUEncode corpus, and Sonic1 qualification as release
  gates.

## OLE2/MSO fixed-prefix read classification — 2026-08-23

- Preflight the fixed MSO uncompressed-size prefix, preserving parse results
  for short streams and `CL_EREAD` for fully in-range callback failures;
  preserve `CL_EREAD` and an incomplete result for streaming MSO callback
  failures; retain compiled scanner, sanitizer, production OLE2/MSO corpus,
  and Sonic1 qualification as release gates.

## ARJ fixed-header read classification — 2026-08-23

- Preflight ARJ main and member fixed-header ranges, preserving format/parse
  results for short ranges and `CL_EREAD` for fully in-range fmap callback
  failures; retain compiled scanner, sanitizer, production ARJ corpus, and
  Sonic1 qualification as release gates.

## PE icon bitmap-header read classification — 2026-08-23

- Preflight PE icon bitmap headers, preserving parse results for short ranges
  and `CL_EREAD` for fully in-range fmap callback failures; retain compiled
  scanner, sanitizer, PE corpus, and Sonic1 qualification as release gates.

## EGG fixed-index-header read classification — 2026-08-23

- Preflight EGG archive and file/block fixed headers plus EOF marker reads,
  preserving parse results for short ranges and `CL_EREAD` for fully in-range
  fmap callback failures; retain compiled scanner, sanitizer, production EGG
  corpus, and Sonic1 qualification as release gates.

## EGG extra-field and compressed-range read classification — 2026-08-23

- Preflight EGG extra-field headers, size fields, declared payloads, legacy
  whole-block extraction, and streamed compressed ranges, preserving parse
  results for short ranges and `CL_EREAD` for fully in-range fmap callback
  failures; retain compiled scanner, sanitizer, production EGG corpus, and
  Sonic1 qualification as release gates.

## OLE2 sector-range read classification — 2026-08-23

- Stop zero-padding map-short OLE2 CFB sectors as successful reads; retain
  `CL_EPARSE` for truncated sectors and `CL_EREAD` for fully in-range fmap
  callback failures, with sticky incomplete state and top-level reconciliation;
  retain compiled scanner, sanitizer, production OLE2 corpus, and Sonic1
  qualification as release gates.

## HFS+ non-empty fork block admission — 2026-08-23

- Treat a non-empty HFS+ fork with zero declared allocation blocks as an
  explicit format-incomplete result instead of skipping it as an empty child;
  retain compiled HFS+ corpus, sanitizer, and Sonic1 qualification as release
  gates.

## XAR compressed-member range read classification — 2026-08-23

- Classify XAR gzip/LZMA member input windows as `CL_EPARSE` when truncated and
  `CL_EREAD` when a fully in-range fmap callback fails, preserving sticky
  incomplete state through decoder cleanup; retain compiled scanner,
  sanitizer, production XAR corpus, and Sonic1 qualification as release gates.

## OLE2 encryption-window read classification — 2026-08-23

- Route the bounded native-width encryption metadata probe through a checked
  range helper and retain `CL_EREAD` for fully in-range fmap callback failures;
  add compiled fault-injection coverage and retain encrypted-Office corpus,
  sanitizer, and Sonic1 qualification as release gates.

## UDF descriptor status reset — 2026-08-23

- Reset UDF descriptor read status for every range attempt and distinguish
  short/out-of-map ranges from in-range callback failures; retain compiled
  descriptor/read-fault, sanitizer, production UDF corpus, and Sonic1
  qualification as release gates.

## TIFF unknown-field rejection — 2026-08-23

- Reject unknown TIFF IFD field types as explicit incomplete parse results and
  preserve the missing-map guard; retain compiled malformed-IFD, sanitizer,
  production TIFF corpus, and Sonic1 qualification as release gates.

## RIFF range-status reset — 2026-08-23

- Reset RIFF range status per request and reject a missing fmap at the detector
boundary; retain compiled callback-fault, malformed RIFF, sanitizer,
production RIFF corpus, and Sonic1 qualification as release gates.

## RTF implicit embedded-object close status — 2026-08-23

- Propagate non-clean status from an implicitly closed RTF embedded-object
  callback and clear callback state before cleanup; retain compiled callback,
  sanitizer, production RTF corpus, and Sonic1 qualification as release gates.

## HWP3 character-style read classification — 2026-08-23

- Route the paragraph character-style byte through the checked fixed-range
  helper so in-range fmap callback failures remain `CL_EREAD` with sticky
  incomplete state and an explicit reason; retain compiled callback,
  sanitizer, production HWP3 corpus, and Sonic1 qualification as release gates.

## PE icon nested-window read classification — 2026-08-23

- Preflight PE icon group headers, icon data pointers, palettes, and pixel
  windows, preserving parse results for short ranges and `CL_EREAD` for fully
  in-range fmap callback failures; reject pixel-size arithmetic overflow while
  retaining the documented broken 32-bit mask fallback; retain compiled
  scanner, sanitizer, production PE/icon corpus, and Sonic1 qualification as
  release gates.

## JPEG application-marker probe classification — 2026-08-23

- Keep short APP0/APP1/APP2/APP8/APP14 payloads as ordinary non-matches while
  preserving `CL_EREAD`, sticky incomplete state, and non-cacheability for
  fully in-range fmap callback failures; retain compiled scanner, sanitizer,
  production JPEG corpus, and Sonic1 qualification as release gates.

## MSEXPAND fixed-header range classification — 2026-08-23

- Preflight the packed MSEXPAND header, preserving `CL_EPARSE` for a short
  SZDD header and `CL_EREAD` with sticky incomplete state for a fully in-range
  fmap callback failure; retain compiled scanner, sanitizer, production SZDD
corpus, and Sonic1 qualification as release gates.

## NSIS fixed-header range classification — 2026-08-23

- Preflight the NSIS 0x1c-byte decoder header, preserving `CL_EPARSE` for a
  truncated header and `CL_EREAD` with sticky incomplete state for a fully
  in-range fmap callback failure; retain compiled scanner, sanitizer,
production NSIS corpus, and Sonic1 qualification as release gates.

## InstallShield MSI fixed-header range classification — 2026-08-23

- Preflight the InstallShield MSI 0x20-byte control header, preserving
  `CL_EPARSE` for truncation and `CL_EREAD` with sticky incomplete state for a
  fully in-range fmap callback failure; retain compiled scanner, sanitizer,
  production InstallShield corpus, and Sonic1 qualification as release gates.

## ZIP64 extra-field read classification — 2026-08-23

- Distinguish malformed or short ZIP64 local/central extra fields from fully
  in-range fmap callback failures, preserving `CL_EPARSE`/`CL_EFORMAT` for the
  former and `CL_EREAD` with sticky incomplete state for the latter; retain
  compiled scanner, sanitizer, production ZIP corpus, and Sonic1 qualification
  as release gates.

## GIF/PNG missing-map handling — 2026-08-23

- Reject missing input maps at the GIF and PNG parser boundaries with explicit
  incomplete parse results; retain compiled media corpus, sanitizer, and Sonic1
  qualification as release gates.

## HFS+ catalog-node range classification — 2026-08-23

- Preflight each HFS+ catalog-node block so genuinely short nodes remain
  explicit format/incomplete results while fully in-range fmap callback
  failures preserve `CL_EREAD`; retain compiled HFS+ corpus, sanitizer, and
  Sonic1 qualification as release gates.

## Legacy bytecode read-coordinate admission — 2026-08-23

- Reject negative, host-unrepresentable, and size-overflowing coordinates in
  the legacy bytecode `read` entry before fmap conversion; retain independently
  compiled v1/v2 fixture and interpreter/JIT qualification as release gates.

## TNEF missing-map handling — 2026-08-23

- Reject a missing TNEF input map before parser entry dereferences it, preserving
  an explicit incomplete `CL_ENULLARG` result; retain compiled mail corpus,
  sanitizer, and Sonic1 qualification as release gates.

## ISO9660 Joliet name-expansion admission — 2026-08-23

- Mark Joliet UTF-16BE conversion failure and converted directory-name expansion
  beyond the fixed destination buffer incomplete instead of silently scanning a
  substituted or truncated name; retain compiled ISO corpus, sanitizer, and
  Sonic1 qualification as release gates.

## MIME header lookahead read failure — 2026-08-23

- MIME header continuation lookahead now preserves an in-range fmap callback
  failure as `CL_EREAD` instead of treating it as a normal non-continuation;
  compiled mail fault-injection, parser-corpus, and Sonic1 qualification remain
  open.

## Shared fmap string-read failure classification — 2026-08-23

- Replace ambiguous `fmap_need_offstr()` production use with bounded,
  status-aware windows; migrate ARJ and legacy InstallShield, preserve
  `CL_EREAD` versus `CL_EPARSE`, and bound InstallShield to its selected range;
  retain compiled parser, sanitizer, corpus, and Sonic1 qualification gates.

## MSPack decoder read-failure propagation — 2026-08-23

- Preserve in-range fmap callback failures as `CL_EREAD` through CAB/CHM
  decoder open and extraction, while retaining `CL_ETIMEOUT` for deadline
  expiry; retain compiled MSPack corpus, sanitizer, and Sonic1 qualification
  gates.

## Legacy InstallShield CAB header read classification — 2026-08-23

- Preserve `CL_EPARSE` for a genuinely short embedded InstallShield header and
  `CL_EREAD` for an in-range fmap callback failure; retain compiled corpus,
  sanitizer, and Sonic1 qualification gates.

## OneNote legacy reader read-failure propagation — 2026-08-23

- Preserve Rust OneNote source I/O failures as `CL_EREAD` while retaining
  `CL_EPARSE` for genuine EOF/truncation; retain compiled corpus, sanitizer,
  and Sonic1 qualification gates.

## Structured-detector clipped-window read classification — 2026-08-23

- Preserve CL_EREAD only for fully in-range structured-detector callback
  failures; classify a failed clipped EOF window as incomplete parse input,
  retaining compiled detector corpus, sanitizer, and Sonic1 qualification
  gates.

## MIME line read-failure propagation — 2026-08-23

- Preserve in-range fmap callback failures from the bounded MIME line reader
  as `CL_EREAD` while retaining EOF/truncation classification; retain compiled
  mail corpus, sanitizer, and Sonic1 qualification gates.

## InstallShield MSI file-record read classification — 2026-08-23

- Preserve `CL_EPARSE` for short MSI file records and `CL_EREAD` for in-range
  fmap callback failures; retain compiled corpus, sanitizer, and Sonic1
  qualification gates.

## ALZ reader read-failure propagation — 2026-08-23

- Preserve `CL_EREAD` for in-range fmap callback failures at ALZ header,
  signature, central-directory, and member-data boundaries while retaining
  incomplete parse results for genuine truncation; retain compiled ALZ corpus,
  sanitizer, and Sonic1 qualification gates.

## 7-Zip bounded EOF classification — 2026-08-23

- Clip 7-Zip fmap input requests at the map boundary so genuine truncation
  remains `CL_EPARSE` while fully in-range backing-read failures remain
  `CL_EREAD`; retain compiled 7-Zip corpus, sanitizer, and Sonic1
  qualification gates.

## SWF clipped compressed-input read classification — 2026-08-23

- Classify a backing callback failure on a compressed-input request that
  crosses the fmap boundary as truncated SWF input rather than `CL_EREAD`;
  retain the distinct in-range callback-fault regression and compiled SWF
  corpus, sanitizer, and Sonic1 qualification gates.

## MSPack clipped decoder-read classification — 2026-08-23

- Preserve decoder truncation semantics when a CAB/CHM fmap request crosses
  EOF and its clipped backing read fails, while retaining CL_EREAD for
  fully in-range callback faults; retain compiled CAB/CHM corpus, sanitizer,
  and Sonic1 qualification gates.

## PE unpacker payload-read classification — 2026-08-23

- Route confirmed MEW, Upack, Petite, WWPack, and Aspack reconstruction reads
  through complete-range admission so clipped sections remain parse/incomplete
  results and in-range callback failures remain `CL_EREAD`; retain PE corpus,
  sanitizer, and Sonic1 qualification gates.

## Structured-report counter saturation — 2026-08-23

- Saturate structured-report logical/file/parser/detector counters at
  `UINT64_MAX` so very large directory or parser walks cannot wrap diagnostic
  evidence to zero; retain compiled report and Sonic1 qualification gates.

## OLE2 document-stream encryption probe read propagation — 2026-08-23

- Route the `WordDocument`, `WorkBook`, and `PowerPoint Document` encryption
  probes through checked fmap ranges and propagate truncation versus in-range
  callback failures through the property walker; focused WordDocument and
  WorkBook regressions are present, while compiled Office corpus, sanitizer,
  and Sonic1 qualification remain release gates.

## HWP raw-deflate input read classification — 2026-08-23

- Bound HWP raw-deflate reads to the declared compressed stream and preserve
  `CL_EREAD` plus incomplete state for fully in-range fmap callback failures;
  retain compiled HWP corpus, sanitizer, and Sonic1 qualification gates.

## Authenticode parse/read failure classification — 2026-08-23

- Mark embedded Authenticode ASN.1 parse/read failures incomplete before
  external catalog trust can continue; confirmed embedded certificate errors
  now terminate the certificate walk instead of being skipped. Retain the
  focused callback regression, compiled PE corpus, sanitizer, and Sonic1
  qualification gates.
- Cover the post-`asn1_parse_mscat()` hash-container validation exits with a
  signed-fixture callback regression; hash mismatches remain verification
  failures rather than parser failures.

## FSG and UPX confirmed-read failure classification — 2026-08-23

- Mark legacy FSG source/support windows and UPX compressed-section windows
  incomplete/non-cacheable on in-range callback failure; retain packed-fixture
  regressions, full PE corpus, sanitizer, and Sonic1 qualification gates.

## Context-aware fmap hash read classification — 2026-08-23

- Make context-aware fmap hash input, initialization, and digest failures
  sticky incomplete/non-cacheable, with a two-window callback regression;
  retain compiled matcher/hash, sanitizer, and Sonic1 qualification gates.

## AutoIt version-byte read classification — 2026-08-23

- Mark confirmed AutoIt version-byte read failures incomplete and
  non-cacheable, with a focused callback regression; retain compiled AutoIt
  corpus, sanitizer, and Sonic1 qualification gates.

## PE import DLL-name read classification — 2026-08-23

- Mark in-range PE import DLL-name fmap failures incomplete and non-cacheable
  before the import-hash pass unwinds; retain the focused callback regression,
  compiled PE corpus, sanitizer, and Sonic1 qualification gates.

## PE header ingress read classification — 2026-08-23

- Preserve `CL_EREAD` and sticky incomplete state for in-range PE DOS/NT,
  optional-header, data-directory, and section-header fmap callback failures;
  retain existing short-range candidate/parse results and the focused DOS
  signature regression, with compiled PE corpus, sanitizer, and Sonic1
  qualification as release gates.

## AutoIt header-window read classification — 2026-08-23

- Mark AutoIt signature and versioned-body header-window read failures
  incomplete and non-cacheable, with a focused signature-window callback
  regression; retain compiled AutoIt corpus, sanitizer, and Sonic1 gates.

## InstallShield MSI admission-window read classification — 2026-08-23

- Mark InstallShield MSI magic and control-header read failures incomplete and
  non-cacheable in the direct admission helper, with a focused callback
  regression; retain compiled InstallShield corpus, sanitizer, and Sonic1
  qualification gates.

## Bytecode PDF-object read classification — 2026-08-23

- Mark bounded bytecode PDF object-window fmap failures incomplete and
  non-cacheable, with an injected-read regression alongside the page-lifetime
  test; retain compiled bytecode/PDF corpus, sanitizer, and Sonic1 gates.

## Bytecode buffer-pipe read classification — 2026-08-23

- Make file-backed bytecode buffer-pipe range and fmap-read failures sticky
  incomplete/non-cacheable, with an exact-boundary injected-read regression;
  retain compiled bytecode/decoder, sanitizer, and Sonic1 gates.

## NsPack confirmed-read failure classification — 2026-08-23

- Return `CL_EREAD` and mark the layer incomplete when confirmed NsPack loader,
  compressed-data, or OEP metadata windows cannot be read; retain PE corpus,
  sanitizer, and Sonic1 qualification gates.

## MEW confirmed-loader read classification — 2026-08-23

- Return `CL_EREAD` and mark the layer incomplete when a confirmed MEW loader
  metadata window cannot be read; retain PE corpus, sanitizer, and Sonic1
  qualification gates.

## Embedded EGG SFX read-result classification — 2026-08-23

- Preserve a distinct `EGG SFX header could not be read completely` result when
  a confirmed embedded header's fmap callback fails; retain the existing
  malformed/unsupported result for parse failures and the rejection path for
  short weak candidates. Compiled scanner, sanitizer, production EGG corpus,
  and Sonic1 qualification remain release gates.

## Embedded 7-Zip SFX read-result classification — 2026-08-23

- Preserve a distinct `7-Zip SFX start header could not be read completely`
  reason for confirmed embedded-header fmap failures, while retaining the
  malformed/unsupported result for parse failures and candidate rejection for
  weak signatures. Compiled scanner, production 7-Zip SFX corpus, sanitizer,
  and Sonic1 qualification remain release gates.

## HFS+ compressed-resource read classification — 2026-08-23

- Mark required HFS+ compressed-resource headers, resource tables, block counts,
  and block-table reads incomplete at the point of temporary-file failure,
  preserving `CL_EREAD` instead of relying on generic end-of-parser
  reconciliation. Compiled HFS+ corpus, sanitizer, and Sonic1 qualification
  remain release gates.

## Runtime evidence manifest path binding — 2026-08-23

- Require source, Git tree, and index manifests to contain the same canonical,
  sorted path set, and require content-manifest revisions to equal the source
  manifest digest; accept the Git-less producer's source-manifest copies for
  tree/index files; add a negative verifier regression for path disagreement.
  Runtime/build semantic qualification and external attestation remain release
  gates.

## Embedded RAR SFX read-result classification — 2026-08-23

- Preserve a distinct `RAR SFX main header could not be read completely`
  reason for confirmed embedded-header fmap failures, while retaining the
  malformed/truncated result for parse failures and candidate rejection for
  weak signatures. Compiled scanner, production RAR corpus, and backend/Sonic1
  qualification remain release gates.

## PE heuristic window read classification — 2026-08-23

- Preserve required Magistr tail-window and Polipos code/jump-window failures
  as explicit `CL_EREAD` or `CL_EPARSE` incomplete results instead of silently
  skipping confirmed PE-specific inspection; retain compiled PE corpus,
  sanitizer, Polipos jump-target coverage, and Sonic1 qualification as release
  gates.

## TAR end-of-archive classification — 2026-08-23

- Require two complete all-zero TAR end-marker blocks; classify missing,
  single-block, malformed, and truncated termination as explicit parse-incomplete
  results, with compiled TAR corpus, sanitizer, and Sonic1 qualification
  retained as release gates.

## NsPack bitched-entry read classification — 2026-08-23

- Preserve confirmed bitched NsPack entry-metadata read failures as explicit
  `CL_EREAD` or `CL_EPARSE` incomplete results; retain compiled PE corpus,
  sanitizer, and Sonic1 qualification as release gates.

## PE initial icon-group read classification — 2026-08-23

- Preserve initial PE icon-group header callback and range failures as explicit
  `CL_EREAD` or `CL_EPARSE` incomplete results; retain compiled icon corpus,
  sanitizer, and Sonic1 qualification as release gates.

## ISO volume-descriptor terminator classification — 2026-08-23

- Require a complete `0xFF/CD001` ISO volume-descriptor terminator and classify
  missing, malformed, out-of-map, and callback-failed termination as explicit
  incomplete results; retain compiled ISO/Joliet corpus, sanitizer, and Sonic1
  qualification as release gates.

## UDF file-set descriptor completeness — 2026-08-23

- Require the file-set descriptor after the anchor instead of treating a
  wrong in-range descriptor as optional; keep read/range failures distinct and
  retain compiled UDF corpus, sanitizer, and Sonic1 qualification as release
  gates.

## Shared zero-byte temporary-output writes — 2026-08-23

- The shared `cli_writen()` helper now stops zero-byte write progress and
  returns the completed prefix instead of spinning forever, and `cli_filecopy()`
  propagates source-read, short/zero-byte-write, and close failures; add
  compiled zero-progress/fault-injection coverage for all large
  temporary-output paths.

## clamd INSTREAM zero-progress staging — 2026-08-23

- Require the active INSTREAM receiver to accept a chunk only when the shared
  writer returns its exact length; add compiled daemon zero-progress/fault
  injection and Sonic1 qualification for partial staged streams.

## clamd response send progress — 2026-08-23

- Make `mdprintf()` send only the unsent response suffix, retry `EINTR`, wait
  for both nonblocking errno variants, and reject zero-byte progress; add
  compiled protocol fault injection and Sonic1 qualification.

## BinHex temporary fork short-write and rewind disposition — 2026-08-23

- Keep BinHex data/resource fork short or zero-progress writes and failed nested-scan rewinds sticky-incomplete and non-cacheable; add compiled write/seek fault coverage.

## HFS+ compressed-resource handoff failures — 2026-08-23

- Keep HFS+ compressed-resource seeks, block reads, decoder setup/teardown,
  compressed metadata validation, fork writes, and inline compressed output
  sticky-incomplete and non-cacheable; add compiled HFS+ fault-injection and
  corpus coverage.

## HFS+ metadata and node format failures — 2026-08-23

- Preserve HFS+ malformed tree headers, catalog/attribute records, extents,
  node coordinates, and catalog-fork geometry as sticky-incomplete; add
  compiled malformed-volume and allocation fault coverage.

## OLE2 property-tree admission failures — 2026-08-23

- Preserve OLE2 property-tree recursion/file/worklist limits, JSON timeout,
  scan-size admission, invalid-header/first-data-block geometry, and tracking
  allocation failures as sticky-incomplete; add compiled limit/allocation
  fault coverage.

## ELF section metadata allocation failures — 2026-08-23

- Keep ELF32/ELF64 native section-metadata allocation failures
  sticky-incomplete and non-cacheable; add compiled ELF allocation fault
  coverage.

## XAR unsupported member encodings — 2026-08-23

- Treat explicit XAR member encodings with a missing media type or unsupported
  style as `CL_EUNPACK` incomplete results instead of scanning encoded bytes as
  raw content; retain compiled XAR corpus, sanitizer, and Sonic1 qualification
  as release gates.

## GPT primary-table validation fallback — 2026-08-23

- Preserve GPT primary/secondary validation `CL_EREAD` and deadline failures
  instead of treating them as malformed-header fallback and allowing a
  secondary-only scan to look clean; retain compiled GPT fault injection,
  sanitizer, corpus, and Sonic1 qualification as release gates.

## HTML normalized metadata allocation propagation — 2026-08-23

- Propagate tag-argument, tag replacement, link-content, form-data, and
  file-backed phishing URL allocation failures as incomplete/non-cacheable
  results instead of allowing partial normalized output or metadata to look
  complete; retain compiled allocation-fault, sanitizer, HTML/MHTML corpus,
  and Sonic1 qualification as release gates.

## TNEF zero-length attribute checksum accounting — 2026-08-23

- Consume the mandatory checksum after every zero-length TNEF attribute so a
  nonzero checksum cannot shift the next-header boundary; retain exact-EOF,
  callback-fault, malformed-container, sanitizer, and Sonic1 qualification as
  release gates.

## RIFF declared-container boundary accounting — 2026-08-23

- Bound RIFF root and nested `LIST` traversal to declared container ranges,
  including padding and coordinate overflow checks; retain empty-list,
  malformed-range, callback-fault, sanitizer, and Sonic1 qualification as
  release gates.

## ISO9660 declared-volume boundary accounting — 2026-08-23

- Validate ISO9660's paired Volume Space Size fields and bound block admission
to the declared end as well as fmap length so appended overlay bytes cannot
become members; retain the overlay-boundary, malformed-volume, sanitizer,
and Sonic1 qualification as release gates.

## HFS+ declared tree-header boundary — 2026-08-23

- Bound HFS+ tree-header coordinates by the declared volume before fmap access,
  retaining the exact-end boundary fixture, compiled corpus, sanitizer, and
  Sonic1 qualification as release gates.

## APM declared partition-map boundary — 2026-08-23

- Bound APM normal and intersection entry reads by the declared partition-map
  extent, retaining the mapped-but-undeclared entry fixture, compiled corpus,
  sanitizer, and Sonic1 qualification as release gates.


## Embedded matcher-offset range admission — 2026-08-23

- Reject negative or out-of-map raw embedded-type matcher offsets before child
  range subtraction or nested handoff, and preserve the incomplete result past
  later type-parser dispatch; retain compiled embedded-candidate,
  sanitizer, production-SFX, and Sonic1 qualification as release gates.

## 7-Zip declared-output write admission — 2026-08-23

- Bound each streaming 7-Zip output callback by the member's declared
  uncompressed size before writing, so decoder over-production cannot exceed
  the temporary reservation; retain the regular-file/decoder-size check and
  add arithmetic regression coverage, with compiled 7-Zip, sanitizer, corpus,
  and Sonic1 qualification remaining release gates.

## CAB/CHM declared-output admission — 2026-08-23

- Clamp MSPack decoder writes to the declared CAB/CHM member size and require
  successful materialized output to be a regular file of exactly that size
  before nested scanning; retain the existing broader scan-budget cap and add
  focused materialization coverage, with compiled parser, sanitizer, corpus,
  and Sonic1 qualification remaining release gates.

## TAR GNU base-256 size admission — 2026-08-23

- Accept checked positive GNU base-256 TAR size fields and bounded PAX decimal
  `size=` overrides in addition to legacy octal, while rejecting
  negative/overflow values; retain compiled TAR, sanitizer, corpus, and Sonic1
  qualification as release gates.

## TIFF BigTIFF unsupported classification (historical) — 2026-08-23

- This fail-closed placeholder was superseded by the bounded BigTIFF IFD
  implementation below.

## AutoIt EA06 bounded decompiled-output spool — 2026-08-23

- Close the former EA06 1 GiB decompiled-script allocation boundary with a
  quota-accounted 64 KiB output window, overlapping input/output reservation
  accounting, and reservation-aware nested scanning. Retain compiled AutoIt
  corpus and supported-build Sonic1 qualification as release gates.

## EGG oversized extra-field bounded traversal — 2026-08-23

- Replace the blanket oversized-extra-field rejection with full-span
  validation plus bounded fixed-prefix reads for skippable, OS, and encryption
  metadata. Scanner-aware filename/comment payloads now retain ranges and scan
  their complete content through direct fmaps or fixed-window codepage
  conversion; only `cli_egg_open()` compatibility strings remain contiguous.
  Compiled EGG corpus and Sonic1 qualification are still required.

## Bounded BigTIFF IFD traversal — 2026-08-23

- Parse both endian variants of the 16-byte BigTIFF header, 64-bit entry counts
  and IFD links, fixed 20-byte entries, and LONG8/SLONG8/IFD8 fields without
  retaining a directory or mapped value payload. Keep malformed extensions,
  count/size overflow, out-of-range values, callback failures, and deadlines
  fail-visible. The release gate now binds a deterministic sparse
  4,294,967,368-byte fixture, with its first IFD and external LONG8 value above
  4 GiB, to exact release/sanitizer parser oracles and post-run verification.
  Retain the complete compiled TIFF corpus and materialized Sonic1
  qualification as release gates.

## PDF single-Flate bounded streaming — 2026-08-23

- Qualify the new 64 KiB-input/256 KiB-output single-Flate path with compiled
  malformed and valid PDF corpora, sanitizer fault injection, and a
  materialized multi-gigabyte stream on Sonic1. Preserve transactional rollback
  and exact temporary accounting. Supported ordinary filter chains now use the
  bounded spool path below; convert object streams and encryption before
  retiring the remaining `pdf-stream-over-1g` capability exception.

## PDF single-RunLength bounded streaming — 2026-08-23

- Qualify the fixed-window RunLength packet walker with compiled valid and
  malformed PDF corpora, materialized multi-gigabyte streams, decoder fault
  injection, and Sonic1 release/sanitizer runs. Retain exact post-marker,
  marker-less, rollback, deadline, scan-limit, and temporary-quota oracles.

## PDF single-ASCII filter bounded streaming — 2026-08-23

- Qualify the fixed-window ASCIIHex and ASCII85 walkers with compiled PDF
  corpora, materialized multi-gigabyte streams, write/seek/deadline fault
  injection, and Sonic1 release/sanitizer runs. Preserve exact whitespace,
  odd-nibble, quintet-range, `z`, terminator, post-marker, and marker-less
  oracles.

## PDF single-LZW bounded streaming — 2026-08-23

- Qualify the fixed-dictionary LZW walker with compiled valid/malformed PDF
  corpora, both `EarlyChange` modes, materialized multi-gigabyte streams,
  decoder and output fault injection, and Sonic1 release/sanitizer runs.
  Preserve EOI, resynchronization, predictor-unsupported, rollback, deadline,
  scan-limit, and temporary-quota oracles.

## PDF predictor fail-closed admission — 2026-08-23

- Keep non-identity Flate/LZW predictors explicit incomplete unless bounded
  TIFF/PNG predictor reversal is implemented. Qualify identity, malformed,
  unsupported, raw-fallback, corpus, and Sonic1 behavior before release.

## PDF bounded filter-chain spools — 2026-08-23

- Qualify chains composed of Flate, RunLength, ASCIIHex, ASCII85, and LZW with
  compiled valid/malformed corpora, every supported filter ordering,
  materialized multi-gigabyte intermediates, write/seek/map/read/cleanup fault
  injection, and Sonic1 release/sanitizer runs. Preserve simultaneous
  input/output temporary accounting, release consumed inputs only after the
  next stage completes, and require exact final-output/quota rollback before
  raw fallback. Per-filter DecodeParms arrays are implemented by the later
  2026-08-24 milestone; retain unsupported/mixed chains and encrypted
  production qualification as explicit gaps.

## PDF file-backed object streams — 2026-08-23

- Qualify ordinary unencrypted raw and supported-filter object streams with a
  compiled valid/malformed corpus. A deterministic PDF 1.7 generator and
  scanner-facing gate now cover raw, Flate, ASCIIHex-to-Flate, malformed-after-
  one-valid-object, and fully allocated 64 MiB–4 GiB decoded children while
  binding hashes, parser/mapping/cleanup diagnostics, RSS, faults, I/O, and
  temporary cleanup. Run that gate with release and sanitizer scanners on
  Sonic1 and retain the resulting evidence. Preserve exact temporary ownership
  transfer, malformed-backing lifetime, containing-object status propagation,
  and page-range release. Bounded Identity, RC4, AESV2, and AESV3 object streams
  are now implemented, and deterministic empty-password Standard R2 RC4,
  Standard R4 AESV2, and deprecated compatibility-only Standard R5 AESV3 cases
  cover raw and supported filters. Nonempty-password variants for every handler
  now prove structured unsupported/no-clean/no-plaintext behavior. Extend the
  evidence gate to materialized multi-gigabyte encrypted children,
  broader malformed encryption dictionaries and quota/read/cleanup faults, and
  release/sanitizer scanners on Sonic1. The first-release non-mmap policy is now
  explicit: the certified profile requires private file-backed mappings,
  advertises that capability, and rejects a large-file daemon configuration
  without it; non-mmap builds retain historical-size behavior and explicit
  incomplete PDF boundaries outside the certification claim.

## PDF bounded encrypted-stream qualification — 2026-08-23

- Empty-password Standard R2 RC4, Standard R4 AESV2, and deprecated Standard R5
  AESV3 now have deterministic complete raw, Flate, and ASCIIHex-to-Flate PDFs
  plus evidence-gate oracles for key discovery and their bounded decrypt paths.
  Deterministic nonempty credentials now require explicit structured
  unsupported status and forbid clean or plaintext-marker results. Unknown
  crypt-filter methods now require `UNSUPPORTED`; truncated AESV2 ciphertext
  and invalid PKCS#7 padding require `MALFORMED_CONFIRMED`, exact diagnostics,
  and no clean/plaintext/residue outcome. Extend this to broader malformed
  encryption dictionaries, quota/read/cleanup faults, and materialized
  multi-gigabyte release and sanitizer runs on Sonic1. Preserve object-key
  vectors, CBC IV/block shape,
  strict nonzero PKCS#7 padding, RC4 state across windows,
  decryption-before-filter ordering, simultaneous plaintext/downstream quota,
  exact rollback, file-backed object ownership, and no temporary residue.
  One explicit Crypt stage is now bounded in any filter position; retain
  repeated Crypt stages and unsupported/mixed filters as explicit incomplete
  boundaries. Non-mmap object streams remain deliberately
  outside the certified first-release profile.

## PDF per-filter DecodeParms arrays — 2026-08-24

- Direct DecodeParms dictionaries retain their compatibility behavior. Arrays
  must contain exactly one dictionary or `null` for every declared filter, and
  each dictionary is dispatched only to its corresponding stage in streamed,
  encrypted, and residual legacy chains. Short, long, scalar, or invalid-entry
  arrays fail before output, mark the scan incomplete, and remain non-cacheable.
- Focused Linux ARM64 GCC tests pass 2/2 for direct dispatch and parser syntax,
  including `/DecodeParms`, abbreviated `/DP`, `null`, predictor placement,
  exact raw fallback, zero-output malformed admission, and temporary-accounting
  cleanup. Direct GCC compilation also passes for `pdf.c`, `pdfdecode.c`, and
  the complete `check_clamav.c` translation unit with only pre-existing
  isolated-build warnings.
- Add production and sanitizer corpus execution, materialized multi-gigabyte
  chains, broader malformed dictionary syntax, quota/read/write/cleanup fault
  injection, unsupported/mixed filters, repeated Crypt stages, and Sonic1
  release evidence before parser-family qualification.

## PDF explicit Crypt filter ordering — 2026-08-24

- Route exactly one explicit Crypt stage through the ordinary quota-accounted
  filter rotation at any declared position. The stage reads only its matching
  DecodeParms, resolves Identity/RC4/AES through the bounded decryptor, and
  overlaps intermediate/final temporary reservations until the next stage is
  complete.
- Focused Linux ARM64 GCC evidence passes 1/1 for both Crypt-to-ASCIIHex and
  ASCIIHex-to-Crypt Identity ordering, exact decoded output, expected peak
  temporary accounting, and a repeated-Crypt chain that fails visibly with
  exact raw fallback.
- A second focused GCC case passes 1/1 with 40 internal oracles. RC4, AESV2,
  and AESV3 each succeed with Crypt before and after Flate, RunLength,
  ASCIIHex, ASCII85, and LZW. Every surrounding filter also proves RC4 one-
  byte-short quota rollback and malformed AES-padding raw restoration. The
  same case passes with GCC AddressSanitizer/UBSan and leak detection; the
  refactored LZW fixtures pass their focused 6/6 normal and sanitizer suite.
- Add production PDF corpora, broader malformed crypt dictionaries,
  production/sanitizer runs,
  materialized multi-gigabyte stages, fault injection, and Sonic1 evidence.

## PDF exact DecodeParms dictionary selection — 2026-08-24

- Parse the complete root stream dictionary under the shared deadline and
  select only exact decoded `/DecodeParms` or `/DP` nodes. Ignore matching text
  in literal strings, comments, nested dictionaries, and longer names; retain
  long-form precedence and reject duplicate exact keys, malformed values, or
  dictionary/array allocation failures as incomplete and non-cacheable.
- Focused Linux ARM64 GCC evidence passes 3/3. The new case contains ten
  adversarial oracles for nested literal decoys, comments containing delimiters,
  nested-dictionary decoys, longer names, escaped names, long-form precedence,
  malformed arrays and preceding values, malformed name escapes, and duplicate
  exact keys. The two
  explicit-Crypt focused cases also pass against the same current parser
  objects. All three focused binaries also pass with the touched PDF production
  objects under GCC AddressSanitizer/UBSan with leak detection.
- Add production/sanitizer PDF corpus execution, allocation/read fault
  injection, materialized multi-gigabyte streams, and Sonic1 release evidence
  before parser-family qualification.

## PDF exact crypt-filter dictionary selection — 2026-08-24

- Parse the bounded `/CF` dictionary structurally and require one exact decoded
  filter name whose value is a dictionary containing one exact name-valued
  `/CFM`. Exact `Identity` and a missing `/Name` retain their specified
  defaults; missing, duplicate, scalar, truncated, prefixed, or unknown
  entries resolve to `ENC_UNKNOWN` and therefore remain explicitly incomplete.
- Focused Linux ARM64 GCC evidence passes 1/1 with 23 internal valid and
  fail-closed oracles, normally and with AddressSanitizer/UBSan plus leak
  detection. The existing 40-oracle surrounding-filter matrix, three-case
  DecodeParms parser suite, and explicit Identity ordering case also pass
  against the hardened production objects in normal and sanitizer modes.
- Add full Standard encryption-dictionary corpus mutations, allocation/read
  fault injection, production scanner execution, materialized multi-gigabyte
  encrypted streams, and Sonic1 evidence before parser-family qualification.

## PDF exact Crypt DecodeParms semantics — 2026-08-24

- Treat `/Type` and `/Name` in an explicit Crypt stage as exact, unique fields.
  If `/Type` is present it must be the `CryptFilterDecodeParms` name; `/Name`
  may appear at most once and must be a PDF name object. Wrongly typed,
  missing-valued, duplicate, or invalid entries fail before decryption and
  preserve transactional raw fallback. Longer keys remain irrelevant.
- Focused Linux ARM64 GCC evidence passes 1/1 with ten internal scenarios,
  normally and under AddressSanitizer/UBSan with leak detection. The existing
  23-oracle `/CF` dictionary case, 40-oracle cipher/filter matrix, three-case
  DecodeParms parser suite, and explicit Identity ordering case also pass
  against the same current production objects in both modes.
- Add complete stream-dictionary corpus mutations, allocation/read fault
  injection, production scanner execution, materialized multi-gigabyte
  encrypted streams, and Sonic1 evidence before parser-family qualification.

## PDF Standard encryption-dictionary corpus mutations — 2026-08-24

- The deterministic object-stream corpus now adds six complete Standard R4
  AESV2 PDFs with duplicate, scalar, or missing `/StdCF` entries and missing,
  duplicate, or scalar `/CFM` values. Together with the existing unknown-method
  case, each requires explicit `UNSUPPORTED`, no decryptor selection, no clean
  or plaintext-marker result, no parsed object child, and no temporary residue.
- Evidence schema 7 binds exactly 26 fixture, log, report, resource, and
  provenance records. Generator tests pass 37 cases; shell syntax, Python
  syntax, and whitespace checks pass locally.
- Run the exact Linux x86-64 orchestrator and current production scanner on
  Sonic1 when SSH service is reachable. Production-scanner and output-window
  allocator fault injection plus materialized multi-gigabyte encrypted streams
  remain open.

## PDF bounded-spool fault rollback — 2026-08-24

- Linker-injected GCC tests now prove five independent failure classes:
  encrypted RC4 output writes and intermediate-stage close return `CL_EWRITE`;
  file-backed map creation returns `CL_ERESOURCE`; an in-range intermediate
  read returns `CL_EREAD`; and fixed output-window allocation returns `CL_EMEM`
  for Flate, RunLength, ASCIIHex, ASCII85, and LZW.
- Every case rolls output and temporary accounting back to zero, creates no
  object-stream child, marks the scan incomplete and non-cacheable, and passes
  5/5 normally and against ASan/UBSan PDF production objects with leak
  detection. Adjacent PDF suites remain green in both modes.
- Add production-scanner fault injection; keep Sonic1 and materialized
  multi-gigabyte evidence open.

## 7-Zip BCJ2 solid-folder streaming — 2026-08-24

- Keep the completed bounded architecture: quota-accounted CALL/JUMP/control
  scratch files, direct resumable MAIN merging, checked 64-bit pack positions,
  256 KiB decompressor progress windows, deadline checkpoints, unchanged CRC
  layering, ABI-compatible wrappers, and exact all-exit cleanup.
- Local differential, terminal-opcode, window-boundary, truncation,
  output-failure, CALL/JUMP graph, native-width, pack-overflow, and production
  scratch-provider oracles pass; a one-MiB raw LZMA fixture also confirms four
  exact 256 KiB output windows and nine progress checkpoints.
- Add representative production BCJ2 archives, malformed graph/coder corpus,
  scratch create/read/write/seek/close/unlink fault injection in the normal
  unit binary, sanitizer execution, a materialized multi-gigabyte solid-folder
  case, certified Linux x86-64 execution, and Sonic1 evidence before marking
  the 7-Zip parser family qualified.

## Bounded VBA module bodies — 2026-08-24

- Fixed-window VBA inflate, persistent codepage conversion, incremental
  normalization, transactional quota accounting/rollback, native 64-bit output
  position, legacy-wrapper compatibility, and the explicit whole-module
  callback boundary are implemented.
- Focused GCC syntax and behavior oracles pass, including cross-window
  normalizer parity.
- The aggregate project-directory metadata stream is now a quota-accounted,
  read-only file-backed mapping on certified 64-bit mmap builds, with consumed
  page release and fixed-window metadata conversion; only the Unicode stream
  name retains the existing 128-byte OLE property-name contract. Non-mmap builds
  retain an explicit unsupported compatibility path. Production-linked normal,
  streamed-metadata, quota-failure, and scan-limit-failure oracles pass, and the
  182-entry capability/source gate covers the design.
- Add production Office/VBA and malformed-codepage corpus, sanitizer and
  allocation/read/write/map/unmap/rollback injection, materialized
  multi-gigabyte directory/module evidence, certified Linux x86-64 execution,
  and Sonic1 qualification.

## Bounded EGG filename/comment metadata — 2026-08-24

- Add compiled EGG filename, file-comment, and archive-comment corpora covering
  UTF-8, codepage 949, split multibyte sequences, encrypted metadata, malformed
  conversion, and exact-tail signatures. The generated codepage-932 fixture
  already proves bounded conversion and exact converted-byte detection. Run
  read/write/seek/temp quota/deadline fault injection, sanitizer builds,
  materialized multi-gigabyte metadata, certified Linux x86-64 execution, and
  Sonic1 qualification. The scanner range path is implemented; the public
  legacy null-terminated-string API intentionally retains its 1 GiB
  compatibility ceiling.

## Bounded HFS+ inline decmpfs output — 2026-08-24

- Add compiled HFS+ decmpfs corpus for zero-length, trailing-input, truncated,
  malformed-zlib, exact-limit, and multi-gigabyte outputs. Run decoder
  allocation/finalization, deadline, disk-full, close/unlink, sanitizer,
  certified Linux x86-64, and Sonic1 qualification. The former 64 KiB output
  ceiling is closed by fixed-window inflation with exact size and write-failure
  oracles.

## SIS compressed-member qualification — 2026-08-24

- Extend the passing exact decoded-member signature oracle to stored and 9.x
  packages, malformed/trailing zlib streams, multi-window and materialized
  large members, sanitizer builds, certified Linux x86-64, and Sonic1. The
  legacy compressed-member fixture now proves nested matcher handoff directly.

## TAR binary size-field qualification — 2026-08-24

- Extend the passing positive/negative/overflow base-256 and local/global PAX
  scope oracles to truncated and large materialized fields. Add production TAR
  corpus, sanitizer and read/write/seek/cleanup fault injection, certified
  Linux x86-64, and Sonic1 qualification. Valid binary fields are preserved by
  an exact-width copy and reach nested matching; unrepresentable and negative
  fields fail visibly and remain non-cacheable.

## CPIO CRC parser qualification — 2026-08-24

- Extend the passing exact child-signature, mismatch, malformed-field, and
  truncated-data oracles to zero-length entries, wrapping sums, and materialized
  large members, plus injected deadline expiry. Add old/ODC/newc/CRC production
  corpus, sanitizer execution, certified Linux x86-64, and Sonic1
  qualification. CRC validation, multi-window traversal, in-range read-failure
  classification, and malware precedence are implemented with bounded fmap
  windows.

## Rust parser null-context admission — 2026-08-25

- `scan_onenote()`, `cli_scanalz()`, and `scan_lha_lzh()` now reject a null
  parser context as `CL_ENULLARG` before current-layer fmap lookup or C FFI
  reporting. A recognized parser with malformed current-layer state remains
  `CL_EPARSE` with the shared sticky incomplete/non-cacheable marker.
- A focused `rust_map` Check TCase and source guards cover the three parser
  entry points. The host Rust 1.97.1 offline attempt stopped at the existing
  missing OpenSSL development metadata, without installing software. The
  available production-linked container archive is stale relative to this
  source and its mixed C/Rust run is not authoritative; rebuild current C and
  Rust together, then run the TCase, Rust suite, parser corpus, sanitizer,
  materialized large-file, certified Linux x86-64, and Sonic1 gates.

## ARJ declared-header string boundaries — 2026-08-25

- Keep the ARJ filename/comment fmap requests bounded to the exact declared
  header remainder; retain the regression proving a terminator immediately
  outside that remainder is malformed and non-cacheable. The modified Check
  object compiles and the isolated production-linked GCC harness passes 1/1;
  run the complete ARJ corpus, sanitizer and fault-injection matrix, certified
  Linux x86-64 build, materialized large-file case, production-CVD/service
  smoke, and Sonic1 qualification before release certification.

## BinHex header-length preflight — 2026-08-25

- Keep the complete decoded BinHex header check ahead of data/resource length
  reads so truncated streams cannot derive limits from uninitialized bytes. The
  main Check-suite regression and source guards are registered, and the
  production-linked GCC harness passes 1/1; run the full BinHex corpus,
  sanitizer/fault-injection matrix, certified Linux x86-64 build, materialized
  large-file case, production-CVD/service smoke, and Sonic1 qualification.

## Explicit magic-scan ingress map admission — 2026-08-25

- Preserve the top-level `cli_magic_scan()` null-context and missing-fmap
  boundary before any parser dispatch; retain the registered regression and
  source guards, and extend the passing current-source production-linked
  ingress harness to the full scanner/archive build with the parser corpus,
  sanitizer, certified Linux x86-64, materialized large-file,


## CPIO direct-entry context admission — 2026-08-25

- Keep old, ODC, and newc/CRC direct parser calls explicit for null contexts
  and missing maps; run the registered regression against current CPIO-linked
  production objects, then extend the numeric/CRC evidence to full corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, and Sonic1 qualification.

## DMG retained stripe endian conversion — 2026-08-25

- Keep retained in-memory `blkx` stripe records in host order after one
  conversion; repeated ordering, geometry, and reconstruction passes must not
  byte-swap them again.
- Preserve the streamed metadata path's per-record conversion and retain the
  stored-stripe production-path regression. Full DMG corpus, sanitizer,
  materialized large-file, production-CVD, service, and Sonic1 qualification
  remain open.

## MBR native-width partition coordinate admission — 2026-08-25

- Keep primary, extended-chain, boot-record, and intersection coordinate
  arithmetic checked before native-size multiplication or addition; reject
  undersized caller sector sizes before subtracting packed record widths.
- Retain the sparse native-width overflow regression and extend MBR evidence
  to corpus, sanitizer, materialized large-file, production-CVD, service, and
  Sonic1 qualification.
