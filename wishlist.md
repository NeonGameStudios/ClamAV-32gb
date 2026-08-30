# Wishlist

## Rust evidence FFI admission — 2026-08-30

- Keep Rust evidence query and mutation entry points fail-visible for null
  handles and error outputs. Null queries now return safe empty/false values;
  mutation and child-evidence paths reject null state before raw ownership or
  panic-on-null error reporting. Focused regressions and source guards cover
  verdict, alert, indicator, add, and remove operations. Current Rust/C ABI,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  final release qualification remain required.

## Rust CDIFF update and FFI admission — 2026-08-30

- Keep the freshclam/sigtool CDIFF path fail-visible for null verifier
  handles, malformed short signed files, EOF-beyond hash requests, missing
  command remainders, temporary-file flush failures, and signing-service
  failures. The Rust signing path now frees the C-owned signature result and
  no longer asserts on a null service response; focused unit tests and source
  guards cover these boundaries. Current Rust/C ABI, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final release
  qualification remain required.

## Rust signed-database and logger FFI safety — 2026-08-30

- Keep signed-database FFI boundaries fail-visible: reject null certificate
  arrays and verifier handles before raw-slice or `Box::from_raw()` use,
  report invalid intermediate paths and signer strings, and avoid CVD getter
  panics on interior-NUL metadata. Sanitize interior NULs in Rust log messages
  before C dispatch. Source guards cover the new boundaries; Rust/C ABI,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  final release qualification remain required.

## Rust cleanup-helper FFI errors — 2026-08-30

- Keep `glob_rm()` fail-visible for invalid glob patterns instead of allowing
  `glob(...).expect()` to panic across the C ABI. Route null or invalid UTF-8
  strings through the caller-provided `FFIError` output for both `glob_rm()`
  and `mkdir_w32()`. The focused Rust regressions and source guards cover the
  boundaries; current Rust/C ABI execution, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, and final release qualification remain
  required.

## MSPack filename-backed ferror propagation — 2026-08-30

- Keep filename-backed MSPack reads fail-visible when `fread()` sets the
  stream error indicator, including a positive short read; return the
  callback error and preserve `CL_EREAD` rather than treating it as EOF.
- Retain the source guards and add a focused filename-read fault-injection
  case. Current-source GCC, sanitizer, complete MSPack corpus,
  production-CVD/service, materialized-large-file, Sonic1, and final release
  qualification remain required.

## Rust fmap reader destination admission — 2026-08-30

- Keep `FMapReader::read()` bounded by both the remaining map range and the
  caller-provided destination slice; a short destination must never cause a
  slice-overrun panic at the Rust/C parser boundary.
- Retain `reader_never_requests_more_than_the_destination_buffer` and its
  source guards. Rust execution remains pending on the existing OpenSSL/Cargo
  environment, followed by full Rust/C ABI, sanitizer, parser corpus,
  production-CVD/service, materialized-large-file, Sonic1, and final release
  qualification.

## SIS wrapper error-status type preservation — 2026-08-30

- Keep `cli_scansis()` parser and cleanup results in `cl_error_t` storage all
  the way through temporary-directory cleanup. The source guard pins the
  typed call; production-GCC compilation, complete SIS corpus, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final release
  qualification remain open.

## MSPack filename-backed read callback contract — 2026-08-30

- Keep the custom MSPack `read()` callback byte-count correct for complete and
  short filename-backed reads, and return zero for zero-byte requests. The
  current-source GCC callback harness and its GCC ASan/UBSan leak-enabled
  variant pass; complete CAB/CHM corpus, production-CVD/service,
  materialized-large-file, Sonic1, and release qualification remain open.

## MBR zero-length partition admission — 2026-08-30

- Keep non-empty primary and extended MBR entries with zero sectors fail-visible
  before nested scanning; empty entries may retain format-compatible stale
  coordinates. The focused primary-entry regression and source guards cover
  the new boundary. Complete partition corpus, sanitizer, production-CVD/
  service, materialized-large-file, Sonic1, and release qualification remain
  open.

## clamd structured report for empty directory walks — 2026-08-30

- Keep successful structured path and `MULTISCAN` walks that contain no
  scannable files represented by an explicit clean, complete zero-file report;
  do not classify the absence of a per-file report as `RESOURCE_FAILURE`.
  The registered empty-directory daemon regression covers the JSON frame and
  terminator; full command-family parity, production-CVD/service,
  materialized-large-file, Sonic1, and release qualification remain open.

## GPT partition-name diagnostic fallback — 2026-08-30

- Keep the GPT partition-name diagnostic on an explicit empty-string fallback
  when UTF-16 conversion returns `NULL`; full GPT/partition-image corpus,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  final release qualification remain open.

## EGG LZMA stream initialization teardown — 2026-08-30

- Keep EGG streaming LZMA cleanup conditional on a decoder that actually
  initialized. The existing bounded-member regression now injects init
  failure and requires `CL_EUNPACK`, zero output, and no shutdown call;
  complete EGG corpus, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, and release qualification remain.

## YARA VM unaligned pointer operands — 2026-08-30

- Keep bundled YARA jump, rule, and object pointer operands decoded with
  `memcpy()` rather than typed dereferences from packed bytecode. The
  registered valid unaligned-JLE regression and isolated current-source GCC
  plus GCC ASan/UBSan leak-enabled runners pass; full YARA matcher/corpus,
  production-CVD/service, materialized-large-file, Sonic1, and release
  qualification remain.

## HFS+ inline decoder initialization visibility — 2026-08-30

- Keep HFS+ inline decmpfs decoder initialization fail-visible and avoid
  finalizing an uninitialized zlib stream. The registered fault-injected
  regression now requires `CL_EMEM`, exact incomplete state, zero output, and
  cache taint; complete compressed-resource corpus, production-CVD/service,
  materialized-large-file, Sonic1, and release qualification remain.

## XAR LZMA member decoder initialization visibility — 2026-08-30

- Keep failed XAR LZMA member initialization fail-visible with the exact
  incomplete reason while retaining output-buffer cleanup and avoiding
  shutdown of an uninitialized decoder. The source-guarded fault-injected
  regression and focused current-source Docker GCC runner now cover the
  boundary; the runner also passes with GCC
  AddressSanitizer/UndefinedBehaviorSanitizer and leak detection. Complete
  XAR corpus, production-CVD/service, materialized-large-file, Sonic1, and
  release qualification remain.

## NSIS non-solid decoder timeout cleanup — 2026-08-30

- Keep the NSIS non-solid compressed-member timeout branch paired with
  `nsis_shutdown()` after BZIP2 or LZMA initialization. Preserve the
  fail-visible timeout/incomplete result. The disposable current-source GCC
  runner and its GCC ASan/UBSan leak-enabled variant now prove the BZIP2
  timeout/finalization boundary; complete NSIS/SFX corpus,
  production-CVD/service, materialized-large-file, Sonic1, and release
  qualification remain.

## BZIP2 concatenated-stream decoder initialization cleanup — 2026-08-30

- Keep BZIP2 concatenated-stream teardown conditional on a successful active
  `BZ2_bzDecompressInit()` after each stream boundary. The focused
  current-source GCC and GCC ASan/UBSan leak-enabled runners pass injected
  second-stream initialization failure with `CL_EMEM`, a cleared verdict,
  and cache taint; complete BZIP2 corpus, production-CVD/service,
  materialized-large-file, Sonic1, and release qualification remain.

## XAR gzip member decoder initialization cleanup — 2026-08-30

- Keep XAR gzip member initialization fail-visible: retain the explicit
  incomplete `CL_EFORMAT` result, finalize only an initialized zlib stream,
  and route the failure directly through member cleanup so the outer TOC
  loop cannot convert it to clean. The focused current-source GCC and GCC
  ASan/UBSan leak-enabled runners pass the injected member initialization
  failure; complete XAR corpus, production-CVD/service,
  materialized-large-file, Sonic1, and release qualification remain.

## OLE2 MSO decoder initialization cleanup — 2026-08-30

- Keep the OLE2 MSO stream teardown conditional on successful `inflateInit()`
  initialization and preserve the explicit incomplete `CL_EUNPACK` result.
  The isolated current-source production-linked GCC and GCC ASan/UBSan
  leak-enabled runners pass the injected initialization failure; complete
  OLE2/MSO corpus, production-CVD/service, materialized-large-file, Sonic1,
  and release qualification remain.

## HWP raw-deflate decoder initialization cleanup — 2026-08-30

- Keep the shared HWP/HWP5/HWPML raw-deflate cleanup conditional on successful
  `inflateInit2()` initialization, and preserve the explicit incomplete
  `CL_EUNPACK` result. The existing HWP3 regression and isolated current-source
  production-linked GCC plus GCC ASan/UBSan leak-enabled runners pass the
  injected initialization failure; complete HWP/HWPML corpus,
  production-CVD/service, materialized-large-file, Sonic1, and release
  qualification remain.

## InstallShield CAB decoder initialization cleanup — 2026-08-30

- Keep legacy InstallShield CAB teardown conditional on successful
  `inflateInit2()` initialization. Preserve the fail-visible `CL_EUNPACK`
  result and temporary-output cleanup. The source-guarded focused fault
  injection passes in the isolated current-source production-linked GCC and
  GCC ASan/UBSan leak-enabled runners. Complete the InstallShield/CAB corpus,
  production-CVD/service, materialized-large-file, Sonic1, and release
  qualification.

## PE bytecode-unpacker metadata cleanup — 2026-08-30

- Keep the second `cli_scanpe()` bytecode-context allocation failure fail
  visible and destroy the populated PE metadata before returning `CL_EMEM`.
  Retain the source guard, add a current-source fault-injected PE execution
  and sanitizer/leak evidence, then complete the PE unpacker/corpus,
  production-CVD/service, materialized-large-file, Sonic1, and release
  qualification.

## Bytecode preparation context cleanup — 2026-08-30

- Keep `cli_bytecode_prepare2()`'s startup context on one cleanup path when
  the test-mode self-check or a bytecode-mode transition fails after
  allocation. The new cleanup label preserves the original failure status;
  retain the no-engine teardown regression, add focused fault-injected
  execution and sanitizer evidence, then complete bytecode/JIT,
  production-CVD/service, materialized-large-file, Sonic1, and release
  qualification.

## ELF bytecode-context allocation cleanup — 2026-08-30

- Keep `cli_unpackelf()`'s bytecode context cleanup initialized before the
  allocation branch. The current static-Linux fault-injected regression
  verifies `CL_EMEM`, sticky incomplete state, the exact diagnostic, and
  non-cacheability; add current-source GCC and ASan/UBSan runner evidence,
  then complete ELF unpacker/corpus, production-CVD/service,
  materialized-large-file, Sonic1, and final release qualification.

## HFS+ compressed-resource map admission — 2026-08-30

- Keep HFS+ decmpfs resource discovery aligned with the resource map's
  declared type-list and per-type reference-list offsets. Validate map/data
  extents and every compressed-resource block table range before seeking or
  decoding, and finalize initialized zlib streams on all failure exits. The
  current-source declared-offset oracle passes under production GCC and GCC
  ASan/UBSan; keep focused compressed-resource corpus and sanitizer/fault-
  injection coverage open, then complete production-CVD/service,
  materialized-large-file, Sonic1, and final release qualification.

## TAR member data read admission — 2026-08-30

- Keep TAR member staging fail-visible when a data window fails in range or
  ends at the map boundary. Do not substitute fabricated zero bytes; preserve
  `CL_EREAD` versus `CL_EPARSE`, clean up the staged output and temporary
  reservation, and retain the current end-of-map regression. Complete TAR
  corpus, sanitizer, production-CVD/service, materialized-large-file, Sonic1,
  and final release qualification.

## SWF decoder initialization evidence — 2026-08-30

- Keep CWS and ZWS decoder-initialization failures sticky and non-cacheable
  before temporary cleanup, preserving `CL_EUNPACK`; retain the current-source
  zlib fault-injection regression and source guards, and add equivalent LZMA
  fault injection when the release harness is extended. Complete SWF corpus,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  final release qualification.

## clamd dispatch-failure resource ownership — 2026-08-30

- Keep clamd dispatch failure cleanup fail-visible and leak-free: transfer
  INSTREAM descriptors and staged names only after duplicate ownership is
  established, close/unlink them on worker-dispatch failure, and close
  received FILDES descriptors that fail before dispatch. Add focused daemon
  fault injection, then complete production-CVD/service,
  materialized-large-file, Sonic1, and final release qualification.

## InstallShield MSI decompressor cleanup status — 2026-08-30

- Keep `inflateInit()` failure cleanup fail-visible in confirmed InstallShield
  MSI extraction: merge member temporary close/unlink failures with the
  original `CL_EUNPACK`, while retaining sticky incomplete state. Add focused
  fault injection and complete InstallShield/SFX, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final release
  qualification.

## Rust archive metadata file-index ABI boundary — 2026-08-30

- Keep the ALZ/LHA Rust-to-C archive metadata bridge fail-visible when a
  `usize` member index cannot be represented by the callback's 32-bit
  `filepos`; never wrap the index and match metadata against the wrong member.
  Retain the focused narrowing regression and source guard, then complete
  current Rust/C-ABI, archive corpus, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, and final release qualification.

## 7-Zip SFX recovery admission and unaligned header reads — 2026-08-30

- Keep 7-Zip SFX admission fail-closed for zero recovery tuples without a
  recoverable tail header, and preserve ordinary start-header CRC validation
  plus `CL_EREAD` for in-range tail read failures.
- Keep the bytewise fixed-width reads and the weak-candidate regression so
  odd-offset SFX matches remain sanitizer-clean; preserve valid empty archives
  and recovery-mode archives. Complete current-object,
  production-CVD/service, full SFX corpus, materialized-large-file, Sonic1,
  and final release qualification.

## 7-Zip zero-length FilesInfo Name — 2026-08-30

- Keep `FilesInfo/Name` property admission fail-closed: reject a declared
  zero-length property before reading its external flag or forming `size - 1`.
- Retain the CRC-valid malformed-header regression and source guard; the
  isolated current-source SDK oracle passes 1/1 under production GCC and
  Docker ASan/UBSan. Complete current-object, production-CVD/service,
  sanitizer, materialized-large-file, Sonic1, and final 7-Zip release
  qualification.

## Structured scan report allocation output — 2026-08-30

- Keep `cl_scanmap_ex2()` and `cl_scandesc_ex2_with_temporary_bytes()` clear
  caller-provided report outputs before allocation, so a report-allocation
  `CL_EMEM` cannot leave stale ownership published.
- Retain the injected calloc regression for both public APIs, the static
  source guard, and the Linux static-test link wrapper. Complete current
  object, production-CVD/service, sanitizer, materialized-large-file,
  Sonic1, and final release qualification.

## CVD age-directory close status — 2026-08-30

- Keep `cl_cvdgetage()` fail-visible when the signature directory cannot be
  closed; preserve earlier failures and return `CL_EREAD` for a clean walk
  followed by `closedir()` failure.
- Retain the registered close-failure wrapper and source guard. Complete
  current-object, production-CVD/service, sanitizer, materialized-large-file,
  Sonic1, and final release qualification.

## Production CVD unpack failure propagation — 2026-08-30

- Keep Rust CVD unpacking fail-visible for archive-entry enumeration, entry
  path, non-regular-entry, and destination write failures; do not publish a
  partial signature database as successful.
- Retain `unpack_to_propagates_archive_entry_failures` and its source guards.
  Run it with a current Rust toolchain, then complete production CVD/service,
  sanitizer, materialized-large-file, Sonic1, and final release qualification.

## OLE2 XLM/BIFF metadata admission — 2026-08-30

- Keep requested OLE2 digital-signature, XLM/BIFF indicator and language,
  stream-enumeration/type, HWP5-type, and encryption metadata writes
  fail-visible: propagate the original `cli_json*` error and mark the layer
  incomplete instead of allowing a partial metadata result to appear clean.
- Retain the current-source Docker production-GCC compile and source guards;
  add focused JSON fault injection, then complete OLE/VBA/XLM corpus,
  sanitizer, certified Linux x86-64, production-CVD/service,
  materialized-large-file, Sonic1, and final parser/release qualification.

## HWP5 header metadata record admission — 2026-08-30

- Keep `cli_hwp5header()` fail-visible when `RawVersion`, `RawFlags`, or any
  enabled HWP5 flag-array metadata record cannot be allocated or written;
  return the original error and mark the layer incomplete.
- Retain `test_hwp5_header_metadata_record_failure_is_fail_visible`, the
  `cli_jsonint` static-test wrapper, and source guards. Full HWP corpus,
  sanitizer, certified Linux x86-64, production-CVD/service,
  materialized-large-file, Sonic1, and final parser/release qualification
  remain open.

## 7-Zip individual-allocation ceiling — 2026-08-29

- Keep every vendored 7-Zip declared-count allocation below the shared 1 GiB
  individual ceiling as well as native-size product admission; include
  sentinel bytes in direct substream metadata products and fail FilesInfo
  table admission as `CL_EMEM` before allocation.
- Retain the crafted allocation-ceiling regression, current-source Docker
  production-GCC syntax evidence, and source guards. Full 7-Zip/BCJ2 corpus,
  sanitizer, certified Linux x86-64, production-CVD/service,
  materialized-large-file, Sonic1, and final parser/release qualification
  remain open.

## NSIS bundled bzip2 allocation admission — 2026-08-29

- Keep the bundled NSIS bzip2 allocator fail-closed for non-positive signed
  callback arguments, native-size multiplication overflow, and products above
  the shared 1 GiB individual-allocation ceiling.
- Retain the source guard and Docker production-GCC syntax evidence. Complete
  NSIS/SFX corpus, sanitizer, certified Linux x86-64, production-CVD/service,
  materialized-large-file, Sonic1, and final parser/release qualification
  remain open.

## Codepage conversion output ceiling — 2026-08-29

- Keep codepage-to-UTF-8 output sizing behind checked NUL-terminator addition,
  native-width multiplication, and the shared 1 GiB individual-allocation
  ceiling for both direct and iconv retry buffers.
- Retain the invalid-pointer `SIZE_MAX` iconv regression where available,
  source guards, and current-source GCC syntax evidence. Full converter corpus,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  final parser/release qualification remain open.

## Generic hash-table capacity and rehash failure visibility — 2026-08-29

- Keep string/u32 hash-table and hashset capacities behind
  cli_hashtab_table_size() and checked power-of-two rounding; reject native
  or 1-GiB product overflow before allocation.
- Preserve fail-visible growth errors, reset probe state after rehash, release
  failed u32 rehash allocations, and reject oversized len + 1 key copies.
  Retain test_hashtab_capacity_admission_is_fail_visible, the source guards,
  and the current-source runner. Full caller corpus, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final
  parser/release qualification remain open.

## PDFNG string materialization admission — 2026-08-29

- Mark PDFNG working, escape, decrypt, and UTF-conversion string allocation
  failures incomplete before returning a null parse result.
- Retain the no-read over-limit regression and add production-GCC, complete
  PDFNG/string corpus, sanitizer, production-CVD/service, materialized-large-
  file, Sonic1, and final qualification evidence.

## Bytecode interpreter layout-size admission — 2026-08-29

- Keep aligned global, function-value, constant, and context parameter
  layouts behind `cli_bytecode_layout_size_add()` so cumulative totals cannot
  wrap or exceed the individual allocation ceiling.
- Retain `test_bytecode_layout_size_admission_is_fail_visible`, current-source
  GCC compilation, and source guards; complete bytecode execution/JIT,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  parser/release qualification remain open.

## JavaScript-normalizer decoder table admission — 2026-08-29

- Keep decoder delimiter-token and parser-token table products behind
  `cli_jsnorm_table_size()` and the 1-GiB individual-allocation ceiling.
- Preserve decoder append failures and parser token-growth failures through
  the normalizer's sticky error state so HTML and bytecode callers receive a
  fail-visible result. Retain
  `test_jsnorm_table_size_rejects_overflow` and source guards. Full
  JavaScript/HTML corpus, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, and parser/release qualification remain
  open.

## Bytecode VM pointer-table admission — 2026-08-29

- Keep stack and global pointer-registration table growth behind
  `cli_bytecode_table_size_check()` so native multiplication and the 1-GiB
  individual-allocation ceiling are checked before `cli_max_realloc()`.
- Retain sticky `allocation_failed` propagation, the existing
  `test_bytecode_table_size_admission_is_fail_visible` boundary regression,
  and source guards. Full bytecode execution/JIT, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and release
  qualification remain open.

## Bytecode API constructor failure atomicity — 2026-08-29

- Keep hashset, map, inflate, LZMA, BZip2, and JavaScript-normalizer
  constructors from publishing a resource-table count until the new slot has
  initialized successfully; clear the extra slot and preserve the old count
  when initialization fails.
- Retain
  `test_bytecode_resource_constructors_publish_only_initialized_slots` and
  its source guards. Current-source production-GCC compilation and focused
  production-linked execution remain required; complete bytecode execution/JIT,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  release qualification remain open.

## PCRE metadata table admission — 2026-08-29

- Keep PCRE metadata and per-scan offset-state tables behind checked native-size
  admission before allocation, and reject saturated metadata counts before
  count-plus-one arithmetic.
- Retain the source guards and shared table-boundary regression. Full PCRE
  corpus, sanitizer, full-subject, production-CVD/service,
  materialized-large-file, Sonic1, and matcher/release qualification remain
  open.

## AC root table admission — 2026-08-29

- Keep AC list, transition-cleanup, node, pattern, and relative-offset pointer
  tables behind `cli_readdb_table_size()` before mempool growth, and reject
  saturated counters before count-plus-one or capacity arithmetic.
- Preserve transition-tracker rollback on later node-table failure and retain
  the source guards plus shared table-boundary regression. Full AC corpus,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  matcher/release qualification remain open.

## Byte-compare table admission — 2026-08-29

- Keep per-pattern component-pointer and root byte-compare metadata tables
  behind `cli_readdb_table_size()` before mempool allocation, and reject
  saturated metadata counts before increment.
- Retain the shared readdb table-boundary regression and byte-compare source
  guards. Full byte-compare signature corpus, sanitizer, production-CVD/
  service, materialized-large-file, Sonic1, and matcher/release qualification
  remain open.

## Regex matcher table admission — 2026-08-29

- Keep phishing/allow-list suffix buckets and compiled-regex pointer tables
  behind `cli_regex_table_size()` before native-size multiplication; commit
  regex counts and pointers only after allocation succeeds, and preserve
  hash/table failure visibility, rolling back a compiled-regex slot when
  suffix extraction fails.
- Retain `test_regex_table_size_rejects_product_wrap` and its source guards.
  Current `regex_list.c`, `regex_list.h`, and `check_regex.c` compile with
  Docker production GCC, and the isolated current-source UBSan oracle prints
  `regex_table_size_guard_passed`; full phishing/regex corpus, sanitizer,
  service, materialized-large-file, Sonic1, and release qualification remain
  open.

## Phishing URL canonicalizer boundary — 2026-08-29

- Keep `cli_url_canon()` behind null-pointer and three-byte destination-reserve
  validation; cap the internal URL coordinate before pointer formation and
  copy exactly the bounded input length.
- Retain `test_url_canon_rejects_invalid_destination_and_bounds_input` and its
  source guards. Complete phishing corpus, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, and final matcher/release qualification
  remain open.

## Iconv cache table admission — 2026-08-29

- Keep process/thread-local iconv handle-table growth behind
  `cli_iconv_cache_table_size()`; reject native-size or 1 GiB individual
  allocation overflow before updating cache state, and propagate hashtable
  insertion failure.
- Retain `test_iconv_cache_table_size_rejects_product_wrap` and its source
  guards. Current `entconv.c`, `entconv.h`, and `check_str.c` compile with
  Docker production GCC, and the isolated current-source UBSan oracle prints
  `iconv_cache_table_size_guard_passed`; full encoding/converter corpus,
  sanitizer, service, materialized-large-file, Sonic1, and release
  qualification remain open.

## Signature-database table admission — 2026-08-29

- Keep icon, logical-signature, bytecode, YARA string, and database-directory
  tables behind `cli_readdb_table_size()` before native-size multiplication;
  reject saturated fixed-width counters and propagate YARA table insertion
  failures.
- Retain `test_readdb_table_size_rejects_product_wrap` and its source guards.
  Current `readdb.c` and `check_matchers.c` compile with Docker production GCC,
  and the isolated current-source production-linked UBSan oracle prints
  `readdb_table_size_guard_passed`; full production CVD/signature corpus,
  sanitizer, service, materialized-large-file, Sonic1, matcher, and release
  qualification remain open.

## MIME message table admission — 2026-08-29

- Keep MIME argument, encoding, and multipart message tables behind
  `cli_message_table_size()` before count-plus-one arithmetic or
  `cli_max_realloc()`; reject saturated signed counters and mark an
  over-limit multipart representation incomplete.
- Retain `test_message_table_size_rejects_product_wrap` and its source guards.
  Current `message.c`, `mbox.c`, and `check_str.c` compile with Docker
  production GCC, and the isolated current-source production-linked UBSan
  oracle prints `message_table_size_guard_passed`; full MIME/mbox/MHTML
  corpus, sanitizer, production-CVD/service, materialized-large-file,
  Sonic1, parser-family, and release qualification remain open.

## Hash matcher table admission — 2026-08-29

- Keep exact-hash digest arrays, virus-name pointer arrays, and the 64-bit
  size side table behind `cli_hm_table_size()` before `MPOOL_REALLOC2()`;
  reject saturated `uint32_t` item counts before increment or indexed copy.
- Retain `test_hash_table_size_rejects_product_wrap` and its source guards.
  The current matcher-hash source and matcher Check source compile with
  Docker production GCC, and the focused current-source production-linked
  UBSan harness prints `hash_table_size_guard_passed`; full production
  signature-database/corpus, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, parser-family, and release qualification
  remain open.

## HTML normalization pointer-table admission — 2026-08-29

- Keep HTML tag-argument and form-data URL table growth behind
  `cli_html_tag_table_size()`, rejecting native-width/product overflow and
  requests above `CLI_MAX_ALLOCATION` before `cli_max_realloc()`; reject
  negative or saturated signed tag counters before count-plus-one arithmetic.
- Retain `test_html_normalization_table_size_rejects_overflow` and its source
  guards. The current `htmlnorm.c` object and `check_htmlnorm.c` source
  compile with Docker production GCC, and the isolated current-source
  production-linked UBSan harness prints
  `htmlnorm_table_size_guard_passed`; full HTML normalization/form-data
  corpus, sanitizer, production-CVD/service, materialized-large-file,
  Sonic1, parser-family, and release qualification remain open.

## Directory-walk entry-table admission — 2026-08-29

- Keep recursive `cli_ftw()` entry growth behind native-size and individual
  allocation-ceiling checks before incrementing the entry count or indexing a
  newly allocated slot; preserve callback-visible `CL_EMEM` and cleanup.
- Retain `test_cli_ftw_entry_table_size_rejects_overflow` and its source
  guards. The current `others_common.c` object and Check source compile with
  Docker production GCC subject to the known unrelated `cryptff` declaration
  failures in the monolithic translation, and the isolated current-source
  production-linked harness prints `ftw_entry_table_size_guard_passed`; full
  directory-ingress corpus, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, parser-family, and release qualification
  remain open.

## Bytecode JSON API size admission — 2026-08-29

- Keep JSON object and array table growth behind the shared native-width
  count/product helper, rejecting saturated counts before dereference or
  reallocation.
- Keep bytecode JSON name lengths in `size_t`, cap them before forming the
  NUL terminator size, and retain
  `test_bytecode_json_api_admission_is_fail_visible` plus its source guards.
  The current `bytecode_api.c` and Check source compile with Docker production
  GCC, and the isolated current-source production-linked UBSan harness prints
  `bytecode_json_api_guard_passed`; full bytecode JSON corpus/execution,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1,
  parser-family, and release qualification remain open.

## Shared Uniq table-size admission — 2026-08-29

- Keep `uniq_init()` behind checked `uint64_t` table-size derivation,
  native-size validation, and the individual allocation ceiling so a large
  count cannot create an undersized table with an oversized logical capacity.
- Retain `test_uniq_init_rejects_table_size_wrap` and its source guards. The
  current `uniq.c`, `uniq.h`, and `check_uniq.c` pass Docker production-GCC
  syntax checks, and the isolated current-source production-linked harness
  prints `uniq_table_size_guard_passed`; full OLE/Uniq corpus, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, parser-family,
  and release qualification remain open.

## Shared Base64 length admission — 2026-08-29

- Keep Base64 decode length derivation behind native `int`, input-ceiling,
  and checked `3 * len` admission before input inspection; pass only the
  checked decoded length to OpenSSL and preserve fail-visible BIO errors.
- Retain `test_base64_decode_rejects_length_overflow` and its source guards.
  The current `conv.c` and `check_str.c` pass Docker production-GCC syntax
  checks, and the isolated current-source production-linked harness prints
  `base64_length_guard_passed`; full Base64 call-site/corpus, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, parser-family,
  and release qualification remain open.

## cli_str2hex output-size admission — 2026-08-29

- Keep `cli_str2hex()` behind the pre-allocation output-size check so
  `2 * len + 1` is formed in `size_t` only after native-width and
  `CLI_MAX_ALLOCATION` admission; preserve NULL for oversized conversion
  requests.
- Retain `test_str2hex_rejects_output_size_wrap` and its source guards. The
  current `str.c` and `check_str.c` pass Docker production-GCC syntax checks,
  and the isolated current-source production-linked harness prints
  `str2hex_output_size_guard_passed`; full string/call-site corpus,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1,
  parser-family, and release qualification remain open.

## BM pattern-table product admission — 2026-08-29

- Keep BM offset-mode pattern growth and per-scan offset tables behind
  `cli_bm_pattern_table_size()`, rejecting native-width and
  `CLI_MAX_ALLOCATION` product overflow before allocation; reject a saturated
  `bm_patterns` count before `bm_patterns + 1` can wrap.
- Retain `test_bm_pattern_table_size_rejects_product_wrap` and its source
  guards. The current BM source and matcher test pass the Docker production-
  GCC syntax checks, and the isolated current-source harness prints
  `bm_pattern_table_guard_passed`; full production-signature corpus,
  sanitizer, certified Linux x86-64, production-CVD/service,
  materialized-large-file, Sonic1, parser-family, and release qualification
  remain open.

## Aspack block-buffer size admission — 2026-08-29

- Keep Aspack compressed-block work-buffer sizing behind
  `cli_aspack_block_buffer_size()`, performing the `block_size + 0x10e` sum in
  a wide type and rejecting native-width or `CLI_MAX_ALLOCATION` overflow
  before allocation, `stream.iend`, or block copy; preserve sticky incomplete
  state on the confirmed-path rejection.
- Retain `test_pe_aspack_block_buffer_size_rejects_overflow` and its source
  guards. The current Aspack source passes the Docker production-GCC syntax
  check and the isolated current-source harness prints
  `aspack_block_buffer_guard_passed`; full Aspack/PE corpus, sanitizer,
  certified Linux x86-64, production-CVD/service, materialized-large-file,
  Sonic1, parser-family, and release qualification remain open.

## MEW section-table product admission — 2026-08-29

- Keep non-LZMA MEW rebuilt section-table growth behind
  `cli_mew_section_table_size()`, rejecting native-size product overflow and
  requests above `CLI_MAX_ALLOCATION` before `cli_max_realloc()` or section
  writes; preserve sticky incomplete state on the existing rebuild failure.
- Retain `test_pe_mew_section_table_size_rejects_overflow` and its source
  guards. The current MEW source passes the Docker production-GCC syntax
  check and the isolated current-source harness prints
  `mew_section_table_guard_passed`; full MEW/PE corpus, sanitizer, certified
  Linux x86-64, production-CVD/service, materialized-large-file, Sonic1,
  parser-family, and release qualification remain open.

## USE_MPOOL malloc-size admission — 2026-08-29

- Keep `mpool_malloc()` behind checked fragment-overhead and alignment
  additions so a maximal native `size_t` request cannot wrap into a small
  fragment class. Retain the extended
  `test_mpool_allocation_size_wrap_is_fail_visible` regression and source guards;
  the current allocator and matcher test sources pass Docker production-GCC
  syntax checks, and the isolated current-source harness prints
  `mpool_malloc_size_wrap_rejected`. Full allocator-variant, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, parser-family,
  and release qualification remain open.

## Bytecode API map value-size admission — 2026-08-29

- Keep bytecode API map value-table growth behind native-width and
  `CLI_MAX_ALLOCATION` product checks, including the `UINT32_MAX` entry-count
  boundary; allocate and zero only the checked product.
- Retain `test_bytecode_map_value_size_product_is_fail_visible` and its source
  guards. The current hashtab and bytecode test sources pass Docker
  production-GCC syntax checks, and the isolated current-source harness prints
  `bytecode_map_value_product_rejected`. Full bytecode execution, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, parser-family, and
  release qualification remain open.

## Bytecode header table-size admission — 2026-08-29

- Keep the initial bytecode function and type table products behind
  `cli_bytecode_table_size_check()`, rejecting native-size multiplication
  overflow and requests above `CLI_MAX_ALLOCATION` before allocation.
- Retain `test_bytecode_table_size_admission_is_fail_visible` and the source
  guards for the exact ceiling, `SIZE_MAX`, zero-count, and zero-width
  boundaries; the modified source and test translation pass Docker
  production-GCC syntax checks and the isolated current-source helper harness
  passes. Full bytecode execution/JIT, sanitizer, certified Linux x86-64,
  production-CVD/service, materialized-large-file, Sonic1, parser-family,
  and release qualification remain open.

## PEspin rebuilt-output size admission — 2026-08-29

- Keep PEspin rebuilt-output accounting in `uint64_t`; never accumulate
  attacker-controlled section sizes in a signed or narrower native type.
- Retain `cli_pespin_output_size_check()` before the final contiguous output
  allocation, with `test_pespin_output_size_check_is_fail_visible` covering
  the exact 1-GiB ceiling and `UINT64_MAX`; full PE/unpacker corpus, sanitizer,
  certified Linux x86-64, production-CVD/service, materialized-large-file,
  Sonic1, parser-family, and release qualification remain open.

## PE FSG section-table product admission — 2026-08-29

- Keep both legacy PE FSG section-table allocations behind
  `cli_pe_fsg_section_table_size()`, rejecting native-size product overflow
  and requests above `CLI_MAX_ALLOCATION` before allocation or section-table
  writes.
- Retain `test_pe_fsg_section_table_size_rejects_overflow` and its source
  guards. The isolated current-source GCC helper harness passes with
  `pe_fsg_section_table_guard_passed`; full PE/unpacker corpus, sanitizer,
  certified Linux x86-64, production-CVD/service, materialized-large-file,
  Sonic1, parser-family, and release qualification remain open.

## Mpool calloc count-product admission — 2026-08-29

- Keep `USE_MPOOL` calloc fail-closed: reject zero operands and
  `nmemb > SIZE_MAX / size` before multiplying the requested count and element
  size.
- Retain `test_mpool_allocation_size_wrap_is_fail_visible` and the source guard;
  the modified allocator and matcher test source pass Docker production-GCC
  syntax checks with `USE_MPOOL`, and the isolated current allocator harness
  prints `mpool_count_product_rejected`. Full allocator-variant, sanitizer,
  certified Linux x86-64, production-CVD/service, materialized-large-file,
  Sonic1, parser-family, and release qualification remain open.

## AC matcher count-product admission — 2026-08-29

- Keep AC per-scan state allocation products in `size_t` before invoking the
  guarded allocators; reject unrepresentable relative-offset and
  logical-signature count products with `CL_EMEM`.
- Retain `test_ac_initdata_rejects_count_product_wrap` and the source guards.
  The modified AC source and matcher unit translation unit pass the existing
  Docker production-GCC syntax checks; this is allocation-admission and
  compile evidence only. Full production-signature corpus, sanitizer,
  certified Linux x86-64, production-CVD/service, materialized-large-file,
  Sonic1, parser-family, and release qualification remain open.

## XZ index-allocation product admission — 2026-08-29

- Keep XZ index and backward stream-table allocations fail-closed: validate
  block-count and growth arithmetic before multiplying by record sizes, and
  return `SZ_ERROR_MEM` when the result cannot be represented.
- Retain the canonical source guards and Docker production-GCC syntax evidence
  for the modified XZ translation unit. This is static narrower-`size_t`
  evidence only; complete XZ corpus, sanitizer matrix, certified Linux
  x86-64, production-CVD/service, materialized-large-file, Sonic1,
  parser-family, and release qualification remain open.

## 7-Zip allocation-product admission — 2026-08-29

- Keep every vendored 7-Zip array allocation fail-closed: convert the declared
  count once and reject `count > SIZE_MAX/sizeof(T)` before multiplication or
  allocation, returning `SZ_ERROR_MEM` on product overflow.
- Retain the canonical source guard and Docker production-GCC syntax evidence
  for the modified translation unit. This is static portability evidence only;
  a 32-bit runtime, complete 7-Zip/BCJ2 corpus, sanitizer matrix,
  certified Linux x86-64, production-CVD/service, materialized-large-file,
  Sonic1, parser-family, and release qualification remain open.

## HTML raw fallback after normalization admission — 2026-08-29

- Keep a recognized HTML input fail-visible when `MaxHTMLNormalize` prevents
  normalization: preserve sticky incomplete/non-cacheable state and still
  run the bounded raw scan so exact signatures in the original bytes remain
  detectable.
- Retain the current-source production-linked public-API regression, which
  passes 1/1 for the exact strong `Clamav-Unit-Test-Signature.UNOFFICIAL`
  alert, and its GCC ASan/UBSan runner, which passes 1/1 without a sanitizer
  finding. Complete malformed-normalization fallback coverage, coherent
  full-C-ABI relink, full HTML corpus, certified Linux x86-64,
  production-CVD/service, materialized-large-file, Sonic1, parser-family,
  and release qualification remain open.

## GZip legacy-fallback fmap boundary — 2026-08-29

- Keep the legacy zlib fallback bounded to the visible fmap: stage nested and
  memory-backed maps through checked windows before the descriptor-only API,
  charge the staged source against the shared temporary quota, and preserve
  deadline, read, parse, write, rewind, close, and unlink failures.
- Retain `test_gzip_legacy_fallback_stages_visible_map`, the
  `inflateInit2_` fault-injection seam, and source guards. A focused
  current-source production-linked public-API runner passes 1/1 for the
  forced-fallback bounded nested map, and its GCC ASan/UBSan build passes 1/1
  without a sanitizer finding. Complete coherent static production-linked
  fallback execution, legacy-fallback read-failure/cleanup/quota coverage,
  full GZip corpus, certified Linux x86-64, production-CVD/service,
  materialized-large-file, Sonic1, parser-family, and release qualification
  remain open.

## GPT header-location admission — 2026-08-29

- Keep primary and secondary GPT copies bound to their physical locations:
  validation must require the expected `currentLBA` and reciprocal
  `backupLBA` before accepting a header as usable metadata. A misplaced
  secondary copy returns the existing fail-visible invalid-header result and
  disables caching while preserving the usable primary walk.
- Retain `test_gpt_secondary_location_is_fail_visible` and its source guards.
  The current-source GCC ASan/UBSan runner passes 1/1 for the malformed
  secondary location. Complete GPT/partition-image corpus, coherent public
  TCase, production-CVD/service, materialized-large-file, certified Linux
  x86-64, Sonic1, parser-family, and release evidence remain open.

## ELF version admission — 2026-08-29

- Keep confirmed ELF admission fail-closed by requiring both `EI_VERSION` and
  `e_version` to equal the current ELF version before program- or
  section-table metadata is trusted; invalid or reserved values return
  `CL_EFORMAT`, record `ELF file version is invalid`, and disable caching.
- Retain `test_elf_version_is_fail_visible` and its source guards. The
  current-source GCC ASan/UBSan runner passes 2/2 for invalid identification
  and object-header versions. Complete ELF corpus, coherent public TCase,
  production-CVD/service, materialized-large-file, certified Linux x86-64,
  Sonic1, parser-family, and release evidence remain open.

## Legacy CPIO high-word size arithmetic — 2026-08-29

- Keep old-binary CPIO member-size assembly explicitly widened before the
  high-word shift so valid large declared sizes cannot invoke signed-shift
  undefined behavior.
- Retain `test_cpio_old_high_word_size_is_fail_visible` and its source guard.
  The current-source GCC ASan/UBSan direct parser runner passes the short-map
  boundary with `CL_EPARSE` and non-cacheability. Complete CPIO corpus,
  coherent public TCase, production-CVD/service, materialized-large-file,
  certified Linux x86-64, Sonic1, parser-family, and release evidence remain
  open.

## EGG decoded-block CRC verification — 2026-08-29

- Keep EGG block extraction fail-closed by computing CRC-32 over decoded output
  in bounded windows and verifying it against the block header before success
  or nested handoff; cover both scanner streaming and the legacy contiguous
  extraction path.
- Retain the expanded `test_egg_lzma_stream_extracts_bounded_member` valid/
  mismatch regression and source guards. The current-source GCC ASan/UBSan
  runner passes 2/2 for the streaming cases. Complete EGG/SFX corpus,
  coherent public TCase execution, production-CVD/service, materialized large
  file, certified Linux x86-64, Sonic1, parser-family, and release evidence
  remain open.

## DMG truncated-range read classification — 2026-08-29

- Keep DMG `blkx` metadata reads fail-visible by using the full-range fmap
  helper: truncated or out-of-range requests return `CL_EPARSE`, while an
  in-range backing callback failure remains `CL_EREAD`; both outcomes must
  remain incomplete and non-cacheable.
- Retain `test_dmg_truncated_metadata_is_parse_not_read` and its source guards.
  The current-source GCC ASan/UBSan direct runner passes 2/2 for both range
  classes. Complete DMG corpus, coherent public TCase relink/execution,
  production-CVD/service, materialized large-file, certified Linux x86-64,
  Sonic1, parser-family, and release evidence remain open.

## ARJ member CRC verification — 2026-08-29

- Keep ARJ extraction fail-closed: convert the declared `orig_crc`, account
  for CRC-32 across every stored and decompressed output write, and reject a
  mismatch before nested scanning with an incomplete, non-cacheable result.
- Retain `test_arj_member_crc_mismatch_is_fail_visible` and its source guards.
  The current-source direct parser GCC ASan/UBSan accounting runner passes;
  complete public scanner relink/execution, ARJ/ARJ-SFX corpus, sanitizer,
  production-CVD/service, materialized large-file, certified Linux x86-64,
  Sonic1, parser-family, and release evidence remain open.

## ARJ-SFX checksum handoff — 2026-08-29

- Keep the valid prefixed ARJ-SFX regression's stored member CRC declaration in
  sync with the ARJ extractor's fail-closed checksum validation, so the test
  proves SFX admission and exact child matching rather than checksum omission.
- Retain the fixture source guard. Complete ARJ-SFX corpus, coherent public
  TCase execution, sanitizer, production-CVD/service, materialized large-file,
  certified Linux x86-64, Sonic1, parser-family, and release evidence remain
  open.

## AutoIt initial header read status — 2026-08-29

- Keep direct AutoIt header admission fail-visible when the initial version
  byte cannot be read: return `CL_EREAD`, mark the context incomplete, and
  disable caching just as later header reads do.
- Retain the expanded `test_autoit_version_read_failure_is_fail_visible`
  regression and source guard. Current-source AutoIt compile and focused
  execution, complete corpus, sanitizer, production-CVD/service, materialized
  large-file, certified Linux x86-64, Sonic1, parser-family, and release
  evidence remain open.

## ALZ end-marker boundary admission — 2026-08-29

- Keep the bounded ALZ parser fail-closed when bytes remain after the
  end-of-central-directory marker; compare the reader position with the source
  length before returning a successful parse result.
- Retain `trailing_bytes_after_end_marker_are_fail_visible` and its source
  guards. The authoritative current-source isolated Rust 1.97.1 runner passes
  the full ALZ module suite 42/42. Full C-ABI linkage, sanitizer,
  production-CVD/service, materialized-large-file, certified Linux x86-64,
  Sonic1, parser-family, and release evidence remain open.

## 7-Zip FilesInfo stream-count admission — 2026-08-29

- Keep FilesInfo stream metadata fail-closed: reject an index at or beyond
  `numUnpackStreams` and require the consumed stream count to match exactly.
- Retain `test_7z_files_info_stream_count_is_fail_visible` and its source
  guard. The authoritative current-source SDK reader passes the focused GCC
  and GCC ASan/UBSan checks; complete 7-Zip/BCJ2 corpus, coherent
  production-linked TCase, production-CVD/service, materialized large-file,
  certified Linux x86-64, Sonic1, parser-family, and release evidence remain
  open.

## GIF fixed-extension admission — 2026-08-29

- Keep GIF Plain Text and Application extension first-block sizes fail-closed:
  require 12 and 11 bytes respectively before trusting their sub-block
  boundaries.
- Retain `test_gif_fixed_extension_block_sizes_are_validated` and its source
  guards; current-source GCC and GCC ASan/UBSan focused runs pass 2/2 with
  exact incomplete reasons and non-cacheability. Keep complete GIF/image
  corpus, production-linked full-C execution, production-CVD/service,
  materialized large-file, certified Linux x86-64, Sonic1, parser-family, and
  release qualification open.

## ELF metadata deadline admission — 2026-08-29

- Keep `cli_elfheader()` deadline checks at the header, program-table, and
  section-table phase boundaries so metadata-only callers cannot begin a
  required walk after the shared deadline has expired.
- Retain `test_elf_metadata_time_limit_is_fail_visible` and its source guards;
  the isolated current-source production-shared-library check passes 1/1 for
  `CL_ETIMEOUT`, the specific metadata deadline reason, and non-cacheability.
  Complete coherent ELF TCase, corpus, sanitizer, production-CVD/service,
  materialized large-file, certified Linux x86-64, Sonic1, parser-family, and
  release qualification remain open.

## ELF timeout-path isolation — 2026-08-29

- Treat the mixed `elf` TCase timeout SIGSEGV as a stale internal `cli_ctx`
  ABI harness failure, not production parser evidence.
- Retain the disposable direct current-source `cli_scanelf` check linked with
  production shared libraries: it passes 1/1 for `CL_ETIMEOUT`, the canonical
  incomplete reason, and non-cacheability. Replace this provisional isolation
  evidence with a coherent full ELF TCase, then complete ELF corpus,
  sanitizer, production-CVD/service, materialized large-file, certified Linux
  x86-64, Sonic1, parser-family, and release qualification.

## ARJ Huffman code-length admission — 2026-08-29

- Preserve the fail-closed `read_pt_len()` count bound and immediate
  decoder-status checks for malformed compressed members.
- Retain `test_arj_invalid_code_length_count_is_fail_visible` and its source
  guards. Keep current-source production-linked execution, complete ARJ/
  ARJ-SFX corpus, sanitizer, production-CVD/service, materialized large-file,
  Sonic1, and final parser-family/release evidence remain open; the focused
  current-source production-linked decoder run passes 2/2.

## 7-Zip dynamic-buffer growth admission — 2026-08-28

- Keep `DynBuf_Write()` fail-closed for invalid buffer invariants, null
  arguments, `pos + size` overflow, and 25%-growth overflow before allocation.
- Retain `test_7z_dynbuf_growth_overflow_is_fail_visible` and its source guard.
  Keep current-source production-linked execution, complete 7-Zip/BCJ2
  corpus, sanitizer, production-CVD/service, materialized large-file, Sonic1,
  and final parser-family/release evidence open.

## HFS+ volume-header read status — 2026-08-28

- Preserve `CL_EREAD` for an in-range HFS+ volume-header fmap callback
  failure, with `HFS+ volume header could not be read completely`, sticky
  incomplete state, and disabled caching.
- Retain `test_hfsplus_volume_header_read_failure_is_fail_visible` and its
  source guard. Keep complete HFS+ corpus, production-CVD/service,
  sanitizer, materialized large-file, Sonic1, and final parser-family/release
  evidence open.

## GPT secondary-header admission — 2026-08-28

- Keep a malformed secondary GPT header fail-visible even when the primary
  table remains usable: record `GPT secondary header was invalid`, preserve
  primary detections, return `CL_EPARSE` for otherwise clean traversal, and
  disable caching.
- Retain `test_gpt_invalid_secondary_header_is_fail_visible` and its source
  guard. Keep complete GPT/partition corpus, production-CVD/service,
  sanitizer, materialized large-file, Sonic1, and final parser-family/release
  evidence open.

## CPIO invalid-header admission — 2026-08-28

- Keep fully read but invalid CPIO header magic fail-visible for every variant:
  record `CPIO header magic was invalid`, preserve `CL_EFORMAT`, and disable
  caching on the recognized layer.
- Retain `test_cpio_invalid_next_header_is_fail_visible` and its source guard.
  Keep complete CPIO corpus, production-CVD/service, sanitizer, materialized
  large-file, Sonic1, and final parser-family/release evidence open.

## BinHex empty-stream admission — 2026-08-28

- Keep a recognized zero-length BinHex fmap fail-visible: return `CL_EPARSE`,
  record `BinHex stream is empty`, and disable caching.
- Retain `test_binhex_empty_stream_is_fail_visible` and its source guard.
  Keep complete BinHex corpus, production-CVD/service, sanitizer, materialized
  large-file, Sonic1, and final parser-family/release evidence open.

## TAR member output admission — 2026-08-28

- Keep TAR member temporary-output creation failures sticky and non-cacheable;
  return `CL_ETMPFILE` only with the required incomplete state recorded.
- Retain `test_tar_member_output_open_failure_is_fail_visible` and its source
  guard. The focused current-source direct runner passes the expected result.
  Keep complete TAR corpus, production-CVD/service, sanitizer, materialized
  large-file, Sonic1, and final parser-family/release evidence open.

## XAR heap extent admission — 2026-08-28

- Keep confirmed XAR data/EA heap extents bounded by the input fmap after
  checked native-width arithmetic; an out-of-map extent must return
  `CL_EPARSE`, mark the layer incomplete, and disable caching.
- Retain `test_xar_heap_extent_outside_map_is_fail_visible` and its source
  guards. Keep current-source production-linked execution, complete XAR
  corpus, sanitizer, production-CVD/service, materialized large-file, Sonic1,
  and final parser-family/release evidence open.

## UUEncode explicit-map cache binding — 2026-08-28

- Keep `cli_uuencode()` bound to the explicit input fmap before any required
  path can fail, so incomplete reporting disables caching on the map actually
  being inspected.
- Retain `test_uuencode_explicit_map_is_cache_bound` and its source guards.
  Keep complete UUEncode/mail corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and final parser-family/release evidence
  open.

## TNEF message-range fail visibility — 2026-08-28

- Keep message-level TNEF range failures sticky and non-cacheable when a
  declared payload extends past the input; retain bounded fixed-width debug
  metadata reads within each declared attribute payload.
- Retain `test_tnef_message_attribute_range_is_fail_visible` and its source
  guards. The focused current-source GCC direct-parser runner passes the same
  boundary. Complete corpus, production-linked TNEF execution, sanitizer,
  materialized large-file, production-CVD/service, Sonic1, and final
  parser-family/release evidence remain open.

## Structured-detector counter width — 2026-08-28

- Keep cumulative credit-card and SSN detector counts saturating `uint64_t`
  values across bounded fmap windows; retain the configured `uint32_t`
  thresholds and existing `CL_EREAD`/timeout behavior.
- The current-source GCC compile and production-linked `structured_map`
  boundary TCase remain focused evidence. Keep complete detector corpus,
  sanitizer, production-CVD/service, materialized large-file, Sonic1, and
  final release qualification open.

## Service gate ELF-interpreter binding — 2026-08-28

- Keep service ELF interpreter records separate from `ldd`-resolved shared
  libraries: bind each `clamscan`, `clamd`, `clamdscan`, and `clamav-milter`
  executable to its absolute `PT_INTERP` path and SHA-256, and retain the
  before/after immutability check.
- Retain the synthetic service-evidence tamper regression. This does not
  replace authorized production-CVD/service, materialized, sanitizer,
  Linux x86-64, Sonic1, or final release qualification.

## Runtime gate ELF-interpreter binding — 2026-08-28

- Keep the release gate’s ELF interpreter separate from `ldd`-resolved shared
  libraries: record the absolute `PT_INTERP` path and SHA-256, and copy/bind
  only `name => path` runtime-library records through the controlled loader
  directory.
- Retain the verifier’s positive interpreter check and tampered-interpreter
  rejection. The synthetic runtime-evidence control suite passes; this does
  not replace Linux x86-64, sanitizer, production-CVD/service, materialized,
  Sonic1, or final release qualification.

## OneNote legacy reader declared-range EOF — 2026-08-28

- Keep `scan_legacy_reader()` fail-visible when its underlying reader reaches
  EOF before the declared `file_len`; a marker-free truncated legacy document
  must return `Error::Parse` rather than a clean result.
- Retain `legacy_reader_rejects_eof_before_declared_file_length` with the
  existing streaming, boundary, sink-failure, and source-read-failure cases.
  The isolated current-source Rust OneNote module test passes 11/11 with the
  existing Rust 1.97.1 environment.
- Keep complete OneNote corpus, current full-C ABI, sanitizer,
  production-CVD/service, materialized large-file, Sonic1, and parser-family
  qualification open.

## GIF short-signature admission — 2026-08-28

- Keep forced GIF entries shorter than the three-byte signature fail-visible:
  record `Heuristics.Broken.Media.GIF.TruncatedMagic`, return `CL_EPARSE`,
  mark the layer incomplete, and disable caching.
- Retain `test_gif_truncated_signature_is_fail_visible` and its source guards.
  The current GIF and unit sources compile with production GCC, and a
  current-source GCC ASan/UBSan direct-parser runner passes the boundary.
  Keep production-linked Check execution, complete GIF/image corpus,
  certified Linux, materialized large-file, production-CVD/service, Sonic1,
  and final parser-family/release evidence open.

## SIS 9.x fixed-field boundary and header origin — 2026-08-28

- Keep SIS 9.x traversal rooted after the four-UID header and require every
  fixed-width nested field payload before reading its metadata; short
  `ARRAY`, `FILEDATA`, and `COMPRESSED` fields must become incomplete
  `CL_EPARSE` results without crossing field boundaries or underflowing the
  remaining-size counter.
- Retain `test_sis9x_short_nested_field_is_fail_visible` and its source guards.
  The current SIS and unit sources compile with production GCC; a
  current-source GCC direct-parser runner and an ASan/UBSan direct-parser
  runner both pass with sticky incomplete state and disabled caching. Keep
  production-linked Check execution, full SIS corpus, certified Linux,
  production-CVD/service, materialized large-file, Sonic1, and final
  parser-family/release evidence open.

## Shared containment macro coordinate wrap — 2026-08-28

- Keep all shared `CLI_ISCONTAINED*` macros on subtraction-based end-range
  checks so large offsets cannot wrap before containment is decided; preserve
  the zero-length behavior of the `_2` forms.
- Retain `test_containment_macros_reject_coordinate_wrap` and its source
  guards. The current unit source compiles with production GCC, and a
  current-source GCC plus ASan/UBSan header harness passes the near-limit
  valid and wrapped cases. Keep full consumer/parser, production-CVD/service,
  materialized large-file, Sonic1, and final release evidence open.

## File-type signature range preflight — 2026-08-28

- Keep file and partition magic probes on subtraction-based range checks so a
  fixed-width `offset + length` cannot wrap before pointer formation.
- Retain `test_filetype_signature_ranges_do_not_wrap` and its source guards.
  The current source and unit translation unit compile with production GCC; a
  current-source production-linked GCC harness and an ASan/UBSan harness pass
  the oversized-offset file and partition cases. Keep complete type-database
  and dispatch, production-CVD/service, materialized large-file, Sonic1, and
  final parser-family/release evidence open.

## PNG IHDR alignment boundary — 2026-08-28

- Keep PNG IHDR width and height reads alignment-safe by copying the bounded
  four-byte fields through `memcpy` before big-endian conversion.
- Retain `test_png_ihdr_unaligned_input_is_defined` and its source guards. The
  current PNG and unit sources compile with production GCC, the isolated
  current-source production-linked Check TCase passes 1/1, and the
  current-source GCC ASan/UBSan runner passes without a sanitizer finding.
  Keep complete PNG/image corpus, materialized large-file, production-
  CVD/service, Sonic1, and final parser-family qualification open.

## XAR numeric TOC metadata admission — 2026-08-28

- Keep XAR numeric `<offset>`, `<length>`, and `<size>` values strict after
  decimal conversion: XML whitespace is permitted, but negative values and
  trailing non-whitespace bytes must remain malformed and fail-visible.
- Retain `test_xar_numeric_metadata_trailing_bytes_is_fail_visible` and its
  source guards. The current source and unit translation unit compile with
  production GCC flags; the isolated current-source production-linked Check
  TCase passes 1/1, and the current-source GCC ASan/UBSan runner passes.
  Complete XAR corpus, production-CVD/service, materialized large-file,
  Sonic1, and final parser-family qualification remain open.

## Byte-compare unaligned binary-field admission — 2026-08-28

- Keep 2-, 4-, and 8-byte binary byte-compare fields alignment-safe by copying
  mapped bytes through `memcpy` before endian conversion; retain the direct
  one-byte path.
- Retain `test_byte_compare_unaligned_binary_read_is_defined` and its source
  guard. The current matcher and unit source compile with production GCC, and
  the direct ASan/UBSan harness passes. Keep complete byte-compare signatures,
  production CVD/service, materialized large-file, Sonic1, and final release
  evidence open.

## YARA unaligned scalar-read admission — 2026-08-28

- Keep bundled YARA fixed-width fmap reads defined for valid unaligned
  offsets: both map and VM-context helpers copy through `memcpy` after their
  existing bounded-range checks.
- Retain `test_yara_unaligned_integer_read_is_defined` and
  `test_yara_unaligned_context_read_is_defined`. The current source and
  matcher test translation unit compile with production GCC, and standalone
  current-source ASan/UBSan map and context-reader drivers pass. Keep the full
  YARA corpus, coherent full-binary relink, production-CVD/service,
  materialized large-file, Sonic1, and final release qualification open.

## JPEG entropy harness reconciliation — 2026-08-28

- Keep the current JPEG boundary and entropy implementation unchanged: the
  direct `jpeg_map` regressions pass 12/12 when isolated, and a standalone
  current-source GCC ASan/UBSan driver passes the nine single/multi-scan,
  window-boundary, timeout, truncation, malformed-SOS, callback-failure, and
  no-image scenarios.
- Do not use the aggregate mixed-object crash as product evidence. Its
  sanitizer stack ends in the stale `cli_checktimelimit()` implementation
  reading an incompatible `cli_ctx`; the ABI-safe direct driver is clean.
  Preserve the existing coherent public API and nested-thumbnail evidence,
  and keep complete JPEG/image corpus, certified Linux, materialized
  large-file, production-CVD/service, Sonic1, and final release qualification
  open.

## RTF empty and partial object-data admission — 2026-08-28

- Keep RTF `objdata` close handling fail-visible when no decoded byte has
  arrived or when OLE10 magic progress stops before all eight bytes; preserve
  the exact incomplete reason and non-cacheable state.
- Retain the empty-object and partial-magic regressions and source guards. The
  current RTF and unit sources compile with production GCC flags, and the
  isolated ASan/UBSan runner passes both cases. Keep clean full-binary RTF
  execution, complete corpus, production-CVD/service, materialized large-file,
  Sonic1, and final parser-family qualification open.

## OLE2 BIFF terminal-field admission — 2026-08-28

- Keep the WorkBook encryption probe's subtraction-based 16-bit range check;
  valid FilePass encryption fields ending exactly at the bounded BIFF window
  must be accepted, while malformed length skips must fail before leaving the
  window.
- Retain the terminal-FilePass public regression and source guards. The
  current OLE2 and unit sources compile with production GCC flags, and the
  isolated current-source ASan/UBSan reader harness passes the exact-end and
  malformed-skip checks. Keep full OLE/VBA/XLM corpus, clean full-binary
  execution, production-CVD/service, materialized large-file, Sonic1, and
  final release qualification open.

## UUEncode empty-output admission — 2026-08-28

- Keep the post-`fileblobSetFilename()` incomplete-state check so an empty
  attachment cannot normalize a failed temporary-output admission to clean;
  retain the invalid-directory regression and source guards.
- The current source and unit translation unit compile with the production
  GCC flags, and the focused current-source runner returns the expected
  fail-visible state. Keep full UUEncode/mail corpus, sanitizer, certified
  Linux, production-CVD/service, materialized large-file, Sonic1, and release
  qualification open.

## Masked ZIP-SFX focused rerun — 2026-08-28

- Retain the current-source production-linked admission checks: confirmed
  masked central extent, injected `CL_EREAD`, and local-only weak-candidate
  `CL_EFORMAT` behavior all passed with the expected cache/incomplete state.
- This complements the existing exact-child/layer-attribute `zip_sfx` and
  missing-map `zip_map` evidence. Keep full ZIP/SFX corpus, sanitizer,
  certified Linux, production-CVD/service, materialized large-file, Sonic1,
  and release qualification open.

## RIFF detector alignment boundary — 2026-08-28

- Keep RIFF root/chunk fmap views byte-oriented with explicit byte offsets for
  unaligned-safe access; retain the unaligned nested-LIST regression and source
  guards.
- The current RIFF source compiles warning-clean with the production GCC
  flags, and the isolated ASan/UBSan runner passes. Full RIFF corpus,
  certified Linux x86-64, production-CVD/service, materialized large-file,
  Sonic1, and final parser-family qualification remain required.

## Mydoom detector alignment boundary — 2026-08-28

- Keep the Mydoom detector's mapped input pointer byte-oriented so unaligned
  fmap bases never pass through a `uint32_t *`; retain the intentionally
  unaligned regression and source guard.
- Full Mydoom/raw signature, sanitizer, certified Linux x86-64,
  production-CVD/service, materialized large-file, Sonic1, and final
  parser-family qualification remain required.

## AutoIt EA06 debug-string termination — 2026-08-28

- Keep the decrypted EA06 magic diagnostic explicitly NUL-terminated after
  `u2a()` conversion, including the already-single-byte path; retain the
  source guard and production GCC compile evidence.
- Full AutoIt corpus, sanitizer, certified Linux x86-64, production-CVD/
  service, materialized large-file, Sonic1, and final parser-family
  qualification remain required.

## ARJ empty-comment diagnostics — 2026-08-28

- Keep ARJ debug diagnostics safe when a valid minimal header has no normalized
  comment buffer; retain the empty-comment regression and source guards.
- The current ARJ source and unit translation unit compile with the production
  GCC flags, and the disposable current-source production-library runner
  passes with debug logging enabled. Complete ARJ corpus, sanitizer, certified
  Linux x86-64, production-CVD/service, materialized large-file, Sonic1, and
  final parser-family qualification remain required.

## APM fixed-width debug fields — 2026-08-28

- Keep fixed-width APM name/type diagnostics precision-bounded and retain the
  explicit native-width intersection-index format. The current APM source
  compiles with the production GCC warning flags, and the disposable ASan/UBSan
  fixture passes without a finding.
- Retain `test_apm_fixed_width_debug_fields_are_bounded` and its source guards;
  complete APM corpus, sanitizer, certified Linux x86-64,
  production-CVD/service, materialized large-file, Sonic1, and final
  parser-family qualification remain required.

## APM nested partition-name termination — 2026-08-29

- Keep fixed-width APM partition names explicitly NUL-terminated before nested
  fmap metadata duplication. The current-source GCC object compile and the
  disposable production-library ASan/UBSan full-width-name fixture pass;
  retain the full-width name/type corpus coverage and source guards.
- Complete APM corpus, sanitizer, certified Linux x86-64,
  production-CVD/service, materialized large-file, Sonic1, and final
  parser-family qualification remain required.

## ALZ empty-member accounting — 2026-08-28

- Keep ALZ extraction accounting ahead of empty-member cleanup so a successful
  empty member cannot expose the preceding member's size to the total-size
  limit. Retain the three-member boundary regression and the source guard.
- The native Rust 1.97.1 Docker harness reached dependency compilation but was
  killed with exit 137 before test execution; complete ALZ corpus, native
  Rust, sanitizer, certified Linux x86-64, production-CVD/service,
  materialized large-file, Sonic1, and final parser-family qualification
  remain required.

## 7-Zip FilesInfo property-boundary admission — 2026-08-28

- Keep every known `FilesInfo` property within its declared payload and
  reject both short and oversized `EmptyStream`, `EmptyFile`, name,
  attribute, and timestamp records before subsequent header IDs are parsed.
- Retain `test_7z_files_info_property_boundary_is_fail_visible`, the 3/3
  current-source production-linked 7z TCase, and source guards. Complete
  7-Zip corpus, sanitizer, certified Linux x86-64, production-CVD/service,
  materialized large-file, Sonic1, and final parser-family qualification
  remain required.

## 7-Zip archive-property skip propagation — 2026-08-28

- Keep every declared archive-property skip fail-visible; a truncated
  property must return `CL_EPARSE`, mark the layer incomplete, and disable
  caching before following any subsequent IDs.
- Retain `test_7z_archive_property_truncation_is_fail_visible`, the 2/2
  current-source production-linked 7z-property TCase, and source guards.
  Complete 7-Zip corpus, sanitizer, certified Linux x86-64,
  production-CVD/service, materialized large-file, Sonic1, and final
  parser-family qualification remain required.

## Bundled YARA instruction-stream admission — 2026-08-28

- Keep bundled YARA rule code length explicit and bounded to the contiguous
  64 KiB code-page contract; reject arena spill into a non-contiguous page
  before the matcher stores the rule.
- Keep matcher admission fail-visible for unknown opcodes, truncated
  fixed-width operands, out-of-range or operand-interior jump targets, data
  after `OP_HALT`, and missing terminal `OP_HALT`; return `CL_EPARSE`, mark
  the layer incomplete, and disable caching.
- Retain the truncated-operand and invalid-jump regressions, the current-source
  GCC compilation, and the 15/15 isolated production-linked YARA TCase. Keep
  full YARA corpus, sanitizer, certified Linux x86-64, production-CVD/service,
  materialized large-file, Sonic1, and final release qualification open.

## HWP3 variable-length native-width admission — 2026-08-28

- Keep reserved, field-code, cross-reference, and drawing special-character
  lengths checked in native-width arithmetic before paragraph traversal; a
  wrapped `UINT32_MAX` value must return an incomplete parse before nested
  bytes are treated as a valid suffix.
- Retain `test_hwp3_variable_length_native_addition_is_fail_visible`, the
  3/3 current-source production-linked GCC regression, and source guards.
  Complete HWP3 corpus, sanitizer, certified Linux x86-64,
  production-CVD/service, materialized large-file, Sonic1, and final
  parser-family qualification remain required.

## PDF object-stream pair-coordinate admission — 2026-08-28

- Keep object-stream helpers fail-visible for null PDF/output/stream
  arguments, and reject pair cursors at or beyond the decoded pair table
  before forming pointers or subtracting native-width offsets.
- Retain `test_pdf_object_stream_pair_bounds_are_fail_visible` and the source
  guards. Complete PDF corpus, sanitizer, certified Linux x86-64,
  production-CVD/service, materialized large-file, Sonic1, and final
  parser-family qualification remain required.

## PDF legacy dictionary-width admission — 2026-08-28

- Keep stream and encryption dictionaries within the signed `int` width used
  by the legacy PDF dictionary helpers. Validate pointer distances and object
  sizes before conversion, and reject invalid or oversized values as sticky
  incomplete, non-cacheable results.
- Retain `test_pdf_legacy_dictionary_length_boundary_is_fail_visible` and the
  source guards; the null/normal/limit oracle passes in the existing Docker
  GCC environment. Keep full PDF corpus, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, and final PDF qualification open.

## MSPack CAB/CHM output close failures — 2026-08-28

- Keep CAB and CHM decoder output `fclose()` failures fail-visible as
  `CL_EWRITE`, with sticky incomplete state and a non-cacheable input fmap;
  cleanup must preserve earlier parser, timeout, read, and detection results.
- The current-source production-linked GCC regression passes both the CAB and
  CHM corpus close-failure paths. Keep complete MSPack corpus, sanitizer,
  certified Linux x86-64, production CVD/service, materialized large-file,
  Sonic1, and final release qualification open.

## Crypto key-file close failures — 2026-08-28

- Keep successful PEM parsing followed by `fclose()` failure fail-visible and
  release the parsed private key or certificate/CRL object before returning.
- The current-source production-linked GCC regression injects close failure
  through both key loading and key-file signing, then verifies successful
  loading and signing with normal close behavior. Keep full certificate/CRL
  close-failure coverage, production CVD/service, sanitizer, certified Linux
  x86-64, materialized large-file, Sonic1, and final release qualification
  open.

## Signature counting and hash-stream I/O — 2026-08-28

- Keep line-based signature counting fail-visible: stop on the actual
  `fgetc()` result, preserve input read and source-close failures, and never
  publish a partial count to loader progress. Public `cl_countsigs()` must
  reject a null path and preserve directory enumeration and close failures.
- The focused production-link fault-injection test covers signature-file
  reads/closes, directory reads/closes, and hash-file reads/closes. Keep full
  current-source execution, complete CVD/service parity, sanitizer, certified
  Linux x86-64, materialized large-file, Sonic1, and final release
  qualification open.

## UDF descriptor-size arithmetic — 2026-08-28

- Keep all UDF variable-descriptor size construction checked in native-width
  arithmetic. File-identifier and file-entry indexing and direct allocation
  descriptor parsing must fail visibly before a wrapped size can create or
  expose an incomplete copied descriptor.
- The shared size-add helper is used by all three UDF size consumers; the
  focused current-header oracle passes normal, overflow, and null-output cases,
  and the UDF source passes warning-enabled GCC syntax checking. Keep
  production-linked UDF corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and final UDF qualification open.

## HFS+ compressed-resource index width — 2026-08-28

- Keep compressed-resource instance accumulation and packed reference-entry
  multiplication in checked 64-bit arithmetic. Convert both the reference
  seek offset and the resource data offset to native `off_t` only after
  round-trip validation, and preserve a sticky incomplete, non-cacheable
  result for overflow or unrepresentable offsets.
- The current HFS+ source passes warning-enabled GCC syntax checking, and an
  isolated current-header oracle covers null, ordinary, and overflowing
  reference indices. Keep production-linked HFS+ corpus, sanitizer,
  production-CVD/service, materialized large-file, Sonic1, and final HFS+
  qualification open.

## HFS+ compressed-resource block-offset admission — 2026-08-28

- Keep compressed-resource block-table offsets in checked 64-bit arithmetic
  before converting to native `off_t` and seeking. Negative, overflowing, or
  non-representable coordinates must remain sticky incomplete and
  non-cacheable.
- Retain the null, ordinary, and overflowing
  `cli_hfsplus_resource_block_offset()` oracle. Keep production-linked HFS+
  corpus, sanitizer, production-CVD/service, materialized-large-file, Sonic1,
  and final HFS+ qualification open.

## UnRAR declared-output bound — 2026-08-28

- Keep optional UnRAR extraction bounded by the member's declared unpacked
  size. Count decoder callback output before the backend writes it, reject a
  cumulative overrun with a dedicated bridge status, and preserve an
  incomplete, non-cacheable public result through scanner cleanup.
- The scanner now passes the declared 64-bit member size to the bridge;
  `test_rar_declared_output_limit_is_fail_visible` checks the bound and
  `CL_EUNPACK` mapping, and the C/GCC and C++/G++ source checks pass. Keep
  backend-enabled execution, complete RAR corpus, sanitizer,
  production-CVD/service parity, materialized large-file, Sonic1, and final
  RAR qualification open.

## Legacy Word macro external-name span — 2026-08-28

- Keep `MacroExtNames` traversal byte-span based and bounded by the declared
  Word macro directory. The legacy reader must consume every valid external
  name before interpreting the following directory record, and all 0x03,
  menu, external-name, and internal-name skips must remain inside that range.
- The two-record current-source regression is GCC syntax-checked and passes in
  an isolated current VBA-object harness linked with the existing production
  shared library. Keep full production-linked unit execution, malformed
  Word/OLE corpus, sanitizer, production-CVD/service, materialized large-file,
  Sonic1, and final OLE/VBA qualification open.

## OLE2 output-write failure visibility — 2026-08-28

- Preserve sticky incomplete and non-cacheable state when OLE2 embedded
  streams or MSO inflation cannot write their temporary output completely;
  return the specific `CL_EWRITE` result through the existing cleanup path.
- The wrapped-write regression is registered and current-source GCC syntax
  checks pass. Keep production-linked execution, complete OLE/VBA/XLM corpus,
  sanitizer, production-CVD/service, materialized large-file, Sonic1, and
  final OLE2 qualification open until the full unit binary can be relinked.

## PE short-entrypoint legacy-path boundary — 2026-08-28

- Keep short PE32 entry-point windows out of fixed-offset legacy heuristic and
  unpacker paths without returning a cacheable clean result before the common
  `BC_PE_UNPACKER` handoff. Mark the skipped inspection incomplete and
  non-cacheable with an explicit reason.
- The deterministic regression fixture is source-compiled, and the isolated
  current-object smoke harness reports `CL_SUCCESS`, the expected incomplete
  reason, and `dont_cache_flag=1`. Production-linked unit execution remains
  open because the reusable container could not relink the full test binary;
  keep complete PE/unpacker corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and final PE qualification open.

## UnRAR operational status propagation — 2026-08-28

- Preserve UnRAR create, close, read, and write failures as distinct bridge
  statuses and map them to fail-visible public ClamAV results instead of
  flattening them to a generic format error. The gated
  `test_rar_backend_error_mapping_is_fail_visible` regression covers the
  mapping when UnRAR is enabled.
- Keep optional UnRAR extraction, production-CVD/service parity, sanitizer,
  materialized large-file, Sonic1, and final RAR qualification open until a
  backend-enabled production build exercises the complete path.

## Conditional parser dispatch status initialization — 2026-08-28

- Keep `cli_magic_scan()`'s local parser result initialized to `CL_SUCCESS`
  before conditional parser dispatch. Disabled or non-applicable branches
  must not merge indeterminate status into the scan result.
- The current-source production-linked `dispatch_status` fixture passes 1/1
  for disabled archive/document branches; the existing OneNote dispatch
  regression also covers the enabled malformed-parser branch. Keep the
  complete dispatch matrix, sanitizer, production-CVD/
  service, materialized large-file, Sonic1, and final release qualification
  open.

## fmap staged-copy read-failure evidence — 2026-08-28

- Keep `fmap_dump_to_file()` fail-visible for a backing-read failure after a
  partial copy: return `CL_EREAD`, remove the partial temporary file, and
  leave output ownership unset. This is the staging contract used by RAR and
  other fallback paths.
- The injected current-source production-linked GCC `fmap_dump_read_failure`
  fixture passes 1/1 over a `BUFSIZ+1` map and verifies the error, cleared
  output name, and invalid output descriptor. Keep optional UnRAR extraction,
  sanitizer, production-CVD/service, materialized large-file, Sonic1, and
  final RAR/parser-family qualification open.

## ELF header-size admission — 2026-08-28

- Require `e_ehsize` to cover the known ELF32 or ELF64 file-header fields and
  remain within the containing map before accepting program- or section-table
  metadata; permit in-map future extension bytes as the ELF ABI allows. An
  undersized declaration must return `CL_EFORMAT`, record the sticky
  incomplete reason `ELF file header size is invalid`, and disable clean-result
  caching.
- The current-source production-linked GCC fixture passes 6/6 across both ELF
  classes, covering undersized declarations, out-of-map extensions, and
  permitted in-map extensions. Keep complete ELF corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
  final parser-family qualification open.

## Mach-O load-command alignment admission — 2026-08-28

- Enforce the Mach-O format’s load-command alignment: command sizes must be
  multiples of four for 32-bit images and eight for 64-bit images. Misaligned
  sizes must fail before command-specific parsing and leave the layer
  incomplete/non-cacheable.
- The current-source production-linked GCC fixture passes 2/2 for malformed
  32-bit and 64-bit command sizes. Keep complete Mach-O corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and final parser-family qualification open.

## Bytecode output ownership and status propagation audit — 2026-08-27

- Keep partial bytecode writes fail-visible while retaining only the
  physically materialized prefix in `written` and `temporary_reserved`; the
  unmaterialized suffix must be released immediately and all remaining
  reservation must be released by context cleanup.
- Keep `cli_bcapi_extract_new()` on its existing `int32_t` callback ABI while
  returning exact ClamAV status codes, and preserve those output failures
  through both interpreter/JIT runner paths. Truncation failures must upgrade
  `CL_VERIFIED` and `CL_BREAK` as well as clean status.
- Keep `cli_bytecode_runhook()` as the sole owner of bytecode output handoff,
  rewind, nested scan, reservation release, and cleanup; Mach-O must not
  reclaim a result a second time.
- The current-source production-linked bytecode regressions pass for
  materialized short-write accounting and runner-level write-failure
  propagation. Rebuilt Mach-O cases pass `macho_fat` 2/2,
  `macho_sections` 1/1, `macho_corpus` 2/2, `macho_unsupported` 2/2,
  `macho_map` 1/1, and `macho_boundary` 1/1. Keep complete bytecode
  fixture/interpreter/JIT and output-fault coverage, sanitizer, certified
  Linux x86-64, materialized large-file/resource, production-CVD/service,
  Sonic1, and final parser-family qualification open.

## LHA/LZH completion and header-allocation audit — 2026-08-27

- Keep every parsed header under the cumulative 1 GiB fallible allocation
  admission in the provenance-pinned local `delharc` 0.6.1 fork; configured
  cap failures remain `CL_ERESOURCE`, allocator failures remain `CL_EMEM`, and
  the same limit must apply to every subsequent member header.
- Keep physical EOF distinct from the required zero archive terminator. Reject
  any `-lhd-` directory with nonzero compressed or original size, report
  unsupported methods as incomplete `CL_EUNPACK`, and send zero-byte regular
  members through the ordinary nested scanner so root/child `MaxFiles`
  accounting remains inclusive.
- The offline vendored decoder suite passes 13/13 plus doctests, the production
  Rust archive rebuilds with the existing Rust 1.97.1 environment, and the
  current-source production-linked GCC `rust_lha` case passes 9/9 including
  all 13 nested-PNG corpus archives. Keep complete LHA variant corpus,
  sanitizers, certified Linux x86-64, materialized large-file/resource
  evidence, production-CVD/service parity, Sonic1, and final parser-family
  qualification open.

## Signature database and hash-stream I/O audit — 2026-08-27

- Keep line-based signature loading and shared hash generation fail-visible on
  input-read and source-close failures; never publish a digest from incomplete
  input and release a digest whose source close failed.
- The current sources pass the production warning-enabled GCC syntax checks.
  Keep injected read/close-failure execution, production CVD/service,
  sanitizer, certified Linux x86-64, materialized large-file, Sonic1, and
  release qualification open.

## GIF LZW admission and image completion audit — 2026-08-27

- Keep the image LZW minimum-code-size byte on the fixed-range reader: values
  outside 2–8 must be incomplete/non-cacheable, truncation must remain a parse
  result, and fully in-range callback failures must preserve `CL_EREAD`.
- The warning-clean current GIF source and coherent production-linked harness
  pass `gif` 9/9, `gif_api` 1/1, and `gif_corpus` 1/1 across a complete valid
  one-pixel image, invalid low/high code sizes, injected read failure, exact
  missing-trailer behavior, and exact nested overlay matching. Keep complete
  GIF corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## MIME direct-context and first-line admission audit — 2026-08-27

- Keep `cli_mbox()` fail-visible at its direct boundary: null context or a
  valid fmap without the required engine/options returns `CL_ENULLARG` before
  parser traversal, while missing fmap remains incomplete `CL_EPARSE`.
- Keep the initial MIME line bounded and explicitly NUL-terminated before
  chomp/header handling. The MIME source is warning-clean under the production
  GCC flags, and the coherent production-linked `mail_map`, `mail`,
  `mail_api`, `mail_partial`, and `mhtml` cases pass 2/2, 10/10, 2/2, 1/1,
  and 4/4. Complete MIME/mbox/MHTML corpus, sanitizer, certified Linux x86-64,
materialized large-file, production-CVD/service, Sonic1, and parser-family
qualification remain open.

## JPEG SOS and entropy completion audit — 2026-08-27

- Keep JPEG clean completion conditional on a valid SOS and an observed EOI.
  Entropy traversal uses fixed 8 KiB reads, preserves state across read-window
  boundaries, handles stuffed, fill, TEM, restart, and multi-scan markers, and
  checks the shared deadline between windows.
- Keep malformed SOS, entropy truncation, metadata-only EOF, and EOI-before-
  scan fail-visible and non-cacheable; preserve `CL_EREAD` for a fully in-range
  entropy callback failure. The current-source production-linked `jpeg_map`
  case passes 13/13 and `jpeg_corpus` passes 1/1. Complete JPEG/image corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain open.

## XAR parser engine admission — 2026-08-27

- Keep `cli_scanxar()` fail-visible when a recognized fmap is supplied without
  the engine required by shared limit checks and temporary-output cleanup;
  return `CL_ENULLARG` before timing, TOC, or member work.
- The current-source production-linked GCC `xar_map` case passes 2/2; `xar`
  passes 9/9, `xar_metadata` 1/1, `xar_corpus` 1/1, and `xar_subdoc` 1/1.
  Keep complete XAR parser-family, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release
  qualification open.

## HWP3 direct-entry options admission — 2026-08-27

- Keep `cli_scanhwp3()` fail-visible when a valid fmap and engine are supplied
  without `ctx->options`; the direct entry now returns `CL_ENULLARG` before
  `SCAN_COLLECT_METADATA` can dereference the missing options object. The
  current-source production-linked GCC `hwp3_map` case passes 3/3, while
  `hwp3_api` remains 1/1 and `hwp3_corpus` remains 1/1. Keep complete HWP3
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## HWP3 metadata failure visibility — 2026-08-28

- Keep `cli_scanhwp3()` fail-visible when metadata collection is requested and
  any HWP3 header, document-info, summary, information-block, font-count,
  style-count, or paragraph-count record cannot be allocated or written. The
  direct HWP3 path now checks every `cli_json*` result, returns the failure
  status, marks the layer incomplete, and disables caching; the allocation
  boundary records `HWP3 font-count metadata could not be allocated` and the
  document-info record boundary records
  `HWP3 document-info name metadata could not be recorded`.
- The current-source production-linked GCC `hwp_fontmeta_isolated` fixture
  passes 2/2 for injected `FontCounts` allocation and document-info record
  failures, including the exact sticky reasons and non-cacheability. Keep
  full-C ABI-consistent HWP3 corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification open.

## OneNote public compatibility fallback validation — 2026-08-27

- Validate the complete legacy stream before the public `OneNote::from_bytes()`
  compatibility iterator is returned after modern-parser rejection. Magic-only
  and truncated legacy inputs now return `Error::Parse`; the current-source
  Rust OneNote unit filter passes 10/10, while production-linked `rust_onenote`
  passes 2/2 and `rust_map` passes 1/1. Keep full OneNote corpus, current
  full-C ABI, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release qualification open.

## ISO direct parser context evidence — 2026-08-27

- Add and register a direct null-context regression alongside the existing ISO
  missing-map, missing-engine, read-failure, and extent-boundary checks. The
  current-source production-linked GCC `iso_map` case passes 14/14, and the
  existing `iso` corpus case passes 1/1 across the materialized logo fixtures
  with exact nested PNG matching. Keep complete ISO corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification open.

## InstallShield direct parser context evidence — 2026-08-27

- Add and register null-context regressions for both confirmed InstallShield
  direct entry points alongside the existing missing-map check. The
  current-source production-linked GCC `ishield_map` case passes 2/2; the
  existing `ishield_sfx` case passes 1/1 with exact nested child matching.
  Keep complete InstallShield MSI/legacy/CAB corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification open.

## HWPOLE2 direct parser context evidence — 2026-08-27

- Add and register a direct null-context regression alongside the existing
  HWPOLE2 missing-map and public-API prefix-read checks. The current-source
  production-linked GCC `hwpole2_map` case passes 3/3, and the isolated
  `hwpole2_corpus` case passes 1/1 over the materialized `clam.ppt` payload
  wrapper with exact nested child matching. Keep complete HWPOLE2 corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## GPT direct parser context evidence — 2026-08-27

- Add and register a direct null-context regression alongside the existing GPT
  read and validation boundaries. The current-source production-linked GCC
  `gpt` case passes 5/5, `partition_map` remains 4/4, and the isolated
  `gpt_corpus` case passes 1/1 over the CRC-validated synthetic image with
  exact nested child matching. Keep complete GPT/partition-image corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## GIF direct parser context evidence — 2026-08-27

- Add and register a direct null-context regression alongside the existing
  GIF validation and missing-map checks. The current-source production-linked
  GCC `gif` case passes 8/8, `gif_api` passes 1/1, and the rebuilt
  `gif_corpus` overlay case passes 1/1 with exact child matching. Keep complete
  GIF corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## 7-Zip direct parser context evidence — 2026-08-27

- Add and register a null-context regression alongside the existing confirmed
  7-Zip missing-map check. The current-source production-linked GCC `7z_map`
  case passes 2/2; the existing `7z` case passes 8/8, `7z_sfx` 1/1, and
  `7z_sfx_corpus` 1/1. Keep full BCJ2/archive corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
parser-family qualification open.

## APM direct parser context evidence — 2026-08-27

- Add and register a null-context regression alongside the existing confirmed
  APM missing-map and partition-read checks. The current-source production-
  linked GCC `apm_map` case passes 3/3; the existing `apm` case passes 5/5 and
  `apm_corpus` 1/1. Keep full partition-image corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification open.

## Direct parser context evidence — 2026-08-27

- Add and register null-context regressions for the DMG, XDP, HWPML, and HFS+
  direct entries, alongside their existing map/engine checks. Current-source
  production-linked GCC map cases pass DMG 9/9, XDP 3/3, HWPML 3/3, and HFS+
  13/13, including the expanded null-context checks. Complete parser corpora,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain open.

## RTF direct-entry context and engine evidence — 2026-08-27

- Keep the RTF direct entry fail-visible for null context, missing fmap, and a
  valid fmap without the engine required by temporary cleanup. Dedicated
  null-context and missing-engine regressions are registered alongside the
  existing missing-map check. After rebuilding `rtf.c` from the authoritative
  source, the current-source production-linked GCC `rtf_map` case passes 11/11
  and the parser case passes 1/1; complete RTF
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain open.

## PDF direct-entry context evidence — 2026-08-27

- Add and register a direct null-context regression alongside the existing
  public PDF map/read-failure test. The current-source production-linked GCC
  `pdf_map` case passes 2/2 for both entry-state/error paths and the existing
  `pdf` parser case passes 14/14; complete PDF corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
 production-CVD/service, Sonic1, and parser-family qualification remain
  open.

## TIFF direct-entry context evidence — 2026-08-27

- Add and register a direct null-context regression alongside the existing
  TIFF missing-map check. The current-source production-linked GCC `tiff_map`
  case passes 2/2 for both entry states; complete TIFF corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification remain open.

## UDF direct-entry context evidence — 2026-08-27

- Add and register a direct null-context regression alongside the existing
  UDF map admission checks. The current-source production-linked GCC
  `udf_map` case passes 11/11 across the expanded entry-state set and existing
  boundary checks; complete UDF corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain open.

## TNEF direct-entry context evidence — 2026-08-27

- Add and register a direct null-context regression alongside the existing
  missing-map test; the current-source production-linked GCC `tnef_map` case
  passes 2/2. Full TNEF corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  remain open.

## DMG parser engine admission — 2026-08-27

- Keep `cli_scandmg()` fail-visible when a recognized fmap is supplied
  without the engine required by retained XML staging and cleanup; return
  `CL_ENULLARG` before trailer inspection.
- The current-source production-linked GCC `dmg_map` case passes 9/9 and
  `dmg` passes 6/6. Keep complete DMG corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification open.

## MSXML streaming helper and XDP engine admission — 2026-08-27

- Keep the shared streaming MSXML helper fail-visible when a recognized fmap
  is supplied without an engine required by Base64/materialization callbacks;
  return `CL_ENULLARG` before parser work.
- The rebuilt current-source production-linked GCC `xdp_map` case passes 3/3,
  `xdp` passes 3/3, and `xdp_corpus` passes 1/1. Existing MSXML evidence
  remains `msxml_map` 2/2, `msxml` 5/5, and `msxml_corpus` 1/1. Keep complete
  XDP/DMG/XML corpus, sanitizer, certified Linux x86-64, materialized
large-file, production-CVD/service, Sonic1, and parser-family qualification
open.

## Scan-level metadata JSON cleanup-status audit — 2026-08-27

- Preserve requested `keeptmp` metadata JSON write and close failures as
  `CL_EWRITE`/incomplete without hiding detections or earlier errors.
- Add focused injected write/close report regressions and source guards. Keep
  full service, sanitizer, production-CVD, Sonic1, and release qualification
  open.

## HWP3 parser engine admission — 2026-08-27

- Keep `cli_scanhwp3()` fail-visible when a recognized fmap is supplied
  without the engine required by paragraph recursion limits; return
  `CL_ENULLARG` before HWP3 traversal.
- The current-source production-linked GCC `hwp3_map` case passes 2/2,
  `hwp3_api` passes 1/1, and `hwp3_corpus` passes 1/1. Keep complete HWP3
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## MSXML parser engine admission — 2026-08-27

- Keep `cli_scanmsxml()` fail-visible when a recognized fmap is supplied
  without the engine required by Base64/callback materialization cleanup;
  return `CL_ENULLARG` before XML reader creation or cleanup.
- The current-source production-linked GCC `msxml_map` case passes 2/2,
  `msxml` passes 5/5, and `msxml_corpus` passes 1/1 across the XML Word/Excel
  dispatch paths. Keep complete XML corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification open.

## HWPML parser engine admission — 2026-08-27

- Keep `cli_scanhwpml()` fail-visible when a recognized fmap is supplied
  without the engine required by decoded-attachment cleanup; return
  `CL_ENULLARG` before XML traversal or cleanup.
- The current-source production-linked GCC `hwpml_map` case passes 3/3, the
  parser boundary case passes 2/2, and `hwpml_corpus` passes 1/1. Keep
  complete HWPML/XML corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  open.

## OLE2 extraction engine and options admission — 2026-08-27

- Keep exported `cli_ole2_extract()` fail-visible when a recognized fmap is
  supplied without the engine or scan options required by OLE2 admission and
  metadata collection; return `CL_ENULLARG` before OLE2 header inspection.
- The current-source production-linked GCC `ole2_map` case passes 4/4 and
  `ole2_xlm` passes 2/2. A broader mixed relink failed one PPT child detection
  and crashed in the timeout case through the known mixed old/current
  `cli_ctx` ABI, so retain the full OLE2 corpus gate until a clean full C-ABI
  rebuild. Keep complete OLE/VBA/XLM corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification open.

## HFS+ parser engine admission — 2026-08-27

- Keep `cli_scanhfsplus()` fail-visible when a recognized fmap is supplied
  without the engine required by temporary-file cleanup; return `CL_ENULLARG`
  before HFS+ traversal or cleanup.
- The current-source production-linked GCC `hfs_map` case passes 13/13 and
  `hfs_inline` passes 1/1. The catalog-boundary fixture records the earlier
  declared-volume admission result, while the `hfs_fork` callback/materialization
  case remains a mixed-harness rebuild gate after a pre-oracle crash. Keep
  complete HFS+ corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  open.

## UDF parser engine admission — 2026-08-27

- Keep `cli_scanudf()` fail-visible when a recognized fmap is supplied without
  the engine required by extracted-file temporary cleanup; return
  `CL_ENULLARG` before descriptor traversal or extraction.
- The current-source production-linked GCC `udf_map` case passes 10/10 and
  the isolated `udf_corpus` case passes 1/1. Keep complete UDF corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## SIS parser engine admission — 2026-08-27

- Keep `cli_scansis()` fail-visible when a recognized fmap is supplied without
  the engine required by temporary-directory policy; return `CL_ENULLARG`
  before SIS traversal or cleanup.
- The current-source production-linked GCC `sis_map` case passes 2/2, and the
  established `sis_structure` and `sis_member` cases pass 1/1 each. Keep the
  full SIS corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## ISO9660 parser engine admission — 2026-08-27

- Keep `cli_scaniso()` fail-visible when a recognized fmap is supplied without
  the engine required by temporary cleanup and nested dispatch; return
  `CL_ENULLARG` before descriptor traversal or extraction.
- The current-source production-linked GCC `iso_map` case passes 14/14 and
  the materialized `iso` case passes 1/1. Keep full ISO corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification open.

## CPIO parser engine admission — 2026-08-27

- Keep the shared CPIO context validator fail-visible when a recognized fmap
  is supplied without the engine required by cleanup and scan-limit state;
  return `CL_ENULLARG` before any old, ODC, NEWC, or CRC traversal.
- The current-source production-linked GCC `cpio_map` case passes 5/5, while
  the focused `cpio_crc` and `cpio_numeric` cases pass 4/4 and 3/3. Keep the
  complete CPIO corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release qualification open.

## Partition parser engine admission — 2026-08-27

- Keep APM, GPT, and MBR direct parser entries fail-visible when a recognized
  fmap is supplied without the required engine: return `CL_ENULLARG` before
  `maxpartitions` or nested-dispatch state is accessed.
- The current-source production-linked GCC `partition_map` case passes 4/4;
  `apm_map`, `apm`, `apm_corpus`, `gpt`, and `mbr` pass 3/3, 5/5, 1/1, 4/4,
  and 5/5. Keep full partition-image corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  release qualification open.

## Structured-detector engine admission — 2026-08-27

- Keep `cli_scan_structured()` fail-visible for null context, missing fmap,
  and missing engine: caller argument failures return `CL_ENULLARG`, while a
  recognized layer without input returns `CL_EPARSE` with sticky incomplete
  state; preserve the shared canonical timeout reason.
- The current-source production-linked GCC `structured_map` TCase passes 4/4
  across those entry states, in-range and clipped read failures, and timeout.
  Keep full structured-detector corpus/raw-dispatch, sanitizer, production-
  CVD/service, Sonic1, and release qualification open.

## CABSFX admission-failure execution — 2026-08-27

- Keep the three public CABSFX admission cases fail-visible: valid prefixed
  CAB nested dispatch, confirmed declared-extent truncation as `CL_EPARSE`,
  and an in-range fixed-header callback failure as `CL_EREAD`, with stale
  verdict/alerts reset and fmap caching disabled on confirmed failures.
- The current-source production-linked GCC `cabsfx` TCase passes 3/3. Keep
  complete CAB/SFX corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  open.

## Mach-O unpack-entry preflight — 2026-08-27

- Keep exported `cli_unpackmacho()` fail-visible for null context, missing
  fmap, and missing engine: use `CL_ENULLARG` for caller arguments and
  `CL_EPARSE` plus sticky incomplete state for a recognized layer without
  input.
- The current-source production-linked GCC `macho_map` regression covers all
  three unpack-entry states. Keep Mach-O corpus, sanitizer, production-CVD/
  service, Sonic1, and release qualification open.

## ELF unpack-entry preflight — 2026-08-27

- Keep the exported `cli_unpackelf()` helper fail-visible for null context,
  missing fmap, and missing engine: use `CL_ENULLARG` for caller arguments,
  and `CL_EPARSE` plus sticky incomplete state for a recognized layer without
  input.
- The current-source production-linked GCC `elf_map` regression covers all
  three states. Keep full ELF unpacker/corpus, sanitizer, production-CVD/
  service, Sonic1, and release qualification open.

## HWP3 null-context classification — 2026-08-27

- Keep `cli_scanhwp3(NULL)` on the standard `CL_ENULLARG` caller-error
  boundary; a recognized context without an fmap remains `CL_EPARSE` with
  sticky incomplete state.
- The isolated current-source `hwp3_map` regression covers the null-context
  result. Keep HWP3 corpus, sanitizer, production-CVD/service, Sonic1, and
  release qualification open.

## TAR direct-entry fmap classification — 2026-08-27

- Keep `cli_untar()` fail-visible for unavailable input: a null context or a
  valid map with no output directory returns `CL_ENULLARG`, while a recognized
  context without an fmap returns `CL_EPARSE`, marks the layer incomplete, and
  disables caching.
- The current-source production-linked GCC `tar_map` case passes 2/2,
  including the direct output-directory check, and `tar_member` passes 6/6,
  including an in-range member-data read failure that remains `CL_EREAD` and
  non-cacheable.
  The broader `tar` case retains the known mixed old/current `cli_ctx` timeout
  SIGSEGV; keep full TAR corpus, sanitizer, production-CVD/service, Sonic1,
  and release qualification open.

## AutoIt header-admission context/map classification — 2026-08-26

- Keep `cli_autoit_header_check()` fail-visible for unavailable input: only a
  null context returns `CL_ENULLARG`; a recognized context without an fmap
  returns `CL_EPARSE` and marks the layer incomplete; the shared incomplete
  marker keeps any available fmap non-cacheable.
- The current-source GCC helper harness passes both classifications, with the
  direct regression registered in `autoit_map`. Keep full AutoIt corpus,
  sanitizer, production-CVD/service, Sonic1, and release qualification open.

## ARJ-SFX weak-candidate rejection — 2026-08-26

- Keep a structurally disproven ARJ-SFX magic candidate out of layer
  admission: a zero main-header size must leave the root scan `CL_SUCCESS`,
  clean, cacheable, and non-incomplete.
- The current-source production-linked `arjsfx` evidence is now 4/4 across
  weak rejection, valid nested admission, confirmed truncation, and an
  in-range callback failure. Keep full ARJ-SFX corpus, sanitizer,
  production-CVD/service, Sonic1, and release qualification open.

## ARJ metadata-offset range hardening — 2026-08-26

- Range-check variable first-header, CRC, and extended-header offset advances;
  encrypted members must not skip beyond the input fmap.
- The current-source ARJ object and unit-test source pass warning-enabled GCC
  syntax checks; a focused current-source harness passes the encrypted-member
  range regression with `CL_EFORMAT`, incomplete state, and non-cacheability,
  with source guards added. Keep full ARJ corpus, sanitizer,
  production-CVD/service, Sonic1, and release qualification open.

## APM MaxPartitions loop-bound hardening — 2026-08-26

- Keep both inclusive APM partition walks on a counter wider than the full
  `uint32_t` `MaxPartitions` setting so `UINT32_MAX` cannot wrap the loop back
  to zero.
- The current-source APM object passes the warning-enabled GCC syntax check
  and a source guard covers the widened counter. Keep full APM corpus,
  sanitizer, production-CVD/service, Sonic1, and release qualification open.

## ALZ zero-byte compressed-member admission — 2026-08-26

- Permit a zero-byte member only when it is stored and declares zero output;
  reject zero compressed bytes paired with nonzero output or a compressed
  method as malformed instead of treating the member as cleanly skipped.
- The standalone current-source Rust harness passes both malformed cases.
  Keep full Rust/C ABI, production-CVD, sanitizer, service, Sonic1, and
  release qualification open.

## ALZ deflate trailing-stream validation — 2026-08-26

- Require deflate decoding to consume the entire declared compressed member
  before finalizing the extraction sink; reject trailing compressed bytes as a
  malformed, non-dispatched member.
- The disposable offline ALZ-only Rust 1.97.1 harness passes all 38 ALZ tests,
  including the new trailing-stream regression. Keep full Rust/C ABI,
  production-CVD, sanitizer, service, Sonic1, and release qualification open.

## 7-Zip substream-size arithmetic — 2026-08-26

- Reject a substream-size sum that overflows `UInt64` or exceeds the folder's
  declared output before inferring the final substream size.
- A crafted current-source GCC harness passes the overflow boundary, and the
  unit-test helper covers both overflow and declared-size overrun. Keep full
  7-Zip corpus, sanitizer, production-CVD/service, Sonic1, and release
  qualification open.

## 7-Zip signed-seek boundary — 2026-08-26

- Reject 7-Zip `UInt64` seek coordinates above signed `Int64` capacity before
  the SDK callback can wrap them to a different location.
- The legacy `SzFolder_Decode()` regression passes 1/1 with the input position
  unchanged. Keep full 7-Zip corpus, sanitizer, production-CVD/service,
  Sonic1, and release qualification open.

## Crypto key/certificate file-close audit — 2026-08-27

- Treat successful PEM parsing followed by `fclose()` failure as a failed
  verification/key/CRL load and release the parsed object.
- The current source passes the production warning-enabled GCC syntax check.
  Keep injected close-failure execution, production CVD/service, sanitizer,
  certified Linux x86-64, materialized large-file, Sonic1, and release
  qualification open.

## Logical-expression parse-status propagation — 2026-08-26

- Reject out-of-range logical subsignature IDs before indexing the fixed
  64-entry arrays, and preserve `CL_EPARSE` for malformed expressions instead
  of allowing the evaluator's initial clean status to escape.
- A focused current-source GCC section-garbage-collected harness passes direct
  parser and `cli_exp_eval()` checks for the boundary. Rerun the full
  production-linked matcher TCase with this regression; keep full
  logical-expression, production-signature, sanitizer, service, Sonic1, and
  release qualification open.

## Bundled YARA VM unknown-opcode handling — 2026-08-26

- Return `CL_EPARSE` for an unknown bundled-YARA opcode so malformed bytecode
  cannot reach an assertion or continue as a clean execution.
- A focused current-source GCC section-garbage-collected harness passes the
  unknown-opcode check. Rerun the full production-linked matcher TCase, and
  keep sanitizer, production-CVD/service, Sonic1, and release qualification
  open.

## JPEG short-SOI admission — 2026-08-26

- Treat a forced JPEG layer containing only the two-byte `FF D8` start-of-image
  marker as a truncated header instead of returning the initial clean status;
  preserve `CL_EREAD` if the in-range two-byte confirmation read fails.
- The current-source JPEG object builds warning-clean with GCC, and the
  production-linked `jpeg_map` and `jpeg_corpus` cases pass 12/12 and 1/1,
  respectively, including the short-SOI regression. Keep full media corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## UnRAR metadata-width and filename termination audit — 2026-08-27

- Reconstruct UnRAR packed/unpacked sizes with unsigned 64-bit arithmetic and
  explicitly NUL-terminate the bounded metadata filename before scanner path
  handling. The bridge passes warning-enabled GCC C++ compilation and source
  guards; retain enabled-UnRAR extraction corpus, backend fault injection,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification gates.

## TIFF first-IFD runtime evidence — 2026-08-27

- The current-source production-linked GCC `tiff` case passes 9/9, including
  the direct out-of-range-first-IFD regression; `tiff_map` passes 1/1 and
  `tiff_corpus` passes 1/1. Keep the complete TIFF/image corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification gates open.

## RFC 1341 partial-message parameter admission — 2026-08-26

- Require a nonempty `message/partial` identifier and strictly positive
  decimal `number`/`total` values, bound each count at the existing 1024-part
  MIME limit, and reject `number > total` before saving or reassembling a
  fragment. Reassembly and directory enumeration now honor the shared
  `MaxScanTime` deadline.
- The current-source production-linked GCC `mail_partial` regression passes
  1/1 and the public `mail_api` case passes 2/2. The broader `mail` case has
  zero assertion failures in 10 checks but retains the known mixed old/current
  `cli_ctx` ABI SIGSEGV in its timeout test; keep full MIME/mbox/MHTML corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification as release
  gates.

## Current-source GZip/HTML harness refresh — 2026-08-26

- After synchronizing the current normalizer header and relinking the GCC
  production harness against the current scanner, `bz_core` passes 6/6 and
  `bz_map` passes 4/4; the current HTML boundary case remains 12/12,
  including raw matching when normalization is skipped.
- Keep malformed-normalization raw fallback, full HTML/GZip corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification open.

## Bundled YARA arithmetic-domain audit — 2026-08-27

- Reject divide/modulo by zero, signed `INT64_MIN / -1`, and shift counts
  outside the 64-bit VM operand width with `CL_EPARSE`; preserve the existing
  incomplete and non-cacheable matcher status.
- The focused current-source VM harness passes invalid arithmetic and valid
  controls. Public divide-by-zero and invalid-shift regressions are registered
  and compile-checked with production GCC; execute them in a current-source
  production-linked matcher TCase.
- Add instruction-stream bounds validation, then complete YARA corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification.

## ELF program-table admission without an entry point — 2026-08-26

- Traverse and validate every declared ELF32/ELF64 program table even when
  `e_entry` is zero; keep entry-point mapping conditional on a nonzero entry.
- The current-source GCC parser build is warning-clean, and the production-
  linked `elf_map` and `elf_corpus` cases pass 8/8 and 1/1. Keep complete ELF
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification as release
  gates.

## EGG archive-header admission — 2026-08-26

- Enforce the supported EGG version, nonzero header ID, and zero reserved
  field in direct archive parsing, matching SFX admission; malformed fields
  return `CL_EPARSE` and remain incomplete/non-cacheable.
- The current-source GCC parser build is warning-clean, and the
  production-linked `egg_map`, `egg_metadata`, and `egg_sfx` cases pass 6/6,
  1/1, and 1/1. Keep complete EGG corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification as release gates.

## DMG warning-clean source qualification — 2026-08-26

- Rebuild canonical `dmg.c` with GCC `-Wall -Wextra -Wformat-security` after
  removing the unused zero-stripe `read_failed` declaration.
- The current-source production-linked `dmg_map` case passes 7/7 across strict
  Base64/terminal-END, host-order stripes, bounded external sorting, malformed
  metadata, trailer read failure, invalid trailer, and missing-map admission.
- Keep full DMG corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  as release gates.

## CPIO zero-name member admission — 2026-08-26

- Reject zero `namesize` members in old binary, ODC, newc, and CRC CPIO
  streams as explicit incomplete `CL_EPARSE` results before member dispatch.
- The current-source production-linked GCC `cpio_numeric` case passes 2/2,
  while `cpio`, `cpio_map`, and `cpio_crc` pass 1/1, 4/4, and 4/4. Keep
  complete CPIO corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  as release gates.

## BinHex length and cleanup-status audit — 2026-08-26

- Decode data/resource fork lengths bytewise in big-endian order so high-bit
  bytes do not invoke undefined signed shifts, and keep cleanup status typed as
  `cl_error_t` when passing it to cleanup helpers.
- The current-source GCC parser build is warning-clean and the production-
  linked `binhex_map` TCase passes 11/11. Keep full corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification as release gates.

## AutoIt decoded-size portability audit — 2026-08-26

- Decode the EA05 and EA06 compressed-member output sizes bytewise in
  big-endian order; do not type-pun an unaligned `uint32_t *` over the local
  header buffer.
- The current-source GCC parser build is warning-clean, and the production-
  linked `autoit_map`, `autoit_corpus`, and `autoit_sfx` TCases pass 5/5, 1/1,
  and 1/1. Keep full corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  as release gates.

## ARJ truncated compressed-member fail-closed audit — 2026-08-26

- ARJ compressed bit-window refills now stop with `CL_EFORMAT` when the
  declared compressed member is exhausted instead of synthesizing zero
  padding; the overflow path records the same fail-visible status.
- The current-source production-linked GCC `arj_compressed` regression passes
  1/1 with a clean verdict and non-cacheable fmap; the established `arj`,
  `arj_map`, and `arjsfx` evidence is 10/10, 4/4, and 3/3. Keep complete
  ARJ/ARJ-SFX corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  as release gates.

## XAR fixed-header size admission — 2026-08-26

- Require the declared XAR header size to cover the fixed header before
  accepting the TOC range; smaller declarations must be incomplete and
  non-cacheable.
- The current-source GCC parser build is warning-clean. The production-linked
  `xar` TCase passes 9/9, and `xar_map`, `xar_metadata`, `xar_corpus`, and
  `xar_subdoc` pass 1/1 each. Retain full corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification as release gates.

## ELF data-encoding admission — 2026-08-26

- Accept only ELF's defined `EI_DATA` values and make reserved encodings
  fail-visible before program or section-table traversal.
- The current-source GCC parser build is warning-clean; `elf_map` passes 7/7
  and `elf_corpus` passes 1/1. The mixed-harness timeout SIGSEGV remains
  reproducible in the four-test `elf` case; retain sanitizer, production-CVD/
  service, materialized large-file, Sonic1, and parser-family qualification as
  release gates.

## TNEF nonzero-attribute checksum accounting — 2026-08-26

- Read and range-check the mandatory two-byte checksum after every nonzero
  TNEF message or attachment attribute; a clipped checksum must be an explicit
  incomplete parse and an in-range callback failure must remain `CL_EREAD`;
  negative attribute lengths must be fail-visible and non-cacheable.
- The three new direct regressions pass in the current-source production-linked
  GCC TNEF TCase. The full 16-test TNEF run still exposes the previously
  reproduced mixed-harness timeout SIGSEGV and materialized-corpus matcher
  miss; retain complete corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and parser-family qualification as release
  gates.

## GIF version admission audit — 2026-08-26

- Require the GIF version field to be exactly `87a` or `89a`; unsupported
  versions must return explicit incomplete/non-cacheable parse results before
  screen and block parsing.
- The exact invalid-version regression is registered alongside the existing
  warning-clean GIF build and production-linked `gif` 8/8, `gif_api` 1/1, and
  rebuilt `gif_corpus` 1/1 evidence with the exact child marker. Keep complete
  GIF corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## JPEG parser counter width audit — 2026-08-26

- Keep the JPEG segment ordinal and JFIF, Exif, and SPIFF application-marker
  counters at native 64-bit width so they cannot wrap during a 32-GiB parse and
  alter duplicate-marker or marker-position decisions.
- The current-source JPEG object compiles warning-clean under GCC
  `-Wall -Wextra -Wformat-security`; production-linked `jpeg_map` passes
  12/12 and `jpeg_corpus` passes 1/1. Keep full JPEG corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification open.

## HFS+ attributes-tree UTF-16 name boundary — 2026-08-26

- Validate the UTF-16 byte span, fixed attribute record, and declared payload
  before reading an HFS+ attributes-tree record; malformed confirmed nodes
  must remain explicit incomplete/non-cacheable results.
- The current-source production-linked GCC `hfs_map` TCase passes 10/10,
  including the boundary regression, and `hfs_inline` passes 1/1. Keep the
  mixed-harness `hfs_fork` gate, full HFS+ corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification open.

## Mach-O universal-binary unsupported-count admission — 2026-08-26

- Replace the generic `cafebabe` architecture-count clean skip with an
  explicit incomplete/non-cacheable `CL_EPARSE` result for Java-bytecode-like
  values outside the classifier range and malformed or future FAT headers.
- The current-source production-linked GCC `macho_unsupported` TCase passes
  2/2, with `macho_map` passing 1/1 and the corrected `macho_corpus` passing
  2/2. Keep full
  Java/FAT corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## Mach-O universal-binary empty-table admission — 2026-08-26

- A confirmed `cafebabe` header with zero architectures now returns explicit
  incomplete/non-cacheable `CL_EPARSE` with reason `Mach-O universal-binary
  architecture table is invalid`; a zero-entry FAT header has no child to
  inspect.
- The current-source production-linked GCC `macho_unsupported` TCase passes
  2/2 for count-39 and count-0, while `macho_map` passes 1/1 and the corrected
  `macho_corpus` passes 2/2. The broader direct `macho`/`macho_timeout` matrix
  retains known mixed old/current `cli_ctx` ABI errors. Keep full Mach-O
  qualification, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and release gates open.

## PNG palette structural admission — 2026-08-26

- Reject invalid PLTE lengths, PLTE-after-IDAT, duplicate PLTE chunks,
  grayscale PLTE chunks, and indexed images missing PLTE with explicit
  incomplete/non-cacheable parse results.
- The current-source `png.c` GCC build is warning-clean and the
  production-linked `png` TCase passes 7/7 checks. Keep complete PNG corpus,
  sanitizer, certified Linux x86-64, materialized large-file, production-CVD/
  service, Sonic1, and parser-family qualification open.

## GIF Graphic Control Extension field validation — 2026-08-26

- Validate the fixed Graphic Control Extension block size and zero terminator
  before advancing the GIF cursor; malformed confirmed fields now return
  `CL_EPARSE` with sticky incomplete/non-cacheable state.
- The current-source production-linked GCC `gif` TCase passes 6/6, including
  both malformed-field regressions, and `gif_api` passes 1/1. Keep complete
  GIF corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## Bytecode malformed-record boundary hardening — 2026-08-26

- Keep variable/fixed-width bytecode reads bounded, reject zero or
  host-unrepresentable encoded IDs before narrowing, validate type/global/
  destination maps, require constant GEP offsets, and check allocation
  products against the shared ceiling.
- The current-source production-linked GCC parser build is warning-clean; the
  isolated valid-fixture loader and truncated-record prefix TCase each pass
  1/1. Keep full bytecode execution, independent format-8 fixture, sanitizer,
  production-CVD/service, Sonic1, and release qualification open.

## Bundled YARA VM malformed-state hardening — 2026-08-26

- The bundled YARA VM now rejects empty-stack pops, out-of-range fixed
  memory-slot operands, impossible call argument counts, and insufficient call
  operands; VM locals are initialized before execution.
- The edited interpreter compiles warning-clean with GCC
  `-Wall -Wextra -Wformat-security`, and the current-source
  production-linked matcher TCase passes 39/39, including empty-stack,
  invalid-memory, and impossible-call-operand regressions with explicit non-cacheable parse-incomplete
  results. Keep full YARA corpus, sanitizer, production-CVD/service, Sonic1,
  and release qualification open.

## Fresh current-source NSIS/MSXML qualification — 2026-08-26

- The current-source production-linked GCC harness passes `nulsft` 4/4,
  `nulsft_map` 2/2, `nulsft_corpus` 1/1, `msxml` 4/4, `msxml_map` 1/1,
  `msxml_corpus` 1/1, `ooxml_entry` 1/1, and `ppt_entry` 1/1.
- The NSIS object is warning-clean under GCC `-Wall -Wextra
  -Wformat-security`; the materialized archive reaches the exact nested child
  matcher. Keep full NSIS/MSXML/OOXML corpus, sanitizer, certified Linux,
  production-CVD/service, Sonic1, and release qualification open.

## Fresh current-source OneNote qualification — 2026-08-26

- The current-source production-linked GCC harness passes `onenote` 2/2,
  `rust_onenote` 2/2, and `rust_map` 1/1. The materialized OneNote corpus
  reaches the exact nested MZP matcher, with Rust read/truncation and map
  boundaries preserved.
- The earlier CL_EPARSE comparison was stale/mixed C/Rust linkage. Keep full
  OneNote/OOXML corpus, sanitizer, certified Linux, materialized large-file,
  production-CVD/service, Sonic1, and release qualification open.

## Fresh current-source SIS corpus qualification — 2026-08-26

- A source-consistent current-source production-linked GCC rebuild passes
  `sis` 1/1, `sis_member` 1/1, and `sis_map` 1/1. The materialized
  `clam.sis` oracle reaches the exact nested MZP matcher after compressed-
  member extraction; the earlier clean result was stale/mixed helper linkage.
- Keep full SIS corpus, sanitizer, certified Linux, production-CVD/service,
  materialized-large-file, Sonic1, and release qualification open.

## Fresh current-source MSEXPAND qualification — 2026-08-26

- A fresh current-source production-linked GCC rebuild passes the complete
  `msexpand` TCase 6/6 and `msexpand_map` 2/2, including null-context and
  missing-map admission, header/read boundaries, output and temporary limits,
  timeout, and materialized `clam.exe.szdd` decompression with exact nested
  matching.
- The earlier 4/6 and 5/6 results were stale/mixed helper-linkage artifacts.
  Keep complete SZDD corpus, sanitizer, certified Linux, production-CVD/
  service, Sonic1, and release qualification open.

## Fresh current-source ZIP corpus qualification — 2026-08-26

- The authoritative current-source production-linked GCC rebuild passes the
  ordinary `zip` TCase 14/14 with zero failures, including both split-logo
  fixtures, materialized `clam.zip`, and the focused ZIP boundaries.
- The same current-source binary passes `zip_sfx` 3/3 and `zip_map` 1/1. The
  earlier 13/14 result was a mixed/incompletely relinked harness artifact and
  is superseded. Keep full ZIP corpus, sanitizer, certified Linux,
  production-CVD/service, Sonic1, and release qualification open.

## TAR zero-length member traversal — 2026-08-26

- Keep zero-length regular and skipped entries from consuming the following
  512-byte header. The focused production-linked GCC `tar_member` TCase passes
  5/5, including exact nested matching in the member after an empty member.
- Keep full TAR corpus, sanitizer, production-CVD/service, Sonic1, and release
  gates open.

## SIS legacy option-skip bounds — 2026-08-26

- Keep legacy SIS `PKGoption` skip expansion in 64-bit arithmetic and require
  every buffered skip to fit within the remaining fmap. The pre-fix regression
  returned clean for a wrapped count; the current-source production-linked GCC
  `sis_structure` case now passes 1/1 with incomplete/non-cacheable `CL_EPARSE`.
- `sis_member` and `sis_map` each pass 1/1. The fresh current-source static
  relink does not reproduce the historical materialized `sis` nested-MZP
  result, so current-source corpus qualification remains open. Keep sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and release gates open.

## PNG structural admission — 2026-08-26

- Require `IHDR` to be first and unique, validate chunk-type bytes, and reject
  invalid IHDR color/depth, compression, filter, and interlace combinations as
  incomplete/non-cacheable results. The focused production-linked GCC `png`
  TCase passes 6/6 with exact reason assertions.
- Keep full PNG/image corpus, sanitizer, production-CVD/service, Sonic1, and
  release gates open.

## PDF ASCII85 partial-tail classification — 2026-08-26

- Markerless ASCII85 remains compatible when the stream ends on complete
  groups, but a partial trailing group now returns `CL_EPARSE`, rolls back
  decoded output, performs exact raw fallback, and remains incomplete and
  non-cacheable.
- The focused PDF TCase passes 14/14, including the partial-tail and raw
  rollback regression. Keep full PDF corpus, sanitizer, production-CVD/service,
  Sonic1, and release gates open.

## Fresh ZIP corpus evidence correction — 2026-08-26

- Fresh current-source `unzip.c`/`scanners.c` objects pass `zip_sfx` 3/3 and
  `zip_map` 1/1, confirming the masked ZIP-SFX admission and exact child-only
  regressions.
- The same ordinary `zip` TCase is 13/14: the existing materialized
  `clam.zip` corpus oracle returns `CL_EPARSE`. The prior 14/14 claim is
  withdrawn pending a full current C rebuild; this does not regress the
  masked-SFX milestone.
- Keep full ZIP corpus, sanitizer, certified Linux, production-CVD/service,
  Sonic1, and release qualification open.

## MSEXPAND null-context classification — 2026-08-26

- `cli_msexpand()` now returns `CL_ENULLARG` for a null scan context, while a
  recognized SZDD layer with no input map remains `CL_EPARSE` and incomplete.
- The current-source production-linked `msexpand_map` case passes 2/2, and the
  new null-context regression passes inside the six-check `msexpand` TCase.
  That TCase is 4/6 because the existing time-limit case segfaults and the
  materialized corpus oracle mismatches in the mixed static/shared-ABI
  harness. Full SZDD corpus, sanitizer, service, Sonic1, and release
  qualification remain open.

## Logical-signature definition validation — 2026-08-26

- `cli_exp_eval()` and `lsig_eval()` now reject unavailable logical matcher
  context, tables, entries, expressions, and input maps before dereference,
  marking confirmed malformed matcher state incomplete and non-cacheable.
- The hash-read fixture now owns its registered name in the engine memory pool,
  matching the teardown contract. The standalone current-source production-
  linked matcher TCase passes 36/36, including the malformed-definition and
  fail-visible hash regressions; full logical expressions, production
  signatures, sanitizer, service, Sonic1, and release qualification remain
  open.

## RTF parser state and child-dispatch hardening — 2026-08-26

- RTF parser-stack growth is checked before native allocation arithmetic;
  unmatched closing groups no longer underflow the nesting counter; object
  state uses quota-accounted zero initialization; action-table allocation
  failure returns `CL_EMEM` without asserting on a null table; and zero-valued
  temporary descriptors are recognized.
- The object-end decode branch is reachable for completed descriptors, and
  split reserved-field chunks advance by the bytes consumed so the following
  payload-size field is preserved. The current-source GCC parser compile is
  warning-clean; the current-source production-linked `rtf_map` TCase passes
  9/9 and `rtf` passes 1/1 against materialized `clam.exe.rtf`, including the
  exact split-field assertion. Keep full RTF corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
  release gates open.

## OneNote modern-fallback admission — 2026-08-26

- A OneNote document that fails the modern parser now falls back to the
  legacy extractor only when a legacy file-data-store marker is present; a
  full-magic document with no such record is an explicit parse-incomplete,
  non-cacheable result instead of clean.
- The current-source Rust test filter passes 7/7, `rust_onenote` passes 2/2,
  and the modified dispatch boundary rejects the no-record fixture. Keep the
  mixed full-corpus ABI rerun, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## ALZ member CRC validation — 2026-08-26

- ALZ now validates the standard streaming CRC-32 for every complete stored,
  deflate, and BZip2 member before nested scanning; a mismatch is a visible,
  non-cacheable malformed result.
- The current-source Rust 1.97.1 release build passes all 36 ALZ Rust unit
  tests, the production-linked GCC `rust_alz` case passes 2/2, and `rust_map`
  passes 1/1. Keep full C/Rust ABI, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## LHA/LZH compressed-range admission — 2026-08-26

- LHA/LZH now tracks bounded source consumption and rejects a parsed member
  whose checked compressed range extends beyond the input fmap, including the
  zero-output/truncated-member case that delharc could otherwise normalize to
  a clean result.
- The current-source Rust 1.97.1 release build and production-linked GCC
  `rust_lha` case pass 4/4; `rust_map` passes 1/1. Keep full C/Rust ABI,
  sanitizer, certified Linux x86-64, materialized large-file, production-CVD/
  service, Sonic1, and release gates open.

## RTF OLE10 magic validation — 2026-08-26

- RTF `\objdata` now rejects an invalid OLE10 magic prefix as `CL_EPARSE`
  before allocating or scanning a malformed embedded object; the layer is
  incomplete and non-cacheable.
- A clean current-source production-linked GCC relink of the test, RTF,
  scanner, matcher, PE, and helper objects passes `rtf` 1/1 against the
  materialized `clam.exe.rtf` fixture and passes `rtf_map` 9/9, including the
  invalid-magic regression. This replaces the earlier mixed static/shared-ABI
  result. Keep full RTF parser-family, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## SIS compressed-member current-source qualification — 2026-08-26

- The authoritative current-source production-linked GCC `sis_member` case
  passes 1/1 after direct compiled matcher setup for a zlib-compressed legacy
  member, and `sis_map` passes 1/1. The materialized `sis` result is withheld
  from current-source qualification because the fresh static relink returns
  clean while the cached pre-change shared-library harness retains the
  historical 1/1 alert.
- Keep full SIS corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## OneNote and OOXML current-source boundary rerun — 2026-08-26

- The authoritative current-source production-linked GCC harness passes
  `rust_onenote` 2/2 and `onenote` 2/2, plus `ooxml_entry` 1/1,
  `ppt_entry` 1/1, and `msxml` 4/4.
- Keep complete OneNote/OOXML part corpora, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## TAR member-size and PAX-scope qualification — 2026-08-26

- The authoritative current-source production-linked GCC `tar_member` case
  passes 5/5 after direct compiled matcher setup, covering GNU base-256 and
  PAX child handoff, local PAX override/global-scope restoration, and visible
  rejection of unrepresentable positive and negative base-256 sizes, plus the
  zero-length-member next-header regression. Existing
  `tar` passes 6/6 and `tar_corpus` passes 1/1.
- Keep complete TAR corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## Mail, MHTML, and MBR current-source qualification — 2026-08-26

- The rebuilt current-source production-linked GCC harness passes `mail_api`
  2/2, `mbr` 5/5, `mbr_corpus` 1/1, `mhtml` 4/4, and `partition_map` 3/3.
  The `mail` TCase executes 10 checks with zero assertion failures but retains
  the known mixed old/current `cli_ctx` ABI SIGSEGV in its timeout test; the
  isolated `mail_partial` regression passes 1/1. Coverage includes MIME
  streaming/error boundaries, MHTML large-body handling, MBR coordinate/limit
  cases, and exact partition-child matching.
- Keep complete MIME/MHTML and partition-image corpora, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
  release gates open.

## InstallShield current-source admission qualification — 2026-08-26

- The current-source production-linked GCC harness passes `ishield_map` 2/2
  for confirmed-entry missing-map admission and `ishield_sfx` 1/1 for a valid
  PE-backed SFX whose child reaches an exact matcher.
- Keep complete MSI/legacy/CAB corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## Explicit ignored-type boundary — 2026-08-26

- Record `CL_TYPE_IGNORED` as unsupported: its legacy classifier entries have
  no deep parser and intentionally bypass raw matching, so recognized input
  is not presented as clean or deeply inspected.
- Reopen this boundary only if a future release enables a bounded parser for
  one of the ignored formats.

## Graphics current-source qualification — 2026-08-26

- The current-source production-linked GCC harness passes `graphics_map` 2/2,
  `graphics_api` 1/1, and `graphics_corpus` 1/1. Coverage includes BMP and
  JPEG-2000 map admission, public in-range read-failure classification, and
  exact pixel-offset matching from a complete BMP corpus fixture.
- Keep full graphics decoding/corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## DMG and ELF current-source qualification — 2026-08-26

- The current-source production-linked GCC harness passes `dmg` 6/6 and
  `dmg_map` 7/7, plus `elf_map` 6/6, `elf` 4/4, and `elf_corpus` 1/1. The
  cases cover bounded DMG metadata/reconstruction and external sorting, ELF
  missing-map and metadata boundaries, native-coordinate limits, timeout,
  and exact ELF64 segment matching.
- Keep sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release gates open.

## EGG metadata and SFX focused qualification — 2026-08-26

- The authoritative current-source production-linked GCC harness passes
  `egg_map` 5/5, `egg_metadata` 1/1, and `egg_sfx` 1/1. The metadata case
  exercises a codepage-932 converted filename through public `CL_TYPE_EGG`
  scanning with exact converted-byte matching and report metrics; the map
  and SFX cases cover bounded metadata/LZMA and header-admission boundaries.
- Keep complete EGG corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## CPIO CRC parser qualification — 2026-08-26

- The authoritative current-source production-linked GCC `cpio_crc` case
  passes 4/4 using direct compiled matcher setup. It covers exact nested
  member matching, checksum-mismatch precedence, a tail marker after more
  than two 64 KiB checksum windows, and an injected checksum read failure;
  the existing `cpio` corpus passes 1/1, `cpio_map` 4/4, and `cpio_numeric`
  1/1.
- Keep full CPIO corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## CAB-SFX nested-dispatch qualification — 2026-08-26

- The current-source production-linked GCC `cabsfx` case passes 1/1: a valid
  prefixed CAB SFX reaches an exact offset-0 nested child matcher through
  public `CL_TYPE_CABSFX` dispatch.
- Keep full CAB-SFX corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## BZip2 parser boundary and concatenated-stream qualification — 2026-08-26

- The current-source production-linked GCC `bz_core` case passes 6/6 after
  isolating concatenated-member tail detection with the existing boundary and
  materialized BZip2/GZip nested-MZP corpus checks.
- Keep sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release gates open.

## BinHex parser boundary and corpus qualification — 2026-08-26

- The current-source production-linked GCC `binhex_map` case passes 11/11,
  covering admission, truncation, timeout, temporary quota/cleanup,
  encoded-input read failure, and materialized `clam.exe.binhex` nested-MZP
  matching through the data fork.
- Keep complete encoded-document corpus, sanitizer, certified Linux x86-64,
  materialized large-file, ingress/service, production-CVD, Sonic1, and
  release gates open.

## Mydoom detector corpus qualification — 2026-08-26

- The current-source production-linked GCC `mydoom_map` case passes 4/4,
  including three boundary/read-failure checks and a valid two-record corpus
  that reaches `Heuristics.Worm.Mydoom.M.log` through public
  `CL_TYPE_BINARY_DATA` dispatch with heuristic precedence enabled.
- Keep broader raw-signature/ingress parity, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and release
  gates open.

## Binary-data raw-matcher dispatch qualification — 2026-08-26

- The isolated current-source production-linked GCC `binary_data` case
  passes 1/1 over a 65,556-byte synthetic binary payload whose exact-tail
  custom matcher is reached through public `CL_TYPE_BINARY_DATA` dispatch.
- Keep broader hash/AC/BM/logical/YARA coverage, ingress parity, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and release gates open.

## AutoIt parser-family corpus qualification — 2026-08-26

- The isolated current-source production-linked GCC `autoit_corpus` case
  passes 1/1 over build-generated EA05 stored, EA05 compressed, and EA06
  stored-script fixtures. The EA05 variants reach exact nested ABCD alerts
  through public `CL_TYPE_AUTOIT` dispatch; the EA06 fixture completes its
  one-line script decompilation and remains cacheable. Existing `autoit_map`
  passes 5/5 and `autoit_sfx` passes 1/1.
- Keep sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release gates open.

## 7-Zip current-source qualification — 2026-08-26

- The current-source production-linked GCC harness, relinked with current
  scanner, PE, `others`, `fmap`, and 7-Zip objects, passes all eight `7z`
  checks, including materialized `clam.7z` nested detection. `7z_map` passes
  2/2, `7z_sfx` passes 1/1, and `7z_sfx_corpus` passes 1/1. This replaces the
  earlier mixed static/shared-ABI corpus result.
- Keep full 7-Zip/SFX corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## HWPOLE2 embedded-OLE2 corpus qualification — 2026-08-26

- The isolated current-source production-linked GCC `hwpole2_corpus` case
  passes 1/1 through public `CL_TYPE_HWPOLE2` dispatch over a materialized
  `clam.ppt` OLE2 payload with a matching 32-bit size prefix; bounded nested
  scanning reaches an exact child marker, and the public map-boundary TCase
  passes 2/2.
- Keep full HWPOLE2/OLE2 corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## HWP3 structural/member corpus qualification — 2026-08-26

- The isolated current-source production-linked GCC `hwp3_corpus` case
  passes 1/1 through public `CL_TYPE_HWP3` dispatch over a complete synthetic
  HWP3 structure whose bounded OLE-data information block reaches an exact
  child marker through nested traversal; the isolated public HWP3 API boundary
  case passes 1/1.
- Keep the direct-context mixed-ABI rebuild gate, full HWP3 corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and release gates open.

## HWP3 information-block range classification — 2026-08-26

- A declared HWP3 information-block payload that extends beyond the input fmap
  now marks the scan incomplete with reason `HWP3 information block extends
  beyond the input map` and returns `CL_EPARSE`; actual in-range fmap callback
  failures remain `CL_EREAD`.
- The new regression passes within the direct HWP3 TCase. The current-source
  production-linked TCase reports 16 checks, 0 assertion failures, and 8 known
  errors from the mixed old/current `cli_ctx` ABI harness; isolated `hwp3_api`
  and `hwp3_corpus` remain 1/1. Keep full HWP3 corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
  release gates open.

## HWPML decoded-member corpus qualification — 2026-08-26

- The isolated current-source production-linked GCC `hwpml_corpus` case
  passes 1/1 over a complete HWPML document whose attribute-driven Base64
  `BINDATA` member reaches an exact child marker after bounded decoded
  temporary materialization and nested scanning through `CL_TYPE_XML_HWP`;
  the existing HWPML boundary TCase passes 2/2.
- Keep full HWPML/XML corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## MSXML decoded-member corpus qualification — 2026-08-26

- The isolated current-source production-linked GCC `msxml_corpus` case
  passes 1/1 across both public `CL_TYPE_XML_WORD` and `CL_TYPE_XML_XL`
  dispatch paths over a complete XML document whose newline-delimited Base64
  `bindata` member reaches an exact child marker after temporary materialization
  and nested scanning.
- Keep full MSXML/XML corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## XDP decoded-member corpus qualification — 2026-08-26

- The isolated current-source production-linked GCC `xdp_corpus` case passes
  1/1 over a complete XML XDP document whose base64 chunk reaches an exact
  child marker through public `CL_TYPE_XDP` dispatch and nested output
  scanning.
- Keep full XDP/MSXML corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## UUEncode member corpus qualification — 2026-08-26

- The isolated current-source production-linked GCC `uuencode_corpus` case
  passes 1/1 over a complete terminated stream whose decoded member reaches
  an exact child marker through public `CL_TYPE_UUENCODED` dispatch.
- Keep full UUEncode/mail corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## UDF clean-volume completion — 2026-08-26

- The UDF scanner previously indexed the first payload block after a completed
  file-identifier/file-entry run as another descriptor volume, turning a valid
  clean volume into `CL_EPARSE` at fmap end.
- The current-source production-linked GCC `udf_corpus` case now passes 1/1
  for exact child detection and clean-volume completion; a following primary
  descriptor remains the supported signal for another volume. `udf_map` passes
  9/9.
- Keep full UDF corpus, native-width review, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and release
  gates open.

## UDF descriptor/member corpus qualification — 2026-08-26

- The current-source production-linked GCC `udf_map` case passes 9/9, and the
  isolated `udf_corpus` case passes 1/1 over a complete UDF descriptor
  sequence whose bounded extracted-file materialization reaches an exact
  child marker matcher.
- Keep full UDF corpus, native-width review, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and release
  gates open.

## XAR member corpus qualification — 2026-08-26

- The `xar.c` object was freshly rebuilt with the production GCC flags. The
  current-source production-linked GCC `xar` case passes 8/8, `xar_map` and
  `xar_metadata` pass 1/1 each, and the isolated `xar_corpus` case passes 1/1
  over a complete compressed TOC with an exact nested uncompressed-member
  matcher. This supersedes the earlier mixed-object XAR crash observation.
- Keep full XAR corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## XAR subdocument inner-content handoff — 2026-08-26

- The production-linked GCC `xar_subdoc` case passes 1/1 over a complete TOC
  with `<subdoc><x>OK</x></subdoc>` and reaches the exact child end marker at
  offset 5 in the streamed inner payload. The `subdoc` wrapper remains outside
  the nested scan by design.
- Keep sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release qualification open.

## Generic graphics BMP corpus qualification — 2026-08-26

- The isolated current-source production-linked GCC `graphics_corpus` case
  passes 1/1 over a structurally complete one-pixel, 24-bit BMP whose exact
  pixel-offset child marker is detected through `CL_TYPE_GRAPHICS`.
- Keep pixel decoding, complete graphics corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and release
  gates open.

## ELF executable corpus qualification — 2026-08-26

- The current-source production-linked GCC elf case passes 4/4, elf_map
  passes 6/6, and the isolated elf_corpus case passes 1/1 over a complete
  ELF64 executable description with a bounded PT_LOAD payload and an exact
  segment-offset child matcher.
- Keep full ELF corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## MBR partition corpus qualification — 2026-08-26

- The current-source production-linked GCC mbr case passes 5/5,
  partition_map passes 3/3, and the isolated mbr_corpus case passes 1/1 over
  a valid two-sector master boot record whose in-range partition reaches an
  exact child matcher through partition traversal.
- Keep full MBR/partition-image corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## APM partition corpus qualification — 2026-08-26

- The current-source production-linked GCC apm case passes 5/5, apm_map
  passes 3/3, and the isolated apm_corpus case passes 1/1 over a valid
  four-block Apple Partition Map whose payload partition reaches an exact
  child matcher through partition traversal.
- Keep full APM partition corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## GPT partition-image corpus qualification — 2026-08-26

- The current-source production-linked GCC gpt case passes 5/5, and the
  isolated gpt_corpus case passes 1/1 over a valid six-sector GPT image with
  CRC-validated primary and backup headers, one usable partition, and an
  exact child matcher reached through partition traversal.
- Keep full GPT/partition-image corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## Mach-O universal-binary dispatch and member admission — 2026-08-27

- Preserve file-type-aware raw metadata dispatch: FAT wrappers expose valid
  empty wrapper metadata, and recursive thin members use thin Mach-O metadata.
- Preserve full-table preflight, table-overlap rejection, nonzero member sizes,
  and checked member ends. The corrected canonical-endian, auto-classified
  corpus passes `macho_fat` 2/2 and `macho_corpus` 2/2, including a clean,
  cacheable scan and an exact member-relative child match; adjacent
  `macho_unsupported`, `macho_map`, and `macho_boundary` cases pass 2/2, 1/1,
  and 1/1.
- Keep full Mach-O/Java-FAT corpus, sanitizer, certified Linux x86-64,
  materialized large-file/resource, production-CVD/service, Sonic1, and release
  gates open.

## Mach-O cumulative section-count width — 2026-08-27

- Keep the cumulative section count representable by the 16-bit executable
  metadata ABI: exactly 65,535 is admitted and 65,536 is fail-visible before
  allocation or assignment.
- The current-source production-linked `macho_sections` boundary case passes
  1/1, while the pre-fix-object negative control fails 0/1 by returning clean.
- Keep sanitizer, complete Mach-O corpus, certified Linux x86-64, materialized
  large-file/resource, production-CVD/service, Sonic1, and release gates open.

## XZ decompressed-output corpus qualification — 2026-08-26

- The current-source production-linked GCC `xz` case passes 2/2,
  `xz_trailing` passes 1/1, and the isolated `xz_corpus` case passes 1/1 over
  a complete valid XZ stream whose bounded decompressed output reaches an
  exact child matcher after temporary spooling and nested scanning.
- Keep complete XZ corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## RIFF nested-container corpus qualification — 2026-08-26

- The current-source production-linked GCC `riff` case passes 6/6,
  `riff_map` passes 1/1, and the isolated `riff_corpus` case passes 1/1 over
  a valid ACON RIFF with a bounded nested LIST and child chunk; direct
  traversal reaches the declared boundary and the typed scan reaches an
  exact fixed-offset child matcher.
- Keep full RIFF/member-extraction qualification, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and release
  gates open.

## SWF compressed corpus qualification — 2026-08-26

- The current-source production-linked GCC `swf` case passes 10/10,
  `swf_api` passes 1/1, `swf_map` passes 1/1, and the isolated SWF corpus
  case passes 1/1 over a zlib-compressed CWS stream whose decompressed output
  reaches an exact fixed-offset child matcher after nested output scanning.
- Keep complete SWF corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release gates open.

## TIFF valid-structure corpus qualification — 2026-08-26

- The current-source production-linked GCC `tiff` case passes 8/8,
  `tiff_map` passes 1/1, and the isolated `tiff_corpus` case passes 1/1 over
  valid classic TIFF and BigTIFF IFD fixtures; both roots are structurally
  complete and do not begin with `MZP`.
- Keep complete TIFF/image corpus open. The three `tiff_large` callback-map
  cases remain a mixed-harness gate because `cl_fmap_open_handle()` returns a
  null map before parser entry, along with sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates.

## JPEG Photoshop-thumbnail corpus qualification — 2026-08-26

- The current-source production-linked GCC harness, relinked with current
  scanner, PE, `others`, `fmap`, and JPEG objects, passes `jpeg_map` 12/12 and
  the isolated `jpeg_corpus` case 1/1 over a valid APP13 Photoshop resource
  with a bounded thumbnail payload; exact offset-0 `MZP` matching is reached
  through the 8BIM thumbnail nested scan.
- Keep complete JPEG/image corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## GIF bounded overlay corpus qualification — 2026-08-25

- The current-source production-linked GCC `gif` case passes 5/5, and the
  isolated `gif_corpus` case passes 1/1 over a valid minimal GIF root with a
  bounded child after the trailer; exact offset-0 `MZP` matching is reached
  through the broken-media overlay handoff.
- Keep complete GIF/image corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## TAR materialized corpus qualification — 2026-08-25

- The current-source production-linked GCC `tar` case passes 6/6, and the
  isolated `tar_corpus` case passes 1/1 over TAR roots decompressed from
  materialized `clam.tar.gz` and `clam.exe_and_mail.tar.gz`; exact offset-0
  child `MZP` matching is reached through TAR member traversal.
- GNU base-256/PAX signature-loader cases remain limited by the mixed
  harness's `cl_load()`/`CL_EMALFDB` setup. Keep complete TAR corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release gates open.

## PE packer corpus qualification — 2026-08-25

- The current-source production-linked GCC `pe` case passes 11/11 and
  `pe_map` passes 2/2. The isolated `pe_corpus` case passes 1/1 across
  materialized FSG and UPX fixtures; exact offset-0 `MZP` matching is reached
  only after their unpacking handoff.
- Keep complete PE packer/heuristic/resource corpus, fault injection,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release gates open.

## PDF decoder and materialized corpus qualification — 2026-08-25

- Preserve `CL_EPARSE` in streaming Flate and LZW decoders when fallback-line
  resynchronization reaches EOF without finding an alternate stream; a helper
  `CL_SUCCESS` must not overwrite the original decode failure. The current
  production-linked GCC `pdf` case passes 14/14 after this fix.
- The isolated `pdf_corpus` case passes 1/1 for materialized `clam.pdf`, with
  an exact offset-0 child `MZP` matcher reached through PDF extraction. Keep
  full PDF corpus, encrypted large-stream, sanitizer, certified Linux x86-64,
  production-CVD/service, Sonic1, and release gates open.

## CPIO materialized corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `cpio` TCase passes
  1/1 across materialized 1 KiB old-binary big-endian, old-binary little-
  endian, NEWC, and ODC fixtures. Each exact offset-0 `MZP` alert is reached
  through member extraction; the archive roots do not satisfy the matcher.
- The existing current-source `cpio_map` and `cpio_numeric` cases pass 4/4 and
  1/1. The older CRC and neighboring TAR loader cases stop at `cl_load()` with
  `CL_EMALFDB` in the mixed ABI harness before parser execution; keep full CPIO
  corpus, CRC loader-harness, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## BZip2 and GZip corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `bz_core` case
  passes 5/5, including materialized `clam.exe.bz2`, `clam.tar.gz`, and
  `clam.exe_and_mail.tar.gz`; each exact embedded `MZP` marker is absent from
  the compressed outer bytes and is detected after decompression and nested
  handoff.
- Keep full BZip2 concatenated-member/corpus, GZip legacy-fallback/corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release qualification open.

## GZip corpus dispatch qualification — 2026-08-25

- `test_gzip_corpus_detects_embedded_mz` passes as part of the current-source
  production-linked `bz_core` 5/5 run for both materialized GZip fixtures via
  public `cl_scanmap_ex` and exact nested matching; neither compressed outer
  byte stream contains `MZP`.
- Preserve the legacy-fallback and complete GZip corpus, full-C ABI,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release qualification gates.

## Mail encoded-attachment corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `mail` case executes
  10 checks with zero assertion failures, including a public fmap scan of
  materialized `clam.mail`; its timeout test retains the known mixed
  old/current `cli_ctx` ABI SIGSEGV. The exact embedded `MZP` marker is absent
  from the outer message and is detected only after encoded-attachment
  extraction and nested handoff. The `mail_api` case remains 2/2, and the
  isolated invalid-partial-count regression passes 1/1.
- Keep full MIME/mbox corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release qualification open.

## SIS compressed-member corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `sis` case passes
  1/1 against materialized `clam.sis`; the exact embedded `MZP` marker is
  absent from the outer package and is detected after compressed-member
  extraction and nested handoff. The existing `sis_member` compressed stream
  oracle remains green.
- Keep full SIS corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release qualification open.

## RTF embedded-object corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `rtf` case passes
  1/1 against the materialized `clam.exe.rtf` fixture, detecting an exact
  embedded `MZP` marker only after RTF object decoding and nested handoff. The
  existing `rtf_map` case passes 8/8.
- Keep full RTF corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release qualification open.

## ZIP ordinary corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `zip` case passes
  13/14 in the fresh current-source rebuild. Both split-logo fixtures and the
  focused boundary cases are green, but the existing materialized `clam.zip`
  corpus oracle returns `CL_EPARSE`; the earlier 14/14 claim is withheld. The
  masked `zip_sfx` case passes 3/3 and `zip_map` passes 1/1.
- Keep full ZIP corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release qualification open.

## ISO9660 corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `iso` case passes
  1/1 across both materialized logo ISO fixtures, including standard and
  no-Joliet forms with exact nested PNG child detection. The current-source
  production-linked `iso_map` case passes 12/12, including the late-terminator
  regression.
- Keep full ISO9660 corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release qualification open.

## OLE2 embedded-member qualification — 2026-08-25

- The authoritative current-source production-linked GCC `ole2` case passes
  13/13, including materialized `has_png_and_jpeg.xls` and `clam.ppt` fixtures
  with exact embedded-PNG and embedded-MZP child detection. The existing
  `ole2_xlm` and `ole2_map` cases pass 2/2 each.
- Keep complete OLE2/VBA/XLM corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and release
  qualification open.

## ALZ corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `rust_alz` case
  passes 1/1 across all five materialized ALZ archives, detecting exact
  nested-member signatures for text and ELF payloads through stored, deflate,
  and BZip2 paths. The cached Rust release suite passes all 34 ALZ unit tests,
  and `rust_map` passes 1/1.
- Keep full current-C-ABI execution, sanitizer, certified Linux x86-64,
  materialized large-file boundaries, production-CVD/service parity, Sonic1,
  and release qualification open before changing `CL_TYPE_ALZ` from pending.

## LHA/LZH corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `rust_lha` case
  passes 3/3: direct and public-API in-range fmap read failures remain
  `CL_EREAD` and non-cacheable, and all 13 materialized LHA/LZH corpus files
  produce a nested PNG exact-signature detection. The shared `rust_map` case
  passes 1/1.
- Keep full current-C-ABI execution, sanitizer, certified Linux x86-64,
  materialized large-file boundaries, production-CVD/service parity, Sonic1,
  and release qualification open before changing `CL_TYPE_LHA_LZH` from
  pending.

## HTML normalization boundary qualification — 2026-08-25

- The authoritative current-source production-linked GCC `html` case passes
  12/12 for normalization-cap admission, normalized HTML/script matcher-work
  accounting, no-tags input and generated-size limits, HTML input and UTF-16
  read/timeout boundaries, script timeout and window stability, and cleanup
  close-failure propagation with JS I/O wrappers enabled, and the materialized
  `clam.exe.html` RFC2397 fixture. It has no outer `MZP` marker and its
  base64 child reaches an exact nested MZP matcher through the synthetic mail
  layer.
- Keep the raw-fallback regression open: the original broad-suite fixture
  path/ABI returned `CL_EPARSE` without an alert in this mixed linked harness,
  so it is not counted as complete until reproduced with the full C ABI. Keep
  full HTML corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release qualification open.

## RAR unavailable-backend qualification — 2026-08-25

- The current-source production-linked GCC `rar` case passes 2/2 in the
  authoritative build, whose optional UnRAR backend is unavailable. RAR and
  RAR-SFX recognition remains explicit incomplete/non-cacheable, and the
  confirmed SFX header read fault remains visible.
- Treat this as unavailable-backend evidence only. Keep optional UnRAR
  extraction, compiled RAR corpus, sanitizer, production-CVD/service parity,
  materialized large-file, and Sonic1 qualification open.

## MSPack bounded-parser qualification — 2026-08-25

- The authoritative current-source production-linked GCC `mspack` case passes
  4/4 across scan-size and temporary admission, declared-output-size
  validation, canonical timeout propagation, and truncated CAB fixed-header
  boundaries.
- The existing `mspack_map` case passes 5/5 across CAB/CHM missing-map,
  decoder-read, clipped-read, constructor, and callback-timeout boundaries.
  Keep complete CAB/CHM corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service parity, and Sonic1
  qualification open.

## ELF focused-coordinate qualification — 2026-08-25

- The authoritative current-source production-linked GCC `elf` case passes
  4/4 for canonical timeout propagation and ELF64/ELF32 native-coordinate
  boundary fixtures; the ELF32 fixture uses an aging fmap and verifies that
  the fetched section-table range reaches beyond 4 GiB.
- The existing `elf_map` case passes 6/6 for null/missing-map,
  truncated-header/program-table, program-header callback, and metadata
  callback boundaries. Keep complete executable corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service parity, and
  Sonic1 qualification open.

## NSIS member-table corpus qualification — 2026-08-25

- The current-source production-linked GCC `nulsft` case passes 4/4, and the
  isolated `nulsft_corpus` case passes 1/1 over a valid fixed-header NSIS
  archive with a bounded uncompressed `MZP` member reached through member
  extraction. Keep complete NSIS/SFX and decoder corpus, sanitizer,
  materialized large-file, production-CVD/service, Sonic1, and release gates
  open.

## PNG materialized overlay corpus qualification — 2026-08-25

- The current-source production-linked GCC `png` case passes 6/6, and the
  isolated `png_corpus` case passes 1/1. It starts from materialized
  `logo.png`, appends a bounded 64-byte `MZP` child, and requires the exact
  `PNG.Member.MZ.UNOFFICIAL` alert through the valid IEND-overlay handoff;
  full PNG/image corpus, sanitizer, materialized large-file,
  production-CVD/service, Sonic1, and release gates remain open.

## Child-descriptor entry null-context admission — 2026-08-25

- Return `CL_ENULLARG` from the descriptor-based nested-scan entry before
  descriptor inspection when its context is null. Keep full descriptor/fd
  ingress parity, sanitizer, production-CVD, service, and Sonic1 qualification
  open.

## GIF/PNG/TIFF direct-entry admission — 2026-08-25

- GIF, PNG, and TIFF direct parser entries now return `CL_ENULLARG` for a null
  context and preserve `CL_EPARSE` for recognized layers whose fmap is
  unavailable. Add compiled media corpus, sanitizer, production parser-family,
  and Sonic1 qualification before release.

## PNG focused-boundary qualification — 2026-08-25

- The production-linked `png` TCase passes 5/5 for truncated chunks, an
  in-range callback failure, truncated-header classification, shared deadline
  expiry, and sparse 2-GiB ancillary-chunk bounded mapping. Retain full PNG
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, and Sonic1 qualification as release gates.

## TIFF focused-boundary qualification — 2026-08-25

- The production-linked `tiff` TCase passes 8/8 and `tiff_map` passes 1/1 for
  classic/BigTIFF truncation, callback failures, malformed structures,
  endian variants, deadline expiry, and missing-map admission.
- Keep the three >4-GiB callback-map cases as a current-full-build gate: the
  mixed harness returns a null fmap before parser entry. Retain full TIFF
  corpus, sanitizer, certified Linux x86-64, production-CVD/service,
  materialized large-file, and Sonic1 qualification as release gates.

## GIF focused-boundary qualification — 2026-08-25

- The production-linked `gif` TCase passes 5/5 for truncated block forms,
  header callback failures, truncated screen-descriptor classification, shared
  deadline expiry, and missing-map admission. Retain full GIF corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, and Sonic1 qualification as release gates.

## SWF direct-entry admission — 2026-08-25

- Preserve `CL_ENULLARG` for a null SWF parser context, while marking a
  recognized layer with no input fmap incomplete and returning `CL_EPARSE`.
- The dedicated `swf_map` regression covers both admission states. Keep full
  SWF corpus, sanitizer, materialized large-file, production-CVD, service, and
Sonic1 qualification open.

## SWF bounded-parser qualification — 2026-08-25

- The current-source production-linked GCC `swf` case passes 10/10 across
  compressed/uncompressed truncation, callback faults, clipped input,
  temporary quota, injected cleanup failure, and timeout; `swf_map` and
  `swf_api` pass 1/1 each. Timeout preserves the canonical MaxScanTime reason.
- Add complete SWF corpus, sanitizer, production-CVD/service parity,
  materialized large-file, and Sonic1 evidence before certification.

## XAR direct-entry admission — 2026-08-25

- Preserve `CL_ENULLARG` for a null XAR parser context and keep missing input
  maps fail-visible as incomplete parses.
- The dedicated `xar_map` regression covers both states. Keep TOC-root closure,
  XAR corpus, sanitizer, materialized large-file, production-CVD, service, and
  Sonic1 qualification open.

## XAR focused-boundary qualification — 2026-08-25

- The production-linked `xar` case passes 8/8 for timeout, malformed metadata,
  compressed-member read failure, unsupported encoding, XML-reader failure,
  missing TOC-root closure, and TOC/subdocument temporary quotas;
  `xar_map` and `xar_metadata` each pass 1/1.
- Keep the compiled engine, dconf, and two-slot recursion-layer setup for the
  nested TOC/member regressions. The previous crashes were uninitialized test
  setup, not current parser evidence. Retain full XAR corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  and Sonic1 qualification as release gates.


## Mydoom detector direct-entry admission — 2026-08-25

- Preserve `CL_ENULLARG` for a null Mydoom detector context, while marking a
  recognized layer with no input fmap incomplete and returning `CL_EPARSE`.
- The dedicated `mydoom_map` regression covers both admission states. Keep
  compiled detector corpus, raw-dispatch, sanitizer, production-CVD, service,
  and Sonic1 qualification open.

## BinHex direct-entry admission — 2026-08-25

- Preserve `CL_ENULLARG` for a null BinHex parser context, while marking a
  recognized layer with no input fmap incomplete and returning `CL_EPARSE`.
- The dedicated `binhex_map` regression covers both admission states. Keep full
  BinHex corpus, sanitizer, materialized large-file, production-CVD, service,
  and Sonic1 qualification open.

## ARJ header-entry admission — 2026-08-25

- Preserve `CL_ENULLARG` for a null ARJ parser context and output-size
  destination, but mark a recognized ARJ layer with no input fmap incomplete
  and return `CL_EPARSE`.
- The dedicated `arj_map` regression covers the three argument states. Keep
  full ARJ/ARJ-SFX corpus, sanitizer, materialized large-file, production-CVD,
service, and Sonic1 qualification open.

## ARJ bounded-decoder qualification — 2026-08-25

- The current-source production-linked GCC `arj` case passes 9/9 across
  header/signature truncation, callback failure, extraction failure, output
  mismatch, member/temporary limits, and timeout; `arj_map` passes 4/4.
  Timeout preserves the canonical MaxScanTime reason.
- Add complete ARJ/ARJ-SFX corpus, sanitizer, production-CVD/service parity,
  materialized large-file, and Sonic1 evidence before certification.

## ARJ corpus dispatch qualification — 2026-08-25

- The expanded current-source production-linked GCC `arj` case passes 10/10,
  including public `cl_scanmap_ex` scanning of materialized `clam.arj`; its
  exact embedded `MZP` marker is absent from the ARJ outer bytes and is
  detected after member extraction and nested handoff.
- Add complete ARJ/ARJ-SFX corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service parity, Sonic1, and release
  evidence before certification.

## APM bounded-partition qualification — 2026-08-25

- The current-source production-linked GCC `apm` case passes 5/5 for
  partition limits, malformed maps/partitions, table boundaries, and native
  coordinate overflow; `apm_map` passes 2/2. Explicit format/record-limit
  classes and sticky incomplete state remain fail-visible.
- Add complete APM partition corpus, sanitizer, production-CVD/service parity,
  materialized large-file, and Sonic1 evidence before certification.

## GPT bounded-partition qualification — 2026-08-25

- The current-source production-linked GCC `gpt` case passes 4/4 for
  protective-MBR/sector-size/primary-table read faults and invalid-partition
  bounds; `partition_map` passes 3/3 for MBR/GPT map and coordinate cases.
- Add complete GPT/partition-image corpus, sanitizer, production-CVD/service
  parity, materialized large-file, and Sonic1 evidence before certification.

## JPEG direct-entry admission — 2026-08-25

- Preserve `CL_ENULLARG` for a null JPEG parser context while keeping missing
  input maps fail-visible as incomplete parses.
- The dedicated `jpeg_map` regression covers both states. Keep JPEG corpus,
  sanitizer, materialized large-file, production-CVD, service, and Sonic1
  qualification open.

## JPEG focused-boundary qualification — 2026-08-25

- The production-linked `jpeg_map` case passes 12/12 for admission,
  truncation, timeout, direct and public-API callback faults,
  application/exploit probes, Photoshop resource bounds, and exact EOF. Retain
  full JPEG corpus, current full-build large-coordinate evidence, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service, and
  Sonic1 qualification as release gates.

## ISO9660 focused-boundary qualification — 2026-08-25

- The production-linked `iso_map` case passes 11/11 for admission,
  truncation/terminator, direct and public-API read faults, timeout, extent and
  name bounds, coordinate overflow, Joliet expansion, and declared-volume
  accounting. Retain full ISO9660 corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification as
  release gates.

## UDF focused-boundary qualification — 2026-08-25

- The production-linked `udf_map` case passes 9/9 for admission, truncation,
  timeout, descriptor callback failure, identifier/list/set rejection,
  information-length and partition bounds, and allocation alignment. Retain
  full UDF corpus, native-width review, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification as
  release gates.

## TNEF bounded-attachment qualification — 2026-08-25

- The current-source production-linked GCC `tnef` case passes 13/13 for
  checksum/EOF handling, callback faults, truncation, attachment/message-body
  paths, timeout, temporary limit, and the materialized `clam.tnef` corpus
  fixture. The fixture has no outer `MZP` marker and reaches an exact nested
  `MZP` matcher result after attachment extraction; `tnef_map` passes 1/1.
  Timeout retains the canonical MaxScanTime reason.
- Add complete TNEF corpus, sanitizer, production-CVD/service parity,
  materialized large-file, and Sonic1 evidence before certification.

## HFS+ focused-boundary qualification — 2026-08-25

- `hfs_map` passes 9/9 and `hfs_inline` passes 1/1 for tree/catalog/fork/
  attribute bounds, callback failures, temporary setup, truncation, deadline,
  bounded inline decompression, and write rollback. The tree-header admission
  unit mismatch is corrected in `hfsplus.c`.
- Keep the `hfs_fork` materialization callback case as a current-full-build
  gate because the mixed harness crashes before its oracle. Retain full HFS+
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, and Sonic1 qualification as release gates.

## OLE2 64-bit stream-size qualification — 2026-08-25

- Decode the complete 64-bit CFB directory-entry stream size without changing
  the 128-byte entry layout. The production-linked `ole2_xlm` case passes 2/2,
  including the high-word mutation that prevents silent low-32-bit scanning;
  retain full OLE2/VBA corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, and Sonic1 qualification as release gates.

## RTF focused-boundary qualification — 2026-08-25

- The isolated production-linked `rtf_map` case passes 8/8 for truncation,
  timeout, callback failure, split OLE10 headers, complete descriptions, split
  reserved fields, and implicit-close status propagation. Keep the malformed
  split-object result fail-visible as parse-incomplete or explicit resource-
  incomplete; retain full RTF/OLE corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification as
  release gates.

## PowerPoint VBA helper context admission — 2026-08-25

- Reject a null context in `cli_ppt_vba_read_ex()` before temporary-directory
  creation or iterator access, and return a zero optional reservation result.
- The focused `ppt_entry` regression passes. Keep full OOXML/PowerPoint corpus,
  sanitizer, materialized large-file, production-CVD, and Sonic1 qualification
  open.

## OOXML direct-entry qualification — 2026-08-25

- The current-source production-linked GCC `ooxml_entry` case passes 1/1
  across Word, PowerPoint, Excel, and HWP `cli_process_ooxml()` branches;
  `ppt_entry` passes 1/1 and `msxml` passes 4/4. These checks preserve
  `CL_ENULLARG` and XML-reader fault visibility before ZIP-part traversal.
- Complete OOXML ZIP-part/content-types/core-properties corpus and full-C
  ABI-consistent execution, then add sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service parity, and Sonic1 evidence
  before certification.

## OOXML content-types part-name admission — 2026-08-28

- Keep `ooxml_content_cb()` from converting an empty or unrooted untrusted
  `PartName` through `xmlStrlen(PN) - 1` and `PN + 1`; require a non-empty
  rooted path before ZIP lookup and record `OOXML_ERROR_INVALID_PART_NAME`.
- Retain `test_ooxml_rejects_invalid_declared_part_name` for empty, unrooted,
  and `/` values. Current-source production-linked execution, full OOXML
  corpus, sanitizer, materialized-large-file, production-CVD/service, Sonic1,
  and parser-family qualification remain open.

## UUEncode direct-entry admission — 2026-08-25

- Preserve `CL_ENULLARG` for a null UUEncode parser context, but mark a
  recognized layer with no input fmap incomplete and return `CL_EPARSE` before
  deadline or line-reader access.
- The direct-entry regression covers both boundaries. Keep full UUEncode
  corpus, sanitizer, materialized large-file, production-CVD, and Sonic1
  qualification open.

## HWPML missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null HWPML parser context, but mark a
  recognized HWPML layer with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `hwpml_map` regression passes and records the
  sticky reason. Keep full HWPML/XML corpus, sanitizer, materialized
  large-file, production-CVD, and Sonic1 qualification open.

## MSXML focused-boundary qualification — 2026-08-25

- The authoritative current-source production-linked GCC `msxml` case passes
  4/4 for truncated XML, callback read failure, malformed Base64, and timeout;
  `msxml_map` passes 1/1. Keep the timeout fixture’s initialized scan options
  and canonical sticky reason assertion.
- Retain compiled XML/OOXML corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification as
  release gates.

## XZ focused-boundary qualification — 2026-08-25

- The authoritative current-source production-linked GCC `xz` case passes
  2/2 for scan-size limiting and truncated-stream format classification;
  `xz_trailing` passes 1/1 for rejecting a second concatenated stream.
- Retain full XZ/compressed corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification as
  release gates.

## ZIP-SFX and ZIP map focused qualification — 2026-08-25

- The authoritative current-source production-linked GCC `zip` TCase passes
  12/12 across central metadata, ZIP64, descriptor, callback, masked-header,
  and max-files boundary behavior. EOCD/ZIP64 in-range read failures now
  preserve `CL_EREAD` instead of being hidden by local-header fallback.
- The authoritative current-source production-linked GCC `zip_sfx` case passes
  3/3 for weak masked-header rejection, confirmed central-directory
  extent/read-failure classification, and exact child matching; `zip_map`
  passes 1/1 for missing-map admission.
- Retain full ZIP/ZIP-SFX corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification as
  release gates.

## HWPML focused-boundary qualification — 2026-08-25

- The authoritative current-source production-linked GCC `hwpml` case passes
  2/2 for truncated XML and bounded/malformed Base64; `hwpml_map` passes 1/1.
  The Base64 regression is isolated from the broad case and checks decoded
  bytes, exact size, malformed-input status, rollback, and non-cacheability.
- Retain full HWPML/XML corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, and Sonic1 qualification as release
  gates.

## InstallShield missing-map confirmed-entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for null InstallShield parser contexts, but mark
  recognized MSI and legacy extraction layers with no input fmap incomplete
  and return `CL_EPARSE`; leave the weak MSI header-admission probe
  non-confirming.
- The isolated production-linked `ishield_map` regression passes for both
  confirmed entries. Keep full InstallShield/CAB corpus, sanitizer,
  materialized large-file, production-CVD, and Sonic1 qualification open.

## InstallShield SFX nested admission qualification — 2026-08-25

- The current-source production-linked GCC `ishield_sfx` case passes 1/1 for
  a valid PE-backed InstallShield SFX with an encrypted/compressed member and
  exact nested child detection; adjacent `autoit_sfx` passes 1/1 and `pe_map`
  passes 2/2. Unsigned-PE Authenticode checks now return `CL_EVERIFY` for a
  no-trust result rather than `CL_BREAK`, so normal raw/parser scanning is not
  suppressed before embedded SFX admission.
- Retain full InstallShield/CAB corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification as
  release gates.

## SIS missing-map entry classification — 2026-08-25

- Preserve `CL_ENULLARG` for a null SIS parser context, but mark a recognized
  SIS layer with no input fmap incomplete and return `CL_EPARSE`.
- The isolated production-linked `sis_map` regression passes and records the
  sticky reason. Keep full SIS corpus, sanitizer, materialized large-file,
  production-CVD, and Sonic1 qualification open.

## 7-Zip missing-map confirmed-entry classification — 2026-08-25

- Fresh current-source `scanners.c`, `7z_iface.c`, and `7zIn.c` objects in the
  production-linked GCC harness pass 7/8 focused `7z` checks; the eighth
  check over materialized `clam.7z` returns `CL_EPARSE` before its custom
  nested alert is surfaced. `7z_map` and `7z_sfx` pass 1/1 each. Withhold the
  corpus result until a full current C rebuild resolves the mixed
  static/shared-ABI harness boundary, and retain full BCJ2/archive,
  sanitizer, materialized large-folder, production-CVD/service, and Sonic1
  qualification as release gates.
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

## XDP focused-boundary qualification — 2026-08-25

- The authoritative current-source production-linked GCC `xdp` case passes
  3/3 for deadline propagation, cumulative retained-dump quota rejection,
  overlapping dump/Base64 accounting, exact peak counters, rollback, and
  cleanup; `xdp_map` passes 1/1 for missing-map admission.
- Retain full XDP/XML corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, and Sonic1 qualification as release
  gates.

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
- The focused production-linked GCC case passes 3/3 with weak masked-header
  rejection, exact child-only detection, layer-attribute observation,
  malformed-central rejection, and an injected in-range central-record read
  failure classified as `CL_EREAD`.
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

## Partition-intersection coordinate audit — 2026-08-26

- The shared APM/GPT/MBR intersection helper no longer adds attacker-
  controlled starts and sizes to test overlap. It compares ordered start
  distances instead, preventing wrapped interval ends from hiding a real
  overlap. A focused GCC object harness passes both large-coordinate
  directions and reports `CL_VIRUS`.
- Keep all three partition parser rows pending until complete partition-image
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and release evidence are complete.
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

## MSPack CAB/CHM output-close audit — 2026-08-27

- Preserve CAB/CHM extracted-output `fclose()` failures as `CL_EWRITE` and
  incomplete results through the decoder callback state, without hiding an
  earlier timeout, read, parser, or detection result.
- The current source passes the production warning-enabled GCC syntax check and
  source guards. Keep close-failure execution, complete corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and release qualification open.
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
- The public `CL_TYPE_SCRIPT` scanner now has a focused in-range callback-fault
  oracle; add malformed-input, output cleanup, full corpus, sanitizer,
  production-CVD/service, materialized large-file, and Sonic1 qualification.
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
- SCRENC mapped-input failures now preserve `CL_EREAD` through the scanner
  instead of flattening them to `CL_EPARSE`; add malformed-header, output
  close/write, full corpus, sanitizer, production-CVD/service, and Sonic1
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
- XAR now fails closed with `CL_EMEM` when an explicitly requested SHA-1 or
  MD5 checksum context cannot be allocated, instead of treating that required
  checksum as absent; add allocator-fault and broader XAR qualification.
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
- NSIS header admission and direct extraction now reject recognized layers with
  no input fmap as explicit incomplete parses; add compiled NSIS corpus and
  sanitizer qualification.
- PE direct scanning now rejects a recognized layer with no input fmap as an
  explicit incomplete parse; add compiled PE corpus, sanitizer, and production
  CVD qualification.
- OLE10 embedded-object admission now rejects a null context before temporary
  processing; add compiled OLE/OLE10 corpus and sanitizer qualification.
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

## Byte-compare normalizer admission — 2026-08-29

- Keep byte-compare signature lengths behind the bounded unsigned parser and
  retain `size_t` through comparison and normalization; reject negative or
  overflowing metadata before storage.
- Keep whitespace and odd-length hex NUL-terminated representations behind
  the individual allocation ceiling and checked size arithmetic. Retain
  `test_byte_compare_normalization_ceiling_is_fail_visible` and its source
  guards. Complete byte-compare corpus, production-linked unit execution,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  final matcher/release qualification remain open.

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

## RIFF bounded-parser qualification — 2026-08-25

- The current-source production-linked GCC `riff` case passes 6/6 for null
  context, header/chunk callback failures, truncated chunks, declared
  container boundaries, and timeout; `riff_map` passes 1/1 for missing-map
  admission, with the canonical MaxScanTime reason preserved.
- Add complete RIFF corpus, sanitizer, production-CVD/service parity,
  materialized large-file, and Sonic1 evidence before certification.

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
  odd-nibble, quintet-range, `z`, terminator, post-marker, complete
  marker-less, and partial-markerless-tail oracles.

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

## CPIO focused-map audit — 2026-08-25

- The focused `cpio_map` TCase covers truncated headers, NEWC member-name and
  initial-read callback failures, and impossible next headers; retain the
  existing CRC and numeric focused cases. Direct `cli_scancpio_*` missing-map
  admission needs a current ABI-consistent rebuild because the mixed harness
  signaled in that oracle.
- Run the focused CPIO map case with the rebuilt production-linked build, then
  complete CPIO corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, and Sonic1 qualification.

## DMG focused-map audit — 2026-08-25

- Promote the existing strict Base64/end, host-order stripe, bounded external
  sort, malformed metadata, trailer-read, and invalid-trailer regressions into
  `dmg_map` beside missing-map admission.
- The focused DMG map run passes 7/7. Complete DMG corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, and Sonic1
  qualification.

## EGG focused-map audit — 2026-08-25

- Promote fixed-header/extra-field range and admission, oversized skippable
  field, and bounded LZMA extraction regressions into `egg_map`; retain the
  broad timeout oracle until its fixture supplies scan options.
- The focused EGG map run passes 5/5. Complete EGG/EGGSFX corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service, and
  Sonic1 qualification.

- The isolated current-source production-linked `egg_sfx` case passes 1/1 for
  valid, unsupported-version, malformed, and truncated header admission;
  complete EGGSFX dispatch and nested-child coverage remain required.

## ELF focused-map audit — 2026-08-25

- Promote truncated-header/program-table and program-header/metadata callback
  failures into `elf_map` beside the existing null/missing-map entry tests.
- The focused ELF map run passes 6/6. Complete executable corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service, and
  Sonic1 qualification.

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

## MBR focused parser qualification — 2026-08-25

- The current-source production-linked GCC harness passes the dedicated `mbr`
  TCase 5/5 for master-record callback failure, MaxPartitions, missing-map
  entry points, native-width coordinate overflow, and timeout; the existing
  `partition_map` case passes 3/3 for MBR/GPT dispatch boundaries. The
  overflow fixture returns `CL_EFORMAT` with incomplete/non-cacheable state.
- Complete materialized partition-image corpus, full-C ABI-consistent
  execution, sanitizer, certified Linux x86-64, production-CVD/service
  parity, and Sonic1 evidence before certification.

## BZip2 focused-stream audit — 2026-08-25

- The focused compressed-stream subset runs the truncated-stream and
  input-read-failure oracles, passing 2/2. Preserve the shared GZip/XZ checks where the
  implementation is common.
- Re-run the concatenated-member and temporary-quota cases in a current
  ABI-consistent harness; the mixed harness currently produces zero loaded
  synthetic signatures and an adjacent XZ `CL_EFORMAT` result. Then complete
  BZip2 corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, and Sonic1 qualification.
## Mach-O direct-entry admission — 2026-08-25

- Preserve `CL_ENULLARG` for thin, universal, and metadata-wrapper Mach-O null
  contexts while keeping missing input maps fail-visible as incomplete parses.
- The dedicated `macho_map` regression covers both boundaries, and
  `macho_boundary` passes 1/1 for a declared load-command boundary. The
  current-source production-linked `macho` case passes 11/11 while
  `macho_timeout` passes 2/2 across callback/truncation, timeout,
  native-width, universal-range, alignment, and 32-bit entry-point overflow
  coverage. Keep executable corpus, sanitizer, materialized large-file,
  production-CVD, service, and Sonic1 qualification open.

## Mach-O focused parser audit — 2026-08-25

- Retain the null-options guards for optional heuristic/metadata reporting,
  reject 32-bit raw-address addition beyond `UINT32_MAX`, and keep x86 thread
  state entry-point extraction covered by source guards and the focused
  production-linked GCC regressions.
- The current-source `macho` TCase passes 11/11 and `macho_timeout` passes
  2/2, including a sparse synthetic universal-binary fmap. Complete full
  Mach-O corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, and Sonic1 qualification before parser completion.

## ELF direct-entry admission — 2026-08-25

- Preserve `CL_ENULLARG` for null ELF scan and metadata contexts while keeping
  missing input maps fail-visible as incomplete parses.
- The dedicated `elf_map` regression covers both direct entries. Keep
  executable corpus, sanitizer, materialized large-file, production-CVD,
  service, and Sonic1 qualification open.

## OLE2/XAR/RTF/JPEG boundary audit — 2026-08-25

- Retain the OLE2 XLM/BIFF declared-length and callback-failure semantics;
  the isolated production-linked `ole2_xlm` regression passes 1/1. Extend it
  to full OLE2/XLM corpus, sanitizer, materialized large-file, certified
  Linux x86-64, production-CVD/service, and Sonic1 qualification.
- Keep XAR TOC root-close admission, RTF complete description consumption, and
  JPEG clipped-versus-callback read classification pinned by source guards.
  The isolated map-boundary cases pass, but the broader XAR TCase must be
  rerun after relinking a current, ABI-consistent production harness; the
  mixed-generation binary's three XAR crashes are not current-source
  evidence.
- Rebuild the Rust archive from the authoritative source with a compatible
  Linux toolchain before accepting the `rust_map` null-context oracle. The
  current source guards are correct; the existing linked archive is stale,
  and the host offline Rust attempt stopped at missing OpenSSL development
  metadata without installing software.

## Matcher fixture and fail-visible boundary audit — 2026-08-25

- Keep the matcher unit fixture's bounded synthetic fmap callback and explicit
  failing callback aligned with the context-aware hash contract. The focused
  production-linked run had zero assertion failures across the 34 checks that
  completed, including the hash-read and no-generic-root incomplete-result
  oracles.
- Re-run the full matcher TCase after rebuilding all C objects as one
  ABI-consistent production harness. The current mixed-generation harness
  raises a teardown signal in `cl_engine_free()` after the hash case; do not
  treat that signal as current matcher-source evidence, but do not certify the
  matcher family until the clean rebuild passes.

## 7-Zip SFX admission audit — 2026-08-25

- Keep complete start-header admission for embedded 7-Zip candidates: weak
  magic must remain non-confirming, clipped headers must not taint the parent,
  and confirmed in-range callback failures must remain `CL_EREAD`, incomplete,
  and non-cacheable.
- The dedicated production-linked `7z_sfx` TCase passes 1/1 for the read
  failure oracle. Add valid nested-member, malformed, unsupported, production
  CVD, sanitizer, materialized large-file, and Sonic1 completion evidence
  before certifying the branch.

## APM partition-read boundary audit — 2026-08-25

- Keep the APM `apm_map` focused boundary coverage for missing maps and
  in-range partition-entry read failures. The production-linked TCase passes
  2/2 with `CL_EREAD`, sticky incomplete state, and non-cacheability preserved.
- Extend APM evidence to partition-count/table/coordinate limits, full corpus,
  sanitizer, certified Linux x86-64, materialized large-file, production-CVD,
  service, and Sonic1 qualification before certification.

## ARJ header-range audit — 2026-08-25

- The focused production-linked `arj_map` TCase passes 4/4 for context/map
  admission, fixed main-header read failure, declared filename-window read
  failure, and the declared-header string boundary. The fixture now injects
  the callback failure at the actual filename start (offset 34) rather than
  inside the fixed header.
- Preserve the ARJ `CL_EREAD`/`CL_EPARSE` and non-cacheability distinctions;
  extend evidence to full corpus, decoder, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification.

## ARJ-SFX nested admission audit — 2026-08-25

- The current-source production-linked `arjsfx` TCase now passes 3/3: a valid
  prefixed ARJ SFX is admitted through the embedded branch and its stored
  child reaches an exact offset-0 matcher; a confirmed but truncated main
  header returns `CL_EPARSE`; and an in-range header callback failure returns
  `CL_EREAD`. Both failure cases leave a clean verdict and mark the fmap
  non-cacheable.
- The full ARJ TCase still has the pre-existing mixed static/shared `cli_ctx`
  harness failures in both prior and newly relinked binaries; isolate and
  resolve that integration issue before release certification. Complete the
  ARJ-SFX corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, and Sonic1 evidence before certification.

## BinHex focused-boundary audit — 2026-08-25

- Expand the focused `binhex_map` TCase with admission, header-completion,
  timeout, data/resource truncation, temporary-quota, cleanup-close,
  encoded-input read-failure, and materialized `clam.exe.binhex` corpus
  oracles; the current production-linked run passes 11/11. Its exact embedded
  `MZP` marker is absent from the encoded outer bytes and is detected after
  BinHex extraction and nested handoff. A current full C rebuild remains
  required before certification.
- Preserve the bounded decoding, temporary-accounting, write/handoff deadline,
  and non-cacheable failure contracts; then complete BinHex corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service, and
  Sonic1 evidence.

## Mydoom detector boundary audit — 2026-08-25

- The focused `mydoom_map` TCase now includes null-context, missing-map, and
  detector-window read-failure admission; its current production-linked run
  passes 3/3. Keep the `CL_EREAD`, sticky-reason, and non-cacheable assertions
  source-guarded.
- Extend Mydoom evidence to compiled detector corpus, raw dispatch, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service, and
  Sonic1 qualification.

## AutoIt focused-entry audit — 2026-08-25

- The focused `autoit_map` TCase now includes the malformed-EA06,
  expired-deadline, and version/header read-failure regressions; its current
  production-linked run passes 4/4. Keep the source guards and
  fail-visible/non-cacheable assertions aligned with the parser's bounded
  traversal and temporary-accounting contract.
- Rebuild all C objects as one ABI-consistent production harness, then extend
  AutoIt evidence to full corpus, decoder, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification.

## ALZ current-source qualification audit — 2026-08-25

- Preserve the bounded ALZ `FMapReader`, quota-accounted spools, exact output
  size checks, deadline propagation, and fail-visible read/limit mappings.
  Current-source production-linked `rust_map` passes 1/1, and the locked Rust
  release suite passes all 34 ALZ unit tests with temporary C-engine link
  stubs.
- Complete ALZ corpus, current full-C ABI-consistent C execution, sanitizer,
  certified Linux x86-64, materialized large-file, production CVD/service,
  and Sonic1 evidence before changing `CL_TYPE_ALZ` from pending.

## LHA/LZH current-source qualification audit — 2026-08-25

- Preserve the bounded context-aware `FMapReader`, quota-accounted member
  spools, output/deadline checks, and fail-closed decoder panic boundary. The
  dedicated current-source production-linked `rust_lha` case passes 2/2 for
  direct and public-API in-range initial fmap read failures, while `rust_map`
  passes 1/1.
- Add valid LHA/LZH corpus and nested-member detection evidence, then complete
  the current full-C ABI build, sanitizer, certified Linux x86-64, materialized
  large-file, production CVD/service, and Sonic1 qualification before moving
  `CL_TYPE_LHA_LZH` beyond pending.

## OneNote current-source qualification audit — 2026-08-25

- Preserve the OneNote fixed-prefix distinction: the current-source
  production-linked `rust_onenote` TCase passes 2/2 for in-range read failure
  versus genuine truncation, the shared `rust_map` case passes 1/1, and the
  focused `onenote` case passes 2/2, including the direct parser-entrypoint
  corpus oracle over all three materialized fixtures and the independent
  dynamic-configuration boundary.
- Preserve the direct extracted-attachment matcher evidence, then complete the
  current full-C ABI build, sanitizer, certified Linux x86-64, materialized
  large-file, production CVD/service, and Sonic1 qualification before moving
  `CL_TYPE_ONENOTE` beyond pending.

## CAB current-source corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `mspack` TCase now
  passes 6/6, including the direct `cli_scanmscab()` oracle over materialized
  `clam.cab`; its nonzero-offset marker is detected only after CAB member
  extraction and nested handoff. Preserve the `mspack_map` 5/5 boundary
  evidence.
- Complete CAB/CHM and InstallShield corpus, full-C ABI-consistent execution,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 qualification before moving
  `CL_TYPE_MSCAB` or `CL_TYPE_MSCHM` beyond pending.

## MSEXPAND current-source corpus qualification — 2026-08-25

- The authoritative current-source production-linked GCC `msexpand` TCase now
  passes 5/5, including materialized `clam.exe.szdd` through public
  `CL_TYPE_MSSZDD` dispatch. Its child-offset matcher proves the exact marker
  is found after decompression and nested handoff rather than in the
  compressed root.
- Complete the SZDD corpus and full-C ABI-consistent execution, then add
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## GZip current-source qualification audit — 2026-08-25

- The expanded current-source production-linked `bz_core` TCase passes 5/5,
  including the dedicated valid-GZip in-range callback-failure oracle that
  preserves `CL_EREAD`, a clean verdict, and non-cacheability, the shared
  truncated-stream/compressed-input boundaries, and both materialized GZip
  corpus fixtures with nested `MZP` detection.
- Extend GZip and legacy-fallback evidence to complete corpus, full-C
  ABI-consistent execution, sanitizer, certified Linux x86-64, materialized
  large-file, production CVD/service parity, and Sonic1 qualification before
  certification.

## HTML normalization read-status audit — 2026-08-25

- Preserve the new normalizer-to-scanner read-status plumbing: an in-range
  fmap callback failure now returns `CL_EREAD`, keeps the layer incomplete and
  non-cacheable. The broader current-source production-linked `bz_map` run is
  a mixed-ABI gate because its HTML oracle returns a different public error
  code; the isolated `bz_core` run passes 3/3 for the compressed boundaries.
- Extend HTML, RFC2397, and script-normalization evidence to complete corpus,
  full-C ABI-consistent execution, sanitizer, certified Linux x86-64,
  materialized large-file, production CVD/service parity, and Sonic1
  qualification before certification.

## UTF-16 HTML current-source qualification audit — 2026-08-25

- The current-source production-linked `text_encoding` TCase passes 3/3,
  including the dedicated UTF-16 HTML initial-byte-order read-failure oracle,
  which preserves `CL_EREAD`, a clean verdict, and non-cacheability.
- Extend UTF-16 HTML evidence to complete corpus, full-C ABI-consistent
  execution, sanitizer, certified Linux x86-64, materialized large-file,
  production CVD/service parity, and Sonic1 qualification before
  certification.

## HWP3 current-source qualification audit — 2026-08-25

- The isolated current-source production-linked `hwp3_api` TCase passes 1/1
  through `cl_scanmap_ex` for an in-range document-info read failure, keeping
  `CL_EREAD`, clean verdict, and non-cacheability visible. The detailed direct
  `cli_ctx` matrix remains a mixed-ABI full-C rebuild gate after 8 signal
  errors in its 16-check run.
- Complete the HWP3 corpus and full-C ABI-consistent matrix, then add
  sanitizer, certified Linux x86-64, materialized large-file, production
  CVD/service parity, and Sonic1 evidence before certification.

## MIME public API read-failure audit — 2026-08-25

- The dedicated current-source production-linked `mail_api` TCase passes 2/2
  through `cl_scanmap_ex` for `CL_TYPE_MAIL` and `CL_TYPE_MHTML` in-range MIME
  line read failures, preserving `CL_EREAD`, clean verdicts, and
  non-cacheability. Existing direct mbox line/header-lookahead failures and
  public truncated attachment cases remain in the boundary matrix.
- Complete MIME/mbox/MHTML corpus and full-C ABI-consistent execution, then
  add sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## Mail/mbox focused parser audit — 2026-08-25

- The current-source production-linked GCC harness executes the dedicated
  `mail` TCase as 10 checks with zero assertion failures across initial MIME
  input, missing-map, line and header-lookahead callback, timeout, oversized-
  line, UUEncode, and truncated BinHex boundaries, but the timeout test
  retains the known mixed old/current `cli_ctx` ABI SIGSEGV. The isolated
  invalid-partial-count `mail_partial` TCase passes 1/1. Truncated BinHex
  returns the parser's explicit `CL_EFORMAT` failure while retaining
  incomplete/non-cacheable state; the existing `mail_api` TCase passes 2/2
  for public `CL_TYPE_MAIL` and `CL_TYPE_MHTML` initial-read failures.
- Complete the MIME/mbox/MHTML corpus, streaming 64–65 MiB CVD-backed tests,
  full-C ABI-consistent execution, sanitizer, certified Linux x86-64,
  materialized large-file, production CVD/service parity, and Sonic1 evidence
  before certification.

## MHTML focused parser qualification — 2026-08-25

- The current-source production-linked GCC harness passes the dedicated
  `mhtml` TCase 4/4 for unterminated and oversized comment XML, a 65 MiB
  streamed multipart/related HTML root, and public `CL_TYPE_MHTML` initial
  input failure. Header/boundary admission remains bounded while long HTML
  body chunks stream through the disk-backed spool.
- Complete MHTML/HTML corpus, full-C ABI-consistent execution, sanitizer,
  certified Linux x86-64, production-CVD/service parity, materialized
  large-file, and Sonic1 evidence before certification.

## MSEXPAND public API read-failure audit — 2026-08-25

- The isolated current-source production-linked `msexpand_map` TCase passes
  2/2 for missing-map admission and a public `CL_TYPE_MSSZDD` fixed-header
  callback failure, preserving `CL_EREAD`, a clean verdict, and
  non-cacheability; direct tests retain truncation, output, temporary-limit,
  and timeout coverage.
- Complete SZDD/MSEXPAND corpus and full-C ABI-consistent execution, then add
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## MSPack current-source boundary qualification — 2026-08-25

- The focused current-source production-linked `mspack_map` TCase passes 5/5
  across CAB/CHM missing-map, decoder read, clipped-read, constructor, and
  callback-timeout boundaries. Required failures remain incomplete and
  non-cacheable, with the shared timeout reason preserved.
- Complete CAB/CHM and InstallShield corpus and full-C ABI-consistent
  execution, then add sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service parity, and Sonic1 evidence before
  certification.

## CHM corpus dispatch qualification — 2026-08-25

- The expanded current-source production-linked GCC `mspack` case passes 5/5,
  including public `cl_scanmap_ex` scanning of materialized `clam.chm`; its
  exact embedded `MZP` marker is absent from the CHM outer bytes and is
  detected after member extraction and nested handoff.
- Add full CAB/CHM and InstallShield corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and release
  evidence before certification.

## PE focused parser qualification — 2026-08-25

- The focused current-source production-linked GCC `pe` TCase passes 11/11,
  and `pe_map` passes 2/2 across missing-map admission, public-API and direct
  header read/truncation boundaries, native-width PE coordinates, version
  resources, and icon-resource truncation/range/tree failures. Required
  failures remain incomplete and non-cacheable; in-range callback failures
  preserve `CL_EREAD`.
- Complete the PE corpus and unpacker/heuristic/resource-fault matrix in
  full-C ABI-consistent execution, then add sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service parity, and Sonic1 evidence
  before certification.

## OLE2 focused parser qualification — 2026-08-25

- The focused current-source production-linked GCC `ole2` TCase passes 13/13;
  `ole2_xlm` and `ole2_map` pass 2/2 each across missing-map/API admission,
  header/property-tree faults, MSO prefix and CFB geometry boundaries, VBA
  materialization, timeout, native encryption-window read faults, output-close
  propagation, XLM sector handling, a partial BIFF record at the declared
  WorkBook boundary, 64-bit stream sizes, and materialized PowerPoint child
  detection. Required failures
  remain incomplete and non-cacheable, with `CL_EREAD` and the shared timeout
  reason preserved.
- Complete the OLE/VBA/XLM corpus and fixture-specific sector, quota, and
  Word/Workbook probe matrix in full-C ABI-consistent execution, then add
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## MSEXPAND focused parser qualification — 2026-08-25

- The focused current-source production-linked GCC `msexpand` TCase passes
  4/4 and `msexpand_map` passes 2/2 across header truncation/read failure,
  missing input, truncated/overproduced output, scan-size and temporary-size
  limits, and timeout. The decoder preserves `CL_EPARSE` versus `CL_EFORMAT`,
  public header faults preserve `CL_EREAD`, and timeout keeps the shared
  `Heuristics.Limits.Exceeded.MaxScanTime` reason.
- Complete the compiled SZDD corpus and full-C ABI-consistent execution, then
  add sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## NSIS/SFX focused parser qualification — 2026-08-25

- The focused current-source production-linked GCC `nulsft` TCase passes 4/4
  and `nulsft_map` passes 2/2 across NSIS header truncation/read failure,
  null/missing-map entry points, public `CL_TYPE_NULSFT` read-failure
  dispatch, and timeout, preserving `CL_EREAD`, incomplete/non-cacheable
  state, and the shared timeout reason.
- Complete the NSIS/SFX corpus and decoder member-table/raw/compressed/
  solid-stream fault matrix in full-C ABI-consistent execution, then add
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## TAR focused boundary qualification — 2026-08-25

- The focused current-source production-linked GCC `tar` TCase passes 6/6
  across truncated headers/end markers, timeout, initial-header read failure,
  invalid magic, and temporary-size admission, preserving fail-visible
  incomplete/non-cacheable state, `CL_EREAD`, and the shared timeout reason.
- The signature-driven `tar_member` cases remain unclaimed because temporary
  custom-signature loading failed in the reusable fixture; complete GNU
  base-256/PAX/member corpus and full-C ABI-consistent execution, then add
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## HWPOLE2 current-source qualification audit — 2026-08-25

- The current-source production-linked `hwpole2_map` TCase passes 2/2 for
  missing-map admission and a public-API fixed-prefix read failure, preserving
  `CL_EREAD`, clean verdict, and non-cacheability; direct tests retain
  truncation, declared-size, and 32-bit-width coverage.
- Extend HWPOLE2/OLE evidence to complete corpus, full-C ABI-consistent
  execution, sanitizer, certified Linux x86-64, materialized large-file,
  production CVD/service parity, and Sonic1 qualification before
  certification.

## PE public API read-failure audit — 2026-08-25

- The isolated current-source production-linked `pe_map` TCase passes 2/2 for
  missing-map admission and a public `CL_TYPE_MSEXE` DOS-header callback
  failure, preserving `CL_EREAD`, a clean verdict, and non-cacheability.
- Complete PE-specific corpus and full-C ABI-consistent execution, then add
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## OLE2 public API read-failure audit — 2026-08-25

- The isolated current-source production-linked `ole2_map` TCase passes 2/2
  for missing-map admission and a public `CL_TYPE_MSOLE2` fixed-header
  callback failure, preserving `CL_EREAD`, a clean verdict, and
  non-cacheability; direct tests retain CFB sector, encryption-probe,
  property-tree, geometry, temporary-limit, and timeout coverage.
- Complete OLE/VBA/XLM corpus and full-C ABI-consistent execution, then add
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## NSIS public API read-failure audit — 2026-08-25

- The isolated current-source production-linked `nulsft_map` TCase passes 2/2
  for direct missing-map entry points and a public `CL_TYPE_NULSFT`
  fixed-header callback failure, preserving `CL_EREAD`, a clean verdict, and
  non-cacheability; direct tests retain truncation, decoder/output,
  temporary-limit, and timeout coverage.
- Complete NSIS corpus and full-C ABI-consistent execution, then add
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## AutoIt public API read-failure audit — 2026-08-25

- The isolated current-source production-linked `autoit_map` TCase now
  covers missing-map admission, direct version/header failures, and a public
  `CL_TYPE_AUTOIT` fixed-header callback failure, preserving `CL_EREAD`, a
  clean verdict, and non-cacheability; malformed EA06 admission and timeout
  coverage remain in the direct matrix.
- Complete AutoIt EA05/EA06 corpus and full-C ABI-consistent execution, then
  add sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## AutoIt SFX nested admission audit — 2026-08-25

- The current-source production-linked `autoit_sfx` TCase passes 1/1: a
  minimal prefixed MZ-rooted AutoIt EA05 signature is admitted through the
  embedded branch and its exact offset-0 child marker is detected in the
  nested layer.
- Add malformed and callback-failure SFX cases, then complete AutoIt
  EA05/EA06 corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, and Sonic1 evidence before
  certification.

## PDF public API read-failure audit — 2026-08-25

- The focused current-source production-linked `pdf_map` TCase now includes a
  public `CL_TYPE_PDF` version-window callback failure, preserving `CL_EREAD`,
  a clean verdict, and non-cacheability; direct parser, trailer-xref,
  malformed-object, filter, crypt, quota, and cleanup cases remain covered.
- Complete PDF corpus and full-C ABI-consistent execution, then add sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service
  parity, and Sonic1 evidence before certification.

## Graphics fallback public API read-failure audit — 2026-08-25

- The isolated current-source production-linked `graphics_map`/`graphics_api`
  TCases now cover missing-map admission and a public `CL_TYPE_GRAPHICS`
  callback failure, preserving `CL_EREAD`, a clean verdict, and
  non-cacheability;
  generic graphics without a structural parser remain explicit incomplete.
- Complete BMP/JPEG 2000 and generic-graphics corpus and full-C
  ABI-consistent execution, then add sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service parity, and Sonic1 evidence
  before certification.

- The isolated current-source `graphics_api` case passes 1/1; rebuild the
  broader `graphics_map` direct BMP/JPEG 2000/TIFF error-code matrix with a
  consistent ABI before counting it as production-linked evidence.

## GIF public API read-failure audit — 2026-08-25

- The isolated current-source production-linked `gif_api` TCase covers a
  public `CL_TYPE_GIF` header read failure, preserving `CL_EREAD`, a clean
  verdict, and non-cacheability; direct signature/version, truncation,
  timeout, and missing-map cases remain covered.
- Complete GIF corpus and full-C ABI-consistent execution, then add sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service
  parity, and Sonic1 evidence before certification.

## SWF public API read-failure audit — 2026-08-25

- The isolated current-source production-linked `swf_api` TCase covers a
  public `CL_TYPE_SWF` fixed-header read failure, preserving `CL_EREAD`, a
  clean verdict, and non-cacheability; direct missing-map, frame metadata,
  compressed-input, decoder/output-limit, cleanup, and timeout cases remain.
- Complete SWF corpus and full-C ABI-consistent execution, then add sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service
  parity, and Sonic1 evidence before certification.

## CPIO production-linked focused audit — 2026-08-25

- The rebuilt current-source production-linked harness passes `cpio_map` 4/4,
  `cpio_crc` 4/4, and `cpio_numeric` 1/1. These cases cover all four CPIO
  fixed-header forms, NEWC callback boundaries, impossible coordinates, CRC
  nested matching/mismatch/multiwindow/read-failure behavior, and strict ODC
  plus newc numeric fields.
- Keep all CPIO rows pending until direct missing-map/null-context matrices,
  complete old/ODC/newc/CRC corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service parity, and Sonic1 evidence
  are complete.

## CryptFF public API read-failure audit — 2026-08-25

- The current-source production-linked `cryptff` TCase passes 3/3 for
  temporary-output write/close, quota, and timeout boundaries, while the
  isolated `cryptff_api` TCase covers a public `CL_TYPE_CRYPTFF` source-window
  callback failure, preserving `CL_EREAD`, clean verdict state, and
  non-cacheability.
- Complete CryptFF corpus and full-C ABI-consistent execution, then add
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 evidence before certification.

## CAB SFX nested admission audit — 2026-08-25

- The current-source production-linked `cabsfx` TCase passes 1/1 for a valid
  prefixed CAB SFX whose extracted child reaches an exact offset-0 matcher
  through public map scanning.
- The 2026-08-26 source update adds public malformed-header and in-range
  callback-failure cases; execute them in a current-source production-linked
  harness, then complete CAB and SFX corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service parity, and Sonic1 evidence.

## CAB SFX admission failure audit — 2026-08-26

- Public CABSFX regressions now cover the valid prefixed CAB child match,
  confirmed declared-extent truncation (`CL_EPARSE`), and in-range fixed-header
  callback failure (`CL_EREAD`), with clean verdict reset and non-cacheability.
- Complete CAB/SFX corpus, full-C ABI-consistent execution, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service
  parity, and Sonic1 qualification remain release gates.

## BZip2/GZip isolated core audit — 2026-08-25

- The isolated current-source production-linked `bz_core` TCase passes 5/5
  for truncated compressed streams, BZ/GZip callback failures, and the
  BZip2/GZip materialized nested-MZP corpus cases; retain the broader HTML
  dispatch mismatch as a mixed-harness rebuild gate rather than counting it
  as compressed-parser evidence.
- Complete BZ/GZip concatenated-member, legacy-fallback, and temporary-quota
  corpus, full-C ABI-consistent execution, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service parity, and Sonic1
  qualification.

## ELF64 table-cursor overflow audit — 2026-08-26

- Keep explicit checked advances for ELF64 program- and section-header table
  cursors. Complete-range preflight already rejects an entry that cannot fit;
  the additional invariant prevents a future read path from wrapping to an
  unrelated low-offset structure. The parser compiles warning-clean under the
  production GCC flags; existing `elf_map` 8/8 and `elf_corpus` 1/1 evidence
  remains valid.
- Add a direct overflow-injection regression, then complete ELF corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service parity, and Sonic1 qualification.

## CPIO member-name termination audit — 2026-08-26

- Validate the final declared name byte in old-binary, ODC, NEWC, and CRC CPIO
  members before advancing to padding or payload. A missing terminator is an
  incomplete `CL_EPARSE`; an in-range callback failure remains `CL_EREAD`.
- The current-source public-API regression covers all four forms and verifies
  a clean verdict reset and non-cacheability. Keep complete CPIO corpus,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification as release
  gates.

## MSXML bounded attribute representation audit — 2026-08-27

- Legacy and streaming MSXML now fail closed when a callback element declares
  more than the fixed `MAX_ATTRIBS` metadata representation; silently omitted
  attributes can no longer drive a partial nested scan.
- The dual-path focused regression covers the legacy reader and streaming SAX
  parser and verifies `CL_EPARSE`, sticky incompleteness, and non-cacheability.
  Keep full MSXML/XDP/HWPML corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, and Sonic1 qualification
  as release gates.

## TIFF first-IFD offset arithmetic audit — 2026-08-27

- Reject a first IFD offset beyond the containing map before subtracting it
  from `map->len`; the direct TIFF test verifies `CL_EPARSE`, sticky
  incompleteness, the specific reason, and non-cacheability.
- The existing focused production-linked TIFF case remains 8/8; the new ninth
  direct regression is registered and compile-checked but still needs runtime
  execution in a current-source production-linked harness. Keep full
  TIFF/image corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  open.

## Logical matcher definition-boundary audit — 2026-08-27

- Replace prefix-accepting logical-expression number scans with bounded exact
  decimal parsing, reject chained leaf modifiers and `unsigned int` overflow,
  and validate referenced subsignature IDs against the declared count before
  indexing runtime arrays.
- Validate logical macro table/pattern/group state before dereference. The
  focused parser harness passes valid block-modifier forms and rejects suffix
  and overflow cases; the four new public regressions are registered and
  compile-checked with production GCC but await a current-source
  production-linked matcher TCase.
- Keep full logical-expression and production-signature corpus, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification open.

## Bytecode type-layout admission audit — 2026-08-27

- Resolve parsed type layouts after the complete type table is available with
  an explicit bounded traversal; reject recursive by-value arrays/structures,
  empty or oversized layouts, invalid children/alignment, and constant
  component products above the individual allocation ceiling.
- The current-source bytecode and unit-test translation units compile with
  production GCC warning flags. Recursive and UINT_MAX-array loader
  regressions are registered but await a fresh production-linked TCase;
  retain full bytecode fixture/interpreter/JIT corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification as release gates.

## ISO9660 descriptor-sequence coverage audit — 2026-08-27

- Validate the primary descriptor before ISO admission and walk every complete
  descriptor through the declared volume boundary instead of stopping at
  sector 31. Require the valid `0xff/CD001` terminator and retain checked
  coordinate arithmetic plus per-descriptor deadline checks.
- The late-terminator regression now passes in the current-source
  production-linked `iso_map` case, 12/12; the `iso` case passes 1/1 across
  both materialized logo fixtures. Keep full ISO corpus, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification open.

## HFS+ declared-volume boundary audit — 2026-08-27

- Validate the HFS+ `totalBlocks * blockSize` volume extent before tree or
  fork admission, including the minimum range containing the volume header,
  so a mapped prefix cannot be reported clean when the declared volume is
  truncated at EOF. The exact tail-truncation regression is registered and
  current-source GCC compile-checked. A temporary current-source
  production-linked GCC harness passes the same boundary with sticky
  incomplete/non-cacheable state; retain complete corpus, sanitizer, certified
  Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification as release
  gates.

## UDF file-identifier ICB correlation audit — 2026-08-27

- Pair UDF File Identifier Descriptors with File Entries using the
  partition-relative ICB/tag locations defined by ECMA-167 rather than list
  position; reject unmatched references as sticky, non-cacheable
  `CL_EPARSE`.
- The current-source production-linked GCC `udf_map` case passes 9/9 and
  `udf_corpus` passes 1/1, including exact child detection, clean-volume
  completion, and the ICB mismatch regression. Keep complete UDF corpus,
  sanitizer, certified Linux x86-64, materialized large file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## Encrypted OLE2 stream cleanup fail-visible audit — 2026-08-27

- Mark any unclassified encrypted OTF traversal, seek, or materialization
  error at cleanup so a required encrypted stream cannot return an error while
  leaving its fmap cacheable; preserve the first specific incomplete reason.
- The touched source compiles with production GCC flags and the isolated
  current-source `ole2_xlm` and `ole2_map` cases pass 2/2 each. The available
  encrypted fixture uses a non-default password and stops at the existing
  `CL_EUNPACK` fail-closed path before materialization, so short-write fault
  injection remains an explicit test gap. Keep complete OLE/VBA/XLM corpus and
  fault matrix, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## MSEXPAND invalid-magic classification audit — 2026-08-27

- Mark invalid SZDD fixed magic as an incomplete, non-cacheable `CL_EFORMAT`
  result at the direct decoder boundary; explicit `CL_TYPE_MSSZDD` dispatch
  must not publish an unclassified malformed-header failure.
- The new regression is included in the current-source GCC harness and
  `msexpand_map` passes 2/2. The broader reused harness still has known
  mixed-generation timeout/corpus failures, so complete SZDD corpus, full-C
  execution, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain open.

## 7-Zip cleanup-status precedence audit — 2026-08-27

- Upgrade `CL_BREAK` as well as clean/trusted statuses when temporary 7-Zip
  output close or unlink fails, while preserving detections and earlier parser
  errors; keep the direct status-precedence regression and complete 7-Zip/
  7-Zip-SFX, sanitizer, certified Linux x86-64, materialized-large-file,
  production-CVD/service, Sonic1, and parser-family qualification gates open.

## ALZ/Rust temporary-spool cleanup audit — 2026-08-27

- Keep shared Rust temporary spools explicitly and idempotently finalized at
  successful ALZ, OneNote, LHA/LZH, and reader-helper nested-scan boundaries;
  close, unlink, and reservation failures must upgrade clean, verified, and
  `CL_BREAK` statuses while preserving detections and earlier parser errors,
  and must mark the containing parser incomplete/non-cacheable.
- The direct cleanup-precedence regression and source guards are present. Fresh
  Rust execution is open because the host lacks OpenSSL/pkg-config metadata and
  the reusable Linux container has an older Cargo plus an incomplete offline
  git-dependency cache. Keep current-C ABI, sanitizer, certified Linux x86-64,
  materialized large-file/resource, production-CVD/service, Sonic1, and final
  parser-family qualification open.

## BinHex cleanup-status precedence audit — 2026-08-27

- Preserve distinct `CL_EWRITE` close and `CL_EUNLINK` unlink failures for
  BinHex temporary forks; upgrade clean, verified, and `CL_BREAK` statuses
  while preserving detections and earlier parser/resource errors, and keep
  every cleanup failure incomplete/non-cacheable.
- The current BinHex object passes the production warning-enabled GCC syntax
  check and source guards cover the new status helper plus existing cleanup
  regression. The prior coherent production-linked `binhex_map` case remains
  11/11; a fresh current-object full relink and execution are open. Keep full
  BinHex corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## Shared compressed-output cleanup audit — 2026-08-27

- Keep `cli_cleanup_compressed_temp()` fail-visible across GZip, BZip2, XZ,
  SZDD, RAR, and compressed metadata paths: distinguish close/unlink failures,
  upgrade clean, verified, and `CL_BREAK`, and preserve detections and earlier
  parser/resource errors.
- The helper declaration, direct precedence regression, and source guards are
  present; current scanner syntax checking passes with only pre-existing
  scanner warnings. Fresh full Check execution remains open because the
  reusable harness has mixed-generation test/object gaps. Keep complete
  compressed-parser corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  open.

## InstallShield cleanup-status precedence audit — 2026-08-27

- Make MSI, legacy embedded-file, and CAB temporary-output close/unlink
  failures fail-visible through the shared cleanup-status helper: preserve
  `CL_EWRITE` versus `CL_EUNLINK`, upgrade clean/verified/`CL_BREAK`, and keep
  detections or earlier parser/resource errors authoritative.
- The current InstallShield source passes the established GCC syntax check and
  source guards cover all six cleanup call sites. The common direct precedence
  regression covers the status contract; current-object production-linked
  execution, corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  remain open.

## HWP and TAR cleanup-status precedence audit — 2026-08-27

- Make HWP decompressed output, HWPML decoded output, and TAR member staging
  cleanup fail-visible through the shared helper: preserve `CL_EWRITE` versus
  `CL_EUNLINK`, upgrade clean/verified/`CL_BREAK`, and keep detections or
  earlier parser/resource errors authoritative.
- Current HWP and TAR sources pass the established warning-enabled GCC syntax
  checks with no diagnostics, and source guards cover the cleanup call sites.
  Existing focused production-linked results remain prior-object evidence;
  current-object execution, complete corpora, sanitizer, certified Linux
x86-64, materialized large-file, production-CVD/service, Sonic1, and
parser-family qualification remain open.

## XLM/OLE2 cleanup-status precedence audit — 2026-08-27

- Make XLM macro input, temporary-output, and temporary-file cleanup
  fail-visible through the shared helper: preserve `CL_EREAD`, `CL_EWRITE`,
  and `CL_EUNLINK`, upgrade clean/verified/`CL_BREAK`, and keep detections or
  earlier parser/resource errors authoritative.
- The current XLM source passes the established GCC syntax check with its
  pre-existing signedness warnings, and source guards cover all three cleanup
  status classes and call sites. Current-object execution, complete
  OLE/VBA/XLM corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## HFS+ cleanup-status precedence audit — 2026-08-27

- Make HFS+ fork, compressed-resource, and temporary-directory cleanup
  fail-visible through the shared helper: preserve `CL_EWRITE` versus
  `CL_EUNLINK`, upgrade clean/verified/`CL_BREAK`, retain detections or earlier
  parser/resource errors, and mark every cleanup failure incomplete.
- The current HFS+ source passes the established warning-enabled GCC syntax
  check with no diagnostics, and source guards require the shared helper plus
  removal of the old status-only pattern. Current-object execution, complete
  HFS+ corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain
  open.

## RAR and script-normalization cleanup audit — 2026-08-27

- Make optional RAR descriptor/file cleanup and script normalized-output
  cleanup fail-visible through the shared helper: preserve `CL_EREAD`,
  `CL_EWRITE`, and `CL_EUNLINK`, upgrade `CL_BREAK`, retain detections or
  earlier parser/resource errors, and keep cleanup failures non-cacheable.
- The current scanner source passes the established GCC syntax check with
  known mixed-generation warnings, and source guards cover the RAR/script
  helper calls. Current-object execution, complete corpora, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification remain open.

## DMG cleanup-status precedence audit — 2026-08-27

- Make DMG XML staging, reconstructed-partition output, external metadata
  sorting, and temporary-directory cleanup fail-visible: preserve
  `CL_EWRITE` versus `CL_EUNLINK`, upgrade clean/verified/`CL_BREAK`, and
  retain detections or earlier parser/resource errors.
- Use a single XML-staging cleanup exit so close failures remain visible on
  timeout, read, reservation, and write exits. Current source guards and GCC
  syntax evidence cover the change; current-object execution, complete
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain
  open.

## ISO9660 and UDF cleanup-status precedence audit — 2026-08-27

- Make ISO9660 and UDF temporary-output close/unlink cleanup fail-visible
  through the shared helper: preserve `CL_EWRITE` versus `CL_EUNLINK`,
  upgrade clean/verified/`CL_BREAK`, and retain detections or earlier
  parser/resource errors as authoritative.
- The current source guards cover both parser call sites. Existing focused
  ISO9660 and UDF production-linked evidence remains prior-object evidence;
  current-object execution, complete corpora, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification remain open.

## ZIP cleanup-status precedence audit — 2026-08-27

- Make ZIP stored/legacy/encrypted member staging and temporary-directory
  cleanup fail-visible through the shared helper: preserve `CL_EWRITE`
  versus `CL_EUNLINK`, upgrade clean/verified/`CL_BREAK`, and retain
  detections or earlier parser/resource errors.
- Route legacy rewind failures through descriptor close and temporary-path
  cleanup so the error cannot leak a temporary file. Current source guards
  cover the helper calls; complete archive corpus, current-object execution,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain
  open.

## SWF and CAB/CHM cleanup-status precedence audit — 2026-08-27

- Preserve `CL_EWRITE` for SWF temporary-output close failures and
  `CL_EUNLINK` for removal failures through the shared cleanup helper.
- Make CAB/CHM temporary-file removal fail-visible through the shared MSPACK
  helper, upgrading `CL_BREAK` while retaining detections and earlier
  parser/resource errors. Current source guards and GCC syntax evidence cover
  the change; complete SWF/CAB/CHM corpora, current-object execution,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain
  open.

## ARJ, NSIS, and shared scanner cleanup audit — 2026-08-27

- Make ARJ output/directory, NSIS output/member/directory, and shared
  reserved-file/directory cleanup use the common precedence helper. Preserve
  `CL_EWRITE`, `CL_EREAD`, and `CL_EUNLINK` by operation, upgrade
  clean/verified/`CL_BREAK`, and retain detections or earlier parser errors.
- Current GCC syntax and source guards cover the paths; complete ARJ/NSIS
  corpora, current-object execution, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## PDF and ELF cleanup-status precedence audit — 2026-08-27

- Route PDF generated/staged output and ELF bytecode-unpacked output cleanup
  through the shared helper, preserving `CL_EWRITE` versus `CL_EUNLINK`,
  upgrading clean/verified/`CL_BREAK`, and retaining detections or earlier
  parser/resource errors.
- Current source guards and GCC syntax evidence cover both helpers; current
  object execution, complete corpora, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## OLE2 cleanup-status precedence audit — 2026-08-27

- Make the OLE2 cleanup notifier preserve `CL_EWRITE` for close and
  `CL_EUNLINK` for removal, upgrade clean/verified/`CL_BREAK`, and retain
  detections or earlier parser/resource errors.
- Keep zlib-finalization failure classified separately as `CL_EUNPACK`.
  Current source guards and GCC syntax evidence cover the change; current
  object execution, complete OLE/VBA/XLM corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification remain open.

## XAR cleanup-status handoff audit — 2026-08-27

- Apply returned XAR member/TOC close and unlink cleanup statuses through the
  shared helper for every prior result, including `CL_BREAK`; preserve
  `CL_EWRITE`/`CL_EUNLINK` and detections or earlier parser errors.
- Current source guards and GCC syntax evidence cover the handoff. Complete
  XAR corpus, current-object execution, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## RTF, SIS, and AutoIt cleanup-status precedence audit — 2026-08-27

- Route RTF, SIS, and AutoIt descriptor close, member/path removal,
  temporary-directory cleanup, and deferred RTF callback teardown through the
  shared cleanup-status precedence helper. Preserve `CL_EWRITE` versus
  `CL_EUNLINK`, upgrade `CL_BREAK`, and retain detections or earlier parser or
  resource errors.
- Current AutoIt, RTF, and SIS sources pass GCC syntax checks and source
  guards cover the handoffs; current-object execution, complete corpora,
  sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification remain
  open.

## EGG and OLE2 scanner cleanup-status audit — 2026-08-27

- Route EGG member spool teardown and OLE2 summary, VBA, PowerPoint,
  embedded-stream, directory, and scan-level temporary cleanup through the
  shared precedence helper. Preserve `CL_EWRITE` for temporary output close,
  `CL_EREAD` for input/directory close, and `CL_EUNLINK` for removal; retain
  detections and earlier parser/resource errors.
- Canonical-header GCC syntax and source guards cover the scanner changes;
  current-object execution, complete EGG/OLE2/VBA corpora, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification remain open.

## PE unpacker cleanup-status audit — 2026-08-27

- Route PE unpacker macro and direct UPX/FSG temporary descriptor/path cleanup
  through a shared helper. Preserve `CL_EWRITE` for close and `CL_EUNLINK`
  for removal, upgrade clean/verified/`CL_BREAK`, and retain detections or
  earlier parser/resource errors across all enabled unpacker paths.
- Current PE source passes the canonical-header GCC syntax check and source
  guards cover the helper; current-object execution, complete unpacker and
  heuristic corpora, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  remain open.

## Bytecode and JavaScript output cleanup-status audit — 2026-08-27

- Route bytecode VM/API temporary and unpacked-output teardown, truncation,
  and JavaScript normalized-output close through the shared cleanup-status
  precedence helper. Preserve `CL_EWRITE`, upgrade `CL_BREAK`, and retain
  detections or earlier parser, resource, or timeout errors while marking
  required cleanup failures incomplete.
- Current GCC syntax and source guards cover the changed paths;
  current-object execution, complete bytecode/script corpora, sanitizer,
  certified Linux x86-64, materialized large-file, production-CVD/service,
  Sonic1, and parser-family qualification remain open.

## OLE10 extraction cleanup-status precedence audit — 2026-08-27

- Route OLE10 temporary-output close and unlink failures through the shared
  cleanup-status precedence helper, preserving `CL_EWRITE` and `CL_EUNLINK`
  without hiding earlier parser, resource, timeout, or detection results.
- Source guards cover both handoffs; current-object execution, complete
  OLE2/VBA/PowerPoint corpora, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## VBA project and PowerPoint cleanup-status audit — 2026-08-27

- Preserve cleanup failures for file-backed VBA directory backing, module
  inputs, mapped metadata, and project outputs through the shared status
  helper; record PowerPoint temporary-output unlink failures as incomplete.
- Current GCC syntax and source guards cover the handoffs; current-object
  execution, complete OLE2/VBA/PowerPoint corpora, sanitizer, certified Linux
x86-64, materialized large-file, production-CVD/service, Sonic1, and
parser-family qualification remain open.

## MSXML temporary-output cleanup-status audit — 2026-08-27

- Preserve `CL_EWRITE` for MSXML callback/Base64/streaming output close
  failures and `CL_EUNLINK` for removals through the shared precedence helper;
  retain earlier XML, callback, timeout, resource, or detection results.
- Current GCC syntax and source guards cover the changed paths; current-object
  execution, complete MSXML/OOXML/XDP/HWPML corpora, sanitizer, certified
 Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
 parser-family qualification remain open.

## PDF referenced-object cleanup audit — 2026-08-27

- Centralize PDFNG referenced-object temporary descriptor/path cleanup and
  check iconv-state closure, marking failures incomplete without hiding prior
  parser, timeout, resource, or detection results.
- Current GCC syntax and source guards cover the paths; current-object
  execution, complete PDF/filter corpora, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## XLM extracted-image cleanup-status audit — 2026-08-27

- Route XLM drawing-group image temporary-output close and unlink failures
  through the shared cleanup-status precedence helper, preserving
  `CL_EWRITE`/`CL_EUNLINK` and earlier parser, resource, timeout, or detection
  results.
- Current GCC syntax and source guards cover the path; current-object
  execution, complete XLM/OLE2 corpora, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## HTML normalized-view cleanup-status audit — 2026-08-27

- Route normalized-view close and temporary-directory cleanup through the
  shared precedence helper, preserving detections and earlier errors while
  upgrading `CL_BREAK` to `CL_EWRITE` or `CL_EUNLINK`.
- Current GCC syntax and source guards cover the handoff; current-object
  execution, complete HTML/script corpora, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## XAR and fmap cleanup-status precedence audit — 2026-08-27

- Preserve XAR subdocument and fmap dump cleanup failures after `CL_BREAK`
  using the shared precedence contract without hiding prior parser/resource or
  detection results.
- Current fmap/XAR GCC syntax and source guards pass; current-object execution,
  complete archive/fmap corpora, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## PDF filter-stage cleanup-status audit — 2026-08-27

- Route PDF filter-stage close, unlink, and temporary-accounting cleanup
  failures through the shared precedence helper, preserving `CL_EWRITE`,
  `CL_EUNLINK`, and `CL_ERESOURCE` without hiding earlier results.
- Current PDF decoder GCC syntax and source guards cover the paths;
  current-object execution, complete PDF/filter corpora, sanitizer, certified
  Linux x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification remain open.

## PDF object-stream cleanup-status audit — 2026-08-27

- Route PDF object-stream unmap, temporary-accounting, and ownership failures
  through the shared precedence helper, preserving `CL_ERESOURCE`/`CL_EPARSE`
  without hiding earlier parser/resource or detection results.
- Current PDF GCC syntax and source guards cover the paths; current-object
  execution, complete PDF/object-stream corpora, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification remain open.

## InstallShield partial-output cleanup audit — 2026-08-27

- Record InstallShield decompressor-initialization failure-path close and
  unlink failures as incomplete while retaining the original failure.
- Current GCC syntax and source guards cover the path; current-object
  execution, complete InstallShield corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification remain open.

## RAR archive-comment output cleanup audit — 2026-08-27

- Preserve RAR `keeptmp` archive-comment output-open, output-close, and
  temporary-directory removal failures as fail-visible incomplete results,
  while retaining earlier timeout, parser/resource, or detection results.
- Current RAR GCC syntax and source guards cover the paths; optional-backend
  execution, complete RAR corpus, sanitizer, certified Linux x86-64,
  materialized large-file, production-CVD/service, Sonic1, and parser-family
  qualification remain open.

## TNEF debug-dump cleanup and read-status audit — 2026-08-27

- Preserve TNEF unknown-level debug-dump temporary-file allocation/open,
  backing-read, and output-close failures as fail-visible incomplete results;
  retain earlier timeout or write failures through the shared cleanup-status
  precedence helper.
- Add focused debug-dump read/open regressions and source guards. Keep complete
  TNEF corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## RAR extracted-member failure cleanup audit — 2026-08-27

- Preserve RAR extracted-member temporary-file removal failures on deadline,
  decoder-error, and failed nested-scan exits as `CL_EUNLINK`/incomplete while
  retaining earlier timeout, unpack, parser, resource, or detection results.
- Add a source guard against ignored extracted-member unlink calls. Keep
  optional-backend execution, complete RAR corpus, sanitizer, certified Linux
  x86-64, materialized large-file, production-CVD/service, Sonic1, and
  parser-family qualification open.

## EGG archive-comment output cleanup audit — 2026-08-27

- Preserve EGG `keeptmp` archive-comment temporary filename allocation, open,
  write, and close failures as explicit incomplete results, including close
  checks after both write failure and successful output.
- Add source guards for the archive-comment status paths. Keep complete EGG
  corpus, sanitizer, certified Linux x86-64, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification open.

## GZip legacy-fallback cleanup audit — 2026-08-27

- Preserve legacy GZip duplicated-source close and decoder-close failures on
  fallback open/temporary-creation exits as fail-visible cleanup results while
  retaining the original decoder-open or temporary-file status.
- The current-source GCC syntax check and source guards pass, and `bz_map`
  passes 4/4. The reused six-check `bz_core` harness passes 4/6 because its
  two materialized corpus detections return `CL_EPARSE` under both current and
  pre-change scanner links; do not treat that as fresh corpus evidence. Keep
  complete GZip corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and parser-family qualification
  open.

## Production CVD/CLD/CUD archive-ingress audit — 2026-08-27

- Keep CVD/CLD/CUD archive read, seek, member-consumption, end-block, and
  stream-close failures fail-visible through the database-load return status.
- The current source passes the production warning-enabled GCC syntax check and
  registers isolated load/unpack coverage. Keep current-object execution,
  production CVDs, service parity, sanitizer, materialized large-file, Sonic1,
  and release qualification open.

## Production CVD public API boundary audit — 2026-08-27

- Reject null CVD parse/free/header arguments and require a complete 512-byte
  header before exposing public metadata.
- Preserve CVD header read and close failures; focused null-boundary tests and
  source guards are registered. Keep current-object execution, production CVD,
  service parity, sanitizer, materialized large-file, Sonic1, and release
  qualification open.

## Recognized ignored-type fail-closed audit — 2026-08-27

- Keep recognized `CL_TYPE_IGNORED` inputs explicit: no parser/raw pass is
  available, so return `CL_EPARSE`, mark incomplete, and prevent clean caching.
- Retain focused execution coverage and keep full ingress parity, production
  CVD/service, sanitizer, materialized large-file, Sonic1, and release evidence
  open.

## Descriptor child-scan engine boundary audit — 2026-08-27

- Reject a descriptor child scan before dereferencing a missing engine; mark
  the available parent map incomplete and non-cacheable.
- Keep focused missing-engine execution, ingress parity, production CVD,
  service, sanitizer, materialized large-file, Sonic1, and release evidence
  open.

## Signature-counting stream cleanup audit — 2026-08-27

- Preserve `cl_countsigs()` file and directory read/close failures as
  `CL_EREAD`, and never add a partial count after a failed stream.
- Keep injected close-failure execution, production CVD/service parity,
  sanitizer, materialized large-file, Sonic1, and release evidence open.
## HTML normalizer public-input boundary audit — 2026-08-27

- Reject a null map and invalid non-empty memory-normalizer inputs before
  dereference or pointer arithmetic; mark a supplied context incomplete so
  invalid public inputs cannot appear clean.
- Add focused API coverage and source guards. Keep current-object execution,
  complete HTML corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service, Sonic1, and release qualification open.

## Matcher public-entry boundary audit — 2026-08-27

- Keep lower-level matcher APIs fail-visible for null contexts, missing
  engines, non-empty null buffers, and missing current maps.
- Retain focused API coverage and source guards; full matcher/signature,
  sanitizer, materialized large-file, production-CVD/service, Sonic1, and
  release qualification remain open.

## Matcher internal API boundary hardening — 2026-08-27

Hardened `cli_matchmeta()` and `cli_check_fp()` against null or malformed recursion-stack state. Invalid contexts now return `CL_ENULLARG`; missing false-positive hash-layer maps return `CL_EPARSE` and set sticky incomplete/non-cacheable state. Added focused regressions and capability/source-guard evidence. Production-linked runtime execution remains pending.

## Fileblob cleanup-context hardening — 2026-08-27

Made destructive fileblob cleanup safe when its attached context has no engine, and added a regression for quota/admission failure followed by cleanup. Production-linked mail/fileblob and full release qualification remain pending.

## SWF compressed-entry boundary hardening — 2026-08-27

Added explicit engine admission for CWS/ZWS decompression before temporary-output setup, preventing a valid compressed header from reaching cleanup code with a null engine. Added a direct regression; complete SWF/parser-family, sanitizer, Sonic1, and release qualification remain pending.

## SWF compressed-entry incomplete-state hardening — 2026-08-28

Keep recognized CWS/ZWS input fail-visible when a direct parser call lacks an
owning engine. The compressed branches now mark the layer incomplete and
non-cacheable with `SWF compressed input requires an owning engine` before
returning `CL_ENULLARG`; the focused regression asserts the reason and cache
flag. Full SWF corpus, production-CVD/service, sanitizer, materialized
large-file, Sonic1, and release qualification remain pending.

## Bytecode context cleanup without an engine — 2026-08-27

- Keep bytecode context teardown safe when temporary output or normalized
  JavaScript state is being released before an owning engine is attached.
- The cleanup predicates now remove temporary state without dereferencing a
  missing engine, and `test_bytecode_context_cleanup_without_engine_is_safe`
  covers a real temporary file. Retain full bytecode execution, sanitizer,
  production-CVD/service, materialized large-file, Sonic1, and release gates.

## PDF parser engine admission — 2026-08-27

- Keep direct PDF parser calls fail-visible when a recognized map has no
  owning engine; reject before limit accounting or temporary-output setup.
- test_pdf_missing_engine_is_fail_visible covers the boundary. Retain
  complete PDF corpus, sanitizer, production-CVD/service, materialized
large-file, Sonic1, and release qualification gates.

## Native executable parser engine admission — 2026-08-27

- Keep full ELF, Mach-O, and universal Mach-O parser entries fail-visible when
  a recognized map has no owning engine; reject before deadline or heuristic
  state access while preserving engine-free cli_machoheader metadata parsing.
- test_executable_parsers_require_engine covers the full-scan ELF, Mach-O, and
  universal Mach-O boundaries. Retain complete executable corpus, sanitizer,
  production-CVD/service, materialized large-file, Sonic1, and release
  qualification gates.

## ZIP and 7-Zip scan-entry engine admission — 2026-08-27

- Keep full ZIP catalogue, single-member, ZIP search, and 7-Zip extraction
  entries fail-visible when a recognized map has no owning engine.
- Preserve engine-independent structural ZIP and 7-Zip header probes.
- Retain complete archive corpora, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, and release qualification gates.

## PE, AutoIt, and MSPack engine admission — 2026-08-27

- Keep direct PE, AutoIt, CAB, and CHM parser entries fail-visible when a
  recognized map has no owning engine; reject before decoder or temporary
  state access.
- Retain complete PE/AutoIt/CAB/CHM corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification gates.

## PE metadata helper admission — 2026-08-27

- Keep cli_peheader and cli_check_auth_header fail-visible for null contexts,
  missing maps, missing engine state, and unrepresentable header offsets.
- Retain complete PE metadata/certificate corpora, sanitizer,
production-CVD/service, materialized-large-file, Sonic1, and release
qualification gates.

## Shared resource-limit helper admission — 2026-08-27

- Keep cli_checklimits and cli_updatelimits fail-visible when scan ownership is
  missing; never dereference resource limits from a context without an engine.
- Retain complete resource-limit corpus, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, and release qualification gates.

## Recursion stack API admission — 2026-08-27

- Keep recursion-stack push/pop and type/size lookup fail-visible for null or
  partially initialized contexts. Preserve the existing empty-stack behavior,
  but never index a missing, zero-sized, or out-of-range stack, and require an
  owning engine before engine-dependent layer transitions.
- Retain complete nested-parser corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification gates.

## HWP5 stream admission — 2026-08-27

- Keep cli_scanhwp5_stream fail-visible for null context/header arguments and
  missing engine ownership before stream flag access or nested scanning.
- Preserve the engine-free cli_hwp5header metadata helper while requiring a
  scan options object before metadata collection, and retain complete HWP
  corpus, sanitizer, production-CVD/service, materialized large-file, Sonic1,
  and release qualification gates.

## BinHex parser admission — 2026-08-27

- Keep BinHex fail-visible when called without an owning engine before
  temporary-output, cleanup, or nested-scan access.
- Retain complete BinHex corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification gates.

## PE icon helper admission — 2026-08-27

- Keep cli_scanicon fail-visible for null icon-set/context/PE metadata
  arguments, missing recognized maps, and missing engine ownership before
  resource traversal.
- Retain complete PE icon corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification gates.

## OLE/MSO and VBA helper admission — 2026-08-27

- Keep the MSO prefix helper fail-visible for missing map, output, and scan
  context arguments before any fmap read or incomplete marking.
- Keep the OLE property-name helper fail-visible for null names and buffers
  shorter than the minimum UTF-16 terminator-bearing input.
- Keep the VBA project-directory entry fail-visible for missing context or
  engine ownership before temporary directory, decompression, or cleanup
  state access.
- Keep OLE10 and PowerPoint VBA extraction fail-visible when engine ownership
  is missing before parsing or temporary-output setup.
- Keep OLE summary metadata fail-visible when scan options are missing before
  metadata timeout checks.
- Retain complete OLE/VBA corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification gates.

## MSXML reader and streaming admission — 2026-08-27

- Keep reader-based MSXML fail-visible for null XML readers and key tables.
- Require scan options before reader-based or streaming JSON timeout and
  metadata access.
- Retain complete XML/OOXML/HWPML corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification gates.

## Media nested-handoff admission — 2026-08-27

- Keep GIF/PNG overlay and JPEG Photoshop-thumbnail handoffs fail-visible when
  engine ownership is absent, with sticky incomplete/non-cacheable results.
- Retain complete media corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification gates.

## UUEncode parser admission — 2026-08-27

- Keep UUEncode fail-visible when engine ownership is absent before decoded
  attachment materialization and matcher-root access.
- Retain complete UUEncode corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification gates.
## TNEF parser admission — 2026-08-27

- Keep TNEF fail-visible when engine ownership is absent before decoded
  attachment materialization and matcher-root access.
- Retain complete TNEF corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification gates.

## MSEXPAND parser admission — 2026-08-27
- Keep MSEXPAND fail-visible when owning engine state is absent before time/limit helper access.
- Retain complete SZDD corpus, sanitizer, production-CVD/service, materialized large-file, Sonic1, and release qualification gates.

## TAR parser admission — 2026-08-27
- Keep TAR fail-visible when owning engine state is absent before limit checks or temporary member cleanup.
- Retain complete TAR corpus, sanitizer, production-CVD/service, materialized large-file, Sonic1, and release qualification gates.

## Fileblob materialization admission — 2026-08-27
- Keep `fileblobAddData()` fail-visible when a materialization context lacks owning engine state; no early matcher-root dereference may occur.
- Retain complete mail/fileblob corpus, sanitizer, production-CVD/service, materialized large-file, Sonic1, and release qualification gates.

## Virus-found callback admission — 2026-08-27
- Keep `cli_virus_found_cb()` fail-visible when engine ownership is absent before legacy or modern callback dispatch.
- Retain complete callback/ingress parity, sanitizer, production-CVD/service, materialized large-file, Sonic1, and release qualification gates.

## Virus-indicator append admission — 2026-08-27
- Keep virus-indicator append APIs fail-visible for null contexts, null names, and invalid recursion-stack state before string or stack access.
- Retain complete callback/ingress parity, sanitizer, production-CVD/service, materialized large-file, Sonic1, and release qualification gates.

## XDP parser admission — 2026-08-27
- Keep XDP fail-visible for a recognized input map without an owning engine before retained-dump or streaming-MSXML state access.
- Retain complete XDP corpus, sanitizer, production-CVD, materialized large-file, Sonic1, and release qualification gates.

## Rust archive parser engine admission — 2026-08-27

- Keep ALZ, LHA/LZH, and OneNote Rust parser entries fail-visible when a valid
  current-layer fmap has no owning engine; reject before parser metadata,
  temporary-spool, or nested-scan access and preserve the invalid-argument
  result without false incomplete/cache-taint state.
- Retain complete Rust parser corpus, sanitizer, production-CVD/service,
  materialized large-file, certified Linux x86-64, Sonic1, and release
  qualification gates.
## MBR/GPT type-confirmation admission — 2026-08-27

- Preserve non-format failures from `cli_mbr_check2()` during embedded MBR/GPT
  type confirmation; an in-range partition-table read failure must remain
  `CL_EREAD` and mark the containing layer incomplete instead of becoming a
  clean raw-only result.
- Keep malformed weak MBR candidates rejectable without tainting the parent.
- Retain the public `mbr` type-confirmation regression and complete partition
  corpus, sanitizer, production-CVD/service, materialized large-file,
  certified Linux x86-64, Sonic1, and release qualification gates.

## MIME direct detector-configuration admission — 2026-08-27

- Keep `cli_mbox()` fail-visible when a recognized fmap is supplied without
  detector configuration required by phishing and HTML normalization paths;
  return `CL_ENULLARG` before MIME parsing.
- Retain the direct MIME admission regression and complete MIME corpus,
  sanitizer, production-CVD/service, materialized large-file, certified Linux
  x86-64, Sonic1, and release qualification gates.

## Structured detector scan-options admission — 2026-08-27

- Keep `cli_scan_structured()` fail-visible when a recognized fmap has an
  owning engine but no scan options; return `CL_ENULLARG` before deadline or
  detector work.
- Retain the direct structured-detector regression and complete detector
  corpus, sanitizer, production-CVD/service, materialized large-file,
  certified Linux x86-64, Sonic1, and release qualification gates.

## PDF direct scan-state admission — 2026-08-27

- Keep `cli_pdf()` fail-visible when a recognized fmap is supplied without the
  scan options or detector configuration required by metadata extraction and
  heuristic finalization; return `CL_ENULLARG` before parser work.
- Retain the direct PDF scan-state regression and complete PDF corpus,
  sanitizer, production-CVD/service, materialized large-file, certified
  Linux x86-64, Sonic1, and release qualification gates.

## Bytecode engine-query admission — 2026-08-27

- Keep bytecode engine scan-option and database-option queries fail-visible for
  null API contexts, missing bytecode owners, missing scan options, and missing
  engines; return an empty result before dereference.
- Retain the direct bytecode query regression and full bytecode execution,
  sanitizer, production-CVD/service, materialized large-file, certified Linux
  x86-64, Sonic1, and release qualification gates.

## YARA instruction-stream admission — 2026-08-27

- Keep bundled YARA fail-visible when a recognized rule has no instruction
  stream; return `CL_EPARSE`, mark the current layer incomplete, and disable
  caching before the first VM opcode fetch.
- Retain the direct YARA admission regression and complete YARA evaluation,
  sanitizer, production-CVD/service, materialized large-file, certified Linux
  x86-64, Sonic1, and release qualification gates.

## CVD public API null-state admission — 2026-08-28

- Keep CVD verify, unpack, database-load, and age helpers fail-visible for null
  paths, directories, engines, and output pointers; return `CL_ENULLARG`
  before filesystem, string, or engine-state access.
- Retain the direct CVD null-argument regression and the current-source
  production-linked `cvd_api_nulls` and `cvd_header_fixture` checks (1/1 each),
  then complete production-CVD, service-parity, sanitizer, materialized
  large-file, certified Linux x86-64, Sonic1, and release qualification gates.

## XAR LZMA member extent completion — 2026-08-28

- Require a successful XAR LZMA decoder to consume the entire declared member
  extent; trailing compressed-range bytes must return `CL_EFORMAT` with sticky
  incomplete, non-cacheable state before nested member scanning.
- The registered `test_xar_lzma_trailing_data_is_fail_visible` regression and
  focused current-source production-linked GCC harness cover a valid LZMA
  member followed by one trailing byte and observe a cleared public verdict
  with `CL_EPARSE`.
- Retain full XAR corpus, sanitizer, production-CVD/service, materialized
  large-file, certified Linux x86-64, Sonic1, and release qualification gates.

## XAR compressed member output-size agreement — 2026-08-28

- Require gzip and LZMA members to produce exactly the TOC-declared `size`
  before nested scanning; mismatches must return `CL_EFORMAT` with sticky
  incomplete, non-cacheable state.
- Retain the paired gzip/LZMA `test_xar_compressed_output_size_is_fail_visible`
  regression and focused current-source production-linked evidence, plus full
  XAR corpus, sanitizer, production-CVD/service, materialized large-file,
  certified Linux x86-64, Sonic1, and release qualification gates.

## YARA matcher-state admission — 2026-08-28

- Keep bundled YARA fail-visible when a recognized rule has a valid
  instruction stream but no matcher-state object; return `CL_EPARSE`, mark the
  current layer incomplete, and disable caching before VM execution.
- Retain the direct `test_yara_missing_matcher_state_is_fail_visible`
  regression and current-source production-linked GCC evidence, then complete
  YARA evaluation and corpus, sanitizer, production-CVD/service, materialized
  large-file, certified Linux x86-64, Sonic1, and release qualification gates.

## TAR EOF cleanup and coordinate admission — 2026-08-28

- Keep TAR fail-visible and resource-balanced when a staged member reaches EOF
  before the required end marker; close/unlink the active temporary output,
  release its temporary reservation, and check fmap-coordinate advancement
  before returning the missing-end-marker parse/read result.
- Retain `test_tar_eof_releases_member_resources`, current-source GCC syntax
  evidence, and the focused production-linked harness, then complete TAR
  corpus, sanitizer, production-CVD/service, materialized large-file,
  certified Linux x86-64, Sonic1, and release qualification gates.


## EGG SFX dispatch reachability — 2026-08-29

- Add the missing nonzero-offset built-in EGG signature so normal file typing
  can select `CL_TYPE_EGGSFX` and exercise the existing admission and nested
  `CL_TYPE_EGG` dispatch branch.
- Retain the current-source production-linked GCC `egg_sfx` result of 2/2:
  fixed-header admission plus a valid prefixed EGG with exact nested-child
  matching through the public map API.
- Keep complete EGG/SFX corpus, sanitizer, production-CVD/service,
  materialized-large-file, certified Linux x86-64, Sonic1, parser-family, and
  release qualification open.

## ELF64 direct table-cursor overflow regression — 2026-08-28

- Keep the ELF64 program- and section-header cursor checks before the next
  metadata read so `UINT64_MAX` wraparound cannot redirect inspection to a
  low offset. The allocation-free production-linked regression passes 2/2 and
  verifies only the two header reads occur.
- Complete ELF corpus, sanitizer, certified Linux x86-64, materialized
  large-file, production-CVD/service parity, Sonic1, and release qualification
  remain required.

## RAR skipped-member error propagation — 2026-08-28

- Preserve UnRAR decoder read, write, allocation, and output failures while
  skipping encrypted, directory, or size-limited members; only an end-of-
  archive `CL_BREAK` while consuming a declared member should become the
  existing parse failure.
- Retain the gated
  `test_rar_skip_read_failure_preserves_operational_status` regression and
  complete backend-enabled RAR corpus, sanitizer, production-CVD/service,
  materialized large-file, Sonic1, and release qualification.

## HFS+ key-length padding admission — 2026-08-28

- Keep catalog and attribute-tree key-length padding in a widened intermediate
  type; an odd `UINT16_MAX` key length must fail node-boundary validation
  instead of wrapping to zero.
- Retain `test_hfsplus_catalog_key_length_padding_is_fail_visible` and complete
  HFS+ corpus, sanitizer, production-CVD/service, materialized large-file,
  certified Linux x86-64, Sonic1, and release qualification.
## ISO9660 Joliet identifier parity — 2026-08-28

- Reject confirmed Joliet directory identifiers whose byte length is odd;
  generic UTF-16 conversion must not silently truncate malformed names.
- Retain `test_iso_joliet_odd_name_length_is_fail_visible`, the source guards,
  and the current-source production-linked direct 1/1 regression. Complete
  ISO corpus, sanitizer, production-CVD/service, materialized large-file,
  certified Linux x86-64, Sonic1, and parser-family qualification remain
  required.
## VBA compressed back-reference admission — 2026-08-28

- Reject VBA copy tokens whose distance is not backed by already produced
  history; never allow `pos - distance - 1` to wrap into the history window.
- Reject a flag-announced literal that reaches EOF before final emission, so a
  partial prefix cannot be mistaken for a complete module.
- Retain `test_vba_inflate_stream_rejects_initial_backreference`,
  `test_vba_inflate_stream_rejects_truncated_literal`, the source guards, and
  the current-source production-linked direct 2/2 regression.
  Complete OLE/VBA corpus, sanitizer, production-CVD/service, materialized
  large-file, certified Linux x86-64, Sonic1, and parser-family qualification
  remain required.

## SWF declared boundary and fixed-tag audit — 2026-08-28

- Bound uncompressed FWS frame/tag reads to the declared file length, reject
  undersized fixed-size ScriptLimits/FileAttributes payloads, and scan a
  declared-boundary overlay only with an owning engine.
- The current-source production-linked GCC direct SWF harness passes 2/2 for
  fixed-tag rejection and exact overlay matching; coherent unit coverage now
  includes MZ overlay detection and missing-engine admission.
- Keep complete SWF corpus, sanitizer, materialized large-file,
  production-CVD/service, Sonic1, and parser-family qualification as release
  gates.

## 7-Zip legacy-fallback output reset — 2026-08-28

- Reset the temporary output with truncate-and-rewind before invoking the
  whole-folder fallback after `SZ_ERROR_UNSUPPORTED`; retain
  `test_7z_legacy_fallback_discards_stream_prefix` and source guards.
- Retain the Linux-static decoder-injected
  `test_7z_legacy_fallback_after_partial_stream` integration case, then
  complete 7-Zip corpus, sanitizer, production-CVD/service, materialized
  large-file, Sonic1, and parser-family qualification.

## ALZ BZip2 declared-range completion — 2026-08-28

- Keep one byte of the bounded BZip2 member outside `DecoderReader` until it
  requests more input, so a valid compressed prefix followed by trailing
  bytes cannot be dispatched as a complete ALZ member while preserving bulk
  reads for large members.
- Retain the complete-stream and trailing-byte regressions. The current-source
  disposable offline Rust 1.97.1 ALZ harness passes all 40 ALZ tests. Full
  current-C ABI, sanitizer, production-CVD/service, materialized large-file,
  Sonic1, and parser-family qualification remain required.

## LHA/LZH pathname allocation admission — 2026-08-28

- Preflight the combined raw filename and extra-header lengths before
  `parse_pathname()` so its worst-case percent-encoding allocation cannot
  exceed the 1-GiB individual allocation boundary; preserve checked addition
  and multiplication overflow as `CL_ERESOURCE`.
- Retain `lha_pathname_admission_rejects_expansion_overflow` and complete LHA
  variant corpus, sanitizer, production-CVD/service, materialized large-file,
  Sonic1, and parser-family qualification.

## OneNote legacy iterator range admission — 2026-08-28

- Keep both public legacy iterator methods on checked native-size conversion
  and fixed-header-plus-payload arithmetic before copying or advancing to the
  next record.
- Retain the source guards and complete OneNote corpus, current full-C ABI,
  sanitizer, production-CVD/service, materialized large-file, Sonic1, and
  parser-family qualification.

## OneNote legacy reader declared-range admission — 2026-08-28

- Keep `scan_legacy_reader()` from reading the fixed 16-byte prefix when the
  caller-declared `file_len` is shorter than that prefix, and cap marker-search
  reads to the remaining declared extent.
- Retain `legacy_reader_rejects_declared_length_before_fixed_prefix` and
  `legacy_reader_does_not_scan_beyond_declared_length` alongside the existing
  declared-EOF, streaming, boundary, and source-failure tests.
  Keep the broader OneNote corpus, full-C ABI, sanitizer, production-CVD/
  service, materialized-large-file, Sonic1, and parser-family qualification
  open.

## Embedded parser qualification recheck — 2026-08-29

- Retain the fresh current-source production-linked evidence: AutoIt
  admission/SFX/generated corpus 9/9, binary-data exact-tail dispatch 1/1,
  Mydoom detector 5/5, BinHex focused map/failure 11/11, and CABSFX 3/3.
- Keep BZip2’s two materialized corpus detections open until the downstream
  InstallShield malformed-record path is separately qualified; the current
  six-check BZip2 core run is 4/6 with the two corpus cases returning
  fail-visible `CL_EPARSE`.
- Complete the remaining parser-family, sanitizer, production-CVD/service,
  materialized-large-file, certified Linux x86-64, Sonic1, and release gates.

## CPIO parser qualification recheck — 2026-08-29

- Retain the fresh current-source production-linked CPIO boundary evidence:
  15/15 across checksum/member matching, checksum mismatch/read failure,
  64 KiB-window tail matching, malformed and unterminated names and numeric
  fields, timeout, missing-map/engine admission, header/member ranges, and
  read failures; timeout uses the canonical
  `Heuristics.Limits.Exceeded.MaxScanTime` reason.
- Keep the legacy four-file materialized corpus open. Each original 1 KiB
  old-binary (both endian), NEWC, and ODC fixture returns fail-visible
  `CL_EPARSE` after downstream InstallShield/PE admission without the expected
  `Cpio.Member.MZ` alert, while controlled known-valid replacements pass
  16/16. Do not count that corpus as complete CPIO nested-detection evidence.
- Complete CPIO parser-family, sanitizer, production-CVD/service,
  materialized-large-file, certified Linux x86-64, Sonic1, and release gates.

## DMG parser qualification recheck — 2026-08-29

- Retain the relinked current-source production-linked GCC DMG result: the
  isolated `dmg` TCase passes 9/9 across context/map/engine admission, strict
  Base64 and terminal-END validation, host-order retained stripes, bounded
  external sorting, malformed metadata, trailer read failure, and invalid
  trailer handling.
- Keep full DMG corpus, sanitizer, production-CVD/service,
  materialized-large-file, certified Linux x86-64, Sonic1, parser-family, and
  release qualification open.

## EGG metadata-index resource accounting — 2026-08-29

- Retain exact shared contiguous reservations for scanner-aware EGG
  filename/comment range-index growth, rollback on allocation failure, and
  release on handle cleanup. The new focused current-source
  production-linked GCC EGG TCase passes 8/8, including a `CL_ERESOURCE`
  metadata-index regression with sticky incomplete/non-cacheable state and
  zero residual accounting.
- Keep complete EGG and split-sequence corpus, additional codepages,
  sanitizer/I/O-fault, production-CVD/service, materialized-large-metadata,
  certified Linux x86-64, Sonic1, and parser-family/release qualification
  open.

## MULTISCAN one-worker fallback guard — 2026-08-29

- Keep `MULTISCAN` sequential when `MaxThreads=1`; the source guard now pins
  the explicit fallback branch and contract comment.
- Compiled daemon/service, concurrency, sanitizer, production-CVD, and Sonic1
  evidence remain open.

## InstallShield CAB-index allocation failure — 2026-08-29

- Mark confirmed InstallShield CAB-index growth failure incomplete before
  returning `CL_EMEM`, so a failed legacy PE-overlay walk cannot remain
  cacheable.
- Retain the source guard and add injected allocation-failure execution when
  the current GCC production harness is available; complete InstallShield/PE
  corpus, sanitizer, production-CVD/service, materialized-large-file, and
  Sonic1 qualification remain required.

## PEspin resource-section failure handling — 2026-08-29

- Preserve sticky incomplete/non-cacheable state when confirmed PEspin resource
  allocation or decompression fails and the parser falls back to original
  section bytes.
- Add injected resource-failure execution and retain complete PE/unpacker,
  sanitizer, production-CVD/service, materialized-large-file, and Sonic1
  qualification as open requirements.

## SIS legacy metadata failures — 2026-08-29

- Keep malformed old-format package identifiers, language counts, and
  file-record pointers fail-visible and non-cacheable after header admission.
- Preserve sticky `CL_EMEM` for language-name and file-metadata allocation
  failures; add injected allocation-failure execution and retain complete SIS,
  sanitizer, production-CVD/service, materialized-large-file, and Sonic1
  qualification as open requirements.

## Regex executor allocation products — 2026-08-29

- Keep large-state regex state-set, capture-array, and back-reference position
  allocations behind native product and 1 GiB ceiling checks.
- Add direct overflow/failure execution and retain full phishing/regex corpus,
  sanitizer, production-CVD/service, materialized-large-file, and Sonic1
  qualification as open requirements.

## NSIS missing-engine admission — 2026-08-29

- Keep NULSFT header-check and confirmed decoder entries fail-visible with
  `CL_ENULLARG` when the owning engine is absent, before deadline or temporary
  output access.
- Add linked execution of the new regression and retain complete NSIS/SFX,
  sanitizer, production-CVD/service, materialized-large-file, and Sonic1
  qualification as open requirements.

## Stats JSON buffer and escaping — 2026-08-29

- Keep stats serialization behind checked native-size growth and the shared
  individual-allocation ceiling; escape metadata and signature names before
  emitting JSON and base commas on serialized samples.
- Add current-source GCC/sanitizer execution of long metadata, escaped names,
  and skipped-sample cases, while retaining production-CVD/service, Sonic1,
  and final report qualification as open requirements.

## Rust fmap native-to-64-bit coordinates — 2026-08-29

- Keep Rust fmap reader lengths, `SeekFrom::End`, read-result accounting, and
  LHA member-range admission behind checked native-to-64-bit conversions.
- Retain focused Rust execution, current full-C ABI, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final
parser/release qualification as open requirements.

## Legacy PDF RunLength input range — 2026-08-29

- Keep legacy RunLength packet admission subtraction-based after the encoded
  length byte is consumed, including repeated-byte packets at the uint32_t
  boundary.
- Add current-source GCC and sanitizer execution when the production harness
  is available; retain complete PDF filter, production-CVD/service,
  materialized-large-file, Sonic1, and final qualification as open.

## UTF-16 converter output-size admission — 2026-08-29

- Keep the shared UTF-16-to-UTF-8 converter behind quotient-first native-size
  arithmetic and the 1-GiB individual allocation ceiling; reject wrapped
  lengths before reading the input buffer.
- Retain `test_utf16_to_utf8_rejects_length_overflow` for both native-size wrap
  and the individual allocation ceiling, along with the source guards.
  Current-source GCC execution, sanitizer, complete text-normalization/ISO/HTML
  corpus, production-CVD/service, materialized-large-file, Sonic1, and final
  parser/release qualification remain open.

## PDF encryption password-check workspace admission — 2026-08-29

- Keep legacy R2-R4 password-check workspaces behind checked
  prefix/file-ID/suffix arithmetic and cli_max_calloc; reject overflow and
  workspaces above the individual 1 GiB allocation ceiling before copying the
  PDF /ID bytes.
- Retain test_pdf_encryption_buffer_size_is_fail_visible and its source
  guards. Current-source GCC execution, encrypted PDF corpus, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final
  parser/release qualification remain open.

## 7-Zip member-name buffer ownership — 2026-08-29

- Allocate a replacement UTF-16 member-name buffer before freeing the prior
  dynamic buffer, so later growth failures cannot leave cleanup with a
  dangling pointer or double-free.
- Add injected multi-member filename-growth failure coverage and retain
  complete 7-Zip/BCJ2 corpus, sanitizer, production-CVD/service,
  materialized-large-file, Sonic1, and final qualification as open.

## MIME multipart allocation-failure visibility — 2026-08-29

- Keep MIME multipart table, message-object, original-header, and folded-header
  allocation failures sticky and fail-visible before part admission or header
  parsing can continue with incomplete state.
- Add injected allocator execution and retain complete MIME/mbox/MHTML corpus,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
final qualification as open.

## MIME export failure visibility — 2026-08-29

- Keep MIME decoded-line, output-object, writer, text-node, and line-link
  failures sticky and fail-visible; never return partially decoded output as
  a successful attachment or text conversion.
- Add injected allocator/write execution and retain complete MIME/mbox/MHTML
  corpus, sanitizer, production-CVD/service, materialized-large-file, Sonic1,
  and final qualification as open.

## MIME header-constructor allocation visibility — 2026-08-29

- Keep parser-table initialization, message construction, header read-list
  growth, and MIME scratch-buffer failures sticky and fail-visible before
  partial header state can be returned or scanned.
- Add injected allocator execution and retain complete MIME/mbox/MHTML corpus,
  sanitizer, production-CVD/service, materialized-large-file, Sonic1, and
  final qualification as open.

## OpenIOC database admission — 2026-08-29

- Keep OpenIOC XML/hash-value allocation, engine, length arithmetic, and XML
  reader failures fail-visible, require a complete `<ioc>` root before hash
  admission, and release pending hash nodes on every parse or database-admission
  abort.
- Retain `test_openioc_malformed_xml_is_fail_visible` and add injected
  allocator execution, then retain complete OpenIOC corpus, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final
  qualification as open.

## Scan recursion-stack admission — 2026-08-29

- Keep the public scan-common recursion-layer table behind native-size and
  individual-allocation admission before nested parser state is published;
  retain CL_EMEM as the fail-visible result for an over-limit configuration.
- Add a focused oversized-MaxRecursion execution and retain nested-parser
  corpus, sanitizer, production-CVD/service, materialized-large-file, Sonic1,
  and final qualification as open.

## Hash-set export allocation admission — 2026-08-29

- Keep `cli_hashset_toarray()` behind null-input and native-size/
  individual-allocation product checks before result-array allocation.
- Retain the no-allocation over-limit regression and add full hash-table
  caller, sanitizer, production-CVD/service, materialized-large-file, Sonic1,
  and final qualification evidence.

## AC logical match-offset growth admission — 2026-08-29

- Keep YARA-offset logical-signature match history growth behind checked
  native-size, uint32-index, and individual-allocation limits before reallocation.
- Retain `test_ac_match_offset_growth_rejects_product_wrap` and add complete
  production-signature, sanitizer, production-CVD/service, materialized-large-file,
  Sonic1, and final matcher qualification evidence.

## Milter configuration and recipient allocation admission — 2026-08-29

- Keep `RejectMsg` expansion behind checked native-size and shared 1-GiB
  allocation admission, and keep recipient-array growth behind checked count
  products before `cli_max_realloc()`.
- Publish recipient strings only after their bounded copy succeeds, and free
  an allocated zero-count recipient array during cleanup so allocation failure
  cannot expose an uninitialized slot to `nullify()`.
- Retain the current-source GCC quota regression; full milter translation-unit,
  runtime, sanitizer, service, materialized-large-file, Sonic1, and final
  release qualification remain open because the existing Docker image lacks
  `libmilter` headers.

## HTML normalized metadata transactional growth — 2026-08-29

- Keep HTML tag/value/content table growth slots initialized before later
  allocation or duplication can fail, and free only entries whose table growth
  actually succeeded.
- Allocate tag replacements and form-data URLs before releasing or publishing
  prior state so allocation failure preserves the existing metadata table.
- Retain the expanded over-limit URL-table regression and add injected
  allocator-failure execution; complete HTML/MIME corpus, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final
  qualification remain required.

## CVD numeric-header parsing — 2026-08-29

- Keep CVD version, signature-count, functionality-level, and creation-seconds
  fields digit-only with checked unsigned accumulation; malformed, negative, or
  out-of-range values must fail closed before database metadata is published.
- Retain `test_cl_cvdparse_rejects_invalid_numeric_fields` and the source guards;
  current-source production-GCC execution, complete CVD corpus,
  production-CVD/service, sanitizer, materialized-large-file, Sonic1, and final
  release qualification remain required.

## CVD embedded TAR size parsing — 2026-08-29

- Keep CVD TAR member-size fields behind complete octal parsing, checked
  uint64 accumulation, and an explicit `UINT_MAX` admission before `dbio->size`
  is published.
- Add malformed, partial, and oversized CVD archive fixtures; retain
  current-source production-GCC, production-CVD/service, sanitizer,
  materialized-large-file, Sonic1, and final release qualification as required
  evidence.

## Public signature-count overflow — 2026-08-29

- Keep `cl_countsigs()` additions checked for the public `unsigned int` range
  across line-based files, CVD/CUD totals, and CBC entries; return
  `CL_ERESOURCE` and preserve the prior count instead of exposing wraparound.
- Retain the near-limit file/directory regression and source guards; current
  source execution with the generated Rust bridge, complete CVD/service parity,
  sanitizer, materialized-large-file, Sonic1, and final release qualification
  remain required.

## Matcher target-info context — 2026-08-29

- Keep `cli_targetinfo()` fail-visible for null output, null scan context, and
  context-without-fmap calls; missing map state must not be dereferenced or
  treated as usable executable metadata.
- Retain `test_targetinfo_rejects_missing_context` and its source guard; full
  matcher signatures/CVDs, sanitizer, materialized-large-file, Sonic1, and
  final release qualification remain required.

## OneNote Rust FFI panic containment — 2026-08-29

- Keep the exported `scan_onenote()` wrapper inside `catch_unwind`; parser
  panics must return `CL_EFORMAT` through the shared incomplete/non-cacheable
  path rather than crossing the C ABI.
- Add an injected-panic execution case when the Rust test/build environment is
  available; retain complete OneNote corpus, current full-C ABI, sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final release
qualification as required evidence.

## CVD Rust FFI null-pointer admission — 2026-08-30

- Keep raw CVD parse, open, unpack, and verify entry points fail-visible when
  their error/output pointers or CVD handle is null; no `ffi_error!` macro or
  `Box::from_raw()` call may be reached with an invalid boundary argument.
- Keep raw CVD getters null-safe with documented sentinel returns, and retain
  `ffi_null_arguments_are_fail_visible` plus the source guards. Current
  Rust/C ABI execution, complete CVD corpus, production-CVD/service,
  sanitizer, materialized-large-file, Sonic1, and final release qualification
  remain required.

## OLE2 allocation-table and extraction-output admission — 2026-08-30

- Keep BAT/XBAT sector-chain admission behind declared count and start-block
  checks before reading allocation tables or following malformed chains.
- Require a destination directory before macro/image stream materialization and
  keep the optional `files` result null-safe. Retain the source guards and
  current-source OLE2 map/XLM, corpus, reader-sanitizer,
  production-CVD/service, materialized-large-file, Sonic1, and final
  parser/release qualification as required evidence.

## XAR checksum-value allocation admission — 2026-08-30

- Keep valid-length archived and extracted checksum XML values fail-visible:
  an `xmlStrdup()` failure must return `CL_EMEM`, mark the confirmed layer
  incomplete, and never downgrade required checksum metadata to absent state.
- Retain source guards for the helper and both call sites. Add allocator-fault
  execution when the current test/build environment supports it, and keep
  complete XAR corpus, sanitizer, production-CVD/service, materialized
  large-file, Sonic1, and final parser-family/release qualification open.

## RTF action-table initialization admission — 2026-08-30

- Keep RTF action-table creation, insertion, and post-insert key lookup
  failures fail-visible as `CL_EMEM` with sticky incomplete state; a failed
  control-word key copy must not silently disable RTF actions.
- Retain the source guards and add allocator-fault execution when the current
  test/build environment supports it. Keep complete RTF corpus, sanitizer,
  production-CVD/service, materialized large-file, Sonic1, and final
  parser-family qualification open.
