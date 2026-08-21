# 32 GiB Large-File Fork Audit

**Audit date:** 2026-08-13
**Baseline:** ClamAV 1.5.3
**Audited tree:** `ClamAV-LargeFile 1.5.3-largefile-devel`
**Target:** scan inputs from 0 through and including 32 GiB on supported
64-bit systems without coordinate truncation, silent partial inspection, or
unbounded whole-input residency in paths that must be streamed
**Verdict:** **source-hardening candidate; production release remains blocked**

## Current superseding status — audit1.md V-01–V-08 remediation

This table is the authoritative status for the current worktree. All older
appendices below are historical evidence and must not be read as superseding
this revision-scoped disposition. The canonical worktree is a Git checkout;
the current source still has no supported-Linux compile or immutable runtime
qualification, so those claims remain open until the revised tree is rebuilt
from a real supported-Linux checkout.

| Requirement | Current disposition | Evidence state |
|---|---|---|
| Logical-object accounting | Normalized and handler-retyped views no longer consume `MaxScanSize`/`MaxFiles` a second time; their matcher bytes remain charged to `MaxMatcherWork` | Local source guard and focused unit regression registered; supported-Linux execution pending |
| Nested/sliced RAR staging | Accessible-fmap range handling and staging-error propagation implemented | Local source controls pass; compiled Sonic1 verification pending |
| JavaScript normalizer failures | Open/write/close status now propagates through HTML and bytecode callers | Local source controls pass; exact fault-injection regression pending |
| Normalized-script remapping | `fmap_new()` failure marks the scan incomplete and non-clean | Local source change; compiled regression pending |
| CAB/CHM constructor failures | Constructor failures now mark the scan incomplete | Local source change; fault-injection regression pending |
| MaxScanTime parsing | Checked full-width conversion rejects overflow and trailing data | Boundary unit test added; supported-Linux build pending |
| `cl_fmap_set_hash()` ABI | Digest-pointer API retained with libclamav SONAME transition | Source/API test added; compatibility build pending |
| Sanitizer deadline/verifier | Release and sanitizer deadlines are separated; workflow control test added | Local shell controls pass; workflow run pending |
| Runtime evidence binding | Copied runtime components and relative hashes are required; CMake-captured source commit/tree, complete Git tree/index metadata, and compile-command graph are bound into the evidence; peak temp is sampled during scans | Local synthetic verifier passes; real Linux evidence pending |
| Service/workload qualification | clamd/clamdscan/milter, production-CVD, materialized/cold-cache, expansion, latency, and RSS gates remain open | Not yet verified |
| Exact-trigger compiled regression suite | Additional RAR, MaxScanTime, PDF/HWP3/ZIP/XZ, and API coverage added; broader parser fault-injection coverage remains open | Not yet complete |

The release remains production-blocked until every row has supported-Linux
compiled evidence and the service/workload gates pass.

## Current source-hardening follow-up — 2026-08-19

The canonical worktree adds six source-level controls while preserving the
production-blocked verdict. The capability manifest now checks 135 entries,
including all parser dispatch branches, matcher families, large-file-relevant
build switches, and explicit first-release unsupported boundaries. Public
engine numeric setters reject negative or narrowing values before assignment,
HTML no-tags normalization over its cap now returns an incomplete result
instead of silently omitting a required normalized view, logical MaxScanSize/
MaxFiles accounting now excludes normalized and handler-retyped views,
JavaScript normalized output is admitted against shared matcher-work at
bounded flushes, UTF-16 HTML normalization now has fail-visible conversion,
read, write, mapping, and temporary-quota paths, and
scanner-facing OneNote attachment extraction no longer creates an intermediate
whole-member buffer. Structured reports now preserve detection precedence over
sticky incomplete parser state. Focused unit tests and shell source guards are registered, but the current macOS checkout has not
produced a supported Linux compile, sanitizer run, or new Sonic1 qualification
for this follow-up.

The Rust `FMap::need_off()` adapter now rejects out-of-range native-size
windows before invoking the C `need()` callback or forming a slice, including
zero-length requests at the exact end of the map. Its focused Rust tests verify
the boundary and callback suppression; compiled Rust/layout qualification
remains open.

The Rust OneNote scanner now treats a short fixed prefix as malformed input but
returns `CL_EREAD` when a callback fails for an in-range prefix. ALZ's existing
field-read error is likewise preserved as `CL_EREAD` instead of generic parse
status; compiled Rust and parser-corpus qualification remains open.

## Current source-hardening follow-up — 2026-08-20

The enabled Mydoom-log detector previously treated failure to obtain its
required fmap window as `CL_CLEAN`. That could silently skip the detector
after an injected read/map failure and let the outer raw pass appear clean.
The detector now marks the scan incomplete, returns `CL_EREAD`, and prevents
the affected fmap from being cached as clean. A focused unit regression and
the source guard cover the failure path; supported-Linux compilation and
runtime qualification remain open.

The UUENCODE ingress now distinguishes an empty map from failure to read the
first line of a nonempty map. The latter marks the scan incomplete and
returns `CL_EREAD` instead of allowing a required encoded attachment path to
be reported as clean. A focused fault-injection regression and source guard
cover this boundary; supported-Linux compilation and runtime qualification
remain open.

The mbox dispatcher applies the same empty-input versus failed-first-line
distinction as the standalone UUENCODE path. A nonempty fmap that cannot
provide its initial MIME line now returns `CL_EREAD`, marks the scan
incomplete, and is not cacheable as clean. A focused regression and source
guard cover the boundary; supported-Linux compilation and runtime
qualification remain open.

## Python bytecode unsupported boundary — 2026-08-21

Python bytecode magic is recognized by the type detector, but the fork does
not have a bounded parser that can inspect the version-dependent code-object
formats. The dispatch path now records that deliberate unsupported boundary
as an incomplete, non-cacheable result before continuing the mandatory outer
raw matcher, so a clean raw-only result cannot be mistaken for a complete
Python-bytecode scan. A focused public-map regression, source guard, and
capability-manifest entry cover the invariant; a future bounded parser and
production Python corpus remain outside the current release qualification.

## AI-model parser unsupported boundary — 2026-08-21

GGUF, ONNX, and TensorFlow Lite signatures are recognized by the type
detector, but this fork does not have a bounded parser for their model
formats. The AI-model dispatch path now records that deliberate unsupported
boundary as incomplete and non-cacheable before the mandatory outer raw
matcher, preventing raw-only clean results from being presented as complete
model scans. A focused public-map regression, source guard, and capability
manifest entry cover the invariant; model-parser implementation and
production model corpus qualification remain open.

## OLE2 summary metadata result propagation — 2026-08-21

When metadata collection was enabled, `cli_ole2_scan_tempdir()` discarded the
return status from summary-property parsing. The parser did mark some local
failures incomplete, but a lookup, allocation, or other summary failure could
be lost while later embedded-stream work returned success. The summary result
is now retained as a deferred failure while all remaining OLE2 content is
still inspected, and it is returned if no later status supersedes it. Source
guards cover the propagation; compiled Linux fault-injection and Office corpus
qualification remain open.

## Sequential parser status preservation — 2026-08-21

ZIP local- and central-header parsing now treats an in-range fmap callback
failure while reading a member filename as `CL_EREAD` instead of silently
continuing as if the name were absent. Local parsing also copies from the
callback's returned window, not the original map pointer. EOCD search now
distinguishes an unreadable in-range probe from an absent candidate instead of
falling back to local-header discovery. Focused regressions cover all three
boundaries. ZIP64 locator and ZIP64 EOCD windows now likewise distinguish
unreadable metadata from a bad signature. Compiled Linux archive-corpus
qualification remains open. Local-header discovery now treats an in-range
window read failure as `CL_EREAD` instead of as the end of the search, with a
focused direct-index regression. Data-descriptor signature and payload window
read failures now likewise return `CL_EREAD` and prevent caching, with focused
coverage for both windows.

OOXML metadata parsing could return a specific error and then have the
following ZIP pass replace it with `CL_SUCCESS`; text/script mail handling had
the same overwrite pattern. Sequential parser passes now merge results so a
later detection or critical resource failure wins, while a later clean result
cannot erase the first specific parser error. The focused merge regression and
source guards are registered; compiled Linux/Sonic1 mixed-parser fault
injection and broader parser-corpus qualification remain open.


The shared mbox line reader now receives the scan context and marks failed
fmap windows or invalid line ranges incomplete instead of treating them as
ordinary end-of-message. A focused inner-reader fault injection covers this
path; supported-Linux compilation and runtime qualification remain open.

The opt-in clamd report commands now serialize the public `_ex2` report,
including aggregated logical/parser/detector counters and request-level peak
resources for multi-file walks, rather than reducing those results to a status
code and two strings. If report serialization or its transport allocation
fails, clamd emits a schema-shaped `RESOURCE_FAILURE` report with a skipped
operation instead of a compact clean fallback; clients reject the historical
string-valued clean fallback and require a successful status on `COMPLETE`.
Runtime daemon qualification remains an open release gate.

The structured report's `skipped_operations` metric now counts repeated
required parser/matcher skips with saturating arithmetic and is summed across
directory children; the old sticky-flag-only context shape remains compatible
through a one-skip fallback.

The clamd receive loop now scopes structured-report mode to the individual
request. Path/FILDES report commands clear the receive-loop flag after their
worker copy is queued, and legacy commands explicitly clear stale state; the
internal `INSTREAMSCAN` transition remains the deliberate inheritance point.

The structured-report producer now applies the same 16 MiB frame ceiling as
the common clamd, clamonacc, and milter receivers. An oversized serialized
report falls back to the bounded status object before allocation and 32-bit
wire-length conversion, so report growth cannot become a transport truncation
or allocation hazard.

The clamd INSTREAM receive loop now treats a temporary-file write failure as
terminal. It does not dispatch the partial staged descriptor, emits one
legacy or structured response according to the request, and lets connection
cleanup remove the partial file. The same response-suppression state prevents
the outer receive loop from appending a second legacy error after a structured
quota or write report.

The dormant legacy `STREAM` implementation has been replaced with an explicit
unsupported return. This removes its independent truncating socket path from
the active build while preserving a clear failure for any out-of-tree caller;
the length-framed, complete-file `INSTREAM` path remains the supported API.

Mail message export now refuses already-truncated materializations and
propagates decoder, output-allocation, and trailing-buffer write failures
instead of returning a partial attachment blob. This closes a concrete
false-clean path for MHTML, phishing-URL, RFC2047, and attachment consumers
that rely on `messageToBlob()`.

The 7-Zip fmap adapter now translates `cli_writen()` failure into the
short-write signal required by `ISeqOutStream`; its signed 64-bit seek adapter
also rejects negative and out-of-map positions before arithmetic. This keeps
failed extraction and archive-coordinate overflow fail-visible instead of
feeding bogus byte counts to the decoder.

7-Zip header, packed-stream, and legacy solid-folder coordinate arithmetic is
now checked before addition or narrowing. The legacy compatibility extractor
cannot truncate a member offset or size to 32 bits, and encoded-header staging
cannot wrap its 64-bit data position.

The packed-stream position checks also include the current data base when
validating each pack-size increment, so the final cumulative position cannot
wrap after an individually representable member size.

The 7-Zip adapter now preserves SDK input-read, output-write, and allocation
failures as `CL_EREAD`, `CL_EWRITE`, and `CL_EMEM` rather than collapsing them
into generic parse status. A valid empty archive with an injected next-header
read failure verifies the `CL_EREAD` path and cache suppression; broader
compiled archive-corpus and sanitizer qualification remain open.

DMG trailer, XML-spool, and streamed stripe fmap failures now distinguish an
in-range read failure (`CL_EREAD`) from an out-of-range or malformed window
(`CL_EPARSE`) while retaining the sticky incomplete/non-cacheable state. The
trailer fault-injection regression covers the first boundary; compiled DMG
corpus and sanitizer qualification remain open.

The `clamscan` file and stdin front ends now enforce report completion before
publishing a clean or trusted `OK`; a non-detection incomplete report is
converted to an error instead of being counted as clean.

The clamd INSTREAM admission path now shares the client-side stream-limit
normalizer. A zero-valued `StreamMaxLength` therefore selects the bounded
32-GiB ceiling at the daemon staging boundary instead of becoming a zero-byte
quota; a focused unit regression covers both zero and explicit limits.

The clamd INSTREAM receive loop now computes the buffered portion of an
attacker-controlled chunk with subtraction-form bounds. This prevents a
32-bit `size_t` addition wrap from turning a malformed maximum-size chunk into
an out-of-bounds read; the helper has a focused maximum-chunk regression.

clamd directory scans now add an incomplete child report for recursion-limit,
unsupported-special-file, stat, allocation, and realpath skips. Intentional
symlink exclusions remain policy skips, but required paths that the walker
cannot inspect can no longer disappear from an otherwise `COMPLETE` aggregate.

clamav-milter now uses `INSTREAMREPORT`/`FILDESREPORT` and consumes the same
length-prefixed structured report used by clamdscan. A clean milter action is
therefore limited to a `COMPLETE` report; incomplete, resource, malformed, and
application-abort reports take the configured failure action. The active milter
scan request is serialized across conversations so a second request cannot
simultaneously stage and reserve resources while the first is being scanned.
The milter now preserves the structured report's `last_alert` value for
reject formatting, logging, and `VirusEvent` instead of substituting a generic
transport label. Its nonblocking socket path now reads each report frame with
the configured receive deadline and handles short reads and `EAGAIN` safely.

On-access stream, fd-passing, and path requests now use the corresponding
structured report commands and parse the length-prefixed frames through the
same status classifier. A report that is incomplete or cannot be received is
returned as a worker error (and therefore denied in prevention mode), while a
monitoring-only event may still allow without labeling the object clean.

clamd now emits a single machine-readable startup capability manifest after
engine initialization. It records the compiled width/build boundaries, hard
resource ceilings, active configured limits, structured-report and bytecode-v2
support, and fd-passing availability; `parser_qualification=unclaimed` keeps
this observability line from being mistaken for release qualification.

On-access prevention now denies permission events after stat or size-limit
preflight failures even when the worker correctly avoids submitting a partial
object; monitoring-only events continue to allow and log.

The on-access INSTREAM sender now checks for post-stat growth on every regular
file stream, not only quarantine/action streams. A changed file is rejected as
`CL_EREAD` when it grows below the stream ceiling, while growth at the ceiling
remains `CL_EMAXSIZE`; neither path can publish a clean prefix. Compiled
fanotify and monitoring-mode qualification remain open.

## On-access report-status propagation — 2026-08-21

The on-access client parsed incomplete structured reports into `ret_code`, but
then replaced every non-detection result with `CL_CLEAN` or generic
`CL_ECREAT` after `onas_dsresult()` returned. The client now preserves the
specific parser, limit, timeout, resource, or transport status while keeping a
detection authoritative. Source guards cover the invariant; compiled
fanotify, monitoring-mode, and end-to-end clamonacc qualification remain open.

## Executive summary

The fork now has a coherent 64-bit raw-scan path and materially stronger
fail-visible behavior. The audit found and corrected defects that could wrap
match offsets, bypass signatures, invert nested scan results, trust an
incompletely hashed executable, scan only a truncated archive prefix, or let
resident memory grow with the complete input.

Commit `bba68110e04f78504d2af389050c349e01861315` now builds and passes its
normal and focused tests on the `sonic1` Ubuntu Linux x86-64 host. Its
one-worker runtime gate also detects the exact 32 GiB edge marker at engine
offset `34359738304`, and a separate warm-cache scan succeeds inside a hard
8 GiB memory-and-swap limit. These results close the earlier exact-edge and
single-worker raw-scan proof gaps.

The implementation is still **not certified for production**. Sanitizer
evidence, worker counts 2 and 4, clamd/milter large-transfer integration,
production-signature-database and deep-parser workloads, cold-cache behavior,
and some generic false-clean and broader archive-corpus gaps remain open. The
current ZIP strong-encryption and masked-header paths are explicitly
incomplete/non-clean and have focused regressions.

Large-file support in this tree must therefore be understood as follows:

- Native raw matching, scan accounting, cache keys, stats, and the audited
  bounded container paths retain 64-bit file coordinates.
- Fixed-format and legacy ABIs remain fixed-width where required. If a
  necessary inspection cannot represent the input, the scan is marked
  incomplete and cannot be reported or cached as clean.
- Contiguous parsers have explicit caps. Exceeding one is a visible non-clean
  result, not successful support for an object of that size.
- The upper policy bound is 32 GiB. This is not an unlimited mode and does not
  imply that 32 GiB of RAM may be consumed.

## Scope and constraints

The review covered:

- AC/BM matching, logical signatures, exact-size hashes, PCRE, byte-compare,
  and bytecode bridges;
- fmap paging and aging, I/O-failure handling, cache keys, stats, callbacks,
  and C/Rust layouts;
- ZIP/ZIP64, CAB, CHM, UDF, GPT, AutoIt, XAR, NSIS, EGG, ARJ, DMG, InstallShield,
  PE/AuthentiCode, ELF, Mach-O, HFS+, PDF, XDP, and HWPML paths;
- clamd/clamdscan streaming and clamav-milter quotas;
- size/time policy propagation; and
- the boundary corpus, POC harness, evidence verifier, CTest registration,
  and GitHub Actions release gates.

The development host is macOS and was not modified. Earlier compilation and
small tests used a constrained Debian ARM64 container. Current runtime
validation used the real `sonic1` Ubuntu Linux x86-64 system, with Docker used
to isolate the build and scans. The 8 GiB result was produced by a separate
container with hard memory and memory-plus-swap limits of 8 GiB, four CPUs,
and no additional swap allowance. It was a warm-cache sparse raw-file test,
not a cold-cache or production-workload certification.

## Remediation status

| Area | Status | Audited disposition |
|---|---|---|
| Matcher offsets and sorting | Source-fixed and focused-tested | BM uses an explicit 64-bit comparator; native sentinels cannot collide with valid 32-bit-boundary offsets; absolute/window coordinates and byte-compare overlap de-duplication are checked. |
| Signature size/offset parsing | Source-fixed and focused-tested | Logical `FileSize`, calculated offsets, and exact-size hash keys retain native 64-bit values; reserved sentinel values are rejected. |
| PCRE | Fail-visible bounded support | On qualifying 64-bit anonymous-map builds, PCRE subjects follow the 32 GiB contiguous ceiling; other builds retain the 1 GiB allocation ceiling. Size-limit skips mark active layers incomplete/non-cacheable, full-map dispatch uses overflow-safe range arithmetic, and full-subject fmap read failures now return `CL_EREAD` with the same sticky state. |
| Bytecode | Fail-visible ABI boundary | The legacy bytecode ABI remains 32-bit. Maps or offsets that cannot be represented are rejected only when an applicable hook would run, and the result is incomplete/non-clean. |
| fmap and hashing | Source-fixed and synthetic-tested | Aging uses a persistent bounded cursor and release budget; read failures roll back page state and return `CL_EREAD`; hash and extraction readers use bounded windows. |
| Cache, stats, and FFI | Source-fixed and focused-tested | File sizes are 64-bit in cache/stat records and JSON; checked-in Rust layouts match the widened C structures and have layout assertions. |
| Top-level limits and timeout | Source-fixed and focused-tested | `MaxFileSize` overflow and `MaxScanTime` cannot become an unqualified clean verdict. Detection and critical-error precedence is preserved. |
| ZIP and ZIP64 | Bounded core methods implemented | Stored, Deflate, Deflate64, BZIP2, Implode, and ZipCrypto use bounded input. Decoder terminal state, exact output, input exhaustion, and callback status are enforced. ZIP64 coordinates are checked and native-width. Short central/local headers are incomplete/non-clean. Unsupported methods, strong encryption, and masked headers are incomplete/non-clean. Output-write, temporary-file/map, rewind, close, and cleanup failures now also set the sticky incomplete state before nested extraction can be treated as complete. |
| CAB and CHM | Source-fixed and focused-tested | Short writes, exhausted budgets, decoder failures, and partial temp output are fail-visible; cumulative `MaxScanSize` exhaustion before the next member now marks the scan incomplete and returns `CL_EMAXSIZE`; partial members are not scanned as complete. |
| PE/AuthentiCode | Source-fixed and focused-tested | AuthentiCode/catalog/section hashes use checked native-width regions and 1 MiB reads; incomplete hashing prohibits trust. Overlay sizes remain native-width until an explicitly checked legacy bridge. Malformed or truncated PE headers now mark the scan incomplete and return a non-clean result instead of being normalized to clean after skipping PE-specific inspection. Optional PE unpacker size-limit failures now preserve their non-clean result, mark the scan incomplete/non-cacheable, and do not scan partial unpacked output; legacy unpackers now reject contiguous working requests above the 1 GiB individual-allocation ceiling as explicit `CL_ERESOURCE` incomplete results. |
| ELF | Source-fixed and focused-tested | Truncated or incomplete ELF header, program-header, and section-header parsing no longer converts `CL_BREAK` into a clean result; the public ELF scanner marks the scan incomplete and returns `CL_EPARSE`. |
| Mach-O | Source-fixed and focused-tested | The public Mach-O and universal-binary scanners now mark truncated or malformed header/load-command/entry-point inspection incomplete and return `CL_EPARSE`; the internal Mach-O header probe retains its non-scanning error behavior. |
| HFS+ | Source-fixed and focused-tested | Truncated or invalid HFS+ volume headers, declared attributes-tree failures, node-walk limits, and downstream parser failures now mark the scan incomplete, return a non-clean result, and cannot be cached as clean; an existing attributes tree is never treated as absent after a lookup failure. |
| PDF, XDP, HWPML, OOXML metadata, and MSXML embedded-content callers | Fail-visible bounded support | Whole-map materialization was removed from audited entry paths. PDF now stages through the shared temporary quota and uses a file-backed mapping on mmap-capable builds; non-mmap builds retain an explicit 64 MiB fallback gate. PDF raw/decoded stream and extracted-object limit/write failures preserve non-clean status and refuse partial output. XDP and HWPML now use bounded SAX push parsers, incrementally spool decoded content, and keep temporary admission and nested-scan failures fail-visible. OOXML reader initialization, required-part lookup, and metadata XML truncation now mark the scan incomplete. The MSXML embedded-content caller still opts out of parse-error suppression and marks truncated XML non-cacheable. |
| Nested fmap and InstallShield | Source-fixed and focused-tested | Nested ranges are strict and forced-to-disk copies are chunked. InstallShield legacy metadata now rejects truncated or malformed partial records, preserves exact-end records, and rejects invalid embedded header metadata instead of normalizing it to clean; it does not scan capped or malformed partial output as complete. |
| ISO9660 | Source-fixed and focused-tested | Truncated volume descriptors, unavailable directory blocks, malformed directory records, unsupported interleaving, multi-extent records, and per-file scan-limit skips now mark the scan incomplete. Extracted-file temporary creation, nested-scan, close, cleanup, and directory-traversal allocation failures now also remain sticky; broader optical-image corpus qualification remains open. |
| 7-Zip | Source-fixed and focused-tested | Seek, header-open, checked header/packed-stream/solid coordinates, member-name representability/allocation, member-extraction, output-write, metadata matching, temporary-file, close, cleanup, and member-limit failures now remain non-clean; broader 7-Zip encrypted/malformed corpus qualification remains open. |
| XAR | Source-fixed and focused-tested | Truncated or invalid headers, unavailable TOCs, and downstream TOC/parser failures now mark the scan incomplete rather than allowing `CL_EFORMAT`/read failures to normalize to clean. TOC temporary admission/creation, member/subdocument staging, close, cleanup, and preserved subdocument scan failures are also fail-visible; broader XAR corpus qualification remains open. |
| Legacy expansion/mail parsers | Fail-visible follow-up in progress | OLE2 entry/materialization/member-limit paths, OLE10/RTF embedded-object header, payload-copy, nested-scan, and cleanup failures, VBA decompression/materialization failures, bounded mail materialization across `messageAddLine()` and `messageMoveText()`, multipart-child truncation propagation, enabled phishing URL inspection now rejects oversized or failed HTML materialization/normalization, MSEXPAND, TNEF short-header/attribute paths, UUENCODE, mail UUENCODE callers, BinHex partial-work paths, mail BinHex context propagation, SIS parser-entry/EOF/member-limit paths, TAR truncated-header/content paths, CPIO short-header paths, partial GZip/BZip2/XZ streams, the legacy GZip compatibility fallback, partial SWF zlib/LZMA streams plus truncated FWS headers/declared-size mismatches and frame-metadata reads, HWP3 document-info/document-summary/callback parser failures, RTF unmatched group/control-word or incomplete embedded-object payload paths, RAR header/limit/encrypted-member/extraction failures, ARJ member-limit, partial extraction, and rewind failures, PEspin expanded-section limit accounting, and UNIX mbox nested `MAXREC`/`MAXFILES` propagation now return explicit non-clean results and mark scans non-cacheable; BinHex data/resource-fork EOF paths now also refuse to dispatch partial nested output; SIS legacy and 9.x member input/output now stream through 64 KiB windows into quota-reserved spools; broader legacy-parser coverage and production-CVD qualification remain open. |
| MBR, APM, and GPT partition scanners | Source-fixed and focused-tested | Malformed or truncated partition headers and table entries now reapply the sticky incomplete invariant at scanner finalization; APM entry signatures, native-width declared-size arithmetic, and APM/GPT nested partition ranges are checked before dispatch, preventing malformed metadata from normalizing to clean. |
| UDF, AutoIt, NSIS, EGG, and ARJ | Hardened in this milestone | Result inversion, unchecked arithmetic, partial-decode success, unknown non-empty methods, and scanner-facing whole-input decoder reads were converted to checked, bounded, fail-visible paths; ALZ encrypted/data-descriptor/unsupported-compression members now produce explicit scanner-facing incomplete results; AutoIt EA05/EA06 encrypted compressed input now decrypts through 64 KiB windows, EA06 missing member markers are malformed rather than clean, parser temporary-directory admission failures are sticky, and decoded output and stored-member paths remain explicitly bounded by the legacy contiguous-allocation ceiling; NSIS members now stream through 64 KiB input windows with quota-accounted output, including the stateful solid path, and temporary-directory admission failures are sticky; scanner-facing EGG members now decode through 64 KiB fmap/output windows into a `MaxTemporarySize`-reserved descriptor, while the compatibility byte-buffer API retains its individual-allocation guard; ARJ SFX member-range normalization and extraction/rewind failures are fail-visible; UDF's mandatory descriptor-area, descriptor-fetch, and unknown generic-identifier failures now mark the scan incomplete and return `CL_EPARSE`; valid generic identifier recognition is covered by focused synthetic descriptor fixtures. |
| DMG | Source-fixed and focused-tested | Truncated or invalid `koly` trailers now mark the scan incomplete; the XML resource fork is consumed through bounded SAX input, decoded `<data>` values use quota-accounted spools, and one `mish` block remains bounded at 64 MiB. Fork-relative offsets, stripe geometry, exact output, decoder completion, decoder-initialization allocation, XML-path allocation, time limits, temporary admission, output-write, temporary-file, cleanup, and multi-segment rejection failures are fail-visible. Each stripe list requires exactly one zero-length final `END` record. |
| clamdscan and milter | Source-fixed; quota test passes | Client-side stream truncation is rejected; milter totals and reservations are checked 64-bit values with exact-boundary and overflow tests. |
| Runtime evidence | One-worker x86-64 gate passed; release matrix open | The gate binds results to source/scanner hashes, verifies exact engine offsets and worker RSS, excludes sparse corpus payloads, creates `SHA256SUMS`, and publishes attested success artifacts separately from failed diagnostics. Commit `bba68110e04f78504d2af389050c349e01861315` passed the one-worker gate on `sonic1`; sanitizer and multi-worker evidence remain outstanding. |

The active release and sanitizer qualification gates now use the roadmap's
four-hour `MaxScanTime` value of 14,400,000 ms. Historical evidence entries
retain the deadlines that were actually used when those runs were recorded.

## Verification completed

The following evidence was produced on the `sonic1` Ubuntu Linux x86-64 host
for exact code commit `bba68110e04f78504d2af389050c349e01861315`:

- the full Release configuration built to 100% with `ENABLE_STATIC_LIB`,
  `ENABLE_EXAMPLES`, and `ENABLE_MILTER` enabled;
- focused `libclamav`, `clamscan`, and examples tests passed 3 of 3;
- focused Valgrind tests passed 2 of 2;
- the complete non-Rust CTest selection passed 16 of 16 in 1106.34 seconds;
- an isolated writable exact source clone passed all 62 Rust tests;
- the patched one-worker runtime gate exited 0 and recorded
  `runtime_gate=pass`;
- all 11 sparse boundary rows detected their markers and reported the exact
  engine offsets, including the exact 32 GiB edge at `34359738304`;
- the 32 GiB+1 policy rejection passed, cancellation returned the expected
  status 124, and the one-worker concurrency check passed with aggregate RSS
  of 100792 KiB; and
- a separate warm-cache exact-edge scan in a container hard-limited to 8 GiB
  memory, 8 GiB memory-plus-swap, and four CPUs reported `FOUND` in 1:49.95,
  with 100944 KiB peak RSS and zero swap use.

The 8 GiB result demonstrates that the sparse raw exact-edge case does not
require RAM proportional to the file size. It does not establish the memory
requirements of a production signature database, deep parsers, materialized
32 GiB input, concurrent workers, or a cold page cache.

Subsequent fail-visible parser work found RAR header, configured-limit,
encrypted-member, and extraction-error paths that could otherwise leave
`cli_scanrar_file()` with a clean result after required content was not
inspected. The working tree now preserves the mapped UnRAR error, marks those
paths incomplete/non-cacheable, and retains configured-limit results. The
synthetic `test_rar_truncated_header_is_fail_visible` regression reached the
member-header error path and passed in the disposable ARM64 harness; the full
run reported 1,329 checks, 816 fixture/environment failures, and 0 errors.
All four local safety gates passed. Sonic1 Docker status also succeeded, but
the remote `scanners.c` and test-source checksums differ from this worktree, so
no remote rebuild qualification claim is made.

The ARJ extraction follow-up found `cli_scanarj()` scanning a temporary member
even when `cli_unarj_extract_file()` had failed, and ignoring a failed rewind.
The scanner now marks those paths incomplete, closes the partial descriptor,
and refuses nested scanning. The public
`test_arj_truncated_member_extraction_is_fail_visible` regression passes in the
rebuilt disposable ARM64 harness; the full run reports 1,330 checks, 816
fixture/environment failures, and 0 errors. The source guard passes. Local
hashes are `scanners.c=702d96317bfafd233722227826320cd064185f27868f654d1c41cac758e8f300`
and `check_clamav.c=08581f2bb5cc8ad282f1ba232945ad9ba31e227ed615af3b470ad87abcac22b7`.
Sonic1 Docker access remains verified, but its scanner and test-source checksums
differ from this worktree, so no remote rebuild qualification claim is made.

The legacy GZip compatibility fallback was also unsafe: it could pass temporary
output to the nested scanner after a `gzread()` error, a configured limit, a
write failure, or an unclean `gzclose()`. It now requires a clean decoder EOF
and close before nested scanning, preserves the failure status, marks the scan
incomplete/non-cacheable, and refuses partial output. The public
`test_gzip_bzip_truncated_streams_are_fail_visible` regression covers the main
GZip path; source guards cover the fallback diagnostics. The disposable ARM64
harness reports 1,330 checks, 816 fixture/environment failures, and 0 errors;
all four local safety gates pass. Final local hashes are
`scanners.c=2058ad161d767ddd2a3236f1f526a3cc23f8acd9c1f5339bfb05bfa2c148876c`
and
`check_clamav.c=08581f2bb5cc8ad282f1ba232945ad9ba31e227ed615af3b470ad87abcac22b7`.
The fresh Sonic1 host-list request `req_4cde3cc9fecf4ca598715bf27c458492`
returned `sonic1`; Docker request `req_b05826ed19d044c6bb325013394f981e`
showed the three existing ClamAV containers up. Remote `scanners.c` and test
source checksums remain
`50f08543b6af7b782ebcd7e69124f30d43a3d0d36fd6970e4bb87597ac541a96` and
`767d8b90b1324639b5aa86f78a0d32814e7706fdf14a04272360187026dc8352`
(`req_4218401a0fed4364ab7bb55281a73aec` and
`req_af22ebc5736e4317b31a318957258db3`), so no remote rebuild qualification
claim is made.

The PE optional-unpacker audit found the shared `CLI_UNPSIZELIMITS()` macro
turning configured size/scan-limit failures into `CL_CLEAN` after skipping
unpacking. It now preserves the exact limit result, marks the scan
incomplete/non-cacheable, and returns the failure. The public
`test_pe_unpack_limit_is_fail_visible` regression exercises the recognized UPX
fixture in the disposable ARM64 harness; the full run reports 1,331 checks,
814 fixture/environment failures, and 0 errors, with no new test failure. All
four local safety gates pass. Final local hashes are
`pe.c=8a4e95a3bda2cbadc5f9c59398488fec6d97efa3fbd67ecc9e5bc62e9d901142`,
`scanners.c=2058ad161d767ddd2a3236f1f526a3cc23f8acd9c1f5339bfb05bfa2c148876c`,
and
`check_clamav.c=299dd7cb9befd20fb9e51082f0de737d4781ecc95b64ceba20802bde87b101fd`.
The fresh Sonic1 host-list request `req_9c1bcba0aea34faa93e9d18a5066a5b1`
returned `sonic1`; Docker request `req_b8ecb39d94414784822a0296e52e5ce2`
showed all three existing ClamAV containers up. Remote `pe.c` and test-source
checksums are `d21661c28cc8f0822d30002f3b6c76cc63743e57b38edecbdce5b581a05e2422`
and `767d8b90b1324639b5aa86f78a0d32814e7706fdf14a04272360187026dc8352`
(`req_22d03d46307f41a9a16304b0640e78ea` and
`req_8beff3e6629e418db722734d109da137`), so no remote rebuild qualification
claim is made.

The PDF stream/extracted-object follow-up found raw and decoded stream paths,
plus the legacy JavaScript/object writer, discarding configured-limit or write
failures after skipping or partially writing output. They now check the
prospective bounded total, preserve `CL_EMAXSIZE` and other limit statuses,
mark the scan incomplete/non-cacheable, and refuse partial output. The public
`test_pdf_stream_limit_is_fail_visible` and
`test_pdf_extracted_object_limit_is_fail_visible` regressions pass in the
disposable ARM64 static harness; the full run reports 1,333 checks, 817 known
fixture/environment failures, and 0 errors, with both new cases absent from
failure output. All four local safety gates pass. Local SHA-256 values are
`pdf.c=0b83e3f28ef841022e44bb3ffcfb24548725cd74b02a826b39e22d5abd019a31`,
`pdfdecode.c=1a76ce43611701106798463297eb6f2f89bb2f2d3fd653383aed2e38831c9c31`,
and `check_clamav.c=6195e40668bdc89090188742ba8c7848fc75bece789eab23d3b64c918c5312b9`.
Fresh Sonic1 host-list request `req_89b90bc39c2e4347b2168c00587901b5` returned
`sonic1`; Docker request `req_b55b48136be9427780d9b9e69da89a02` succeeded and
showed all three existing ClamAV containers up. Remote `pdf.c`, `pdfdecode.c`,
and test-source checksums are `b9d26f8de6b0b8352bd6760eaeb3fc135e7075fffb57fbf6483224f2f268d922`,
`a1a811fcc0d6d6a2373f8cb9e5065cb11a249bdc74d78dbee8fad6fa6078ff3f`, and
`767d8b90b1324639b5aa86f78a0d32814e7706fdf14a04272360187026dc8352`
(`req_b0d265e9ec974dcbbb8032d7147f9cbd`, `req_ce7e3dcb0eee439a958dd764cc9217c0`,
and `req_22fcd72b8b9646d5870520d35d626a45`), so the remote source does not
qualify this local follow-up and no remote rebuild claim is made.

The ARJ member-limit audit found `cli_scanarj()` converting a configured
member-size/scan-limit failure into `CL_SUCCESS` after skipping that member.
It now preserves the first deferred limit result while allowing later members
to be inspected, stops immediately on timeout, marks the scan incomplete and
non-cacheable, and returns the limit when no stronger result occurs. The public
`test_arj_member_limit_is_fail_visible` and existing
`test_arj_truncated_member_extraction_is_fail_visible` regressions pass in the
disposable ARM64 static harness; the full run reports 1,334 checks, 817 known
fixture/environment failures, and 0 errors. All four local safety gates pass.
Local SHA-256 values are
`scanners.c=15d8d7902a717fe604c54d895e67f6f9731016f303d57984cc7e6c4fd2dd98a3`,
`check_clamav.c=e8f5cb68b309d1850fbf8c55328b9759a3c0022e6e2d27f10299a5dccf906ca5`,
and
`largefile_source_guards.sh=88251750174660601dc8274827c763e9f24a78cdd90f80db72a0ebfd339e7d77`.
Fresh Sonic1 host-list request `req_1ad364b37c584f2381133fb4a7bfa233`
returned `sonic1`; Docker request `req_5985e388d1a547728829b72d04e146e5`
using `sonic1-camera-key` succeeded and showed the three existing ClamAV test
containers up. Remote `scanners.c` and test-source checksums are
`50f08543b6af7b782ebcd7e69124f30d43a3d0d36fd6970e4bb87597ac541a96` and
`767d8b90b1324639b5aa86f78a0d32814e7706fdf14a04272360187026dc8352`
(`req_c266bd53abe741da829168dda804c868` and
`req_cf8f577d6f6f404396389ca88aa45a6e`), so no remote rebuild qualification
claim is made for this local ARJ follow-up.

The OLE2 property-tree audit found oversized embedded files being skipped
without recording a deferred limit result, and the old condition could ignore
`MaxScanSize` when `MaxFileSize` was unset. The walker now checks both limits
independently, records the first `CL_EMAXSIZE` while continuing sibling
inspection, marks the scan incomplete/non-cacheable, and returns the deferred
limit when no stronger result occurs. The fixture-backed
`test_ole2_member_limit_is_fail_visible` regression passes in the disposable
ARM64 static harness; the full run reports 1,335 checks, 817 known
fixture/environment failures, and 0 errors. All four local safety gates pass.
Local SHA-256 values are
`ole2_extract.c=eaba46a94a5aeaef7664774d3951d6c3ecfdf651b47be03626f0846924c116c7`,
`check_clamav.c=ca115aa4735576289ab31f6268a8752ae2170778e5ab5d85509e3b8a5292b274`,
and
`largefile_source_guards.sh=c4e4ec674acf8086fad445517b0ed97dae8436c7421ba4dd8866080cb7770029`.
Fresh Sonic1 host-list request `req_98c8b9951fd044468b081c29ab3d87e1`
returned `sonic1`; Docker request `req_801da2e90300458c8343d78b4e430dbf`
using `sonic1-camera-key` succeeded and showed the three existing ClamAV test
containers up. Remote `ole2_extract.c` and test-source checksums are
`314f8896f7112587330415dc0152c6dc6e111cb06b3460d5a4e3c88abf966504` and
`767d8b90b1324639b5aa86f78a0d32814e7706fdf14a04272360187026dc8352`
(`req_5ac907a0e535491c812e7c635e042551` and
`req_93102cb71ff4450f85713062515b1eca`), so no remote rebuild qualification
claim is made for this local OLE2 follow-up.

The PEspin limit audit found the expanded-section total being accumulated in
`unsigned long` and the unpacker returning a private size status that its
caller could normalize away. `cli_pespin_check_limits()` now uses `uint64_t`,
records `Heuristics.Limits.Exceeded.MaxFileSize` through the common sticky
limit path, and the PEspin cleanup case returns `CL_EMAXSIZE`. The focused
`test_pespin_limit_accounting_is_fail_visible` regression passes in the
disposable ARM64 harness with two `UINT32_MAX` sections against a 4 GiB
limit. The current UnRAR-disabled harness reports 1,305 checks, 786 known
fixture/environment failures, and 0 errors; the four local safety gates pass.
Local SHA-256 values are
`spin.c=8f3e2744edb17b73870f7bc91238b8caa0f3ca566d9cc0ef35ebdba72543f701`,
`spin.h=d5510a68be2e0570c56207a6b71a75850e18e573e9bb7ab45ed3a00a7b3184b7`,
`pe.c=5a908aa9e986cf1be3e3d42d3d5fec989518da475a4e48b384f4a5f4bd9a72fb`,
`check_clamav.c=f3f9415f23c5040b84afaef1fa2345a85e7572341a3fabe57a0060d3fe1d6237`,
and
`largefile_source_guards.sh=eaae5c0450df7d5059e2c5d5bdca6c485b970692f1c45a6d3276eb3fe7becd85`.
Final fresh host-list request `req_3a883c4974e24e8e93c6e97150e9b28d` returned
`sonic1`; Docker request `req_81faaf3650fb46cabe511252099a2182` using
`login_profile=sonic1-camera-key` succeeded with exit 0 and showed the three
ClamAV test containers up.
The encrypted PEspin fixture itself still reaches an earlier PE-format
rejection in this checkout, so this evidence is deliberately helper-level;
no Sonic1 rebuild or remote qualification claim is made for this follow-up.

## Remaining release blockers

### 1. Sanitizer and multi-worker evidence remains open

The dedicated workflow must complete ASan/UBSan C/C++ build/tests and runtime
evidence. Worker counts 2 and 4 must pass within the configured aggregate RSS
budget. The successful one-worker run does not predict parser scratch use or
database residency under multiple concurrent production scans.

### 2. Full integration protocols remain open at scale

The 64 GiB host must exercise actual clamd INSTREAM/FILDES and
clamav-milter transfers across 4 GiB and at the 32 GiB boundary. Pure quota
tests prove arithmetic but not socket framing, cancellation, temporary-file
behavior, or daemon lifecycle.

### 3. Production workload and cold-cache certification remains open

The passing gate uses sparse files and a purpose-built boundary signature.
Production signature databases, materialized files, cold-cache reads, and
malformed or expanding deep-parser workloads must be characterized for RSS,
page-cache pressure, temporary storage, latency, and failure behavior. The
warm-cache 8 GiB result must not be treated as a minimum-RAM guarantee for
production deployment.

### 4. Remaining generic false-clean and archive-corpus gaps

Some generic size, recursion, and file-count limit paths can still normalize
an incomplete inspection to success unless the sticky incomplete state is
set. The current ZIP strong-encryption and masked-header paths now have an
explicit incomplete/non-clean disposition and focused regressions; broader
encrypted/malformed archive corpus coverage remains a release-qualification
item. Until the remaining generic paths are closed and regression-tested, an
apparently clean result is not universally proof of complete inspection.

### 5. Fail-visible caps are not full deep-parser capability

PCRE subjects above 1 GiB; PDF deep parsing above 64 MiB only on non-mmap
fallback builds; one decoded DMG `blkx` metadata block above 64 MiB; applicable legacy bytecode on inputs above
4 GiB; and bounded NSIS/EGG or unsupported archive encryption/compression
paths can produce an explicit incomplete/non-clean result. This is safe
failure behavior, but it is not evidence that every nested object up to
32 GiB receives every optional deep-analysis pass.

### 6. Broader parser compatibility remains a release qualification item

The complete configured normal suite passes after the InstallShield, NSIS,
and DMG fixes. Focused DMG fixtures cover split text/CDATA with XML whitespace,
invalid alphabet, misplaced padding, incomplete quartets, post-padding
suffixes, missing `END`, and non-final `END`. A broader real-world Apple DMG
corpus and multi-gigabyte malformed-container corpus still belongs in release
qualification; multi-segment DMGs remain intentionally unsupported and fail
visibly.

### 7. Release infrastructure must be exercised, not only reviewed

The repository expects a self-hosted runner labelled
`clamav-largefile-64gb`. A real workflow run must prove that runner capacity,
cgroup headroom, toolchain, immutable source revision, artifact hashes, and
attestation publication all work together. A locally manufactured evidence
directory is not release provenance.

## Required production acceptance gate

Use the manual GitHub Actions inputs only on the dedicated Linux x86-64 host:

```sh
gh workflow run cmake.yml --repo OWNER/REPO --ref BRANCH \
  -f run_largefile_runtime=true \
  -f run_largefile_sanitizer=true \
  -f production_database=/srv/clamav/production-db \
  -f production_file=/srv/clamav/fixtures/production-cvd-edge.bin \
  -f materialized_file=/srv/clamav/fixtures/materialized-deep-parser.bin \
  -f expansion_fixture=/srv/clamav/fixtures/parser-expansion.bin
```

Successful evidence artifacts are named:

- `clamav-largefile-runtime-verified`
- `clamav-largefile-sanitizer-verified`

The artifact must exclude `corpus/`, contain `runtime_gate=pass` in
`build-identity.txt`, pass `tools/largefile_runtime_evidence_check.sh`, match
its `SHA256SUMS`, and have a GitHub build-provenance attestation for that
manifest. Failed diagnostic artifacts must not be promoted as release
evidence.

## Final verdict

This milestone materially closes the previously identified coordinate,
resource, and fail-open defects in the audited 32 GiB raw path. Commit
`bba68110e04f78504d2af389050c349e01861315` has credible Linux x86-64 proof
for exact-offset raw detection through 32 GiB, the 32 GiB+1 policy boundary,
cancellation, and one-worker operation, including a warm-cache exact-edge scan
under a hard 8 GiB memory-and-swap ceiling.

It is **not yet appropriate to publish as production-ready 32 GiB ClamAV**.
That designation still requires sanitizer and 2/4-worker evidence,
large-transfer clamd/milter integration, production-database/deep-parser and
cold-cache resource qualification, and closure of the remaining generic
false-clean gaps described above.

## Latest bounded mail-limit follow-up — 2026-08-15

The UNIX mbox dispatcher previously handled `FAIL` and `VIRUS` from a completed
message but dropped recursive `MAXREC` and `MAXFILES` statuses while advancing
to the next message. Nested multipart return paths also did not explicitly
preserve `MAXFILES`. `libclamav/mbox.c` now maps both statuses to their public
non-clean results, records the corresponding exceed-max heuristic, and stops
the mailbox walk. A synthetic two-part multipart containing a nested
`message/rfc822` part, followed by
a header-only mailbox entry exercises the path with `MaxFiles=1`; the new
`test_mbox_nested_maxfiles_is_fail_visible` regression executed in the
standalone API case without a failure entry.

The disposable ARM64 UnRAR-disabled harness built `check_clamav` successfully
and reported 1,306 checks, 786 known fixture/environment failures, and 0
errors; the failures are the existing missing-CVD/corpus setup cases. The four
local safety gates passed. Current SHA-256 values are
`mbox.c=ea0c1dbef45714db3408bc70f2397033ab649096fb25f880fccd13b342469384`,
`check_clamav.c=d81d11e1d9bbeadd6ed102bc7e16cf53025c5eee580047eadc6228e1bd836f3e`,
and
`largefile_source_guards.sh=2a7a2703bbcd9bd91e3f671f7bb801d766756fbcfdf0ab2ab09c609bd0c808f2`.
The prior PEspin hashes remain unchanged.

Fresh MCP-SSH host-list request `req_426f3ab06872438da254971e3648a391`
returned `sonic1`. Docker status request
`req_d5e17b9a827d46e68c55c0a27b302d0d` using
`login_profile=sonic1-camera-key` succeeded with exit 0 and showed the three
existing ClamAV test containers running. The remote checkout was not rebuilt
for this local mbox change; production-CVD, cold-cache, CI/release, and remote
rebuild qualification remain open.

A subsequent non-destructive Docker inspection request
`req_aec06e41d1744d79a9d6dad9f52b571e` succeeded with exit 0 and confirmed all
three containers are `running`, use image `clamav-32gb:test-tools-742a8a4`, and
have working directory `/workspace/ClamAV`. A source-hash request
`req_e6c81b5f32e748f58f5d0367aa05da2f` showed the remote
`libclamav/mbox.c` hash `8439f4d9ac311ba0775d2ef0e4f7c51b90e91b1b36162711bd757ece21fd534`
and `unit_tests/check_clamav.c` hash
`8912af667dcdf0d8766b1507790f4c7813d552aead93bfbaafa0761be593ed20`, which
do not match the current local mbox follow-up. This confirms Docker access and
container liveness only; no remote rebuild or qualification of the new patch
is claimed.

The prior manual OOXML review did not find a reproducible limit bypass because
the metadata parser's non-critical returns are normalized to permit ZIP
content scanning, while the common sticky incomplete-result reconciliation
retains configured-limit failures at the outer scan boundary. A subsequent
source review did identify a separate false-clean class: libxml2 reader
initialization failures, truncated `[Content_Types].xml`, and missing required
OOXML metadata parts could be normalized to success. The current follow-up
marks those conditions incomplete and keeps OOXML metadata XML parsing
fail-visible. The existing architectural `FIXMELIMITS` comments in mbox,
PEspin, and PDF remain audit follow-up markers rather than newly demonstrated
false-clean defects.

## Latest large-file follow-up — HWP embedded OLE2 boundary — 2026-08-15

The HWP embedded-OLE2 wrapper stores its payload-size prefix in a 32-bit
field. `libclamav/hwp.c` now rejects payloads larger than `UINT32_MAX` with
`CL_EPARSE`, marks the scan incomplete and non-cacheable, and marks truncated
prefix reads incomplete before nested scanning. The focused
`test_large_document_parser_caps_are_fail_visible` regression covers the
oversized wrapper.

The disposable ARM64 `check_clamav` target rebuilt successfully. Its aggregate
run reported `1306` checks, `786` known fixture/environment failures, and `0`
errors; the new HWPole2 regression was absent from the failure output. All
four local safety gates passed. Local hashes are
`hwp.c=72686bc5f292ffb88f936065a6e7663c0ed55ca190000775cee04966f81dd2ba`,
`check_clamav.c=43fefc8210cf9dc463a98fd60c2fb480a657ca15b514a49803e2b8c3c3f73322`,
and
`largefile_source_guards.sh=38dda79789ff6f80321d9e96bd384a5b4302bf8dc464e26cf9705721d662f9db`.

Fresh MCP-SSH host discovery request `req_00af40b0aada46de98bb3c3c5ba908ff`
returned `sonic1`. Docker request
`req_c246b4efe35544a1bbcbcdd5a9579391` using `sonic1-camera-key` showed all
three existing ClamAV test containers up. Inspect request
`req_d239185d81b04ef8a0f29b10018f3498` confirmed the primary container is
`running`, uses `clamav-32gb:test-tools-742a8a4`, and mounts
`/workspace/ClamAV` read-only. Remote hash request
`req_1c42c75365504b7bb05b1a80bc5cb021` returned HWP/test/guard hashes that do
not match the current local sources. No source upload, remote rebuild, or
remote qualification of this patch is claimed.

## Validation refresh — 2026-08-15

The resumed local validation rebuilt both `check_clamav` and the separate
`check_clamfi_quota` target in the disposable ARM64 environment. The
registered large-file/release-control CTest subset passed 4/4:
`largefile_poc_fail_closed`, `largefile_source_guards`,
`largefile_runtime_evidence_check`, and `clamav_milter_quota`. The workflow
YAML parse also passed.

The aggregate `check_clamav` run in the source-mounted disposable environment
reported `1142` checks, `840` fixture/environment failures, and `0` errors.
This is not a clean-suite claim: the checkout used for that run lacks the
full LFS/corpus/CVD/certificate environment, and the runner hard-codes
`srunner_run_all` rather than exposing a focused command-line selector. The
new HWPole2 regression did not appear in the failure output, but it is not
claimed as a separately isolated runner result.

Fresh MCP-SSH verification used host-list request
`req_2ec6db7f3d1442f29fb13caaae9e9fc8`, Docker status request
`req_51e5181dcc8d493a865337373b4f983b`, inspect request
`req_ede657cb810b44ba8f98540f64991433`, and source-hash request
`req_48a1b5ad007348d1b2fd2b0b65767c95`. With
`login_profile=sonic1-camera-key`, `docker ps` showed all three existing
ClamAV test containers up. The primary container uses
`clamav-32gb:test-tools-742a8a4`, mounts the remote checkout read-only at
`/workspace/ClamAV`, and remains running. Its HWP/test/guard hashes differ
from the current local sources, so Docker liveness is verified but no remote
rebuild or qualification of this patch is claimed. Production CVD, cold-cache,
full release/CI, and broader remote qualification remain open.

## Latest GIF parser boundary follow-up — 2026-08-15

The recognized GIF parser had four unchecked boundary transitions: fixed
graphic-control payloads, local color tables, the LZW minimum-code-size byte,
and the end-of-image trailer. A truncated GIF could therefore advance over
unavailable bytes or accept an image without a trailer as clean. The parser
now marks each path sticky-incomplete and non-cacheable, preserves heuristic
reporting for full scan contexts, returns `CL_EPARSE` for minimal direct
callers, and retains overlay scanning only when the parser status permits it.

`test_gif_truncated_blocks_are_fail_visible` covers all four cases in a
dedicated Check `gif` group. The focused ARM64 invocation
`CK_FORK=no CK_RUN_SUITE=cl_suite CK_RUN_CASE=gif ./unit_tests/check_clamav`
passed 1/1 with 0 failures and 0 errors. The rebuilt aggregate harness
reported `1307` checks, `786` fixture/environment failures, and `0` errors;
the GIF regression was explicitly recorded as passed. The registered
large-file/release-control CTest subset passed 4/4, as did the source guards,
fail-closed/runtime-evidence controls, and workflow YAML parse. Local hashes:
`gif.c=d5fedded1cad41267f6ec2c7e9141e89d67f434f63f9de8db649e71b4d66a4f9`,
`check_clamav.c=fed677b3e8def065d9328b5a056de9e44840e54aefbf0280a9125392a43fa8ce`,
and
`largefile_source_guards.sh=4a9084ccc2099a89ae4688776a75075a052b1872d4d045e3247d4af3bad91d99`.

Fresh MCP-SSH evidence used host-list request
`req_3891a53b4be04bb48a52983a28a9d728`, Docker status request
`req_2916efb44812499c8bba23d01d56e3af`, inspect request
`req_d8b5757de5b9493bbec6192556d38280`, image request
`req_824c25d8f52c44c180cf43403adc2971`, and source hashes
`req_4d5f7ebb11264a25906e0864739c01c8`. With
`login_profile=sonic1-camera-key`, all three existing containers were up on
`clamav-32gb:test-tools-742a8a4`, image digest
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
The primary container still mounts `/workspace/ClamAV` read-only. Remote
GIF/test/guard hashes differ from the local patch, so this verifies Docker
liveness and image/source provenance only; no remote rebuild or qualification
is claimed.

## Latest PNG parser boundary follow-up — 2026-08-15

The recognized PNG parser now treats truncated chunk types, chunk data, and
CRCs, malformed `IHDR` lengths/dimensions, non-empty `IEND` chunks, and a
missing `IEND` as sticky incomplete and non-cacheable. Minimal direct parser
callers receive `CL_EPARSE`; full scan contexts retain broken-media heuristic
reporting and overlay scanning only when the parser status permits it.

`test_png_truncated_chunks_are_fail_visible` covers five synthetic cases in a
dedicated Check `png` group. The focused disposable ARM64 invocation
`CK_FORK=no CK_RUN_SUITE=cl_suite CK_RUN_CASE=png ./unit_tests/check_clamav`
passed 1/1 with 0 failures and 0 errors. The aggregate harness reported
`1308` checks, `786` known fixture/environment failures, and `0` errors. The
registered large-file/release-control CTest subset passed 4/4, and the source,
fail-closed/runtime-evidence, and workflow YAML controls passed. Local hashes:
`png.c=847ea343241241429388b5b242989d48d881eb2d48bc53fc7bb07e553e0f209d`,
`check_clamav.c=c8f7d40c5f55046c22abcb8bf5512b692d8edfeb35dae9ffb1ea9eaf7e6dea4c`,
and
`largefile_source_guards.sh=53bca065b69fea84a34ef4572a85f43c801acbad25aba1fee80464b2fd5afbf4`.

Fresh MCP-SSH evidence used host-list request
`req_a64c9e1e92074a32a784242258314923`, Docker status request
`req_ade8413ef3514607803ade1e4e51a620`, inspect request
`req_ee1ef808a7f249e183d24c3d0e5b153f`, image request
`req_cb12f6d811cd487396dc198406244fa9`, and container source hashes
`req_36b8dfb768334f439c933adb4187ef5d`. With
`login_profile=sonic1-camera-key`, all three existing containers were up on
`clamav-32gb:test-tools-742a8a4`; the primary container was `running`, its
`/workspace/ClamAV` bind was read-only, and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
The remote PNG/test/guard hashes differ from the current local patch, so this
verifies Docker liveness and provenance only; no remote rebuild or qualification
of the PNG change is claimed. Production CVD, broader parser corpus,
cold-cache workload, sanitizer/multi-worker current-head, full release/CI, and
remote rebuild qualification remain open.

## Latest PDF trailer boundary follow-up — 2026-08-15

The PDF parser now makes recognized documents with a missing `%%EOF`, missing
`startxref`, negative/out-of-range xref offsets, or an invalid xref fail-visible
and non-cacheable. Structural errors are recorded while parsing and applied at
the common return boundary, preserving object detections and virus results.
Minimal direct parser callers receive `CL_EPARSE`.

`test_pdf_truncated_trailer_is_fail_visible` covers missing `%%EOF`, missing
`startxref`, and a negative xref in a dedicated Check `pdf` group. The focused
disposable ARM64 invocation passed 1/1 with 0 failures and 0 errors. The current
forked aggregate snapshot reported `1145` checks, `840` known
fixture/environment failures, and `0` errors; the no-fork aggregate remains an
intermittent harness limitation and exited 139 after the same 1145 checks, with
0 Check-reported errors. The registered large-file/release-control CTest subset
passed 4/4, and source, fail-closed/runtime-evidence, and workflow YAML
controls passed.

Local hashes are `pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`check_clamav.c=50451a1805f689f546d45e853c89ce50e992cbfe0c18880b4ad67146b1207acc`,
and `largefile_source_guards.sh=0aa1f42a3f52e4cd842d5f58def7ffe3b95e8bb1b79444b1af5864c0a81fd4ad`.

Fresh MCP-SSH evidence used host-list request
`req_699bfdd0509d4bbd8fdfd635b6ab3794`, Docker status request
`req_fa690ea074a144be9c92a4ee20a35506`, inspect request
`req_5551d4e47af1434e98483e833ff80065`, image request
`req_81bda151c5284ac6845bfdc4f19419cd`, and container source hashes
`req_c9b2355d08a24997a960d3573107304f`, using
`login_profile=sonic1-camera-key`. All three containers were up on
`clamav-32gb:test-tools-742a8a4`; the primary `/workspace/ClamAV` bind was
read-only and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PDF/test/guard hashes differ from the local patch, so Docker liveness
and image/source provenance are verified without a remote rebuild or PDF
qualification claim. Production CVD, broader parser corpus, cold-cache,
sanitizer/multi-worker current-head, full release/CI, and remote rebuild gates
remain open.

## Latest XLM extraction completion follow-up — 2026-08-19

The Excel 4/XLM extraction path previously treated a missing materialized BIFF
stream as clean and could scan buffered or truncated staging output as though
the input had reached a complete record boundary. It now marks missing input,
truncated BIFF headers, output flush/close failures, and non-clean nested scans
as explicit incomplete results. Focused missing-input and truncated-header
regressions and source guards are registered. Recursive OLE2 dispatch now
distinguishes streams belonging to another extraction subtree from an actual
XLM/image extraction failure. This is a local source change;
compiled Linux/Sonic1, sanitizer, and broader XLM corpus qualification remain
open.

## ALZ partial-member limit handling — 2026-08-21

ALZ stored, Deflate, and BZip2 extraction previously finalized the bytes
already produced when a member crossed a per-file or aggregate quota, allowing
the scanner sink to inspect a truncated prefix before the limit result was
recorded. Quota and decoder-error paths now abort the active member and discard
its partial output; only complete members reach nested scanning. Focused Rust
regressions cover quota and decoder-error discard behavior, and source guards
record the invariant. Compiled Linux/Sonic1, sanitizer, and broader ALZ corpus
qualification remain open.


## Latest 7-Zip member-name width follow-up — 2026-08-19

The 7-Zip SDK exposes member-name lengths as `size_t`, but the scanner stored
that value in an `int` and multiplied it before allocation. The scanner now
keeps the native width and rejects an unrepresentable UTF-16 allocation as an
explicit resource/incomplete result. This closes the local arithmetic hazard;
compiled Linux, sanitizer, malformed-archive corpus, and Sonic1 qualification
remain open.

## Latest PDF decode and aggregate lifecycle follow-up — 2026-08-15

PDF best-effort object extraction no longer loses the incomplete state when a
filtered stream returns `CL_EPARSE` and the parser continues to later objects:
`pdf_decodestream()` now marks the containing layer incomplete and
non-cacheable before its status is normalized for continued parsing. The
dedicated `test_pdf_decode_error_is_fail_visible` regression uses malformed
Flate data and verifies the parse result, sticky state, and cache suppression.

The fixture-incomplete bytecode parallel-load test also now checks for its
`bytecode.cvd` fixture on the main test thread before creating workers. A
missing checkout fixture remains a visible failure, but Check assertions are no
longer raised from worker threads. The focused PDF group passed 2/2. Three
consecutive current no-fork aggregate runs completed without a crash: `1146`
checks, `840` known fixture/environment failures, and `0` errors, exiting 1 for
those fixtures. The matching forked aggregate also reported `1146` checks,
`840` failures, and `0` errors. The isolated bytecode suite reported 48 checks,
5 fixture failures, and 0 errors. The registered CTest subset passed 4/4;
source, fail-closed/runtime-evidence, and workflow YAML controls passed.

Local hashes are
`pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`pdfdecode.c=5aa98bba6753b3950edf207bbcfd8a25e4ee154b17acf743cf21fb4316cc73e7`,
`check_clamav.c=886628a0c83441f27d3c427fbad97dd038b0753a47c2d08af560aac977f5f84f`,
`check_bytecode.c=b0e9254e0dfc987ed3069d91d73dfab518fc069ebc05887ac77cfa071117a0f5`,
and
`largefile_source_guards.sh=f7e3b418020923be94b622a716c731f5d053e708fc4368a1c434909325f4acb0`.

Fresh MCP-SSH evidence used host-list request
`req_3d029d63018b4790b7700971d09bc890`, Docker status request
`req_5c341b5a6a0b4140a412ff4faa853cbf`, inspect request
`req_1fa443f9d5934ddb9532d14f6c10acac`, image request
`req_a4cc36b931f74290b33b09fe9c7e7ce5`, and container source hashes
`req_e60bf09ef17942cf80d9b499d5e0a3ae`, using
`login_profile=sonic1-camera-key`. All three containers were up on
`clamav-32gb:test-tools-742a8a4`; the primary `/workspace/ClamAV` bind was
read-only and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PDF/decode/test/guard hashes differ from the local patch, so Docker
liveness and image/source provenance are verified without a remote rebuild or
qualification claim.

## Latest HWPML XML boundary follow-up — 2026-08-15

The attachment-bearing HWPML path now passes `MSXML_FLAG_FAIL_INCOMPLETE` to
the streaming XML parser. A truncated XML reader result therefore marks the
layer incomplete and non-cacheable and returns `CL_EPARSE`, instead of being
silently suppressed as metadata-only best effort. The dedicated
`test_hwpml_truncated_document_is_fail_visible` group passed 1/1.

Three consecutive current no-fork aggregate runs and one forked run completed
without a crash: `1147` checks, `840` known fixture/environment failures, and
`0` errors. The registered CTest subset passed 4/4, and source,
fail-closed/runtime-evidence, and workflow YAML controls passed.

Local hashes are
`hwp.c=be3f3b5a9d09532cf872fab3ff4c4fd278c30eaa27c14dabee5fc224b108f00b`,
`pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`pdfdecode.c=5aa98bba6753b3950edf207bbcfd8a25e4ee154b17acf743cf21fb4316cc73e7`,
`check_clamav.c=0737b2e7cc94744f84a620cbbb49ca76b12adefdaca52f56ae1e7a02147b0fd0`,
`check_bytecode.c=b0e9254e0dfc987ed3069d91d73dfab518fc069ebc05887ac77cfa071117a0f5`,
and
`largefile_source_guards.sh=4016ec50dd8a6907ec30cd65f423ebf2fa3e9e1bb20a5f7b97a46da4810d9d15`.

Fresh MCP-SSH evidence used host-list request
`req_32f6b1d1395e4a32935d36053c8b0184`, Docker status request
`req_a17de6e58ad9491cb0f60a0c9e79a4bf`, inspect request
`req_04a57ef44632451ca9395d3feaa829a1`, image request
`req_8ea41451f46c4a4bb1ceba85f5467b33`, and container source hashes
`req_d4300ebb99084dfa9b4660450e71b879`, using
`login_profile=sonic1-camera-key`. All three containers were up on
`clamav-32gb:test-tools-742a8a4`; the primary `/workspace/ClamAV` bind was
read-only and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote HWPML/PDF/decode/test/guard hashes differ from the local patch, so
Docker liveness and image/source provenance are verified without a remote
rebuild or qualification claim.

## Latest HWP3 password-protection follow-up — 2026-08-15

The HWP3 parser previously returned `CL_SUCCESS` after recognizing a
password-protected document, leaving unsupported deep parsing indistinguishable
from a complete clean scan. That branch now records the sticky incomplete
state, disables fmap clean caching, and returns `CL_EPARSE` through the common
finalization path. The dedicated HWP3 group, including the existing truncated
parser case and new `test_hwp3_password_protection_is_fail_visible`, passed
2/2.

Three consecutive current no-fork aggregate runs and one forked run completed
without a crash: `1148` checks, `840` known fixture/environment failures, and
`0` errors. The registered CTest subset passed 4/4, and source,
fail-closed/runtime-evidence, and workflow YAML controls passed.

Local hashes are `hwp.c=59e781add619b9fce9340d1051bd997490ffb59922c61b07d013c64849640e9f`,
`check_clamav.c=db823a713e0d8a0729c7aa4a31b2945a84f84ac27b85819d8bf9df219c9a7887`,
and
`largefile_source_guards.sh=0e6bb413a7a0ff120da8791d76b7f81a94e303c6b80157e7333a499c59e260a2`.

Fresh MCP-SSH verification used host-list request
`req_0ef932c6522e4fce9be05f156ee33a7f` and Docker status request
`req_40f0d5693b2c4c30bbc631e74a04ddd7`, using
`login_profile=sonic1-camera-key`. Sonic1 reported the three validation
containers `clamav-32gb-final-f08c7b0`, `clamav-32gb-sanitizer-tests-rw`, and
`clamav-32gb-test-d5b8392` up on `clamav-32gb:test-tools-742a8a4`. A fresh
container-hash request `req_48eb6b0b814c46c08e2c91951a791672` returned
`hwp.c=b44c5ce8c4c5e90152dd5463cf3e147077a519c99d1b076265d02c670e076fcd`
and
`check_clamav.c=8912af667dcdf0d8766b1507790f4c7813d552aead93bfbaafa0761be593ed20`;
both differ from the current local patch. Remote Docker liveness and source
provenance are verified, but no remote rebuild or qualification claim is made.

This closes the observed HWP3 password false-clean path. Production CVD,
broader parser corpus, cold-cache workload, sanitizer/multi-worker current-head
evidence, full release/CI runner, and remote rebuild qualification remain open.

## Latest XAR XML reader boundary follow-up — 2026-08-15

The XAR TOC reader previously treated libxml2 reader status `-1` as ordinary
end-of-input in both the subdocument pre-scan and member-value loop. A malformed
TOC could therefore become `CL_BREAK`, which the outer scanner normalized to
`CL_SUCCESS`. The reader-error paths now return a non-clean parse result and
mark the scan incomplete and non-cacheable. The dedicated XAR group, including
`test_xar_xml_reader_error_is_fail_visible`, passed 1/1.

The current worktree was also rebuilt in a disposable ARM64 Clang
ASan/UBSan configuration. The XAR case passed 1/1 under instrumentation; the
full current `cl_suite` completed 881 checks with 785 known fixture/setup
failures, 0 Check errors, and no sanitizer/runtime diagnostics in its logs.
This is unit-test sanitizer evidence, not the required x86-64 1/2/4-worker
runtime gate.

Three consecutive current no-fork aggregate runs and one forked run completed
without a crash: `1149` checks, `840` known fixture/environment failures, and
`0` errors. The registered CTest subset passed 4/4, and source,
fail-closed/runtime-evidence, and workflow YAML controls passed.

Local hashes are `xar.c=221de20fb3524395e18dd68c941e05fc97bcbfa5cac8f51e1bae707dad7b5cc2`,
`check_clamav.c=f722a699955d3e2cc3af036bb9b928320b58011883442d67529588801d8e2e8c`,
and
`largefile_source_guards.sh=f71d081bee3e21644756df97c3a48eaff25b0238e53c5467540c3064738753b9`.

Fresh MCP-SSH verification used host-list request
`req_8ad4ce043c154c3cb2a07f07783a7fae` and Docker status request
`req_e59c7388fb224f5f954a4ab126d9e426`, using
`login_profile=sonic1-camera-key`. Sonic1 reported all three validation
containers up on `clamav-32gb:test-tools-742a8a4`. Container-hash request
`req_b15eb96998f54f4481d50543edeed8fb` returned remote `xar.c`, test, and guard
hashes different from the current local patch. Remote Docker liveness and
source provenance are verified, but no remote rebuild or qualification claim
is made.

This closes the observed XAR XML reader false-clean path. Production CVD,
broader parser corpus, cold-cache workload, sanitizer/multi-worker current-head
evidence, full release/CI runner, and remote rebuild qualification remain open.

The final CAB/CHM bridge review found that both post-extraction `CL_EOPEN`
normalizations were too broad: an existing extracted member that could not be
opened could be reported clean. CAB and CHM now normalize `CL_EOPEN` only when
the extractor produced no output; when an output exists but cannot be opened,
they mark the scan incomplete and return `CL_EPARSE`. The source guards,
fail-closed gates, and disposable ARM64 Clang ASan/UBSan build passed. The
fresh full Check invocation recorded `1313` checks with `782` failures and
`166` errors at 27% because the broader fixture/setup run is incomplete (it
includes missing `clam.exe` fixture data); the focused
`test_mspack_scan_limit_is_fail_visible` CAB regression passed. The sanitizer
stderr also contains ASan leak summaries, so this is not a clean sanitizer
suite result. A direct existing-file-open reproducer is still absent, and
production corpus plus remote qualification remain open.

The disposable x86-64 Release runtime evidence then passed all 11 exact-size
and offset boundary POC cases. The 32 GiB+1 policy log recorded the expected
`MaxFileSize` rejection, and the 1/2/4-worker logs all reported the expected
detection with auditable RSS sums of 106844, 213832, and 420032 KiB. The
evidence was retained under `/private/tmp/clamav-32gb-x86-evidence-3`; the
final verifier marker was not written because the run was stopped after its
x86-64 ASan/UBSan 16 GiB case exceeded the configured 900000 ms limit under
emulation. That sanitizer log contains no ASan/UBSan diagnostic; this remains
partial runtime evidence, not closure of the sanitizer acceptance gate.

The restored native ARM64 Clang ASan/UBSan scanner returned `9/11` passing rows
from the same large-file POC under the official 900000 ms deadline: all cases
through 8 GiB and `32g-head.bin` passed with exact sizes, offsets, and
detections. Diagnostic-only direct scans then completed the two tail cases with
`--max-scantime=3600000`: `16g.bin` detected at offset `17179869184` in
18:23.74 with 111780 KiB peak RSS, and `32g-edge.bin` detected at offset
`34359738304` in 37:47.10 with 142712 KiB peak RSS. Neither emitted an
ASan/UBSan diagnostic. The extended deadline is now explicit in the harness,
closing the native ARM64 diagnostic boundary coverage, but this is not an
x86-64 workflow artifact and does not close the 1/2/4-worker current-head,
attestation, remote-rebuild, or production-corpus gates.

The latest fresh MCP-SSH host-list request `req_cbaae94a1f5041078b510ebdf98dd7c9`
and Docker status request `req_5fb18a2002384628bbb8cd74942c4114` using
`sonic1-camera-key` both succeeded. Sonic1 again reported the three existing
ClamAV validation containers up on `clamav-32gb:test-tools-742a8a4`. A fresh
source-hash request `req_5f3430c0746b43cc92fedf44af9f53de` returned remote
`pdfdecode.c=a1a811fcc0d6d6a2373f8cb9e5065cb11a249bdc74d78dbee8fad6fa6078ff3f`,
`check_clamav.c=8912af667dcdf0d8766b1507790f4c7813d552aead93bfbaafa0761be593ed20`,
and `largefile_source_guards.sh=ae67ea5ac68a19efe1d7895b845e6d1073e91cf28eb3013f0d642486af670735`;
all differ from the current local hashes. This verifies Docker liveness, not
current-head remote qualification.

## Latest PDF empty-filter boundary follow-up — 2026-08-15

The PDF Flate and LZW decoders previously treated a recognized stream
containing only the tolerated leading carriage return as successfully handled.
That left the raw carriage return eligible for fallback scanning, so the
decoder failure could be reported as clean. Both filters now return
`CL_EFORMAT` for that empty compressed payload; the public stream path maps it
to `CL_EPARSE`, marks the layer incomplete, and disables clean caching. The
new `test_pdf_empty_flate_stream_is_fail_visible` regression passed with the
existing PDF trailer and decode-error cases: 3/3 checks in the disposable
ARM64 Clang ASan/UBSan PDF testcase, with no sanitizer diagnostics.

The complete current workflow, production-CVD, broader parser, and remote
current-source qualification gates remain open. Sonic1 remains liveness and
provenance evidence only because its `pdfdecode.c` and test sources differ from
this worktree. Focused evidence is preserved at
`/private/tmp/clamav-32gb-pdf-group-evidence`.

## Latest RAR extracted-member open follow-up — 2026-08-15

The RAR bridge previously normalized every `CL_EOPEN` returned while scanning
an extracted member to `CL_SUCCESS`, even when the extractor had left an
output file on disk. That could turn an existing but uninspectable member into
a false-clean archive result. The branch now treats only the no-output case as
optional; an existing output that cannot be opened marks the scan incomplete,
disables clean caching, and returns `CL_EPARSE`.

The current disposable ARM64 Clang build produced `check_clamav`. Its
available `cl_api` group ran 90 checks with 1 known missing-fixture failure,
0 errors, and no sanitizer diagnostics; the cached configuration has
`ENABLE_UNRAR=OFF`, so the RAR-specific runtime test is not present in this
local run. Source, fail-closed/runtime-evidence, and workflow-YAML controls
passed. Evidence is preserved at
`/private/tmp/clamav-32gb-rar-followup`.

Local hashes are
`scanners.c=e7675bcc8a25944dd62b4a47f5a9e895503def16e26c976395954d9ba028c539`,
`check_clamav.c=f722a699955d3e2cc3af036bb9b928320b58011883442d67529588801d8e2e8c`,
and
`largefile_source_guards.sh=18b2a6f1e2b53a0dca343bd39691b924b4e815a1bc586ab6c8d8f941ad3f67d7`.

Fresh Sonic1 verification used host-list request
`req_9b35faf347be4a3b879e0ec84aff03c6`, Docker status request
`req_a3d5a72125f34abfb3da4ad5a1996d2a`, and source-hash request
`req_b23839fe35a9484b92346e18c6cdeeb2` with `sonic1-camera-key`. All three
containers remain up on `clamav-32gb:test-tools-742a8a4`; remote
`scanners.c=50f08543b6af7b782ebcd7e69124f30d43a3d0d36fd6970e4bb87597ac541a96`,
`check_clamav.c=8912af667dcdf0d8766b1507790f4c7813d552aead93bfbaafa0761be593ed20`,
and `largefile_source_guards.sh=ae67ea5ac68a19efe1d7895b845e6d1073e91cf28eb3013f0d642486af670735`
differ from the local patch. No remote rebuild or qualification claim is made.

## Latest OLE2 VBA candidate-failure follow-up — 2026-08-15

The OLE2 VBA directory resolver retries ambiguous extracted `dir` candidates,
but previously reset every candidate parse failure to `CL_SUCCESS`; if all
found candidates were malformed, no VBA project was inspected and the outer
scan could remain clean. The resolver now remembers whether a candidate was
found and whether any candidate succeeded. When all found candidates fail, it
marks the scan incomplete and non-cacheable and returns the first failure;
missing candidates remain optional, and a successful candidate retains the
existing fallback behavior.

The current disposable ARM64 Clang build again produced `check_clamav`. The
available `cl_api` group ran 90 checks with 1 known missing-fixture failure,
0 errors, and no sanitizer diagnostics. Source, fail-closed/runtime-evidence,
and workflow-YAML controls passed. Evidence is preserved at
`/private/tmp/clamav-32gb-ole2-candidate-followup`.

Local hashes are
`scanners.c=4e47e835b73b933e742c4c3e3ec17ee36f31ee885d0150db51bfe325d9e69cab`,
`check_clamav.c=f722a699955d3e2cc3af036bb9b928320b58011883442d67529588801d8e2e8c`,
and
`largefile_source_guards.sh=e3ae41f3008eb37716f25a3c72663099a17cef6058576378d6aa37cf568ca246`.

Fresh Sonic1 verification used host-list request
`req_ae8375c0d2a84f778d4d9c6a15682664`, Docker status request
`req_3984a13ff393443e952bddd099deccba`, and source-hash request
`req_06806989926f474c970471c38007f52c` with `sonic1-camera-key`. All three
containers remain up on `clamav-32gb:test-tools-742a8a4`; remote scanner,
test, and guard hashes remain different from this worktree. No remote rebuild
or qualification claim is made.

## Latest TIFF structural-boundary follow-up — 2026-08-15

The TIFF parser previously routed truncated first-IFD offsets, directory
entries, next-IFD links, out-of-range value data, and out-of-order IFD links
only through optional heuristic reporting. It now marks those structural
failures incomplete and non-cacheable before preserving the existing
heuristic-reporting behavior. The new four-case
`test_tiff_truncated_structures_are_fail_visible` regression passed. The
disposable ARM64 Clang target rebuilt `check_clamav`; the aggregate recorded
1,315 checks, 782 known fixture/setup failures, and 0 Check errors. The
aggregate sanitizer log contains existing unrelated UBSan diagnostics in
`disasm.c` and `bytecode_vm.c`, so it is not a clean sanitizer-suite result.
Evidence is preserved at `/private/tmp/clamav-32gb-tiff-followup`.

Local hashes are
`tiff.c=ef8f191f2b08b2405082b12c0aef6d7431b85dd2a581d904b954745d8b220f19`,
`check_clamav.c=6714a74149e4f6d802c56e1edee9007cc424c62fb9c18faf18f2053cadb8ec9c`,
and
`largefile_source_guards.sh=25da3e0ca4f7e1589a06a576290ec68dc001cd27026b28d5d6cca8cb240f0b27`.

Fresh Sonic1 verification used host-list request
`req_9c60bf3c06f9431c830483f0666ee5dd`, Docker status request
`req_27315fa4e1804a2db095d8dff66a94a9`, and source-hash request
`req_2fa173b3f991425f89d321d005f39549` with `sonic1-camera-key`. All three
validation containers remain up on `clamav-32gb:test-tools-742a8a4`. Remote
TIFF, test, and guard hashes differ from the current worktree. No remote
rebuild or qualification claim is made.

The zero first-IFD offset case now uses the same sticky parser-error helper as
the other TIFF structural failures. This prevents optional heuristic
configuration from converting a confirmed invalid TIFF structure into a clean
result; the focused structural regression now includes that case.

## Latest PE icon structural-boundary follow-up — 2026-08-15

The PE icon matcher previously discarded every non-virus return from its
optional icon parser. A declared icon whose resource data, bitmap header,
palette, or pixel data was outside the input map could therefore leave the
outer scan apparently clean. Structural icon failures now mark the scan
incomplete and non-cacheable and return `CL_EPARSE`; a configured icon-count
limit likewise remains fail-visible as `CL_EMAXSIZE`. Valid icons outside the
matcher’s intentional dimension/shape range remain optional and unchanged.
The remaining PE icon materialization, scaling, and metrics-allocation
failures now also mark the containing scan incomplete and return the resource
error instead of allowing the parser to continue with a missing or
uninitialized image representation. The existing structural icon regression
and source guards remain registered; allocator fault-injection execution is
still a supported-Linux qualification item.

The new `test_pe_icon_truncated_resource_is_fail_visible` regression passed.
The disposable Debug build rebuilt `check_clamav`, and the focused
`CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api` run recorded 91 checks, 3 known
fixture/environment failures, and 0 Check errors. The three failures are the
existing invalid `test-5.cvd`, missing `CVD_CERTS_DIR`, and absent UPX fixture;
the PE icon regression passed. Source, fail-closed/runtime-evidence, and
workflow-YAML controls passed. Evidence was collected from the disposable
verifier at `/private/tmp/clamav-32gb-pe-icon-followup/check_clamav.test.log`
and `/private/tmp/clamav-32gb-pe-icon-followup/check_clamav.test-stderr.log`.

Local SHA-256 values are
`pe_icons.c=8b78b8772b531caaf3bc303a01c02efdfafb293f16d6df7c8c7ca08490d2402e`,
`check_clamav.c=0e99771893fc195e53a44ee6055439e002904c15d392eb0596e3a7790b952cdb`,
and
`largefile_source_guards.sh=65473c02f98891f62e1fa7835cbe74c206af2b28d0be72b9eb0ea8e0d3472157`.

Fresh Sonic1 host-list request `req_572cfff8cd374851a50a1035ddba70df` and
Docker status request `req_6aeb774e6c5e43678af69bc0a3f4a6b8`, using
`sonic1-camera-key`, succeeded. The three validation containers remain up on
`clamav-32gb:test-tools-742a8a4`. Remote hashes from request
`req_32b2cfaaca154689874a54f30747eaa4` differ from the local PE icon, test,
and guard hashes, so Docker liveness and provenance are verified without a
remote rebuild or current-source qualification claim.

## Latest RIFF/ANI heuristic structural-boundary follow-up — 2026-08-15

The enabled RIFF/ANI exploit heuristic previously returned a clean-compatible
result when a recognized RIFF/RIFX `ACON` payload ended before its next chunk
header or declared chunk data. It now marks truncated chunk headers, list
types, declared payloads, padding, and excessive nested-list depth incomplete
and non-cacheable, and propagates `CL_EPARSE` through the RIFF scanner. The new
`test_riff_truncated_chunk_is_fail_visible` regression passed while valid
non-exploit RIFF behavior remains unchanged.

The disposable ARM64 Debug static target rebuilt `check_clamav`. The focused
`CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api` run recorded 93 checks, 3 known
fixture/environment failures, and 0 Check errors; the known failures are the
invalid `test-5.cvd`, missing `CVD_CERTS_DIR`, and absent UPX fixture. The
static test build enabled the bundled UnRAR interface only to provide its
internal header; it does not close the separate `ENABLE_UNRAR=OFF` runtime
gate. Source, fail-closed/runtime-evidence, and workflow-YAML controls passed.
Evidence is preserved at
`/private/tmp/clamav-32gb-riiff-followup/check_clamav.test.log` and
`/private/tmp/clamav-32gb-riiff-followup/check_clamav.test-stderr.log`.

Local SHA-256 values are
`special.c=a962e94f4cf1cc09f94732fbd666a2a365225e134587fe21659c972bd2c94547`,
`scanners.c=77b947c95d343ff778dfee464e369780f97231c9d934de64558db1600af55339`,
`check_clamav.c=7dea4f0130e9d8a4e1386f7d02f65a8a80f34e6c31fd6ebb54b51f6c5e14a801`,
and
`largefile_source_guards.sh=b2572cb074406252443d2bb1f6cc1a27150f750e1919111e39b2fddbed54a358`.
Evidence log hashes are
`check_clamav.test.log=5412331211f36bad784e7c0362b20b9eb98e74769ca1161727c3583246f77d8a`
and
`check_clamav.test-stderr.log=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Fresh Sonic1 verification used host-list request
`req_1029d3e0c65c4074af98961b011d04cd`, Docker status request
`req_47b054397a254c6a850e85fb65e9d587`, and source-hash request
`req_8d06bd4b68194a68a5ca8c15f90ff5d3`, all with `sonic1-camera-key`.
The three validation containers remain up on
`clamav-32gb:test-tools-742a8a4`. Remote RIFF, scanner, test, and guard hashes
differ from the current worktree, so this verifies Docker liveness and
provenance only; no remote rebuild or current-source qualification is claimed.

## Latest JPEG broken-media structural-boundary follow-up — 2026-08-15

The enabled JPEG broken-media parser previously allowed a recognized JPEG that
ended during its header, marker, segment-size, or segment-data structure to
return without marking the scan incomplete. These structural paths now mark
the scan incomplete and non-cacheable and return `CL_EPARSE` to direct parser
callers; complete scan contexts retain the existing heuristic reporting path.
The new `test_jpeg_truncated_structures_are_fail_visible` regression covered a
truncated JPEG header and segment-size field and passed.

The disposable ARM64 Debug static target rebuilt `check_clamav`. The focused
`CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api` run recorded 94 checks, 3 known
fixture/environment failures, and 0 Check errors; the known failures are the
invalid `test-5.cvd`, missing `CVD_CERTS_DIR`, and absent UPX fixture. The
static configuration reused the bundled UnRAR interface only for internal
test headers; the separate `ENABLE_UNRAR=OFF` runtime gate remains open.
Source, fail-closed/runtime-evidence, and workflow-YAML controls passed.
Evidence is preserved at
`/private/tmp/clamav-32gb-jpeg-followup.test.log` and
`/private/tmp/clamav-32gb-jpeg-followup.test-stderr.log`.

Local SHA-256 values are
`jpeg.c=00032dc147c4e99db16bb79eb6e31c4ead018e8c3dc9bbec3916672d221ce26c`,
`check_clamav.c=a968a0c3635c8e8bc9d6ffd9631972554b0278d52fee4d9f87ff0bcfd55a2beb`,
and
`largefile_source_guards.sh=3841fae0964f43cca8fc39925329cc8668e6d1c55ed020331ac61e4b2e5ac3c2`.
Evidence log hashes are
`check_clamav.test.log=fe434a53f6e18a00aa99ecdc4a7575906495fe63398ccf57b399f15d1d9eec69`
and
`check_clamav.test-stderr.log=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Fresh Sonic1 verification used host-list request
`req_30d04aa0ec2043b8912aa0994ed74a2d`, Docker status request
`req_f3d86a5a7e324ad1a1d51017dde7da4a`, and source-hash request
`req_d700129808934fa091a2204363af3ab7`, all with `sonic1-camera-key`.
The three validation containers remain up on `clamav-32gb:test-tools-742a8a4`.
Remote JPEG, test, and guard hashes differ from this worktree, so Docker
liveness and provenance are verified without a remote rebuild or qualification
claim.

## Latest HTML normalization mapped-read boundary follow-up — 2026-08-15

HTML normalization previously treated a mapped-page read failure as ordinary
end-of-input. The normalizer could therefore report success after producing a
partial normalized view, and `cli_scanhtml` ignored that result. Mapped-read
failures now set an input read-error bit, mark the scan incomplete and
non-cacheable, and make the HTML scanner return `CL_EPARSE`. Normal end-of-map
EOF remains unchanged. The new
`test_htmlnorm_mapped_read_failure_is_fail_visible` regression passed.

The disposable ARM64 Debug static target rebuilt `check_clamav`. The focused
HTML-normalizer suite passed 7/7 checks. The focused
`CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api` run recorded 94 checks, 3 known
fixture/environment failures, and 0 Check errors; the known failures are the
invalid `test-5.cvd`, missing `CVD_CERTS_DIR`, and absent UPX fixture. Source,
fail-closed/runtime-evidence, and workflow-YAML controls passed. Evidence is
preserved at `/private/tmp/clamav-32gb-htmlnorm-followup.test.log`,
`/private/tmp/clamav-32gb-htmlnorm-followup.test-stderr.log`,
`/private/tmp/clamav-32gb-htmlnorm-clapi.test.log`, and
`/private/tmp/clamav-32gb-htmlnorm-clapi.test-stderr.log`.

Local SHA-256 values are
`htmlnorm.h=8a95937161423611c17aaf8300cdda3de35d1f153426ce0fdd8beedccbd8fe02`,
`htmlnorm.c=f52f2ab26464c1df98f29dfd4185da4db0c4c8433f9bef57067e4e824e528c61`,
`scanners.c=da08186669254e4cd7212626e442f169587acb062d8fddb2291220c0d2de5180`,
`check_htmlnorm.c=b8e27924d39f8fa26f05fe8ef2b8f3146d9f0ed8b437b08b2d764a149b1fd561`,
and
`largefile_source_guards.sh=6ef48ebb2cf2f736f74835c1c0a3113e05ca39816ea64178a658719b6cc2e2de`.
Evidence log hashes are
`htmlnorm-followup.test.log=eb330e5096f2a7fc2a9853134a3b51993ed6740ccb0e80f04661d8d12f55c5f1`,
`htmlnorm-followup.test-stderr.log=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
`htmlnorm-clapi.test.log=fe434a53f6e18a00aa99ecdc4a7575906495fe63398ccf57b399f15d1d9eec69`,
and
`htmlnorm-clapi.test-stderr.log=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Fresh Sonic1 verification used host-list request
`req_34f81c6f259b463c94181fe14982f019`, Docker status request
`req_6932f7de74cb41209c6ecba3b96cc62d`, and source-hash request
`req_999b98cb219041dc8055fa7513bc4184`, all with `sonic1-camera-key`. The
three validation containers remain up on `clamav-32gb:test-tools-742a8a4`.
Remote HTML-normalizer, scanner, test, and guard hashes differ from this
worktree, so Docker liveness and provenance are verified without a remote
rebuild or current-source qualification claim.

## Latest script text-normalization mapped-read boundary follow-up — 2026-08-15

The script normalizer previously returned the bytes normalized before a
mapped-page read failure. `cli_scanscript` treated that partial result as
normal termination and could scan a truncated normalized view. Text
normalization now carries a sticky mapped-read error, and both the relative-
offset and in-memory script paths mark the scan incomplete and non-cacheable
and return `CL_EPARSE` when required input cannot be read. The new
`test_text_normalize_map_read_failure_is_fail_visible` regression forces a
failure after one valid page and passed.

The disposable ARM64 Debug static target rebuilt `check_clamav`. The focused
`CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api` run recorded 95 checks, 3 known
fixture/environment failures, and 0 Check errors; the known failures are the
invalid `test-5.cvd`, missing `CVD_CERTS_DIR`, and absent UPX fixture. Source,
fail-closed/runtime-evidence, and workflow-YAML controls passed. Evidence is
preserved at `/private/tmp/clamav-32gb-textnorm-followup.test.log` and
`/private/tmp/clamav-32gb-textnorm-followup.test-stderr.log`.

Local SHA-256 values are
`textnorm.h=7c255840e4cbfb35fed8ab7024203afdb4e0efec11fc2045afbfd5d7e877f81a`,
`textnorm.c=da81716c695028e6c4047f5d1bdd243c3bef8b7f458d5eb4936d4b25e4ac4995`,
`scanners.c=e863d9363227f438d21a41d2e852ed2d0f3029fd3031f3699fb02c673c32ac21`,
`check_clamav.c=8db48e263c64df043ccb2e15f0a91bb8a25d00046b301e2df4b6efda5b14005d`,
and
`largefile_source_guards.sh=14db8f5a030c4ebb29ec45a360d8aaaf8066b582ecedadc4601434db53be2d5a`.
Evidence log hashes are
`textnorm-followup.test.log=cbecf50ca31de04110dfd49cf33ab21d0d63bfd5d8d7134d4142fe1dbd8c5fd2`
and
`textnorm-followup.test-stderr.log=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Fresh Sonic1 verification used host-list request
`req_6c512903cdad4d98adf4a68f3b9512cb`, Docker status request
`req_7290f17a8fec4dca9a8dacd1bb737a3e`, and source-hash request
`req_92bec118bde546adb13e1e340b52b57b`, all with `sonic1-camera-key`. The
three validation containers remain up on `clamav-32gb:test-tools-742a8a4`.
Remote text-normalization, scanner, test, and guard hashes differ from this
worktree, so Docker liveness and provenance are verified without a remote
rebuild or current-source qualification claim.

## Latest bytecode mapped-read fail-closed follow-up — 2026-08-15

The bytecode input APIs now distinguish normal EOF from an actual contained
fmap read failure. `cli_bcapi_read`, disassembly, bounded bytecode search,
byte lookup, and strict number parsing mark the scan incomplete and
non-cacheable when bytes that are present in the input map cannot be read;
ordinary EOF and short final ranges remain non-incomplete. The regression
`test_bytecode_map_read_failure_is_fail_visible` exercises both the EOF path
and a failing second page, including the `read_number` path.

The disposable verifier rebuilt `check_clamav` without compiler warnings. The
focused `CK_RUN_SUITE=bytecode CK_RUN_CASE=map_read` run recorded 1 check, 0
failures, 0 errors, and an empty stderr log. Source, fail-closed/runtime-
evidence, and workflow-YAML controls passed. Evidence is preserved at
`/private/tmp/clamav-32gb-riiff-build/clamav-32gb-bytecode-followup.test.log`
and its corresponding `-stderr.log`.

The existing `bytecode` arithmetic case also ran 48 checks with 5 known
missing-fixture failures and 0 errors; the failures were the absent
`clam.exe` and invalid/missing `bytecode.cvd` fixtures. Its evidence is at
`/private/tmp/clamav-32gb-riiff-build/clamav-32gb-bytecode-suite-followup.test.log`
with SHA-256
`93dda6273533d7ade59a4d9b331b29992357a10c4663d09db4feaccb55dc1731`.

Local SHA-256 values are
`bytecode_api.c=a6e46a7a13bfbbf518cc3b22045e065defeb4c39205aadbf6f93486fca5d5886`,
`check_bytecode.c=09ef622daa918d660b2a26ebc923f10dac4730e59dd26f74876e1651b926cc05`,
and
`largefile_source_guards.sh=f36a0bfdf8c3893fc9c9108942fd55e35f179e9408d6030003e3df46d4b635a`.
Evidence-log hashes are
`bytecode-followup.test.log=bc324e8cc63bacb611ccc0beb08c49b65096b989434be965e83606737fd6582e`
and
`bytecode-followup.test-stderr.log=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Fresh MCP-SSH verification used host-list request
`req_fa90aaa8ac7347589d67bbfb894ecc9`, Docker status request
`req_233203b5d3ae41388afc121c11a05257`, and source-hash request
`req_0ad85b1d50fb4cbca6d05b7f1b998bfe`, all with `sonic1-camera-key`. The
three validation containers remain up for two days on
`clamav-32gb:test-tools-742a8a4`. Remote bytecode and guard hashes differ
from this worktree, so Docker liveness and provenance are verified without a
remote rebuild or current-source qualification claim.

## ENABLE_UNRAR=OFF static/runtime qualification follow-up — 2026-08-15

A fresh ARM64 Debug static-only configure with `ENABLE_UNRAR=OFF`,
`ENABLE_STATIC_LIB=ON`, `ENABLE_SHARED_LIB=OFF`, `ENABLE_MILTER=OFF`, and
`ENABLE_CLAMONACC=OFF` exposed a CMake include-propagation defect: the static
`clamav_static` target did not propagate the header-only
`ClamAV::libunrar_iface_iface` target when the actual UnRAR library was
disabled, even though `unrar_iface.h` remains included by the static build.
The fix keeps that interface target linked unconditionally and links the
actual UnRAR static library only when `ENABLE_UNRAR` is enabled. The source
guard now protects this CMake condition as well.

The isolated OFF build completed through `check_clamav` and rebuilt
`clamscan`; the latter reported `ClamAV 1.5.3-largefile-devel`. The focused
`bytecode/map_read` case recorded 1 check, 0 failures, and 0 errors. The
focused `cl_api` group recorded 94 checks, 3 known fixture/configuration
failures, and 0 errors: invalid `test-5.cvd`, missing `CVD_CERTS_DIR`, and an
absent `clam-upx.exe` fixture. The build output included two unrelated
`mbr.c` enum-conversion warnings but no build failure.

Evidence is preserved under `/private/tmp/clamav-32gb-unrar-off-build`:
`configure.log=7fdfcf2b166424a71808555a583691b2bbdb47298df43b499a888031387e59de`,
`build.log=93274bc02e9c57c6c81a012957fe2d5755d69c785aae6ee58e516d69000e0f32`,
`bytecode-map-read.test.log=bc324e8cc63bacb611ccc0beb08c49b65096b989434be965e83606737fd6582e`,
and `cl-api.test.log=c1af36168434976e2285c2f16ef67cf97bdeee4461de6439a2afc4b03e4f8729`.
The two stderr logs are empty. Local source hashes are
`libclamav/CMakeLists.txt=96af31d137e51c097c91edee031e5b9c3a507e034a41481d2d846901778f55a4`
and
`tools/largefile_source_guards.sh=9b94eb516e76e604fe0d37a59fca90aabf71582188b8572f738750944c3e5c72`.
The source guards, PoC fail-closed regression, runtime-evidence verifier, and
workflow YAML parse all passed after the fix.

The latest Sonic1 refresh used host-list request
`req_43b0c96280ba417687edac23d02c4fb2` and Docker status request
`req_fab5c844ca4d478bb7c427d44861caa6` with `sonic1-camera-key`. The same
three validation containers remain up for two days on
`clamav-32gb:test-tools-742a8a4`. A current source-provenance probe
(`req_213e81e680444f1cbef0b582ec4a2f21`) found no `/workspace/ClamAV` on the
remote, so this refresh verifies Docker liveness only; it does not claim a
current-source remote rebuild. Production CVD/corpus, clean sanitizer and
multiworker evidence, full release/CI, attestation, and current-source remote
qualification remain open.

## Sonic1 runtime-gate and control refresh — 2026-08-15

The remote source is mounted inside the validation container at
`/workspace/ClamAV`; the earlier direct host-level probe of that path was not a
valid source check. The current container inspection used host-list request
`req_24ba5fb6716b4c70afa45bddb205ba6c`, container/image inspection request
`req_48f2f9445bfe4900873740a648e1bbb4`/`req_c86c7a506b16475ba8f3aad1cd8a5328`,
and source-hash request `req_8d515360de244407b7514efd2316e05d`, all with
`sonic1-camera-key`. The three containers are running on image digest
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`;
the primary source bind is read-only and the remote checkout is clean at
commit `5becea1236d466ee21f9bd5d3bcd0595ebc1460b`.

The registered large-file/release-control CTest subset passed 4/4 in the
release build (request `req_86a7789110c04e67bc51307f31ef70ee`) and 4/4 in the
populated ASan/UBSan build (request `req_c6a0f8efee2b41cc8cdb3acfdc67109d`).
The release runtime evidence at `/work/evidence/runtime-5becea1-prod`
records `host_preflight=pass`, `largefile_poc=pass`, cancellation pass,
`policy_32g_plus_one=pass`, and 1/2/4-worker concurrency pass. Its build
identity is preserved by request `req_bc5e52ea542b495eaadb673555d4758f`.
The sanitizer runtime evidence at
`/work/evidence/runtime-sanitizer-5becea1-prod` records the same gates plus
`sanitizer=pass`, with build identity captured by request
`req_fe901fb0eb6f46b6be64841ac1022736`; both evidence manifests were hashed in
request `req_7496c6592ce8409fbcb8998f4c247829`.

This closes the remote baseline runtime/control evidence gap for commit
`5becea1`, but not current-source qualification: remote hashes for the CMake,
bytecode, test, and guard files differ from this worktree. A current-worktree
source synchronization and rebuild, broader current-head parser coverage, and
full release/CI and attestation gates remain open.

## Current-source Sonic1 transfer and runtime qualification — 2026-08-16

Using the upgraded MCP-SSH server over a fresh MCP protocol session, the
explicitly authorized source archive was durably uploaded to `sonic1` with
`sonic1-camera-key`. Transfer `transfer_812ddf56b65743cd80fa772956ff8a64`
committed by atomic rename to
`/home/camera/clamav-32gb-current-src-20260815.tar.gz`. The declared and
independently verified size is `8,751,040` bytes and the SHA-256 is
`7c8a29318df214d307083ab6509da431e97d208b67523e758060e1bf781b06fe`.
The temporary MCP-SSH runtime config raised only the SFTP write ceiling to
32 MiB so the 8.75 MiB declared upload could complete; no ClamAV source or
remote Docker policy was changed.

The archive was extracted at
`/work/ClamAV-current-20260816` in container
`clamav-32gb-final-f08c7b0` (container ID
`cc5164b5cb60be6df04b2b2630012446d8ebedfe47f2e5b0fe06296718fa5795`, image
ID `sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`).
The archive omitted repository ancillary paths, so README/docs/unit-test
inputs were restored from the container's existing read-only checkout. The
`.github` tree was also restored only from that baseline; its workflow file is
not the current local workflow, and the source-guard suite consequently stops
on the missing `CLAMAV_MAX_SCAN_TIME_MS` workflow control. This is recorded as
an archive-completeness limitation, not as a current-code guard pass.

The transferred code itself matches the local worktree exactly for
`libclamav/CMakeLists.txt` (`96af31d1...f55a4`), `libclamav/bytecode_api.c`
(`a6e46a7a...d5886`), `unit_tests/check_bytecode.c`
(`09ef622d...cc05`), and `tools/largefile_source_guards.sh`
(`9b94eb51...5c72`). A shared-plus-static build configured successfully, but
its `check_clamav` target linked against the shared-library alias and failed
on private parser symbols. A separate static-only configure/build
(`ENABLE_STATIC_LIB=ON`, `ENABLE_SHARED_LIB=OFF`) completed successfully;
`clamscan --version` reported `ClamAV 1.5.3-largefile-devel`.

Current-source remote tests passed:

- CTest release controls: 3/3 (`largefile_poc_fail_closed`,
  `largefile_runtime_evidence_check`, `clamav_milter_quota`).
- Bytecode mapped-read fail-closed regression: 1 check, 0 failures, 0 errors.
- Sparse boundary POC: all 11 cases passed from 2 GiB through 32 GiB,
  including exact 4 GiB boundaries, the 32 GiB head marker at engine offset
  `4096`, and the final 32 GiB marker at engine offset `34359738304`.
  Every row reported `size_matches=yes`, `scan_status=1`, detection, exact
  marker placement, and `offset_matches=yes`.

The final POC evidence is retained remotely under
`/work/evidence/current-source-20260816`; `results.tsv` hashes to
`13343e1f867e4dc78f3b169a9da18fb22795892597b8fe2eb558157d8c316ad1`, the
signature database to
`3e2a61bd40811db8da58c08f9903908528d23828b84e220567dfda0212f2083f`, and
the corpus manifest to
`2e0897e26f19380b3fddc7bd4af704d770904c94d08bbb43e622f83cc598b90a`.
The first POC attempt failed before scanning because the default CVD cert path
was absent; rerunning with the existing remote cert tree at
`/work/ClamAV-current-20260816/certs` passed. Full sanitizer, multi-worker,
production-CVD/deep-parser, complete repository-metadata, and release/CI
attestation gates remain open.

## Current-source qualification follow-up — 2026-08-16

The upgraded MCP-SSH server was used with host `sonic1` and login profile
`sonic1-camera-key` for the remaining current-source checks. The first combined
runtime-gate attempt stopped at host preflight because the validation
container's finite cgroup was full of file cache from the earlier 32 GiB scans;
the host itself still had approximately 61 GiB available. A non-destructive
host page-cache reclaim was requested through MCP-SSH, after which the strict
48 GiB effective-memory preflight passed. No files or processes were removed.

The rerun was MCP-SSH async job
`job_add3b5da368a45d5a6601b8f8646b5fb` and ended with exit 0. Its evidence is
preserved at
`/work/evidence/current-source-runtime-gate-20260816-run3`. The independent
`largefile_runtime_evidence_check.sh` returned exit 0 and
`large-file runtime evidence verified`. The evidence records
`host_preflight=pass`, `largefile_poc=pass`, `temp_budget=pass`, cancellation
pass, `policy_32g_plus_one=pass`, and `runtime_gate=pass`.

This closes current-source sanitizer and multi-worker qualification for the
scanner code represented by synthetic validation commit
`34fc460b4e977bb9090e73b42977394de92d8219`. The release concurrency checks
passed at levels 1, 2, and 4 with aggregate peak RSS values of 100,260,
200,608, and 402,052 KiB, respectively, against the 33,554,432 KiB budget.
The same gate's ASan/UBSan POC recorded `sanitizer=pass` with strict
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`; no sanitizer diagnostics
were present. The final runtime checksum manifest was independently verified.

Current-source deep-parser coverage was then run over all 46 files in
`unit_tests/input/other_scanfiles` with both Release and ASan/UBSan scanners.
The text-signature matrix produced matching Release/sanitizer statuses and
log hashes (`ef9abc5d273236029e170f57312180b5a026a723538b420206c1b1d1fdcf634f`),
22 detections in each, and two expected fail-visible parser statuses. A second
matrix loaded 13 repository test-database files—six `test-*.cvd` files,
`bytecode.cvd`, and six checked-in signature files—and again produced matching
Release/sanitizer statuses and log hashes
(`ee23e20c5b14d7b5a0482ef96511ca33ab085e4f89b468ea8e561539659230b1`), 22
detections in each, and no ASan/UBSan diagnostics. Its two bytecode runtime
warnings are expected behavior from the test `bytecode.cvd`; this is
test-CVD/deep-parser evidence, not production-CVD qualification. Checksums are
preserved in `/work/evidence/current-source-cvd-deep-parser-20260816/SHA256SUMS`
and verify successfully.

Repository metadata is now complete in the remote staging tree. A supplemental
metadata archive was transferred as
`transfer_3bffed85dcfc4ccb9da00f1c3b7016b0` (SHA-256
`10a51eb693404180e6891dfad2cb2308d8823111996dbc9eb52b5366581405e0`), and a
follow-up archive transferred as
`transfer_6cc4a1491652415a837609d753a2c8ec` (SHA-256
`dfc8ec285302fdd47f2e9901288fda70bf63c3760665571a31c2393571f3dd32`) restored
the two initially omitted files: `.devcontainer/README.md` and
`libclammspack/README`. The remote metadata tree was clean at synthetic
validation snapshot `93c69c28b139182ceead0cae1b9271e2531a0a81`; a later
audit-only correction commit contains the final wording. The preceding
code/metadata snapshot was `431a310d81010f3323c97c7483d541f8a5c04048`. It contains 1,470 source files,
has zero `._*` AppleDouble sidecars, and its sorted path-inventory hash
`faab3a89578bff25e70694bc59ed9c4721cb6a971e432dcbc1a498ac54f35ca5` matches
the local worktree. Selected workflow, README, security, audit, status,
source-guard, and runtime-gate SHA-256 values also match locally and remotely.
All five `.github` YAML files parsed successfully in the local YAML parser;
their exact hashes match the remote tree (the remote validation image has no
YAML parser installed, and no dependency was installed).

Production-CVD/deep-parser qualification is now closed for this current-source
validation snapshot. Because `database.clamav.net` returned HTTP 403 from
Cloudflare from both local and remote requests, the signed CVDs were obtained
from the accessible `packages.microsoft.com/clamav/` mirror and treated as a
dated mirror snapshot, not as a claim about the official endpoint's transport.
The files were `main.cvd` (89,072,577 bytes, SHA-256
`0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365`, Build
16 Dec 2025, version 63, 3,287,027 signatures), `daily.cvd` (23,426,423
bytes, SHA-256 `f0765cf6edee76be8e7cf7e0bf3b8c6eca20609204aa560da2b3beda9f368a5a`,
Build 16 Aug 2026, version 28094, 355,605 signatures), and `bytecode.cvd`
(281,702 bytes, SHA-256
`6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb`, Build
11 Sep 2025, version 339, 80 signatures). The current-source `sigtool --info`
reported `Verification OK.` for all three with the remote certificate tree;
each was F-level 90.

The production-CVD matrix loaded only those three CVDs and scanned all 46
files in `unit_tests/input/other_scanfiles` with both Release and strict
ASan/UBSan scanners. It completed all 46 rows despite the MCP-SSH wrapper
returning its 15-minute timeout after the final row; the evidence itself has
46 result rows. Release and sanitizer statuses matched exactly: 43 rows were
`0/0`, and the three expected fail-visible parser cases were `2/2`
(`pdf/out-of-order.pdf`, `pdf/uri-and-ref.pdf`, and `zip/logos.z01`). The
non-clean logs explicitly report invalid PDF xrefs or truncated/out-of-map ZIP
member data. There were zero sanitizer diagnostics, zero `FOUND` detections
from this production-only database, and the concatenated Release and sanitizer
log hashes were both
`c2fc40fe6063ab2b0102f90340d97855a6045daa5eae1f550326b89cbfff0e5b`.
The complete evidence and verified checksum manifest are preserved at
`/work/evidence/current-source-production-cvd-deep-parser-20260816`, with
`SHA256SUMS` hash
`b3550f7e98d4c5f3fe60b32f72731613e9dacb031745cdf8865b6b660813dd48`.

## Auditor-remediation disposition — revision R2 — 2026-08-16

This section is the current status for the source tree after reviewing the
independent findings in `audit1.md`. It supersedes earlier source-closure and
production-qualification labels above; those entries remain historical
records of earlier snapshots and must not be read as qualification of this
revision.

| Auditor finding | Current disposition | Evidence or remaining gate |
|---|---|---|
| F-01 HTML bypass/failure | Source remediated | Oversized normalization is sticky `CL_EPARSE`; normalizer read and normalized-output write failures are sticky and non-clean. The default-cap compiled regression is now registered; Linux execution remains required. |
| F-02 metadata hash failure | Source remediated | Hash failure now marks incomplete and returns the underlying read error (or `CL_EREAD`). The injected public metadata-hash regression is now registered; Linux execution remains required. |
| F-03/F-04 PDF and HWP partial decode | Source remediated | Flate/LZW require decoder terminal state; HWP raw-deflate refuses partial callback scanning. A truncated-prefix LZW regression is now registered alongside the Flate/HWP tests; Linux execution remains required. |
| F-05 ZIP variable-header truncation | Source remediated | Filename, extra-field, ZIP64, descriptor, and member-range failures are sticky; exact-end empty fields remain valid. Output-write and close fault-injection regressions are also registered alongside the compiled ZIP regression; Linux execution remains required. |
| F-06 XZ/CAB/CHM/PE failure propagation | Source remediated | Decoder/open/read failures now mark incomplete; XZ output accounting is 64-bit and overflow/write failures are visible. The XZ and CAB/CHM constructor regressions are registered; Linux execution remains required. |
| F-07 whole-input Rust parsers | Bounded staged support; qualification open | LHA uses bounded `Read + Seek`; ALZ now parses through the same adapter and streams member output into quota-accounted spools; OneNote probes the root through the bounded reader and streams legacy attachment ranges directly into quota-accounted spools, while the modern third-party parser still uses a disk-backed mapping because its API is slice-based. The artificial 256 MiB admission cap is removed. OneNote corpus, sanitizer, and real clamd RSS tests remain open. |
| F-08 public fmap hash API | Source remediated | `cl_fmap_set_hash()` takes a digest pointer and a public API regression now checks a full SHA-256 digest. The test is registered and must pass in a compiled build. |
| F-09 Mach-O shift/divisor | Source remediated | 64-bit alignment exponents ≥32 are rejected before shifting. The compiled malformed-section regression is registered; Linux execution remains required. |
| F-10 parser-local width/state | Source remediated in reviewed paths | Script offsets, JPEG coordinates, and XZ output totals use bounded native/64-bit state; JPEG segment bounds and scan-time checks are explicit. Image-fuzzy detector allocation, mapping, calculation, and matcher-side failures now preserve the sticky incomplete result instead of being discarded. Broader parser-width review remains open. |
| F-11 RAR staging copy | Source remediated | `fmap_dump_to_file()` rejects a nonzero unread remainder and removes the partial tempfile. Fault-injected RAR staging coverage is registered; Linux execution remains required. |
| F-12 protocol/API limits | Parser boundary remediated; protocol scale open | `StreamMaxLength` and public scan-size/time overflow/negative paths are bounded, and both clamd config-file and CLI `SIZE64` parsing paths now reject negative values before later engine setup. Full socket-level clamd INSTREAM/FILDES tests at 4 GiB and 32 GiB, plus the remaining setter matrix, remain open. |
| F-13 runtime provenance | Gate remediated structurally | The gate now binds the CMake source root and configure-time commit/tree, preserves complete Git tree/index metadata plus the copied launcher/build graph/loaded dependency artifacts and hashes, records sanitizer symbols and the Rust suite result, and enforces the canonical matrix. A real Linux rebuild must produce the evidence. |
| F-14 acceptance workflow | Partially remediated | Canonical `1 2 4` workers, mandatory temp budget, explicit production/deep-parser fixture inputs, combined release/sanitizer decision, and post-attestation verified artifact ordering are enforced. Mandatory clamd/clamdscan/milter, materialized/cold-cache, production-CVD, parser-expansion, latency, and RSS jobs remain open. |
| F-15 contradictory qualification claims | Documentation remediated for this revision | This table supersedes the historical append-only labels. Prior test-CVD and production-CVD results are snapshot evidence, not qualification of R2. |
| F-16 OneNote dispatch | Source remediated | Dispatch now checks `DCONF_DOC & DOC_CONF_ONENOTE`. The compiled configuration regression is registered; Linux execution remains required. |

Local static controls currently pass: both runtime-gate scripts parse with
`sh -n`, the workflow parses as YAML, `largefile_source_guards.sh` passes, and
`largefile_runtime_evidence_check_test.sh` passes. A full C/Rust compile was
not claimed here: this macOS workspace lacks the Linux build dependencies and
the Rust dependency checkout is unavailable offline. No new Sonic1 rebuild or
service-level qualification was performed for revision R2. The production
release verdict therefore remains blocked.

The RFC2047 mail-header decoder now propagates `messageAddStr()` and
`messageToBlob()` materialization failures to the sticky incomplete scan state
and discards partial decoded output. The previous ignored append failure could
otherwise leave a required decoded-header view incomplete while allowing the
mail parser to continue without a fail-visible report. The focused source
guard and materialization-limit unit regression are registered; compiled
execution remains a Linux/Sonic1 qualification gate.

The shared fileblob destruction helper now preserves non-detection errors from
the authoritative descriptor scan and marks the owning context incomplete for
unclassified failures. Previously its default branch returned `CL_CLEAN` for
resource, I/O, and parser errors, allowing callers that only checked for
`CL_VIRUS` to continue as if the required attachment scan had completed. A
focused incomplete-fileblob regression and source guard are registered;
compiled execution remains a Linux/Sonic1 qualification gate.

Nested MIME handling now marks unsupported transfer encodings, disabled or
failed partial-message handling, external-body references, unsupported
`message/*` formats, and failed encapsulated-header parsing incomplete. This
closes the mailbox-loop case where an internal `FAIL` was discarded while the
overall mailbox return remained clean. The intentionally supported
disposition-notification branch is unchanged; compiled mail-corpus execution
remains a Linux/Sonic1 qualification gate.

Mail-generated fileblob callers now use a single wrapper that rejects missing
temporary spools, preserves non-clean scan errors, and maps them to the MIME
`FAIL` state where the caller has an `mbox_status`. This includes text parts,
bounces, BinHex, nested attachments, and the direct `textToFileblob()` path.

Deferred multipart text aggregation now also preserves the final spool scan
result; it was previously destroyed without an authoritative scan. A focused
source guard is registered; compiled execution remains a Linux/Sonic1
qualification gate.

The shared mail spool wrapper now restores `mctx->ctx` after the legacy
`textToFileblob()` conversion clears it, ensuring every parser-generated mail
spool reaches the authoritative descriptor scanner with resource accounting
and fail-visible result policy enabled.

Embedded ZIP SFX, CAB SFX, and ARJ SFX admission now preserves non-format
header-check failures as incomplete results. Only `CL_EFORMAT` remains a
disproven weak candidate; `CL_EPARSE`, resource, and I/O failures mark the
parent and are retained as non-clean status. This closes the remaining
candidate-state gap in `scanraw()`; supported-build embedded-corpus execution
remains open.

Embedded PE dispatch now preserves `MaxEmbeddedPE` exhaustion and the
32-bit-containing-offset ABI boundary as `CL_ERESOURCE`-class incomplete
results, in addition to setting the sticky marker. This prevents recognized
PE content from being silently skipped by `scanraw()`.

The embedded PE header check now distinguishes generic `CL_ERROR` candidate
rejection from all other header failures. Truncated, timed-out, resource, and
read/parse failures set the sticky incomplete state and preserve their status;
only the disproven generic candidate remains non-tainting.

The clean-cache lookup and insertion paths now reject incomplete or timed-out
contexts in addition to the scanner-level admission guard. This prevents a
cached child from bypassing sticky incomplete-state reconciliation during
nested unwinding and prevents any incomplete layer from being recorded as
clean. The focused cache regression is registered; compiled Linux/Sonic1
execution remains a release gate.

The final `cli_magic_scan()` raw pass no longer honors the legacy HTML raw-skip
configuration bit. An enabled HTML parser that reaches `MaxHTMLNormalize` or
another incomplete state now still receives the required outer raw signature
pass, while the sticky incomplete result remains fail-visible if no detection
occurs. A compiled NDB-marker regression is registered; Linux/Sonic1
execution remains a release gate.

The PDF stream decoder boundary is now explicit: `pdf_extract_obj()` passes its
native `size_t` stream length to `pdf_decodestream()`, and the decoder rejects
lengths above its legacy 32-bit filter-input ABI with `CL_ERESOURCE` before any
narrowing or prefix scan. The containing layer is marked incomplete and
non-cacheable, with a focused boundary regression. This is a fail-closed
unsupported boundary, not a claim that every PDF filter is already a fully
streaming 32 GiB implementation.

PDF object-stream cursors and parsed object starts are now native-width as
well. The previous 32-bit object-start field and object-stream pair assignment
could wrap coordinates above 4 GiB before containment or extraction; the
focused unit regression now preserves a native-width object coordinate.
Object-stream containment now uses subtraction-based checked bounds for both
the current and next offsets, avoiding a wrapped base-plus-offset comparison
before malformed content is rejected.

The PDF bytecode-hook bridge now retains native-width size and start
coordinates and exposes format-8 pdf_getobjsize64 and pdf_get_offset64
accessors. Existing v1 APIs are preserved and return their invalid sentinel
when a coordinate cannot be represented; independent format-8 compiler output
and interpreter/JIT qualification remain open.

Ordinary and multipart mail bodies now switch to quota-accounted disk-backed
`fileblob` spools at the header/body separator in both direct-message and UNIX
mbox ingress. Ordinary bodies are scanned from the completed spool; multipart
boundaries are consumed one child at a time; base64 and quoted-printable bodies
are decoded line by line. Spool creation/write/decode/boundary failures remain
incomplete and non-clean. Phishing URL inspection is explicitly incomplete for
streamed text when enabled, and unsupported nested encodings remain fail-closed.
The large-body integration tests now verify that both ingress forms scan past
the former 64 MiB materialization boundary; compiled Linux/Sonic1 execution
remains a release gate.

## Latest OLE10 embedded-object boundary follow-up — 2026-08-19

The RTF/OLE10 bridge previously treated truncated headers, out-of-range
payload sizes, short reads, and partial temporary output as clean or as a
scannable child. It now validates the declared object range, requires exact
payload copying and output rewind, and preserves nested-scan and cleanup
failures as incomplete/non-cacheable results. The focused
`test_ole10_truncated_object_is_fail_visible` regression and source guards are
registered. This is a local source change only: supported-Linux execution,
sanitizer coverage, Sonic1 rebuild, and broader OLE/RTF corpus qualification
remain open.

## Clamd size-option parser boundary — 2026-08-19

The shared `SIZE64` option parser now rejects negative values before suffix
scaling or overflow fallback in both the configuration-file and CLI parsing
paths. This closes the `MaxScanSize`/related-setting case where `-1` could
survive generic parsing and be deferred to a later engine setter. The focused
clamd parser regression covers `MaxScanSize`, `MaxFileSize`, `StreamMaxLength`,
`OnAccessMaxFileSize`, `MaxHTMLNormalize`, and `PCREMaxFileSize`; compiled
Linux/Sonic1 protocol-scale tests at 4 GiB and 32 GiB remain open.

## Structured clamd report framing — 2026-08-19

The structured report transport now retries `EINTR`-interrupted socket reads,
which is required for a report to remain readable when a long-running large
file scan overlaps an ordinary process signal. A focused socketpair regression
covers fragmented header/payload delivery, the zero-length terminator, and the
16 MiB frame ceiling. This is protocol-boundary evidence only; compiled Linux,
Sonic1, sanitizer, and 4 GiB/32 GiB service integration remain release gates.

## OLE2 temporary-stream cleanup — 2026-08-19

OLE2 extracted-stream handlers now mark failed output close, zlib finalization,
and temporary removal operations incomplete instead of allowing a nominal
success to continue. Cleanup failures after a detection preserve `CL_VIRUS`,
but clean/`CL_BREAK` outcomes become non-clean and non-cacheable. The existing
Linux static-library close wrapper now has a focused OLE2 regression; compiled
execution, sanitizer coverage, and broader OLE2/Office corpus qualification
remain open.

## BinHex temporary-stream cleanup — 2026-08-19

BinHex data/resource temporary descriptor closes and temporary-file removals
now propagate into the sticky incomplete state. A focused Linux close-wrapper
regression confirms that cleanup failures add failure evidence beyond a
pre-existing truncated-input error; compiled execution, sanitizer coverage,
and broader legacy-mail corpus qualification remain open.

## SWF temporary-stream cleanup — 2026-08-19

The CWS and ZWS temporary-output paths now centralize descriptor close and
temporary removal handling across decoder errors, limits, output-length
mismatches, nested scans, and normal completion. Cleanup failures mark the
layer incomplete and cannot be normalized to clean. A Linux static-library
close-wrapper CWS regression is registered; compiled execution, sanitizer
coverage, and broader SWF corpus qualification remain open.

## VBA project temporary cleanup — 2026-08-19

The OLE2 VBA-directory scanner now checks close and removal of staged
`vba_project` output during candidate retries, successful nested scans, and
final unwind. Cleanup failures mark the containing scan incomplete without
overwriting a prior detection or parser error. Supported-Linux execution,
sanitizer coverage, and a real Office/VBA corpus remain open.

## FILDES preflight and structured-report completion — 2026-08-19

The clamdscan FILDES and FILDESREPORT ingress paths now preflight known regular
file descriptors against the configured `MaxFileSize` before sending ancillary
data. A zero setting is treated as the fork's bounded 32-GiB ceiling, and
stat/non-regular/over-limit inputs are refused before a request is emitted;
the daemon remains the authoritative second check for files that change after
preflight. The common INSTREAM client now propagates a failed final
zero-length terminator write. The non-IDSESSION structured-report consumer
also rejects an empty terminator-only response, closing a false-success path
where no scan report had been received. The focused FILDES unit regression is
registered, but compiled Linux execution, Sonic1 service qualification,
sanitizer coverage, and 4-GiB/32-GiB socket integration remain open.

## IDSESSION structured-report terminator — 2026-08-19

The clamdscan IDSESSION structured-report path now consumes the zero-length
terminator belonging to each report object before the next request is read.
Without this, the next `dspreport()` invocation could consume the previous
request's terminator and classify a valid multi-request session as a transport
failure. The focused socketpair regression exercises a fragmented report
header/payload followed by the terminator and reads both frames in order.
Compiled Linux execution, Sonic1 service qualification, sanitizer coverage,
and 4-GiB/32-GiB multi-request integration remain open.

## Service protocol qualification coverage — 2026-08-19

The service qualification harness now runs the production oracle through
clamdscan FILDES (`--fdpass`) and length-framed INSTREAM (`--stream`) paths,
and repeats both protocols for the exact boundary fixture after switching to
the edge signature database. These cases validate the same structured report
completion, type, signature, and status oracle as the path scan. The harness
change closes a coverage omission in the acceptance workflow; no actual
supported-Linux/Sonic1 run, sanitizer result, or 4-GiB/32-GiB service
qualification is claimed by this source change.

## Structured-data detector read failure — 2026-08-20

The structured credit-card/SSN detector previously treated a backing-map
`fmap_readn()` error like end-of-file and returned `CL_SUCCESS`. It now marks
the scan incomplete, disables result caching, and returns `CL_EREAD`; exact
end-of-map EOF remains a normal completed scan. The focused fault-injection
regression and source guard are registered. Compiled Linux/Sonic1 execution,
sanitizer coverage, and production structured-data corpus qualification remain
open.

## TNEF initial header read failure — 2026-08-20

TNEF now marks a failed signature or attribute-level read incomplete before
returning a non-clean result, so direct parser callers cannot mistake an
operational read failure for a completed container. A focused fault-injection
regression and source guard are registered. Compiled Linux/Sonic1 execution,
sanitizer coverage, and broader TNEF corpus qualification remain open.

The follow-up also separates exact end-of-map from an in-range attribute-level
fmap failure. The former remains the valid end of the attribute list; the
latter is now classified as `CL_EREAD`, while genuinely short headers remain
`CL_EPARSE`; both mark the layer incomplete and disable clean-result caching.

## TNEF attribute-header read status — 2026-08-21

TNEF attribute-header parsing now preserves the distinction between an
in-range fmap callback failure and genuinely short input. The former returns
`CL_EREAD`, marks the scan incomplete, and disables clean-result caching; the
latter remains `CL_EPARSE`. Exact end-of-map and the accepted trailing-newline
case remain normal attribute-list termination. The focused fault-injection
regression now expects `CL_EREAD`, while the existing short-header regression
continues to require `CL_EPARSE`; compiled Linux/Sonic1, sanitizer, and
production TNEF corpus qualification remain open.

The JPEG Photoshop APP13 helper had the same shape: an incomplete `8BIM`
resource header or data range returned `CL_BREAK`, and the caller normalized
that status to clean. It now reserves `CL_BREAK` for an exact end-of-map and
returns an incomplete parse result for truncated names, sizes, data ranges, or
fmap reads. A focused regression covers a truncated Photoshop resource.

TIFF's initial magic probe also now distinguishes a map that is too short to
be a confirmed TIFF from an in-range fmap read failure. The former remains a
normal non-TIFF result; the latter marks the layer incomplete and returns
`CL_EPARSE`. A focused fault-injection regression is registered.

GIF now applies the same distinction to its three-byte signature and version
reads: short non-candidates remain clean, while an in-range mapping failure or
a confirmed `GIF` prefix without a complete version marks the layer incomplete
and returns a non-clean parse result.

The RIFF/ANI exploit heuristic now applies the same distinction to its fixed
12-byte RIFF/ACON probe. A genuinely short input remains a non-candidate, but
an in-range fmap failure marks the layer incomplete and returns `CL_EPARSE`
instead of becoming a clean non-RIFF result.

## PE import-thunk completion — 2026-08-20

PE import-hash inspection now requires each thunk table to reach its explicit
terminator, enforces the `PE_MAXIMPORTS` bound, and treats invalid or unreadable
non-ordinal import names as incomplete instead of silently omitting them. A
fault-injected checked-in PE fixture regression and source guards are
registered. Compiled Linux/Sonic1 execution, sanitizer coverage, and broader
PE/import corpus qualification remain open.

## PE import-descriptor completion — 2026-08-20

PE import-descriptor inspection now distinguishes failed reads from short
reads, rejects import-table ranges outside the input map, requires a valid
zero descriptor terminator, rejects malformed terminators, and enforces the
`PE_MAXIMPORTS` bound. The checked-in PE regression now also exercises a
malformed terminator, with source guards registered. Compiled Linux/Sonic1
execution, sanitizer coverage, and broader PE/import corpus qualification
remain open.

## CPIO member-name read completion — 2026-08-20

All four CPIO readers now distinguish a failed member-name read from a short
truncated read, mark the layer incomplete and non-cacheable, and return the
specific read or parse status instead of silently reducing the result to a
generic format failure. A fault-injected newc regression and source guards
are registered. Compiled Linux/Sonic1 execution, sanitizer coverage, and
broader CPIO corpus qualification remain open.

## PE import-DLL name validation — 2026-08-20

PE import-table validation now checks the mapped DLL-name bytes before copying
them into the destination string. The previous call passed the still-NULL
destination pointer, allowing invalid import names to bypass validation. The
checked-in PE regression now corrupts the first imported DLL name and requires
an incomplete, non-cacheable `CL_EFORMAT` result; source guards are
registered. Compiled Linux/Sonic1 execution, sanitizer coverage, and broader
PE corpus qualification remain open.

## YARA fmap read-failure propagation — 2026-08-20

YARA integer reads now distinguish a valid out-of-range `UNDEFINED` value from
an in-range fmap window that could not be read. The latter returns `CL_EREAD`,
marks the scan incomplete and non-cacheable, and prevents a required YARA
matcher from turning an operational failure into a clean result. A focused
fault-injected matcher regression and source guards are registered. Compiled
Linux/Sonic1 execution, sanitizer coverage, and full YARA qualification remain
open.

## PE import-function name termination — 2026-08-20

PE32 and PE32+ import-thunk inspection now requires imported function names to
contain a real NUL terminator within the bounded fmap window before copying
them. This prevents `CLI_STRNDUP` from converting a truncated 256-byte name
into a syntactically complete name. The checked-in PE regression corrupts the
first function-name window and requires an incomplete, non-cacheable `CL_EFORMAT`
result; source guards are registered. Compiled Linux/Sonic1 execution, sanitizer
coverage, and broader PE corpus qualification remain open.

## Bytecode execution-failure propagation — 2026-08-20

Required logical-signature bytecode failures no longer normalize to `CL_SUCCESS`;
they mark the scan incomplete and non-cacheable and return the underlying
execution error. Applicable production bytecode-hook failures now follow the
same policy while preserving a later malware detection. A focused unprepared
logical-and-hook-bytecode regression and source guards are registered. Compiled
Linux/Sonic1 interpreter/JIT execution, sanitizer coverage, and official
bytecode qualification remain open.

## PE Petite reconstruction read failures — 2026-08-20

The legacy Petite unpacker previously normalized a detected candidate's missing
raw section, invalid reconstruction range, or failed section read to `CL_CLEAN`.
Those required reconstruction failures now mark the layer incomplete and
non-cacheable, returning `CL_EFORMAT` for structural failures and `CL_EREAD`
for fmap failures. A checked-in PE fixture regression injects the Petite
section read failure; compiled Linux/Sonic1 execution, sanitizer coverage, and
broader PE unpacker corpus qualification remain open.

## OLE2 fixed-header fmap failure — 2026-08-21

The OLE2 extractor previously left its default `CL_CLEAN` status intact when a
valid-sized input failed the fixed-header fmap read or contained invalid
block-size exponents. It now marks the layer incomplete and non-cacheable and
returns `CL_EREAD` or `CL_EFORMAT` respectively. Fault-injected Office and
malformed-header regressions plus source guards are registered; compiled
Linux/Sonic1, sanitizer, and broader OLE2/Office corpus qualification remain
open.

## BinHex encoded-input fmap failure — 2026-08-21

The BinHex decoder previously returned `CL_EREAD` when its first encoded-input
window could not be mapped, but did not mark the layer incomplete. That left
the parser's sticky completion and non-cacheable state dependent on a caller
to infer the failure from the return code. The read-failure path now records
`BinHex encoded input could not be read completely` through
`cli_mark_scan_incomplete()`. A direct fault-injected parser regression checks
the `CL_EREAD`, incomplete, reason, and non-cacheable invariants; the source
guard and capability manifest record the same contract. Compiled Linux/Sonic1,
sanitizer, and broader BinHex corpus qualification remain open.

## File-type detection fmap failure — 2026-08-21

The unknown-type dispatch path previously converted a failed initial or
OOXML-probe fmap read into `CL_EREAD` and jumped directly to `early_ret`.
Because that path did not pass through the normal result reconciliation, the
root could lack the sticky incomplete marker and non-cacheable state. The
central `cli_magic_scan()` type-error branch now records
`file type detection could not read the input completely` before returning.
A direct fault-injected `cli_magic_scan(CL_TYPE_ANY)` regression checks the
status, completion reason, and cache invariant; the source guard and ingress
capability rows record the contract. Compiled Linux/Sonic1, sanitizer, and
full ingress qualification remain open.

## PCRE full-subject fmap failure — 2026-08-21

The full-map PCRE path previously converted a failed in-range subject mapping
to `CL_EMEM` without recording the required scan as incomplete. The matcher
loop could also continue past a `CL_EREAD` returned by a matcher branch. The
path now releases the contiguous reservation, marks
`PCRE subject could not be mapped completely`, returns `CL_EREAD`, and makes
that status terminal in both generic and target matcher passes. A synthetic
full-map callback regression checks the return status, sticky reason, and
non-cacheable map; source guards and the PCRE capability row record the
contract. Compiled Linux/Sonic1, sanitizer, full-size PCRE, and RSS
qualification remain open.

## HFS+ file-tree header fmap failure — 2026-08-21

The HFS+ tree-header reader previously returned a generic format error when a
confirmed tree header was in range but its fmap window could not be read. The
path now marks the layer incomplete and returns `CL_EREAD`, preserving the
direct parser contract and preventing callers from inferring that the missing
tree was merely malformed. A synthetic catalog-tree fault-injection regression,
source guard, and capability-manifest entry record the invariant. Compiled
Linux/Sonic1, sanitizer, and broader HFS+ corpus qualification remain open.

## TIFF fmap read failure — 2026-08-21

TIFF header, IFD, entry, and next-IFD `fmap_readn()` failures previously all
used the malformed/truncated heuristic path. The parser now distinguishes an
in-range fmap callback failure as `CL_EREAD` and keeps a genuinely short
structure as the existing parser error. The initial-header fault-injection
regression now asserts the operational status, reason, and non-cacheable
state; source guards record all read boundaries. Compiled Linux/Sonic1,
sanitizer, and broader TIFF corpus qualification remain open.

## HFS+ fork-content fmap failure — 2026-08-21

HFS+ data/resource-fork windows that fail in the fmap previously returned a
generic map error without a direct incomplete-result contract. The path now
marks the layer incomplete and non-cacheable and returns `CL_EREAD`. A
synthetic fork-content fault-injection regression, source guard, and
capability-manifest entry record the invariant. Compiled Linux/Sonic1,
sanitizer, and broader HFS+ corpus qualification remain open.

## HFS+ catalog-node fmap failure — 2026-08-21

HFS+ catalog and attribute node-body reads previously collapsed an in-range
fmap callback failure into `CL_EFORMAT`, making an operational read failure
indistinguishable from malformed tree data. The node fetch path now marks the
layer incomplete and returns `CL_EREAD` for the fmap error while retaining
`CL_EFORMAT` for a genuinely short node. A synthetic catalog-node
fault-injection regression and source guard record the distinction. Compiled
Linux/Sonic1, sanitizer, and broader HFS+ corpus qualification remain open.

## PNG chunk fmap read failure — 2026-08-21

PNG chunk-length, chunk-type, IHDR, and CRC windows that fail in the fmap were
previously collapsed into the same path as ordinary short input. The parser
now marks an in-range callback failure incomplete and returns `CL_EREAD`, while
ordinary short input remains a parser error. A focused chunk-boundary
fault-injection regression, source guard, and capability-manifest entry record
the invariant. Compiled Linux/Sonic1, sanitizer, and broader PNG corpus
qualification remain open.

## RTF in-range fmap read failure — 2026-08-21

The RTF bounded reader previously treated an in-range `fmap` callback failure
like exact end-of-map: its loop stopped, cleanup ran, and the default result
could remain `CL_CLEAN`. The parser now distinguishes exact EOF from an
in-range read failure, marks the layer incomplete and non-cacheable, and
returns `CL_EREAD` unless a stronger detection or application result already
has precedence. A direct fault-injected RTF regression, source guard, and
capability-manifest entry record the contract. Compiled Linux/Sonic1,
sanitizer, and broader RTF/OLE corpus qualification remain open.

## PE icon resource-tree fmap failure — 2026-08-21

The PE resource lookup used by icon matching previously returned `void` and
silently stopped when a resource-directory fmap window was unavailable. A
declared resource tree could therefore leave the optional icon matcher with a
clean-compatible result despite not being inspected. The icon path now uses a
status-returning lookup that distinguishes structural ranges from in-range
fmap failures, marks the layer incomplete/non-cacheable, and returns
`CL_EREAD` for operational reads. A synthetic root-resource fault-injection
regression, source guards, and the PE capability entry record the contract.
Compiled Linux/Sonic1, sanitizer, and broader PE/resource corpus
qualification remain open.

## Forced nested-fmap read failures — 2026-08-21

The force-to-disk nested-fmap path now classifies a failed in-range source
window as `CL_EREAD` after the explicit nested range has already passed bounds
and resource admission. It still marks the layer incomplete and non-cacheable,
and its existing fault-injected regression now asserts the operational status
and reason. Compiled Linux/Sonic1, sanitizer, and broad nested-parser
qualification remain open.

## HWP3 document metadata fmap failures — 2026-08-21

HWP3 required document-info and metadata-enabled document-summary windows now
mark the layer incomplete and non-cacheable and return `CL_EREAD` when an
in-range fmap read fails. A direct document-info fault-injection regression,
source guards, and the HWP3 capability entry record the contract. Compiled
Linux/Sonic1 execution, sanitizer coverage, and broader HWP3 corpus
qualification remain open.

## PDF parser input-window fmap failures — 2026-08-21

Confirmed PDF scans now mark the layer incomplete and non-cacheable and return
`CL_EREAD` when the bounded version or trailer fmap window fails in range.
A direct parser fault-injection regression covers the version window, with
source guards and capability evidence registered. Compiled Linux/Sonic1,
sanitizer, and broader PDF corpus qualification remain open.

## Legacy bytecode ABI overflow — 2026-08-21

An applicable legacy logical-bytecode signature above the 32-bit file-size or
offset ABI was previously marked incomplete and non-cacheable but could still
return the evaluator's default `CL_CLEAN` status. The dispatch path now returns
`CL_EPARSE`, so an unsupported v1 bytecode layer cannot be reported as a clean
logical evaluation. A synthetic >4 GiB logical-signature regression verifies
the status, reason, and cache invariant without allocating the input size;
compiled Linux/Sonic1, interpreter/JIT, sanitizer, production-bytecode, and
mixed-ABI qualification remain open.

## APM partition fmap read failure — 2026-08-21

APM's required driver-map, fallback, partition-table, partition-entry, and
intersection-table reads now distinguish an in-range fmap callback failure
from an ordinary short map. The callback failure returns `CL_EREAD`, marks the
layer incomplete, and disables clean-result caching; malformed or truncated
input retains the parser's format error. A focused partition-entry
fault-injection regression, source guard, and capability-manifest entry record
the invariant. Compiled Linux/Sonic1, sanitizer, and broader APM corpus
qualification remain open.

## ELF metadata read failure — 2026-08-21

Metadata-only ELF parsing, used to calculate executable-relative signature
coordinates, now distinguishes in-range fmap callback failures from genuinely
short metadata. Callback failures return `CL_EREAD` and mark the scan
incomplete; short headers retain the parser's `CL_BREAK`/`CL_EPARSE` path. This
prevents raw signature analysis from continuing with skipped executable
metadata while leaving the existing raw matcher behavior intact. The focused
program-header fmap fault-injection regression now asserts `CL_EREAD`, with
source guards and capability evidence registered. Compiled Linux/Sonic1,
sanitizer, and broader ELF corpus qualification remain open.

## Mach-O metadata read failure — 2026-08-21

Mach-O metadata parsing, used to calculate executable-relative signature
coordinates, now distinguishes in-range fmap callback failures from genuinely
short input for required headers, load commands, sections, and thread state.
Callback failures return `CL_EREAD` and mark the scan incomplete; short input
retains the existing `CL_EPARSE` path. This prevents raw signature analysis
from continuing with skipped executable metadata while leaving the existing
raw matcher behavior intact. Universal-binary header and architecture-table
reads follow the same distinction. Focused load-command fault-injection
regressions, source guards, and capability-manifest entries record the
invariant. Compiled Linux/Sonic1, sanitizer, and broader Mach-O corpus
qualification remain open.

## Executable target-metadata failure — 2026-08-21

The shared executable-target metadata bridge now marks a failed PE, ELF, or
Mach-O metadata parse incomplete before relative-signature analysis continues.
This closes the remaining PE target-info path where a failed optional metadata
parse could disable PE-relative signatures while leaving the outer raw scan
eligible for a clean result. A focused PE target-info regression, source guard,
and capability-manifest entry record the invariant. Compiled Linux/Sonic1,
sanitizer, and full executable-signature qualification remain open.

## MBR/GPT partition fmap read failures — 2026-08-21

The MBR and GPT partition scanners now distinguish an in-range fmap callback
failure from a partition record that is simply outside a short input map.
Required master/extended boot records, protective and GPT headers, partition
entries, and intersection-table entries return `CL_EREAD` and mark the layer
incomplete when their backing window fails. A focused MBR/GPT boot-record
fault-injection regression, source guards, and capability-manifest entries
record the invariant. Compiled Linux/Sonic1, sanitizer, and broader partition
corpus qualification remain open.

## Public large-file setter negative values — 2026-08-21

The public `cl_engine_set_num()` API previously replaced negative values for
`MaxFileSize` and several 32-GiB parser gates with their defaults after a
warning. That made an invalid caller request silently change the resource
contract and could leave the caller believing its requested limit had been
applied. These setters now reject negative values with `CL_EARG` before
mutating the engine; valid zero and positive values retain their existing
semantics. The focused setter regression also verifies that a failed negative
update leaves the prior `MaxFileSize` unchanged. Compiled Linux/Sonic1
execution and full API compatibility qualification remain open.

## TIFF IFD value-size arithmetic — 2026-08-21

TIFF IFD entries now calculate type-width multiplication through checked
native-size arithmetic and validate external value ranges with subtraction
form before any map-dependent interpretation. An unrepresentable value size
or out-of-map external value is marked incomplete and non-cacheable rather
than relying on wrapping addition. A focused malformed IFD regression and
source guards record the invariant; compiled Linux/Sonic1, sanitizer, and
broader TIFF corpus qualification remain open.

## GIF block-range arithmetic — 2026-08-21

GIF version, global/local color-table, extension-sub-block, and image-data
range checks now use a shared subtraction-form helper that first verifies the
starting offset is within the fmap. This prevents a wrapping `offset +
length` comparison from admitting an out-of-range block on a large map.
The focused truncated-block regression now covers global-table and extension
sub-block admission as well as the existing image paths; source guards and
capability evidence record the invariant. Compiled Linux/Sonic1, sanitizer,
and broader GIF corpus qualification remain open.

## HWP3 information-block arithmetic — 2026-08-21

HWP3 information-block admission now verifies the starting offset and compares
the declared length against the remaining fmap range without wrapping
addition. Image and background-image blocks also reject lengths shorter than
their fixed 32-byte and 324-byte headers before subtracting those headers for
nested scanning. A focused malformed-information-block regression, source
guards, and capability evidence record the invariant; compiled Linux/Sonic1,
sanitizer, and broader HWP3 corpus qualification remain open.

## Direct clamd SCANREPORT qualification path — 2026-08-21

The mandatory service gate previously reached the structured `CONTSCANREPORT`,
`MULTISCANREPORT`, `ALLMATCHSCANREPORT`, `FILDESREPORT`, and
`INSTREAMREPORT` paths through `clamdscan`, but had no direct wire-level
exercise of `SCANREPORT`. The new standard-library protocol probe sends a
length-prefixed `zSCANREPORT` request over the running Unix socket, validates
the JSON frame, zero terminator, root size, file type, completion, verdict,
metrics, and oracle-bound detection, and writes the validated report into the
attested service evidence. The service workflow now requires this pass;
compiled Linux/Sonic1 execution and the remaining production gates remain
open.

## ARJ header range admission — 2026-08-21

ARJ main and member header admission now validates the starting offset before
subtracting it from the fmap length, then checks the complete length-prefixed
header range with native-size arithmetic. This preserves the existing
fail-visible result for truncated input while preventing an invalid offset
from turning the remaining-length calculation into an underflow. Source guards
and the existing truncated-main-header regression record the invariant;
compiled Linux/Sonic1, sanitizer, and broader ARJ corpus qualification remain
open.

## HTML normalized-output open failures — 2026-08-21

HTML normalization intentionally permits an individual normalized output to be
absent when the source contains no corresponding content, but failures other
than `ENOENT` now mark the HTML layer incomplete and return an open/access
error. The no-comment, no-tags, and JavaScript normalized views therefore
cannot disappear silently after successful normalization. Source guards record
the three paths; compiled Linux/Sonic1, sanitizer, and broader HTML corpus
qualification remain open.

## Direct structured clamd command-family gate — 2026-08-21

The direct Unix-socket report probe now runs every structured command family:
`SCANREPORT`, `CONTSCANREPORT`, `MULTISCANREPORT`, `ALLMATCHSCANREPORT`,
`FILDESREPORT`, and `INSTREAMREPORT`. Each request validates the framed JSON,
zero terminator, input oracle, completion state, verdict, metrics, file type,
and skipped-operation count before writing evidence; the workflow requires all
six pass markers. Compiled Linux/Sonic1 execution and full production
qualification remain open.

## CAB/CHM fmap coordinate admission — 2026-08-21

The shared libmspack fmap bridge now validates that the containing-map length
fits in `off_t`, that the SFX origin plus decoder-relative offset remains
inside the map, and that start/current/end seeks cannot wrap or leave the map.
Decoder read failures, including fixed-header fmap callback failures, therefore
remain errors instead of reaching fmap through wrapped coordinates. Source
guards record the bridge invariant; compiled
Linux/Sonic1, sanitizer, and broader CAB/CHM corpus qualification remain open.

## PDF truncated-object admission — 2026-08-21

PDF object discovery already retained a confirmed object when its `endobj`
terminator was absent, but only exposed that condition in metadata. The
truncated object now increments invalid-object accounting, and PDF finalization
marks the layer incomplete/non-cacheable and returns a non-clean format result.
A focused truncated-object regression and source guards record the invariant;
compiled Linux/Sonic1, sanitizer, and broader PDF corpus qualification remain
open.

## MSEXPAND declared-output admission — 2026-08-21

MSEXPAND already rejected truncated input, but its fixed-size output macro
accepted a write that exceeded the declared decompressed size and returned clean.
The decoder now checks the pending write against that declaration before every
temporary-spool write and only completes on an exact size match. A focused
`CL_TYPE_MSSZDD` regression covers overproduced literal output; compiled
Linux/Sonic1, sanitizer, and broader SZDD corpus qualification remain open.

## OLE2/MSO declared-output admission — 2026-08-21

The MSO zlib stream path already required a terminal decoder state, but only
warned when its declared uncompressed-size prefix disagreed with the produced
byte count. It now marks that confirmed layer incomplete and returns
`CL_EFORMAT` before nested scanning. Source guards record the invariant;
compiled Linux/Sonic1, sanitizer, and broader OLE2 corpus qualification remain
open.

## ZWS/SWF declared-input admission — 2026-08-21

ZWS previously logged a mismatch between its declared compressed-stream length
and the bytes present in the fmap, then continued toward LZMA decoding. The
path now rejects truncated or mismatched length fields before decoder setup and
marks the layer incomplete; a focused public SWF regression covers the exact
boundary. Compiled Linux/Sonic1, sanitizer, and broader SWF corpus
qualification remain open.

## HWPOLE2 declared-payload admission — 2026-08-21

The HWP embedded-OLE2 wrapper previously warned when its 32-bit declared
uncompressed payload size disagreed with the bytes present after the prefix,
then dispatched the nested scan anyway. The confirmed wrapper now marks that
layer incomplete and returns `CL_EPARSE` before nested scanning. A focused
regression and source guard record the non-cacheable fail-closed result;
compiled Linux/Sonic1, sanitizer, and broader HWP corpus qualification remain
open.

## LHA limit and metadata-result propagation — 2026-08-21

The Rust LHA/LZH scanner previously treated every non-success archive-metadata
result as a size-limit skip and skipped members that `check_scan_limits()` could
not admit, allowing the archive to finish as clean without inspecting required
content. It now propagates detection/cancellation, converts callback failures
and limit admission failures into sticky incomplete results, and stops before
member extraction. Source guards record both fail-visible branches; compiled
Rust/Linux/Sonic1, sanitizer, and broader LHA corpus qualification remain open.

## Legacy archive metadata-result propagation — 2026-08-21

CPIO ODC/newc, TAR, RAR, EGG, ARJ, and InstallShield metadata callers now
propagate every non-success result from `cli_matchmeta()`. Previously several
paths only recognized `CL_VIRUS`, allowing callback/resource failures to
continue into extraction, normalize to success, or be mislabeled as malware.
Non-detection callback statuses remain caller-visible, while ordinary clean
metadata continues to permit extraction. Source guards record the corrected
callers; compiled Linux/Sonic1, callback-fault injection, sanitizer, and wider
archive-corpus qualification remain open.

## UNIX mbox attachment scan-result propagation — 2026-08-21

UNIX mbox bounce and BinHex attachment paths previously checked only for
`CL_VIRUS`. A temporary-spool scan that returned an I/O, resource, parser, or
cancellation result could therefore mark the context incomplete while the
mbox parser continued with a clean internal status. Those callers now map
every non-clean result to the mbox `FAIL` state, BinHex no longer reduces the
scan result to a boolean, and the no-body aggregation branch preserves
`FAIL`. Source guards record the corrected paths;
compiled Linux/Sonic1, fault-injection, sanitizer, and broader mail-corpus
qualification remain open.

## PE, Authenticode, and bytecode alert-result propagation — 2026-08-21

PE import wildcard hash matches previously called `cli_append_virus()` without
retaining its result, so a wildcard-only match or evidence-storage failure could
leave the import scan clean. Authenticode certificate block-list matches had a
similar gap: non-success alert-append results could be normalized to clean by
the certificate parser and by the raw matcher wrapper. Applicable bytecode hooks
also ignored alert-append errors and callback breaks after a bytecode reported an
alert. These paths now preserve the append status, mark operational evidence
failures incomplete, and allow only the expected no-catalog-match result to
continue through the Authenticode raw-scan fallback. Source guards record the
corrected branches; compiled Linux/Sonic1, signature/callback/resource fault
injection, sanitizer, and production PE/bytecode corpus qualification remain
open.

## AC all-matches alert-result propagation — 2026-08-21

The AC matcher’s all-matches branches previously ignored non-success results
from `cli_append_virus()`. Evidence-storage failures could therefore be lost
while scanning continued, allowing a required signature result to disappear
from the final verdict. The matcher now preserves expected trusted and
detection results, returns callback breaks, and marks operational append
failures incomplete before returning them. Source guards record both branches;
compiled Linux/Sonic1, callback/resource fault injection, sanitizer, and
production signature-corpus qualification remain open.

## Structured-detector alert-result propagation — 2026-08-21

The structured credit-card and SSN detectors previously returned only
`CL_VIRUS` from their heuristic alert append calls. Evidence-storage failures
and callback control results could therefore be discarded. Both paths now
preserve trusted, detection, callback, and operational results; operational
append failures mark the scan incomplete before returning. Source guards record
the two detectors; compiled Linux/Sonic1, fault injection, sanitizer, and
production structured-data corpus qualification remain open.

## Legacy callback alert-result propagation — 2026-08-21

Legacy file-inspection, pre-scan, and post-scan callback paths previously kept
the callback’s `CL_VIRUS` status even when recording the callback alert returned
`CL_VERIFIED`, `CL_BREAK`, or an operational failure. They now preserve the
append result, mark operational recording failures incomplete, and retain the
normal callback-block behavior when the append succeeds. Source guards record
all three paths; compiled Linux/Sonic1, callback fault injection, sanitizer,
and API/front-end qualification remain open.

## OLE2/RAR heuristic alert-result propagation — 2026-08-21

Both OLE2 VBA macro-presence paths and the encrypted-RAR heuristic previously
only promoted `CL_VIRUS` from `cli_append_potentially_unwanted()`. Trusted,
callback-break, and operational recording results could be discarded. These
paths now preserve every non-success result and mark operational alert-recording
failures incomplete. Source guards record the parser branches; compiled
Linux/Sonic1, callback/resource fault injection, sanitizer, and OLE/RAR corpus
qualification remain open.

## ELF broken-executable heuristic result propagation — 2026-08-21

ELF metadata-error branches previously retained only `CL_VIRUS` from the
`Heuristics.Broken.Executable` alert recorder. Callback breaks, trusted results,
and operational recording failures could be discarded while the parser returned
its ordinary format/read status. The branches now share a fail-visible helper:
successful alert recording preserves the original parser status, while every
other result is propagated and operational failures mark the scan incomplete.
The source guard records the invariant; compiled Linux/Sonic1, callback/resource
fault injection, sanitizer, and broader ELF corpus qualification remain open.

## Mach-O broken-executable heuristic result propagation — 2026-08-21

Mach-O and universal-binary malformed-metadata macros previously retained only
`CL_VIRUS` from the `Heuristics.Broken.Executable` alert recorder. Callback
breaks, trusted results, and operational recording failures could therefore be
discarded or replaced by the parser’s generic `CL_EPARSE`. Both paths now share
a helper that preserves the normal parser result after successful recording and
propagates every other alert result, marking operational recording failures
incomplete. The source guard and capability manifest record the invariant;
compiled Linux/Sonic1, callback/resource fault injection, sanitizer, and broader
Mach-O corpus qualification remain open.

## Encrypted EGG heuristic result propagation — 2026-08-21

The EGG scanner’s encrypted-member heuristic previously promoted only
`CL_VIRUS`; trusted, callback-break, and operational alert-recording results
were discarded. It now preserves every non-success result and marks an
operational alert-recording failure incomplete before returning it. The source
guard and capability manifest record the invariant; compiled Linux/Sonic1,
callback/resource fault injection, sanitizer, and broader EGG corpus
qualification remain open.

## PE broken-executable heuristic result propagation — 2026-08-21

The malformed-PE header path previously retained only `CL_VIRUS` from the
`Heuristics.Broken.Executable` alert recorder, discarding trusted, callback-break,
and operational recording results. It now propagates every non-success result
and marks operational alert-recording failures incomplete before returning. The
source guard and capability manifest record the invariant; compiled
Linux/Sonic1, callback/resource fault injection, sanitizer, and broader PE
corpus qualification remain open.

## Extended-MBR intersection result propagation — 2026-08-21

The extended-MBR traversal previously stopped on an intersection only when the
alert recorder returned `CL_VIRUS`; trusted, callback-break, and operational
results could be overwritten by continued logical-partition traversal. The path
now stops on every non-success alert result, preserving the result and its
fail-visible scan state. The source guard and capability manifest record the
invariant; compiled Linux/Sonic1, callback/resource fault injection, sanitizer,
and broader partition-image corpus qualification remain open.

## BM all-matches alert-result propagation — 2026-08-21

The Boyer–Moore matcher’s all-matches branch previously ignored non-success
results from `cli_append_virus()`. Evidence-storage failures or callback
breaks could therefore be lost while the matcher continued. The branch now
preserves expected trusted and detection results, returns callback breaks, and
marks operational append failures incomplete before returning them. Source
guards record the invariant; compiled Linux/Sonic1, callback/resource fault
injection, sanitizer, and production signature-corpus qualification remain
open.

## Legacy clamd descriptor/stream result preservation — 2026-08-21

The legacy `FILDES` and staged `INSTREAM` command handlers previously converted
every `scanfd()` result other than `CL_VIRUS`, `CL_EMEM`, and `CL_ETIMEOUT` to
zero after the scanner had emitted its response. Parser, limit, read, format,
and callback results could therefore disappear from the worker and IDSESSION
completion status. The handlers now retain a non-success result as a command
error while preserving the existing virus, OOM, timeout, and clean behavior.
Source guards and the capability manifest record the correction; compiled
Linux/Sonic1, malformed/limit integration, IDSESSION, sanitizer, and broader
front-end parity qualification remain open.

## Matcher result propagation — 2026-08-21

The buffer and fmap matcher callers previously stopped only for virus, memory,
and one read result after each target or generic matcher pass. Resource,
timeout, callback, and other matcher failures could therefore be replaced by
the next matcher pass or by a clean result. Both callers now preserve every
non-success error below `CL_TYPENO`, while allowing file-type result codes to
continue through the intended type-detection path. Source guards record the
invariant; compiled Linux/Sonic1, resource/callback fault injection, sanitizer,
and production signature-corpus qualification remain open.

## PDF extracted-object hook result propagation — 2026-08-21

The PDF post-dump bytecode hook previously fell back to the parent PDF fmap
when mapping the extracted object failed, allowing the hook to inspect the
wrong bytes. It also ignored post-hook errors other than `CL_VIRUS`. The hook
now marks the layer incomplete and returns `CL_EREAD` when the extracted fmap
cannot be created, and propagates every non-success hook result except the
existing intentional `CL_BREAK` continuation. Source guards record both
invariants; compiled Linux/Sonic1, bytecode fault injection, sanitizer, and
production PDF/bytecode corpus qualification remain open.

## PE bytecode hook failure propagation — 2026-08-21

The PE `BC_PE_ALL` and `BC_PE_UNPACKER` callers previously discarded hook
initialization, execution, and unpacked-layer errors after the hook returned,
allowing the enclosing PE scan to continue and eventually report clean. They
now destroy the PE/bytecode contexts and return every non-success result,
while preserving the existing `CL_BREAK` clean-stop behavior. Source guards
record both callers; compiled Linux/Sonic1, bytecode fault injection,
sanitizer, and production PE/bytecode corpus qualification remain open.

## PE header and import-pass result propagation — 2026-08-21

The PE entry path previously continued into section, import, heuristic, and
unpacker analysis for header results outside its small explicit switch, even
though `cli_peheader()` can return read, memory, argument, and other failures.
The import-table caller also logged `CL_ENULLARG` and continued. The entry path
now proceeds only for `CL_SUCCESS`, and the import pass preserves its invalid
invocation result. Source guards record both boundaries; compiled
Linux/Sonic1, fault injection, sanitizer, and production PE corpus
qualification remain open.

## False-positive hash failure propagation — 2026-08-21

The false-positive hash checker previously converted fmap hash preparation or
read failures to `CL_VIRUS`, and its alert caller then continued as though no
false-positive hash check had failed. Required hash failures now preserve the
underlying error, mark the scan incomplete/non-cacheable, and stop the alert
append path; the normal no-match (`CL_VIRUS`) and trusted
(`CL_VERIFIED`) semantics are unchanged. A focused metadata-only-fmap
regression and source guards are registered. Compiled Linux/Sonic1, sanitizer,
callback/resource fault injection, and production signature-corpus
qualification remain open.

## False-positive trust-update propagation — 2026-08-21

False-positive hash matches previously ignored `cli_trust_layers()` failures,
and metadata collection could dereference a null trust reason after an
allocation failure. The three FP branches now preserve trust-update errors and
mark the scan incomplete/non-cacheable; metadata trust explicitly rejects a
missing reason while non-metadata trust behavior remains unchanged. Focused
matcher regressions and source guards are registered. Compiled Linux/Sonic1,
sanitizer, allocation fault injection, and production signature-corpus
qualification remain open.

## Callback trust-update propagation — 2026-08-21

Modern alert callbacks and legacy pre-scan, file-inspection, and post-scan
callbacks previously ignored failures while removing evidence and updating
trusted-layer metadata. They now preserve the trust-update error, mark the
scan incomplete/non-cacheable, and only return `CL_VERIFIED` after the trust
operation succeeds. Single-layer metadata trust also rejects a missing reason.
Focused source guards and the matcher trust-reason regression are registered.
Compiled Linux/Sonic1, sanitizer, allocation fault injection, and callback
qualification remain open.

## On-access file preflight propagation — 2026-08-21

The on-access file handler previously used stat and size-limit failures to
disable submission and deny fanotify permission events, but returned the
success from the response helper to extra-scan callers. It now preserves the
preflight error for file callers and logs incomplete inotify/fanotify file
scans, matching the existing directory traversal behavior. Source guards and
the capability manifest record the invariant; compiled Linux/Sonic1,
fanotify/inotify integration, sanitizer, and resource-budget qualification
remain open.

## Windows memory-scan result propagation — 2026-08-21

The Windows-only memory-scan helper previously switched on the output verdict
without checking the `cl_scandesc_ex()` return status. A parser, limit, or
operational failure could therefore leave the default `NOTHING_FOUND` verdict
and be logged as `OK`. The helper now records the error and increments the
memory-scan error count before any clean normalization. Native Windows remains
explicitly outside the certified Linux x86-64 first-release target; source
guards and the capability manifest record that boundary.

## Raw matcher hash-cache failure propagation — 2026-08-21

The raw matcher previously discarded the return value from `fmap_set_hash()`
after finishing a required hash. A cache-insertion failure could therefore
leave the hash-dependent stage incomplete while later logic continued toward a
clean or cacheable result. The matcher now preserves the error, marks the scan
incomplete/non-cacheable, and stops before hash-signature lookup. The source
guard and capability manifest record the invariant; compiled Linux/Sonic1,
fault injection, sanitizer, and production signature-corpus qualification
remain open.

## clamd large-file admission threshold correction — 2026-08-21

The daemon admission check used `CLI_DEFAULT_MAXFILESIZE` and
`CLI_DEFAULT_MAXSCANSIZE` as the thresholds for its historical, low-resource
startup bypass. When the gated 32/64 GiB defaults were enabled, those values
became the large-file defaults themselves, so clamd could skip the required
Linux x86-64 platform, effective-memory, and temporary-space checks. The
bypass now uses fixed historical 100 MiB/400 MiB thresholds, and a focused
regression proves that a 32/64 GiB configuration is admitted to the checks and
cannot succeed with an invalid temporary directory. Full supported-Linux
startup, workload, sanitizer, and resource qualification remain open.

## MULTISCAN worker OOM/result propagation — 2026-08-21

The per-file `COMMAND_MULTISCANFILE` worker path previously ignored the scan
callback's direct result and returned only its accumulated error count. That
could bypass `ExitOnOOM`, and an unexpected non-success callback result could
be reduced to a successful worker completion when no counter had been updated.
The worker now preserves fatal OOM termination and records any remaining
unexpected non-success as an error while retaining the existing infected-file
and structured-report aggregation behavior. Source guards and the capability
manifest record the invariant; compiled Linux/Sonic1, allocation fault
injection, sanitizer, and full parallel service qualification remain open.

## Structured clamd fallback completion classification — 2026-08-21

When a structured clamd report could not reuse the public report object, the
bounded fallback object previously labeled every non-detection status outside
the explicit limit/resource cases as `UNSUPPORTED`. That conflated transport,
allocation, descriptor, and other operational failures with deliberate parser
or format boundaries. The fallback now classifies `CL_EPARSE`/`CL_EFORMAT` as
`MALFORMED_CONFIRMED`, the explicit unsupported decoder/bytecode statuses as
`UNSUPPORTED`, and all other non-success statuses as `RESOURCE_FAILURE`,
matching the public report classification contract. Source guards and the
capability manifest record the producer behavior, and the shared classifier
unit test covers each fallback class; compiled protocol and Linux/Sonic1
service qualification remain open.

The public report finalizer now applies the same `UNSUPPORTED` classification
to `CL_EUNPACK`, `CL_EBYTECODE`, and `CL_EBYTECODE_TESTFAIL` when no more
specific parser reason is available. This prevents the library `_ex2` API from
disagreeing with clamd fallback reports about an unsupported decoder/runtime
boundary. A focused library unit test covers all three statuses; compiled
Linux/Sonic1 and full service qualification remain open.

## clamdscan stdin legacy error propagation — 2026-08-21

The no-`--report-json` stdin path passed the infection-count return variable as
`dsresult()`'s `printok` output and supplied no error counter. A legacy clamd
`ERROR` response could therefore leave the outer error count at zero and be
returned as a clean result. The client now uses a separate print-status value
and propagates daemon errors into the client result; a socket-level regression
proves that an `ERROR` response increments the error counter. Compiled
Linux/Sonic1 and full clamdscan service qualification remain open.

## MHTML related-body streaming — 2026-08-21

`multipart/related` was the remaining MIME path that forced the complete
parent body into the 64 MiB materialization budget so the legacy handler could
select its HTML root after collecting all parts. Related parents now use the
disk-backed multipart path; child messages remain spooled until the same
HTML-first/text-fallback selection is complete, and MHTML preclassification
reads the selected child from a file-backed source. A 65 MiB related-body
regression fixture and source guards were added. Supported-Linux compilation,
libxml2 memory/RSS behavior, sanitizer execution, and full MHTML corpus
qualification remain open.

## TAR initial-header read completion — 2026-08-21

The TAR reader previously treated a zero-length result from its first fmap
window as normal end-of-file, even when the requested header offset was still
inside the mapped input. A failed initial header read could therefore return
clean for a TAR input that had not been inspected. The reader now distinguishes
exact EOF from an in-range failed read, marks the scan incomplete, and returns
`CL_EREAD`; a focused fault-injection regression also verifies the result is
non-cacheable and cannot leave a clean verdict. Supported-Linux compilation,
fault-injection execution, sanitizer, and complete TAR corpus qualification
remain open.

## YARA in-rule deadline enforcement — 2026-08-21

The ClamAV YARA interpreter previously received a zero internal timeout, so a
single logical rule containing a long-running loop could run without an active
`MaxScanTime` check until the outer logical-signature loop regained control.
YARA execution now carries the scan context and checks the same wall-clock
deadline every bounded instruction interval, returning `CL_ETIMEOUT` through
the normal terminal-result path. A focused loop regression verifies the timeout
and sticky abort state; supported-Linux compilation, sanitizer, and production
YARA corpus qualification remain open.

## Bytecode scan-deadline clamping — 2026-08-21

The bytecode VM has an independent watchdog, but its configured timeout could
exceed a caller's shorter `MaxScanTime`; successful logical or hook executions
also did not re-check the scan deadline before continuing. Bytecode contexts now
clamp their watchdog to the remaining scan deadline and both logical and hook
dispatch paths perform an authoritative post-run check, while detections retain
their normal precedence. A focused regression verifies the clamp and unlimited
scan behavior; supported-Linux interpreter/JIT compilation, sanitizer, and
production bytecode qualification remain open.

## JPEG required read status — 2026-08-21

The JPEG parser previously treated an operational fmap callback failure while
reading the confirmed header, marker, segment-size, or Photoshop resource size
as an ordinary short/missing structure; an initial header callback failure
could therefore leave the parser's default clean result untouched. These
required reads now distinguish in-range callback failure (`CL_EREAD`) from
genuinely short input (`CL_EPARSE` or the existing exact-end behavior), mark
the scan incomplete, and preserve the non-cacheable state. A focused header
fault-injection regression, source guards, and capability-manifest evidence
record the invariant. Compiled Linux/Sonic1, sanitizer, callback-fault, and
production JPEG corpus qualification remain open.

## GIF required read status — 2026-08-21

The GIF parser previously routed in-range fmap callback failures through the
same heuristic parse path as truncated structures. Required signature, version,
descriptor, block-label, extension, and image-data reads now preserve callback
failures as `CL_EREAD`, while genuinely short structures retain `CL_EPARSE` and
the existing fail-visible behavior. The focused header fault-injection
regression now asserts the operational status and reason; source guards and
capability evidence record the invariant. Compiled Linux/Sonic1, sanitizer,
callback-fault, and production GIF corpus qualification remain open.

## ISO9660 required read status — 2026-08-21

ISO9660 volume descriptors and data blocks previously returned the same parse
status for an in-range fmap callback failure and a genuinely unavailable block.
The volume descriptor, secondary-descriptor probe, directory-block, and
file-data paths now preserve callback failures as `CL_EREAD`; arithmetic or
out-of-map conditions retain `CL_EPARSE` and their existing incomplete reasons.
A focused volume-descriptor fault-injection regression, source guards, and
capability evidence record the distinction. Compiled Linux/Sonic1, sanitizer,
callback-fault, and production ISO9660 corpus qualification remain open.

## UDF required descriptor read status — 2026-08-21

UDF descriptor helpers previously treated an in-range fmap callback failure as
the same condition as a short or out-of-map descriptor. Descriptor admission
now carries the read status through generic-volume, required-volume, and file
volume descriptor walks: callback failures return `CL_EREAD`, while genuinely
unavailable ranges remain `CL_EPARSE`, with both paths marking the layer
incomplete and non-cacheable. A focused generic-descriptor fault-injection
regression, source guards, and capability-manifest evidence record the
distinction. Compiled Linux/Sonic1, sanitizer, callback-fault, and production
UDF corpus qualification remain open.

## SWF required read status — 2026-08-21

SWF fixed frame metadata reads previously returned truncation/format statuses
for both an in-range fmap callback failure and genuinely short input;
compressed CWS/ZWS input failures could also be normalized to `CL_EUNPACK`.
Shared exact and chunk readers now preserve in-range callback failures as
`CL_EREAD`, while short or out-of-map input retains the format/decompression
failure path. A focused header and frame-metadata callback regression, source
guards, and capability-manifest evidence record the distinction. Compiled
Linux/Sonic1, sanitizer, callback-fault, and production SWF corpus
qualification remain open.

## ARJ extraction read status — 2026-08-21

ARJ compressed bit-window refills and stored-member copies previously treated
an in-range fmap callback failure as a corrupted/truncated file and returned
`CL_EFORMAT`. A shared bounded-window helper now distinguishes exact EOF or
out-of-map input from callback failure, preserving `CL_EREAD` through the
decoder and stored extractor; `cli_scanarj()` records the specific incomplete
read reason and refuses to scan partial output. A focused stored-member
fault-injection regression, source guards, and capability-manifest evidence
record the invariant. Compiled Linux/Sonic1, sanitizer, callback-fault, and
production ARJ corpus qualification remain open.

## CPIO coordinate read status — 2026-08-21

The four CPIO readers used `fmap_readn()` directly, whose `(size_t)-1`
sentinel represents both an in-range callback failure and an impossible offset.
After a malformed member declaration advanced the parser beyond the input, the
next header could therefore be reported as `CL_EREAD` instead of a truncated
archive. A bounded `cpio_readn()` helper now classifies out-of-map or
cross-boundary requests as short input (`CL_EPARSE`) while preserving
in-range callback failures as `CL_EREAD` for fixed headers and member names.
Focused regressions cover both cases; compiled Linux/Sonic1, sanitizer,
callback-fault, and production CPIO corpus qualification remain open.

## Compressed-stream input read status — 2026-08-21

The fmap-backed GZip, BZip2, and XZ readers previously treated a failed
in-range input window like an ordinary end-of-stream condition. They now
classify a failed window as `CL_EREAD` and retain the incomplete/non-cacheable
state, while exact EOF still follows each decoder's existing premature-end
status. A focused callback-fault regression covers all three streaming paths;
compiled Linux/Sonic1, sanitizer, callback-fault, and production compressed
corpus qualification remain open.

## Script-normalization read status — 2026-08-21

The shared text normalizer previously exposed only a boolean read-failure flag,
so `cli_scanscript()` converted an in-range fmap callback failure into
`CL_EPARSE`. The normalizer now carries `CL_EREAD` for a failed in-range
window, treats an impossible offset as `CL_EPARSE`, and the scanner preserves
that status through its cleanup path. The focused normalizer regression now
asserts `CL_EREAD`; compiled scanner-level, sanitizer, callback-fault, and
production script-corpus qualification remain open.

## Service-build provenance binding — 2026-08-21

The mandatory service qualification now verifies that its build was configured
from the audited source root and the same immutable source commit/manifest as
the runtime gate. It records the CMake cache, compile-command graph, hashes of
`clamscan`, `clamd`, `clamdscan`, and `clamav-milter`, and the hashes of their
resolved runtime dependencies; the service executables are re-hashed after the
workload to detect mutation during qualification. The service evidence now
cannot claim a production workload for an unbound or substituted build.
Supported-Linux execution and full service qualification remain release gates.

## Service-evidence post-run verification — 2026-08-21

The service workload now has a standalone post-run verifier. It checks the
evidence checksum manifest, required pass markers, source/build identity,
copied CMake and compile-command hashes, both pre/post service executable
hash lists, and every recorded runtime-dependency hash against the build and
host files. The workflow runs this verifier after creating `SHA256SUMS`, so a
later evidence mutation or build/runtime substitution cannot pass solely on
the qualification script's in-process checks. Supported-Linux execution and
full service qualification remain release gates.

## RIFF callback read status — 2026-08-21

RIFF exploit inspection now distinguishes an in-range fmap callback failure
from a range that is genuinely unavailable. Header, chunk-header, and nested
list-type callback failures return `CL_EREAD`, retain the incomplete and
non-cacheable state, and propagate through the RIFF scanner wrapper; truncated
coordinates remain `CL_EPARSE`. Focused header and chunk fault-injection
regressions, source guards, and capability evidence record the distinction.
Compiled Linux/Sonic1, sanitizer, callback-fault, and production RIFF corpus
qualification remain open.

## SIS metadata read status — 2026-08-21

Old-format SIS metadata parsing previously ignored failures while reading the
application name/capability tables and dependency headers. A failed
`fmap_need_off()` or `getsistring()` path could therefore leave the parser's
default clean status intact even though declared metadata was not inspected.
The parser now uses bounded copies for those tables, preserves `CL_EREAD`
versus truncated `CL_EPARSE`, marks the layer incomplete, and stops on failed
metadata strings or dependencies. Header and language-table failures receive
the same fail-visible treatment. A synthetic name-table truncation regression,
source guards, and capability evidence cover the boundary; compiled
Linux/Sonic1, sanitizer, callback-fault, and production SIS corpus
qualification remain open.
