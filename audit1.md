# Independent read-only audit of audit.md

**Review date:** 2026-08-16  
**Reviewed report:** audit.md, SHA-256 ce78ba7003031e6007bfe000c8ee6718175252ec5fed5e149ddda47617fb4e48  
**Review target:** the delivered source tree at /Volumes/512gbNVME/github-external/ClamAV  
**Method:** static, read-only source and evidence review; no build, scanner run, dependency installation, or network access
**Excluded by request:** the previous contents of audit1.md were not read

## Child-descriptor entry null-context admission — 2026-08-25

The descriptor-based nested-scan entry previously returned legacy `CL_EARG`
when its scan context was null. It now returns `CL_ENULLARG` before `fstat` or
child-map admission. The focused direct regression is registered; descriptor
fault injection, full ingress parity, sanitizer, production-CVD, service, and
Sonic1 qualification remain open.

## SWF direct-entry admission — 2026-08-25

The SWF parser now returns `CL_ENULLARG` for a null context while retaining
the explicit incomplete `CL_EPARSE` result for a recognized layer without an
input fmap. The dedicated production-linked `swf_map` case covers both
states; full SWF corpus, sanitizer, materialized large-file, production-CVD,
service, and Sonic1 qualification remain open.

## GIF/PNG/TIFF direct-entry admission — 2026-08-25

The direct GIF, PNG, and TIFF parser entries previously returned legacy
`CL_EARG` for a null parser context. They now return `CL_ENULLARG`, while the
existing non-null missing-map paths remain parser-specific `CL_EPARSE`
incomplete results. A focused direct regression covers all three entries; the
compiled media corpus, sanitizer, production parser-family, and Sonic1 gates
remain open.

## JPEG direct-entry admission — 2026-08-25

The JPEG direct parser now returns `CL_ENULLARG` for a null context while a
recognized layer with no input fmap remains an explicit incomplete parse. The
dedicated `jpeg_map` production-linked case covers both states; JPEG corpus,
sanitizer, materialized large-file, production-CVD, service, and Sonic1
qualification remain open.

## Mydoom detector direct-entry admission — 2026-08-25

The Mydoom log detector now returns `CL_ENULLARG` for a null context while
retaining the explicit incomplete `CL_EPARSE` result for a recognized layer
without an input fmap. The dedicated production-linked `mydoom_map` case
covers both states; compiled detector corpus, raw-dispatch, sanitizer,
production-CVD, service, and Sonic1 qualification remain open.

## BinHex direct-entry admission — 2026-08-25

The BinHex parser now returns `CL_ENULLARG` for a null context while retaining
the explicit incomplete `CL_EPARSE` result for a recognized layer without an
input fmap. The dedicated production-linked `binhex_map` case covers both
states; full BinHex corpus, sanitizer, materialized large-file, production-CVD,
service, and Sonic1 qualification remain open.

## ARJ header-entry admission — 2026-08-25

`cli_unarj_header_check()` now distinguishes a null parser context
(`CL_ENULLARG`) from a recognized ARJ layer without an input fmap
(`CL_EPARSE` with sticky incomplete state), while retaining `CL_ENULLARG` for
a missing output-size destination. The dedicated production-linked `arj_map`
case covers all three boundaries; full ARJ/ARJ-SFX corpus, sanitizer,
materialized large-file, production-CVD, service, and Sonic1 qualification
remain open.

## PowerPoint VBA helper context admission — 2026-08-25

The PowerPoint VBA extraction helper now rejects a null context before
temporary-directory creation, iterator access, or cleanup, while preserving a
zero optional temporary-reservation result. The dedicated production-linked
`ppt_entry` case passes with `/dev/null`; full OOXML/PowerPoint corpus,
sanitizer, materialized large-file, production-CVD, and Sonic1 qualification
remain open.

## UUEncode direct-entry admission — 2026-08-25

The UUEncode helper now distinguishes a null parser context from a recognized
layer whose input fmap is unavailable. Null contexts return `CL_ENULLARG`;
missing fmaps mark the scan incomplete with the explicit `UUencoded input map
is unavailable` reason and return `CL_EPARSE`, preventing the helper from
entering the deadline or line-reader paths with invalid state. The direct-entry
regression is compiled into the production-linked test harness; full UUEncode
corpus, sanitizer, materialized large-file, production-CVD, and Sonic1
qualification remain open.

## XAR direct-entry admission — 2026-08-25

The XAR direct parser now returns `CL_ENULLARG` for a null context while a
recognized layer with no input fmap remains an explicit `CL_EPARSE` with sticky
incomplete state. The dedicated production-linked `xar_map` case covers both
admission states; TOC-root closure, XAR corpus, sanitizer, materialized
large-file, production-CVD, service, and Sonic1 qualification remain open.


## HWPML missing-map entry classification — 2026-08-25

The HWPML direct parser now distinguishes a null parser context from a
recognized HWPML layer whose input fmap is unavailable. The former remains
`CL_ENULLARG`; the latter marks the scan incomplete with the explicit `HWPML
input map is unavailable` reason and returns `CL_EPARSE`. The dedicated
production-linked `hwpml_map` case passes with the sticky reason, and source
and capability-manifest guards cover the boundary. Full HWPML/XML corpus,
sanitizer, materialized large-file, production-CVD, and Sonic1 qualification
remain open.

## InstallShield missing-map confirmed-entry classification — 2026-08-25

The confirmed InstallShield MSI and legacy extraction entries now distinguish
null parser contexts from recognized layers whose input fmap is unavailable.
Null contexts remain `CL_ENULLARG`; missing fmaps mark the scan incomplete
with explicit `InstallShield MSI input map is unavailable` or
`InstallShield input map is unavailable` reasons and return `CL_EPARSE`. The
weak MSI header-admission helper remains non-confirming. The dedicated
production-linked `ishield_map` case passes both entries, and source and
capability-manifest guards cover the boundary. Full InstallShield/CAB corpus,
sanitizer, materialized large-file, production-CVD, and Sonic1 qualification
remain open.

## SIS missing-map entry classification — 2026-08-25

The SIS direct parser now distinguishes a null parser context from a
recognized SIS layer whose input fmap is unavailable. The former remains
`CL_ENULLARG`; the latter marks the scan incomplete with the explicit `SIS
input map is unavailable` reason and returns `CL_EPARSE`. The dedicated
production-linked `sis_map` case passes with the sticky reason, and source and
capability-manifest guards cover the boundary. Full SIS corpus, sanitizer,
materialized large-file, production-CVD, and Sonic1 qualification remain open.

## 7-Zip missing-map confirmed-entry classification — 2026-08-25

The confirmed 7-Zip parser now distinguishes a null parser context from a
recognized 7-Zip layer whose input fmap is unavailable. The former remains
`CL_ENULLARG`; the latter marks the scan incomplete with the explicit `7-Zip
input map is unavailable` reason and returns `CL_EPARSE`. The weak header
admission probe remains non-confirming. The dedicated production-linked
`7z_map` case passes with the sticky reason, and source and capability-manifest
guards cover the boundary. Full 7-Zip/BCJ2 corpus, sanitizer, materialized
large-file, production-CVD, and Sonic1 qualification remain open.

## AutoIt missing-map confirmed-entry classification — 2026-08-25

The confirmed AutoIt parser entry now distinguishes a null parser context from
a recognized AutoIt layer whose input fmap is unavailable. The former remains
`CL_ENULLARG`; the latter marks the scan incomplete with the explicit `AutoIt
input map is unavailable` reason and returns `CL_EPARSE`. The weak header
admission helper remains a non-confirming probe. The dedicated
production-linked `autoit_map` case passes with the sticky reason, and source
and capability-manifest guards cover the boundary. Full AutoIt corpus,
sanitizer, materialized large-file, production-CVD, and Sonic1 qualification
remain open.

## XDP missing-map entry classification — 2026-08-25

The XDP direct parser now distinguishes a null parser context from a
recognized XDP layer whose input fmap is unavailable. The former remains
`CL_ENULLARG`; the latter marks the scan incomplete with the explicit `XDP
input map is unavailable` reason and returns `CL_EPARSE`. The dedicated
production-linked `xdp_map` case passes with the sticky reason, and source and
capability-manifest guards cover the boundary. Full XDP/XML corpus,
sanitizer, materialized large-file, production-CVD, and Sonic1 qualification
remain open.

## DMG missing-map entry classification — 2026-08-25

The DMG direct parser now distinguishes a null parser context from a
recognized DMG layer whose input fmap is unavailable. The former remains
`CL_ENULLARG`; the latter marks the scan incomplete with the explicit `DMG
input map is unavailable` reason and returns `CL_EPARSE`. The dedicated
production-linked `dmg_map` case passes with the sticky reason, and source and
capability-manifest guards cover the boundary. Full DMG corpus, sanitizer,
materialized large-file, production-CVD, and Sonic1 qualification remain open.

## MBR/GPT missing-map entry classification — 2026-08-25

The partition dispatch boundary now distinguishes null contexts from
recognized MBR/GPT layers whose input fmap is unavailable. MBR's check and
scan entry points and GPT scanning preserve `CL_ENULLARG` for a null context;
missing fmaps mark the layer incomplete with explicit `MBR input map is
unavailable` or `GPT input map is unavailable` reasons and return `CL_EPARSE`.
The dedicated production-linked `partition_map` case passes both families,
including both MBR entry points, and source and capability-manifest guards
cover the boundary. Complete partition corpus, sanitizer, materialized
large-file, production-CVD, and Sonic1 qualification remain open.

## HWPOLE2 missing-map entry classification — 2026-08-25

The HWPOLE2 parser now distinguishes a null parser context from a recognized
HWPOLE2 layer whose input fmap is unavailable. The former remains
`CL_ENULLARG`; the latter marks the scan incomplete with the explicit
`HWPOLE2 input map is unavailable` reason and returns `CL_EPARSE`. The
dedicated production-linked `hwpole2_map` case passes with the sticky reason,
and source and capability-manifest guards cover the boundary. Full
HWPOLE2/OLE corpus, sanitizer, materialized large-file, production-CVD, and
Sonic1 qualification remain open.

## APM missing-map entry classification — 2026-08-25

The APM parser now distinguishes a null parser context from a recognized APM
scan whose input fmap is unavailable. The former remains `CL_ENULLARG`; the
latter marks the scan incomplete with the explicit `APM input map is
unavailable` reason and returns `CL_EPARSE`, preventing a recognized parser
from being treated as an ordinary null-argument failure. The dedicated
production-linked `apm_map` case passes with the sticky reason, and source and
capability-manifest guards cover the boundary. Full APM corpus, sanitizer,
materialized large-file, production-CVD, and Sonic1 qualification remain open.

## PE direct-entry map admission — 2026-08-25

The PE direct scanner checked for a null context but dereferenced the current
layer fmap immediately afterward. It now returns `CL_EPARSE` with sticky
incomplete state for a recognized layer with no input map while retaining
`CL_ENULLARG` for a null context. The isolated production-linked `pe_map`
regression covers both boundaries. Compiled PE corpus, sanitizer, production
CVD, materialized large-file, and Sonic1 qualification remain release gates.

## OLE10 null-context admission — 2026-08-25

The OLE10 embedded-object helper could accept a null context through its
descriptor validation and later dereference the context during temporary
admission for a valid descriptor. It now returns `CL_ENULLARG` before any
descriptor processing; the isolated `ole10_entry` regression exercises a valid
descriptor with a null context. OLE corpus, sanitizer, and Sonic1 qualification
remain release gates.

**Logical bytecode dispatch preflight.** `cli_bytecode_runlsig()` now validates
the scan context, bytecode table, one-based index, logical-signature match
arrays, and fmap before forming `all_bcs[bc_idx - 1]`. The focused bytecode
regression covers null-table and zero-index calls, preventing malformed
signature metadata from reaching undefined pointer arithmetic before the
large-file ABI admission checks. Independently compiled fixture,
interpreter/JIT, and supported-build qualification remain open.

**YARA matcher-work accounting.** YARA-compatible logical roots can read
integer fields from the current fmap after the raw matcher pass. Each root now
charges one bounded fmap-length pass to `MaxMatcherWork`, and a rejected charge
marks the scan incomplete and non-cacheable before YARA execution. The focused
matcher regression covers both the admitted and exhausted-budget paths; full
rule, production-signature, sanitizer, and large-file qualification remain
open.

## XAR unsupported member encodings — 2026-08-23

An explicit XAR `<encoding>` element with an unknown media type, or without a
`style`, was previously treated as an uncompressed member. The scanner could
therefore copy encoded bytes into a child and report clean without inspecting
the required decoded content. Those declarations now return `CL_EUNPACK`, mark
the layer incomplete, and remain non-cacheable; absent `<encoding>` continues
to mean the format-defined uncompressed representation, while the recognized
gzip, bzip2, LZMA, XZ, and octet-stream styles retain their existing paths. A
focused unsupported-encoding regression and static source guards cover the
change; compiled XAR corpus, sanitizer, and Sonic1 qualification remain open.

## HFS+ compressed-resource handoff failures — 2026-08-23

HFS+ compressed-resource processing previously returned seek, decoder, or
temporary-output errors without identifying the required child inspection as
incomplete. Resource-map/index/data seeks, block reads, decoder
initialization/finalization, compressed metadata validation, fork writes, and
inline compressed output now record specific sticky-incomplete reasons before
returning. This keeps malformed or partially materialized compressed children
non-cacheable instead of allowing parser status reconciliation to expose a
clean result. Static source guards pass; compiled HFS+ fault injection,
sanitizer, corpus, and supported-build Sonic1 qualification remain open.

## HFS+ metadata and node format failures — 2026-08-23

The HFS+ tree-header, catalog, attribute-tree, extent, and node-coordinate
validation paths previously returned format or allocation errors that relied
only on the generic outer-parser fallback. They now record parser-specific
sticky-incomplete reasons, including unsupported ExtentOverflow node lookup,
before returning. The top-level null-context path also returns directly
without dereferencing an invalid context. Static source guards pass; compiled
malformed-volume and allocation fault injection, sanitizer, corpus, and
supported-build Sonic1 qualification remain open.

## OLE2 property-tree admission failures — 2026-08-23

OLE2 property-tree recursion/file/worklist limits, JSON timeout, scan-size
admission, invalid header magic, first-data-block geometry, and property or
extracted-file tracking allocation failures now mark required inspection
incomplete before returning. This prevents a confirmed OLE2 layer from being
reconciled as clean after those mandatory walks stop early. Static source
guards pass; compiled OLE2 limit/allocation fault injection, sanitizer,
corpus, and supported-build Sonic1 qualification remain open.

## ELF section metadata allocation failures — 2026-08-23

ELF32 and ELF64 section parsing allocated native metadata arrays after the
working section table; those allocations could return `CL_EMEM` without
marking the required section inspection incomplete. Both native metadata
allocation failures now record sticky incomplete state. Static source guards
pass; compiled ELF allocation fault injection, sanitizer, corpus, and
supported-build Sonic1 qualification remain open.

## HFS+ non-empty fork block admission — 2026-08-23

`hfsplus_scanfile()` previously returned success for a fork with a non-zero
logical size and zero declared allocation blocks, skipping the required fork
contents. Such a fork now returns `CL_EFORMAT` and marks the layer incomplete;
the existing HFS+ fork regression covers the boundary. Compiled HFS+ corpus,
sanitizer, and supported-build Sonic1 qualification remain open.

## UDF file-set descriptor completeness — 2026-08-23

The UDF descriptor walk previously treated a non-file-set descriptor after the
anchor as an optional omission and continued into file-list indexing. A
structurally incomplete volume could therefore bypass the required file-set
boundary and reach a clean result when its remaining lists happened to look
consistent. The accepted sequence now requires a file-set descriptor; a
wrong in-range tag is `CL_EPARSE`, while callback and out-of-map failures keep
their existing `CL_EREAD`/`CL_EPARSE` distinction. A focused synthetic
regression covers the missing-file-set case. Compiled UDF corpus, sanitizer,
and supported-build Sonic1 qualification remain open.

**Logical bytecode-reference admission.** `lsig_eval()` now validates the
referenced bytecode table and one-based entry before forming its indexed
pointer. A missing entry marks the current layer incomplete and non-cacheable
and returns `CL_EPARSE`; the malformed logical-signature regression covers this
fail-visible path. Full logical-expression, mixed-ABI, production-signature,
and supported-build qualification remain open.

**ISO9660 block-coordinate arithmetic.** The ISO block reader now validates
its fmap base window, computes logical/absolute offsets in 64-bit arithmetic,
and rejects directory-record block-coordinate overflow before reading. The
existing truncated-directory and unsupported-layout regressions continue to
cover the fail-visible reader path; full ISO corpus, sanitizer, and
supported-build qualification remain open.

## Verdict

The conservative headline in audit.md — production release remains blocked — is correct. Many of its narrower raw-matcher, cache-width, fmap-aging, exact-boundary, and limit-propagation findings are also supported by the current source.

The remediation and closure claims are not reliable enough for release use, however. The current tree still contains:

- a deterministic default-path HTML whole-scan bypass above 40 MiB;
- multiple parser paths that scan only a decoded prefix, skip required container inspection, or normalize a parser failure to clean;
- whole-input Rust parser requests that can prefault and lock as much as 32 GiB;
- an exported API that reads beyond a one-byte stack object;
- remaining 32-bit coordinates/counters in large-file paths;
- an attacker-controlled undefined shift and possible zero divisor in the 64-bit Mach-O parser; and
- evidence tooling that does not cryptographically or semantically bind the tested engine and sanitizer instrumentation to the reported source revision.

Accordingly, several audit.md statements are false as written, especially the blanket assertions at lines 35–41 and the closure rows at lines 76, 80, 83, 85, 90, and 95. The later “current-source” and “production-CVD/deep-parser” appendices do not repair those source defects and conflict with the report’s own executive status.

## Scope and confidence

This review traced return values from the format parsers through cli_scan_result_should_halt(), final public reconciliation, and clean-cache eligibility. That distinction matters:

- cli_mark_scan_incomplete() is the mechanism that sets sticky incomplete state and marks containing fmaps non-cacheable (libclamav/scanners.c:4432–4478).
- Without that state, cli_scan_result_should_halt() explicitly normalizes CL_EFORMAT, CL_EPARSE, CL_EREAD, CL_EUNPACK, and unlisted parser errors to CL_SUCCESS (libclamav/scanners.c:4907–4919).
- Final reconciliation only recovers a non-clean result when sticky incomplete state was actually set (libclamav/scanners.c:6725–6735).

The findings below are therefore not based merely on a parser returning an error. Each fail-open finding identifies the missing sticky state or an earlier literal-success return.

The workspace has no .git directory, so the commits named in audit.md cannot be resolved or compared in this delivery. Before replacing audit1.md, an aggregate SHA-256 over the sorted SHA-256 records for every regular file except audit1.md was:

    e2929f6308a020940c74678491d8b2082f139975876fadc7e3a216152581249f

The same aggregate was obtained after writing this report, confirming that no other regular workspace file changed during the audit.

This review did not dynamically reproduce the triggers. Findings marked as operational require a read, write, allocation, or loader failure; the control flow and resulting status are nevertheless explicit in source.

## Findings summary

| ID | Severity | Finding | Primary audit.md claim affected |
|---|---|---|---|
| F-01 | Critical | Default HTML cap can bypass both normalization and raw malware matching | 6–8, 35–41 |
| F-02 | High | Metadata hash read failure becomes clean before scanning starts | 76 |
| F-03 | High | PDF Flate/LZW accepts and scans partial decoder output | 85, 191–197, 608–615 |
| F-04 | High | HWP/HWPML raw-deflate errors scan a partial prefix as complete | 85, 90 |
| F-05 | High | Truncated ZIP variable local-header fields can disappear into a clean result | 79 |
| F-06 | High | XZ, CAB, and CHM parser failures still normalize clean; PE has a literal-clean read failure | 76, 80, 81, 90 |
| F-07 | High | OneNote, LHA/LZH, and ALZ request and lock the complete fmap | 6–8, 40–43, 76–77 |
| F-08 | High | Exported cl_fmap_set_hash() performs an out-of-bounds stack read | 76–77 |
| F-09 | High | 64-bit Mach-O alignment permits undefined shift/divisor behavior | 83 |
| F-10 | Medium-High | Script, JPEG, and Windows XZ paths retain 32-bit large-file state | 6–8, 35–41 |
| F-11 | Medium-High | fmap_dump_to_file() reports a partial RAR staging copy as success | 76, 90 |
| F-12 | Medium-High | Public/protocol limit paths can exceed or disable the advertised ceiling | 42, 78, 94 |
| F-13 | High | Runtime evidence does not bind source, launcher, loaded engine, or sanitizer instrumentation | 95, 1315–1323 |
| F-14 | High | The prescribed acceptance workflow cannot enforce the report’s own acceptance requirements | 286–371 |
| F-15 | High | The audit is internally contradictory and overstates a tiny production-CVD matrix | 19–30, 286–309, 373–386, 1315–1391 |
| F-16 | Medium | OneNote dispatch tests the SIS archive bit instead of the OneNote document bit | 47–55, 77 |

## Detailed findings

### F-01 — Critical: default HTML cap can bypass both normalization and raw malware matching

The default maximum HTML normalization size is 40 MiB (libclamav/default.h:45–48). For a recognized CL_TYPE_HTML input larger than that:

1. cli_scanhtml() returns CL_SUCCESS immediately and does not call cli_mark_scan_incomplete() (libclamav/scanners.c:2725–2740).
2. HTML is dispatched before the ordinary raw scan (libclamav/scanners.c:5539–5542).
3. The ordinary raw scan is deliberately skipped for HTML when HTML parsing and DOC_CONF_HTML_SKIPRAW are enabled (libclamav/scanners.c:5832–5835).
4. HTML and HTMLSKIPRAW are both enabled in the default dynamic configuration (libclamav/dconf.c:113–118).

In the ordinary non-sdb path, a padded 40 MiB-plus HTML file therefore receives neither normalized HTML scanning nor raw signature matching. The parser returns clean without sticky incomplete state, so the layer is also eligible for the clean cache if metadata collection is not active and the later cache hash succeeds.

This is a deterministic, content-controlled bypass far below the fork’s claimed 32 GiB ceiling. It directly disproves audit.md lines 38–41, which say necessary fixed-width/capped inspection fails visibly rather than cleanly. The shipped option help even says that oversized HTML “will not be normalized or scanned” (common/optparser.c:498), confirming that this is current behavior rather than an unreachable branch.

The August 15 HTML follow-up in audit.md lines 1035–1043 addresses only mapped-input read failure. Other normalizer failures remain ignored:

- cli_scanhtml() discards the boolean returned by html_normalise_map*() (libclamav/scanners.c:2756–2767).
- allocator and output-open failures return false without marking the scan incomplete (libclamav/htmlnorm.c:788–823).
- html_output_flush() and html_output_str() ignore cli_writen() results (libclamav/htmlnorm.c:317–347).

Those operational failures can leave absent or partial normalized files; the caller can still return clean while raw HTML scanning remains disabled.

Required correction: an enabled HTML pass that is skipped or fails must set sticky incomplete state, remain non-cacheable, and return a visible non-clean result, or the engine must perform a complete raw fallback. Add a default-configuration regression using a recognized HTML file at MaxHTMLNormalize+1 and fault-injection tests for normalization allocation/open/write failures.

### F-02 — High: metadata hash read failure becomes clean before scanning starts

When metadata collection is enabled, cli_magic_scan() calculates hashes before cache lookup, parser dispatch, and raw matching (libclamav/scanners.c:5254–5287). If fmap_get_hash() fails or returns no digest, the caller does this:

    status = CL_SUCCESS;
    goto done;

That branch is at libclamav/scanners.c:5288–5293. The lower-level hash reader correctly returns CL_EREAD when any 10 MiB mapped window cannot be obtained (libclamav/fmap.c:1422–1429), but the caller discards it and never calls cli_mark_scan_incomplete().

A file truncated or changed during scanning, a real mapped I/O failure, or a failing public-fmap pread callback can therefore cause the scanner to skip all subsequent file-content matching and parsing and return clean. Metadata collection prevents this result from being added to the clean cache (libclamav/cache.c:674–679), so the demonstrated impact is a false-clean verdict, not cache poisoning.

This contradicts audit.md line 76. Bounded hash windows are useful, but “read failures return CL_EREAD” is not a valid end-to-end disposition when the immediate caller converts that error to success before any scan.

### F-03 — High: PDF Flate/LZW accepts and scans partial decoder output

The PDF Flate filter loops only while zlib reports Z_OK and compressed input remains (libclamav/pdfdecode.c:724–746). It then accepts both Z_STREAM_END and plain Z_OK as completion (lines 751–759). Z_OK with no input left means the stream need not have reached its terminal state.

More seriously, if zlib returns an actual stream/data/memory error after producing at least one byte, the code only marks the object BAD_FLATE and leaves rc as CL_SUCCESS (lines 761–781). It installs the partial output into the token (lines 787–805).

The LZW filter has the same behavior: input exhaustion with LZW_OK is accepted, and decoder errors after any output leave rc successful and install the partial buffer (libclamav/pdfdecode.c:1017–1049, 1060–1092, 1100–1117).

pdf_decodestream_internal() increments the successful-filter count and writes/scans that buffer as decoded content (libclamav/pdfdecode.c:352–374). The public wrapper marks the layer incomplete only when the returned status is CL_EPARSE (lines 190–193), which these paths never produce.

Trigger: a recognized PDF Flate or LZW stream that emits a benign prefix and then truncates, exhausts input without decoder end, or produces a decoder error.

Impact: only the decoded prefix is scanned; content requiring the remaining compressed stream/filter chain is omitted while the PDF-specific pass can return clean. Raw PDF bytes may still be pattern-matched, but that does not substitute for inspection of compressed content.

This contradicts audit.md line 85 and shows that the reported decode-error/empty-filter fixes at lines 608–615 and 810–820 are narrower than the closure wording.

### F-04 — High: HWP/HWPML raw-deflate errors scan a partial prefix as complete

decompress_and_callback() reads and inflates HWP raw-deflate content at libclamav/hwp.c:118–154. A non-OK/non-END decoder result is fatal only when no output was produced. Once any output exists, the code logs “Scanning what was decompressed” and continues (lines 158–167).

It then scans the partial tempfile and overwrites the decompression failure with the nested scan result (lines 169–179). Plain Z_OK at input exhaustion is also allowed to reach scanning even though Z_STREAM_END was not observed. A clean nested prefix therefore becomes the parser result with no sticky incomplete state.

This helper is used for compressed HWP3 content (libclamav/hwp.c:1919–1922) and compressed HWPML attachments (lines 2192–2213). HWP3’s finalizer only marks incomplete when the helper returns non-success (lines 1929–1931), so a clean partial-prefix scan evades it.

Configured limit failures are not the issue here; cli_checklimits() has its own sticky handling. The flaw is decoder error or missing terminal state after partial output. It contradicts the broad HWP/HWPML claims at audit.md lines 85 and 90.

### F-05 — High: truncated ZIP variable local-header fields can disappear into a clean result

parse_local_file_header() returns CL_EPARSE when:

- a declared local filename is at or beyond the remaining map (libclamav/unzip.c:1413–1416);
- a required ZIP64 extra field exceeds the remaining bytes (lines 1490–1493); or
- the general local extra field is at or beyond the remaining bytes (lines 1570–1573).

Unlike the fixed-header and member-data branches, these three branches do not call cli_mark_scan_incomplete().

The bytewise local-header indexer deliberately treats CL_EPARSE and CL_EFORMAT as recoverable probe results and continues (libclamav/unzip.c:2292–2306). It finally returns CL_SUCCESS even if every candidate was discarded (lines 2364–2366).

A recognized ZIP of at least one central-header length, with no central directory and a complete 30-byte local fixed header whose filename/extra length runs off the input, takes the local-header fallback (libclamav/unzip.c:2883–2904), produces zero records, and sets status to CL_SUCCESS (lines 2926–2927). Because no sticky marker was set, final policy cannot recover a non-clean result.

Embedded ZIP’s cli_unzip_single() also returns the unmarked parse result (libclamav/unzip.c:3115–3140), which the common policy normalizes to clean.

Impact: compressed member content is not extracted or scanned, yet the container-specific result can be clean. This directly contradicts audit.md line 79, which says short local headers are incomplete/non-clean.

### F-06 — High: XZ, CAB, and CHM parser failures still normalize clean; PE has a literal-clean read failure

These are separate manifestations of the same missing-sticky-state error:

**XZ.** cli_scanxz() detects input exhaustion before XZ_STREAM_END, logs a premature end, and returns CL_EFORMAT without marking incomplete (libclamav/scanners.c:1544–1554). XZ is dispatched at lines 5499–5501. Common reconciliation then converts CL_EFORMAT to CL_SUCCESS. A valid XZ prefix followed by truncation can skip the decompressed suffix cleanly, contrary to audit.md line 90.

**CAB/CHM.** The libmspack CAB and CHM bridges return CL_EFORMAT when a recognized archive cannot be opened, but do not mark incomplete (libclamav/libmspack.c:457–461 and 585–589). Dispatch occurs at libclamav/scanners.c:5534–5536 and 5584–5586. The August 15 follow-up at audit.md lines 763–775 fixed post-extraction CL_EOPEN handling, not initial archive-open rejection. Audit.md line 80 overstates closure.

**PE operational read failure.** If fmap_readn() fails at the already parsed PE entry point, cli_scanpe() destroys its state and returns literal CL_CLEAN (libclamav/pe.c:2863–2867). This skips later overlay, bytecode, import, and unpacker work. It is an operational I/O route rather than a simple malformed-header trigger, but it remains incompatible with the end-to-end fmap/PE read-failure claims at audit.md lines 76 and 81.

In each case raw container bytes may have been scanned. The false-clean concerns the required decompression or format-specific inspection that makes container scanning meaningful.

### F-07 — High: OneNote, LHA/LZH, and ALZ request and lock the complete fmap

The Rust FMap::need_off() wrapper calls the C fmap need function with lock=1 and returns a plain Rust slice (libclamav_rust/src/fmap.rs:65–88). It has no unneed call, guard, or Drop implementation.

Three parsers request the entire input in one call:

- OneNote: libclamav_rust/src/scanners.rs:101–125, especially line 110;
- LHA/LZH: lines 156–174, especially line 165; and
- ALZ: lines 408–436, especially line 423.

They are dispatched directly from libclamav/scanners.c:5433–5446.

For descriptor-backed maps, fmap_readpage() prefaults every requested page and applies page locks (libclamav/fmap.c:723–756, 845–859). Locked pages are not available to the bounded aging policy. With MaxFileSize raised toward 32 GiB, a recognized file can therefore drive resident input toward the complete file size before parsing, precisely the condition the target at audit.md lines 6–8 and 40–43 says must not occur.

The failure disposition compounds the resource flaw. need_off() errors cause the Rust scanners to return CL_ERROR without marking incomplete. CL_ERROR is not in the critical halt list and falls through to the default success normalization at libclamav/scanners.c:4915–4919. Attachments/member content requiring these parsers can thus be skipped cleanly after mapping failure.

The sparse raw runtime gate does not exercise these paths. The report’s parser inventory also omits them, which is a material scope gap in a fork whose main change is maximum input size.

### F-08 — High: exported cl_fmap_set_hash() performs an out-of-bounds stack read

The public header declares:

    cl_fmap_set_hash(const cl_fmap_t *map, const char *hash_alg, char hash)

See libclamav/clamav.h:683–695. The implementation has the same scalar-char signature and passes &hash to the internal setter (libclamav/fmap.c:1643–1665).

The internal fmap_set_hash() then copies cli_hash_len(type) bytes from that pointer (libclamav/fmap.c:1314–1337). Supported digest lengths are 16, 20, or 32 bytes, but the source object is one byte. Every successful public call therefore invokes undefined behavior and reads 15–31 bytes beyond the stack object.

The symbol is exported in libclamav/libclamav.map:80. A later cl_fmap_get_hash() can expose the bogus stored digest as hex, creating a potential library-stack disclosure to the API caller as well as corrupt hash state. No in-tree caller was found, which limits ordinary scanned-file reachability; it does not make an exported memory-unsafe ABI valid.

This was missed by the audit’s fmap/cache/FFI coverage and contradicts the broad fixed disposition at audit.md lines 76–77.

### F-09 — High: 64-bit Mach-O alignment permits undefined shift/divisor behavior

The 64-bit Mach-O section parser reads attacker-controlled section64.align and computes:

    section64.align = 1 << EC32(section64.align, conv);

It then uses that value as a modulo divisor (libclamav/macho.c:398–410). There is no exponent bound. Shifting a signed int by 31 or by at least its width is undefined; a resulting zero also makes the following modulo undefined.

The 32-bit sibling explicitly rejects alignment exponents of 32 or more before the identical calculation (libclamav/macho.c:413–429), demonstrating the missing 64-bit check.

Trigger: a recognized 64-bit Mach-O segment with a malicious section alignment exponent.

Impact: sanitizer failure and a plausible process/worker crash before the malformed-file macros can make the result fail-visible. This contradicts audit.md line 83’s statement that malformed Mach-O header/load-command inspection is closed.

### F-10 — Medium-High: script, JPEG, and Windows XZ paths retain 32-bit large-file state

**Script normalization.** cli_scanscript() declares its cumulative normalized match offset as uint32_t (libclamav/scanners.c:2855–2865). It passes that value to cli_scan_buff(), whose offset parameter is already uint64_t (libclamav/matcher.h:311), and adds each output chunk back into the 32-bit value (libclamav/scanners.c:3009–3016). If MaxScriptNormalize is raised above 4 GiB, normalized match coordinates wrap, affecting absolute/logical signature evaluation. With the default 20 MiB cap, the function instead returns CL_SUCCESS without marking incomplete for larger scripts (libclamav/scanners.c:2890–2894). Raw script bytes are still scanned, but normalization-dependent detections are silently skipped. Both outcomes conflict with audit.md lines 35–41.

**JPEG.** cli_parsejpeg() stores its map offset in unsigned int (libclamav/jpeg.c:325–333), compares it to size_t map length, and repeatedly adds attacker-controlled 16-bit segment lengths (lines 366–429). Above 4 GiB the coordinate wraps and can revisit earlier bytes, misparse, or loop. No time-limit check exists in that loop. This parser runs only when image parsing and broken-media heuristics are enabled, but the August 15 JPEG review at audit.md lines 995–1003 addressed truncation and missed the large-coordinate defect.

**XZ on 64-bit Windows.** cli_scanxz() tracks total decoded output in unsigned long int (libclamav/scanners.c:1510–1518). On LLP64 Windows that is 32-bit, wraps after 4 GiB, and is the value passed to cli_checklimits() at lines 1567–1585. Unix LP64 builds are not affected. On Windows, the fork’s raised limits can therefore be bypassed for XZ temp output.

These paths show that the raw matcher’s 64-bit cleanup was not followed by a complete audit of parser-local coordinates and counters.

### F-11 — Medium-High: fmap_dump_to_file() reports a partial RAR staging copy as success

fmap_dump_to_file() copies in BUFSIZ windows using fmap_need_off_once_len() (libclamav/fmap.c:1267–1288). That helper reports len=0 both at ordinary EOF and when the underlying mapped read fails (libclamav/fmap.h:390–401).

The dump loop exits whenever len becomes zero, even when bytes_remaining is nonzero. It then exposes the tempfile and unconditionally returns CL_SUCCESS (libclamav/fmap.c:1290–1296). A failed rewind is only logged.

RAR uses this helper for memory-backed, nested, inaccessible, or unprivileged maps and as its filename-open fallback (libclamav/scanners.c:571–607). UnRAR can therefore receive a partial temporary copy as though it were the complete fmap. Recent RAR parser hardening may cause many such copies to fail later, but it does not repair the false-success helper contract or guarantee sticky incomplete state.

This weakens audit.md lines 76 and 90. The dump helper must distinguish clean EOF after the requested byte count from an unavailable mapped window and must reject a nonzero remainder.

### F-12 — Medium-High: public/protocol limit paths can exceed or disable the advertised ceiling

**clamd INSTREAM staging.** StreamMaxLength is a generic SIZE64 option (common/optparser.c:334). The special zero-to-32-GiB conversion and greater-than-32-GiB rejection apply only to the option named MaxFileSize (common/optparser.c:1361–1373 and 1587–1596). StreamMaxLength 0 therefore becomes the generic numerical limit, and an explicit value above 32 GiB is also accepted.

clamd copies that value directly into the INSTREAM quota (clamd/session.c:613–620) and writes chunks to a tempfile until the quota is consumed (clamd/server-th.c:817–899). The engine may later reject the object at MaxFileSize, but clamd can first accept and materialize far more than 32 GiB. This is a disk/resource-DoS boundary and contradicts the blanket upper-bound wording at audit.md line 42.

**Public engine setters.** cl_engine_set_num() retains a TODO for destination overflow (libclamav/others.c:695–704). CL_ENGINE_MAX_SCANSIZE assigns signed long long directly to uint64_t (lines 706–708), so a negative value becomes near-unlimited. CL_ENGINE_MAX_SCANTIME narrows directly to uint32_t (lines 864–866); 4294967296 becomes zero, which disables the timer in scan_common() (libclamav/scanners.c:6460–6469). Normal command-line parsing is more constrained, but the public API does not support audit.md line 78’s unconditional claim.

### F-13 — High: runtime evidence does not bind source, launcher, loaded engine, or sanitizer instrumentation

The runtime gate obtains a clean source commit from one root (tools/largefile_runtime_gate.sh:147–168), but accepts the scanner path independently and merely copies the adjacent CMakeCache.txt (lines 170–194). It does not verify CMAKE_HOME_DIRECTORY, a build provenance record, or that the binary was produced from the recorded root/commit.

The workflow enables the static library but leaves shared libraries enabled (CMakeOptions.cmake:110–115). clamscan links ClamAV::libclamav, which aliases the shared library when shared builds are enabled (clamscan/CMakeLists.txt:39–42; libclamav/CMakeLists.txt:403–405, 529). The gate hashes only the clamscan launcher, CMakeCache.txt, Cargo.lock, and scripts (tools/largefile_runtime_gate.sh:170–235). It neither copies nor hashes libclamav.so, Rust/UnRAR libraries, nor the resolved runtime dependency set. It also runs the original build-tree executable rather than the copied artifact (lines 259, 287, 317, and 365).

Thus a stale or substituted loaded engine can perform the scan while the copied launcher’s hash and manifest still verify. A real single-job workflow gives contextual assurance, but the artifact/verifier does not preserve or prove that relationship.

The sanitizer path has the same semantic gap. Any executable named by CLAMAV_SANITIZER_CLAMSCAN is accepted; exit zero plus absence of diagnostic text becomes sanitizer=pass (tools/largefile_runtime_gate.sh:425–437). The verifier checks only the copied file’s hash, the pass marker, and diagnostic-text absence (tools/largefile_runtime_evidence_check.sh:250–286). It never verifies ASan/UBSan symbols, runtime dependencies, or instrumentation.

The evidence-check control test intentionally demonstrates structural rather than semantic validation: plain text files named as synthetic release and sanitizer scanners are accepted in its positive fixture (tools/largefile_runtime_evidence_check_test.sh:18–20, 110–111).

This does not prove the reported Sonic1 scanner was substituted. It proves that audit.md line 95 and lines 1315–1323 claim stronger source/sanitizer binding than the gate can establish.

### F-14 — High: the prescribed acceptance workflow cannot enforce the report’s own requirements

audit.md lines 295–309 and 382–386 require large clamd/clamdscan/milter transfers, production databases, materialized and cold-cache workloads, deep/malformed/expanding parsers, and resource characterization. The prescribed workflow’s runtime step only runs tools/largefile_runtime_gate.sh against clamscan and the synthetic sparse POC (.github/workflows/cmake.yml:376–393). It has no exact-edge clamd, clamdscan, milter, production-CVD, materialized-file, or cold-cache release gate.

Other enforcement weaknesses:

- “Workers” are independent clamscan processes, not clamd workers or threads (tools/largefile_runtime_gate.sh:345–420).
- The workflow inputs permit arbitrary concurrency levels and budgets (.github/workflows/cmake.yml:18–37). The gate and verifier iterate whatever list is supplied and do not require 1, 2, and 4. A whitespace-only list creates no concurrency iterations and is not rejected (tools/largefile_runtime_gate.sh:36, 345–420; tools/largefile_runtime_evidence_check.sh:18, 328–404).
- Release and sanitizer jobs are separately optional (.github/workflows/cmake.yml:134–136 and 315–317); there is no combined release-decision job requiring both.
- Temporary-space enforcement runs only when CLAMAV_MAX_TEMP_BYTES is set (tools/largefile_runtime_gate.sh:267–280). The workflow does not set it, and the verifier does not require temp_budget=pass.
- The fixed-name “verified” artifact is uploaded before the attestation action (.github/workflows/cmake.yml:229–243 and 395–409). If attestation fails, an artifact already named verified can remain.
- The sanitizer C/C++ flags do not instrument Rust; the workflow explicitly excludes the Rust suite from sanitizer CTest (.github/workflows/cmake.yml:188–196). That limitation is material for the whole-input Rust paths in F-07.

A green run of the documented command at audit.md lines 348–371 therefore cannot establish all conditions that the same report calls mandatory.

### F-15 — High: the audit is internally contradictory and overstates a tiny production-CVD matrix

The executive summary, blocker list, and final verdict say sanitizer, workers 2/4, and production-CVD/deep-parser qualification remain open:

- audit.md:19–30;
- audit.md:95;
- audit.md:286–309; and
- audit.md:373–386.

The August 16 appendices then say current-source sanitizer and worker counts 1/2/4 are closed (audit.md:1315–1323) and “Production-CVD/deep-parser qualification is now closed” (lines 1360–1389). A current audit cannot simultaneously use both dispositions without a revision-specific superseding verdict. The top verdict is tied to bba68110…, while later claims refer to synthetic validation commit 34fc460b… and still later metadata snapshots.

The production-CVD matrix is not a 32 GiB production workload. The cited directory contains:

- 46 files;
- 1,322,291 bytes total; and
- a largest file of 107,520 bytes.

The reported run produced 43 clean rows, three expected parse errors, and zero production-signature detections (audit.md:1376–1387). It demonstrates that the three CVDs load and that this small fixture set completes consistently under two binaries. It does not test a large/materialized input, cold cache, production malware detection, expanding content, concurrency, RSS, page-cache pressure, temporary storage, or latency. It cannot satisfy the earlier workload requirement at audit.md lines 302–309.

Provenance is also not reproducible from this delivery:

- .git is absent, so bba68110…, 34fc460b…, 93c69c…, and 431a310d… cannot be resolved here.
- The remote evidence directories and manifests cited in the appendices are not delivered.
- The reported path-inventory hash binds sorted names, not every file’s content; selected-file hashes do not close that gap.

The audit should be rewritten around one immutable source revision, one superseding status table, and locally/verifiably delivered evidence. Until then, “closed” should be replaced with the exact narrow proposition the evidence proves.

### F-16 — Medium: OneNote dispatch tests the SIS archive bit instead of the OneNote document bit

The OneNote case checks:

    DCONF_ARCH & DOC_CONF_ONENOTE

at libclamav/scanners.c:5433–5435. It should use the document configuration word. DOC_CONF_ONENOTE is 0x400, while 0x400 in the archive word is ARCH_CONF_SIS (libclamav/dconf.h:71–114).

Because both defaults are enabled, ordinary default testing hides the defect. In a tailored configuration:

- disabling SIS can unintentionally disable OneNote attachment extraction; and
- disabling the OneNote document flag does not control this dispatch as intended.

This is a configuration correctness issue and a sign that the C/Rust parser boundary was not fully reviewed despite audit.md’s scope claim.

## Claims that were supported

The flaws above do not invalidate every result in audit.md. Static review supports these important parts:

- BM offsets and sorting use a proper 64-bit comparator and 64-bit storage (libclamav/matcher-bm.c:43–53, 170–217).
- Native matcher sentinel values are distinct 64-bit values, and colliding absolute ranges are rejected (libclamav/matcher.h:260–267; libclamav/matcher.c:505–515).
- Byte-compare window arithmetic and overlap de-duplication are checked (libclamav/matcher-byte-comp.c:520–579).
- PCRE full-map materialization is preceded by the configured contiguous-allocation check, and an oversized required pass marks the scan incomplete (libclamav/matcher.c:100–118, 233–250).
- Exact-size hash signatures use a 64-bit side table at and above the reserved 32-bit boundary (libclamav/matcher-hash.c:201–228, 389–405, 448–475).
- Fmap aging itself uses a persistent bounded cursor, and a failed new page-in rolls back resident-page bookkeeping (libclamav/fmap.c:595–707).
- Cache and stats size fields examined in this review are 64-bit (libclamav/cache.c:56–65, 121–129; libclamav/others.h:211–219).
- Normal configured scan/file/time limit propagation has materially improved and sets sticky incomplete state in the reviewed central helpers (libclamav/others.c:1270–1386).
- The exact 32 GiB MaxFileSize command-line boundary and 32 GiB+1 rejection logic are present in source.

These positives justify retaining the overall “production blocked” verdict rather than discarding the fork. They do not justify the broad “source-fixed” or “qualification closed” labels.

## Required disposition

Before this fork can make a production-ready 32 GiB claim:

1. Treat F-01 as a release stop: an enabled HTML parser must never return clean after skipping all content because of MaxHTMLNormalize or a normalizer failure.
2. Make every required parser/decode failure set sticky incomplete state before common reconciliation. Add focused regressions for PDF partial Flate/LZW, HWP partial deflate, ZIP variable-header truncation, truncated XZ, and CAB/CHM open rejection.
3. Replace OneNote/LHA/ALZ whole-map slices with bounded readers or explicitly fail visibly at a defensible parser cap. Add a real concurrent clamd RSS test against those formats.
4. Correct cl_fmap_set_hash() as an ABI/API defect and run an instrumented public-API regression.
5. Widen the remaining parser-local coordinates/counters and bound the Mach-O alignment exponent before shifting.
6. Make fmap_dump_to_file() prove that the requested byte count was copied and distinguish read error from EOF.
7. Bind evidence to the complete runtime: source revision, build graph, launcher, loaded shared libraries, Rust/UnRAR components, and sanitizer instrumentation. Enforce canonical worker levels and fixed budgets in the verifier.
8. Add mandatory clamd/clamdscan/milter exact-edge, production-CVD detection, materialized/cold-cache, parser-expansion, RSS, latency, and temp-space jobs. Publish the artifact only after successful attestation.
9. Replace the append-only contradictory audit with a single revision-scoped status table. Evidence from a tiny clean fixture matrix should be labeled database-load/compatibility evidence, not production deep-parser qualification.

## Final assessment

The raw 64-bit matching work appears substantial and several central fail-visible mechanisms are well designed. The remaining defects are nevertheless directly in the security boundary that this fork claims to strengthen. In particular, a default recognized HTML file just over 40 MiB can avoid both normalized and raw scanning, and several compressed formats can still turn incomplete decoding into a clean format-specific result.

The current tree should remain non-production and should not be described as providing complete scan coverage through 32 GiB. audit.md’s final conservative verdict should be retained, but its remediation table, current-source closure statements, production-CVD conclusion, and evidence-binding claims require correction.

## HTML normalized metadata allocation propagation — 2026-08-23

The HTML normalizer previously exposed tag-argument insertion as a `void`
helper. Allocation failures could therefore clear or partially construct the
attribute state used for normalized output and phishing URL extraction while
the normalizer still reached its successful completion path. Link-content,
form-data, and text-URL accumulation had the same silent-discard risk.

`html_tag_arg_add()`, tag replacement, and link-content finalization now return
status. The normalizer checks every required internal and phishing-state
allocation, form-data insertion, and copied link-content value; the file-backed
MHTML text-URL extractor checks its insertions as well. Any failure marks the
scan incomplete and prevents a partial normalized layer from being treated as
complete. Normal successful output is unchanged. Compiled allocation-fault,
sanitizer, and broad HTML/MHTML corpus qualification remain release gates.

## Implementation follow-up — 2026-08-16

The findings above were reviewed against the source and the actionable fixes
were applied in the current worktree. The principal changes are:

- HTML normalization now fails visibly when the input exceeds its normalization
  cap or when mapped input/output cannot be completed; metadata hash failures
  remain non-clean.
- PDF Flate/LZW and HWP raw-deflate require decoder completion before any
  partial output is scanned. ZIP variable-header/descriptor truncation,
  XZ/CAB/CHM/PE failures, and JPEG/script normalization failures now preserve
  sticky incomplete state.
- LHA uses bounded `Read + Seek`; ALZ parses through that adapter and streams
  members into quota-accounted spools. OneNote still stages through bounded
  fmap windows and uses an explicit disk-backed mapping for its third-party
  slice API. Input, parser, decoder, CRC, member, mapping, and panic failures
  remain sticky non-clean results; supported-build qualification remains open.
- `cl_fmap_set_hash()` now accepts a digest pointer, with a public SHA-256 API
  regression added. Mach-O 64-bit alignment exponents are bounded before the
  shift, and RAR staging rejects incomplete copies.
- The runtime gate/verifier now require the canonical `1 2 4` worker matrix,
  a temporary-space budget, CMake source-root binding, loaded dependency
  manifests and hashes, sanitizer instrumentation evidence, and successful
  attestation before a verified artifact is uploaded. A combined workflow job
  requires both release and sanitizer gates.
- `audit.md` now has a revision-R2 disposition table that supersedes its older
  closure labels and identifies the remaining service-level qualification work.

Verification completed locally: shell syntax checks, YAML parsing, the source
guard suite, and the synthetic runtime-evidence verifier all pass. A complete
C/Rust build was not claimed because this macOS workspace lacks the Linux
build dependencies and the Rust dependency checkout is unavailable offline.
The remaining mandatory clamd/clamdscan/milter, materialized/cold-cache,
production-CVD, parser-expansion, latency, and RSS qualification jobs remain
open, so the auditor’s conservative production-blocked verdict still stands.

## Independent fix verification — 2026-08-16

This section records an independent read-only verification of the current
worktree after the implementation follow-up above. It supersedes that
follow-up wherever the two disagree. It does not replace the original finding
descriptions, which remain useful for the trigger and impact analysis.

The source snapshot reviewed here contained `audit.md` SHA-256
`e0d91776de4d602c66a163813835f3a4861134a2fc2b642c20098250b0677830`.
The pre-update SHA-256 of this file was
`1205eed5103ad5f9174c87200746a62e0f6f15c6ccf5022ffdb6a781e856de8a`.

### Verification verdict

The patch set is materially improved, but it is not fully correct or fully
verified. Six original findings are source-closed, the Rust whole-input issue
has an explicit bounded policy, seven findings remain partial, and two remain
open end-to-end. The production-blocked verdict remains correct.

| Finding | Verified disposition | Reason |
|---|---|---|
| F-01 | Source closed; exact fault-injection evidence remains | MaxHTMLNormalize skips and HTML/JavaScript normalization output failures now set sticky incomplete state; compiled fault-injection coverage remains a supported-build gate. |
| F-02 | Source closed; exact trigger untested | Metadata hash failure now sets sticky incomplete state and returns a read error. |
| F-03 | Source closed; exact regressions incomplete | Flate/LZW now require a decoder terminal state and discard partial output on error; the extraction caller now preserves `CL_EPARSE` while continuing independent objects; compiled benign-prefix and LZW regressions remain a supported-build gate. |
| F-04 | Source closed; exact trigger untested | HWP raw-deflate now requires `Z_STREAM_END` and does not scan a partial prefix. |
| F-05 | Source closed; exact trigger untested | ZIP variable filename/extra/ZIP64 truncation is sticky and deferred only while valid preceding records are scanned. |
| F-06 | Source closed; exact fault-injection evidence remains | The reported XZ/CAB/CHM-open/PE faults and CAB/CHM decompressor-construction failure now mark incomplete; focused constructor tests are present but require the supported build environment. |
| F-07 | Bounded source policy; runtime qualification open | LHA uses bounded `Read + Seek`; ALZ uses that adapter and streams members to quota-accounted spools; OneNote stages through bounded fmap windows and uses a disk-backed mapping for its slice API. Mapping and concurrent-RSS qualification remain open. |
| F-08 | Source and release ABI transition closed; old-SO compatibility intentionally unsupported | The digest pointer fix is correct for newly compiled callers, and the fork publishes `CURRENT:REVISION:AGE 14:0:0` / SOVERSION 14. Existing binaries linked to the prior SOVERSION are not an in-place compatibility target and must be rebuilt/relinked for this release. |
| F-09 | Source closed; exact trigger untested | Both Mach-O section branches reject alignment exponents at or above 32 before shifting. |
| F-10 | Source closed; exact boundary evidence remains | Script/JPEG/XZ state is widened or range-checked, and normalized-script output/map failures are sticky; compiled multi-GiB and injected-failure coverage remains a supported-build gate. |
| F-11 | Source closed; nested fault-injection evidence remains | Short-copy detection, accessible-slice range validation, and RAR staging incomplete propagation are present. |
| F-12 | Source closed; boundary evidence present | StreamMaxLength, direct setters, and MaxScanTime configuration/CLI parsing use checked full-width values and reject narrowing/overflow. |
| F-13 | Partial | The gate records more provenance, but it still does not create a self-contained or semantic source-to-runtime binding. |
| F-14 | Open; service qualification required | The release/sanitizer deadline contract, canonical worker matrix, provenance, attestation ordering, and mandatory service/workload job are wired and statically checked. The gate remains intentionally unavailable until authorized production fixtures and an exact-outcome oracle are supplied. |
| F-15 | Partial | The R2 supersession language helps, but historical overclaims remain, R2 is not tied to an immutable source revision, and its workflow disposition is incorrect. |
| F-16 | Source closed; exact trigger untested | OneNote dispatch now uses the document configuration word, but tests do not vary the document and archive dynamic-configuration bits independently. |

### V-01 — High: nested RAR staging required an accessible-slice correction

`fmap_dump_to_file()` now rejects a nonzero unread remainder and deletes the
partial tempfile (libclamav/fmap.c:1267–1295). The earlier audit text below
describes the trigger that motivated the correction; the current source uses
the accessible slice length and propagates staging failure to sticky
incomplete state.

The helper receives map-relative `start_offset` and `end_offset` values, but it
validates and clamps them against `map->real_len` rather than the accessible
slice length `map->len` (libclamav/fmap.c:1217–1224). For a duplicated fmap,
`real_len` is `nested_offset + len` (libclamav/fmap.c:263–315), while
`fmap_need_off_once_len()` correctly stops at `map->len`
(libclamav/fmap.h:390–400).

RAR deliberately chooses staging when the current fmap is nested or sliced
and requests the whole map with `end_offset=SIZE_MAX`
(libclamav/scanners.c:571–577, 593–599). A normal nested slice with a nonzero
`nested_offset` therefore copies its accessible `len` bytes, retains an
unread remainder corresponding to the parent offset, deletes the tempfile,
and returns `CL_EREAD`.

`cli_scanrar()` now calls `cli_mark_scan_incomplete()` when either staging call
fails (libclamav/scanners.c:578–581, 599–601). The common result policy thus
cannot normalize the staging failure to a clean result.

The same end-to-end false-clean remains possible for a genuine mapped-read
failure. The existing fmap dump tests use healthy maps, pass
`end_offset=map->len`, and do not assert the helper status
(unit_tests/check_clamav.c:4309–4315, 4368–4372), so they miss both triggers.

The source correction is complete. A supported Linux build should still add
the nested-slice and fault-injected public-scan regressions to close the exact
runtime evidence gap.

### V-02 — High: the acceptance workflow required a deadline-contract correction

The workflow now uses the intended split:

- `CLAMAV_MAX_SCAN_TIME_MS=900000`; and
- `CLAMAV_SANITIZER_MAX_SCAN_TIME_MS=3600000`.

The evidence control test compares both workflow values with the verifier's
fixed deadlines and checks the required production, materialized,
parser-expansion, and oracle inputs. The release job also runs the mandatory
service qualification before attestation and uploads only after its exact
summary checks pass. The remaining blocker is operational: those inputs must
be authorized and present on the dedicated runner.

### V-03 — High operational gap: HTML JavaScript output failures required a status path

The current source closes the status-path defect. `cli_js_output()` returns a
`cl_error_t`, tracks short writes, checks final close status, and reports open,
write, seek, and close failures (libclamav/jsparse/js-norm.h:31;
libclamav/jsparse/js-norm.c:963–1007). HTML normalization consumes that result
and marks the scan incomplete at every JavaScript flush/finalization site
(libclamav/htmlnorm.c:683–685, 1270, 1924, 2033). The bytecode JavaScript
consumer also preserves the failure (libclamav/bytecode_api.c:1384–1391), and
`cli_scanhtml()` rejects a failed normalized output path rather than silently
falling through (libclamav/scanners.c:2773–2784).

Focused open/write/close unit tests and source guards are present
(unit_tests/check_jsnorm.c and tools/largefile_source_guards.sh). A supported
build should still run the exact injected-failure public-scan regression.

### V-04 — Medium-High: normalized script map failure required sticky propagation

The named F-10 width corrections are present: the cumulative script offset is
64-bit, an over-cap script is sticky, JPEG uses native offsets with time/range
checks, and XZ output accounting is 64-bit
(libclamav/scanners.c:1510–1616, 2873–3058; libclamav/jpeg.c:325–433).

The remaining `fmap_new()` failure in the relative-offset or linked-bytecode
branch now marks the scan incomplete and returns `CL_EREAD` before cleanup
(libclamav/scanners.c:2976–2981). Output-write, input-read, legacy matcher
width, offset-overflow, and incomplete-consumption paths are likewise sticky.
The injected map-failure unit test is registered when the test wrapper is
enabled; supported-build execution remains the evidence gate.

### V-05 — Medium: CAB/CHM constructor failure required an incomplete marker

The current source marks both CAB and CHM decompressor-construction failures
incomplete before returning `CL_EUNPACK` (libclamav/libmspack.c:445–449,
579–583). The recognized-header open failures are likewise marked
(libclamav/libmspack.c:457–462, 586–591), and constructor fault-injection
coverage is wired into the unit-test build. This historical finding is source
closed; compiled execution remains a supported-build gate.

### V-06 — Medium-High: MaxScanTime configuration required checked parsing

The direct `cl_engine_set_num()` fixes are correct: invalid MaxScanSize and
out-of-range MaxScanTime values now return `CL_EARG`
(libclamav/others.c:706–712, 868–874). StreamMaxLength zero and values above the
32 GiB ceiling are also handled in both option paths
(common/optparser.c:1361–1373, 1587–1596).

The current configuration and command-line parsers call the checked
`parse_max_scantime()` conversion instead of `atoi()` (common/optparser.c:71–98,
1323–1331, 1572–1580). It rejects overflow, signs, whitespace, trailing data,
and very long digit strings while accepting zero and `UINT32_MAX`. The
registered `check_clamd` tests cover both configuration-file and CLI paths;
the source finding is closed.

### V-07 — Medium release-compatibility issue: the fmap hash fix changes ABI

The F-08 memory-safety flaw is corrected for newly compiled clients:
`cl_fmap_set_hash()` now accepts a digest pointer and `fmap_set_hash()` copies
from that pointer (libclamav/clamav.h:683–695;
libclamav/fmap.c:1322–1345, 1651–1673). The SHA-256 public API regression at
unit_tests/check_clamav.c:121–145 is meaningful and registered.

The symbol name remains unchanged in libclamav/libclamav.map, which is correct
within a new SONAME. The current fork publishes
CURRENT:REVISION:AGE 14:0:0 / SOVERSION 14 (CMakeLists.txt:47–54), so the
pointer-signature change is not an in-place update to SOVERSION 12. A binary
compiled against the prior scalar third argument must not be loaded against
this release; it must retain the old shared object or be rebuilt/relinked.
No compatibility shim for the old ABI is claimed.

### V-08 — High confidence gap: runtime evidence is not self-contained or semantically bound

The evidence gate now checks a clean Git revision, the CMake source root, a
copied launcher, loaded dependency paths/hashes, and the presence of sanitizer
tokens (tools/largefile_runtime_gate.sh:176–280). These are genuine structural
improvements, but they do not establish the complete claimed relationship:

- Shared libraries remain enabled, and the copied launcher executes with
  build-tree library paths.
- Loaded dependencies are hashed but not copied into the evidence artifact
  (tools/largefile_runtime_gate.sh:238–269, 543–550). Their manifests retain
  absolute runner paths, so a downloaded artifact is not independently
  verifiable by `sha256sum -c`.
- A stale binary from the same CMake source directory can satisfy the source
  root check; no build graph or object-level source identity is recorded.
- Sanitizer proof accepts the presence of any ASan/UBSan symbol or linked
  runtime (tools/largefile_runtime_gate.sh:270–280). It does not prove that
  libclamav, Rust, UnRAR, and every executed parser were instrumented. The
  workflow explicitly excludes Rust from sanitizer CTest
  (.github/workflows/cmake.yml:168–176).
- The positive synthetic verifier fixture uses text files as scanners and a
  fabricated `__asan_init` line, which demonstrates structural validation but
  not runtime semantics.

Temporary-space evidence is also weaker than its label: the POC runs `du` only
after each scanner process exits (tools/largefile_poc.sh:206–207), so peak
temporary data deleted before exit is invisible. The verifier checks that the
results table has twelve fields but does not validate field 12 numerically or
compare it with the fixed budget
(tools/largefile_runtime_evidence_check.sh:382–414).

The workflow still lacks mandatory clamd worker/thread, clamdscan, milter,
materialized/cold-cache, production-detection, parser-expansion, latency, peak
temporary-space, and service-RSS acceptance jobs. Separate clamscan processes
are not a substitute for the clamd concurrency requirement.

### Source fixes that were statically verified

The following original failure chains are correctly repaired in source, even
though exact-trigger compiled coverage remains incomplete:

- F-02: metadata pre-scan hash failure marks incomplete and preserves the
  underlying read error or `CL_EREAD` (libclamav/scanners.c:5318–5323).
- F-03: PDF Flate and LZW accept only terminal decoder states, mark incomplete
  on exhaustion/error, and do not install partial decoded output
  (libclamav/pdfdecode.c:748–819, 1068–1139).
- F-04: HWP raw-deflate requires `Z_STREAM_END` and never invokes the scan
  callback on a partial prefix (libclamav/hwp.c:118–185).
- F-05: ZIP filename, extra-field, ZIP64, descriptor, and member-range failures
  mark incomplete; valid records preceding a malformed candidate are scanned
  before the sticky result is restored (libclamav/unzip.c:1413–1603,
  2295–2307, 2901–2918, 3072–3081).
- The exact reported F-06 paths are fixed: XZ premature EOF/decode/write/limit
  failures, CAB/CHM archive-open rejection, and the PE entry-point read failure
  are fail-visible (libclamav/scanners.c:1510–1616;
  libclamav/libmspack.c:457–462, 586–591; libclamav/pe.c:2863–2869).
- F-07: LHA uses `FMapReader`; ALZ now parses through the same bounded
  `Read + Seek` adapter and streams member output into quota-accounted spools;
  OneNote still stages through bounded fmap windows before creating its
  disk-backed parser mapping. Mapping, parser, decoder, and member-scan
  failures set sticky scan state. Supported-build and concurrent-RSS evidence
  remains open.
- F-09: 64-bit and 32-bit Mach-O section alignment exponents at or above 32
  are rejected before an unsigned shift (libclamav/macho.c:398–435).
- F-16: OneNote dispatch now checks
  `DCONF_DOC & DOC_CONF_ONENOTE` (libclamav/scanners.c:5463–5465).

### Regression coverage assessment

The current tests and source guards do not prove the exact high-risk triggers:

- PDF tests cover Flate and LZW output followed by truncation, plus malformed
  trailers, through focused/direct paths; the full public scan path and
  fault-injected PDF I/O remain open.
- HWP tests now cover raw-deflate output followed by truncation through the
  direct HWP3 path; broader compressed-entry and fault-injected I/O coverage
  remain open.
- The ZIP truncation test contains only a four-byte signature, not a complete
  fixed local header declaring an oversized filename, extra field, or ZIP64
  field.
- The XZ test exercises a small MaxScanSize limit, not premature EOF; CAB/CHM
  open/constructor and PE entry-point I/O failures are not fault-injected.
- The Mach-O test checks a four-byte truncated header, not a 64-bit section
  with an alignment exponent at or above 32.
- OneNote tests now vary the document dynamic-configuration bit independently
  of the ordinary ScanOneNote option; the archive bit remains unvaried.
- Rust tests cover `WHOLE_INPUT_MAX` rejection, failed fmap need, bounded
  reader windows, and window release. Successful whole-input residency and
  concurrent clamd RSS remain open.
- RAR tests now cover a nested mapped-read failure and public incomplete-result
  propagation; `SIZE_MAX` nested-slice boundaries, success-path cleanup fault
  injection, and RAR5 SFX qualification remain open.

`tools/largefile_source_guards.sh` is primarily a source-text presence suite.
Passing it does not demonstrate that the guarded branch is reachable, that
the return status survives reconciliation, or that an original trigger has a
runtime oracle.

### Checks run during this verification

The following local controls passed:

- `sh -n` for the runtime gate, evidence verifier, evidence control test, and
  source-guard scripts;
- YAML parsing of `.github/workflows/cmake.yml`;
- `./tools/largefile_source_guards.sh`;
- `./tools/largefile_poc_fail_closed_test.sh`; and
- `./tools/largefile_runtime_evidence_check_test.sh`.

These are static or synthetic controls. They do not exercise a compiled
ClamAV scanner or the real GitHub workflow.

An offline Rust compile check was attempted with an external temporary target
directory. It could not resolve the uncached `clam-sigutil` Git dependency.
`cargo fmt --check` could not run because the selected Rust toolchain does not
have the rustfmt component installed. No software was installed locally.

The authorized source transfer to Sonic1 completed. On the pinned
`clamav-current-source-v5` container, the release and ASan+UBSan/nightly-Rust
CTest matrices each passed all 12 supported targets, including the exact
compiled C/Rust/sanitizer regressions, fail-closed controls, and the updated
runtime-evidence verifier. The runtime gate also assembled self-contained
source/build/component/sanitizer evidence through
`/work/evidence/runtime-v5-final6`. The tracked MCP-SSH wrapper later timed out
with exit 124, but its bounded stdout reported that the runtime gates passed;
direct job status/output retrieval confirmed that result, and running the
repository evidence verifier in the same container exited 0. The evidence
records the canonical 1/2/4 concurrency matrix, exact 32 GiB and 32 GiB+1
policy cases, cancellation, release and sanitizer provenance, and
`runtime_gate=pass`. The remote content-manifest digest is
`3faee350febbf80ca8eb6b1f383abef14814cfa005aff984b11fd26219f7052e`;
targeted implementation and gate-script hashes match this local source
snapshot. The local `audit1.md` was updated after that transfer and is
documentation-only relative to the tested implementation.

The service qualification remains blocked because this workspace does not
contain an authorized production CVD/database, production file, materialized
input, parser-expansion fixture, or writable cold-cache test authority. The
available corpus is synthetic and is not relabeled as production evidence.

### Updated required disposition

Items 1–8 and the exact-trigger compiled regressions in item 10 are implemented
and covered by the Sonic1 release and ASan+UBSan/nightly-Rust CTest runs.
Synthetic runtime acceptance is now verified by the completed and independently
checked `runtime-v5-final6` evidence directory. The remaining acceptance
blocker is:

1. Run the service qualification with authorized production CVD/database,
   production file, materialized input, parser-expansion fixture, and cold
   cache authority; synthetic inputs cannot satisfy this requirement.

Until that service evidence blocker is addressed, the current tree must remain
non-production and must not claim complete scan coverage through 32 GiB.

## Current implementation status — 2026-08-17

The current worktree now contains the requested implementation changes,
including accessible-range RAR staging with sticky failure propagation,
checked JavaScript output I/O, sticky normalized-script map failures,
fail-visible CAB/CHM decompressor construction (including CAB header probing),
full-width MaxScanTime parsing and configuration/CLI boundary tests, and a
libclamav SONAME transition for the digest-pointer `cl_fmap_set_hash()` ABI.

The workflow and evidence controls now split release and sanitizer deadlines,
require Rust sanitizer evidence, capture peak observed temporary storage,
enforce the canonical worker/RSS/latency/resource budgets, and require the
service, production-CVD, materialized/cold-cache, parser-expansion, and milter
qualification inputs before attestation and upload. Runtime evidence includes
the content manifest, build manifest, copied loaded components, compile graph,
and sanitizer component records. CMake now captures Git revisions from the
source directory itself and falls back to the content-manifest digest for a
Gitless snapshot; failed staging seeks are also fail-closed.

Local shell syntax, source guards, the fail-closed POC control, YAML parsing,
and the synthetic evidence verifier pass. Supported-Linux compilation and
compiled C/Rust/sanitizer execution are verified on Sonic1 as described above.
Synthetic runtime acceptance is also verified from the independently checked
`runtime-v5-final6` evidence directory. Service-level qualification remains
blocked because the required production inputs are absent, so the production
block remains in force.

## Qualification-oracle hardening — 2026-08-18

The service qualification gate now requires a caller-supplied eight-column TSV
oracle for the production, materialized, parser-expansion, and exact-edge
inputs. Before any daemon is started, the gate verifies each fixture's exact
size, SHA-256, and expected top-level `CL_TYPE_*` value contract. Each direct
`clamscan` and `clamdscan --report-json` result must then match the oracle's
exit status, structured-report completion state, file type, and exact alert
token; direct detection runs also require the expected engine offset. The
workflow exposes this as the required `qualification_oracle` input and
records all bound status, completion, signature, offset, type, size, and hash
values in `oracle-binding.txt`.

This closes the prior “FOUND/arbitrary exit code” acceptance weakness, but it
does not provide the missing authorized production database or workload. The
service qualification therefore remains intentionally blocked until the user
supplies those inputs and their expected outcomes.

## Service logical-budget and report-mode coverage — 2026-08-19

The service qualification configuration had been writing `MaxScanSize 32G`,
which did not exercise the release contract's 64-GiB logical-content budget.
It now writes `MaxScanSize 64G`. The exact-edge structured-report gate also
explicitly runs CONTSCAN, MULTISCAN, and ALLMATCHSCAN, alongside the existing
path, FILDES, and INSTREAM cases. The dedicated Linux/Sonic1 run, production
oracle, sanitizer, RSS, latency, and temporary-space evidence remain open.

## Service serial-queue coverage — 2026-08-19

The service qualification harness now uses the roadmap's certified
`MaxThreads 1` / `MaxQueue 2` profile for the ordinary production, materialized,
expansion, and exact-edge service requests. Before the multiworker check it
submits two concurrent materialized-file requests and requires both exact
oracle-bound structured reports plus a `THRMGR: contended, sleeping` daemon-log
record. This prevents a fast fixture or two independent clients from silently
being reported as proof of queue behavior. The harness then restarts clamd
explicitly with `MaxThreads 4` / `MaxQueue 8` for the four-client worker
qualification. Both profiles now explicitly set the 32-GiB file, contiguous,
PCRE, 64-GiB logical, 256-GiB matcher-work, and 64-GiB temporary budgets rather
than inheriting build defaults. The real production oracle, Linux/Sonic1
execution, sanitizer, RSS, latency, temporary-space, and parser-family
evidence remain open.

## Mydoom detector boundary audit — 2026-08-25

The focused production-linked `mydoom_map` TCase now covers null-context,
missing-map, and in-range detector-window callback failures. The read-failure
oracle preserves `CL_EREAD`, the detector-specific incomplete reason, and
non-cacheability. The focused production-linked run passes 3/3. The source
guards pin all three focused registrations; compiled detector corpus,
raw-dispatch, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 evidence remain open.

## BZip2 focused-stream audit — 2026-08-25

The focused production-linked `bz_map` TCase now runs the deterministic shared
compressed-stream oracles for truncated input and injected fmap read failure;
the two-case run passes 2/2. The tests include the BZip2 path alongside its
deliberately common GZip/XZ implementation. An attempted promotion of the
existing concatenated-member and temporary-quota cases exposed mixed-harness
gaps (zero loaded synthetic signatures and an adjacent XZ `CL_EFORMAT` result),
so those cases remain broad-suite/rebuild gates rather than being claimed as
focused evidence. Full BZip2 corpus, sanitizer, certified Linux x86-64,
materialized large-file, production-CVD/service, and Sonic1 evidence remain
open.

## CPIO focused-map audit — 2026-08-25

The focused production-linked `cpio_map` TCase now covers truncated headers
across all four CPIO forms, NEWC member-name callback failure, an impossible
next-header coordinate, and the initial NEWC read
callback failure. The direct `cli_scancpio_*` missing-map oracle remains a
current ABI-consistent rebuild gate after the mixed harness signaled in that
test. The existing `cpio_crc` and numeric cases remain separate focused
evidence for checksum, multi-window, and strict field parsing. Full CPIO
corpus, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 evidence remain open.

## DMG focused-map audit — 2026-08-25

The focused production-linked `dmg_map` TCase now includes strict Base64 and
terminal-end validation, host-order in-memory stripes, bounded external
metadata sorting, malformed metadata, trailer callback failure, and invalid
trailer handling alongside missing-map admission. The existing source guards
pin the DMG bounded staging, sorting, reconstruction, and deadline contracts;
the focused production-linked run passes 7/7. Full DMG corpus, sanitizer,
certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 evidence remain open.

## EGG focused-map audit — 2026-08-25

The focused production-linked `egg_map` TCase now covers fixed-header and
extra-field read/truncation classification, extra-field admission, bounded
oversized skippable fields, and bounded LZMA member extraction. The expired
timeout oracle remains broad-suite evidence until its direct fixture supplies
the shared scan-options context. The focused production-linked run passes 5/5.
Full EGG/EGGSFX corpus, sanitizer, certified Linux x86-64, materialized
large-file, production-CVD/service, and Sonic1 evidence remain open.

## GIF focused-map audit — 2026-08-25

The focused production-linked `gif` TCase now covers truncated block forms,
in-range header callback failures, truncated screen-descriptor classification,
an expired shared deadline, and missing-map admission. The timeout fixture
supplies the shared scan-options context and asserts the sticky
`Heuristics.Limits.Exceeded.MaxScanTime` reason. The focused production-linked
run passes 5/5, and the existing source guards pin the corresponding GIF
range, read-status, deadline, and focused-test contracts. Full GIF corpus,
sanitizer, certified Linux x86-64, materialized large-file, production-CVD/
service, and Sonic1 evidence remain open.

## PNG focused-map audit — 2026-08-25

The focused production-linked `png` TCase covers truncated chunks, an
in-range chunk-header callback failure, truncated chunk-header
classification, an expired shared deadline, and the sparse 2-GiB ancillary
chunk bounded-mapping fixture. Its checked fixture supplies the temporary
directory required by the materialized sparse case, while the timeout fixture
supplies scan options and asserts the sticky
`Heuristics.Limits.Exceeded.MaxScanTime` reason. The focused production-linked
run passes 5/5; the manifest and source guards record the same evidence. Full
PNG corpus, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 evidence remain open.

## TIFF focused-map audit — 2026-08-25

The focused production-linked `tiff` TCase passes 8/8 across classic and
BigTIFF truncation, initial and targeted IFD read failures, malformed
structures, endian variants, and shared-deadline expiry; the dedicated
`tiff_map` missing-map case passes 1/1. The three >4-GiB callback-map tests
are isolated in `tiff_large` and remain a mixed-harness rebuild gate because
the current production-linked object set returns a null fmap from
`cl_fmap_open_handle()` before parser entry. The manifest and source guards
retain that distinction. Full TIFF corpus, current full-build large-coordinate
evidence, sanitizer, certified Linux x86-64, production-CVD/service,
materialized large-file, and Sonic1 evidence remain open.

## JPEG focused-boundary audit — 2026-08-25

The dedicated production-linked `jpeg_map` TCase passes 11/11 across null
context and missing-map admission, truncated headers/segments, shared-deadline
expiry, required-header and segment callback failures, exploit/application
probes, Photoshop resource-header/marker callback failures, segment-boundary
protection, and exact Photoshop EOF. The focused case now carries the shared
scan-options context for its timeout oracle and uses complete Photoshop
resource fixtures. Full JPEG corpus, current full-build large-coordinate
evidence, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 evidence remain open.

## ISO9660 focused-map audit — 2026-08-25

The dedicated production-linked `iso_map` TCase passes 10/10 across missing
map admission, truncated directories, missing volume-descriptor termination,
shared-deadline expiry, in-range volume-read failure, unsupported extent
layouts, long directory names, Joliet UTF-16BE expansion, directory-coordinate
overflow, and declared-volume/file-extent bounds. The timeout and deep
file-extent oracles use the shared scan options and the public
`cl_scanmap_ex`/compiled-engine path. Full ISO9660 corpus, sanitizer,
certified Linux x86-64, materialized large-file, production-CVD/service, and
Sonic1 evidence remain open.

## UDF focused-map audit — 2026-08-25

The dedicated production-linked `udf_map` TCase passes 9/9 across missing-map
and truncated-area admission, shared-deadline expiry, generic-descriptor
callback failure, unsupported identifier handling, file-list/set completeness,
declared information-length and partition-extent accounting, and allocation
descriptor alignment. The timeout fixture supplies scan options and asserts
the sticky `Heuristics.Limits.Exceeded.MaxScanTime` reason. Full UDF corpus,
native-width review, sanitizer, certified Linux x86-64, materialized
large-file, production-CVD/service, and Sonic1 evidence remain open.

## HFS+ focused-boundary audit — 2026-08-25

The production-linked `hfs_map` TCase passes 9/9 across declared-attribute
volume bounds, temporary-directory setup, tree-header and catalog-node read
failures, fork/attribute/catalog accounting, truncation, and shared-deadline
expiry; the separate `hfs_inline` case passes 1/1 for multi-window bounded
decompression and output failure rollback. The production fix corrects the
tree-header admission unit mismatch by comparing one allocation block against
the declared block count. The isolated `hfs_fork` materialization callback case
still crashes before its oracle in the mixed harness and remains a current
full-build gate. Full HFS+ corpus, sanitizer, certified Linux x86-64,
materialized large-file, production-CVD/service, and Sonic1 evidence remain
open.

## OLE2 64-bit stream-size qualification — 2026-08-25

The OLE2 directory-entry model now decodes the complete 64-bit CFB stream-size
field without changing the 128-byte entry layout. The production-linked
`ole2_xlm` TCase passes 2/2: the existing in-range WorkBook sector callback
failure remains exact `CL_EREAD`, and a fixture mutation setting only the
stream-size high word returns an incomplete parse instead of scanning a
silently truncated low-32-bit prefix. The property walker explicitly rejects
sizes beyond native coordinate capacity. Full OLE2/VBA corpus, sanitizer,
certified Linux x86-64, materialized large-file, production-CVD/service, and
Sonic1 evidence remain open.

## RTF focused-boundary audit — 2026-08-25

The isolated production-linked `rtf_map` TCase passes 8/8 for truncated
documents, shared-deadline expiry, in-range fmap callback failure, split OLE10
header probing, complete long-description consumption, split reserved-field
accounting, and implicitly closed-object status propagation. The timeout case
asserts the repository-wide sticky `Heuristics.Limits.Exceeded.MaxScanTime`
reason; malformed split-object output may return either parse-incomplete or
explicit resource-incomplete, but never a clean/cacheable result. Full RTF/OLE
corpus, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 evidence remain open.

## BinHex focused-boundary audit — 2026-08-25

The focused production-linked `binhex_map` TCase now includes admission,
header-completion, timeout, data/resource truncation, temporary-quota,
cleanup-close, and injected encoded-input read-failure oracles. The timeout
fixture supplies scan options and asserts the repository-wide sticky
`Heuristics.Limits.Exceeded.MaxScanTime` reason. The existing source guards
continue to pin bounded decoding, temporary accounting, write/handoff
deadlines, and non-cacheable failures. The focused production-linked run passes
10/10; a current full C build remains required before certifying BinHex. Corpus,
sanitizer, certified Linux x86-64, materialized large-file, production-CVD/
service, and Sonic1 evidence remain open.

The service harness now also samples its temporary root while daemon and milter
requests are active, records the observed peak, and requires
`service_temp_budget=pass` before the workflow can attest or upload service
evidence. This catches temporary files deleted before process exit, which a
post-run directory-size check would miss.

## Loader-bound runtime evidence — 2026-08-19

The runtime gate now captures an `LD_DEBUG=libs` trace for the copied release
scanner and, when present, the copied sanitizer scanner. The post-run verifier
requires each trace to reference its copied runtime-component directory and to
contain no unresolved dependency marker. This strengthens the source/build
provenance chain by proving that the executable invoked by the gate searched the
hashed component set first; the trace and version output are included in the
manifest-bound evidence artifact. It remains evidence for the Linux gate only,
not a substitute for service or parser-family qualification.

## Public limit-setter boundary coverage — 2026-08-19

The public `cl_engine_set_num()` implementation already rejects negative and
out-of-range `MaxScanSize` and `MaxScanTime` values before converting them to
the unsigned engine fields. The focused `check_clamav` regression now exercises
both exact failure classes: negative values and one-past-`64 GiB`/`UINT32_MAX`
values. This closes the missing trigger coverage for the corrected F-12 setter
path; the broader compiled parser and service qualification gates remain open.

## OneNote dynamic-configuration isolation — 2026-08-19

The OneNote dispatch regression now varies `ARCH_CONF_SIS` and
`DOC_CONF_ONENOTE` independently. It proves that both bits disabled and the
archive bit alone skip OneNote cleanly, while the document bit alone dispatches
the malformed fixture and preserves a fail-visible parser result. This closes
the exact dynamic-configuration trigger coverage for F-16; full OneNote parser
and large-input qualification remain open.

## Rust large-input staging — 2026-08-19

ALZ now parses directly through the bounded `FMapReader` `Read + Seek` adapter
and emits decompressed members in chunks into quota-accounted temporary spools.
OneNote still stages the root through the shared temporary quota and parses a
disk-backed `mmap` view required by its third-party slice API. Modern OneNote
inputs above the explicit 256 MiB whole-input parser cap now fail before
staging or mapping; the bounded legacy reader remains available for larger
legacy documents. Failed reads, temporary reservation, mapping, parser,
decoder, and extracted-member scans remain fail-visible. This removes the
artificial ALZ cap and member-vector materialization, but does not by itself
prove third-party 32 GiB memory, sanitizer, or supported-build qualification.

## Rust temporary-spool ownership — 2026-08-19

Rust ALZ/OneNote temporary spools now release their shared temporary-space
reservation exactly once. Cleanup honors `keeptmp` and marks close/removal
failures sticky; a failed rewind before nested scanning is also incomplete.
This prevents early counter release from allowing later staging beyond
`MaxTemporarySize` and keeps cleanup non-clean/non-cacheable. Compiled
Rust/CTest and Linux/Sonic1 RSS/temporary-quota qualification remain open.

## Daemon large-file admission — 2026-08-19

`clamd` now repeats the host-resource admission at startup whenever the
configured file or logical scan ceiling exceeds the historical defaults. On
Linux it measures `MemAvailable` together with cgroup v1/v2 headroom, checks
free blocks in the configured temporary directory, and rejects large-file
configurations when the effective memory, temporary-space, or 64-bit
coordinate requirements are not met. The requirements scale down with lower
configured ceilings and cap at the 48 GiB memory / 68 GiB temporary-space
release envelope. Small-file configurations retain their legacy startup path.

## On-access transport and stat fail-closed correction — 2026-08-19

The on-access client now maps a timed-out socket wait or connection attempt to
`CL_ETIMEOUT`, preserving the distinction from ordinary read/write errors.
The existing prevention response therefore denies timeout, parser, resource,
and other incomplete outcomes instead of treating a timeout as an unspecified
transport result. Failed `stat()` calls clear the scan bit before the client
call, preventing an uninitialized `STATBUF` from selecting a scan mode or
being passed to the daemon. Monitoring-only events retain their log-and-allow
policy, while prevention remains fail-closed.

The change is source-guarded, but the local macOS environment still lacks the
OpenSSL development headers needed for a C syntax/build check. Linux compile
and fanotify runtime verification remain release-gate work on Sonic1.

## AutoIt bounded encrypted input and EA05 output — 2026-08-20

EA05 and EA06 compressed members decrypt their fmap input through a bounded
64 KiB window with preserved MT/LAME keystream state. EA05 decoded output now
uses a 32 KiB back-reference history window and a 64 KiB pending-write buffer
to stream into a temporary file; stored EA05 members are decrypted in chunks
and use the same quota-accounted temporary path. The EA05 format still has
32-bit size fields, so output above 4 GiB remains an explicit unsupported
boundary. At this checkpoint, EA06 script decompilation still retained a
random-access decoded buffer and remained unsupported above the
individual-allocation ceiling; later bounded input/output milestones close
that implementation limit.

The source guards and capability manifest record those two deliberate limits.
This closes the EA05 contiguous-allocation implementation item but does not
claim parser-family qualification: valid EA05 fixtures above 1 GiB, malformed
decoder states, temporary-quota exhaustion, sanitizer execution, and
supported-build Sonic1 evidence remain open release gates.

The pinned Sonic1 Release build completed without compiler warnings. The
existing `clam.ea05.exe` fixture returned the same explicit incomplete result
with the pre-change and current sources. Reproducible 85-byte stored and
95-byte literal-only compressed EA05 fixtures both returned `OK` with the
current scanner; these are regression checks only and do not qualify large
valid members or the parser family.

The scanner-facing EGG spool now also streams LZMA blocks through the bounded
decoder interface, checking the LZMA header size, terminal marker, trailing
input, and exact block output length. The legacy byte-buffer compatibility API,
solid EGG, and AZO remain explicit boundaries. A focused unit fixture covers a
valid LZMA member; corpus, sanitizer, and large-member qualification remain
open. The pinned Sonic1 Release overlay built successfully, and its rebuilt
`clamscan` returned `OK` for the 118-byte fixture from
`tools/largefile_egg_lzma_fixture.py`; this is focused regression evidence, not
full parser-family qualification.

## Embedded 7-Zip candidate admission — 2026-08-19

The embedded 7-Zip SFX path previously treated the six-byte file-type magic as
enough evidence to create a nested layer. It now checks the complete 32-byte
start header and validates the 64-bit next-header range before admission. A
weak/truncated candidate is rejected without marking the parent incomplete;
once the minimum structure is present, malformed or unsupported header values
are explicit incomplete results. The actual archive extractor already uses
bounded fmap reads and streaming member output, so this change is limited to
recognition and layer admission.

The RAR4 SFX branch now performs the same kind of bounded admission for its
fixed main-header prefix and declared header size. A signature with no valid
main-header type is rejected as unrelated data; a valid marker whose declared
header extends beyond the containing fmap is incomplete. RAR5 SFX qualification
remains open.

## RAR staged-input cleanup — 2026-08-19

RAR input staged from a nested or non-file-backed fmap now reserves the staged
input against `MaxTemporarySize` through UnRAR and child scans, then uses the
shared temporary cleanup contract. Descriptor-close and temporary-removal
failures mark the scan incomplete/non-cacheable and preserve an earlier
stronger result, preventing a successful archive scan from hiding cleanup
failure. Compiled RAR/fault-injected cleanup and Linux/Sonic1 qualification
remain open.

## RTF split object-header probe — 2026-08-20

The RTF embedded-object decoder assumed that two decoded payload bytes were
available in every callback before deciding whether the object was an OLE2
stream. An 8 KiB fmap reader boundary can leave exactly one decoded byte in the
callback, making that probe read beyond the output buffer. The decoder now
carries the two-byte probe across callbacks and only commits it once complete;
truncated payloads remain fail-visible. A regression forces the boundary and
verifies an incomplete, non-cacheable result. Compiled sanitizer and broad
RTF/OLE corpus qualification remain open.

## Fuzzy-image contiguous-subject boundary — 2026-08-20

The optional fuzzy-image FFI consumes one contiguous image subject and cannot
be used as a 32 GiB streaming detector. Its scanner path now explicitly marks
images above the individual-allocation ceiling incomplete before mapping them,
and the matcher does not publish a successful fuzzy result after a failed
check. The capability manifest records this as unsupported rather than
pending; image corpus, sanitizer, and supported-build qualification remain
open for inputs within the bounded subject policy.

## EGG metadata-size admission — 2026-08-20

EGG archive and file extra-field handlers accepted attacker-controlled
32-bit metadata sizes and could request multi-gigabyte contiguous fmap
windows. The encryption-header compatibility adjustment also subtracted its
fixed overhead without first proving that the declared size contained it.

At this checkpoint the handlers returned an explicit `CL_EMAXSIZE` result
above the global individual-allocation ceiling, and both encryption paths
rejected undersized headers before subtraction. The then-current
`egg-extra-field-over-1g` capability entry recorded that broad boundary; the
later bounded extra-field milestone narrows it to legacy filename/comment
string materialization. Compiled EGG, sanitizer, parser-corpus, and
supported-build qualification remain open.

## XAR subdocument streaming — 2026-08-23

XAR subdocument handling no longer calls libxml2's `ReadInnerXml`, which
materialized one complete fragment before the existing temporary spool could
account it. The XML reader now serializes elements, attributes, text, CDATA,
comments, processing instructions, and entity references directly through an
`xmlOutputBuffer` into the quota-accounted temporary file. Each writer flush
uses the shared temporary and deadline checks, and malformed, unsupported, or
failed nodes remain explicit incomplete results. The prior whole-fragment
allocation boundary is removed; a single oversized XML node and unsupported
libxml2 node types remain the documented `xar-subdocument-over-1g` boundary.

Source guards and the capability manifest were updated. Compiled XAR corpus,
sanitizer, large-node, and supported-build Sonic1 qualification remain open.

## clamdscan wrapper/session failure reports — 2026-08-20

`clamdscan --report-json` now emits a structured fallback for path
canonicalization allocation failure and for parallel connection or IDSESSION
handshake failure. The fallback preserves the requested target and maps the
failure to a non-clean status; source guards cover all three boundaries.
Compiled fault injection and supported-build Sonic1 evidence remain open.

The `clamdscan -` ingress now emits a structured `stdin` fallback for input
`fstat`, clamd connection, and structured-response failures while retaining its
legacy exit behavior. Source guards cover each failure boundary; compiled
stdin fault injection and supported-build Sonic1 evidence remain open.

## Force-to-disk nested fmap accounting — 2026-08-19

Nested fmap scans forced to disk now reserve the complete staged range against
`MaxTemporarySize` until the child scan and cleanup finish. Temporary-file
creation, close, removal, and partial-copy failures remain fail-visible, and
the child uses the already-held reservation rather than double-counting the
same bytes. Compiled force-to-disk fault-injection and Linux/Sonic1 quota
qualification remain open.

## OLE2 XLM/BIFF read-status preservation — 2026-08-24

The OLE2 XLM/BIFF walker recorded sector callback failures in
hdr.read_status, but its failure exits retained generic CL_EPARSE. The
property-enumeration path could therefore hide an operational WorkBook-sector
read failure behind a parse result.

The walker now propagates hdr.read_status after small-block and big-block
reads, after the BIFF scan, and after the next-sector lookup. A focused
production-linked GCC regression uses the existing workbook fixture, clears
only its bounded encryption-probe window, injects a WorkBook sector read
failure, and passes with exact CL_EREAD, the sector-read incomplete reason,
and non-cacheability. Full OLE2 corpus, sanitizer, production-CVD,
certified Linux x86-64, materialized large-file, and Sonic1 qualification
remain open.

## XZ trailing-stream admission — 2026-08-24

The XZ path stopped at the first `XZ_STREAM_END` and immediately dispatched
the decompressed temporary file. If the decoder left bytes in its current
input window, or the fmap still held another unread window, concatenated or
trailing XZ content was silently skipped and the first output could appear
clean.

The path now requires both the decoder input window and the containing fmap to
be exhausted before nested scanning. Any trailing input is marked
incomplete/non-cacheable and returns `CL_EUNPACK`; a focused production-linked
regression concatenates two valid XZ streams and requires that result. Full XZ
corpus, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD, and Sonic1 qualification remain open.

## APM declared partition-map boundary — 2026-08-23

APM entry reads previously checked only the image fmap. The parser now validates
the declared partition-map extent and bounds both normal and intersection
entry walks to that extent before reading metadata. A focused fixture keeps a
second entry mapped but outside the declared table and verifies an incomplete
result. Compiled APM corpus, sanitizer, and Sonic1 qualification remain
release gates.

## RTF split reserved-field accounting — 2026-08-23

The RTF embedded-object state machine lost progress when its eight-byte
reserved field was split across two fmap chunks: it set the available-byte
count to zero before adding that count to the partial-field counter. The next
chunk was therefore interpreted at the wrong state boundary, allowing the
payload-size field to be consumed as reserved data.

`WAIT_ZERO` now advances `bread` before clearing the consumed chunk count. A
focused 8 KiB boundary regression confirms that the payload-size field remains
in its intended state and that the resulting malformed embedded object stays
an explicit incomplete parse. Compiled RTF/OLE, sanitizer, and Sonic1 corpus
qualification remain release gates.

## CAB/CHM declared-output admission — 2026-08-23

The shared MSPack writer already stopped decoder output when the configured
remaining scan budget was exhausted, but its per-member budget was not tied to
the member's declared uncompressed size. A malformed or defective decoder
could therefore write beyond the reserved member amount whenever the broader
scan budget was larger. The CAB and CHM loops also accepted a successful
short materialization and passed it to nested scanning.

The writer budget is now clamped to the declared member size in both parser
families. Before nested scanning, each existing output is required to be a
regular file whose size exactly matches that declaration; a missing non-empty
member is incomplete, while a genuinely empty member retains the existing
optional no-output behavior. The shared
cli_mspack_output_matches_declared() helper and focused regression cover the
materialization invariant. Compiled CAB/CHM corpus, sanitizer, and Sonic1
qualification remain release gates.

## RIFF declared-container boundary accounting — 2026-08-23

The RIFF exploit walk previously recursed through a `LIST` chunk without
limiting child headers to that list's declared payload, and it used the whole
fmap rather than the root RIFF size as the top-level boundary. A valid empty
list could therefore make the detector inspect the next sibling or overlay as
if it were a child. The walk now validates the root range, bounds every child
to its containing list, accounts for padding and coordinate overflow, and
requires each list walk to finish exactly at its declared end. A focused empty
list regression covers the boundary; compiled RIFF corpus, fault injection,
sanitizer, and Sonic1 qualification remain release gates.

## UDF declared-partition extent accounting — 2026-08-23

UDF extent admission previously validated only the computed fmap range. It now
also checks the extent's block-relative start and byte length against the
Partition Descriptor's declared partition length, after validating the logical
block size. A mapped extent beginning at the partition end is therefore an
explicit incomplete parse instead of an extracted child. The focused fixture
extends the existing UDF allocation test with that boundary; compiled UDF
corpus, sanitizer, width review, and Sonic1 qualification remain release
gates.

## ISO9660 declared-volume boundary accounting — 2026-08-23

ISO9660 directory and file extents were previously constrained by the mapped
fmap but not by the image's declared Volume Space Size. An appended overlay
could therefore be admitted as an ISO member when its block coordinates were
within the fmap. Block admission now caps available bytes at the declared
volume end and rejects invalid zero or undersized volume extents. A focused
file-extent regression places the target byte in mapped overlay space beyond
the declared volume and requires an incomplete result. The paired
little-/big-endian size fields and declared-end-versus-map check are also
fail-visible; compiled ISO corpus, sanitizer, and Sonic1 qualification remain
release gates.

## Fmap hash deadline coverage — 2026-08-22

Internal scan and cache callers now use a context-aware fmap hash helper that
checks `MaxScanTime` before hashing and between each bounded 10 MiB read window.
On expiry it records the timeout as an incomplete scan and returns
`CL_ETIMEOUT`; partially initialized hash contexts are discarded without
publishing a digest. The public `cl_fmap_get_hash()` API has no scan context,
so it retains its legacy behavior. Source-level coverage is complete for the
internal call sites, and `test_fmap_hash_time_limit_is_fail_visible` covers
the fail-visible pre-expired-context boundary; compiled timeout injection and
large-file parser/matcher qualification remain release gates.

## Rust reader timeout status preservation — 2026-08-22

The generic Rust reader-to-spool helper converted every `Read` error to
`CL_EREAD`, even though the context-aware fmap adapter deliberately reports a
deadline expiry as `io::ErrorKind::TimedOut`. CSS embedded-image extraction uses
this helper, so a timed-out decode could lose the specific timeout status while
remaining incomplete. The helper now maps the error through
`rust_reader_status()`, preserving `CL_ETIMEOUT`; compiled CSS timeout
injection and Rust parser-family qualification remain open.

## File-count counter boundary — 2026-08-22

The internal `cli_ctx.scannedfiles` field remains a 32-bit ABI field, while
`MaxFiles=0` intentionally permits an unlimited configured count. Before this
fix, incrementing the counter at `UINT32_MAX` could wrap to zero and let a
later object pass file-count admission. `cli_updatelimits()` now stops at the
native counter boundary with `CL_ERESOURCE`, marks the scan incomplete, and
preserves non-cacheability without changing the established context layout. A
focused limit regression covers the boundary; normal MaxFiles qualification,
sanitizer, and production corpus evidence remain open.

## EGG SFX candidate admission — 2026-08-19

The embedded EGG path now requires the complete fixed header, supported
version, nonzero header identifier, and zero reserved bits before admitting a
nested layer. Short magic-only candidates are rejected without tainting the
parent; complete but malformed or unsupported headers mark the scan
incomplete. A focused admission test and source guards are present; the full
compiled embedded-SFX regression remains a supported-build gate.

## Remaining embedded candidate admission — 2026-08-19

The remaining TODO branches in `scanraw()` are now guarded before nested-layer
creation. NSIS checks its archive marker, fixed header sizes, and containing
range; AutoIt checks the recognized EA05/EA06 entry and fixed pre-member
bytes; InstallShield MSI checks the complete `InstallShield` marker and its
0x20-byte control block; and embedded PDF checks `%PDF-1.[1-9]`. Weak or short
matches are rejected as unrelated candidates, while recognized but malformed
or truncated structures mark the parent scan incomplete. The focused unit
test and static guard pass locally. Supported-build parser-family tests and
the broader 32 GiB qualification evidence remain open.

## Fileblob temporary-spool accounting — 2026-08-19

The shared temporary quota previously began accounting a MIME/fileblob only
when `cli_magic_scan_desc()` started the final scan. Bytes written during
message, bounce, TNEF, and similar materialization therefore could exceed
`MaxTemporarySize` before scanner admission. `fileblob` now keeps a per-spool
reservation, backfills the reservation when its context is attached after
initial writes, releases the build reservation before the descriptor scanner
charges the same file, and releases any remaining reservation on destruction.
Quota, measurement, and write failures set sticky incomplete state so callers
that only test for `CL_VIRUS` cannot turn an uninspected attachment into a
clean result. A focused quota/backfill regression and source guards were added.

This is an accounting/fail-closed correction, not proof that the retained
64 MiB MIME line-list has been replaced with an incremental large-mail parser;
the latter and supported-build qualification remain open.

## XAR TOC streaming — 2026-08-19

The XAR parser previously mapped the entire compressed TOC and allocated its
entire decompressed XML document, enforcing an unrelated 64 MiB deep-parser
cap. It now reads the compressed range in bounded chunks, writes decompressed
XML to a temporary file under the shared temporary quota, scans that completed
child, and parses it through a streaming `xmlReaderForIO` callback. Exact
declared lengths, decoder terminal state, output writes, temporary admission,
and XML reader errors are fail-visible. This removes the specific XAR 64 MiB
heap cap; parser-family fixtures and supported-build 32 GiB qualification
remain open.

The `<subdoc>` handoff now writes through a quota-accounted temporary
descriptor and uses a bounded native-width length check before nested scanning.
The legacy libxml2 `ReadInnerXml` API still materializes each fragment, so
fragments above the 1 GiB individual-allocation boundary are explicit
unsupported/incomplete results rather than unbounded whole-buffer scans.

## HWPML bounded XML streaming — 2026-08-19

The HWPML attachment-bearing path no longer rejects the entire XML layer above
64 MiB or exposes a complete binary text node to the XML reader caller. It now
uses a libxml2 SAX push parser fed from bounded fmap windows. Callback text is
written incrementally to a temporary file charged against the shared
temporary-space budget, and generic base64 fields are decoded across input
boundaries into a quota-accounted spool before nested scanning. Invalid XML,
base64, temporary admission, write, callback, and nested-scan failures remain
sticky incomplete results.

This closes the specific HWPML whole-text-node/64 MiB gate. Parser-family
fixtures, compressed-attachment qualification, and supported-build Sonic1
evidence remain open.

## ELF focused-map audit — 2026-08-25

The focused production-linked `elf_map` TCase now covers null/missing-map
entry points, truncated ELF headers, truncated program-table admission, an
in-range program-header callback failure, and metadata-only callback failure.
The existing source guards pin native-width coordinate checks, bounded header
reads, and incomplete results. The focused production-linked run passes 6/6.
Full executable corpus, sanitizer, certified Linux x86-64, materialized
large-file, production-CVD/service, and Sonic1 evidence remain open.

## XDP bounded XML streaming — 2026-08-19

XDP no longer rejects the complete XML layer at the former 64 MiB gate or
materializes `<chunk>` inner XML and its decoded payload in heap memory. It now
uses the bounded SAX push parser; base64 chunks are decoded across XML input
boundaries into temporary spools charged against the shared temporary-space
budget before nested scanning. XML, base64, temporary-write, resource-limit,
and nested-scan failures remain sticky incomplete results.

This closes the specific XDP whole-text-node/64 MiB gate. XDP corpus,
memory/sanitizer, and supported-build Sonic1 qualification remain open.

## DMG bounded XML streaming — 2026-08-19

The DMG parser no longer rejects an XML resource fork merely because the root
metadata exceeds 64 MiB, and it no longer assembles a complete `<data>` text
node or Base64 string in heap memory. The XML range is exposed as a duplicate
fmap and consumed by the bounded SAX reader; each Base64 value is decoded into
a temporary spool charged against the shared temporary quota. A completed
spool was retained only as one decoded `mish` metadata block, with the then-
existing 64 MiB per-block cap, strict terminal `END` validation, and fail-visible
malformed/unsupported handling. Reconstructed partitions remain quota-charged
while their nested scans run, and retained XML copies use bounded writes.

This closes the specific DMG root-XML and whole-text-node materialization gap.
Real Apple DMG corpus, large metadata, sanitizer, and supported-build Sonic1
qualification remain release gates; multi-segment DMGs remain explicit
unsupported input. The decoded-value cap was superseded by the 2026-08-23
file-backed stripe-reader change below.

## MHTML root preclassification failure visibility — 2026-08-19

`parseRootMHTML()` and its nested MHTML-comment callback previously had
fail-open branches: failed message/text materialization returned `OK`, parser
errors could be suppressed when the metadata JSON object was absent, and a
libxml2 build without HTML support fell through without returning a status.
Those paths now mark the scan incomplete directly, return explicit parser
failure, and enable fail-incomplete handling for the XML walker. Unterminated
comment XML and comment-reader construction failures receive the same sticky
state treatment. The raw MIME/HTML scan remains available, but a failed
preclassification operation cannot produce a clean/cacheable result.

This is source-backed fail-closed coverage. A compiled MHTML regression,
sanitizer run, and supported Linux/Sonic1 parser-family qualification remain
open release gates.

## RFC 1341 partial-message reassembly — 2026-08-19

The RFC 1341 reassembler previously returned success after writing whichever
fragments it found; the loop did not require each numbered part to exist.
That could produce a clean result from a truncated reconstructed message.
The reassembler now requires every part, checks fragment read/close errors,
and validates final output flush/close. Missing or unreadable parts return an
error, so the existing caller sets the sticky incomplete state and does not
scan/cache a partial reconstruction as complete. A focused unit fixture covers
the missing-fragment case; compiled Linux, sanitizer, and broader partial-mail
qualification remain open.

## MIME line materialization allocation failures — 2026-08-19

`messageAddLine()` and `messageAddStr()` previously marked the message
truncated for the bounded 64 MiB reservation failure, but allocation failures
after that reservation could return `-1` without setting the scan's sticky
incomplete state. A shared helper now marks both conditions fail-visible and
records a reason before the parser unwinds. Existing materialization-limit
unit tests assert the sticky state as well as the legacy message flag; actual
fault-injected allocation and supported-build mail qualification remain open.

## PDF unsupported-filter result propagation — 2026-08-19

The PDF decoder previously normalized unimplemented DCT/JPX/FAX/JBIG2 and
unknown filters through `CL_BREAK` after retaining a raw-stream fallback.
Disabled LZW used the same clean-looking path. The decoder now preserves the
raw fallback for signature matching but marks the recognized layer incomplete
and returns `CL_EPARSE`; the direct DCT regression verifies the status,
sticky state, non-cacheability, and raw-byte count. This closes unsupported
filter result propagation, not the remaining streaming-decoder and
production-corpus qualification gates.

## PDF unsupported encryption classification — 2026-08-21

When a recognized encrypted PDF had no usable key or an unsupported encryption
method, the decoder returned a generic parse failure and lost the reason that
deep inspection was unavailable. The raw stream fallback remains available for
matching, but the layer now records an explicit unsupported-encryption reason,
stays non-cacheable, and is classified as unsupported by the structured report.
A focused decoder regression covers the no-key path; encrypted PDF corpus,
sanitizer, and supported-build Sonic1 qualification remain open.

## CryptFF staging completion — 2026-08-19

The CryptFF temporary-decryption path previously accepted an incomplete
header, treated a source-map read stop as ordinary EOF, checked only the
`cli_writen()` error sentinel instead of the requested byte count, ignored
descriptor-close failure, and overwrote a prior result when unlink failed.
The path now validates the fixed header, distinguishes EOF from an early map
read stop, requires `written == bread`, marks all staging/cleanup failures as
sticky incomplete, and preserves detections or parser errors over cleanup
status. A Linux static-wrapper regression covers write and close faults;
compiled Linux/Sonic1, sanitizer, and real CryptFF corpus qualification remain
open.

## Compressed temporary-output completion — 2026-08-19

The main GZip decoder previously accepted a short `cli_writen()` result when
the call did not return `(size_t)-1`, and its GZip/BZip2/XZ/SZDD temporary
staging paths ignored close failures or could overwrite an earlier decoder,
limit, or detection result with unlink failure. The shared compressed cleanup
helper now requires the exact write count at GZip, marks source/staging and
cleanup failures as incomplete/non-cacheable, and preserves the first
meaningful result. The focused GZip write/close wrapper regression is
registered; Linux/Sonic1, sanitizer, and broad compressed-family corpus
qualification remain open.

## Compressed-output temporary quota — 2026-08-20

GZip (main and legacy fallback), BZip2, and XZ now reserve decoded output
chunks against the shared `MaxTemporarySize` budget before writing temporary
data. Overflow, scan-limit, and temporary-quota failures leave the scan
incomplete/non-cacheable; cleanup releases only the bytes actually reserved.
Successful nested scans use `cli_magic_scan_desc_type_reserved()` to avoid
double-counting the same spool. A focused three-family one-byte-quota
regression and source guards were added. This is source-level evidence in the
current canonical worktree; compiled Linux/Sonic1 execution and broad
compressed-family qualification remain open release gates.

The same audit found that SZDD/MSEXPAND checked the declared output against
`MaxScanSize` but did not charge its temporary output to `MaxTemporarySize`.
MSEXPAND now reserves the declared size before decoding, and the completed
temporary member uses `cli_magic_scan_desc_type_reserved()` so it is not
charged twice. Cleanup releases the reservation on success and failure. The
focused MSEXPAND one-byte-quota regression and source guards pass; compiled
Sonic1 execution and broad compressed-family qualification remain open.

The same temporary-output audit found that script normalization's
relative-offset disk view wrote generated chunks without charging them to the
shared quota. `cli_scanscript()` now reserves each chunk before writing and
releases the aggregate reservation after child scanning and cleanup. This is
source-level evidence; compiled script execution and broad parser qualification
remain open.

The temporary-output audit also found that SWF CWS/ZWS decompression staged a
temporary member without charging `MaxTemporarySize`. Both paths now reserve
the output header and decoded chunks before writing, retain the reservation
through nested scanning, and use the reserved descriptor entry point. The
focused CWS quota regression and source guards pass; compiled SWF and broad
parser qualification remain open.

BinHex was the next declared-output path found outside the shared temporary
budget. Its data and resource fork sizes are now reserved before decoding,
held through nested scans, and released during final cleanup; reserved-child
descriptor scans prevent double accounting. The focused one-byte-quota
regression and source guards pass. Compiled and broad parser qualification
remain open.

ISO and UDF extent extraction were also writing known-size files outside the
shared temporary budget. Both paths now reserve their extent length before
materialization, use reserved-child scans, and release the bytes after cleanup.
Source guards pass; compiled filesystem-parser and broad corpus qualification
remain open.

The RTF embedded-object spool also bypassed `MaxTemporarySize`. Its declared
payload plus the OLE10 bridge header is now reserved before creating the temp
file, held through nested scanning, and released during complete or truncated
cleanup. Ordinary objects use reserved-child descriptor scans; OLE10 retains
its specialized bridge. Compiled RTF/OLE qualification remains open.

## Script-normalization temporary cleanup — 2026-08-19

`cli_scanscript()` previously returned allocation or temporary-file creation
errors without setting the sticky state and ignored final close/removal
failures for normalized output. A write-failure branch also discarded close
failure. The path now marks each condition incomplete/non-cacheable and keeps
the first meaningful result. A Linux static-library close-wrapper regression
uses the normalized relative-offset path; Linux/Sonic1, sanitizer, and broad
HTML/script corpus qualification remain open.

## HTML-normalization temporary cleanup — 2026-08-19

`cli_scanhtml()` now marks temporary-directory allocation/creation failures,
checks every normalized child descriptor close, and reports temporary-directory
removal failures without hiding a detection or earlier parser result. The HTML
normalizer also checks its input and generated-output closes, so a successful
normalization return cannot conceal a close failure. A Linux static-library
close-wrapper regression exercises the public HTML scan entry; compiled
execution, sanitizer coverage, and broad HTML corpus qualification remain
open.

## PDF file-backed staging — 2026-08-19

The PDF entry path no longer allocates the complete deep-parser input on the
heap or rejects it solely because it exceeds 64 MiB on mmap-capable builds. It
now copies the fmap range to a temporary file under the shared temporary quota
in bounded windows and maps that file read-only for the legacy pointer-based
object parser. Read, write, mapping, quota, and cleanup failures remain
fail-visible. Builds without mmap support retain the explicit 64 MiB fallback
gate.

This is a root-input staging correction, not proof that all PDF object/stream
decoders are independently streaming or that a large-PDF corpus has passed
supported-build, sanitizer, or Sonic1 qualification.

## Mail phishing URL inspection — 2026-08-19

The phishing URL path no longer materializes the complete message in a heap
blob or rejects it at the former 100 KiB helper boundary. It now reuses a
completed raw body spool, or exports an encoded/legacy message to a
quota-accounted fileblob, maps that file, and runs the existing HTML
normalizer through its fmap reader. The fallback text-URL extractor reads in
64 KiB chunks and recognizes protocol prefixes split across chunk boundaries.
Mapping, normalization, read, and temporary-file failures remain
fail-visible and non-cacheable. Compiled mail/URL regression, memory,
sanitizer, and supported-build Sonic1 qualification remain open.

## Current qualification follow-up — 2026-08-19

The clang-format 16 backlog is closed on `origin/main` through the recorded
formatting commits; no local clang-format 16 executable is available for a
fresh byte-for-byte check. The local source guard suite passes all 141
capability checks, and the POC fail-closed and runtime-evidence verifier
regressions pass.

The current worktree additionally fixes the scan-API test fixture's temporary
directory setup, classifies the known malformed nested AutoIt fixtures as
fail-closed, accepts the valid NSIS header layout where the uncompressed header
can exceed the compressed archive size, and runs phishing URL inspection on
completed streamed mail bodies before raw scanning. These changes still need
compiled Sonic1 verification; the transfer attempt was stopped before any
bytes were written because MCP-SSH required explicit authorization for the
source payload and destination.

The NSIS admission regression now uses a 0x1105-byte header and 0x54d-byte
archive extent, matching the observed valid layout, and separately verifies
that an archive extent beyond the available fmap is rejected. This closes the
previous test gap without weakening the remaining bounds checks.

Read-only Sonic1 provenance confirms that the existing qualification workspace
is not the current authoritative source: its `mbox.c`, `nulsft.c`, and
`unit_tests/check_clamav.c` hashes differ from the local worktree. No test
result from that stale workspace is being attributed to the current changes.

## Runtime loader component selection binding — 2026-08-19

The runtime evidence gate previously proved only that the copied component
directory appeared in `LD_DEBUG` search-path output. It now performs a second
`ldd` resolution with the copied component directory first, records
`loaded-dependencies.txt` (and the sanitizer equivalent), and requires every
dependency captured from the build-tree set to resolve to its copied artifact
by basename. The post-run verifier checks those records and rejects a
substituted build-tree dependency; the control test covers that rejection.

This closes the specific loader-selection ambiguity in F-13 while preserving
the remaining limitation: the evidence is still Linux x86-64 runtime proof,
not compiled qualification of every parser family or a substitute for the
missing authorized production-CVD/service workload.

## Current-source Sonic1 transfer preflight — 2026-08-19

The authoritative source checkpoint `1091a494cd5064582d11e803ae56e973d2c9b57a`
was archived locally at 15,045,340 bytes with SHA-256
`1711a682ef50cd2306eff0f31efaf26b263c0bf3b54c923815a9a6fb5b0cf165`. Sonic1
could not clone the private GitHub repository (`could not read Username`), and
the unauthenticated codeload endpoint returned 404. The MCP-SSH durable upload
handoff reached its listener but failed before transfer with a read-only local
staging directory; its subsequent cleanup found no remote temporary file. A
direct upload source was also rejected because neither `/private/tmp` nor the
canonical workspace is in the MCP-SSH server's configured local transfer roots.

The existing Sonic1 mount remains stale and no current-source bytes were
written to it. No build or scan result from Sonic1 is therefore attributed to
`1091a49`; compiled current-source qualification remains an explicit release
gate.

## Runtime evidence budget and sanitizer binding — 2026-08-19

The evidence verifier now applies the copied-runtime dependency hash and
loader-selection checks to the sanitizer artifact set as well as the release
set. It also rejects any POC row whose recorded temporary usage exceeds the
fixed 64-GiB temporary-space budget. The regression fixture mutates each of
those fields and confirms that the verifier fails closed; shell syntax and the
full synthetic verifier regression pass locally.

These controls strengthen evidence integrity but do not convert synthetic
runtime evidence into parser-family, service, production-CVD, or current-head
Sonic1 qualification. Those release gates remain open.

## Fresh clang-format 16 and Sonic1 qualification evidence — 2026-08-19

The repository's clang-format workflow matrix was rerun locally with the
existing `ghcr.io/jidicula/clang-format:16` container, reporting Ubuntu
clang-format 16.0.6. It checked 413 unique C/C++ files (420 matrix
occurrences because `libfreshclam` is listed twice) and produced no formatting
diagnostics. The formatting backlog is therefore resolved for every file
covered by `.github/workflows/clang-format.yml`.

On Sonic1, the current-source Release build completed after the verified milter
protocol and ALZ accounting fixes. The focused `clamav_milter_protocol` and
`libclamav_rust` CTest targets each passed. The broader current-source
qualification remains open: `clamscan` passed 118 tests with 1 skipped and 5
failures, while `clamd` passed 13 tests with 2 failures. The remaining failures
are concentrated in fail-closed parser expectations for malformed fixtures,
the webapp-export OneNote fixture not producing a detection, and OLE/XLM
metadata cases returning a parser-incomplete error. These results are retained
as qualification findings, not treated as clean production acceptance.

## Certificate verifier no-CN panic qualification — 2026-08-19

Sonic1's valid `/etc/ssl/certs` scan exposed an abort in
`libclamav_rust/src/codesign.rs` when a trust anchor lacked a Common Name. The
verifier now retains such certificates, limits duplicate-name checks to valid
Common Names, and uses an unnamed-signer fallback during verification. Sonic1
rebuilt the full Release target successfully, and the focused
`libclamav_rust` target passed 1/1. Re-running with the system certificate
directory no longer aborts at the missing-Common-Name certificate; it reaches
the existing duplicate-Common-Name trust-store policy error, which remains a
normal initialization failure. This is not a full digital-signature or
OneNote acceptance result.

The OneNote parser probe on the pinned Sonic1 build parsed the 52,297-byte
webapp fixture and extracted a `clam.exe` attachment of 544 bytes. Its SHA-256
exactly matched the repository's `unit_tests/input/clamav.hdb` signature
fixture. The scanner-level webapp test still returned `OK`, so nested scan
propagation remains an open qualification item despite parser extraction
working in isolation.

## Latest Sonic1 parser-contract qualification — 2026-08-19

The OneNote dispatch fix and encrypted-OLE2 fail-closed behavior were rebuilt
in the pinned Sonic1 qualification container. The webapp-export OneNote fixture
now extracts and scans its nested `clam.exe` payload: with the HDB test
signature loaded it returns exit 1 and `ClamAV-Test-File.UNOFFICIAL FOUND`; the
modern and legacy fixture set detects all three files when enabled and returns
clean only when OneNote scanning is disabled.

The encrypted OLE2 fixtures are now handled without interpreting ciphertext as
BIFF or OfficeArt. Metadata is retained, the optional
`Heuristics.Encrypted.OLE2` alert is retained, and encrypted content without a
usable key returns an explicit incomplete result (CLI exit 2) instead of clean.
All encrypted OLE2 alert and metadata cases passed in the focused clamscan
run. The final Sonic1 clamscan CTest run collected 124 cases, passed every
non-skipped case, and retained one intentional platform-specific skip.

The aggregate fail-closed expectations were synchronized for clamscan and
clamd to cover all nine known incomplete fixtures: the two malformed AutoIt
files, three InstallShield files, the encrypted OLE document, the truncated
UUencoded mailbox, the malformed NSIS file, and the malformed WWPack file.
After that correction, the clamscan CTest target passed and the clamd CTest
target passed all 15 service tests. The clamd and clamdscan targets also built
successfully without new compiler errors.

The local source guards, fail-closed POC regression, runtime-evidence verifier,
and `git diff --check` all pass. The previously recorded exact clang-format 16
matrix run remains clean for 413 unique files (420 matrix occurrences); this
machine has no local clang-format 16 executable, and the sandbox blocked a
fresh source transfer into the third-party formatter image, so no new
formatter result is claimed beyond that recorded matrix evidence.

## Final Sonic1 non-valgrind qualification after mailbox fixes — 2026-08-19

The final current-source Release build was run in the pinned Sonic1 container
`868b213e31020ca243d3c33df5904b26586615005fbae1abf04772f5294f8be1`, using
`/work/build-current-044db34-release`. The mailbox fixes now preserve the
legacy materialization path for `message/*` and `multipart/related`, retain
MHTML preclassification errors, and prevent a child parser's incomplete state
from unwinding as a clean mailbox result. The repaired NSIS fixture is now
detected as expected, so its former stale fail-closed test expectation was
removed from clamscan and clamd.

The complete non-valgrind CTest gate passed 11/11 in 107.58 seconds:
`libclamav`, the three large-file guards/evidence tests, both milter tests,
`libclamav_rust`, `clamscan`, `clamd`, `freshclam`, and `sigtool`. The focused
mailbox CTest target also passed 1/1, and Sonic1 source inspection confirms no
temporary diagnostics remain. Local source guards, the fail-closed regression,
the runtime-evidence verifier, and `git diff --check` pass as well.

The exact clang-format 16 CI matrix remains clean for all 413 unique covered
files (420 matrix occurrences); no additional formatter violations were found
and no formatting-only changes are needed. Valgrind-specific CTest cases were
excluded from the 11/11 gate and remain a separate release qualification item.

## Corrected current-source ASan qualification — 2026-08-19

The current-source Sonic1 build was rebuilt with GCC 12.2 C/C++ AddressSanitizer
flags (`-fsanitize=address -fno-omit-frame-pointer`) in
`/work/build-current-044db34-asan`. The first combined ASan/UBSan attempt
exposed a test-integration issue: the C sanitizer flags were inherited by the
Rust test link without Rust's nightly sanitizer mode, producing undefined
`__asan_*` and `__ubsan_*` symbols. No production-code failure was observed.

The project-supported Rust sanitizer path was then used with nightly Rust
1.100.0 and `RUSTFLAGS=-Zsanitizer=address`. The complete corrected build
passed, the isolated `libclamav_rust` target passed 1/1 in 19.50 seconds, and
the full non-Valgrind CTest suite passed 11/11 in 135.44 seconds. This included
the large-file guards and evidence verifier, both milter tests, Rust, clamscan,
clamd, freshclam, and sigtool.

This closes the current-source ASan application/test gate. Valgrind-specific
CTest cases, production CVD/service qualification, and broad parser-corpus
acceptance remain separate release gates.

## Current-source Release Valgrind qualification — 2026-08-19

The pinned Sonic1 current-source Release build
`/work/build-current-044db34-release` completed the full CTest suite with
Valgrind enabled. All 16/16 targets passed in 1121.83 seconds: the normal
libclamav, large-file, milter, Rust, clamscan, clamd, freshclam, and sigtool
targets plus `libclamav_valgrind`, `clamscan_valgrind`, `clamd_valgrind`,
`freshclam_valgrind`, and `sigtool_valgrind`.

This closes the current-source Release sanitizer/memory-check qualification
gate on Sonic1. Production CVD/service qualification and broad parser-corpus
acceptance remain open plan gates.

## Real production-CVD smoke qualification — 2026-08-19

Sonic1 has an authorized real database set under
`/work/usb-scan-20260818-current/db`: `main.cvd` (89,072,577 bytes),
`daily.cvd` (23,426,416 bytes), and `bytecode.cvd` (281,702 bytes). The
recorded SHA-256 values are `0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365`,
`09571f432efc1cc88bfff594768f880ed5abf4b9913e97e5f9c0a98a7a4bed70`, and
`6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb`,
respectively. The pinned image ID was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.

The current-source Release `clamscan` loaded that CVD set when given the
repository's `/work/clamav-current-source-v5/certs` directory and scanned the
authorized 1,529,898,209-byte USB file. With the default PCRE admission it
returned exit 2 and explicitly reported that PCRE signatures require an
oversized contiguous subject. With `--pcre-max-filesize=32G`, it returned exit
2 with the parser-specific diagnostic that ZIP masked local-header values are
unsupported. These are fail-visible parser/feature results, not a CVD
certificate initialization failure.

The five-file USB database runs remain non-acceptance evidence: the prior CVD
and PCRE result tables recorded `LIMIT_OR_INCOMPLETE`/exit 2 for the 1.53 GiB,
2.31 GiB, 3.27 GiB, 4.7 GiB, and 50 GB files. Production-CVD initialization
is therefore demonstrated, but clean production-file/service acceptance and
the parser-family corpus gate remain open.

## Real production-CVD clamd service smoke — 2026-08-19

The current-source Release `clamd` was also started in the pinned Sonic1
image with a temporary Unix socket, the same production CVD directory, the
repository certificate directory, and explicit 32 GiB file, scan, and PCRE
limits. The daemon loaded 3,628,010 signatures, created the socket, and
reported the expected large-file limits before accepting the `clamdscan`
request. The 1,529,898,209-byte authorized USB file then returned exit 2 with
`Can't parse data ERROR`; the daemon log records the same parser diagnostic:
`Scan incomplete: ZIP masked local-header values are unsupported`.

This confirms the production database and large-file configuration through the
service interface, but it is not a clean-file acceptance result. The service
and parser-corpus gates therefore remain open until the authorized real-file
set can complete without an incomplete parser result, or each intentional
format limitation is separately classified and accepted.

## Corrected production-CVD ZIP qualification — 2026-08-19

The earlier production-CVD result was repeated with the canonical ZIP parser
overlaid into the actual Sonic1 build source identified by the CMake dependency
file (`/work/clamav-32gb-044db34`), then rebuilt with an explicit
`unzip.c` recompilation. The canonical source hash was
`5779273c6302f7dcc7ab11d4022d3f163c2edfae918b398c20849153928a4076`.

With 3,628,010 production signatures, the authorized 1,529,898,209-byte USB
file returned `OK` and exit 0 using `--max-filesize=32G`,
`--max-scansize=64G`, `--pcre-max-filesize=32G`, the repository CVD
certificate directory, and `--max-scantime=14400000` (four hours). No ZIP
parser warning was emitted; the scan read 1.42 GiB, accounted for 3.03 GiB of
logical data, and completed in 182.932 seconds. With the default scan-time
budget, the same corrected binary reached the file but returned exit 2 only
for `Heuristics.Limits.Exceeded.MaxScanTime` at 131.166 seconds, confirming
that the earlier ZIP failure was removed and the remaining short-budget result
is a resource-policy outcome.

The actual build source was restored to its pre-test hash
`9a06260112b0a46fc3108e5ba74d9662fe14d7b37b8c48004cc3daf10ac72da8`, the
separate current-source checkout was restored to
`a75e7e57ba7e83467dfcaa7d422dd131c0fe067634ccf8a3d11f11fd7ec799b6`, and all
temporary staging, backup, copied-input, and scan-temp paths were verified
absent. This remains focused mixed-source production evidence; full
current-head, service, 50 GB, and broad parser-corpus acceptance remain open.

## Corrected production-CVD clamd service qualification — 2026-08-19

The same canonical ZIP parser was then overlaid into the actual Sonic1 build
source, and `clamd` plus `clamdscan` rebuilt with an explicit `unzip.c`
compilation. The foreground daemon used the authorized production CVD set,
the repository CVD certificate directory, and explicit limits of 32 GiB
`MaxFileSize`, 64 GiB `MaxScanSize`, 32 GiB `PCREMaxFileSize`, 256 GiB
`MaxMatcherWork`, 64 GiB `MaxTemporarySize`, 32 GiB `MaxContiguousSize`, and
14,400,000 ms `MaxScanTime`. Its startup log recorded the expected byte
values for the file, global-size, PCRE, and time limits.

`clamdscan --fdpass --report-json` scanned the authorized 1,529,898,209-byte
USB file through the Unix socket and returned exit 0/`OK` in 171.946 seconds.
The structured report was `COMPLETE`, `status=0`, `CL_TYPE_BINARY_DATA`,
`root_size=logical_bytes=1529898209`, `matcher_bytes=3258676418`,
`contiguous_bytes=1529898209`, `temporary_bytes=0`, `parser_operations=1`,
`detector_operations=2`, and `skipped_operations=0`; it emitted no ZIP
masked-header diagnostic. The service therefore now has clean production-file
acceptance for this authorized input, while the 50 GB service run and broad
parser-corpus gate remain open.

The daemon was stopped, the build source was restored to hash
`9a06260112b0a46fc3108e5ba74d9662fe14d7b37b8c48004cc3daf10ac72da8`, all
temporary service configuration, socket, pid, log, report, copied-input, and
temporary-storage paths were verified absent, and no clamd process remained in
the pinned container.

## Checked fmap nested-coordinate hardening — 2026-08-19

The shared fmap reader and nested-view layer now checks every
`nested_offset + caller_offset` and `nested_offset + length` addition before
using the result. The handle-backed and memory-backed `need`, string, and
line-reading accessors reject wrapped ranges before pointer arithmetic, and
`fmap_duplicate()` rejects nested-offset and real-length overflow instead of
constructing a wrapped view. The line-reader path also rejects a zero-sized
destination capacity before subtracting one from it.

`test_fmap_rejects_wrapped_nested_ranges` covers the memory-backed accessors
and nested-view constructor; the source guard suite now requires both checked
helpers and the regression. The local source guards, shell syntax checks, and
`git diff --check` pass. A focused Sonic1 CTest run did include the canonical
unit-test translation unit, but Sonic1's `fmap.c` hash did not match the
canonical worktree, so that result is not claimed as compiled verification of
the new fmap implementation. Full current-source compilation remains an open
gate because this macOS workspace has no CMake installation or OpenSSL
development headers.

## ZIP masked local-header handling — 2026-08-19

The ZIP parser now treats general-purpose bit 13 as a masked local CRC/size
field when an authoritative central-directory record is available. Member
metadata, CRC validation, and extraction use the central values, while method,
flags, filename, and local extra-field bounds are still checked against the
local header. A standalone local-only scan remains explicitly incomplete
because it cannot establish the member extent; the embedded SFX admission probe
returns a recoverable format rejection instead, so an isolated masked magic
sequence does not taint an otherwise unrelated containing file.

The focused unit coverage includes a central-directory archive whose local
CRC/sizes are zeroed, a masked SFX candidate with no central directory, and a
local-only masked header that must remain fail-visible. The canonical `unzip.c`
and test translation unit were staged temporarily on Sonic1, rebuilt in the
pinned Release container, and the `libclamav` CTest target passed 1/1 in 30.52
seconds. Because the rest of that remote checkout was stale and unchanged,
this is focused mixed-source verification rather than full current-head
qualification. The authorized production-CVD rescan and broad ZIP corpus
qualification remain open release gates.

## DMG/XLM child reservation ownership — 2026-08-20

The DMG reconstructed-partition path already reserved the complete expected
output before writing it, but then used the ordinary child descriptor scanner,
which attempted to reserve the same bytes a second time. It now transfers the
existing reservation to the reservation-aware child scan. XLM extracted images
now always stage through the same quota-accounted descriptor path, even when
temporary retention is disabled; declared image bytes remain reserved through
writing, nested scanning, and cleanup, while write, close, removal, and quota
failures remain sticky incomplete results.

Source guards and `git diff --check` are the current local evidence. Compiled
DMG/XLM execution, sanitizer coverage, real document corpus testing, and
supported-build Sonic1 qualification remain open release gates.

## HTML CSS image streaming — 2026-08-20

The Rust HTML `<style>` handler previously base64-decoded each embedded CSS
image into a whole `Vec<u8>` and passed it directly to
`cli_magic_scan_buff()`. The production handler now uses the base64 decoder as
a reader, writes decoded bytes in 64 KiB chunks to the shared Rust temporary
spool, and performs the nested descriptor scan while the temporary reservation
remains held. Quota, reader, write, and cleanup failures therefore remain
visible as incomplete results instead of allowing an unaccounted decoded child
buffer.

The existing HTML CSS extraction detection test remains the behavioral
regression coverage, and source guards verify that the handler uses
`DecoderReader` and the quota-accounted reader helper rather than the old
direct buffer scan. Dependency-complete Rust/CTest, sanitizer, large
CSS/HTML-corpus, and supported-build Sonic1 qualification remain open release
gates.

## XLM macro-output accounting — 2026-08-20

XLM macro normalization previously emitted formatted script text directly
through `fprintf`, `fwrite`, and `fputc`, so a large generated macro file could
grow outside the shared temporary quota before its legacy descriptor scan.
Formatted and decoded output now passes through a quota-aware writer that
reserves each chunk before writing, retains the aggregate through the scan,
and returns explicit allocation, quota, and write failures. A one-byte quota
regression verifies fail-closed behavior and reservation cleanup; temporary
removal failure is now also retained as an incomplete result.

Source guards and `git diff --check` are the current local evidence. Compiled
XLM execution, sanitizer coverage, real Office corpus testing, and
supported-build Sonic1 qualification remain open release gates.

## Sonic1 clamscan parser-regression matrix — 2026-08-20

The repository's complete `unit_tests/clamscan` collection was counted and
executed in the pinned Sonic1 container `868b213e31020ca243d3c33df5904b26586615005fbae1abf04772f5294f8be1`,
using the Release build `/work/build-current-044db34-release` and source
`/work/clamav-32gb-044db34`. The invocation supplied the same CTest runtime
environment, including the build library search path and static libmspack/
libunrar bindings; an initial direct-module attempt without those bindings
returned false clean results for RAR and was discarded as invalid evidence.

The collection contained 124 tests across the basic, all-match, ALZ,
assorted, bytecode, container-signature, embedded-file, fuzzy-image, hash,
heuristic, image-extraction, InstallShield, LHA/LZH, offset, OLE2, phishing,
quarantine, regex, HTML-URI, and PDF-URI modules. The final module-level run
returned 123 passed and one intentional platform-specific skip; no test
failed. This is useful parser/detector and fail-closed regression evidence,
but the fixtures are repository-sized and use test signatures. A source-hash
comparison found that the build source is not byte-identical to this
worktree in `libclamav/fmap.c`, `libclamav/unzip.c`,
`libclamav_rust/src/codesign.rs`, and `unit_tests/check_clamav.c`; those
differences were preserved and the run is therefore not current-head compile
qualification. It does not close the production-CVD, exact-large-fixture,
broad parser-family, RSS, or current-head Sonic1 qualification gates.

## Current-head parser-sensitive rerun — 2026-08-20

To remove the four source mismatches above, the canonical worktree versions of
`fmap.c`, `unzip.c`, `codesign.rs`, and `check_clamav.c` were staged into the
Sonic1 build source, hash-verified, and rebuilt in Release. The matching
current-head test sources were used from the build source itself; running the
tests from Sonic1's separate `/workspace/ClamAV` checkout was rejected as
stale-source evidence.

The current-head-sensitive rerun passed the all-match, ALZ, LHA/LZH,
InstallShield, OLE2, assorted, and clamscan basic modules. The clamscan basic
module passed 3/3, and the clamd service all-testfiles case passed 1/1. The
WWPack fixture legitimately reports `ClamAV-Test-File.UNOFFICIAL FOUND` under
the hardened engine; the Python clamscan/clamd expectations now accept that
detection while retaining fail-closed expectations for malformed fixtures.
The C `check_clamav` contract already permits that detection precedence.

After verification, all six temporary source/test overlays and their exact
backups were removed. Sonic1 hashes confirmed that the four restored build
files matched their pre-test hashes, the release targets rebuilt successfully,
and no temporary overlay artifacts remained. This closes the identified
source-selection and WWPack expectation issues, but it is still a focused
current-head rerun rather than full current-head CTest, 50 GB, broad
production-CVD, parser-family, or resource-qualification evidence.

## Explicit PCRE fmap eviction — 2026-08-20

The full-map PCRE matcher now calls `fmap_release_unlocked()` immediately
after the PCRE subject scan, and also on failed full-map acquisition, after
releasing the contiguous-subject reservation. The helper scans the owner
bitmap and evicts only pages that are not locked; locked caller windows remain
governed by their corresponding `fmap_unneed` call. This directly enforces the
roadmap's requirement to release all unlocked fmap pages after a bounded
whole-subject consumer rather than waiting for ordinary aging.

The regression `test_fmap_release_unlocked_evicts_whole_subject_pages` pages a
16 MiB handle-backed subject, verifies that all unlocked pages are released,
then verifies that a subsequent read re-enters the read callback. The
canonical `fmap.c`, `fmap.h`, `matcher.c`, and `check_clamav.c` were compiled in
the pinned Sonic1 Release build; the isolated Check case passed with
`Checks: 1, Failures: 0, Errors: 0`. The temporary remote overlay was restored
from hash-verified backups, the Release targets rebuilt successfully, and all
temporary files were removed. This is focused implementation evidence; the
required RSS-before-deep-parse measurement and full PCRE 32 GiB production
qualification remain open.

## Service database provenance binding — 2026-08-20

The strict service qualification gate now snapshots both the production and
edge signature directories before starting clamd. Each snapshot records sorted
relative paths, exact byte counts, and SHA-256 hashes for every regular file;
symlinks, empty databases, and using the same directory for production and edge
roles are rejected. The manifests and their hashes are recorded in
`oracle-binding.txt`, then recomputed after the final workload and compared
byte-for-byte. A database replacement or mutation during qualification now
fails the gate instead of allowing a result to be attributed to an unbound
signature set.

Shell syntax, the source-guard manifest, the synthetic fail-closed POC control,
the runtime-evidence verifier regression, and `git diff --check` pass. This
hardens evidence integrity but does not close the still-missing authorized
production-file, parser-expansion, cold-cache, or full service qualification
workloads.

## Sonic1 service-gate preflight — 2026-08-20

The pinned Sonic1 container currently has the required Release service
binaries for the pinned `044db34` build and the authorized production CVD directory, with the
recorded `main.cvd`, `daily.cvd`, and `bytecode.cvd` files. It also has the
existing exact 32-GiB synthetic boundary corpus and approximately 151 GB free
on `/work`; the container runs as root and can access the kernel cache-drop
control required by the strict cold-cache gate.

The previously mounted USB directory is not present in the current container,
and no copies of the five authorized real files were found under `/work` or
`/mnt`. The strict service qualification was therefore not started: substituting
the synthetic sparse corpus for the missing real production-file role would not
prove the requested production-CVD workload. Once the real files are mounted or
transferred again, the gate now additionally binds both signature directories
with the database-manifest checks recorded above.

## Current-source Release CTest gate — 2026-08-20

The complete CTest inventory for the current-source Release build
`/work/build-current-044db34-release` passed in the pinned Sonic1 container
`868b213e31020ca243d3c33df5904b26586615005fbae1abf04772f5294f8be1`. The
invocation was `ctest --test-dir /work/build-current-044db34-release
--output-on-failure -j2`; all 16/16 tests passed in 573.04 seconds. This
included the regular and Valgrind libclamav, clamscan, clamd, freshclam, and
sigtool suites; Rust; milter protocol and quota; and the large-file source,
POC fail-closed, and runtime-evidence controls. No CTest failure output or
sanitizer/Valgrind failure was reported.

This closes the current-source Release CTest gate and strengthens the
implementation baseline for the production roadmap. It does not substitute
for the still-open authorized real-file/production-CVD service qualification,
exact-edge parser-family qualification, cold-cache service measurements, or
RSS/temporary-space/latency evidence required before release readiness.

## 7-Zip bounded two-coder output — 2026-08-20

The streaming 7-Zip folder decoder previously accepted only one-coder folders.
Common folders containing a decompressor followed by a BCJ or ARM branch
converter therefore could not use the sequential bounded-output path and could
fall back to whole-folder materialization only when the legacy allocation guard
allowed it. The decoder now accepts those two-coder shapes and routes decoder
output through a bounded 256 KiB branch-filter buffer. BCJ/ARM state,
alignment/look-ahead tails, output CRC, and downstream short writes are
preserved. At this August 20 milestone, graphs such as BCJ2 still remained
fail-visible on the streaming path; the bounded canonical four-coder BCJ2
implementation is recorded in the August 24 section below.

The modified `libclamav/7z/7zDec.c` compiled in the pinned Sonic1 Release
build `/work/build-current-044db34-release`, and the full 16-test Release CTest
gate passed after the rebuild in 561.21 seconds. A direct scan of the existing
`clam.7z` fixture returned the expected
`ClamAV-Test-File.UNOFFICIAL FOUND` result. Existing fixtures cover 7-Zip
scanning and the truncated-header control, but no separately identified
two-coder BCJ/ARM archive fixture is currently available in the corpus.
Accordingly, this closes the implementation/build regression for the supported
folder shape but does not claim exact parser-family runtime qualification; a
real two-coder fixture and the broader production-CVD/resource gates remain
open.

## Current-source ASan/UBSan CTest gate — 2026-08-20

The pinned Sonic1 `RelWithDebInfo` sanitizer build initially exposed a real
build-integrity defect: Rust unit-test binaries linked C archives compiled
with `-fsanitize=address,undefined`, but Cargo did not receive the C sanitizer
link runtime. The failure appeared as unresolved `__asan_*` and `__ubsan_*`
symbols in `libclamav_rust`.

`cmake/FindRust.cmake` now derives a test-only `RUST_TESTFLAGS` value from
the configured CMake executable sanitizer flags and passes the corresponding
`-C link-arg` through Cargo. The corrected build reconfigured and rebuilt
successfully in the pinned Sonic1 container
`868b213e31020ca243d3c33df5904b26586615005fbae1abf04772f5294f8be1`.

The exact workflow command, `ctest -C RelWithDebInfo -V -E '_valgrind$'`,
then passed all 11/11 non-Valgrind tests in 254.09 seconds. This included 73
passing Rust tests, libclamav, clamscan, clamd, freshclam, sigtool, milter,
and the large-file source, fail-closed, and runtime-evidence controls. The
temporary remote source overlay was restored to its pre-test hash and its
staging files were removed.

This closes the valid ASan/UBSan CTest gate. It does not replace the still-
open authorized real-file/production-CVD service qualification, exact-edge
parser-family qualification, cold-cache service measurements, or
RSS/temporary-space/latency evidence required before release readiness.

## LHA/LZH declared-output admission — 2026-08-20

The Rust LHA/LZH scanner already used the bounded `FMapReader` and a
quota-accounted temporary spool, but it could write decoder output beyond the
member's declared size and only reject it after the decoder reached EOF. The
scanner now checks each 64 KiB output chunk before writing, uses checked native
size conversions for compressed and uncompressed metadata, and validates CRCs
for empty members as well. The focused Rust regression covers exact-fit,
overrun, and declared-size underflow cases. Compilation, Sonic1 execution,
corpus, sanitizer, RSS, and large-member qualification remain to be run for
this current change.

## Nested RFC822 mail body spooling — 2026-08-20

The remaining large-mail materialization exception for complete nested
messages is now narrowed. `message/rfc822` and `message/delivery-status`
bodies enter the existing quota-accounted file-backed spool and are returned to
the normal scanner as completed nested input. The legacy line-list state
machine remains for `message/partial`, `external-body`, disposition-notification,
and unknown message subtypes, where a raw nested scan would change semantics or
hide an unsupported feature. A new C regression crosses the former 64 MiB
materialization boundary with a nested RFC822 body; source guards cover both
the policy and the regression registration.

Local shell syntax, the capability manifest, source guards, and `git diff
--check` pass. The local macOS host lacks the OpenSSL development headers for a
C syntax/build check. MCP-SSH rejected exporting the complete current private
worktree archive to Sonic1, so compiled current-source and memory-qualification
evidence for this change remains open and no remote result is attributed to it.

## Daemon admission capability enforcement — 2026-08-20

The large-file `clamd` startup admission now enforces the certified
large-file build definition and the FILDES descriptor-passing capability,
rather than merely reporting them in the startup manifest. Its scaled memory
requirement also includes the configured `MaxContiguousSize`, ensuring that a
retained 32 GiB contiguous matcher subject cannot be under-admitted when only
the file and logical-scan limits are lowered. The source-guard suite, capability
manifest, and `git diff --check` pass. A compiled current-source Sonic1 result
remains open because the current private worktree export is not permitted by
MCP-SSH.

The same gate now rejects large-file `clamd` admission on non-Linux-x86-64
targets. This preserves the plan's first-release boundary: CMake may still
build other 64-bit targets for development, but no unqualified AArch64 or
macOS daemon can present the certified production envelope.

The admission call was moved into `recvloop()` immediately after all
configured scan, temporary, contiguous, and PCRE limits are applied. The
previous ordering checked the engine's historical defaults before applying the
configuration file, which could bypass the resource gate for a requested 32
GiB daemon. The corrected path frees the engine and returns before creating the
worker pool when admission fails.

The production daemon admission also rejects `MaxScanSize=0`, which retains
legacy unlimited behavior for library callers but cannot be used for the
certified daemon envelope. This prevents the 64 GiB logical budget and its
memory admission calculation from being bypassed by an unbounded setting.

The dependency-limited macOS host could not compile the full tree because its
OpenSSL headers are absent. A temporary, non-repository header shim was used
only to syntax-check the changed Linux-style `clamd/largefile_admission.c` and
the complete `clamd/server-th.c` translation units; both passed. The shim was
removed immediately afterward. This is source syntax evidence, not a
dependency-complete or runtime qualification result.

## Front-end ingress admission parity — 2026-08-21

The `clamd` startup resource gate previously inspected engine limits but not
the front-end `StreamMaxLength` and `OnAccessMaxFileSize` options. An explicit
32-GiB front-end limit could therefore retain the historical startup bypass
when the engine's `MaxFileSize` remained at a legacy value, despite allowing
large disk-backed or on-access inputs. Admission now considers the maximum of
all three ingress limits, and a focused test covers both options. Source guards
and whitespace validation remain the available local evidence; compiled
daemon and Sonic1 qualification remain open.

`check_clamd` now links the production admission translation unit and covers
both deterministic boundaries: historical defaults accept without probing a
host path, while `MaxScanSize=0` is rejected with the certified-budget reason.
The tests are registered in the clamd parser case and source-guarded.

## Parallel MULTISCANREPORT aggregation — 2026-08-20

The structured `MULTISCANREPORT` command now dispatches through the normal
`MULTISCAN` path instead of unconditionally degrading to `CONTSCAN`. The
one-worker fallback remains sequential, while multi-worker directory scans
retain parallelism. Child workers run the structured library scan path,
merge reports into the parent under the multiscan group mutex, and parent-side
skip/error reports use the same lock. Child workers suppress their own
transport frames; the parent emits one aggregate report frame after all
children finish. This prevents both the previous loss of child reports and
interleaved response frames. Terminated groups suppress late child
report/status updates before the parent connection can be released during
daemon shutdown.

This is source-level contract evidence only. Dependency-complete compiled
protocol tests, report parity, production-CVD coverage, sanitizer runs, and
resource measurements remain open release gates.

## YARA-compatible exact-tail reads — 2026-08-20

The built-in YARA-compatible executor had an exact-boundary defect: its
non-external fmap integer reader rejected a value when
`offset + sizeof(type) == fmap->len`. It now uses subtraction-based checked
bounds, accepting the valid exact-tail read while rejecting an out-of-range
offset without arithmetic wraparound. `check_matchers` contains a focused
four-byte exact-tail regression.

This is a targeted correctness fix, not a claim of full YARA or production
signature qualification; those parser/matcher and resource gates remain open.

## Nonzero fmap source offsets — 2026-08-20

The handle-backed fmap constructor incorrectly compared the absolute source
offset with the exposed window length. A valid tail window near the end of a
large file could therefore be rejected when `offset >= len`, even though the
requested source range was valid. The constructor now checks only for
`offset + len` arithmetic overflow, and a callback-backed regression reads a
window at source offset 4096 whose length is smaller than that offset.

This is a targeted fmap range correction. Descriptor-backed large-file,
nested-window, sanitizer, and supported Linux/Sonic1 qualification remain
release gates.


## Descriptor root-size preflight — 2026-08-20

`cl_scandesc_ex2()` previously called `fmap_new()` before applying the root
`MaxFileSize` and `MaxScanSize` limits. That could allocate the large-file
page bitmap and reserve address space for an input that was already known to
be over policy, and its `st_size <= 5` fast path could bypass a configured
limit entirely. The descriptor path now rejects negative sizes, records the
root size, and runs a metadata-only limit preflight before fmap creation. The
preflight uses the normal scan reconciliation path so `AlertExceedsMax`,
callbacks, reports, and legacy result semantics are retained; a forced
`fmap_new()` failure regression confirms that an over-limit descriptor returns
`CL_EMAXSIZE` without constructing the full map.

This closes the known-size descriptor admission ordering defect. Path/fd
front-end parity, unknown-length stream enforcement, parser-family execution,
and resource qualification remain release gates.

## Nested child-size preflight — 2026-08-20

The same ordering defect existed below the root: extracted descriptor scans
and nested fmap windows could reserve temporary space or create a child fmap
before `cli_recursion_stack_push()` applied the logical-size and file-count
limits. A shared child-size preflight now runs before those allocations. It
uses time-only admission for normalized or handler-retyped views, matching the
existing logical-object accounting contract, and full shared admission for
real extracted children. Force-to-disk nested scans are rejected before their
temporary copy is staged. The recursion push retains its duplicate check as a
defensive invariant. The force-to-disk nested-range regression verifies that
an over-limit child returns `CL_EMAXSIZE` without reading source bytes.

This closes nested child-map admission ordering at the source level. Compiled
parser execution, report parity, production CVD coverage, sanitizer/resource
qualification, and exact-size runtime evidence remain release gates.

## HFS+ temporary-fork accounting — 2026-08-20

The HFS+ extractor previously materialized declared data/resource forks and
compressed decmpfs output without charging those temporary files to the
shared `MaxTemporarySize` budget. Fork extraction now reserves its declared
size before staging, keeps the reservation through the reserved-child scan,
and transfers ownership explicitly when a compressed resource fork is handed
to the decmpfs path. Compressed output is checked against its declared size
and configured scan limits; unsupported compression, incomplete extents,
short output, and cleanup failures mark the scan incomplete and non-cacheable.

Source guards and `git diff --check` are the current local evidence. A
dependency-complete HFS+ build, corpus/fault-injection regression, sanitizer
run, and supported-build Sonic1 qualification remain open release gates.

## HFS+ declared-attributes failure propagation — 2026-08-20

The HFS+ catalog walker previously treated every attributes-tree header failure
as if the optional attributes fork were absent. A malformed or truncated
declared attributes tree could therefore suppress decmpfs metadata inspection
and leave compressed files incompletely inspected. The walker now skips the
attributes tree only when both its declared logical size and block count are
zero; any non-empty declared tree that cannot be read or validated marks the
scan incomplete and propagates the parser error.

The unit suite now includes a synthetic HFS+ volume with valid extent/catalog
headers and a non-empty attributes fork outside the map; it requires the
fail-visible `CL_EFORMAT` result and non-cacheable state. A dependency-complete
HFS+ build, sanitizer run, and supported-build Sonic1 qualification remain open
release gates.

## RAR staging cleanup propagation — 2026-08-20

The RAR fallback staging helper already rejected a short mapped copy, but its
write, short-read, and rewind failure paths used unchecked `close()` and
`unlink()` calls. A cleanup failure could consequently leave a staged file
behind without being represented by the helper's result. Those paths now use a
shared cleanup routine, the portable `cli_unlink()` wrapper, and preserve the
original staging error while surfacing cleanup failure when it is otherwise the
only failure.

This is source-level evidence only. Fault-injected RAR staging, dependency-
complete build, sanitizer run, and supported-build Sonic1 qualification remain
open release gates.

## UDF extended-file-entry fail-closed handling — 2026-08-20

UDF extended file-entry descriptors are a valid file-entry form, but the
parser does not implement their allocation and extended-attribute semantics.
The previous branch silently skipped them, allowing the later identifier/file
entry pairing to inspect only ordinary entries and potentially report a clean
result with content omitted. The parser now marks the layer incomplete and
returns an explicit unsupported-result status as soon as an extended entry is
encountered.

This is source-level evidence only. A compiled UDF fixture containing an
extended file entry, sanitizer execution, and supported-build Sonic1
qualification remain open release gates.

## HFS+ ExtentOverflow boundary — 2026-08-20

HFS+ data and resource forks expose eight inline extent descriptors. A fork
that needs additional descriptors stores them in the ExtentOverflow B-tree,
which this parser does not yet implement. The previous branch returned a
format error after the inline prefix without identifying the unsupported
feature. It now marks the layer incomplete and returns `CL_EUNPACK` before any
partial fork is scanned as complete. The resource-compression completion log
was also corrected because that path is implemented through the bounded
temporary-fork and decoder flow.

This is source-level evidence only. A compiled HFS+ ExtentOverflow fixture,
sanitizer execution, and supported-build Sonic1 qualification remain open
release gates.

## XLM STRING extension boundary — 2026-08-20

BIFF8 `STRING` records with rich-text formatting runs or East-Asian phonetic
extensions have additional payload fields that the extractor does not decode.
The prior implementation logged those flags and continued using the base
string layout, which could produce a misaligned macro representation while
still reporting success. The extractor now marks the layer incomplete and
returns `CL_EUNPACK` before scanning that output. A focused regression covers a
rich-string record and requires a non-cacheable unsupported result.

This is source-level and unit-test evidence only. A dependency-complete XLM
corpus, sanitizer execution, and supported-build Sonic1 qualification remain
release gates.

## TNEF message-body omission — 2026-08-20

The TNEF message-level `attBODY` attribute was explicitly logged as “not being
scanned,” but the parser retained its initial clean result. A TNEF message
with a body could therefore leave required content uninspected without a
sticky incomplete result. The parser now marks that path incomplete and
returns `CL_EPARSE` for an otherwise-clean direct call, while preserving any
stronger detection or operational error.

A focused body-bearing TNEF regression now requires the non-cacheable,
fail-visible result. Full TNEF corpus, sanitizer, and supported-build Sonic1
qualification remain release gates.

## GPT primary-table validation fallback — 2026-08-23

GPT validation could return an operational partition-table read or deadline
failure while the dispatcher treated the result as an ordinary malformed
primary header and fell back to a clean secondary-only scan. The validation
status is now preserved: only `CL_EFORMAT` is eligible for the documented
primary/secondary format fallback; `CL_EREAD`, `CL_ETIMEOUT`, and other
operational failures terminate the GPT layer and remain incomplete. A focused
unit regression injects a primary-table callback failure while leaving the
secondary copy readable. Compiled GPT media, fault injection, sanitizer, and
Sonic1 qualification remain release gates.

## TNEF zero-length attribute checksum accounting — 2026-08-23

TNEF zero-length attributes still carry their two-byte checksum. The parser
previously continued at the checksum instead of consuming it, so a nonzero
checksum could be interpreted as the next attribute level and desynchronize
the remaining container walk. The zero-length path now reads and advances
over the checksum, preserving `CL_EREAD` for an in-range callback failure and
an incomplete parse for a truncated checksum. A focused exact-EOF regression
covers the corrected boundary; compiled TNEF corpus, sanitizer, and Sonic1
qualification remain release gates.

## VBA project temporary-spool accounting — 2026-08-20

The modern VBA project-directory extractor previously wrote generated script
output without charging those bytes to the shared `MaxTemporarySize` budget,
then scanned the resulting descriptor through the legacy non-reserved path.
Each generated write now reserves its bytes before writing; ownership is
transferred to the OLE caller and held through the reserved child scan, then
released on success, candidate retry, and cleanup. Existing macro metadata and
candidate-selection behavior are preserved.

Source guards and `git diff --check` pass. Dependency-complete Office/VBA
corpus execution, sanitizer coverage, and supported-build Sonic1 qualification
remain open release gates.

## InstallShield temporary-output accounting — 2026-08-20

InstallShield MSI, legacy embedded-file, and CAB extraction paths previously
created temporary output without charging the shared `MaxTemporarySize` budget
and scanned completed members through the legacy descriptor path. The three
paths now reserve output before or during staging, require complete writes,
check declared CAB output before each write, and use reserved-child scans while
the reservation is held. Close/removal failures remain sticky incomplete
results and cannot replace an earlier detection or parser failure.

Source guards and `git diff --check` pass. Dependency-complete InstallShield
corpus execution, sanitizer and fault-injected cleanup coverage, and
supported-build Sonic1 qualification remain open release gates.

## InstallShield unsupported control metadata — 2026-08-21

The InstallShield MSI extractor previously returned `CL_SUCCESS` when any of
its six control metadata fields were nonzero, even though that layout was not
handled by the bounded parser. A confirmed layer could therefore skip MSI
members and still look clean. The branch now records an explicit unsupported,
non-cacheable result (`CL_EUNPACK`), while weak candidates are still rejected
by the separate header-admission check. A focused regression covers the
unsupported control layout and its sticky cache barrier. Full InstallShield
corpus, sanitizer, and supported-build Sonic1 qualification remain open.

## HWP temporary-output accounting — 2026-08-20

The shared HWP3/HWP5/HWPML raw-deflate helper previously wrote decompressed
temporary output without charging the shared `MaxTemporarySize` budget, and
its HWP5/HWPML callbacks used the legacy child descriptor path. It now reserves
each output chunk, holds that ownership through the callback, uses the
reserved-child scan, and checks temporary close/removal failures. HWPML
base64-decoded input keeps its reservation through the direct child scan and
releases it after cleanup.

Source guards and `git diff --check` pass. Dependency-complete HWP/HWPML corpus
execution, sanitizer and fault-injected cleanup coverage, and supported-build
Sonic1 qualification remain open release gates.

## Script-encoded HTML staging — 2026-08-20

The script-encoded HTML decoder previously ignored temporary-output write
failures and returned success when the encoded payload ended before the
declared decoded length. Its generated file also bypassed the shared
`MaxTemporarySize` accounting. The decoder now reserves each emitted chunk,
requires complete writes and close, treats incomplete input or decoding as a
sticky incomplete result, and retains the reservation until the completed
child directory scan takes ownership. A unit regression verifies that a
one-byte temporary budget fails visibly without leaving a reservation behind.

Source guards and `git diff --check` are the current local evidence. A
dependency-complete HTML/script build, fault-injected write/read/close
coverage, sanitizer run, large HTML corpus, and supported-build Sonic1
qualification remain open release gates.

## BinHex short resource-fork omission — 2026-08-20

BinHex previously logged and abandoned a nonzero resource fork shorter than the
minimum resource-stream boundary, which could leave required resource content
uninspected while the enclosing scan remained clean. The parser now marks that
case incomplete and returns `CL_EPARSE`; a zero-length resource fork remains an
allowed empty fork. A focused encoded BinHex regression requires the
non-cacheable, fail-visible result, and source guards cover the new boundary.

Compiled BinHex execution, legacy-mail corpus coverage, sanitizer execution,
and supported-build Sonic1 qualification remain open release gates.

## Word macro-directory truncation — 2026-08-20

The legacy Word macro-directory reader treated a truncated or unknown record
stream as “no macros” and allowed the OLE scan to continue without a sticky
incomplete result. It now validates the declared directory range, reports
position/read/record failures through the scan context, and rejects the
recognized document as incomplete before any partial macro project is used.
A direct truncated-directory regression and source guards cover the boundary.

Compiled legacy-Word/OLE execution, sanitizer and allocation-fault coverage,
and supported-build Sonic1 qualification remain open release gates.

## 7-Zip encryption fail-closed propagation — 2026-08-20

7-Zip encrypted headers and encrypted members previously relied on the optional
`Heuristics.Encrypted.7Zip` alert; when that alert was enabled, the parser could
return a clean status even though the ciphertext was not inspected. Both the
archive-header and member paths now mark the scan incomplete and return a
non-clean parser result when no stronger detection result exists, while
preserving the heuristic alert and any stronger result.

Compiled encrypted 7-Zip fixtures, sanitizer coverage, and supported-build
Sonic1 qualification remain open release gates.

## Structured unsupported-result classification — 2026-08-20

Structured reports now classify encrypted, unavailable, unimplemented, legacy
ABI, and unrepresentable parser paths as `UNSUPPORTED` even when the parser
returns `CL_EPARSE`. This prevents an encrypted 7-Zip layer from being
misreported as confirmed malformed content. A focused report regression covers
the encrypted-header reason; compiled current-head and service qualification
remain release gates.

## HFS+ missing-map entry classification — 2026-08-25

`cli_scanhfsplus()` previously treated a null context and a missing fmap as
the same `CL_ENULLARG` condition. A recognized HFS+ layer with no input map
therefore lacked the sticky incomplete state used by its volume, tree, fork,
and compressed-output failure paths.

The entry point now preserves `CL_ENULLARG` for a null context and returns
`CL_EPARSE` with `HFS+ input map is unavailable` for a missing fmap after
marking the scan incomplete. The isolated production-linked `hfs_map` TCase
passes 1/1. Full HFS+ corpus, sanitizer, materialized large-file, certified
Linux x86-64, production-CVD, and Sonic1 qualification remain release gates.

## UDF missing-map entry classification — 2026-08-25

`cli_scanudf()` entered descriptor traversal without separating a null context
from a missing fmap. The descriptor helper had no map to inspect in the latter
case, leaving the direct parser boundary inconsistent with the already
fail-visible descriptor and extraction paths.

The entry point now preserves `CL_ENULLARG` for a null context and returns
`CL_EPARSE` with `UDF input map is unavailable` for a recognized UDF parser with
no fmap, after marking the scan incomplete. The production-linked `udf_map`
TCase passes 1/1. Full UDF corpus, width review, sanitizer, materialized
large-file, certified Linux x86-64, production-CVD, and Sonic1 qualification
remain release gates.

## Script normalization deadlines — 2026-08-22

Script normalization had two large-map paths that could continue through
bounded fmap windows and normalized-output writes without checking the shared
deadline. Parser entry, file-backed normalization, and in-memory matcher-window
processing now preserve `CL_ETIMEOUT` and run the existing buffer, matcher, file,
and temporary-reservation cleanup. A dispatch-level expired-context regression
and source guards cover the contract; compiled large-script corpus, sanitizer,
and Sonic1 qualification remain release gates.

## ZIP variable-header regression expansion — 2026-08-20

The focused ZIP truncation regression now exercises all three variable local
header boundaries: a filename longer than the mapped slice, a truncated extra
field, and a ZIP64 extra field that does not contain its declared size values.
Each case requires `CL_EPARSE`, sticky incomplete state, and a non-cacheable
fmap. This strengthens exact-trigger coverage; compiled current-head,
sanitizer, and broad ZIP corpus qualification remain release gates.

## Structured report parser hardening — 2026-08-20

The shared clamd report consumer no longer classifies reports by substring
matching. It now parses a bounded JSON object, reads only top-level typed
fields, rejects malformed or contradictory verdict/completion/status
combinations, and decodes `last_alert` through the same JSON parser. This
prevents a nested or inconsistent field from being accepted as a clean result
and keeps the rule shared by clamdscan, milter, and on-access consumers.

A focused clamd unit regression covers nested and contradictory reports.
Dependency-complete builds, service protocol qualification, and supported-build
Sonic1 qualification remain open release gates.

## RFC 1341 partial-body spool handoff — 2026-08-20

`message/partial` now enters the disk-backed MIME spool instead of retaining its
body in the 64 MiB linked-line representation. RFC 1341 reassembly streams the
spooled body directly into the numbered partial file, preserving transfer
decoding and temporary-space accounting without creating a second full-size
staging copy. The existing missing-fragment regression continues to cover
fail-visible reassembly, and a new 65 MiB fragment fixture verifies that the
partial-body path crosses the former materialization boundary successfully.

External-body and unknown `message/*` subtypes
remain explicit unsupported materialization cases. Dependency-complete C/CTest,
sanitizer, broad MIME corpus, and supported-build Sonic1 qualification remain
open release gates.

## RFC 2298 disposition-notification spool handoff — 2026-08-20

message/disposition-notification now uses the disk-backed MIME body spool and
the ordinary bounded fileblob scan path. This removes the former 64 MiB
linked-line materialization boundary while preserving transfer decoding,
temporary-space accounting, and the existing raw scan behavior. A new 65 MiB
regression fixture verifies that the body is scanned past the old
materialization limit.

External-body references and unknown message/* subtypes remain explicit
unsupported materialization cases. Dependency-complete C/CTest, sanitizer,
broad MIME corpus, and supported-build Sonic1 qualification remain open release
gates.

## Structured report close-error propagation — 2026-08-20

The CLI JSONL writers previously ignored `fclose()` failures after writing a
structured report. They now log a close failure and propagate it as a front-end
error in both `clamscan` and `clamdscan`, so a delayed filesystem failure cannot
leave incomplete evidence attached to an otherwise successful invocation.

The source guards and `git diff --check` pass. Dependency-complete front-end
builds, fault-injected report-output coverage, and supported-build Sonic1
service qualification remain open release gates.

## Stdin over-limit staging closeout — 2026-08-20

`clamscan` now initializes the stdin over-limit result to `CL_EMAXSIZE` before
attempting its sentinel file. If sentinel creation fails, the path therefore
returns a deterministic limit result instead of an uninitialized `ret`. The
normal and over-limit staging paths also check `fclose()` and refuse to scan or
report success when buffered temporary output cannot be closed.

The source guards and `git diff --check` pass. Dependency-complete front-end
builds, fault-injected stdin staging, and supported-build Sonic1 qualification
remain open release gates.

## Rust parser failure accounting — 2026-08-20

Rust-backed parser failures previously set only the Rust-side sticky
`scan_incomplete` flag and called `emax_reached()`. They now call the shared C
`cli_mark_scan_incomplete()` helper with a static classification reason. This
keeps the common no-cache propagation, increments `skipped_operations`, and
preserves the first failure reason used by structured reports; the detailed
decoder error remains in the Rust log without storing a dangling temporary
pointer in `cli_ctx`.

The source guards, capability manifest, runtime-evidence verifier regression,
and `git diff --check` pass. `cargo test --offline --lib` could not start
because the pinned `clam-sigutil` Git dependency is not present in the local
Cargo cache. Dependency-complete Rust/CTest, sanitizer, and supported-build
Sonic1 qualification therefore remain open release gates.

## Clamscan directory enumeration closeout — 2026-08-20

The `clamscan` directory walker now treats `readdir()` and `closedir()` errors
as scan errors. A directory that can only be partially enumerated, or whose
descriptor cannot be closed cleanly, can no longer silently produce a clean
result after scanning the entries that happened to be visible.

Source guards and `git diff --check` are the current local evidence.
Fault-injected directory traversal, dependency-complete front-end builds, and
supported-build Sonic1 qualification remain release gates.

## Clamd directory-walk error propagation — 2026-08-20

The shared `cli_ftw()` walker used by clamd directory and `MULTISCAN` paths
now preserves allocation/stat errors and reports `readdir()` or `closedir()`
failures through the existing structured skip callback. Entries collected before
an operational failure may still be scanned, but the overall request cannot be
reported clean or cacheable as if the directory were complete.

Source guards and `git diff --check` are the current local evidence.
Fault-injected service traversal, dependency-complete builds, and supported-
build Sonic1 qualification remain release gates.

## OLE/VBA temporary-directory search failures — 2026-08-20

The OLE/VBA directory-file search now distinguishes an ordinary no-match from
an incomplete traversal. Failed `LSTAT()`, `readdir()`, `closedir()`, or
temporary-directory opening operations mark the scan incomplete instead of
silently omitting the VBA project.

Source guards and `git diff --check` are the current local evidence.
Fault-injected OLE/VBA traversal, dependency-complete builds, and supported-
build Sonic1 qualification remain release gates.

## Shared temporary-directory cleanup closeout — 2026-08-20

The shared `cli_rmdirs()` cleanup helper now fails closed when directory
enumeration, child inspection, or descriptor close operations fail. Parser
cleanup callers that already propagate its return value therefore cannot
report a clean, cacheable result while temporary output removal was
uncertain.

Source guards and `git diff --check` are the current local evidence.
Fault-injected cleanup, dependency-complete builds, and supported-build
Sonic1 qualification remain release gates.

## PE unpacked-output deadlines — 2026-08-22

The internal MEW, Upack, FSG, Petite, PEspin, yC, WWPack, NsPack, and Aspack
paths now propagate scan context into the common deadline-aware rebuilt-output
writer. The direct UPX/FSG path, yC/WWPack output, Aspack fallbacks, and common
nested-scan handoffs preserve timeout and short-write failures. Deterministic
timeout/short-write injection, compiled PE unpacker corpus, sanitizer, and
Sonic1 qualification remain release gates.

## Structured-text traversal deadlines — 2026-08-22

The structured credit-card/SSN detector consumed 8 KiB fmap windows without a
shared cancellation checkpoint. It now checks the deadline at parser entry and
before every window, marks timeout as incomplete, and preserves `CL_ETIMEOUT`
instead of returning clean after a partial scan. A focused expired-context
regression and source guards cover the contract; compiled large-text corpus,
sanitizer, and Sonic1 qualification remain release gates.

## HTML normalization deadlines — 2026-08-22

HTML normalization and script-encoded extraction previously consumed 8 KiB
input chunks without a shared cancellation checkpoint, while UTF-16 conversion
could continue through its full input after the deadline. The normalizer,
script-encoder, UTF-16 converter, and HTML wrappers now preserve timeout as
`CL_ETIMEOUT`, mark the layer incomplete, and retain temporary-file cleanup.
Focused normalizer, script-encoder, and dispatch regressions plus source guards
cover the contract; compiled HTML corpus, sanitizer, and Sonic1 qualification
remain release gates.

## PDF filter traversal deadlines — 2026-08-22

The legacy PDF filter path enforced allocation and decoded-output limits but
could spend its scan budget inside ASCII85, RunLength, Flate, ASCIIHex, LZW, or
filter-chain traversal without a shared deadline checkpoint. Parser entry,
filter selection, parameter walks, decoder resynchronization, and the main
filter loops now preserve `CL_ETIMEOUT` and release decoder/output state on
timeout. A direct expired-context regression and source guards cover parser
entry; the existing 1 GiB contiguous-filter boundary, compiled decoder corpus,
sanitizer, and Sonic1 qualification remain release gates.

## EGG traversal deadlines — 2026-08-22

The scanner-facing EGG path already checked time while writing streamed member
output, but archive indexing, file/block metadata traversal, and decoder loops
could continue without a parser-owned deadline checkpoint. An extended open
path now binds the scanning context to the EGG handle; indexing, metadata,
stored/deflate/BZip2/LZMA streaming, and legacy block traversal preserve
`CL_ETIMEOUT` and mark the scan incomplete. The legacy open API remains a
no-context wrapper for compatibility. A direct expired-context regression and
source guards cover parser entry; callback-injected timeout, compiled EGG
corpus, sanitizer, and Sonic1 qualification remain release gates.

## HWP3 traversal deadline — 2026-08-22

HWP3 now checks the shared deadline at parser entry and while walking
document-info/summary metadata, paragraph characters and content, font-table
entries, and information blocks. Timeout returns remain fail-visible
`CL_ETIMEOUT` results through the existing callback cleanup paths. A direct
expired-context regression and source guards cover parser entry; compiled
HWP3 corpus, sanitizer, and Sonic1 qualification remain release gates.

## OLE2/VBA traversal deadline — 2026-08-22

OLE2 now checks the shared deadline while walking the property tree and sector
chains, materializing VBA and embedded streams, scanning XLM/image streams,
inflating MSO streams, and materializing encrypted streams. Timeout results
retain `CL_ETIMEOUT` through temporary-file and decoder cleanup. A direct
expired-context regression and source guards cover parser entry; compiled
OLE2/VBA corpus, sanitizer, and Sonic1 qualification remain release gates.

## 7-Zip extraction deadline — 2026-08-22

The 7-Zip interface already checked limits between members, but long
`SzArEx_Open` and extraction operations could run without returning to ClamAV.
Its streaming output callback and fmap input read/seek callbacks now check the
shared deadline and preserve `CL_ETIMEOUT` through temporary-output and decoder
read cleanup; parser entry still fails fast for an expired context. Direct
entry and deterministic input-timeout regressions plus source guards cover the
boundaries; compiled solid-archive corpus, sanitizer, and Sonic1 qualification
remain release gates.

## 7-Zip legacy-fallback output deadline — 2026-08-22

The bounded 7-Zip path already checked deadlines in its streaming extraction
callback, but the compatibility fallback for decoder folders below the 1 GiB
individual-allocation ceiling wrote its materialized buffer directly with
`cli_writen()`. That fallback now uses the same deadline-aware output callback,
preserving `CL_ETIMEOUT` before temporary output can be treated as complete.
Compiled fallback/solid-folder timeout injection, corpus, sanitizer, and
Sonic1 qualification remain open.

## Clamscan directory-entry inspection closeout — 2026-08-20

Directory scans now count failed per-entry `LSTAT()` and symlink-follow
`CLAMSTAT()` calls, as well as entry-name allocation failures, as errors. A
vanished or inaccessible child is therefore not silently omitted from an
otherwise clean directory result; symlinks deliberately excluded by policy
remain normal exclusions.

Source guards and `git diff --check` are the current local evidence.
Fault-injected entry inspection, dependency-complete front-end builds, and
supported-build Sonic1 qualification remain release gates.

## RFC 1341 partial-directory traversal closeout — 2026-08-20

RFC 1341 `message/partial` reassembly now fails closed when its temporary
directory cannot be opened, fully enumerated, or closed. A successful nested
scan is attempted only after every numbered fragment has been found and the
directory traversal has completed cleanly.

The source guards and `git diff --check` pass. Fault-injected partial-directory
traversal, dependency-complete builds, and supported-build Sonic1 qualification
remain release gates.

## Parser error status fail-closed policy — 2026-08-20

The central result policy now marks a scan incomplete when a parser or decoder
returns `CL_EFORMAT`, `CL_EPARSE`, `CL_EREAD`, or `CL_EUNPACK` without having
already recorded the shared sticky state. This closes the path where a later
raw matcher could otherwise make a confirmed, partially inspected layer look
clean or cacheable.

The focused policy regression, source guards, capability manifest, runtime
evidence verifier, and `git diff --check` pass. Dependency-complete C/CTest,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## Unspecified parser-error reconciliation — 2026-08-20

The central result policy now treats an unspecified `CL_ERROR` returned by a
parser or decoder as a sticky incomplete result and preserves that status
through reconciliation. Previously it could be treated as advisory, allowing
the later raw pass to overwrite it with `CL_SUCCESS` and making a partially
inspected layer appear clean or cacheable.

The focused parser-result regression and source guards are the current local
evidence. Dependency-complete parser execution, sanitizer coverage, and
supported-build Sonic1 qualification remain release gates.

The reconciliation policy also now covers unmarked parser/decoder
`CL_EOPEN`, `CL_ECREAT`, `CL_EACCES`, and `CL_EMAP` returns, preserving those
operational failures instead of allowing a later raw pass to report clean.

## SIS malformed member-offset propagation — 2026-08-20

Legacy SIS extraction previously logged and skipped a non-empty member whose
declared offset pointed inside the package header, allowing the containing
layer to finish clean after required content was omitted. The path now marks
the layer incomplete and preserves `CL_EPARSE` while continuing to inspect any
valid sibling members. A focused public-map regression and source guard cover
the boundary; compiled SIS corpus and sanitizer qualification remain release
gates.

## MBR partition-limit propagation — 2026-08-20

MBR partition scanning previously stopped at `MaxPartitions` while returning
success, even when a non-empty primary or logical partition remained
uninspected. The primary and extended-partition paths now mark that omission
incomplete and preserve `CL_EMAXFILES`; empty trailing primary entries are
recognized as fully inspected. A focused zero-limit public-map regression and
source guards cover the primary boundary; extended-partition execution remains
a compiled qualification gate.

## APM/GPT partition-limit propagation — 2026-08-20

APM and GPT partition tables now return `CL_EMAXFILES` and mark the scan
incomplete when `MaxPartitions` leaves declared entries uninspected. Existing
parser errors and detections remain stronger outcomes. A focused APM
zero-limit regression and source guards cover the APM boundary; compiled GPT
and partition-corpus qualification remain open.

## UDF file-list completeness — 2026-08-20

UDF now fails closed when the file-identifier and file-entry descriptor lists
have different lengths instead of silently dropping unmatched entries. The
new path returns `CL_EPARSE`, marks the scan non-cacheable, and has a focused
synthetic descriptor-sequence regression; full UDF qualification remains open.

## ALZ metadata failure propagation — 2026-08-20

The Rust ALZ callback previously continued extraction when its required
`cli_matchmeta()` metadata operation returned `CL_EFORMAT`. The C metadata
matcher returns success, detection, or an operational status; `CL_EFORMAT` is
therefore not a normal “no metadata match” result. The callback now stops and
preserves that parser status, so a metadata-inspection failure cannot be
overwritten by a later clean member scan.

A focused Rust helper regression and source guards cover the boundary.
Dependency-complete Rust/CTest, malformed-metadata corpus, sanitizer, and
supported-build Sonic1 qualification remain open release gates.

## OLE2 temporary-tree error propagation — 2026-08-20

Recursive OLE2 scans now preserve the distinction between a globally indexed
stream that belongs to another subtree and an existing OLE10/XLM/image stream
that cannot be inspected, opened, or closed. Confirmed temporary-directory open
failures are also incomplete, so extracted embedded content cannot disappear
silently from an otherwise clean result.

The source guards and `git diff --check` pass. Fault-injected OLE2 tree
execution, dependency-complete builds, sanitizer coverage, and supported-build
Sonic1 qualification remain release gates.

## Legacy OLE macro traversal closeout — 2026-08-20

Legacy VBA, PowerPoint VBA, and Word-macro extraction now distinguishes a
globally indexed file that belongs to another recursive subtree from a present
file that cannot be inspected, opened, parsed, decompressed, or closed. Those
failures remain sticky incomplete results instead of being silently skipped.

The source guards and `git diff --check` pass. Fault-injected OLE/VBA
execution, dependency-complete builds, sanitizer coverage, and supported-build
Sonic1 qualification remain release gates.

## OLE2 indexed-child open failures — 2026-08-20

The OLE2 summary-information scanner previously ignored an indexed stream when
its temporary file could not be opened. Reservation-owned extracted files and
directories could likewise return `CL_EOPEN` without setting the containing
scan's sticky incomplete state. Those paths now mark the scan incomplete and
preserve an explicit open/access result, while an optional absent normalized
directory remains a normal no-op.

The shared non-reserved extracted-directory path now applies the same rule to
confirmed child-file open/close failures and to child descriptor inspection or
map-creation failures.

Source guards and `git diff --check` are the current local evidence.
Fault-injected OLE2 temporary-child open coverage, dependency-complete builds,
sanitizers, and supported-build Sonic1 qualification remain release gates.

## PDF extraction decoder-status propagation — 2026-08-20

The PDF decoder already rejected truncated Flate/LZW streams and marked the
shared scan incomplete, but `pdf_extract_obj()` converted the resulting
`CL_EPARSE` back to success. That made the direct extraction contract weaker
than the decoder contract and allowed an incomplete filtered object to look
successful to callers outside the central scanner.

The extraction layer now preserves `CL_EPARSE`. `pdf_find_and_extract_objs()`
continues with independent objects by counting the failed object and returns a
non-clean aggregate result after the object pass, while the sticky incomplete
state remains attached to the containing fmap and disables clean caching. A
focused malformed-Flate extraction regression covers the full caller path;
compiled PDF corpus, sanitizer, and supported-build Sonic1 qualification
remain release gates.

## On-access FTS traversal completeness — 2026-08-20

The inotify extra-directory scanner previously submitted every non-preorder
FTS record to the file scan path, including unreadable directories and entries
whose `stat()` operation had failed. It also discarded end-of-walk and
`fts_close()` failures, so a partial walk could be logged as if it had
completed. It now scans only recognized file/symlink records, preserves
detected results, and returns an incomplete status for FTS error records,
unknown records, failed child inspection, walk termination, or close failure.
Size-limited children are skipped individually so one oversized sibling does
not suppress independent files.

The inotify hierarchy builder now rejects FTS error records and child-list
enumeration failures, checks the traversal end state, and preserves close
failures instead of installing or returning a partial hierarchy as success.

Source guards and `git diff --check` are the current local evidence. Compiled
inotify/fanotify fault-injected traversal, dependency-complete front-end
builds, sanitizer coverage, and supported-build Sonic1 qualification remain
release gates.

## Streamed multipart spool close propagation — 2026-08-20

The disk-backed multipart MIME walker checked read errors but ignored the
source `fclose()` result. It now marks the mail scan incomplete when the source
descriptor cannot be closed cleanly and changes only an otherwise-successful
result to failure, preserving detections and earlier parser/resource results.

The source guard and `git diff --check` are the current local evidence.
Fault-injected mail-spool cleanup, dependency-complete C/CTest, sanitizer
coverage, and supported-build Sonic1 qualification remain release gates.

## ARJ SFX main-header classification — 2026-08-20

ARJ SFX admission now distinguishes a confirmed ARJ signature with a malformed
or truncated main header from a disproven magic candidate. The former marks the
containing scan incomplete and preserves `CL_EPARSE`; it can no longer be
treated as `CL_EFORMAT` and silently discarded by the raw embedded-candidate
path. A focused four-byte public-map regression and source guards cover this
boundary. Full ARJ corpus, sanitizer, and supported-build Sonic1 qualification
remain release gates.

## CAB SFX fixed-header admission — 2026-08-20

CAB SFX admission now requires the complete fixed 36-byte header before
creating a nested layer. A short `MSCF` hit remains a disproven weak candidate,
while a complete header whose declared cabinet or file-table extent exceeds
the containing map is confirmed malformed/truncated and returns `CL_EPARSE`
with sticky incomplete state. A later libmspack open failure after fixed-header
admission is also fail-visible. A focused synthetic public-map regression and
source guards cover the boundary. Full CAB corpus, sanitizer, and supported-
build Sonic1 qualification remain release gates.

## Embedded-header read-failure classification — 2026-08-20

The remaining embedded SFX/document admission helpers now distinguish an
in-range `fmap` read failure from a disproven short or mismatched signature.
7-Zip, EGG, NSIS, AutoIt, InstallShield, PDF, RAR, and ARJ header reads return
`CL_EREAD` when the required window cannot be read, allowing the central scan
policy to mark the containing layer incomplete instead of silently rejecting a
candidate as unrelated magic. A focused injected-read regression covers PDF
and ARJ, with source guards covering the helper family. Full fault-injected
parser, sanitizer, and supported-build Sonic1 qualification remain release
gates.

## Public scan-file descriptor close propagation — 2026-08-20

`cl_scanfile_ex2()` owned the input descriptor but ignored a failing `close()`
after `cl_scandesc_ex2()` completed. The API now returns `CL_EREAD` for a
clean/trusted result when that close fails and records the failure in the
structured report as `RESOURCE_FAILURE` with one skipped operation. Existing
detections remain authoritative. A focused internal report regression and
source guards cover the state transition; injected close-failure and
dependency-complete test coverage remain open.

## Structured clamd dispatch-failure framing — 2026-08-20

Structured clamd requests previously suppressed the legacy error reply after
a recognized report command failed during worker dispatch, leaving clients
without the required terminal JSON frame. The receive thread now emits the
bounded fallback report with `RESOURCE_FAILURE` (or `CL_EMEM` for allocation
failure) before closing the request. The same handling covers the final
staged-stream dispatch. A focused fallback-parser regression and source guards
cover the protocol contract; compiled failure injection and supported-build
Sonic1 qualification remain open.

## clamscan early-file report completion — 2026-08-20

`clamscan --report-json` previously wrote a JSON object only after
`cl_scandesc_ex2()` ran. Access-denied, allocation, and open failures therefore
incremented the legacy error count while omitting the corresponding input from
the JSONL evidence. The manager now creates a bounded fallback report for
those early exits and writes all reports after completion enforcement. The
source guards cover the fallback and error mappings; compiled failure
injection and supported-build qualification remain open.

## clamscan cleanup failure completion — 2026-08-20

The clamscan manager previously published its structured report and printed a
clean `OK` before closing the scan descriptor or quarantine source, and the
shared action-source close helper discarded close failures. The close helper
now returns `CL_EREAD`; clamscan performs cleanup before report publication and
clean-result output, records a post-scan failure in the report, and preserves
detections as authoritative. A focused invalid-descriptor regression and
source guards cover the change; fault-injected cleanup and supported-build
qualification remain open.

## clamscan stdin structured staging failures — 2026-08-20

`clamscan --report-json` previously had no per-input object when stdin staging
failed before `cl_scanfile_ex2()`, including temporary-file creation, writes,
reads, closeout, and failed over-limit sentinel materialization. The stdin
path now emits a bounded fallback report for those exits and publishes normal
and sentinel reports only after completion enforcement. Legacy return values
remain unchanged; source guards cover the failure mapping and compiled fault
injection plus supported-build qualification remain open.

## clamdscan serial pre-dispatch report completion — 2026-08-20

`clamdscan --report-json` previously emitted no object when its serial walker
failed before sending a file to clamd. The client now writes a structured
non-clean fallback for stat, allocation, quarantine-open, connection, and
protocol failures, preserving the existing error counters and exits. The
parallel IDSESSION path still needs its own fallback/ordering qualification;
fault-injected and supported-build Sonic1 evidence remain open.

## clamdscan parallel pre-dispatch report completion — 2026-08-20

The parallel `clamdscan --report-json` walker now writes a structured
resource-failure fallback when an input fails before an IDSESSION request is
registered, and drains pending IDs into fallback rows after session abort or
daemon disconnect. Successfully completed IDs continue to use the daemon's
framed reports. Source guards cover the pending-ID cleanup and pre-dispatch
status mapping; compiled fault injection and supported-build Sonic1 evidence
remain open.

## clamscan requested-path report completion — 2026-08-20

`clamscan --report-json` now emits a bounded non-clean fallback row when an
explicitly requested path fails allocation or `lstat()`, or is a top-level
unsupported file type. This prevents pre-scan input failures from disappearing
from JSONL evidence while preserving legacy console and exit behavior. Compiled
fault injection and supported-build qualification remain open.

## clamscan directory and symlink report completion — 2026-08-20

The clamscan walker now emits bounded non-clean fallback rows when an explicit
directory cannot be opened or a followed symbolic link cannot be inspected.
Legacy error accounting and ordinary symlink exclusion behavior remain
unchanged; the previously omitted pre-scan failures are now represented in
JSONL evidence. Compiled filesystem-fault injection and supported-build
qualification remain open.

## clamdscan recursion-limit report completion — 2026-08-20

When the client-side directory walker reaches its recursion limit, serial and
parallel `clamdscan --report-json` modes now emit a bounded `LIMIT_INCOMPLETE`
fallback row for the skipped directory. The event counts as an error and
suppresses an overall clean `OK` result; ordinary symlink exclusion remains
unchanged. Compiled traversal fault injection and supported-build
qualification remain open.

## PNG large-chunk bounded mapping — 2026-08-20

The PNG parser previously rejected every chunk length above 2 GiB and mapped
every non-empty chunk as one contiguous fmap window, even though it only
inspects the fixed-size `IHDR` payload. It now validates the 64-bit containing
range, borrows only the 13-byte `IHDR`, and skips large `IDAT`/ancillary
payloads without making them resident. A sparse 2 GiB ancillary-chunk
regression covers successful traversal through the following `IEND` chunk;
compiled media-corpus, sanitizer, and supported-build qualification remain
open release gates.

## OLE2 summary metadata bounded windows — 2026-08-20

The OLE2 summary-information parser previously mapped the complete
attacker-declared property-set size in one fmap request. That size is a
32-bit format field, so a valid large OLE2 stream could make the metadata
parser borrow up to 4 GiB contiguously even though it only processes a
bounded property table and at most 25 properties.

The parser now validates the property-set range, maps only the bounded
property table, and maps a bounded window at each referenced property. Scalar
and string reads validate against both the mapped window and the full
property remainder; wide-string length multiplication is overflow-checked.
This preserves explicit malformed/truncated results without turning a large
metadata declaration into an unbounded contiguous read. Compiled OLE2,
sanitizer, parser-corpus, and supported-build qualification remain open.

## PE resource-string bounded heuristic reads — 2026-08-20

The PE resource-string heuristic passed an attacker-controlled resource length
directly to fmap even though `cli_detect_swizz_str()` stops after its first
8 KiB of UTF-16 input. That could turn a large resource declaration into an
unnecessary contiguous mapping.

The heuristic now validates the resource range without addition wraparound
and maps no more than its fixed 8 KiB inspection prefix. Exact-end resource
ranges remain representable, while malformed ranges are skipped as before.
Compiled PE, sanitizer, parser-corpus, and supported-build qualification
remain open.

## PE import-directory bounded reads — 2026-08-20

The PE import-hash path previously borrowed the complete import-directory
range in one fmap request. Its size is a 32-bit PE data-directory field, so a
large or malicious directory declaration could create a multi-gigabyte
contiguous mapping even though the consumer processes fixed-size import
descriptors sequentially.

The path now validates the import range using subtraction-form bounds checks,
reads one descriptor at a time, and marks a descriptor read failure
incomplete. This also removes the old whole-directory fmap lifetime and keeps
the raw matcher’s required PE import inspection fail-visible. Compiled PE,
sanitizer, parser-corpus, and supported-build qualification remain open.

## AC exact-tail offset qualification slice — 2026-08-20

The AC matcher already stores runtime match coordinates in 64-bit fields, but
the matcher suite had only exercised the corresponding BM offset path above
4 GiB. `test_ac_offset_mode_matches_above_uint32` now builds an AC signature,
scans an exact four-byte tail at offset 5,000,000,000, and asserts both the
signature identity and the returned `off_t` coordinate. The capability
manifest records AC as bounded on this focused evidence while retaining the
production-signature and full 32 GiB qualification gate.

## BM offset-table overflow admission — 2026-08-20

BM offset-mode initialization previously added a signature coordinate and its
prefix/length before checking the containing file size. A near-`UINT64_MAX`
coordinate could therefore wrap into a small offset and enter the scan table.
The path now uses checked addition and subtraction-form range checks; invalid
coordinates are ignored as non-applicable signatures, while a real allocation
or offset-calculation failure still propagates. The focused matcher test keeps
the valid 5,000,000,000-byte coordinate and rejects the wrapped coordinate.

## Byte-compare large-coordinate qualification slice — 2026-08-20

The byte-compare bridge already converts an absolute logical-signature
reference into a signed window-relative coordinate and checks both signed
offset arithmetic and the absolute comparison-coordinate addition. The
matcher suite now exercises a byte-compare result whose referenced subsignature
starts at 5,000,000,000 and verifies that the dependent comparison is counted
at 5,000,000,004. The capability manifest records this focused path as
bounded; production-signature, parser-expansion, and full 32 GiB qualification
remain open.

## Exact-size hash side-table qualification slice — 2026-08-20

The hash matcher keeps legacy sub-`UINT32_MAX` keys in its existing table and
routes larger exact sizes through a 64-bit side table. `test_exact_hash_at_large_size`
now inserts and looks up 5,000,000,000-byte, exactly 32-GiB, and 32-GiB-plus-one
MD5 entries for each supported hash purpose: whole-file detection, PE-section
detection, false-positive checking, and PE-import detection. This closes the
shared table/admission/lookup boundary slice; actual PE section/import
materialization, production signatures, and fuzzy-image qualification remain
open.

## PCRE effective contiguous-limit qualification slice — 2026-08-20

The PCRE admission helper clamps the configured PCRE subject limit to the
certified large-file ceiling and then applies the engine's lower
`MaxContiguousSize` resource limit. The existing boundary regression now also
sets that resource limit to 4 KiB, accepts an exact 4 KiB subject, rejects 4 KiB
plus 1 byte, and verifies sticky incomplete/non-cacheable state. This qualifies the
admission policy only; full-size PCRE matching, sanitizer, and RSS evidence
remain open.

## Public fmap range-clamp overflow — 2026-08-20

`cl_fmap_get_data()` previously tested `offset + len > map->len` before
clamping an oversized caller request. On a 64-bit API caller, a `SIZE_MAX`
length could wrap that addition and reach the fmap reader without the intended
end-of-map clamp. The check now compares `len` with the already validated
`map->len - offset`, and a public API regression verifies that a wrapping
length returns exactly the remaining tail bytes.

## JavaScript normalization text-buffer width — 2026-08-20

The JavaScript normalizer's shared text buffer previously evaluated
`pos + len` without an overflow check and stored its growth target in an
`unsigned`, which could truncate a native-width request on a 64-bit build.
Capacity growth now checks the append arithmetic, uses `size_t` throughout,
and returns failure before any allocation when the request cannot be
represented. A focused test exercises the overflow path without allocating;
the deliberate legacy matcher boundary for normalized output above 4 GiB
remains an explicit unsupported/incomplete result.

## JavaScript normalization token-growth arithmetic — 2026-08-20

The JavaScript normalizer's token vector previously grew by adding a fixed
slack amount and multiplying the resulting element count without checking
native-width overflow. Token-range replacement and token appending also formed
new counts without checked addition, while adjacent string-literal folding
could wrap `str_len + leng + 1` before reallocating. These paths now reject
unrepresentable capacity/count/byte-size requests before allocation; token
replacement validates capacity before freeing the old range so an admission
failure preserves the existing token payloads. The tokenizer suite's existing
adjacent-string regression continues to cover the normal folding path. Full
large-script, sanitizer, parser-corpus, and supported-build qualification
remain open.

## Sanitizer metadata loader binding — 2026-08-21

The runtime gate already bound the sanitizer workload and loader trace to the
copied sanitizer dependency directory, but its metadata block invoked the
copied sanitizer scanner's `--version` command without setting that same
loader path. On a host with a same-basename build-tree library, this could
make the recorded metadata command load a different component than the one
the evidence verifier had selected. The metadata invocation now explicitly
sets `LD_LIBRARY_PATH` to the copied sanitizer component directory first;
the source guard prevents regression. Full sanitizer and supported-build
qualification remain release gates.

## Generic graphics parser boundary — 2026-08-21

`CL_TYPE_GRAPHICS` is the recognized catch-all for formats such as BMP and
JPEG 2000 that do not have a structural parser. Its dispatch branch previously
performed only optional fuzzy-image matching and could return clean after raw
matching when image parsing was enabled. The branch now retains detections and
terminal matcher results but marks a non-detecting layer incomplete with an
explicit unsupported-parser reason. A focused scan-map regression verifies the
non-clean, non-cacheable result; bounded parser implementation and production
graphics corpus qualification remain open.

## SDB type-recognition pass — 2026-08-21

When SDB signatures were loaded, `cli_magic_scan()` ran the outer raw matcher
before the parser but skipped the later raw pass entirely. Because that later
pass also performs embedded file-type recognition, confirmed SFX/archive
candidates could be omitted from the scan without a parser or incomplete
result explaining the omission. The scan now performs that type-recognition
work after parsing with `AC_SCAN_FT` only; the outer virus-signature pass is not
duplicated. The embedded RAR-SFX unavailable-backend regression now exercises
the SDB-enabled path as well. Compiled parser-family and Sonic1 qualification
remain release gates.

The recognition-only matcher mode also suppresses hash and logical-signature
evaluation; only AC file-type signatures run in that pass, so SDB-enabled scans
do not duplicate detector work or alerts.

## PCRE admission coverage — 2026-08-21

The clamd startup gate now reads `PCREMaxFileSize` and `MaxMatcherWork` as part
of the engine limit set. A large PCRE contiguous-subject request can no longer
take the historical file/logical default fast path without host admission;
PCRE and matcher limits are also checked for native-size representability, and
the PCRE subject participates in the memory-basis calculation. A focused clamd
regression covers the bypass case. Compiled runtime and Sonic1 resource
qualification remain release gates.

## Matcher root absence — 2026-08-21

The lower-level buffer and fmap matcher paths now treat an absent generic
matcher root as an empty root when target-specific signatures are present.
They no longer initialize or invoke generic matcher state through a null
pointer, while target-specific matching and logical evaluation remain active.
A focused fmap regression covers the target-only-root shape. Full database,
compiled, sanitizer, and production-signature qualification remain open.

## Structured detection verdict normalization — 2026-08-21

The structured report finalizer now normalizes the legacy-compatible
`CL_VIRUS` plus clean-verdict combination to `CL_VERDICT_STRONG_INDICATOR`.
Without this, directory or MULTISCAN aggregation could produce a report with
`DETECTION_TERMINATED` but a clean verdict, which the structured clamdscan
consumer correctly rejects as contradictory. The existing detection-precedence
and aggregate-report regressions now cover the normalization. Source guards and
whitespace validation pass; compiled daemon/library and production-signature
qualification remain release gates.

## Raw fallback after non-critical parser errors — 2026-08-21

The pre-raw parser stage now treats generic and access/open/map/creation
failures like the existing parse, read, decoder, and configured-limit errors:
the root raw matcher still runs when the root fmap remains available, while
the sticky incomplete state preserves a non-clean, non-cacheable result when
no detection is found. Critical resource, timeout, seek, write, and terminal
abort failures still stop the layer. Source guards and whitespace validation
pass; compiled fault-injection and production-signature qualification remain
release gates.

## INSTREAM source bytes share the temporary budget — 2026-08-21

The clamd INSTREAM receive path now carries the exact staged byte count into
the library scan context. Parser, decoder, and matcher spools are therefore
charged on top of the already-live disk-backed source against the same
MaxTemporarySize ceiling; the existing stream quota still rejects oversized
input before staging. Both legacy and structured INSTREAM scans use the
reservation-aware descriptor path. Static guards and whitespace validation
pass; compiled daemon/protocol and concurrent production qualification remain
release gates.

## INSTREAM queue admission remains a release gate — 2026-08-21

The pre-`7aff518` receive path created the INSTREAM temporary file and staged
the complete request before dispatching the descriptor scan to the worker
pool. That behavior is superseded: the current admission state machine puts a
request in `MODE_WAITQUEUE`, stops polling its body, and creates no temporary
file or staging reservation until a worker slot is admitted. The remaining
release gate is compiled daemon/Sonic1 concurrency qualification proving that
the second simultaneous request stays unstaged while the single worker is
occupied.

## INSTREAM client descriptor rewind — 2026-08-21

The clamd client now stats every non-stdin stream descriptor before beginning
the protocol, rewinds regular files before sending the command, and fails
without sending a partial protocol when stat or rewind fails. Pipes and other
non-regular descriptors remain streamable at their current position. Focused
socket-level regressions cover complete regular-file rewinding and rejection
of an invalid descriptor; compiled Linux/Sonic1 ingress qualification remains
open.

## clamscan stdin summary accounting — 2026-08-21

The stdin path previously incremented `info.files` before scanning and again
for a clean result, while infected and trusted results were counted through
different paths. The speculative increment is removed and the trusted and
detected branches now increment the count explicitly, matching ordinary file
scans. A source guard requires five total completed/alerted-file increment
sites in `clamscan/manager.c`. Compiled CLI and Sonic1 qualification remain
open.

## INSTREAMREPORT preserves structured mode through staging — 2026-08-21

`INSTREAMREPORT` now retains its structured-report flag while the receive loop
stages chunks. The flag is cleared only after the terminating zero chunk has
queued the scan, so quota, write, scan, and completion failures use the
length-prefixed JSON report path rather than silently reverting to legacy text.
A clamd regression sends a detected stream and verifies the JSON completion
frame and zero terminator. Compiled daemon and Sonic1 qualification remain
open.

## clamd structured empty-file parity — 2026-08-21

The clamd directory-walk callback previously returned early for zero-byte
regular files without recording a structured result. A `SCANREPORT` or
`CONTSCANREPORT` request could therefore fall through to the serialization
fallback and classify a valid empty input as `RESOURCE_FAILURE`, while
`clamscan` reported it as a completed clean input. The callback now emits an
explicit `COMPLETE` report with a zero-byte logical object and no skipped
operations. Compiled daemon and Sonic1 qualification remain open.

## Service qualification deadline and oracle tightening — 2026-08-21

The service qualification harness now applies the configured per-file
`CLAMAV_MAX_SCAN_TIME_MS` to clamd, direct clamscan, and the direct structured
report probes. It rejects an outer service timeout shorter than that deadline,
wraps every direct probe in the same timeout, records elapsed evidence for
those probes, and passes the configured deadline to the protocol helper instead
of using a fixed 15-minute socket timeout. Structured reports now require
status/error consistency with the oracle exit (`0`/`1` require `status=0`,
`2` requires a nonzero status) and exact alert identity, allowing only the
documented `.UNOFFICIAL` suffix for unsigned local signatures. Static guards,
shell syntax, and Python parsing pass; compiled Linux/Sonic1 production
qualification remains open.

The exact-edge milter harness now receives the same service timeout and
per-file scan deadline through `MILTER_WIRE_TIMEOUT_S` and
`MILTER_MAX_SCAN_TIME_MS`; its internal 600-second/600,000-millisecond
defaults no longer terminate a valid four-hour qualification early.

## Bytecode fmap-window lifetime — 2026-08-21

File-backed bytecode buffer-pipe reads now release their locked fmap window at
`buffer_pipe_read_stopped()`, before replacing a read window, and during
buffer teardown. The historical `pdf_getobj()` API has no release operation,
so it now uses a bounded unlocked fmap view and documents that the pointer is
only valid during the hook's immediate consumption. Focused unit regressions
verify that both paths leave resident pages evictable, and source guards plus
whitespace validation pass. The C/Rust build, independently compiled ABI-v2
fixture, interpreter/JIT, sanitizer, and production-signature qualification
remain release gates; no compiled result is claimed here.

## PE resource-heuristic fmap cleanup — 2026-08-21

The Swizzor/resource heuristic previously returned immediately when its
bounded resource-error budget was exhausted, bypassing the `fmap_unneed_ptr`
cleanup for the locked entry window. That path now breaks to the common
cleanup, preventing avoidable resident-page retention during PE inspection.
Static guards and whitespace validation pass; compiled PE corpus, sanitizer,
and large-file qualification remain release gates.

## InstallShield file-window cleanup — 2026-08-21

InstallShield header walking now releases the locked `IS_FILEITEM` window on
its scan-limit, file-count, and CAB-extraction error exits, in addition to
the normal member-walk cleanup. Static guards and whitespace validation pass;
compiled InstallShield corpus, sanitizer, and large-file qualification remain
release gates.

## InstallShield recursive metadata lifetime — 2026-08-21

InstallShield file records were still held as locked fmap windows while the
corresponding CAB member was recursively decompressed and scanned. The parser
now copies each fixed record to a local snapshot and releases it before name
resolution; resolved directory and file-name windows are released before the
nested CAB scan as well. Static guards and whitespace validation pass; compiled
InstallShield corpus, sanitizer, and large-file qualification remain release
gates.

## GIF signature-probe fmap lifetime — 2026-08-21

The GIF parser’s immediate three-byte signature probe now uses
`fmap_need_off_once()` instead of retaining a locked window without a matching
release. Static guards and whitespace validation pass; compiled GIF corpus,
sanitizer, and large-file qualification remain release gates.

## NsPack source-window lifetime — 2026-08-21

The legacy NsPack PE unpacker previously released its locked compressed-source
window before passing the pointer to `unspack()`, and two later error exits
could leak the lock entirely. It now holds the bounded window through
`unspack()`, releases it before the result macro can return, and releases it on
the resource-address and OEP-read failures. Static guards and whitespace
validation pass; compiled PE corpus, sanitizer, and large-file qualification
remain release gates.

## PE icon-group entry lifetime — 2026-08-21

PE icon-group scanning previously retained an unlocked group-entry pointer
across `findres_ex()`, which performs nested resource-map reads. It now fetches
each bounded 14-byte entry immediately before decoding it, checks the entry
coordinate with subtraction-form bounds, and avoids mapping the full
attacker-declared group length. Static guards and whitespace validation pass;
compiled PE icon corpus, sanitizer, and large-file qualification remain
release gates.

## ISO9660 descriptor-window lifetime — 2026-08-21

ISO9660 previously released the primary volume-descriptor lock before using its
fields for debug output and root-directory traversal; a selected Joliet
descriptor was also carried as an unlocked fmap pointer across nested work.
Both bounded descriptors are now copied while readable, and all primary-window
error paths release the exact requested range. Static guards and whitespace
validation pass; compiled ISO corpus, sanitizer, and large-file qualification
remain release gates.

## HTML normalized-view size admission — 2026-08-21

The HTML scanner now requires its generated `nocomment.html` view and opens
and sizes the generated `notags.html` view before scanning it.
`MaxHTMLNoTags` therefore measures the normalized view named by
the option instead of the original input length; a source file whose markup is
larger than the cap can proceed when its generated no-tags view fits. Missing
or stat failures and over-limit generated views remain sticky incomplete and
non-cacheable. The focused unit regressions cover both outcomes; supported
build and parser-corpus qualification remain open.

## Script normalization window accounting — 2026-08-21

The in-memory script-normalization path now advances its logical matcher
coordinate by newly normalized bytes only. The overlap retained for boundary
matching is not written or reserved a second time, and a short final window
cannot restore bytes that were never produced. The focused absolute-offset
regression covers a marker beyond the first normalized window. Static guards
and whitespace validation pass; compiled scanner, sanitizer, and production
signature qualification remain open.

## PE resource-entry window bounds — 2026-08-21

The PE resource heuristic now validates resource-entry coordinates with
subtraction-form bounds, reads each fixed-size unnamed entry independently,
and checks RVA additions before nested traversal. A recursive resource walk
therefore no longer retains an attacker-declared fmap window across nested
reads. Static guards and whitespace validation pass; compiled PE corpus,
sanitizer, and production qualification remain open.

## UDF descriptor-window lifetime — 2026-08-21

UDF now releases descriptor views on tag mismatch and snapshots the logical
volume and partition metadata before scanning extracted files. This removes
locked fmap windows from the nested extent-scan lifetime while preserving the
descriptor values required by the extractor. Static guards and whitespace
validation pass; compiled UDF corpus, sanitizer, and production qualification
remain open.

## ZIP header-window lifetime — 2026-08-21

ZIP local-header parsing previously kept its fixed header mapped through member
decompression, and the central-directory walker passed a locked central header
into that nested scan. The local parser now snapshots the decryptor header or
copies scalar decoder fields before releasing the local window; the central
parser snapshots its fixed metadata before invoking local-member parsing, and
the catalogue ZipCrypto path follows the same rule. Static guards and
whitespace validation pass; compiled ZIP corpus, sanitizer, and production
qualification remain open.

## ISO directory-window lifetime — 2026-08-21

ISO9660 directory traversal previously held each mapped directory block while
recursing into subdirectories or materializing and scanning file extents. The
parser now copies the bounded block (at most 2 KiB) to a local buffer and
releases the fmap view before processing entries, preserving the existing
coordinate and parser-status checks without retaining archive pages across
nested work. Static guards and whitespace validation pass; compiled ISO corpus,
sanitizer, and production qualification remain open.

## PDFNG referenced-object allocation bound — 2026-08-21

The PDFNG referenced-string path reloaded a dumped object with raw
`calloc(sb.st_size + 1)`, bypassing the shared 1 GiB individual-allocation
guard. It now rejects objects at that ceiling, marks the PDF layer incomplete,
cleans up the temporary object, and uses `cli_max_calloc()` for accepted sizes.
Static guards and whitespace validation pass; full PDF parser, sanitizer, and
production qualification remain open.

## Bundled CAB/CHM allocation bound — 2026-08-21

The libmspack callback used by CAB and CHM parsing previously allocated
decoder-requested buffers with raw `malloc()`. It now uses `cli_max_malloc()`,
so an attacker-controlled decoder allocation request fails closed at the
individual-allocation ceiling. Static guards and whitespace validation pass;
compiled CAB/CHM corpus, sanitizer, and production qualification remain open.

## XLM drawing-group allocation bound — 2026-08-21

XLM BIFF extraction previously used an unbounded raw allocation for the first
drawing-group record and accumulated later `CONTINUE` records with unchecked
native-size addition. The parser now uses the shared individual-allocation
ceiling for BIFF data and drawing-group storage, checks cumulative growth before
addition, and marks allocation or ceiling failures incomplete while preserving
raw matching. Static guards and whitespace validation pass; compiled XLM/OLE
corpus, sanitizer, and production qualification remain open.

## Shared base64 allocation bound — 2026-08-21

The shared base64 helpers used raw `malloc()` for decoded and encoded buffers.
They now use `cli_max_malloc()`, so MSXML embedded binaries and HWP, OLE, or
PDF metadata fallback paths cannot create a contiguous buffer above the
individual-allocation ceiling before their caller can reserve temporary
storage. Static guards and whitespace validation pass; compiled parser corpus,
sanitizer, and production qualification remain open.

## Bundled decoder allocation bounds — 2026-08-21

Bundled 7-Zip and NSIS zlib allocation callbacks previously called raw
`malloc()`, and NSIS multiplied callback operands before allocation. They now
route through `cli_max_malloc()` with checked multiplication, so decoder
internal buffers fail closed at the individual-allocation ceiling. Static
guards and whitespace validation pass; compiled archive corpus, sanitizer, and
production qualification remain open.

## Bytecode allocation and hex-data bounds — 2026-08-21

Bytecode loader, interpreter, and VM paths still used raw allocations for
untrusted line lengths, data literals, type/count tables, and execution state.
They now use the shared individual-allocation ceiling. The hex-data reader also
checks `offset` and `2 * length` against the containing line before forming the
new coordinate. Static guards and whitespace validation pass; independently
compiled ABI-v2 fixture, interpreter/JIT, sanitizer, and production-signature
qualification remain open.

## TNEF attribute-string length bounds — 2026-08-21

TNEF's debug message-class and attachment-title paths used signed 32-bit
attribute lengths in `length + 1` before conversion to `size_t`. They now
convert first and perform native-width allocation, read, and position updates,
preserving fail-visible behavior at the largest representable positive length.
Static guards and whitespace validation pass; compiled TNEF corpus, sanitizer,
and production qualification remain open.

## CPIO native-width member coordinates — 2026-08-21

CPIO's on-disk namesize and filesize fields are 16- or 32-bit, but the parser
used those narrow variables for archive-coordinate and alignment arithmetic.
The parser now widens decoded values to `size_t` before advancing through
members and uses checked alignment for old/newc member boundaries. A maximum
format field can no longer wrap its padding into a smaller coordinate.
Static guards and whitespace validation pass; compiled CPIO corpus, sanitizer,
and production qualification remain open.

## PE32 unpacker coordinate arithmetic — 2026-08-21

Recognized PE32 MEW, Upack, FSG, UPX, WWPack, and Aspack paths formed section
size or RVA sums in 32-bit arithmetic before the shared allocation and
temporary limits. A wrapped sum could admit a smaller buffer or pass a wrapped
input length to the unpacker. The paths now use checked `uint32_t` additions,
reject overflow as an incomplete recognized layer, and pass validated sums into
the existing bounded allocation/spool paths. PE32+ now completes
architecture-neutral overlay, bytecode, and 64-bit import-table inspection;
the remaining PE32/x86 heuristics and unpackers retain an explicit
unsupported/incomplete boundary.
Static guards and whitespace validation pass; compiled PE corpus, sanitizer,
and production qualification remain open.

## HFS+ inline compressed-output admission — updated 2026-08-24

The HFS+ inline decmpfs path no longer rejects declared output above 64 KiB or
allocates the whole result. It inflates into a fixed 64 KiB output window,
checks the shared deadline around every decoder/write cycle, rejects decoder
stall, trailing input, truncation, and output beyond the declared size, and
writes only exact decoded bytes into the already quota-reserved temporary
file. Decoder setup/finalization and write failures remain sticky incomplete.

The isolated production-linked regression expands beyond two output windows,
verifies exact tail bytes, rejects a one-byte-short declared size, and injects
a write failure. All three paths pass with the expected status and cache
state. Compiled HFS+ corpus, sanitizer, materialized large output, certified
Linux x86-64, and Sonic1 qualification remain open.

## Modern scan-layer callback error propagation — 2026-08-21

The modern scan-layer callback dispatcher previously normalized an unexpected
`cl_error_t` into continued scanning (or an accepted alert). It now marks the
layer incomplete and preserves the callback error. Public pre-hash, pre-scan,
and post-scan map-scan regressions cover the corrected behavior. Static guards
and whitespace validation pass; compiled Linux/Sonic1 and broader callback
fault-injection qualification remain open.

## Legacy callback error propagation — 2026-08-21

Deprecated pre-cache, file-inspection, pre-scan, and post-scan callbacks now
preserve unexpected `cl_error_t` returns. Each unexpected status marks the
layer incomplete and prevents a clean cache result; the pre-cache and pre-scan
call sites now stop instead of continuing after the error. A public
`cl_scanmap_ex2` regression covers all four callback entry points and verifies
the returned status and structured-report status. Static guards and whitespace
validation pass; compiled Linux/Sonic1 and broader callback fault-injection
qualification remain open.

## Executable and UDF traversal deadlines — 2026-08-22

ELF program/section-header inspection, Mach-O load-command/section inspection,
Mach-O universal-binary architecture/member traversal, and UDF descriptor and
file-index traversal previously had no deadline check at their parser-local
loop boundaries. They now check the shared scan deadline before each
attacker-controlled iteration, release temporary metadata arrays on timeout,
and preserve `CL_ETIMEOUT` as a sticky incomplete, non-cacheable result.
Direct expired-context regressions cover ELF, Mach-O, Mach-O universal-binary,
and UDF entry points; source guards and the capability manifest record the new
coverage. Compiled parser corpus, sanitizer, and Sonic1 qualification remain
release gates.

## JPEG 2000 box traversal deadline — 2026-08-22

The bounded JPEG 2000 structural-admission parser now checks the shared scan
deadline at entry and before each top-level box, preserving `CL_ETIMEOUT` as
an incomplete, non-cacheable result. A direct expired-context regression and
source guards cover the new behavior; compiled image corpus, sanitizer, and
Sonic1 qualification remain release gates.

## CPIO member traversal deadline — 2026-08-22

The old, ODC, newc, and CRC CPIO walkers now check the shared scan deadline
before each member-header read and preserve timeout as an incomplete,
non-cacheable result without conflating it with a truncated header. A direct
regression exercises all four entry points; source guards and the capability
manifest record the coverage. Compiled archive corpus, sanitizer, and Sonic1
qualification remain release gates.

## SWF traversal and decoder deadlines — 2026-08-22

SWF uncompressed tag walking and CWS/ZWS decompression now check the shared
scan deadline at parser entry and before each structural or decoder iteration.
Timeouts release decoder state and temporary output before returning
`CL_ETIMEOUT` as an incomplete, non-cacheable result. A direct expired-context
regression and source guards cover the change; compiled SWF corpus, sanitizer,
and Sonic1 qualification remain release gates.

## SWF temporary-output admission deadline — 2026-08-22

SWF CWS/ZWS temporary-output writes now re-check the shared deadline after
quota admission and immediately before each header or decoded-chunk write,
closing the interval between decoder-loop checks and the actual output. An
expired context releases the current reservation and temporary file and
returns `CL_ETIMEOUT`; short writes release the current reservation, mark the
layer incomplete, and return `CL_EWRITE`, without treating partial output as
scannable. Source guards cover the boundary; deterministic output-timeout
injection, compiled SWF corpus, sanitizer, and Sonic1 qualification remain
release gates.

## XLM temporary-output deadlines — 2026-08-22

XLM macro normalization and extracted-image staging now re-check the shared
deadline before temporary quota admission and again before writing output.
Expired contexts release any reservation during cleanup and return
`CL_ETIMEOUT` without allowing partial macro or image output to be scanned as
complete. A focused expired-context macro regression and source guards cover
the boundary; compiled Office/XLM corpus, sanitizer, and Sonic1 qualification
remain release gates.

## NSIS post-admission output deadline — 2026-08-22

NSIS extraction already checked the shared deadline before each output
reservation, but a deadline could expire after quota admission and before the
corresponding temporary write. The output callback now re-checks the deadline
after reserving bytes, releases that reservation on timeout, and returns
`CL_ETIMEOUT` without scanning partial output. A source guard covers this
boundary; deterministic timeout injection, compiled NSIS corpus, sanitizer,
and Sonic1 qualification remain release gates.

## HWP/HWPML output deadlines — 2026-08-22

HWP raw-deflate output and HWPML Base64 attachment output now re-check the
shared deadline before temporary quota admission and again before writing. Any
post-admission timeout releases the just-added reservation and returns
`CL_ETIMEOUT` without treating partial document output as complete. Source
guards cover these boundaries; deterministic timeout injection, compiled
HWP/HWPML corpus, sanitizer, and Sonic1 qualification remain release gates.

## XDP retained-dump accounting and output deadline — 2026-08-24

Optional XDP `keeptmp` staging now retains a cumulative temporary reservation
for the complete dump instead of releasing each 8 KiB chunk while the file
continued growing. That reservation remains active through streaming XML and
Base64 inspection, forcing the retained input and decoded children to share one
`MaxTemporarySize` budget. Every dump failure releases the full reservation and
removes the partial output; the normal parse return releases the retained input
reservation as well.

The focused Linux ARM64 GCC `xdp` case passes 3/3: deadline propagation,
second-window cumulative quota rejection, overlapping dump/Base64 accounting,
exact peak counters, zero-byte rollback, non-cacheability, and rejected-partial
cleanup. Production XDP corpus, sanitizer, Linux x86-64, materialized large-file,
and Sonic1 evidence remain release gates. Sonic1 accepted the configured
MCP-SSH profile during this milestone, but its SSH service timed out and then
refused the connection before any remote command started.

## HTML output-boundary deadlines — 2026-08-22

Buffered HTML normalized output and script-encoded output now re-check the
shared deadline before quota admission, after reserving bytes, and immediately
before each direct write. Timeout paths release the reservation and retain the
incomplete result without scanning partial normalized data. Source guards cover
both output APIs; deterministic timeout injection, compiled HTML/MHTML corpus,
sanitizer, and Sonic1 qualification remain release gates.

## InstallShield output deadlines — 2026-08-22

InstallShield MSI member, embedded-file, and CAB output paths now re-check the
shared deadline before admission and immediately before each materialized
write. Timeout cleanup releases current or aggregate temporary reservations and
keeps partial output from reaching a nested scan. Source guards cover all
three paths; deterministic timeout injection, compiled InstallShield corpus,
sanitizer, and Sonic1 qualification remain release gates.

## MSPack member-boundary deadlines — 2026-08-22

Bundled CAB/CHM decoder callbacks already checked the shared deadline during
reads, seeks, and writes. Member temporary admission and the handoff from a
completed extraction to nested scanning now perform explicit checks as well,
preserving `CL_ETIMEOUT` and reservation cleanup when the deadline expires
outside the decoder callback. Source guards cover both families; deterministic
admission/handoff timeout injection, compiled CAB/CHM corpus, sanitizer, and
Sonic1 qualification remain release gates.

## Bytecode and fileblob output deadlines — 2026-08-22

Bytecode unpacked output and the shared MIME/fileblob spool now check the
shared deadline after temporary quota admission and immediately before the
materialized write. Expired contexts release the current reservation and
return an incomplete result instead of writing output that could later be
treated as complete. Bytecode short or failed writes now also release the
current reservation, preserve the successful-byte count without sentinel
wraparound, and block extraction of partial output. Focused expired-context
and closed-output regressions plus source guards cover the admission path;
deterministic post-admission injection, compiled bytecode/mail corpus,
sanitizer, and Sonic1 qualification remain release gates.

The MSPack decoder callback and bytecode output bridge also re-check the
deadline after their output-budget/accounting updates and immediately before
the underlying write, closing a narrow expiry window between admission and
materialization.

PCRE full-map and buffer subject matching now re-checks the deadline after
contiguous-subject admission and releases that reservation before returning
when the scan has expired.

## Archive and filesystem output deadlines — 2026-08-22

MSEXPAND, TAR, SIS, ISO9660, and UDF staging paths now re-check the shared
deadline before or immediately before materialized output writes. TAR, ISO9660,
and UDF also reject expired temporary admission, while SIS compressed and
stored member sinks preserve timeout cleanup through their shared streaming
helper. Source guards cover these boundaries; deterministic post-admission
injection, compiled archive/filesystem corpus, sanitizer, and Sonic1
qualification remain release gates.

## OLE2 stream output deadlines — 2026-08-22

OLE2 VBA, MSO-inflated, embedded, and encrypted stream materialization now
re-checks the shared deadline after temporary admission and immediately before
each output write. Timeout cleanup preserves reservations and prevents partial
Office/VBA streams from reaching nested scans. Source guards cover all four
paths; deterministic post-admission injection, compiled Office/VBA corpus,
sanitizer, and Sonic1 qualification remain release gates.

## CryptFF traversal deadlines — 2026-08-22

CryptFF already decrypted through a fixed buffer and quota-accounted temporary
output, but it could spend an unbounded time walking source chunks. The parser
now checks the shared deadline before admission and before each source read,
marks timeout as incomplete, and preserves `CL_ETIMEOUT` through its existing
temporary close/removal cleanup. A dispatch-level expired-context regression
and source guards cover the contract; compiled CryptFF corpus, sanitizer, and
Sonic1 qualification remain release gates.

## JPEG segment and Photoshop-resource deadlines — 2026-08-22

JPEG now checks the shared scan deadline before initial header inspection,
before each segment, and before each Photoshop 8BIM resource record. Timeout
results remain sticky incomplete and non-cacheable. A direct expired-context
regression and source guards cover the new boundaries; compiled JPEG corpus,
sanitizer, and Sonic1 qualification remain release gates.

## TAR member traversal deadlines — 2026-08-22

TAR staging already bounded member output and preserved malformed-header and
short-member failures, but the archive loop could process an unbounded number
of headers and 512-byte content blocks without checking the shared deadline.
The parser now checks at entry and before each member/block iteration; an
expired scan cleans up any active temporary member and preserves
`CL_ETIMEOUT`. A direct expired-context regression and source guards cover the
contract; compiled POSIX/legacy TAR corpus, sanitizer, and Sonic1 qualification
remain release gates.

## TNEF traversal deadline — 2026-08-22

TNEF attribute-list iteration, attachment-data copying, and the debug-only
unknown-level dump loop previously had no parser-local deadline checkpoint.
They now check the shared deadline before each attacker-controlled iteration;
timeouts preserve `CL_ETIMEOUT`, mark the layer incomplete, and prevent a
cacheable clean result. A direct expired-context regression and source guards
cover parser entry; compiled TNEF corpus, sanitizer, and Sonic1 qualification
remain release gates.

## UUEncode traversal deadline — 2026-08-22

The UUEncode decoder previously consumed an unbounded sequence of encoded
lines without a parser-local deadline checkpoint. It now checks the shared
deadline before each line, marks timeout incomplete, and preserves
`CL_ETIMEOUT` through standalone and mail-embedded callers rather than
normalizing it to a generic parse result. A direct expired-context regression
and source guards cover standalone entry; compiled UUEncode/mail corpus,
sanitizer, and Sonic1 qualification remain release gates.

## XAR traversal and decoder deadlines — 2026-08-22

XAR TOC XML traversal, compressed TOC inflation, subdocument discovery, gzip
and LZMA member decoding, and raw member copying previously lacked shared
deadline checkpoints. They now check before attacker-controlled iterations;
timeouts release zlib/LZMA state through the existing cleanup paths, release
temporary reservations/files, and remain `CL_ETIMEOUT` incomplete results. A
direct expired-context regression and source guards cover parser entry;
compiled XAR corpus, sanitizer, and Sonic1 qualification remain release gates.

## BinHex traversal deadline — 2026-08-22

BinHex's byte decoder and run-length expansion previously had no parser-local
deadline checkpoints. They now check the shared deadline before each decode
iteration, preserve `CL_ETIMEOUT` as an incomplete non-cacheable result, and
use the existing temporary-file cleanup path on timeout. A direct
expired-context regression and source guards cover parser entry; compiled
BinHex/mail corpus, sanitizer, and Sonic1 qualification remain release gates.

## RTF traversal deadline — 2026-08-22

RTF's top-level document/fmap-chunk walk previously had no shared deadline
checkpoint, allowing a large document to continue through parser state and
embedded-object processing without a time-boundary check. The parser now
checks at entry and before each bounded fmap chunk, preserves timeout as an
incomplete non-cacheable result, and avoids classifying timeout as a callback
read failure. Embedded-object cleanup now preserves a stronger timeout or
operational error instead of overwriting it with a cleanup parser result. A
direct expired-context regression and source guards cover parser entry;
compiled RTF/OLE corpus, sanitizer, and Sonic1 qualification remain release
gates.

## MSEXPAND traversal deadline — 2026-08-22

The SZDD/MSEXPAND decoder already enforced declared output and temporary
quotas, but its bitstream and back-reference loops lacked shared deadline
checkpoints. It now checks at parser entry, before each decode iteration, and
before each bounded back-reference expansion; timeout returns through the
existing caller cleanup so temporary reservations and files are released. A
direct expired-context regression and source guards cover parser entry;
compiled SZDD corpus, sanitizer, and Sonic1 qualification remain release
gates.

## Streaming MSXML/XDP deadline — 2026-08-22

The streaming MSXML path now checks the shared deadline at parser entry and
before input chunks, SAX character/element/comment callbacks, JSON chunk
processing, base64 decoding, and temporary-output writes. A timeout stops the
push parser and remains a fail-visible `CL_ETIMEOUT` result; cleanup of any
active spool still runs through the existing frame-disposal path. A direct
expired-context regression and source guards cover the parser entry;
compiled XML/XDP corpus, sanitizer, and Sonic1 qualification remain release
gates.

The optional XDP `keeptmp` payload copy also checks the shared deadline before
each bounded chunk and returns fail-visible read, write, or temporary-resource
errors instead of silently continuing to XML parsing. A direct expired-context
regression and source guards cover the staging entry; compiled XDP staging and
Sonic1 qualification remain release gates.

## CAB/CHM decoder deadlines — 2026-08-22

The bundled libmspack adapter now carries the scanning context into its fmap
callbacks and checks the shared deadline before decoder reads, seeks, and
writes. Timeout state is shared across decoder-owned handles, marks the layer
incomplete, and is preserved as `CL_ETIMEOUT` through CAB/CHM archive opening
and member extraction. Direct expired-context and constructor-injected
callback-timeout regressions cover both decoder-owned read boundaries, with
source guards; compiled CAB/CHM corpus, sanitizer, and Sonic1 qualification
remain release gates.

## RAR decoder deadlines — 2026-08-22

The optional UnRAR bridge previously checked limits only between backend calls;
member extraction and skip operations could continue inside UnRAR without a
shared cancellation boundary. New versioned `*_ex` interface symbols preserve
the legacy ABI while passing a progress callback into UnRAR's process-data
callback. RAR archive open, header, skip, and extraction boundaries now retain
`CL_ETIMEOUT` and mark the scan incomplete, including cancellation during
decoder work. A callback-injected public scan regression and source guards
cover the contract; compiled UnRAR backend, malformed/corpus, sanitizer, and
Sonic1 qualification remain release gates.

## Rust fmap reader deadlines — 2026-08-22

The scanner-facing Rust `FMapReader` previously bounded coordinates and
window residency but did not check the shared scan deadline during reads or
seeks. It now has an opt-in scan-context constructor, checks before every
non-empty read and seek, marks the scan incomplete, and preserves
`CL_ETIMEOUT` through OneNote, LHA/LZH, ALZ, and Rust root-spool error
handling. The context-free constructor remains available for parser/library
tests. Focused source guards and Rust status-mapping coverage are present;
compiled Rust/layout, parser-corpus, sanitizer, and Sonic1 qualification
remain release gates.

## Partition-image traversal deadlines — 2026-08-22

APM, GPT, and MBR already had checked partition coordinates, read-failure
propagation, and explicit MaxPartitions incompleteness, but their table,
extended-chain, checksum, and intersection walks did not share the parser
deadline boundary. The parser entry points and attacker-controlled traversal
loops now check `cli_checktimelimit()` and preserve `CL_ETIMEOUT` through their
existing cleanup and incomplete-result paths. A focused expired-context
regression covers all three entry points, with source guards and capability
manifest updates; compiled partition-image corpus, sanitizer, and Sonic1
qualification remain release gates.

## SIS metadata and field traversal deadlines — 2026-08-22

SIS member copy and inflate loops already checked the shared deadline, but
old-format language/dependency/file metadata walks and the nested 9.x field
traversal could continue without a cancellation boundary. Parser entry,
metadata reads/loops, and every 9.x structural traversal level now check the
shared deadline and preserve `CL_ETIMEOUT` while existing temporary cleanup
remains active. A direct expired-context regression and source guards cover
the parser entry and timeout contract; compiled SIS corpus, malformed nesting,
sanitizer, and Sonic1 qualification remain release gates.

## ARJ decoder traversal deadlines — 2026-08-22

ARJ header admission and output-size checks were already fail-closed, but
extended-header walks, stored-member copies, and compressed output loops could
continue without consulting the shared deadline. The scan context now travels
through ARJ metadata and decoder state; parser/header entry, header iteration,
stored copies, bit-window refills, and both decompression loops preserve
`CL_ETIMEOUT`. A direct header-check timeout regression and source guards cover
the contract; compiled ARJ decoder-state corpus, sanitizer, and Sonic1
qualification remain release gates.

## NSIS/NULSFT traversal deadlines — 2026-08-22

NSIS extraction already used bounded input/output chunks and shared temporary
quotas, but member-table discovery, raw and compressed member loops, and solid
stream header/output traversal did not consistently check the shared deadline.
The parser now checks at entry and across those traversal boundaries, preserves
`CL_ETIMEOUT`, and leaves the existing output close, decoder shutdown, temporary
reservation release, and directory cleanup paths active. A direct expired-context
regression and source guards cover parser entry; compiled NSIS decoder-state,
malformed-stream, sanitizer, and Sonic1 qualification remain release gates.

## AutoIt EA06 traversal deadlines — 2026-08-22

AutoIt EA06 member extraction previously relied on generic scan-limit checks;
compressed decoding, long back-reference copies, and script-token decompilation
could continue without consulting the shared deadline. The parser now checks at
entry and across member, decoder, back-reference, and script-token traversal,
preserves `CL_ETIMEOUT`, and releases any allocated member buffers on timeout.
A direct expired-context regression and source guards cover parser entry; the
existing random-access/1 GiB EA06 boundary, compiled AutoIt corpus, sanitizer,
and Sonic1 qualification remain release gates.

## AutoIt EA06 non-script spooling — 2026-08-22

EA06 non-script members previously retained the complete stored member or
decoded output in a contiguous allocation before nested scanning. Stored
members now decrypt into a bounded chunk and disk-backed temporary file, while
compressed members reuse the existing 32 KiB history window and bounded output
writer; temporary reservations and cleanup remain active until the child scan
finishes. Script decompilation still requires random access to its decoded
token stream and retains the explicit 1 GiB unsupported boundary. Source guards
cover the bounded paths; compiled stored/compressed fixtures, sanitizer, and
Sonic1 qualification remain release gates.

## RIFF traversal deadlines — 2026-08-22

The RIFF exploit detector already distinguished in-range fmap callback failures
from genuinely truncated structures, but its recursive chunk walk had no shared
scan-deadline checkpoint. Parser entry and every chunk traversal now check the
deadline and mark the layer incomplete with `CL_ETIMEOUT`; the RIFF dispatcher
propagates that status instead of allowing a timeout to become a clean result.
A dispatch-level expired-context regression and source guards cover the
contract; compiled RIFF corpus, callback/timeout fault injection, sanitizer,
and Sonic1 qualification remain release gates.

## Runtime component provenance — 2026-08-22

The release evidence gate previously captured the scanner and ldd-selected
libraries but could omit the Rust static archive and optional UnRAR
interface/backend, which may be statically linked or loaded with dlopen. It
now preserves release and sanitizer Rust archives, records the exact
ENABLE_UNRAR disposition, copies enabled UnRAR interface/backend artifacts,
and places those copied optional artifacts first in the loader path used for
evidence. The verifier hashes and validates every recorded component, while
synthetic controls reject missing or mismatched Rust or enabled-UnRAR
evidence. This closes the component-identity gap structurally; production-CVD,
service, sanitizer-runtime, and Sonic1 qualification remain release gates.

## MIME/mbox traversal deadlines — 2026-08-22

The MIME/mbox path could spend extended time in raw line reads, materialized
header traversal, or disk-backed multipart discovery without consulting the
shared scan deadline. It now checks `cli_checktimelimit()` at message entry,
before each bounded line read, across materialized headers, and during
streamed multipart and related-part traversal. Expiry marks the layer
incomplete with an explicit reason and preserves `CL_ETIMEOUT` through the
outer result policy; the focused expired-context regression also verifies
cache suppression. Compiled timeout injection, sanitizer, and production
mail-corpus qualification remain release gates.

## Inventory reproducibility closeout — 2026-08-22

The committed `docs/largefile-inventory.tsv` had drifted from the current
source after the parser and resource-hardening slices. It has been regenerated
to 32,608 lines from `tools/largefile_inventory.sh`; a byte-for-byte
reproducibility check now runs inside `tools/largefile_source_guards.sh`, so
stale inventory evidence fails the local guard instead of being accepted.

## Logical matcher root status merge — 2026-08-22

`cli_scan_fmap()` evaluates target-specific and generic matcher roots in
sequence. Before this fix, the second `cli_exp_eval()` return value replaced
the first, so a target-root `CL_EPARSE`, `CL_EREAD`, or resource failure could
become `CL_SUCCESS` when the generic root had no matching failure. The two
results now use `cli_merge_scan_status()`: detections retain precedence, and a
later clean root cannot erase an earlier incomplete status. A focused
target-failure/generic-clean regression covers the status contract; complete
logical-signature corpus and production qualification remain open.

## YARA execution-status normalization — 2026-08-22

The bundled YARA interpreter returns its own numeric `ERROR_*` values for
execution failures. `ERROR_EXEC_STACK_OVERFLOW` is 25, which is also
`CL_EMAXFILES` in ClamAV; the old wrapper passed that integer through as a
ClamAV status. The wrapper now normalizes bundled and REAL_YARA results,
maps timeout/memory/resource errors to ClamAV statuses, maps unknown execution
errors to `CL_EPARSE`, and marks every required non-detection failure
incomplete/non-cacheable. A focused stack-overflow regression covers the
collision; full YARA corpus and production qualification remain open.

## ALZ MaxFiles admission propagation — 2026-08-22

The ALZ scanner stopped its metadata callback when `cli_checklimits()` returned
`CL_EMAXFILES`, but its helper left the parser return status as `CL_SUCCESS`.
The shared C context was already sticky-incomplete, yet the Rust parser now
also returns `CL_EMAXFILES` directly so each layer of the boundary preserves
the required non-clean result. A focused Rust helper regression covers this
admission path; full ALZ corpus, sanitizer, and production qualification
remain open.

## ALZ final limit-result propagation — 2026-08-22

ALZ finalization also had paths where a recorded oversized member, cumulative
scan-size exhaustion, or internal file-count stop appended a limit heuristic
and then returned `CL_SUCCESS`. Those paths now return `CL_EMAXSIZE` or
`CL_EMAXFILES` directly after recording the limit, preserving an explicit
non-clean parser result even when outer sticky-state unwinding changes later.
Full ALZ limit-edge corpus, sanitizer, and production qualification remain
open.

## Shared stream-ceiling enforcement — 2026-08-22

`StreamMaxLength` is normally validated by the option parser, but daemon and
client integrations can also pass an `optstruct` directly. The shared
`clamd_stream_limit()` helper now clamps positive values above the certified
32-GiB ceiling before either clamd staging or client-side stream preflight uses
them. This prevents a stale or programmatic integration from widening the
wire-ingress budget by bypassing configuration parsing. A focused clamd unit
regression covers the over-limit option object; compiled service and Sonic1
qualification remain open.

## Structured report unsigned-counter serialization — 2026-08-22

`cl_scan_report_to_json()` previously cast every 64-bit metric and limit to
`int64_t` before handing it to json-c. The scan-report counters intentionally
saturate at `UINT64_MAX` during aggregate and resource accounting, so that cast
could emit a negative JSON number for a valid saturated counter. The serializer
now uses json-c's unsigned integer object on versions that provide it, and
returns `CL_EARG` on older json-c versions when a value cannot be represented,
allowing clamd's existing explicit incomplete fallback to take over. The
32-bit report limits are also serialized through the same 64-bit-safe path. A
focused saturated-counter regression and source guards cover the boundary;
compiled JSON-C-version and service qualification remain release gates.

## PDF ARC4 length propagation — 2026-08-22

`decrypt_any()` previously cast its native `size_t` input length to
`unsigned` before calling the ARC4 helper. The current PDF decoder rejects
streams above the 1 GiB contiguous-allocation boundary, so that cast was not
reachable through today's supported PDF stream path; it was nevertheless a
latent truncation if that boundary or another caller changed. `arc4_apply()`
now accepts `size_t`, the cast and TODO are gone, and the focused ARC4 vector
regression plus source guards preserve native-width propagation. This does
not expand the documented PDF filter boundary.

## PDF packed object-reference bounds — 2026-08-22

The PDF parser represents an object reference as a 32-bit composite: the
object number occupies 24 bits and the generation occupies 8 bits. The parser
previously shifted or masked larger values into that composite, allowing a
malformed large reference to alias a different object. Direct object discovery,
object-stream discovery, `/Length` resolution, encryption dictionaries,
special action references, and PDFNG string/dictionary/array references now
reject out-of-range values and mark the scan incomplete. The focused helper
regression covers the maximum representable reference and both overflow cases;
full malformed-reference corpus qualification remains open.

## Mixed bytecode offset-bridge continuation — 2026-08-22

The mixed format-7/format-8 hook path already continued after a legacy file
size could not be represented, but its separate logical-match offset bridge
still returned immediately when an offset exceeded the v1 range. That made a
small mapped layer with a large native matcher coordinate suppress every later
v2 hook. The bridge now records `CL_EMAXSIZE`, marks the layer incomplete and
non-cacheable, resets the v1 context, and continues. A focused unit regression
checks that the later v2 dispatch selects `match_offsets64` after the v1
conversion fails; mixed interpreter/JIT and production qualification remain
open.

## ELF32 table-coordinate widening — 2026-08-22

ELF32's table-base fields remain 32-bit format values, but the parser now
uses native-width cursors while walking implicit program and section-header
entries. This prevents a table that crosses 4 GiB in a larger containing file
from wrapping its cursor to the beginning and reading unrelated bytes. A
synthetic >4 GiB-coordinate regression verifies the second section header;
compiled ELF corpus, sanitizer, and supported-Linux qualification remain
release gates.

## ELF32 derived entry-point coordinate widening — 2026-08-22

ELF32 program-header fields remain format-defined 32-bit values, but the
derived file coordinate `p_offset + (e_entry - p_vaddr)` can exceed 4 GiB in
a larger containing file. The parser now computes that coordinate in native
width and preserves the explicit incomplete marker only for the legacy
32-bit metadata bridge. The synthetic ELF32 regression covers this overflow
alongside the table-cursor boundary; compiled ELF corpus, sanitizer, and
supported-Linux qualification remain release gates.

## PE32 native RVA-to-file coordinates — 2026-08-22

PE32 section starts and RVAs remain 32-bit format fields, but their containing
file coordinate is not limited to 32 bits: a valid in-section delta can carry
the raw offset above 4 GiB. The native PE translator now performs this sum in
64-bit arithmetic and populates the native executable metadata view. The
legacy translator and bytecode bridge reject an unrepresentable coordinate
instead of wrapping it into an earlier file location, and the PE-specific
scanner marks that skipped legacy layer incomplete. A focused boundary
regression covers both outcomes; compiled PE corpus, unpacker, sanitizer, and
supported-build qualification remain open.

## PE32 unsigned high-bit section fields — 2026-08-22

PE section-header DWORDs are unsigned format fields, so a high bit in a
VirtualAddress, VirtualSize, or raw-coordinate field is not by itself a
malformed header. The PE header path now preserves those values in its native
section metadata and marks only the legacy signed-coordinate PE-specific
analysis incomplete instead of returning `CL_EFORMAT` and discarding the
recognized layer. Checked RVA-extent arithmetic also marks a legacy bridge
incomplete before its 32-bit extent can wrap. A synthetic high-bit section
header regression and source guards cover the disposition; compiled PE,
unpacker, sanitizer, and supported-build qualification remain open.

## PE32 aligned section extents — 2026-08-22

PE alignment-up can turn a legal 32-bit raw-size or virtual-size field into a
native extent above 4 GiB. Section alignment, file-range truncation, and
overlay calculation now retain those values in the native section view; the
legacy section view is narrowed only with an explicit incomplete marker. PE
hash generation also refuses to produce a partial legacy result when that
bridge is incomplete. A sparse logical-map regression covers a 4-GiB aligned
section size and native overlay start, while compiled PE corpus, unpacker,
sanitizer, and supported-build qualification remain open.

## ISO9660 long directory names — 2026-08-22

ISO directory identifiers larger than the fixed 260-byte display buffer are
still deliberately bounded and marked incomplete, but the directory walker
previously used the original on-disk length when searching for a version
suffix and writing the terminator. It now uses the normalized buffer length,
preventing an out-of-bounds write while retaining the non-cacheable incomplete
disposition. A synthetic 260-byte identifier regression and source guards
cover the boundary; compiled ISO corpus, sanitizer, and parser-family
qualification remain open.

## OLE2 encryption metadata window — 2026-08-22

OLE2 encryption detection previously reused the fmap pointer for the fixed
header after indexing it by the encryption-stream offset. That pointer only
covered the header window, so an input with enough sectors to reach the
encryption stream could make the probe read outside the mapped range. The
probe now performs checked native-width range admission, maps at most a 64 KiB
encryption-info window, and marks an in-range callback failure incomplete.
A callback-backed regression verifies that the later native range is fetched;
compiled encrypted-OLE2 corpus, sanitizer, and supported-build qualification
remain release gates.

## HFS+ declared fork-block accounting — 2026-08-22

HFS+ fork extraction checked the format-declared `totalBlocks` value but never
advanced its emitted-block counter. A fork could therefore provide a larger
logical size and consume a later inline extent after its declared block count
was exhausted. The extractor now increments the native output count after
each successfully written block and stops with an incomplete result when the
declared fork ends early. The focused regression injects a failure at the
second block and verifies that the corrected path stops before requesting it;
compiled HFS+ corpus, sanitizer, and production qualification remain open.

## UDF logical information-length accounting — 2026-08-22

UDF file-entry allocation descriptors have a format-defined information length
that must equal the sum of their per-extent information lengths. The previous
extractor ignored the file-entry declaration and could materialize a mismatched
allocation list. Extraction now requires exact aggregate accounting before
materialization and marks an `ext_ad` transformation unsupported when recorded
bytes differ from logical bytes. A focused synthetic descriptor regression
covers the shorter-than-declared case. Static guards and whitespace validation
remain the available local evidence; compiled transformed-extent/read-fault,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## ISO9660 root-directory coordinate overflow — 2026-08-22

ISO child directory records already checked their extent-location plus
extended-attribute-length coordinate, but the primary root-directory record
still performed that addition in a 32-bit expression. A wrapped root could
therefore redirect the walk to an earlier block. The root coordinate now uses
checked 64-bit arithmetic and marks overflow incomplete before directory
state is traversed; the existing coordinate regression covers both child and
root cases. Static guards and whitespace validation remain the available local
evidence; compiled ISO corpus, sanitizer, and supported-build qualification
remain release gates.

## BZip2 concatenated-stream completion — 2026-08-22

The BZip2 decoder previously stopped after the first `BZ_STREAM_END`, leaving
valid concatenated streams uninspected, and had no explicit no-progress guard
for malformed input. The scanner now preserves unread input, reinitializes a
new stream only after a completed member, consumes all concatenated members,
and marks a decoder that consumes neither input nor output incomplete. A
focused signature regression puts the marker in the second member. Static
guards and whitespace validation are available locally; malformed corpus,
sanitizer, and supported-build qualification remain release gates.

## JPEG Photoshop resource-header callback failures — 2026-08-22

The Photoshop resource walker first proves that its seven-byte `8BIM` header
lies in the fmap, so a failed `fmap_need_off_once()` there is an operational
read failure rather than truncation. The parser now preserves `CL_EREAD` and
the incomplete/non-cacheable state; a focused callback regression covers it.
Static guards and whitespace validation remain local evidence; compiled JPEG
corpus, sanitizer, and supported-build qualification remain release gates.

## JPEG Photoshop marker-prefix callback failures — 2026-08-22

APP13 Photoshop recognition is a required read once the segment range has
been admitted. The probe now checks the prefix against the segment payload
length before reading, preventing cross-segment inspection, and preserves an
in-range fmap callback failure as `CL_EREAD` with incomplete/non-cacheable
state. Static guards and whitespace validation remain local evidence;
compiled JPEG corpus, sanitizer, and supported-build qualification remain
release gates. The exact-EOF Photoshop-resource regression remains complete
when the resource list ends at the admitted segment boundary.

## JPEG Photoshop resource segment boundaries — 2026-08-22

The Photoshop resource walker now receives the admitted APP13 segment end and
uses it for resource headers, names, sizes, data, and nested thumbnail bounds.
It no longer treats a later JPEG segment as Photoshop data. The focused
regression places an injected seven-byte read fault at that boundary and
expects the following SOS to remain complete. Static guards and whitespace
validation remain local evidence; compiled thumbnail corpus, sanitizer, and
supported-build qualification remain release gates.

## GPT sector-size probe read failures — 2026-08-22

GPT auto-detection previously used an unlocked fmap probe without a scanning
context. An in-range backing-read failure could therefore be reduced to the
same zero-sector result as an ordinary non-GPT input. The probe now uses
bounded `fmap_readn()` windows, preserves `CL_EREAD`, and marks the layer
incomplete before the parser exits. A focused auto-detection callback
regression covers the 512-byte candidate; static guards remain local evidence,
while compiled partition-image, sanitizer, and supported-build qualification
remain release gates.

## SIS language-table read failures — 2026-08-22

Old-format SIS language metadata is a required borrowed fmap window. Its
admission now checks the native map range before borrowing and distinguishes an
in-range backing-read failure (`CL_EREAD`) from a genuinely truncated table
(`CL_EPARSE`), preserving the sticky incomplete/non-cacheable result in both
cases. A focused callback regression covers the in-range failure; compiled SIS
corpus, sanitizer, and supported-build qualification remain release gates.

## PE version-resource read failures — 2026-08-22

PE version-resource extraction previously ignored the status returned by its
resource-tree walker and silently skipped failed entry or payload windows. The
metadata path now propagates malformed/out-of-range coordinates as `CL_EFORMAT`
and in-range fmap callback failures as `CL_EREAD`, marking the scan incomplete
and non-cacheable before relative version metadata can be omitted. The focused
regression faults the confirmed resource-tree root in the checked-in PE
fixture; compiled PE metadata corpus, sanitizer, and supported-build
qualification remain release gates.

## PE Swizzor resource read failures — 2026-08-22

The enabled Swizzor heuristic used to return a clean heuristic result after a
recursive resource read failed or a resource coordinate was malformed. The
resource walker now returns `CL_EREAD` for in-range fmap callback failures and
`CL_EFORMAT` for malformed/out-of-range coordinates; `cli_scanpe` records the
failure as incomplete and non-cacheable before returning. The focused normal
PE scan regression faults the confirmed resource-tree root; compiled Swizzor
corpus, sanitizer, and supported-build qualification remain release gates.

## PDF trailer-xref read failures — 2026-08-22

The PDF trailer xref probe previously collapsed an in-range backing-read
failure into the same parse status used for malformed xref structure. The
probe now preserves `CL_EREAD` and the incomplete/non-cacheable state for a
callback failure, while retaining `CL_EPARSE` for a successfully read invalid
xref. The focused regression faults the xref window after trailer discovery;
compiled PDF corpus, sanitizer, and supported-build qualification remain
release gates.

## Complete sanitizer compile-graph evidence — 2026-08-22

F-13 evidence validation now rejects a sanitizer compile database with even one
native command lacking ASan or UBSan, while preserving the existing Rust archive
and loader checks. This closes the specific “flags appear somewhere” verifier
weakness; self-contained release attestation, full sanitizer execution, and
service qualification remain open.

## Detection verdict binding in service evidence — 2026-08-22

The service qualification oracle previously bound a detection report to its
`last_alert` string but did not require a non-clean verdict. The direct clamd
report probe, service shell gate, and post-run workload verifier now require
`CL_VERDICT_STRONG_INDICATOR` or `CL_VERDICT_POTENTIALLY_UNWANTED` for every
detection-shaped oracle row; the synthetic regression mutates a valid alert to
a clean verdict and requires rejection. Full Linux/Sonic1 service execution
remains open.

## Structured detection offset binding — 2026-08-22

The structured report path previously exposed only the retained alert name, so
direct clamd report probes silently ignored the oracle's exact match offset.
Root-level AC, BM, and PCRE matcher alerts now preserve a native-width offset in
the structured report when the evidence retains that alert. Parser, hash,
callback, and child-layer alerts intentionally do not publish a guessed
coordinate. The direct protocol checker, shell gate, and post-run workload
verifier now require `last_alert_offset` to be present and equal to the
detection oracle. A synthetic mismatch regression rejects an incorrect
offset; compiled report, service, sanitizer, parser-corpus, and Sonic1
qualification remain release gates.

## Structured report status propagation — 2026-08-22

The shared framed-report parser previously discarded the numeric status on
incomplete reports, so on-access and milter consumers could only distinguish a
boolean incomplete flag and on-access reduced the result to `CL_EPARSE`. It
now validates the status against the `cl_error_t` range, rejects contradictory
clean/error combinations, and returns the exact non-clean status. On-access
and milter frame aggregation preserve that status while retaining detection
precedence across sibling frames; malformed reports still fail closed. The
focused parser regression covers explicit and implicit string incomplete
reports and contradictory numeric statuses. Compiled fanotify, multi-frame,
exact milter-action, sanitizer, and Sonic1 qualification remain open.

## Structured incomplete status normalization — 2026-08-22

The report producer could serialize `status: 0` or `CL_VERIFIED` alongside a
sticky incomplete completion when older callers supplied only the context
marker. That contradicted the framed consumer contract and caused a strict
consumer to reject otherwise meaningful `UNSUPPORTED` or resource reports.
`cli_scan_report_finish()` now derives the most specific non-clean status from
the limit/abort state and reason (`CL_ERESOURCE`, `CL_BREAK`, `CL_EUNPACK`,
`CL_EPARSE`, or `CL_ERROR`) without changing detection precedence. Daemon
unsupported-file skips explicitly use `CL_EUNPACK`; focused report tests cover
resource, generic, and unsupported normalization. Compiled daemon skip, wire,
sanitizer, and Sonic1 qualification remain open.

## MIME header lookahead read failure — 2026-08-23

The legacy MIME header state machine probes the next byte after each collected
header line to decide whether the following line is a continuation. A failed
in-range fmap callback previously returned `NULL` and was treated exactly like
an ordinary non-continuation, so parsing could continue after an operational
read failure. The lookahead now marks the scan incomplete, sets the parse
status to `CL_EREAD`, and stops the header pass. A focused regression injects a
one-shot failure at the lookahead offset and verifies the non-clean,
non-cacheable result.

## APM partition coordinate admission — 2026-08-22

APM block coordinates were multiplied directly into `size_t` offsets, and the
old-school 2048-byte driver scaling had a second unchecked multiplication.
Those products are now admitted through a checked native-size helper before
fmap reads or nested partition scans; the intersection walk also rejects a
32-bit block-count scaling overflow. A focused synthetic coordinate regression
covers the wrap-to-readable-range case on narrow `size_t` builds. Compiled
partition-image, sanitizer, and parser-family qualification remain open.

## VBA 64-bit fmap matcher admission — 2026-08-22

The legacy OLE/VBA path rejected decompressed module buffers above 4 GiB before
matching because it passed their length through `cli_scan_buff()`'s 32-bit
buffer ABI. `vba_scandata()` now creates a child fmap and uses
`cli_scan_fmap()`, so raw matching, full-map PCRE, and logical/YARA evaluation
retain native-size input coordinates. The later bounded VBA-module milestone
replaces source-body materialization with fixed-window decompression, stateful
conversion, incremental normalization, and transactional spool output.
Project-directory metadata and the legacy whole-module callback retain explicit
1 GiB contiguous boundaries. Production corpus, sanitizer, Linux x86-64, and
Sonic1 qualification remain open.

## Script native-width normalized fmap admission — 2026-08-22

Script normalization now writes every generated byte to a quota-accounted
temporary file and scans one normalized child fmap through `cli_scan_fmap()`.
This removes the obsolete per-window 32-bit matcher boundary and preserves
full-map PCRE, logical, and YARA evaluation for normalized output. Empty
generated views remain representable; input-size, temporary-space, parser,
sanitizer, corpus, and Sonic1 qualification remain release gates.

## HTML normalized-output temporary admission — 2026-08-22

HTML nocomment, notags, JavaScript, and RFC2397 normalized outputs now reserve
each emitted chunk against the caller-owned `MaxTemporarySize` budget before
writing. The main HTML scanner holds those reservations through all required
normalized child scans and releases them only after temporary cleanup; the
MBOX/phishing URL normalizer uses the same admission while it runs. Quota and
write failures remain incomplete and non-cacheable, including RFC2397 files
that finish before the normalizer exits. Direct legacy HTML helper wrappers
retain their compatibility behavior and still require separate qualification.

## PDF raw-stream chunking and output admission — 2026-08-22

Unfiltered PDF streams previously entered the contiguous legacy decoder token
and could be rejected by the 1 GiB individual-allocation boundary even though
no filter decoding was required. They now copy to the extracted child in
64 KiB chunks while preserving native-width containing-file coordinates.
Decoded/filtered stream output is admitted through the same caller-owned
temporary reservation used by `pdf_extract_obj`, with both paths re-checking the
shared deadline after admission and immediately before each write. Parser
staging, extracted-object output, and normalized-content output now use the same
fail-closed boundaries. Filtered decoder input and
decoder growth above the 1 GiB individual-allocation boundary remain an
explicit unsupported/incomplete result; full streaming filter conversion,
compiled PDF corpus, sanitizer, and Sonic1 qualification remain open.

## LHA/LZH decoder-output deadline — 2026-08-22

The Rust LHA/LZH path already reads through the bounded context-aware fmap
adapter and writes members through a quota-accounted spool, but a decoder can
emit several output chunks without asking the reader for more input. The member
output loop now checks the shared scan deadline before every bounded decoder
read, preserving `CL_ETIMEOUT` and the incomplete/non-cacheable result even in
that no-new-input interval. Compiled timeout injection, malformed/multi-member
corpus, sanitizer, and Sonic1 qualification remain open.

## HWP raw-deflate input read classification — 2026-08-23

HWP raw-deflate staging previously requested a full `FILEBUFF` window even
when a declared compressed length was shorter, and mapped any failed
`fmap_readn()` request to generic `CL_EUNPACK` without an incomplete marker.
The reader now bounds each request to the declared stream and containing fmap,
returns `CL_EPARSE` for truncation, and preserves `CL_EREAD` with sticky
incomplete state for a fully in-range callback failure. A focused HWP3
regression injects the compressed-window callback fault and checks the exact
status and non-cacheable state. Compiled HWP corpus, sanitizer, and Sonic1
qualification remain open.

## Structured-detector clipped-window read classification — 2026-08-23

The structured-data detector requested fixed 8 KiB windows and treated every
fmap callback failure as CL_EREAD. Since the fmap clips a final request that
extends past EOF, a failure on that clipped window represents an incomplete
input prefix rather than a fully in-range operational read fault. The
detector now returns CL_EREAD only for fully contained callback failures and
returns CL_EPARSE with sticky incomplete state for clipped failures. The
existing in-range fault regression now uses an exact 8191-byte window, and a
new short-input regression covers the clipped case. Compiled detector corpus,
sanitizer, and Sonic1 qualification remain open.

## ALZ extracted-output deadline — 2026-08-22

The bounded ALZ reader already checked the shared deadline while consuming fmap
input, but decoder-emitted member chunks enter the extraction sink through a
separate callback. That callback now checks `MaxScanTime` before temporary
reservation or output writes, preserving `CL_ETIMEOUT` and fail-closed status
when a decoder produces data without another input read. Compiled timeout
injection, malformed/multi-member corpus, sanitizer, and Sonic1 qualification
remain open.

## OneNote attachment-output deadline — 2026-08-22

OneNote’s legacy reader and bounded modern parser both deliver attachment bytes
through callbacks after the source has been read or mapped. Those callbacks now
check `MaxScanTime` before reserving or writing attachment output, preserving
`CL_ETIMEOUT` and fail-closed status when resident attachment data would
otherwise bypass the reader deadline. Compiled timeout injection, modern-parser
size-boundary, corpus, sanitizer, and Sonic1 qualification remain open.

## MIME body-spool export deadline — 2026-08-22

The mail parser already checked its fmap and multipart traversal loops, but the
disk-backed body path could spend additional time copying raw data or decoding
base64/quoted-printable output during reassembly/export without returning to the
shared deadline helper. Body-spool writes and each bounded raw/encoded export
chunk now check `MaxScanTime`, preserving `CL_ETIMEOUT` and fail-closed status
through mail materialization. Compiled timeout injection during reassembly,
mail corpus, sanitizer, and Sonic1 qualification remain open.

## DMG staging and reconstruction deadline — 2026-08-22

DMG stripe decoders already checked the shared deadline around their input and
decoder loops, but the optional XML temporary copy, partition-list handoff, and
shared bounded output writer had separate I/O intervals that could bypass that
check. Those intervals now preserve `CL_ETIMEOUT` before staging or reconstructed
output is treated as complete. Compiled DMG timeout injection, corpus,
sanitizer, and Sonic1 qualification remain open.

## XAR output-reservation deadline — 2026-08-22

XAR’s decoder and member loops already checked `MaxScanTime`, but the common
temporary-output writer used by TOC, subdocument, compressed-member, and
raw-member producers did not re-check the deadline after admission. It now
checks both after reservation and immediately before each spool write, releases
the current reservation on timeout or short write, and preserves `CL_ETIMEOUT`
or `CL_EWRITE` through cleanup. Compiled timeout/short-write injection, corpus,
sanitizer, and Sonic1 qualification remain open.

## Shared compressed-output reservation deadline — 2026-08-22

GZip, BZip2, XZ, SZDD, script normalization, and CryptFF already checked
`MaxScanTime` in their decoder/input loops, but all of them could reach their
common temporary-output reservation as a separate output interval. That shared
admission now rejects expired contexts before reserving bytes for a spool write,
preserving `CL_ETIMEOUT` across the decoder families. Compiled output-timeout
injection, corpus, sanitizer, and Sonic1 qualification remain open.

## HFS+ output deadlines — 2026-08-22

HFS+ ordinary fork, inline compressed, and compressed-resource output paths now
re-check the shared deadline after temporary admission and immediately before
materialized writes. Timeout cleanup releases the fork/resource reservation
and prevents partial output from reaching nested scans. Source guards cover
the output families; deterministic post-admission injection, compiled HFS+
corpus, sanitizer, and Sonic1 qualification remain release gates.

## AutoIt output deadlines — 2026-08-22

EA05/EA06 streamed output and EA06 script materialization now re-check the
shared deadline after temporary admission and immediately before writes. The
shared decoder flush and nested-member handoff are covered, and timeout paths
release reservations before partial output can be scanned. Source guards cover
the output families; deterministic post-admission injection, compiled AutoIt
corpus, sanitizer, and Sonic1 qualification remain release gates.

## ZIP output deadlines — 2026-08-22

Bounded stored, deflate, BZip2, Implode, legacy, and ZipCrypto output paths now
re-check the shared deadline after temporary admission and immediately before
materialized writes. Timeout cleanup preserves the existing member reservation
and prevents partial output from reaching nested scans. Source guards cover
the shared and encrypted writers; deterministic post-admission injection,
compiled ZIP corpus, sanitizer, and Sonic1 qualification remain release gates.

## BinHex and RTF output deadlines — 2026-08-22

BinHex data/resource fork output now re-checks the shared deadline after
temporary admission, immediately before writes, and before nested handoff.
RTF embedded-object admission and each materialized write use the same
fail-closed deadline boundary. Source guards cover both families; deterministic
post-admission injection, compiled BinHex/RTF corpus, sanitizer, and Sonic1
qualification remain release gates.

## VBA, OLE10, and PowerPoint output deadlines — 2026-08-22

The shared VBA project writer, OLE10 copy loop, and PowerPoint output helper
now re-check the deadline after temporary admission and immediately before
materialized writes. PowerPoint traversal and OLE10 nested-scan handoff also
retain explicit timeout results; cleanup releases reservations before partial
Office output can be scanned. Source guards cover these paths; deterministic
post-admission injection, compiled Office/PPT corpus, sanitizer, and Sonic1
qualification remain release gates.

## MSXML materialization deadlines — 2026-08-22

Legacy MSXML callback and Base64 materialization now re-check the shared scan
deadline after temporary admission, immediately before writing, and immediately
before nested scanning or callback handoff. The streaming MSXML writer now also
checks the deadline after each chunk reservation, and its Base64 and callback
handoffs re-check it immediately before dispatch. Expired paths release the
current reservation and keep partial output out of nested scans. Source guards
cover the legacy and streaming boundaries; deterministic timeout injection,
compiled XML/OOXML/HWPML corpus, sanitizer, and Sonic1 qualification remain
release gates.

## Shared compressed-output write deadlines — 2026-08-22

The shared compressed-output reservation now re-checks the scan deadline after
each temporary quota admission, releasing the current chunk when the deadline
expires. GZip (including the legacy fallback), BZip2, XZ, script normalization,
and CryptFF now also re-check the deadline immediately before each materialized
write and preserve the timeout through their existing cleanup paths. Source
guards cover the shared writer and each family-specific timeout reason;
deterministic output-timeout injection, compiled compressed/script/CryptFF
corpus, sanitizer, and Sonic1 qualification remain release gates.

## Shared child-output and staging deadlines — 2026-08-22

Shared descriptor-child and force-to-disk nested-fmap paths now re-check the
deadline after temporary admission, immediately before each materialized write,
and immediately before nested handoff. EGG member output, per-chunk RAR
temporary-input staging, legacy VBA project output, and UTF-16 HTML output now
use the same fail-closed boundaries. Source guards cover the shared and family-specific
reasons; deterministic timeout injection, compiled archive/Office/HTML corpus,
sanitizer, and Sonic1 qualification remain release gates.

## JavaScript normalization output deadlines — 2026-08-22

The quota-backed JavaScript normalization flush now re-checks the shared scan
deadline after each temporary reservation and immediately before writing. A
timeout releases the current reservation and propagates an incomplete result
to HTML and bytecode normalization callers. Source guards cover both deadline
boundaries; deterministic timeout injection, compiled HTML/bytecode corpus,
sanitizer, and Sonic1 qualification remain release gates.

## ARJ output deadlines — 2026-08-22

ARJ stored-member and decompressor output now re-checks the shared scan
deadline immediately before each materialized write. ARJ temporary admission
and the nested-scan handoff are also explicit, while the existing declared-size
and cleanup checks remain in force. Source guards cover these boundaries;
deterministic output-timeout injection, compiled ARJ corpus, sanitizer, and
Sonic1 qualification remain release gates.

## TNEF debug-dump output deadlines — 2026-08-22

The optional TNEF debug-dump path now re-checks the shared deadline immediately
before each materialized write and preserves incomplete write failures instead
of ignoring them. Deterministic debug-output fault injection, compiled TNEF
corpus, sanitizer, and Sonic1 qualification remain release gates.

## Logical matcher continuation after non-critical failure — 2026-08-22

Logical-signature evaluation previously stopped at the first non-success
status. That made an unavailable bytecode entry, legacy-ABI incompatibility,
or other non-critical logical failure suppress independent later signatures
that could still detect the file. The evaluator now merges each result,
continues after non-critical failures, and stops only for detections or
critical timeout/resource/I/O failures. A focused regression verifies that an
unavailable first bytecode entry remains incomplete and non-cacheable while a
later logical signature still produces `CL_VIRUS`; compiled logical-signature,
interpreter/JIT, sanitizer, and production qualification remain open.

## Raw matcher-root continuation after non-critical failure — 2026-08-22

The target-specific raw matcher previously returned immediately from buffer
and fmap scans on any non-clean result, so a non-critical target-root read,
parser, or matcher failure could suppress the independent generic raw pass.
Both raw ingress helpers now merge non-critical target-root failures, continue
with the generic root, and retain the merged non-clean result; detections and
critical failures still stop immediately. Static guards cover both paths;
compiled fault-injection and production-signature qualification remain open.
Local AC-data initialization now follows the same rule: a non-critical setup
failure skips only that root, while the other root remains eligible to run.

## Raw matcher-root setup isolation — 2026-08-22

`cli_scan_fmap()` now treats matcher-root initialization, relative-offset
calculation, Boyer-Moore offset preparation, and PCRE offset preparation as
independent setup stages. A non-critical failure disables only the affected
root, preserves its specific status, recomputes the overlap window from roots
that are actually ready, and continues with the other raw matcher. Critical
memory, timeout, resource, and I/O failures still halt immediately. Static
guards cover root readiness, independent hash accumulation, and cleanup;
compiled fault-injection and production-signature qualification remain open.

## Shared blob allocation arithmetic — 2026-08-22

The compatibility `blob` helper used by legacy text/VBA paths rounded each
append before checking the shared individual-allocation ceiling. Its
`b->size + growth` and `b->len + len` expressions could therefore wrap before
`cli_max_realloc()` or the final copy, potentially turning an oversized request
into a smaller allocation. `blobAddData()` and `blobGrow()` now validate the
existing native-width counters and the cumulative required size first, bound
page/legacy growth arithmetic to `CLI_MAX_ALLOCATION`, and commit the checked
length. Oversized requests return an explicit failure, with a focused unit
regression and source guards. Compiled overflow/fault-injection coverage and
legacy parser-family qualification remain open.

## Rust temporary-spool output deadline — 2026-08-22

The shared Rust `TempSpool::write_all()` helper reserved additional temporary
bytes before issuing its raw `libc::write()`. Several decoder callbacks checked
the deadline before entering the helper, but generic reader, OneNote root, and
other shared spool paths had no final check after that reservation. The helper
now re-checks `MaxScanTime` after quota admission and before writing; if the
deadline expires, it releases only the newly added reservation and returns the
timeout to the caller. The helper also splits large callback slices into bounded
64 KiB writes and checks the deadline before each write, so a large OneNote
attachment cannot monopolize one unchecked output operation. Compiled timeout
injection and Rust parser-family qualification remain open.

## CommuniGate MIME header-skip deadline — 2026-08-22

The single-message CommuniGate Pro compatibility path skipped header lines with
an unbounded `fmap_gets()` loop. On a large input without a blank separator it
could traverse the complete fmap without reaching the MIME parser’s shared
deadline helper, and an incomplete fmap read was indistinguishable from normal
EOF. The loop now checks `MaxScanTime` before each line, returns
`CL_ETIMEOUT` on expiry, and marks an early fmap failure as incomplete
`CL_EREAD`. Static guards cover both boundaries; compiled mailbox timeout and
fault-injection qualification remain release gates.

## HTML phishing URL extraction deadline — 2026-08-22

The file-backed HTML phishing helper `extract_text_urls_map()` processed a
64 KiB window at a time, but its complete-map loop had no parser-owned
`MaxScanTime` checkpoint. A large HTML body could therefore spend the whole
URL extraction pass in a required enabled path without observing the shared
deadline. The helper now checks the deadline before each fmap window and again
before publishing the trailing URL, returning an incomplete result on expiry.
The read remains bounded and short/in-range fmap failures remain fail-visible.
Compiled HTML timeout injection, parser corpus, sanitizer, and supported-build
Sonic1 qualification remain release gates.

## Raw embedded-type dispatch deadline — 2026-08-22

The raw matcher produced a linked list of embedded file-type candidates, but the
central dispatch loop could walk that list without checking `MaxScanTime`. A
large candidate list could therefore delay the deadline while repeatedly
entering required parser admission and header checks. The dispatch loop now
checks the shared deadline before each candidate, marks the scan incomplete on
expiry, and preserves `CL_ETIMEOUT` for the final result. Parser-specific
qualification and Sonic1 runtime evidence remain release gates.

## Runtime loader injection isolation — 2026-08-22

The runtime gate inherited `LD_PRELOAD` and `LD_AUDIT` while collecting loader
traces and running the qualification workload. Either variable could inject
unhashed code and make otherwise valid dependency/source provenance
non-authoritative. The gate now clears both variables before any evidence or
scanner process starts and records `loader_injection=disabled`; the evidence
verifier requires that disposition. The Linux build, sanitizer, and service
qualification runs remain required.

The service gate now applies the same isolation before starting clamd or any
frontend and requires the same disposition in `service-build-identity.txt`.

## Legacy PDF object-search deadline — 2026-08-22

The legacy PDF parser staged the input for stable pointers, but its object
header and `endobj` searches still called `cli_memstr()` over the entire
remaining document. A large or malformed PDF could therefore spend a required
parser pass without observing `MaxScanTime`. Those searches now use overlapping
64 KiB windows with deadline checks and return `CL_ETIMEOUT` as an incomplete
scan. Compiled timeout injection, decoder fault coverage, and Sonic1 PDF
qualification remain release gates.

The legacy PDF dictionary loop also now checks for a missing next token before
subtracting pointer coordinates, preventing malformed large objects from
reaching undefined pointer arithmetic; compiled malformed-object and timeout
qualification remain open.

Legacy PDF stream-boundary detection also now searches for `stream` and
`endstream` through overlapping 64 KiB windows with the shared deadline. A
timeout is reported as an incomplete scan instead of silently treating the
object as a truncated stream; compiled timeout and malformed-stream
qualification remain release gates.

The remaining whole-object PDF searches for stream `/Length`, JavaScript,
`/XRef`, and trailer encryption now use the same deadline-aware windows and
mark the scan incomplete on timeout. The classic dictionary helper and
metadata tree searches still need a context-aware pass, with compiled timeout
qualification remaining open.

The PDF page-tree `/Kids`, `/Count`, and `/Colors` metadata searches now use
the same deadline windows. The `/Colors` numeric parse also now passes the
remaining object length instead of a reversed pointer subtraction, avoiding a
large unsigned length on that callback. URI metadata extraction now checks the
deadline during both bytewise delimiter searches; compiled metadata timeout
and malformed-object qualification remain open.

The legacy PDF dictionary helper now accepts the PDF context and uses deadline
windows for key searches. Literal, hexadecimal, and name-value scans also
checkpoint while decoding large values. The public context-free encryption
method helper remains a compatibility boundary and deliberately retains its
fallback search behavior; compiled dictionary timeout and malformed-value
qualification remain open.

The context-bearing encryption-object `/Standard` search now also uses the
deadline-aware window helper; the PDF version-header search remains bounded to
the existing 1032-byte probe. Compiled encrypted-PDF timeout and malformed
dictionary qualification remain release gates.

The legacy PDF token scanner now receives the PDF context and checkpoints
while walking long comments, whitespace, and line endings. Context-free
compatibility callers retain the original behavior; compiled token-timeout and
malformed-object qualification remain release gates.

The active encryption scanner now routes its crypt-filter lookups through a
context-aware `parse_enc_method_ctx()` while preserving the public
context-free `parse_enc_method()` wrapper for ABI compatibility. Compiled
encrypted-PDF timeout and malformed-filter qualification remain open.

The remaining large legacy-PDF name and JavaScript delimiter scans now use the
same deadline-aware one-byte searches, so dictionary-name normalization and
non-conforming JavaScript recovery cannot consume an entire large object
without observing the shared limit. Compiled timeout and malformed-object
qualification remain open.

## RAR archive-comment staging deadline — 2026-08-22

The optional UnRAR backend's `keeptmp` archive-comment path previously used one
unchecked direct `write()` and ignored partial writes. It now stages comments in
64 KiB chunks, checks the shared deadline before and after the bounded output,
and preserves a fail-visible timeout or short-write result. Compiled optional
backend coverage, deterministic comment-timeout injection, sanitizer, and
Sonic1 qualification remain release gates.

## 7-Zip post-write deadline boundary — 2026-08-22

The 7-Zip streaming output callback already checked `MaxScanTime` before each
decoder write, but a deadline expiring during that write was not observed until
the decoder made another callback. It now checks immediately after each bounded
write as well, reports `CL_ETIMEOUT` through the callback status, and preserves
the existing temporary cleanup and no-partial-child-scan behavior. Compiled
solid-archive timeout injection, sanitizer, and Sonic1 qualification remain
release gates.

## PDFNG referenced-object reload deadline — 2026-08-22

PDFNG indirect-string handling can dump a referenced object and reload it into
one contiguous buffer below the individual-allocation ceiling. That raw reload
could previously consume a large I/O operation without observing `MaxScanTime`.
The path now checks the shared deadline immediately before and after the read,
cleans up the temporary object and buffer on expiry, and leaves the broader
PDFNG in-memory parsing loops as a separate qualification item. Compiled
timeout injection, sanitizer, and Sonic1 qualification remain release gates.

## PDFNG parser-loop deadline checkpoints — 2026-08-22

PDFNG string finalization, UTF conversion, indirect-reference tokenization, and
the large boundary/key/value scans used by dictionary and array parsing could
previously traverse attacker-controlled buffers without parser-owned
`MaxScanTime` checkpoints. These loops now check the shared deadline at bounded
progress intervals, propagate a distinct timeout result from indirect-reference
recognition, and discard partial dictionary/array structures on expiry. Compiled
timeout injection, sanitizer, and Sonic1 qualification remain release gates.

## Runtime evidence gate initialization ordering — 2026-08-22

Static review found that `tools/largefile_runtime_gate.sh` referenced
`runtime_component_dir` while building the initial loader path before assigning
it. Because the gate uses `set -u`, a real Linux qualification run could abort
before dependency evidence and workload execution. The component directory is
now initialized before its first use, and the source guard enforces that order.
The gate still requires the authorized Linux release/sanitizer and service
qualification inputs described above.

## UPX decompressor deadline checkpoints — 2026-08-22

The legacy UPX NRV2B/NRV2D/NRV2E paths previously received no scan context;
their bitstream, back-reference-copy, import-recovery, and PE-rebuild loops
could therefore continue after the shared `MaxScanTime` deadline even though
the surrounding PE path checked it before and after unpacking. The UPX entry
points now receive the scan context, checkpoint the deadline every bounded
number of decoder operations and during large back-reference copies, and mark
the layer incomplete on expiry. The existing 1 GiB contiguous unpacker
boundary remains explicit, and the LZMA-backed UPX path checks the deadline
before and after its decoder call. Static guards and diff checks are covered;
compiled UPX timeout injection, production PE corpus, sanitizer, and Sonic1
qualification remain release gates.

## WWPack decompression deadline checkpoints — 2026-08-22

The legacy WWPack decoder already received scan context for rebuilt-output
handling, but its bitstream, large back-copy, block traversal, and section
reconstruction loops did not independently observe `MaxScanTime`. Those loops
now checkpoint the shared deadline at bounded progress intervals and return a
fail-visible `CL_ETIMEOUT` without handing partial output to the nested scan.
Compiled WWPack timeout injection, short-write coverage, production PE corpus,
sanitizer, and Sonic1 qualification remain release gates.

## Aspack decompression deadline checkpoints — 2026-08-22

The legacy Aspack decoder already propagated `cli_ctx` through its public
entry point, but its block-output and large back-copy loops did not observe
the shared `MaxScanTime`. The decoder state now carries the context and checks
the deadline at bounded progress intervals; expiry marks the layer incomplete,
stops decompression, and prevents partial output from reaching PE rebuild or
nested scanning. Compiled Aspack timeout injection, short-write coverage,
production PE corpus, sanitizer, and Sonic1 qualification remain release gates.

## Upack decompression deadline checkpoints — 2026-08-22

The legacy Upack `unupack399` path could expand output toward the contiguous
unpacker ceiling and then perform call-fix processing without observing the
shared `MaxScanTime`. Its context-aware decoder now checkpoints the output and
back-copy loops, while the caller checks the fix-up traversal before rebuilding
the PE. Timeout is fail-visible and partial output is not handed to rebuild or
nested scanning. Compiled Upack timeout injection, production PE corpus,
sanitizer, and Sonic1 qualification remain release gates.

## FSG decompression deadline checkpoints — 2026-08-22

The shared FSG bitstream decoder previously had no scan context, so FSG 2.0
and multi-section FSG 1.33 output and back-copy loops could run past the
shared `MaxScanTime`. A context-aware `cli_unfsg_ctx()` path now checkpoints
decoder progress and large copies, while the existing context-free wrapper is
retained for MEW and Spin callers. FSG timeout is fail-visible before PE
rebuild or nested scanning. Compiled timeout injection, multi-section corpus,
sanitizer, and Sonic1 qualification remain release gates.

## MEW non-LZMA decompression deadline checkpoints — 2026-08-22

The legacy non-LZMA MEW bitstream decoder previously remained context-free;
its section output and back-copy loops could run beyond the shared
`MaxScanTime`. A context-aware `unmew_ctx()` path now checkpoints decoder
progress, large copies, and MEW section traversal before PE rebuild. The
compiled non-LZMA timeout injection, production corpus, sanitizer, and Sonic1
qualification remain release gates.

## MEW LZMA decompression deadline checkpoints — 2026-08-22

The separate legacy `mew_lzma()` decoder now carries scan context through its
shared LZMA state. Its range-decode helper loops, output/copy loops, and
special-mode call-fix traversal checkpoint `MaxScanTime`; timeout marks the
layer incomplete and prevents the rebuilt PE from being handed to nested
scanning. Compiled LZMA timeout injection, malformed packed-PE coverage,
production corpus, sanitizer, and Sonic1 qualification remain release gates.

## Petite decompression deadline checkpoints — 2026-08-22

The legacy Petite decoder already propagated `cli_ctx` to PE rebuild, but its
compressed-section output, import-table walks, variable-length bitstream
reads, and large back-copy loops did not independently observe
`MaxScanTime`. Those loops now checkpoint progress and return Petite's existing
fail-visible failure convention on expiry, preventing partial output from
reaching rebuild or nested scanning. Compiled Petite timeout injection,
malformed-section coverage, sanitizer, and Sonic1 qualification remain
release gates.

## PEspin context-aware decompression handoffs — 2026-08-22

PEspin already carried the scan context but routed its compressed section and
resource-section handoffs through the context-free FSG wrapper. Both handoffs
now use `cli_unfsg_ctx()`, so FSG timeout and partial-output failures remain
visible to PEspin. PEspin's emulator/XOR loops, compiled timeout injection,
production corpus, sanitizer, and Sonic1 qualification remain release gates.

## yC emulator deadline checkpoints — 2026-08-22

The yC poly emulator previously checked bounds but did not observe
`MaxScanTime` during its per-byte decrypt loop or hostile jump-loop budget.
It now checkpoints both emulator loops, checks section transitions, and
propagates a distinct `CL_ETIMEOUT` result instead of treating timeout as a
virus or generic unpack failure. Compiled timeout injection, hostile jump-loop
coverage, production yC corpus, sanitizer, and Sonic1 qualification remain
release gates.

## DMG blkx metadata retention — 2026-08-22

The streaming DMG callback now validates and handles each completed `blkx`
metadata block before the XML parser can decode the next one. The decoded
metadata and stripe array are released on every callback return, including
timeout, resource, detection, and parser failures; the implementation no
longer queues the complete metadata list in heap memory. At this checkpoint,
the 64 MiB per-block cap remained explicit; the 2026-08-23 file-backed
stripe-reader change below supersedes that decoded-value cap. Compiled multi-block
DMG corpus, deterministic callback-timeout, sanitizer, and supported-build
Sonic1 qualification remain release gates.

## MHTML comment XML memory boundary — 2026-08-22

The MHTML preclassification callback previously used unbounded `strstr()`
searches and passed an attacker-sized XML comment fragment to
`xmlReaderForMemory()`, whose length parameter is an `int`. The callback now
limits the complete comment value to 64 MiB, uses bounded `<xml>` and
`</xml>` searches, checks the fragment length before the reader call, and
returns `CL_ERESOURCE` with sticky incomplete state for oversized metadata.
Missing comment values are also fail-visible. Raw MIME/HTML scanning remains
file-backed and separate from this metadata-only boundary.

The focused oversized-comment fixture and source guards are registered.
Compiled MHTML execution, sanitizer coverage, and supported-build Sonic1
qualification remain open.

## Mach-O 32-bit coordinate overflow — 2026-08-22

The 32-bit Mach-O path previously computed entry-point raw coordinates and
alignment-rounded section sizes in 32-bit arithmetic. Both could wrap before
the parser reported an error. The raw-address helper now checks the addition,
and section alignment uses a widened temporary and rejects an extent above
`UINT32_MAX` as a broken executable. A focused malformed 32-bit section
fixture and source guards are registered; compiled Mach-O, sanitizer, and
Sonic1 qualification remain open.

## Mach-O load-command boundary admission — 2026-08-25

The Mach-O parser previously advanced through the load-command table using the
fixed header and segment sizes without enforcing the file header's
`sizeofcmds` or each command's declared `cmdsize`. A short segment command
could therefore consume bytes belonging to the next command and make malformed
metadata appear inspectable. The parser now range-checks the complete command
table, each command header and declared extent, segment headers and section
tables, and supported architecture thread-state payloads before reading them;
command traversal resumes at the checked command end. The focused
production-linked malformed-segment regression passes, while full Mach-O corpus,
sanitizer, and Sonic1 qualification remain open.

## TIFF missing-map admission — 2026-08-25

The direct TIFF parser marked a missing current fmap as incomplete but returned
`CL_EARG`, conflating unavailable recognized input with an invalid caller
argument. It now returns `CL_EPARSE` with the sticky reason `TIFF input map is
unavailable`, matching the confirmed-layer contract used by the other native
parsers. A focused direct regression is registered; compiled TIFF corpus,
sanitizer, and Sonic1 qualification remain open.

## ELF metadata-entry missing-map admission — 2026-08-25

The executable metadata-only entry `cli_elfheader()` previously assumed both a
non-null context and an available fmap even though the main ELF scanner had
already adopted explicit missing-map admission. It now rejects null caller
arguments and returns `CL_EPARSE` with the sticky `ELF input map is unavailable`
reason when recognized metadata input cannot be inspected. The focused direct
regression is registered; compiled ELF corpus, sanitizer, and Sonic1
qualification remain open.

## TNEF missing-map admission — 2026-08-25

The TNEF direct parser previously returned `CL_ENULLARG` for both a null
context and a non-null context whose recognized input fmap was unavailable.
The latter now returns `CL_EPARSE` after recording `TNEF input map is
unavailable`, preserving `CL_ENULLARG` only for a null caller context. The
focused direct regression passes; compiled TNEF corpus, sanitizer, and Sonic1
qualification remain open.

## BMP and JPEG 2000 missing-map admission — 2026-08-25

The bounded BMP and JPEG 2000 direct entries returned `CL_ENULLARG` for both a
null context and a non-null context whose recognized input fmap was missing.
Both now preserve `CL_ENULLARG` only for a null context and return `CL_EPARSE`
with parser-specific sticky incomplete reasons for unavailable recognized
input. The focused two-oracle direct regression passes; compiled graphics
corpus, sanitizer, and Sonic1 qualification remain open.

## MSPack temporary-output creation failure — 2026-08-22

CAB and CHM member staging reserve temporary space before creating the output
file. When the output directory became unusable after admission, the bridge
returned `CL_EMEM` without setting sticky incomplete state, leaving the
required member scan dependent on outer-layer behavior. Both CAB and CHM now
mark the layer incomplete with a parser-specific reason before returning the
allocation failure. The existing synthetic CAB fixture now exercises the
unusable-output-directory boundary and verifies the fmap is non-cacheable.

The source guards and non-clang regression gates pass. Compiled CHM coverage,
sanitizer runs, production CAB/CHM corpora, and Sonic1 qualification remain
open.

## BinHex temporary-output creation failure — 2026-08-22

BinHex opened its data and resource temporary files before decoding, but a
cli_gentempfd() failure returned directly without marking the required
encoded layer incomplete. Both temporary-output branches now set sticky
incomplete state before returning or cleaning up. The existing parser
temporary-directory regression now covers the data-output branch and verifies
that the input fmap is non-cacheable.

The source guards and non-clang regression gates pass. Compiled BinHex
coverage, sanitizer runs, production corpus, and Sonic1 qualification remain
open.

## HWP, HFS+, and OLE2 temporary-output failures — 2026-08-22

The HWP/HWPML, HFS+, and OLE2 helper layers had several direct temporary-file
allocation or open failures that returned to their callers without recording
a parser-specific incomplete reason. Those branches now mark the layer before
returning, while existing quota/deadline and cleanup ownership remains
unchanged.

The source guards and non-clang regression gates pass. Compiled fault
injection, sanitizer runs, production document/filesystem corpora, and Sonic1
qualification remain open.

## RTF, SWF, InstallShield, and AutoIt staging failures — 2026-08-22

Several parser helpers could return directly when a temporary directory,
temporary filename, or output file could not be allocated/opened. Those paths
now mark the scan incomplete before cleanup or return for RTF, SWF,
InstallShield, and AutoIt. Existing resource/deadline/write accounting is
unchanged.

The source guards and non-clang regression gates pass. Compiled fault
injection, sanitizer runs, production corpora, and Sonic1 qualification remain
open.

## Legacy PDF decoder allocation failures — 2026-08-22

The legacy PDF ASCII85, RunLength, Flate, ASCIIHex, and LZW filters could
return `CL_EMEM` after an output-buffer allocation, growth, final resize, or
decoder initialization failure without setting the scan's sticky incomplete
state. Each required decoder path now records a filter-specific incomplete
reason before returning or entering its cleanup path, so a skipped decoded
stream cannot be published as clean or cacheable while raw matching continues.

The source guards and non-clang regression gates remain the available local
evidence. Compiled allocation/decoder fault injection, sanitizer runs,
production PDF corpus, and Sonic1 qualification remain open.

## Direct clamd report oracle consistency — 2026-08-22

The direct `SCANREPORT`/`CONTSCANREPORT`/`MULTISCANREPORT`/`ALLMATCHSCANREPORT`,
`FILDESREPORT`, and `INSTREAMREPORT` probe previously parsed only the selected
oracle row. It now reuses the independent service verifier's strict parser,
so malformed four-role manifests and inconsistent detection signature/offset
bindings are rejected before a framed report is accepted. A synthetic
regression covers the malformed clean-signature/offset pairing. Compiled
wire-protocol, production-CVD, and Sonic1 qualification remain open.

## Clamd final report status reconciliation — 2026-08-22

`conn_reply_scan_report()` now applies the existing post-scan-failure contract
to a report before JSON serialization when the daemon supplies a later
non-success or detection status. This prevents a complete report from being
published as clean after a worker aggregation, descriptor-close, or transport
boundary failure. Detection-terminated and already-incomplete reports retain
their stronger outcome. Compiled daemon, production-CVD, and Sonic1
qualification remain open.

## AutoIt EA06 script-buffer allocation failure — 2026-08-22

The EA06 script decompiler's bounded output-buffer allocation failure now
marks the current layer incomplete before returning `CL_EMEM`. This preserves
the non-cacheable/fail-visible contract when the explicit 1 GiB random-access
boundary or an injected allocation fault prevents script inspection. Compiled
fault injection, parser corpus, sanitizer, and Sonic1 qualification remain
open.

## RTF parser allocation failures — 2026-08-22

RTF parser stack growth and embedded-object state/description allocations now
mark required inspection incomplete before returning `CL_EMEM`. This keeps
allocation faults non-cacheable and visible even when they occur before
temporary-object admission. Compiled allocation fault injection, parser
corpus, sanitizer, and Sonic1 qualification remain open.

## OLE2 extraction-path allocation failure — 2026-08-22

OLE2 property-tree directory extraction now marks the layer incomplete when a
per-directory temporary path cannot be allocated, before returning `CL_EMEM`.
This aligns path-name allocation with the existing `mkdir()` failure handling
and keeps required embedded-stream inspection non-cacheable. Compiled Office
fault injection, corpus, sanitizer, and Sonic1 qualification remain open.

## HWP metadata allocation failures — 2026-08-22

HWP3/HWP5 metadata objects, converted strings, information-block entries, and
summary-field recording now mark the layer incomplete with explicit reasons
before returning allocation or JSON-recording errors. This preserves the
fail-visible contract for metadata collection without changing raw or nested
content scanning behavior. Compiled HWP fault injection, corpus, sanitizer,
and Sonic1 qualification remain open.

## HFS+ compressed-resource read classification — 2026-08-23

HFS+ compressed-resource processing returned `CL_EREAD` when its temporary
resource header, resource map, resource-type table, resource entry, compressed
length, block count, or block table could not be read. Those failures were
reported only after the parser unwound, so the context lacked the specific
required-operation reason and could be reconciled as a generic HFS+ end state.
The required temporary-file reads now mark the scan incomplete immediately and
retain their operational status; malformed metadata and seek/format outcomes
remain unchanged. Compiled HFS+ corpus, sanitizer, and Sonic1 qualification
remain open.

## AutoIt EA06 bounded script input spool — 2026-08-23

EA06 script handling no longer allocates the complete decoded token stream as
one contiguous buffer. Compressed and stored script members now use the
existing temporary-storage admission and bounded writer, and the decompiler
reads opcodes, scalar values, and string chunks with small `pread` windows and
deadline checks. At this checkpoint its output buffer still started at 64 KiB
and grew as needed, leaving decompiled output above the 1 GiB
individual-allocation ceiling unsupported. Source guards cover the spool and
allocation invariants, and `tools/largefile_autoit_stored_fixture.py` now
generates a deterministic stored EA06 script member for runtime qualification;
the release runtime gate now executes that fixture and requires the parser's
token-decompilation debug marker while recording the generated fixture hash.
Compiled EA06 corpus, sanitizer, and Sonic1 qualification remain release
gates.

## Trust-layer status commit and cleanup — 2026-08-22

Trusting a layer now commits `CL_VERDICT_TRUSTED` only after the optional
metadata/evidence update succeeds. Multi-layer trust reasons use each target
layer's object ID, and missing, allocation, or metadata-update failures mark
the scan incomplete before the shared cleanup path runs. Compiled callback
fault injection and Sonic1 qualification remain open.

## Scan-level temporary-directory setup failures — 2026-08-22

`scan_common()` and recursive child-layer setup previously returned allocation
or `mkdir()` failures without setting the sticky incomplete state. They now
record parser-independent reasons for temporary-directory name allocation and
directory creation failures, and the top-level cleanup path only removes a
directory after successful creation. Public structured-report and direct
recursion-stack regressions verify non-clean, non-cacheable outcomes.

The source guards and non-clang regression gates pass. Compiled fault injection,
sanitizer runs, production corpora, and Sonic1 qualification remain open.

## RAR and bytecode handoff setup failures — 2026-08-22

RAR member extraction now records an incomplete result when its required
output-path allocation fails. Bytecode output-file allocation/open failures
and normalized-JavaScript temporary-directory allocation/creation failures
now use the same sticky fail-closed state, including contexts entered through
the bytecode API without a non-null scan context.

The source guards and non-clang regression gates pass. Compiled UnRAR and
interpreter/JIT fault injection, production corpora, and Sonic1 qualification
remain open.

## UDF and VBA project staging setup failures — 2026-08-22

UDF extracted-file materialization and VBA project temporary-output creation
could return a parser error without setting sticky incomplete state. Both
required staging paths now mark the layer incomplete before cleanup or return,
preserving the non-cacheable result contract.

The source guards and non-clang regression gates pass. Compiled allocation
fault injection, production Office/UDF corpora, and Sonic1 qualification
remain open.

## HFS+ and InstallShield setup allocation failures — 2026-08-22

HFS+ temporary-directory allocation/creation and InstallShield MSI member-name
and CAB output-buffer allocation failures now mark required parser work
incomplete before returning. This preserves the fail-closed contract even
when setup fails before temporary-file creation or quota admission.

The source guards and non-clang regression gates pass. Compiled allocation
fault injection, sanitizer runs, production corpora, and Sonic1 qualification
remain open.

## Legacy parser staging setup failures — 2026-08-22

The legacy parser entry points for HTML RFC2397, XDP, SIS, MSXML, OLE2, TAR,
script-encoded HTML, PDF, TNEF, UUEncode, and mail could return directly when
their required temporary state, directory, or output file could not be
allocated or created. Those paths now mark the layer incomplete before
returning, including the two direct MSXML callback/base64 staging branches.

The source guards and non-clang regression gates pass. Compiled fault
injection, sanitizer runs, production corpora, and Sonic1 qualification remain
open.

## Bytecode hook-context allocation failures — 2026-08-22

PDF, PE, ELF, Mach-O, and root-metadata preclass bytecode entry points now
mark their scan context incomplete when the required hook context cannot be
allocated. The error remains `CL_EMEM`, cleanup ownership is unchanged, and a
failed hook cannot be mistaken for a clean parser result while raw matching or
other independent work continues.

The source guards and non-clang regression gates remain the available local
evidence. Compiled hook fault injection, interpreter/JIT qualification,
production executable corpora, sanitizer runs, and Sonic1 qualification
remain open.

## NSIS required-path failures — 2026-08-22

NSIS member extraction now marks the current layer incomplete when decoder
initialization fails, either compressed or solid temporary output cannot be
created, a confirmed header cannot be read, or an extracted member cannot be
rewound before its nested scan. Candidate-admission coordinate rejection is
still kept separate from confirmed-layer failure classification.

The source guards and non-clang regression gates remain the available local
evidence. Compiled NSIS decoder fault injection, malformed and valid
production corpus coverage, sanitizer runs, and Sonic1 qualification remain
open.

## UUEncode required materialization failures — 2026-08-22

Standalone UUEncode scanning now marks the scan incomplete when message state
or the decoded output blob cannot be allocated, when decoded attachment data
cannot be materialized, or when a confirmed attachment is unterminated or
invalid. The direct parser now carries the same sticky state that the scanner
wrapper already used for embedded UUEncode failures.

The source guards and non-clang regression gates remain the available local
evidence. Compiled allocation fault injection, long and malformed attachment
corpora, sanitizer runs, and Sonic1 qualification remain open.

## TNEF attachment materialization failures — 2026-08-22

TNEF attachment-title allocation, attachment output-blob creation, and
attachment-data materialization failures now mark the current layer
incomplete before returning their operational status. Existing read, format,
deadline, and cleanup behavior is unchanged, but a required attachment can no
longer fail through an unmarked `CL_EMEM` or `CL_ERESOURCE` path.

The source guards and non-clang regression gates remain the available local
evidence. Compiled allocation fault injection, malformed attachment corpus,
sanitizer runs, and Sonic1 qualification remain open.

## Sonic1 qualification connectivity recheck — 2026-08-22

The administrator-provided `sonic1` host and `sonic1-camera-key` profile were
accepted by MCP-SSH policy and resolved to `192.168.1.216:4456`; the declared
login is `camera` with key authentication and sudo capability. The 20-second
connection check passed policy and address resolution but timed out during TCP
connect with `remote_started: false` and a retryable transport result. No
compiled or test result from Sonic1 is attributed to this worktree.

## Mach-O section-table allocation failures — 2026-08-22

After confirmed load-command parsing, Mach-O section-table and native-width
section-table growth could return `CL_EMEM` without marking a normal scan
incomplete. Both allocation paths now record a parser-specific incomplete
reason before cleanup; the metadata-only wrapper continues to reconcile its
own returned error as before.

The source guards and non-clang regression gates remain the available local
evidence. Compiled allocation fault injection, malformed Mach-O corpus,
sanitizer runs, and Sonic1 qualification remain open.

## Partition-intersection tracking allocation failures — 2026-08-22

APM, primary/extended MBR, and GPT intersection walks now mark the current
partition layer incomplete when their required tracking-node allocation
returns `CL_EMEM`. The helper still owns list cleanup and the parser-specific
error remains the returned status, but a required intersection walk can no
longer be mistaken for a completed clean layer.

The source guards and non-clang regression gates remain the available local
evidence. Compiled allocation fault injection, malformed and valid partition
image corpora, sanitizer runs, and Sonic1 qualification remain open.

## HTML phishing allocation failures — 2026-08-22

The HTML phishing path previously discarded URL-normalization allocation
errors, allowed host-construction failures to propagate as negative internal
phishing enum values, ignored hash-state allocation failures inside the URL
hash loop, and treated temporary URL-copy allocation failures as clean. Those
paths now mark the scan incomplete and return a neutral per-URL result so the
failure cannot be reclassified as a phishing heuristic alert; hash lookup
errors are now propagated to the scan-context boundary.

The source guards and non-clang regression gates remain the available local
evidence. Compiled allocation fault injection, production HTML/mail corpora,
sanitizer runs, and Sonic1 qualification remain open.

## ELF scan working-buffer allocation failures — 2026-08-22

ELF program-header and section-header working buffers used by the active scan
path could return `CL_EMEM` without marking required executable inspection
incomplete. Both 32-bit and 64-bit scan paths now record parser-specific
incomplete reasons before returning. Metadata-only `elfinfo` allocations are
left to the existing metadata wrapper, which has no scan context and already
reconciles its returned status.

The source guards and non-clang regression gates remain the available local
evidence. Compiled allocation fault injection, production ELF corpora,
sanitizer runs, and Sonic1 qualification remain open.

## AC embedded-type tracking allocation failures — 2026-08-22

The AC raw matcher can retain matched embedded file-type offsets for later
parser dispatch. Its tracking-node allocation accepted a scan context but
returned `CL_EMEM` without marking the scan incomplete. The active matcher
path now records an incomplete reason before returning, so a required type
dispatch failure cannot be reported or cached as complete.

The source guards and non-clang regression gates remain the available local
evidence. Compiled matcher allocation fault injection, production signature
qualification, sanitizer runs, and Sonic1 qualification remain open.

## HFS+ scan working-buffer allocation failures — 2026-08-22

HFS+ volume-header allocation and catalog-node working-buffer allocation could
return `CL_EMEM` without marking the required partition-layer inspection
incomplete. Both active scan paths now record parser-specific incomplete
reasons before returning; the existing metadata, read, deadline, and
temporary-output paths remain unchanged.

The source guards and non-clang regression gates remain the available local
evidence. Compiled allocation fault injection, production HFS+ corpora,
sanitizer runs, and Sonic1 qualification remain open.

## ARJ decoder-buffer allocation failures — 2026-08-22

Both ARJ compressed decoder paths could return `CL_EMEM` before allocating
their fixed decoder buffer without marking the containing archive layer
incomplete. The paths now record a shared decoder-buffer failure reason before
returning; extraction, deadline, callback-read, and output accounting are
unchanged.

The source guards and non-clang regression gates remain the available local
evidence. Compiled decoder allocation fault injection, production ARJ corpora,
sanitizer runs, and Sonic1 qualification remain open.

## MIME partial-message allocation failures — 2026-08-22

The `message/partial` path could return after failing to allocate its
identifier, disk-backed spool, or final reassembly output without marking the
mail layer incomplete. The mbox and message helpers now record those required
allocation/materialization failures before cleanup or return; regular MIME
body-spool and deadline behavior is unchanged.

The source guards and non-clang regression gates remain the available local
evidence. Fault-injected partial-message coverage, production mail corpora,
sanitizer runs, and Sonic1 qualification remain open.

## Logical matcher result-allocation failures — 2026-08-22

The native logical-signature path could return `CL_EMEM` after failing to grow
partial-signature offset tables, logical match-offset lists, or AC/PCRE raw
result lists without recording the required matcher operation as incomplete.
The context-aware matcher boundaries now mark those failures before returning;
logical-signature macro evaluation passes the same scan context, and failed
offset-list `realloc` preserves the original allocation for cleanup.

The source guards and non-clang regression gates remain the available local
evidence. Compiled list-growth fault injection, production-signature
qualification, sanitizer runs, and Sonic1 qualification remain open.

## Structured report JSON node allocation failures — 2026-08-22

Structured report serialization already checked 64-bit metric-node creation,
but status, verdict, completion, target, file-type, reason, and alert string
nodes were passed directly to json-c without checking allocation results. The
report boundary now checks every integer and string node and returns `CL_EMEM`
after releasing the partial object, so a failed serializer cannot publish a
partial success report.

The source guards and non-clang regression gates remain the available local
evidence. Compiled json-c allocation fault injection, shared/static JSON-C
qualification, sanitizer runs, and Sonic1 qualification remain open.

## Structured report metadata allocation failures — 2026-08-22

Report `strdup` failures for target, file type, reason, or last alert could
silently replace required metadata with `NULL`. The report now retains the
existing value when replacement allocation fails, carries a sticky failure
flag through directory aggregation, converts finalized non-detection reports
to `CL_EMEM`/`RESOURCE_FAILURE`, and rejects JSON serialization before a
partial report can be published. Detections remain authoritative while their
legacy result path unwinds.

The source guards and non-clang regression gates remain the available local
evidence. Fault-injected metadata and merge coverage, sanitizer runs, shared
and static JSON-C qualification, and Sonic1 qualification remain open.

## PCRE limit and match-workspace failures — 2026-08-22

PCRE match-data allocation failures previously returned `CL_EMEM` without
marking the scan, while match-limit and recursion-limit exhaustion was logged
and treated as an ordinary non-match. The PCRE boundary now records workspace
allocation/initialization failures as incomplete and maps match/backtracking
limit exhaustion to `CL_ERESOURCE` with a sticky incomplete reason.

The source guards and non-clang regression gates remain the available local
evidence. Compiled PCRE limit-exhaustion and allocation-fault coverage,
production regex qualification, sanitizer runs, and Sonic1 qualification remain
open.

## BM and PCRE offset-table allocation failures — 2026-08-22

Per-scan BM and PCRE relative-offset tables previously used direct allocation;
PCRE had a scan context but did not mark its allocation failure, and BM setup
merged `CL_EMEM` without a parser-specific sticky reason. Both tables now use
the individual-allocation ceiling, and the context-bearing setup boundaries
mark failures before matcher execution can be treated as complete.

The source guards and non-clang regression gates remain the available local
evidence. Compiled offset-setup fault injection, production-signature
qualification, sanitizer runs, and Sonic1 qualification remain open.

## AC matcher-state allocation ceiling — 2026-08-22

Per-scan AC state, partial-signature offset tables, logical match-offset lists,
and AC/PCRE result lists now use the shared individual-allocation ceiling
instead of unbounded direct allocation calls. Context-bearing raw matcher and
file-type setup boundaries mark those allocation failures as incomplete before
returning, so a later raw or parser pass cannot turn skipped matcher state into
a clean result.

The source guards and non-clang regression gates remain the available local
evidence. Fault-injected matcher-root/file-type setup coverage, production
signature qualification, sanitizer runs, and Sonic1 qualification remain open.

## Milter final-action allocation failures — 2026-08-22

Milter end-of-message handling declared the structured infected reply without
initializing it, so an allocation failure could reach the null check through
an indeterminate pointer. The reply is now initialized and therefore returns
the configured failure action instead of undefined behavior. VirusAction event
argument copies are checked as a group; a failure skips only that optional
event while preserving the mandatory infected action, and failure to allocate a
configured startup VirusAction now aborts milter initialization.

The source guards and non-clang regression gates remain the available local
evidence. Compiled milter allocation fault injection, one-request service
qualification, sanitizer runs, and Sonic1 qualification remain open.

## Logical and bundled-YARA status fall-throughs — 2026-08-22

The logical-signature dispatcher treated an unrecognized signature type as a
successful no-op, which could make required logical work appear complete. It
now records an incomplete/non-cacheable result. The bundled YARA status bridge
also now preserves direct `CL_EMEM` and `CL_ERESOURCE` results instead of
collapsing them into generic parse errors; the existing failure mapping still
marks the scan incomplete and prevents cache publication.

The source guards and non-clang regression gates remain the available local
evidence. A focused `test_logical_unknown_type_is_fail_visible` regression is
registered; bundled-resource-status tests, full logical/YARA qualification,
sanitizer runs, and Sonic1 qualification remain open.

## Bytecode loader table-growth boundaries — 2026-08-22

Bytecode debug-node growth used an unbounded `realloc`, assigned its result
directly, and advanced the node count before newly added cleanup state had
been initialized. Large or malformed metadata could therefore lose the old
allocation, wrap the table size, or make destruction inspect uninitialized
nodes. The loader now checks the decoded count and native-size multiplication,
uses the individual-allocation ceiling with a temporary pointer, zeroes the
new node range, and commits the count only after successful growth. Per-function
constant growth likewise uses the bounded realloc helper and rejects counter
overflow.

The source guards and non-clang regression gates remain the available local
evidence. Compiled malformed-loader and allocation-fault coverage,
interpreter/JIT qualification, sanitizer runs, and Sonic1 qualification
remain open.

## INSTREAM client partial-stream fail-closed boundary — 2026-08-22

The clamd client stream helper had already routed current callers through its
strict limit mode, but retained a dormant boolean that could allow a future
caller to clamp a chunk to the remaining quota and send a normal terminator.
That escape hatch is removed. Every INSTREAM-family submission now rejects
over-limit bytes, treats both ordinary read errors and the exact-limit EOF
probe as hard failures, and sends the protocol terminator only after a complete
input is established. Static guards cover the strict call shape and the
absence of truncation assignment. Compiled read-fault and daemon-side
partial-request qualification remain release gates.

## Bytecode VM pointer-registration allocation failures — 2026-08-22

The interpreter's stack and global pointer-registration tables used unbounded
`realloc` and ignored a failed registration at several call sites. A failed
growth could therefore return a zero pointer identifier and let execution
continue with an invalid pointer map. The tables now use bounded, checked
growth, record allocation failure, and stop the VM with `CL_EMEM` before a
failed result is written or consumed. Early failure cleanup also has
initialized timing state for debug logging.

The source guards and non-clang regression gates remain the available local
evidence. Compiled interpreter fault injection, interpreter/JIT qualification,
sanitizer runs, and Sonic1 qualification remain open.

## Bytecode API resource-table count arithmetic — 2026-08-22

Bytecode API hashset, buffer-pipe, inflate, LZMA, BZip2, JavaScript-normalizer,
and map creation paths formed resource-table sizes with unchecked `count + 1`
and multiplication. The underlying allocator was bounded, but a wrapped count
could bypass the intended table boundary. A shared helper now rejects counter
and native-size overflow before each table growth and reports the failure to
the bytecode event stream; valid allocations continue through the bounded
allocator.

The source guards and non-clang regression gates remain the available local
evidence. Compiled API counter-overflow and allocation-fault coverage,
interpreter/JIT qualification, sanitizer runs, and Sonic1 qualification
remain open.

## Legacy FILDES client hard-ceiling preflight — 2026-08-22

The public `send_fdpass*` wrappers previously bypassed the client-side size
preflight, so a known regular file larger than the fork's 32-GiB ceiling could
be handed to clamd before the daemon rechecked it. The wrappers now share the
checked helper and use the hard ceiling when no daemon option structure is
available. Unknown/non-regular descriptors retain their historical handoff so
the daemon can report the protocol error. A sparse exact-32-GiB and
32-GiB-plus-one regression covers the boundary; compiled FILDES and Sonic1
qualification remain open.

## MIME retained-node accounting — 2026-08-22

The legacy MIME line-list admission counter previously charged only retained
line payload bytes. It now also charges the linked-list node and the ref-count
byte prepended to allocated lines, preventing a large population of short
retained lines from exceeding the intended bounded representation. A
deduplicated blank separator is checked before reservation so discarded input
does not consume the quota. Static source guards and non-clang regression
gates remain available; compiled allocation-fault, sanitizer, production-mail,
and Sonic1 qualification remain open.

## On-access FILDES hard-ceiling preflight — 2026-08-22

The on-access descriptor-passing helper previously sent `FILDESREPORT`
without independently checking the opened regular file against the 32-GiB
ceiling. It now clamps direct-context limits to the hard boundary, checks the
descriptor with `fstat`, and rejects an over-limit regular file before any
protocol bytes are sent, preserving `CL_EMAXSIZE` or `CL_ESTAT`. The normal
scan-thread preflight remains in place; compiled on-access fault-injection,
sanitizer, and Sonic1 qualification remain open.

## On-access stream rewind failure — 2026-08-22

The regular-file on-access stream path ignored a failed rewind and could send
the daemon bytes from a stale descriptor position. It now checks `lseek` before
emitting `INSTREAMREPORT`, returns `CL_ESEEK`, and sends no command when the
input cannot be rewound; non-seekable non-regular streams retain their prior
behavior. Compiled read/seek fault injection, sanitizer, and Sonic1
qualification remain open.

## On-access configured-limit parity — 2026-08-22

The on-access client now combines the daemon `StreamMaxLength` limit with the
local `OnAccessMaxFileSize` limit before opening an action source, submitting a
path command, streaming bytes, or passing a descriptor. Direct callers no
longer rely on the scan-thread preflight alone, and zero or out-of-range
programmatic values normalize to the certified 32-GiB ceiling. The existing
protocol checks remain as a second boundary. Compiled on-access fault
injection, option-parity, and Sonic1 qualification remain open.

## ELF fixed-range truncation classification — 2026-08-22

ELF fixed-size header, program-header, and section-header reads now
preflight the complete requested range before invoking the fmap callback. A
structure whose remaining bytes are beyond EOF therefore stays a parse/
incomplete result even if the callback would fail while serving its in-range
prefix; a fully in-range callback failure remains `CL_EREAD`. The new
regression uses a truncated program header with an injected prefix failure to
prove that the two outcomes remain distinct. Compiled scanner, sanitizer,
production ELF-corpus, and Sonic1 qualification remain open.

## Fixed-range parser truncation classification — 2026-08-22

Mach-O load-command, TIFF IFD, and TNEF attribute-header helpers now
preflight the full fixed-size request before invoking the fmap callback. A
required structure that extends past EOF therefore remains a parse/incomplete
result even when its available prefix would otherwise trigger an injected
callback failure; fully in-range callback failures remain `CL_EREAD`. Focused
regressions cover all three parser families. Compiled scanner, sanitizer,
production-corpus, and Sonic1 qualification remain open.

## GIF/PNG fixed-range truncation classification — 2026-08-22

GIF fixed fields and PNG chunk-length/type/CRC fields now use bounded
fixed-range readers before invoking fmap callbacks. A truncated field stays a
parse/incomplete result even if its available prefix would otherwise trigger a
callback failure; fully in-range callback failures remain `CL_EREAD`. Focused
GIF screen-descriptor and PNG chunk-header regressions cover the boundary.
Compiled scanner, sanitizer, production media-corpus, and Sonic1 qualification
remain open.

## JPEG fixed-range truncation classification — 2026-08-22

JPEG required header, marker, segment-size, Photoshop-marker, and Photoshop
resource-size reads now preflight the complete requested range before invoking
the fmap callback. A truncated segment therefore remains a parse/incomplete
result even when an injected callback would fail on its available prefix;
fully in-range callback failures remain `CL_EREAD`. A focused segment-size
regression covers the boundary. Compiled scanner, sanitizer, production
media-corpus, and Sonic1 qualification remain open.

## BMP/JP2/APM fixed-range truncation classification — 2026-08-22

BMP and JPEG 2000 fixed-header readers and APM partition-map reads now
preflight the complete requested range before invoking fmap callbacks. A
truncated structure therefore remains a parse/format incomplete result even
when a callback would fail on its available prefix; fully in-range callback
failures remain `CL_EREAD`. Focused BMP, JP2, and APM regressions cover the
boundary. Compiled scanner, sanitizer, production media-corpus, and Sonic1
qualification remain open.

## HWP3 fixed-section truncation classification — 2026-08-22

HWP3 document-info and metadata-enabled document-summary reads now preflight
their complete fixed ranges before invoking fmap callbacks. A truncated
section therefore remains a parse/incomplete result even when an injected
callback would fail on its available prefix; a fully in-range callback failure
remains `CL_EREAD`. A focused document-info regression covers the boundary.
Compiled scanner, sanitizer, production document-corpus, and Sonic1
qualification remain open.

## SIS fixed-header truncation classification — 2026-08-22

SIS fixed 16-byte UID headers now preflight the complete range before invoking
the fmap callback. A truncated package therefore remains a parse/incomplete
result even when an injected callback would fail on its available prefix;
fully in-range header callback failures remain `CL_EREAD`. A focused direct
parser regression covers the boundary. Compiled scanner, sanitizer, SIS
corpus, and Sonic1 qualification remain open.

## XAR fixed-header read classification — 2026-08-22

XAR fixed-header reads now preflight the complete range before invoking the
fmap callback. A header shorter than the input remains a parse/incomplete
result, while a fully in-range callback failure remains `CL_EREAD`. A focused
header callback regression covers the operational-read boundary. Compiled
scanner, sanitizer, production XAR corpus, and Sonic1 qualification remain
open.

## ARJ signature truncation classification — 2026-08-22

ARJ signature admission now preflights its complete two-byte range before
invoking the fmap callback. A one-byte candidate therefore remains a
parse/incomplete result even when an injected callback would fail on its
available prefix; a fully in-range signature callback failure remains
`CL_EREAD`. A focused header-check regression covers the boundary. Compiled
scanner, sanitizer, production ARJ corpus, and Sonic1 qualification remain
open.

## HWP3 content-table truncation classification — 2026-08-22

HWP3 content-stream font and style table count reads now preflight their
complete two-byte ranges before invoking the fmap callback. A one-byte table
prefix remains a parse/incomplete result even when an injected callback would
fail on that prefix; a fully in-range callback failure remains `CL_EREAD`.
A focused font-table regression covers the boundary. Compiled scanner,
sanitizer, production HWP3 corpus, and Sonic1 qualification remain open.

## HWP3 paragraph-payload fixed-read classification — 2026-08-22

HWP3 paragraph content units, variable special-character length fields, and
box/drawing header fields now preflight their fixed ranges before invoking the
fmap callback. A short content or special-record prefix remains a
parse/incomplete result even when an injected callback would fail on its
available prefix; a fully in-range callback failure remains `CL_EREAD`. A
focused paragraph-content regression covers the boundary. Compiled scanner,
sanitizer, production HWP3 corpus, and Sonic1 qualification remain open.

## HWP3 paragraph-header truncation classification — 2026-08-22

HWP3 paragraph metadata reads for the prior-style, character-count,
line-count, and font-style flags now preflight their fixed ranges before
invoking the fmap callback. A short character-count prefix remains a
parse/incomplete result even when an injected callback would fail on that
prefix; fully in-range callback failures remain `CL_EREAD`. A focused
paragraph-header regression covers the boundary. Compiled scanner, sanitizer,
production HWP3 corpus, and Sonic1 qualification remain open.

## HWP3 information-block header truncation classification — 2026-08-22

HWP3 information-block ID and length reads now preflight their complete
four-byte ranges before invoking the fmap callback. A short information-block
header remains a parse/incomplete result even when an injected callback would
fail on its available prefix; a fully in-range callback failure remains
`CL_EREAD`. Focused regressions cover both outcomes. Compiled scanner,
sanitizer, production HWP3 corpus, and Sonic1 qualification remain open.

## Shared fixed-range reader and PE fixed-metadata classification — 2026-08-22

The fmap layer now exposes `fmap_readn_full()`, which refuses to shorten a
request that extends beyond the map while preserving `(size_t)-1` for a
fully in-range backing-read failure. HWP3 fixed reads and PE DOS/NT,
optional-header, data-directory, section-header, certificate-header, import
descriptor, and 32/64-bit thunk reads use the shared helper. Intentionally
partial entry-point and unpacker reads remain streaming operations. The
focused fmap regression proves that a short range and an in-range callback
failure remain distinguishable. Compiled scanner, sanitizer, production PE
corpus, and Sonic1 qualification remain open.

## SIS fixed metadata range classification — 2026-08-22

SIS UID, main metadata, name-table, and dependency-header reads now preflight
their complete requested ranges before invoking the fmap callback. Genuinely
short ranges therefore remain parse/incomplete results, while fully in-range
callback failures remain `CL_EREAD`. Focused regressions cover truncated main
headers and in-range main-header callback failure. Compiled scanner, sanitizer,
production SIS corpus, and Sonic1 qualification remain open.

## HWPOLE2 fixed-prefix range classification — 2026-08-22

HWPOLE2 now preflights its fixed 32-bit uncompressed-size prefix and reports a
genuinely short header as `CL_EPARSE`, while an in-range fmap callback failure
remains `CL_EREAD`. Focused regressions cover both outcomes. Its native
32-bit payload-size representation remains an explicit boundary for larger
inputs; compiled scanner, sanitizer, production HWP corpus, and Sonic1
qualification remain open.

## TNEF attachment-range admission — 2026-08-22

TNEF now validates each declared attachment payload range before creating or
filling an output blob. A payload extending past the fmap is therefore a
malformed/incomplete parse rather than an operational read failure; a fully
in-range fmap callback failure remains `CL_EREAD`. Focused regressions cover
both outcomes. Compiled scanner, sanitizer, production TNEF corpus, and
Sonic1 qualification remain open.

## UUEncode mid-attachment read classification — 2026-08-22

UUEncode now distinguishes a fmap line-read failure after the `begin` line
from a genuinely unterminated or invalid attachment across both standalone
and embedded-mail call paths. The former remains `CL_EREAD` and non-cacheable;
the latter remains a parse/incomplete result. Focused callback regressions
cover standalone and embedded-mail mid-attachment failures. Compiled scanner,
sanitizer, production UUEncode corpus, and Sonic1 qualification remain open.

## OLE2/MSO fixed-prefix read classification — 2026-08-23

The MSO stream inflater now preflights its fixed four-byte uncompressed-size
prefix with `fmap_readn_full()`. A genuinely short prefix is reported as
`CL_EPARSE` with an incomplete result, while a fully in-range fmap callback
failure remains `CL_EREAD`. Streaming MSO callback failures also preserve
`CL_EREAD` and mark the layer incomplete instead of being relabeled as
`CL_EUNPACK`. Focused regressions cover the prefix range classes. Compiled
scanner, sanitizer, production OLE2/MSO corpus, and Sonic1 qualification
remain open.

## ARJ fixed-header read classification — 2026-08-23

ARJ main and member fixed-header reads now preflight their complete ranges
before invoking the fmap callback. A genuinely short header remains a format
or parse failure, while a fully in-range callback failure remains `CL_EREAD`
with an explicit incomplete reason. Focused main-header callback coverage
guards the boundary. Compiled scanner, sanitizer, production ARJ corpus, and
Sonic1 qualification remain open.

## PE icon bitmap-header read classification — 2026-08-23

The PE icon parser now preflights the complete bitmap header before invoking
the fmap callback. A genuinely short header remains a parse/incomplete result,
while a fully in-range callback failure remains `CL_EREAD` with an explicit
incomplete reason. Focused injected-read coverage guards the boundary.
Compiled scanner, sanitizer, PE corpus, and Sonic1 qualification remain open.

## EGG fixed-index-header read classification — 2026-08-23

EGG archive and file/block fixed headers, together with their EOF marker
reads, now preflight the requested ranges. Short metadata remains a parse/
incomplete result, while a fully in-range fmap callback failure remains
`CL_EREAD` with an explicit incomplete reason. Focused archive-header
regressions cover both outcomes. Compiled scanner, sanitizer, production EGG
corpus, and Sonic1 qualification remain open.

## EGG extra-field and compressed-range read classification — 2026-08-23

EGG archive/file extra-field headers, size fields, declared payloads, and
legacy whole-block extraction now preflight their ranges. Streaming block reads
also distinguish a short compressed stream from an in-range fmap callback
failure. Short ranges remain parse/incomplete results; callback failures remain
`CL_EREAD` with explicit incomplete reasons. Focused archive-comment regressions
cover header and payload callback failures plus truncation. Compiled scanner,
sanitizer, production EGG corpus, and Sonic1 qualification remain open.

## OLE2 sector-range read classification — 2026-08-23

The OLE2 CFB sector reader no longer zero-pads a map-short sector and returns
success. It records the first sector-range outcome, marks the owning scan
incomplete immediately, and preserves `CL_EPARSE` for a genuinely truncated
sector versus `CL_EREAD` for a fully in-range fmap callback failure. The
top-level extractor reconciles an ignored sector-walk failure before returning
clean. A fixture-backed regression covers both classes. Compiled scanner,
sanitizer, production OLE2 corpus, and Sonic1 qualification remain open.

## XAR compressed-member range read classification — 2026-08-23

XAR gzip and LZMA member input windows now pass through a checked range helper.
The helper preserves `CL_EPARSE` for a short range and `CL_EREAD` for a fully
in-range fmap callback failure, while the decoder path marks the compressed
member incomplete before temporary cleanup. A synthetic gzip-member callback
regression covers the in-range failure path. Compiled scanner, sanitizer,
production XAR corpus, and Sonic1 qualification remain open.

## OLE2 encryption-window read classification — 2026-08-23

The bounded native-width OLE2 encryption probe now uses an explicit checked
range helper. A fully in-range fmap callback failure remains `CL_EREAD`, marks
the layer incomplete, and prevents caching; an unavailable probe range remains
a parse/truncation result. The compiled fault-injection regression now asserts
the callback-failure status and reason. Compiled scanner, sanitizer, encrypted
Office corpus, and Sonic1 qualification remain open.

## UDF descriptor status reset — 2026-08-23

The UDF descriptor fmap helper now preflights every requested range, resets the
caller-visible status before each attempt, reports `CL_SUCCESS` for a successful
read, preserves `CL_EPARSE` for a short/out-of-map range, and reports `CL_EREAD`
only for an in-range backing-read failure. This prevents stale status from
changing a later descriptor result. Compiled scanner, sanitizer, UDF corpus,
and Sonic1 qualification remain open.

## TIFF unknown-field rejection — 2026-08-23

TIFF IFD entries with an unknown field type are now explicit incomplete parse
results instead of silently becoming zero-width values and allowing a clean
parser return. The parser also rejects a missing input fmap before dereferencing
it. A malformed-IFD regression covers the unsupported-type path. Compiled
scanner, sanitizer, production TIFF corpus, and Sonic1 qualification remain
open.

## RIFF range-status reset — 2026-08-23

The RIFF exploit detector now rejects a missing fmap before dereference and its
bounded range helper resets status for every request, preserving `CL_EPARSE`
for unavailable ranges and `CL_EREAD` only for in-range callback failures. A
direct missing-map regression covers the public detector boundary. Compiled
scanner, sanitizer, production RIFF corpus, and Sonic1 qualification remain
open.

## RTF implicit embedded-object close status — 2026-08-23

RTF now propagates a non-clean status returned while an embedded-object
callback is implicitly closed by a subsequent recognized control word. The
callback state is cleared before the cleanup macro runs, preventing a lost
detection or extraction failure and avoiding a second close attempt. Compiled
scanner, sanitizer, production RTF corpus, and Sonic1 qualification remain
open.

## HWP3 character-style read classification — 2026-08-23

The HWP3 paragraph character-style byte now uses the checked fixed-range read
helper. A fully in-range fmap callback failure is marked incomplete and
returned as `CL_EREAD` with an explicit reason instead of bypassing sticky
state; the focused callback regression also verifies that the map cannot be
cached. Compiled scanner, sanitizer, production HWP3 corpus, and Sonic1
qualification remain open.

## PE icon nested-window read classification — 2026-08-23

PE icon group headers, icon data pointers, palettes, and pixel windows now
preflight their requested ranges before invoking fmap callbacks. A genuinely
short range remains a parse/incomplete result, while a fully in-range callback
failure remains `CL_EREAD` with an explicit incomplete reason. Pixel-window
size multiplication is checked before the range request, and the intentionally
tolerated broken 32-bit icon-mask fallback remains unchanged. A focused
resource-tree regression covers callback failure at the group-header boundary.
Compiled scanner, sanitizer, production PE/icon corpus, and Sonic1
qualification remain open.

## JPEG application-marker probe classification — 2026-08-23

JPEG APP0, APP1, APP2, APP8, and APP14 metadata probes now use a segment-bounded
reader. A genuinely short optional payload remains an ordinary non-match, but
an in-range fmap callback failure is returned as `CL_EREAD`, marked incomplete,
and made non-cacheable instead of being silently treated as unfamiliar
metadata. The focused APP0 regression covers the callback-failure boundary.
Compiled scanner, sanitizer, production JPEG corpus, and Sonic1 qualification
remain open.

## MSEXPAND fixed-header range classification — 2026-08-23

MSEXPAND now preflights its packed fixed header before invoking the fmap
callback. A genuinely short SZDD header remains `CL_EPARSE`, while a fully
in-range callback failure remains `CL_EREAD` with an explicit incomplete
reason. Focused direct-parser coverage asserts both classes and the
non-cacheable state. Compiled scanner, sanitizer, production SZDD corpus, and
Sonic1 qualification remain open.

## NSIS fixed-header range classification — 2026-08-23

The NSIS decoder now preflights its 0x1c-byte archive header before invoking
the fmap callback. A genuinely truncated header remains `CL_EPARSE`, while a
fully in-range callback failure remains `CL_EREAD` with an explicit incomplete
reason. Focused `cli_scannulsft` coverage asserts both classes and the
non-cacheable state. Compiled scanner, sanitizer, production NSIS corpus, and
Sonic1 qualification remain open.

## NSIS direct-entry map admission — 2026-08-25

The NSIS header-admission and decoder entry points treated a recognized layer
with no input fmap as the same `CL_ENULLARG` result as a null context, without
recording incomplete state. They now retain `CL_ENULLARG` for null contexts and
return `CL_EPARSE` with explicit sticky reasons for missing maps. The isolated
production-linked `nulsft_map` regression covers both entry points. Compiled
NSIS corpus, sanitizer, and Sonic1 qualification remain release gates.

## InstallShield MSI fixed-header range classification — 2026-08-23

The direct InstallShield MSI scanner now preflights its 0x20-byte control
header before dereferencing it. A genuinely short header remains `CL_EPARSE`,
while a fully in-range fmap callback failure remains `CL_EREAD` with an
explicit incomplete reason. Existing MSI fault-injection coverage now asserts
both outcomes and non-cacheability. Compiled scanner, sanitizer, production
InstallShield corpus, and Sonic1 qualification remain open.

## ZIP64 extra-field read classification — 2026-08-23

ZIP local and central ZIP64 extra-field windows now distinguish a genuinely
short or malformed extra (`CL_EPARSE`/`CL_EFORMAT`) from a fully in-range fmap
callback failure (`CL_EREAD`). Both local-only extraction and central-directory
catalogue paths mark the layer incomplete and non-cacheable on callback failure;
focused fault-injection coverage exercises both windows. Compiled scanner,
sanitizer, production ZIP corpus, and Sonic1 qualification remain open.

## GIF/PNG missing-map handling — 2026-08-23

The GIF and PNG direct parser entry points now reject a missing input fmap as an
explicit incomplete parse result instead of dereferencing a null map. Focused
direct-parser coverage asserts the fail-visible reasons for both families.
Compiled media corpus, sanitizer, and Sonic1 qualification remain open.

## HFS+ catalog-node range classification — 2026-08-23

HFS+ catalog-node fetches now preflight each block against the containing fmap.
A genuinely short node remains an explicit format/incomplete result, while a
fully in-range callback failure remains `CL_EREAD`. The existing callback
regression now also exercises a one-byte-short catalog leaf. Compiled HFS+
corpus, sanitizer, and Sonic1 qualification remain open.

## Legacy bytecode read-coordinate admission — 2026-08-23

The v1 bytecode `read` entry now rejects negative offsets and host-
unrepresentable or size-overflowing ranges before converting the coordinate to
the fmap API. A focused regression covers invalid signed state, while
independently compiled v1/v2 fixtures and interpreter/JIT qualification remain
open.

## TNEF missing-map handling — 2026-08-23

The TNEF parser now rejects a missing input fmap before its time-limit and
header logic dereferences the map, returning `CL_ENULLARG` with an explicit
incomplete reason for a non-null context. Focused direct-parser coverage covers
the boundary; compiled mail corpus, sanitizer, and Sonic1 qualification remain
open.

## ISO9660 Joliet name-expansion admission — 2026-08-23

ISO9660 now treats failed Joliet UTF-16BE-to-UTF-8 conversion and output-name
expansion beyond its fixed destination buffer as incomplete instead of silently
scanning under an empty or truncated name. A focused Joliet fixture exercises
the expansion boundary and preserves the non-cacheable `CL_EPARSE` result.
Compiled ISO corpus, sanitizer, and Sonic1 qualification remain open.

## Rust fmap in-range read-failure classification — 2026-08-23

The Rust `FMapReader` previously converted a null `need()` callback result into
`UnexpectedEof`, even after clipping the request to a fully in-range fmap
window. The adapter now carries a typed `ReadFailure` marker for that
operational condition, while true end-of-input remains a zero-length read.
Scanner-facing Rust status mapping preserves the failure as `CL_EREAD`, and
focused Rust coverage exercises both the direct `need_off()` and reader paths.
The LHA/LZH decoder's construction, member-read, and next-header error
boundaries now convert the dependency's wrapped I/O error so this distinction
survives the parser boundary as well. Compiled Rust/layout, parser-corpus,
sanitizer, and Sonic1 qualification remain open.

## Shared fmap string-read failure classification — 2026-08-23

`fmap_need_offstr()` collapsed a missing terminator, an out-of-range string,
and an in-range backing callback failure into NULL. The ARJ filename/comment
paths and legacy InstallShield embedded metadata therefore could turn an
operational read failure into an ordinary malformed result; InstallShield also
searched beyond its selected subrange. A new bounded unlocked-window helper
returns `CL_EREAD` for callback failure and `CL_EPARSE` for absent terminators,
and both production callers now use it. Focused fmap, ARJ, and InstallShield
fault-injection tests cover the distinction and range boundary. Compiled
parser, sanitizer, production corpus, and Sonic1 qualification remain open.

## MSPack decoder read-failure propagation — 2026-08-23

The MSPack fmap bridge already recognized a fully in-range callback failure as
`fmap_readn() == (size_t)-1`, but CAB/CHM decoder-open and extraction paths
collapsed that condition into ordinary parse/format failure. The bridge now
records the operational read failure separately from deadline expiry and
preserves `CL_EREAD` through CAB/CHM open and member extraction, with explicit
incomplete reasons and a focused CAB header regression. Compiled MSPack/CAB/
CHM corpus, sanitizer, and Sonic1 qualification remain open.

## Legacy InstallShield CAB header read classification — 2026-08-23

The legacy InstallShield embedded-header path range-checks the declared header
before locking its fixed structure, so a genuinely short header remains
`CL_EPARSE` while a fully in-range fmap callback failure now remains
`CL_EREAD`. The existing embedded-header regression now covers both outcomes;
compiled InstallShield corpus, sanitizer, and Sonic1 qualification remain
open.

## OneNote legacy reader read-failure propagation — 2026-08-23

The Rust OneNote legacy reader previously mapped every `Read`/`Seek` error to
`Error::Parse`, so a context-aware fmap callback failure reached the scanner as
`CL_EPARSE`. Reader errors now preserve genuine source I/O failures as a typed
`Error::ReadFailure`; scanner mapping returns `CL_EREAD`, while
`UnexpectedEof` and declared-range truncation remain parse failures. A focused
reader regression exercises the distinction. Compiled OneNote corpus,
sanitizer, and Sonic1 qualification remain open.

## MIME line read-failure propagation — 2026-08-23

The mail parser now carries an in-range fmap callback failure from its bounded
MIME line reader to `cli_mbox()`, preserving `CL_EREAD` instead of collapsing
that operational failure into the generic incomplete `CL_EPARSE` result. EOF
at the map boundary remains normal termination, and the existing focused line
fault-injection regression now expects `CL_EREAD`; compiled mail corpus,
sanitizer, and Sonic1 qualification remain open.

## InstallShield MSI file-record read classification — 2026-08-23

The MSI embedded-file record path now range-preflights its fixed record before
the callback, so a genuinely short record remains `CL_EPARSE` while a fully
in-range fmap callback failure remains `CL_EREAD`. Focused MSI coverage
exercises both outcomes; compiled InstallShield corpus, sanitizer, and Sonic1
qualification remain open.

## ALZ reader read-failure propagation — 2026-08-23

The Rust ALZ reader previously swallowed callback failures at the initial
signature, archive-signature, central-directory, and extracted-member read
boundaries. Header truncation now remains an incomplete parse result, while an
in-range fmap backing-read failure is carried as a typed `ReadFailure` and
returns `CL_EREAD`; deadline expiry remains `CL_ETIMEOUT`. Stored, deflate, and
BZip2 member reads use the same operational classification, and later-member
failures are no longer downgraded to a generic parse flag. Focused Rust reader
tests cover header and stored-member callback faults. Compiled ALZ corpus,
sanitizer, and Sonic1 qualification remain open.

## 7-Zip bounded EOF classification — 2026-08-23

The 7-Zip fmap input adapter previously passed requests extending past the
input map directly to `fmap_readn()`, whose shared sentinel is also used for
an in-range backing-read failure. The adapter now clips requests at the map
boundary and returns the decoder's input-EOF result for genuine truncation;
fully in-range callback failures still return `SZ_ERROR_READ` and therefore
`CL_EREAD`. A focused regression preserves `CL_EPARSE` for a truncated member,
alongside the existing injected callback-failure regression. Compiled 7-Zip
corpus, sanitizer, and Sonic1 qualification remain open.

## Sonic1 qualification connectivity blocker — 2026-08-23

The exact configured MCP-SSH host/profile (`sonic1` / `sonic1-camera-key`)
remains unavailable at the connect phase on `192.168.1.216:4456`. A new
read-only checkout-state probe timed out after 20 seconds with
`remote_started=false`; no remote command ran. Sonic1 production and sanitizer
qualification therefore remain an external blocker, while local non-CMake
evidence continues independently.

## SWF clipped compressed-input read classification — 2026-08-23

The SWF compressed-input helper previously classified any callback failure
whose starting offset was below the map end as `CL_EREAD`. Because
`fmap_readn()` clips requests that extend past EOF before invoking the backing
callback, that rule mislabeled a callback failure on a truncated final prefix
as an operational read fault. The helper now checks whether the original
request was fully contained before returning `CL_EREAD`; clipped or
out-of-range requests remain format/incomplete results. A focused CWS
regression covers the one-byte-final-prefix fault, while the existing
fully-in-range callback regression remains unchanged. Compiled SWF corpus,
sanitizer, and Sonic1 qualification remain open.

## MSPack clipped decoder-read classification — 2026-08-23

The bundled MSPack fmap bridge previously set its operational-read sentinel
for every fmap_readn() failure. Since fmap_readn() clips requests that cross
EOF, a callback failure while servicing that clipped prefix was misclassified
as CL_EREAD instead of decoder truncation. The bridge now returns decoder EOF
semantics for clipped requests and retains CL_EREAD only for fully in-range
callback failures. A focused CAB fixture reaches a folder read beginning at
the final byte and verifies that the result remains CL_EFORMAT; the existing
fully in-range callback-fault regression remains unchanged. Compiled CAB/CHM
corpus, sanitizer, and Sonic1 qualification remain open.

## PE unpacker payload-read classification — 2026-08-23

Confirmed MEW, Upack, Petite, WWPack, and Aspack reconstruction paths were
still using truncating `fmap_readn()` calls or breaking out of a recognized
unpacker after a failed section read. That could skip required PE-specific
inspection and allow the outer scan to continue as clean. The shared PE
`pe_readn_full()` helper now distinguishes a clipped section range
(`CL_EPARSE`) from an in-range fmap callback failure (`CL_EREAD`), marks the
layer incomplete, and returns the failure through each affected unpacker path.
The existing Petite callback regression now exercises the helper; complete
PE corpus, sanitizer, and Sonic1 qualification remain open.

## Structured-report counter saturation — 2026-08-23

Structured report logical/file/parser/detector counters previously used plain
increments. A sufficiently large directory or parser walk could wrap one of
those diagnostic values to zero in the serialized report, weakening evidence
of how much work was actually attempted. Report counter increments now
saturate at `UINT64_MAX`; the focused unit regression covers all three
increment paths plus file counting. This changes report evidence only and
does not alter scan admission. Compiled report and Sonic1 qualification remain
open.

## OLE2 document-stream encryption probe read propagation — 2026-08-23

The OLE2 property walker identified `WordDocument`, `WorkBook`, and
`PowerPoint Document` streams, but their fixed encryption probes still used
raw `fmap_need_off_once()` calls whose NULL result could be ignored. The probes
now use the existing checked native-width range helper, distinguish truncation
from an in-range callback failure, mark the layer incomplete, and return the
status through both property-tree passes. Focused callback-backed
`password.fat.doc` and `password.fat.xls` regressions verify that failed
WordDocument and WorkBook probes return `CL_EREAD` and make the fmap
non-cacheable. Compiled Office corpus, sanitizer, and Sonic1 qualification
remain open.

## Authenticode parse/read failure classification — 2026-08-23

The embedded Authenticode ASN.1 parser previously returned `CL_EPARSE` after
both malformed input and swallowed fmap read failures without marking the
current layer incomplete. Such a result could leave the PE path eligible to
continue toward external catalog trust. The post-`asn1_parse_mscat()` hash
container checks now route their parser failures through the same sticky
incomplete helper, making the failure non-cacheable and causing the existing
catalog-trust gate to refuse that layer. Hash mismatches remain `CL_EVERIFY`
because the structure was parsed but the computed digest did not match. A
focused callback-backed parser regression covers both the initial in-range
read failure and a post-parser hash-container read failure on the signed PE
fixture; compiled PE corpus, sanitizer, and Sonic1 qualification remain open.

Confirmed embedded X.509 certificate parse errors now terminate the
Authenticode certificate walk as incomplete instead of being skipped after the
certificate cursor advances. This keeps malformed or callback-failed embedded
certificate inspection from reaching external catalog trust; the existing
initial and post-container callback regressions remain the available compiled
evidence.

## FSG and UPX confirmed-read failure classification — 2026-08-23

Legacy FSG source/support windows and the UPX compressed-section window could
previously return after a failed `fmap` request without marking the packed PE
layer incomplete. The paths now preflight native ranges, distinguish an
in-range callback failure (`CL_EREAD`) from an unavailable range (`CL_EPARSE`),
and record sticky incomplete state before unwinding. Packed FSG and UPX fixture
regressions target the compressed-section window; full PE corpus, sanitizer,
and Sonic1 qualification remain open.

## Context-aware fmap hash read classification — 2026-08-23

The context-aware fmap hash helper returned `CL_EREAD` when a bounded hash
window could not be obtained, but did not itself set sticky incomplete state.
That left callers which propagated the status without an additional mark
vulnerable to losing the non-cacheable invariant. Context-aware missing-map,
window-read, hash-initialization, and digest-update failures now mark the scan
incomplete; the public no-context hash API remains behaviorally unchanged.
A two-window injected-read regression verifies `CL_EREAD`, the reason, and the
non-cacheable map state. Compiled matcher/hash qualification, sanitizer, and
Sonic1 qualification remain open.

## AutoIt version-byte read classification — 2026-08-23

The confirmed AutoIt parser entry previously returned `CL_EREAD` when its
version-byte fmap request failed, but did not mark the layer incomplete. The
entry now records an explicit incomplete reason before returning, preserving
the non-cacheable invariant. A focused callback regression covers the
version-byte boundary; compiled AutoIt corpus, sanitizer, and Sonic1
qualification remain open.

## PE import DLL-name read classification — 2026-08-23

The PE import-hash pass already treated descriptor and thunk read failures as
incomplete, but an in-range fmap failure while acquiring an imported DLL name
returned `CL_EREAD` without setting the sticky incomplete state. The path now
records an explicit reason before unwinding, so PE-specific inspection cannot
be cached or continue as a complete layer. The existing PE fault-injection
test now directly exercises that callback boundary and verifies the status,
reason, and non-cacheable map state. Compiled PE corpus, sanitizer, and
Sonic1 qualification remain open.

## PE header ingress read classification — 2026-08-23

The PE header parser already claimed to distinguish in-range fmap callback
failures from short DOS/NT/optional/data-directory/section-header ranges, but
several direct reads still collapsed the callback failure into `CL_ERROR` or
`CL_EFORMAT`. That was especially unsafe for embedded PE admission, where
`CL_ERROR` intentionally means “not actually PE” and is not marked incomplete.
A shared header-read helper now returns `CL_EREAD` and records a specific
incomplete reason for operational callback failures while preserving the
existing short-range status. A focused DOS-signature callback regression
verifies the status and non-cacheable state. Compiled PE corpus, sanitizer,
and Sonic1 qualification remain open.

## AutoIt header-window read classification — 2026-08-23

The AutoIt header checker’s initial version-byte read was sticky, but its
follow-up signature and versioned-body windows could still return `CL_EREAD`
without marking the direct helper context incomplete. Both windows now record
specific incomplete reasons before returning. The AutoIt regression also
injects a failure into the larger signature window and verifies the status,
reason, and non-cacheable map state. Compiled AutoIt corpus, sanitizer, and
Sonic1 qualification remain open.

## InstallShield MSI admission-window read classification — 2026-08-23

The InstallShield MSI header checker already returned `CL_EREAD` for a failed
magic or control-block read, but did not make that direct admission context
sticky incomplete. Both required windows now record explicit incomplete
reasons before returning. The embedded-admission regression injects the magic
window failure and verifies the status, reason, and non-cacheable map state.
Compiled InstallShield corpus, sanitizer, and Sonic1 qualification remain
open.

## Bytecode PDF-object read classification — 2026-08-23

The bytecode PDF `pdf_getobj()` API returned a NULL borrowed pointer when its
bounded fmap window could not be supplied, but did not notify the owning scan
context. Required PDF bytecode inspection could therefore lose the sticky
incomplete/non-cacheable state. The API now records an explicit incomplete
reason on that failure. The existing page-lifetime regression now also injects
an object-window read failure and verifies the context and map state. Compiled
bytecode/PDF corpus, sanitizer, and Sonic1 qualification remain open.

## Bytecode buffer-pipe read classification — 2026-08-23

File-backed bytecode buffer pipes previously returned NULL when their borrowed
fmap window could not be supplied, without recording whether the range was
outside the map or the backing read failed. Required decoder work could then
unwind without sticky incomplete state. The API now rejects out-of-range
windows explicitly and marks both range and in-range read failures. The
64-bit buffer-pipe regression injects an exact-boundary backing-read failure
and verifies the incomplete reason and non-cacheable map state. Compiled
bytecode/decoder corpus, sanitizer, and Sonic1 qualification remain open.

## NsPack confirmed-read failure classification — 2026-08-23

After the NsPack entry-point marker is confirmed, loader metadata, compressed
payload, and OEP metadata are required for the PE-specific unpacking path. The
legacy loop previously broke out on those fmap failures and could continue
through later PE work without a direct `CL_EREAD` result. Those confirmed-read
exits now mark the layer incomplete, release any acquired source/destination
resources, and return `CL_EREAD`; the pre-recognition heuristic probe remains
non-terminal. A focused PE32 fixture injects the loader-metadata callback
failure and verifies the status, reason, and non-cacheable map state. The
compiled PE corpus, sanitizer, and Sonic1 qualification remain open.

## MEW confirmed-loader read classification — 2026-08-23

After the MEW entry-point characteristics select the fixed loader metadata
window, a failed `fmap_need_off_once()` previously broke out of the MEW path
without recording that required unpacker inspection had been skipped. The
window now marks the layer incomplete and returns `CL_EREAD`. The existing
XOR-backed `clam-mew.exe` corpus path has a focused callback regression for
the `0x154`/`0x158` loader boundary. Compiled PE corpus, sanitizer, and Sonic1
qualification remain open.

## MSXML fmap callback failure classification — 2026-08-23

The legacy MSXML `xmlReaderForIO()` adapter returned `-1` when a bounded fmap
window could not be acquired, but did not retain that cause after libxml2
converted the callback failure into a generic reader/parser error. A required
MSXML metadata scan could therefore report only `CL_EPARSE`, losing the
operational distinction needed for diagnostics and qualification. The adapter
now records the callback fault in `msxml_cbdata`, preserves it through reader
initialization and close, marks the layer incomplete, and returns `CL_EREAD`
unless a higher-priority detection, timeout, or allocation failure already
terminated the scan. A focused callback-backed MSXML regression verifies the
status, reason, and non-cacheable map state. Compiled MSXML/HWPML corpus,
sanitizer, and Sonic1 qualification remain open.

## MSXML direct-entry map admission — 2026-08-25

The legacy MSXML direct entry checked for a null context but allowed a valid
context with no input fmap to reach the XML reader callback, where the missing
map could be dereferenced. It now returns `CL_EPARSE` with sticky incomplete
state for that recognized-layer boundary while retaining `CL_ENULLARG` for a
null context. The isolated production-linked `msxml_map` regression covers
both cases. Compiled XML/OOXML corpus, sanitizer, and Sonic1 qualification
remain release gates.

## OLE2 direct extraction map admission — 2026-08-25

The OLE2 extraction entry rejected a null context but could dereference the
engine or input fmap for a recognized layer whose map was unavailable. It now
returns `CL_EPARSE` with sticky incomplete state before those accesses while
retaining `CL_ENULLARG` for a null context. The isolated production-linked
`ole2_map` regression covers both direct-entry boundaries. Compiled OLE2
corpus, sanitizer, and Sonic1 qualification remain release gates.

## Embedded EGG SFX read-result classification — 2026-08-23

The embedded EGG SFX admission helper already distinguished a fully in-range
fmap callback failure (`CL_EREAD`) from a short candidate (`CL_EFORMAT`) and a
malformed or unsupported fixed header (`CL_EPARSE`). The scanner-facing branch
was still reporting both read and parse failures with the same generic
“malformed or unsupported” reason. It now preserves a dedicated incomplete
reason for `CL_EREAD`, while leaving weak-candidate rejection and parse-result
classification unchanged. Compiled scanner, sanitizer, production EGG corpus,
and Sonic1 qualification remain open.

## Embedded 7-Zip SFX read-result classification — 2026-08-23

The embedded 7-Zip admission helper already returned `CL_EREAD` when its
confirmed 32-byte start-header window failed through the fmap callback, but
the scanner-facing branch reported the same generic reason as malformed or
unsupported headers. It now preserves a dedicated incomplete reason for
`CL_EREAD`, while retaining weak-candidate rejection and parse-result
classification. A focused public embedded-SFX regression verifies the read
failure remains `CL_EREAD` and non-cacheable. Compiled scanner, production
7-Zip SFX corpus, sanitizer, and Sonic1 qualification remain open.

## Runtime evidence manifest path binding — 2026-08-23

The runtime verifier previously checked the hashes and line counts of the
source, Git-tree, and index manifests independently, but did not prove that
they described the same files. It now validates canonical sorted path sets
across all three manifests and rejects duplicate, absolute, or traversal
paths. Git-backed evidence is explicitly typed as `git-commit`; snapshot
evidence is typed as `content-manifest` and must use the source-manifest digest
as both revision identifiers. A synthetic negative regression confirms that a
source/tree path mismatch is rejected. The verifier accepts both Git's tab-
delimited tree/index output and the Git-less producer's copied source-manifest
format. Full semantic build/runtime binding and external attestation remain
open.

## Embedded RAR SFX read-result classification — 2026-08-23

The embedded RAR SFX admission helper already preflighted the confirmed
fourteen-byte main-header range and returned `CL_EREAD` for an in-range fmap
callback failure. The scanner-facing branch still assigned that result the
generic malformed/truncated reason used for parse failures. It now preserves a
dedicated incomplete reason for `CL_EREAD`, while leaving weak-candidate
rejection and malformed-header classification unchanged. A focused callback
regression verifies that the embedded scan remains `CL_EREAD` and
non-cacheable. Compiled scanner, production RAR corpus, and backend/Sonic1
qualification remain open.

## PE heuristic window read classification — 2026-08-23

The enabled Magistr and Polipos PE heuristics had three required fmap windows
that silently fell through when `fmap_need_off_once()` returned `NULL`: the
Magistr tail signature window, the Polipos code section, and each Polipos jump
target. A callback failure could therefore skip confirmed PE-specific
inspection and still allow a later clean result. These windows now use the
bounded PE range/read classifier, return `CL_EREAD` for in-range callback
failures, return `CL_EPARSE` for out-of-range coordinates, and mark the layer
incomplete before releasing `peinfo` and any Polipos jump array. A focused
fixture regression covers the Magistr and Polipos code-section read failures;
the Polipos jump-target branch remains covered by the same source guard and
requires compiled corpus qualification. Compiled PE corpus, sanitizer, and
Sonic1 qualification remain open.

## TAR end-of-archive classification — 2026-08-23

The TAR parser previously treated exact EOF after a member as clean and stopped
after only one zero block. That allowed a missing or incomplete
end-of-archive marker sequence to bypass the parser's fail-closed contract.
The parser now requires two complete zero blocks, marks missing/single-block
termination as `CL_EPARSE`, and distinguishes a truncated marker block from an
in-range header callback failure; marker blocks must be entirely zero-filled. A
focused regression covers no marker, one marker, and the valid two-marker
boundary. Compiled TAR corpus, sanitizer, and Sonic1 qualification remain open.

## NsPack bitched-entry read classification — 2026-08-23

The enabled NsPack path had a confirmed bitched-header branch whose 24-byte
entry-metadata `fmap_need_off_once()` failure simply broke out of the heuristic
loop. An in-range callback fault could therefore suppress the remainder of the
NsPack inspection without a non-cacheable result. The branch now uses the PE
bounded range/read classifier, returning `CL_EREAD` for callback failures and
`CL_EPARSE` for out-of-map coordinates. The existing NsPack fault-injection
regression also covers this entry boundary; compiled PE corpus, sanitizer, and
Sonic1 qualification remain open.

## PE initial icon-group read classification — 2026-08-23

The PE icon parser's initial group-header callback failure previously left the
group callback as if no group had been found, allowing the icon pass to return
clean after skipping confirmed icon inspection. The initial group header now
uses the same range/read classification as later icon windows, preserving
`CL_EREAD` for an in-range callback failure and `CL_EPARSE` for an out-of-map
coordinate. The existing focused icon-group fault regression now exercises the
corrected branch; compiled icon corpus, sanitizer, and Sonic1 qualification
remain open.

## ISO volume-descriptor terminator classification — 2026-08-23

The ISO descriptor walk previously stopped on a non-descriptor block or on an
out-of-map request and continued into the root directory. A truncated image
could therefore reach a clean empty-directory result without proving that the
volume-descriptor sequence ended correctly. The walk now requires a complete
`0xFF/CD001` terminator, preserves in-range fmap callback failures as
`CL_EREAD`, and returns `CL_EPARSE` for missing, malformed, or out-of-map
termination. A focused empty-root regression covers the missing-terminator
case; compiled ISO/Joliet corpus, sanitizer, and Sonic1 qualification remain
open.

## Raw matching of short non-empty layers — 2026-08-23

The scanner had several historical five-byte fast paths that returned clean
before the raw matcher ran: root `cl_scandesc_ex2()` inputs, descriptor-backed
children, and nested fmap views. That violated the release contract for a
non-empty layer and could skip a valid short raw signature. The fast paths now
only bypass the matcher for an actually empty input; one-byte and other
sub-five-byte layers follow the normal raw-matching path. A focused one-byte
signature regression covers the public fmap API, and source guards prevent the
old shortcuts from returning. Full front-end and production-signature
qualification remain open.

## PE icon alpha-mask read failures — 2026-08-23

The PE icon parser previously treated every failed 32-bit alpha-mask fmap
lookup as the known malformed-icon case, even when the requested mask range
was inside the map. The path now distinguishes an in-range backing-read
failure from the documented out-of-range malformed-icon fallback; the former
frees the decoded image, marks the layer incomplete, and returns `CL_EREAD`.
A focused callback regression verifies the reason and non-cacheable map state.
Compiled PE/icon corpus, sanitizer, and Sonic1 qualification remain open.

## Legacy bytecode coordinate narrowing — 2026-08-23

The legacy bytecode ABI exposed signed 32-bit results for `seek` and
`file_find`, plus the PDF object-offset API. A valid native coordinate above
`INT32_MAX` was previously narrowed to the historical `-1` sentinel without
recording that required bytecode inspection had been skipped. The v1 wrappers
now reject those coordinates before narrowing and mark the scan incomplete and
non-cacheable; the v2 APIs retain native-width results. A synthetic
2-GiB-plus fmap regression covers the seek, search, and PDF-offset boundaries.
Independently compiled v1/v2 fixtures, interpreter/JIT execution, sanitizer,
and Sonic1 qualification remain open.

## Bytecode JavaScript-normalizer limit cleanup — 2026-08-23

The JavaScript-normalizer API retained its borrowed input window after
`cli_checklimits()` rejected a request at the file-count boundary. The shared
limit checker already records that boundary as incomplete; the normalizer now
releases the window before returning its legacy failure sentinel. A focused
regression covers MaxFiles and confirms that the input pipe is drained;
independently compiled interpreter/JIT fixtures, sanitizer, and Sonic1
qualification remain open.

## JPEG exploit-probe read classification — 2026-08-23

The JPEG MS04-028 comment-marker probe ignored a failed `fmap_readn()` call
before reading the segment length. A transient in-range callback fault could
therefore suppress that exploit check while the parser continued. The probe
now uses the parser's range-aware read helper and returns `CL_EREAD` with an
incomplete, non-cacheable result for an in-range callback failure; genuinely
short input remains classified by the following segment-length parse. A
one-shot callback-fault regression covers this boundary, while compiled media
corpus, sanitizer, and Sonic1 qualification remain open.

## PCRE man-page platform ceiling — 2026-08-23

The checked-in `clamd.conf` man-page source still described PCRE as having a
universal 1 GiB ceiling and listed only the legacy 100 MiB default. That was
contradictory on qualifying 64-bit anonymous-map builds, where the effective
PCRE ceiling is 32 GiB and the opt-in large-file-default profile selects 32G.
The documentation now states both platform cases and the build-profile
default; generated-man-page qualification remains open.

## Service runtime dependency immutability evidence — 2026-08-23

The mandatory service qualification previously hashed the clamd, clamdscan,
milter, and clamscan runtime dependencies before the workload and checked the
paths again in the post-run verifier, but it did not prove that the dependency
set remained unchanged during qualification. It now records a second,
canonical path/hash manifest after the workload, rejects any set or content
change, and requires the explicit summary marker
service_runtime_dependencies_unchanged=pass. The synthetic service-evidence
regression mutates the after-manifest and confirms verifier rejection. This
strengthens runtime attestation; authorized production-CVD, sanitizer, and
Sonic1 execution remain open.

## Authenticode certificate-header read classification — 2026-08-23

The confirmed PE security-directory path previously discarded a failed
`fmap_readn_full()` for the fixed certificate header and fell through with
its default verification/format status. The path now distinguishes a
genuinely truncated certificate header (`CL_EPARSE`) from an in-range fmap
callback failure (`CL_EREAD`), marks the layer incomplete before leaving the
path, and therefore prevents clean/cache/trust normalization. The focused
signed-PE callback regression reuses the existing fixture and asserts the
`CL_EREAD` result, sticky reason, and non-cacheable map. Compiled PE corpus,
sanitizer, and Sonic1 qualification remain open.

## On-access source-read status propagation — 2026-08-23

`onas_send_stream()` previously returned a failed local `read()` with only
`-1`; the caller then classified it as `CL_EWRITE` because no protocol status
was set. The source-side failures now record `CL_EREAD` before unwinding,
preserving the distinction between a partial local input read and a
socket/write failure. This remains source-validated only; compiled on-access
fault injection, sanitizer, and Sonic1 qualification remain open.

## Zero-valued front-end admission limits — 2026-08-23

`StreamMaxLength=0` and `OnAccessMaxFileSize=0` select the certified 32-GiB
ceiling in their respective front-end consumers. Daemon startup admission
previously passed those explicit zeros through as zero and could therefore
take the historical low-resource startup path when `MaxFileSize` itself was
configured below the ceiling. Admission now normalizes each explicit zero to
32 GiB before computing the memory and temporary-space requirements. The new
unit regression covers both options with a lower engine `MaxFileSize`.

## Shared clamd client stream EINTR handling — 2026-08-23

The shared legacy INSTREAM helper used by clamdscan treated a source `read()`
returning `EINTR` as a hard failure. The ordinary chunk read and the
one-byte-over-limit sentinel probe now retry signal interruptions before
classifying the result; genuine read errors still stop the request without
sending a terminator for a partial stream. Compiled nonblocking/fault
injection and Sonic1 qualification remain open.

## Milter large-stream transport width and interruption handling — 2026-08-23

The milter's `nc_send()` helper accepted a `size_t` length but stored the
native `send()` result in an `int`, which could narrow progress for a
multi-gigabyte stream chunk. Its send path also treated an interrupt as a
hard transport failure, and the small reply reader had the same receive-side
problem. The helpers now preserve `ssize_t` results and retry `EINTR` (and
`EWOULDBLOCK` for the reply reader), keeping transient signal interruptions
from turning a valid large request into a failed scan. Compiled transport
fault injection, sanitizer, and Sonic1 qualification remain open.

## Rust decoder-spool interrupted writes — 2026-08-23

The shared Rust temporary spool treated an interrupted `libc::write()` as a
hard `CL_EWRITE`. Long LHA/LZH, ALZ, or OneNote output can legitimately cross
an `EINTR` signal boundary, so that behavior could turn a complete decode into
an incomplete scan without an actual storage failure. The spool now retries
`EINTR`, rejects a zero-byte write explicitly, and preserves the existing
cleanup and reservation rollback for real failures. A focused Rust regression
covers the retry classification; compiled short-write/fault injection,
sanitizer, and parser-family qualification remain open.

## Shared zero-byte temporary-output writes — 2026-08-23

`cli_writen()` retried `EINTR` and handled ordinary short writes, but a
zero-byte `write()` left its todo count unchanged and could spin forever. This
is a fail-stop hazard for every disk-backed parser spool. It now returns the
completed prefix and marks the caller's exact-byte check as failed, so
partial/zero progress cannot be scanned or normalized as complete. The shared
`cli_filecopy()` caller now also propagates source-read, short/zero-byte-write,
and close failures instead of publishing a truncated copy as successful.
Compiled zero-progress fault injection, sanitizer, and Sonic1 qualification
remain open.

## clamd INSTREAM zero-progress staging — 2026-08-23

The active clamd INSTREAM receive path previously treated only
`cli_writen() == (size_t)-1` as a temporary-file failure. After the shared
writer correctly returns a completed prefix for zero-byte progress, that check
could accept a partial chunk and later dispatch an incomplete staged file. The
caller now requires the exact chunk length and tears down the request on any
short or failed write. Compiled daemon fault injection, sanitizer, and Sonic1
qualification remain open.

## clamd response send progress — 2026-08-23

`mdprintf()` previously passed the original formatted length to every
`send()` call, so a partial socket write could resend bytes already delivered
and read beyond the response buffer. A zero-byte send also left its loop
counter unchanged. It now sends the unsent suffix, retries `EINTR`, waits for
both nonblocking errno variants, and treats zero progress as a failed response.
Compiled protocol fault injection, sanitizer, and Sonic1 qualification remain
open.

## BinHex temporary fork short-write disposition — 2026-08-23

The BinHex data and resource fork staging paths returned `CL_EWRITE` after a
short or zero-progress temporary write without setting the sticky incomplete
state. The rewind-before-nested-scan failures likewise returned `CL_ESEEK`
without recording that required child inspection had been skipped. Common
result reconciliation could therefore normalize a partially extracted or
unscanned fork to clean. Both output paths now record explicit incomplete
reasons before returning these failures, preserving the non-cacheable,
fail-closed result. Compiled write/seek fault injection, sanitizer, and Sonic1
qualification remain open.

## HFS+ declared tree-header boundary — 2026-08-23

HFS+ tree-header admission previously checked only whether the first extent's
computed offset was inside the fmap. A header block beyond the volume's
declared `totalBlocks` could therefore be read from appended mapped bytes. The
header coordinate is now bounded by the declared volume before fmap admission;
the focused attributes-tree fixture covers an extent at the exact volume end.
Compiled HFS+ corpus, sanitizer, and Sonic1 qualification remain release gates.


## Embedded matcher-offset range admission — 2026-08-23

The raw embedded-type dispatcher now rejects negative or out-of-map matcher offsets before any child-range subtraction, PE metadata bridge, or nested parser handoff. This keeps malformed internal coordinates from wrapping into a child fmap or being treated as a confirmed layer, and prevents a later type-parser pass from restoring a clean status. Compiled embedded-candidate and production-SFX qualification remain release gates.

## 7-Zip declared-output write admission — 2026-08-23

The bounded 7-Zip path reserved temporary space using each member's declared
uncompressed size, but its streaming output callback did not reject a decoder
write that would cross that declaration. The final file-size comparison caught
the mismatch only after the extra bytes had already been written, so a hostile
or defective decoder could exceed the temporary reservation and consume disk
space before failing.

CClamFileOutStream now tracks the declared member size and bytes written.
cli_7z_output_range_allowed() uses checked subtraction to reject an output
chunk that would exceed the declaration before cli_writen() is called. The
callback also records short/failed writes as incomplete and retains the actual
written count for the legacy whole-buffer fallback. The existing regular-file
and decoder-produced-size checks remain as a second independent boundary.

test_7z_output_range_is_bounded covers zero-size, exact-edge, overrun, and
UINT64_MAX arithmetic cases. Static source guards and the inventory pass
remain available; compiled 7-Zip, sanitizer, production corpus, and Sonic1
qualification remain release gates.

## TAR GNU base-256 size admission — 2026-08-23

The TAR size field previously accepted only legacy ASCII octal. Valid GNU TAR
archives use the high-bit binary encoding when a member size exceeds that
field's octal range, so those members were classified as invalid before their
content could be considered. TAR now accepts checked positive base-256 size
fields and bounded PAX decimal `size=` overrides, rejects negative or
overflowing values, and retains the existing native-width and shared-limit
checks. Focused valid POSIX TAR regressions cover both encodings and complete
two-block termination. Malformed/oversized PAX records, compiled TAR corpus,
sanitizer, and Sonic1 qualification remain open.

## TIFF BigTIFF unsupported classification (historical) — 2026-08-23

The TIFF parser recognized only classic TIFF magic and treated BigTIFF's
`II+\0`/`MM\0+` signatures as an unrelated clean input. BigTIFF uses a
different 64-bit IFD layout that this parser does not implement, so the
recognized format now returns an explicit unsupported/incomplete result and
cannot be cached as clean. A focused direct-parser regression covers the
little-endian BigTIFF signature; compiled media corpus, sanitizer, and Sonic1
qualification remained open. This placeholder was superseded by the bounded
BigTIFF implementation recorded below.

## clamd path-walk status propagation — 2026-08-23

The daemon path/directory command now preserves a non-success result returned
by `cli_ftw()` when traversal fails before `scan_callback()` can increment the
per-request error counter. Structured requests also retain that status for the
final report, preventing a traversal failure from becoming a clean result with
no scanned object. Static source guards pass; compiled daemon fault injection,
protocol, sanitizer, and Sonic1 qualification remain release gates.

## clamd infected-file aggregate accounting — 2026-08-23

`ALLMATCHES` callback delivery can report several signatures for one file, but
the daemon summary needs to count infected files rather than signatures.
`scan_cb_data` now keeps a separate infected-file counter for command and
multiscan aggregation, preventing unsigned summary underflow while preserving
per-signature callback output. Static source guards pass; compiled multi-match,
protocol, sanitizer, and Sonic1 qualification remain release gates.

## HWP3 embedded-item status aggregation — 2026-08-23

The HWP3 information-block loop assigned each hyperlink/media nested-scan
result directly to one shared status. A detection or parser failure in an
earlier item could therefore be overwritten by a later clean item during the
same block. The loop now merges every nested result with the shared scan-status
precedence rules, preserving detections and fail-visible parser/resource
failures while still visiting later items. Static source guards pass; compiled
HWP3 corpus, nested-detection regression, sanitizer, and Sonic1 qualification
remain release gates.

## Raw embedded-dispatch status aggregation — 2026-08-23

`scanraw()` can dispatch several recognized embedded parsers, SFX layers, or
type-retyped views during one raw pass. Its aggregate `nret` status was
previously overwritten by each direct child result, allowing a later clean
candidate to hide an earlier detection or parser/resource failure. All
recognized-layer, SFX, partition, HTML, and mail dispatch results now use the
shared status-precedence merge, preserving the strongest result while retaining
the existing weak-candidate rejection behavior. Static source guards pass;
compiled multi-candidate detection/error coverage, sanitizer, and Sonic1
qualification remain release gates.

## OLE2 XLM/BIFF completion checks — 2026-08-23

The OLE2 XLM/image walker previously accepted a workbook block chain that
ended before the property's declared length and accepted a BIFF record that
ended mid-header or payload. The walker now requires both complete block-chain
length and the BIFF parser's initial state before reporting success; either
boundary returns `CL_EPARSE`, marks the layer incomplete, and prevents a clean
cache/verdict. Static source guards pass; compiled OLE2 truncation corpus,
sanitizer, and Sonic1 qualification remain release gates.

## XAR TOC root-completion check — 2026-08-23

The XAR TOC entry walker previously returned `CL_BREAK` both when it observed
the closing `</xar>` element and when libxml2 reached EOF after a complete
entry. A truncated TOC could therefore finish without an explicit parser
failure. The walker now requires the root close before returning the normal
TOC-end sentinel; EOF first marks the layer incomplete and returns `CL_EPARSE`.
A focused missing-root-close regression is registered; compiled XAR corpus,
sanitizer, and Sonic1 qualification remain release gates.

## RTF long-description state accounting — 2026-08-23

RTF retained only the first 64 description bytes, but its state machine also
used that display cap as the total consumed count. A description longer than
64 bytes could therefore leave the parser in `WAIT_DESC` and consume the
following reserved/data fields incorrectly, especially across fmap chunks.
The parser now advances by the full declared description length while copying
only the bounded display prefix. A chunk-boundary regression verifies that the
subsequent OLE10 handoff is reached and its truncated header remains
fail-visible; compiled RTF/OLE corpus, sanitizer, and Sonic1 qualification
remain release gates.

## JPEG missing-map admission — 2026-08-23

The JPEG direct parser dereferenced `ctx->fmap` through its bounded reader
without first checking that the scan context supplied an input map. A direct
library caller could therefore crash instead of receiving a fail-visible
result. JPEG now rejects a missing map with an explicit incomplete parse, and
a focused direct-entry regression is registered; compiled media corpus,
sanitizer, and Sonic1 qualification remain release gates.

## SWF missing-map admission — 2026-08-23

The SWF direct parser initialized its fmap pointer from `ctx->fmap` before
checking the caller's input. A direct library caller with no input map could
therefore crash before the parser's existing truncation and decoder guards
could run. `cli_scanswf()` now rejects a missing map as an explicit incomplete
parse, while a null context remains an argument error. A focused direct-entry
regression is registered; compiled SWF corpus, sanitizer, and Sonic1
qualification remain release gates.

## Mach-O missing-map admission — 2026-08-23

The thin Mach-O and universal-binary parser entry points initialized their
fmap pointers before checking the caller's input. A direct library caller
with no map could therefore crash before the existing bounded header and
architecture checks ran. Both entries now return explicit incomplete results
for unavailable input maps, with separate diagnostics for thin and universal
binary input. A focused regression covers both paths; compiled Mach-O corpus,
sanitizer, and Sonic1 qualification remain release gates.

## ELF, ZIP, and HWP3 missing-map admission — 2026-08-23

The direct ELF, ZIP central-directory, and HWP3 parser entries each loaded
`ctx->fmap` before validating the caller's input. A direct library call with
no map could therefore crash before the parser's existing range and
completion checks ran. Each entry now returns an explicit incomplete result
for an unavailable map, while a null context remains an argument error.
Focused direct-entry regressions cover all three paths; compiled executable,
archive, and HWP3 corpora, sanitizer, and Sonic1 qualification remain release
gates.

## XAR TOC metadata-result retention — 2026-08-25

The confirmed XAR data/EA walker returned `CL_EFORMAT` for incomplete numeric
metadata and for an XML reader failure, but those exits did not consistently
set the sticky incomplete state required to prevent caching a partially
inspected TOC. Both paths now use the XAR incomplete-result helper, and a
direct production-linked regression asserts the metadata reason and
non-cacheable state. Broader compiled XAR corpus, sanitizer, and Sonic1
qualification remain release gates.

## RIFF missing-map admission — 2026-08-25

The confirmed RIFF exploit parser previously returned `CL_ENULLARG` when a
non-null scan context had no input fmap, allowing a recognized layer to be
treated as an argument omission rather than an incomplete parse. The entry
now returns `CL_EPARSE`, records `RIFF input map is unavailable`, and remains
non-cacheable; the direct production-linked regression covers the boundary.
Parser-family corpus, sanitizer, and Sonic1 qualification remain release
gates.

## RTF missing-map admission — 2026-08-25

The RTF direct parser previously entered its deadline and temporary-directory
path without checking whether the recognized layer still had an input fmap.
It now returns `CL_ENULLARG` for a null context, or `CL_EPARSE` with the
sticky reason `RTF input map is unavailable` for a missing map. An isolated
production-linked direct regression covers the latter boundary; compiled RTF
and OLE corpus, sanitizer, and Sonic1 qualification remain release gates.

## BinHex and XAR missing-map admission — 2026-08-23

The BinHex and XAR public parser entries also initialized `ctx->fmap` before
validating the scan context. They now reject an unavailable input map with an
explicit incomplete result, while a null context remains an argument error.
Focused direct-entry regressions cover both paths; compiled encoded-document
and archive corpora, sanitizer, and Sonic1 qualification remain release
gates.

## CHM null-context admission — 2026-08-25

The CHM direct MSPack entry initialized its fmap wrapper from `ctx` before
checking the context pointer, so a null direct call could fault before the
documented argument result. The wrapper is now initialized empty and populated
only after the null-context and missing-map checks; the isolated production-
linked `mspack_map` regression covers both boundaries. Compiled CHM corpus,
sanitizer, and Sonic1 qualification remain release gates.

## Mydoom detector missing-map admission — 2026-08-23

The Mydoom log detector was the remaining standalone raw-detector entry that
initialized `ctx->fmap` before validating the scan context. It now reports an
explicit incomplete result for an unavailable input map, while a null context
remains an argument error. A focused direct-detector regression is
registered; compiled detector corpus, raw-dispatch, sanitizer, and Sonic1
qualification remain release gates.

## MSEXPAND and structured-detector missing-map admission — 2026-08-23

The exported MSEXPAND decoder and structured-data detector previously
validated only the context pointer, then dereferenced a missing fmap. Both
entries now return explicit incomplete results for unavailable input maps
before touching decoder or engine state. Focused direct-entry regressions are
registered; compiled SZDD/detector corpora, sanitizer, raw-dispatch, and
Sonic1 qualification remain release gates.

## MIME/mbox missing-map admission — 2026-08-23

The public `cli_mbox()` wrapper validated only its temporary-directory
argument and forwarded a context with no fmap to the legacy MIME line reader,
which dereferenced it immediately. The wrapper now returns an explicit
incomplete result for an unavailable input map, with a focused direct-entry
regression; compiled MIME corpus, sanitizer, and Sonic1 qualification remain
release gates.

## DMG large blkx metadata fmap streaming — 2026-08-23

The DMG XML decoder no longer applies the independent 64 MiB decoded-value
cap. Base64 output remains in the shared quota-accounted temporary spool. A
blkx metadata block within the legacy 64 MiB sort boundary retains the existing
validated array path; larger blocks are exposed through a bounded fmap and
their fixed-width stripe records are read and endian-normalized one at a time.
Terminal `END`, exact decoded length, data-fork bounds, stripe geometry, and
shared deadline checks remain fail-visible. Sorted large metadata therefore
does not require a contiguous heap allocation; unsorted metadata above the
legacy sort boundary remains an explicit incomplete result because preserving
the prior qsort behavior would require an external sort implementation.

The callback releases both the file-backed fmap and fixed header on every
return. Source guards and the capability manifest now record
`dmg-blkx-metadata-unsorted-over-64m`. Compiled DMG corpus, large-metadata
fixture, sanitizer, and supported-build Sonic1 qualification remain release
gates.

## DMG large blkx bounded external sort — 2026-08-23

The remaining valid-unsorted metadata boundary is now closed. When a
file-backed blkx table is not ordered by reconstructed sector, the parser
sorts raw fixed-width records in 4 MiB runs and merges them with fixed-size
read/write buffers through one auxiliary spool. Run memory is charged to the
shared contiguous-residency budget. That spool is reserved in full against
`MaxTemporarySize`, all run and merge I/O observes the shared deadline, short
reads/writes and cleanup failures remain fail-visible, and the final ordering
is copied back into the already-reserved decoded spool before the auxiliary
reservation is released. Partition reconstruction therefore does not overlap
two metadata-sized sort spools.

The focused regression forces four sorted runs, two merge passes, and the
final copy-back path; verifies every output sector in order; and asserts both
the temporary peak and post-sort reservation. One-byte-short contiguous and
temporary budgets are also required to fail visibly without leaking either
reservation. The former
`dmg-blkx-metadata-unsorted-over-64m` capability exception has been removed.
Compiled DMG corpus, sanitizer, and supported-build Sonic1 qualification
remain release gates.

## AutoIt EA06 bounded decompiled-output spool — 2026-08-23

EA06 script decompilation now sends reconstructed tokens directly through one
64 KiB pending window into a quota-accounted temporary spool instead of
growing a complete contiguous output buffer. A `uint64_t` output count checks
file and scan limits before appends; flushes check the shared deadline and
temporary budget before exact writes. The decoded-input reservation stays live
while output is generated, charging both spools at their real peak, and the
output reservation is held until nested scanning and cleanup finish.

The deterministic stored EA06 fixture now emits 65,557 bytes and crosses the
64 KiB flush boundary. Its LAME generator was corrected to match both state
transitions made by the C decoder. The actual production parser harness
verified every reconstructed byte, one nested scan, an exact 196,673-byte
temporary peak, and zero leaked reservation in normal and ASan/UBSan runs.
The focused writer harness also passed exact-output and one-byte-short file and
temporary-budget cases. Source guards cover the bounded writer and reject the
retired contiguous-output machinery. The
`autoit-ea06-script-over-1g` capability exception is removed; compiled corpus
and supported-build Sonic1 qualification remain release gates.

## EGG oversized extra-field bounded traversal — 2026-08-23

The archive and file extra-field parsers no longer apply a blanket 1 GiB
materialization check. They validate the complete declared span arithmetically,
then skip semantically unused payloads or read only the fixed structure needed
for split, OS, and encryption metadata. Encryption parsing requests a
method-specific prefix no larger than 29 bytes and accounts for either encoded
size-field width before subtracting header-inclusive overhead. Fixed OS
metadata rejects declared truncation before reading, while oversized trailing
payload remains skippable.

All unaligned index size/magic loads now use ClamAV's safe little-endian
readers. The focused sparse regression represents four payloads above 1 GiB—
archive/file dummy fields, AES metadata, and Windows metadata—without backing
the holes and asserts bounded contiguous requests. An actual-production-source
harness passed those paths normally and under ASan/UBSan. The broad
`egg-extra-field-over-1g` exception was retired in favor of the string-only
boundary, which the scanner-aware range implementation below now closes. Only
the legacy contiguous-string API retains a compatibility ceiling. Compiled EGG
corpus and supported-build Sonic1 qualification remain open.

## Bounded BigTIFF IFD traversal — 2026-08-23

The TIFF parser now implements the BigTIFF structural layout documented by
libtiff: a 16-byte header with validated eight-byte offset width and reserved
field, 64-bit IFD entry counts and links, 20-byte fixed entries, an eight-byte
inline-value threshold, and LONG8, SLONG8, and IFD8 field types. Classic TIFF
continues through the same bounded walker with its original 16/32-bit fields.

Neither variant retains an attacker-declared directory or maps external value
payloads. Entry-count multiplication is checked and preflighted against the
fmap; each entry is read into one 20-byte buffer; 64-bit coordinates are
validated before native-width conversion; and long directories re-check the
shared deadline every 4,096 entries. Malformed BigTIFF header extensions,
unknown types, unrepresentable offsets, out-of-map values, truncation, and
in-range fmap callback failures remain explicit incomplete results.

Focused tests cover little- and big-endian valid files, inline LONG8 metadata,
malformed fixed structures, all five fixed-read callback boundaries, and a
pair of sparse logical BigTIFFs whose first IFD and external value range are
above 4 GiB; the latter verifies that validation does not map the payload.
Compiled media corpus,
sanitizer, and Sonic1 qualification remain release gates. As an additional
production-source corpus check, all nine TIFF files in libtiff's archived
`BigTIFFSamples.zip` passed normal and ASan/UBSan traversal, including classic,
Motorola-endian, LONG/LONG8, tiled, long-strip, and IFD4/IFD8 SubIFD variants.
The downloaded bundle is 9,497 bytes with SHA-256
`aa2960126b3904732742e674ac16d06c219c7c359898cfd5eb0af5822b598090`.

The release runtime gate now generates a deterministic sparse BigTIFF whose
first IFD begins at byte 4,294,967,312 and whose external LONG8 value begins at
byte 4,294,967,352. Its logical size is 4,294,967,368 bytes and its SHA-256 is
`06b8d598efcbad2fe8cbaedb41c74ef3dcf442825f781cb919eace3ff3f85c1d`.
Both release and sanitizer scanners must enter the BigTIFF parser, preserve the
above-4-GiB IFD coordinate, complete one IFD, and avoid the retired unsupported
classification. The post-run verifier binds those logs to the generator,
independent file-type result, size, and hash; its positive and fail-closed
control suite passes locally. The complete compiled TIFF corpus and
materialized Sonic1 release/sanitizer evidence remain required before this
parser family is qualified.

## PDF single-Flate bounded streaming — 2026-08-23

The common unencrypted, single-filter Flate path now bypasses the legacy
contiguous decoder token. It consumes native-width source lengths in 64 KiB
zlib windows and emits decoded bytes through a fixed 256 KiB,
deadline-checked, scan-limit-checked, temporary-quota-accounted output window.

Decoder output is transactional. The implementation records output and quota
baselines, truncates and rewinds on every failed attempt, and releases only the
bytes reserved by that attempt before the established raw fallback is written.
Tests cover exact multi-window output/accounting, one-byte-short quota rollback,
truncated-output replacement by the exact raw stream, and a logical Flate input
length above `UINT32_MAX` whose valid stream terminates in the first bounded
window. Object streams and encryption remain explicit unsupported boundaries;
supported ordinary filter chains now use the bounded spool design below.
Compiled corpus, sanitizer, materialized large-stream, and Sonic1 evidence are
still required.

An isolated Linux GCC translation-unit check found that the accumulated unit
test source had an unmatched `_WIN32` conditional and referenced several late
callback definitions before their declarations. The HTML-only guard now closes
at its intended boundary, shared callback state/prototypes are declared before
first use, and the source guard checks preprocessor balance. Both production
`pdfdecode.c` and the complete `check_clamav.c` translation unit now pass GCC
syntax/code-generation checks with temporary generated-header stubs; existing
unrelated legacy warnings remain. A read-only Sonic1 status probe again timed
out during Connect without starting a remote command, so remote compiled and
runtime evidence remains pending.

The real production `pdf_decodestream()` was also linked into an isolated GCC
harness. Its four streaming cases passed both normally and under GCC
AddressSanitizer/UBSan with leak detection: multi-window output, quota rollback,
truncated raw fallback, and native-width input admission. This is focused local
evidence; full PDF corpus and Sonic1 sanitizer qualification remain open.

## PDF single-RunLength bounded streaming — 2026-08-23

Ordinary single-filter, unencrypted `RunLengthDecode` objects now traverse
native-width encoded input without a whole-buffer token. Decoder packets are
batched into one fixed 256 KiB output window, input traversal checks the shared
deadline at 64 KiB intervals, and every flush is admitted against scan and
temporary limits. The shared output transaction truncates and rewinds the child
and releases only the current attempt's reservations before raw fallback.

Regressions cover exact multi-window bytes (including ignored post-marker
data), one-byte-short temporary admission with zero file/quota residue,
malformation after a valid decoded prefix with exact raw replacement, and a
logical source length above `UINT32_MAX` that reaches an early end marker. The
production harness now passes all eight Flate and RunLength cases both normally
and under GCC AddressSanitizer/UBSan with leak detection. Full PDF corpus,
materialized large-object, and Sonic1 qualification remain open.

## PDF single-ASCII filter bounded streaming — 2026-08-23

Single-filter, unencrypted ASCIIHex and ASCII85 streams now decode from
native-width input through bounded state into the shared 256 KiB transactional
output window. Deadline checks occur at 64 KiB encoded-input intervals, and
every flush is admitted against scan and temporary limits before an exact
write. Failures roll back all decoded bytes and only the current attempt's
reservation before raw fallback.

ASCIIHex now handles the complete PDF whitespace set and odd-nibble padding;
ASCII85 preserves marker-less compatibility while validating final groups,
32-bit tuple range, and `z` placement. Regressions bind exact multi-window
output, all PDF whitespace bytes, known vectors, partial groups, marker
behavior, one-byte-short quota rollback, invalid or overflowing input after
written prefixes, and early terminators under logical lengths above
`UINT32_MAX`. The production harness passes all 20 streamed-filter cases both
normally and under GCC AddressSanitizer/UBSan with leak detection. Encryption,
object streams, compiled corpus, and Sonic1 qualification remain open.

## PDF single-LZW bounded streaming — 2026-08-23

Ordinary unencrypted single-filter LZW streams now feed the fixed-state decoder
through 64 KiB native-width input windows and emit through the shared 256 KiB
transactional output window. Dictionary and partial-bit state survive input
and output boundaries; each flush is deadline-, scan-limit-, and
temporary-quota-accounted. Failed attempts remove all decoded prefixes and
their reservations before exact raw fallback.

`EarlyChange` 0 and 1 are parsed strictly and tested across a code-width
transition. Malformed values and unsupported non-identity predictors are
explicit incomplete results. The legacy token decoder also no longer calls
`lzwInflateEnd()` after failed initialization. Regressions bind multi-window
exact output, one-byte-short quota rollback, missing EOI after a written
prefix, parameter failures, and early EOI with a logical source length above
`UINT32_MAX`. The production harness passes all 26 single-filter cases both
normally and under GCC AddressSanitizer/UBSan with leak detection.
Encrypted/object streams, compiled corpus, materialized large streams, and
Sonic1 qualification remain open.

## PDF predictor fail-closed admission — 2026-08-23

Flate and LZW now share strict DecodeParms admission for `/Predictor`.
Identity value 1 proceeds; missing, non-scalar, non-numeric, and non-identity
values mark the scan incomplete before decoder output and preserve exact raw
fallback. This closes the prior silent treatment of TIFF/PNG-predicted output
as fully decoded while leaving predictor reversal explicitly unsupported.

Regressions bind valid identity-Flate output and every malformed/unsupported
parameter class. The production harness passes all 27 streamed-filter cases
normally and under GCC AddressSanitizer/UBSan with leak detection.

## PDF bounded filter-chain spools — 2026-08-23

Ordinary unencrypted chains composed only of Flate, RunLength, ASCIIHex,
ASCII85, and LZW now share a native-width bounded reader. The original stream
is exposed in at most 64 KiB memory windows. Each non-final decoder writes to a
quota-accounted temporary file, and the next decoder reads that completed
stage through 64 KiB fmap windows while retaining only fixed decoder state and
one 256 KiB output buffer.

Temporary accounting deliberately overlaps the completed input stage with the
stage being produced. The consumed input is released only after the next
decoder succeeds. Any decode, deadline, quota, write, size-verification,
mapping, read, close, or unlink failure destroys every intermediate, truncates
and rewinds the final child to its pre-chain offset, and restores the exact
reservation baseline before the existing raw-fallback policy is applied.

Five committed regressions bind exact multi-window ASCIIHex-to-Flate output,
one-byte-short overlapping quota admission with zero residue, second-stage
truncation with exact raw replacement, three-stage spool rotation, and logical
input above `UINT32_MAX` whose encoded stream terminates in the first bounded
window. The linked production harness exercises every supported decoder as an
intermediate writer and file-backed reader, validates three-stage peak
accounting, adds an injected intermediate fmap read failure, and proves
`CL_EREAD` propagation without raw fallback or leaked quota/files. A simulated
post-decode unlink failure also proves that final output and quota are rolled
back after a successful decode if stage cleanup fails, including when a
zero-output `CL_BREAK` would otherwise permit a successful raw fallback. The
injectable bounded fmap harness passes all 37 cases normally and under GCC
AddressSanitizer/UBSan with leak detection. A second build links the production
`fmap.c` implementation directly; all 36 applicable cases also pass normally
and under the same sanitizers. `pdfdecode.c`, `lzwdec.c`, and the complete
`check_clamav.c` translation unit pass GCC compilation; only pre-existing
isolated-build warnings remain.

Encrypted object streams, unsupported or mixed filter chains, exhaustive
filter-order corpus coverage, materialized multi-gigabyte intermediates, and
Sonic1 release/sanitizer qualification remain open. Per-filter DecodeParms
arrays are addressed by the later 2026-08-24 milestone.

## PDF file-backed object streams — 2026-08-23

Mmap-capable builds now route ordinary unencrypted object streams through the
bounded raw/single-filter/filter-chain decoders and retain the completed child
as a read-only file-backed mapping. The output regular-file size is verified
before mapping. Its exact temporary reservation moves from the extraction
scope to the object-stream owner, survives descriptor close and unlink, and is
released only after final unmap. Parsed and extracted ranges receive explicit
`MADV_DONTNEED` release after sequential access.

Object-index parse status is retained independently from decoder status. A
malformed stream that already added an embedded object keeps its backing and
returns an incomplete containing-object result; a pre-attachment decode or
mapping failure discards only the unreferenced newest owner. Object-stream
array growth no longer uses realloc-or-free, and failed removal no longer
shrinks the live owner array through a second allocation. The same review
removed a duplicate PDF encryption-search declaration and restored the
missing declaration in its actual consumer, with both mmap and fallback
configurations passing GCC compilation.

Six regressions cover raw and Flate mappings, exact retained quota and teardown,
malformed backing behind one valid object, containing-object status
propagation, quota rejection without a mapping, and native-width logical input
above `UINT32_MAX`. The production mapping/index/cleanup harness passes 2/2
normally and under GCC ASan/UBSan with leak detection. Integrated decoder
coverage passes 39/39 with the injectable bounded fmap and 38/38 with
production `fmap.c`, normally and under the same sanitizers. The complete
`check_clamav.c` translation unit also passes GCC syntax compilation with only
pre-existing isolated-build warnings.

Encrypted object streams, unsupported/mixed filters, non-mmap object-stream
builds, compiled corpus, materialized-large fixtures, and Sonic1 qualification
remain open. Per-filter DecodeParms arrays are addressed by the later
2026-08-24 milestone.

## PDF object-stream qualification corpus — 2026-08-23

A deterministic streaming generator now creates complete PDF 1.7 files with a
cross-reference stream and a type-2 entry for the embedded object. It covers
raw, Flate, ASCIIHex-to-Flate, malformed indexing after one valid object, and
an exact-size opaque object stream written without sparse seeks. It now also
emits complete empty-password Standard R2 RC4, Standard R4 AESV2, and
compatibility-only deprecated Standard R5 AESV3 documents for raw, Flate, and
ASCIIHex-to-Flate object streams, plus nonempty-password raw variants for all
three handlers, including deterministic
owner/user entries, permissions, file ID, object keys, AES IVs, encrypted
content, an unencrypted XRef stream, and a Standard crypt-filter dictionary.
It also emits deterministic AESV2 documents with an unknown crypt-filter method,
one-byte-truncated ciphertext, and invalid PKCS#7 padding. Its thirty-one-case
self-test verifies independent RC4 and NIST AES-128/256
vectors,
AES encryption/decryption and padding, deterministic hashes, filter reversal,
xref coordinates, security metadata, compressed-object ownership, invalid-
request rejection, and allocated multi-window encrypted fixtures. An existing
OpenSSL executable accelerates large AES corpus generation; the independently
tested pure-Python implementation remains the oracle and fallback, so no
package installation is required.

The scanner-facing qualification gate accepts an existing clamscan and
database and performs no build configuration. It binds size/hash/allocation,
requires marker detection and real object-stream parser diagnostics, requires
file-backed attach and cleanup diagnostics, distinguishes expected malformed
status, rejects temporary residue, and records RSS, page faults, and file I/O
for 64 MiB–4 GiB decoded children. The thirty-one generator tests pass. Poppler
independently accepts the RC4, AESV2, and AESV3 raw, Flate, and filter-chain
forms as
one-page encrypted PDF 1.7 documents with the compressed JavaScript page
object. Poppler also rejects each password case without credentials and parses
it completely with the deterministic password. A Linux x86-64 orchestrator
self-test passes twenty cases, including
allocation proof for a 64 MiB decoded child and exact Standard R2/RC4 and
Standard R4/AESV2 plus Standard R5/AESV3 key-discovery and bounded-decrypt
diagnostics. Password cases require status 2, structured `UNSUPPORTED`, a
non-clean status, a skipped operation, no `OK`, no bounded decrypt, and no
plaintext marker. The unknown crypt filter is separately required to report
`UNSUPPORTED` without entering bounded AES; truncated ciphertext and invalid
padding must report `MALFORMED_CONFIRMED`, preserve their exact diagnostic, and
leave no clean/plaintext result or temporary residue. Its scanner and GNU-time
outputs are deliberate stubs, so this validates the gate rather than
ClamAV. Sonic1 remains unavailable at TCP connect
(20-second timeout), so no production or sanitizer scanner result is claimed.

The gate now samples peak temporary storage while the scanner runs and records
an immutable source manifest plus commit/tree state, a copied Linux x86-64 ELF
scanner, its version and resolved runtime dependencies, the OpenSSL accelerator
version, a per-file database manifest, the exact custom signature, tool hashes,
fixture/log hashes, and
normalized result hashes. A companion checker requires a clean source by
default and independently verifies every binding, exact case set, parser
oracle, malformed distinction, RSS/temporary ceiling, allocation proof, and
cleanup state. The orchestrator self-test also proves that a tampered scan log
is rejected.

## PDF bounded encrypted streams and object-stream ownership — 2026-08-23

Decryptable PDF streams no longer enter the contiguous legacy token when they
use Identity, RC4 (`V2`), AESV2, or AESV3 and are followed only by the bounded
Flate, RunLength, ASCIIHex, ASCII85, or LZW filters. Object-key derivation is
shared with the compatibility decryptor. RC4 carries one cipher state across
64 KiB input windows. AES consumes a 16-byte IV and complete CBC blocks,
retains only the final plaintext block until strict nonzero PKCS#7 padding is
validated, and emits through the existing 256 KiB transactional output window.
An explicit Crypt filter uses this path only when it is first; implicit
document decryption remains before every declared filter, and XRef streams
retain their existing decryption exception.

When filters follow decryption, plaintext is written to a quota-accounted
temporary file and read through bounded fmap windows. Its reservation overlaps
every downstream intermediate and the final child. Failures in key setup,
ciphertext shape, padding, deadline, scan limits, quota, write, size
verification, mapping, read, close, or cleanup release the plaintext stage and
restore the exact final-output and reservation baseline. A successfully
decrypted mmap-capable object stream transfers only its final child's
reservation and mapping to the object-stream owner. Identity Crypt filters are
valid without a document key; genuinely encrypted streams without a usable key
remain explicit incomplete and retain raw ciphertext fallback for matching.

Committed regressions bind independent RC4/AESV2 object-key vectors, RC4 state
across the 64 KiB boundary, AESV2 and AESV3 object-stream mappings, strict AES
padding rollback, explicit Identity-before-ASCIIHex ordering, exact ownership,
and one-byte-short overlapping quota cleanup. The focused Linux GCC harness
passes 45/45 cases normally and under AddressSanitizer/UBSan with leak
detection; the production `fmap.c` build passes its 43/43 applicable cases
normally and under the same sanitizers. Linux GCC syntax checks pass for
`pdf.c`, `pdfdecode.c`, and the complete `check_clamav.c` translation unit;
only pre-existing isolated-build warnings remain.

This closes the implementation gap, not release qualification. Deterministic
empty-password Standard R2 RC4, Standard R4 AESV2, and deprecated Standard R5
AESV3 PDF 1.7 corpus generation and evidence oracles now cover raw and supported
filtered object streams. Deterministic nonempty credentials for all three
handlers prove explicit unsupported/no-clean/no-plaintext behavior. Unknown
crypt filters now have a deterministic `UNSUPPORTED` oracle, while truncated
AESV2 ciphertext and invalid PKCS#7 padding have deterministic
`MALFORMED_CONFIRMED` oracles. Materialized multi-gigabyte encrypted streams,
broader malformed dictionaries, quota/read/cleanup faults, production and
sanitizer clamscan runs, Sonic1 evidence, and unsupported/mixed filters remain
open.
One explicit Crypt stage at any position is addressed by the later 2026-08-24
bounded-ordering milestone; repeated Crypt stages remain fail-visible.

The first-release non-mmap policy is now explicit and enforced at daemon
admission. The certified 32 GiB Linux x86-64 profile requires private
file-backed mappings (`HAVE_MMAP` and `HAVE_SYS_MMAN_H`); the startup capability
manifest records that bit, and a large-file configuration is rejected when it
is absent. Historical-size configurations retain their existing behavior.
Non-mmap builds remain outside the certified profile and keep the bounded
64 MiB PDF fallback plus fail-visible resource/incomplete boundaries. Exact
unit oracles cover every missing build capability independently. Non-mmap PDF
object streams are therefore an explicit unsupported release boundary, not an
unresolved policy decision.

## PDF per-filter DecodeParms arrays — 2026-08-24

The PDF parser now accepts either the historical direct DecodeParms dictionary
or an array aligned one-for-one with the declared filter array. Every array
entry must be a dictionary or the exact scalar `null`, and each dictionary is
selected only for its corresponding stage across streamed, encrypted, and
residual legacy paths. Short arrays, extra entries, other scalars, and
unparseable values fail before decoder output, mark the layer incomplete, and
prevent clean caching.

Focused Linux ARM64 GCC evidence passes 2/2 direct-dispatch and parser-syntax
cases. The oracles cover `/DecodeParms`, `/DP`, dictionary and `null` placement,
an unsupported predictor routed to the intended Flate stage, exact raw
fallback, zero output for malformed array shape/type, and zero retained
temporary accounting. Direct GCC compilation passes for `pdf.c`,
`pdfdecode.c`, and the complete `check_clamav.c` translation unit with only
pre-existing isolated-build warnings.

This closes the implementation gap, not parser-family qualification. Certified
Linux x86-64 production/sanitizer corpus runs, broader malformed dictionaries,
materialized multi-gigabyte chains, quota/read/write/cleanup fault injection,
unsupported/mixed filters and Sonic1 release evidence remain open.

## PDF bounded explicit-Crypt ordering — 2026-08-24

A supported filter chain may now contain one explicit Crypt filter at any
position. The ordinary quota-accounted stage rotation invokes the existing
bounded Identity, RC4, AESV2, or AESV3 reader for that stage and selects only
its corresponding DecodeParms entry. Completed input and output stages overlap
in temporary accounting, and every downstream decoder retains the existing
transactional rollback and exact raw-fallback policy. Repeated Crypt filters or
chains containing another unsupported filter remain explicit incomplete.

The focused Linux ARM64 GCC regression passes 1/1. It proves exact output and
temporary peaks for both Crypt-to-ASCIIHex and ASCIIHex-to-Crypt Identity
ordering, then proves that a two-Crypt chain returns `CL_EPARSE`, marks the
layer incomplete, restores the exact encoded input, and leaves only the final
raw-child reservation. Direct GCC compilation of `pdfdecode.c` and the full
`check_clamav.c` translation unit also passes with the previously recorded
isolated warning only.

A second focused Linux ARM64 GCC case passes 1/1 with 40 internal oracles.
RC4, AESV2, and AESV3 each pass with Crypt before and after Flate, RunLength,
ASCIIHex, ASCII85, and LZW, with the named DecodeParms entry selecting the
intended method at the Crypt stage. Every surrounding filter rejects a one-
byte-short RC4 peak with `CL_ERESOURCE`, zero output, and zero residue, and
restores its exact encoded raw input after malformed AES padding returns
`CL_EPARSE`. The same case passes against GCC AddressSanitizer/UBSan-
instrumented PDF production objects with leak detection. The refactored
arbitrary-input LZW encoder also preserves the established six-case LZW
focused suite normally and under the same sanitizer configuration.

Production PDF corpora, broader malformed crypt dictionaries,
production/sanitizer execution, materialized
multi-gigabyte stages, quota/read/write/cleanup faults, and Sonic1 evidence
remain release gates.

## PDF exact DecodeParms dictionary selection — 2026-08-24

The stream extractor previously located DecodeParms with substring searches,
so apparent keys inside strings, comments, nested dictionaries, or longer names
could be mistaken for the root stream parameter key. It now parses the complete
root stream dictionary under the shared deadline, compares decoded node names
exactly, prefers `/DecodeParms` over `/DP`, and rejects duplicate selected keys.
Scalar values, malformed name escapes, and malformed nested values return
`CL_EPARSE`, mark the scan incomplete, and prevent clean caching.

The shared PDFNG dictionary and array walkers now ignore comments during
boundary and object traversal. Literal-string boundary and value parsing both
balance nested parentheses and respect escaped characters. Failed nested
string, array, or dictionary parsing returns failure instead of advancing from
an unset end pointer or exposing a partial DecodeParms value. Dictionary and
array container, key, value, and node allocation failures now mark sticky
incomplete state and return failure rather than a partial tree.

Focused Linux ARM64 GCC evidence passes 3/3. The new exact-selection regression
contains ten internal adversarial cases covering literal/comment/nested/long-
name decoys, comments containing dictionary delimiters, valid and invalid
hex-escaped names, long-form precedence, malformed array syntax and a malformed
preceding value, duplicate exact keys, and an all-decoy dictionary. The prior
Identity ordering and
RC4/AES explicit-Crypt focused binaries were relinked against the current
`pdf.c`, `pdfng.c`, and `pdfdecode.c` objects and pass 1/1 each. Direct GCC
compilation passes for both production translation units and the complete unit
translation unit, with only the previously recorded ISO fixture warning. All
three focused binaries also pass with the touched `pdf.c`, `pdfng.c`, and
`pdfdecode.c` production objects instrumented by GCC AddressSanitizer/UBSan and
leak detection. Certified Linux x86-64 production/sanitizer corpus runs,
allocation/read fault injection, materialized multi-gigabyte streams, and
Sonic1 evidence remain release gates.

## PDF exact crypt-filter dictionary selection — 2026-08-24

`parse_enc_method_ctx()` no longer uses substring key lookup and prefix cipher
matching. It structurally parses the bounded `/CF` dictionary, matches decoded
PDF names exactly (including bounded `#xx` escapes), rejects duplicate filter
or `/CFM` keys, requires dictionary/name value types, and returns
`ENC_UNKNOWN` for missing, ambiguous, malformed, prefixed, or unsupported
entries. Downstream decryption therefore preserves the existing explicit
incomplete/non-cacheable result instead of silently choosing Identity or a
supported cipher. `pdf_parse_dict()` also accepts a valid closing `>>` exactly
at the end of the supplied span while still rejecting truncation.

A focused Linux ARM64 GCC case passes 1/1 with 23 internal exact and
fail-closed oracles. The same case passes with the touched PDF production
objects under GCC AddressSanitizer/UBSan and leak detection. Adjacent evidence
also remains green against those objects: the 40-oracle cipher/filter ordering
case passes 1/1, exact DecodeParms parsing passes 3/3, and explicit Identity
ordering passes 1/1, all normally and under the same sanitizer configuration.
Full Standard encryption-dictionary corpus mutations, allocation/read fault
injection, production scanner execution, materialized multi-gigabyte encrypted
streams, and Sonic1 evidence remain release gates.

## PDF exact Crypt DecodeParms semantics — 2026-08-24

`pdf_resolve_decryption_method()` now requires exact, unique `/Type` and
`/Name` fields for explicit Crypt stages. A present `/Type` must identify
`CryptFilterDecodeParms`; duplicate, wrongly typed, null, or invalid fields
return `CL_EPARSE` before decryption. Longer names remain irrelevant. The
ordinary chain transaction then restores the exact encoded input, retains only
the raw-child reservation, marks the layer incomplete, and prevents caching.

A focused Linux ARM64 GCC case passes 1/1 with ten internal valid,
exact-key, duplicate, wrong-type, null-value, and invalid-value scenarios. It
passes normally and with `pdf.c`, `pdfng.c`, and `pdfdecode.c` under GCC
AddressSanitizer/UBSan plus leak detection. Adjacent focused evidence also
passes against those current objects in both modes: exact `/CF` selection 1/1
with 23 internal oracles, cipher/filter ordering 1/1 with 40, DecodeParms
parsing 3/3, and explicit Identity ordering 1/1. Complete stream/encryption-
dictionary corpus mutations, allocation/read fault injection, production
scanner execution, materialized multi-gigabyte encrypted streams, and Sonic1
evidence remain release gates.

## PDF Standard encryption-dictionary corpus mutations — 2026-08-24

The deterministic production-scanner object-stream gate now contains six
additional Standard R4 AESV2 fixtures that mutate the complete encryption
dictionary: duplicate, scalar, and missing selected crypt-filter entries plus
missing, duplicate, and scalar `/CFM` values. The prior unknown `/CFM`, invalid
ciphertext length, and invalid-padding fixtures remain. Every structural case
has an exact unsupported oracle that forbids crypt-method selection, decryption,
clean output, plaintext marker exposure, parsed child objects, and temporary
residue.

Evidence schema 7 binds exactly 26 fixtures and their metadata, scanner logs,
structured reports, resource observations, database/runtime provenance, and
source hashes. The deterministic generator passes 37 tests, and shell syntax,
Python syntax, whitespace, capability-manifest, and source-guard checks pass
locally. The Linux x86-64 orchestrator and current production scanner run
remain pending: Sonic1 accepted the configured MCP-SSH profile but its SSH
service refused or timed out before any remote command started. Materialized
multi-gigabyte encrypted streams and production-scanner fault injection also
remain release gates.

## PDF bounded-spool fault rollback — 2026-08-24

Five linker-injected GCC failure classes now exercise the bounded
encrypted/filter spool transaction itself. A failed encrypted RC4 output write
and an intermediate-stage close return `CL_EWRITE`; failed file-backed map
creation returns `CL_ERESOURCE`; a failed in-range mapped read returns
`CL_EREAD`; and fixed output-window allocation returns `CL_EMEM` for Flate,
RunLength, ASCIIHex, ASCII85, and LZW. Every path truncates final output,
releases both stage and final reservations to zero, creates no object-stream
child, marks the layer incomplete, and sets the source fmap non-cacheable.

The focused suite passes 5/5 normally and with `pdf.c`, `pdfng.c`, and
`pdfdecode.c` instrumented by GCC AddressSanitizer/UBSan plus leak detection.
The adjacent exact crypt dictionary, Crypt DecodeParms, 40-oracle cipher/filter,
three-case DecodeParms, and non-first Crypt suites also remain green normally
and under the same sanitizer configuration. Production-scanner fault
injection, materialized multi-gigabyte streams, and Sonic1 evidence remain
release gates.

## Encoded-text script normalization — 2026-08-24

UTF-16LE and UTF-16BE text now pass through bounded streaming UTF-8 conversion
before script normalization, including BOM and cross-window surrogate state.
Malformed code units remain incomplete and non-cacheable. UTF-8 text is
validated incrementally for complete, minimal, scalar-value sequences before
normalization. A focused Linux ARM64 GCC case passes all three normalized
encoding branches plus cross-window and malformed-input oracles; sanitizer,
production corpus, Linux x86-64, and Sonic1 qualification remain open.

## Bounded UTF-16 HTML normalization — 2026-08-24

`CL_TYPE_HTML_UTF16` no longer uses the lossy whole-chunk
`cli_utf16toascii()` conversion. It decodes UTF-16LE and UTF-16BE to UTF-8 in
fixed 4 KiB input windows, carries a pending high surrogate between windows,
and reserves each exact decoded output length before staging it for the normal
HTML child scan. BOM-less input is accepted only when its first code unit
unambiguously establishes byte order. Odd code units, reversed byte order,
invalid surrogate state, ambiguous byte order, read/write/map/cleanup failure,
and nested-scan failure remain incomplete and non-cacheable.

The focused Linux ARM64 GCC `text_encoding` case passes 2/2. Its HTML branch
proves LE/BE decoding with and without BOMs, signature detection in the decoded
child, a valid surrogate pair split exactly across the 4 KiB input boundary,
exact temporary-account release, and exact fail-closed reasons for an odd code
unit, a lone high surrogate, and unknown byte order. Production HTML corpus,
sanitizer, Linux x86-64, materialized multi-gigabyte input, and Sonic1 evidence
remain release gates.

## Bounded 7-Zip BCJ2 solid folders — 2026-08-24

The accepted four-coder BCJ2 graph now stays on the sequential extraction
path. CALL, JUMP, and range-control data use exact-size, quota-accounted,
deadline-aware scratch files; MAIN streams directly through a resumable
fixed-window BCJ2 merger. Checked 64-bit pack coordinates, unchanged folder
and member CRC validation, sticky ClamAV error precedence, and all-exit scratch
cleanup replace the former whole-folder fallback for this graph. LZMA/LZMA2
decode work is limited to 256 KiB of output between progress callbacks, output
ending on a branch opcode preserves legacy side-stream semantics, and original
internal stream-extraction symbols remain ABI-compatible wrappers.

Focused local GCC evidence passes direct legacy differential, boundary,
terminal-opcode, truncation, output-failure, CALL/JUMP graph, native-width,
pack-overflow, and production scratch-provider oracles. A one-MiB raw LZMA
fixture additionally emits four exact 256 KiB writes with nine progress
checkpoints. Translation-unit syntax checks pass. Production
BCJ2 corpus, sanitizer, certified Linux x86-64, materialized large-folder, and
Sonic1 qualification remain open; the existing container's Rust 1.65 cannot
configure the checkout's Rust 1.97 requirement, and no toolchain was installed.

## Bounded VBA module decompression and normalization — 2026-08-24

VBA source-module bodies no longer pass through the legacy `blob` accumulator
on supported release builds. `cli_vba_inflate_stream()` retains only the 4 KiB
VBA history window, uses a native 64-bit decompressed position, and emits fixed
windows through a sticky-error callback. A persistent codepage converter
carries multibyte state across those windows, and an incremental normalizer
retains the final two output bytes so underscore/newline folding remains exact
across every split point. Normalized bytes enter the existing VBA project file
through exact temporary reservations and deadline checks.

Each module write is transactional. The scanner records the output offset and
reservation before decompression, truncates and releases the exact delta on any
decoder, conversion, normalization, resource, timeout, or write failure, and
marks the layer incomplete/non-cacheable. The old pointer-returning inflater is
preserved as a compatibility wrapper. `cl_engine_set_clcb_vba` still receives a
whole contiguous module only at or below the 1 GiB individual-allocation
ceiling; larger modules continue through bounded scanning but callback delivery
is explicitly incomplete. At this milestone, the compact project-directory
metadata stream still retained its legacy 1 GiB contiguous boundary; the
file-backed follow-up below removes that boundary from the certified mmap
profile.

Strict GCC syntax passes for both changed production translation units. Focused
GCC oracles pass split UTF-8, persistent ISO-8859-1 iconv state, incomplete-tail
handling, inflater output/error propagation, and byte-exact normalizer parity at
1-, 2-, 3-, 7-, and 31-byte windows. The capability manifest and source guards
pass with 181 entries. The existing isolated container cannot complete CMake
configuration because its Cargo 1.65 predates the checkout's required 1.97; no
software was installed. Production Office/VBA corpus, sanitizer, materialized
multi-gigabyte modules, certified Linux x86-64, and Sonic1 evidence remain open.

## File-backed VBA project-directory metadata — 2026-08-24

On certified 64-bit mmap builds, the aggregate compressed VBA `dir` stream now
decompresses through the bounded 4 KiB inflater into an exact quota-accounted
temporary file. The scanner verifies the regular-file length, maps it read-only
and sequentially, and advises consumed page ranges away while retaining a 1 MiB
look-behind window. The mapping and its temporary-storage reservation remain
owned until parsing ends, including malformed exits. Non-mmap builds retain the
legacy contiguous inflater as an explicit unsupported release-profile boundary.

The decompressed byte count is checked with native 64-bit arithmetic against
scan and temporary limits on every output window. Empty or unrepresentable
lengths, malformed backing size, map/unmap, descriptor, unlink, quota, deadline,
conversion, and write failures remain incomplete and non-cacheable. Project and
module text metadata now converts through fixed 8 KiB input windows with
persistent codepage state, removing artificial name/docstring caps. The Unicode
module stream name alone remains bounded by the existing 128-byte OLE
property-name interface used to resolve its extracted stream.

The current production translation unit passes strict GCC syntax in the
isolated Linux environment. Production-linked focused oracles pass both normal
file-backed parsing with exact reservation transfer, streamed project-name
output, a one-byte-short quota case, and a one-byte-short decompressed scan-limit
case. Both rejection paths retain zero output, zero temporary accounting, and
explicit incomplete state. The earlier bounded stream/codepage and incremental
normalizer oracles remain green. The capability manifest now passes with 182
entries. Production Office/VBA corpus, sanitizer and injected backing-I/O
failures, materialized multi-gigabyte directories/modules, certified Linux
x86-64, and Sonic1 qualification remain release gates.

## Bounded EGG filename/comment metadata — 2026-08-24

`cli_egg_open_ex()` now indexes each filename and archive/file comment as a
native-width source range. It reads only optional two-byte codepage and
four-byte parent identifiers while indexing. Filenames above the individual
allocation ceiling use a generated display name, but the original range is
not truncated or treated as inspected: UTF-8 ranges pass directly to nested
fmap scanning, and non-UTF-8 names are converted through persistent 64 KiB
input windows into a quota-accounted temporary descriptor before normalized
scanning. File comments, previously retained but not scanner-visible, enter
the same complete range traversal.

The converter path checks cumulative output against file/scan limits, reserves
temporary bytes before each exact write, checks the shared deadline around
input and output, and keeps the reservation through nested scanning and
cleanup. Unsupported codepages, encrypted metadata, malformed conversion,
read/write/seek/scan/cleanup failures, and resource exhaustion remain explicit
incomplete results. `cli_egg_open()` remains a compatibility API with its
contiguous 1 GiB string ceiling, now named
`egg-legacy-string-metadata-over-1g` rather than a parser-wide exception.

The sparse regression indexes scanner-aware filename and archive-comment
payloads above 1 GiB with maximum requests of 16 and 14 bytes respectively,
then proves the legacy filename path returns `CL_EMAXSIZE`. A focused harness
linked with the production EGG translation unit passes the scanner/legacy
contract under GCC. An isolated end-to-end scanner test converts a codepage-932
filename and detects an exact signature present only in the converted UTF-8
bytes, with matcher and temporary-work accounting. Parser, scanner, and full
unit translation units pass GCC syntax checks; the capability set contains 183
entries after regeneration. Compiled EGG corpus, additional codepages and
split-sequence cases, sanitizer and I/O fault injection, materialized large
metadata, certified Linux x86-64, and Sonic1 evidence remain open.

## SIS compressed-member matcher handoff — 2026-08-24

The existing SIS compressed-member regression asserted only that the archive
returned clean, so it did not prove the decoded bytes reached nested matching.
The fixture now loads an exact custom signature for the eight-byte
`SISDATA!` output and requires the specific `SIS.Member.Exact.UNOFFICIAL`
alert. The isolated test passes linked with the current SIS production object.
Complete SIS corpus, sanitizer, materialized large members, certified Linux
x86-64, and Sonic1 qualification remain open.

## TAR binary size-field preservation — 2026-08-24

Strengthening the GNU base-256 TAR regression from a generic clean assertion
to an exact child-only signature exposed a real parser defect: the parser used
`strncpy()` to copy the fixed 12-byte size field. Positive GNU binary fields
contain embedded NUL bytes, so the copy stopped after the `0x80` marker and
zero-filled away the low-order size bytes. The archive was then skipped as an
invalid entry, while the former weak oracle still reported success.

The parser now copies all 12 bytes with `memcpy()` and adds a separate
terminator for the legacy octal path. Isolated production-linked tests require
the exact `Tar.Member.Exact.UNOFFICIAL` alert at child offset zero for both a
GNU base-256 member and a PAX-sized member. A third public-API regression
rejects a positive prefix above 64 bits, a `0x80` value whose remaining bytes
overflow `uint64_t`, and a negative two's-complement field. All three tests
pass, and every rejected archive remains non-cacheable. A fourth test proves a
local PAX `size=` overrides a global value for one member and that the global
value resumes afterward. Its signatures are constrained to child offset zero
and `EOF-8`, preventing a raw containing-archive match. The focused case passes
4 checks with 0 failures.

The exact-offset signature cannot match the containing TAR at its root, so the
result proves extraction and nested matcher handoff. Complete TAR corpus,
sanitizer, truncated binary-field variants, certified Linux x86-64, and
Sonic1 qualification remain release gates.

## CPIO CRC member validation — 2026-08-24

The `070702` CPIO path previously used its CRC flag only to select the magic
string. It never parsed the header's checksum field or compared it with member
content, so a corrupted CRC-format archive could complete cleanly. The parser
now strictly parses all eight hexadecimal checksum characters and computes the
format's wrapping 32-bit additive checksum through unlocked 64 KiB fmap
windows. Each window checks the shared deadline; short ranges remain
`CL_EPARSE`, fully in-range callback failures remain `CL_EREAD`, and malformed
or mismatched checksums remain incomplete and non-cacheable.

Checksum status is merged after nested scanning, preserving a malware alert
over a checksum failure while retaining the checksum error for a clean member.
The focused production-linked public-API case proves an exact child-offset
signature on valid and checksum-mismatched malware, plus benign mismatch,
malformed checksum syntax, and truncated member data. A third test validates a
member spanning more than two checksum windows and requires an `EOF-8` child
tail signature. A fourth test injects failure into the exact first 64 KiB
checksum request and requires `CL_EREAD`, no alert, and non-cacheable state.
All four tests pass with no failures. Complete old/newc/CRC
corpus, large materialized CRC members,
sanitizer, certified Linux x86-64, and Sonic1 qualification remain release
gates.

## CAB/CHM missing-map entry hardening — 2026-08-24

The next parser-family audit found that the public/internal CAB header check,
CAB scan entry, and CHM scan entry assumed `ctx->fmap` was present before
constructing their bounded MSPack adapter. Direct callers with no input map
could therefore dereference a null map instead of returning a fail-visible
result.

All three entry points now reject an unavailable fmap with `CL_EPARSE`, mark
the context incomplete/non-cacheable, and preserve `CL_ENULLARG` for a null
context where applicable. The focused regression exercises CAB header
admission, CAB extraction dispatch, and CHM dispatch independently and checks
their specific incomplete reasons. The capability manifest and source guards
record the boundary. Full CAB/CHM production corpus, sanitizer, materialized
large-member, certified Linux x86-64, and Sonic1 qualification remain open.

## Masked ZIP-SFX central-directory admission — 2026-08-24

Masked ZIP local headers no longer enter ZIP-SFX admission on local magic
alone. The bounded probe duplicates the candidate suffix, validates a
reachable EOCD (including ZIP64 placement when required), validates the first
central record's fixed and variable fields through its comment, resolves ZIP64
catalogue values, and requires that record to reference local-header offset
zero with the masked-header flag. A local-only masked magic remains an
unconfirmed weak candidate; a confirmed malformed central structure or
in-range backing read failure marks the scan incomplete and non-cacheable.

Confirmed embedded archives carry `LAYER_ATTRIBUTES_ZIP_CENTRAL` and use the
full `cli_unzip()` catalogue path, while ordinary embedded local records retain
`cli_unzip_single()`. This prevents the previous silent skip of valid masked
members and proves the central values reach the authoritative extractor.

The focused production-linked GCC case passes 2/2 with zero failures in the
isolated `zip_sfx` TCase when the existing certificate directory is supplied:
the exact child-only signature is detected, the layer attribute is observed,
malformed central magic returns `CL_EPARSE` with non-cacheable state, and an
in-range central-record read fault returns `CL_EREAD` with the required
incomplete reason. The touched `unzip.c`, `scanners.c`, and unit translation
units compile with GCC; source guards and manifest evidence pass. Complete ZIP
corpus, sanitizer, materialized large-file,
certified Linux x86-64, production-CVD, and Sonic1 qualification remain open.

## Rust current-layer fmap boundary — 2026-08-24

The next shared boundary audit found that the Rust `current_fmap()` adapter
checked only the context pointer before forming a slice from
`ctx->recursion_stack` and indexing `ctx->recursion_level`. A missing stack
could therefore reach an invalid raw slice, while a stale level could panic or
read outside the declared stack.

`current_fmap()` now rejects a null recursion stack with `Error::NullParam`,
rejects a zero-length stack or an out-of-range level with `Error::Format`, and
performs those checks before `slice::from_raw_parts()` or indexing. Rust unit
regressions cover both malformed context states, and source guards plus the
capability manifest record the boundary. The host Rust 1.97.1 toolchain
attempted the focused Cargo test but the existing environment lacks OpenSSL
development metadata (`pkg-config`/headers), so the crate did not reach test
execution; no package was installed. Parser-family corpus, production-linked
Rust qualification, sanitizer, certified Linux x86-64, materialized
large-file, and Sonic1 evidence remain open.

## Rust parser current-fmap status mapping — 2026-08-24

The shared boundary audit also found that ALZ, LHA/LZH, and OneNote converted
every `current_fmap()` failure to generic `CL_ERROR`, losing the distinction
between a null C context, malformed layer state, and an in-range backing-read
failure. Their entry points now map those failures to `CL_ENULLARG`,
`CL_EPARSE`, and `CL_EREAD` respectively, while retaining the sticky
incomplete/non-cacheable report state. A focused Rust regression covers each
class and source guards bind the three parser call sites. Cargo execution is
still blocked before test compilation by the existing missing OpenSSL
development metadata; parser-family corpus, production-linked Rust,
sanitizer, certified Linux x86-64, materialized large-file, and Sonic1
qualification remain open.

## CPIO fixed-width numeric fields — 2026-08-25

The ODC and newc CPIO walkers previously copied fixed-width namesize and
filesize fields into temporary strings and used `sscanf`. That accepts a valid
numeric prefix followed by an invalid byte, so malformed headers could be
interpreted as a smaller member and move the archive cursor incorrectly.

ODC fields now require exact-width octal digits with checked `uint32_t`
accumulation; newc and CRC fields reuse the exact-width hexadecimal parser
already used for CRC checksums. A malformed recognized field marks the layer
incomplete and returns `CL_EPARSE`, rather than continuing with a prefix value.

The production-linked public-API `cpio_numeric` TCase covers malformed
name-size and file-size fields in both ODC and newc and verifies clean verdict
reset plus non-cacheability. It passes 1/1; the existing four-case `cpio_crc`
TCase also passes against the tightened parser. Complete old/ODC/newc/CRC
corpus, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD, and Sonic1 qualification remain release gates.

## ISO9660 missing-map entry classification — 2026-08-25

`cli_scaniso()` previously returned `CL_ENULLARG` for both a null context and
an otherwise valid context whose recognized ISO input fmap was unavailable.
The latter path did not mark the scan incomplete, unlike the parser's other
required-input failures.

The entry point now preserves `CL_ENULLARG` only for a null context and
returns `CL_EPARSE` with the sticky reason `ISO input map is unavailable` for
a missing fmap. The isolated production-linked `iso_map` TCase passes 1/1 and
verifies the incomplete state. Full ISO/Joliet corpus, sanitizer, materialized
large-file, certified Linux x86-64, production-CVD, and Sonic1 qualification
remain release gates.

## Rust parser null-context admission — 2026-08-25

The Rust ALZ, LHA/LZH, and OneNote entry points now reject a null `cli_ctx`
with `CL_ENULLARG` before current-layer fmap lookup or shared C reporting.
Malformed current-layer state still maps to `CL_EPARSE` and calls the shared
incomplete marker for a valid context. This makes the FFI boundary explicit and
prevents a null parser call from depending on downstream C null handling.

The `rust_map` Check TCase is registered and the source guard requires the
entry-point checks. The host Rust 1.97.1 offline attempt stopped in
`openssl-sys` because this macOS environment has no OpenSSL development
metadata; no software was installed. The existing production-linked container
archive is older than the authoritative Rust source, and its mixed C/Rust
execution is therefore not attributed as current-source evidence. A current
C/Rust rebuild, isolated TCase, Rust suite, parser corpus, sanitizer,
materialized large-file, certified Linux x86-64, and Sonic1 qualification are
still required.

## ARJ declared-header string boundaries — 2026-08-25

ARJ main and member filename/comment admission previously asked the bounded fmap
string helper for one byte beyond each declared string window. A terminator just
outside the declared header remainder could therefore be consumed and metadata
traversal could continue under a header boundary that the format did not provide.
Both callers now pass the exact declared remainder; an absent terminator remains
`CL_EPARSE`, while an in-range backing callback failure remains `CL_EREAD`.

The boundary regression is registered in the main Check suite and the modified
test object compiles with the production GCC flags. An isolated production-linked
GCC harness passes 1/1 and reports the expected incomplete, non-cacheable
`CL_EPARSE` result. The full monolithic test binary was not relinked because the
existing container archive is stale for unrelated newer test symbols. Complete
ARJ corpus, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 qualification remain open.

## ARJ header-range audit — 2026-08-25

The focused production-linked `arj_map` TCase now passes 4/4 for context/map
admission, fixed main-header callback failure, declared filename-window
callback failure, and the declared-header string boundary. The string-read
fixture was corrected to inject the failure at the actual filename start
(offset 34 after the two-byte archive signature and fixed 30-byte header), so
the oracle exercises the intended range rather than a byte inside the fixed
header. The parser preserves `CL_EREAD` and non-cacheability for the injected
callback failure and `CL_EPARSE` for the out-of-declared-header case. Full ARJ
corpus, decoder, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 qualification remain open.

## BinHex header-length preflight — 2026-08-25

BinHex decoded-header processing previously read the data and resource fork
length fields before checking that the complete fixed header was present. A
truncated input could therefore derive limit arguments from uninitialized
decoded-buffer bytes before eventually returning malformed. The parser now
checks the complete header end before either length read and retains the
incomplete, non-cacheable `CL_EPARSE` result.

The main Check-suite regression is registered and the modified test object
compiles with the production GCC flags. An isolated production-linked GCC
harness passes 1/1 with the exact truncated-header reason. Complete BinHex
corpus, sanitizer/fault-injection, certified Linux x86-64, materialized
large-file, production-CVD/service, and Sonic1 qualification remain open.

## Explicit magic-scan ingress map admission — 2026-08-25

`cli_magic_scan()` previously dereferenced `ctx->engine`, `ctx->fmap`, and
layer cleanup state before it could classify an invalid direct parser call.
The ingress now returns `CL_ENULLARG` for a null context and marks a valid
context with no input fmap incomplete before returning `CL_EPARSE`. This
protects every explicitly dispatched parser, including legacy CryptFF, from
turning missing-layer state into a crash or an unreported clean result.

The main Check-suite regression is registered and the modified test object
compiles with production GCC flags. The source guards and capability manifest
pass, and the current-source production-linked ingress harness passes 1/1 with


## CPIO direct-entry context admission — 2026-08-25

The old, ODC, and newc/CRC CPIO entry points previously entered deadline and
fmap traversal with no context or no input-map classification. They now return
`CL_ENULLARG` for a null context and mark a recognized layer incomplete with
`CL_EPARSE` for a missing fmap before any format-specific reads.

The main Check-suite regression and source guards are registered. Current-source
CPIO object/test compilation and a production-linked focused execution remain
to be run; the existing CPIO numeric/CRC focused evidence remains separate.
Complete CPIO corpus, sanitizer, certified Linux x86-64, materialized
large-file, production-CVD/service, and Sonic1 qualification remain open.

## DMG retained stripe endian conversion — 2026-08-25

The bounded DMG path retains small decoded `blkx` metadata in an in-memory
stripe array and walks that array multiple times for ordering, geometry, and
reconstruction. The traversal helper was endian-converting the array on every
pass, so a valid stored or compressed stripe became an unrelated type and
coordinate after the first pass. The decoded-byte path now validates the
big-endian records and converts the retained array to host order exactly once;
streamed metadata continues to convert each record when it is read. A
production-linked valid stored-stripe DMG regression is registered to prove
that the reconstructed child reaches the nested matcher cleanly. Full DMG
corpus, sanitizer, materialized large-file, production-CVD, service, and
Sonic1 evidence remain required.

## MBR native-width partition coordinate admission — 2026-08-25

The MBR parser multiplied attacker-controlled LBA values by the caller's
sector size in primary and extended partition paths without checking native
width. It also subtracted the packed boot-record size before validating that a
caller-supplied sector size was large enough. The parser now uses checked LBA
scaling, LBA addition, boot-record offsets, and partition-range end bounds in
both scan and intersection walks, and rejects undersized sector sizes before
those calculations. A sparse production-linked map regression drives a valid
MBR header through a sector-size/LBA product above `SIZE_MAX` and verifies the
result is `CL_EFORMAT`, incomplete, and non-cacheable. Full MBR corpus,
sanitizer, certified Linux x86-64, materialized large-file, production-CVD,
service, and Sonic1 evidence remain required.
## Mach-O direct-entry admission — 2026-08-25

The thin and universal Mach-O parser entries now return `CL_ENULLARG` for a
null context. The metadata wrapper also exits before attempting to mark a null
context incomplete. Missing input maps remain explicit `CL_EPARSE` results with
sticky incomplete state. The dedicated production-linked `macho_map` case
covers both null-context and missing-map boundaries; executable corpus,
sanitizer, materialized large-file, production-CVD, service, and Sonic1
qualification remain open.

## ELF direct-entry admission — 2026-08-25

The ELF scanner and metadata-only parser now return `CL_ENULLARG` for null
contexts, while a recognized layer with no input fmap remains `CL_EPARSE` with
sticky incomplete state. The dedicated `elf_map` case covers both direct
entries; executable corpus, sanitizer, materialized large-file, production-CVD,
service, and Sonic1 qualification remain open.

## OLE2/XAR/RTF/JPEG boundary audit — 2026-08-25

The next pending parser-family review confirmed that the canonical source
contains the required fail-visible boundaries for four adjacent families. The
OLE2 XLM/BIFF path rejects chains and records that end before their declared
lengths and preserves `CL_EREAD` for an in-range sector callback failure. Its
isolated production-linked `ole2_xlm` regression passes 1/1 after the
canonical workbook fixture was materialized into the existing scratch
harness. The XAR TOC path requires an observed closing root element, the RTF
object path consumes the complete declared description while retaining only a
bounded display prefix, and JPEG fixed reads distinguish clipped ranges from
in-range callback failures. The isolated `xar_map`, `xar_metadata`,
`ole2_map`, `rtf_map`, and `jpeg_map` boundary cases pass.

The broader XAR synthetic TCase still produces three segmentation faults in
the mixed-generation production-linked binary. Those failures are not
attributed to current parser source because the harness combines current C
objects with stale ABI generations; a current full C build and isolated
current-source XAR execution remain required. Source guards now pin the XAR
root-close, RTF description-consumption, and JPEG read-status requirements.
Complete OLE2/XAR/RTF/media corpora, sanitizer, certified Linux x86-64,
materialized large-file, production-CVD/service, and Sonic1 qualification
remain open.

The Rust boundary review also confirmed that the authoritative source already
returns `CL_ENULLARG` before fmap lookup for OneNote, ALZ, and LHA/LZH. The
linked `rust_map` failure is from the stale Rust archive (`scan_onenote(NULL)`
returns the old generic error), not from the current source. An offline host
Rust 1.97.1 test attempt reached `openssl-sys` and stopped because this host
has no OpenSSL development metadata; no software was installed. Current C/Rust
rebuild and Rust, sanitizer, Linux x86-64, materialized large-file, and
Sonic1 evidence remain release gates.

## Matcher fixture and fail-visible boundary audit — 2026-08-25

The matcher unit fixture now provides a bounded synthetic fmap read callback
for direct-buffer tests instead of relying on a zeroed metadata stub. The
false-positive read-failure regression uses an explicit callback that fails an
in-range hash window and asserts `CL_EREAD`, the sticky
`fmap hash input could not be read completely` reason, and non-cacheability.
The no-generic-root scan regression now asserts the observed incomplete result
(`Executable metadata parsing ended before inspection completed`) rather than
calling a clean-looking result safe. The updated matcher object compiles with
GCC, and the production-linked focused run completed 34 of 35 checks with no
assertion failures. The remaining check raises a signal in `cl_engine_free()`
teardown after the hash case in the mixed-generation harness; this is retained
as an ABI-consistency qualification gap and is not attributed to the current
matcher source under the repository's mixed-ABI warning. A current full C
build is required before matcher production certification.

## 7-Zip SFX admission audit — 2026-08-25

The embedded 7-Zip SFX branch already requires the complete start header
before admitting a nested layer: weak six-byte magic is rejected as a
non-confirming candidate, clipped headers remain non-layers, and confirmed
in-range fmap callback failures return `CL_EREAD` with a sticky incomplete
reason. The existing read-failure regression is now registered in a dedicated
`7z_sfx` TCase; the production-linked focused run passes 1/1. Full 7-Zip/SFX
corpus, successful nested-member detection, sanitizer, certified Linux x86-64,
materialized large-file, production-CVD/service, and Sonic1 evidence remain
required.

## APM partition-read boundary audit — 2026-08-25

The APM parser's focused production-linked TCase now covers both recognized
missing-map admission and an in-range partition-entry fmap callback failure.
The two-case `apm_map` run passes 2/2; the callback failure preserves
`CL_EREAD`, the explicit partition-read incomplete reason, and
non-cacheability. Partition-count, table-boundary, coordinate-overflow,
corpus, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 qualification remain open.

## AutoIt focused-entry audit — 2026-08-25

The dedicated production-linked `autoit_map` TCase now covers the confirmed
entry boundary, malformed EA06 member admission, an expired shared deadline,
and both the version-byte and larger header-window read-failure paths. The
existing AutoIt source guards continue to pin bounded member traversal,
temporary/output accounting, timeout propagation, and non-cacheable incomplete
results. The focused production-linked run passes 4/4; the expired-timeout
oracle uses the shared `Heuristics.Limits.Exceeded.MaxScanTime` reason, matching
the repository-wide sticky timeout contract. A current full C build remains
required before certifying the parser family; corpus, sanitizer, certified
Linux x86-64, materialized large-file, production-CVD/service, and Sonic1
evidence remain open.
