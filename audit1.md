# Independent read-only audit of audit.md

**Review date:** 2026-08-16  
**Reviewed report:** audit.md, SHA-256 ce78ba7003031e6007bfe000c8ee6718175252ec5fed5e149ddda47617fb4e48  
**Review target:** the delivered source tree at /Volumes/512gbNVME/github-external/ClamAV  
**Method:** static, read-only source and evidence review; no build, scanner run, dependency installation, or network access  
**Excluded by request:** the previous contents of audit1.md were not read  

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
| F-03 | Source closed; exact regressions incomplete | Flate/LZW now require a decoder terminal state and discard partial output on error; benign-prefix-then-error and LZW regressions are absent. |
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

## Rust large-input staging — 2026-08-19

ALZ now parses directly through the bounded `FMapReader` `Read + Seek` adapter
and emits decompressed members in chunks into quota-accounted temporary spools.
OneNote still stages the root through the shared temporary quota and parses a
disk-backed `mmap` view required by its third-party slice API. The prior 256
MiB admission cap was removed; failed reads, temporary reservation, mapping,
parser, decoder, and extracted-member scans remain fail-visible. This removes
the artificial ALZ cap and member-vector materialization, but does not by
itself prove third-party 32 GiB memory, sanitizer, or supported-build
qualification.

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

## Force-to-disk nested fmap accounting — 2026-08-19

Nested fmap scans forced to disk now reserve the complete staged range against
`MaxTemporarySize` until the child scan and cleanup finish. Temporary-file
creation, close, removal, and partial-copy failures remain fail-visible, and
the child uses the already-held reservation rather than double-counting the
same bytes. Compiled force-to-disk fault-injection and Linux/Sonic1 quota
qualification remain open.

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
spool is retained only as one decoded `mish` metadata block, with the existing
64 MiB per-block cap, strict terminal `END` validation, and fail-visible
malformed/unsupported handling. Reconstructed partitions remain quota-charged
while their nested scans run, and retained XML copies use bounded writes.

This closes the specific DMG root-XML and whole-text-node materialization gap.
Real Apple DMG corpus, large metadata, sanitizer, and supported-build Sonic1
qualification remain release gates; multi-segment DMGs remain explicit
unsupported input.

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
