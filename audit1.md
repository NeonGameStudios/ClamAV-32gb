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

## AutoIt bounded encrypted input and EA05 output — 2026-08-20

EA05 and EA06 compressed members decrypt their fmap input through a bounded
64 KiB window with preserved MT/LAME keystream state. EA05 decoded output now
uses a 32 KiB back-reference history window and a 64 KiB pending-write buffer
to stream into a temporary file; stored EA05 members are decrypted in chunks
and use the same quota-accounted temporary path. The EA05 format still has
32-bit size fields, so output above 4 GiB remains an explicit unsupported
boundary. EA06 script decompilation still retains a random-access decoded
buffer and remains unsupported above the individual-allocation ceiling.

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
existing reservation to the reservation-aware child scan. XLM's optional
extracted-image path now reserves its declared image bytes before writing and
uses the same ownership transfer through nested scanning; write and quota
failures remain sticky incomplete results.

Source guards and `git diff --check` are the current local evidence. Compiled
DMG/XLM execution, sanitizer coverage, real document corpus testing, and
supported-build Sonic1 qualification remain open release gates.

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
preserved; unsupported graphs such as BCJ2 remain fail-visible on the streaming
path.

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
