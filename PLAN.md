# ClamAV 32 GiB Full-Scan Completion Plan

For step-by-step execution and bounded Luna 5.6 task prompts, start with the
[execution roadmap](docs/32gb-luna-execution-roadmap.md). PLAN.md remains the
authoritative release contract; the execution guide does not certify completion.

## Summary

The fork is ClamAV 1.5.3 with a mostly C scanning engine in `libclamav`, several Rust parsers, and thin front ends for `clamscan`, `clamd`, `clamdscan`, milter, and on-access scanning. Those front ends largely converge on the same descriptor/fmap pipeline, so the existing 64-bit raw-scanning foundation is strong; the unfinished work is cumulative accounting, resource admission, complete parser coverage, and reliable proof of completeness.

Use [ClamAV-32gb](<repository-root>) as the canonical Git repository. The release contract is:

- Accept every input from zero through exactly 32 GiB across modern library APIs, CLI/stdin, clamd path/FILDES/INSTREAM command families, clamdscan modes, milter, and on-access scanning.
- Fully inspect every structurally confirmed layer handled by an enabled parser, subject to the shared 64 GiB logical, file-count, recursion, temporary-space, and four-hour limits.
- Always run the outer raw matchers unless a detection or critical failure legitimately terminates the scan.
- Never report or cache `OK` when a required parser, matcher, decoder, or signature ABI was skipped.
- Treat unsupported encryption/codecs and inherent format restrictions as explicit incomplete results.
- Treat disproven weak embedded-magic candidates as “not a layer,” allowing the completed raw scan to remain authoritative.

## Defaults and Interfaces

The certified Linux x86-64 defaults will be:

| Setting | Default/ceiling |
|---|---:|
| `MaxFileSize`, `StreamMaxLength`, `OnAccessMaxFileSize` | 32 GiB inclusive |
| `MaxScanSize` | 64 GiB logical content |
| New `MaxMatcherWork` | 256 GiB across raw and normalized representations |
| New `MaxTemporarySize` | 64 GiB |
| New `MaxContiguousSize`, `PCREMaxFileSize` | 32 GiB |
| HTML/script/embedded-PE/ZIP-recognition size gates | 32 GiB |
| `MaxScanTime` | 14,400,000 ms |
| `MaxThreads`, `OnAccessMaxThreads` | 1 |
| `MaxQueue` | 2 |
| `AlertExceedsMax` | Yes |

`MaxScanSize` will count the root and each extracted/decompressed logical object once. Retyped or normalized views inherit the logical object identity and charge `MaxMatcherWork` instead, preventing a 32 GiB root from exhausting its entire deep-scan budget before its first child.

Add versioned, backward-compatible interfaces:

- `cl_scanfile_ex2`, `cl_scandesc_ex2`, and `cl_scanmap_ex2` return an optional opaque `cl_scan_report_t`.
- Report queries and JSON serialization expose the verdict, overall completion, parser/detector operations, logical and matcher bytes, limits, elapsed time, peak contiguous memory, and peak temporary storage.
- Completion states distinguish complete, detection-terminated, limit-incomplete, unsupported, malformed-confirmed, resource failure, and application abort. Existing verdicts and legacy APIs retain their behavior.
- Add `CL_ERESOURCE` for admission failures; incomplete scans continue returning specific `CL_EMAX*`, `CL_ETIMEOUT`, or parser errors when appropriate.
- `clamscan --report-json=<path>` emits versioned JSONL while preserving ordinary console output.
- Add opt-in clamd commands `SCANREPORT`, `CONTSCANREPORT`, `MULTISCANREPORT`, `ALLMATCHSCANREPORT`, `FILDESREPORT`, and `INSTREAMREPORT`. Responses use length-prefixed JSON frames followed by a zero frame; legacy commands remain unchanged.
- Add bytecode ABI v2 with 64-bit file size, offsets, seek/read/search results, and matcher bridges. ABI v1 remains supported on representable layers; an applicable v1-only module above 4 GiB is explicitly incomplete until migrated.

## Implementation Sequence

1. **Freeze and correct the baseline**

   - Preserve the current uncommitted Sonic1 report in the canonical repository, bind it to a source-manifest digest, and reconcile stale commit references.
   - Regenerate the size/type inventory and correct contradictory PCRE documentation: qualifying Linux x86-64 builds support a 32 GiB subject, while other builds do not qualify.
   - Convert the inventory into a checked capability manifest covering every ingress, parser dispatch branch, matcher, optional build feature, and deliberate unsupported feature.
   - Repair the existing service gate before relying on it: bind every input by size/type/hash/oracle, require exact outcomes, honor configured deadlines, and stop accepting arbitrary exit 0/1/2 as success.

2. **Build the shared accounting and resource layer**

   - Add separate counters for logical content, matcher work, contiguous residency, temporary bytes, files, recursion, and time.
   - Introduce common bounded reader and spool abstractions. Readers use checked 64-bit offsets and borrow/release fmap windows; spools enforce logical/temp quotas and expose completed output as child fmaps.
   - Keep the global 1 GiB individual-allocation guard. PCRE is the sole default path allowed to borrow an entire 32 GiB contiguous subject.
   - Pin the PCRE subject only during matching, release all unlocked fmap pages immediately afterward, and assert that resident memory falls before deep parsing begins.
   - Refuse `clamd` startup unless the build has all certified features, effective available/cgroup memory is at least 48 GiB, temporary storage has at least 68 GiB free, and required file/address limits are representable. Lower configured ceilings scale these checks downward.
   - Keep temporary staging on disk, not tmpfs. Track the INSTREAM source plus parser spools against the shared 64 GiB temporary budget.

3. **Make every ingress obey the same contract**

   - Preflight known-size path/fd inputs before scanning; stop unknown-length stdin and INSTREAM at byte 32 GiB + 1 and remove partial staging.
   - Preserve active INSTREAM’s complete-file staging and descriptor scan, but remove or repair the dormant truncating legacy STREAM implementation.
   - Make `MULTISCAN` operate sequentially when `MaxThreads=1` instead of rejecting the request.
   - Make milter process one request at a time and replace the 64 MiB MIME materialization path with the streaming mail implementation below. Its final action must distinguish malware from incomplete/resource rejection.
   - Set on-access to 32 GiB and deny permission events for any incomplete, timeout, resource, or parser result. Monitoring-only events may log and allow, but must never be labeled clean.
   - Route all front ends through the same structured report and assert result parity between path, descriptor, fmap, FILDES, and staged-stream forms.

4. **Complete detector and parser families**

   - **PCRE and native signatures:** qualify full-subject PCRE with production CVDs and custom logical signatures; retain match/backtracking limits, with exhaustion reported as incomplete. Cover hash, AC/BM, logical, YARA, and exact-offset matching through the final byte.
   - **Bytecode:** implement ABI v2 in the engine and `clambc`, migrate test/custom signatures, and qualify official bytecode behavior. Do not emulate arbitrary v1 whole-file semantics with repeated 4 GiB windows.
   - **ZIP/archive/executable:** use ZIP central-directory values for masked local fields where authoritative; unsupported encryption without credentials remains incomplete. Add streaming 7-Zip solid-folder extraction with 64-bit offsets, then convert NSIS, AutoIt, EGG, PE unpackers, and other whole-buffer paths to bounded spools. Preserve format-defined 32-bit RVAs while widening containing-file coordinates.
   - **Rust parsers:** expose an fmap-backed Rust `Read + Seek` adapter. Convert LHA/LZH first, then ALZ and OneNote, and spool extracted members instead of returning whole-member vectors.
   - **Documents and normalization:** replace mail’s retained line list with incremental MIME state and attachment spooling. Convert PDF object/stream decoding, XDP, HWPML, XAR, and DMG metadata to streaming readers. HTML and script normalization already have chunked foundations; remove independent small caps, charge generated views to matcher work, and require complete output.
   - **Remaining enabled parsers:** audit RAR, ISO/UDF/HFS+, OLE/VBA, filesystems, media/images, fuzzy hashing, and third-party decoders against the same reader/spool/report contract. Every current dispatch branch must either complete valid content within shared limits or have a documented unsupported-feature result.
   - **Embedded recognition:** introduce candidate/confirmed/rejected states. Weak ZIP, 7-Zip, InstallShield, or PE magic cannot taint the root until minimum structure is validated; a confirmed malformed or unsupported layer remains incomplete. This directly addresses the M4V and EXE observations without weakening fail-closed behavior.

5. **Activate the defaults only after qualification**

   - Keep the new behavior behind explicit development configuration until all enabled-parser and ingress gates pass.
   - Flip the fork defaults to the table above in the final release commit, update samples/man pages/API comments, and emit the compiled capability manifest at startup.
   - Do not claim macOS, AArch64, deprecated whole-buffer callbacks above 1 GiB, or bytecode v1 above 4 GiB as qualified.

## Test and Acceptance Plan

- **Per commit:** run C/Rust/unit/CTest suites; arithmetic tests at every cap; fault-injected reads, writes, seeks, allocation, decoder termination, callbacks, cache behavior, and report serialization. Cover all library APIs and clamdscan option combinations with exact exit/verdict/no-`OK` assertions.
- **Nightly on Sonic1:** use materialized 64 MiB–4 GiB valid, malformed, false-candidate, unsupported, and limit-boundary fixtures for every enabled parser family. Run Release and ASan/UBSan, warm/cold cache, production CVDs plus custom signature families, and compare normalized reports.
- **Weekly/release candidate:** use manifest-bound, fully allocated exact-32-GiB and 32-GiB+1 fixtures. Exercise library path/fd/fmap, clamscan file/stdin, every clamd command family, clamdscan stream/fdpass/multiscan combinations, milter, and privileged fanotify on-access.
- Include exact-tail PCRE, bytecode-v2, raw, archive-member, MIME-attachment, and embedded-PE markers. Detection tests require the expected signature and offset; bare `FOUND` is insufficient because limit heuristics also use it.
- Every parser dispatch branch receives a 32 GiB outer-coordinate fixture. Each implementation family also receives a fully materialized exact-edge case; smaller homologous fixtures cover exhaustive malformed and decoder-state combinations.
- Acceptance requires peak process RSS no higher than 40 GiB during PCRE, post-PCRE RSS below 12 GiB before deep parsing, temporary usage no higher than 64 GiB, no swap/OOM/sanitizer diagnostics, completion within four hours, daemon health after each case, and no leaked temporary files, sockets, PIDs, or processes.
- Test two simultaneous requests to prove the second remains queued and does not begin staging or reserve resources while the single worker is occupied.
- A clean result is valid only with `CL_SUCCESS`, a clean/trusted verdict, report completion `COMPLETE`, and no required operation skipped. Incomplete results must remain non-cacheable. On-access must deny them.
- Run a Sonic1 canary with current production CVDs and authorized real files, recording per-parser completion, limits, latency, RSS/PSS/VAS, page faults, I/O, temporary peaks, and report hashes before declaring production readiness.

## Assumptions

- GiB values are binary; exactly 32 GiB is accepted and 32 GiB + 1 is rejected.
- The 50 GB test file remains intentionally outside scope.
- The 64 GiB logical budget permits a 32 GiB root plus up to 32 GiB of extracted content; larger expansion is a correct explicit limit result.
- Encryption without a usable key, unsupported codecs, and inherent format-width restrictions are not considered successful deep scans.
- Linux x86-64 is the only first-release production platform.
- Validation will reuse a pinned Sonic1 container and existing toolchain; no new host software installation is required.
