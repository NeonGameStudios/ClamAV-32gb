# ClamAV Large-File Support

Status: Review-ready 32 GiB raw-scan release candidate; production acceptance
pending

## GIF bounded overlay corpus qualification — 2026-08-25

The current-source production-linked GCC `gif` case passes 5/5, and the
isolated `gif_corpus` case passes 1/1. It uses a valid minimal GIF root with a
bounded child after the GIF trailer; the root does not begin with `MZP`, and
the exact `GIF.Member.MZ.UNOFFICIAL` alert is reached through the broken-media
overlay handoff. Full GIF/image corpus, sanitizer, certified Linux x86-64,
materialized large-file, production-CVD/service, Sonic1, and release
qualification remain open.

## NSIS member-table corpus qualification — 2026-08-25

The current-source production-linked GCC `nulsft` case passes 4/4, and the
isolated `nulsft_corpus` case passes 1/1. It constructs a valid fixed-header
NSIS archive with an uncompressed 64-byte member beginning with `MZP`; the
exact `NSIS.Member.MZ.UNOFFICIAL` alert is reached only after NSIS member
extraction, while the NSIS root does not begin with `MZP`. Full NSIS/SFX and
decoder corpus, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, Sonic1, and release qualification remain open.

## PNG materialized overlay corpus qualification — 2026-08-25

The current-source production-linked GCC `png` case passes 5/5, and the
isolated `png_corpus` case passes 1/1. It starts from canonical materialized
`logo.png`, appends a bounded 64-byte child beginning with `MZP`, and reaches
the exact `PNG.Member.MZ.UNOFFICIAL` alert through the valid PNG IEND-overlay
handoff. The PNG root does not begin with `MZP`. Full PNG/image corpus,
sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, Sonic1, and release qualification remain open.

## TAR materialized corpus qualification — 2026-08-25

The current-source production-linked GCC `tar` case passes 6/6, and the
isolated `tar_corpus` case passes 1/1. It decompresses materialized
`clam.tar.gz` and `clam.exe_and_mail.tar.gz` to TAR roots whose bytes do not
begin with `MZP`; each exact offset-0 child alert is reached through TAR
member traversal. The focused GNU base-256/PAX signature-loader cases remain
limited by the mixed harness's `cl_load()`/`CL_EMALFDB` setup. Full TAR corpus,
sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, Sonic1, and release qualification remain open.

## PE packer corpus qualification — 2026-08-25

The current-source production-linked GCC `pe` case passes 11/11 and `pe_map`
passes 2/2. The isolated `pe_corpus` case passes 1/1 across materialized
`clam-fsg.exe` and `clam-upx.exe`; neither outer PE root begins with `MZP`,
while the exact offset-0 child matcher reports `Pe.Member.MZ.UNOFFICIAL`
after unpacking. Full PE packer/resource corpus, sanitizer, certified Linux
x86-64, materialized large-file, production-CVD/service, Sonic1, and release
qualification remain open.

## CPIO materialized corpus qualification — 2026-08-25

The authoritative current-source production-linked GCC `cpio` TCase passes
1/1 across four materialized 1 KiB fixtures: old binary big-endian, old binary
little-endian, NEWC, and ODC. The outer CPIO bytes do not begin with `MZP`;
each exact offset-0 `MZP` alert is therefore reached through member extraction
and nested matcher handoff. The existing `cpio_map` and `cpio_numeric` cases
pass 4/4 and 1/1.

The older CRC and neighboring TAR signature-loader cases currently stop in
their `cl_load()` setup with `CL_EMALFDB` in the mixed ABI harness before
parser execution. That harness limitation is recorded separately from the
successful direct-matcher corpus oracle. Complete CPIO corpus, CRC loader
harness, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, Sonic1, and release qualification remain open.

## PDF decoder and materialized corpus qualification — 2026-08-25

The streaming Flate and LZW resynchronization paths now preserve the original
decode `CL_EPARSE` when a successful fallback-line search reaches EOF without
finding another compressed stream. This prevents malformed filtered data from
being reported as clean. The current-source production-linked GCC `pdf` TCase
passes 13/13, and the isolated `pdf_corpus` TCase passes 1/1 for materialized
`clam.pdf`; its exact offset-0 child `MZP` alert is reached after extraction,
not by the PDF root. Full PDF corpus, encrypted large-stream, sanitizer,
certified Linux x86-64, production-CVD/service, Sonic1, and release
qualification remain open.

## Current qualification contract

The service/release gate now requires an external eight-column TSV oracle in
addition to the four fixture paths. The file must contain this header and one
row for each role: `production`, `materialized`, `expansion`, and `edge`:

```text
role\texpected_size\texpected_sha256\texpected_exit\texpected_completion\texpected_signature\texpected_offset\texpected_type
```

The oracle binds each materialized input by exact byte count, SHA-256, and
top-level `CL_TYPE_*` value. It also requires the expected exit status and
structured-report completion state; detection rows must provide the exact
signature token and engine offset, while non-detection rows use `-` for the
signature and offset. The workflow input is `qualification_oracle`. A gate run
without this manifest is rejected, so a bare `FOUND` line or arbitrary exit
code cannot be presented as production evidence. The gate's
`oracle-binding.txt` records the expected status, completion, signature,
offset, and type alongside each verified size and hash.

The direct framed clamd report probe uses the same strict oracle parser as the
post-run workload verifier. It therefore rejects malformed role rows,
signature/offset pairings, completion values, file types, or expected exits
before a report frame can be recorded as qualification evidence.

Before serializing an existing clamd report, the final wire boundary also
reconciles any later non-success worker, close, aggregation, or detection
status through the post-scan-failure contract. A report that was complete
before that failure is converted to an explicit non-clean result.

The service gate also snapshots every regular file in the production and edge
database directories as a sorted relative-path/size/SHA-256 manifest before
starting clamd. The directories must be distinct, symlink-free, and non-empty;
the manifests are recorded with their hashes in `oracle-binding.txt` and are
recomputed after the final workload. A database replacement or mutation during
qualification fails the gate rather than leaving the workload associated with
an unrecorded signature set.

Large-file `clamd` configurations now perform the same admission decision at
startup on Linux: effective `/proc/meminfo` and cgroup headroom must meet the
scaled memory requirement, the configured temporary directory must have the
scaled free-space requirement, and the process must expose 64-bit address and
file-coordinate types. Historical small-file configurations keep their normal
startup path. A failed admission is logged and the daemon does not open its
scan sockets.

Structured clamd report producers and consumers now share a 16 MiB payload
ceiling. If report serialization would exceed that bound or its transport
buffer cannot be allocated, clamd sends a small schema-shaped
`RESOURCE_FAILURE` report with `skipped_operations` set instead of a clean
fallback; clients reject any larger received frame and require a successful
status on `COMPLETE`. Detection reports also include the optional native-width
`last_alert_offset` when the retained alert is a root-object AC, BM, or PCRE
matcher result. Structured qualification rejects detection evidence that
omits or mismatches the oracle offset; parser, hash, callback, and child-layer
alerts remain offset-less rather than publishing an unverified coordinate.

The shared framed-report parser now returns the validated numeric `cl_error_t`
for incomplete reports. On-access callers preserve timeout, resource, limit,
and parser statuses instead of replacing them with a generic parse error, and
milter logging records the same status while still refusing a clean action.
Detection remains authoritative when a multi-frame response contains both a
detection and an incomplete sibling; contradictory clean/error combinations
are rejected. Compiled multi-frame and exact milter-action qualification
remains a release gate.

Report producers also normalize a sticky incomplete context before
serialization: a legacy `CL_SUCCESS`/`CL_VERIFIED` status becomes the most
specific available non-clean status (`CL_ERESOURCE`, `CL_BREAK`, `CL_EUNPACK`,
`CL_EPARSE`, or `CL_ERROR`). Daemon unsupported-file skips explicitly use
`CL_EUNPACK`, so the framed parser never receives an `UNSUPPORTED` or resource
completion paired with a clean numeric status. Compiled daemon skip and wire
qualification remains a release gate.

The clamd INSTREAM receiver also fails closed on staging writes: a failed
temporary-file write stops the stream immediately, emits one protocol-matched
error, and removes the partial descriptor without dispatching it to the
scanner. Quota failures use the same single-response rule.

The deprecated legacy `STREAM` helper is now an explicit fail-visible stub;
it cannot bind a socket, truncate input at a legacy limit, or scan a partial
prefix. `INSTREAM` is the only supported staged stream path.

The first authorized real-file Sonic1 run is documented in
[`largefile-realfile-sonic1-20260818.md`](largefile-realfile-sonic1-20260818.md).
It confirms that the fork's 32 GiB ceiling is an explicit configuration
ceiling, while the current runtime defaults remain 100 MiB per file and
400 MiB per scan.

The completed follow-up run qualifies raw top-level scanning for four mounted
files below 32 GiB on the rebuilt 64-bit Sonic1 binary. The run used the
production CVD mirror, `--max-filesize=32G`, `--max-scansize=32G`, a 15-minute
scan-time budget, and `--scan-archive=no`; the 2.31 GiB PE-shaped input also
used `--scan-pe=no` after its embedded InstallShield metadata produced a
fail-visible parser error. The 50 GiB input remained fail-visible as
`Heuristics.Limits.Exceeded.MaxFileSize`. These results are raw-scan evidence,
not deep-parser qualification; the detailed timings and diagnostics are in
the Sonic1 report.

LHA uses the bounded Rust `FMapReader` directly. ALZ now parses through the
same `Read + Seek` adapter and delivers decompressed members in chunks to
quota-accounted temporary spools. OneNote stages its root through the shared
temporary quota and exposes a disk-backed `mmap` view to its third-party slice
API, but its modern and legacy attachment callbacks now borrow member bytes
directly into the scanner spool instead of creating an intermediate whole-member
`Vec<u8>`. Bounded-read, temporary-reservation, mapping, parser, decoder, and
extracted-member scan failures remain explicit incomplete results. ALZ stored,
deflate, and BZip2 members must also produce exactly their declared
uncompressed size before the child scan starts; a mismatch discards the output
and leaves the archive incomplete. The legacy
reader path is not subject to the modern parser's 256 MiB whole-input cap; the
third-party modern parser still retains that explicit cap because its pinned
API accepts only a borrowed whole-file slice. Third-party parser memory and
large-corpus qualification remain release gates.

The optional UnRAR path now treats incomplete archive comments and bad-CRC
member extraction as incomplete rather than scanning a partial representation.
Before a member is inspected, the extractor must materialize a regular file
whose size matches the declared unpacked size; the validated descriptor is
then scanned while its declared temporary reservation remains charged. RAR
corpus and backend-enabled build qualification remain release gates.

The 7-Zip path likewise validates each successfully decoded member twice before
dispatching it to nested scanning: the decoder-produced byte count and the
materialized regular file's `st_size` must both equal the archive-declared
member size. A mismatch is an incomplete `CL_EUNPACK` result and the partial
output is never scanned. The current-source production-linked GCC corpus case
also passes against `clam.7z`, whose outer bytes contain no `MZP` marker while
the extracted member reaches an exact nested marker. 7-Zip parser-corpus and
supported-build qualification remain release gates.

Local macOS validation has begun with a native host-preflight and runtime gate;
its first result is documented in
[`largefile-macos-20260818.md`](largefile-macos-20260818.md). The current
execution context exposes 16 GiB rather than the expected 64 GiB and lacks
CMake/Ninja, so the gate correctly stopped before starting a 32 GiB scan.
Sonic1 Linux evidence must not be substituted for this macOS qualification.

## Target

LargeFile 1.0 targets direct raw scanning of inputs from 0 through 32 GiB and
bounded inspection of audited containers on supported 64-bit x86-64/AMD64 and
AArch64/ARM64 builds. Linux x86-64 is the initial release-certification target;
builds on other accepted 64-bit platforms are compile/test coverage until they
receive their own runtime evidence. The implementation must not silently
truncate file positions, object sizes, scan counters, match positions, hashes,
or parser state.

This is a bounded large-file capability, not an unlimited-resource mode. A
parser or matching subsystem that cannot safely process an object must either
continue with the safe raw scan path and report the limitation, or fail the
scan visibly. It must never produce an unqualified clean result for data it
did not inspect.

## Coordinate and type rules

Use explicit semantic types rather than widening every integer:

- `cli_fileoff_t` / `uint64_t`: absolute positions within the input or a
  containing object.
- `size_t`: host-memory buffer lengths and indexes, after checked conversion
  from a file/object size.
- Fixed-width integers: fields whose width is defined by a file format,
  database format, bytecode ABI, or serialized API.
- Checked helpers: addition, range containment, multiplication, and conversion
  between file coordinates and memory lengths.

The audit must distinguish format-defined 32-bit values from runtime
coordinates. For example, a PE RVA can remain 32-bit while the containing-file
offset used to locate that PE must not be limited to 32 bits.

## Current ClamAV-32gb fork status

The current fork implementation is anchored at commit
`5becea1236d466ee21f9bd5d3bcd0595ebc1460b`; documentation and workflow
follow-up is recorded separately at `4118580283da65f01cfa0822c848ac13568c1724`.
The detailed current record is
[`32gb-status.md`](../32gb-status.md), which supersedes the older baseline
measurements and handoff wording below while retaining them as provenance.

Since the historical one-worker baseline, the fork has passed direct Release
and ASan/UBSan raw-file validation through the exact 32 GiB boundary,
eight-worker exact-edge FILDES and INSTREAM daemon checks, representative
parser/archive fixtures, and eight concurrent one-GiB nested-archive scans.
The latest daemon run passed eight synchronized `clamdscan --fdpass` clients
per build with `MaxThreads 8`, `MaxQueue 16`, and 32-GiB limits; all sixteen
private-marker scans returned the expected detection status, with empty
post-shutdown temporary directories and verified input/log manifests. The
remote evidence is preserved at
`/work/evidence/clamd-nested-1g-thread8-clean-final-release-20260814` and
`/work/evidence/clamd-nested-1g-thread8-clean-final-sanitizer-20260814`.

The current Release and final ASan/UBSan builds also passed a host-page-cache
drop followed by identical sparse 32-GiB exact-edge raw scans. Each detected
the marker at offset 34,359,738,304, returned exit 1, emitted no diagnostics,
and cleaned temporary storage to 4,096 bytes. Release took 1:58.49 with
100,948 KiB peak RSS; sanitizer took 3:41.08 with 137,068 KiB peak RSS. This
closes a production-scale cold-cache raw-edge gap, but remains private-marker
workload evidence rather than production-CVD qualification. Evidence is
preserved at `/work/evidence/cold-cache-exact-edge-final-release-20260814` and
`/work/evidence/cold-cache-exact-edge-final-sanitizer-20260814`.

A dedicated final ASan/UBSan public-format probe also loaded the six signed
repository test CVD fixtures with the repository verification certificate and
scanned the nested `other_scanfiles` corpus after a host page-cache drop. Cold
and hot output matched the Release hash for all 46 inputs; both returned the
expected status 2 solely for the standalone split-ZIP segment and emitted no
CVD-load or sanitizer/runtime diagnostic. This is signed test-CVD evidence,
not production-CVD qualification. Evidence is preserved at
`/work/evidence/public-cvd-cold-hot-sanitizer-20260814-run1`.

An independent final ASan/UBSan exact-edge `clamscan` run then combined the
six signed test CVDs with the private marker database. It found the marker at
engine offset `34359738304` in the exact 34,359,738,368-byte fixture, returned
exit 1 in 213.450802 seconds, verified and loaded all six CVDs, emitted no
sanitizer or database-load diagnostic, and left temporary storage empty. This
is combined signed-test-CVD plus private-marker evidence, not production-CVD
qualification. Evidence is preserved at
`/work/evidence/cvd-public-exact-edge-sanitizer-20260814-run2`.

The final Release counterpart used the identical combined database and
exact-edge fixture. It found the same marker at offset `34359738304` in
118.816549 seconds, with the same scanner hash, all six CVDs verified and
loaded, no database-load diagnostic, and an empty temporary directory.
Evidence is preserved at
`/work/evidence/cvd-public-exact-edge-release-20260814-run1`.

A final Release daemon-side parity run used the same exact-edge fixture
through an isolated `clamd`/`clamdscan --fdpass` UNIX socket. Its manifest
contained the six signed test CVDs, signed CDIFF inputs, and private marker
NDB; `clamd` reported `Loaded 45 signatures` and the configured 32-GiB limits.
The daemon detected the marker at fixture offset `34359738304`, returned exit 1
in 142.531045 seconds, emitted no stderr or database-load diagnostic, and
shut down cleanly with no socket, PID file, temporary files, or active
validation daemon. This is signed-test-CVD plus private-marker daemon
evidence, not production-CVD qualification. Evidence is preserved at
`/work/evidence/cvd-clamd-public-exact-edge-release-20260814-run2`.

The matching final ASan/UBSan daemon run used the same combined database and
fixture. `clamd` reported `Loaded 45 signatures` and recorded the marker at
engine offset `34359738304`; `clamdscan --fdpass` returned exit 1 in
235.147097 seconds. No sanitizer, runtime, or database-load diagnostic
appeared, and shutdown left no socket, PID file, temporary files, or active
validation daemon. This is signed-test-CVD plus private-marker evidence, not
production-CVD qualification. Evidence is preserved at
`/work/evidence/cvd-clamd-public-exact-edge-sanitizer-20260814-run1`.

A bounded POSIX TAR and GZIP/TAR cross-parser limit matrix passed 532/532
assertions for each final Release and ASan/UBSan build across 52 result records.
Late-marker MaxScanSize, MaxFiles, and MaxRecursion cases returned explicit
incomplete results, alert-enabled runs surfaced the corresponding limit
detections, and `--allmatch` retained an early marker while reporting a later
MaxFiles or MaxRecursion limit. Both builds produced the same normalized
semantic-results hash
`7e62acf9da68d3b406c91f8b74ce8cc7e27c02ea4647b2245e8ac98c28be64bf`, with no
database, sanitizer, runtime, or temporary-file diagnostics. This narrows but
does not close the generic legacy-parser audit or production-CVD qualification;
some early-marker MaxScanSize fixtures also hit top-level container-size
preflight and are boundary checks rather than precedence claims. Evidence is
preserved at `/work/evidence/cross-parser-limit-matrix-release-20260814-run2`
and `/work/evidence/cross-parser-limit-matrix-sanitizer-20260814-run2`.

A follow-up compressed-ZIP matrix passed 178/178 assertions per build across 16
authoritative records. It covered late-member MaxScanSize, early detection
precedence, MaxFiles continuation, and nested MaxRecursion; `--allmatch`
retained early markers while exposing later limit warnings/alerts. Both builds
produced the same semantic-results hash
`a30c03d8b05bdeec9da6fdfe030e53f1b3b20e9d0644bd7b95b12ef36b66d00d`, with no
database, sanitizer, runtime, or temporary-file diagnostics. This strengthens
ZIP-family evidence but does not close the generic legacy-parser audit or
production-CVD qualification. Initial fixture and serialization diagnostics are
preserved outside the authoritative `out/` records. Evidence is preserved at
`/work/evidence/cross-parser-limit-matrix-zip-release-20260814-run1` and
`/work/evidence/cross-parser-limit-matrix-zip-sanitizer-20260814-run1`.

The same cache-drop procedure passed synchronized two- and four-worker raw
edge scans in both builds: all twelve clients detected the marker at the exact
engine offset, with zero temporary files and no sanitizer diagnostics. Summed
per-worker peak RSS upper bounds were 200,828/272,796 KiB at two workers and
402,616/543,280 KiB at four workers (Release/sanitizer). Evidence is preserved
at `/work/evidence/concurrency-2way-exact-edge-final-release-20260814`,
`/work/evidence/concurrency-2way-exact-edge-final-sanitizer-20260814`,
`/work/evidence/concurrency-4way-exact-edge-final-release-20260814`, and
`/work/evidence/concurrency-4way-exact-edge-final-sanitizer-20260814`.

The configured final Release CTest `libclamav` target also passed 100% in
27.07 seconds with zero stderr, exercising the checked-in synthetic limit and
ZIP-boundary regressions in the same fixture and certificate environment used
by CTest. This confirms execution of the regression suite but does not close
the broader generic false-clean or production-database gaps. Evidence is
preserved at `/work/evidence/correctness-libclamav-final-release-20260814`.

The same final source commit was rebuilt with ASan/UBSan and `ENABLE_TESTS=ON`;
the full build generated 390 decrypted fixture files before the configured
`libclamav` CTest target ran. It passed 100% in 32.07 seconds with zero stderr
and no AddressSanitizer, UndefinedBehaviorSanitizer, or runtime-error
signatures. Evidence hashes are preserved at
`/work/evidence/correctness-libclamav-final-sanitizer-20260814-v3`.

The same final ASan/UBSan build also passed the configured `clamd` CTest target
in 32.35 seconds with 100% tests passed, zero stderr, and no sanitizer
diagnostics. Evidence hashes are preserved at
`/work/evidence/correctness-clamd-final-sanitizer-20260814`.

It also passed the remaining committed-source core-tool CTest targets—
`clamav_milter_quota`, `clamscan`, `freshclam`, and `sigtool`—4/4 in 51.46
seconds. The timed run reached 346,644 KiB maximum RSS, returned CTest exit 0,
had no sanitizer/runtime diagnostics, passed evidence-hash verification, and
left no matching test processes. The corrected validation record is preserved
at `/work/evidence/correctness-core-tools-final-sanitizer-20260814/post-validation.txt`;
the initial wrapper false negative is explained there and the underlying CTest
output remains in the same evidence directory.

The final sanitizer build was also reconfigured with `ENABLE_MILTER=ON`; the
`clamav-milter` target built with ASan/UBSan and `clamav_milter_quota` passed
1/1. Its exact-edge libmilter harness reached 34,091,302,912 of the expected
34,359,738,316 body bytes before sanitizer `clamd` reached 43,615,092 KiB RSS,
so the run was stopped for safety and is explicitly not-qualified. A first
109-byte Unix-socket path failure was corrected with a 62-byte test root.
Memory recovered cleanly and no test processes remained. Evidence, hashes,
and resource samples are preserved at
`/work/evidence/milter-working-tree-harness-final-sanitizer-20260814`; the
Release working-tree exact-edge pass remains separate and does not close this
sanitizer resource gap.

For comparison, the local follow-up cap files were tested only in an isolated
ASan/UBSan checkout and then restored: a real 4-GiB milter wire completed with
exactly 4,294,967,244 body bytes, returned the expected `r` result, and logged
`Heuristics.Limits.Exceeded.MailMaterialization`. The timed harness reached
380,048 KiB maximum RSS in 19.43 seconds, left a 172 KiB runtime footprint,
and emitted no sanitizer diagnostics. This remains working-tree-only evidence
until the cap changes are committed and retested from the fork revision.
Evidence and source hashes are preserved at
`/work/evidence/milter-working-tree-cap-sanitizer-20260814`.

The same isolated cap checkout then passed the literal 32-GiB milter boundary:
the harness sent exactly 34,359,738,316 body bytes for a
34,359,738,368-byte message, returned `r`, and logged
`Heuristics.Limits.Exceeded.MailMaterialization FOUND`. Under ASan/UBSan the
timed run completed in 2:39.70 with 380,124 KiB maximum RSS and zero swaps;
the preserved runtime root was 172 KiB after shutdown, with no temporary files
or sanitizer/runtime diagnostics. Evidence and checksums are preserved at
`/work/evidence/milter-working-tree-cap-sanitizer-20260814/exact-edge`.
The source was restored to committed `5becea1` and its sanitizer milter target
was rebuilt afterward, so this is still working-tree-only follow-up evidence,
not committed-fork qualification.

The same isolated cap checkout, with the local public-API regression additions,
then ran the full `libclamav` CTest under ASan/UBSan with
`CVD_CERTS_DIR=/workspace/ClamAV/certs`. It passed 1/1 in 42.93 seconds, and
the detailed Check log records all four materialization regressions as passed:
the two mbox and two single-message cases, each with and without heuristic
alerts. Maximum RSS was 886,720 KiB, swaps stayed at zero, no sanitizer or
runtime diagnostics were present, and no test process remained. Evidence and
source hashes are preserved at
`/work/evidence/milter-working-tree-cap-sanitizer-20260814/unit-regression`.
The initial run without `CVD_CERTS_DIR` skipped fixture-loading tests and is
not counted as qualification.

A follow-up Sonic1 validation then applied the cap and regression tests to an
isolated checkout based on `5becea1`. Its complete ASan/UBSan build with
`ENABLE_MILTER=ON` passed `libclamav` 1/1 and the milter quota/protocol pair
2/2. The literal exact-edge milter wire sent exactly 34,359,738,316 body bytes
for a 34,359,738,368-byte message, returned `r`, and logged
`Heuristics.Limits.Exceeded.MailMaterialization FOUND`. No sanitizer/runtime
diagnostics or temporary files remained. The validated follow-up is preserved
as local Sonic1 commit `938a196` on `codex/sonic1-validation-fixes` and was not
pushed upstream. Checksummed evidence is preserved at
`/work/evidence/cap-committed-validation-20260814`.

A targeted adversarial mbox fixture with 8,388,608 seven-byte body lines
(`67,108,864` logical body bytes) exercised the cap-enabled ASan/UBSan
`clamscan` path. It returned exit status 1 with
`Heuristics.Limits.Exceeded.MailMaterialization FOUND` in 1:21.43, peaked at
429,212 KiB RSS, and recorded zero major faults and zero swaps. No sanitizer
diagnostics were emitted. This measures dense-line parser-node overhead while
confirming fail-visible behavior; the source was restored to committed
`5becea1` and rebuilt afterward. Checksummed working-tree-only evidence is at
`/work/evidence/deep-parser-density-20260814`.

The same dense mbox fixture was then rerun from validated cap commit `938a196`
with its ASan/UBSan `clamscan` build. It returned exit status 1 with
`Heuristics.Limits.Exceeded.MailMaterialization FOUND` in 1:21.22, peaked at
428,104 KiB RSS, and recorded zero major faults, zero swaps, and no sanitizer
diagnostics. Checksummed committed-source evidence is preserved at
`/work/evidence/deep-parser-density-938a196-20260814`.

A stronger mbox precedence fixture placed a correctly base64-encoded private
marker in an attachment of the first message and a 67 MiB dense second
message behind it. On commit `938a196`, the ASan/UBSan single-match run found
the attachment in 0.16 seconds at 70,536 KiB RSS without reaching the later
materialization cap. With `--allmatch`, the run reported both the attachment
marker and `Heuristics.Limits.Exceeded.MailMaterialization FOUND` in 1:21.15
at 430,016 KiB RSS. No sanitizer diagnostics or temporary mail directories
remained; the checksummed evidence pack is preserved at
`/work/evidence/mbox-detection-plus-cap-938a196-20260814/custom/attachment-level-b64`.

The 46-fixture deep-parser matrix was also run through a 13-file database
combining repository test CVDs, the bytecode CVD, and existing test signatures.
The database loaded successfully and reproduced 22 detections with the same
`fc8cf08eedec79549268bf553d0979dee2debde487861fffe4e4970fd0abedd0` stdout
hash in 0.67 seconds at 207,128 KiB RSS; no sanitizer
diagnostics were emitted. This is CVD-format test-database evidence only, not
production-CVD qualification. Checksummed evidence is preserved at
`/work/evidence/cvd-matrix-938a196-20260814-run2`.

An independent Sonic1 parity rerun then used the existing Release and
ASan/UBSan `clamscan` binaries against that identical 13-file database and
46-fixture corpus. Both runs returned the expected exit 1 with 46 output
lines and 22 detections; stdout and stderr matched byte-for-byte, with the
same `fc8cf08eedec79549268bf553d0979dee2debde487861fffe4e4970fd0abedd0`
stdout hash. The only diagnostics were the expected truncated-ZIP warning and
repository bytecode-runtime warnings; no sanitizer or database-load
diagnostic appeared. Checksummed parity evidence is preserved at
`/work/evidence/cvd-matrix-parity-20260814-run1`. A bounded Sonic1 database
inventory found signed repository test CVDs and custom test signatures but no
production CVD, so this strengthens test-CVD parity without closing the
production-database qualification gap.

The same final-commit ASan/UBSan `clamd`/`clamdscan --fdpass` path was then
checked against that CVD-format test database plus a private tail-marker NDB.
A zero-tail 34,359,738,368-byte exact-edge control returned `OK`/exit 0 in
465.285 seconds; a separate sparse fixture with `CLAMAV-CLAMD-EDGE\0` at
offset 34,359,738,350 returned `FinalClamd.Edge32.UNOFFICIAL FOUND`/exit 1
in 252.652 seconds. No sanitizer diagnostics appeared, and shutdown left no
socket, PID, or temporary files. This is CVD-format test-database plus
private-marker evidence only, not production-CVD qualification. Evidence is
preserved at `/work/evidence/cvd-clamd-exact-edge-938a196-20260814-run2` and
`/work/evidence/cvd-clamd-marker-edge-938a196-20260814-run1`.

A current clean-`938a196` ASan/UBSan audit passed the valid non-Valgrind CTest
subset 10/10 in 129.22 seconds, including the large-file guards, milter,
clamscan, clamd, freshclam, and sigtool entries, with no sanitizer diagnostics.
The separate Release inventory passed all 16 non-Rust entries; its Rust
failures were caused by the read-only source mount rather than a scan result.
This is source/test evidence only and does not close production-CVD or
production-workload qualification. Checksummed evidence is preserved at
`/work/evidence/ctest-sanitizer-selected-938a196-20260814-run1` and
`/work/evidence/ctest-release-all-938a196-20260814-run1`.

The Rust entry was then rerun from a correctly structured writable copy of
implementation commit `5becea1` against the Release static artifacts. All 63
integrated Rust tests passed, checksum verification returned status 0, and no
test or sanitizer diagnostics were present. The earlier 11 failures remain
an environment-only read-only-source-mount diagnostic. Corrected evidence is
preserved at `/work/evidence/rust-release-writable-938a196-20260814-run3`.

A real nested-ZIP Release `clamscan` probe then exercised cumulative
`MaxScanSize` propagation. A later-child crossing returned exit 2 and the
fail-visible `Exceeded max scan size ERROR` result with `AlertExceedsMax=no`,
or the explicit `Heuristics.Limits.Exceeded.MaxScanSize FOUND` alert when
enabled. An earlier-child marker retained exit-1 detection precedence even
when a later child crossed the limit. This closes the observed nested-ZIP
false-clean case only; broader parser coverage remains open. A corresponding
`MaxFiles=2` probe returned exit 2 with `Exceeded max scan files ERROR` when
the alert was disabled and `Heuristics.Limits.Exceeded.MaxFiles FOUND` when it
was enabled. Checksummed evidence is preserved at
`/work/evidence/nested-limit-probe-20260814-run1`.

The repository `clam_cache_emax.tgz` fixture also passed the real Release
MaxRecursion guard using an isolated test database: alert-disabled returned
exit 2 with `Exceeded max recursion depth ERROR` after an ignored shallower
detection, while alert-enabled returned exit 1 with
`Heuristics.Limits.Exceeded.MaxRecursion FOUND`. This validates the real
fixture's false-clean guard but not every parser path. Evidence is preserved
at `/work/evidence/maxrecursion-probe-20260814-run1`.

A public Release matrix over real BZIP2/Deflate64/Implode, split, nested
7z-in-ZIP, and split-logos ZIP fixtures returned exit 2 with `Can't parse data
ERROR` and an explicit incomplete warning for every cut that removed member
data. Tail-only cuts remained clean because their local member data was still
complete and fallback scanning was valid. This validates structural
truncation handling in two real formats; broader production ZIP coverage and
strong-encrypted contents remain unsupported by design. Separate public Release
probes qualify a small single-member and a two-member traditional ZipCrypto
archive, including a deliberate wrong-first password fallback, plus a 64 MiB
stored member. A synthetic production-structure ZIP with strong-encryption
flags is also rejected fail-visibly with and without configured passwords.
Evidence is preserved at
`/work/evidence/zip-public-truncation-20260814-run2`.

The available Release milter binary also accepted an exact-edge wire run using
the local working-tree harness and complete repository signature corpus: the
34,359,738,368-byte message returned the bounded fail-visible
`Heuristics.Limits.Exceeded.MailMaterialization` result, peaked at 22,708 KiB,
and cleaned its temporary directory. This result is explicitly working-tree
only because committed `5becea1` lacks the harness; evidence is preserved at
`/work/evidence/milter-working-tree-harness-20260814`.

Production CVD, production-format/deep-parser, production-workload cold-cache,
and externally attested release-runner qualification remain open. The bounded
committed-source milter materialization behavior is now validated and
fail-visible; extending deep mail analysis requires a streaming or spooling
design.

## Toolchain requirement

The repository pins the Rust toolchain to the Cargo 1.97 release line in
`rust-toolchain.toml`. CMake also enforces Cargo 1.97 or newer so builds that
use a system Cargo fail during configuration with an actionable message.
Cargo 1.65 cannot read the repository's version-4 `Cargo.lock`; Cargo 1.97
compiled and ran the existing Rust suite successfully (62 tests passed in an
isolated writable exact source clone on the Linux x86-64 validation host).

## Initial baseline findings

The 1.5.3 source has these deliberate or high-priority boundaries:

- `common/optparser.c`: size-policy options must retain 64-bit parsing all the
  way through option storage and engine configuration.
- `libclamav/others.c`: `CL_ENGINE_MAX_FILESIZE` is explicitly clamped near
  `INT_MAX`.
- `libclamav/matcher.c`: raw scan buffer lengths and scan offsets are
  `uint32_t`.
- `libclamav/matcher-ac.h` and matcher APIs: runtime match offsets include
  32-bit fields.
- `libclamav/matcher-hash.h`: exact-size hash lookup and registration use
  `uint32_t` sizes.
- `clamd/scanner.h`: legacy scan counters use `unsigned long`.
- `libclamav/execs.h`: executable metadata includes containing-file offsets
  that must be classified separately from format-defined fields.

These findings are audit inputs, not automatic conversion instructions. The
current implementation has resolved the principal runtime truncation and
fail-open issues called out by the repository audit. The complete configured
normal suite is green in the constrained Linux build; remaining work includes
intentional ABI/parser caps and the high-memory release-gate validation
described below.

## Audit-fix disposition

- BM offset tables use an explicit 64-bit comparator and have a focused
  ordering regression test.
- Milter message accounting uses checked 64-bit totals and sends large input
  in protocol-sized chunks.
- Bytecode/logical, version-info, embedded-PE, and incomplete CAB extraction
  paths mark the scan incomplete and return a non-clean parse result instead
  of silently returning clean.
- ZIP EOCD search is bounded to the legal classic trailer window, ZIP64
  placement is checked separately, and fallback local-header scanning observes
  the scan deadline even on malformed input.
- ZIP bounded extraction now marks output-write, temporary-file allocation/open,
  rewind, close, temporary-map, and cleanup failures incomplete before those
  errors can unwind through legacy or ZipCrypto paths. Partial member output is
  never presented to the nested scanner as a complete extraction.
- ISO9660 now marks extracted-file temporary creation, nested-scan, close,
  cleanup, and directory-traversal allocation failures incomplete before they
  reach the containing-image result.
- 7-Zip now marks member-name allocation, temporary-file creation/close/remove,
  member metadata matching, and extracted-file scan failures incomplete while
  preserving detection and other terminal results.
- XAR now marks TOC temporary admission/creation, member/subdocument staging,
  close, and cleanup failures, and preserves subdocument scan errors instead of
  allowing successful cleanup to overwrite them.
- The POC harness now computes the signature per row, verifies size, status,
  signature, and engine-reported offset, aggregates failures, works with both
  GNU and BSD `time`, and is covered by executable positive/negative scanner
  stubs plus a fail-closed CTest/CI check.
- Size-policy parsing and engine configuration enforce a 32 GiB ceiling, and
  the CMake configuration rejects platforms without 64-bit pointer, size, and
  file-offset types.
- Logical FileSize ranges and calculated matcher offsets now retain 64-bit
  values. Native matcher sentinels are outside the valid file-offset range,
  exact-size hashes route `UINT32_MAX` through the 64-bit table, byte-compare
  converts absolute references to window-relative coordinates, and stateful
  logical/multipart signatures defer the append-time optimization to the
  authoritative full-file scan.
- CAB/CHM extraction limits now distinguish unlimited from exhausted budgets,
  mark a pre-member `MaxScanSize` exhaustion incomplete/non-clean, fail closed
  on short writes or decoder errors, and remove partial temporary output when
  it exists. Rust bindings and their C/Rust layout assertions now include the
  widened matcher and logical-signature fields.

## Re-audit implementation follow-up

The 2026-08-10 re-audit findings were applied as source changes. The C90 hash
loop declarations, 64-bit sentinel collisions, exact-size hash boundary,
byte-compare window coordinate conversion, libmspack short-write/CHM policy,
positive harness controls, stale Rust layouts, append-state limitation, CAB
cleanup, centralized settings validation, and explicit supported-architecture
policy are now covered by source guards, focused unit-test additions, or both.

The source continues to build in the constrained Linux ARM64 development
environment. In addition, exact commit
`bba68110e04f78504d2af389050c349e01861315` has now completed a full Release
build, normal/focused tests, and a one-worker exact-boundary runtime gate on
the `sonic1` Ubuntu Linux x86-64 host. This is meaningful target-platform
evidence, but it is not production certification. Broader adversarial
containers, production-database/deep-parser and production-workload cold-cache
measurements, clamd/milter large transfers, and known false-clean and broader
production-format ZIP gaps remain open; current final-build sanitizer and 2/4-worker
raw-edge evidence is recorded in the status section above.

The reproducible runtime gate runner is now `tools/largefile_runtime_gate.sh`.
It refuses non-Linux and non-x86-64 hosts, verifies the scanner ELF
architecture, requires an explicit aggregate worker RSS budget, runs the sparse
boundary POC, checks the exact 32 GiB+1 policy rejection, records concurrent
worker RSS, verifies cancellation of a long-running edge scan, and fails
unless an ASan/UBSan scanner is supplied through
`CLAMAV_SANITIZER_CLAMSCAN`. Run it with an output directory outside the source
tree, for example:

    tools/largefile_runtime_gate.sh \
        /path/to/release/clamscan \
        /var/tmp/clamav-largefile-release-2026-08-13 \
        33554432

Set `CLAMAV_REQUIRE_SANITIZER=0` only for the non-sanitized runtime pass; the
separate sanitizer pass must use the default requirement. The manual workflow
defaults `CLAMAV_SANITIZER_MAX_SCAN_TIME_MS` to 3,600,000 milliseconds so
instrumented full-file boundary scans have diagnostic headroom without
relaxing the release deadline. `CLAMAV_CONCURRENCY_LEVELS` can expand the
default `1 2 4` worker matrix after the target's memory budget
has been established. The output directory contains the build identity,
per-case logs, results, policy-rejection evidence, and concurrency measurements
needed for release review. A source checkout, source-only test, or ARM64 run
is not a substitute for this gate.

Release-gate concurrency is fixed to the exact-edge `32g-edge.bin` fixture, so
the resource measurement represents concurrent 32 GiB scans rather than a
smaller boundary sample. Use the lower-level POC harness for staged lower-size
tests; the release runner and evidence verifier reject those results as the
32 GiB worker budget.

## Sonic1 Linux x86-64 validation

The following results are bound to exact code commit
`bba68110e04f78504d2af389050c349e01861315` and were produced in Docker on the
real `sonic1` Ubuntu Linux x86-64 host:

- the full Release configuration, with `ENABLE_STATIC_LIB`,
  `ENABLE_EXAMPLES`, and `ENABLE_MILTER` enabled, built to 100%;
- focused `libclamav`, `clamscan`, and examples tests passed 3 of 3;
- focused Valgrind tests passed 2 of 2;
- the complete non-Rust CTest selection passed 16 of 16 in 1106.34 seconds;
- an isolated writable exact source clone passed all 62 Rust tests; and
- the non-sanitized one-worker runtime gate exited 0 with
  `runtime_gate=pass`.

The runtime gate detected all 11 sparse boundary rows at their exact engine
offsets. The exact 32 GiB edge signature was reported at `34359738304`; the
32 GiB+1 policy check passed; the cancellation test returned the expected
status 124; and the one-worker concurrency measurement passed at 100792 KiB
aggregate RSS.

A separate warm-cache exact-edge scan ran with four CPUs inside a hard 8 GiB
memory limit and an equal 8 GiB memory-plus-swap limit, so no additional swap
was available. It reported `FOUND` in 1:49.95 with 100944 KiB peak RSS and
zero swap use. This demonstrates bounded process residency for the tested
sparse raw-file/signature workload. It is not a minimum-RAM guarantee: it did
not exercise cold-cache reads, materialized 32 GiB data, production signature
databases, deep parsers, archive expansion, or multiple workers.

This validation closes the earlier Linux x86-64 exact-edge and one-worker raw
scan gaps. It does **not** make the fork production-ready. Clamd/milter large
transfers, production-database and deep-parser resource certification,
production-workload cold-cache measurement, and the known false-clean and
broader production-format ZIP issues remain release blockers; current final-build sanitizer
and 2/4-worker raw-edge results are documented above.

## Runtime-gate execution handoff

The release workflow is intentionally manual because the exact 32 GiB edge
case requires substantial I/O and scan time, while production database,
parser, cache, and concurrency memory costs have not yet been established.
After this source tree is published to the private fork, run the ordinary and
sanitizer jobs from an x86-64 Linux runner with an explicit measured budget:

    gh workflow run cmake.yml --repo OWNER/REPO --ref BRANCH \
        -f run_largefile_runtime=true \
        -f run_largefile_sanitizer=true \
        -f rss_budget_kb=33554432 \
        -f min_available_kb=50331648 \
        -f 'concurrency_levels=1 2 4'
    gh run watch --repo OWNER/REPO
    gh run download --repo OWNER/REPO --name clamav-largefile-runtime-verified
    gh run download --repo OWNER/REPO --name clamav-largefile-sanitizer-verified

The uploaded artifacts, not the workflow's start or build status, are the
release evidence: inspect build-identity.txt,
host-preflight/host-preflight.txt, every results.tsv, the
32 GiB+1 rejection log, sanitizer logs, cancellation status, and the per-worker
RSS measurements before approving the fork. Run
`tools/largefile_runtime_evidence_check.sh` against each downloaded artifact,
passing the same RSS budget; it independently verifies those invariants and
rejects incomplete or over-budget evidence.

    tools/largefile_runtime_evidence_check.sh \
        /path/to/clamav-largefile-runtime-verified no '1 2 4' 33554432
    tools/largefile_runtime_evidence_check.sh \
        /path/to/clamav-largefile-sanitizer-verified yes '1 2 4' 33554432

The host preflight is provenance, not a memory-stability test. Validate the
deployment host's memory first, then use the preflight report to confirm that
Linux sees the expected 64 GiB and is not constrained by an unexpected cgroup
or shell limit.

The raw-scan POC has now addressed the `MaxFileSize` parser/clamp, the
ordinary AC/legacy absolute match-coordinate path, and calculated relative
offset caches. The current bounded-area audit also carries native logical,
YARA, macro, byte-compare, ZIP raw-catalogue, and OLE2 block-reader offsets
through 64-bit runtime coordinates. Fixed-width bytecode, PE version-info,
classic ZIP header, CFB sector-ID, and VBA stream fields remain bounded at
their ABI or format boundaries and are guarded explicitly.

The current audit also removes several artificial runtime limits: cumulative
INSTREAM quotas and scanner size-policy options now use 64-bit storage,
`fmap_readn()` returns a successful read larger than `INT_MAX`, and the
Microsoft archive adapter accepts offsets
that fit the platform's `off_t` instead of imposing a 2 GiB check. Archive
extraction budgets now use checked 64-bit remaining-size arithmetic and report
partial writes correctly. Calculated AC, BM, and PCRE target-relative offset
caches are 64-bit; fixed-width logical-signature, bytecode, and version-info
interfaces remain explicitly bounded where their ABI or format requires it.
Exact-size hash signatures retain the legacy 32-bit lookup table and add a
64-bit side table for sizes at or above 4 GiB, including `UINT32_MAX`. The boundary harness now reports only
offsets emitted by the engine; its independent marker-at-offset check is no
longer promoted to an engine-reported offset.

## Memory and resource budget

`MaxFileSize` and `MaxScanSize` are scan-policy limits, not RAM limits. A
file-backed map reserves virtual address space; resident memory depends on
pages touched, page tables, parser scratch buffers, decompression, extraction,
the loaded signature database, and the number of concurrent scans.

For commit `bba68110e04f78504d2af389050c349e01861315`, the one-worker sparse
exact-edge gate measured 100792 KiB aggregate RSS. The separate warm-cache
hard-8-GiB-container run measured 100944 KiB peak RSS and zero swap use. Those
measurements characterize the purpose-built raw boundary workload only; they
must not be extrapolated to production database loading, deep parsing,
materialized input, cold-cache I/O, or concurrent workers.

The implementation and deployment tests must measure:

- process RSS and virtual address space;
- system available memory and page-cache pressure;
- page faults, read throughput, CPU time, and temporary storage;
- one scan and concurrent scans at 1, 2, 4, 8, 16, and 32 GiB;
- parser scratch and decompression allocations;
- archive expansion, recursion, file-count, and scan-time limits.

Before a release-gate run, tools/largefile_runtime_gate.sh now captures a
Linux x86-64 host preflight under host-preflight/host-preflight.txt. The
report records physical and currently available memory, cgroup memory limits
and usage, CPU count, page size, shell resource limits, filesystem capacity,
and the available build/runtime tools. Its admission check uses the smaller of
host `MemAvailable` and finite cgroup headroom. This prevents a result produced
inside a small Docker or CI memory limit from being mistaken for evidence from
the 64 GiB deployment host. The release workflow defaults to a 48 GiB
effective-headroom floor (`50331648` KiB); a lower exploratory value must not
be promoted as production evidence.

One-worker testing on the 64 GiB Ubuntu host is complete for the sparse raw
boundary workload. Worker counts 2 and 4 are still required. Deployment
concurrency must be chosen from measured peak resource use, not from the
32 GiB file limit. Keep PCRE and other contiguous-buffer consumers separately
capped until their large-input behavior is designed and tested. An
operating-system or container-level memory ceiling should be part of the
deployment test, with a limit breach producing a visible
non-clean/indeterminate result rather than a clean verdict.

Sparse boundary files are appropriate for offset correctness. Materialized
files and adversarial containers are required for realistic I/O, cache,
decompression, and memory testing.

## Workstreams

1. Generate and classify the type/offset inventory.
2. Establish 64-bit build assumptions: `sizeof(size_t)`, `sizeof(off_t)`, and
   pointer width; require large-file support in the platform configuration.
3. Enforce the intentional 32 GiB `MaxFileSize` policy ceiling after parser
   and matcher gates are in place.
4. Widen raw matcher runtime coordinates while preserving signature-format
   widths and bytecode ABI compatibility.
5. Keep PCRE as a separately bounded subsystem. On qualifying 64-bit
   anonymous-map builds its contiguous-subject ceiling follows the 32 GiB
   large-file ceiling; other builds retain the historical 1 GiB allocation
   ceiling, and all builds still require measured memory/time headroom.
6. Add versioned 64-bit exact-size hash indexing without breaking existing
   HDB/MDB databases.
7. Audit nested maps, extraction, parser limits, third-party boundaries,
   reporting, cache keys, callbacks, and legacy APIs. The current slice covers
   INSTREAM quota propagation, `fmap_readn()`, Microsoft archive offsets,
   calculated matcher offsets, ZIP search bounds, and exact-size hash keys.
8. Add boundary, differential, parser-adversarial, sanitizer, and workload
   tests before enabling 32 GiB defaults.

## Validation results and historical POC context

Structured reports expose a saturating `skipped_operations` count for required
parser or matcher paths that could not complete. Directory-level report
aggregation adds those counts, while legacy contexts that provide only the
sticky incomplete flag retain a one-skip compatibility fallback.

The earlier `sonic1` Linux x86-64 raw-boundary result for commit
`bba68110e04f78504d2af389050c349e01861315` is retained as historical
provenance: all 11 rows reported exact engine offsets, including `34359738304`
for the 32 GiB edge, and both one-worker resource checks stayed near 100 MiB
RSS. The current authoritative result is the final `5becea1` record above.

An earlier ClamAV 1.5.3 POC in a Linux ARM64 development container detected
through 16 GiB but was killed during its 32 GiB edge run after reaching about
3.56 GiB RSS. That historical result predates the bounded fmap-aging and
subsequent hardening work. It remains useful as evidence that environment and
implementation details matter, but it is superseded for the current
single-worker sparse raw path by the successful x86-64 exact-edge runs. It
does not provide sanitizer, production-parser, or concurrency evidence.

## Known open correctness gaps

- A follow-up working-tree audit found two legacy-parser limit exits that did
  not enter the shared sticky-incomplete path before returning: the HWP3
  recursion guard and the initial OLE2 cumulative `MaxScanSize` guard. Both
  now call `cli_append_potentially_unwanted_if_heur_exceedsmax()` before their
  existing `CL_EMAX*` return, and
  `test_legacy_parser_limit_returns_are_fail_visible` covers the direct parser
  state (`scan_incomplete`, the exact limit cause, and non-cacheability). The
  patched static build passed 1,285/1,285 Check assertions on Sonic1, and a
  public HWP3 probe returned exit 2 with `Exceeded max recursion depth ERROR`
  when `AlertExceedsMax=no`. This closes those two observed legacy exits only;
  the generic cross-parser audit remains open for other parser paths.

- A subsequent source review found that the OLE2 VBA materialization pass
  discarded the property-tree handler result and that several incomplete
  stream-materialization branches could fall through as `CL_SUCCESS`. The
  working tree now preserves the first-pass and VBA-pass return codes,
  converts incomplete block extraction to an explicit parser error, marks the
  scan incomplete/non-cacheable, and adds
  `test_ole2_vba_materialization_failure_is_fail_visible` using a real XLS
  corpus fixture and an invalid materialization output directory. Local source
  guards pass. A disposable
  ARM64 `rust:1.97-bookworm` CMake/Cargo build compiled and linked
  `check_clamav`; the direct harness recorded both new tests as passed. The
  broader harness was not a clean repository-wide result because this checkout
  lacks several large/LFS fixtures and certificate setup (`1,261` checks,
  `786` fixture/environment failures, `0` errors). The new source patch has
  not been rebuilt on Sonic1: its existing Release and ASan/UBSan binaries
  still show diagnostic drift (`OK`/exit 0 versus `Exceeded max scan files
  ERROR`/exit 2) for the same probe. Production-CVD and broader legacy-parser
  qualification remain open.

- A follow-up OLE2 audit found additional partial-work paths beyond the VBA
  materialization pass: malformed property-tree indices/chains/entry types and
  loops, fixed recursion/file caps, directory creation failures, XLM/image
  pre-scanning failures, and incomplete plain or encrypted OTF stream extraction
  could otherwise be normalized to clean. The
  working tree now returns explicit limit/read/write/parse errors, preserves
  embedded stream scan failures, requires a terminal zlib state before scanning
  MSO output, aborts MSO inflation before scanning partial output when a
  configured limit is reached, and marks partial streams incomplete/non-cacheable.
  Source guards and the focused disposable ARM64 build remained passing. Sonic1's
  persistent checkout is
  clean at `5becea1`, but its OLE2 source checksum differs from this working
  tree, so the follow-up patch is not present in the remote binaries.

- A final OLE2 entry-path check found that a file shorter than the fixed OLE2
  header could still return `CL_CLEAN`; it now marks the scan incomplete and
  returns `CL_EPARSE`, with a public `CL_TYPE_MSOLE2` truncated-header
  regression. The combined SIS/OLE2 focused ARM64 build and source guards pass,
  and Sonic1 remains unrebuilt because its source differs.

- A broader compressed-container pass found the older GZip and BZip2 scanners
  writing and scanning partial temporary output after decoder errors, EOF, or a
  configured limit. Those paths now require a terminal decoder state before
  calling the nested scanner, preserve the limit/error result, and mark partial
  output incomplete. A public truncated `CL_TYPE_GZ`/`CL_TYPE_BZ` regression and
  source guards were added; the disposable ARM64 harness records the regression
  as passed alongside the existing focused parser tests. Sonic1 is unrebuilt
  because its source differs.

- An SWF follow-up found the same partial-output risk in the CWS zlib and ZWS
  LZMA decompression paths. Both now require decoder completion before nested
  scanning, preserve limit/write/decode failures, mark partial output incomplete,
  and verify the declared uncompressed length. The uncompressed FWS entry path
  also rejects short fixed headers and maps shorter than the declared file size.
  The public truncated CWS regression and direct FWS header/size regression pass
  in the corrected disposable ARM64 harness; the source guards pass. Sonic1 is
  unrebuilt because its SWF source differs from the current worktree.

- A follow-up ZIP slice found `cli_unzip()`, `unzip_search()`, and
  `unzip_single_internal()` treating maps or local headers shorter than their
  fixed structures as successful scans. These paths now mark the scan
  incomplete and return `CL_EPARSE`; a direct regression covers all three entry
  points and passes in the disposable ARM64 harness, with the source and
  fail-closed gates passing as well. Sonic1 is unrebuilt because its `unzip.c`
  source differs from the current worktree.

- A TNEF parser-entry follow-up found that a recognized signature shorter than
  the fixed six-byte TNEF header returned clean before parsing. It now marks the
  scan incomplete and returns `CL_EPARSE`; the direct short-header regression
  passes alongside the existing public truncated-attribute regression and the
  ARM64 focused suite. Sonic1 is unrebuilt because its TNEF source differs from
  the current worktree.

- An InstallShield legacy-metadata pass found `cli_scanishield()` breaking out
  on partial filename/path/version/size records with its initial success status.
  It now distinguishes a clean end-of-record boundary from truncated or
  malformed metadata, marks the scan incomplete, and returns `CL_EPARSE`. The
  direct truncated-metadata regression passes in the ARM64 harness and source
  guards; Sonic1 is unrebuilt because its InstallShield source differs from the
  current worktree.

- A follow-up InstallShield audit found `is_parse_hdr()` converting an invalid
  embedded header's `CL_BREAK` into a clean result, and found the metadata range
  check rejecting an exactly-ending final record. It now marks incomplete header
  metadata or invalid header magic and returns `CL_EPARSE`, preserves valid
  exact-end records, and no longer normalizes that parse failure to success. The
  direct invalid-embedded-header regression passes with the truncated-metadata
  regression and the local source, fail-closed, runtime-evidence, and workflow
  YAML gates; Sonic1 remains unrebuilt because its InstallShield source differs
  from the current worktree.

- An ARJ SFX header-validation pass found `cli_unarj_header_check()` accepting a
  declared member whose compressed range extended beyond the fmap, then treating
  the resulting later header error as a valid archive because one file had already
  been found. It now checks member containment before advancing, preserves
  non-terminal header errors, marks the scan incomplete, and returns a non-clean
  result. The direct truncated-member regression passes in the ARM64 harness with
  the existing parser matrix and all four local gates; Sonic1 is unrebuilt because
  its `unarj.c` source differs from the current worktree.

- A PE parser pass found `cli_scanpe()` converting malformed-header `CL_EFORMAT`
  and `CL_ERROR` results into `CL_SUCCESS` after skipping PE-specific analysis.
  It now marks malformed or truncated PE-header parsing incomplete, preserves
  broken-PE heuristic detection precedence, and returns a non-clean status. The
  public `test_pe_truncated_header_is_fail_visible` regression passes in the
  ARM64 `cl_api` group; the only two group failures are the known missing/corrupt
  CVD fixtures. Source guards pass; Sonic1 remains unrebuilt because its `pe.c`
  differs from the current worktree.

- A CAB/CHM bridge pass found `cli_scanmscab()` and `cli_scanmschm()` returning
  `CL_CLEAN` when cumulative `MaxScanSize` was already exhausted before the
  next member. Both now mark the scan incomplete and return `CL_EMAXSIZE` before
  creating extraction output. The public synthetic CAB regression passes in the
  ARM64 `cl_api` group (71 checks with only the two known CVD fixture/setup
  failures); source guards and fail-closed gates pass. Sonic1 remains unrebuilt
  because its `libmspack.c` differs from the current worktree.

- An ELF parser pass found `cli_scanelf()` converting `CL_BREAK` from incomplete
  header, program-header, and section-header parsing into `CL_CLEAN`. The public
  scanner now marks those paths incomplete and returns `CL_EPARSE`, while the
  internal header probe keeps its existing behavior. The truncated-ELF public
  regression passes in the ARM64 `cl_api` group (72 checks with only the two
  known CVD fixture/setup failures); source guards and fail-closed gates pass.
  Sonic1 remains unrebuilt because its `elf.c` differs from the current
  worktree.

- A Mach-O parser pass found the public scanner returning `CL_EFORMAT` for a
  truncated or malformed recognized Mach-O without setting the sticky incomplete
  state, allowing generic result reconciliation to normalize the failure to
  clean. The public Mach-O and universal-binary paths now mark incomplete
  header, load-command, section, entry-point, and architecture-table failures
  and return `CL_EPARSE`; the internal `cli_machoheader()` probe keeps its
  existing non-scanning behavior. The public truncated-Mach-O regression passes
  in the ARM64 `cl_api` group (74 checks with only the two known CVD
  fixture/setup failures); source guards and fail-closed gates pass. Sonic1
  remains unrebuilt because its `macho.c` differs from the current worktree.

- An UDF parser-entry pass found `cli_scanudf()` returning `CL_SUCCESS` when
  the mandatory descriptor area or required volume descriptors could not be
  read. Those paths now mark the scan incomplete and return `CL_EPARSE`; the
  public truncated-descriptor regression passes in the ARM64 `cl_api` group
  (75 checks with only the two known CVD fixture/setup failures), with source
  guards and fail-closed gates passing. Sonic1 remains unrebuilt because its
  `udf.c` differs from the current worktree.

- An HFS+ parser-entry pass found short or invalid volume headers returning a
  parser error without sticky incomplete state, and downstream HFS+ failures had
  the same normalization risk. HFS+ volume-header and final parser error paths
  now mark the scan incomplete; truncated headers return `CL_EPARSE` and cannot
  be cached as clean. The public truncated-HFS+ regression passes in the ARM64
  `cl_api` group (76 checks with only the two known CVD fixture/setup failures),
  with source guards and fail-closed gates passing. Sonic1 remains unrebuilt
  because its `hfsplus.c` differs from the current worktree.

- A follow-up ISO9660 audit found unsupported interleaved child records and
  multi-extent records could be skipped or partially scanned without a sticky
  incomplete result, and malformed-record exits could retain a mapped directory
  block. Those layouts now return `CL_EPARSE`, mark the scan non-cacheable, and
  avoid treating partial content as complete. The public regression covering both
  layouts passes in the rebuilt ARM64 `cl_api` group (77 checks with only the two
  known CVD fixture/setup failures); source guards and fail-closed gates pass.
  Sonic1 remains unrebuilt because its `iso9660.c` differs from the current
  worktree.

- A XAR parser-entry audit found truncated or invalid headers and unavailable TOC
  data returning parser/read errors without sticky incomplete state. The public
  header path now marks the scan incomplete, and the final TOC/parser error path
  reapplies the invariant before returning. The public truncated-header
  regression passes in the rebuilt ARM64 `cl_api` group (78 checks with only the
  two known CVD fixture/setup failures); source guards and fail-closed gates
  pass. Sonic1 remains unrebuilt because its `xar.c` differs from the current
  worktree.

- A DMG trailer audit found an invalid `koly` trailer returning `CL_EFORMAT`
  without sticky incomplete state once trailer validation was reached. The
  invalid-trailer path now returns `CL_EPARSE` and marks the fmap non-cacheable.
  The focused ARM64 `dmg` case passes all 4 checks with 0 failures and 0 errors;
  the broader `cl_api` group remains at 78 checks with only the two known CVD
  fixture/setup failures. Sonic1 remains unrebuilt because its `dmg.c` differs
  from the current worktree.

- A partition-parser finalization audit found MBR, APM, and GPT malformed or
  truncated header/table errors returning without reapplying sticky incomplete
  state. The three public parser entry paths now mark those failures incomplete
  at finalization. `test_partition_parser_errors_are_fail_visible` passes in the
  rebuilt ARM64 `cl_api` group (79 checks with only the two known CVD fixture/setup
  failures); source guards and fail-closed gates pass. Sonic1 remains unrebuilt
  because its partition-parser sources differ from the current worktree.

- An XZ decompression pass found `cli_scanxz()` writing a partial temporary
  member and then scanning it after `cli_checklimits()` rejected the expanded
  size. The limit path now preserves the limit result, marks the scan
  incomplete, and refuses to scan partial XZ output. The public XZ-limit
  regression passes in the ARM64 `cl_api` group (73 checks with only the two
  known CVD fixture/setup failures); source guards and fail-closed gates pass.
  Sonic1 remains unrebuilt because its `scanners.c` differs from the current
  worktree.

- A broader legacy-parser audit found that MSEXPAND could return clean after
  truncated input and could discard configured-limit results. It now propagates
  the limit, marks header/read/write/truncation failures incomplete, and has a
  public `CL_TYPE_MSSZDD` regression. The focused ARM64 build, parser tests,
  and source guards pass; broader legacy-parser coverage remains open.

- The same audit found TNEF's truncated-attribute branch explicitly returning
  clean. It now returns `CL_EPARSE`, marks the fmap non-cacheable, and has a
  public `CL_TYPE_TNEF` regression. The current-source production-linked GCC
  TNEF case passes 13/13, including the materialized `clam.tnef` fixture,
  which has no outer `MZP` marker and reaches an exact nested marker after
  attachment extraction. Full TNEF corpus, sanitizer, production-CVD/service,
  materialized-large-file, and Sonic1 qualification remain separate release
  gates.

- The current-source production-linked GCC HTML case now passes 12/12,
  including `clam.exe.html`. Its outer HTML bytes contain no `MZP` marker;
  the RFC2397 base64 child is decoded through the synthetic mail layer and
  reaches an exact nested marker. Raw fallback after normalization admission
  failure, full HTML corpus, sanitizer, supported-build, materialized-large-
  file, production-CVD/service, and Sonic1 qualification remain open.

- The next legacy-parser pass found UUENCODE accepting an attachment that ended
  at EOF, a blank line, or malformed encoded data without requiring the `end`
  terminator. The decoder now requires that exact terminator, returns
  `CL_EPARSE` on incomplete or invalid input, and marks the scan incomplete and
  non-cacheable. The public `CL_TYPE_UUENCODED` regression, focused ARM64 build,
  and source guards pass. The full local harness reports `1,295` checks,
  `816` fixture/environment failures, and `0` errors; Sonic1 remains a separate
  source/build qualification because the current follow-up sources were not
  transferred there.

- A follow-up check found that the two mail-parser callers of the shared
  UUENCODE decoder discarded that failure and retained the raw line instead.
  Both callers now mark the containing scan incomplete and non-cacheable before
  retaining the undecoded text, with a public `CL_TYPE_MAIL` regression covering
  an unterminated attachment. The current disposable ARM64 harness build passed
  the focused legacy-parser cases; its library-only run recorded `1,266` checks,
  `786` fixture/environment skips or failures, and `0` errors. The remote source
  and build qualification remains separate.

- The next pass found BinHex returning clean when its recognized stream ended
  before the header, data fork, resource fork, or terminal state was complete;
  it also discarded configured resource-limit results. Those paths now preserve
  the limit, mark incomplete extraction non-cacheable, and return `CL_EPARSE`
  when the encoded stream cannot reach a complete state. A follow-up check
  found that the data/resource-fork EOF branches still dispatched their partial
  temporary files to the nested scanner after marking them incomplete. Those
  branches now refuse partial nested scans and retain the parse failure. The
  public `CL_TYPE_BINHEX` regressions and focused ARM64 build pass. The current
  library-only harness recorded `1,267` checks, `786` fixture/environment
  failures, and `0` errors; remote source/build qualification remains separate.

- A mail-level BinHex follow-up then exposed that `messageExport()` returned from
  its fast-copy path before installing the fileblob scan context, so a mail body
  could bypass the authoritative nested scan. The context is now set before that
  early return, and a failed BinHex mail materialization marks the containing scan
  incomplete. An explicit MIME `CL_TYPE_MAIL` BinHex regression passes in the
  ARM64 build; the full harness still has only the known fixture/environment
  failures, and the source guards and fail-closed gates pass.

- The next SIS slice found the recognized 9.x handler returning clean when its
  contents field or size was truncated; the legacy handler's buffered field/skip
  macros had the same EOF normalization. Those parser-entry and EOF paths now
  mark the scan incomplete and return `CL_EPARSE`. A direct `CL_TYPE_SIS`
  truncated-contents regression passes in the ARM64 build; the full harness still
  has only the known fixture/environment failures, and the source guards and
  fail-closed gates pass.

- The next TAR slice found `cli_untar()` returning clean for a short header and
  forcing an incomplete entry to end at EOF, allowing partial content to be
  scanned as complete. It now marks invalid or truncated headers, checksums,
  sizes, and entry content incomplete and returns `CL_EPARSE` after preserving
  child detection precedence. A direct `CL_TYPE_POSIX_TAR` truncated-header
  regression passes in the ARM64 build; Sonic1 remains reachable, but its
  checkout lacks this current TAR patch, so no remote rebuild qualification
  claim is made.

- The next CPIO slice found all four format handlers returning their initial
  success status when the top-level header loop ended on a short or failed
  `fmap_readn()`. They now distinguish a complete trailer from an incomplete
  header, mark the scan non-cacheable, and return `CL_EPARSE` or `CL_EREAD` as
  appropriate. A six-byte regression covering `CL_TYPE_CPIO_OLD`,
  `CL_TYPE_CPIO_ODC`, `CL_TYPE_CPIO_NEWC`, and `CL_TYPE_CPIO_CRC` runs without
  failure in the ARM64 harness; the broader harness still has only the known
  fixture/environment failures, and Sonic1's CPIO source differs from the
  current worktree.

- The next ISO9660 slice found the parser treating unavailable volume-descriptor
  data and directory blocks as clean, while malformed directory records,
  unsupported interleaved roots, and per-file limit skips could also fall through
  without a sticky incomplete result. Those paths now mark the scan
  non-cacheable and return `CL_EPARSE` or the specific limit result. A synthetic
  public `cl_scanmap_ex()` regression with a valid ISO descriptor sequence and a
  root directory block beyond the map runs without failure in the ARM64 harness;
  the broader harness still has only the known fixture/environment failures,
  and Sonic1's ISO source differs from the current worktree.

- The next 7-Zip slice found explicit fail-open paths for archive seek failure,
  header-open errors, member extraction errors, extracted-output write errors,
  and discarded per-member scan-limit results. Those paths now mark the scan
  incomplete and non-cacheable, preserve non-clean results, and avoid scanning
  partial extracted output. A public six-byte `CL_TYPE_7Z` truncated-header
  regression runs without failure in the disposable ARM64 harness alongside the
  CPIO and ISO regressions; the broader harness still has only the known
  fixture/environment failures. Sonic1's 7-Zip source differs from the current
  worktree, so no remote rebuild qualification claim is made.

- The current-source production-linked GCC 7-Zip TCase now passes 8/8,
  including the materialized `clam.7z` fixture. The fixture contains no outer
  `MZP` marker, and bounded extraction reaches an exact nested marker. Full
  BCJ2/archive, sanitizer, materialized-large-file, production-CVD/service,
  and Sonic1 qualification remain release gates.

- A follow-up SIS slice found the old and 9.x handlers discarding member scan
  limits and allowing decompression, short-read, or output-write failures to
  fall through as clean. Those paths now preserve the first non-clean result,
  mark incomplete content non-cacheable, and return explicit limit/read/parse or
  write errors. A synthetic old-format `CL_TYPE_SIS` regression with an
  eight-byte member over a one-byte `MaxScanSize` runs without failure in the
  disposable ARM64 harness; the broader harness remains limited by the known
  fixture/environment failures. Sonic1's SIS source has not been rebuilt for
  this follow-up.

- A HWP3 parser-entry/finalization audit found document-info, document-summary,
  and callback parser failures returning without reapplying the sticky incomplete
  state. `cli_scanhwp3()` now routes those failures through finalization and
  marks the scan incomplete and non-cacheable when no higher-priority result
  exists. The public `test_hwp3_parser_errors_are_fail_visible` regression uses
  a truncated document-summary section. The rebuilt disposable ARM64
  `check_clamav` harness completed with 1,325 checks, 816 fixture/environment
  failures, and 0 errors; the new HWP3 case was not among the reported failures.
  All four local safety gates pass. Sonic1 Docker access is verified, but its
  HWP3 and test-source checksums differ from the current worktree, so no remote
  rebuild qualification claim is made.

- An additional SWF audit found the public FWS parser's `INITBITS`, `GETBITS`,
  and `GETWORD` short-read branches returning `CL_EFORMAT` without marking the
  scan incomplete after frame metadata inspection had begun. Those branches now
  apply the sticky incomplete/non-cacheable invariant. The public
  `test_swf_truncated_frame_metadata_is_fail_visible` regression reaches the
  FWS frame header and truncates the required frame count. The rebuilt ARM64
  `check_clamav` harness completed with 1,326 checks, 816 fixture/environment
  failures, and 0 errors; the new SWF case was not among the reported failures.
  All four local safety gates pass. Sonic1 Docker access is verified, but its
  SWF and test-source checksums differ from the current worktree, so no remote
  rebuild qualification claim is made.

- An MSXML caller audit found `cli_msxml_parse_document()` suppressing
  `CL_EPARSE` for the XML path that can materialize and scan embedded Base64
  content. A new opt-in `MSXML_FLAG_FAIL_INCOMPLETE` preserves parser failures
  and marks the layer non-cacheable, while metadata-only callers retain their
  best-effort suppression behavior. `cli_scanmsxml()` uses the flag and checks
  reader close status. The public
  `test_msxml_truncated_document_is_fail_visible` regression passes in the
  rebuilt ARM64 harness; the full run now reports 1,327 checks, 816
  fixture/environment failures, and 0 errors, with the new case absent from the
  failure output. All four local safety gates pass. Sonic1 Docker access is
  verified, but its MSXML and test-source checksums differ from the current
  worktree, so no remote rebuild qualification claim is made.

- An RTF finalization audit found unmatched group/control-word state and
  incomplete embedded-object payloads reaching cleanup, where a partial
  temporary file could previously be treated as complete or the parent scan
  could normalize to clean. RTF finalization now marks the scan incomplete and
  non-cacheable, returns `CL_EPARSE` when no stronger result exists, and avoids
  scanning a partial embedded object. The public
  `test_rtf_truncated_document_is_fail_visible` regression passes in the
  rebuilt disposable ARM64 harness; the full run reports 1,328 checks, 816
  fixture/environment failures, and 0 errors, with the new case absent from
  the failure output. All four local safety gates pass. Sonic1 Docker access
  is verified, but its RTF and test-source checksums differ from the current
  worktree, so no remote rebuild qualification claim is made.

- A RAR parser-entry/finalization audit found `cli_scanrar_file()` discarding
  non-terminal member-header errors, losing configured-limit status, and
  treating encrypted or failed members as though their contents had been
  inspected. It now maps UnRAR errors, marks incomplete header/member
  inspection non-cacheable, preserves configured-limit results, and refuses to
  normalize failed extraction to clean. The synthetic
  `test_rar_truncated_header_is_fail_visible` regression reached the member
  header error path and passes in the rebuilt disposable ARM64 harness; the
  full run reports 1,329 checks, 816 fixture/environment failures, and 0
  errors, with the new case absent from the failure output. All four local
  safety gates pass. Sonic1 Docker access is verified, but its RAR scanner and
  test-source checksums differ from the current worktree, so no remote rebuild
  qualification claim is made.

- An ARJ extraction audit found `cli_scanarj()` passing a temporary member to the
  nested scanner even after `cli_unarj_extract_file()` failed, and ignoring a
  failed rewind before scanning extracted output. It now marks extraction and
  rewind failures incomplete/non-cacheable, closes the partial descriptor, and
  refuses nested scanning. The public
  `test_arj_truncated_member_extraction_is_fail_visible` regression passes in
  the rebuilt disposable ARM64 harness; the full run reports 1,330 checks, 816
  fixture/environment failures, and 0 errors. Source guards pass. Sonic1 Docker
  access is verified, but its scanner and test-source checksums differ from the
  current worktree, so no remote rebuild qualification claim is made.

- The legacy GZip compatibility fallback could pass temporary output to the
  nested scanner after a `gzread()` error, configured limit, write failure, or
  unclean `gzclose()`. It now requires clean decoder EOF/close, preserves the
  failure status, marks the scan incomplete/non-cacheable, and refuses partial
  output. The public `test_gzip_bzip_truncated_streams_are_fail_visible`
  regression covers the main GZip path and source guards cover the fallback
  diagnostics. The disposable ARM64 harness reports 1,330 checks, 816
  fixture/environment failures, and 0 errors; all four local safety gates pass.
  Sonic1 Docker access was freshly verified with `sonic1-camera-key`; the
  remote scanner and test-source hashes differ, so no remote rebuild
  qualification claim is made.

- The PE optional-unpacker audit found the shared `CLI_UNPSIZELIMITS()` macro
  converting configured size/scan-limit failures into `CL_CLEAN` after skipping
  unpacking. It now preserves the exact limit result, marks the scan
  incomplete/non-cacheable, and returns the failure. The public
  `test_pe_unpack_limit_is_fail_visible` regression exercises the recognized
  UPX fixture in the disposable ARM64 harness; the full run reports 1,331
  checks, 814 fixture/environment failures, and 0 errors, with no new test
  failure. All four local safety gates pass. Final local `pe.c` SHA-256 is
  `8a4e95a3bda2cbadc5f9c59398488fec6d97efa3fbd67ecc9e5bc62e9d901142`.
  Sonic1 Docker access was freshly verified with `sonic1-camera-key`; the
  remote `pe.c` and test-source hashes differ from the current worktree, so no
  remote rebuild qualification claim is made.

- The PDF stream/extracted-object follow-up found raw and decoded stream paths,
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
  Fresh host-list request `req_89b90bc39c2e4347b2168c00587901b5` returned
  `sonic1`; Docker request `req_b55b48136be9427780d9b9e69da89a02` succeeded and
  showed all three existing ClamAV containers up. Remote `pdf.c`, `pdfdecode.c`,
  and test-source checksums differ from the local worktree, so no remote rebuild
  qualification claim is made.

- The ARJ member-limit audit found `cli_scanarj()` converting a configured
  member-size/scan-limit failure into `CL_SUCCESS` after skipping that member.
  It now preserves the first deferred limit result while allowing later
  members to be inspected, stops immediately on timeout, marks the scan
  incomplete and non-cacheable, and returns the limit when no stronger result
  occurs. The public `test_arj_member_limit_is_fail_visible` and existing
  `test_arj_truncated_member_extraction_is_fail_visible` regressions pass in
  the disposable ARM64 static harness; the full run reports 1,334 checks, 817
  known fixture/environment failures, and 0 errors. All four local safety
  gates pass. Local SHA-256 values are
  `scanners.c=15d8d7902a717fe604c54d895e67f6f9731016f303d57984cc7e6c4fd2dd98a3`,
  `check_clamav.c=e8f5cb68b309d1850fbf8c55328b9759a3c0022e6e2d27f10299a5dccf906ca5`,
  and
  `largefile_source_guards.sh=88251750174660601dc8274827c763e9f24a78cdd90f80db72a0ebfd339e7d77`.
  Fresh host-list request `req_1ad364b37c584f2381133fb4a7bfa233` returned
  `sonic1`; Docker request `req_5985e388d1a547728829b72d04e146e5` using
  `sonic1-camera-key` succeeded and showed the three existing ClamAV test
  containers up. Remote `scanners.c` and test-source checksums are
  `50f08543b6af7b782ebcd7e69124f30d43a3d0d36fd6970e4bb87597ac541a96` and
  `767d8b90b1324639b5aa86f78a0d32814e7706fdf14a04272360187026dc8352`
  (`req_c266bd53abe741da829168dda804c868` and
  `req_cf8f577d6f6f404396389ca88aa45a6e`), so no remote rebuild qualification
  claim is made for this local ARJ follow-up.

- The OLE2 property-tree audit found oversized embedded files being skipped
  without recording a deferred limit result, and the old condition could
  ignore `MaxScanSize` when `MaxFileSize` was unset. The walker now checks
  both limits independently, records the first `CL_EMAXSIZE` while continuing
  sibling inspection, marks the scan incomplete/non-cacheable, and returns the
  deferred limit when no stronger result occurs. The fixture-backed
  `test_ole2_member_limit_is_fail_visible` regression passes in the disposable
  ARM64 static harness; the full run reports 1,335 checks, 817 known
  fixture/environment failures, and 0 errors. All four local safety gates
  pass. Local SHA-256 values are
  `ole2_extract.c=eaba46a94a5aeaef7664774d3951d6c3ecfdf651b47be03626f0846924c116c7`,
  `check_clamav.c=ca115aa4735576289ab31f6268a8752ae2170778e5ab5d85509e3b8a5292b274`,
  and
  `largefile_source_guards.sh=c4e4ec674acf8086fad445517b0ed97dae8436c7421ba4dd8866080cb7770029`.
  Fresh host-list request `req_98c8b9951fd044468b081c29ab3d87e1` returned
  `sonic1`; Docker request `req_801da2e90300458c8343d78b4e430dbf` using
  `sonic1-camera-key` succeeded and showed the three existing ClamAV test
  containers up. Remote `ole2_extract.c` and test-source checksums are
  `314f8896f7112587330415dc0152c6dc6e111cb06b3460d5a4e3c88abf966504` and
  `767d8b90b1324639b5aa86f78a0d32814e7706fdf14a04272360187026dc8352`
  (`req_5ac907a0e535491c812e7c635e042551` and
  `req_93102cb71ff4450f85713062515b1eca`), so no remote rebuild qualification
  claim is made for this local OLE2 follow-up.

- The PEspin limit audit found the expanded-section total being accumulated in
  `unsigned long` and the unpacker returning a private size status that its
  caller could normalize away. `cli_pespin_check_limits()` now uses `uint64_t`,
  records `Heuristics.Limits.Exceeded.MaxFileSize` through the common sticky
  limit path, and the PEspin cleanup case returns `CL_EMAXSIZE`. The focused
  `test_pespin_limit_accounting_is_fail_visible` regression passes in the
  disposable ARM64 harness with two `UINT32_MAX` sections against a 4 GiB
  limit. The current UnRAR-disabled harness reports 1,305 checks, 786 known
  fixture/environment failures, and 0 errors; the four local safety gates
  pass. Local SHA-256 values are
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

- Generic `MaxScanSize`, `MaxFiles`, and `MaxRecursion` still require a
  cross-parser sticky-incomplete audit. Focused synthetic tests and public
  Release probes now cover representative nested ZIP and recursion paths with
  explicit non-clean results and preserved detection precedence, but this does
  not prove that every legacy parser path cannot normalize a limit result to a
  false clean after partial inspection.
- UNIX mbox traversal now preserves recursive `MAXREC` and `MAXFILES` results
  when advancing between messages, and nested multipart return paths explicitly
  propagate `MAXFILES` to the public scan result. The focused
  `test_mbox_nested_maxfiles_is_fail_visible` regression covers a two-part
  multipart containing a nested `message/rfc822` part with `MaxFiles=1`; broader mail corpus and
  production-CVD qualification remain open.
- The focused ZIP cases for unsupported strong encryption, masked headers,
  local-only data descriptors, unsupported methods, truncated streams, exact
  output, and inclusive file-count accounting now have committed sanitizer
  closure tests. A public Release `clamscan` probe also qualifies one small
  traditional ZipCrypto stored member both without a password (exit 2 with an
  explicit incomplete warning) and with a `.pwdb` password (exit 1 with the
  decrypted marker detected). Follow-up public probes also qualify
  multi-member fallback and a 64 MiB stored member. Strong encryption and
  broader production-format ZIP variants remain outside supported decryption;
  the strong-encryption rejection path is fail-visible. Evidence is preserved
  at
  `/work/evidence/encrypted-zip-probe-20260814-run1`.
  Extended evidence is at
  `/work/evidence/encrypted-zip-extended-20260814-run1`.
  Strong-encryption rejection evidence is at
  `/work/evidence/zip-strong-encryption-public-20260814-run1`.

These are release blockers. The successful raw-boundary gate does not cover
or waive them.

## Remaining bounded paths

- The shared individual-allocation `calloc` wrapper admits `nmemb * size`
  through division-form arithmetic before multiplication. This keeps the
  1 GiB guard fail-closed on platforms whose native `size_t` can wrap the
  product; the checked product is reused for allocation-failure diagnostics.

- PCRE full-map matching now uses the 64-bit-capable PCRE2 wrapper, but PCRE2
  still requires one contiguous subject. On qualifying 64-bit anonymous-map
  builds, `PCREMaxFileSize` is bounded by the 32 GiB large-file ceiling; other
  builds retain the 1 GiB single-allocation ceiling. A required pass above the
  effective platform cap marks every active layer non-cacheable and returns
  an observable incomplete result.
- Bytecode globals and the bytecode `cli_bytecode_runlsig()` entry point remain
  `uint32_t` ABI. Native logical/YARA/macro/byte-compare offsets are now
  `uint64_t`; a bytecode-dependent logical signature is marked incomplete and
  cannot produce an unqualified clean result when an offset cannot be bridged.
- PE version-info matching remains a 32-bit RVA/hashset format boundary. A
  version-info match above 4 GiB is marked incomplete rather than silently
  treated as clean; this is distinct from the widened containing-file
  coordinates used by the native matcher.
- PE Authenticode and external-catalog hashes use native-width region
  coordinates and feed the digest in bounded 1 MiB fmap windows. Region
  overflow, short reads, digest failures, or another already-incomplete scan
  path prohibit trust and remain observable at the public scan result. PE
  section-signature hashes use the same bounded reader, and overlay offsets
  and lengths stay native-width until the fixed 32-bit bytecode metadata ABI;
  an unrepresentable bytecode bridge is marked incomplete.
- Authenticode certificate parsing no longer skips a confirmed embedded X.509
  certificate after an ASN.1/read failure. The certificate walk terminates with
  sticky incomplete state before catalog trust can proceed.
- ZIP raw local-header catalogue coordinates and OOXML search results now use
  `size_t`, so large maps are not truncated before raw-header indexing. ZIP64
  central-directory placement is parsed with checked 64-bit offsets and is
  accepted only when the catalogue is contained by the fmap.
- OLE2 block byte offsets no longer stop at `INT32_MAX`; they are calculated in
  64 bits and checked against the native fmap range. CFB sector IDs and stream
  lengths remain format-defined 32-bit values, and malformed chains beyond
  the signed block-coordinate limit return `CL_EFORMAT`. VBA’s in-memory
  matcher still rejects a decompressed buffer above its legacy 32-bit API.
- Embedded PE metadata still carries a 32-bit containing-file offset for its
  compatibility ABI. For recognized candidates above 4 GiB, header admission
  roots a bounded child fmap at the native-width containing offset and invokes
  the legacy parser with a zero relative offset; the containing raw scan keeps
  its native-width coordinate and still marks any later parser limitation
  incomplete.
- UDF allocation offsets, HFS+ block-to-byte conversions, and audited XAR/DMG
  extents use checked native-width arithmetic. XAR and DMG compressed input is
  consumed in bounded chunks, cumulative output limits are checked, and a
  decoder must reach its terminal state with the exact declared output.
  Malformed metadata, unknown non-empty methods, truncated streams, and
  configured-limit crossings are incomplete/non-clean rather than a scan of a
  partial prefix. Other format-specific boundaries still require dedicated
  adversarial and large-payload fixtures before an upstream support claim.
- Contiguous metadata/decompression remains intentionally capped for
  compatibility EGG byte-buffer callers at the 1 GiB allocation ceiling. The
  scanner-facing EGG path now
  consumes fmap input and decoder output in 64 KiB windows, writing members to
  a quota-accounted temporary spool. NSIS members now consume fmap input in
  64 KiB windows and charge extracted bytes to the shared temporary quota. The DMG XML
  resource fork itself is consumed through
  bounded SAX input and quota-accounted Base64 spools. Crossing a per-format
  limit is fail-visible; it is not full deep-parser qualification through
  32 GiB.
- DMG blkx Base64 is decoded incrementally across XML callback boundaries into
  a quota-accounted spool. Blocks through 64 MiB retain the bounded sortable
  array; larger sorted blocks are read from the spool one fixed-width stripe
  at a time, while larger unsorted blocks use 4 MiB sorted runs and a
  quota-accounted auxiliary spool for bounded external merging. Run memory is
  charged to `MaxContiguousSize`; the final ordering is copied back into the
  already-reserved decoded spool before partition reconstruction. Complete
  alphabet, quartet, padding, suffix, stripe geometry, and terminal `END`
  records are validated. Focused valid, malformed, and external-sort fixtures
  guard these rules; full DMG corpus and supported-build qualification remain
  release gates.
- BM offset mode now carries 64-bit runtime coordinates, but its bounded
  32-bit scan-window API still needs dedicated fixtures. PCRE full-map matching
  remains separately capped by the platform-aware `PCREMaxFileSize` policy.

- PCRE full-map dispatch uses checked range arithmetic. It tests whether the
  current bounded window reaches the end of the fmap without evaluating
  `offset + length`, so a near-`UINT64_MAX` runtime offset cannot wrap and
  accidentally suppress the required whole-subject pass. The source guard
  rejects regressions to the overflowing comparison; compiled large-offset
  matcher qualification remains part of the Linux/Sonic1 release gate.

## Acceptance criteria

LargeFile 1.0 is complete only when a 64-bit build can scan the complete
0–32 GiB range, detect signatures across the 2 GiB and 4 GiB boundaries,
report exact positions and sizes, preserve bounded memory behavior, and pass
the normal test suite plus the large-file suite under sanitizers. Worker
counts 2 and 4, clamd/milter large transfers, production-database/deep-parser
and cold-cache resource tests must pass, and the known false-clean and ZIP
strong-encryption false-clean gaps must be closed. Unsupported strong-encryption
contents may remain unscanned only when the rejection is explicit and
observable. Unsupported deep-parser paths must be explicit and observable.

## Proof-of-concept scope

The current implementation slice widens the direct raw-scan path, ordinary
AC/legacy signature match positions, and calculated AC/BM/PCRE relative offset
caches to 64 bits while retaining bounded scan windows. PCRE full-map scans now
pass 64-bit lengths to PCRE2, while the `PCREMaxFileSize` memory policy remains
enforced beneath the effective platform-aware contiguous-subject ceiling.
Exceeding that cap, a top-level `MaxFileSize`, or `MaxScanTime` cannot be reported as an
unqualified clean scan. The bounded-area slice extends native logical/YARA/macro/
byte-compare offsets and ZIP/OLE2 runtime coordinates without changing the
legacy bytecode or file-format ABIs. BM offset mode is no longer rejected
solely because its file position is above 4 GiB, but remains a separate
fixture-driven audit item because the scan-window API is bounded. The guarded
frozen-bytecode and fixed-format boundaries are deliberately fail-visible.
The exact 32 GiB x86-64 one-worker gate is complete for the validated commit;
current final-build sanitizer and 2/4-worker raw-edge extensions are covered,
while daemon/milter, production-workload cold-cache, and open-correctness
release gates remain. Run the harness as follows inside a
Linux build environment:

```sh
CLAMAV_CVD_CERTS_DIR=/path/to/test-or-production-certs \
  tools/largefile_poc.sh /path/to/clamscan /path/to/boundary-corpus /path/to/results
```

The same variable must be supplied to `largefile_runtime_gate.sh` when the
scanner is run from a build tree whose compiled-in certificate directory has
not been installed. The gate validates the directory and applies it to the
POC, cancellation, policy, concurrency, and sanitizer scanner invocations.
The release gate sets a bounded per-file deadline of 900,000 milliseconds by
default because a full hash plus an EOF marker scan at 32 GiB can exceed the
stock 120-second limit. Override it with a positive
`CLAMAV_MAX_SCAN_TIME_MS`; the selected value is recorded in the evidence.
When an ASan/UBSan scanner is supplied, the sanitizer POC may use a separate
diagnostic-only deadline through `CLAMAV_SANITIZER_MAX_SCAN_TIME_MS`. It
defaults to the release deadline, must be at least that large, and is recorded
as `sanitizer_max_scan_time_ms`. The manual sanitizer workflow supplies that
same input as `CLAMAV_MAX_SCAN_TIME_MS` because its primary scanner is also
instrumented; the release workflow leaves the production deadline at 900,000
milliseconds.

The harness reports non-clean resource termination separately from successful
detection and records the expected/actual fixture size, marker-at-offset
check, any offset emitted by the engine, RSS, page faults, CPU time, and
temporary-storage usage. A marker-at-offset result is not an engine match
offset unless the debug log contains that offset explicitly.

## HWP embedded-OLE2 representational boundary

HWP embedded-OLE2 stores its payload-size prefix in a 32-bit field. The
large-file implementation rejects a native payload larger than `UINT32_MAX`
before entering nested scanning, returns `CL_EPARSE`, and marks the scan
incomplete and non-cacheable. Truncated size-prefix reads are also
fail-visible. This is a safe representational boundary, not a claim of deep
HWPole2 support for arbitrarily large payloads. The focused regression is part
of `test_large_document_parser_caps_are_fail_visible`.

## Validation refresh — 2026-08-15

The disposable ARM64 build produced `check_clamav` and `check_clamfi_quota`.
The registered large-file/release-control CTest subset passed 4/4, and the
workflow YAML parse passed. The aggregate `check_clamav` run reported `1142`
checks, `840` fixture/environment failures, and `0` errors in a
source-mounted environment missing the complete LFS/corpus/CVD/certificate
inputs. Its Check runner hard-codes `srunner_run_all`, so the HWPole2
regression was not independently selectable; it had no failure entry in the
aggregate output. This does not replace the required complete fixture,
sanitizer, production-CVD, cold-cache, daemon/milter, and release-runner
qualification gates.

Fresh MCP-SSH verification with `sonic1-camera-key` used host-list request
`req_2ec6db7f3d1442f29fb13caaae9e9fc8`, Docker status request
`req_51e5181dcc8d493a865337373b4f983b`, inspect request
`req_ede657cb810b44ba8f98540f64991433`, and source-hash request
`req_48a1b5ad007348d1b2fd2b0b65767c95`. Docker was reachable; all three
existing ClamAV test containers were up, and the primary container used
`clamav-32gb:test-tools-742a8a4` with `/workspace/ClamAV` mounted read-only.
The remote HWP/test/guard hashes differ from the current local patch, so no
remote rebuild or qualification is claimed.

## GIF parser boundary hardening — 2026-08-15

The GIF parser's recognized-image path now validates fixed graphic-control
payloads, local color tables, the LZW minimum-code-size byte, image data
blocks, and the required image trailer before advancing. Each truncated path
marks the scan incomplete and non-cacheable; minimal direct parser callers
receive `CL_EPARSE`, while full scan contexts retain heuristic reporting.
`test_gif_truncated_blocks_are_fail_visible` runs in the dedicated Check
`gif` group and passed 1/1 in the disposable ARM64 build. The aggregate
harness reported `1307` checks, `786` fixture/environment failures, and `0`
errors, with the GIF regression recorded as passed. The registered
large-file/release-control CTest subset passed 4/4. This closes the observed
GIF boundary-normalization paths, not the broader production image/archive
corpus qualification.

Fresh MCP-SSH verification used `sonic1-camera-key`: host list
`req_3891a53b4be04bb48a52983a28a9d728`, Docker status
`req_2916efb44812499c8bba23d01d56e3af`, inspect
`req_d8b5757de5b9493bbec6192556d38280`, image identity
`req_824c25d8f52c44c180cf43403adc2971`, and source hashes
`req_4d5f7ebb11264a25906e0864739c01c8`. All three existing containers were
up on `clamav-32gb:test-tools-742a8a4`, image digest
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`;
the primary `/workspace/ClamAV` bind is read-only. Remote GIF/test/guard
hashes differ from the current patch, so no remote rebuild or qualification
is claimed.

## PNG parser boundary hardening — 2026-08-15

The PNG parser now validates boundary transitions that previously could fall
through to success: truncated chunk types, chunk data, and CRCs; invalid
`IHDR` length or dimensions; non-empty `IEND`; and end-of-input before an
`IEND` chunk. Each path marks the scan incomplete and non-cacheable. Minimal
direct parser callers receive `CL_EPARSE`; full scan contexts retain heuristic
reporting and only scan an overlay when the parser status allows recovery.
The dedicated `test_png_truncated_chunks_are_fail_visible` Check `png` group
passed 1/1 in the disposable ARM64 build. The aggregate harness reported
`1308` checks, `786` fixture/environment failures, and `0` errors. The
registered large-file/release-control CTest subset passed 4/4, and source,
fail-closed/runtime-evidence, and workflow YAML controls passed. This closes
the observed PNG boundary-normalization paths, not broader production image,
archive, CVD, cold-cache, sanitizer/multi-worker, or release-runner
qualification.

Local hashes are `png.c=847ea343241241429388b5b242989d48d881eb2d48bc53fc7bb07e553e0f209d`,
`check_clamav.c=c8f7d40c5f55046c22abcb8bf5512b692d8edfeb35dae9ffb1ea9eaf7e6dea4c`,
and
`largefile_source_guards.sh=53bca065b69fea84a34ef4572a85f43c801acbad25aba1fee80464b2fd5afbf4`.

Fresh MCP-SSH verification used `sonic1-camera-key`: host list
`req_a64c9e1e92074a32a784242258314923`, Docker status
`req_ade8413ef3514607803ade1e4e51a620`, inspect
`req_ee1ef808a7f249e183d24c3d0e5b153f`, image identity
`req_cb12f6d811cd487396dc198406244fa9`, and container hashes
`req_36b8dfb768334f439c933adb4187ef5d`. All three containers were up on
`clamav-32gb:test-tools-742a8a4`, image digest
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`;
the primary `/workspace/ClamAV` bind is read-only. Remote PNG/test/guard
hashes differ from the current patch, so Docker liveness and image/source
provenance are verified without a remote rebuild or qualification claim.

## PDF trailer boundary hardening — 2026-08-15

The PDF parser now validates recognized trailer boundaries that previously could
fall through to success: missing `%%EOF`, missing `startxref`, negative or
out-of-range xref offsets, and invalid xrefs. These paths return `CL_EPARSE` to
minimal direct callers and mark the scan incomplete and non-cacheable. The
structural error is applied at the common return boundary after parsing, which
preserves existing object detections and virus results.

The dedicated `test_pdf_truncated_trailer_is_fail_visible` Check `pdf` group
passed 1/1 in the disposable ARM64 build. The current forked aggregate
snapshot reported `1145` checks, `840` known fixture/environment failures, and
`0` errors; the no-fork aggregate remains an intermittent harness limitation
and exited 139 after 1145 checks with 0 Check-reported errors. The registered
large-file/release-control CTest subset passed 4/4, and source,
fail-closed/runtime-evidence, and workflow YAML controls passed. This closes the
observed PDF trailer-normalization paths, not broader production CVD, parser
corpus, cold-cache, sanitizer/multi-worker, release-runner, or remote rebuild
qualification.

Local hashes are `pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`check_clamav.c=50451a1805f689f546d45e853c89ce50e992cbfe0c18880b4ad67146b1207acc`,
and `largefile_source_guards.sh=0aa1f42a3f52e4cd842d5f58def7ffe3b95e8bb1b79444b1af5864c0a81fd4ad`.

Fresh MCP-SSH verification used `sonic1-camera-key`: host list
`req_699bfdd0509d4bbd8fdfd635b6ab3794`, Docker status
`req_fa690ea074a144be9c92a4ee20a35506`, inspect
`req_5551d4e47af1434e98483e833ff80065`, image identity
`req_81bda151c5284ac6845bfdc4f19419cd`, and container hashes
`req_c9b2355d08a24997a960d3573107304f`. All three containers were up on
`clamav-32gb:test-tools-742a8a4`, the primary `/workspace/ClamAV` bind was
read-only, and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PDF/test/guard hashes differ from the current patch, so Docker liveness
and image/source provenance are verified without a remote rebuild or
qualification claim.

## PDF decode and aggregate lifecycle hardening — 2026-08-15

When a PDF filtered stream cannot be decoded and returns `CL_EPARSE` during
best-effort object extraction, `pdf_decodestream()` now marks the containing
layer incomplete and non-cacheable before the parser continues. This closes the
observed decode-error false-clean normalization path; the malformed-Flate
regression passes in the dedicated PDF group.

The bytecode parallel-load test now checks for its `bytecode.cvd` fixture on the
main thread before creating workers. Missing checkout fixtures remain visible
failures, but Check assertions are no longer raised from worker threads. The
focused PDF group passed 2/2. Three consecutive no-fork aggregate runs
completed without a crash with `1146` checks, `840` known fixture/environment
failures, and `0` errors; the forked aggregate matched those counts. The
isolated bytecode suite reported 48 checks, 5 fixture failures, and 0 errors.
The registered CTest subset passed 4/4, and source, fail-closed/runtime-
evidence, and workflow YAML controls passed. Broader production CVD, parser
corpus, cold-cache, sanitizer/multi-worker, release-runner, and remote rebuild
qualification remain open.

## UDF declared-partition extent accounting — 2026-08-23

UDF file extents are now bounded by the declared Partition Descriptor length
before fmap admission. This prevents an extent at the partition end from
consuming mapped bytes outside the partition and preserves an explicit
incomplete result for invalid logical-block geometry. The focused allocation
fixture covers the boundary; compiled UDF corpus, sanitizer, width review, and
Sonic1 qualification remain open.

## ISO9660 declared-volume boundary accounting — 2026-08-23

ISO9660 block admission now honors the image's declared Volume Space Size in
addition to the mapped fmap length. Directory and file extents cannot consume
appended overlay bytes beyond the declared volume, and invalid zero or
undersized or map-exceeding volume extents remain explicit incomplete results.
The paired little-/big-endian size fields are validated as well. The focused
overlay-boundary regression is recorded in the source evidence; compiled ISO
corpus, sanitizer, and Sonic1 qualification remain open.

Local hashes are `pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`pdfdecode.c=5aa98bba6753b3950edf207bbcfd8a25e4ee154b17acf743cf21fb4316cc73e7`,
`check_clamav.c=886628a0c83441f27d3c427fbad97dd038b0753a47c2d08af560aac977f5f84f`,
`check_bytecode.c=b0e9254e0dfc987ed3069d91d73dfab518fc069ebc05887ac77cfa071117a0f5`,
and `largefile_source_guards.sh=f7e3b418020923be94b622a716c731f5d053e708fc4368a1c434909325f4acb0`.

Fresh MCP-SSH verification used `sonic1-camera-key`: host list
`req_3d029d63018b4790b7700971d09bc890`, Docker status
`req_5c341b5a6a0b4140a412ff4faa853cbf`, inspect
`req_1fa443f9d5934ddb9532d14f6c10acac`, image identity
`req_a4cc36b931f74290b33b09fe9c7e7ce5`, and container hashes
`req_e60bf09ef17942cf80d9b499d5e0a3ae`. All three containers were up on
`clamav-32gb:test-tools-742a8a4`, the primary `/workspace/ClamAV` bind was
read-only, and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PDF/decode/test/guard hashes differ from the current patch, so Docker
liveness and image/source provenance are verified without a remote rebuild or
qualification claim.

## HWPML XML boundary hardening — 2026-08-15

The HWPML attachment-bearing path now invokes the streaming XML parser with
`MSXML_FLAG_FAIL_INCOMPLETE`. Truncated XML is therefore returned as
`CL_EPARSE`, marked incomplete, and made non-cacheable instead of being
suppressed as metadata-only best effort. The dedicated
`test_hwpml_truncated_document_is_fail_visible` group passed 1/1.

Three consecutive no-fork aggregates and one forked aggregate completed without
a crash with `1147` checks, `840` known fixture/environment failures, and `0`
errors. The registered CTest subset passed 4/4, and source,
fail-closed/runtime-evidence, and workflow YAML controls passed. This closes the
observed HWPML XML boundary path; production CVD, broader parser corpus,
cold-cache, sanitizer/multi-worker, release-runner, and remote rebuild
qualification remain open.

Local hashes are `hwp.c=be3f3b5a9d09532cf872fab3ff4c4fd278c30eaa27c14dabee5fc224b108f00b`,
`pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`pdfdecode.c=5aa98bba6753b3950edf207bbcfd8a25e4ee154b17acf743cf21fb4316cc73e7`,
`check_clamav.c=0737b2e7cc94744f84a620cbbb49ca76b12adefdaca52f56ae1e7a02147b0fd0`,
`check_bytecode.c=b0e9254e0dfc987ed3069d91d73dfab518fc069ebc05887ac77cfa071117a0f5`,
and `largefile_source_guards.sh=4016ec50dd8a6907ec30cd65f423ebf2fa3e9e1bb20a5f7b97a46da4810d9d15`.

Fresh MCP-SSH verification used `sonic1-camera-key`: host list
`req_32f6b1d1395e4a32935d36053c8b0184`, Docker status
`req_a17de6e58ad9491cb0f60a0c9e79a4bf`, inspect
`req_04a57ef44632451ca9395d3feaa829a1`, image identity
`req_8ea41451f46c4a4bb1ceba85f5467b33`, and container hashes
`req_d4300ebb99084dfa9b4660450e71b879`. All three containers were up on
`clamav-32gb:test-tools-742a8a4`, the primary `/workspace/ClamAV` bind was
read-only, and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote HWPML/PDF/decode/test/guard hashes differ from the current patch, so
Docker liveness and image/source provenance are verified without a remote
rebuild or qualification claim.

## HWP3 password-protection boundary hardening — 2026-08-15

The HWP3 parser previously returned `CL_SUCCESS` after recognizing a
password-protected document, leaving unsupported deep parsing indistinguishable
from a complete clean scan. That branch now records the sticky incomplete
state, disables fmap clean caching, and returns `CL_EPARSE` through the common
finalization path. The dedicated HWP3 Check group, including the existing
truncated parser case and new `test_hwp3_password_protection_is_fail_visible`,
passed 2/2.

Three consecutive current no-fork aggregate runs and one forked run completed
without a crash: `1148` checks, `840` known fixture/environment failures, and
`0` errors. The registered CTest subset passed 4/4, and source,
fail-closed/runtime-evidence, and workflow YAML controls passed.

Local hashes are `hwp.c=59e781add619b9fce9340d1051bd997490ffb59922c61b07d013c64849640e9f`,
`check_clamav.c=db823a713e0d8a0729c7aa4a31b2945a84f84ac27b85819d8bf9df219c9a7887`,
and
`largefile_source_guards.sh=0e6bb413a7a0ff120da8791d76b7f81a94e303c6b80157e7333a499c59e260a2`.

Fresh MCP-SSH verification used `sonic1-camera-key`: host-list request
`req_0ef932c6522e4fce9be05f156ee33a7f`, Docker status request
`req_40f0d5693b2c4c30bbc631e74a04ddd7`, and container-hash request
`req_48eb6b0b814c46c08e2c91951a791672`. All three validation containers were
up on `clamav-32gb:test-tools-742a8a4`; the remote HWP3 and test hashes differ
from the current local patch. Remote Docker liveness and source provenance are
verified, but no remote rebuild or qualification claim is made.

This closes the observed HWP3 password false-clean path. Production CVD,
broader parser corpus, cold-cache workload, sanitizer/multi-worker current-head
evidence, full release/CI runner, and remote rebuild qualification remain open.

## XAR XML reader boundary hardening — 2026-08-15

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

Fresh MCP-SSH verification used `sonic1-camera-key`: host-list request
`req_8ad4ce043c154c3cb2a07f07783a7fae`, Docker status request
`req_e59c7388fb224f5f954a4ab126d9e426`, and container-hash request
`req_b15eb96998f54f4481d50543edeed8fb`. All three validation containers were
up on `clamav-32gb:test-tools-742a8a4`; remote XAR, test, and guard hashes
differ from the current local patch. Remote Docker liveness and source
provenance are verified, but no remote rebuild or qualification claim is made.

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

## RAR extracted-member open boundary — 2026-08-15

The RAR bridge previously converted every `CL_EOPEN` from scanning an
extracted member into `CL_SUCCESS`, including the case where an extracted file
still existed but could not be opened. It now preserves the optional behavior
only when no output exists; an existing uninspectable output marks the scan
incomplete and non-cacheable and returns `CL_EPARSE`. This closes the observed
RAR extracted-member open false-clean path locally. The current ARM64 Clang
target built and the available `cl_api` group ran 90 checks with 1 known
missing-fixture failure, 0 errors, and no sanitizer diagnostics. The cached
configuration has `ENABLE_UNRAR=OFF`, so RAR runtime coverage remains pending.
Sonic1 remains unrebuilt because its scanner and test-source hashes differ
from the current worktree. Evidence is preserved at
`/private/tmp/clamav-32gb-rar-followup`.

## OLE2 VBA candidate-resolution boundary — 2026-08-15

The OLE2 VBA directory resolver previously reset every failed extracted `dir`
candidate to `CL_SUCCESS`; when all found candidates were malformed, no VBA
project was inspected and the outer scan could remain clean. It now tracks
found and successful candidates, marks an all-candidates-failed result
incomplete and non-cacheable, and returns the first failure. Missing candidates
remain optional and a successful candidate keeps the existing fallback path.
The current ARM64 Clang target built and the available `cl_api` group ran 90
checks with 1 known missing-fixture failure, 0 errors, and no sanitizer
diagnostics. Sonic1 remains unrebuilt because its source hashes differ from
the current worktree. Evidence is preserved at
`/private/tmp/clamav-32gb-ole2-candidate-followup`.

## TIFF structural-boundary follow-up — 2026-08-15

TIFF structural failures for truncated first-IFD offsets, directory entries,
next-IFD links, out-of-range value data, and out-of-order IFD links now mark
the scan incomplete and non-cacheable before optional heuristic reporting.
The four-case TIFF regression passed in the disposable ARM64 Clang build.
The broader aggregate had 1,315 checks, 782 known fixture/setup failures, and
0 Check errors; unrelated UBSan diagnostics in disassembly and bytecode tests
mean it is not a clean sanitizer-suite result. Evidence is preserved at
`/private/tmp/clamav-32gb-tiff-followup`.

Sonic1 Docker liveness was refreshed with `sonic1-camera-key`; all three
validation containers remain up, but remote TIFF, test, and guard hashes
differ from this worktree. No remote rebuild qualification is claimed.

## PE icon structural failures — 2026-08-15

PE icon matching now preserves fail-closed semantics when a declared icon
resource cannot be inspected completely. Resource offsets, bitmap headers,
palettes, pixel data, and icon-group boundaries that are truncated or outside
the map mark the scan incomplete and disable clean caching; reaching the
configured icon-count limit remains observable as `CL_EMAXSIZE`. This closes
the PE icon false-clean boundary without changing the intentional skip for
valid icons outside the matcher’s supported dimensions or shape.

## RIFF/ANI heuristic structural failures — 2026-08-15

The enabled RIFF/ANI exploit heuristic now preserves fail-closed semantics for
recognized RIFF/RIFX `ACON` payloads that end before a complete chunk header,
list type, declared payload, padding byte, or bounded nested-list traversal.
These failures mark the scan incomplete and non-cacheable and return
`CL_EPARSE`; valid non-exploit RIFF behavior remains unchanged. The regression
`test_riff_truncated_chunk_is_fail_visible` passed in the focused ARM64 Debug
static test build. The run recorded 93 checks, 3 known fixture/environment
failures, and 0 Check errors. Evidence is preserved at
`/private/tmp/clamav-32gb-riiff-followup`.

Sonic1 Docker liveness was refreshed with `sonic1-camera-key`; its current
source hashes differ from this worktree, so no remote rebuild qualification is
claimed. The separate `ENABLE_UNRAR=OFF` runtime gate remains open.

## JPEG broken-media structural failures — 2026-08-15

The enabled JPEG broken-media parser now preserves fail-closed semantics when
a recognized JPEG ends during its header, marker, segment-size, or segment-data
structure. These paths mark the scan incomplete and non-cacheable and return
`CL_EPARSE` to direct parser callers while complete scan contexts retain the
existing heuristic reporting path. The regression
`test_jpeg_truncated_structures_are_fail_visible` passed in the focused ARM64
Debug static test build. The run recorded 94 checks, 3 known
fixture/environment failures, and 0 Check errors. Evidence is preserved at
`/private/tmp/clamav-32gb-jpeg-followup.test.log`.

Sonic1 Docker liveness was refreshed with `sonic1-camera-key`; its current
JPEG, test, and guard hashes differ from this worktree, so no remote rebuild
qualification is claimed. The separate `ENABLE_UNRAR=OFF` runtime gate
remains open.

## HTML normalization mapped-read structural failures — 2026-08-15

The HTML normalizer previously converted a mapped-page read failure into an
ordinary end-of-input result. A partial normalized representation could then
be scanned as if normalization completed, and the HTML scanner ignored the
normalizer's boolean result. Mapped reads now carry an explicit input-error
bit; the normalizer marks the scan incomplete/non-cacheable and returns false,
while `cli_scanhtml` propagates `CL_EPARSE`. Exact end-of-map EOF remains a
normal completion path.

The regression `test_htmlnorm_mapped_read_failure_is_fail_visible` passed in
the focused ARM64 Debug static build. The HTML suite passed 7/7 checks and the
focused `cl_api` group recorded 94 checks, 3 known fixture/environment
failures, and 0 Check errors. Evidence is preserved at
`/private/tmp/clamav-32gb-htmlnorm-followup.test.log` and
`/private/tmp/clamav-32gb-htmlnorm-clapi.test.log`.

Sonic1 Docker liveness was refreshed with `sonic1-camera-key`; all three
validation containers remain up on `clamav-32gb:test-tools-742a8a4`. The
remote HTML-normalizer, scanner, test, and guard hashes differ from this
worktree, so no remote rebuild or current-source qualification is claimed.
The separate `ENABLE_UNRAR=OFF` runtime gate remains open.

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

Fresh MCP-SSH verification used host-list request
`req_fa90aaa8ac7347589d67bbfb894ecc9`, Docker status request
`req_233203b5d3ae41388afc121c11a05257`, and source-hash request
`req_0ad85b1d50fb4cbca6d05b7f1b998bfe`, all with `sonic1-camera-key`. The
three validation containers remain up for two days on
`clamav-32gb:test-tools-742a8a4`. Remote bytecode and guard hashes differ
from this worktree, so Docker liveness and provenance are verified without a
remote rebuild or current-source qualification claim.

## Script text-normalization mapped-read failures — 2026-08-15

The script normalizer previously allowed a mapped-page read failure to leave a
partial normalized representation eligible for scanning. It now carries a
sticky read-error bit; both script-normalization branches mark the scan
incomplete and non-cacheable and return `CL_EPARSE` when required input cannot
be read. The regression
`test_text_normalize_map_read_failure_is_fail_visible` passed in the focused
ARM64 Debug static build. The focused `cl_api` group recorded 95 checks, 3
known fixture/environment failures, and 0 Check errors. Evidence is preserved
at `/private/tmp/clamav-32gb-textnorm-followup.test.log`.

Sonic1 Docker liveness was refreshed with `sonic1-camera-key`; all three
validation containers remain up on `clamav-32gb:test-tools-742a8a4`. The
remote text-normalization, scanner, test, and guard hashes differ from this
worktree, so no remote rebuild or current-source qualification is claimed.
The separate `ENABLE_UNRAR=OFF` runtime gate remains open.

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

## On-access fail-closed transport handling — 2026-08-19

The on-access client now preserves socket wait timeouts as `CL_ETIMEOUT`
instead of reducing them to a generic read/write failure. The same result is
returned for connection-level timeouts, and the prevention path treats these
outcomes like parser, resource, and other incomplete results when deciding a
fanotify permission response. A failed `stat()` no longer passes an
uninitialized `STATBUF` into the scan client; it is recorded as incomplete and
the permission response is decided by the configured prevention policy.

This closes the on-access result-classification and unsafe-stat fall-through
gaps, but it does not claim that the legacy `OnAccessMaxFileSize` default has
been raised to 32 GiB. That default remains a separate release qualification
decision.

## 7-Zip temporary-output admission — 2026-08-20

The 7-Zip streaming member path now reserves each declared member size against
the shared `MaxTemporarySize` budget before creating its temporary output and
holds that reservation through extraction and the reservation-aware nested
scan. Every cleanup path releases the reservation, and an unrepresentable
member size fails closed as a resource failure. This closes an accounting gap;
decoder, filesystem, and Linux/Sonic1 runtime qualification remain open.

## CAB/CHM temporary-output admission — 2026-08-20

The libmspack CAB and CHM bridges now reserve each declared extracted-member
size against `MaxTemporarySize` before creating disk output and hold the
reservation through extraction and nested scanning. Negative CHM member
lengths are rejected as unrepresentable, and cleanup failures remain
fail-visible. This closes the temporary-quota bypass; dependency-complete
parser, sanitizer, and Linux/Sonic1 qualification remain open.

## RAR temporary-output admission — 2026-08-20

The enabled RAR extraction path now reserves each unencrypted member's
declared unpacked size against `MaxTemporarySize` before creating output and
holds the reservation through extraction and the reservation-aware nested
scan, avoiding a second charge for the same materialized child. Extracted-file
removal failures are now incomplete/non-cacheable instead of diagnostic-only.
RAR extraction remains subject to the optional UnRAR build and separate
dependency-complete runtime qualification.

## ARJ temporary-output admission — 2026-08-20

The enabled ARJ extraction path now reserves each unencrypted member's
declared original size against `MaxTemporarySize` before creating output and
holds that reservation through the nested descriptor scan. Encrypted members
are explicitly reported as uninspected rather than being treated as clean.
ARJ temporary-limit and encrypted-member behavior still require a
dependency-complete runtime qualification.

ARJ descriptor-close and temporary-directory removal failures are now
fail-visible across normal, limit, extraction-error, and detection exits while
preserving an earlier detection or parser result.

The ARJ compressed decoders now reject back-reference lengths that exceed the
declared member size, fail closed on invalid ring-buffer positions, and check
the final partial-output write before returning success. A malformed or failed
decoder therefore cannot hand a partial temporary member to the nested scan.

## ZIP temporary-output admission — 2026-08-20

The bounded ZIP readers now reserve the declared output size against
`MaxTemporarySize` before staging a member and retain the reservation through
the nested scan. The default ZIP callback uses the reservation-aware descriptor
scanner, and ZipCrypto's intermediate decrypted stream is accounted for while
its decompressed child is scanned. ZIP compression, encryption, filesystem,
and Linux/Sonic1 runtime qualification remain open.

## TAR temporary-output admission — 2026-08-20

The POSIX TAR member path now reserves each declared member size against
`MaxTemporarySize` and keeps the reservation through the nested scan and
cleanup. Members rejected by logical/file-size limits are skipped as complete
units, and truncated members are cleaned up without being nested-scanned.
Invalid POSIX `ustar` magic is now a sticky incomplete `CL_EPARSE` result after
checksum validation, rather than an unmarked parser error. TAR format-width,
parser, filesystem, and Linux/Sonic1 runtime qualification remain open.

## Embedded 7-Zip candidate admission — 2026-08-19

Embedded 7-Zip SFX matches now require the complete 32-byte start header and
checked 64-bit next-header range before a nested layer is admitted. A six-byte
magic match at the end of an unrelated payload is rejected as a candidate and
does not taint the parent scan. A candidate with a complete but malformed or
unsupported start header is retained as an explicit incomplete result. If the
confirmed start-header window fails through the fmap callback, the admission
branch preserves `CL_EREAD` and reports `7-Zip SFX start header could not be
read completely` instead of conflating the read failure with malformed input.

RAR4 SFX matches now receive the analogous bounded check for the fixed main
header prefix and declared header extent before UnRAR admission. RAR5 remains
covered by its ordinary top-level parser path and still requires separate SFX
qualification.

RAR input staged from a nested or non-file-backed fmap now reserves the staged
input against `MaxTemporarySize` through UnRAR and child scans, then uses the
shared temporary cleanup contract. Descriptor-close and temporary-removal
failures mark the scan incomplete/non-cacheable and preserve an earlier
stronger result, preventing a successful archive scan from hiding cleanup
failure. Compiled RAR/fault-injected cleanup and Linux/Sonic1 qualification
remain open.

Nested fmap scans forced to disk now reserve the complete staged range against
`MaxTemporarySize` until the child scan and cleanup finish. Temporary-file
creation, close, removal, and partial-copy failures remain fail-visible, and
the child uses the already-held reservation rather than double-counting the
same bytes. Compiled force-to-disk fault-injection and Linux/Sonic1 quota
qualification remain open.

EGG SFX candidates now require the complete fixed EGG header, a supported
version, a nonzero header identifier, and zero reserved bits before a nested
layer is admitted. Short magic-only matches are rejected without tainting the
parent; a complete but malformed or unsupported header is an explicit
incomplete result.

## Remaining embedded candidate admission — 2026-08-19

The NSIS, AutoIt, InstallShield MSI, and embedded PDF branches now perform a
bounded minimum-header check before creating a nested layer. Obvious weak or
short candidates are rejected without tainting the containing file; candidates
with a recognized marker but a malformed or truncated required structure are
reported as incomplete. The checks do not claim that these parser families
have been converted to 32 GiB deep streaming; their existing parser-specific
allocation, format, and qualification limits remain separate release gates.

## AutoIt bounded encrypted input and EA05 output — 2026-08-20

EA05 and EA06 compressed members decrypt their fmap input through a 64 KiB
window instead of materializing the complete encrypted member. The stream
reader checks the declared range, preserves MT/LAME keystream state across
refills, and makes short input or decoder-header failures incomplete.

EA05 decoded output now goes directly to a quota-accounted temporary file. Its
15-bit back-reference decoder retains only a 32 KiB history window plus a 64
KiB write buffer, and stored EA05 members are decrypted and written in 64 KiB
chunks. This removes the former 1 GiB individual-allocation dependency for
EA05 members; the format’s 32-bit size fields remain an explicit 4 GiB output
boundary. At this checkpoint, EA06 script decompilation still required random
access to its decoded member and retained an explicit unsupported-over-1-GiB
capability; the later bounded script-input and script-output spool milestones
remove that implementation limit.

Both EA05 and EA06 temporary child outputs are now admitted against
`MaxTemporarySize` and scanned through the reservation-aware descriptor entry
point, so a declared output reservation is not charged a second time at the
child boundary. The EA06 constraints described at this checkpoint were later
replaced by bounded input and output spools.

This is an implementation improvement, not parser-family qualification: valid
EA05 compressed/stored fixtures above 1 GiB, malformed decoder states,
temporary-quota exhaustion, sanitizer execution, and supported-build Sonic1
evidence remain release gates. The reproducible small stored/compressed
regression fixture generator is `tools/largefile_autoit_stored_fixture.py`.

The pinned Sonic1 Release build completed without compiler warnings. The
existing `clam.ea05.exe` fixture returned the same explicit incomplete result
with the pre-change and current sources. Reproducible 85-byte stored and
95-byte literal-only compressed EA05 fixtures both returned `OK` with the
current scanner; these are regression checks only and do not qualify large
valid members or the parser family.

## AutoIt temporary cleanup propagation — 2026-08-20

AutoIt EA05 and EA06 now treat generated-output close, temporary-file removal,
and extraction-directory removal failures as incomplete results. Cleanup
failures preserve an earlier detection and make an otherwise-clean generated
member non-clean. Valid large-member, malformed-decoder, sanitizer, and
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

## Clamscan directory-entry inspection closeout — 2026-08-20

Directory scans now count failed per-entry `LSTAT()` and symlink-follow
`CLAMSTAT()` calls, as well as entry-name allocation failures, as errors. A
vanished or inaccessible child is therefore not silently omitted from an
otherwise clean directory result; symlinks deliberately excluded by policy
remain normal exclusions.

Source guards and `git diff --check` are the current local evidence.
Fault-injected entry inspection, dependency-complete front-end builds, and
supported-build Sonic1 qualification remain release gates.

## BinHex short resource-fork boundary — 2026-08-20

BinHex no longer reports a clean result after silently abandoning a nonzero
resource fork shorter than the minimum resource-stream boundary. That path now
marks the scan incomplete and returns `CL_EPARSE`; a declared zero-length
resource fork remains valid. A focused encoded BinHex regression and source
guards cover the boundary. Compiled parser execution, legacy-mail corpus,
sanitizer coverage, and supported-build Sonic1 qualification remain release
gates.

## HFS+ non-empty fork block admission — 2026-08-23

`hfsplus_scanfile()` previously returned success for a fork with a non-zero
logical size and zero declared allocation blocks, skipping the required fork
contents. Such a fork now returns `CL_EFORMAT` and marks the layer incomplete;
the existing HFS+ fork regression covers the boundary. Compiled HFS+ corpus,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## UDF file-set descriptor completeness — 2026-08-23

The UDF descriptor walk previously treated a non-file-set descriptor after the
anchor as an optional omission and continued into file-list indexing. A
structurally incomplete volume could therefore bypass the required file-set
boundary and reach a clean result when its remaining lists happened to look
consistent. The accepted sequence now requires a file-set descriptor; a
wrong in-range tag is `CL_EPARSE`, while callback and out-of-map failures keep
their existing `CL_EREAD`/`CL_EPARSE` distinction. A focused synthetic
regression covers the missing-file-set case. Compiled UDF corpus, sanitizer,
and supported-build Sonic1 qualification remain release gates.

## Word macro-directory truncation — 2026-08-20

The legacy Word macro-directory reader now validates its declared range and
marks truncated, unreadable, unknown, or unallocatable macro metadata as an
incomplete result instead of treating it as “no macros.” A direct regression
and source guards cover the fail-closed boundary. Compiled legacy-Word/OLE,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## 7-Zip encrypted-content result propagation — 2026-08-20

Encrypted 7-Zip headers and members now remain incomplete even when the
optional encrypted-archive heuristic is enabled. The parser preserves the
heuristic alert and stronger detections, but cannot return clean after
ciphertext was left uninspected. Compiled encrypted fixtures, sanitizer, and
supported-build Sonic1 qualification remain release gates.

## OLE metadata and VBA input cleanup propagation — 2026-08-20

OLE summary-property parser errors and close failures are now retained by the
OLE2 temporary-directory scanner instead of being discarded after metadata
inspection. VBA module and project-directory input descriptor close failures
are also marked incomplete and preserve a prior parser failure or detection.

The ordinary and encrypted OLE2 embedded-stream handlers and the HWP5 summary
handler now apply the same rule: any non-success summary-property result marks
the layer incomplete and stops the nested scan, instead of propagating only a
timeout. This prevents malformed summary metadata from being reported as a
fully inspected clean layer.

Source guards and `git diff --check` are the current local evidence. Compiled
fault-injected OLE/VBA cleanup coverage, sanitizer execution, and supported
build Sonic1 qualification remain release gates.

## OOXML required-part failure propagation — 2026-08-20

OOXML content-types lookups now distinguish an absent optional property part
from a ZIP-directory or extraction failure. Non-success lookup and nested
property-parser results are propagated and marked incomplete, while a
declared-but-absent property part now becomes an explicit malformed-package
result. Property parts that are never declared remain optional.
The HWP-flavored OOXML entry points apply the same distinction to their
required version and content parts.

Source guards and `git diff --check` are the current local evidence. Compiled
malformed-archive and fault-injected ZIP/OOXML coverage, sanitizer execution,
and supported-build Sonic1 qualification remain release gates.

## UDF descriptor indexing failure propagation — 2026-08-20

UDF file-identifier and file-entry indexing now rejects a descriptor whose
declared size crosses its 2 KiB volume block, instead of stopping the local
walk and allowing the containing volume to continue as if the remaining
entries had been inspected. Allocation/indexing failures are propagated as
incomplete results; valid zero padding after the final descriptor remains
accepted.

Source guards and `git diff --check` are the current local evidence. Compiled
malformed-UDF fixtures, sanitizer execution, and supported-build Sonic1
qualification remain release gates.

## AutoIt EA06 member admission — 2026-08-20

After an EA06 header is admitted, the parser now requires the next member
record to begin with the format-defined `FILE` marker. A missing marker is
reported as malformed and incomplete instead of returning clean after
silently abandoning the EA06 layer. The focused public-scan regression is
registered in `check_clamav`; full AutoIt corpus, sanitizer, and
supported-build Sonic1 qualification remain release gates.

UDF extended file-entry descriptors are a separate intentional unsupported
boundary. Because the parser does not implement their allocation and
extended-attribute semantics, encountering one marks the layer incomplete and
returns an explicit unsupported result; it is never silently skipped.

## UDF fragmented-file extraction — 2026-08-20

UDF file entries may contain multiple short, long, or extended allocation
descriptors. The extractor now validates the complete descriptor list, checks
each extent against the input map, accounts for the aggregate logical and
temporary size, and concatenates the recorded extents into one bounded child
scan. This removes the former single-descriptor boundary that could reject
valid fragmented files or inspect only one extent. Embedded, continuation, and
other non-recorded extent forms remain explicit unsupported results.

A focused malformed descriptor-list regression and source guards cover the
alignment/fail-closed boundary. Compiled multi-extent UDF corpus coverage,
sanitizer execution, and supported-build Sonic1 qualification remain release
gates.

## UDF logical information-length accounting — 2026-08-22

UDF file-entry allocation descriptors have a format-defined information length
that must equal the sum of their per-extent information lengths. Extraction now
requires that exact accounting before materialization, rejects allocation lists
that are shorter or longer than the declaration, and marks transformed `ext_ad`
content unsupported when recorded bytes differ from logical bytes. A focused
synthetic regression covers the shorter-than-declared boundary; compiled
transformed-extent/read-fault, sanitizer, and supported-build Sonic1
qualification remain release gates.

## UDF required descriptor read status — 2026-08-21

UDF descriptor helpers now distinguish an in-range fmap callback failure from
an actually short or out-of-map descriptor. The generic-volume, required
volume, and file-volume descriptor walks preserve callback failures as
`CL_EREAD` and retain `CL_EPARSE` for unavailable ranges; both outcomes mark
the layer incomplete and non-cacheable. A focused generic-descriptor
fault-injection regression and source guards cover the boundary. Compiled UDF
corpus, sanitizer, callback-fault, and supported-build Sonic1 qualification
remain release gates.

## HFS+ catalog coordinate and size arithmetic — 2026-08-20

HFS+ catalog validation now computes the required node storage in 64-bit
arithmetic, preventing a large node count multiplied by node size from
wrapping to a small value and allowing a false clean walk. Catalog block
coordinates are also retained as 64-bit values until native fmap-range
validation, avoiding truncation for catalogs whose logical offsets exceed
4 GiB. Resource-compression block-table counts now use checked native-width
allocation/read sizing and return `CL_ERESOURCE` before a wrapped table can be
allocated or read. A focused synthetic catalog-size regression covers the
former 32-bit-product wrap; compiled large-volume corpus and Sonic1
qualification remain release gates.

## Structured service-oracle invariants — 2026-08-20

The service qualification oracle now validates the report schema version,
non-negative metric fields, root-size binding, and the complete-result contract.
Any report claiming `COMPLETE` must carry status `CL_SUCCESS`, a clean or
trusted verdict, and zero skipped operations. This prevents a contradictory
structured report from passing the service gate merely because its completion
string and alert text look correct; actual Linux, sanitizer, and Sonic1
qualification remain release gates.

## Mach-O universal-binary member ranges — 2026-08-20

Universal-binary architecture offsets and sizes remain their format-defined
32-bit fields, but their containing range is now promoted before addition and
checked against the full fmap length. A member whose end wraps or lies beyond
the input is marked incomplete and returns `CL_EPARSE` before nested dispatch;
the sparse regression exercises that boundary with a synthetic map at the
4-GiB edge. Full universal-binary corpus, sanitizer, and supported-build
Sonic1 qualification remain release gates.

HFS+ fork records that exhaust their eight inline extents are another explicit
unsupported boundary. The parser does not yet perform the required
`ExtentOverflow` B-tree lookup, so it marks the containing layer incomplete and
returns an unsupported result instead of scanning only the inline prefix. HFS+
resource compression is implemented through the bounded temporary-fork path;
its completion diagnostic is not an unsupported-feature indication.

XLM/BIFF8 `STRING` records carrying rich-text formatting runs or East-Asian
phonetic extensions are also an explicit unsupported boundary. Their extension
payload changes the record layout, so the extractor now stops with an
incomplete/unsupported result instead of scanning a potentially misaligned
macro prefix as complete.

TNEF message-body attributes are required content, not optional metadata. The
TNEF parser now marks an `attBODY` attribute incomplete and returns a visible
parser error when no stronger result exists; it no longer reports a clean scan
while leaving the message body uninspected.

## Scan-level temporary-directory cleanup propagation — 2026-08-20

When recursive temporary-directory mode is enabled, scan-level directory
removal now occurs before structured-report finalization. A removal failure is
marked incomplete and becomes `CL_EUNLINK` when no stronger result exists, so
the public status and structured completion report cannot disagree about a
cleanup failure.

Source guards and `git diff --check` are the current local evidence. Compiled
fault-injected scan-level cleanup, sanitizer execution, and supported-build
Sonic1 qualification remain release gates.

## ZIP temporary-directory cleanup propagation — 2026-08-20

The ZIP outer extraction directory now checks removal after member processing.
Cleanup failure marks the scan incomplete and returns `CL_EUNLINK` when no
stronger detection or parser/resource result already exists.

Source guards and `git diff --check` are the current local evidence. Compiled
fault-injected ZIP-directory cleanup, sanitizer execution, and supported-build
Sonic1 qualification remain release gates.

## UUEncode temporary-output accounting — 2026-08-20

Standalone UUEncode extraction now carries the active scan context into its
disk-backed fileblob, so decoded attachment bytes are charged to
`MaxTemporarySize` while they are materialized. A quota or fileblob write
failure is no longer hidden by a present UUEncode terminator; the parser
returns an incomplete result and does not scan partial output.

The focused temporary-quota regression and source guards are the current local
evidence. Compiled write-fault coverage, sanitizer execution, and supported
build Sonic1 qualification remain release gates.

## Legacy PE unpacker contiguous admission — 2026-08-19

Recognized legacy PE unpackers now pass their requested working size through a
shared admission check before allocating a contiguous buffer. Requests above
the global 1 GiB individual-allocation ceiling return `CL_ERESOURCE`, mark the
scan incomplete/non-cacheable, and do not begin partial unpacking. Temporary
file creation/open failures and recognized unpacker failures are likewise
sticky non-clean results. This is an explicit unsupported boundary for legacy
PE unpackers, not a claim that they can deeply inspect a 32 GiB executable;
bounded PE-unpacker conversion remains a release gate.

## VBA decompression failure propagation — 2026-08-19

VBA project and module decompression now treats seek failures, intermediate
output failures, and missing module streams as incomplete parser results.
OLE/VBA callers no longer silently continue as clean when a recognized macro
cannot be materialized or decrypted; they retain a deferred non-clean status
while allowing unrelated sibling content to be examined. Decompressed modules
now enter the 64-bit fmap matcher path, preserving full-map PCRE and
logical/YARA evaluation instead of narrowing the legacy buffer-matcher length
to 32 bits.

VBA source-module bodies no longer use the contiguous inflater path on builds
with the required codepage converter. A fixed 4 KiB decompression history feeds
a persistent bounded codepage converter, which feeds a stateful incremental
normalizer. The normalized source is written transactionally into the existing
quota-accounted project spool, and any decoder, conversion, deadline, quota, or
write failure rolls the partial module back before an explicit error marker is
written. The decompressed position and produced-byte accounting are 64-bit.

On certified 64-bit mmap builds, the compact project-directory metadata stream
uses the file-backed path described below. Non-mmap builds retain the legacy
contiguous inflater as an explicit unsupported release-profile boundary. The
public `cl_engine_set_clcb_vba` callback still requires one contiguous
normalized module; modules above 1 GiB continue through bounded scanner
inspection, but callback delivery is marked incomplete. Production Office/VBA
corpus, sanitizer, materialized large-module, Linux x86-64, and Sonic1
qualification remain release gates.

## Mail text-list accounting — 2026-08-19

The 64 MiB deep-parser materialization ceiling still covers ref-counted
`messageAddLine()` input and text moved between parser message objects. Ordinary
single-part text/application bodies and multipart bodies now switch to
quota-accounted disk spools immediately after header parsing, so their body
bytes are no longer retained as linked lists. A ceiling breach in a path that
still requires the legacy line representation marks the message truncated and
returns a failure; malformed headers, unsupported encodings, and streaming
decoder failures remain explicit incomplete results.

Truncated multipart children are rejected before `do_multipart()` writes an
attachment or enters a nested parser. The top-level body parser applies the
same check, so a child or moved message cannot be silently scanned as a
partial clean representation.

When phishing URL inspection is enabled, the URL extractor now consumes the
decoded message through a disk-backed fmap and bounded HTML normalization
reader instead of materializing a whole-message blob. Text URLs are recognized
with a 64 KiB chunked state machine, including prefixes split across chunk
boundaries. Mapping, normalization, read, and temporary-file failures remain
incomplete/non-clean; the former 100 KiB helper boundary is removed.

Normalized and handler-retyped views now inherit the logical object identity
of their source layer. They do not consume `MaxScanSize` or `MaxFiles` a second
time; bytes actually presented to matchers are charged to `MaxMatcherWork`.
Real extracted or decompressed children retain ordinary logical-content
accounting. An enabled image-fuzzy detector also marks calculation, metadata,
mapping, and contiguous-admission failures incomplete instead of allowing a
silent detector skip to return clean.

UTF-16 HTML normalization now uses the shared 4 KiB bounded UTF-16-to-UTF-8
decoder instead of the lossy UTF-16-to-ASCII helper. It accepts little- and
big-endian input with a BOM or an unambiguous first code unit, carries a high
surrogate across input windows, and reserves the exact decoded byte count
against `MaxTemporarySize` before each staged write. Odd code units, reversed
byte order, invalid surrogate sequences, ambiguous byte order, zero-progress
readers, short writes, mapping failures, child-scan failures, and temporary
cleanup failures are incomplete and non-cacheable. A focused Linux ARM64 GCC
case passes both endian forms with and without a BOM, a surrogate split exactly
at the 4 KiB boundary, exact reservation release, signature detection from the
decoded child, and malformed-input rejection. Production corpus, sanitizer,
Linux x86-64, materialized large-file, and Sonic1 qualification remain open.

OOXML metadata inspection now treats libxml2 reader-initialization failures,
truncated `[Content_Types].xml` and HWP metadata documents, and missing
required OOXML metadata parts as incomplete rather than clean. The OOXML
metadata callers opt into `MSXML_FLAG_FAIL_INCOMPLETE`, so XML parse errors are
not silently suppressed while the ZIP content scan continues. This closes a
false-clean metadata path; OOXML deep-parser corpus and supported-Linux
qualification remain open.

Structured reports now preserve detection precedence over sticky incomplete
parser state. A detection that terminates the scan is reported as
`DETECTION_TERMINATED`, even when cleanup or an earlier optional parser left an
incomplete marker; incomplete states still prevent clean completion and remain
visible for non-detecting scans. Operational I/O, temporary-file, lock, and
allocation failures are reported as `RESOURCE_FAILURE` instead of being
classified from parser wording.

The opt-in clamd report commands now carry the same versioned JSON schema as
the public `_ex2` library reports, including resource counters, configured
limits, file type, reason, and completion. Directory walks aggregate additive
logical/parser/detector counters and retain the highest-severity completion;
contiguous and temporary usage are reported as request peaks. The clamdscan
status parser accepts both this library schema and the compact legacy fallback
frame, so a numeric library verdict cannot be mistaken for a clean result
merely because it lacks the legacy text label.

`clamscan` now applies the same completion rule before printing or counting an
`OK` result. Non-detection reports in `UNSUPPORTED`, `MALFORMED_CONFIRMED`,
`RESOURCE_FAILURE`, `LIMIT_INCOMPLETE`, or `APPLICATION_ABORT` states are
returned and logged as errors for both file and stdin scans, including trusted
verdicts.

On-access prevention now applies its deny-on-error decision after preflight as
well as after a submitted scan. A stat failure or `OnAccessMaxFileSize`
rejection cannot become an allow merely because the worker skipped submission;
monitoring-only events retain their allow-and-log behavior.

## Parser-gate ceiling enforcement — 2026-08-19

The 32 GiB policy ceiling now applies consistently to `OnAccessMaxFileSize`
and to the public engine/settings controls for embedded-PE, HTML normalization,
normalized HTML, script normalization, and ZIP type-recognition gates. Values
above 32 GiB are rejected; exact 32 GiB is accepted. This prevents a front-end
or library caller from silently widening a parser-specific gate beyond the
qualified outer-file policy while the legacy small defaults remain in place.

## Fileblob temporary-spool accounting — 2026-08-19

MIME, bounce-message, TNEF, and other fileblob paths now reserve each staged
byte against the shared `MaxTemporarySize` budget while the temporary file is
being built. If a caller attaches the scan context after writing has started,
the existing file length is measured and admitted before more data is accepted.
Reservation failures and temporary-file write/stat failures mark the scan
incomplete; they cannot be hidden by the legacy fileblob caller convention that
only checks for `CL_VIRUS`. The build-time reservation is released before the
normal descriptor scan reservation and is always released during destruction.
Fileblob destruction now also marks the scan incomplete when closing or removing
its temporary spool fails, including destructive cleanup after a detection.

This closes the accounting and fail-visible spool gap. It does not yet claim
that every MIME form has identical semantics: ordinary single-part mail and
multipart bodies now use disk-backed spools, while compatibility-only bounce
heuristics and a few unsupported nested encodings continue to use explicit
fail-closed fallbacks.

TNEF now binds the scan context before attachment data is appended and creates
a disk spool for unnamed attachments, so data is admitted incrementally rather
than accumulating in memory. Short attachment reads and fileblob write or
resource failures are fail-visible and preserve an explicit non-clean result.

## Disk-backed MIME body spooling — 2026-08-19

Single-part text/application bodies and multipart bodies in both direct-message
and UNIX mbox ingress are finalized at the header/body separator and appended
incrementally to quota-accounted `fileblob` spools. Ordinary bodies are scanned
from the completed spool, while multipart boundaries are consumed one part at a
time and each child is scanned before the next child is staged. Base64 and
quoted-printable export is line-at-a-time. Failed creation, write, decoding,
boundary, or export paths mark the scan incomplete; raw body matching therefore
cannot turn a partial spool into a clean result. URL-phishing inspection now
reuses the completed raw spool through the file-backed normalization path, so
streamed text bodies do not require a whole-message heap view. Unsupported
nested encodings and compatibility-only bounce heuristics remain separate
release-gate work.

## XAR TOC streaming — 2026-08-19

XAR TOC decompression now reads the compressed extent in bounded chunks,
writes decompressed XML to a temporary file charged against the shared
`MaxTemporarySize`, scans that completed child, and feeds libxml2 through
`xmlReaderForIO`. The previous complete-map/complete-heap path and its
independent 64 MiB TOC cap were removed. Declared compressed and decompressed
lengths, decoder progress, exact output length, temporary writes, and XML
reader failures remain fail-visible. The XAR parser still has separate
format-specific and qualification gates; this change is not a claim of full
32 GiB XAR corpus qualification.

## HWPML bounded XML streaming — 2026-08-19

HWPML no longer rejects the complete XML layer at the former 64 MiB deep-parser
cap. Its attachment-bearing path now uses a libxml2 SAX push parser fed from
bounded fmap windows. Binary callback text is written incrementally to a
temporary file charged against `MaxTemporarySize`, and generic base64 fields
are decoded across input boundaries into a quota-accounted spool before the
nested scan. Malformed XML, invalid base64, temporary admission failures,
short writes, callback failures, and nested scan failures remain fail-visible.

This removes the specific HWPML whole-text-node/64 MiB gate. It does not claim
full HWPML corpus qualification, compressed-attachment decoder qualification,
or current-source Sonic1/build evidence; those remain release gates.

The legacy MSXML reader fallback now also charges callback and base64 temporary
outputs against `MaxTemporarySize`; completed base64 children use the
reservation-aware nested scanner, while custom callback handoffs retain the
spool reservation through the callback's own reserved nested scan. Allocation,
write, quota, and nested-scan failures remain fail-visible. Legacy XML-reader
memory behavior and broader Office/HWP corpus qualification remain release
gates.

## MSXML temporary cleanup propagation — 2026-08-20

The legacy and streaming MSXML paths now treat temporary descriptor close and
removal failures as incomplete cleanup results. A successful callback or
embedded-object scan can no longer hide a failed cleanup operation; an earlier
detection remains authoritative while the sticky incomplete state is retained.
This closes cleanup-only false-clean paths without changing the legacy
best-effort behavior for callers that do not request fail-incomplete XML
semantics. Compiled MSXML fault-injection, sanitizer, and supported-build
Sonic1 qualification remain release gates.

## XDP bounded XML streaming — 2026-08-19

XDP no longer rejects the complete XML layer at the former 64 MiB gate or
materializes `<chunk>` inner XML and its decoded payload in heap memory. XDP
now uses the bounded SAX push parser; each base64 chunk is decoded across XML
input boundaries into a temporary spool charged against `MaxTemporarySize`,
then scanned as a completed nested layer. XML, base64, temporary-write,
resource-limit, and nested-scan failures remain fail-visible.

This removes the specific XDP whole-text-node/64 MiB gate. XDP format corpus,
memory, sanitizer, and supported-build Sonic1 qualification remain open.

## DMG bounded XML streaming — 2026-08-19

DMG resource-fork XML is now parsed through a bounded SAX reader over an fmap
range. `<data>` Base64 text is decoded across XML callback boundaries into a
temporary spool charged against `MaxTemporarySize`; the parser retains only
one completed `mish` metadata block at a time. Metadata within the legacy
64 MiB sort boundary uses the existing validated array, while larger metadata
is exposed through a quota-accounted fmap and consumed one fixed-width stripe
at a time. Reconstructed partitions reserve their expected temporary output
while the nested scan runs, and optional retained XML copies use bounded,
quota-accounted writes. Malformed XML/Base64, temporary admission, write,
decoder, allocation, temporary-file, cleanup, and nested-scan failures remain
fail-visible.

Decoder initialization failures are fail-visible as well: allocation failures
from the ADC, deflate, and BZIP2 stripe decoders, plus XML temporary-path
allocation failure, mark the containing DMG scan incomplete before returning
the resource error.

This removes the former root-XML and decoded-metadata 64 MiB gates and
whole-text-node allocation. Large unsorted stripe tables use a bounded
external merge sort whose one auxiliary spool is admitted against
`MaxTemporarySize` and released before partition reconstruction. Real Apple
DMG corpus, large metadata, sanitizer, and supported-build Sonic1
qualification remain release gates; multi-segment DMGs remain explicit
unsupported input.

## DMG blkx metadata retention — 2026-08-22

The streaming DMG callback now validates and handles each completed `blkx`
metadata block before the XML parser can decode the next one. The decoded
metadata and stripe array are released on every callback return, including
timeout, resource, detection, and parser failures; large blocks remain
file-backed and are read one stripe at a time, while the bounded legacy array
is retained only where sorting is required. The outer XML range remains
streamed and quota-accounted.

Compiled multi-block DMG corpus, deterministic callback-timeout, sanitizer,
and supported-build Sonic1 qualification remain release gates.

## PDF file-backed staging — 2026-08-19

The PDF entry path no longer allocates the complete deep-parser input on the
heap or rejects it solely because it exceeds 64 MiB on mmap-capable builds. It
copies the fmap range to a temporary file charged against `MaxTemporarySize`
in bounded windows, then exposes that file through a read-only mapping so the
legacy pointer-based object parser has stable addresses without a proportional
heap allocation. Read, write, mapping, temporary-admission, and cleanup
failures remain fail-visible. Builds without mmap support retain the explicit
64 MiB fallback gate.

This removes the specific PDF root-input heap/cap bottleneck; it does not claim
that every PDF object/stream decoder is independently streaming or that a real
large-PDF corpus has passed supported-build, sanitizer, or Sonic1 qualification.

Legacy extracted-object and normalized-content temporary files now charge
incrementally against `MaxTemporarySize` and retain their reservations through
the reservation-aware nested scans. Read, write, quota, rewind, and cleanup
failures remain fail-visible. This closes the temporary-spool accounting gap
for extracted objects. Ordinary supported filter chains now use independently
quota-accounted intermediate spools; later milestones also add bounded object
streams, encryption, and per-filter DecodeParms arrays. Unsupported or mixed
filters remain recorded as `pdf-stream-over-1g`. Parser-family and large-PDF
qualification remain open.

## ALZ bounded reader and member streaming — 2026-08-19

ALZ no longer converts the complete fmap into a borrowed Rust slice. Its
header and member parser now operates on the bounded `Read + Seek` adapter,
seeks only to validated member ranges, and restores the next-header position
after each decoder. Stored, Deflate, and BZIP2 output is delivered in bounded
chunks to the scanner’s temporary spool; the previous per-member `Vec<u8>`
accumulation is retained only by the compatibility byte-slice API used by
unit tests and callers that explicitly request it. Temporary admission,
decoder completion, short reads, member limits, unrepresentable declared
sizes, and nested scan failures are fail-visible; the scanner never silently
skips an ALZ member's metadata because a platform-width conversion failed.
The bounded parser also requires the ALZ end-of-central-directory marker;
physical EOF before that marker is now an incomplete archive rather than a
successful prefix scan.

This closes the ALZ whole-root and whole-member materialization path. ALZ
third-party-equivalent corpus, sanitizer, and concurrent-RSS qualification
remain release gates.

## LHA/LZH declared-output admission — 2026-08-20

The bounded LHA/LZH scanner now converts decoder size fields to `size_t` with
checked overflow handling, consumes decoder output in 64 KiB chunks, and rejects
the next chunk before writing it when it would exceed the member's declared
uncompressed size. This prevents malformed output from temporarily extending a
quota reservation before the final size comparison. Empty members now undergo
the same CRC validation as non-empty members. The focused Rust regression covers
exact-fit, overrun, and accounting-underflow cases; corpus, sanitizer, RSS, and
large-member qualification remain release gates. The public parser entry now
also places the complete decoder lifecycle—construction, header access, member
reads, CRC validation, and next-header traversal—inside one panic boundary;
unexpected decoder panics become a sticky incomplete `CL_EFORMAT` result rather
than escaping the scan callback.

## Rust temporary-spool ownership — 2026-08-19

Rust ALZ/OneNote temporary spools now release their shared temporary-space
reservation exactly once. Cleanup honors `keeptmp` and marks close/removal
failures sticky; a failed rewind before nested scanning is also incomplete.
Spool-written and source-copy counters now use checked arithmetic and return a
resource/read failure on accounting overflow instead of saturating silently.
This prevents early counter release from allowing later staging beyond
`MaxTemporarySize` and keeps cleanup non-clean/non-cacheable. Compiled
Rust/CTest and Linux/Sonic1 RSS/temporary-quota qualification remain open.

## Capability manifest and public setter boundaries — 2026-08-19

The checked capability manifest now covers the required library and service
ingresses, every parser dispatch branch, the AC/BM/byte-compare/hash/PCRE/
logical/YARA/bytecode/fuzzy-image matcher families, the large-file-relevant
build switches, and deliberate unsupported boundaries. `pending` rows are
coverage obligations, not qualification claims; unsupported rows require the
explicit `unsupported` status.

Public numeric engine setters now reject negative values and narrowing
overflow for their 32-bit and 8-bit destinations, and settings-copy apply
rejects AC depth values that cannot be represented by the matcher ABI. HTML
no-tags normalization now measures the generated `notags.html` file against
`MaxHTMLNoTags`, rather than applying that limit to the original input length;
an over-limit required view remains fail-visible rather than a silent parser
omission. The new unit regressions and source guards are registered, but a
supported Linux compile and runtime execution remain open.

## HTML normalized-view size admission — 2026-08-21

The HTML scanner now requires its generated `nocomment.html` and opens and
sizes the generated `notags.html` view before
dispatching it to the nested scanner. `MaxHTMLNoTags` therefore applies to the
view it names, while an input whose markup is larger but whose normalized text
fits is no longer rejected solely because of its source length. File-stat
missing/stat failures and generated views over the limit remain sticky incomplete results,
non-cacheable, and visible to the caller. The focused unit regression covers
both the over-limit failure and the input-versus-generated-size distinction;
supported-build and parser-corpus qualification remain open.

## HTML normalized metadata allocation propagation — 2026-08-23

HTML tag-argument insertion, tag-value replacement, link-content finalization,
form-data insertion, and the file-backed phishing text-URL extractor now
propagate allocation failures. The normalizer marks those failures incomplete
instead of silently dropping an attribute or URL and later publishing a
partial normalized view as successful. The existing chunked output quota,
deadline, close, and nested-scan checks remain in force; compiled allocation
fault injection, sanitizer, and full HTML/MHTML corpus qualification remain
release gates.

## TNEF zero-length attribute checksum accounting — 2026-08-23

TNEF zero-length attributes now consume their mandatory two-byte checksum
before the next attribute header is read. This prevents a nonzero checksum
from shifting the parser state and preserves explicit read or parse-incomplete
results when the checksum cannot be consumed. The focused exact-EOF regression
is recorded in the source evidence; compiled TNEF corpus, sanitizer, and
Sonic1 qualification remain open.

## RIFF declared-container boundary accounting — 2026-08-23

RIFF exploit inspection now honors the root RIFF size and each nested `LIST`
chunk's declared payload range. Child headers cannot escape their containing
list into a sibling or overlay, and padding/coordinate overflow is explicitly
incomplete. The focused empty-list boundary regression is recorded in the
source evidence; compiled RIFF corpus, fault injection, sanitizer, and Sonic1
qualification remain open.

## RTF split reserved-field accounting — 2026-08-23

When an embedded RTF object’s eight-byte reserved field crosses an 8 KiB fmap
chunk boundary, the parser now retains the bytes already consumed before
reading the next chunk. This prevents the following payload-size field from
being interpreted as padding and keeps object extraction aligned with the
format state machine. The focused boundary regression and existing fail-closed
object cleanup remain part of the source evidence; compiled RTF/OLE, sanitizer,
and Sonic1 corpus qualification remain open.

## OneNote bounded legacy extraction — 2026-08-19

The scanner-facing OneNote callback now borrows modern-parser attachment bytes
from the staged root mapping and writes them to the quota-accounted temporary
spool before scanning, eliminating the previous intermediate whole-member
allocation. The legacy fallback now probes the header through `FMapReader` and
scans marker, header, and payload ranges in bounded chunks, streaming each
attachment directly into that spool without mapping the complete root. Sink
write, scan, and truncated-input failures abort the attachment and remain
fail-visible. The owned `ExtractedFile` iterator remains for compatibility
callers. The third-party modern root parser is still slice-based and therefore
uses the staged mapping only through its explicit 256 MiB whole-input cap;
larger modern documents return `CL_ERESOURCE` before staging or mapping.
Legacy documents continue to use the bounded reader path above that cap. This
is a deliberate unsupported boundary until the upstream parser exposes a
reader-backed API; OneNote corpus, sanitizer, and RSS qualification remain
open.

## OneNote materialized corpus dispatch — 2026-08-25

The current production-linked GCC OneNote oracle exercises all three
materialized `.one` fixtures through the scanner-facing `scan_onenote()` entry
point with an exact child matcher. Because the root raw scan is bypassed, the
expected alert demonstrates that parser dispatch and the extracted-attachment
handoff are active. The focused `onenote` case passes 2/2; complete corpus,
full-C ABI, sanitizer, certified Linux x86-64, materialized large-file,
production-CVD/service, and Sonic1 qualification remain open.

## CAB materialized corpus dispatch — 2026-08-25

The current production-linked GCC MSPack oracle invokes `cli_scanmscab()`
directly on the materialized `clam.cab` fixture, bypassing the root raw scan.
Its embedded marker is therefore detected only after CAB member extraction and
nested child scanning. The focused `mspack` case passes 6/6, including the
existing CHM corpus and decoder-boundary cases; complete CAB/CHM and
InstallShield corpus, full-C ABI, sanitizer, certified Linux x86-64,
materialized large-file, production-CVD/service, and Sonic1 qualification
remain open.

## MSEXPAND materialized corpus dispatch — 2026-08-25

The current production-linked GCC MSEXPAND oracle scans materialized
`clam.exe.szdd` through public `CL_TYPE_MSSZDD` dispatch. Its exact child-offset
matcher is not satisfied by the compressed root and is reported only after
decompression and nested handoff. The focused `msexpand` case passes 5/5;
complete SZDD corpus, full-C ABI, sanitizer, certified Linux x86-64,
materialized large-file, production-CVD/service, and Sonic1 qualification
remain open.

## PDF decoder input-width boundary — 2026-08-19

The PDF stream decoder API now carries the source stream length as `size_t`
through the caller instead of narrowing it to `uint32_t` at the object
boundary. The token buffer is also subject to the shared 1 GiB individual
allocation ceiling, so a stream routed through a residual legacy token larger
than `CLI_MAX_ALLOCATION` is rejected before decoding with `CL_ERESOURCE`.
Those legacy implementations still use 32-bit input lengths and reject a
larger stream before narrowing. Ordinary unencrypted streams and chains made
only from the five supported filters now bypass both boundaries through the
bounded reader/spool path. Later milestones address object streams, encryption,
and per-filter DecodeParms arrays. Unsupported or mixed chains remain release
gates. Every residual
rejection marks the containing scan incomplete and cannot be treated as a
scanned prefix.

PDF object and object-stream positions are also native-width now. The
object-stream pair cursor and parsed object start no longer narrow to
32-bit values before containment checks, extraction, or diagnostics; a focused
unit regression preserves an offset above 4 GiB. Object-stream qualification
still remains separately bounded by the explicit legacy filter-input boundary.
Object-stream containment now uses subtraction-based checked bounds for both
the current and next object offsets, so malformed large values cannot wrap the
first-plus-offset calculation before the parser rejects them.

The PDF ARC4 primitive now accepts `size_t` lengths as well. This removes the
remaining call-site narrowing in encrypted-string and encrypted-stream
decryption, so raising the explicit contiguous-buffer ceiling later cannot
silently decrypt only a truncated prefix. The current PDF decoder still
retains the documented 1 GiB allocation boundary.

The legacy PDF parser stores an object reference as a packed 32-bit value
(24-bit object number plus 8-bit generation). All direct, indirect, object
stream, encryption, string, dictionary, and array reference paths now reject
values outside that representable range before shifting or masking them. An
out-of-range reference marks the scan incomplete instead of aliasing an
unrelated object through integer wraparound; the focused regression covers the
upper valid boundary and both overflow cases.

The capability manifest retains `pdf-stream-over-1g` for the deliberately
unsupported residual paths. This is not an outer-file limit: ordinary
unencrypted supported filters and their chains use native-width bounded
readers, and later milestones cover supported object streams, encryption, and
per-filter DecodeParms arrays. Unsupported or mixed chains may still require
the legacy contiguous token.
Crossing that token's 1 GiB allocation or 4 GiB width boundary makes the
containing scan incomplete rather than allowing a truncated or wrapped prefix
to be treated as complete.

## TIFF IFD cursor width — 2026-08-20

Classic TIFF on-disk offsets remain 32-bit, but the parser's working IFD
cursor is now `size_t`. Advancing a malformed IFD located near `UINT32_MAX`
therefore cannot wrap back to the beginning of a larger map. The focused
regression uses a sparse logical map above 4 GiB and records the post-IFD
read coordinate; TIFF parser-family and complete corpus qualification remain
open.

## ELF64 executable metadata coordinates — 2026-08-20

ELF64 entrypoint and section coordinates now retain their native 64-bit values
in a parallel matcher metadata view. Relative `EP`, `SL`, `SX`, and `SE`
offset calculations therefore remain correct when a valid section or entrypoint
starts above 4 GiB; the legacy bytecode-facing executable structure remains
32-bit for ABI compatibility.

If an ELF coordinate cannot be represented by that legacy ABI, the narrowed
section is not exposed as a zero-offset section. Legacy bytecode metadata is
disabled for the layer and the scan is marked incomplete, while native raw and
relative matcher paths continue using the complete coordinates. Program-header
interval and entry-offset arithmetic is subtraction/check based and malformed
overflow returns a fail-visible parser error. Sparse-map regressions cover both
native coordinate preservation and entry-offset overflow; full ELF parser,
bytecode-v2, sanitizer, and supported-build Sonic1 qualification remain open.

## Script normalization matcher boundary — 2026-08-19; superseded 2026-08-22

The earlier script path passed normalized windows through the legacy 32-bit
matcher subject ABI, so normalized output above 4 GiB was an explicit
incomplete boundary even when the outer 32-GiB policy allowed the input. The
current path writes the complete normalized view to quota-accounted temporary
storage and scans one child fmap through the native-width matcher path. The
obsolete `script-normalization-over-4g` capability boundary is therefore
removed; parser, temporary-space, sanitizer, corpus, and Sonic1 qualification
remain release gates.

## Script normalization window accounting — 2026-08-21

The preceding implementation treated matcher overlap as window context rather
than new output. That evidence remains useful for the focused regression
`test_script_normalization_window_offset_is_stable`, which covers an absolute target
signature beyond the first normalized window; compiled scanner, sanitizer, and
production-signature qualification remain release gates.

## PE resource-entry window bounds — 2026-08-21

The PE Swizzor/resource heuristic now validates the named and unnamed entry
array against the containing fmap and reads each 8-byte unnamed entry through
an unlocked bounded view. It no longer retains an attacker-declared entry
window while recursively inspecting child resources, and RVA additions are
checked before recursion or translation. Static guards and whitespace
validation pass; compiled PE corpus, sanitizer, and large-file qualification
remain release gates.

## UDF descriptor-window lifetime — 2026-08-21

UDF descriptor helpers now release a locked view when the tag does not match
the required descriptor type. Accepted logical-volume and partition
descriptors are copied into bounded metadata snapshots before extracted-file
traversal, so nested extent reads no longer retain their original fmap
windows. Static guards and whitespace validation pass; compiled UDF corpus,
sanitizer, and large-file qualification remain release gates.

## Bytecode v2 PDF coordinate bridge — 2026-08-19

The internal PDF-hook context now retains native-width PDF size and start
coordinates. Format-8 bytecode has appended 64-bit PDF object-size and
object-offset accessors; all existing v1 API entries and numbering remain
unchanged. The legacy offset accessor returns its invalid sentinel when the
coordinate is not representable instead of wrapping. The independently
compiled format-8 fixture and supported-build interpreter/JIT qualification
remain release gates.

## NSIS non-solid bounded input — 2026-08-19

NSIS non-solid members no longer map their complete compressed payload before
decoding. Stored and compressed members are read from the fmap in bounded
64 KiB chunks, decompressed into bounded output chunks, and written to the
existing temporary extraction file while charging output against the shared
temporary quota through the nested scan. Exact input exhaustion, decoder
terminal state, trailing compressed data, output limits, and write failures
are fail-visible. Solid NSIS archives now retain decoder state while refilling
64 KiB fmap windows, skip the four-byte archive CRC, and write each extracted
member through the same temporary-byte quota as non-solid members. NSIS corpus,
sanitizer, and RSS qualification remain open.

## SIS bounded member extraction — 2026-08-19

Both legacy and 9.x SIS member handlers now read fmap input in 64 KiB windows
and stream stored or zlib-compressed output directly into temporary files.
Declared input and output sizes are checked before extraction, output is
reserved against `MaxTemporarySize` until the nested descriptor scan finishes,
and zlib completion, exact output length, trailing input, read, write, and
time-limit failures mark the scan incomplete rather than scanning a partial
member. A production-linked exact-signature oracle now proves the synthetic
compressed member reaches nested matching as `SISDATA!`; it no longer relies
on a clean return as indirect evidence. SIS parser corpus, sanitizer, and
large-payload/Sonic1 qualification remain open.

## SIS temporary cleanup propagation — 2026-08-20

Legacy and 9.x SIS extraction now treats temporary descriptor close failures
and top-level temporary-directory removal failures as incomplete results. A
cleanup error cannot replace an earlier detection, while an otherwise-clean
member or archive becomes non-clean. SIS parser corpus, sanitizer, and
supported-build Sonic1 qualification remain release gates.

## NSIS solid bounded input — 2026-08-19

The stateful solid NSIS path no longer maps the complete compressed archive or
reserves a contiguous input allocation. It keeps the decoder state across
member boundaries, reads at most 64 KiB at a time, excludes the archive CRC
from decoder input, and treats short input, unexpected trailing data, and
partial member output as incomplete. Extracted members remain disk-backed and
are charged incrementally against the shared temporary quota before scanning.

## NSIS temporary cleanup propagation — 2026-08-20

NSIS extraction now treats output close, extracted-member removal, and
temporary-directory removal failures as incomplete results. Cleanup failures
cannot overwrite an earlier detection; otherwise-clean extraction now returns
a non-clean error and retains the sticky incomplete state. Parser-family,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## Normalized JavaScript matcher-work accounting — 2026-08-19

JavaScript normalization output is now admitted against the shared
`MaxMatcherWork` budget at each bounded 64 KiB output flush before the bytes
are written to the temporary normalized-script file. The bytecode normalization
path also tracks consumed input with checked arithmetic, and HTML normalization
uses the same context-aware output path. A matcher-work admission failure is
fail-visible and prevents the normalized view from being scanned as complete.

## Image-fuzzy detector result propagation — 2026-08-19

Image-fuzzy hashing is an enabled detector family, so its bounded allocation,
mapping, metadata, and Rust-calculation failures must not be discarded by the
image dispatch branches. Those branches now retain the calculator's non-clean
result while the calculator marks the scan incomplete; the matcher-side FFI
failure path also reapplies the sticky incomplete state before returning its
error. This preserves the explicit bounded rejection contract instead of
allowing a failed optional detector to look like a complete image scan.

## EGG bounded member extraction — 2026-08-19

The scanner-facing EGG path no longer maps a complete compressed block or
retains a complete decoded member before scanning it. Stored, Deflate, BZIP2,
and LZMA blocks are read from the fmap in 64 KiB windows, decoded into 64 KiB
buffers, and written directly to a temporary descriptor. The LZMA path
preserves decoder state across refills and checks its declared output size and
terminal marker. The declared member size is reserved against
`MaxTemporarySize` before extraction, and the reserved descriptor scan avoids
double-counting that spool. Short reads, decoder termination failures,
trailing compressed bytes, output-size disagreements, deadline crossings,
write failures, unsupported AZO, and solid EGG remain explicit incomplete
results.

The legacy `cli_egg_extract_file()` byte-buffer API remains available for
compatibility callers and retains the global individual-allocation guard; it
is not used by the production scanner. EGG corpus, sanitizer, and supported
Linux x86-64 Sonic1 qualification remain release gates.
The pinned Sonic1 Release overlay built successfully after the LZMA change, and
the 118-byte fixture generated by `tools/largefile_egg_lzma_fixture.py` returned
`OK` from the rebuilt `clamscan` against the test database. This is focused
regression evidence only; malformed, large-member, corpus, sanitizer, and
service qualification remain open.
The compatibility limitation is recorded as
`egg-compat-member-over-1g`; it does not constrain the scanner-facing
streaming path.

## clamd startup capability manifest — 2026-08-19

After engine initialization, clamd emits one machine-readable
`Large-file capability manifest` line. Schema 2 records the compiled pointer,
`size_t`, and `off_t` widths; hard 32 GiB/64 GiB/resource ceilings; active
engine limits; structured-report and bytecode-v2 support; fd-passing
and private file-backed-mapping availability; and an explicit
`parser_qualification=unclaimed` marker. This
binds runtime logs to the actual binary/configuration without turning a
startup capability description into parser or service qualification evidence.
The startup admission check also reads the clamd front-end limits
`StreamMaxLength` and `OnAccessMaxFileSize`; an explicitly enlarged stream or
on-access ingress can no longer bypass the large-file host-resource gate just
because the engine's `MaxFileSize` field remains at a historical value.

Certified large-file startup now also fails closed when `RLIMIT_FSIZE` cannot
be measured or is lower than the largest configured ingress. On Linux, the
configured temporary directory must have a measurable filesystem type and must
not be backed by tmpfs or ramfs; temporary-capacity qualification represents durable
disk-backed staging rather than memory that competes with the 48 GiB admission
floor. Deterministic policy tests cover finite, exact-boundary, unlimited,
query-failure, disk, tmpfs, and ramfs outcomes. Current-source Linux x86-64
startup and Sonic1 runtime evidence remain release gates.

The same certified admission gate requires `MaxThreads=1`. Its memory and
temporary requirements describe one active scan, and the first-release
contract requires a second request to remain queued without staging or
reserving resources. A multi-worker configuration must therefore be rejected
until admission is changed to reserve independently measured resources for
every simultaneously active worker.

Linux memory admission resolves the daemon process's actual cgroup membership
and controller mount from `/proc/self/cgroup` and `/proc/self/mountinfo`. It
walks the visible cgroup v2 or v1 memory hierarchy and uses the smallest finite
`limit - current` headroom instead of assuming that hierarchy-root files apply
to a nested service or container. An applicable hierarchy with an unreadable,
malformed, or mismatched limit/current pair fails closed. Deterministic v1 and
v2 fixtures cover inherited limits, an unlimited leaf under a bounded parent,
an exhausted leaf, a missing usage counter, hybrid v2/v1 controller fallback,
and multiple matching mounts without hiding a visible ancestor limit;
current-container probing also passes locally.

The release-readiness gate is separate from the capability coverage validator.
`bounded` and `pending` rows always make it exit nonzero, including in concise
status mode. A `qualified` row must reference an absolute runtime or service
evidence directory whose existing verifier passes, whose source-manifest hash
matches the row, and whose source content still matches the current checkout
outside the capability status control itself. Synthetic evidence is accepted
only by an explicitly supplied test manifest and can never qualify the
authoritative release manifest.

## Milter structured-report alert and nonblocking transport — 2026-08-19

The milter structured-report client now preserves the report's `last_alert`
signature name for reject formatting, logging, and `VirusEvent` rather than
using a generic transport label. The milter socket is nonblocking, so its
framed-report reader now performs deadline-aware exact reads, handles short
reads and `EAGAIN`, enforces the shared 16 MiB report-frame cap, and rejects
malformed alert strings. This improves transport correctness but does not
replace the required supported-Linux large-transfer, sanitizer, or milter
qualification runs.

## RFC2047 bounded failure propagation — 2026-08-19

RFC2047 mail-header decoding now propagates bounded materialization and decoded
blob failures to the scan's sticky incomplete state. The decoder no longer
ignores `messageAddStr()` failure or returns a partially decoded header after
`messageToBlob()` rejects an incomplete materialization. This keeps a required
mail-parser view from being treated as complete merely because raw header
matching continued.

## Fileblob scan error preservation — 2026-08-19

`fileblobScanAndDestroy()` now preserves operational and parser errors from
`fileblobScan()` instead of translating every non-detection into `CL_CLEAN`.
It also marks the owning scan incomplete for an otherwise-unclassified scan
failure. This closes a generic false-clean path for disk-backed MIME
attachments and other parser-generated temporary files.

## Unsupported nested MIME results — 2026-08-19

Unsupported transfer encodings and `message/*` formats, disabled partial
message reassembly, external-body references, and failed nested-message
parsing now set the sticky incomplete result. The supported
`disposition-notification` path remains unchanged. This prevents a required
MIME branch from being skipped while a mailbox-level scan is still reported as
clean.

Mail attachment, bounce, BinHex, and text-part callers now share a
fail-visible fileblob wrapper. It handles missing temporary spools and
propagates non-clean scan errors, including the formerly unsafe direct
`fileblobScanAndDestroy(textToFileblob(...))` call.

Deferred multipart text aggregation now scans its final temporary text-part
spool before destroying it. Spool creation, materialization, detection, and
scan errors are propagated instead of allowing the aggregated text view to be
discarded uninspected.

The mail spool wrapper also restores the active scan context after
`textToFileblob()` clears it for legacy conversion callers. This ensures the
authoritative descriptor scan is actually performed rather than being treated
as a no-context clean result.

## SFX candidate error classification — 2026-08-19

ZIP, CAB, and ARJ embedded candidates now distinguish a disproven signature
(`CL_EFORMAT`, rejected without tainting the parent) from a recognized but
truncated, unreadable, or resource-failed header. The latter marks the parent
scan incomplete and preserves the non-clean result instead of silently
discarding the header-check failure.

Embedded PE recognition now treats `MaxEmbeddedPE` exhaustion as an explicit
incomplete/resource result. The former legacy 32-bit containing-offset ABI
boundary is handled by rooting header admission in a bounded child fmap, so a
recognized candidate above 4 GiB is no longer skipped before its PE header is
checked.

Embedded PE header admission now keeps generic “not actually PE” results as
disproven candidates, but marks truncation, timeout, resource, allocation, and
read failures incomplete. A failed confirmed header inspection can no longer
be mistaken for an unrelated magic hit.

## Incomplete-scan cache exclusion — 2026-08-19

The clean-cache lookup and insertion paths now fail closed when the active
scan context is incomplete or timed out. This is enforced both in
`cli_magic_scan()` and in the cache implementation itself, so a cached child
cannot bypass the sticky incomplete result during nested-scan unwinding, and
no incomplete layer can be inserted as clean. The focused cache regression is
registered; compiled Linux/Sonic1 execution remains a release gate.

## Mandatory raw pass after HTML parser skips — 2026-08-19

The legacy `HTMLSKIPRAW` dynamic-configuration bit no longer suppresses the
outer raw matcher in the large-file scanner path. Raw signatures remain
authoritative even when the enabled HTML parser rejects an input at
`MaxHTMLNormalize` or another normalized-view boundary. A compiled regression
loads the in-tree NDB marker and verifies detection from an over-cap HTML
input; Linux/Sonic1 execution remains a release gate.

## ISO9660 temporary and traversal failures — 2026-08-19

ISO9660 extracted-file staging now marks temporary-file creation, nested scan,
close, and cleanup failures incomplete. Directory traversal hashset allocation
and extension failures are also sticky, so a recognized ISO cannot return a
clean result after an extracted file or required traversal state was not fully
processed. Source guards cover these paths; compiled Linux fault-injection and
optical-image corpus execution remain release gates.

## 7-Zip member failure propagation — 2026-08-19

The 7-Zip scanner now marks member-name allocation and temporary-file creation,
close, and cleanup failures incomplete. It also preserves non-virus failures
from metadata matching and nested extracted-file scanning instead of continuing
as though the member completed. Detection and application-abort precedence is
retained; source guards cover the paths, while compiled Linux and broader
encrypted/malformed 7-Zip corpus execution remain release gates.

7-Zip member-name lengths now retain the SDK's native `size_t` type and are
checked before conversion to an allocation size. A malformed or unrepresentable
name length returns an explicit resource/incomplete result instead of wrapping
through an `int` or byte-count multiplication.

## XAR temporary failure propagation — 2026-08-19

XAR TOC temporary-space reservation and creation failures now mark the scan
incomplete. Temporary close and removal failures are reported, and subdocument
scan or write errors can no longer be replaced by a successful cleanup return;
the same preservation applies to member and TOC cleanup at the final unwind.
Source guards cover the paths; compiled Linux fault-injection and broader XAR
corpus execution remain release gates.

## ZIP extraction operational failures — 2026-08-19

The bounded ZIP reader now treats output-write, temporary-file allocation/open,
rewind, close, temporary-map creation, and cleanup failures as incomplete
inspection states. The same sticky state is applied to the legacy extraction
fallback and the traditional ZipCrypto staging path, so a resource or I/O
failure cannot allow partial member output to be nested-scanned or allow the
containing archive to be reported as clean. Source guards cover the failure
reasons and error classifier, and the Linux static unit-test harness registers
write- and close-fault regressions; their compiled execution remains a release
gate.

## OLE10 embedded-object boundary — 2026-08-19

The RTF/OLE10 bridge now rejects truncated or out-of-range object headers and
payloads before scanning a partial temporary file. Rewind, copy, nested-scan,
temporary-output, and cleanup failures are fail-visible and mark the containing
scan incomplete/non-cacheable. The focused `test_ole10_truncated_object_is_fail_visible`
regression is registered; supported-Linux execution, sanitizer coverage, and
broader legacy OLE/RTF corpus qualification remain release gates.

The bridge now reserves the declared OLE10 payload before temporary-file
creation and retains that reservation through the nested scan. Quota rejection
is fail-visible and cannot be bypassed by the legacy embedded-object path. The
focused `test_ole10_temporary_limit_is_fail_visible` regression is registered;
compiled execution and broader Office/RTF corpus qualification remain release
gates.

## XLM extraction completion boundary — 2026-08-19

The Excel 4/XLM extraction path now treats a missing materialized BIFF stream,
truncated BIFF record headers, temporary-output flush/close failures, and
non-clean nested scans as incomplete and non-cacheable. A partial XLM staging
file is no longer scanned as if it were complete. The focused missing-input and
truncated-header regressions are registered. Recursive OLE2 dispatch now skips
names belonging to another extraction subtree while preserving real XLM/image
extraction failures. Compiled Linux/Sonic1 execution, sanitizer coverage, and
broader XLM corpus qualification remain release gates.

Legacy VBA, PowerPoint VBA, and Word-macro traversal now applies the same
distinction to present files: failed inspection, open, parse, decompression, or
close operations are retained as incomplete, while names absent from the
current recursive subtree remain normal. This keeps the older extraction path
from silently dropping a confirmed macro stream.

## Clamd size-option parser boundary — 2026-08-19

The shared `SIZE64` parser now rejects negative values before suffix scaling or
overflow fallback in both configuration-file and CLI paths. The focused clamd
parser regression covers `MaxScanSize`, `MaxFileSize`, `StreamMaxLength`,
`OnAccessMaxFileSize`, `MaxHTMLNormalize`, and `PCREMaxFileSize`. Socket-level
INSTREAM/FILDES tests at 4 GiB and 32 GiB, sanitizer coverage, and Sonic1
execution remain release gates.

## Structured clamd report framing — 2026-08-19

The structured report reader now retries interrupted socket reads instead of
turning an ordinary signal interruption into a transport failure during a
long-running scan. Focused coverage exercises fragmented length/payload
delivery, the zero-length terminator, and rejection of frames above the 16 MiB
transport bound. This protects report integrity without changing the legacy
clamd response protocol; compiled Linux/Sonic1 protocol-scale execution and
sanitizer coverage remain release gates.

## OLE2 temporary-stream cleanup — 2026-08-19

OLE2 VBA, ordinary embedded streams, encrypted streams, and MSO decompression
now admit declared or incrementally produced temporary output against
`MaxTemporarySize`, retain the reservation through the nested scan, and use
the reservation-aware descriptor path. Output close, zlib finalization, and
temporary removal failures remain sticky incomplete states. A cleanup failure
after a detection preserves the detection, while a nominal clean/`CL_BREAK`
result becomes non-clean. The focused temporary-limit and Linux static
close-fault regressions are registered; compiled execution, sanitizer
coverage, and broader OLE2 corpus qualification remain release gates.

The OLE10 embedded-object handoff now checks output close and removal failures
on both successful scans and early copy/rewind exits, preserving earlier
detections or parser errors while keeping the temporary reservation lifecycle
balanced.

Recursive OLE2 temporary-tree scans now distinguish a stream that belongs to a
different subtree from an existing stream that cannot be inspected, opened, or
closed. OLE10 and XLM/image failures, as well as failure to open a confirmed
temporary directory, are therefore explicit incomplete results instead of
silent omissions.

The same rule now covers OLE summary-information streams and reservation-owned
extracted children. An indexed summary stream or child file that cannot be
opened marks the containing layer incomplete; an optional normalized directory
that is simply absent remains a normal no-op.

The shared extracted-directory scanner also now treats a confirmed child-file
open/close failure, child descriptor inspection failure, or child fmap creation
failure as incomplete. A file found during enumeration can no longer vanish
from the scan contract after enumeration succeeds.

## BinHex temporary-stream cleanup — 2026-08-19

BinHex data/resource temporary descriptor close failures and temporary-file
removal failures now increment the sticky incomplete state. Detection results
remain authoritative, while an otherwise clean or `CL_BREAK` result cannot
survive failed cleanup. The Linux static-library close wrapper adds focused
coverage for the cleanup path; compiled execution, sanitizer coverage, and
broader legacy-mail corpus qualification remain release gates.

## SWF temporary-stream cleanup — 2026-08-19

The CWS and ZWS decompression paths now route decoder-error, limit, output-
length, nested-scan, and successful completion exits through one temporary
cleanup helper. Descriptor close and temporary removal failures mark the SWF
layer incomplete and cannot be hidden by an otherwise clean result. The Linux
static-library close wrapper adds a focused CWS regression; compiled execution,
sanitizer coverage, and broader SWF corpus qualification remain release gates.

## VBA project temporary cleanup — 2026-08-19

The OLE2 VBA-directory scanner now checks close and removal of staged
`vba_project` output during candidate retries, successful nested scans, and
final unwind. Failures mark the containing scan incomplete while preserving a
prior detection or parser error. Supported-Linux execution, sanitizer
coverage, and a real Office/VBA corpus remain release gates.

## PowerPoint VBA temporary-output accounting — 2026-08-20

The legacy PowerPoint VBA extractor now reserves decompressed atom output
incrementally against `MaxTemporarySize` and retains that reservation through
the nested directory scan. Truncated or out-of-range atoms, incomplete zlib
input/output, descriptor close failures, and temporary-directory removal
failures are fail-visible; a partial PowerPoint stream is never scanned as a
complete layer. The reservation-aware directory path avoids charging the same
materialized child twice.

Source guards and `git diff --check` are the current local evidence. Compiled
PowerPoint/VBA corpus execution, sanitizer and fault-injected cleanup coverage,
and supported-build Sonic1 qualification remain release gates.

## FILDES preflight and structured-report completion — 2026-08-19

Known regular-file FILDES inputs from clamdscan now undergo a client-side
`MaxFileSize` preflight before the descriptor is sent, including the
`FILDESREPORT` path. The daemon still rechecks the descriptor after receipt so
file growth between the two observations cannot create a false clean. The
preflight uses the fork's bounded 32-GiB policy when the configured value is
zero, and rejects non-regular or unstatable descriptors without sending a
request. INSTREAM now reports a failed final zero-length terminator write, and
the structured clamdscan report consumer rejects a terminator-only response
instead of treating it as a clean, successful scan. A focused Linux unit test
covers exact-limit and over-limit FILDES behavior; supported-Linux execution,
Sonic1 service qualification, sanitizer coverage, and 4-GiB/32-GiB socket
tests remain release gates.

## IDSESSION structured-report terminator — 2026-08-19

The clamdscan IDSESSION consumer now consumes the required zero-length frame
after each JSON report before returning to the request loop. Previously the
report object was parsed correctly but its terminator remained buffered, so a
subsequent request could see the prior terminator as an empty response. The
focused socketpair regression now delivers a fragmented JSON frame followed by
its terminator and verifies both frames are consumed in order. Supported-Linux
IDSESSION execution, Sonic1 service qualification, sanitizer coverage, and
4-GiB/32-GiB integration remain release gates.

## Service protocol qualification coverage — 2026-08-19

The Linux service qualification harness now exercises real clamdscan
`--fdpass`/FILDES and `--stream`/INSTREAM transfers in addition to path scans.
Production fixtures are run through both protocols, and the exact-edge
fixture is run through both after switching to the boundary database. Each
case remains bound to the existing size/hash/status/completion/signature/type
oracle and structured JSON report checks. This improves protocol coverage but
does not itself constitute a completed run; the dedicated 64-GiB Linux runner,
sanitizer, RSS, latency, and Sonic1 evidence gates remain required.

The service configuration now gives the logical scan budget its required
64-GiB ceiling, and the exact-edge report gate explicitly runs CONTSCAN,
MULTISCAN, and ALLMATCHSCAN modes in addition to path, FILDES, and INSTREAM.
These are still qualification requirements rather than evidence that the
dedicated runner has passed them.

## Service resource-evidence fail-closed behavior — 2026-08-19

The service qualification harness now fails if the live clamd RSS sampler or
temporary-directory sampler produces no usable samples, or if a live process
reports malformed measurement data. A zero-valued peak is therefore no longer
accepted as evidence that the service stayed within budget. This strengthens
the gate’s evidence integrity; it does not replace the required Linux,
sanitizer, RSS, temporary-space, and Sonic1 qualification run.

## MHTML root preclassification failures — 2026-08-19

The MHTML root-HTML preclassification wrapper now treats materialization
failure, HTML-document construction failure, XML-reader construction failure,
unterminated XML in an MHTML comment, and parser errors as incomplete
inspection. The structured metadata error helper is best-effort and can
return success when no metadata object is available, so each failure also
sets the scan's sticky incomplete state directly. Builds without libxml2 HTML
support now return an explicit failure instead of falling through without a
status. The raw MIME/HTML scan still proceeds through its normal path, but a
required preclassification operation can no longer be hidden by a clean
result or cache entry.

The focused source guards cover each failure reason and the fail-incomplete
XML-parser flag. A compiled MHTML regression, sanitizer run, and supported
Linux/Sonic1 parser-family qualification remain release gates.

## MHTML comment XML memory boundary — 2026-08-22

MHTML preclassification comments are metadata only, but the legacy callback
previously searched them with unbounded string operations and passed the
entire discovered fragment to `xmlReaderForMemory()`. That allowed a large
comment to create an unaccounted contiguous parser allocation and narrowed a
pointer difference to libxml2's `int` length parameter. The callback now
limits each comment to 64 MiB, searches `<xml>` and `</xml>` only within that
bounded value, checks the fragment length before the reader call, and returns
an explicit resource-incomplete result when the boundary is exceeded. Raw
MIME/HTML scanning remains on its separate file-backed path.

A focused oversized-comment unit fixture and source guards cover the new
boundary. Compiled Linux execution, sanitizer coverage, and broader MHTML
corpus/Sonic1 qualification remain release gates.

## Mach-O 32-bit coordinate overflow — 2026-08-22

The 32-bit Mach-O metadata path now checks the raw-address addition used to
map an entry point and calculates aligned section extents in a widened
temporary before storing the format-defined 32-bit result. A wrapped file
coordinate or aligned section size is now a fail-visible malformed layer
instead of a small, misleading range. The existing 64-bit native-coordinate
path remains independently checked.

A focused malformed 32-bit section regression and source guards cover the
overflow boundary. Compiled Mach-O corpus, sanitizer, and Sonic1
qualification remain release gates.

## RFC 1341 partial-message reassembly — 2026-08-19

RFC 1341 `message/partial` reassembly now requires every numbered fragment
from 1 through `total` to be present. A missing fragment previously produced a
partial output file and a successful helper return, allowing the caller to
continue as if the message were complete. Fragment reads now check both read
and close errors. The final reassembled output is now a quota-accounted
`fileblob` and is scanned through the normal nested descriptor path, so
temporary-space admission, output writes, scan errors, and detections remain
visible to the mailbox caller. Any failure returns an error so the caller
marks the scan incomplete and keeps an uninspected partial output out of the
scan/cache path. The reassembly directory is also fail-closed: open, enumerate,
and close failures now mark the message incomplete rather than allowing a
partial directory view to be scanned as complete.

The focused unit fixture supplies only fragment two and asserts a non-clean
result. Compiled Linux execution, sanitizer coverage, and broader partial-mail
corpus qualification remain release gates.

## MIME line materialization allocation failures — 2026-08-19

MIME line/string materialization now uses one failure helper for quota
exhaustion and post-reservation allocation failures. It marks the message
truncated and sets the scan's sticky incomplete state before returning an
error, including when a text-node allocation fails after the bounded-memory
reservation has already been charged. The existing limit regressions now
assert both the message truncation and scan-incomplete state. Fault-injected
allocation execution, sanitizer coverage, and broad mail-corpus qualification
remain release gates.

## PDF unsupported-filter result propagation — 2026-08-19

Recognized DCT, JPX, FAX, JBIG2, and unknown PDF filters previously returned
`CL_BREAK`, which could let raw bytes be scanned while the required decoded
layer was treated as complete. Disabled LZW decoding had the same behavior.
Those paths now preserve the raw fallback but mark the containing scan
incomplete and return a parser failure, so the layer is non-cacheable and a
non-detecting result cannot be reported clean. The direct DCT regression
asserts both raw-byte fallback and the `CL_EPARSE`/incomplete result.

This is fail-visible unsupported-feature handling; it does not claim that
these image/document filters have been converted to bounded streaming
decoders or qualified on Linux/Sonic1.

## PDF temporary-output cleanup propagation — 2026-08-20

PDF normalized-object output, extracted-object output, and file-backed parser
staging now share a cleanup contract that checks descriptor close and required
temporary-file removal. Cleanup failures mark the scan incomplete while
preserving an earlier detection, parser error, or configured limit result, and
release any held temporary-space reservation on every unwind path.

Source guards and `git diff --check` are the current local evidence. Compiled
PDF corpus, sanitizer/fault-injected cleanup, and supported-build Sonic1
qualification remain release gates.

## CryptFF staging completion — 2026-08-19

CryptFF decryption now requires the complete fixed header, detects source-map
read gaps, requires every temporary-output write to complete, and checks the
temporary descriptor close and removal. Allocation, staging, and cleanup
failures mark the containing layer incomplete/non-cacheable; a cleanup error
cannot replace a prior detection or parser failure with a misleading status.
The Linux static-library wrapper adds focused write- and close-fault coverage.
Compiled execution, sanitizer coverage, and real CryptFF/parser-family
qualification remain release gates.

## Compressed temporary-output completion — 2026-08-19

The GZip main and legacy fallback paths now require complete writes, mark
source-read and temporary-resource failures, and use one cleanup contract that
checks descriptor close and temporary removal without replacing a prior
detection, decoder, or configured-limit result. BZip2, XZ, and SZDD staging
paths use the same close/removal and result-preservation rules. A Linux
static-library wrapper regression covers GZip write and close faults. Compiled
execution, sanitizer coverage, and broad compressed-container qualification
remain release gates.

## Compressed-output temporary quota — 2026-08-20

GZip, including its legacy compatibility fallback, BZip2, and XZ now reserve
each decoded output chunk against `MaxTemporarySize` before writing it to the
temporary spool. Output-size arithmetic and scan-limit failures are fail-closed;
cleanup releases the bytes reserved by the decoder, and successful nested scans
use the reserved descriptor path so the same spool is not charged twice. The
focused regression covers all three decoder families with a one-byte temporary
budget. Compiled execution on the supported Linux/Sonic1 build and broad
compressed-family qualification remain release gates.

SZDD/MSEXPAND now reserves its declared decompressed size against
`MaxTemporarySize` before reading output and scans the completed spool through
the reserved-child path. The reservation is released on every close/removal
path, and a one-byte quota regression verifies that an oversized declared
output fails before partial staging. Compiled execution and broad
compressed-family qualification remain release gates.

Script normalization that requires a disk-backed relative-offset view now
reserves each generated output chunk against `MaxTemporarySize` before writing
it, and releases the reservation after the normalized scan and cleanup. This
prevents the legacy normalized-file path from bypassing the shared temporary
budget; compiled execution and broad script qualification remain release gates.

SWF CWS and ZWS decompression now reserve the output header and each decoded
chunk against `MaxTemporarySize` before writing, retain that reservation through
the nested scan, and release it during cleanup. Successful scans use the
reserved-child descriptor path, while quota and decoder failures remain
fail-closed. A focused CWS one-byte-quota regression was added; compiled SWF
and broad parser qualification remain release gates.

BinHex now reserves the declared data and resource fork sizes against
`MaxTemporarySize` before decoding, keeps both reservations through their
nested scans, and uses reserved-child descriptor scans to avoid double charging.
Reservation failures are fail-visible and all successful or failed cleanup
paths release the held bytes. A focused BinHex one-byte-quota regression was
added; compiled and broad parser qualification remain release gates.

ISO and UDF extracted-file extent materialization now reserves the known extent
length against `MaxTemporarySize` before writing and scans the completed file
through the reserved-child descriptor path. Cleanup releases the reservation
on both parser failure and successful child scans; extent quota failures are
fail-visible. Compiled filesystem-parser and broad corpus qualification remain
release gates.

UDF short writes, descriptor-close failures, and temporary-file removal
failures now also mark the containing filesystem scan incomplete while
preserving an earlier detection or parser error. HFS+ now applies the same
fail-closed rule to removal of its extracted temporary directory. Source guards
and `git diff --check` are the current local evidence; compiled fault-injected
cleanup and supported-build filesystem qualification remain release gates.

RTF embedded objects now reserve their declared payload plus the OLE10 bridge
header before staging, retain that reservation through nested scanning, and
release it on both complete and truncated-object cleanup. Ordinary embedded
objects use the reserved-child descriptor path; the existing OLE10 bridge keeps
its specialized scanner. Compiled RTF/OLE qualification remains a release gate.

## RTF temporary cleanup propagation — 2026-08-20

RTF embedded-object close and removal failures, plus temporary-directory
cleanup failures, now remain visible as incomplete results. Cleanup errors no
longer overwrite an earlier detection, while otherwise-clean RTF inspection
becomes non-clean when required output cleanup fails. Compiled RTF/OLE,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## Script-normalization temporary cleanup — 2026-08-19

Script normalization now marks normalization-buffer allocation and temporary
output creation failures, checks close and removal of the normalized output,
and preserves a detection, parser, or configured-limit result when cleanup
fails. The close-fault regression exercises the normalized relative-offset
path through the public scanner entry. Compiled execution, sanitizer coverage,
and broad HTML/script corpus qualification remain release gates.

## HTML-normalization temporary cleanup — 2026-08-19

HTML normalization now marks temporary-directory allocation and creation
failures, checks every normalized child descriptor close, and reports temporary
directory removal failures without hiding an earlier detection or parser
result. The normalizer also checks its input and generated-output closes. The
close-fault regression exercises the public HTML scan entry. Compiled
execution, sanitizer coverage, and broad HTML corpus qualification remain
release gates.

## Mail parser limit admission and ABI status reconciliation — 2026-08-19

MIME recursion and file-count admission now set the shared sticky incomplete
state at the point where the child is refused, before returning `MAXREC` or
`MAXFILES` to the mailbox caller. The existing public nested-`MaxFiles`
regression continues to assert the exact non-clean limit result; this closes
the lower-level cache/report boundary without changing detection precedence.

The public `cl_fmap_set_hash()` digest-pointer correction is published under
the fork's existing SONAME transition: `CURRENT:REVISION:AGE 14:0:0` and
SOVERSION 14. The symbol name remains stable within that new SONAME, but
binaries built against the prior scalar-argument ABI must not be loaded
against this release and require the old shared object or a rebuild. No old-
ABI compatibility claim is made.

The complete current-source Release CTest gate subsequently passed on the
pinned Sonic1 container `868b213e31020ca243d3c33df5904b26586615005fbae1abf04772f5294f8be1`
using `/work/build-current-044db34-release`: 16/16 tests passed in 573.04
seconds, including Valgrind, Rust, clamd/clamscan, milter, and all large-file
regression controls. This is full Release regression evidence, not a substitute
for the still-missing production-CVD real-file service canary and resource
qualification measurements.

The matching current-source ASan/UBSan gate also passes on Sonic1. A Rust
test-link defect was found and fixed in `cmake/FindRust.cmake`: Cargo now
receives the C sanitizer linker runtime when the CMake executable linker flags
enable ASan/UBSan instrumentation. After rebuilding the pinned
`RelWithDebInfo` tree, the exact CI command `ctest -C RelWithDebInfo -V
-E '_valgrind$'` passed 11/11 tests in 254.09 seconds, including all 73 Rust
tests. This is sanitizer qualification evidence; production-CVD real-file
service qualification and RSS/temporary-space/latency measurements remain
release gates.

## 7-Zip bounded two-coder output — 2026-08-20

The 7-Zip sequential extraction path now also handles the common two-coder
folder shape in which a decompressor is followed by a BCJ or ARM branch
converter. Decoder output passes through a bounded 256 KiB staging buffer;
converter state, 64-bit folder/member accounting, alignment look-ahead, output
CRC, and downstream short-write failures remain visible. This removes the
previous need to fall back to whole-folder materialization for those supported
filter folders. At this August 20 milestone, BCJ2 remained explicitly
unsupported on the streaming path and had to fail visibly or use the guarded
legacy path where its allocation limit permitted; the bounded canonical
four-coder implementation is documented in the August 24 section below.

The changed source compiled successfully in the pinned Sonic1 Release build,
and the complete 16-test Release CTest gate passed after the rebuild in 561.21
seconds. A direct scan of the existing `clam.7z` fixture also returned the
expected `ClamAV-Test-File.UNOFFICIAL FOUND` result. The existing corpus and
truncated-header regression do not provide a separately identified two-coder
BCJ/ARM archive fixture; that parser-family runtime qualification remains open
rather than being claimed by the build and general regression evidence.

## Nested RFC822 mail body spooling — 2026-08-20

The mail parser now stages `message/rfc822` and `message/delivery-status`
bodies through the shared disk-backed, temporary-quota spool instead of
retaining every body line in the parent message. The completed spool is handed
back to the normal scanner, preserving nested mail dispatch while removing the
former 64 MiB in-memory materialization boundary for these complete nested
message types. `message/partial`, `external-body`, disposition notifications,
and unknown message subtypes remain on the legacy state machine because their
special semantics cannot be replaced by a raw nested scan without changing
coverage; unsupported or incomplete results remain fail-visible.

`check_clamav` now includes a nested RFC822 fixture whose body crosses the
former materialization limit, and the source-guard suite requires the new
dispatch policy. Local shell/source guards and whitespace checks pass. A
compiled current-source Linux/Sonic1 result is still required because the
current worktree transfer was not permitted by the MCP-SSH export policy.

## Daemon admission capability enforcement — 2026-08-20

The large-file `clamd` startup admission now enforces the certified
large-file build definition and the FILDES descriptor-passing capability,
rather than merely reporting them in the startup manifest. Its scaled memory
requirement also includes the configured `MaxContiguousSize`, ensuring that a
retained 32 GiB contiguous matcher subject cannot be under-admitted when only
the file and logical-scan limits are lowered. Local source guards, the
capability manifest, and `git diff --check` pass. Compiled current-source
Sonic1 verification remains open because MCP-SSH did not permit exporting the
current private worktree.

The same admission gate rejects the large-file daemon envelope on non-Linux-
x86-64 targets. Other 64-bit targets may still build for development, but the
first production release does not claim AArch64 or macOS daemon qualification.

The admission call now runs inside `recvloop()` immediately after all
configured scan, temporary, contiguous, and PCRE limits are applied. This
prevents the daemon from checking historical engine defaults before reading the
large-file configuration. A failed admission frees the engine and returns
before the worker pool is created or requests are accepted.

For the same reason, the production daemon rejects `MaxScanSize=0`: legacy
library callers retain the historical unlimited setting, but the certified
daemon envelope requires the shared bounded 64 GiB logical budget.

The macOS host lacks the OpenSSL headers needed for a dependency-complete
build. A temporary non-repository header shim allowed syntax-only checking of
the changed Linux-style `clamd/largefile_admission.c` and complete
`clamd/server-th.c` translation units; both passed, and the shim was removed.
This does not substitute for the required dependency-complete Sonic1 build or
runtime qualification.

`check_clamd` now compiles the production admission translation unit and
covers both deterministic boundaries: historical defaults accept without
probing a host path, while `MaxScanSize=0` is rejected with the certified
budget reason. The tests are registered in the clamd parser case and covered
by source guards.

## Parallel MULTISCANREPORT aggregation — 2026-08-20

`MULTISCANREPORT` now retains the normal `MULTISCAN` dispatcher. With more
than one worker, directory children scan in parallel; with one worker, the
existing sequential fallback remains in effect. Each child uses the
structured library report path but contributes to the parent report under the
multiscan group lock; parent-side skip/error reports use that lock as well.
Child workers do not emit transport frames. The request therefore produces
one aggregate length-prefixed JSON response without interleaving child
frames. Source guards cover the dispatcher, ownership, lock, and no-child-
frame contract. Terminated groups suppress late child report/status updates
before the parent connection can be released during daemon shutdown.

This closes the front-end contract in source. Compiled protocol execution,
report-parity checks against path/descriptor/stream forms, production CVD
coverage, and sanitizer/resource qualification remain release gates.

## YARA-compatible exact-tail reads — 2026-08-20

The built-in YARA-compatible executor now accepts integer reads whose final
byte ends exactly at the fmap boundary. The previous `offset +
sizeof(type) >= length` check rejected those valid reads and could miss an
exact-tail logical/YARA condition. The replacement uses subtraction-based
bounds checking, so it also avoids offset-addition overflow. A focused
`check_matchers` regression covers an exact four-byte tail and an
out-of-range one-byte-shifted read.

This closes the identified boundary defect only. Full YARA evaluation,
matcher-work accounting, production signature, sanitizer, and large-file
qualification remain pending.

## Nonzero fmap source offsets — 2026-08-20

The handle-backed fmap constructor now treats `offset` as a source-file
coordinate and `len` as the exposed window length. It no longer rejects a
valid tail window merely because the source offset is greater than or equal to
the window length; it rejects only source-range arithmetic overflow. A focused
callback-backed regression covers a small window beginning at a page-aligned
offset beyond its own length. This improves descriptor/nested-window
correctness but does not replace supported-build or large-file runtime
qualification.

## Descriptor root-size preflight — 2026-08-20

Known-size descriptor scans now enforce the root `MaxFileSize` and
`MaxScanSize` limits before creating the full fmap. Over-limit inputs use the
normal limit-result path with a metadata-only fmap, preserving
`AlertExceedsMax`, callbacks, structured reports, and legacy result behavior
without allocating the large-file page bitmap or reserving the scan mapping.
Negative descriptor sizes are rejected, and the small-file fast path is now
reached only after the root limit check. A Linux fault-injected regression
confirms that an over-limit descriptor returns `CL_EMAXSIZE` even when
`fmap_new()` is forced to fail.

## Nested child-size preflight — 2026-08-20

Known-size extracted descriptors and nested fmap windows now use the same
admission policy before reserving temporary space or creating a child fmap.
This prevents an over-limit child from allocating a page bitmap, mapping a
descriptor, or staging a force-to-disk copy. Normalized and handler-retyped
views continue to perform only the time check used by the recursion-stack
invariant, so they do not consume logical scan size twice. The recursion push
still repeats the policy check after successful map creation as a defensive
invariant. The existing force-to-disk nested-range regression now also sets a
smaller `MaxFileSize` and verifies that no source bytes are read before the
limit result is returned.

## HFS+ temporary-fork accounting — 2026-08-20

HFS+ data and resource forks now reserve their declared logical size against
`MaxTemporarySize` before extraction, retain that reservation through the
reserved-child scan, and release it after close and cleanup. Compressed
decmpfs output is admitted against both its declared scan limits and the
temporary quota before staging; output overrun, short output, unsupported
compression, incomplete extents, and temporary cleanup failures are
fail-visible. The compressed resource-fork staging reservation is transferred
explicitly across its intermediate file lifetime so it cannot bypass the
shared quota.

Source guards and `git diff --check` remain the available local evidence. A
dependency-complete compiled HFS+ corpus, sanitizer run, and supported-build
Sonic1 qualification remain release gates.

## DMG/XLM child reservation ownership — 2026-08-20

DMG reconstructed partitions now pass their existing full-output reservation
to the reservation-aware child descriptor scan instead of reserving the same
partition a second time. XLM extracted images now always use a temporary
descriptor, including when temporary retention is disabled; the declared image
size is reserved before writing, requires a complete write, and stays reserved
through the nested scan and cleanup. Source guards and `git diff --check` pass;
compiled parser execution, document/image corpus, sanitizer, and supported-
build Sonic1 qualification remain release gates.

DMG reconstructed-partition close/removal failures now remain fail-visible
even when an earlier detection or parser error exists, and all DMG temporary
directory unwind paths report removal failures. Detections remain authoritative
without allowing cleanup errors to produce a cacheable clean result.

## XLM macro-output accounting — 2026-08-20

XLM macro normalization now routes formatted and decoded output through a
quota-aware writer that reserves bytes before each write and retains the
aggregate reservation through the macro scan. Quota, allocation, formatting,
write, flush, removal, and cleanup failures remain fail-visible. A one-byte quota
regression and source guards cover the new path; compiled XLM/Office corpus,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## VBA project temporary-spool accounting — 2026-08-20

The modern VBA project-directory extractor now reserves each generated script
output write against `MaxTemporarySize` before writing it. The reservation is
transferred to the OLE caller and held through the reserved child scan, then
released across successful, failed-candidate, and cleanup paths. This removes
the generated-project path's temporary-quota bypass while preserving its
existing candidate retry and macro metadata behavior.

Source guards and `git diff --check` are the current local evidence. A
dependency-complete Office/VBA corpus, sanitizer run, and supported-build
Sonic1 qualification remain release gates.

## InstallShield temporary-output accounting — 2026-08-20

InstallShield MSI, legacy embedded-file, and CAB extraction paths now charge
temporary output against `MaxTemporarySize` before or during staging, require
complete temporary writes, and retain the reservation through the nested scan.
Successful nested scans use the reserved-child descriptor path so the same
spool is not charged twice. Declared CAB output is checked before each write,
and descriptor close/removal failures remain explicit incomplete results while
preserving an earlier detection or parser error.

Source guards and `git diff --check` are the current local evidence. A
dependency-complete InstallShield corpus, sanitizer run, fault-injected
temporary cleanup, and supported-build Sonic1 qualification remain open
release gates.

## HWP temporary-output accounting — 2026-08-20

The shared HWP3/HWP5/HWPML raw-deflate helper now reserves each decompressed
output chunk against `MaxTemporarySize`, keeps the reservation through the
callback, and scans the completed temporary child through the reserved
descriptor path. HWPML base64-decoded temporary input remains reserved through
its direct child scan, while cleanup checks close/removal failures and releases
the owned bytes on every path.

Source guards and `git diff --check` are the current local evidence. A
dependency-complete HWP/HWPML corpus, sanitizer and fault-injected cleanup
coverage, and supported-build Sonic1 qualification remain open release gates.

## Gated large-file default profile — 2026-08-20

The build now exposes `-DENABLE_LARGE_FILE_DEFAULTS=ON` as an explicit
development/deployment profile. It is accepted only for Linux x86-64 and
selects the roadmap defaults: 32 GiB root/stream/on-access/PCRE and parser
size ceilings, 64 GiB logical scan size, four-hour scan time, and one worker
with a two-entry queue. The ordinary build remains on its historical defaults
until the full parser, ingress, sanitizer, and Sonic1 qualification gates
pass.

The profile is deliberately a build-time choice, is visible in the CMake
summary, and is covered by the engine default regression. Enabling it is not
itself release qualification; the capability manifest keeps this feature
pending until the complete acceptance matrix is current-source verified.

## PE32+ common inspection and legacy-x86 boundary — 2026-08-24

PE32+ now completes the architecture-neutral PE passes after header parsing:
outer raw matching, section hashing, overlay inspection, the `BC_PE_ALL`
bytecode hook, and import-table metadata/hash traversal with native 64-bit
thunks. Failures in the 64-bit thunk path remain explicit and non-cacheable.

The remaining hand-written PE heuristics and unpackers assume PE32/x86
entry-point and ImageBase semantics. A confirmed PE32+ layer therefore stops
at that narrower boundary with `CL_EPARSE` and the explicit reason
`PE32+ legacy x86 heuristic and unpacker inspection is unsupported`; it cannot
be reported or cached as fully clean. A deterministic PE32+ import fixture
passes the focused Linux ARM64 GCC test for common-path metadata and injected
64-bit-thunk read failure. Production PE32+ corpora, Linux x86-64,
ASan/UBSan, and Sonic1 qualification remain release gates.

## Bytecode extracted-output accounting — 2026-08-20

Bytecode extraction totals are now native-width and each output write reserves
the requested bytes against `MaxTemporarySize`. The reservation remains held
through `extract_new` and bytecode unpacker child scans, including the PE,
ELF, and Mach-O hook handoffs; transferred ownership is released only after
the scan and temporary cleanup. Complete writes are required, arithmetic
overflow and write failures mark the scan incomplete, and the logical scan
counter now accepts a 64-bit byte count.

ELF and Mach-O unpacker handoffs now also fail closed on rewind, descriptor
close, and temporary-file removal failures while preserving earlier detections
or parser errors and releasing the transferred reservation after cleanup.

Bytecode context reset, JavaScript normalization, and incremental extracted-file
cleanup now also fail closed on descriptor close, rewind, open, truncation, and
temporary-file removal failures without replacing an earlier detection or parser
error. The reservation is still released after every cleanup path.

Source guards and `git diff --check` are the current local evidence. A
dependency-complete bytecode-v2 fixture exercising multi-gigabyte repeated
writes, interpreter/JIT behavior, sanitizer/fault-injected cleanup, and
supported-build Sonic1 qualification remain release gates.

## XAR member temporary-output accounting — 2026-08-20

XAR now keeps the decompressed TOC reservation through its descriptor scan and
streaming XML walk, and reserves gzip, LZMA, and raw-member output chunks
against `MaxTemporarySize` before writing them. Completed TOC and member scans
use the reservation-aware descriptor path; cleanup releases the corresponding
reservation after close/removal and preserves failure results.

XAR `<subdoc>` fragments now use the same reservation-aware temporary
descriptor handoff instead of being scanned directly from an unaccounted
in-memory buffer. Their XML length is checked without narrowing through the
legacy `int` API, and fragments above the 1 GiB individual-allocation boundary
return an explicit incomplete result. The upstream `ReadInnerXml` API still
materializes the fragment, so that format-specific boundary remains an
unsupported capability until a streaming fragment API is available.

Source guards and `git diff --check` are the current local evidence. A
dependency-complete XAR corpus covering all encodings, sanitizer/fault-injected
cleanup, and supported-build Sonic1 qualification remain release gates.

## Legacy PE temporary-output accounting — 2026-08-20

Recognized legacy PE unpackers now reserve their declared reconstructed-output
capacity against `MaxTemporarySize` before creating the temporary descriptor.
The reservation remains held through the reservation-aware nested scan and is
released on unpack failure, output-write failure, cleanup, or completion. The
UPX/FSG direct path now requires complete output writes and uses the same
reservation-aware child entry point.

Source guards and `git diff --check` are the current local evidence. Legacy
packer fixture, sanitizer/fault-injected cleanup, and supported-build Sonic1
qualification remain release gates.

## Extracted-directory traversal failure propagation — 2026-08-20

The shared extracted-directory walker now rejects null inputs and treats
`LSTAT`, `readdir`, and `closedir` failures as incomplete, non-clean results.
Previously an entry that could not be inspected could be skipped while the
containing parser continued as if every extracted member had been scanned.

Source guards and `git diff --check` are the current local evidence. Compiled
fault-injected directory traversal and parser-family qualification remain
release gates.

The OLE2 temporary-directory recursion now applies the same rule to nested
VBA/XLM/image directories, so a vanished or unreadable directory entry cannot
be treated as an empty subtree.

## CryptFF temporary-output accounting — 2026-08-20

CryptFF decryption now checks its growing logical output with 64-bit
arithmetic, reserves each output chunk against `MaxTemporarySize`, requires a
complete write, and scans the completed temporary file through the
reservation-aware descriptor path. Shared cleanup now releases the reservation
and preserves explicit close/removal failures. The regression suite covers
write, close, and temporary-quota failures as incomplete, non-cacheable
results.

Source guards and `git diff --check` are the current local evidence. A
dependency-complete CryptFF corpus, sanitizer/fault-injected cleanup run, and
supported-build Sonic1 qualification remain release gates.

## Scanner temporary-directory cleanup propagation — 2026-08-20

The shared scanner wrappers now check removal of their parser-owned temporary
directories for OLE2, TAR, script-encoded HTML, PDF, TNEF, UUEncode, and mail
scans. A removal failure marks the scan incomplete and changes only an
otherwise-successful result to `CL_EUNLINK`, preserving detections and prior
parser/resource failures.

Source guards and `git diff --check` are the current local evidence. Compiled
fault-injected directory-cleanup coverage, sanitizer execution, and supported
build Sonic1 qualification remain release gates.

## Rust parser failure accounting — 2026-08-20

Rust-backed parser failures now use the shared `cli_mark_scan_incomplete()` C
helper instead of setting only the Rust-side sticky flag. This preserves the
common non-cacheable propagation, increments the structured report's skipped
operation count, and records a context-lifetime-safe classification reason
while retaining the detailed decoder error in the Rust log. The checked-in
bindgen allowlist and bindings now expose the helper.

The source guards, capability manifest, runtime-evidence verifier regression,
and whitespace checks pass. The local offline Cargo test cannot resolve the
pinned `clam-sigutil` Git dependency, so dependency-complete Rust compilation,
sanitizer execution, and supported-build Sonic1 parser qualification remain
open release gates.

## Structured report close-error propagation — 2026-08-20

`clamscan --report-json` and `clamdscan --report-json` now treat a failure to
close the JSONL output as an error. A buffered write can succeed while the
filesystem reports a delayed failure during close; ignoring that result could
leave the scan evidence incomplete while returning success. The front ends
now log the close failure and return an error status while preserving the
existing scan verdict handling.

Source guards and `git diff --check` pass. Fault-injected front-end execution,
dependency-complete builds, and supported-build Sonic1 service qualification
remain release gates.

## Parser error status fail-closed policy — 2026-08-20

The central scan-result policy now converts parser and decoder returns of
`CL_EFORMAT`, `CL_EPARSE`, `CL_EREAD`, and `CL_EUNPACK` into the shared sticky
incomplete state when the parser did not already do so. This prevents a later
raw scan or sibling parser from turning a confirmed but partially inspected
layer into a clean or cacheable result while preserving detection and stronger
resource-error precedence.

An unspecified `CL_ERROR` from the same parser/decoder boundary is now treated
the same way and is preserved as the public result. It cannot be normalized to
`CL_SUCCESS` after a later raw pass.

The same policy now covers parser/decoder `CL_EOPEN`, `CL_ECREAT`, `CL_EACCES`,
and `CL_EMAP` returns when the callee did not already record the failure. These
operational errors cannot silently become a clean result after required
extracted content or a decoder map was skipped.

## SIS malformed member-offset propagation — 2026-08-20

Legacy SIS extraction now treats a declared non-empty member whose offset
points inside the package header as malformed instead of silently skipping the
member and returning clean. Valid sibling language members may still be
processed, but the containing layer is sticky incomplete, non-cacheable, and
returns `CL_EPARSE` when no stronger result exists. A focused public-map
regression and source guard cover the boundary; dependency-complete SIS
corpus, sanitizer, and supported-build Sonic1 qualification remain open.

## MBR partition-limit propagation — 2026-08-20

MBR scanning now distinguishes a partition-count limit from a fully inspected
table. If a non-empty primary or logical partition remains beyond
`MaxPartitions`, the scan is marked incomplete and returns `CL_EMAXFILES` when
no stronger result exists; empty trailing table entries do not create a false
limit. A focused zero-limit public-map regression and source guards cover the
primary-table boundary. Compiled extended-partition, sanitizer, and
supported-build Sonic1 qualification remain open.

## APM/GPT partition-limit propagation — 2026-08-20

APM and GPT scanning now preserve a specific `CL_EMAXFILES` result when their
declared partition tables exceed `MaxPartitions`, rather than returning clean
after scanning only the permitted prefix. The sticky incomplete state remains
non-cacheable, while stronger parser errors or detections retain precedence.
A focused APM zero-limit regression and source guards cover the APM path;
compiled GPT/partition corpus, sanitizer, and supported-build Sonic1
qualification remain open.

## APM partition-entry range validation — 2026-08-20

APM now promotes declared image-size arithmetic to the native fmap width,
validates each entry signature, and treats an out-of-range partition as an
incomplete `CL_EFORMAT` result instead of logging it and continuing as clean.
This prevents malformed APM metadata from silently skipping a nested scan; a
focused direct-parser regression and source guards cover the boundary. Full
partition corpus, sanitizer, and supported-build Sonic1 qualification remain
release gates.

## GPT partition-entry range validation — 2026-08-20

GPT now treats a non-empty partition outside the header-defined usable range
or the input fmap as an incomplete `CL_EFORMAT` result instead of skipping the
entry and continuing as clean. A CRC-valid synthetic GPT regression exercises
the public scanner path, with source guards covering both boundaries. Full
partition corpus, sanitizer, and supported-build Sonic1 qualification remain
release gates.

## ALZ unsupported-member admission — 2026-08-20

The Rust ALZ parser now records encrypted, data-descriptor, and unsupported
compression members while continuing its metadata walk. The scanner-facing
adapter converts that state into an explicit incomplete `CL_EUNPACK` result,
so an archive with an uninspected member cannot return clean. A focused Rust
regression and source guards cover the admission boundary; dependency-complete
Rust, corpus, sanitizer, and supported-build Sonic1 qualification remain
release gates.

## UDF file-list completeness — 2026-08-20

UDF no longer scans the smaller of its file-identifier and file-entry lists.
When the descriptor counts differ, unmatched content is now treated as a
confirmed structural failure and returns `CL_EPARSE` with a non-cacheable
incomplete scan. A focused synthetic descriptor-sequence regression and source
guard cover the boundary; full UDF corpus, sanitizer, and supported-build
Sonic1 qualification remain open.

The focused policy regression and source guards pass. Full C/CTest execution,
sanitizer coverage, and supported-build Sonic1 qualification remain release
gates.

## ALZ metadata failure propagation — 2026-08-20

The bounded Rust ALZ scanner no longer treats a `CL_EFORMAT` returned by the
archive metadata matcher as a recoverable condition. Metadata inspection is a
required operation for each recognized member; a format failure now stops that
member's extraction and preserves the non-clean result instead of allowing the
decoder to continue as though the metadata pass completed.

The focused Rust helper regression and source guards cover this boundary.
Dependency-complete Rust/CTest, malformed-metadata corpus, sanitizer, and
supported-build Sonic1 qualification remain release gates.

## Stdin over-limit staging closeout — 2026-08-20

The `clamscan` stdin path now initializes the over-limit result before trying
to materialize its boundary sentinel, so a failed `ftruncate()` cannot expose
an uninitialized return code. It also checks the temporary staging file's
`fclose()` both on the over-limit path and before a normal scan; close failures
remove the staging file and return an error rather than scanning uncertain
contents.

Source guards and `git diff --check` pass. Fault-injected stdin staging,
dependency-complete front-end builds, and supported-build Sonic1 qualification
remain release gates.

## Clamscan directory enumeration closeout — 2026-08-20

The `clamscan` directory walker now treats `readdir()` and `closedir()` errors
as scan errors. A directory that can only be partially enumerated, or whose
descriptor cannot be closed cleanly, can no longer silently produce a clean
result after scanning the entries that happened to be visible.

Source guards and `git diff --check` are the current local evidence.
Fault-injected directory traversal, dependency-complete front-end builds, and
supported-build Sonic1 qualification remain release gates.

## PDF extraction decoder-status propagation — 2026-08-20

The PDF decoder's truncated and unsupported-filter paths already marked the
scan incomplete, but `pdf_extract_obj()` normalized its `CL_EPARSE` result to
success. The extraction layer now preserves that status, so direct PDF object
extraction cannot report a clean result for an incompletely decoded filtered
stream. The object walker still visits independent siblings and retains a
non-clean aggregate result after the failed object is counted.

The focused malformed-Flate extraction regression and source guards cover the
boundary. Dependency-complete PDF corpus, sanitizer, and supported-build
Sonic1 qualification remain release gates.

## On-access FTS traversal completeness — 2026-08-20

The inotify extra-directory scan now distinguishes directories from scanable
file entries and treats `FTS_DNR`, `FTS_ERR`, `FTS_NS`, unknown FTS records,
failed `stat()` calls, end-of-walk errors, and `fts_close()` failures as
incomplete results. A size-limited child is skipped without disabling scans of
independent siblings, while the worker logs the non-clean aggregate status.

The inotify hierarchy hash builder applies the same fail-closed policy to FTS
records, child enumeration, end-of-walk errors, and traversal close failures;
it can no longer install a partial directory hierarchy and report success.

Source guards and `git diff --check` are the current local evidence. Compiled
inotify/fanotify traversal fault injection, dependency-complete front-end
builds, sanitizer coverage, and supported-build Sonic1 qualification remain
release gates.

## Streamed multipart spool close propagation — 2026-08-20

The disk-backed multipart MIME walker now checks the source `fclose()` result
after reading and scanning its parts. A close failure marks the mail scan
incomplete and changes only an otherwise-successful result to failure, while a
detection or earlier stronger result remains authoritative.

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

## ARJ extraction read status — 2026-08-21

ARJ compressed bit-window refills and stored-member copies now distinguish an
in-range fmap callback failure from exact EOF or an out-of-map range. Callback
failures preserve `CL_EREAD` through the decoder and stored extractor, and
the scanner refuses to inspect partial output. A focused stored-member
fault-injection regression and source guards cover the boundary. Compiled ARJ
corpus, sanitizer, callback-fault, and supported-build Sonic1 qualification
remain release gates.

## CPIO coordinate read status — 2026-08-21

The four CPIO readers now classify an out-of-map or cross-boundary structure
as truncated input (`CL_EPARSE`) instead of mistaking `fmap_readn()`'s shared
error sentinel for an operational callback failure. Fully in-range callback
failures remain `CL_EREAD`, and focused regressions cover both boundaries.
Compiled CPIO corpus, sanitizer, callback-fault, and supported-build Sonic1
qualification remain release gates.

## Compressed-stream input read status — 2026-08-21

Fmap-backed GZip, BZip2, and XZ input now preserves `CL_EREAD` when an
in-range callback cannot provide the next compressed window. Genuine EOF and
decoder failures retain their existing non-clean statuses, and a focused
callback-fault regression covers all three formats. Compiled compressed
corpus, sanitizer, callback-fault, and supported-build Sonic1 qualification
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

## Public scan-file close-error propagation — 2026-08-20

The public `cl_scanfile_ex2()` convenience API now checks the close of the
descriptor it owns. A close failure after an otherwise clean or trusted scan
is returned as `CL_EREAD` and changes the structured report to
`RESOURCE_FAILURE` with a skipped-operation count, so a delayed descriptor
I/O error cannot be published as clean evidence. Detection remains the
authoritative result when a virus was already found. The focused report
regression and source guards cover the post-scan transition; injected close,
sanitizer, dependency-complete, and supported-build Sonic1 qualification
remain release gates.

## Structured clamd dispatch-failure framing — 2026-08-20

Opt-in structured clamd requests now emit a bounded fallback JSON report when
worker dispatch fails before a scanner-owned report exists. This covers both
path/descriptor command dispatch and the final staged `INSTREAMREPORT` scan;
the legacy text error remains suppressed so clients receive exactly the
length-prefixed report plus zero terminator required by the structured
protocol. A focused client-parser regression and source guards cover the
fallback shape; compiled dispatch-failure injection and supported-build
Sonic1 protocol qualification remain release gates.

## clamscan early-file report completion — 2026-08-20

`clamscan --report-json` now emits a structured fallback object for file
inputs that fail before `cl_scandesc_ex2()` creates a library report, including
access, allocation, and open failures. Successful scan reports are written
after completion enforcement, so the JSONL artifact cannot omit an errored
input or publish an incomplete result as clean. Legacy console and exit
behavior is preserved; compiled early-failure injection and supported-build
Sonic1 qualification remain release gates.

## clamscan cleanup failure completion — 2026-08-20

The clamscan action/scan path now reports failures closing its owned scan
descriptor or quarantine source as `CL_EREAD`. Cleanup runs before the
structured JSONL report is finalized and before a clean `OK` is printed, so a
post-scan descriptor failure cannot be published as clean evidence. The
internal action-source close API returns the failure while preserving the
existing reset semantics; a focused invalid-descriptor regression covers the
contract. Fault-injected clamscan cleanup and supported-build Sonic1
qualification remain release gates.

## Script-normalization read status — 2026-08-21

Script normalization now carries the specific fmap read result through the
shared text-normalizer state. An in-range callback failure remains `CL_EREAD`,
while an impossible offset remains `CL_EPARSE`; the normalized layer is still
marked incomplete and non-cacheable. The focused normalizer regression covers
the operational read status; compiled scanner-level, sanitizer, callback-fault,
and supported-build Sonic1 qualification remain release gates.

## Service-build provenance binding — 2026-08-21

The mandatory service qualification now binds its `clamd`, `clamdscan`,
`clamscan`, and milter workload to the audited source root, configure-time
source commit/manifest, CMake cache, compile-command graph, executable hashes,
and resolved runtime dependency hashes. Service binaries are re-hashed after
the workload and the gate fails if any changes. This closes the evidence gap
between the standalone runtime gate and the daemon/client/milter workload;
supported-Linux execution and full service qualification remain release gates.

## clamscan stdin structured staging failures — 2026-08-20

The stdin staging path now emits a per-input structured fallback report when
temporary-directory access, temporary-file creation, writes, reads, closes, or
the over-limit sentinel fails before a scanner report exists. Normal and
sentinel scan reports are published only after completion enforcement, so
`--report-json` cannot silently omit a failed stdin input. Legacy exit behavior
is preserved; compiled fault injection and supported-build Sonic1 qualification
remain release gates.

## clamdscan serial pre-dispatch report completion — 2026-08-20

The serial `clamdscan --report-json` walker now emits a bounded structured
fallback object for file inputs that fail before clamd owns the request,
including stat, allocation, quarantine-open, connection, and protocol
failures. Successful daemon reports remain unchanged, while a client-side
error can no longer silently omit its input from the JSONL artifact. Parallel
IDSESSION fallback coverage, fault injection, and supported-build Sonic1
qualification remain release gates.

## clamdscan parallel pre-dispatch report completion — 2026-08-20

The IDSESSION walker now emits structured fallback objects for parallel inputs
that fail before a request ID is registered, and for registered IDs left
pending when the session aborts or clamd disconnects. Successfully completed
IDs retain their daemon-owned framed reports. This closes the client-side
JSONL omission for parallel pre-dispatch failures; compiled IDSESSION fault
injection and supported-build Sonic1 qualification remain release gates.

## Fuzzy-image contiguous-subject boundary — 2026-08-20

The optional fuzzy-image FFI consumes one contiguous image subject and cannot
be used as a 32 GiB streaming detector. Images above the individual-allocation
ceiling are rejected before mapping with an explicit incomplete state, and a
failed detector cannot be published as a successful fuzzy result. The
capability manifest records this deliberate unsupported boundary; image
corpus, sanitizer, and supported-build qualification remain release gates.

## Bytecode logical-dispatch argument validation — 2026-08-20

The logical-bytecode entry point now validates the scan context, bytecode
table, one-based bytecode index, signature match arrays, and fmap before
forming the indexed bytecode pointer. Invalid dispatch metadata therefore
returns `CL_ENULLARG` instead of performing undefined pointer arithmetic before
the v1/v2 coordinate admission checks. A focused regression covers null and
zero-index dispatch; independently compiled fixture, interpreter/JIT, and
supported-build Sonic1 qualification remain release gates.

## Bytecode execution-failure propagation — 2026-08-20

Required logical-signature bytecode execution failures now remain visible as a
non-clean result instead of being normalized to `CL_SUCCESS`. Applicable hook
bytecode failures mark the scan incomplete and non-cacheable while preserving
any malware detection found by another hook. The focused unprepared logical
and hook-bytecode regression covers both dispatch paths; interpreter/JIT,
sanitizer, official bytecode, and supported-build Sonic1 qualification remain
release gates.

## Legacy bytecode ABI overflow — 2026-08-21

An applicable v1 logical-bytecode signature cannot represent a file size of
exactly 4 GiB or larger, or a logical-signature offset above `UINT32_MAX`.
That admission failure now returns
`CL_EPARSE` as well as marking the layer incomplete and non-cacheable; it can no
longer fall through as the evaluator's default clean result. A synthetic >4 GiB
logical-signature regression covers the status, reason, and cache invariant
without allocating a 4 GiB input. Compiled Linux/Sonic1, interpreter/JIT,
sanitizer, production-bytecode, and mixed-ABI qualification remain release
gates.

## Mixed bytecode ABI hook continuation — 2026-08-21

Hook tables can contain both legacy format-7 and format-8 bytecode. On a layer
above 4 GiB, a v1 hook still produces an explicit incomplete, non-cacheable
result, and a v1 hook whose logical match offset is above `UINT32_MAX` is
treated the same way. Neither admission failure aborts the hook loop before a
later v2 hook is attempted. This preserves detections available through the
widened ABI without misreporting the skipped legacy detector as complete. The
focused unit regression verifies that the later v2 dispatch selects the native
offset array after the v1 offset bridge rejects the coordinate. Mixed-ABI
interpreter/JIT, sanitizer, production-bytecode, and supported-build Sonic1
qualification remain release gates.

## Bytecode v2 split-window search and format isolation — 2026-08-24

The shared bytecode file-search implementation now overlaps adjacent 4 KiB
input windows by `needle_length - 1`, so a multi-byte signature beginning at
the final byte of one window is found in both legacy and 64-bit APIs. Focused
fixtures cover the split at byte 4,095 and the same split after the 4 GiB
coordinate boundary, normally and with ASan/UBSan.

The bytecode loader now enforces the format-8 boundary for every appended v2
API and global. Format-6/7 modules cannot opt into 64-bit interfaces by
manually encoding their IDs, zero API IDs are rejected before one-based index
conversion, and external-global pointer initializers must remain inside both
the module's declared table and its format generation. A loader regression
mutates a compiled format-7 CBC fixture and checks both the rejecting legacy
path and accepting format-8 path. `clambc` also supplies its deterministic test
matcher offsets through the 64-bit hook field.

The bytecode scan-option query now performs allocation-free, exact-length ASCII
case-insensitive matching. This fixes the historical index-zero lowercase
write, inverted category comparisons, terminator-inclusive substring lengths,
and the documented `heuristic precedence` key; embedded-NUL and trailing-name
aliases are rejected. An independently compiled format-8 fixture and
interpreter/JIT execution remain release gates.

## Mixed bytecode offset-bridge continuation — 2026-08-22

The legacy hook offset bridge now preserves its `CL_EMAXSIZE` admission error,
marks the layer incomplete and non-cacheable, and continues to later hooks
instead of returning before a compatible format-8 hook can run. This closes a
second mixed-ABI suppression path: a small mapped layer can still carry a
logical match coordinate that cannot fit the v1 offset array even when the
v1 file-size field itself is representable.

## YARA logical-pass matcher-work accounting — 2026-08-20

YARA-compatible logical evaluation can read integer fields from the current
fmap after the outer raw matcher has completed. Each logical root now charges
one bounded pass over that fmap to `MaxMatcherWork`; if the shared budget cannot
admit it, evaluation stops with a resource-incomplete, non-cacheable result.
The focused matcher regression covers both the successful charge and the
fail-closed limit path. Full YARA rule evaluation, production signatures,
sanitizer, and large-file qualification remain release gates.

## YARA fmap read-failure propagation — 2026-08-20

YARA integer reads now distinguish a valid out-of-range `UNDEFINED` value from
an in-range fmap window that failed to load. An operational read returns
`CL_EREAD`, marks the scan incomplete and non-cacheable, and cannot be
converted into a clean result by the YARA executor. The focused regression
injects the fmap failure; compiled Linux/Sonic1, sanitizer, and full YARA
qualification remain release gates.

## Logical bytecode-reference admission — 2026-08-20

The logical-signature evaluator now validates the referenced bytecode table and
one-based entry before dereferencing it. A missing or stale entry marks the
current layer incomplete, non-cacheable, and returns `CL_EPARSE`; it cannot
crash or fall through as a clean logical evaluation. A focused malformed
logical-signature regression covers the fail-visible path. Full logical
expression, mixed ABI, production-signature, and supported-build qualification
remain release gates.

## ISO9660 checked block coordinates — 2026-08-20

ISO9660 block reads now validate the fmap base window before subtraction, use
64-bit logical and absolute offsets, and reject impossible block-size/range
arithmetic before passing a coordinate to fmap. Directory-record block plus
extended-attribute additions are checked against the 32-bit ISO coordinate
field and mark the layer incomplete on overflow. Existing truncated-directory
and unsupported-layout regressions remain applicable; full ISO corpus,
sanitizer, and supported-build qualification remain release gates.

## clamscan directory and symlink report completion — 2026-08-20

The clamscan walker now emits bounded non-clean fallback rows when an explicit
directory cannot be opened or a followed symbolic link cannot be inspected.
These failures remain visible in legacy errors and now also remain represented
in JSONL evidence; normal symlink exclusion behavior is unchanged. Compiled
filesystem-fault injection and supported-build Sonic1 qualification remain
release gates.

## clamdscan wrapper/session failure reports — 2026-08-20

The structured-report path now emits a bounded fallback object when path
canonicalization fails, or when a parallel session cannot connect or accept
the IDSESSION handshake. This prevents wrapper and whole-session failures from
silently producing no JSONL row; compiled fault injection and supported-build
Sonic1 qualification remain release gates.

The stdin ingress now uses the same fallback for descriptor inspection,
connection, and structured-response failures, so `clamdscan -` also retains a
bounded non-clean JSONL row. Compiled stdin fault injection and supported-build
Sonic1 qualification remain release gates.

## clamdscan recursion-limit report completion — 2026-08-20

When the client-side directory walker reaches its recursion limit, both serial
and parallel `clamdscan --report-json` modes now emit a bounded
`LIMIT_INCOMPLETE` fallback row for the skipped directory. The event also
counts as an error and suppresses an overall clean `OK` result, while ordinary
symlink exclusion remains unchanged. Compiled traversal fault injection and
supported-build Sonic1 qualification remain release gates.

## clamscan requested-path report completion — 2026-08-20

The `clamscan --report-json` ingress now emits a bounded non-clean fallback row
when an explicitly requested path cannot be duplicated or inspected, or when
its top-level type is not scannable. This keeps the JSONL artifact aligned with
the requested inputs instead of silently omitting pre-scan failures. Legacy
console output and exit behavior are unchanged; compiled allocation/path fault
injection and supported-build Sonic1 qualification remain release gates.

## RTF split object-header probe — 2026-08-20

The RTF decoder now carries the two-byte embedded-object probe across 8 KiB
fmap reader boundaries. A payload ending one reader chunk after its first
decoded byte no longer causes an out-of-bounds probe; truncated payloads remain
incomplete and non-cacheable. The focused regression is registered in
`check_clamav`; compiled sanitizer and broad RTF/OLE corpus qualification
remain release gates.

## SWF tag-payload boundary — 2026-08-20

The debug SWF tag walk now checks each declared tag payload against the
remaining fmap range before advancing or inspecting it. A tag that extends
beyond EOF, or whose length cannot fit the remaining coordinate range, marks
the layer incomplete and returns `CL_EPARSE` instead of advancing past the map
and returning clean. The focused regression exercises a truncated `SHOWFRAME`
payload; compressed-output, sanitizer, and full SWF corpus qualification remain
release gates.

## SWF required read status — 2026-08-21

SWF fixed frame-metadata reads and CWS/ZWS compressed-input reads now
distinguish an in-range fmap callback failure from genuinely short or
out-of-map input. Callback failures preserve `CL_EREAD`; short input retains
the format/decompression failure path, and partial decompressor output is
still never scanned. A focused header and frame-metadata callback regression
and source guards cover the boundary. Compiled SWF corpus, sanitizer,
callback-fault, and supported-build Sonic1 qualification remain release gates.

## Mach-O native section metadata — 2026-08-20

64-bit Mach-O section virtual addresses, sizes, aligned raw sizes, and entry
point mapping now retain native-width coordinates in `cli_exe_section64`.
Values that cannot cross the legacy bytecode section ABI are no longer exposed
as narrowed metadata; the legacy view is zeroed and marked incomplete while
native matcher consumers retain the complete coordinates. Entry-point mapping
uses subtraction-based range checks and checked native arithmetic. A sparse
64-bit section regression covers the preservation and legacy-boundary behavior;
full Mach-O, bytecode, sanitizer, and supported-build Sonic1 qualification
remain release gates.

## HFS+ compressed-attribute lookup completeness — 2026-08-20

When an HFS+ volume declares an attributes B-tree, failure to inspect that
tree can hide `decmpfs` metadata needed to recover a compressed file. The
catalog walker now preserves that parser error and marks the layer incomplete
instead of assuming that the file is uncompressed. A genuinely empty,
undeclared attributes fork remains the supported “no attributes tree” case.
The bounded catalog and attributes-tree node caps also return explicit
`CL_EMAXFILES` incomplete results when a valid chain does not terminate within
the cap.
The focused malformed-attribute-tree regression is registered in
`check_clamav`; full HFS+ corpus, sanitizer, and supported-build Sonic1
qualification remain release gates.

## TNEF attribute-header fmap failure — 2026-08-20

The TNEF attribute-list reader now distinguishes an exact end-of-map from an
in-range fmap failure. Exact EOF remains the valid end of a TNEF attribute
list; a failed in-range read marks the layer incomplete and returns
`CL_EPARSE`, preventing a direct parser caller from treating a partially
inspected container as clean. The focused fault-injection regression and
source guard are registered; compiled Linux/Sonic1, sanitizer, and broader
TNEF corpus qualification remain release gates.

## JPEG Photoshop resource boundary — 2026-08-20

The JPEG APP13 Photoshop-resource walk now treats exact end-of-map as the only
normal end of its `8BIM` list. Truncated resource headers, names, size fields,
data ranges, and mapped reads mark the layer incomplete and return `CL_EPARSE`
to direct parser callers instead of being normalized from `CL_BREAK` to clean.
The focused truncated-resource regression and source guard are registered;
compiled JPEG, sanitizer, and broader media corpus qualification remain release
gates.

## TIFF initial magic read failure — 2026-08-20

The TIFF parser now keeps a genuinely short input as a non-TIFF result but
fails closed when a map containing the complete four-byte magic field cannot be
read. The operational failure marks the layer incomplete and returns
`CL_EPARSE` instead of being normalized to clean. The focused fault-injection
regression and source guard are registered; compiled TIFF, sanitizer, and
broader media corpus qualification remain release gates.

## GIF header read failures — 2026-08-20

The GIF parser now keeps genuinely short non-candidates clean but fails closed
when its confirmed signature or version range cannot be read. These paths mark
the layer incomplete and return `CL_EPARSE`; focused fault-injection coverage
and source guards are registered. Compiled GIF, sanitizer, and broader media
corpus qualification remain release gates.

## RIFF header read failures — 2026-08-20

The RIFF/ANI heuristic now keeps inputs shorter than its fixed 12-byte probe as
non-candidates but fails closed when that complete range cannot be read from
the fmap. The failure marks the layer incomplete and returns `CL_EPARSE`;
focused fault-injection coverage and source guards are registered. Compiled
RIFF/ANI, sanitizer, and broader media-corpus qualification remain release
gates.

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

The AES password-derivation path now routes its attacker-controlled
salt-derived buffer through the shared individual-allocation ceiling instead
of plain `calloc()`. An oversized encrypted verifier therefore remains an
explicitly uninspectable encrypted document rather than requesting an
unbounded heap buffer; encrypted Office corpus and supported-build
qualification remain open.

## BinHex encoded-input fmap failure — 2026-08-21

The BinHex decoder now marks an in-range encoded-input fmap failure incomplete
and non-cacheable before returning `CL_EREAD`. This closes the direct-parser
state gap where callers could receive a read error without the shared
completion marker. A fault-injected regression, source guard, and capability
manifest entry are registered; compiled Linux/Sonic1, sanitizer, and broader
BinHex corpus qualification remain open.

## File-type detection fmap failure — 2026-08-21

Unknown-type scans now mark the root incomplete and non-cacheable when the
initial or OOXML-probe fmap read fails, before returning `CL_EREAD` through the
central `cli_magic_scan()` dispatch path. This prevents the early type-error
return from bypassing the shared completion contract. A direct fault-injected
regression and source guard are registered; compiled Linux/Sonic1, sanitizer,
and full ingress qualification remain open.

## PCRE full-subject fmap failure — 2026-08-21

PCRE full-subject mapping failures now release the contiguous reservation,
mark the scan incomplete and non-cacheable, and return `CL_EREAD`; the generic
and target matcher loops stop on that status instead of continuing into later
logical work. The focused synthetic regression and source guard are
registered. Compiled Linux/Sonic1, sanitizer, full-size PCRE, and RSS
qualification remain open.

## Bytecode fmap-window lifetime — 2026-08-21

File-backed bytecode buffer-pipe reads now retain a locked fmap window only
until the matching `buffer_pipe_read_stopped()` call, and context teardown
also releases any abandoned window. The PDF object accessor has no ABI
release operation, so it now uses a bounded unlocked fmap view rather than
leaking a page lock across the bytecode hook lifetime. Focused bytecode tests
verify that both paths leave their resident pages evictable. Independently
compiled ABI-v2, interpreter/JIT, sanitizer, and production-signature
qualification remain open.

## PE resource-heuristic fmap cleanup — 2026-08-21

The PE Swizzor/resource heuristic now exits its bounded error-budget path
through the shared cleanup that releases the locked resource-entry fmap
window. Previously that early return retained the page lock until the map was
destroyed, which could keep resident input pages alive during later PE
inspection. Source guards cover the cleanup invariant; compiled PE corpus,
sanitizer, and large-file qualification remain open.

## InstallShield file-window cleanup — 2026-08-21

InstallShield header walking now releases each locked `IS_FILEITEM` fmap
window before returning for a scan-limit, file-count, or CAB extraction
failure. Those exits previously released borrowed names but could retain the
file-record lock until map destruction. The cleanup is source-guarded;
compiled InstallShield corpus, sanitizer, and large-file qualification remain
open.

## GIF signature-probe fmap lifetime — 2026-08-21

GIF signature recognition now uses an unlocked bounded fmap view because the
three-byte probe is consumed immediately and is not retained across parser
operations. This removes a page lock that previously had no matching
`fmap_unneed` call. The source guard covers the lifetime rule; compiled GIF
corpus, sanitizer, and large-file qualification remain open.

## NsPack source-window lifetime — 2026-08-21

The legacy NsPack PE unpacker now keeps its bounded compressed-source fmap
window locked until `unspack()` has consumed it. Error exits release the window
before leaving the heuristic, and the result-handling macro receives the
already-computed unpack result so its direct-return branches cannot bypass
cleanup. Static guards and whitespace validation pass; compiled PE corpus,
sanitizer, and large-file qualification remain release gates.

## ISO9660 descriptor-window lifetime — 2026-08-21

ISO9660 now snapshots the bounded primary volume descriptor and selected Joliet
descriptor before releasing the fmap window. The later debug and directory
walk therefore use local descriptor bytes even while nested block reads and
allocations can evict unlocked map pages. Static guards and whitespace
validation pass; compiled ISO corpus, sanitizer, and large-file qualification
remain release gates.

## HFS+ file-tree header fmap failure — 2026-08-21

HFS+ confirmed tree-header windows that fail in the fmap now mark the layer
incomplete and return `CL_EREAD` instead of exposing only a generic format
error. This preserves the direct parser contract and prevents an unreadable
tree from being treated as merely malformed. A synthetic catalog-tree
fault-injection regression, source guard, and capability-manifest entry are
registered; compiled Linux/Sonic1, sanitizer, and broader HFS+ corpus
qualification remain open.

## HFS+ fork-content fmap failure — 2026-08-21

HFS+ data/resource-fork windows that fail in the fmap now mark the layer
incomplete and non-cacheable and return `CL_EREAD` instead of exposing only a
generic map error. A synthetic fork-content fault-injection regression, source
guard, and capability-manifest entry are registered; compiled Linux/Sonic1,
sanitizer, and broader HFS+ corpus qualification remain open.

## PNG chunk fmap read failure — 2026-08-21

PNG chunk-length, chunk-type, IHDR, and CRC windows that fail in the fmap now
mark the layer incomplete and return `CL_EREAD`; ordinary short input remains
a parser error. A focused chunk-boundary fault-injection regression, source
guard, and capability-manifest entry are registered. Compiled Linux/Sonic1,
sanitizer, and broader PNG corpus qualification remain open.

## RTF in-range fmap read failure — 2026-08-21

The RTF bounded reader now distinguishes exact end-of-map from an in-range
fmap callback failure. The latter marks the layer incomplete and returns
`CL_EREAD` rather than allowing cleanup to expose the default clean result;
existing stronger detection or application results retain precedence. A direct
fault-injected regression, source guard, and capability-manifest entry are
registered. Compiled Linux/Sonic1, sanitizer, and broader RTF/OLE corpus
qualification remain open.

## PE icon resource-tree fmap failure — 2026-08-21

PE icon matching now uses a status-returning resource lookup. A declared
resource tree whose directory window is structurally outside the map returns a
format error; an in-range fmap failure returns `CL_EREAD` and marks the layer
incomplete/non-cacheable instead of silently exposing a clean-compatible icon
result. A synthetic root-resource fault-injection regression, source guards,
and the PE capability entry are registered. Compiled Linux/Sonic1, sanitizer,
and broader PE/resource corpus qualification remain open.

## PE icon-group entry lifetime — 2026-08-21

PE icon-group scanning now rereads each bounded 14-byte entry immediately
before decoding it. The entry pointer no longer crosses `findres_ex()` nested
resource work, and attacker-declared group lengths are not mapped as one large
contiguous window. Static guards and whitespace validation pass; compiled PE
icon corpus, sanitizer, and large-file qualification remain release gates.

## PE icon bitmap-header range validation — 2026-08-21

PE icon parsing now validates the declared bitmap-header size against the
containing fmap before advancing to palettes or pixel data. The offset uses
the native map-coordinate width, and a header that would extend past the map
is an explicit incomplete/non-cacheable parse result rather than a wrapped
32-bit coordinate that can cause unrelated bytes to be interpreted as icon
metadata. The focused regression and source guards are registered; compiled
Linux/Sonic1, sanitizer, and broader PE/icon corpus qualification remain
open.

## Forced nested-fmap read failures — 2026-08-21

After a nested range passes bounds and resource admission, a source-window
failure while materializing it to disk now returns `CL_EREAD` instead of the
generic map error. The path remains incomplete and non-cacheable, and the
fault-injected nested-range regression checks the status and reason. Compiled
Linux/Sonic1, sanitizer, and broad nested-parser qualification remain open.

## HWP3 document metadata fmap failures — 2026-08-21

HWP3 required document-info and metadata-enabled document-summary reads now
mark the layer incomplete and non-cacheable and return `CL_EREAD` when an
in-range fmap window cannot be read. A direct document-info fault-injection
regression and source guards are registered; compiled Linux/Sonic1,
sanitizer, and broader HWP3 corpus qualification remain open.

## PDF parser input-window fmap failures — 2026-08-21

Confirmed PDF scans now mark the layer incomplete and non-cacheable and return
`CL_EREAD` when the bounded version or trailer fmap window fails in range. A
direct parser fault-injection regression covers the version window, with
source guards and capability evidence registered. Compiled Linux/Sonic1,
sanitizer, and broader PDF corpus qualification remain open.

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
coordinates, now marks any required header, program-header, or section-header
failure incomplete before returning the parser error. This prevents raw
signature analysis from continuing with skipped executable metadata while
leaving the existing raw matcher behavior intact. A focused program-header
fmap fault-injection regression, source guard, and capability-manifest entry
record the invariant. Compiled Linux/Sonic1, sanitizer, and broader ELF
corpus qualification remain open.

## Mach-O metadata read failure — 2026-08-21

Metadata-only Mach-O parsing, used to calculate executable-relative signature
coordinates, now marks any required header, load-command, section, or thread
state failure incomplete before returning the parser error. This prevents raw
signature analysis from continuing with skipped executable metadata while
leaving the existing raw matcher behavior intact. A focused load-command fmap
fault-injection regression, source guard, and capability-manifest entry record
the invariant. Compiled Linux/Sonic1, sanitizer, and broader Mach-O corpus
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

## Service-evidence post-run verification — 2026-08-21

The mandatory service workload now has a standalone post-run verifier. It
rechecks the evidence checksum manifest, required pass markers, source/build
identity, copied build-graph hashes, service executable hashes before and
after the workload, and every recorded runtime-dependency hash. CI runs it
after creating `SHA256SUMS`, making later evidence mutation or build/runtime
substitution fail closed. Supported-Linux execution and full service
qualification remain release gates.

## RIFF callback read status — 2026-08-21

RIFF exploit inspection now distinguishes an in-range fmap callback failure
from a genuinely unavailable range. Header, chunk-header, and nested
list-type callback failures return `CL_EREAD`, retain the incomplete and
non-cacheable state, and propagate through the scanner wrapper; truncated
coordinates remain `CL_EPARSE`. Focused fault-injection regressions, source
guards, and capability evidence record the invariant. Compiled Linux/Sonic1,
sanitizer, callback-fault, and production RIFF corpus qualification remain
open.

## Raw fallback after non-critical parser errors — 2026-08-21

The pre-raw parser stage now continues to the mandatory outer raw matcher for
generic and access/open/map/creation failures, in addition to parse, read,
decoder, and configured-limit results. The root fmap is still usable in these
cases, so a raw signature can remain authoritative; if no detection occurs,
the sticky incomplete state keeps the result non-clean and non-cacheable.
Critical resource, timeout, seek, write, and terminal-abort failures continue
to stop the layer. Compiled fault-injection and production-signature
qualification remain open.

## INSTREAM source bytes share the temporary budget — 2026-08-21

The clamd INSTREAM receive path now carries the exact staged byte count into
the library scan context. Parser, decoder, and matcher spools are charged on
top of the already-live disk-backed source against the same MaxTemporarySize
ceiling, while the existing stream quota rejects oversized input before
staging. Both legacy and structured INSTREAM scans use the reservation-aware
descriptor path. Compiled daemon/protocol and concurrent production
qualification remain open.

## INSTREAM queue admission remains a release gate — 2026-08-21

The former receive path created the INSTREAM temporary file and staged the
complete request before dispatching the descriptor scan to the worker pool.
The admission state machine now keeps a queued request out of staging and
temporary accounting until a worker slot is available. The capability
manifest records the implementation; compiled daemon and Sonic1 runtime
validation remain open.

## INSTREAM client descriptor rewind — 2026-08-21

The clamd client now validates every non-stdin stream descriptor before
starting the protocol. Regular files are rewound first so an already-used
descriptor cannot scan only a suffix, and stat or rewind failures return before
the command is sent. Pipes and other non-regular descriptors remain supported
as streaming inputs. Focused socket-level regressions cover both the complete
regular-file payload and invalid-descriptor rejection; compiled Linux/Sonic1
qualification remains open.

## clamscan stdin summary accounting — 2026-08-21

The stdin front end now counts a successfully scanned input exactly once in
the CLI summary. Clean, trusted, and detected stdin results each contribute
one scanned file; errors do not get a speculative pre-count. This aligns
stdin accounting with ordinary file scans and prevents a clean stdin input
from being reported twice. Compiled CLI and Sonic1 qualification remain open.

## INSTREAMREPORT preserves structured mode through staging — 2026-08-21

`INSTREAMREPORT` now keeps structured mode active while chunks are staged and
clears it only after the terminating zero chunk dispatches the scan. This
keeps quota, write, scan, and completion failures on the length-prefixed JSON
protocol. A clamd regression verifies the detected-stream JSON completion and
zero terminator; compiled daemon and Sonic1 qualification remain open.

## clamd structured empty-file parity — 2026-08-21

The clamd directory walker now records an explicit `COMPLETE` structured
report for zero-byte regular files. Previously those files returned before
the structured callback, which could produce a fallback `RESOURCE_FAILURE`
report even though the input was valid and `clamscan` treated it as a clean
completed scan. The report records one zero-byte logical object and no
skipped operation. Compiled daemon and Sonic1 qualification remain open.

## Service qualification deadline and oracle tightening — 2026-08-21

The service gate now applies `CLAMAV_MAX_SCAN_TIME_MS` consistently to clamd,
direct `clamscan`, and all direct structured-report probes. Its outer service
timeout must cover that deadline; each direct probe is timeout-wrapped,
elapsed-time evidence is recorded, and the protocol helper receives the same
deadline rather than relying on a fixed 15-minute socket timeout. Structured
reports must also agree with the oracle's process result (`0`/`1` require a
zero report status, while `2` requires a nonzero status) and must carry the
exact expected alert, with only the `.UNOFFICIAL` suffix permitted for an
unsigned local signature. This closes a remaining acceptance-harness gap;
compiled Linux/Sonic1 production qualification remains open.

The exact-edge milter subprocess is bound to the same service timeout and
per-file scan deadline through `MILTER_WIRE_TIMEOUT_S` and
`MILTER_MAX_SCAN_TIME_MS`. This removes the harness's former fixed
600-second wire wait and 600,000-millisecond clamd scan limit from the
four-hour qualification path.

## INSTREAM worker admission before staging — 2026-08-21

The daemon no longer creates an INSTREAM temporary file merely because the
client sent the command. When all certified worker slots are occupied, the
receive loop places the request in `MODE_WAITQUEUE`, stops polling that socket
for body data, and leaves the command/body bytes buffered in the kernel or the
bounded command buffer. No temporary file, stream-byte reservation, or parser
spool is created for the waiting request.

When a worker completes, the thread manager wakes the receive loop. The
pending command then acquires a bounded scan-admission reservation, creates its
temporary file, and resumes normal INSTREAM staging. Reservation consumption is
atomic with worker-queue insertion; allocation, temporary-file, disconnect,
timeout, and shutdown paths release an unconsumed reservation. Admission
retries preserve the original read deadline instead of extending it while the
worker pool remains full. Structured `INSTREAMREPORT` requests retain their
report mode while waiting and produce a bounded timeout report if admission
itself expires.

The service qualification harness now runs its two-request serial queue gate
through `clamdscan --stream` and requires both the `INSTREAM admission pending`
and resumed-admission daemon-log markers. Compiled Linux, sanitizer,
production-database, and Sonic1 runs remain release gates.

## MIME unsupported-body spooling — 2026-08-21

The remaining `message/*` MIME path no longer keeps an entire body in the
legacy line list merely to reach an unsupported-format result. All MIME bodies
now enter the shared disk-backed spool, including `external-body` and unknown
message subtypes. Those subtypes still return an explicit incomplete result
after bounded spooling; they are not reported clean and are not silently
treated as nested scans. The former 64 MiB materialization cliff is therefore
removed from this unsupported path while its format limitation remains
documented. Focused source guards cover the dispatch and fail-closed result;
compiled parser and Sonic1 qualification remain release gates.

## Legacy callback error propagation — 2026-08-21

Deprecated pre-cache, file-inspection, pre-scan, and post-scan callbacks now
preserve unexpected `cl_error_t` returns. Each such return marks the layer
incomplete and prevents a clean cache entry, rather than being discarded as a
warning or allowing a clean result. A public `cl_scanmap_ex2` regression covers
all four callback entry points and verifies both the returned status and the
structured report status. Compiled Linux/Sonic1 and broader callback
fault-injection qualification remain open.

## Modern callback error propagation — 2026-08-21

The scan-layer callback dispatcher no longer converts an unexpected callback
error into continued scanning or an accepted alert. Pre-hash, pre-scan, and
post-scan callback errors now mark the layer incomplete, preserve the callback
status, and prevent a clean cache result. The public `cl_scanmap_ex2`
regression covers all three locations and verifies the structured report.
Compiled Linux/Sonic1 and broader callback fault-injection qualification remain
open.

## Service workload semantic post-run verification — 2026-08-21

The service qualification output now copies the caller-supplied eight-column
oracle and records every workload accepted by the gate: direct `clamscan`,
clamdscan path/FD/stream scans, structured report probes, the serial queue, the
four-worker profile, parser-expansion and cold-cache runs, and the exact-edge
milter test. `largefile_service_evidence_check.sh` invokes a separate
standard-library verifier after checksum, provenance, executable, and
dependency checks. It independently re-hashes each recorded input and
revalidates report schema, completion, type, root size, counters,
status, signature/offset, and the milter rejection marker. Missing, duplicate,
or unexpected workload records fail the evidence gate. Production CVD and
Sonic1 qualification remain release gates.

Detection-shaped reports are also required to carry a non-clean verdict
(`CL_VERDICT_STRONG_INDICATOR` or `CL_VERDICT_POTENTIALLY_UNWANTED`) in addition
to the oracle's exact alert name. A matching `last_alert` paired with a clean
verdict is rejected by the service qualification, direct report-protocol, and
post-run workload verifiers.

## FILDES unavailable-build failure semantics — 2026-08-21

The legacy clamd `FILDES` worker now returns a non-clean completion when the
binary was built without descriptor-passing support, after sending its
explicit `FILDES support not compiled in` wire error. This prevents an
unsupported optional ingress from being counted as a successful worker or
`IDSESSION` aggregate. Certified Linux x86-64 builds still require descriptor
passing and need compiled no-feature integration coverage before that variant
can be claimed.

## Embedded PE header admission above 4 GiB — 2026-08-21

Embedded PE header validation no longer rejects a recognized candidate solely
because its containing-file offset exceeds the 32-bit legacy executable
metadata ABI. The scanner now creates a bounded fmap view rooted at the
native-width candidate offset, runs the existing PE header parser at relative
offset zero, propagates any child non-cacheable state back to the containing
map, restores the parent context, and then continues with the normal nested
scan. The legacy metadata ABI is unchanged; parser-specific 32-bit limits
inside the child remain explicit incomplete results. A focused regression
exercises the same bounded-child technique with a synthetic offset above 4
GiB. Compiled scanner, sanitizer, production-database, and Sonic1 evidence
remain release gates.

## Local macOS qualification preflight — 2026-08-22

A fresh native macOS host-preflight on Darwin arm64 recorded
`memory_available_kb=5323248` against the required
`minimum_available_kb=50331648` and therefore failed the host-resource gate.
The environment also reports no CMake or Ninja binary; its `hw.memsize` query is
restricted, while the memory-pressure capture identifies a roughly 16 GiB
system. This is an environment limitation, not a scan result or a
qualification claim; the 64 GB bare-metal host and a dependency-complete build
remain required for the planned macOS raw-path run.

## ZIP fixed-header fmap read status — 2026-08-21

ZIP fixed local-header and central-directory-header admission now validates
the requested range before calling the fmap callback. An out-of-range request
remains `CL_EPARSE`, while an in-range backing-read failure is reported as
`CL_EREAD`, marked incomplete, and made non-cacheable. This prevents a storage
or callback fault from being misrepresented as ordinary malformed ZIP input.

Focused local-header and central-header callback-fault regressions and the
source guard are registered. The current macOS checkout has no CMake/Ninja
build tree, so the compiled unit tests remain a release qualification gate
rather than a claimed local runtime result.

## Current-head Sonic1 liveness attempt — 2026-08-21

The MCP-SSH host inventory and the declared `sonic1-camera-key` capabilities
were available, but a bounded `uname -a` command timed out during SSH connect
after the effective 20-second limit. The response reported
`remote_started=false` and no remote command output. This is a host-liveness
failure, not build or scan evidence; current-head Linux/Sonic1 qualification
remains open.

A subsequent read-only retry after resuming the roadmap produced the same
20-second connect timeout, again with `remote_started=false` and no remote
output. No Sonic1 build, scan, or resource result is inferred from either
attempt.

## Source inventory refresh — 2026-08-21

The authoritative `docs/largefile-inventory.tsv` was regenerated from the
current source tree after the recent parser, daemon, Rust, and test changes.
The generator reproduces the committed 32,608-line inventory exactly, and the
162-entry capability manifest still validates every required ingress, matcher,
feature, unsupported boundary, parser dispatch branch, and source path.

## clamscan stdin staging shares the temporary budget — 2026-08-22

`clamscan` now admits each stdin chunk against the engine's
`MaxTemporarySize` before writing it to its staging file, and passes the
complete staged byte count into the descriptor scan. A successful exact-size
stdin scan therefore charges the staged source plus parser spools; a
temporary-budget crossing returns `CL_ERESOURCE` and removes the partial file.
A `MaxFileSize` crossing still uses the one-byte-over-limit sentinel only when
that sentinel itself fits the temporary budget. The service qualification
gate now records exact-edge `clamscan` stdin and `clamdscan -` stdin
workloads against the same hash/type/status oracle; compiled stdin,
temporary-budget, and exact-edge runtime evidence remain open. A focused
library regression also verifies that
the path-based helper reports the staged reservation at the exact quota and
returns `CL_ERESOURCE` when the reservation crosses it.
The Linux raw runtime gate also schedules a sparse 32-GiB-plus-one stdin
boundary and rejects a clean-prefix result, while a separate exact-32-GiB
stdin run must detect the final marker at offset `34359738304`; the dedicated
host run remains required.

## BMP and JPEG 2000 structural admission remains fail-visible — 2026-08-21

Recognized BMP inputs now receive bounded structural validation of the file
header, DIB dimensions, compression, pixel offset, declared file size, and
derived uncompressed pixel range (including the legal zero image-size case)
without mapping the attacker-declared image payload. Recognized JPEG 2000
inputs receive bounded JP2 box-length validation, required-box admission, and
codestream-start validation without mapping the codestream payload. These do
not claim complete image decoding: valid structurally admitted BMP and JP2
inputs return explicit unsupported/incomplete results, while malformed or
truncated inputs preserve `CL_EPARSE` and backing callback failures preserve
`CL_EREAD`. Other generic graphics remain on the explicit unsupported
boundary. Full image parser and production-corpus qualification remain open.

## Opt-in library exact-edge qualification

The unit suite now includes a dedicated sparse exact-32-GiB library test. It
creates a file with the marker in the final 64 bytes, loads a private
signature, and scans it independently through `cl_scanfile_ex2()`,
`cl_scandesc_ex2()`, and `cl_scanmap_ex2()`. Each API must produce the exact
detection, `DETECTION_TERMINATED` report, 32-GiB root size, and at least one
complete 32-GiB matcher pass. The ordinary unit suite does not run this
four-hour-scale test.

Enable it only on a qualified Linux x86-64 build:

```sh
cmake -S . -B build -DENABLE_TESTS=ON \
  -DENABLE_LARGE_FILE_QUALIFICATION_TEST=ON
cmake --build build --target check_clamav
ctest --test-dir build -R '^largefile_library_exact_32g$' -V
```

The CTest entry supplies `CLAMAV_LARGEFILE_QUALIFY=1` and selects only the
dedicated Check case. This is library-path evidence; it does not replace the
front-end, production-database, sanitizer, or Sonic1 service gates.

## Milter descriptor rewind fail-closed handling — 2026-08-21

The local milter path now checks the temporary-file `lseek()` used immediately
before FILDES submission. A rewind failure closes the request and returns the
configured failure action rather than submitting a descriptor whose scan
position is unknown. This preserves the milter completeness contract; compiled
exact-edge, mutation, and production-database qualification remain open.

## On-access unsent-request fail-closed handling — 2026-08-21

The on-access client no longer treats a zero-length send result as a successful
soft skip. A file can disappear between the event preflight and `safe_open()`;
that request now increments the error count, receives `CL_EOPEN` (or preserves
the more specific existing error), and returns a non-clean result. Monitoring-
only mode can still allow the event, but it receives an explicit incomplete
status for logging; prevention mode can therefore deny the permission event.
This closes a clean-prefix/unsent-request fail-open path. Compiled fanotify,
monitoring-mode, and mutation integration qualification remain open.

## Compressed-stream deadline enforcement — 2026-08-21

The GZip main and legacy fallback, BZip2, and XZ streaming decoders now check
the shared `MaxScanTime` deadline before each decoder/read iteration and during
the GZip output loop. CPU-heavy compressed input that produces little output
can no longer bypass the scan deadline until the whole input is consumed;
timeouts preserve the non-clean status and discard the partial temporary
member. Compiled timeout injection, sanitizer, and production compressed-stream
qualification remain open.

## CPIO cursor arithmetic — 2026-08-22

The old binary, ODC, and newc/CRC CPIO handlers now route every header, name,
padding, and member-data cursor advance through a checked native-width helper.
An attacker-controlled length that would wrap the archive coordinate is now a
fail-visible `CL_EPARSE` result with the layer marked incomplete. Existing
header/name callback-fault and impossible-next-header regressions remain
applicable; compiled CPIO coordinate-boundary and production-corpus
qualification remain open.

## ARJ extracted-size admission — 2026-08-22

ARJ materialized members are now checked with `fstat()` before nested scanning:
the output must be a regular file whose native-width size exactly matches the
declared original size. A mismatch is marked incomplete and returns
`CL_EUNPACK`, so stored members cannot scan a short output as if extraction had
completed. The compiled malformed-output, filesystem-fault, sanitizer, and
production ARJ qualification gates remain open.

## HFS+ traversal deadlines — 2026-08-22

HFS+ now checks the shared deadline at parser entry and while walking catalog
nodes, attribute nodes, fork blocks, resource block tables, and compressed
resource blocks. A timeout marks the partition incomplete and prevents a clean
result after a partial traversal. Compiled timeout injection, sanitizer, and
large-volume HFS+ qualification remain open.

## ISO9660 traversal deadlines — 2026-08-22

ISO9660 now checks the shared deadline at scan entry, volume walking, directory
blocks, directory entries, and file-extent staging. Timeout expiry marks the
confirmed image incomplete and prevents a clean result after partial traversal.
Compiled timeout injection, sanitizer, and production ISO9660 qualification
remain open.

## TIFF IFD traversal deadline — 2026-08-22

TIFF now checks the shared scan deadline before each linked IFD is entered and
marks the layer incomplete when the deadline expires. This bounds work from a
large or cyclic-looking directory chain without changing the native-width
coordinate and value-range checks. Compiled timeout injection, sanitizer, and
production TIFF corpus qualification remain open.

## GIF and PNG traversal deadlines — 2026-08-22

GIF block, extension-sub-block, and image-data-sub-block loops now check the
shared scan deadline, as does PNG chunk traversal. Deadline expiry marks the
confirmed media layer incomplete and prevents a clean overlay result. Compiled
timeout injection, sanitizer, and production GIF/PNG corpus qualification
remain open.

## MIME/mbox traversal deadlines — 2026-08-22

The MIME/mbox parser now checks the shared `MaxScanTime` deadline before raw
message entry, at each bounded line read, while parsing materialized headers,
and during disk-backed multipart discovery and related-part traversal. Expiry
marks the message incomplete and preserves `CL_ETIMEOUT`, so a large message
cannot spend unbounded time in line/header/multipart handling before reaching
the common scan-result policy. A focused expired-context regression verifies
the fail-visible result and cache suppression; compiled MIME timeout injection,
sanitizer, and production mail-corpus qualification remain open.

## Logical matcher root status merge — 2026-08-22

Target-specific and generic logical/YARA matcher roots are evaluated
sequentially. Their statuses now pass through `cli_merge_scan_status()` rather
than allowing the later root to overwrite the earlier result. This preserves a
target-root parser, bytecode, read, or resource failure when the generic root
returns clean, while retaining detection precedence. A focused two-root
regression and source guards cover the fail-closed merge; complete logical
signature corpus and production qualification remain release gates.

## YARA execution-status normalization — 2026-08-22

Bundled YARA execution errors are normalized before they enter ClamAV’s
`cl_error_t` policy. This prevents `ERROR_EXEC_STACK_OVERFLOW` (numeric 25)
from colliding with `CL_EMAXFILES`; unknown execution failures become
`CL_EPARSE`, while timeout, memory, resource, and fmap-read failures remain
fail-visible and non-cacheable. A focused overflow regression covers the
boundary; full YARA corpus and production qualification remain release gates.

## ALZ MaxFiles admission propagation — 2026-08-22

The ALZ metadata callback now preserves `CL_EMAXFILES` when the shared file
count limit prevents a recognized member from being inspected. The Rust
parser no longer returns clean merely because the outer C context carries a
sticky incomplete flag; the direct result and cache/report policy now agree.
A focused helper regression covers the boundary, while full ALZ corpus,
sanitizer, and supported-build qualification remain release gates.

## ALZ final limit-result propagation — 2026-08-22

ALZ finalization now returns `CL_EMAXSIZE` for a recorded oversized or
cumulative-size skip and `CL_EMAXFILES` for an internally counted file-limit
stop. The parser still records the standard heuristic and sticky incomplete
state, but no longer returns clean after required members were omitted. Full
ALZ limit-edge corpus, sanitizer, and supported-build qualification remain
release gates.

- The shared `clamd_stream_limit()` helper now clamps positive
  `StreamMaxLength` values above the certified 32-GiB ceiling even when a
  caller supplies an `optstruct` directly. Both daemon staging and client
  preflight therefore retain the same hard ingress bound; a focused clamd unit
  regression covers the bypass case, while compiled service and Sonic1
  qualification remain open.

- The established 32-bit `cli_ctx.scannedfiles` counter now fails closed at
  `UINT32_MAX` when `MaxFiles=0` is used, returning `CL_ERESOURCE` and marking
  the scan incomplete instead of wrapping and admitting another object. The
  internal ABI is unchanged; the focused limit regression covers this native
  counter boundary, while production file-count qualification remains open.
- Structured report JSON now serializes 64-bit counters through json-c's
  unsigned-integer type, and legacy json-c versions refuse values above
  `INT64_MAX` rather than emitting negative metrics. A focused saturated-counter
  regression covers the boundary; compiled report and service qualification
  remain open.

## ELF32 table-coordinate widening — 2026-08-22

ELF32 keeps its on-disk entry-point, program-table, and section-table offsets
at 32 bits, but a table's later implicit entries can still lie beyond the
4 GiB boundary in a larger containing file. The parser now widens its
program/section table cursors and derived entry-point file coordinates to
native-width containing-file arithmetic instead of wrapping after the first
entry or rejecting a segment whose derived file offset crosses 4 GiB.
Format-defined 32-bit section and entry coordinates remain unchanged; the
legacy metadata bridge is explicitly incomplete when it cannot represent the
native coordinate. A synthetic table fixture verifies both the derived
entry-point coordinate and a second section header above `UINT32_MAX`. Full
ELF corpus, sanitizer, and supported-Linux qualification remain open.

## PE32 native RVA-to-file coordinates — 2026-08-22

PE32 RVAs and section-header fields remain format-defined 32-bit values, but a
section's 32-bit raw start plus an in-section RVA delta can cross 4 GiB in a
larger containing file. PE translation now computes that sum in native width
and exposes native section metadata and entry-point coordinates to the modern
matcher. The legacy `cli_rawaddr()` and bytecode bridge reject an
unrepresentable coordinate rather than wrapping it; PE-specific inspection
therefore remains explicitly incomplete when the legacy ABI is required. A
focused boundary regression covers both the native result and the fail-closed
legacy result. Full PE corpus, unpacker, sanitizer, and supported-Linux
qualification remain open.

## PE32 unsigned high-bit section fields — 2026-08-22

PE section-header DWORDs are unsigned format fields. A high bit in a
`VirtualAddress`, `VirtualSize`, or raw-coordinate field is therefore not
automatically a malformed header. The PE header parser now keeps those values
in the native section metadata and marks only the legacy signed-coordinate
PE-specific path incomplete instead of rejecting the recognized layer. RVA
extent aggregation is checked before updating the legacy 32-bit range, so an
overflow becomes an explicit incomplete result rather than a wrapped bound. A
synthetic high-bit section-header regression and source guards cover the
disposition; compiled PE corpus, unpacker, sanitizer, and supported-build
qualification remain open.

## PE32 aligned section extents — 2026-08-22

PE alignment-up can turn a legal 32-bit raw-size or virtual-size field into a
native extent above 4 GiB. Section alignment, file-range truncation, and
overlay calculation now retain those values in the native section view; the
legacy section view is narrowed only with an explicit incomplete marker. PE
hash generation refuses to produce a partial legacy result when that bridge is
incomplete. A sparse logical-map regression covers a 4-GiB aligned section
size and native overlay start; compiled PE corpus, unpacker, sanitizer, and
supported-build qualification remain open.

## ISO9660 long directory names — 2026-08-22

ISO directory identifiers larger than the fixed 260-byte display buffer are
bounded and marked incomplete. The directory walker now uses the normalized
buffer length when searching for a version suffix and writing the terminator,
so a long identifier cannot index past the display buffer. A synthetic
260-byte identifier regression and source guards cover the boundary; compiled
ISO corpus, sanitizer, and parser-family qualification remain open.

## ISO9660 root-directory coordinate overflow — 2026-08-22

The primary ISO root directory uses the same extent-location plus
extended-attribute-length arithmetic as child directory records. That sum is
now performed in 64-bit arithmetic and rejected before the root walk when it
cannot be represented by the ISO block coordinate; otherwise a wrapped value
could redirect inspection to an earlier block. The existing coordinate
regression now covers both child and root records; compiled ISO corpus,
sanitizer, and parser-family qualification remain open.

## BZip2 concatenated streams — 2026-08-22

BZip2 extraction now continues through concatenated streams, preserving unread
bytes from the completed decoder window and reinitializing only after
`BZ_STREAM_END`. A decoder that makes no progress while input remains is
marked incomplete instead of spinning indefinitely. The focused regression
places a signature marker in the second stream; malformed decoder-state,
sanitizer, and production BZip2 corpus qualification remain open.

## JPEG Photoshop resource-header read failures — 2026-08-22

The JPEG parser already distinguished fmap callback failures while reading
segment sizes and Photoshop resource sizes, but its in-range `8BIM`
resource-header window converted a callback failure into a parse result. That
window now preserves `CL_EREAD` and remains non-cacheable; a focused callback
regression covers the boundary. Compiled Photoshop-resource, sanitizer, and
production JPEG corpus qualification remain open.

## JPEG Photoshop marker-prefix read failures — 2026-08-22

The APP13 Photoshop marker probe now requires the complete marker prefix to be
inside the APP13 segment before reading it, so a short APP13 payload cannot
borrow bytes from the following JPEG segment. An in-range fmap callback
failure while reading that confirmed marker prefix now remains `CL_EREAD` and
non-cacheable. A focused callback regression covers the boundary; compiled
marker-fault, sanitizer, and production JPEG corpus qualification remain open.
The existing exact-EOF Photoshop-resource regression continues to classify a
resource list ending at the segment boundary as complete.

## JPEG Photoshop resource segment boundaries — 2026-08-22

Photoshop `8BIM` resources and nested thumbnail JPEGs are now bounded by the
containing APP13 segment rather than the whole fmap. A resource that reaches
the segment boundary ends normally, while a resource or thumbnail that claims
bytes beyond it remains a non-cacheable parse failure. A focused boundary
regression injects a callback fault at the following segment; compiled
thumbnail corpus, sanitizer, and production JPEG qualification remain open.

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

PE version-resource extraction previously discarded the status from its
resource-tree walker and skipped failed entry or payload windows. The target
metadata path now preserves resource-tree, entry, and payload coordinate or
backing-read failures as non-cacheable `CL_EFORMAT` or `CL_EREAD` results. A
focused callback regression covers a confirmed resource-tree read failure;
compiled PE metadata corpus, sanitizer, and supported-build qualification
remain release gates.

## PE Swizzor resource read failures — 2026-08-22

The enabled Swizzor resource heuristic previously treated failed recursive
resource windows and malformed resource coordinates as ignorable heuristic
noise, allowing a clean result after incomplete inspection. Its bounded walk
now propagates `CL_EREAD` for backing-read failures and `CL_EFORMAT` for
malformed or out-of-range coordinates to `cli_scanpe`, which marks the layer
incomplete and non-cacheable. A focused normal-scan callback regression covers
the confirmed resource-tree root; compiled Swizzor corpus, sanitizer, and
supported-build qualification remain release gates.

## PDF trailer-xref read failures — 2026-08-22

The PDF trailer xref window is an admitted in-range read. A backing fmap
callback failure in that window now remains `CL_EREAD`, incomplete, and
non-cacheable, while a successfully read but malformed xref remains
`CL_EPARSE`. The focused regression faults the xref window after version and
trailer discovery; compiled PDF corpus, sanitizer, and supported-build
qualification remain release gates.

## Complete sanitizer compile-graph evidence — 2026-08-22

The runtime gate and post-run verifier now inspect every command-based native
entry in the sanitizer compile database and reject any entry missing either
ASan or UBSan. This prevents a partially instrumented build from satisfying the
sanitizer provenance gate because one command happens to carry both flags.
Actual Linux/Sonic1 sanitizer execution and parser coverage remain release
gates.

## HTML normalized-output temporary admission — 2026-08-22

HTML nocomment, notags, JavaScript, and RFC2397 normalized output is now
admitted in chunks against the caller-owned `MaxTemporarySize` budget before
each write. The main HTML scanner retains those reservations through required
normalized child scans and cleanup, while MBOX/phishing URL normalization uses
the same admission for its file-backed pass. Quota and write failures remain
incomplete and non-cacheable, including RFC2397 outputs that finish before
the normalizer exits. Direct legacy HTML helper wrappers retain their
compatibility behavior and require separate qualification.

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

## 7-Zip legacy-fallback output deadline — 2026-08-22

The bounded 7-Zip path already checked deadlines in its streaming extraction
callback, but the compatibility fallback for decoder folders below the 1 GiB
individual-allocation ceiling wrote its materialized buffer directly with
`cli_writen()`. That fallback now uses the same deadline-aware output callback,
preserving `CL_ETIMEOUT` before temporary output can be treated as complete.
Compiled fallback/solid-folder timeout injection, corpus, sanitizer, and
Sonic1 qualification remain open.

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

## SWF temporary-output admission deadline — 2026-08-22

SWF CWS/ZWS temporary-output writes now re-check `MaxScanTime` after quota
admission and immediately before each header or decoded-chunk write, closing
the interval between decoder-loop checks and the actual output. An expired
context releases the current reservation and temporary file and returns
`CL_ETIMEOUT`; short writes release the current reservation, mark the layer
incomplete, and return `CL_EWRITE`, without treating partial output as
scannable. Source guards cover this boundary; deterministic output-timeout
injection, compiled corpus, sanitizer, and Sonic1 qualification remain release
gates.

## XLM temporary-output deadlines — 2026-08-22

XLM macro normalization and extracted-image staging now re-check `MaxScanTime`
before temporary quota admission and again before writing output. Expired
contexts release any reservation during cleanup and return `CL_ETIMEOUT`
without allowing partial macro or image output to be scanned as complete. A
focused expired-context macro regression and source guards cover the boundary;
compiled Office/XLM corpus, sanitizer, and Sonic1 qualification remain release
gates.

## NSIS post-admission output deadline — 2026-08-22

NSIS extraction already checked `MaxScanTime` before each output reservation,
but a deadline could expire after quota admission and before the corresponding
temporary write. The output callback now re-checks the deadline after reserving
bytes, releases that reservation on timeout, and returns `CL_ETIMEOUT` without
scanning partial output. A source guard covers this boundary; deterministic
timeout injection, compiled NSIS corpus, sanitizer, and Sonic1 qualification
remain release gates.

## HWP/HWPML output deadlines — 2026-08-22

HWP raw-deflate output and HWPML Base64 attachment output now re-check
`MaxScanTime` before temporary quota admission and again before writing. Any
post-admission timeout releases the just-added reservation and returns
`CL_ETIMEOUT` without treating partial document output as complete. Source
guards cover these boundaries; deterministic timeout injection, compiled
HWP/HWPML corpus, sanitizer, and Sonic1 qualification remain release gates.

## XDP retained-dump accounting and output deadline — 2026-08-24

Optional XDP `keeptmp` staging now retains a cumulative temporary reservation
for the complete dump instead of releasing each 8 KiB chunk while the file
continued growing. The reservation stays live through streaming XML and Base64
inspection, so the retained input and decoded child outputs share one
`MaxTemporarySize` budget. Admission, deadline, read, write, close, and partial-
cleanup failures release the complete reservation and remain incomplete and
non-cacheable; successful parsing also returns the counter to zero.

The focused Linux ARM64 GCC `xdp` case passes 3/3. It proves the existing
timeout path with a valid scan context, cumulative rejection on the second dump
window, overlap between a successful retained dump and decoded Base64 output,
exact peak accounting, zero-byte rollback, and removal of a rejected partial
dump. Production XDP corpus, sanitizer, Linux x86-64, materialized large-file,
and Sonic1 qualification remain open; Sonic1's SSH service refused or timed out
before any command started during this milestone.

## HTML output-boundary deadlines — 2026-08-22

Buffered HTML normalized output and script-encoded output now re-check
`MaxScanTime` before quota admission, after reserving bytes, and immediately
before each direct write. Timeout paths release the reservation and retain the
incomplete result without scanning partial normalized data. Source guards cover
both output APIs; deterministic timeout injection, compiled HTML/MHTML corpus,
sanitizer, and Sonic1 qualification remain release gates.

## InstallShield output deadlines — 2026-08-22

InstallShield MSI member, embedded-file, and CAB output paths now re-check
`MaxScanTime` before admission and immediately before each materialized write.
Timeout cleanup releases current or aggregate temporary reservations and keeps
partial output from reaching a nested scan. Source guards cover all three
paths; deterministic timeout injection, compiled InstallShield corpus,
sanitizer, and Sonic1 qualification remain release gates.

## MSPack member-boundary deadlines — 2026-08-22

Bundled CAB/CHM decoder callbacks already checked `MaxScanTime` during reads,
seeks, and writes. Member temporary admission and the handoff from a completed
extraction to nested scanning now perform explicit checks as well, preserving
`CL_ETIMEOUT` and reservation cleanup when the deadline expires outside the
decoder callback. Source guards cover both families; deterministic
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

## HFS+ output deadlines — 2026-08-22

HFS+ ordinary fork, inline compressed, and compressed-resource output paths now
re-check the shared deadline after temporary admission and immediately before
materialized writes. Timeout cleanup releases the fork/resource reservation
and prevents partial output from reaching nested scans. Source guards cover
the output families; deterministic post-admission injection, compiled HFS+
corpus, sanitizer, and Sonic1 qualification remain release gates.

## AutoIt output deadlines — 2026-08-22

EA05/EA06 streamed output and EA06 script-output paths now re-check the
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

Logical-signature evaluation now merges non-critical failures and continues to
independent later signatures. Detections and critical timeout/resource/I/O
failures still stop evaluation, while an unavailable bytecode entry or
legacy-ABI incompatibility remains incomplete and non-cacheable without
silencing a later detection. The focused regression and source guards cover
this status contract; compiled logical-signature, interpreter/JIT, sanitizer,
and production qualification remain release gates.

## Raw matcher-root continuation after non-critical failure — 2026-08-22

Target-specific raw matcher failures in buffer and fmap scans now remain
fail-visible without suppressing the independent generic raw pass. Non-critical
parser/read/matcher results are merged and scanning continues; detections and
critical timeout/resource/I/O failures still halt immediately. Static guards
cover both ingress helpers, while compiled fault-injection and
production-signature qualification remain release gates.

## Rust temporary-spool write boundaries — 2026-08-22

Rust parser output that arrives as a large callback slice now reaches disk
through bounded 64 KiB writes, with a shared `MaxScanTime` check before every
write. A timeout or short write remains fail-visible and releases any
reservation added for the current chunk, so a large OneNote attachment or
other Rust-produced view cannot monopolize one unchecked output operation.
Compiled Rust parser, deterministic write-timeout, sanitizer, and Sonic1
qualification remain release gates.

## MIME retained-node accounting — 2026-08-22

The legacy MIME line-list admission counter now charges retained payload bytes
plus each linked-list node and the ref-count byte prepended by `lineCreate()`.
This prevents a message containing many short retained lines from exceeding
the intended bounded representation. Intentionally deduplicated blank
separators are checked before reservation, so discarded input does not consume
the quota. Static source guards and non-clang regression gates pass; compiled
allocation-fault, sanitizer, production-mail, and Sonic1 qualification remain
open.

## On-access FILDES hard-ceiling preflight — 2026-08-22

The on-access descriptor-passing helper now clamps direct-context limits to the
hard 32-GiB boundary, checks the descriptor with `fstat`, and rejects an
over-limit regular file before sending `FILDESREPORT`. The existing scan-thread
preflight remains, while this protocol-layer check closes the direct-caller
bypass and preserves explicit `CL_EMAXSIZE`/`CL_ESTAT` results. Compiled
on-access fault-injection, sanitizer, and Sonic1 qualification remain open.

## On-access stream rewind failure — 2026-08-22

Regular-file on-access streams now require a successful rewind before sending
`INSTREAMREPORT`. A failed `lseek` returns `CL_ESEEK` and sends no command,
preventing a stale descriptor position from producing a partial or unrelated
scan; non-seekable non-regular inputs retain their existing behavior. Compiled
read/seek fault injection, sanitizer, and Sonic1 qualification remain open.

## PE icon nested-window read classification — 2026-08-23

PE icon group headers, icon data pointers, palettes, and pixel windows now
preflight their complete ranges before invoking fmap callbacks. Short ranges
remain parse/incomplete results, while fully in-range callback failures remain
`CL_EREAD` with explicit incomplete reasons. Pixel-window size arithmetic is
checked before admission, and the intentionally tolerated broken 32-bit mask
fallback remains unchanged. Compiled PE/icon corpus, sanitizer, and Sonic1
qualification remain release gates.

## JPEG application-marker probe classification — 2026-08-23

JPEG APP metadata probes now stay within their declared segment. Short optional
payloads remain ordinary non-matches, while fully in-range fmap callback
failures remain `CL_EREAD` with explicit incomplete state instead of being
silently ignored. Compiled JPEG corpus, sanitizer, and Sonic1 qualification
remain release gates.

## MSEXPAND fixed-header range classification — 2026-08-23

MSEXPAND now distinguishes a genuinely short packed header (`CL_EPARSE`) from
an in-range fmap callback failure (`CL_EREAD`) before decoder admission. The
focused direct-parser regression covers both outcomes; compiled SZDD corpus,
sanitizer, and Sonic1 qualification remain release gates.

## NSIS fixed-header range classification — 2026-08-23

NSIS now distinguishes a genuinely truncated 0x1c-byte decoder header
(`CL_EPARSE`) from an in-range fmap callback failure (`CL_EREAD`) before
member-table admission. The focused `cli_scannulsft` regression covers both
outcomes; compiled NSIS corpus, sanitizer, and Sonic1 qualification remain
release gates.

## InstallShield MSI fixed-header range classification — 2026-08-23

The direct InstallShield MSI scanner now distinguishes a short 0x20-byte
control header (`CL_EPARSE`) from an in-range fmap callback failure
(`CL_EREAD`) before reading metadata. Existing MSI fault-injection coverage
asserts both outcomes; compiled InstallShield corpus, sanitizer, and Sonic1
qualification remain release gates.

## ZIP64 extra-field read classification — 2026-08-23

ZIP local and central ZIP64 extra-field reads now preserve parse/format status
for genuinely short or malformed metadata and return `CL_EREAD` for fully
in-range fmap callback failures. Both paths mark the scan incomplete and
non-cacheable; focused local-only and central-directory fault-injection cases
cover the distinction. Compiled ZIP corpus, sanitizer, and Sonic1
qualification remain release gates.

## GIF/PNG missing-map handling — 2026-08-23

GIF and PNG parser entry points now reject a missing input fmap before any
metadata dereference and return an explicit incomplete parse result. Focused
direct-parser tests cover both media families; compiled corpus, sanitizer, and
Sonic1 qualification remain release gates.

## HFS+ catalog-node range classification — 2026-08-23

HFS+ catalog-node block reads now preflight the requested range against the
input fmap. A short node remains an explicit format/incomplete result, while a
fully in-range callback failure remains `CL_EREAD`; focused coverage exercises
the one-byte-short leaf boundary. Compiled HFS+ corpus, sanitizer, and Sonic1
qualification remain release gates.

## Legacy bytecode read-coordinate admission — 2026-08-23

The legacy bytecode `read` entry rejects negative offsets and host-
unrepresentable or size-overflowing ranges before passing coordinates to fmap.
This prevents malformed v1 state from wrapping into a different input range;
independently compiled fixture and interpreter/JIT qualification remain release
gates.

## TNEF missing-map handling — 2026-08-23

TNEF now checks for a missing input fmap before time-limit or header processing
and returns an explicit incomplete `CL_ENULLARG` result for a non-null context.
Focused direct-parser coverage exercises the boundary; compiled mail corpus,
sanitizer, and Sonic1 qualification remain release gates.

## ISO9660 Joliet name-expansion admission — 2026-08-23

ISO9660 now marks Joliet UTF-16BE-to-UTF-8 conversion failure and converted
directory names that exceed the fixed destination buffer as incomplete rather
than silently substituting an empty or truncated name. A focused Joliet fixture
exercises the expansion boundary; compiled ISO corpus, sanitizer, and Sonic1
qualification remain release gates.

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
sanitizer, and Sonic1 qualification remain release gates.

## MIME header lookahead read failure — 2026-08-23

MIME header continuation detection now distinguishes a failed in-range fmap
lookahead from an ordinary non-continuation. The failure stops header parsing,
preserves `CL_EREAD`, and leaves the layer incomplete and non-cacheable. The
focused unit regression injects the failure once so a retry cannot hide the
original operational error.

## Shared fmap string-read failure classification — 2026-08-23

ARJ filename/comment metadata and legacy embedded InstallShield strings now
use bounded fmap windows that distinguish an in-range backing read failure
(`CL_EREAD`) from a missing terminator (`CL_EPARSE`). InstallShield string
lookups are also constrained to the selected input range. Focused fmap, ARJ,
and InstallShield fault-injection coverage is recorded; compiled parser,
sanitizer, corpus, and Sonic1 qualification remain release gates.

## MSPack decoder read-failure propagation — 2026-08-23

CAB/CHM decoder-owned fmap callback failures now remain `CL_EREAD` through
decoder open and member extraction instead of being collapsed into parse or
format results. Deadline expiry remains `CL_ETIMEOUT`, and focused CAB fault
injection covers the decoder-owned read boundary; compiled MSPack corpus,
sanitizer, and Sonic1 qualification remain release gates.

## Legacy InstallShield CAB header read classification — 2026-08-23

The embedded InstallShield header path now distinguishes a genuinely short
declared header (`CL_EPARSE`) from a fully in-range fmap callback failure
(`CL_EREAD`). Focused coverage exercises both outcomes; compiled InstallShield
corpus, sanitizer, and Sonic1 qualification remain release gates.

## OneNote legacy reader read-failure propagation — 2026-08-23

The Rust OneNote legacy reader now preserves source I/O failures as
`CL_EREAD`; genuine `UnexpectedEof` and declared-range truncation remain
`CL_EPARSE`. Focused reader coverage exercises the distinction, while compiled
OneNote corpus, sanitizer, and Sonic1 qualification remain release gates.

## MIME line read-failure propagation — 2026-08-23

The mail parser now carries an in-range fmap callback failure from its bounded
MIME line reader to `cli_mbox()`, preserving `CL_EREAD` instead of collapsing
that operational failure into generic incomplete `CL_EPARSE`. EOF at the map
boundary remains normal termination; the focused line fault-injection
regression covers the distinction, while compiled mail corpus, sanitizer, and
Sonic1 qualification remain release gates.

## InstallShield MSI file-record read classification — 2026-08-23

MSI embedded-file records now distinguish a genuinely short fixed record
(`CL_EPARSE`) from a fully in-range fmap callback failure (`CL_EREAD`).
Focused MSI coverage exercises both outcomes; compiled InstallShield corpus,
sanitizer, and Sonic1 qualification remain release gates.

## PE header ingress read classification — 2026-08-23

PE header admission now uses one bounded read-classification helper for the
DOS/NT headers, optional-header extensions, data directories, and section
headers. An in-range fmap callback failure returns `CL_EREAD` with an explicit
incomplete reason, so embedded PE candidates cannot discard an operational
read fault as “not actually PE”; genuinely short ranges retain their existing
candidate or parse status. A focused DOS-signature callback regression covers
the boundary. Compiled PE corpus, sanitizer, and Sonic1 qualification remain
release gates.

## PE heuristic window read classification — 2026-08-23

The enabled Magistr and Polipos heuristics now classify failures from their
required tail, code-section, and jump-target fmap windows. In-range callback
failures return `CL_EREAD`; invalid or out-of-map coordinates return `CL_EPARSE`;
both mark the layer incomplete and non-cacheable before PE-specific inspection
is abandoned. Focused Magistr and Polipos code-section fault injection is
registered; compiled PE corpus, sanitizer, Polipos jump-target coverage, and
Sonic1 qualification remain release gates.

## TAR end-of-archive classification — 2026-08-23

TAR traversal now requires two complete zero blocks for end-of-archive
termination. Exact EOF after a member, a single zero block, a malformed marker,
or a partial marker returns `CL_EPARSE`, marks the layer incomplete, and
prevents caching a clean result; callback failures while reading a marker
remain `CL_EREAD`. Focused coverage exercises missing, single-block, and valid
termination, while compiled TAR corpus, sanitizer, and Sonic1 qualification
remain release gates.

## NsPack bitched-entry read classification — 2026-08-23

The confirmed bitched NsPack entry-metadata window now distinguishes an
in-range fmap callback failure (`CL_EREAD`) from an out-of-map coordinate
(`CL_EPARSE`) and stops PE-specific inspection before the result can look clean.
The focused NsPack callback regression covers this boundary, while compiled PE
corpus, sanitizer, and Sonic1 qualification remain release gates.

## PE initial icon-group read classification — 2026-08-23

The initial PE icon-group header now distinguishes an in-range fmap callback
failure (`CL_EREAD`) from an out-of-map coordinate (`CL_EPARSE`) before icon
traversal can fall through as clean. The existing focused icon-group callback
regression covers the corrected branch, while compiled icon corpus, sanitizer,
and Sonic1 qualification remain release gates.

## ISO volume-descriptor terminator classification — 2026-08-23

ISO volume traversal now requires a complete `0xFF/CD001` terminator after the
primary/secondary descriptor sequence. Missing, malformed, or out-of-map
termination returns `CL_EPARSE`; an in-range fmap callback failure remains
`CL_EREAD`, and the root directory is not scanned after an incomplete
descriptor walk. Focused missing-terminator coverage is registered, while
compiled ISO/Joliet corpus, sanitizer, and Sonic1 qualification remain release
gates.

## Rust decoder-spool interrupted writes — 2026-08-23

The shared Rust temporary spool now retries `EINTR` from `write()` instead of
turning a signal interruption into a false `CL_EWRITE`. Zero-byte writes and
other write failures remain explicit incomplete output, and reservation
rollback/cleanup behavior is unchanged. This protects LHA/LZH, ALZ, and
OneNote materialization; compiled fault injection, sanitizer, and parser-family
qualification remain release gates.

## Shared zero-byte temporary-output writes — 2026-08-23

The shared `cli_writen()` helper now treats a successful zero-byte `write()`
as incomplete progress and returns the completed prefix instead of looping
forever. Existing exact-length checks therefore fail closed for parser spools
and normalized output; `cli_filecopy()` also propagates source-read,
short/zero-byte-write, and close failures instead of publishing a truncated
copy as successful. Compiled zero-progress fault injection, sanitizer, and
Sonic1 qualification remain release gates.

## clamd INSTREAM zero-progress staging — 2026-08-23

The active clamd INSTREAM receive path now requires `cli_writen()` to return
the exact chunk length. A zero-byte or short temporary-file write therefore
cannot be acknowledged as a successful chunk and later scanned as a complete
file; the request is reported as a write failure and cleaned up instead.
Compiled daemon fault injection, sanitizer, and Sonic1 qualification remain
release gates.

## clamd response send progress — 2026-08-23

`mdprintf()` now sends only the unsent response suffix after a partial socket
write, retries `EINTR`, waits for both nonblocking errno variants, and rejects
zero-byte progress. This prevents duplicate or out-of-bounds response bytes
and prevents a stalled clamd response from being reported as successful.
Compiled protocol fault injection, sanitizer, and Sonic1 qualification remain
release gates.

## BinHex temporary fork short-write and rewind disposition — 2026-08-23

The BinHex data and resource fork staging paths returned `CL_EWRITE` after a
short or zero-progress temporary write without setting the sticky incomplete
state. Rewind failures before nested handoff likewise returned `CL_ESEEK`
without recording that required child inspection had been skipped. Both output
paths now record explicit incomplete reasons before returning these failures,
preserving the non-cacheable, fail-closed result. Compiled write/seek fault
injection, sanitizer, and Sonic1 qualification remain open.

## HFS+ compressed-resource handoff failures — 2026-08-23

HFS+ compressed-resource processing now records specific sticky-incomplete
reasons for resource-map/index/data seeks, block reads, decoder
initialization/finalization, compressed metadata validation, fork writes, and
inline compressed output failures. These operations are required to materialize
and inspect the compressed child; preserving the reason prevents parser status
reconciliation from exposing a clean result after a partial handoff. Static
source guards pass; compiled HFS+ fault injection, sanitizer, corpus, and
supported-build Sonic1 qualification remain release gates.

## HFS+ metadata and node format failures — 2026-08-23

HFS+ tree-header, catalog, attribute-tree, extent, and node-coordinate
validation failures now record parser-specific sticky-incomplete reasons
before returning, including unsupported ExtentOverflow node lookup. Catalog
fork geometry failures are also fail-visible, and the null-context entry path
now returns without dereferencing an invalid context. Static source guards
pass; compiled malformed-volume and allocation fault injection, sanitizer,
corpus, and supported-build Sonic1 qualification remain release gates.

## OLE2 property-tree admission failures — 2026-08-23

OLE2 property-tree recursion/file/worklist limits, JSON timeout, scan-size
admission, invalid header magic, first-data-block geometry, and property or
extracted-file tracking allocation failures now mark required inspection
incomplete before returning. Static source guards pass; compiled OLE2
limit/allocation fault injection, sanitizer, corpus, and supported-build
Sonic1 qualification remain release gates.

## ELF section metadata allocation failures — 2026-08-23

ELF32 and ELF64 section parsing now marks native section-metadata array
allocation failures incomplete before returning `CL_EMEM`, preventing a
required section inspection from being reconciled as clean. Static source
guards pass; compiled ELF allocation fault injection, sanitizer, corpus, and
supported-build Sonic1 qualification remain release gates.

## XAR unsupported member encodings — 2026-08-23

An explicit XAR member encoding with an unknown media type, or with no
`style`, is now treated as unsupported rather than as raw uncompressed data.
The parser returns `CL_EUNPACK`, marks the layer incomplete, and prevents a
clean cache result without decoded-member inspection. Missing `<encoding>`
continues to represent an uncompressed member, and recognized gzip, bzip2,
LZMA, XZ, and octet-stream styles are unchanged. Focused source guards and a
unit regression are present; compiled XAR corpus, sanitizer, and Sonic1
qualification remain release gates.

## GPT primary-table validation fallback — 2026-08-23

GPT primary/secondary header selection now distinguishes malformed format data
from operational validation failures. A callback read failure or deadline
crossing while checking a partition table is no longer treated as a malformed
primary header that can be hidden by a successful secondary-only scan; only
`CL_EFORMAT` uses the documented redundancy fallback. The resulting GPT layer
remains incomplete and non-cacheable. Focused callback-fault coverage is
present; compiled GPT media, sanitizer, and Sonic1 qualification remain
release gates.

## HFS+ declared tree-header boundary — 2026-08-23

HFS+ tree-header coordinates are now bounded by the volume header's declared
`totalBlocks` before fmap admission. This prevents a header at the exact
declared volume end from consuming appended mapped bytes as a valid tree.
Compiled HFS+ corpus, sanitizer, and Sonic1 qualification remain open.

## APM declared partition-map boundary — 2026-08-23

APM entry reads now remain within the partition map's declared
`pBlockStart/pBlockCount` extent, including the optional partition-intersection
walk. Appended mapped bytes can no longer become partition metadata merely
because they are readable. Compiled APM corpus, sanitizer, and Sonic1
qualification remain open.


## Embedded matcher-offset range admission — 2026-08-23

Raw embedded-type dispatch now rejects negative or out-of-map matcher offsets before child-range subtraction or nested parser handoff. This prevents malformed internal coordinates from wrapping into a child fmap or being treated as a confirmed layer, and prevents a later type-parser pass from restoring a clean status. Compiled embedded-candidate and production-SFX qualification remain open.

## TAR GNU base-256 size admission — 2026-08-23

TAR size fields now accept checked positive GNU base-256 values in addition to
legacy ASCII octal. This preserves valid member sizes beyond the legacy octal
range and bounded PAX decimal `size=` overrides while rejecting negative or
overflowing encodings before temporary admission. Focused valid POSIX TAR
regressions cover both encodings and complete end markers. Malformed/oversized
PAX records, compiled TAR corpus, sanitizer, and supported-build Sonic1
qualification remain release gates.

## TIFF BigTIFF unsupported classification — 2026-08-23

The TIFF parser now distinguishes classic TIFF from BigTIFF magic. BigTIFF's
64-bit IFD layout is not implemented, so recognized `II+\0` and `MM\0+` inputs
return an explicit unsupported/incomplete result instead of falling through as
clean. Focused direct-parser coverage is present; compiled media corpus,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## clamd path-walk status propagation — 2026-08-23

The daemon path/directory command now preserves a non-success result returned
by `cli_ftw()` when traversal fails before `scan_callback()` can increment the
per-request error counter. Structured requests also retain that status for the
final report, preventing a traversal failure from becoming a clean result with
no scanned object. Static source guards pass; compiled daemon fault injection,
protocol, sanitizer, and Sonic1 qualification remain release gates.

## clamd infected-file aggregate accounting — 2026-08-23

`ALLMATCHES` callback delivery can report several signatures for one file, but
the daemon summary needs one infected-file count. A separate counter now keeps
summary arithmetic independent from per-signature callback telemetry, avoiding
underflow for multi-detection files while preserving each detection response.
Compiled multi-match, protocol, sanitizer, and Sonic1 qualification remain
release gates.

## HWP3 embedded-item status aggregation — 2026-08-23

The HWP3 information-block loop now merges each hyperlink/media nested-scan
status instead of replacing the prior result. An earlier detection or parser
failure therefore cannot be hidden by a later clean item in the same block;
the existing raw and later-item scanning behavior remains intact. Compiled
HWP3 nested-detection coverage, sanitizer, and supported-build Sonic1
qualification remain release gates.

## Raw embedded-dispatch status aggregation — 2026-08-23

`scanraw()` can dispatch several recognized embedded parsers, SFX layers,
partitions, or type-retyped views during one raw pass. Every child result now
uses shared status precedence when updating the aggregate, so a later clean
candidate cannot hide an earlier detection or parser/resource failure. Weak
candidate rejection remains unchanged. Compiled multi-candidate coverage,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## OLE2 XLM/BIFF completion checks — 2026-08-23

OLE2 XLM/image inspection now rejects a property block chain that ends before
the declared stream length and a BIFF record that ends mid-header or payload.
Both cases remain explicit incomplete/non-cacheable results instead of clean
OLE2 scans. Compiled truncation corpus, sanitizer, and supported-build Sonic1
qualification remain release gates.

## XAR TOC root-completion check — 2026-08-23

XAR TOC traversal now distinguishes a properly observed closing `</xar>` from
XML EOF after the last complete entry. Missing the root close is an explicit
incomplete/non-cacheable result instead of a normal end-of-TOC condition. A
focused missing-root-close regression is registered; compiled XAR corpus,
sanitizer, and supported-build Sonic1 qualification remain release gates.

## RTF long-description state accounting — 2026-08-23

RTF object descriptions now consume their full declared byte count across fmap
chunks while retaining only the bounded 64-byte display prefix. The reserved
field and payload-size state can no longer be misparsed when a description is
longer than the display cap. A focused chunk-boundary regression is registered;
compiled RTF/OLE corpus, sanitizer, and supported-build Sonic1 qualification
remain release gates.

## JPEG missing-map admission — 2026-08-23

The JPEG parser now checks for an input fmap before its bounded header reader
is used. A direct caller with no map receives an explicit incomplete parse
instead of an invalid dereference. A focused direct-entry regression is
registered; compiled media corpus, sanitizer, and supported-build Sonic1
qualification remain release gates.

## HTML normalized-view matcher-work accounting — 2026-08-23

Required HTML normalized children are scanned as file-backed normalized maps,
so their bytes contribute to the shared `MaxMatcherWork` budget instead of
being treated as free parser output. A compiled `cl_scanmap_ex2` regression
loads a non-matching signature to force the root raw pass and verifies through
the structured report that matcher bytes exceed the root size after the
normalized views are scanned. Full HTML corpus, sanitizer, and supported-build
Sonic1 qualification remain release gates.

## Script normalized-view matcher-work accounting — 2026-08-23

Script normalization retains its generated representation in a file-backed
fmap and sends that normalized view through the regular matcher path. A
compiled `cl_scanmap_ex2` regression loads a non-matching signature to force
the root raw pass and verifies through the structured report that matcher
bytes exceed the root size after the normalized script is scanned. Full script
corpus, sanitizer, and supported-build Sonic1 qualification remain release
gates.

## Encoded-text script normalization — 2026-08-24

`CL_TYPE_TEXT_UTF16LE` and `CL_TYPE_TEXT_UTF16BE` no longer feed interleaved
code-unit bytes directly into the byte-oriented script normalizer. They are
decoded incrementally to UTF-8 through a fixed 4 KiB input window and bounded
output window before the existing quota-accounted, file-backed normalized
matcher pass. BOM handling is explicit, surrogate pairs may cross windows,
and odd lengths, reversed byte order, lone surrogates, or incomplete pairs
remain incomplete and non-cacheable.

`CL_TYPE_TEXT_UTF8` is now validated across fmap windows before normalization;
invalid continuation bytes, overlong forms, surrogate values, truncated final
sequences, and values above U+10FFFF remain explicit incomplete results rather
than bytes silently discarded by the ASCII-oriented normalizer. The focused
Linux ARM64 GCC case passes UTF-16LE, UTF-16BE, and UTF-8 normalized-signature
detection, a surrogate pair split at the 4 KiB boundary, and malformed
UTF-16/UTF-8 fail-visible oracles. Full text corpora, ASan/UBSan, Linux x86-64,
and Sonic1 qualification remain open.

## AutoIt EA06 bounded decompiled-output spool — 2026-08-23

EA06 script decompilation no longer grows a contiguous output allocation. The
file-backed decoded token stream is read through bounded `pread` windows and
the reconstructed script is emitted sequentially through one 64 KiB pending
window into a quota-accounted temporary spool. A native-width output counter
checks file and scan limits before each append; every flush checks the shared
deadline and temporary budget before writing. The decoded-input reservation
remains live while output is produced, so their real overlap is charged, and
the output reservation remains live through the nested scan.

The deterministic EA06 fixture now reconstructs exactly 65,557 bytes, forcing
a full 64 KiB flush plus a second flush. The fixture generator's LAME byte
stream was corrected to perform the same two state transitions as the C
decoder. A harness including the production parser verified the exact output,
one nested scan, a 196,673-byte temporary peak (131,116-byte token spool plus
65,557-byte script spool), and zero reservation leakage; normal and
ASan/UBSan executions passed. The focused writer harness also verifies exact
output and one-byte-short file and temporary-budget failures. The former
`autoit-ea06-script-over-1g` exception is removed; compiled corpus and
supported-build Sonic1 qualification remain release gates.

## EGG oversized extra-field bounded traversal — 2026-08-23

EGG no longer rejects every archive or file extra field above the 1 GiB
individual-allocation ceiling. Each declared payload span is first validated
against the containing fmap without requesting it as one mapping. Dummy,
solid, split, unknown, and other skippable fields advance directly across the
validated span. Windows/POSIX metadata reads only its fixed structure, and
encryption metadata selects a bounded method-specific prefix of at most 29
bytes while preserving the format's header-inclusive size accounting.

The index parser also replaced its unaligned 16/32-bit pointer loads with
ClamAV's safe little-endian readers. A sparse logical-map regression covers
archive and file dummy fields, AES metadata, and Windows metadata with payloads
more than 1 GiB without allocating the holes; its largest contiguous request
is 21 bytes. The same production paths pass normal and ASan/UBSan harnesses.
The former broad `egg-extra-field-over-1g` exception was initially narrowed to
the string fields. Scanner-aware filename/comment indexing now closes that
remaining parser boundary as described in the 2026-08-24 follow-up below;
only the legacy contiguous-string API retains its compatibility ceiling.

## Bounded BigTIFF IFD traversal — 2026-08-23

BigTIFF is now structurally inspected rather than classified as unsupported.
Both byte orders use the specified 16-byte header, 64-bit IFD counts and links,
fixed 20-byte entries, and LONG8/SLONG8/IFD8 field widths. The walker retains
only one entry, validates count multiplication and every external value range,
and preserves native 64-bit coordinates above 4 GiB. It never maps an external
value payload merely to validate the directory.

Malformed header extensions, truncated structures, unsupported field types,
out-of-range or host-unrepresentable coordinates, backing-read failures, and
deadline expiry remain explicit incomplete results. Focused little-/big-endian,
fault-injection, malformed-layout, and sparse-above-4-GiB tests are present;
compiled TIFF corpus and Sonic1 qualification remain release gates. All nine
TIFF files in libtiff's archived BigTIFF sample bundle also pass the production
parser normally and under ASan/UBSan; the 9,497-byte bundle SHA-256 is
`aa2960126b3904732742e674ac16d06c219c7c359898cfd5eb0af5822b598090`.
The layout follows the
[libtiff BigTIFF design](https://libtiff.gitlab.io/libtiff/specification/bigtiff.html).

The release runtime gate now creates a deterministic sparse BigTIFF with its
first IFD at 4,294,967,312, an external LONG8 value at 4,294,967,352, and a
logical size of 4,294,967,368 bytes. Its SHA-256 is
`06b8d598efcbad2fe8cbaedb41c74ef3dcf442825f781cb919eace3ff3f85c1d`.
Release and sanitizer scans must report entry into the BigTIFF parser, the
exact above-4-GiB IFD coordinate, and completion of one IFD without an
unsupported diagnostic. The post-run evidence checker independently binds the
generator output, file type, size, hash, and parser logs; its acceptance and
rejection controls pass locally. Sonic1 must still produce the bound release
and sanitizer evidence, and the complete compiled TIFF corpus must pass,
before BigTIFF is considered qualified.

## PDF single-Flate bounded streaming — 2026-08-23

Ordinary unencrypted PDF streams with exactly one `FlateDecode` filter no
longer enter the legacy whole-input/whole-output decoder token. The decoder
feeds zlib through 64 KiB native-width input windows and writes through one
fixed 256 KiB output window. Every emitted prefix is checked against the
shared file/scan deadline and limits, then reserved against
`MaxTemporarySize` before an exact write.

The output transaction records the child-file position and temporary
reservation before decoding. Malformed input, truncation, timeout, resource,
or write failure truncates and rewinds the child and releases only that
attempt's reservation. Parse failures then preserve the established raw-stream
fallback without leaving decoded-prefix bytes ahead of it. Focused regressions
cover multi-window exact output, one-byte-short temporary admission with zero
leakage, malformed-prefix rollback, and native-width source admission above
`UINT32_MAX`.

Object streams still retain decoded bytes for object parsing, and encrypted
streams retain their explicit legacy contiguous/width boundary. Supported
ordinary filter chains now use the file-backed path described below. Compiled
PDF corpus, sanitizer, materialized large-stream, and supported-build Sonic1
qualification remain release gates.

The isolated Linux GCC translation-unit check also exposed an older unmatched
`_WIN32` guard and late callback declarations in `check_clamav.c`. The guard is
now closed at the end of its HTML-only block, shared callback state/prototypes
are visible before first use, and the source guard rejects future unbalanced
preprocessor conditionals. Sonic1 was not mutated: a fresh read-only status
probe timed out during SSH Connect with `remote_started=false`.

An isolated production-code harness linked the real `pdf_decodestream()` and
passed all four streaming cases under ordinary GCC and GCC
AddressSanitizer/UBSan with leak detection: multi-window exact output,
one-byte-short quota rollback, truncated-stream raw fallback, and native-width
input admission. Full parser/corpus sanitizer qualification remains pending.

## PDF single-RunLength bounded streaming — 2026-08-23

Ordinary unencrypted PDF streams with exactly one `RunLengthDecode` filter now
bypass the legacy whole-buffer token. The native-width packet walker checks the
shared deadline at least every 64 KiB of encoded input, accumulates decoded
packets in one fixed 256 KiB window, and checks logical and temporary limits
before each exact output write. End markers and complete marker-less packet
sequences preserve the legacy decoder semantics, while data after an observed
marker is ignored.

Malformed packets, timeout, output-limit, quota, seek, and write failures use
the same output-position and temporary-reservation transaction as streamed
Flate. A failure removes every decoded prefix before the established raw-stream
fallback runs. Focused tests cover exact output across multiple output windows,
one-byte-short quota rollback with zero leakage, malformed input after a valid
prefix, and a native-width logical input above `UINT32_MAX` that terminates at
an early marker. The production-code harness passes all eight Flate and
RunLength cases under ordinary GCC and GCC AddressSanitizer/UBSan with leak
detection. Object streams and encryption remain explicit PDF qualification
gaps.

## PDF single-ASCII filter bounded streaming — 2026-08-23

Ordinary unencrypted single-filter `ASCIIHexDecode` and `ASCII85Decode` streams
now use the shared fixed-window output transaction instead of allocating a
token proportional to encoded input. Both native-width walkers check the
deadline at 64 KiB input intervals and flush through one 256 KiB buffer with
scan-limit and temporary-quota admission.

ASCIIHex accepts all PDF whitespace, pads an odd final nibble with zero, and
ignores data after `>`. ASCII85 retains the established marker-less behavior,
supports whitespace and `z` groups, validates `z` placement and one-character
final groups, rejects full or partial groups whose numeric value exceeds the
32-bit ASCII85 tuple, completes two- through four-character groups at `~>`, and
ignores post-marker data. Invalid input after a written decoded prefix rolls
back the file and reservations before exact raw fallback.

Focused tests cover exact output beyond one window, odd nibbles, known ASCII85
vectors, zero groups, partial groups, whitespace, post-marker bytes,
one-byte-short quotas, invalid and overflowing groups after valid output, and
native-width logical lengths above `UINT32_MAX` with early terminators. The
production harness passes all 20 Flate, RunLength, ASCIIHex, and ASCII85 cases
normally and under GCC AddressSanitizer/UBSan with leak detection. Object
streams, encryption, and chains containing unsupported filters remain the
explicit token-backed PDF gaps.

## PDF single-LZW bounded streaming — 2026-08-23

Ordinary unencrypted single-filter `LZWDecode` streams now preserve the
decoder's fixed dictionary and bit state across 64 KiB native-width input
windows, rather than narrowing the complete input into its unsigned legacy
field. Decoded bytes use the shared 256 KiB transactional output window with
deadline, scan-limit, and temporary-quota admission before exact writes.

Both defined `EarlyChange` modes are parsed strictly and exercised across the
9-to-10-bit code-width boundary. Missing, non-scalar, non-numeric, and
out-of-range values are fail-visible, and predictor values other than the
identity default are explicitly unsupported instead of silently treated as
decoded. Disabled LZW support, missing EOI codes, invalid dictionary input,
limits, and I/O failures remain incomplete and non-cacheable. The legacy
filter-chain decoder now destroys state only after successful initialization.

Focused regressions cover exact output beyond one output window and multiple
input windows, one-byte-short quota rollback, truncation after a written
prefix with exact raw replacement, `EarlyChange` zero, malformed and
unsupported parameters, and an early EOI under a logical input length above
`UINT32_MAX`. The real production harness passes all 26 streamed-filter cases
normally and under GCC AddressSanitizer/UBSan with leak detection. Later
milestones address encrypted streams, object streams, and per-filter
DecodeParms arrays. Compiled corpus, materialized large-stream, and Sonic1
qualification remain open.

## PDF predictor fail-closed admission — 2026-08-23

Flate and LZW DecodeParms now accept only the identity predictor value `1`.
Missing, non-scalar, non-numeric, and non-identity values return an explicit
incomplete parse result before decoder output starts; the ordinary
single-filter path then writes the exact encoded stream for raw matching.
This replaces the previous silent acceptance of predictor-transformed bytes as
if they were fully decoded. The same check protects bounded and residual legacy
filter-chain paths.

Focused tests prove identity-Flate output and exact raw fallback for TIFF/PNG
predictors and malformed parameter forms. The real production harness passes
all 27 streamed-filter cases normally and under GCC AddressSanitizer/UBSan with
leak detection. Predictor reversal remains deliberately unsupported; the
release contract is fail-closed rather than a false complete scan.

## PDF bounded filter-chain spools — 2026-08-23

Ordinary unencrypted chains composed entirely of `ASCIIHexDecode`,
`ASCII85Decode`, `RunLengthDecode`, `FlateDecode`, and `LZWDecode` now bypass
the legacy contiguous token. Every decoder consumes the same native-width
reader: original memory is exposed in at most 64 KiB windows, while completed
intermediate output is reopened through an fmap-backed 64 KiB file window.
Each decoder retains only its fixed state and 256 KiB transactional output
buffer.

Intermediate files are created beneath the scan layer's temporary directory
and charged incrementally to `MaxTemporarySize`. A completed input spool stays
reserved for the entire next decode, so input and output overlap is counted at
the actual peak. It is released only after that next filter completes. A
decoder, mapping, read, size-verification, close, unlink, quota, deadline, or
write failure destroys every stage, truncates and rewinds the final child to
its pre-chain offset, restores the exact temporary-accounting baseline, and
then permits raw fallback only for the established parse/break classes.

Committed regressions cover exact multi-window ASCIIHex-to-Flate output,
simultaneous input/output quota failure with no file or reservation residue,
second-stage truncation with exact raw replacement, three-stage spool rotation,
and native-width logical input above `UINT32_MAX`. The linked production
harness additionally exercises every supported decoder as an intermediate
writer and file-backed reader, validates a three-stage peak, injects an
intermediate fmap read failure, verifies a non-fallback `CL_EREAD`, and proves
that post-decode cleanup failures also roll back final output and cannot be
hidden by a zero-output `CL_BREAK`. Its injectable bounded-fmap variant passes
all 37 cases normally and under GCC AddressSanitizer/UBSan with leak detection.
A second variant links the actual production `fmap.c`; all 36 applicable cases
also pass normally and under the same sanitizers. Encrypted object streams,
unsupported or mixed filter chains, compiled
PDF corpus, materialized multi-gigabyte chains, and Sonic1 release/sanitizer
qualification remain open.

## PDF file-backed object streams — 2026-08-23

On mmap-capable builds, ordinary unencrypted object streams with no filter or
only the supported native-width filters no longer transfer a decoded heap
token into the object parser. Decoding writes the quota-accounted extracted
child, verifies its regular-file type and exact size, maps it read-only, and
transfers exactly that file's temporary reservation into the retained
object-stream owner. The extracted-file descriptor can then close and its
directory entry can be removed while the mapping and its storage charge remain
live until every embedded object has been parsed and extracted.

Malformed streams retain their mapping whenever already-created objects refer
to its offsets. Their parse status is preserved and returned by the containing
object extraction instead of freeing the backing or reporting a complete
result. Failed decode or attachment before any backing exists discards only
the new owner without reallocating or losing prior object-stream owners.
`MADV_SEQUENTIAL` limits read-ahead behavior, and parsed/extracted object ranges
are released with `MADV_DONTNEED`; final teardown unmaps before releasing the
retained temporary reservation.

Six regressions bind raw and Flate-backed streams, exact quota ownership and
cleanup, malformed backing retained behind a valid first object,
containing-object error propagation, one-byte-short quota rejection, and a
supported filter route whose logical source length exceeds `UINT32_MAX`. The
production mapping/index/cleanup harness passes 2/2 normally and under GCC
AddressSanitizer/UBSan with leak detection. The integrated decoder harness now
passes 39/39 with its injectable bounded fmap and 38/38 with production
`fmap.c`, both normally and under the same sanitizers. Mmap and non-mmap source
configurations plus the complete unit-test translation unit pass GCC syntax
compilation; only pre-existing isolated-build warnings remain.

Unsupported/mixed filters, materialized multi-gigabyte encrypted fixtures,
broader malformed encryption dictionaries, and Sonic1 release/sanitizer
qualification remain open. Per-filter DecodeParms arrays are addressed by the
later 2026-08-24 milestone.

The certified 32 GiB Linux x86-64 profile now explicitly requires private
file-backed mapping support (`HAVE_MMAP` plus `HAVE_SYS_MMAN_H`). `clamd`
advertises that capability in its startup manifest and refuses any configured
large-file envelope when it is absent. Historical-size configurations retain
their existing startup behavior, and non-mmap builds remain supported only
outside the certified profile: their bounded 64 MiB PDF fallback and explicit
incomplete/resource results are not promoted into a 32 GiB claim. The build-
profile helper has exact unit oracles for missing large-file support, platform,
file-backed mapping, and FILDES support. This resolves the non-mmap release
policy; it does not qualify non-mmap PDF object streams.

The deterministic `largefile_pdf_objstm_fixture.py` generator now emits
structurally valid PDF 1.7 files with a cross-reference stream and compressed-
object entry. Raw, Flate, ASCIIHex-to-Flate, and malformed-after-one-valid-
object forms are self-verified, and the raw form can stream an exact decoded
size without sparse seeks. Complete empty-password Standard R2/RC4, Standard
R4/AESV2, and deprecated compatibility-only Standard R5/AESV3 documents cover
each supported filter form. Deterministic nonempty-password variants cover the
same security handlers as explicit unsupported/no-plaintext cases. Three
deterministic AESV2 faults cover an unknown crypt-filter method, a physically
truncated ciphertext body, and invalid PKCS#7 padding. AES generation
uses an existing OpenSSL executable when available while a pure-Python NIST-
vector-tested implementation remains the independent oracle and fallback.
`largefile_pdf_objstm_qualification.sh` binds each
fixture by size and hash, rejects holes in the materialized case, requires
production parser plus map/cleanup diagnostics, checks exact marker detection
and malformed-status visibility, records RSS/page-fault/I/O evidence, and
rejects leaked temporary files. Every case now binds a versioned JSON report;
password cases require `UNSUPPORTED`, a non-clean status, a skipped operation,
no `OK`, and no plaintext marker. The unknown crypt filter requires the same
fail-closed `UNSUPPORTED` class without entering bounded AES, while truncated
ciphertext and bad padding require `MALFORMED_CONFIRMED`, bounded-AES evidence,
their exact reason, no plaintext result, and no residue. The generator self-test
passes 31 cases;
Poppler independently accepts the RC4, AESV2, and AESV3 raw, Flate, and filter-chain
documents as one-page encrypted PDF 1.7 files with JavaScript, and the Linux
x86-64 orchestrator self-test passes all 20 scanner cases with a fully
allocated 64 MiB child. That orchestrator uses a deterministic scanner/time
stub and is not production scan evidence. Production scanner, sanitizer,
multi-gigabyte materialized, and Sonic1 runs are still required before changing
the capability status.

The gate also records a full source manifest, commit/tree state, a copied
Linux x86-64 ELF scanner, its version and resolved runtime dependencies, the
OpenSSL accelerator version, a per-file database manifest, the exact custom
signature, tool hashes, fixture/log/report hashes, peak temporary usage, and
normalized resource results. The
companion evidence checker rejects dirty release sources by default and
revalidates every binding, exact case oracle, resource ceiling, malformed-
status distinction, allocation proof, and empty temporary directory. Its
self-test proves that a modified scanner log is rejected.

## PDF per-filter DecodeParms arrays — 2026-08-24

The PDF parser now accepts either the historical direct DecodeParms dictionary
or an array aligned one-for-one with the declared filter array. Array entries
must be dictionaries or the exact scalar `null`; each filter receives only its
corresponding dictionary in streamed, encrypted, and residual legacy paths.
Short arrays, extra entries, other scalars, and malformed parser values fail
before decoder output, mark the layer incomplete, and prevent clean caching.

Focused Linux ARM64 GCC evidence passes 2/2 cases. It proves that a predictor
dictionary in the ASCIIHex position is not reused by Flate, moving it to the
Flate position fails visibly with exact raw fallback, malformed array shapes
produce zero output and zero retained temporary accounting, and parser syntax
for `/DecodeParms`, `/DP`, and an invalid scalar reaches the same policy.
Direct GCC compilation passes for `pdf.c`, `pdfdecode.c`, and the complete
`check_clamav.c` translation unit; only previously recorded isolated-build
warnings remain. This is implementation evidence, not certified Linux x86-64
release evidence. Production/sanitizer corpus runs, broader malformed
dictionaries, materialized multi-gigabyte chains, quota/read/write/cleanup
faults, unsupported/mixed filters, and Sonic1 qualification remain open.

## PDF explicit Crypt filter ordering — 2026-08-24

Exactly one explicit Crypt filter may now appear at any position in a supported
filter chain. The shared quota-accounted stage rotation dispatches that stage
to the bounded Identity, RC4, AESV2, or AESV3 reader and supplies only its
corresponding DecodeParms dictionary. Intermediate input remains reserved while
the Crypt or next output stage is produced, and failures retain transactional
rollback plus exact raw fallback. A repeated Crypt stage or any other
unsupported filter keeps the chain explicitly incomplete.

Focused Linux ARM64 GCC evidence passes 1/1. The regression proves exact output
and expected temporary peaks for Crypt-to-ASCIIHex and ASCIIHex-to-Crypt
Identity ordering, then proves `CL_EPARSE`, incomplete/non-cacheable state,
exact encoded fallback, and bounded reservation cleanup for a two-Crypt chain.
`pdfdecode.c` and the full `check_clamav.c` translation unit compile directly
with GCC; only the previously recorded isolated unit warning remains.

A second focused Linux ARM64 GCC case passes 1/1 with 40 internal oracles.
RC4, AESV2, and AESV3 each produce exact output with Crypt before and after
Flate, RunLength, ASCIIHex, ASCII85, and LZW. For every surrounding filter, a
one-byte-short RC4 temporary peak returns `CL_ERESOURCE` with zero output and
residue, while malformed AES padding returns `CL_EPARSE` after restoring the
exact filter-encoded raw input. The same 40-oracle case passes with the touched
PDF production objects under GCC AddressSanitizer/UBSan and leak detection.
The arbitrary-input LZW encoder is also used by the established LZW fixtures;
their six focused stream, quota, truncation, `EarlyChange`, parameter, and
native-width cases pass normally and under the same sanitizer configuration.

Production PDF corpora, broader malformed crypt dictionaries,
production/sanitizer runs, materialized multi-
gigabyte stages, fault injection, and Sonic1 release evidence remain open.

## PDF exact DecodeParms dictionary selection — 2026-08-24

Stream extraction no longer searches for `/DecodeParms` or `/DP` as raw
substrings. It parses the complete root stream dictionary under the existing
deadline, uses the parser's decoded PDF names, and selects only exact root
nodes. Text in literal strings, comments, nested dictionaries, and longer names
such as `/DecodeParmsExtra` cannot supply filter parameters. The long form
retains precedence over `/DP`; duplicate exact long-form keys, duplicate short-
form keys when no long form exists, malformed name escapes, malformed nested
values, and scalar parameter values remain explicit parse-incomplete and
non-cacheable results.

Dictionary and array boundary traversal now ignores comments and balances
nested literal parentheses while respecting escapes. Comments are also skipped
between dictionary keys and values and between array entries. A failed nested
dictionary, array, or string parse can no longer leave an uninitialized cursor
or silently produce a usable partial DecodeParms node. Dictionary/array
container, key, value, and node allocation failures now set sticky incomplete
state and return failure instead of exposing a partial parse tree.

Focused Linux ARM64 GCC evidence passes 3/3. The exact-selection case contains
ten internal oracles covering nested literal and dictionary decoys, comments
containing `>>` and apparent keys, longer names, a hex-escaped valid key, long-
form precedence, a malformed array and malformed preceding value, an invalid
name escape, a duplicate exact key, and a dictionary containing only decoys.
The earlier explicit Identity
Crypt ordering and RC4/AES ordering cases each pass 1/1 after relinking against
these exact parser objects. Direct GCC compilation passes for `pdf.c`,
`pdfng.c`, and the complete `check_clamav.c` translation unit; the unit TU emits
only its previously recorded ISO fixture warning. The same three focused
binaries pass with `pdf.c`, `pdfng.c`, and `pdfdecode.c` instrumented by GCC
AddressSanitizer/UBSan with leak detection. Full production/sanitizer corpus
execution, allocation/read fault injection, materialized multi-gigabyte streams,
and Sonic1 release evidence remain open.

## PDF exact crypt-filter dictionary selection — 2026-08-24

Crypt-filter method selection no longer searches `/CF` with raw substrings or
accepts method prefixes. The bounded `/CF` span is parsed as a complete PDF
dictionary. Selection requires one exact decoded filter-name node, a dictionary
value, and one exact name-valued `/CFM`. PDF name hex escapes are compared
without allocating or reading beyond the two escaped hex digits. Duplicate
filter names or `/CFM` keys, longer-name collisions, scalar values, missing or
unknown methods, malformed/truncated dictionaries, and partial fragments all
resolve to `ENC_UNKNOWN`; the existing decrypt path consequently reports the
layer incomplete instead of treating it as Identity or a supported cipher.

The shared dictionary parser also now accepts a valid dictionary whose closing
`>>` occupies the final two bytes of its bounded span. This exact-end case was
previously rejected because the final-boundary check used `>=` rather than
`>`. The change remains bounded and does not admit a missing closing delimiter.

Focused Linux ARM64 GCC evidence passes 1/1 with 23 internal oracles covering
RC4, AESV2, AESV3, `None`, `Identity`, missing-name defaults, PDF-name escapes,
comments around dictionaries and `/CFM` values, nested decoys, longer keys,
duplicate keys, scalar entries,
missing/duplicate/scalar `/CFM`, supported-method prefixes, unknown methods,
truncation, a bare fragment, an invalid non-dictionary entry, and absent input.
The case passes normally and with the touched `pdf.c`, `pdfng.c`, and
`pdfdecode.c` objects under GCC AddressSanitizer/UBSan with leak detection. The
existing 40-oracle Crypt/filter matrix, three-case DecodeParms parser suite,
and explicit Identity ordering case also pass in normal and sanitizer modes
against the hardened objects. Full Standard encryption-dictionary corpus
mutations, allocation/read fault injection, production scanner execution,
materialized multi-gigabyte encrypted streams, and Sonic1 evidence remain open.

## PDF exact Crypt DecodeParms semantics — 2026-08-24

An explicit Crypt stage now treats `/Type` and `/Name` as exact and unique
DecodeParms fields. A present `/Type` must be the PDF name
`CryptFilterDecodeParms`; `/Name` may occur at most once and must be a non-null
PDF name object. Duplicate fields, wrong value types, absent values, or
an invalid `/Type` return `CL_EPARSE` before decryption, mark the layer
incomplete/non-cacheable, and retain the filter chain's exact raw-input
fallback. Longer keys such as `/TypeExtra` and `/NameExtra` do not alter the
defaults. Name values accept bounded PDF `#xx` escapes through the same exact
comparison used for `/CF` selection.

Focused Linux ARM64 GCC evidence passes 1/1 with ten internal scenarios: a
valid escaped `/Type` plus RC4 `/Name`, exact rejection of longer keys with
Identity defaulting, duplicate `/Name`, dictionary-valued `/Name`, null
`/Name`, literal-string `/Name`, duplicate `/Type`, an invalid `/Type` value,
dictionary-valued `/Type`, and literal-string `/Type`. Every malformed case
proves `CL_EPARSE`, exact encoded raw fallback,
retained temporary accounting, incomplete state, and non-cacheability. The
case passes normally and under GCC AddressSanitizer/UBSan with leak detection.
The 23-oracle `/CF` case, 40-oracle cipher/filter matrix, three-case
DecodeParms parser suite, and explicit Identity ordering case also remain green
against the same current production objects in both modes. Complete
stream/encryption-dictionary corpus mutations, allocation/read fault injection,
production scanner execution, materialized multi-gigabyte encrypted streams,
and Sonic1 evidence remain open.

## 7-Zip bounded BCJ2 solid-folder streaming — 2026-08-24

The canonical four-coder BCJ2 folder graph no longer falls back to a complete
solid-folder allocation. Copy, LZMA, LZMA2, or PPMd decoders stage only the
CALL and JUMP side streams, while the range-control stream is copied to a
third scratch file. Each scratch file reserves its declared 64-bit size from
the shared temporary budget before creation, enforces exact output and input,
checks the scan deadline around I/O, and releases its descriptor, path, and
reservation on every exit. The MAIN decoder writes directly into a resumable
BCJ2 merger with fixed 8 KiB input and 16 KiB output windows. Folder and member
CRC layers remain unchanged, and the selected member is still the only final
output materialized for nested scanning.

The merger preserves five-byte range initialization, partial MAIN writes,
CALL/JUMP selection, range normalization, intentional 32-bit x86 destination
arithmetic, and 64-bit containing-folder coordinates. Checked pack-stream
position arithmetic rejects overflow. A progress wrapper checks deadlines
even while a late solid member causes the member filter to discard an earlier
folder prefix, and `cli_7unz()` gives selected-output, scratch-provider, and
archive-input statuses precedence over generic SDK errors. LZMA and LZMA2
decode steps are capped at 256 KiB of produced output between callbacks, so a
large dictionary cannot defer that progress/deadline check for a full cycle.
The original internal stream-extraction symbols remain ABI-compatible wrappers
around provider-aware suffixed entry points.

Three isolated runtime oracles pass with the existing local ARM64 GCC
toolchain: the decoder/terminal-opcode/window-boundary/graph/native-width/
overflow oracle, the production scratch-provider write/read/cleanup/overrun
oracle, and a one-MiB raw LZMA fixture that emits four exact 256 KiB writes
with nine progress checkpoints. All changed production and unit translation
units also pass direct GCC syntax compilation. Full CMake execution in that
container is unavailable because the canonical checkout requires Rust 1.97
while the existing image contains Rust 1.65; no software was installed.
Production BCJ2 archives, sanitizer execution, Linux x86-64, materialized
multi-gigabyte solid folders, and Sonic1 evidence remain release gates.

## File-backed VBA project-directory metadata — 2026-08-24

Certified 64-bit mmap builds no longer inflate the aggregate VBA `dir` stream
into one heap allocation. Fixed-window decompression writes to an exact
quota-accounted temporary file while checking native-width scan limits and the
shared deadline. The scanner verifies that the backing object is a regular file
whose actual size equals the produced count, maps it privately read-only, gives
the kernel a sequential-access hint, and advises consumed page ranges away
behind a 1 MiB parsing window. The backing reservation remains charged until
the mapping is released, so the mapped directory and generated project output
are accounted concurrently.

Project and module text metadata converts through fixed 8 KiB input windows
with persistent codepage state, so variable-length names and docstrings do not
introduce an independent allocation cap. The Unicode module stream name alone
retains the existing 128-byte OLE property-name contract needed to resolve its
extracted stream. Overflow, limit, quota, decompression, conversion,
backing-size, map/unmap, read/write, close/unlink, and deadline failures remain
incomplete and non-cacheable. Builds without mmap support retain the legacy
contiguous directory inflater as an explicit unsupported compatibility path;
the public whole-module VBA callback retains its separate 1 GiB ABI boundary.

The current production translation unit passes isolated GCC syntax checks.
Production-linked focused oracles pass successful parsing with exact backing
reservation release and streamed project-name output. One-byte-short temporary
quota and decompressed scan-limit cases both reject with no output or residual
temporary charge. Existing bounded stream/codepage and incremental normalizer
oracles remain green. The capability manifest contains 182 entries.
Production Office/VBA corpus, sanitizer and injected backing-I/O failures,
materialized multi-gigabyte directories/modules, certified Linux x86-64, and
Sonic1 qualification remain release gates.

## Bounded EGG filename and comment scanning — 2026-08-24

Scanner-aware EGG opens now retain native-width source ranges for every
filename and archive/file comment rather than requiring those payloads to fit
one allocation. UTF-8 metadata scans directly from the containing fmap.
Filenames declaring another codepage are read in fixed 64 KiB windows through
the persistent converter and staged into exact, incrementally quota-accounted
temporary storage before normalized scanning. Deadlines, scan limits, read,
conversion, write, rewind, nested-scan, close, unlink, and accounting failures
remain incomplete and non-cacheable.

An oversized filename receives a bounded generated display identifier for
member bookkeeping, while the complete original range is still scanned. Small
compatibility strings retain their established behavior, and encrypted string
metadata is explicitly unsupported rather than silently skipped. The public
legacy `cli_egg_open()` null-terminated string interface still has the 1 GiB
individual-allocation ceiling, now recorded as
`egg-legacy-string-metadata-over-1g`; it no longer limits the scanner path.

Sparse runtime evidence proves scanner-aware admission of filename and archive
comment payloads above 1 GiB without backing the holes or requesting more than
16 contiguous bytes during indexing. A production-linked GCC harness confirms
scanner-aware success and legacy-interface rejection. An isolated scanner test
converts a Shift-JIS filename in bounded state and detects a signature that
matches only its UTF-8 form, while confirming matcher and temporary-work
accounting. GCC syntax checks cover the parser, scanner integration, and full
unit translation unit. Compiled EGG corpus, sanitizer/fault injection,
additional codepages and split-sequence cases, materialized large metadata,
certified Linux x86-64, and Sonic1 qualification remain release gates.

## Bounded HFS+ inline decmpfs output — 2026-08-24

HFS+ inline zlib-compressed attributes now decode through a fixed 64 KiB
output window instead of rejecting output above 64 KiB and allocating the
whole declared result. The decoder checks the shared deadline before each
inflate and write, rejects no-progress, trailing input, truncation, declared
size overrun/underrun, and preserves setup, finalization, and exact-write
failures as incomplete and non-cacheable. The existing full-size temporary
reservation remains held through nested scanning.

An isolated test linked with the current HFS+ production object expands a
compressed fixture beyond two output windows and verifies exact tail bytes. It
also proves a one-byte-short declaration and injected write failure return the
specific incomplete result without becoming cacheable. Compiled HFS+ corpus,
sanitizer/fault injection beyond writes, materialized multi-gigabyte output,
certified Linux x86-64, and Sonic1 qualification remain release gates.

## TAR binary size-field preservation — 2026-08-24

GNU base-256 TAR sizes are fixed-width binary fields and normally contain NUL
bytes between the leading `0x80` marker and the low-order size bytes. TAR now
copies the complete 12-byte field before parsing instead of using a string copy
that truncated at the first NUL and silently skipped valid members.

The focused production-linked regression requires an exact signature at child
offset zero for both GNU base-256 and PAX size encodings. A third test rejects
two unrepresentable positive encodings and a negative two's-complement value,
with explicit incomplete/non-cacheable results. A fourth test proves local PAX
size scope and restoration of the preceding global value using child-only
offset and end-relative signatures. All four tests pass, and the constraints
prevent the signatures from matching the containing TAR as raw data. This
closes the prior weak-clean oracle; complete TAR corpus,
sanitizer, truncated binary encodings, certified Linux x86-64, and Sonic1
qualification remain release gates.

## CPIO CRC member validation — 2026-08-24

The `070702` parser now validates its eight-character hexadecimal checksum
field instead of treating CRC archives exactly like unchecked newc archives.
Member bytes are summed with wrapping 32-bit arithmetic through fixed 64 KiB
unlocked fmap windows, with deadline checks and explicit distinction between
truncated data and in-range backing-read failure.

Malformed fields, mismatches, and truncated member ranges are incomplete and
non-cacheable. An available member is still scanned, and status merging keeps
a detection stronger than a checksum error. Production-linked public-API
tests prove an exact child-only signature for valid and mismatched malware and
fail-visible outcomes for benign mismatch, malformed syntax, and truncation. A
third fixture spans more than two checksum windows and detects only an
end-relative marker in the extracted child. An injected first-window backing
failure returns `CL_EREAD` without an alert and remains non-cacheable. Complete
CPIO corpus, large materialized CRC members, sanitizer, certified Linux x86-64,
and Sonic1 qualification remain open.
