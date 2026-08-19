# ClamAV Large-File Support

Status: Review-ready 32 GiB raw-scan release candidate; production acceptance
pending

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

Large-file `clamd` configurations now perform the same admission decision at
startup on Linux: effective `/proc/meminfo` and cgroup headroom must meet the
scaled memory requirement, the configured temporary directory must have the
scaled free-space requirement, and the process must expose 64-bit address and
file-coordinate types. Historical small-file configurations keep their normal
startup path. A failed admission is logged and the daemon does not open its
scan sockets.

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

ALZ and OneNote currently have an explicit 256 MiB whole-input parser cap.
Inputs above that cap are rejected before parser staging/mapping with an
incomplete result while the raw matcher path remains available. Their member
spools are quota-accounted, but these parsers are not yet qualified as
streaming-deep-parser implementations through 32 GiB.

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
  public `CL_TYPE_TNEF` regression; remote source/build qualification remains
  separate because Sonic1 does not contain the local follow-up sources.

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
  when the encoded stream cannot reach a complete state. The public
  `CL_TYPE_BINHEX` regression and focused ARM64 build pass. The current
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
  compatibility ABI; embedded PE analysis marks offsets above 4 GiB
  incomplete with an explicit diagnostic while the raw signature scan
  continues.
- UDF allocation offsets, HFS+ block-to-byte conversions, and audited XAR/DMG
  extents use checked native-width arithmetic. XAR and DMG compressed input is
  consumed in bounded chunks, cumulative output limits are checked, and a
  decoder must reach its terminal state with the exact declared output.
  Malformed metadata, unknown non-empty methods, truncated streams, and
  configured-limit crossings are incomplete/non-clean rather than a scan of a
  partial prefix. Other format-specific boundaries still require dedicated
  adversarial and large-payload fixtures before an upstream support claim.
- Contiguous metadata/decompression remains intentionally capped: XAR TOCs and
  DMG XML at 64 MiB, NSIS contiguous input and EGG decoder buffers at the 1 GiB
  allocation ceiling. Crossing these limits is fail-visible; it is not full
  deep-parser support through 32 GiB.
- DMG blkx Base64 is prevalidated for its complete alphabet, quartet, padding,
  and suffix grammar while allowing XML whitespace and split text/CDATA.
  Stripe tables require exactly one zero-length final `END` record. Focused
  valid and malformed fixtures guard both rules, and the complete configured
  CTest suite passes with these checks enabled.
- BM offset mode now carries 64-bit runtime coordinates, but its bounded
  32-bit scan-window API still needs dedicated fixtures. PCRE full-map matching
  remains separately capped by the platform-aware `PCREMaxFileSize` policy.

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

## Embedded 7-Zip candidate admission — 2026-08-19

Embedded 7-Zip SFX matches now require the complete 32-byte start header and
checked 64-bit next-header range before a nested layer is admitted. A six-byte
magic match at the end of an unrelated payload is rejected as a candidate and
does not taint the parent scan. A candidate with a complete but malformed or
unsupported start header is retained as an explicit incomplete result.

RAR4 SFX matches now receive the analogous bounded check for the fixed main
header prefix and declared header extent before UnRAR admission. RAR5 remains
covered by its ordinary top-level parser path and still requires separate SFX
qualification.

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

This closes the accounting and fail-visible spool gap. It does not yet claim
that the retained 64 MiB MIME message line-list has been replaced by a fully
incremental MIME parser; that remains an explicit parser-family release gate.
