# Brief 32 GiB Status Summary

## Current qualification snapshot — 2026-09-04

The current branch is **not release-qualified**. At the current audit point,
the authoritative capability manifest has 590 entries: 0 qualified, 143
bounded, 426 pending, and 21 unsupported. It reports 576 release-blocking
rows, including 7 required rows marked unsupported, and all 80 enabled parser
rows remain blocked on release evidence. `tools/largefile_release_readiness.sh`
reports this distinction and fails unless every non-excluded row is
independently qualified. The release gate also rejects relabelling a required
parser or matcher as a deliberate unsupported row through its fixed shared
allowlist. Historical sections below remain evidence for their stated
revisions and are not current-source release certification.

The current requirement-level disposition is recorded in `audit1.md` under
“Current PLAN.md requirement audit”. The latest implementation commit is
`139974d5`.

Local Linux ARM64 GCC evidence now covers the latest PDF crypt dictionaries,
DecodeParms semantics, bounded-spool rollback, and all five bounded-filter
output-window allocation failures, normally and with ASan/UBSan. These results
do not replace Linux x86-64 production qualification. The working tree also
adds fail-closed daemon checks for `RLIMIT_FSIZE` and disk-backed temporary
staging, and enforces the certified one-worker profile, with deterministic GCC
and ASan/UBSan policy evidence. Nested v1/v2 cgroup membership and ancestor
headroom are resolved rather than assuming hierarchy-root limits; current-source
x86-64 daemon startup remains unqualified. Sonic1 remains unreachable at its
SSH port on 2026-09-03, so no current-source remote command ran.
Bytecode v1/v2 search now preserves split signatures across 4 KiB windows,
including above 4 GiB; the loader enforces format-8-only APIs/globals and
`clambc` supplies native test offsets. Exact bytecode scan-option queries are
also repaired. Focused GCC and ASan/UBSan checks pass, and a compiled loader
regression covers format isolation, but no independently compiled format-8
interpreter/JIT fixture exists yet.
Historical sections below remain evidence for their stated revisions; any use
of “current head” there refers to that historical checkpoint, not today’s
branch tip.

The implementation at commit
`5becea1236d466ee21f9bd5d3bcd0595ebc1460b` passed the Release suite,
1,284 `libclamav` checks, all 63 Rust tests, all six Valgrind suites, and a
fresh ten-suite ASan/UBSan build. Release and sanitizer exact-32-GiB gates
verified all boundary offsets, rejected 32 GiB + 1, passed cancellation, and
passed exact-edge concurrency with 1, 2, and 4 workers. A private `clamd`
instance detected the end-of-file marker at offset `34359738304` through both
FILDES and exact-edge INSTREAM, while `clamdscan --stream` refused an
oversized regular file rather than sending a truncated prefix. A new
`clamav_milter_protocol` CTest covers real libmilter framing and clean,
infected, exact-limit, and limit-plus-one verdicts. A fully allocated exact-
edge FILDES scan also passed with representative repository test signatures;
the generated 32 GiB fixture was removed after its logs and compact metadata
were preserved. The opt-in literal 32 GiB milter wire upload reached the exact
message boundary. A follow-up source change now caps the mail/text parser's
retained line list at 64 MiB and returns
`Heuristics.Limits.Exceeded.MailMaterialization`; a 4 GiB mail-shaped FILDES
scan peaked at 17,516 KiB instead of the prior 4,619,712 KiB, and both 4 GiB
and exact 32 GiB milter-wire cases returned the bounded fail-visible result.
A corrected 67 MiB Unix mbox containing a later second message also returned
the same indicator at an 8,144 KiB RSS peak.
The local working-tree milter harness was then transferred as an isolated,
SHA-256-recorded test artifact and sent the exact 34,359,738,316-byte body for
a 34,359,738,368-byte message through the Release milter in 2:02.27. It
returned `result=r`, logged the bounded materialization indicator, peaked at
22,708 KiB, and cleaned its temporary directory. This is working-tree-only
evidence because committed `5becea1` does not contain the harness; compact
evidence is preserved at
`/work/evidence/milter-working-tree-harness-20260814`.
The final-commit ASan/UBSan `clamd`/`clamdscan --fdpass` pair then detected a
private exact-edge FILDES marker at offset 34,359,738,350 in 220.694 seconds;
peak daemon RSS was 131,640 KiB with zero major faults and no sanitizer
diagnostics. The private socket, PID, input, and temporary directory were
removed afterward. Evidence is preserved at
`/work/evidence/clamd-protocol-final-sanitizer-20260814`.
A final-commit ASan/UBSan `clamd`/`clamdscan --stream` run then found the
private exact-edge marker at offset 34,359,738,350 in 292.151 seconds with
125,580 KiB peak daemon RSS, 34,359,750,656 bytes peak temporary usage, no
sanitizer diagnostics, and clean input/socket/PID/temp teardown. Evidence is
preserved at
`/work/evidence/clamd-instream-final-sanitizer-20260814-retry4`.
A corrected native FILDES follow-up then scanned eight concurrent exact-edge
32 GiB sparse files through a `MaxThreads 8` daemon. All eight reached the
tail marker and returned the same normalized detection response in 5:54.352;
peak clamd RSS was 620,836 KiB, maximum observed daemon threads were 10, and
temporary usage remained 4 KiB. This is higher-concurrency custom-database
fixture evidence, not production-CVD qualification.
A repeat with aggregate per-thread `/proc` counters again reached all eight
tail markers in 5:52.817, peaked at 622,096 KiB RSS with 10 daemon threads,
used no temporary staging, and recorded zero major page faults. The sampled
minor-fault counter rose by 268,594,526. The raw responses were identical
after normalizing descriptor numbers; a validator-only `.UNOFFICIAL` naming
mismatch is preserved in the compact evidence at
`/work/evidence/fildes-thread8-pf2-20260814`.
Public-API `libclamav` regressions for Unix mbox with alerts enabled, Unix mbox
with alerts disabled, and the recognized single-message parser route are now
included in the Sonic1 CTest run. The latest Release run passed all four
regressions in 26.98 seconds, including the single-message no-alert case,
which asserts `CL_EMAXSIZE` with `CL_VERDICT_NOTHING_FOUND` and no alert. The
aligned ASan/UBSan run also passed all four in 43.12 seconds with no sanitizer
diagnostics. During that sanitizer alignment, an enum-status defect in the
unexpected MIME-subtype path was corrected so the internal parser returns
`FAIL` and the public caller maps it to `CL_EFORMAT`.
The same Release build then passed the remaining six non-Valgrind core CTest
targets—milter quota, clamscan, clamd, freshclam, sigtool, and examples—in
82.58 seconds using the repository's existing fixtures. This strengthens
fixture-based regression coverage but does not replace production-CVD or
custom-database qualification.
The targeted Release `libclamav_valgrind` entry then passed in 352.91 seconds
with all 1,288 checks passing, including the four mail regressions, and no
detected memory-safety diagnostic.
The Release scanner also completed a controlled cold/hot pass over the 9.7 MiB
generated parser corpus: both outputs were byte-identical with 51 detections,
2 clean fixtures, no scanner errors, and the expected fail-visible recursion
limit warning; cold/hot major page faults were 221/0. This remains fixture
evidence rather than production-CVD qualification.
The Release `clamscan` then scanned a separate exact-edge sparse file with the
broader repository `other_sigs` fixtures, `bytecode.cvd`, and a private marker
signature. With explicit `--max-filesize=32G --max-scansize=32G` limits, it
reached the marker at offset 34,359,738,349 in 118.063 seconds and returned
the expected `LargeDB.Edge32.UNOFFICIAL FOUND`; peak RSS was 107,880 KiB with
33,326,633 aggregate minor faults and zero major faults. The generated input
used 4,096 physical bytes and was removed after verification. A no-options
control stopped at the standalone client's default max-scan-size guard, so
this invocation detail is part of the evidence. This remains broader
repository-database evidence, not production-CVD qualification; compact
evidence is preserved at
`/work/evidence/large-db-edge-clamscan-20260814-explicit3`.
An aligned ASan/UBSan `clamscan` build from the same `5becea1` source commit
then repeated that broader exact-edge case. With explicit
`--max-scantime=900000` in addition to the 32 GiB file/scan limits, it reached
the marker and returned the expected exit 1 in 221.154 seconds; peak RSS was
164,260 KiB, minor faults were 34,578,820, major faults were zero, and stderr
was empty. A no-explicit-scan-time control stopped at the default 120-second
limit before the marker, so the scan-time policy is recorded with the passing
evidence at
`/work/evidence/large-db-edge-clamscan-sanitizer-5becea1-retry900s`.
An isolated clamd stress pass also completed 24 parser-corpus scans while
performing 12 database reloads; every reload succeeded and a post-reload
probe detected the added signature with no connection or daemon errors.
A separate 46-file, 1.4 MiB repository archive/deep-parser matrix produced 22
expected detections with identical Release cold/hot output, 0.26/0.25 second
runtime, and 32,072/32,184 KiB peak RSS. The aligned sanitizer scan reproduced
the same output in 0.58 seconds with no sanitizer diagnostics. These are
fixture-qualified results, not production-CVD qualification.
The preserved sanitizer matrix used the older `bba6811` binary, so it was
rerun with the final-commit ASan/UBSan build: all 46 inputs again produced 22
detections and the expected truncated-ZIP warning, with 103,884 KiB peak RSS,
no sanitizer diagnostics, and an empty temporary directory afterward. Fresh
evidence is preserved at
`/work/evidence/deep-parser-fixture-matrix-final-sanitizer-20260814`.

The same matrix was then rerun from cap commit `938a196`: 46 inputs, 22
detections, the expected fail-visible truncated-ZIP warning, exit 1, 0.52
seconds, and 158,876 KiB peak RSS with zero major faults, zero swaps, and no
sanitizer diagnostics. Evidence is preserved at
`/work/evidence/deep-parser-matrix-938a196-20260814`.

The matrix was also rerun through a 13-file database combining the repository's
test CVDs, bytecode CVD, and existing test signatures. The database loaded
successfully and reproduced all 46 inputs, 22 detections, and the same
`fc8cf08eedec79549268bf553d0979dee2debde487861fffe4e4970fd0abedd0` stdout
hash in 0.67 seconds at 207,128 KiB peak RSS, with no
sanitizer diagnostics. This is CVD-format test-database evidence only; Sonic1
still has no production CVD set. Checksummed evidence is preserved at
`/work/evidence/cvd-matrix-938a196-20260814-run2`.

A fresh independent parity rerun used the existing Release and ASan/UBSan
`clamscan` binaries against that identical 13-file database and 46-fixture
corpus. Both runs returned exit 1 with 46 output lines and 22 detections;
stdout and stderr matched byte-for-byte, with the same
`fc8cf08eedec79549268bf553d0979dee2debde487861fffe4e4970fd0abedd0` stdout
hash. Only the expected truncated-ZIP and repository bytecode-runtime
warnings appeared; no sanitizer or database-load diagnostic appeared.
Checksummed evidence is preserved at
`/work/evidence/cvd-matrix-parity-20260814-run1`. Sonic1 inventory still found
no production CVD, so this is test-CVD parity evidence only.

A dedicated final ASan/UBSan cold/hot rerun then loaded the signed repository
test CVDs with the correct certificate directory and scanned the same nested
public corpus after a host page-cache drop. Both passes returned the expected
split-ZIP status 2, produced 46 identical lines matching the Release stdout
hash, and emitted no CVD-load or sanitizer/runtime diagnostic. Checksummed
evidence is preserved at
`/work/evidence/public-cvd-cold-hot-sanitizer-20260814-run1`.

An independent final ASan/UBSan exact-edge `clamscan` run combined all six
signed test CVDs with the private marker database. It found the marker at
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

A final Release daemon-side parity run then used the same exact-edge fixture
through an isolated `clamd`/`clamdscan --fdpass` socket. The combined database
manifest contained the six signed test CVDs, signed CDIFF inputs, and private
marker NDB; `clamd` reported `Loaded 45 signatures`. It detected the marker at
fixture offset `34359738304`, returned exit 1 in 142.531045 seconds, emitted no
stderr or database-load diagnostic, and shut down with exit 0 after removing
its socket and PID file. Temporary storage and active validation processes
were empty. This is signed-test-CVD plus private-marker daemon evidence, not
production-CVD qualification. Evidence is preserved at
`/work/evidence/cvd-clamd-public-exact-edge-release-20260814-run2`.

The matching final ASan/UBSan daemon run used the same combined database and
fixture. It reported `Loaded 45 signatures`, recorded the marker at engine
offset `34359738304`, and returned exit 1 in 235.147097 seconds through
`clamdscan --fdpass`. No sanitizer, runtime, or database-load diagnostic
appeared; shutdown removed the socket and PID file and left temporary storage
empty. This is signed-test-CVD plus private-marker evidence, not
production-CVD qualification. Evidence is preserved at
`/work/evidence/cvd-clamd-public-exact-edge-sanitizer-20260814-run1`.

A bounded POSIX TAR and GZIP/TAR cross-parser limit matrix passed 532/532
assertions for each final Release and ASan/UBSan build across 52 result records.
Late-marker MaxScanSize, MaxFiles, and MaxRecursion cases were explicitly
incomplete, alert-enabled runs surfaced the corresponding limit detections, and
`--allmatch` retained an early marker while reporting a later MaxFiles or
MaxRecursion limit. The normalized semantic-results hash matched between builds
(`7e62acf9da68d3b406c91f8b74ce8cc7e27c02ea4647b2245e8ac98c28be64bf`) with no
database, sanitizer, runtime, or temporary-file diagnostics. This narrows the
generic sticky-incomplete audit but does not close every legacy parser or
production-CVD workload. Evidence is preserved at
`/work/evidence/cross-parser-limit-matrix-release-20260814-run2` and
`/work/evidence/cross-parser-limit-matrix-sanitizer-20260814-run2`.

A follow-up compressed-ZIP matrix passed 178/178 assertions per build across 16
authoritative records. It covered late-member MaxScanSize, early detection
precedence, MaxFiles continuation, and nested MaxRecursion; `--allmatch`
retained early markers while exposing later limit warnings/alerts. Release and
ASan/UBSan semantic results matched at
`a30c03d8b05bdeec9da6fdfe030e53f1b3b20e9d0644bd7b95b12ef36b66d00d`, with no
database, sanitizer, runtime, or temporary-file diagnostics. This strengthens
ZIP-family evidence but does not close every legacy parser or production-CVD
workload. Evidence is preserved at
`/work/evidence/cross-parser-limit-matrix-zip-release-20260814-run1` and
`/work/evidence/cross-parser-limit-matrix-zip-sanitizer-20260814-run1`.

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
Checksummed evidence is preserved at
`/work/evidence/ctest-sanitizer-selected-938a196-20260814-run1` and
`/work/evidence/ctest-release-all-938a196-20260814-run1`.

The Rust entry was then rerun from a correctly structured writable copy of
implementation commit `5becea1` against the Release static artifacts: all 63
integrated tests passed, with checksum verification status 0. The earlier
11 failures remain documented as the read-only-source-mount diagnostic; the
corrected evidence is at
`/work/evidence/rust-release-writable-938a196-20260814-run3`.

A real nested-ZIP Release `clamscan` probe also preserved the fail-visible
`MaxScanSize` result with `AlertExceedsMax=no` (exit 2), the explicit
`Heuristics.Limits.Exceeded.MaxScanSize FOUND` alert with it enabled, and
earlier-child detection precedence when a later child crossed the cumulative
limit. The same path with `MaxFiles=2` returned exit 2 without the alert and
the explicit `Heuristics.Limits.Exceeded.MaxFiles FOUND` result with it
enabled. This closes the observed nested-ZIP false-clean cases, not the
broader parser matrix. Checksummed evidence is at
`/work/evidence/nested-limit-probe-20260814-run1`.

The repository `clam_cache_emax.tgz` fixture then passed the real Release
MaxRecursion guard: alert-disabled returned exit 2 with `Exceeded max
recursion depth ERROR` after an ignored shallower detection, while
alert-enabled returned exit 1 with
`Heuristics.Limits.Exceeded.MaxRecursion FOUND`. Evidence is preserved at
`/work/evidence/maxrecursion-probe-20260814-run1`; broader parser paths remain
open.

A follow-up working-tree audit closed two additional observed legacy-parser
limit exits: HWP3 recursion and the initial OLE2 cumulative `MaxScanSize`
guard now enter the shared sticky-incomplete helper before returning. The
direct regression checks the exact limit cause and non-cacheable fmap state
for both paths. Its isolated static Sonic1 build passed 1,285/1,285 Check
assertions, and the public HWP3 probe returned exit 2 with
`Exceeded max recursion depth ERROR` when `AlertExceedsMax=no`. This narrows
the generic audit but does not close all legacy parser paths.

A current-source review then found a separate OLE2 VBA materialization
fail-open: the property-tree result from both enumeration and VBA
materialization passes was discarded, and incomplete embedded-stream block
extraction could fall through as `CL_CLEAN`. The working tree now propagates
those results, marks incomplete materialization non-cacheable, and adds
`test_ole2_vba_materialization_failure_is_fail_visible` using the real
`has_png_and_jpeg.xls` fixture and an invalid materialization output directory.
Source guards pass. A
disposable ARM64 CMake/Cargo build compiled and linked `check_clamav`, and the
direct harness recorded both new tests as passed; its broader run was limited
by missing/LFS fixtures and certificate setup (`1,261` checks, `786`
environment/fixture failures, `0` errors). The new patch is not yet rebuilt on
Sonic1; existing binaries still show diagnostic drift on the same probe. This
is not Sonic1 qualification; production CVD, broader parser, and rebuild
qualification remain open.

A follow-up OLE2 audit found additional partial-work paths beyond the VBA
materialization pass: malformed property-tree indices/chains/entry types and
loops, fixed recursion/file caps, directory creation failures, XLM/image
pre-scanning failures, and incomplete plain or encrypted OTF stream extraction
could otherwise be normalized to clean. The
working tree now returns explicit limit/read/write/parse errors, preserves
embedded stream scan failures, requires a terminal zlib state before scanning
MSO output, aborts MSO inflation before scanning partial output when a
configured limit is reached, and marks partial streams incomplete/non-cacheable.
Source guards and the focused disposable ARM64 build remained passing. Sonic1's
persistent checkout is clean
at `5becea1`, but its OLE2 source checksum differs from this working tree, so
the follow-up patch is not present in the remote binaries.

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

A broader legacy-parser audit found that MSEXPAND could return clean after
truncated input and could discard configured-limit results. It now propagates
the limit, marks header/read/write/truncation failures incomplete, and has a
public `CL_TYPE_MSSZDD` regression. The focused ARM64 build, parser tests, and
source guards pass; broader legacy-parser coverage remains open.

The same audit found TNEF's truncated-attribute branch explicitly returning
clean. It now returns `CL_EPARSE`, marks the fmap non-cacheable, and has a
public `CL_TYPE_TNEF` regression; remote source/build qualification remains
separate because Sonic1 does not contain the local follow-up sources.

- A Mach-O parser pass found the public scanner normalizing truncated or malformed
  recognized Mach-O input to clean after returning `CL_EFORMAT` without sticky
  incomplete state. The public Mach-O and universal-binary paths now mark those
  failures incomplete and return `CL_EPARSE`; the internal header probe retains
  its non-scanning behavior. The public regression passes in the ARM64 `cl_api`
  group (74 checks with only the two known CVD fixture/setup failures), with
  source guards and fail-closed gates passing. Sonic1 remains unrebuilt because
  its Mach-O source differs.

- An UDF parser-entry pass found mandatory descriptor-area and volume-descriptor
  read failures returning clean. Those paths now mark the scan incomplete and
  return `CL_EPARSE`; the public truncated-descriptor regression passes in the
  ARM64 `cl_api` group (75 checks with only the two known CVD fixture/setup
  failures), with source guards and fail-closed gates passing. Sonic1 remains
  unrebuilt because its UDF source differs.

- An HFS+ parser-entry pass found short or invalid volume headers returning a
  parser error without sticky incomplete state. HFS+ volume-header and final
  parser error paths now mark the scan incomplete; truncated headers return
  `CL_EPARSE` and cannot be cached as clean. The public regression passes in the
  ARM64 `cl_api` group (76 checks with only the two known CVD fixture/setup
  failures), with source guards and fail-closed gates passing. Sonic1 remains
  unrebuilt because its HFS+ source differs.

- A follow-up ISO9660 audit found unsupported interleaved child records and
  multi-extent records could be skipped or partially scanned without a sticky
  incomplete result, and malformed-record exits could retain a mapped directory
  block. Those layouts now return `CL_EPARSE`, mark the scan non-cacheable, and
  avoid treating partial content as complete. The public regression covering both
  layouts passes in the rebuilt ARM64 `cl_api` group (77 checks with only the two
  known CVD fixture/setup failures); source guards and fail-closed gates pass.
  Sonic1 remains unrebuilt because its ISO9660 source differs.

- A XAR parser-entry audit found truncated or invalid headers and unavailable TOC
  data returning parser/read errors without sticky incomplete state. The public
  header path now marks the scan incomplete, and the final TOC/parser error path
  reapplies the invariant before returning. The public truncated-header
  regression passes in the rebuilt ARM64 `cl_api` group (78 checks with only the
  two known CVD fixture/setup failures); source guards and fail-closed gates pass.
  Sonic1 remains unrebuilt because its XAR source differs.

- A DMG trailer audit found an invalid `koly` trailer returning `CL_EFORMAT`
  without sticky incomplete state once trailer validation was reached. The
  invalid-trailer path now returns `CL_EPARSE` and marks the fmap non-cacheable.
  The focused ARM64 `dmg` case passes all 4 checks with 0 failures and 0 errors;
  the broader `cl_api` group remains at 78 checks with only the two known CVD
  fixture/setup failures. Sonic1 remains unrebuilt because its DMG source differs.

- A partition-parser finalization audit found MBR, APM, and GPT malformed or
  truncated header/table errors returning without reapplying sticky incomplete
  state. The three public parser entry paths now mark those failures incomplete
  at finalization. `test_partition_parser_errors_are_fail_visible` passes in the
  rebuilt ARM64 `cl_api` group (79 checks with only the two known CVD fixture/setup
  failures); source guards and fail-closed gates pass. Sonic1 remains unrebuilt
  because its partition-parser sources differ from the current worktree.

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
  Final local `scanners.c` SHA-256 is
  `2058ad161d767ddd2a3236f1f526a3cc23f8acd9c1f5339bfb05bfa2c148876c`.
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
  failure. All four local safety gates pass. Final local hashes are
  `pe.c=8a4e95a3bda2cbadc5f9c59398488fec6d97efa3fbd67ecc9e5bc62e9d901142`,
  `scanners.c=2058ad161d767ddd2a3236f1f526a3cc23f8acd9c1f5339bfb05bfa2c148876c`,
  and
  `check_clamav.c=299dd7cb9befd20fb9e51082f0de737d4781ecc95b64ceba20802bde87b101fd`.
  Fresh Sonic1 Docker access with `sonic1-camera-key` showed all three existing
  ClamAV containers up; the remote `pe.c` and test-source hashes differ from
  this worktree, so no remote rebuild qualification claim is made.

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
  and test-source checksums are `b9d26f8de6b0b8352bd6760eaeb3fc135e7075fffb57fbf6483224f2f268d922`,
  `a1a811fcc0d6d6a2373f8cb9e5065cb11a249bdc74d78dbee8fad6fa6078ff3f`, and
  `767d8b90b1324639b5aa86f78a0d32814e7706fdf14a04272360187026dc8352`; no
  remote rebuild qualification claim is made.

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

- The UNIX mbox dispatcher previously dropped recursive `MAXREC` and `MAXFILES`
  statuses while advancing through a mailbox, and nested multipart paths did
  not explicitly preserve `MAXFILES`. The fix maps both to public non-clean
  results, records the exceed-max heuristic, and stops the mailbox walk. The
  new two-part multipart containing a nested `message/rfc822` part, with
  `MaxFiles=1`, executed without a failure entry. The ARM64 UnRAR-disabled
  harness built successfully and
  reported 1,306 checks, 786 known fixture/environment failures, and 0 errors;
  all four local safety gates passed. Changed-file hashes are
  `mbox.c=ea0c1dbef45714db3408bc70f2397033ab649096fb25f880fccd13b342469384`,
  `check_clamav.c=d81d11e1d9bbeadd6ed102bc7e16cf53025c5eee580047eadc6228e1bd836f3e`,
  and
  `largefile_source_guards.sh=2a7a2703bbcd9bd91e3f671f7bb801d766756fbcfdf0ab2ab09c609bd0c808f2`.
  Fresh host-list request `req_426f3ab06872438da254971e3648a391` returned
  `sonic1`; Docker request `req_d5e17b9a827d46e68c55c0a27b302d0d` using
  `sonic1-camera-key` succeeded with exit 0 and showed the three existing
  ClamAV test containers running. No Sonic1 rebuild qualification claim is made.

  A later Docker inspection request `req_aec06e41d1744d79a9d6dad9f52b571e`
  confirmed all three containers are running from image
  `clamav-32gb:test-tools-742a8a4` with working directory `/workspace/ClamAV`.
  Source hashes from `req_e6c81b5f32e748f58f5d0367aa05da2f` were
  `mbox.c=8439f4d9ac311ba0775d2ef0e4f7c51b90e91b1b36162711bd757ece21fd534`
  and
  `check_clamav.c=8912af667dcdf0d8766b1507790f4c7813d552aead93bfbaafa0761be593ed20`,
  confirming that Sonic1 does not contain the current local mbox follow-up.
  The manual OOXML review found no reproducible new false-clean limit path;
  configured-limit failures remain preserved by the shared sticky result path.

A public Release matrix over real BZIP2/Deflate64/Implode, split, nested
7z-in-ZIP, and split-logos ZIP fixtures returned exit 2 plus an explicit
incomplete warning for all four cuts that removed member data. Tail-only cuts
remained clean because the local member data was intact and fallback scanning
was complete. Evidence is preserved at
`/work/evidence/zip-public-truncation-20260814-run2`.

A bounded public Release `clamscan` probe then covered one 191-byte traditional
ZipCrypto stored member: without a password it returned exit 2 with an explicit
incomplete warning, while the test `.pwdb` path returned exit 1 and detected the
decrypted private marker. A follow-up matrix then detected both members of a
two-member archive despite a deliberately wrong first password, and decrypted
a 64 MiB stored member in 1.598 seconds; both no-password controls returned
exit 2. The extended manifest verified with no temporary decrypted files or
non-zombie scanners. A synthetic production-structure strong-encryption ZIP
with flags `0x0041` and extra field `0x0017` also returned exit 2 with an
explicit `ZIP strong encryption is unsupported` warning, with and without the
password database, and did not detect its marker. This qualifies fail-visible
rejection, not strong-encryption decryption; broader production-format
encrypted coverage remains open. Evidence is preserved at
`/work/evidence/encrypted-zip-probe-20260814-run1`.
Extended evidence is at
`/work/evidence/encrypted-zip-extended-20260814-run1`.
Strong-encryption evidence is at
`/work/evidence/zip-strong-encryption-public-20260814-run1`.

Sonic1 database inventory found no production `main.cvd`, `daily.cvd`, or
`.cld` set; only the repository's small signed test CVD fixtures were
available. A corrected final-Release cold/hot recursive probe loaded those
six CVDs with the repository test certificate, scanned the nested public
`other_scanfiles` corpus, and produced identical 46-line output in both
passes. Both returned the expected status 2 only for the standalone
`zip/logos.z01` split-ZIP segment, with the explicit truncated-member warning;
validation found no signature or database-load error. Host page-cache drop and
all input/database/certificate hashes are recorded. This is signed test-CVD
and cold-cache parser evidence, not production-CVD qualification. Evidence is
preserved at `/work/evidence/public-cvd-cold-hot-20260814-run2`; the preceding
wrong-certificate negative control is at
`/work/evidence/public-cvd-cold-hot-20260814`.

Native INSTREAM measurements then returned `stream: OK` for 64 MiB, 256 MiB,
and 1 GiB streams while temporary usage peaked at exactly the streamed size.
A 65,368-byte deflated ZIP expanding to 64 MiB peaked at 67,174,232 temporary
bytes; all temporary files were removed after shutdown. This establishes the
roughly 32 GiB temporary-disk floor for a 32 GiB stream before expansion and
concurrency overhead, using a tiny one-worker test database.
A four-worker follow-up then returned `stream: OK` for four concurrent 1 GiB
streams and reached exactly 4,294,967,296 aggregate temporary-file bytes, with
53,960 KiB peak daemon RSS and 54,088 KiB HWM. The temporary directory was
empty after shutdown; production-CVD and expansion-heavy production workloads
remain unqualified.
An isolated `MaxThreads 8`/`MaxQueue 16` daemon then handled eight concurrent
256 MiB native INSTREAM clients. All eight sent the exact payload and returned
identical detections; aggregate temporary usage reached 2,147,487,744 bytes,
with 104,552 KiB peak clamd RSS and 10 observed daemon threads. The temporary
directory and private daemon files were clean after shutdown. This is higher
worker-count custom-database fixture evidence, not production-CVD qualification.
A separate representative custom-database overlap pass returned `stream: OK`
for four concurrent 256 MiB streams while 12 database reloads ran; all four
streams and reloads succeeded, and a post-reload probe found the newly added
signature. Aggregate temporary usage peaked at 1,073,745,920 bytes, with
46,840 KiB peak RSS and 48,892 KiB HWM; the temporary directory was empty after
shutdown. Production-CVD reload qualification remains open.
A higher-concurrency custom-database pass then overlapped eight exact-edge
FILDES scans with ten `ConcurrentDatabaseReload yes` reloads. All eight scans
reached their 32 GiB tail markers in 3:00.079 with identical normalized
responses; peak clamd RSS was 582,648 KiB, maximum observed threads were 10,
temporary usage was zero, and the maximum sampled major-fault count was 18. A
post-scan generation-12 reload and NUL-framed probe also passed. Evidence is
preserved at `/work/evidence/fildes-thread8-reload-20260814`; this remains
custom-database evidence, not production-CVD qualification.
An expansion-heavy nested-archive pass then found the marker in four concurrent
three-level ZIPs, each expanding to 256 MiB, with Release aggregate temporary
usage peaking at 1,074,793,460 bytes and aggregate/single-worker peak RSS of
137,912/36,372 KiB. The aligned four-worker sanitizer pass used 64 MiB payloads,
peaked at 268,703,064 temporary bytes and 272,236/65,060 KiB aggregate/single
worker RSS, and emitted no sanitizer diagnostics. Both temporary directories
returned to 4 KiB. This is representative custom-database fixture evidence;
production-CVD and production-scale expansion qualification remain open.
The final-commit ASan/UBSan rebuild then matched the Release 256 MiB
four-worker nested-expansion case: all four detections passed, aggregate
temporary usage peaked at 1,074,806,784 bytes, aggregate/single-worker RSS was
285,792/73,596 KiB, and no sanitizer or runtime-error diagnostic was emitted.
The evidence-local temporary directory was empty afterward; compact evidence
is preserved at `/work/evidence/nested-expansion-final-sanitizer-20260814`.
The final Release and final-commit sanitizer builds then passed four concurrent
three-level ZIPs each expanding to exactly 1 GiB: all eight workers detected
the private tail marker and returned exit 1. Temporary usage peaked at
4,307,564,940 bytes with 46,714,961,920 bytes still available; Release
aggregate/single-worker RSS was 138,412/38,484 KiB and sanitizer was
286,692/75,324 KiB. No worker stderr, sanitizer diagnostic, or leftover
temporary data remained. This is private-database expansion evidence, not
production-CVD qualification. Evidence is preserved at
`/work/evidence/nested-expansion-1g-concurrent-final-release-20260814` and
`/work/evidence/nested-expansion-1g-concurrent-final-sanitizer-20260814`.
An eight-worker extension then passed eight concurrent three-level ZIPs per
build, each expanding to exactly 1 GiB. All sixteen workers detected the
private marker and returned exit 1; Release aggregate/single-worker RSS was
260,884/38,724 KiB and sanitizer was 579,708/76,268 KiB. Temporary usage
peaked at 8,615,125,784 bytes, both temporary directories returned to 4 KiB,
and no worker stderr or sanitizer diagnostics remained. This strengthens
custom-database concurrency evidence but does not replace production-CVD or
production-format qualification. Evidence is preserved at
`/work/evidence/nested-expansion-1g-8way-final-release-20260814` and
`/work/evidence/nested-expansion-1g-8way-final-sanitizer-20260814`.

The same eight-way one-GiB nested ZIP workload also passed through final
Release and ASan/UBSan `clamd` with eight threads, queue depth 16, and 32-GiB
limits: all sixteen synchronized `clamdscan --fdpass` clients detected the
private marker and returned exit 1. Release peak daemon RSS was 90,324 KiB and
sanitizer was 137,456 KiB; both reached 8,615,121,688 temporary bytes, stayed
above 46.7 GB available space, observed 10 daemon threads, emitted no
diagnostics, and cleaned their temporary directories after shutdown. This is
clean daemon-side private-database evidence, not production-CVD or
production-format qualification. Evidence is preserved at
`/work/evidence/clamd-nested-1g-thread8-clean-final-release-20260814` and
`/work/evidence/clamd-nested-1g-thread8-clean-final-sanitizer-20260814`.

Both final `clamscan` builds also rejected `--max-filesize=34359738369` before
opening the input, returned exit 2, and emitted the expected 32-GiB ceiling
error. Evidence is preserved at
`/work/evidence/maxfilesize-policy-final-release-20260814` and
`/work/evidence/maxfilesize-policy-final-sanitizer-20260814`.

An exact 34,359,738,368-byte expanded three-level Zip64 fixture failed
visibly under both final Release and ASan/UBSan `MaxScanSize=32G` cumulative
budgets, while both final Release and ASan/UBSan exploratory runs with
`MaxFileSize=32G` and `MaxScanSize=64G` extracted the full payload and detected
the marker at the exact 32-GiB offset. Release/sanitizer peak RSS was
125,144/162,604 KiB and
temporary usage peaked at 34,659,607,228 bytes; both cleaned up afterward with
no diagnostics. This proves expansion capacity under the larger exploratory
budget, not default 32-GiB cumulative-budget or production-CVD qualification.
Evidence is preserved at
`/work/evidence/nested-expansion-32g-final-release-20260814` and
`/work/evidence/clamd-nested-1g-thread8-clean-final-sanitizer-20260814/large32g`.

After synchronously dropping the host page cache, both current builds also
scanned identical sparse 32-GiB edge fixtures and detected the marker at the
exact 34,359,738,304-byte engine offset. Release took 1:58.49 with 100,948 KiB
peak RSS; sanitizer took 3:41.08 with 137,068 KiB peak RSS. Both returned exit
1, recorded no diagnostics, and cleaned temporary storage to 4,096 bytes.
Evidence is preserved at
`/work/evidence/cold-cache-exact-edge-final-release-20260814` and
`/work/evidence/cold-cache-exact-edge-final-sanitizer-20260814`.

The same cache-drop procedure passed synchronized two- and four-worker raw
edge scans in both builds: all twelve clients detected the marker at the exact
engine offset, with zero temporary files and no sanitizer diagnostics. Summed
per-worker peak RSS upper bounds were 200,828/272,796 KiB at two workers and
402,616/543,280 KiB at four workers (Release/sanitizer). Evidence is preserved
at the corresponding `concurrency-2way-exact-edge-final-*` and
`concurrency-4way-exact-edge-final-*` directories.

The final Release CTest `libclamav` target also passed 100% in 27.07 seconds
with zero stderr, covering the checked-in synthetic limit and ZIP-boundary
regressions. Evidence is preserved at
`/work/evidence/correctness-libclamav-final-release-20260814`.

The final source commit was also rebuilt with ASan/UBSan and `ENABLE_TESTS=ON`;
after generating 390 fixture files, its `libclamav` CTest passed 100% in
32.07 seconds with zero stderr and no sanitizer diagnostics. Evidence hashes
are preserved at
`/work/evidence/correctness-libclamav-final-sanitizer-20260814-v3`.

The same final ASan/UBSan build also passed the configured `clamd` CTest target
in 32.35 seconds with 100% tests passed, zero stderr, and no sanitizer
diagnostics. Evidence hashes are preserved at
`/work/evidence/correctness-clamd-final-sanitizer-20260814`.

It also passed the remaining committed-source core-tool CTest targets—
`clamav_milter_quota`, `clamscan`, `freshclam`, and `sigtool`—4/4 in 51.46
seconds. The timed run reached 346,644 KiB maximum RSS, returned CTest exit 0,
had no sanitizer/runtime diagnostics, passed evidence-hash verification, and
left no matching test processes. A wrapper false negative caused by matching
CTest's benign `Label Time Summary:` text is documented by the corrected
record at `/work/evidence/correctness-core-tools-final-sanitizer-20260814/post-validation.txt`;
the underlying CTest output remains preserved in the same evidence directory.

The final sanitizer build was also reconfigured with `ENABLE_MILTER=ON`; the
`clamav-milter` target built with ASan/UBSan and `clamav_milter_quota` passed
1/1. Its exact-edge libmilter harness then reached 34,091,302,912 of the
expected 34,359,738,316 body bytes before sanitizer `clamd` reached
43,615,092 KiB RSS, so the run was stopped for safety and is explicitly
`not-qualified`. The initial 109-byte socket-path failure was corrected with a
62-byte test root. Memory recovered cleanly and no test processes remained.
Evidence, including hashes and resource samples, is preserved at
`/work/evidence/milter-working-tree-harness-final-sanitizer-20260814`; the
Release working-tree exact-edge pass remains separate and does not close this
sanitizer gap.

For comparison, the local follow-up cap files were tested only in an isolated
ASan/UBSan checkout and then restored: a real 4-GiB milter wire completed with
exactly 4,294,967,244 body bytes, returned the expected `r` result, and logged
`Heuristics.Limits.Exceeded.MailMaterialization`. The timed harness reached
380,048 KiB maximum RSS in 19.43 seconds, left a 172 KiB runtime footprint,
and emitted no sanitizer diagnostics. This is working-tree-only evidence until
the cap changes are committed and retested from the fork revision. Evidence
and source hashes are preserved at
`/work/evidence/milter-working-tree-cap-sanitizer-20260814`.

The same isolated cap checkout then passed the literal 32-GiB milter boundary:
the harness sent exactly 34,359,738,316 body bytes for a 34,359,738,368-byte
message, returned `r`, and logged
`Heuristics.Limits.Exceeded.MailMaterialization FOUND`. Under ASan/UBSan the
timed run completed in 2:39.70 with 380,124 KiB maximum RSS, zero swaps, a
172 KiB post-shutdown runtime footprint, no temporary files, and no
sanitizer/runtime diagnostics. Evidence and checksums are preserved at
`/work/evidence/milter-working-tree-cap-sanitizer-20260814/exact-edge`.
The source was restored to committed `5becea1` and the committed sanitizer
milter target rebuilt afterward; this remains working-tree-only evidence.

The same isolated cap checkout, with the local public-API regression additions,
then ran `libclamav` CTest under ASan/UBSan with
`CVD_CERTS_DIR=/workspace/ClamAV/certs`: 1/1 passed in 42.93 seconds, and all
four materialization regressions (mbox/single-message, alert/no-alert) were
recorded as `P (Passed)`. Maximum RSS was 886,720 KiB, swaps stayed at zero,
and no sanitizer/runtime diagnostics or test processes remained. Evidence and
source hashes are preserved at
`/work/evidence/milter-working-tree-cap-sanitizer-20260814/unit-regression`.
The earlier run without `CVD_CERTS_DIR` skipped fixture-loading tests and is
not counted.

A follow-up Sonic1 validation applied the cap and regression tests to an
isolated checkout based on `5becea1`. Its complete ASan/UBSan build with
`ENABLE_MILTER=ON` passed `libclamav` 1/1 and the milter quota/protocol pair
2/2; the literal exact-edge milter wire sent exactly 34,359,738,316 body bytes
for a 34,359,738,368-byte message, returned `r`, and logged
`Heuristics.Limits.Exceeded.MailMaterialization FOUND`. No sanitizer/runtime
diagnostics or temporary files remained. The validated follow-up is preserved
as local Sonic1 commit `938a196` on `codex/sonic1-validation-fixes` and was not
pushed upstream. Checksummed evidence is at
`/work/evidence/cap-committed-validation-20260814`.

A targeted adversarial mbox fixture with 8,388,608 seven-byte body lines
(`67,108,864` logical body bytes) also exercised the cap-enabled ASan/UBSan
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
diagnostics. Checksummed committed-source evidence is at
`/work/evidence/deep-parser-density-938a196-20260814`.

The committed sanitizer `libclamav` suite also passed 1/1 in 42.99 seconds
with explicit ZIP closure cases for exact output, truncated streams, unsupported
strong encryption/masked headers/data descriptors/methods, and inclusive
`MaxFiles` detection precedence. Evidence is preserved at
`/work/evidence/zip-boundary-938a196-20260814`.

A stronger mbox precedence fixture then put a correctly base64-encoded private
marker in an attachment of the first message and a 67 MiB dense second message
behind it. The final-commit ASan/UBSan `clamscan` single-match run returned the
attachment marker in 0.16 seconds at 70,536 KiB RSS without reaching the later
materialization cap; the all-match run returned both the attachment marker and
`Heuristics.Limits.Exceeded.MailMaterialization` in 1:21.15 at 430,016 KiB RSS.
No sanitizer diagnostics or temporary mail directories remained. This closes
the attachment-level detection-precedence and all-match-retention check, with
checksummed evidence at
`/work/evidence/mbox-detection-plus-cap-938a196-20260814/custom/attachment-level-b64`.

That implementation is ready for review as a bounded sparse raw-scan release
candidate, but it is not yet production-certified. The current explicit cap is
safe fail-visible handling rather than deep scanning beyond 64 MiB of a mail
parser representation. Remaining qualification work is production
CVD/custom-database and broader adversarial deep-parser/cold-cache testing,
deciding
whether to replace the cap with streaming/spooling mail analysis, and an
attested run on the labelled GitHub release runner. The pending
sanitizer-workflow update builds milter and leaves non-instrumented Rust and
Valgrind suites in the Release test path; it passed local controls but has not
yet been exercised by GitHub Actions. The follow-on documentation/workflow
commit does not claim a rerun of the full remote matrix at its new HEAD.

## Latest HWP embedded-OLE2 boundary follow-up — 2026-08-15

The HWP embedded-OLE2 wrapper now rejects a native payload larger than its
32-bit size-field range with `CL_EPARSE`, marks the scan incomplete and
non-cacheable, and marks truncated size-prefix reads incomplete. The focused
large-document-cap regression passed in the rebuilt disposable ARM64 target.
The aggregate C run reported `1306` checks, `786` known fixture/environment
failures, and `0` errors; the new regression had no failure entry. All four
local safety gates passed.

Fresh Sonic1 MCP-SSH verification used host-list request
`req_00af40b0aada46de98bb3c3c5ba908ff`, Docker request
`req_c246b4efe35544a1bbcbcdd5a9579391`, and inspect request
`req_d239185d81b04ef8a0f29b10018f3498`; all three existing ClamAV test
containers are up, and the primary one is `running` with image
`clamav-32gb:test-tools-742a8a4` and a read-only `/workspace/ClamAV` bind.
Remote source-hash request `req_1c42c75365504b7bb05b1a80bc5cb021` showed the
remote HWP/test/guard sources differ from the current local patch. No remote
rebuild or qualification claim is made.

## Validation refresh — 2026-08-15

Both disposable ARM64 test targets built, and the registered large-file and
release-control CTest subset passed 4/4. The broader `check_clamav` run was
environment-bound at `1142` checks, `840` fixture/environment failures, and
`0` errors because the source-mounted checkout did not contain the complete
LFS/corpus/CVD/certificate setup. The HWPole2 regression had no failure entry,
but the Check runner provides no focused case selector, so this is not claimed
as an isolated execution. Workflow YAML parsing also passed.

Fresh MCP-SSH evidence used `sonic1-camera-key`: host list
`req_2ec6db7f3d1442f29fb13caaae9e9fc8`, Docker status
`req_51e5181dcc8d493a865337373b4f983b`, inspect
`req_ede657cb810b44ba8f98540f64991433`, and source hashes
`req_48a1b5ad007348d1b2fd2b0b65767c95`. All three existing ClamAV test
containers were up; the primary used `clamav-32gb:test-tools-742a8a4` with a
read-only `/workspace/ClamAV` bind. Remote HWP/test/guard hashes differ from
the current patch, so Docker access and liveness are verified without a
remote rebuild or qualification claim.

## Latest GIF parser boundary follow-up — 2026-08-15

The recognized GIF parser now marks truncated graphic-control payloads, local
color tables, LZW minimum-code-size bytes, image data blocks, and missing image
trailers incomplete and non-cacheable. The isolated ARM64 Check `gif` group
passed 1/1. The aggregate harness reported `1307` checks, `786`
fixture/environment failures, and `0` errors, with the GIF regression passed;
the registered large-file/release-control CTest subset passed 4/4. Source,
fail-closed/runtime-evidence, and workflow YAML controls also passed.

Local hashes are `gif.c=d5fedded1cad41267f6ec2c7e9141e89d67f434f63f9de8db649e71b4d66a4f9`,
`check_clamav.c=fed677b3e8def065d9328b5a056de9e44840e54aefbf0280a9125392a43fa8ce`,
and
`largefile_source_guards.sh=4a9084ccc2099a89ae4688776a75075a052b1872d4d045e3247d4af3bad91d99`.

Fresh Sonic1 requests used host list `req_3891a53b4be04bb48a52983a28a9d728`,
Docker status `req_2916efb44812499c8bba23d01d56e3af`, inspect
`req_d8b5757de5b9493bbec6192556d38280`, image identity
`req_824c25d8f52c44c180cf43403adc2971`, and source hashes
`req_4d5f7ebb11264a25906e0864739c01c8`, using
`sonic1-camera-key`. All three existing containers were up on
`clamav-32gb:test-tools-742a8a4`, digest
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`;
the primary `/workspace/ClamAV` bind remains read-only. Remote GIF/test/guard
hashes differ from the local patch, so Docker liveness is verified without a
remote rebuild or qualification claim.

## Latest PNG parser boundary follow-up — 2026-08-15

PNG boundary failures for truncated chunk types/data/CRCs, malformed `IHDR`,
non-empty `IEND`, and missing `IEND` are now sticky incomplete and
non-cacheable. The isolated ARM64 Check `png` group passed 1/1. The aggregate
harness reported `1308` checks, `786` fixture/environment failures, and `0`
errors; the registered large-file/release-control CTest subset and local
source, fail-closed/runtime-evidence, and workflow YAML controls passed.

Local hashes are `png.c=847ea343241241429388b5b242989d48d881eb2d48bc53fc7bb07e553e0f209d`,
`check_clamav.c=c8f7d40c5f55046c22abcb8bf5512b692d8edfeb35dae9ffb1ea9eaf7e6dea4c`,
and
`largefile_source_guards.sh=53bca065b69fea84a34ef4572a85f43c801acbad25aba1fee80464b2fd5afbf4`.

Fresh Sonic1 requests were host list `req_a64c9e1e92074a32a784242258314923`,
Docker status `req_ade8413ef3514607803ade1e4e51a620`, inspect
`req_ee1ef808a7f249e183d24c3d0e5b153f`, image identity
`req_cb12f6d811cd487396dc198406244fa9`, and container hashes
`req_36b8dfb768334f439c933adb4187ef5d`, using `sonic1-camera-key`. All three
containers were up on `clamav-32gb:test-tools-742a8a4`, with the primary
`/workspace/ClamAV` bind read-only and image digest
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PNG/test/guard hashes differ from local, so Docker liveness and
provenance are verified without a remote rebuild or qualification claim.

## Latest PDF trailer boundary follow-up — 2026-08-15

Recognized PDFs with missing `%%EOF` or `startxref`, negative/out-of-range xref
offsets, or invalid xrefs now fail visibly, return `CL_EPARSE` to direct parser
callers, and are non-cacheable. The sticky incomplete state is applied at the
common return boundary after parsing so object detections and virus results are
preserved.

The isolated ARM64 Check `pdf` group passed 1/1. The current forked aggregate
reported `1145` checks, `840` known fixture/environment failures, and `0`
errors; the no-fork aggregate remains an intermittent harness limitation and
exited 139 after 1145 checks with 0 Check-reported errors. The registered
large-file/release-control CTest subset and local source, fail-closed/runtime-
evidence, and workflow YAML controls passed.

Local hashes are `pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`check_clamav.c=50451a1805f689f546d45e853c89ce50e992cbfe0c18880b4ad67146b1207acc`,
and `largefile_source_guards.sh=0aa1f42a3f52e4cd842d5f58def7ffe3b95e8bb1b79444b1af5864c0a81fd4ad`.

Fresh Sonic1 requests were host list `req_699bfdd0509d4bbd8fdfd635b6ab3794`,
Docker status `req_fa690ea074a144be9c92a4ee20a35506`, inspect
`req_5551d4e47af1434e98483e833ff80065`, image identity
`req_81bda151c5284ac6845bfdc4f19419cd`, and container hashes
`req_c9b2355d08a24997a960d3573107304f`, using `sonic1-camera-key`. All three
containers were up on `clamav-32gb:test-tools-742a8a4`; the primary
`/workspace/ClamAV` bind was read-only and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PDF/test/guard hashes differ from local, so Docker liveness and
provenance are verified without a remote rebuild or qualification claim.

## Latest PDF decode and aggregate lifecycle follow-up — 2026-08-15

PDF filtered-stream decode `CL_EPARSE` results now mark the containing layer
incomplete and non-cacheable before best-effort object extraction continues.
The bytecode parallel-load test preflights its `bytecode.cvd` fixture on the
main thread, so missing fixtures remain visible failures without unsafe Check
assertions from worker threads.

The isolated ARM64 PDF group passed 2/2. Three consecutive no-fork aggregate
runs completed without a crash with `1146` checks, `840` known
fixture/environment failures, and `0` errors; the forked aggregate matched.
The isolated bytecode suite reported 48 checks, 5 fixture failures, and 0
errors. The registered CTest subset and local source, fail-closed/runtime-
evidence, and workflow YAML controls passed.

Local hashes are `pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`pdfdecode.c=5aa98bba6753b3950edf207bbcfd8a25e4ee154b17acf743cf21fb4316cc73e7`,
`check_clamav.c=886628a0c83441f27d3c427fbad97dd038b0753a47c2d08af560aac977f5f84f`,
`check_bytecode.c=b0e9254e0dfc987ed3069d91d73dfab518fc069ebc05887ac77cfa071117a0f5`,
and `largefile_source_guards.sh=f7e3b418020923be94b622a716c731f5d053e708fc4368a1c434909325f4acb0`.

Fresh Sonic1 requests were host list `req_3d029d63018b4790b7700971d09bc890`,
Docker status `req_5c341b5a6a0b4140a412ff4faa853cbf`, inspect
`req_1fa443f9d5934ddb9532d14f6c10acac`, image identity
`req_a4cc36b931f74290b33b09fe9c7e7ce5`, and container hashes
`req_e60bf09ef17942cf80d9b499d5e0a3ae`, using `sonic1-camera-key`. All three
containers were up on `clamav-32gb:test-tools-742a8a4`; the primary
`/workspace/ClamAV` bind was read-only and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PDF/decode/test/guard hashes differ from local, so Docker liveness and
provenance are verified without a remote rebuild or qualification claim.

## Latest HWPML XML boundary follow-up — 2026-08-15

HWPML attachment scanning now enables `MSXML_FLAG_FAIL_INCOMPLETE`, making
truncated XML return `CL_EPARSE`, mark the layer incomplete, and disable
caching. The isolated HWPML group passed 1/1. Three no-fork aggregates and one
forked aggregate completed without a crash with `1147` checks, `840` known
fixture/environment failures, and `0` errors. The registered CTest subset and
local source, fail-closed/runtime-evidence, and workflow YAML controls passed.

Local hashes are `hwp.c=be3f3b5a9d09532cf872fab3ff4c4fd278c30eaa27c14dabee5fc224b108f00b`,
`pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`pdfdecode.c=5aa98bba6753b3950edf207bbcfd8a25e4ee154b17acf743cf21fb4316cc73e7`,
`check_clamav.c=0737b2e7cc94744f84a620cbbb49ca76b12adefdaca52f56ae1e7a02147b0fd0`,
`check_bytecode.c=b0e9254e0dfc987ed3069d91d73dfab518fc069ebc05887ac77cfa071117a0f5`,
and `largefile_source_guards.sh=4016ec50dd8a6907ec30cd65f423ebf2fa3e9e1bb20a5f7b97a46da4810d9d15`.

Fresh Sonic1 requests were host list `req_32f6b1d1395e4a32935d36053c8b0184`,
Docker status `req_a17de6e58ad9491cb0f60a0c9e79a4bf`, inspect
`req_04a57ef44632451ca9395d3feaa829a1`, image identity
`req_8ea41451f46c4a4bb1ceba85f5467b33`, and container hashes
`req_d4300ebb99084dfa9b4660450e71b879`, using `sonic1-camera-key`. All three
containers were up on `clamav-32gb:test-tools-742a8a4`; the primary
`/workspace/ClamAV` bind was read-only and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote HWPML/PDF/decode/test/guard hashes differ from local, so Docker
liveness and provenance are verified without a remote rebuild or qualification
claim.

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
`req_40f0d5693b2c4c30bbc631e74a04ddd7`, using `sonic1-camera-key`. Sonic1
reported the three validation containers up on `clamav-32gb:test-tools-742a8a4`.
A fresh container-hash request `req_48eb6b0b814c46c08e2c91951a791672` returned
remote HWP3 and test hashes different from the current local patch. Remote
Docker liveness and source provenance are verified, but no remote rebuild or
qualification claim is made.

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
`req_e59c7388fb224f5f954a4ab126d9e426`, using `sonic1-camera-key`. Sonic1
reported all three validation containers up on `clamav-32gb:test-tools-742a8a4`.
Container-hash request `req_b15eb96998f54f4481d50543edeed8fb` returned remote
XAR, test, and guard hashes different from the current local patch. Remote
Docker liveness and source provenance are verified, but no remote rebuild or
qualification claim is made.

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

The RAR bridge now fails closed when an extracted output exists but cannot be
opened. Only a genuinely missing output remains an optional `CL_EOPEN` case.
The ARM64 Clang target built; the available `cl_api` group reported 90 checks,
1 known missing-fixture failure, 0 errors, and no sanitizer diagnostics.
`ENABLE_UNRAR=OFF` prevented the RAR-specific runtime test from compiling.
Local evidence is preserved at `/private/tmp/clamav-32gb-rar-followup`.

## Latest OLE2 VBA candidate-failure follow-up — 2026-08-15

An all-found-but-malformed OLE2 VBA `dir` candidate set is now incomplete and
non-cacheable instead of clean. The ARM64 Clang target built; the available
`cl_api` group reported 90 checks, 1 known missing-fixture failure, 0 errors,
and no sanitizer diagnostics. Sonic1 liveness is verified, but its source
hashes differ from this worktree. Evidence is preserved at
`/private/tmp/clamav-32gb-ole2-candidate-followup`.

## Latest TIFF structural-boundary follow-up — 2026-08-15

The TIFF parser now fails visibly on truncated first-IFD offsets, directory
entries, next-IFD links, out-of-range value data, and out-of-order IFD links.
The four-case `test_tiff_truncated_structures_are_fail_visible` regression
passed. The ARM64 Clang target rebuilt; the aggregate recorded 1,315 checks,
782 known fixture/setup failures, and 0 Check errors. Existing unrelated UBSan
diagnostics remain in disassembly and bytecode tests, so the aggregate is not
a clean sanitizer-suite result. Evidence is preserved at
`/private/tmp/clamav-32gb-tiff-followup`.

Fresh Sonic1 verification with `sonic1-camera-key` confirmed all three
validation containers up on `clamav-32gb:test-tools-742a8a4`. Remote TIFF,
test, and guard hashes differ from this worktree; no remote rebuild or
qualification claim is made.

## Latest PE icon follow-up — 2026-08-15

Declared PE icon data that cannot be read completely is now fail-visible:
the matcher marks the scan incomplete/non-cacheable and returns `CL_EPARSE`.
Icon-count exhaustion remains `CL_EMAXSIZE`; valid out-of-scope dimensions are
still optional. The new PE icon regression passed in the focused `cl_api`
case (91 checks, 3 known fixture/environment failures, 0 Check errors).
Sonic1 Docker liveness succeeded with `sonic1-camera-key`; its source hashes
differ from the local follow-up, so no remote rebuild qualification is made.

## Latest RIFF/ANI follow-up — 2026-08-15

The enabled RIFF/ANI exploit heuristic now fails closed for truncated or
out-of-map RIFF/RIFX `ACON` chunk headers, list types, declared data, padding,
and excessive nested-list depth. It marks the scan incomplete/non-cacheable
and returns `CL_EPARSE`; the new RIFF regression passed. The focused ARM64
static `cl_api` run recorded 93 checks, 3 known fixture/environment failures,
and 0 Check errors. The separate `ENABLE_UNRAR=OFF` runtime gate remains open.
Evidence is preserved at `/private/tmp/clamav-32gb-riiff-followup`.

Sonic1 host-list request `req_1029d3e0c65c4074af98961b011d04cd`, Docker status
request `req_47b054397a254c6a850e85fb65e9d587`, and source-hash request
`req_8d06bd4b68194a68a5ca8c15f90ff5d3` succeeded with `sonic1-camera-key`.
All three validation containers remain up on `clamav-32gb:test-tools-742a8a4`;
remote hashes differ from the current worktree, so no remote rebuild
qualification is claimed.

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

## Latest script text-normalization mapped-read follow-up — 2026-08-15

Script normalization now marks mapped-read failures incomplete and
non-cacheable and returns `CL_EPARSE` through `cli_scanscript` instead of
scanning partial normalized output. The focused ARM64 static `cl_api` run
recorded 95 checks, 3 known fixture/environment failures, and 0 Check errors;
the new partial-map regression passed. Evidence is preserved at
`/private/tmp/clamav-32gb-textnorm-followup.test.log`.

Sonic1 host-list request `req_6c512903cdad4d98adf4a68f3b9512cb`, Docker status
request `req_7290f17a8fec4dca9a8dacd1bb737a3e`, and source-hash request
`req_92bec118bde546adb13e1e340b52b57b` succeeded with `sonic1-camera-key`.
All three validation containers remain up on `clamav-32gb:test-tools-742a8a4`;
remote hashes differ from the current worktree, so no remote rebuild
qualification is claimed.

## Latest HTML normalization mapped-read follow-up — 2026-08-15

HTML normalization now marks mapped-page read failures incomplete and
non-cacheable and returns `CL_EPARSE` through the HTML scanner instead of
treating a partial normalized view as ordinary EOF. The focused HTML suite
passed 7/7 checks; the focused ARM64 static `cl_api` run recorded 94 checks,
3 known fixture/environment failures, and 0 Check errors. Evidence is
preserved at `/private/tmp/clamav-32gb-htmlnorm-followup.test.log` and
`/private/tmp/clamav-32gb-htmlnorm-clapi.test.log`.

Sonic1 host-list request `req_34f81c6f259b463c94181fe14982f019`, Docker status
request `req_6932f7de74cb41209c6ecba3b96cc62d`, and source-hash request
`req_999b98cb219041dc8055fa7513bc4184` succeeded with `sonic1-camera-key`.
All three validation containers remain up on `clamav-32gb:test-tools-742a8a4`;
remote hashes differ from the current worktree, so no remote rebuild
qualification is claimed.

## Latest JPEG broken-media follow-up — 2026-08-15

The enabled JPEG broken-media parser now fails closed for recognized JPEGs
truncated during their header, marker, segment-size, or segment-data
structures. It marks the scan incomplete/non-cacheable and returns `CL_EPARSE`
to direct parser callers; the new JPEG regression passed. The focused ARM64
static `cl_api` run recorded 94 checks, 3 known fixture/environment failures,
and 0 Check errors. The separate `ENABLE_UNRAR=OFF` runtime gate remains open.
Evidence is preserved at `/private/tmp/clamav-32gb-jpeg-followup.test.log`.

Sonic1 host-list request `req_30d04aa0ec2043b8912aa0994ed74a2d`, Docker status
request `req_f3d86a5a7e324ad1a1d51017dde7da4a`, and source-hash request
`req_d700129808934fa091a2204363af3ab7` succeeded with `sonic1-camera-key`.
All three validation containers remain up on `clamav-32gb:test-tools-742a8a4`;
remote hashes differ from the current worktree, so no remote rebuild
qualification is claimed.
