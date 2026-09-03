# ClamAV 32 GiB Development and Validation Status

## Current qualification warning — 2026-09-03

This branch is not release-qualified. The current manifest records 0
qualified, 141 bounded, 398 pending, and 26 unsupported capabilities; 546 rows
remain release-blocking, including 7 required rows marked unsupported, and all
80 enabled parser rows still require release evidence. The August 14–18
“current-head” statements below are historical and remain bound to their named
commits and manifests. Sonic1 was unreachable by SSH on 2026-09-03, so none of
the latest PDF or admission work has current-source
Linux x86-64 production evidence. The working tree now fails certified daemon
startup when `RLIMIT_FSIZE` cannot accommodate one maximum-sized ingress, or
when staging is on tmpfs/ramfs; focused local
GCC and ASan/UBSan policy tests pass, but do not qualify daemon startup.
The same gate rejects `MaxThreads != 1` because its resource budget covers one
active scan and the first-release contract requires later requests to queue.
Linux memory admission now resolves the daemon's actual v1/v2 cgroup mount and
membership and uses the smallest finite headroom across visible ancestors;
synthetic hierarchy and real-container probes pass locally.
Bytecode search now overlaps adjacent 4 KiB windows and finds a split marker
both below and above 4 GiB. Format-6/7 modules are rejected if they declare or
reference format-8-only interfaces, and `clambc` initializes native matcher
offsets. Exact, allocation-free scan-option queries now reject partial and
embedded-NUL names. Focused GCC and ASan/UBSan checks pass, and the loader
format-isolation regression compiles; independently compiled format-8
interpreter/JIT and Sonic1 production-bytecode evidence remain open. The
release gate now uses a fixed shared allowlist for deliberate unsupported rows,
so a required parser or matcher cannot bypass qualification by relabelling.

**Status date:** 2026-09-03

## Latest current-head rebinding and Sonic1 evidence — 2026-08-18

The Sonic1 current-source container was reconfigured after a manifest audit
found that its existing Release and sanitizer build trees still referenced an
older source manifest.  The mounted source manifest is now
`2d476381e0dda500dd21a754a1a741c647da48ba8bf1ff79818d3ebcf6eb1023`, and
both build caches and `source-manifest.txt` files match it.

From that rebound source/build pair, Release and sanitizer both passed the
focused RAR/API suite with 103 checks and 0 failures, and both passed the two
`MaxScanTime` configuration/CLI boundary tests.  The Release and sanitizer
large-file control subsets each passed 5/5, including the runtime-evidence
verifier and milter protocol/quota tests.  The retained `runtime-v5-final6`
artifact also passed its internal evidence verifier; it remains historical
runtime evidence and is not relabeled as production-CVD qualification.

Sonic1 still has no authorized production CVD/database or production workload,
so production certification remains blocked.

**Upstream baseline:** ClamAV 1.5.3

**Validation branch:** `codex/sonic1-validation-fixes`

**Validated source commit:** `5becea1236d466ee21f9bd5d3bcd0595ebc1460b`

**Target:** safely scan files from 0 through and including 32 GiB on supported
64-bit Linux systems, without coordinate truncation, silent prefix scanning,
or memory residency proportional to the complete input.

## Brief summary

The implementation at commit
`5becea1236d466ee21f9bd5d3bcd0595ebc1460b` passed the ordinary Release
suite, all 1,284 `libclamav` checks, all 63 Rust tests in a writable exact
source copy, all six Release Valgrind suites, and a fresh ten-suite ASan/UBSan
build. Release and sanitizer runtime gates both detected all 11 sparse boundary
markers at their exact engine offsets through 32 GiB, rejected 32 GiB + 1,
passed cancellation, and passed exact-edge concurrency at 1, 2, and 4 workers.

A private `clamd` instance also detected a marker in the final 64 bytes of an
exactly 32 GiB file through FILDES and INSTREAM, while `clamdscan --stream`
refused a regular 32 GiB + 1 file without sending a truncated prefix. The
repository now contains a repeatable real libmilter protocol test covering
clean, infected, exact-limit, and limit-plus-one messages. The candidate is
now a stronger review candidate for the bounded sparse raw-file path, but it
is not yet production-certified: a follow-up working-tree change now bounds
the mail parser's retained line list at 64 MiB and returns a visible
`Heuristics.Limits.Exceeded.MailMaterialization` result instead of growing with
the complete wire. This is safe fail-visible mail handling rather than full
deep-parser support for multi-gigabyte mail bodies; production
CVD/custom-database, deep-parser, materialized/cold-cache workloads, and
GitHub runner provenance also remain to be completed.

## 1. Candidate and test environment

The final validation was performed on the real `sonic1` Ubuntu Linux x86-64
host through MCP-SSH. Docker was used to isolate the build and runtime tests;
no ClamAV system service or production socket was modified.

During host preparation, the MCP-SSH connection and a non-destructive sudo
operation were verified, Docker Engine was installed on `sonic1`, and the
exact candidate source was synchronized into `/workspace/ClamAV`. No software
was installed on the macOS development machine. The later validation used
only the dedicated Docker environment and private test paths under `/work`.

| Item | Value |
|---|---|
| Repository | `NeonGameStudios/ClamAV-32gb` |
| Source commit | `5becea1236d466ee21f9bd5d3bcd0595ebc1460b` |
| Source state recorded by gates | Clean |
| ClamAV version | `1.5.3-largefile-devel` |
| Platform | Ubuntu Linux, x86-64 |
| Host memory reported by preflight | 65,234,452 KiB |
| Docker version | Client/Server 29.1.3 |
| Test container | `clamav-32gb-final-f08c7b0` |
| Container `/work` host bind | `/home/camera/clamav-32gb-work-f08c7b0` |
| Container `/workspace/ClamAV` host bind | `/home/camera/ClamAV-32gb-f08c7b0` (read-only) |
| Final runtime-gate cgroup limit | 56 GiB |
| Scan deadline | 900,000 ms |
| Configured sum-of-worker-peaks RSS budget | 33,554,432 KiB |
| Required effective-memory floor | 50,331,648 KiB (48 GiB) |

The Release build directory retained the earlier milestone name
`/work/build-release-f08c7b0`, but the runtime evidence records the final clean
source commit and scanner hash. The fresh sanitizer build was configured and
built at `/work/build-sanitizer-5becea1`.

Unless explicitly called a host path, every `/work/...` and
`/workspace/ClamAV/...` path below is written from the container's point of
view. A reviewer working directly on `sonic1` can find the preserved evidence
under `/home/camera/clamav-32gb-work-f08c7b0/evidence`.

## 2. Work completed

### 2.1 Native 64-bit scan coordinates

- Widened native matcher offsets, ranges, exact-size hash keys, logical
  signature file-size ranges, cache sizes, scan statistics, and public scan
  counters where the format and ABI permit it.
- Replaced the Boyer-Moore offset sort's accidental 32-bit comparator with an
  explicit overflow-safe 64-bit comparator.
- Introduced true 64-bit native offset sentinels and guarded the legacy
  32-bit bytecode bridge against reserved-value collisions and file-size
  truncation.
- Corrected window-local versus absolute byte-comparison coordinates and
  de-duplicated matches across overlapping scan windows.
- Added boundary coverage around 2 GiB, 4 GiB - 2, 4 GiB - 1, 4 GiB,
  4 GiB + 1, 8 GiB, 16 GiB, and the exact 32 GiB edge.

### 2.2 Bounded memory and I/O behavior

- Reworked fmap aging to use persistent bounded cursors and release budgets
  instead of rescanning the full page bitmap on every window.
- Made fmap read failures fail visibly and roll back page/accounting state so
  a partial read cannot be treated as clean EOF or cached as clean.
- Removed or capped audited whole-map/whole-member materialization paths and
  converted supported paths to bounded reads.
- Widened cache and telemetry file sizes and synchronized the checked-in Rust
  FFI layouts with C, including field-offset assertions that catch tail-field
  drift hidden by padding.
- Made deprecated contiguous callbacks and parsers fail visibly above their
  explicit supported caps rather than attempting to page an entire 32 GiB
  object into memory.

### 2.3 Fail-visible policy and result precedence

- Preserved specific `MaxFileSize`, `MaxScanSize`, `MaxFiles`, and
  `MaxRecursion` outcomes, including exact-limit versus next-byte/item tests.
- Separated callback cancellation from real scan timeout state so `CL_BREAK`
  is not misreported as `CL_ETIMEOUT`.
- Preserved detection, critical error, timeout, configured-limit, and generic
  incomplete precedence through nested scans and deferred alert callbacks.
- Allowed enclosing containers to continue scanning independent siblings
  after a nested recursion-limit skip, while restoring the exact fail-visible
  result at the root if no stronger detection occurs.
- Rejected `clamdscan --stream` truncation instead of ending a deliberately
  shortened stream with a normal zero-length terminator.
- Widened and checked milter cumulative quota arithmetic; exact limits are
  accepted, crossings and integer overflow are rejected, and a partial stream
  is not submitted as complete.

### 2.4 ZIP and archive handling

- Implemented bounded input for ZIP Stored, Deflate, Deflate64, BZIP2,
  Implode, and traditional ZipCrypto paths.
- Required decoder terminal state, declared-input exhaustion, exact output
  size, bounded progress, time checks, and exact callback-result propagation.
- Promoted ZIP64 member sizes and offsets through checked native-width paths.
- Made masked headers, unsupported strong encryption, unsupported methods,
  local-only data descriptors without authoritative bounds, malformed ZIP64,
  and truncated streams incomplete/non-clean.
- Made `MaxFiles` inclusive: exactly N members are allowed; discovering N + 1
  scans the already validated prefix, preserves detections, and returns a
  visible limit result otherwise.
- Preserved valid split-ZIP prefix members for scanning while restoring the
  later truncation as an incomplete result.
- Hardened CAB/CHM extraction budgets, short writes, cleanup, and partial
  output so a truncated member is not scanned as complete.
- Re-ran the focused ZIP boundary suite from Sonic1 commit `938a196` under
  ASan/UBSan: `libclamav` passed 1/1 in 42.99 seconds, including exact-output
  and truncated-stream handling, unsupported strong-encryption/masked-header/
  data-descriptor/method rejection, and inclusive `MaxFiles` detection
  precedence. Checksummed evidence is preserved at
  `/work/evidence/zip-boundary-938a196-20260814`.

### 2.5 Other parser and trust-path hardening

The audit also corrected or bounded relevant paths in PE/AuthentiCode, UDF,
GPT, AutoIt, XAR, NSIS, EGG, DMG, InstallShield, PDF, XDP, HWPML, nested fmap,
mail, OLE2, icons, bytecode, and related container scanners. The recurring
policy is:

1. use checked native-width arithmetic and bounded I/O where practical;
2. require complete decoder/parser terminal state before scanning output as a
   complete child;
3. preserve malware and critical-result precedence; and
4. if a legacy ABI or intentionally capped parser cannot inspect the input,
   mark it incomplete and non-cacheable rather than returning clean.

Not every parser has full 32 GiB deep-analysis capability. Intentional
fail-visible caps and unsupported formats are listed under remaining work.

### 2.6 Test and release infrastructure

- Added a reproducible sparse boundary-corpus generator and a fail-closed POC
  that verifies detection, signature identity, marker identity, actual file
  size, and the exact engine offset.
- Added independent runtime-evidence verification, source guards, checksum
  manifests, build identity, cgroup-aware preflight, cancellation checks,
  exact 32 GiB + 1 rejection, and exact-edge 1/2/4-worker measurements.
- Fixed scanner paths, milter enablement, GNU-time requirements, evidence
  authenticity checks, sparse-corpus artifact exclusion, and deterministic
  concurrency evidence in CI tooling.
- The pending workflow change enables milter in the sanitizer configuration
  and excludes Valgrind and Rust from the C/C++ sanitizer CTest run. Valgrind
  runs against Release binaries; Rust sanitizer support would require a
  separate nightly-Rust design. Release Rust tests remain enabled separately.

## 3. Git milestone history

The validation branch contains these checkpoints after the previously
published `742a8a4` snapshot:

| Commit | Purpose |
|---|---|
| `d5b8392` | Fix x86-64 callback/timeout, split-ZIP, InstallShield, and runtime-evidence regressions. |
| `bba6811` | Export focused ZIP test seams only through the private test symbol namespace. |
| `f08c7b0` | Close configured-limit, callback, bounded-ZIP, sanitizer-alignment, and Rust-ABI blockers. |
| `712ce71` | Export configured-limit helpers privately for allocation-free tests. |
| `a017917` | Continue sibling scans after nested recursion limits while preserving a root limit result. |
| `6839072` | Keep the recursion-policy regression self-contained. |
| `12e3a71` | Preserve MaxFileSize specificity and malware-detection precedence through ALZ and recursion cases. |
| `5becea1` | Count expected fail-visible scan errors correctly in the clamscan test. |

Across these commits, 35 files changed relative to `742a8a4`, with 3,948
insertions and 2,399 deletions before this status-document update.

## 4. Build and ordinary test results

### 4.1 Release build and CTest

The Release build completed successfully. The ordinary non-Rust/non-Valgrind
CTest selection passed 10 of 10 in 93.11 seconds:

| Test | Result | Time |
|---|---:|---:|
| `libclamav` | Pass | 19.73 s |
| `largefile_poc_fail_closed` | Pass | 0.15 s |
| `largefile_source_guards` | Pass | 0.20 s |
| `largefile_runtime_evidence_check` | Pass | 0.44 s |
| `clamav_milter_quota` | Pass | 0.00 s |
| `clamscan` | Pass | 27.12 s |
| `clamd` | Pass | 25.54 s |
| `freshclam` | Pass | 17.41 s |
| `sigtool` | Pass | 1.31 s |
| `examples` | Pass | 1.20 s |

The underlying `check_clamav` result was:

```text
100%: Checks: 1284, Failures: 0, Errors: 0
```

Preserved logs:

- `/work/build-release-f08c7b0.log`
- `/work/ctest-release-ordinary-5becea1.log`
- `/work/ctest-release-ordinary-5becea1.exit` (`0`)
- `/work/build-release-f08c7b0/unit_tests/test.log`

### 4.2 Rust

The first CTest Rust invocation reported 52 passed and 11 failed because the
source checkout was deliberately mounted read-only and those 11 cdiff tests
create temporary files inside their package source directory. This was an
environmental write-location failure, not a logic failure.

An exact writable source copy at `/work/rust-source-5becea1` then passed:

```text
test result: ok. 63 passed; 0 failed; 0 ignored
```

This includes the new C/Rust layout assertions and configured-limit policy
coverage. Preserved logs are `/work/ctest-rust-5becea1.log` for the expected
read-only failure and `/work/cargo-rust-writable-5becea1.log` plus its exit
file (`0`) for the passing run.

### 4.3 Valgrind

All six Release Valgrind suites passed in 1,079.66 seconds:

| Suite | Result | Time |
|---|---:|---:|
| `libclamav_valgrind` | Pass | 340.43 s |
| `clamscan_valgrind` | Pass | 501.97 s |
| `clamd_valgrind` | Pass | 144.78 s |
| `freshclam_valgrind` | Pass | 46.29 s |
| `sigtool_valgrind` | Pass | 29.25 s |
| `examples_valgrind` | Pass | 16.93 s |

Preserved result: `/work/ctest-valgrind-5becea1.log` and exit file `0`.

### 4.4 Fresh ASan/UBSan build and CTest

A fresh `RelWithDebInfo` build completed with AddressSanitizer and
UndefinedBehaviorSanitizer enabled for C and C++, including static libraries,
examples, and milter. The ten compatible suites passed 10 of 10 in 121.19
seconds with leak detection and halt-on-error enabled:

| Test | Result | Time |
|---|---:|---:|
| `libclamav` | Pass | 31.79 s |
| `largefile_poc_fail_closed` | Pass | 0.19 s |
| `largefile_source_guards` | Pass | 0.33 s |
| `largefile_runtime_evidence_check` | Pass | 0.72 s |
| `clamav_milter_quota` | Pass | 0.02 s |
| `clamscan` | Pass | 43.67 s |
| `clamd` | Pass | 36.77 s |
| `freshclam` | Pass | 3.79 s |
| `sigtool` | Pass | 2.13 s |
| `examples` | Pass | 1.77 s |

No ASan, LeakSanitizer, UBSan, or `runtime error:` diagnostic was found in the
sanitizer runtime evidence logs. Preserved build/test logs:

- `/work/build-sanitizer-5becea1.log` and exit file `0`
- `/work/ctest-sanitizer-5becea1.log` and exit file `0`

## 5. Exact boundary runtime results

Two separate production-threshold gate runs passed:

- Release: `/work/evidence/runtime-5becea1-prod`
- ASan/UBSan: `/work/evidence/runtime-sanitizer-5becea1-prod`

Both gates exited `0`, and each evidence root passed the independent evidence
verifier with exit `0`. Each root records `host_preflight=pass`,
`largefile_poc=pass`,
`cancellation=pass status=124`, `policy_32g_plus_one=pass`, every requested
concurrency level as passed, and `runtime_gate=pass`. Each root has a
`SHA256SUMS` manifest and copied provenance inputs.

### 5.1 Boundary corpus

Every row detected its case-specific marker and signature, reported the exact
actual size, and reported an engine offset exactly equal to the expected
offset. The sanitizer gate repeated the same 11 cases a second time under
instrumentation with identical offsets.

| Case | Expected engine offset | File size | Release | Sanitizer |
|---|---:|---:|---:|---:|
| `2g-minus` | 2,147,483,647 | 2,147,483,711 | Pass | Pass |
| `2g` | 2,147,483,648 | 2,147,483,712 | Pass | Pass |
| `2g-plus` | 2,147,483,649 | 2,147,483,713 | Pass | Pass |
| `4g-minus-two` | 4,294,967,294 | 4,294,967,358 | Pass | Pass |
| `4g-minus` | 4,294,967,295 | 4,294,967,359 | Pass | Pass |
| `4g` | 4,294,967,296 | 4,294,967,360 | Pass | Pass |
| `4g-plus` | 4,294,967,297 | 4,294,967,361 | Pass | Pass |
| `8g` | 8,589,934,592 | 8,589,934,656 | Pass | Pass |
| `16g` | 17,179,869,184 | 17,179,869,248 | Pass | Pass |
| `32g-head` | 4,096 | 34,359,738,368 | Pass | Pass |
| `32g-edge` | 34,359,738,304 | 34,359,738,368 | Pass | Pass |

The exact 32 GiB file is 34,359,738,368 bytes. The edge marker begins in the
file's final 64 bytes at offset 34,359,738,304.

Primary results:

- `runtime-5becea1-prod/poc/results.tsv`
- `runtime-sanitizer-5becea1-prod/poc/results.tsv`
- `runtime-sanitizer-5becea1-prod/sanitizer/results.tsv`

### 5.2 32 GiB + 1 and cancellation

The policy fixture is 34,359,738,369 bytes. Both gate logs contained these
result substrings (the complete lines also include ClamAV prefixes and the
fixture path):

```text
Scan incomplete: Heuristics.Limits.Exceeded.MaxFileSize
Heuristics.Limits.Exceeded.MaxFileSize FOUND
```

This is a visible limit result rather than an apparently clean prefix scan.
The cancellation test returned GNU timeout status 124 in both gates.

### 5.3 Concurrent exact-edge scans

Every worker independently found the tail-only
`LargeFile.POC.32g-edge.UNOFFICIAL` signature while scanning
`32g-edge.bin`. The POC rows separately prove its exact engine offset. The
sum of worker peak RSS values stayed far below the 32 GiB evidence budget.

| Build | Workers | Per-worker elapsed/peak RSS | Sum of worker peak RSS |
|---|---:|---|---:|
| Release | 1 | `1:53.92`, 100,948 KiB | 100,948 KiB |
| Release | 2 | `1:52.49`, 100,872 KiB; `1:52.42`, 101,064 KiB | 201,936 KiB |
| Release | 4 | `1:54.13`, 100,772 KiB; `1:55.09`, 100,740 KiB; `1:54.91`, 101,064 KiB; `1:54.91`, 100,968 KiB | 403,544 KiB |
| ASan/UBSan | 1 | `3:37.01`, 136,016 KiB | 136,016 KiB |
| ASan/UBSan | 2 | `3:33.69`, 136,164 KiB; `3:33.87`, 135,856 KiB | 272,020 KiB |
| ASan/UBSan | 4 | `3:35.72`, 135,788 KiB; `3:35.56`, 136,068 KiB; `3:35.68`, 136,044 KiB; `3:35.61`, 136,072 KiB | 543,972 KiB |

The release gate's effective available-memory measurement was 54,265,620 KiB;
the sanitizer gate measured 58,677,480 KiB. No OOM or OOM-kill occurred.
Repeated sparse reads did create substantial Linux page cache and exercised
cgroup reclaim. More RAM can improve cache retention and throughput, but the
scanner's measured per-process peak RSS did not grow with the 32 GiB file
size.

### 5.4 Evidence identity

| Artifact | SHA-256 |
|---|---|
| Release `clamscan` | `70556e120476a7690c6c3b2c691ee2d8ee9fed3ef7fd1a95914578015e29b4c9` |
| Sanitizer `clamscan` | `a57cf06095f53d0caba097ae15e90492c697b1e26cdf106b3c304fa84beddbc6` |
| `Cargo.lock` | `82622be89f5d5060b991c8b590691d0945586644b5a0395c53633e996bf5cf8a` |
| Release CMake cache | `db9ce47583d86dd76749cdc9caf3d2f93eb0bf31ac2a30474af137051f9e5860` |
| Sanitizer CMake cache | `0ae5ac4b21b2e229c45686d7c387bd3812cfb54a60ed387bbb2076c76fba1940` |

## 6. Private clamd protocol validation

Evidence is preserved at `/work/evidence/clamd-protocol-5becea1`.

### 6.1 Isolation and configuration

The daemon used only:

- private Unix socket `/work/c5.sock`;
- private PID file `/work/c5.pid`;
- evidence-local signature, temporary, and log directories;
- one scan thread and a queue of four; and
- `MaxFileSize`, `MaxScanSize`, and `StreamMaxLength` all set to exactly 32 GiB.

There was no TCP listener and no system-service change. The exact binaries
were:

| Binary | SHA-256 |
|---|---|
| `clamd` | `b861df9ccc7bb90429878e0bcb2497467d24d85890da85f7e697972cc52a8f0f` |
| `clamdscan` | `da3efa26935004ced27dc5dd422ae20433e5b0a4d483d946be5bd79695582112` |

The first private startup failed because the image's default CVD certificate
directory `/usr/local/etc/certs` did not exist. The failure was preserved in
`logs/failed-start-*`. Relaunching with the repository's test certificate
directory succeeded; `logs/readiness.txt` records the ready daemon.

### 6.2 End-of-file detection oracle

The private database contains only this marker signature:

```text
LargeFile.ProtocolTail:0:*:434c414d41562d4c462d3332472d4544474500
```

It represents `CLAMAV-LF-32G-EDGE` followed by NUL. An independent read of the
last 64 bytes verified that exact byte sequence begins at offset
34,359,738,304 and is followed by zeros to EOF. Therefore a detection at that
offset proves the scan reached the end of the exact 32 GiB input; an early
prefix cannot satisfy this oracle.

### 6.3 32 GiB + 1 stream refusal

`clamdscan --stream` was invoked on a regular 34,359,738,369-byte file. It
returned exit 2 immediately with:

```text
File size exceeds StreamMaxLength; refusing to send a truncated stream. ERROR
```

There was no `FOUND`, no `OK`, no daemon INSTREAM command, and no daemon
temporary file. Client peak RSS was 8,228 KiB. This validates the client-side
fix for the former silent-prefix behavior.

### 6.4 Exact 32 GiB FILDES scan

The exact-edge FILDES scan returned exit 1 and:

```text
/work/evidence/runtime-5becea1-prod/corpus/32g-edge.bin: LargeFile.ProtocolTail.UNOFFICIAL FOUND
```

The daemon debug log recorded:

```text
signature LargeFile.ProtocolTail.UNOFFICIAL matched at 34359738304
```

The client elapsed time was 2:13.61 with 6,684 KiB peak RSS. The daemon's
VmHWM rose from 15,056 KiB before the scan to 96,584 KiB after it; post-scan
VmRSS was 9,832 KiB. The private daemon was then sent SIGTERM after validating
its exact PID and command line; it stopped, its PID and socket were removed,
and no matching process remained active.

An aligned final-commit ASan/UBSan private daemon then repeated the exact-edge
FILDES path through the freshly built `clamdscan --fdpass` client. The isolated
daemon used `MaxFileSize 32G`, `MaxScanSize 32G`, `StreamMaxLength 32G`, and
`MaxScanTime 900000`; it found `FinalClamd.Edge32.UNOFFICIAL` at offset
34,359,738,350 in the 34,359,738,368-byte fixture, returned the expected exit
1 in 220.694 seconds, and shut down with exit 0. Peak daemon RSS was 131,640
KiB, aggregate minor faults were 34,586,408, and major faults were zero. The
client stderr was empty, no ASan/UBSan/runtime diagnostic was emitted, and the
generated input, socket, PID, and temporary directory were removed. This is
final-commit sanitizer protocol evidence using a private marker database, not
production-CVD qualification. Compact evidence is preserved at
`/work/evidence/clamd-protocol-final-sanitizer-20260814`.

Primary evidence:

- `logs/fdpass.exit`, `logs/fdpass.out`, `logs/fdpass.err`, `logs/fdpass.time`
- `logs/clamd.log`, `logs/clamd.stderr`
- `logs/daemon-before-fdpass.status`, `logs/daemon-after-fdpass.status`
- `logs/stream-plus-one.*`
- `logs/shutdown.txt`

A higher-concurrency native FILDES follow-up then used the protocol framing
implemented by `common/clamdcom.c` (`zFILDES` followed by a one-byte ancillary
message) with `MaxThreads 8` and `MaxQueue 16`. Eight barrier-synchronized
sparse files were each exactly 34,359,738,368 bytes, with the marker beginning
at offset 34,359,738,348. All eight workers returned exit 0 and
`Fildes.Thread8.UNOFFICIAL FOUND`; normalized response hashes were identical.
The first worker started at the same barrier within 4 ms, and the last worker
finished 354,352 ms later. Peak clamd RSS was 620,836 KiB with 10 observed
daemon threads, minimum available space was 63,865,294,848 bytes, and the
temporary directory stayed at 4,096 bytes. The eight sparse inputs were
removed after their exact-size/marker metadata was preserved. This extends
exact-edge FILDES coverage to eight concurrent workers in a test-only custom
database; it is not production-CVD qualification. Compact evidence is
preserved at `/work/evidence/fildes-thread8-zfildes-20260814`. An initial
malformed native probe using the wrong command framing is retained separately
as a diagnostic at `/work/evidence/fildes-thread8-20260814` and is not counted
as a scan result.

A repeat of that eight-worker exact-edge run added an aggregate
`/proc/<pid>/task/*/stat` resource sample. The same eight 34,359,738,368-byte
files again reached the tail marker through the corrected `zFILDES` framing in
352,817 ms; all eight raw responses contained
`Fildes.Thread8.PF.UNOFFICIAL.UNOFFICIAL FOUND`, and their normalized response
hashes were identical. Peak clamd RSS was 622,096 KiB with 10 observed daemon
threads, minimum available space was 63,864,815,616 bytes, and temporary usage
remained zero. The sampled aggregate counters rose by 268,594,526 minor page
faults and zero major page faults. The NDB fixture already included the
`.UNOFFICIAL` suffix, so the worker's initial result rows were reclassified
only after validating the raw responses; that validator-only mismatch is
preserved in the evidence directory. Compact evidence is preserved at
`/work/evidence/fildes-thread8-pf2-20260814`.

### 6.5 Exact-edge INSTREAM follow-up

An isolated follow-up used the same 32 GiB-aware Release binaries and the
private tail-marker database, but sent the exact-edge sparse file through
`clamdscan --stream`. The daemon log recorded quota remaining at zero,
completed all chunks, and returned:

```text
instream(local): LargeFile.ProtocolTail.UNOFFICIAL FOUND
```

The stream client received the same `FOUND` verdict and the exact-edge
temporary directory was empty after shutdown. The daemon PID and socket were
removed and no clamd or clamdscan process remained. The preserved follow-up
directory is `/work/evidence/clamd-instream-5becea1` (host path
`/home/camera/clamav-32gb-work-f08c7b0/evidence/clamd-instream-5becea1`). Its
raw debug log is intentionally retained for auditability and is approximately
3.1 GiB; this is evidence storage, not scanner RSS.

An aligned final-commit ASan/UBSan private daemon then repeated the exact-edge
INSTREAM path with explicit 32 GiB `StreamMaxLength` settings in both the
daemon and client configurations. The 34,359,738,368-byte sparse input carried
`CLAMAV-CLAMD-EDGE` followed by NUL at offset 34,359,738,350, and
`clamdscan --stream` returned `FinalClamd.Instream32.UNOFFICIAL FOUND` with
exit 1 while the daemon exited 0. The scan took 292.151 seconds (292.188
seconds including the harness); maximum temporary usage was 34,359,750,656
bytes, minimum available space was 20,972,945,408 bytes, peak daemon RSS was
125,580 KiB, aggregate minor faults increased by 17,865,016, and the maximum
major-fault count was 114. Client stderr was empty, no ASan/UBSan/runtime
diagnostic was emitted, and the generated input, socket, PID, and temporary
directory were removed. Compact evidence is preserved at
`/work/evidence/clamd-instream-final-sanitizer-20260814-retry4`. This is
final-commit sanitizer protocol evidence using a private marker database, not
production-CVD qualification.

### 6.6 Real libmilter protocol follow-up

`unit_tests/milter_protocol_test.py` now launches temporary clamd and
clamav-milter instances, speaks the version-6 libmilter wire protocol, and
cleans up both processes and sockets. CMake registers it as
`clamav_milter_protocol` when `ENABLE_APP`, `ENABLE_MILTER`, and POSIX support
are present. The test uses a 256-byte wire limit deliberately so it remains a
fast regression test; the allocation-free `clamav_milter_quota` test retains
the exact 4 GiB, exact 32 GiB, 32 GiB + 1, and uint64-overflow boundaries.

On Sonic1, CTest reconfiguration succeeded and the paired quota/protocol run
passed 2 of 2:

```text
clamav_milter_quota       Passed  0.01 sec
clamav_milter_protocol    Passed  5.40 sec
```

The same four cases also passed with `MILTER_EXTRA_DATABASE` pointed at the
complete available repository test-signature directory
`/work/rust-source-5becea1/unit_tests/input`. This optional input exercises the
milter lifecycle with the representative `.hdb`, `.ndb`, `.pdb`, and ALZ test
signatures while leaving the default CTest fixture deterministic.

The protocol evidence is preserved at `/work/evidence/milter-protocol-5becea1`
(host path `/home/camera/clamav-32gb-work-f08c7b0/evidence/milter-protocol-5becea1`).
This proves framing, verdict propagation, exact-limit acceptance, over-limit
fail-closed behavior, and connection lifecycle for a small wire fixture; it
does not prove a literal 4 GiB or 32 GiB milter transfer.

### 6.7 Fully allocated exact-edge FILDES follow-up

The isolated Release daemon was also tested with a fully allocated, rather
than sparse, file whose exact size was 34,359,738,368 bytes. The file was
confirmed allocated (`stat` reported 67,108,880 blocks; `du` reported
34,359,746,560 bytes), and the private database contained the tail-marker
signature plus the available repository `.hdb`, `.ndb`, `.pdb`, and ALZ test
signatures. `clamdscan --fdpass` returned exit 1 as expected for a detection:

```text
/work/evidence/materialized-fildes-5becea1/corpus/32g-materialized.bin: LargeFile.ProtocolTail.UNOFFICIAL FOUND
```

The daemon log recorded the same `FOUND` verdict. The RSS monitor recorded a
93,064 KiB VmHWM and 91,880 KiB peak VmRSS; this is consistent with bounded
daemon memory rather than a 32 GiB allocation. After SIGTERM, the daemon
process, PID file, socket, and temporary files were absent. Compact metadata
and logs are preserved at `/work/evidence/materialized-fildes-5becea1`
(host path `/home/camera/clamav-32gb-work-f08c7b0/evidence/materialized-fildes-5becea1`).
The generated 32 GiB fixture was removed after verification to reclaim Sonic1
disk space; the evidence database is test-only and is not an official
production CVD.

### 6.8 Literal milter wire and mail-parser boundary

The protocol harness has an opt-in manual mode (`MILTER_EXACT_EDGE=1`) that
streams fixed 32 KiB libmilter body packets and does not enlarge the default
CTest. On Sonic1 it delivered exactly 34,359,738,316 body bytes and an exact
34,359,738,368-byte message, including the tail marker. The EOM verdict did
not complete: clamd entered the mail/text path, grew to approximately 16 GiB
RSS, and was stopped before host memory pressure became unsafe. The preserved
clamd log records a `cli_max_malloc()` request for a roughly 32 GiB text blob
and `Couldn't grow the blob`.

A bounded 4 GiB nonzero milter-wire run reproduced the same behavior at
approximately 2.9 GiB clamd RSS. A separate fully materialized 4,294,967,346-
byte mail-shaped FILDES file, beginning with the same `From`/`Subject` form
but bypassing milter entirely, reached 4,619,712 KiB RSS before being stopped;
its log recorded the same blob-growth warning. In contrast, the raw
4,294,967,296-byte nonzero FILDES file completed with the tail signature and
returned to baseline memory. This isolates the current gap to the
mail-shaped parser/materialization path, not Unix FD passing itself.

Evidence is preserved under `/work/evidence/milter-wire-exact-4-5becea1`,
`/work/evidence/milter-wire-4g-z-5becea1`, and
`/work/evidence/mail-shaped-4g-z-5becea1` (host bind
`/home/camera/clamav-32gb-work-f08c7b0/evidence`). The generated 4 GiB
mail-shaped fixture was removed after the follow-up comparison; its compact
logs and RSS metadata remain in the evidence roots.

### 6.9 Bounded mail materialization follow-up

The follow-up working-tree change adds a 64 MiB cap to the internal
`messageAddStr()` line-list representation and propagates truncation through
the mail parser as `CL_EMAXSIZE` with the explicit
`Heuristics.Limits.Exceeded.MailMaterialization` indicator. It also retains the
fmap `fmap_gets()` page-release fix, so line-oriented reads do not wait for the
normal aging high-water mark before releasing copied pages.

On Sonic1, the synchronized Release build passed the full `libclamav` CTest
selection and the focused fmap regression. A fully materialized
4,294,967,346-byte mail-shaped FILDES input returned the explicit
materialization indicator in 0.701 seconds with a 17,516 KiB daemon peak RSS.
The prior equivalent run peaked at 4,619,712 KiB, providing a direct
before/after memory-boundary result.

The real libmilter harness then delivered exactly 4,294,967,296 message bytes
with 32 KiB body packets and returned `result=r`; clamd logged the same
materialization indicator and no temporary file remained. The exact-edge
libmilter run delivered 34,359,738,316 body bytes and an exact
34,359,738,368-byte message, returned `result=r`, logged the same bounded
indicator, and left no temporary file or live daemon. Evidence is preserved at
`/work/evidence/mail-shaped-4g-z-cap-5becea1`,
`/work/evidence/milter-wire-4g-cap-5becea1`, and
`/work/evidence/milter-wire-exact-cap2-5becea1`.

To recheck the exact wire boundary against the current Release binaries with
the complete available repository signature corpus, the local working-tree
`milter_protocol_test.py` harness was transferred into an isolated evidence
directory (SHA-256
`878d5ffa21783624ad64d25237a53cb19fc485872c1626c8a92c7903bab85f10`). It sent
exactly 34,359,738,316 body bytes for a 34,359,738,368-byte message in 2:02.27,
returned `result=r`, and clamd logged
`Heuristics.Limits.Exceeded.MailMaterialization` with 22,708 KiB maximum
resident set size. The runtime temporary directory returned to 4,096 bytes,
all daemon processes exited, and evidence hashes verified at
`/work/evidence/milter-working-tree-harness-20260814`. This is a
working-tree-only runtime result: committed `5becea1` does not contain that
harness, so it is not a clean-checkout CTest qualification.

A corrected rebuilt Release run also scanned a 67,109,060-byte Unix mbox
fixture containing a later second message. It returned
`Heuristics.Limits.Exceeded.MailMaterialization` in 4.71 seconds with an
8,144 KiB RSS peak, confirming that the bounded result remains fail-visible
for mbox-shaped input rather than becoming clean after the later-message
boundary. Its compact evidence is under
`/work/evidence/mail-mbox-multi-cap-5becea1`.

The unit suite now also includes public-API regressions for
`test_mbox_materialization_limit_is_fail_visible`,
`test_mbox_materialization_limit_without_alert_is_fail_visible`, and
`test_single_message_materialization_limit_is_fail_visible`, and
`test_single_message_materialization_limit_without_alert_is_fail_visible`.
Each constructs
a bounded oversized mail fixture and exercises `cl_scanfile_ex()`; the
alert-enabled cases assert the named limit indicator, while both no-alert cases
assert `CL_EMAXSIZE`, `CL_VERDICT_NOTHING_FOUND`, and a null alert so the
bounded failure cannot become clean when heuristic alerts are disabled. The
single-message cases begin with a recognized `Date:` mail header so they
exercise the ordinary single-message parser route rather than the generic text
scanner. The latest corrected Sonic1 Release build passed the complete
`libclamav` CTest entry, including all four regressions, in 26.98 seconds.
Compact evidence is preserved at
`/work/evidence/mail-parser-single-no-alert-5becea1`.

An aligned Sonic1 ASan/UBSan checkout then rebuilt the same current source
paths and passed its complete `libclamav` CTest entry in 43.12 seconds. The
Check log explicitly records all four mail regressions as `Passed`, and the
sanitizer stderr log contains no AddressSanitizer, UndefinedBehaviorSanitizer,
or runtime-error diagnostic. Compact evidence is preserved at
`/work/evidence/mail-parser-single-no-alert-sanitizer-5becea1`.

That sanitizer build also exposed an enum mismatch in `libclamav/mbox.c`: the
unexpected MIME-subtype path was assigning the public `CL_EFORMAT` value to
the parser's internal `mbox_status`. It now returns the internal `FAIL` value,
which the caller maps to `CL_EFORMAT`; this preserves the format failure while
removing the sanitizer enum-conversion defect.

The same Release build also passed the remaining six non-Valgrind core CTest
targets—milter quota, clamscan, clamd, freshclam, sigtool, and examples—in
82.58 seconds. These tests exercised the repository's existing signature and
parser fixtures, including daemon and updater paths; they do not substitute
for a full production CVD or custom-database qualification. Compact evidence
is preserved at `/work/evidence/release-core-suite-5becea1`.

Finally, the targeted Release `libclamav_valgrind` CTest entry passed in
352.91 seconds with all 1,288 checks passing and no failures or errors. Its
pass records include the four mail-materialization regressions, and no
Valgrind, AddressSanitizer, UndefinedBehaviorSanitizer, or runtime-error
diagnostic pattern was found in the preserved check/evidence logs. Compact
evidence is preserved at
`/work/evidence/libclamav-valgrind-followup-5becea1`.

As a separate cold-read workload, the Release `clamscan` binary scanned the
9.7 MiB generated parser corpus using the repository's signature and
certificate fixtures. After one host page-cache drop, the cold pass returned
the expected non-clean status with 51 detections, 2 clean fixtures, no scanner
errors, an intentional `Heuristics.Limits.Exceeded.MaxRecursion` warning,
221 major page faults, and a 29,860 KiB peak RSS in 0.64 seconds. An immediate
hot-cache repeat returned the same exit status and byte-identical scan output,
with 0 major page faults, 30,040 KiB peak RSS, and 0.59 seconds. This is
fixture-based parser and cache behavior evidence, not a production-CVD
qualification. Compact evidence is preserved at
`/work/evidence/parser-corpus-cold-hot-5becea1`.

The Release `clamscan` binary then scanned a separate exact-edge sparse file
with the repository's broader `other_sigs` fixtures, `bytecode.cvd`, and a
private tail-marker signature. The standalone client was invoked with explicit
`--max-filesize=32G --max-scansize=32G` limits; a control invocation without
those options stopped at its default `Exceeded max scan size` guard before
reading the marker. With the explicit policy, the 34,359,738,368-byte file
returned the expected exit 1 and `LargeDB.Edge32.UNOFFICIAL FOUND` in 118.063
seconds. The marker began at offset 34,359,738,349, the sparse fixture used
4,096 physical bytes, peak scanner RSS was 107,880 KiB, aggregate minor faults
were 33,326,633, and major faults were zero. The generated input was removed
after the logs and compact metadata were preserved. This is broader
repository-database evidence, not production-CVD qualification. Compact
evidence is preserved at
`/work/evidence/large-db-edge-clamscan-20260814-explicit3`.

An aligned ASan/UBSan `clamscan` build from the same `5becea1` source commit
then repeated the broader exact-edge test with the same repository fixtures and
explicit `--max-filesize=32G --max-scansize=32G` policy. The first invocation
also demonstrated that the sanitizer binary's default 120-second per-file
deadline is too short for this workload: it stopped at 121.093 seconds with
`Heuristics.Limits.Exceeded.MaxScanTime` and no sanitizer diagnostic. With the
runtime gate's explicit `--max-scantime=900000`, the exact 34,359,738,368-byte
file reached the marker at offset 34,359,738,349 and returned the expected exit
1 and `LargeDB.Edge32.UNOFFICIAL FOUND` in 221.154 seconds. Peak scanner RSS
was 164,260 KiB, aggregate minor faults were 34,578,820, major faults were
zero, stderr was empty, and the generated input and temporary directory were
empty after the scan. This is final-commit sanitizer evidence for the broader
repository database, not production-CVD qualification. Compact evidence is
preserved at
`/work/evidence/large-db-edge-clamscan-sanitizer-5becea1-retry900s`.

An isolated clamd stress pass then overlapped 24 parser-corpus scans across
four workers with 12 database reloads. All 24 scans returned the expected
detection status, all 12 reload commands succeeded, and a final probe found a
signature added during the reload loop. No connection, daemon, or sanitizer
diagnostic was emitted. This exercises reload overlap with active parser work
using repository fixtures; it does not replace production-database
qualification. Compact evidence is preserved at
`/work/evidence/clamd-reload-stress-5becea1`.

### 6.9 INSTREAM temporary-disk characterization

A fresh isolated one-thread Release daemon measured native INSTREAM staging
with the same exact 32 GiB limits and private marker database. Throttled
zero-filled streams returned `stream: OK` at 64 MiB, 256 MiB, and 1 GiB; the
evidence-local temporary directory peaked at exactly 67,108,864,
268,435,456, and 1,073,741,824 bytes respectively. The daemon's peak RSS
remained 23,924/24,440/25,976 KiB for those cases. After each scan the
temporary file was removed.

The same daemon received a 65,368-byte deflated ZIP whose one member expanded
to 64 MiB. It returned `stream: OK`, and temporary usage peaked at 67,174,232
bytes—the staged stream plus the expanded member—while daemon peak RSS reached
25,976 KiB. The temporary directory was empty after shutdown. This establishes
that a 32 GiB INSTREAM deployment needs roughly 32 GiB of temporary disk before
any additional expansion, parser scratch, or concurrent-worker overhead. The
measurement uses a tiny test database and one worker, so it is a resource
characterization rather than production capacity qualification. Compact
evidence is preserved at
`/work/evidence/instream-temp-direct3-20260814`.

The preliminary `clamdscan --stream` harness also demonstrated that the client
side refuses files above its configured stream limit before opening an INSTREAM
command when `StreamMaxLength` is omitted from the client config. That control
finding is preserved at `/work/evidence/instream-temp-matrix-20260814`; the
successful resource measurement used the daemon protocol directly to avoid
confounding client-side preflight behavior.

A four-worker follow-up streamed four 1 GiB inputs concurrently through a
`MaxThreads 4` daemon. All four replies were `stream: OK` with identical
response hashes. Aggregate temporary files reached exactly 4,294,967,296
bytes; `du` reported 4,294,971,392 bytes including the 4,096-byte temporary
directory itself. Minimum available space remained 59,572,260,864 bytes, and
daemon peak RSS/HWM were 53,960/54,088 KiB. The temporary directory was empty
after shutdown. This confirms additive INSTREAM staging across workers in the
isolated test configuration, not production-CVD capacity. Compact evidence is
preserved at
`/work/evidence/instream-temp-concurrent4-exact-20260814`.

An isolated Release daemon then extended the same native INSTREAM check to
`MaxThreads 8` and `MaxQueue 16`, retaining exact 32 GiB `MaxFileSize`,
`MaxScanSize`, and `StreamMaxLength` limits. Eight barrier-synchronized clients
each sent exactly 268,435,456 bytes and all returned the identical
`Thread8.Instream.UNOFFICIAL FOUND` response. Aggregate temporary usage reached
2,147,487,744 bytes—eight 256 MiB payloads plus the 4,096-byte directory
overhead—while minimum available space remained 61,718,388,736 bytes. Peak
clamd RSS was 104,552 KiB and the largest observed daemon thread count was 10;
the temporary directory, private socket, and PID file were clean after
shutdown. This advances higher-worker-count INSTREAM coverage in the isolated
custom-database configuration, not production-CVD qualification. Compact
evidence is preserved at
`/work/evidence/instream-thread8-certs-20260814`.

A separate isolated Release daemon then overlapped four throttled 256 MiB
native INSTREAM streams with 12 `clamdscan --reload` operations against a
representative custom database. All four stream clients returned exit 0 and
identical response hashes; all 12 reloads returned exit 0. The baseline probe
was clean, while the final probe after the reload loop returned
`ClamAV-RELOAD-TestFile.UNOFFICIAL FOUND`. Aggregate temporary usage peaked at
1,073,745,920 bytes (four 256 MiB payloads plus directory overhead), minimum
available space was 62,793,293,824 bytes, and daemon peak RSS/HWM were
46,840/48,892 KiB. The temporary directory was empty after shutdown and the
daemon logged each reload as a successful two-signature database load. This
qualifies reload overlap for the representative custom database only; it does
not replace production-CVD, production-thread-count, or expansion-heavy
qualification. Compact evidence is preserved at
`/work/evidence/clamd-instream-reload-concurrent-20260814`.

A higher-concurrency follow-up then set `ConcurrentDatabaseReload yes` and
overlapped eight exact-edge native FILDES scans with ten successful reloads at
15-second intervals. All eight 34,359,738,368-byte files reached the marker at
offset 34,359,738,348 in 180,079 ms; normalized response hashes were
identical, and the daemon log recorded eight detections plus ten successful
two-signature database loads. Peak clamd RSS was 582,648 KiB with 10 observed
threads, minimum available space was 63,864,504,320 bytes, temporary usage
remained zero, and the aggregate monitor's maximum major-fault count was 18.
A separate post-scan recovery daemon reloaded generation 12 and detected its
probe using NUL-framed `SCAN` handling. This is custom-database overlap
evidence, not production-CVD qualification. Compact evidence, including the
initial helper diagnostic, is preserved at
`/work/evidence/fildes-thread8-reload-20260814`.

As a further repository-fixture workload, the Release scanner then processed
46 archive and deep-parser inputs totaling 1.4 MiB with the checked-in
`other_sigs` database. Two repeated scans returned the expected detection
status `1`, each reported 22 detections, and produced identical output hashes.
The scans completed in 0.26/0.25 seconds with 32,072/32,184 KiB peak RSS and
zero major page faults. The only parser diagnostic was the expected
fail-visible warning for truncated ZIP member data. The aligned ASan/UBSan
scanner produced the same 22 detections and output hash in 0.58 seconds, with
160,172 KiB peak RSS, zero major page faults, and no sanitizer or runtime-error
diagnostic. Compact evidence is preserved at
`/work/evidence/deep-parser-fixture-matrix-certs-20260814` and
`/work/evidence/deep-parser-fixture-matrix-sanitizer-20260814`.

Because the preserved sanitizer matrix above was produced by the older
`/work/build-sanitizer-bba6811` binary, the same 46-file matrix was rerun with
the final-commit ASan/UBSan `clamscan` build. It again returned exit 1 with 22
detections and the same intentional truncated-ZIP warning. The fresh run
peaked at 103,884 KiB RSS, recorded 20,102 aggregate minor faults and a
maximum aggregate major-fault sample of 1, and retained no sanitizer or
runtime-error diagnostic. The output hash was
`fa8116c07c20867354b7f0f410bdb163f1039bd5015c4fc9214389b82737ecc1`; the
evidence-local temporary directory was empty afterward. Compact evidence is
preserved at
`/work/evidence/deep-parser-fixture-matrix-final-sanitizer-20260814`.

The same 46-file matrix was then rerun from cap commit `938a196` with the
current ASan/UBSan build. It again produced 22 detections and the one expected
fail-visible truncated-ZIP warning, returned exit 1, completed in 0.52 seconds,
and peaked at 158,876 KiB RSS with zero major faults, zero swaps, and no
sanitizer/runtime diagnostics. The output hash was
`fc8cf08eedec79549268bf553d0979dee2debde487861fffe4e4970fd0abedd0`;
checksummed evidence is preserved at
`/work/evidence/deep-parser-matrix-938a196-20260814`.

The first manual invocation of this matrix was intentionally retained as a
harness diagnostic: without `CVD_CERTS_DIR=/workspace/ClamAV/certs`, the
Release binary tried the absent `/usr/local/etc/certs` path and stopped before
scanning. The corrected rerun used the repository certificate directory;
failure evidence is preserved separately at
`/work/evidence/deep-parser-fixture-matrix-20260814`.

The same matrix was then rerun through a 13-file database combining the
repository's test CVDs, bytecode CVD, and existing test signatures. The CVD
database loaded successfully; all 46 inputs again produced 22 detections and
the same `fc8cf08eedec79549268bf553d0979dee2debde487861fffe4e4970fd0abedd0`
stdout hash, with the expected truncated-ZIP and
bytecode warnings. The ASan/UBSan run completed in 0.67 seconds at 207,128 KiB
RSS with no sanitizer diagnostics. This strengthens CVD-format test-database
coverage but is not production-CVD qualification: Sonic1 has no production
CVD set. Checksummed evidence and the explicit qualification note are
preserved at `/work/evidence/cvd-matrix-938a196-20260814-run2`; the manifest
verification returned status 0.

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

The same final-commit ASan/UBSan `clamd`/`clamdscan --fdpass` path was then
checked against that CVD-format test database plus a private tail-marker NDB.
A zero-tail 34,359,738,368-byte exact-edge control returned `OK`/exit 0 in
465.285 seconds; a separate sparse fixture with `CLAMAV-CLAMD-EDGE\0` at
offset 34,359,738,350 returned `FinalClamd.Edge32.UNOFFICIAL FOUND`/exit 1
in 252.652 seconds. The daemon ran with 32-GiB file, scan, and stream limits;
no ASan/UBSan diagnostics appeared, and shutdown left no socket, PID, or
temporary files. This is CVD-format test-database plus private-marker evidence
only, not production-CVD qualification. Checksummed evidence is preserved at
`/work/evidence/cvd-clamd-exact-edge-938a196-20260814-run2` and
`/work/evidence/cvd-clamd-marker-edge-938a196-20260814-run1`.

A current source-level ASan/UBSan audit of clean commit `938a196` then reran
the valid non-Valgrind CTest subset: all 10 entries passed in 129.22 seconds,
including `libclamav`, the three large-file guard checks, both milter tests,
`clamscan`, `clamd`, `freshclam`, and `sigtool`. No sanitizer diagnostics were
observed. The complete-inventory attempt from the ASan build was retained only
as a toolchain diagnostic because its Valgrind/Rust entries were not valid under
the mixed ASan environment. A separate Release inventory passed all 16
non-Rust entries; its sole failure was 11 Rust temp-file cases against a
read-only source mount (52 Rust cases passed). These environment results do
not change the existing writable-checkout Rust evidence or close production-CVD
qualification. Checksummed evidence is preserved at
`/work/evidence/ctest-sanitizer-selected-938a196-20260814-run1` and
`/work/evidence/ctest-release-all-938a196-20260814-run1`.

The Rust entry was then rerun from a correctly structured, writable source
copy of implementation commit `5becea1` against the existing Release static
artifacts. All 63 integrated Rust tests passed (`0` failed), with no test
failures or sanitizer diagnostics; the checksum manifest returned status 0.
The earlier 52-pass/11-failure result is retained as the read-only-mount
diagnostic described above. The corrected result is preserved at
`/work/evidence/rust-release-writable-938a196-20260814-run3`.

A real nested-ZIP `MaxScanSize` probe then exercised the public Release
`clamscan` path. With the marker in a later child and `AlertExceedsMax=no`,
the 1,384-byte outer ZIP returned exit 2 with `Exceeded max scan size ERROR`
and `Scan incomplete: Heuristics.Limits.Exceeded.MaxScanSize`; enabling the
alert returned the explicit `Heuristics.Limits.Exceeded.MaxScanSize FOUND`
result. A companion 1,294-byte ZIP detected an earlier child marker with exit
1 even though a later child crossed the 1,494-byte cumulative limit. This
closes the observed real nested-ZIP false-clean case for this path, while the
broader parser matrix remains open. The same public path with `MaxFiles=2`
returned exit 2 and `Exceeded max scan files ERROR` without the alert, or
`Heuristics.Limits.Exceeded.MaxFiles FOUND` with it enabled, for a later
uninspected child. Checksummed evidence is preserved at
`/work/evidence/nested-limit-probe-20260814-run1`.

The repository's real `clam_cache_emax.tgz` fixture was also scanned through
the Release public path with an isolated copy of `clamav.hdb` and an ignore
entry for `ClamAV-Test-File`. With `AlertExceedsMax` disabled, the deep branch
returned exit 2, `Exceeded max recursion depth ERROR`, and
`Scan incomplete: Heuristics.Limits.Exceeded.MaxRecursion` after the shallower
ignored detection was filtered. With the alert enabled, it returned exit 1
with `Heuristics.Limits.Exceeded.MaxRecursion FOUND`. This validates the real
recursion-limit false-clean guard for the repository fixture; broader parser
paths remain open. Evidence is preserved at
`/work/evidence/maxrecursion-probe-20260814-run1`.

A current-source review then found a separate OLE2 VBA materialization
fail-open: the property-tree result from both the enumeration and VBA
materialization passes was not preserved, and incomplete embedded-stream block
extraction could be normalized to `CL_CLEAN`. The working tree now propagates
those results, marks incomplete materialization as non-cacheable, and adds
`test_ole2_vba_materialization_failure_is_fail_visible` using the real
`has_png_and_jpeg.xls` fixture and an invalid materialization output directory.
Source guards pass. A
disposable ARM64 `rust:1.97-bookworm` CMake/Cargo build compiled and linked
`check_clamav`; the direct harness recorded both new tests as passed. The
broader harness was not a clean repository-wide result because this checkout
lacks several large/LFS fixtures and certificate setup (`1,261` checks,
`786` fixture/environment failures, `0` errors). The new source patch has not
been rebuilt on Sonic1: its existing Release and ASan/UBSan binaries still
show diagnostic drift (`OK`/exit 0 versus `Exceeded max scan files ERROR`/exit
2) for the same probe. Production-CVD and broader legacy-parser qualification
remain open.

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

A final OLE2 entry-path check found that a file shorter than the fixed OLE2
header could still return `CL_CLEAN`; it now marks the scan incomplete and
returns `CL_EPARSE`, with a public `CL_TYPE_MSOLE2` truncated-header
regression. The combined SIS/OLE2 focused ARM64 build and source guards pass,
and Sonic1 remains unrebuilt because its source differs.

A broader compressed-container pass found the older GZip and BZip2 scanners
writing and scanning partial temporary output after decoder errors, EOF, or a
configured limit. Those paths now require a terminal decoder state before
calling the nested scanner, preserve the limit/error result, and mark partial
output incomplete. A public truncated `CL_TYPE_GZ`/`CL_TYPE_BZ` regression and
source guards were added; the disposable ARM64 harness records the regression
as passed alongside the existing focused parser tests. Sonic1 is unrebuilt
because its source differs.

An SWF follow-up found the same partial-output risk in the CWS zlib and ZWS LZMA
decompression paths. Both now require decoder completion before nested scanning,
preserve limit/write/decode failures, mark partial output incomplete, and verify
the declared uncompressed length. The uncompressed FWS entry path also rejects
short fixed headers and maps shorter than the declared file size. The public
truncated CWS regression and direct FWS header/size regression pass in the
corrected disposable ARM64 harness; the source guards pass. Sonic1 is unrebuilt
because its SWF source differs from the current worktree.

A follow-up ZIP slice found `cli_unzip()`, `unzip_search()`, and
`unzip_single_internal()` treating maps or local headers shorter than their
fixed structures as successful scans. These paths now mark the scan incomplete
and return `CL_EPARSE`; a direct regression covers all three entry points and
passes in the disposable ARM64 harness, with the source and fail-closed gates
passing as well. Sonic1 is unrebuilt because its `unzip.c` source differs from
the current worktree.

A TNEF parser-entry follow-up found that a recognized signature shorter than the
fixed six-byte TNEF header returned clean before parsing. It now marks the scan
incomplete and returns `CL_EPARSE`; the direct short-header regression passes
alongside the existing public truncated-attribute regression and the ARM64
focused suite. Sonic1 is unrebuilt because its TNEF source differs from the
current worktree.

An InstallShield legacy-metadata pass found `cli_scanishield()` breaking out on
partial filename/path/version/size records with its initial success status. It
now distinguishes a clean end-of-record boundary from truncated or malformed
metadata, marks the scan incomplete, and returns `CL_EPARSE`. The direct
truncated-metadata regression passes in the ARM64 harness and source guards;
Sonic1 is unrebuilt because its InstallShield source differs from the current
worktree.

A follow-up InstallShield audit found `is_parse_hdr()` converting an invalid
embedded header's `CL_BREAK` into a clean result, and found the metadata range
check rejecting an exactly-ending final record. It now marks incomplete header
metadata or invalid header magic and returns `CL_EPARSE`, preserves valid
exact-end records, and no longer normalizes that parse failure to success. The
direct invalid-embedded-header regression passes with the truncated-metadata
regression and the local source, fail-closed, runtime-evidence, and workflow
YAML gates; Sonic1 remains unrebuilt because its InstallShield source differs
from the current worktree.

An ARJ SFX header-validation pass found `cli_unarj_header_check()` accepting a
declared member whose compressed range extended beyond the fmap, then treating
the resulting later header error as a valid archive because one file had already
been found. It now checks member containment before advancing, preserves
non-terminal header errors, marks the scan incomplete, and returns a non-clean
result. The direct truncated-member regression passes in the ARM64 harness with
the existing parser matrix and all four local gates; Sonic1 is unrebuilt because
its `unarj.c` source differs from the current worktree.

A PE parser pass found `cli_scanpe()` converting malformed-header `CL_EFORMAT`
and `CL_ERROR` results into `CL_SUCCESS` after skipping PE-specific analysis.
It now marks malformed or truncated PE-header parsing incomplete, preserves
broken-PE heuristic detection precedence, and returns a non-clean status. The
public `test_pe_truncated_header_is_fail_visible` regression passes in the ARM64
`cl_api` group; the only two group failures are the known missing/corrupt CVD
fixtures. Source guards pass; Sonic1 remains unrebuilt because its `pe.c`
differs from the current worktree.

A CAB/CHM bridge pass found `cli_scanmscab()` and `cli_scanmschm()` returning
`CL_CLEAN` when cumulative `MaxScanSize` was already exhausted before the next
member. Both now mark the scan incomplete and return `CL_EMAXSIZE` before
creating extraction output. The public synthetic CAB regression
`test_mspack_scan_limit_is_fail_visible` passes in the ARM64 `cl_api` group;
the 71-check group has only the two known CVD fixture/setup failures. Source
guards and fail-closed gates pass. Sonic1 remains unrebuilt because its
`libmspack.c` differs from the current worktree.

An ELF parser pass found `cli_scanelf()` converting `CL_BREAK` from incomplete
header, program-header, and section-header parsing into `CL_CLEAN`. The public
scanner now marks those paths incomplete and returns `CL_EPARSE`, while the
internal header probe keeps its existing behavior. The public truncated-ELF
regression passes in the ARM64 `cl_api` group; the 72-check group has only the
two known CVD fixture/setup failures. Source guards and fail-closed gates pass.
Sonic1 remains unrebuilt because its `elf.c` differs from the current worktree.

A Mach-O parser pass found the public scanner returning `CL_EFORMAT` for a
truncated or malformed recognized Mach-O without setting the sticky incomplete
state, allowing generic result reconciliation to normalize the failure to clean.
The public Mach-O and universal-binary paths now mark incomplete header,
load-command, section, entry-point, and architecture-table failures and return
`CL_EPARSE`; the internal `cli_machoheader()` probe keeps its existing
non-scanning behavior. The public truncated-Mach-O regression passes in the
ARM64 `cl_api` group; the 74-check group has only the two known CVD
fixture/setup failures. Source guards and all four local safety gates pass.
Sonic1 remains unrebuilt because its `macho.c` differs from the current worktree.

An UDF parser-entry pass found `cli_scanudf()` returning `CL_SUCCESS` when the
mandatory descriptor area or required volume descriptors could not be read.
Those paths now mark the scan incomplete and return `CL_EPARSE`; the public
truncated-descriptor regression passes in the ARM64 `cl_api` group, which now
has 75 checks with only the two known CVD fixture/setup failures. Source guards
and all four local safety gates pass. Sonic1 remains unrebuilt because its
`udf.c` differs from the current worktree.

An HFS+ parser-entry pass found short or invalid volume headers returning a
parser error without sticky incomplete state, and downstream HFS+ failures had
the same normalization risk. HFS+ volume-header and final parser error paths
now mark the scan incomplete; truncated headers return `CL_EPARSE` and cannot be
cached as clean. The public truncated-HFS+ regression passes in the ARM64
`cl_api` group, which now has 76 checks with only the two known CVD fixture/setup
failures. Source guards and all four local safety gates pass. Sonic1 remains
unrebuilt because its `hfsplus.c` differs from the current worktree.

A follow-up ISO9660 audit found unsupported interleaved child records and
multi-extent records could be skipped or partially scanned without a sticky
incomplete result, and malformed-record exits could retain a mapped directory
block. Those layouts now return `CL_EPARSE`, mark the scan non-cacheable, and
avoid treating partial content as complete. The public ISO regression covering
both layouts passes in the rebuilt ARM64 `cl_api` group, which now has 77 checks
with only the same two known CVD fixture/setup failures. All four local safety
gates pass. Sonic1 is unrebuilt because its `iso9660.c` differs from the current
worktree.

A XAR parser-entry audit found truncated or invalid headers and unavailable TOC
data returning parser/read errors without sticky incomplete state. The public
header path now marks the scan incomplete, and the final TOC/parser error path
reapplies the invariant before returning. The public
`test_xar_truncated_header_is_fail_visible` regression passes in the rebuilt
ARM64 `cl_api` group, which now has 78 checks with only the same two known CVD
fixture/setup failures. All four local safety gates pass. Sonic1 is unrebuilt
because its `xar.c` differs from the current worktree.

A DMG trailer audit found an invalid `koly` trailer returning `CL_EFORMAT`
without sticky incomplete state once trailer validation was reached. The
invalid-trailer path now returns `CL_EPARSE` and marks the fmap non-cacheable.
The focused ARM64 `dmg` case passes all 4 checks with 0 failures and 0 errors;
the broader `cl_api` group remains at 78 checks with only the same two known CVD
fixture/setup failures. Sonic1 is unrebuilt because its `dmg.c` differs from
the current worktree.

A partition-parser finalization audit found MBR, APM, and GPT malformed or
truncated header/table errors returning without reapplying sticky incomplete
state. The three public parser entry paths now mark those failures incomplete
at finalization. `test_partition_parser_errors_are_fail_visible` passes in the
rebuilt ARM64 `cl_api` group, which now has 79 checks with only the same two
known CVD fixture/setup failures. All four local safety gates pass. Sonic1 is
unrebuilt because its partition-parser sources differ from the current worktree.

An XZ decompression pass found `cli_scanxz()` writing a partial temporary member
and then scanning it after `cli_checklimits()` rejected the expanded size. The
limit path now preserves the limit result, marks the scan incomplete, and
refuses to scan partial XZ output. The public XZ-limit regression passes in the
ARM64 `cl_api` group; the 73-check group has only the two known CVD fixture/setup
failures. Source guards and fail-closed gates pass. Sonic1 remains unrebuilt
because its `scanners.c` differs from the current worktree.

A broader legacy-parser audit found that MSEXPAND could return clean after
truncated input and could discard configured-limit results. It now propagates
the limit, marks header/read/write/truncation failures incomplete, and has a
public `CL_TYPE_MSSZDD` regression. The focused ARM64 build, parser tests, and
source guards pass; broader legacy-parser coverage remains open.

The same audit found TNEF's truncated-attribute branch explicitly returning
clean. It now returns `CL_EPARSE`, marks the fmap non-cacheable, and has a
public `CL_TYPE_TNEF` regression; remote source/build qualification remains
separate because Sonic1 does not contain the local follow-up sources.

The next legacy-parser pass found UUENCODE accepting an attachment that ended
at EOF, a blank line, or malformed encoded data without requiring the `end`
terminator. The decoder now requires that exact terminator, returns
`CL_EPARSE` on incomplete or invalid input, and marks the scan incomplete and
non-cacheable. The public `CL_TYPE_UUENCODED` regression, focused ARM64 build,
and source guards pass. The full local harness reports `1,295` checks,
`816` fixture/environment failures, and `0` errors; Sonic1 remains a separate
source/build qualification because the current follow-up sources were not
transferred there.

A follow-up check found that the two mail-parser callers of the shared
UUENCODE decoder discarded that failure and retained the raw line instead.
Both callers now mark the containing scan incomplete and non-cacheable before
retaining the undecoded text, with a public `CL_TYPE_MAIL` regression covering
an unterminated attachment. The current disposable ARM64 harness build passed
the focused legacy-parser cases; its library-only run recorded `1,266` checks,
`786` fixture/environment skips or failures, and `0` errors. The remote source
and build qualification remains separate.

The next pass found BinHex returning clean when its recognized stream ended
before the header, data fork, resource fork, or terminal state was complete;
it also discarded configured resource-limit results. Those paths now preserve
the limit, mark incomplete extraction non-cacheable, and return `CL_EPARSE`
when the encoded stream cannot reach a complete state. The public
`CL_TYPE_BINHEX` regression and focused ARM64 build pass. The current
library-only harness recorded `1,267` checks, `786` fixture/environment
failures, and `0` errors; remote source/build qualification remains separate.

A mail-level BinHex follow-up then exposed that `messageExport()` returned from
its fast-copy path before installing the fileblob scan context, so a mail body
could bypass the authoritative nested scan. The context is now set before that
early return, and a failed BinHex mail materialization marks the containing scan
incomplete. An explicit MIME `CL_TYPE_MAIL` BinHex regression passes in the
ARM64 build; the full harness still has only the known fixture/environment
failures, and the source guards and fail-closed gates pass.

The next SIS slice found the recognized 9.x handler returning clean when its
contents field or size was truncated; the legacy handler's buffered field/skip
macros had the same EOF normalization. Those parser-entry and EOF paths now
mark the scan incomplete and return `CL_EPARSE`. A direct `CL_TYPE_SIS`
truncated-contents regression passes in the ARM64 build; the full harness still
has only the known fixture/environment failures, and the source guards and
fail-closed gates pass.

The next TAR slice found `cli_untar()` returning clean for a short header and
forcing an incomplete entry to end at EOF, allowing partial content to be
scanned as complete. It now marks invalid or truncated headers, checksums,
sizes, and entry content incomplete and returns `CL_EPARSE` after preserving
child detection precedence. A direct `CL_TYPE_POSIX_TAR` truncated-header
regression passes in the ARM64 build; Sonic1 remains reachable, but its
checkout lacks this current TAR patch, so no remote rebuild qualification claim
is made.

The next CPIO slice found all four format handlers returning their initial
success status when the top-level header loop ended on a short or failed
`fmap_readn()`. They now distinguish a complete trailer from an incomplete
header, mark the scan non-cacheable, and return `CL_EPARSE` or `CL_EREAD` as
appropriate. A six-byte regression covering `CL_TYPE_CPIO_OLD`,
`CL_TYPE_CPIO_ODC`, `CL_TYPE_CPIO_NEWC`, and `CL_TYPE_CPIO_CRC` runs without
failure in the ARM64 harness; the broader harness still has only the known
fixture/environment failures, and Sonic1's CPIO source differs from the
current worktree.

The next ISO9660 slice found the parser treating unavailable volume-descriptor
data and directory blocks as clean, while malformed directory records,
unsupported interleaved roots, and per-file limit skips could also fall through
without a sticky incomplete result. Those paths now mark the scan
non-cacheable and return `CL_EPARSE` or the specific limit result. A synthetic
public `cl_scanmap_ex()` regression with a valid ISO descriptor sequence and a
root directory block beyond the map runs without failure in the ARM64 harness;
the broader harness still has only the known fixture/environment failures, and
Sonic1's ISO source differs from the current worktree.

The next 7-Zip slice found explicit fail-open paths for archive seek failure,
header-open errors, member extraction errors, extracted-output write errors,
and discarded per-member scan-limit results. Those paths now mark the scan
incomplete and non-cacheable, preserve non-clean results, and avoid scanning
partial extracted output. A public six-byte `CL_TYPE_7Z` truncated-header
regression runs without failure in the disposable ARM64 harness alongside the
CPIO and ISO regressions; the broader harness still has only the known
fixture/environment failures. Sonic1's 7-Zip source differs from the current
worktree, so no remote rebuild qualification claim is made.

A follow-up SIS slice found the old and 9.x handlers discarding member scan
limits and allowing decompression, short-read, or output-write failures to
fall through as clean. Those paths now preserve the first non-clean result,
mark incomplete content non-cacheable, and return explicit limit/read/parse or
write errors. A synthetic old-format `CL_TYPE_SIS` regression with an
eight-byte member over a one-byte `MaxScanSize` runs without failure in the
disposable ARM64 harness; the broader harness remains limited by the known
fixture/environment failures. Sonic1's SIS source has not been rebuilt for
this follow-up.

A HWP3 parser-entry/finalization audit found document-info, document-summary,
and callback parser failures returning without reapplying the sticky incomplete
state. `cli_scanhwp3()` now routes those failures through finalization and marks
the scan incomplete and non-cacheable when no higher-priority result exists.
The public `test_hwp3_parser_errors_are_fail_visible` regression uses a
truncated document-summary section. The rebuilt disposable ARM64
`check_clamav` harness completed with 1,325 checks, 816 fixture/environment
failures, and 0 errors; the new HWP3 case was not among the reported failures.
All four local safety gates pass. Sonic1 Docker access is verified, but its
HWP3 and test-source checksums differ from the current worktree, so no remote
rebuild qualification claim is made.

An additional SWF audit found the public FWS parser's `INITBITS`, `GETBITS`,
and `GETWORD` short-read branches returning `CL_EFORMAT` without marking the
scan incomplete after frame metadata inspection had begun. Those branches now
apply the sticky incomplete/non-cacheable invariant. The public
`test_swf_truncated_frame_metadata_is_fail_visible` regression reaches the FWS
frame header and truncates the required frame count. The rebuilt ARM64
`check_clamav` harness completed with 1,326 checks, 816 fixture/environment
failures, and 0 errors; the new SWF case was not among the reported failures.
All four local safety gates pass. Sonic1 Docker access is verified, but its
SWF and test-source checksums differ from the current worktree, so no remote
rebuild qualification claim is made.

An MSXML caller audit found `cli_msxml_parse_document()` suppressing
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

An RTF finalization audit found unmatched group/control-word state and
incomplete embedded-object payloads reaching cleanup, where a partial
temporary file could previously be treated as complete or the parent scan
could normalize to clean. RTF finalization now marks the scan incomplete and
non-cacheable, returns `CL_EPARSE` when no stronger result exists, and avoids
scanning a partial embedded object. The public
`test_rtf_truncated_document_is_fail_visible` regression passes in the
rebuilt disposable ARM64 harness; the full run reports 1,328 checks, 816
fixture/environment failures, and 0 errors, with the new case absent from the
failure output. All four local safety gates pass. Sonic1 Docker access is
verified, but its RTF and test-source checksums differ from the current
worktree, so no remote rebuild qualification claim is made.

A RAR parser-entry/finalization audit found `cli_scanrar_file()` discarding
non-terminal member-header errors, losing configured-limit status, and
treating encrypted or failed members as though their contents had been
inspected. It now maps UnRAR errors, marks incomplete header/member inspection
non-cacheable, preserves configured-limit results, and refuses to normalize
failed extraction to clean. The synthetic
`test_rar_truncated_header_is_fail_visible` regression reached the member
header error path and passes in the rebuilt disposable ARM64 harness; the full
run reports 1,329 checks, 816 fixture/environment failures, and 0 errors, with
the new case absent from the failure output. All four local safety gates pass.
Sonic1 Docker access is verified, but its RAR scanner and test-source checksums
differ from the current worktree, so no remote rebuild qualification claim is
made.

An ARJ extraction audit found `cli_scanarj()` passing a temporary member to the
nested scanner even after `cli_unarj_extract_file()` failed, and ignoring a
failed rewind before scanning extracted output. It now marks extraction and
rewind failures incomplete/non-cacheable, closes the partial descriptor, and
refuses nested scanning. The public
`test_arj_truncated_member_extraction_is_fail_visible` regression passes in the
rebuilt disposable ARM64 harness; the full run reports 1,330 checks, 816
fixture/environment failures, and 0 errors. Source guards pass. Sonic1 Docker
access is verified, but its scanner and test-source checksums differ from the
current worktree, so no remote rebuild qualification claim is made.

The legacy GZip compatibility fallback could pass temporary output to the
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
Fresh Sonic1 Docker access with `sonic1-camera-key` showed all three existing
ClamAV containers up. The remote `pe.c` and test-source checksums differ from
the worktree, so no remote rebuild qualification claim is made.

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
Fresh host-list request `req_89b90bc39c2e4347b2168c00587901b5` returned
`sonic1`; Docker request `req_b55b48136be9427780d9b9e69da89a02` succeeded and
showed all three existing ClamAV containers up. Remote `pdf.c`, `pdfdecode.c`,
and test-source checksums differ from the local worktree, so no remote rebuild
qualification claim is made.

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
Fresh host-list request `req_1ad364b37c584f2381133fb4a7bfa233` returned
`sonic1`; Docker request `req_5985e388d1a547728829b72d04e146e5` using
`sonic1-camera-key` succeeded and showed the three existing ClamAV test
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
Fresh host-list request `req_98c8b9951fd044468b081c29ab3d87e1` returned
`sonic1`; Docker request `req_801da2e90300458c8343d78b4e430dbf` using
`sonic1-camera-key` succeeded and showed the three existing ClamAV test
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

The UNIX mbox dispatcher had another fail-open boundary: while advancing past
a completed message it handled `FAIL` and `VIRUS` but dropped recursive `MAXREC`
and `MAXFILES` results. Nested multipart return paths also lacked explicit
`MAXFILES` propagation. `libclamav/mbox.c` now maps both statuses to public
non-clean results, records the exceed-max heuristic, and stops the mailbox
walk. The new two-part multipart containing a nested `message/rfc822` part,
with `MaxFiles=1`,
`test_mbox_nested_maxfiles_is_fail_visible`, executed in the standalone API
case without a failure entry.

The disposable ARM64 UnRAR-disabled harness built `check_clamav` and reported
1,306 checks, 786 known fixture/environment failures, and 0 errors; the
failures are existing missing-CVD/corpus setup cases. All four local safety
gates passed. Current changed-file hashes are
`mbox.c=ea0c1dbef45714db3408bc70f2397033ab649096fb25f880fccd13b342469384`,
`check_clamav.c=d81d11e1d9bbeadd6ed102bc7e16cf53025c5eee580047eadc6228e1bd836f3e`,
and
`largefile_source_guards.sh=2a7a2703bbcd9bd91e3f671f7bb801d766756fbcfdf0ab2ab09c609bd0c808f2`.

Fresh host-list request `req_426f3ab06872438da254971e3648a391` returned
`sonic1`; Docker request `req_d5e17b9a827d46e68c55c0a27b302d0d` using
`login_profile=sonic1-camera-key` succeeded with exit 0 and showed all three
existing ClamAV test containers running. Sonic1 was not rebuilt for this local
mbox change, so remote rebuild qualification remains open.

A later non-destructive Docker inspection request
`req_aec06e41d1744d79a9d6dad9f52b571e` confirmed all three containers are
`running`, use image `clamav-32gb:test-tools-742a8a4`, and use working directory
`/workspace/ClamAV`. Remote source hashes from
`req_e6c81b5f32e748f58f5d0367aa05da2f` were
`mbox.c=8439f4d9ac311ba0775d2ef0e4f7c51b90e91b1b36162711bd757ece21fd534`
and
`check_clamav.c=8912af667dcdf0d8766b1507790f4c7813d552aead93bfbaafa0761be593ed20`,
so the remote checkout does not contain the current local mbox follow-up. The
inspection verifies Docker access and liveness, not remote qualification.

The manual OOXML review did not identify a reproducible new false-clean limit
path. Non-critical metadata statuses are intentionally normalized so ZIP
content scanning proceeds, and the shared sticky incomplete-result path retains
configured-limit failures at the outer scan boundary.

A public Release ZIP matrix then scanned intact and truncated real fixtures:
`clam.zip`, BZIP2/Deflate64/Implode ZIPs, a split-ZIP control, nested
7z-in-ZIP, and split `logos.zip`/`logos.z01`. All four cuts that removed
member data returned exit 2 with `Can't parse data ERROR` and
`Scan incomplete: ZIP member data is truncated or outside the archive map`.
Shallower cuts that removed only tail metadata remained clean because their
member data was still available to the bounded local-header fallback. This
validates fail-visible behavior for structural truncation in two real archive
formats, while broader production-format coverage remains open.
Checksummed evidence is preserved at
`/work/evidence/zip-public-truncation-20260814-run2`.

A bounded public Release `clamscan` probe then exercised the supported traditional
ZipCrypto password-database path. A 191-byte stored-member fixture returned exit
2 with `Can't parse data ERROR` and
`ZIP encrypted member could not be decrypted with a configured password` when
no password database was supplied. Supplying a test `.pwdb` entry with the
correct password returned exit 1 and detected
`Encrypted.Zip.Public.Marker.UNOFFICIAL.UNOFFICIAL FOUND`. The manifest verified
with status 0 and no non-zombie scanner processes remained. This qualifies one
small stored ZipCrypto member through the public path. A follow-up public
matrix then scanned a 334-byte two-member archive with a deliberately wrong
password first in the `.pwdb`; `--allmatch` returned exit 1 and detected both
member markers. The same path decrypted and detected a 64 MiB stored encrypted
member in 1.598 seconds; its no-password control returned exit 2. The extended
manifest verified with status 0, with no temporary decrypted files or non-zombie
scanner processes remaining. This extends traditional ZipCrypto coverage to
multi-member and 64 MiB stored members; strong-encrypted contents remain
unsupported by design, while broader production-format encrypted coverage
remains open. Checksummed evidence is
preserved at
`/work/evidence/encrypted-zip-probe-20260814-run1`.

Extended encrypted-ZIP evidence is preserved at
`/work/evidence/encrypted-zip-extended-20260814-run1`.

A synthetic production-structure ZIP with general-purpose flags `0x0041`
(encrypted plus strong encryption) and extra field `0x0017` was then scanned
through the public Release path. With and without the configured password
database it returned exit 2, `Can't parse data ERROR`, and
`ZIP strong encryption is unsupported`; the embedded marker was not detected.
The manifest verified with status 0 and no temporary decrypted files or
non-zombie scanner processes. This qualifies fail-visible rejection of the
unsupported strong-encryption form, not decryption support for strong-encrypted
contents. Evidence is preserved at
`/work/evidence/zip-strong-encryption-public-20260814-run1`.

An expansion-heavy nested-archive pass then scanned four three-level ZIPs
concurrently with the marker at the end of each 256 MiB expanded payload. The
Release workers all returned the expected detection status `1` and
`Nested.Expansion.Test.UNOFFICIAL FOUND`; aggregate temporary usage peaked at
1,074,793,460 bytes, minimum available space was 62,791,471,104 bytes, and
aggregate/single-worker peak RSS was 137,912/36,372 KiB. The temporary
directory returned to 4,096 bytes after shutdown. The aligned four-worker
ASan/UBSan run used 64 MiB payloads, also returned four expected detections,
peaked at 268,703,064 temporary bytes and 272,236/65,060 KiB aggregate/single
worker RSS, and emitted no sanitizer or runtime-error diagnostics. These are
representative custom-database nested-expansion fixtures, not production-CVD
capacity results. Compact evidence is preserved at
`/work/evidence/nested-expansion-concurrent2-20260814` and
`/work/evidence/nested-expansion-sanitizer-20260814`. The first attempt is
retained separately as a harness-only monitor wait-order diagnostic at
`/work/evidence/nested-expansion-concurrent-20260814`.

An aligned final-commit ASan/UBSan `clamscan` rebuild then repeated the
four-worker 256 MiB nested-expansion fixture, closing the source-provenance
gap in the earlier sanitizer result. All four workers returned the expected
exit 1 and `Nested.Expansion.Test.UNOFFICIAL FOUND`; aggregate temporary usage
peaked at 1,074,806,784 bytes, minimum available space was 65,324,261,376
bytes, and aggregate/single-worker peak RSS was 285,792/73,596 KiB. The
sampled aggregate minor-fault delta was 1,107,049 and the maximum aggregate
major-fault sample was 158. No ASan, UBSan, or runtime-error diagnostic was
emitted, and the evidence-local temporary directory was empty after the run.
This remains representative custom-database expansion evidence, not
production-CVD capacity qualification. Compact evidence is preserved at
`/work/evidence/nested-expansion-final-sanitizer-20260814`.

The final Release and final-commit ASan/UBSan builds then extended this
workload to four concurrent three-level ZIPs, each expanding to exactly 1 GiB
(`1,073,741,824` bytes) with the same tail marker. All eight workers returned
the expected exit 1 and `Nested.Expansion.Test.UNOFFICIAL FOUND`; Release
worker times were 6.828--7.433 seconds and sanitizer worker times were
10.099--10.457 seconds. The resource-sampled runs peaked at 4,307,564,940
temporary bytes and left 46,714,961,920 bytes available. Release aggregate and
single-worker peak RSS was 138,412/38,484 KiB with a 3,084,456 minor-fault
delta and 46 maximum aggregate major faults; sanitizer was
286,692/75,324 KiB with a 3,980,015 minor-fault delta and 441 maximum
aggregate major faults. Both temporary directories returned to 4,096 bytes,
all worker stderr and sanitizer-diagnostic files were empty, and the fixtures
record source commit `5becea1236d466ee21f9bd5d3bcd0595ebc1460b`. This is
stronger production-scale expansion-shaped evidence, but it still uses the
private marker database rather than the unavailable production CVD set and
does not close production-CVD qualification. Compact evidence is preserved at
`/work/evidence/nested-expansion-1g-concurrent-final-release-20260814` and
`/work/evidence/nested-expansion-1g-concurrent-final-sanitizer-20260814`.

To extend the concurrency qualification, the final Release and final-commit
ASan/UBSan builds then scanned eight concurrent three-level ZIPs, each
expanding to exactly 1 GiB. All sixteen workers across the two builds returned
the expected exit 1 and `Nested.Expansion.Test.UNOFFICIAL FOUND`; Release
worker times were 7.010--7.990 seconds and sanitizer worker times were
10.280--12.987 seconds. Release temporary usage peaked at 8,615,125,784
bytes with 46,712,446,976 bytes available, aggregate/single-worker peak RSS of
260,884/38,724 KiB, a 6,738,920 minor-fault delta, and 30 maximum aggregate
major faults. Sanitizer temporary usage also peaked at 8,615,125,784 bytes
with 46,712,213,504 bytes available, aggregate/single-worker peak RSS of
579,708/76,268 KiB, a 7,357,076 minor-fault delta, and 531 maximum aggregate
major faults. Both temporary directories returned to 4,096 bytes; all worker
stderr and sanitizer-diagnostic files were empty; and no scanner processes
remained. This strengthens the production-scale concurrency-shaped evidence,
but uses the same private marker database and does not close production-CVD or
production-format qualification. Compact evidence is preserved at
`/work/evidence/nested-expansion-1g-8way-final-release-20260814` and
`/work/evidence/nested-expansion-1g-8way-final-sanitizer-20260814`.

The same eight-way, one-GiB nested-archive workload then passed through the
final Release and final-commit ASan/UBSan `clamd` instances with eight daemon
threads, queue depth 16, and the 32-GiB scan limits. Eight synchronized
`clamdscan --fdpass` clients per build were ready-gated and released together
after direct UNIX-socket `PING`/`PONG` readiness; all sixteen returned exit 1
and `Nested.Expansion.Test.UNOFFICIAL FOUND`. Release client times were
7.737--8.576 seconds, with 8,615,121,688 maximum daemon temporary bytes,
46,707,265,536 minimum available bytes, 90,324 KiB peak daemon RSS, 10 peak
threads, a 4,215,635 aggregate minor-fault delta, and zero sampled aggregate
major faults. Sanitizer client times were 11.927--13.199 seconds, with the
same temporary peak, 46,706,970,624 minimum available bytes, 137,456 KiB peak
daemon RSS, 10 peak threads, a 4,482,782 aggregate minor-fault delta, and
zero sampled aggregate major faults. Both daemon temporary directories were
empty after shutdown (0 file bytes, 4,096-byte directory footprint), all
worker/daemon/shutdown stderr and sanitizer-diagnostic files were empty, and
the input and log SHA-256 manifests verified. This is clean daemon-side
private-marker-database evidence; it does not close production-CVD,
production-format, or cold-cache qualification. Compact evidence is
preserved at
`/work/evidence/clamd-nested-1g-thread8-clean-final-release-20260814` and
`/work/evidence/clamd-nested-1g-thread8-clean-final-sanitizer-20260814`.

As a direct current-binary policy check, both final `clamscan` builds rejected
`--max-filesize=34359738369` before opening the input, returned exit 2, and
emitted `ERROR: MaxFileSize cannot exceed 32G in this build`. The Release check
completed in 7 ms and the sanitizer check in 44 ms; compact manifests and log
hashes are preserved at
`/work/evidence/maxfilesize-policy-final-release-20260814` and
`/work/evidence/maxfilesize-policy-final-sanitizer-20260814`.

A single-worker three-level Zip64 fixture with an exactly 34,359,738,368-byte
expanded payload was then used to separate the configured cumulative scan
budget from engine capacity. With the final Release and final-commit ASan/UBSan
builds' production-style `MaxFileSize=32G` and `MaxScanSize=32G`, the scan
reached the payload path but returned the expected fail-visible
`Heuristics.Limits.Exceeded.MaxScanSize` after the outer archive bytes consumed
additional scan budget; neither build reported a clean result. In a separate
exploratory pass retaining `MaxFileSize=32G` but raising `MaxScanSize` to 64G,
both final Release and
final-commit ASan/UBSan builds extracted the full payload and detected
`Nested.Expansion.Test.UNOFFICIAL` at offset 34,359,738,368. Release took
180.500 seconds, peaked at 34,659,607,228 temporary bytes and 125,144 KiB
RSS, left 20,512,116,736 bytes available, and recorded zero sampled major
faults. Sanitizer took 285.528 seconds, reached the same temporary peak and
162,604 KiB RSS, left 20,062,121,984 bytes available, and recorded two sampled
major faults. Both temporary directories returned to 4,096 bytes, all
sanitizer diagnostics were empty, and input/log manifests verified. This is a
useful production-scale expansion-capacity result with the private marker
database, not a claim that the default 32-GiB cumulative budget permits
arbitrary 32-GiB nested archives or that production-CVD qualification is
complete. Evidence is preserved at
`/work/evidence/nested-expansion-32g-final-release-20260814` and
`/work/evidence/clamd-nested-1g-thread8-clean-final-sanitizer-20260814/large32g`.

To cover the remaining cold-cache gap with current-build raw input, the host
page cache was synchronously dropped immediately before separate Release and
final-commit ASan/UBSan scans of identical sparse 34,359,738,368-byte edge
fixtures. Both scans returned exit 1, detected
`LargeFile.POC.32g-edge.UNOFFICIAL` at engine offset 34,359,738,304, and
returned their temporary directories to 4,096 bytes without sanitizer or
runtime diagnostics. Release took 1:58.49, reached 100,948 KiB maximum RSS,
recorded 177 major and 33,589,910 minor page faults, and read 32,096 filesystem
blocks. The sanitizer build took 3:41.08, reached 137,068 KiB maximum RSS,
recorded 479 major and 34,653,526 minor page faults, and read 97,336 filesystem
blocks. The compact evidence manifests verify all scan, resource, cache-control,
fixture, and cleanup records at
`/work/evidence/cold-cache-exact-edge-final-release-20260814` and
`/work/evidence/cold-cache-exact-edge-final-sanitizer-20260814`. This closes a
production-scale cold-cache raw-edge gap, but it remains private-marker
workload evidence rather than production-CVD qualification.

The same cache-drop procedure then ran synchronized two- and four-worker raw
edge scans in both current builds. All four two-worker clients and all eight
four-worker clients returned exit 1 and detected the marker at engine offset
34,359,738,304. Summed per-worker maximum-RSS upper bounds were
200,828/272,796 KiB at two workers and 402,616/543,280 KiB at four workers
(Release/sanitizer); aggregate major/minor faults were 322/721 and
67,179,886/69,307,273 at two workers, then 1,959/9,647 and
134,362,662/138,628,982 at four workers. Each run left zero temporary files
and only the expected 12,288-byte or 20,480-byte directory footprint, with
empty sanitizer diagnostics and verified compact manifests. Evidence is
preserved at
`/work/evidence/concurrency-2way-exact-edge-final-release-20260814`,
`/work/evidence/concurrency-2way-exact-edge-final-sanitizer-20260814`,
`/work/evidence/concurrency-4way-exact-edge-final-release-20260814`, and
`/work/evidence/concurrency-4way-exact-edge-final-sanitizer-20260814`. This
closes the current-build 2/4-worker raw-edge gate, but not production-CVD
threading or concurrent reload qualification.

The configured final Release CTest `libclamav` target then passed 100% of its
single registered test in 27.07 seconds with zero stderr, exercising the
checked-in synthetic limit, ZIP boundary, and fail-visible result-precedence
coverage under the same fixture and certificate environment used by CTest.
This confirms that regression suite executes successfully in the final build;
it does not by itself close the broader generic false-clean or
production-database gaps. Compact evidence is preserved at
`/work/evidence/correctness-libclamav-final-release-20260814`.

The same final source commit was then rebuilt with ASan/UBSan and
`ENABLE_TESTS=ON`; the full build materialized 390 generated fixture files
before running the configured `libclamav` CTest target. It passed 100% in
32.07 seconds with zero stderr and no AddressSanitizer, UndefinedBehaviorSanitizer,
or runtime-error signatures. No test process remained and the compact
evidence hashes verified at
`/work/evidence/correctness-libclamav-final-sanitizer-20260814-v3`.

The same final-commit ASan/UBSan build also passed the configured `clamd`
CTest target in 32.35 seconds with 100% tests passed, zero stderr, no
AddressSanitizer/UndefinedBehaviorSanitizer/runtime-error signatures, and no
leftover daemon or test process. Evidence hashes verified at
`/work/evidence/correctness-clamd-final-sanitizer-20260814`.

The same final-commit ASan/UBSan build also passed the remaining committed-source
core-tool CTest targets—`clamav_milter_quota`, `clamscan`, `freshclam`, and
`sigtool`—4/4 in 51.46 seconds. The timed run reached 346,644 KiB maximum RSS,
returned CTest exit 0, had no sanitizer or runtime-error signatures, passed
the recorded evidence hashes, and left no matching test processes. The first
evidence wrapper reported `validation=fail` because its broad `SUMMARY:` grep
matched CTest's benign `Label Time Summary:` line; the corrected validation
record scans only sanitizer/runtime signatures and records the pass at
`/work/evidence/correctness-core-tools-final-sanitizer-20260814/post-validation.txt`.
The underlying CTest output and original wrapper record remain preserved in
`/work/evidence/correctness-core-tools-final-sanitizer-20260814`.

The final sanitizer build was then reconfigured with `ENABLE_MILTER=ON` to
match the corrected workflow. The `clamav-milter` target built successfully
with `-fsanitize=address,undefined -fno-omit-frame-pointer`, and the
`clamav_milter_quota` CTest passed 1/1 in 0.02 seconds with 17,644 KiB maximum
RSS. A real exact-edge libmilter harness run was attempted against these
sanitizer `clamd` and `clamav-milter` binaries using the complete repository
fixture corpus. The first attempt exposed only a harness path defect: its
109-byte Unix-socket path exceeded the Linux socket-path limit, so it was
rerun with a 62-byte socket path. The corrected run streamed through
34,091,302,912 of the expected 34,359,738,316 body bytes before sanitizer
`clamd` reached 43,615,092 KiB RSS on the 62-GiB host, leaving 19 GiB available
memory and 3.6 GiB swap in use. It was stopped deliberately for safety before
EOM; it produced no accepted scan result. Memory recovered to 61 GiB available
and 51 GiB free on `/work`, with no exact test processes remaining. This is a
committed-source sanitizer milter materialization/resource gap, not a pass.
The bounded failure evidence, startup diagnostic, resource samples, and
hash manifest are preserved at
`/work/evidence/milter-working-tree-harness-final-sanitizer-20260814`; the
Release working-tree exact-edge pass remains separately recorded at
`/work/evidence/milter-working-tree-harness-20260814`.

As a diagnostic comparison, the local follow-up cap files were installed only
in an isolated sanitizer checkout, rebuilt with `ENABLE_MILTER=ON`, and then
restored from verified committed-source backups. A real 4-GiB milter wire
completed with exactly 4,294,967,244 body bytes and a 4,294,967,296-byte
message, returned the expected `r` result, and logged
`Heuristics.Limits.Exceeded.MailMaterialization`. The timed harness reached
380,048 KiB maximum RSS, completed in 19.43 seconds, left a 172 KiB runtime
footprint after shutdown, and emitted no sanitizer/runtime diagnostics. This
confirms the local cap follow-up bounds this 4-GiB milter path under sanitizer, but it
is working-tree-only evidence until those source changes are committed and
retested from the fork revision. Evidence and source hashes are preserved at
`/work/evidence/milter-working-tree-cap-sanitizer-20260814`.

The same isolated cap checkout then passed the literal 32-GiB milter boundary:
the harness sent exactly 34,359,738,316 body bytes for a
34,359,738,368-byte message, returned `r`, and logged
`Heuristics.Limits.Exceeded.MailMaterialization FOUND`. Under ASan/UBSan the
timed run completed in 2:39.70 with 380,124 KiB maximum RSS and zero swaps;
the preserved runtime root was 172 KiB after shutdown, with no temporary files
or sanitizer/runtime diagnostics. The evidence manifest verified successfully
at `/work/evidence/milter-working-tree-cap-sanitizer-20260814/exact-edge`.
This remains working-tree-only follow-up evidence: the source was restored to
committed `5becea1`, the committed sanitizer milter target was rebuilt, and
the later cap-commit validation below was still required at that point.

The same isolated cap checkout, with the local public-API regression additions,
then ran the full `libclamav` CTest under ASan/UBSan with
`CVD_CERTS_DIR=/workspace/ClamAV/certs`. It passed 1/1 in 42.93 seconds, and
the detailed Check log records all four new regressions as `P (Passed)`:
`test_mbox_materialization_limit_is_fail_visible`,
`test_mbox_materialization_limit_without_alert_is_fail_visible`,
`test_single_message_materialization_limit_is_fail_visible`, and
`test_single_message_materialization_limit_without_alert_is_fail_visible`.
The timed maximum RSS was 886,720 KiB, swaps stayed at zero, no sanitizer or
runtime diagnostics were present, and no test process remained. Evidence and
source hashes are preserved at
`/work/evidence/milter-working-tree-cap-sanitizer-20260814/unit-regression`.
An earlier control without `CVD_CERTS_DIR` skipped the fixture-loading tests
and is not counted as qualification.

A follow-up validation then applied the same cap implementation and regression
tests to an isolated checkout based on `5becea1` on Sonic1. The complete
ASan/UBSan build with `ENABLE_MILTER=ON` passed `libclamav` CTest 1/1 in
42.75 seconds and the `clamav_milter_quota`/`clamav_milter_protocol` pair 2/2
in 5.45 seconds. The literal exact-edge milter wire then sent exactly
34,359,738,316 body bytes for a 34,359,738,368-byte message, returned `r`, and
logged `Heuristics.Limits.Exceeded.MailMaterialization FOUND`. No sanitizer or
runtime diagnostics were emitted, the milter temporary directory was clean,
and no test processes remained. The validated seven-file follow-up was
preserved as local Sonic1 commit `938a196` on `codex/sonic1-validation-fixes`;
it was not pushed upstream. Checksummed runtime evidence is preserved at
`/work/evidence/cap-committed-validation-20260814`, with the exact-edge
manifest checksum recorded as `a18d19e003c805143b1ae2ffd3324474dd9d6bfc9534531e6b53c8c8e8f2a51a`.

A targeted adversarial mbox check then exercised the cap with 8,388,608
seven-byte body lines (`67,108,864` logical body bytes, plus the mbox
headers). The cap-enabled ASan/UBSan `clamscan` run returned exit status 1
with `Heuristics.Limits.Exceeded.MailMaterialization FOUND`, completed in
1:21.43, and reached 429,212 KiB maximum RSS with zero major faults and zero
swaps. No sanitizer diagnostics were emitted. This quantifies the `text` and
`line` node overhead for dense mail while proving that the mbox path remains
fail-visible at the explicit boundary. The source was restored to committed
`5becea1` and rebuilt afterward; this is working-tree-only follow-up evidence
preserved with checksums at
`/work/evidence/deep-parser-density-20260814`.

The same dense mbox fixture was then rerun from the validated cap commit
`938a196` with its ASan/UBSan `clamscan` build. It returned exit status 1 with
`Heuristics.Limits.Exceeded.MailMaterialization FOUND` in 1:21.22, peaked at
428,104 KiB RSS, and recorded zero major faults, zero swaps, and no sanitizer
diagnostics. Checksummed committed-source evidence is preserved at
`/work/evidence/deep-parser-density-938a196-20260814`; the manifest checksum is
`015a60c179e5d8e103427169234dc0d3017fcfca7719c200c4f18ac91d6f7cab`.

A stronger mbox precedence fixture then placed a correctly base64-encoded
private marker in an attachment of the first message and a 67 MiB dense second
message behind it. From commit `938a196`, the ASan/UBSan `clamscan` single-match
run returned `Mbox.Detection.Before.Cap.UNOFFICIAL FOUND` in 0.16 seconds at
70,536 KiB RSS, without reaching the later materialization cap. The explicit
`--allmatch` run returned both that attachment detection and
`Heuristics.Limits.Exceeded.MailMaterialization FOUND` in 1:21.15 at 430,016
KiB RSS. No sanitizer diagnostics or temporary mail directories remained.
This qualifies attachment-level detection precedence and retention of the
earlier detection when all-match continuation reaches a later cap. Checksummed
evidence and the validation note are preserved at
`/work/evidence/mbox-detection-plus-cap-938a196-20260814/custom/attachment-level-b64`;
the manifest verification returned status 0.

For the validated raw-file path, this closes the unsafe proportional-growth
gap by choosing an explicit fail-visible boundary. It does not claim that a
multi-gigabyte MIME body is deep-decoded or scanned beyond that 64 MiB parser
representation; such mail inputs are deliberately incomplete rather than
falsely clean. The cap-enabled committed milter exact-edge run also closes the
bounded sanitizer resource gate for the synthetic private-marker workload;
extending deep mail analysis beyond the 64 MiB representation still requires
a streaming or spooling design.

## 7. Memory interpretation

The current measurements demonstrate that sparse sequential raw scanning is
not using RAM proportional to file size:

- one Release worker peaked near 101 MiB RSS;
- four Release workers had a 403,544 KiB sum of per-worker peak RSS;
- one ASan/UBSan worker peaked near 136 MiB;
- four ASan/UBSan workers had a 543,972 KiB sum of per-worker peak RSS; and
- the private clamd exact-edge scan peaked at 96,584 KiB for the daemon;
- the first eight-worker exact-edge FILDES daemon run peaked at 620,836 KiB
  with 10 observed daemon threads; and
- the repeat resource-sampled eight-worker run peaked at 622,096 KiB with 10
  observed daemon threads and zero major page faults; and
- the eight-worker exact-edge FILDES/reload-overlap run peaked at 582,648 KiB
  with 10 observed daemon threads and a maximum sampled major-fault count of
  18.

These figures use a tiny purpose-built signature database and sparse files.
They are not a production minimum. The signature engine, production CVD and
custom databases, parser scratch, nested expansion, database reload overlap,
thread count, page cache, and INSTREAM temporary files can materially increase
requirements.

Current deployment estimate:

- **4 GiB:** provisional practical minimum for one ordinary production raw
  scan, pending full-database measurement;
- **8 GiB:** sensible starting target for one production large-file worker;
- **48-64 GiB:** appropriate qualification capacity for 1/2/4 concurrency,
  sanitizers, page-cache pressure, and deep-parser workloads.

More RAM helps throughput, concurrency, database reloads, parser scratch, and
filesystem cache. It does not raise the 32 GiB policy ceiling, turn an
unsupported parser into a supported one, or replace INSTREAM temporary-disk
capacity.

## 8. What remains before production certification

### 8.1 Protocol and daemon work

- The literal 32 GiB milter wire upload and EOM handling now have a bounded,
  fail-visible result through the 64 MiB mail-materialization cap. The public
  API also returns `CL_EMAXSIZE` with `CL_VERDICT_NOTHING_FOUND` and no alert
  when the cap is reached without heuristic alerts enabled. A future
  streaming/spooling design could extend deep mail analysis beyond that cap;
  until then, the cap must remain documented and covered by regression tests.
- In an isolated sanitizer checkout containing the local follow-up cap files,
  the real milter harness completed the exact 32-GiB boundary with the
  expected `r` result and `Heuristics.Limits.Exceeded.MailMaterialization`
  alert, at 380,124 KiB maximum RSS and with clean shutdown. This is
  working-tree-only evidence, not a committed-fork qualification; its exact
  body/message counts and checksums are preserved at
  `/work/evidence/milter-working-tree-cap-sanitizer-20260814/exact-edge`.
- The cap-enabled committed-source ASan/UBSan milter path is now qualified for
  the synthetic private-marker boundary: commit `938a196` completed the exact
  32-GiB wire with the expected `r` result, the fail-visible materialization
  alert, clean temporary storage, and no diagnostics or leftover processes.
  The earlier 43,615,092 KiB clamd-RSS safety stop belongs to the pre-cap
  `5becea1` implementation and remains useful historical evidence, not a
  blocker for the bounded cap path. Production-CVD and deeper streaming or
  spooling mail analysis remain separate qualification work.

### 8.2 Workload qualification

- Measure a full official production CVD plus representative custom
  signatures; the current runtime database is deliberately tiny.
- Sonic1 currently has no `/var/lib/clamav` production database. The only
  CVDs found in the available checkouts are small freshclam fixtures and a
  60 KiB bytecode test database, so no production-CVD claim is made and no
  download or installation was performed.
- The strongest available public-format follow-up is now recorded at
  `/work/evidence/public-cvd-cold-hot-20260814-run2`: the final Release binary
  loaded the repository's six signed test CVD fixtures with the correct
  `unit_tests/input/signing/verify` certificate, scanned the nested
  `other_scanfiles` corpus after a host page-cache drop, and produced identical
  cold/hot output for 46 inputs. Both passes returned the expected status 2
  solely for the standalone split-ZIP segment `zip/logos.z01`, with the
  explicit `ZIP member data is truncated or outside the archive map` warning;
  validation found no CVD signature, certificate, or database-load error. This
  is signed test-CVD and cold-cache parser evidence, not production-CVD
  qualification. The preceding incorrect-certificate attempt is retained as a
  negative control at `/work/evidence/public-cvd-cold-hot-20260814`.
- The same corrected workload was then run under the final ASan/UBSan binary
  after a second host page-cache drop. Its 46-line stdout matched the Release
  hash exactly in both cold and hot passes; both returned the same expected
  split-ZIP status 2, with no CVD-load failure or sanitizer/runtime diagnostic.
  Checksummed evidence is preserved at
  `/work/evidence/public-cvd-cold-hot-sanitizer-20260814-run1`.
- An independent final ASan/UBSan exact-edge `clamscan` run then used a
  combined database containing all six signed test CVDs and the private tail
  marker. It found `LargeFile.POC.32g-edge.UNOFFICIAL` at engine offset
  `34359738304` in the exact 34,359,738,368-byte fixture, returned exit 1 in
  213.450802 seconds, verified/loaded all six CVDs, emitted no sanitizer or
  database-load diagnostic, and left its temporary directory empty. This is
  combined signed-test-CVD plus private-marker evidence, not production-CVD
  qualification. Evidence is preserved at
  `/work/evidence/cvd-public-exact-edge-sanitizer-20260814-run2`.
- The final Release counterpart used the identical combined database and
  exact-edge fixture. It found the same marker at offset `34359738304` in
  118.816549 seconds, with the same scanner hash, all six CVDs verified and
  loaded, no database-load diagnostic, and an empty temporary directory.
  Evidence is preserved at
  `/work/evidence/cvd-public-exact-edge-release-20260814-run1`.
- A final Release daemon-side parity run then used an isolated `clamd`
  configuration with the same exact-edge fixture and a database manifest
  containing the six signed test CVDs, their signed CDIFF inputs, and the
  private marker NDB. `clamd` answered `PONG`, reported `Loaded 45
  signatures`, and logged both 32-GiB limits. `clamdscan --fdpass` detected
  `LargeFile.POC.32g-edge.UNOFFICIAL` for the marker at fixture offset
  `34359738304`, returned exit 1 in 142.531045 seconds, and emitted no stderr
  or database-load diagnostic. Protocol shutdown returned daemon exit 0 and
  removed the socket and PID file; temporary storage and active validation
  processes were empty. This is combined signed-test-CVD plus private-marker
  daemon evidence, not production-CVD qualification. Evidence is preserved at
  `/work/evidence/cvd-clamd-public-exact-edge-release-20260814-run2`.
- The matching final ASan/UBSan daemon run used the same combined database and
  exact-edge fixture. `clamd` reported `Loaded 45 signatures`, and its debug
  stream recorded `LargeFile.POC.32g-edge.UNOFFICIAL` at engine offset
  `34359738304`; `clamdscan --fdpass` returned exit 1 in 235.147097 seconds.
  No ASan, UBSan, runtime, or database-load diagnostic appeared, and protocol
  shutdown removed the socket and PID file with an empty temporary directory.
  This remains signed-test-CVD plus private-marker evidence, not production-CVD
  qualification. Evidence is preserved at
  `/work/evidence/cvd-clamd-public-exact-edge-sanitizer-20260814-run1`.
- A bounded cross-parser limit matrix then exercised POSIX TAR and GZIP/TAR
  fixtures with the private marker database in both the final Release and
  ASan/UBSan containers. The 52-record matrix passed 532/532 assertions per
  build: late-marker MaxScanSize cases, MaxFiles and MaxRecursion cases all
  returned explicit incomplete results, while alert-enabled runs exposed the
  matching `Heuristics.Limits.Exceeded.*` detection. Under `--allmatch`, an
  early marker remained visible when a later MaxFiles or MaxRecursion limit was
  reached; the later limit warning persisted and its alert was visible when
  enabled. Both builds produced the same normalized semantic-results hash
  `7e62acf9da68d3b406c91f8b74ce8cc7e27c02ea4647b2245e8ac98c28be64bf`, with no
  database, sanitizer, runtime, or temporary-file diagnostics. This narrows
  but does not close the generic legacy-parser audit; several early-marker
  MaxScanSize fixtures also hit top-level container-size preflight, so they are
  boundary checks rather than precedence claims. Evidence and validation
  provenance are preserved at
  `/work/evidence/cross-parser-limit-matrix-release-20260814-run2` and
  `/work/evidence/cross-parser-limit-matrix-sanitizer-20260814-run2`.
- A follow-up compressed-ZIP matrix passed 178/178 assertions per build across
  16 authoritative records. A late deflated member crossed MaxScanSize with
  explicit non-clean output; an early marker remained visible before a later
  MaxScanSize or MaxFiles crossing, and `--allmatch` retained that marker while
  exposing the later limit warning/alert. A nested ZIP chain likewise returned
  explicit MaxRecursion at the lower bound, while an outer marker remained
  visible at the calibrated higher bound before a later nested crossing. The
  Release and ASan/UBSan semantic results matched at hash
  `a30c03d8b05bdeec9da6fdfe030e53f1b3b20e9d0644bd7b95b12ef36b66d00d`, with no
  database, sanitizer, runtime, or temporary-file diagnostics. Initial fixture
  and evidence-serialization corrections are preserved outside the
  authoritative `out/` records. This strengthens ZIP-family coverage without
  closing every legacy parser or production-CVD workload. Evidence and
  validation provenance are preserved at
  `/work/evidence/cross-parser-limit-matrix-zip-release-20260814-run1` and
  `/work/evidence/cross-parser-limit-matrix-zip-sanitizer-20260814-run1`.
- A follow-up working-tree audit found two legacy-parser limit exits that were
  not entering the shared sticky-incomplete helper before returning: HWP3's
  recursion guard and OLE2's initial cumulative `MaxScanSize` guard. Both now
  call `cli_append_potentially_unwanted_if_heur_exceedsmax()` before their
  existing `CL_EMAX*` return. The direct regression
  `test_legacy_parser_limit_returns_are_fail_visible` asserts the incomplete
  state, exact limit cause, and non-cacheable fmap for both paths. The
  isolated static Sonic1 build passed 1,285/1,285 Check assertions, and a
  public HWP3 probe with `AlertExceedsMax=no` returned exit 2 with
  `Exceeded max recursion depth ERROR` rather than `OK`. This closes the two
  observed exits only; the broader generic legacy-parser audit remains open.
- A fully allocated exact-edge FILDES scan now passes with representative
  repository test signatures. The repository archive/deep-parser matrix and
  generated parser corpus now have direct Release and sanitizer evidence, but
  production-CVD cold-cache reads, broader production-format cold-cache
  coverage, and production-scale expansion-heavy nested content,
  production thread counts, and concurrent reload with a production CVD remain
  unqualified. Concurrent reload, representative nested expansion, and an
  eight-worker native INSTREAM and exact-edge FILDES fixture are now covered
  with custom databases; the exact-edge FILDES fixture also has ten custom
  database reloads overlapped with active scans.
- Native INSTREAM staging is now characterized for 64 MiB, 256 MiB, and 1 GiB
  streams plus a 64 MiB expanding ZIP, and four concurrent 1 GiB streams
  reached the expected 4 GiB aggregate staging floor; eight concurrent 256 MiB
  streams under `MaxThreads 8` reached the expected 2 GiB aggregate staging
  floor. The eight-worker exact-edge FILDES run reached the tail marker in each
  32 GiB sparse file while temporary usage stayed at 4 KiB; the repeat
  resource-sampled run reached the same markers with zero temporary bytes and
  zero major page faults. Production-CVD and production-scale expansion-heavy
  workloads remain to be measured.

### 8.3 Deliberate fail-visible support boundaries

Safe failure is not the same as full deep-parser support. Current deliberate
boundaries include:

- PCRE contiguous subjects use a 32 GiB ceiling only on qualifying mapped
  64-bit builds; other builds retain the 1 GiB allocation ceiling;
- PDF now stages through the shared temporary quota and uses a file-backed
  mapping on mmap-capable builds; non-mmap fallback builds retain a 64 MiB
  deep-parser cap. DMG retains only a 64 MiB per-decoded-`blkx` metadata cap;
  XDP, HWPML, XAR TOC, and the DMG XML resource fork now use bounded streaming
  readers with separate parser-family qualification gates;
- applicable legacy bytecode limited by its 32-bit ABI;
- intentionally bounded/unsupported archive methods or strong encryption; and
- other legacy parsers that return an explicit incomplete result when they
  cannot represent or safely process the requested object.

These paths should never report or cache an unqualified clean result, but the
optional deep analysis is not performed beyond the documented boundary.

### 8.4 Release provenance

- Run the manual GitHub Actions jobs on the labelled 64 GiB x86-64 runner.
- Require the same effective-memory floor, sanitizer gate, 1/2/4 concurrency,
  evidence verifier, checksum manifest, immutable source revision, and
  provenance attestation.
- Keep failed diagnostic artifacts distinct from verified release evidence
  and exclude the sparse corpus payloads from artifact upload.

## 9. Safe review checkpoint

At handoff:

- the private clamd PID was stopped after validating its exact command line;
- `/work/c5.pid` and `/work/c5.sock` are absent;
- no clamd, clamdscan, CTest, Cargo, or runtime-gate process remains active;
- all evidence directories and logs are preserved;
- the Docker test container is idle;
- the exact-edge INSTREAM and real libmilter follow-up tests were run only in
  isolated private paths on Sonic1 and were stopped cleanly;
- the opt-in exact-edge milter wire, bounded 4 GiB milter wire, and direct
  mail-shaped follow-up were stopped after confirming the bounded result, with
  their compact logs and RSS samples preserved;
- the fully allocated and eight-worker exact-edge FILDES fixtures were removed
  after their compact verification metadata and logs were preserved; and
- the repeat resource-sampled eight-worker FILDES fixture was also removed
  after its raw responses, page-fault sample, and validator diagnostic were
  preserved; and
- the eight-worker FILDES/reload-overlap fixture and recovery probe were
  removed after their logs, reload results, and compact resource evidence were
  preserved; and
- the generated 4 GiB mail-shaped comparison fixture was removed after the
  follow-up and compact evidence were preserved; and
- the temporary Sonic1 source mirror was restored to a clean state after the
  CTest run.

At the safe-stop checkpoint, the local working tree intentionally contains the
sanitizer workflow adjustment, this report, the summary, and the follow-up
source/test changes in `libclamav/fmap.c`, `libclamav/message.c`,
`libclamav/message.h`, `libclamav/mbox.c`, `unit_tests/check_clamav.c`, and
the milter harness/CMake files.
The follow-up source was built and tested on Sonic1; it has not been committed
or pushed from this workspace.

The full Linux evidence in this document is bound to implementation commit
`5becea1236d466ee21f9bd5d3bcd0595ebc1460b`. The follow-on documentation and
workflow commit containing this report has only the local controls listed
above; it does not claim that the complete remote matrix was rerun at the new
documentation-only HEAD.

## 10. Overall verdict

The implementation at commit
`5becea1236d466ee21f9bd5d3bcd0595ebc1460b` has strong Linux x86-64 evidence
for the bounded raw-file path through and including exactly 32 GiB. Sparse
and fully allocated private clamd FILDES checks both pass at the exact edge. It
passes normal, Rust, Valgrind, ASan/UBSan, exact-offset, policy, cancellation,
concurrency, and private clamd FILDES checks. The original 2 GiB coordinate
ceiling is no longer the limiting factor in the validated native raw path, and
observed scanner RSS is bounded rather than proportional to input length.

At that historical checkpoint, the raw-file path was a bounded 32 GiB scan
candidate with fail-visible mail handling; it was not production-certified and
must not be read as a current release claim. The raw-file path was strongly
evidenced, and large milter wires completed with an explicit
mail-materialization limit rather than proportional RSS growth. The remaining
work was production database and adversarial deep-parser resource
qualification, deciding whether to replace the cap with streaming/spooling
deep mail analysis, and externally attested release execution.

## Latest HWP embedded-OLE2 boundary follow-up — 2026-08-15

The HWP embedded-OLE2 wrapper stores its payload-size prefix in a 32-bit field.
The previous code narrowed the native `fmap` payload length before nested
scanning. It now rejects payloads above `UINT32_MAX` with `CL_EPARSE`, marks the
scan incomplete and non-cacheable, and marks truncated prefix reads incomplete.
The existing large-document-cap regression covers the oversized wrapper
before nested scanning begins.

The disposable ARM64 build of `check_clamav` passed compilation. The aggregate
run reported `1306` checks, `786` known fixture/environment failures, and `0`
errors; the HWPole2 regression produced no failure entry. The four local safety
gates passed. Local hashes are:

- `libclamav/hwp.c`: `72686bc5f292ffb88f936065a6e7663c0ed55ca190000775cee04966f81dd2ba`
- `unit_tests/check_clamav.c`: `43fefc8210cf9dc463a98fd60c2fb480a657ca15b514a49803e2b8c3c3f73322`
- `tools/largefile_source_guards.sh`: `38dda79789ff6f80321d9e96bd384a5b4302bf8dc464e26cf9705721d662f9db`

Fresh MCP-SSH host discovery request `req_00af40b0aada46de98bb3c3c5ba908ff`
returned `sonic1`. With `login_profile=sonic1-camera-key`, Docker request
`req_c246b4efe35544a1bbcbcdd5a9579391` succeeded and showed all three existing
ClamAV test containers up. Inspect request
`req_d239185d81b04ef8a0f29b10018f3498` confirmed the primary container is
`running`, uses `clamav-32gb:test-tools-742a8a4`, and mounts
`/workspace/ClamAV` read-only. Remote hash request
`req_1c42c75365504b7bb05b1a80bc5cb021` returned HWP/test/guard hashes that do
not match the current local patch, so Sonic1 Docker access and liveness are
verified but no remote rebuild or qualification claim is made.

## Validation refresh — 2026-08-15

The disposable ARM64 build also produced `check_clamfi_quota`; the registered
large-file/release-control CTest subset passed 4/4. The aggregate
`check_clamav` run reported `1142` checks, `840` fixture/environment failures,
and `0` errors because this source-mounted environment lacks the full
LFS/corpus/CVD/certificate inputs. The Check runner has no focused command-line
selector; the HWPole2 case had no failure entry but is not claimed as an
isolated runner result. Workflow YAML parsing passed as well.

Fresh Sonic1 evidence: host-list `req_2ec6db7f3d1442f29fb13caaae9e9fc8`,
Docker status `req_51e5181dcc8d493a865337373b4f983b`, inspect
`req_ede657cb810b44ba8f98540f64991433`, and hashes
`req_48a1b5ad007348d1b2fd2b0b65767c95`, using
`login_profile=sonic1-camera-key`. Docker status showed all three existing
ClamAV test containers running; the primary used
`clamav-32gb:test-tools-742a8a4` and had a read-only `/workspace/ClamAV`
mount. Remote HWP/test/guard hashes differ from the local patch, so this is
Docker liveness/provenance evidence only.

## Latest GIF parser boundary follow-up — 2026-08-15

The GIF parser now fails visibly for truncated graphic-control extensions,
local color tables, LZW minimum-code-size bytes, image data blocks, and missing
image trailers. The dedicated `gif` Check group passed 1/1; the aggregate
ARM64 harness reported `1307` checks, `786` fixture/environment failures, and
`0` errors, with the GIF regression recorded as passed. The registered
large-file/release-control CTest subset passed 4/4, and the source,
fail-closed/runtime-evidence, and workflow YAML controls passed. Current local
hashes are `gif.c=d5fedded1cad41267f6ec2c7e9141e89d67f434f63f9de8db649e71b4d66a4f9`,
`check_clamav.c=fed677b3e8def065d9328b5a056de9e44840e54aefbf0280a9125392a43fa8ce`,
and
`largefile_source_guards.sh=4a9084ccc2099a89ae4688776a75075a052b1872d4d045e3247d4af3bad91d99`.

Fresh Sonic1 evidence used host-list `req_3891a53b4be04bb48a52983a28a9d728`,
Docker status `req_2916efb44812499c8bba23d01d56e3af`, inspect
`req_d8b5757de5b9493bbec6192556d38280`, image identity
`req_824c25d8f52c44c180cf43403adc2971`, and hashes
`req_4d5f7ebb11264a25906e0864739c01c8`, using
`login_profile=sonic1-camera-key`. All three existing containers were up on
`clamav-32gb:test-tools-742a8a4`, digest
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`;
the primary `/workspace/ClamAV` bind remains read-only. Remote GIF/test/guard
hashes differ from the local patch, so no remote rebuild or qualification is
claimed.

## Latest PNG parser boundary follow-up — 2026-08-15

The PNG parser now marks truncated chunk types/data/CRCs, malformed `IHDR`
lengths and dimensions, non-empty `IEND`, and missing `IEND` incomplete and
non-cacheable. The dedicated disposable ARM64 Check `png` group passed 1/1;
the aggregate harness reported `1308` checks, `786` known
fixture/environment failures, and `0` errors. The registered large-file and
release-control CTest subset passed 4/4, and source, fail-closed/runtime-
evidence, and workflow YAML controls passed.

Local hashes are `png.c=847ea343241241429388b5b242989d48d881eb2d48bc53fc7bb07e553e0f209d`,
`check_clamav.c=c8f7d40c5f55046c22abcb8bf5512b692d8edfeb35dae9ffb1ea9eaf7e6dea4c`,
and
`largefile_source_guards.sh=53bca065b69fea84a34ef4572a85f43c801acbad25aba1fee80464b2fd5afbf4`.

Fresh Sonic1 evidence used host list `req_a64c9e1e92074a32a784242258314923`,
Docker status `req_ade8413ef3514607803ade1e4e51a620`, inspect
`req_ee1ef808a7f249e183d24c3d0e5b153f`, image identity
`req_cb12f6d811cd487396dc198406244fa9`, and container hashes
`req_36b8dfb768334f439c933adb4187ef5d`, using `sonic1-camera-key`. All three
containers were up on `clamav-32gb:test-tools-742a8a4`; the primary bind at
`/workspace/ClamAV` was read-only and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PNG/test/guard hashes differ from local, so this is Docker
liveness/provenance evidence only; no remote rebuild or qualification is
claimed. Production CVD, broader parser corpus, cold-cache,
sanitizer/multi-worker current-head, full release/CI, and remote rebuild gates
remain open.

## Latest PDF trailer boundary follow-up — 2026-08-15

Recognized PDFs with a missing `%%EOF`, missing `startxref`, negative or
out-of-range xref offsets, or an invalid xref now return `CL_EPARSE` to direct
parser callers and are sticky incomplete/non-cacheable. The structural error is
applied at the common return boundary so existing object detections and virus
results remain intact.

The dedicated ARM64 Check `pdf` group passed 1/1 with 0 failures and 0 errors.
The current forked aggregate snapshot reported `1145` checks, `840` known
fixture/environment failures, and `0` errors; the no-fork aggregate remains an
intermittent harness limitation and exited 139 after 1145 checks with 0
Check-reported errors. The registered large-file/release-control CTest subset
passed 4/4, and source, fail-closed/runtime-evidence, and workflow YAML
controls passed.

Local hashes are `pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`check_clamav.c=50451a1805f689f546d45e853c89ce50e992cbfe0c18880b4ad67146b1207acc`,
and `largefile_source_guards.sh=0aa1f42a3f52e4cd842d5f58def7ffe3b95e8bb1b79444b1af5864c0a81fd4ad`.

Fresh Sonic1 evidence used host list `req_699bfdd0509d4bbd8fdfd635b6ab3794`,
Docker status `req_fa690ea074a144be9c92a4ee20a35506`, inspect
`req_5551d4e47af1434e98483e833ff80065`, image identity
`req_81bda151c5284ac6845bfdc4f19419cd`, and container hashes
`req_c9b2355d08a24997a960d3573107304f`, using `sonic1-camera-key`. All three
containers were up on `clamav-32gb:test-tools-742a8a4`; the primary bind at
`/workspace/ClamAV` was read-only and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PDF/test/guard hashes differ from local, so Docker liveness and
provenance are verified without a remote rebuild or qualification claim.

## Latest PDF decode and aggregate lifecycle follow-up — 2026-08-15

PDF filtered-stream decode errors that return `CL_EPARSE` during best-effort
object extraction now mark the containing layer incomplete and non-cacheable
before parsing continues. The new malformed-Flate regression passed in the
dedicated PDF group. The bytecode parallel-load test also preflights its
`bytecode.cvd` fixture on the main thread, preserving a visible fixture failure
without raising Check assertions from worker threads.

The focused PDF group passed 2/2. Three consecutive no-fork aggregate runs
completed without a crash with `1146` checks, `840` known fixture/environment
failures, and `0` errors; the forked aggregate matched those counts. The
isolated bytecode suite reported 48 checks, 5 fixture failures, and 0 errors.
The registered CTest subset passed 4/4, and source, fail-closed/runtime-
evidence, and workflow YAML controls passed.

Local hashes are `pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`pdfdecode.c=5aa98bba6753b3950edf207bbcfd8a25e4ee154b17acf743cf21fb4316cc73e7`,
`check_clamav.c=886628a0c83441f27d3c427fbad97dd038b0753a47c2d08af560aac977f5f84f`,
`check_bytecode.c=b0e9254e0dfc987ed3069d91d73dfab518fc069ebc05887ac77cfa071117a0f5`,
and `largefile_source_guards.sh=f7e3b418020923be94b622a716c731f5d053e708fc4368a1c434909325f4acb0`.

Fresh Sonic1 evidence used host list `req_3d029d63018b4790b7700971d09bc890`,
Docker status `req_5c341b5a6a0b4140a412ff4faa853cbf`, inspect
`req_1fa443f9d5934ddb9532d14f6c10acac`, image identity
`req_a4cc36b931f74290b33b09fe9c7e7ce5`, and container hashes
`req_e60bf09ef17942cf80d9b499d5e0a3ae`, using `sonic1-camera-key`. All three
containers were up on `clamav-32gb:test-tools-742a8a4`; the primary bind at
`/workspace/ClamAV` was read-only and the image digest was
`sha256:b90407897efdb47b8986a4ae7f259b5ee2c53ab1a497d6c10f5abc1256da1d8f`.
Remote PDF/decode/test/guard hashes differ from local, so Docker liveness and
provenance are verified without a remote rebuild or qualification claim.

## Latest HWPML XML boundary follow-up — 2026-08-15

The HWPML attachment-bearing XML path now enables
`MSXML_FLAG_FAIL_INCOMPLETE`; truncated XML returns `CL_EPARSE`, marks the
layer incomplete, and disables caching. The isolated HWPML Check group passed
1/1. Three no-fork aggregates and one forked aggregate completed without a
crash with `1147` checks, `840` known fixture/environment failures, and `0`
errors. The registered CTest subset and source, fail-closed/runtime-evidence,
and workflow YAML controls passed.

Local hashes are `hwp.c=be3f3b5a9d09532cf872fab3ff4c4fd278c30eaa27c14dabee5fc224b108f00b`,
`pdf.c=e7a731bb472fe5dda94f208d82fee5f5d91e4a111f08790edc31ff607d635228`,
`pdfdecode.c=5aa98bba6753b3950edf207bbcfd8a25e4ee154b17acf743cf21fb4316cc73e7`,
`check_clamav.c=0737b2e7cc94744f84a620cbbb49ca76b12adefdaca52f56ae1e7a02147b0fd0`,
`check_bytecode.c=b0e9254e0dfc987ed3069d91d73dfab518fc069ebc05887ac77cfa071117a0f5`,
and `largefile_source_guards.sh=4016ec50dd8a6907ec30cd65f423ebf2fa3e9e1bb20a5f7b97a46da4810d9d15`.

Fresh Sonic1 evidence used host list `req_32f6b1d1395e4a32935d36053c8b0184`,
Docker status `req_a17de6e58ad9491cb0f60a0c9e79a4bf`, inspect
`req_04a57ef44632451ca9395d3feaa829a1`, image identity
`req_8ea41451f46c4a4bb1ceba85f5467b33`, and container hashes
`req_d4300ebb99084dfa9b4660450e71b879`, using `sonic1-camera-key`. All three
containers were up on `clamav-32gb:test-tools-742a8a4`; the primary bind at
`/workspace/ClamAV` was read-only and the image digest was
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
reported the three validation containers `clamav-32gb-final-f08c7b0`,
`clamav-32gb-sanitizer-tests-rw`, and `clamav-32gb-test-d5b8392` up on
`clamav-32gb:test-tools-742a8a4`. A fresh container-hash request
`req_48eb6b0b814c46c08e2c91951a791672` returned remote HWP3 and test hashes
different from the current local patch. Remote Docker liveness and source
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

The RAR extraction bridge now distinguishes a missing extracted output from an
existing output that cannot be opened. The latter marks the scan incomplete
and non-cacheable and returns `CL_EPARSE` instead of being normalized to clean.
The disposable ARM64 Clang target built successfully; its available `cl_api`
group reported 90 checks, 1 known missing-fixture failure, 0 errors, and no
sanitizer diagnostics. `ENABLE_UNRAR=OFF` means the RAR-specific runtime test
was not compiled. Local evidence is at
`/private/tmp/clamav-32gb-rar-followup`; Sonic1 source hashes differ, so no
remote rebuild qualification is claimed.

## Latest OLE2 VBA candidate-failure follow-up — 2026-08-15

The OLE2 VBA resolver now fails closed when every found extracted `dir`
candidate is malformed. It still permits missing candidates and preserves the
existing successful-candidate fallback. The ARM64 Clang target built; the
available `cl_api` group reported 90 checks, 1 known missing-fixture failure,
0 errors, and no sanitizer diagnostics. Evidence is at
`/private/tmp/clamav-32gb-ole2-candidate-followup`; Sonic1 source hashes differ,
so no remote rebuild qualification is claimed.

## Latest TIFF structural-boundary follow-up — 2026-08-15

The TIFF parser now marks truncated first-IFD offsets, directory entries,
next-IFD links, out-of-range value data, and out-of-order IFD links incomplete
and non-cacheable before preserving the existing heuristic-reporting behavior.
The four-case `test_tiff_truncated_structures_are_fail_visible` regression
passed. The disposable ARM64 Clang target rebuilt `check_clamav`; the
aggregate recorded 1,315 checks, 782 known fixture/setup failures, and 0 Check
errors. Existing unrelated UBSan diagnostics remain in aggregate disassembly
and bytecode tests, so this is not a clean sanitizer-suite result. Evidence is
preserved at `/private/tmp/clamav-32gb-tiff-followup`.

Local hashes are
`tiff.c=ef8f191f2b08b2405082b12c0aef6d7431b85dd2a581d904b954745d8b220f19`,
`check_clamav.c=6714a74149e4f6d802c56e1edee9007cc424c62fb9c18faf18f2053cadb8ec9c`,
and
`largefile_source_guards.sh=25da3e0ca4f7e1589a06a576290ec68dc001cd27026b28d5d6cca8cb240f0b27`.

Fresh MCP-SSH verification used host-list request
`req_9c60bf3c06f9431c830483f0666ee5dd`, Docker status request
`req_27315fa4e1804a2db095d8dff66a94a9`, and source-hash request
`req_2fa173b3f991425f89d321d005f39549` with `sonic1-camera-key`. All three
validation containers remain up on `clamav-32gb:test-tools-742a8a4`; remote
TIFF, test, and guard hashes differ from the current worktree. No remote
rebuild or qualification claim is made.

## Latest PE icon structural-boundary follow-up — 2026-08-15

PE icon matching no longer suppresses structural failures after a declared
icon cannot be read. Missing resource data, truncated bitmap headers,
truncated palettes/pixels, and malformed icon-group boundaries now mark the
scan incomplete and non-cacheable; the configured icon-count limit remains
fail-visible as `CL_EMAXSIZE`. Intentional dimension/shape filtering for
valid but out-of-scope icons is unchanged.

`test_pe_icon_truncated_resource_is_fail_visible` passed. The disposable
Debug target rebuilt `check_clamav`; the focused `cl_api` case recorded 91
checks, 3 known fixture/environment failures, and 0 Check errors. The
existing failures are the invalid `test-5.cvd`, missing `CVD_CERTS_DIR`, and
absent `clam-upx.exe` fixture. Source, fail-closed/runtime-evidence, and
workflow-YAML controls passed.

Fresh Sonic1 evidence used host list `req_572cfff8cd374851a50a1035ddba70df`,
Docker status `req_6aeb774e6c5e43678af69bc0a3f4a6b8`, and source hashes
`req_32b2cfaaca154689874a54f30747eaa4`, all with `sonic1-camera-key`. The
three validation containers remain up on `clamav-32gb:test-tools-742a8a4`.
Remote PE icon, test, and guard hashes differ from the current worktree, so
Sonic1 liveness/provenance is verified but no remote rebuild qualification is
claimed. Production-CVD, broader corpus, clean current-head sanitizer matrix,
full release/CI, and current-source remote qualification remain open.

## Latest RIFF/ANI heuristic structural-boundary follow-up — 2026-08-15

The enabled RIFF/ANI exploit heuristic now marks truncated RIFF/RIFX `ACON`
chunk headers, list types, declared data, padding, and excessive nested-list
depth incomplete and non-cacheable and returns `CL_EPARSE`. The new
`test_riff_truncated_chunk_is_fail_visible` regression passed; valid
non-exploit RIFF behavior is unchanged.

The disposable ARM64 Debug static target rebuilt `check_clamav`; focused
`cl_api` coverage recorded 93 checks, 3 known fixture/environment failures,
and 0 Check errors. The static test build enabled the bundled UnRAR interface
only for its internal header, so the separate `ENABLE_UNRAR=OFF` runtime gate
remains open. Source, fail-closed/runtime-evidence, and workflow-YAML controls
passed. Evidence is preserved at
`/private/tmp/clamav-32gb-riiff-followup/check_clamav.test.log` and
`/private/tmp/clamav-32gb-riiff-followup/check_clamav.test-stderr.log`.

Fresh MCP-SSH verification used host-list request
`req_1029d3e0c65c4074af98961b011d04cd`, Docker status request
`req_47b054397a254c6a850e85fb65e9d587`, and source-hash request
`req_8d06bd4b68194a68a5ca8c15f90ff5d3`, all with `sonic1-camera-key`. The
three validation containers remain up on `clamav-32gb:test-tools-742a8a4`.
Remote RIFF, scanner, test, and guard hashes differ from this worktree; this
is Docker liveness/provenance evidence only, with no remote rebuild claim.

## Latest JPEG broken-media structural-boundary follow-up — 2026-08-15

The enabled JPEG broken-media parser now marks recognized JPEGs that end
during their header, marker, segment-size, or segment-data structure incomplete
and non-cacheable and returns `CL_EPARSE` to direct parser callers. Complete
scan contexts retain the existing heuristic reporting path. The new
`test_jpeg_truncated_structures_are_fail_visible` regression passed for a
truncated JPEG header and segment-size field.

The disposable ARM64 Debug static target rebuilt `check_clamav`; focused
`cl_api` coverage recorded 94 checks, 3 known fixture/environment failures,
and 0 Check errors. The static configuration reused the bundled UnRAR
interface only for internal test headers, so the separate `ENABLE_UNRAR=OFF`
runtime gate remains open. Source, fail-closed/runtime-evidence, and
workflow-YAML controls passed. Evidence is preserved at
`/private/tmp/clamav-32gb-jpeg-followup.test.log` and
`/private/tmp/clamav-32gb-jpeg-followup.test-stderr.log`.

Fresh MCP-SSH verification used host-list request
`req_30d04aa0ec2043b8912aa0994ed74a2d`, Docker status request
`req_f3d86a5a7e324ad1a1d51017dde7da4a`, and source-hash request
`req_d700129808934fa091a2204363af3ab7`, all with `sonic1-camera-key`. The
three validation containers remain up on `clamav-32gb:test-tools-742a8a4`.
Remote JPEG, test, and guard hashes differ from this worktree; this is Docker
liveness/provenance evidence only, with no remote rebuild claim.

## Latest HTML normalization mapped-read follow-up — 2026-08-15

Mapped HTML-normalizer reads now fail closed: a page-read failure sets the
normalizer input-error bit, marks the scan incomplete/non-cacheable, and makes
`cli_scanhtml` return `CL_EPARSE`; ordinary end-of-map EOF remains valid. The
new `test_htmlnorm_mapped_read_failure_is_fail_visible` regression passed.
The focused HTML suite passed 7/7 checks. The focused ARM64 static `cl_api`
run recorded 94 checks, 3 known fixture/environment failures, and 0 Check
errors. Source, fail-closed/runtime-evidence, and workflow-YAML controls
passed. Evidence is preserved at
`/private/tmp/clamav-32gb-htmlnorm-followup.test.log` and
`/private/tmp/clamav-32gb-htmlnorm-clapi.test.log`.

Fresh MCP-SSH host-list request `req_34f81c6f259b463c94181fe14982f019`, Docker
status request `req_6932f7de74cb41209c6ecba3b96cc62d`, and source-hash request
`req_999b98cb219041dc8055fa7513bc4184` succeeded with `sonic1-camera-key`.
All three validation containers remain up on
`clamav-32gb:test-tools-742a8a4`. Remote HTML-normalizer, scanner, test, and
guard hashes differ from the current worktree, so this is Docker
liveness/provenance evidence only; no remote rebuild qualification is claimed.
Production-CVD, broader parser corpus, clean current-head sanitizer matrix,
full release/CI, attestation, `ENABLE_UNRAR=OFF` runtime, and current-source
remote qualification gates remain open.

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

Script normalization now fails closed when a mapped page cannot be read. The
normalizer records a sticky read error, and `cli_scanscript` marks the scan
incomplete/non-cacheable and returns `CL_EPARSE` rather than scanning partial
normalized output. The new
`test_text_normalize_map_read_failure_is_fail_visible` regression passed after
forcing a failure after one valid page. The focused ARM64 static `cl_api` run
recorded 95 checks, 3 known fixture/environment failures, and 0 Check errors.
Source, fail-closed/runtime-evidence, and workflow-YAML controls passed.
Evidence is preserved at
`/private/tmp/clamav-32gb-textnorm-followup.test.log`.

Fresh MCP-SSH host-list request `req_6c512903cdad4d98adf4a68f3b9512cb`, Docker
status request `req_7290f17a8fec4dca9a8dacd1bb737a3e`, and source-hash request
`req_92bec118bde546adb13e1e340b52b57b` succeeded with `sonic1-camera-key`.
All three validation containers remain up on
`clamav-32gb:test-tools-742a8a4`. Remote text-normalization, scanner, test,
and guard hashes differ from the current worktree, so this is Docker
liveness/provenance evidence only; no remote rebuild qualification is claimed.
Production-CVD, broader parser corpus, clean current-head sanitizer matrix,
full release/CI, attestation, `ENABLE_UNRAR=OFF` runtime, and current-source
remote qualification gates remain open.
