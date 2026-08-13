# ClamAV 32 GiB Development and Validation Status

**Status date:** 2026-08-13

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
exactly 32 GiB file through FILDES and `clamdscan --stream` refused a regular
32 GiB + 1 file without sending a truncated prefix. The candidate is now a
strong review candidate for the bounded sparse raw-file path, but it is not
yet production-certified: exact-edge clamd INSTREAM, real milter protocol,
production CVD/custom-database, deep-parser, materialized/cold-cache workloads,
and GitHub runner provenance remain to be completed.

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

Primary evidence:

- `logs/fdpass.exit`, `logs/fdpass.out`, `logs/fdpass.err`, `logs/fdpass.time`
- `logs/clamd.log`, `logs/clamd.stderr`
- `logs/daemon-before-fdpass.status`, `logs/daemon-after-fdpass.status`
- `logs/stream-plus-one.*`
- `logs/shutdown.txt`

## 7. Memory interpretation

The current measurements demonstrate that sparse sequential raw scanning is
not using RAM proportional to file size:

- one Release worker peaked near 101 MiB RSS;
- four Release workers had a 403,544 KiB sum of per-worker peak RSS;
- one ASan/UBSan worker peaked near 136 MiB;
- four ASan/UBSan workers had a 543,972 KiB sum of per-worker peak RSS; and
- the private clamd exact-edge scan peaked at 96,584 KiB for the daemon.

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

- Run a complete exact-32-GiB clamd INSTREAM transfer and verify tail-marker
  detection, temporary-file cleanup, daemon/client resource use, and framing.
- Run real libmilter protocol integration for clean, infected, exact-limit,
  and limit-plus-one messages. The allocation-free milter quota test has
  passed, but it does not prove libmilter framing and connection lifecycle.
- A literal 4 GiB/32 GiB milter wire transfer remains unproven unless a safe
  private state-seeding test seam is added.

### 8.2 Workload qualification

- Measure a full official production CVD plus representative custom
  signatures; the current runtime database is deliberately tiny.
- Exercise materialized rather than sparse files, cold-cache reads, malformed
  archives, expansion-heavy nested content, production thread counts, and
  concurrent database reload.
- Characterize temporary-disk usage for INSTREAM and expanding containers.

### 8.3 Deliberate fail-visible support boundaries

Safe failure is not the same as full deep-parser support. Current deliberate
boundaries include:

- PCRE contiguous subjects capped at 1 GiB;
- legacy PDF, XDP, HWPML, XAR TOC, and DMG metadata paths capped at 64 MiB;
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
- the Docker test container is idle; and
- no exact-edge INSTREAM or milter test was started after the review-stop
  request.

At the safe-stop checkpoint, before these documents were prepared, the only
pre-existing local uncommitted source-tree change was the sanitizer workflow
adjustment in `.github/workflows/cmake.yml`. That change and these documents
passed YAML parsing, source guards, the POC fail-closed harness, the runtime-
evidence verifier harness, and `git diff --check`.

The full Linux evidence in this document is bound to implementation commit
`5becea1236d466ee21f9bd5d3bcd0595ebc1460b`. The follow-on documentation and
workflow commit containing this report has only the local controls listed
above; it does not claim that the complete remote matrix was rerun at the new
documentation-only HEAD.

## 10. Overall verdict

The implementation at commit
`5becea1236d466ee21f9bd5d3bcd0595ebc1460b` has strong Linux x86-64 evidence
for the bounded sparse raw-file path through and including exactly 32 GiB. It
passes normal, Rust, Valgrind, ASan/UBSan, exact-offset, policy, cancellation,
concurrency, and private clamd FILDES checks. The original 2 GiB coordinate
ceiling is no longer the limiting factor in the validated native raw path, and
observed scanner RSS is bounded rather than proportional to input length.

The appropriate status is **review-ready 32 GiB raw-scan release candidate,
not yet production-certified**. The remaining work is concentrated in real
INSTREAM/milter integration, production database and adversarial deep-parser
resource qualification, and externally attested release execution.
