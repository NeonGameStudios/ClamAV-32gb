# R03 Sonic1 v3 C ASan/UBSan exact edge — 2026-09-28

This receipt adds a fresh Linux x86-64 C sanitizer build and test run for the
same deterministic v3 candidate used by
`R12-sonic1-v3-onenote32g-and-build-2026-09-28.md`. It is not Rust address
instrumentation or final release qualification.

## Source, runner, and build

- Sonic1 login: `sonic1` / `sonic1-camera-key`; container
  `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
  image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Deterministic source package SHA-256:
  `926a757ff874d23fb771353ecd9a58f51c90e6de602edc1904c69f0cd2bd9cd8`;
  durable transfer `transfer_2b80171d4a1b451ba968061658d69cde`.
  Independently regenerated extracted source manifest SHA-256:
  `4438310a5545a41afa72801adbb89902a06467ba109c863103cadd97f2f6a8c8`.
  Source: `/qualification/source-yc-stream-v3-20260928`.
- Separate sanitizer build:
  `/qualification/build-yc-stream-v3-20260928-asan`.
  Configure job `job_8381c93d14314f1abde8db2f29dd5f95` and build job
  `job_936c20cb6f154d0ab97328af446cd56c` both exited zero. The build
  took 486 seconds with no captured stderr. It used GCC 12.2.0,
  `RelWithDebInfo`, `-fsanitize=address,undefined -fno-omit-frame-pointer`
  for C/C++, sanitizer link flags, Werror, and the same required feature
  toggles as the v3 Release build, including UnRAR, milter, clamonacc,
  static/shared libraries and large-file qualification tests. Systemd was
  requested but its development library was absent; bytecode runtime is
  interpreter. No dependency was installed.
- `CMakeCache.txt` SHA-256:
  `cbeeee7f37466a63855612cd45224a209a588986a983e963e06243dd61ec69e5`;
  `clamscan` SHA-256:
  `3dcb231ba2fe434914202622c220abb0eceb72bc263af3bbe94058fbb1ce3e42`;
  `unit_tests/check_clamav` SHA-256:
  `f4143f475d959dc2bada2d50b25b85f98a63dfb19ff61654b04f8a6df2e53014`.
  The cache binds `CLAMAV_SOURCE_COMMIT` and
  `CLAMAV_SOURCE_MANIFEST_SHA256` to the v3 manifest above. Independent
  inspection of `compile_commands.json` found 543 C/C++ commands and zero
  missing either address or undefined-behavior sanitizer flags.

## Tests and resource boundary

- Managed non-edge CTest job `job_d51d87203c4d4da39251e85d6c290657`
  exited zero: **31/31 passed** in 423.71 seconds, including libclamav,
  stable-Rust functional tests, scanner, daemon, milter, source guards and
  evidence controls. Its dedicated scratch tree
  `/qualification/tmp-yc-stream-v3-20260928-asan-tests` retains about 389 MiB
  of test artifacts. They were not deleted or called clean.
- Managed exact-edge CTest job `job_443723638f0e49f98c8274ef8049cd03`
  exited zero: **1/1 passed** in 752.76 seconds. It exercised the existing
  path, descriptor and fmap assertions against read-only
  `/ram/edge-stable.bin`, exactly 34,359,738,368 bytes with
  `EDGE-LATE-MARKER` at EOF−16. Before and after, `stat` gave the same
  67,108,880 allocated 512-byte blocks, inode 8149459 and mtime 1790047133.
  Its separate scratch directory
  `/qualification/tmp-yc-stream-v3-20260928-asan-edge` was empty afterward.
  CTest reported no failure and job stderr was empty; no sanitizer diagnostic
  was reported. A sampled `check_clamav` RSS is not a peak-memory proof.
- Container `memory.events` remained `oom=0` and `oom_kill=0` before and
  after the exact test. `/proc/swaps` listed no active swap. The qualification
  volume had 42,435,780 KiB available afterward, below the required 68-GiB
  disk-backed service admission threshold.

## Exact-size OneNote C sanitizer follow-up

Managed job `job_9bd5fc06c7944b8991b76572c99113b5` ran the same
fully allocated 34,359,738,368-byte late-child OneNote fixture and custom
`late-mz.ndb` database as the matching-source Release run, using this v3
sanitizer `clamscan` binary, a separate case-private disk-backed temporary
directory, 32-GiB MaxFileSize, and 64-GiB MaxScanSize/MaxTemporarySize.
The database SHA-256 was
`18e92066983cbc35d84ccd8a1c83b09ddf73c965b4032b5930a4b6724965176b`.
ASan leak detection and ASan/UBSan halt-on-error were enabled.

The job exited 1 after 141.316 seconds, the expected malware-detection exit
code. Job stderr had zero bytes. Text output named
`OneNote.Reader.LateMZ.UNOFFICIAL FOUND` and gave input SHA-256
`1c593530684ac8c98d818437db669e556966051e4b1c4b4e9a65c049623feacf`,
equal to the independently computed fixture checksum in the matching Release
receipt. The structured report at
`/qualification/r12-v3-onenote32g-asan-20260928-run01/scan-report.jsonl`
recorded `status=1`, `completion=DETECTION_TERMINATED`,
`file_type=CL_TYPE_ONENOTE`, `root_size=34359738368`,
`logical_bytes=34359738912`, `matcher_bytes=544`,
`temporary_bytes=34359720552`, `files_scanned=2`, and
`skipped_operations=0`. This is a late-child detection, not a clean full-child
scan. The case-private temporary directory was empty afterward; fixture
size, allocated blocks, inode and mtime were unchanged. Container OOM and
OOM-kill counters remained zero. The sampled temporary tree reached about
26 GiB while the job was live; the report's temporary-byte counter is the
case's authoritative scanner value, not a measured process RSS peak.

Only stable Rust 1.97.1 is installed in the container; Sonic1 host has no
`rustup` executable on its path. The build's stable `RUSTFLAGS=-C
link-arg=-fsanitize=address,undefined` links sanitizer runtimes but does
**not** instrument Rust code. The required nightly `-Zsanitizer=address`
artifact and matching Rust suite remain open. This receipt also does not
qualify Rust OneNote address instrumentation, PCRE whole-workload RSS,
service admission, fanotify, production CVDs, capability-specific cases, or final
readiness. No usage reset, software install, GitHub workflow change, commit,
or push was made.

## Matching-source C sanitizer native-tail follow-up

Managed job `job_a521880e535d4751af18e98fac86f0a0` ran the same v3 C
ASan/UBSan `clamscan` against the read-only, fully allocated
34,359,738,368-byte `/ram/edge-stable.bin` used by the Release concurrency
case. It used the custom `large-edge.ndb` signature, a private evidence root
at `/qualification/r13-v3-asan-native-tail-20260928-run01/`,
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`, and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. The exact fixture and
database hashes, plus the Release 1/2/4-worker results, are retained in
`R13-sonic1-v3-concurrency-2026-09-28.md`.

The job exited 1 after 244 seconds, the expected malware-detection code,
with zero captured stderr bytes and
`NDB.LargeFile-Edge.UNOFFICIAL FOUND` on stdout. Its structured report
records `status=1`, `DETECTION_TERMINATED`, `root_size=34359738368`, exact
alert offset 34,359,738,352 (EOF−16), `skipped_operations=0`, and
`temporary_bytes=0`. Host GNU `time -v`, read-only bound into the disposable
container, recorded 122,208 KiB maximum RSS, zero swaps, and exit status 1.
The private temporary directory was empty; the container was removed;
the fixture's size and allocated blocks were unchanged. Host `oom_kill`
remained 46 before and after, with no active swap. This is a C sanitizer
positive tail scan, not Rust address instrumentation or a full release gate.
