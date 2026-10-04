# R12 Sonic1 v3 fully materialized 32-GiB clean control — 2026-09-29

## Candidate and independent oracle

This is a focused clean, full-length native-matcher control on `sonic1` /
`sonic1-camera-key`, not a full parser-family or release qualification. The
deterministic v3 source package SHA-256 is
`926a757ff874d23fb771353ecd9a58f51c90e6de602edc1904c69f0cd2bd9cd8`;
the independently regenerated source manifest SHA-256 is
`4438310a5545a41afa72801adbb89902a06467ba109c863103cadd97f2f6a8c8`.
The container image ID is
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
Release `clamscan` SHA-256 is
`3427c12ad8ad56a6f598838985e803f709d319c903309754ed1fdb6f09bd0d95`;
C ASan/UBSan `clamscan` SHA-256 is
`3dcb231ba2fe434914202622c220abb0eceb72bc263af3bbe94058fbb1ce3e42`.

The read-only `/ram/edge-stable.bin` fixture is exactly 34,359,738,368
bytes, independently hashed earlier to
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
Post-run `stat` preserved 67,108,880 allocated 512-byte blocks, inode
8149459, and mtime 1790047133. The isolated clean-control NDB contains
`NDB.Clamav-Unit-Test-Signature:0:*:434c414d41562d544553542d535452494e472d4e4f542d4549434152`,
whose literal is `CLAMAV-TEST-STRING-NOT-EICAR`; its SHA-256 is
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.

An initial independent absence check was **invalid and failed**: managed
`grep -a -F -q` job `job_95fd6fd19b4a40bb91f62f666aec4c57`
exited 137 with `Killed` on stderr. Sonic1's host `oom_kill` count rose
from 46 to 47. Kernel logs at 2026-09-28 23:59:21 UTC identify `grep`
PID 1171582 as the global-OOM victim, at 30,442,984 KiB anonymous RSS.
The newline-free 32-GiB input can force line-oriented `grep` to retain an
unbounded line. This failed job is retained as an unsafe-oracle diagnostic,
**not** clean-scan evidence and **not** a no-OOM pass. It was not retried.

Replacement managed job `job_36f13a23788c4cb09f2db57658ebbe8c`
used Python `open(..., buffering=0)` and 4-MiB reads, carrying only the
last 27 bytes between chunks for the 28-byte literal. It exited zero after
reading all 34,359,738,368 bytes and reported
`SIGNATURE_ABSENT_BYTES 34359738368 MAX_CHUNK_BYTES 4194304 OVERLAP_BYTES 27`.
It checked file size plus device/inode/size/mtime stability before and
after. This bounded, full-file oracle, not either ClamAV result, supplies
the expected clean verdict. The OOM counter was 47 before both accepted
scanner runs and stayed 47 afterward.

A further bounded, independent full-file oracle ran as managed job
`job_212fd3bc3c444f578babf7946ab86468`. In a single 4-MiB-chunk pass
with 27-byte overlap it recomputed the fixture SHA-256 above, read all
34,359,738,368 bytes, found exactly one `EDGE-LATE-MARKER` at offset
34,359,738,352 (EOF−16), and found zero occurrences of the clean-control
literal. It checked stable device, inode, size, mtime, ctime and allocated
blocks across the read; allocated blocks represented 34,359,746,560 bytes.
The job exited zero with empty stderr, and host `oom_kill` remained 47.
This cross-check strengthens both the clean oracle here and the positive
tail-marker oracle used by the v3 concurrency receipt; it does not erase
the earlier failed `grep` attempt.

The source-controlled bounded oracle was then tested independently as
described in `R05-sonic1-bounded-binary-oracle-2026-09-29.md`. Final managed
job `job_954fec912a0242f68685b41ed16d7070` recomputed the same full
fixture hash and literal results while also retaining
`first_hole_offset=34359738368` (EOF), with allocated bytes above file
size. Its script SHA-256 is
`cbfe3aa36164347e42181c25e8698b1e1f6bae20ff8a721303d375fe029b7024`.

## Matching-source scans

Both disposable containers used the same read-only fixture and isolated
single-file clean-control NDB, explicit 32-GiB MaxFileSize/MaxScanSize/
MaxContiguousSize/PcreMaxFileSize, 64-GiB MaxTemporarySize,
`MaxScanTime=14400000`, case-private disk-backed temporary and JSON report
paths, and a read-only bind of host GNU `time -v`. They ran nonroot with
network disabled, dropped capabilities, and `no-new-privileges`. The
sanitizer job set `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.

| Build | Managed job | Report elapsed | Maximum RSS | Outcome |
| --- | --- | ---: | ---: | --- |
| Release | `job_9fabf83226aa430e87fb7a4b90b08625` | 130,120 ms | 95,868 KiB | exit 0, `COMPLETE`, clean |
| C ASan/UBSan | `job_cd4a9e8880f94dd2a7b4d0ce116f7393` | 235,579 ms | 123,348 KiB | exit 0, `COMPLETE`, clean |

Each stdout said `/ram/edge-stable.bin: OK`; each job had zero captured
stderr bytes. An independent read-only checker required exactly one JSON
report, `status=0`, clean verdict, `root_size=logical_bytes=34359738368`,
`skipped_operations=0`, `temporary_bytes=0`, no alert, GNU-time exit 0 and
zero swaps, and an empty case-private temporary directory. Both passed.
Artifacts remain at
`/qualification/r12-v3-clean-edge-20260929-release-run01/` and
`/qualification/r12-v3-clean-edge-20260929-asan-run01/` respectively. The
post-run host had zero active swap, `oom_kill=47`, and no leftover scan
containers. The qualification volume had 42,435,552 KiB free afterward.

## Boundary

The two accepted scans had no OOM event within their own measured windows;
the earlier `grep` OOM means the wider session **must not** be described as
OOM-free. These controls prove matching-source Release/C-sanitizer parity for
one clean exact-size native-matcher case; they do not supply Rust sanitizer
instrumentation, production CVDs, parser/deep-inspection cases, daemon or
stream ingress, 68-GiB service admission, fanotify, or full R04 case binding.
No software was installed, no usage reset was used, and no GitHub workflow,
commit, or push was made.
