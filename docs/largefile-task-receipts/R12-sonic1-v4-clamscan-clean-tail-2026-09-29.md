# R12 Sonic1 v4 exact-32-GiB clamscan clean/tail parity — 2026-09-29

## Provenance and independent oracle

This is focused, source-bound CLI **file** evidence, not a complete R10/R12
or release gate. Host/profile: `sonic1` / `sonic1-camera-key`. The v4
deterministic source package SHA-256 is
`2efc584180e27b93bfcce704e9a29336353a951c2a36e04c13def7360c93eafe`,
committed by MCP-SSH transfer
`transfer_1fa2dcffa4e94708b78b7b7e06d06a64`; extracted source
manifest SHA-256 is
`1ab7e63f3b74eb987e2eef9b79a672e4fedab83bda83ed13c9895ad9bf8e1ff0`.
The independently checked v4 Release `clamscan` SHA-256 is
`064be4e7f5b9b3d8f65c2ea09d12d28babb288fb98f7b435a350fc1a575a8479`;
the v4 C ASan/UBSan binary SHA-256 is
`37e6cf687ff2984aafc3f2abbf113d04fa6d6f48d72498bf6fce42620f1e48c2`.
All four disposable jobs used image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
network disabled, UID/GID 1000, dropped capabilities, and
`no-new-privileges`. Host GNU `/usr/bin/time` was read-only bound into
each container to write a separate peak-RSS record.

The read-only `/ram/edge-stable.bin` fixture is exactly 34,359,738,368
bytes. The source-controlled independent oracle in
`R05-sonic1-bounded-binary-oracle-2026-09-29.md` recomputed its SHA-256
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`,
confirmed the first hole at EOF, one `EDGE-LATE-MARKER` at offset
34,359,738,352 (EOF−16), and zero occurrences of the clean-control
literal. Its retained result SHA-256 is
`1c275047d0090cc1fcc84434500ce00e4ede4bd5bc032ee9be389e7efa838b62`.
The isolated positive `large-edge.ndb` SHA-256 is
`24f6061b35491ee66a054b4a67145d138356188aeb2e16cd3bdcf98925fd1300`;
the isolated `clean-control.ndb` SHA-256 is
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.

## Four separately retained cases

Each case used the same explicit 32-GiB MaxFileSize, MaxScanSize,
MaxContiguousSize and PcreMaxFileSize, 64-GiB MaxTemporarySize,
`MaxScanTime=14400000`, `--alert-exceeds-max=yes`, a case-private
disk-backed temporary directory, and one structured JSON report. The
sanitizer cases set `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Artifacts are under
`/qualification/r12-v4-clamscan-edge-20260929/{case}/`.

| Case | Managed job | Scanner exit / report completion | Report elapsed | Peak RSS |
| --- | --- | --- | ---: | ---: |
| Release clean | `job_d904db4dd33a433f96a8a53613271e68` | 0 / `COMPLETE` | 139,018 ms | 97,400 KiB |
| Release tail detection | `job_77dcd47ec9524e70b33d70e3890c4761` | 1 / `DETECTION_TERMINATED` | 134,403 ms | 97,292 KiB |
| C ASan/UBSan clean | `job_d2975706249d48078532fa33221e13ec` | 0 / `COMPLETE` | 225,094 ms | 138,516 KiB |
| C ASan/UBSan tail detection | `job_0836130c46344209b2d30efb3ed86120` | 1 / `DETECTION_TERMINATED` | 219,938 ms | 136,104 KiB |

An independent read-only checker parsed exactly one report and one GNU
time file per case. All four reports recorded
`root_size=logical_bytes=34359738368`, `matcher_bytes=34368129024`,
`skipped_operations=0`, `temporary_bytes=0`, and one file scanned. Clean
reports had no alert; both positive reports named
`NDB.LargeFile-Edge.UNOFFICIAL` at exact offset 34,359,738,352.
Normalized Release/C-sanitizer outcome, verdict, completion, size,
matcher/contiguous/temp bytes, file/recursion/parser/detector/skip
counters, file type and alert fields matched for each clean/detection
pair. Expected detection exit 1 is not an execution fault. All job
stderr streams were empty, all GNU-time swap counts were zero, and all
case-private temp directories were empty.

All four containers were observed running together; starts were Unix
seconds 1790646328, 1790646332, 1790646337 and 1790646342, with the
first ending at 1790646467, proving at least 125 seconds of overlap.
The conservative sum of individual peak RSS values was 469,312 KiB;
this mixed-build observation is **not** the same-binary 1/2/4-worker
runtime-gate subcase. Afterward there were no leftover case containers;
fixture size, 67,108,880 allocated 512-byte blocks, inode 8149459 and
mtime 1790047133 were unchanged. Host `oom_kill` remained at its
pre-run value 47, and swap remained disabled. The earlier unrelated
`grep` OOM diagnostic is retained separately and is not erased by these
case-local no-OOM observations.

## Boundary

This demonstrates current-v4 CLI **file** clean completion and exact
tail detection with C-sanitizer parity under custom signatures. It does
not qualify stdin, daemon/client/milter ingress, parser deep inspection,
Rust address instrumentation, the 68-GiB service staging admission,
full-subject PCRE phases, privileged fanotify, production CVDs, all R04
capability case records, or final readiness. No software was installed,
no usage reset was used, and no GitHub workflow, commit, or push occurred.
