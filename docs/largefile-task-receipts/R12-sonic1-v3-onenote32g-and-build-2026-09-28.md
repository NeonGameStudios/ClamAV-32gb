# R12 Sonic1 current-source build and exact 32-GiB OneNote detection — 2026-09-28

## Identity and scope

This is development/acceptance evidence for a fresh dirty-tree candidate, not
final release qualification. Host/profile: `sonic1` / `sonic1-camera-key`.
Container: `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`;
image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The deterministic source package is
`/tmp/clamav-yc-stream-20260928-v3-source.tar.gz`, 17,899,612 bytes,
SHA-256 `926a757ff874d23fb771353ecd9a58f51c90e6de602edc1904c69f0cd2bd9cd8`,
committed by MCP-SSH transfer `transfer_2b80171d4a1b451ba968061658d69cde`.
The independently regenerated source manifest is
`4438310a5545a41afa72801adbb89902a06467ba109c863103cadd97f2f6a8c8`.
Source root: `/qualification/source-yc-stream-v3-20260928`; Release build:
`/qualification/build-yc-stream-v3-20260928-release`.

The Release CMake cache SHA-256 is
`51b305aacc41ddc1a5f508b7a1ac0333fbc0cdfa2ef126880dd39d0f7f3098ba`;
`clamscan` SHA-256 is
`3427c12ad8ad56a6f598838985e803f709d319c903309754ed1fdb6f09bd0d95`;
`unit_tests/check_clamav` SHA-256 is
`132fb0800a6b88d8b737637625d45319edbcd6f94701c97def6b4e4269e6c740`.
The configure (`job_b4da88c0295f4e52b27ef04ac0729a7e`) and full Release
build (`job_92a52b904efc4555a04a7c0048aa2121`) exited zero with Werror.
The non-edge CTest suite (`job_810cd73a628841b1bf1ad1fc2ae1e011`)
passed 31/31, and the exact, fully materialized library path/fd/fmap edge
CTest (`job_945a297649b24f0b990ab9b451019ee5`) passed 1/1. The latter
used the read-only 34,359,738,368-byte `/ram/edge-stable.bin` with
`EDGE-LATE-MARKER` at EOF−16. These runs do not replace sanitizer evidence.

## OneNote late-child run

The positive fixture
`/dev/shm/r12-v17-onenote32g-clamscan-diskspool-20260927-run01-input.one`
was exactly 34,359,738,368 bytes and fully allocated (`stat` 67,108,864
512-byte blocks). Its SHA-256, checked by a separate managed hash job
`job_db443d1c82094fc5a6602015e1e5e474`, was
`1c593530684ac8c98d818437db669e556966051e4b1c4b4e9a65c049623feacf`;
this equals the scanner's reported input hash. The original 52,297-byte
OneNote source has `MZP` at offset 33,342. In the padded exact-size fixture,
the independent expected position is
`34359738368 - 52297 + 33342 = 34359719413` (EOF−18,955); a direct
three-byte read there returned `MZP`.

Managed scan `job_ee73117da39b4141913e1f0c2e01df6f` used the v3 Release
binary, private custom DB `late-mz.ndb` (`OneNote.Reader.LateMZ:0:0:4d5a50`),
32-GiB `MaxFileSize`, 64-GiB `MaxScanSize` and `MaxTemporarySize`, disk
forcing, and a case-private temporary directory. It exited 1 in 137.435
seconds, the expected detection exit code, not an execution fault. Text
output named `OneNote.Reader.LateMZ.UNOFFICIAL FOUND`. The structured report
at `/qualification/r12-v3-onenote32g-clamscan-20260928-run01/scan-report.jsonl`
records `status=1`, `completion=DETECTION_TERMINATED`,
`file_type=CL_TYPE_ONENOTE`, `root_size=34359738368`,
`logical_bytes=34359738912`, `matcher_bytes=544`,
`temporary_bytes=34359720552`, `files_scanned=2`,
`max_recursion_depth=1`, `skipped_operations=0`, and exact alert name.
The 544-byte child scan count is consistent with stopping at the late
detected child; it is not a claim that all logical child content was scanned.

Post-scan `stat` preserved fixture size, block count, inode 1619 and mtime
1790541183. The case-private temporary directory contained only `.` and
`..`; container `memory.events` showed `oom=0`, `oom_kill=0`. The
qualification volume had 46,852,296 KiB available afterward. The run's
reported temporary bytes remain under the 64-GiB scan budget, but the volume
does **not** meet the separate 68-GiB disk-backed service admission rule.
The shared non-edge CTest temporary tree retains about 389 MiB in `clamav-*`
files and two metadata directories dated 22:12–22:15 UTC, before this
OneNote job began at 22:25 UTC. It is not certified clean by this
case-private cleanup check, and those retained test artifacts were not
deleted or attributed to the OneNote scan.

## Boundary

The earlier v3 OneNote attempt set `MaxScanSize` to 32 GiB and legitimately
returned `Heuristics.Limits.Exceeded.MaxScanSize`; it is superseded by this
64-GiB-budget rerun, not relabeled as a parser failure. This receipt proves a
current-source Release build, broad CTest pass, exact-size library edge and
one late-child OneNote detection. It does not qualify every parser/ingress
case, Rust address instrumentation, production CVDs, whole-workload PCRE RSS,
fanotify, 68-GiB service admission, or final release readiness. No software
was installed, no GitHub workflow was changed or triggered, and nothing was
pushed.
