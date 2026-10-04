# R13 Sonic1 v3 exact-edge concurrency — 2026-09-28

## Identity and scope

This is focused Linux x86-64 evidence for the separate 1/2/4-worker,
32-GiB whole-workload RSS subcase. It is not the full
`largefile_runtime_gate.sh`, PCRE phase proof, service queue proof, or final
release qualification. Host/profile: `sonic1` / `sonic1-camera-key`.

The deterministic v3 source package SHA-256 is
`926a757ff874d23fb771353ecd9a58f51c90e6de602edc1904c69f0cd2bd9cd8`;
the independently regenerated source manifest SHA-256 is
`4438310a5545a41afa72801adbb89902a06467ba109c863103cadd97f2f6a8c8`.
The v3 Release `clamscan` SHA-256 is
`3427c12ad8ad56a6f598838985e803f709d319c903309754ed1fdb6f09bd0d95`.
Each worker used the same pinned image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
the v3 Release build under `/qualification`, a read-only bind of host GNU
`/usr/bin/time` for measured peak RSS, and a read-only fixture bind. No
software was installed in the image or host.

The previously independently hashed, fully allocated fixture
`/ram/edge-stable.bin` is exactly 34,359,738,368 bytes, SHA-256
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`,
with `EDGE-LATE-MARKER` at EOF−16. Post-run `stat` still reported
34,359,738,368 bytes and 67,108,880 allocated 512-byte blocks. The custom
database contains `NDB.LargeFile-Edge:0:*:454447452d4c4154452d4d41524b4552`;
`large-edge.ndb` SHA-256 is
`24f6061b35491ee66a054b4a67145d138356188aeb2e16cd3bdcf98925fd1300`.
The accompanying `clean-control.ndb` SHA-256 is
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.

Subsequent bounded independent oracle job
`job_212fd3bc3c444f578babf7946ab86468` reread all 34,359,738,368
bytes, recomputed that exact fixture SHA-256, and found exactly one
`EDGE-LATE-MARKER` at offset 34,359,738,352 (EOF−16). It also confirmed
the clean-control literal was absent. Details, including a separate failed
line-oriented-oracle diagnostic, are in
`R12-sonic1-v3-clean-exact-2026-09-29.md`; the latter failure is not part
of these earlier concurrency scans' no-OOM claim.
The later source-controlled `largefile_binary_literal_oracle.py` run
`job_954fec912a0242f68685b41ed16d7070` also proved the first hole is
at EOF; its checksum and bounded full-file result are retained in
`R05-sonic1-bounded-binary-oracle-2026-09-29.md`.

## Execution and independent checks

All cases used explicit 32-GiB `MaxFileSize`, `MaxScanSize`,
`MaxContiguousSize`, and `PcreMaxFileSize`, 64-GiB `MaxTemporarySize`,
`MaxScanTime=14400000`, `--alert-exceeds-max=yes`, and separate report,
GNU-time, and temporary paths per worker. Each disposable container used
`--network none`, UID/GID 1000, dropped capabilities, and
`no-new-privileges`. Retained artifacts are under
`/qualification/r13-v3-concurrency-20260928/`.

| Level | MCP-SSH jobs | Conservative sum of per-worker peak RSS | Result |
| --- | --- | ---: | --- |
| 1 | `job_70c742ecd9b849fcb1d5f8c268a8cd4e` | 95,648 KiB | pass |
| 2 | `job_27412f9762304d4a953d0b615b227430`, `job_06ee691ea3764a6da63f80f0263fb0d1` | 194,612 KiB | pass; 89-second overlap |
| 4 | `job_f6bb24e89bd145f887e0fcdee6ed6024`, `job_8ea4f3176b09402499ec5fe341c2a0c2`, `job_7632b3d59984460d8a5bc36edbca832a`, `job_95cdc7c7d0744ae9a806726be38e8796` | 391,604 KiB | pass; all four simultaneously observed running |

For level 4, job starts were Unix seconds 1790639046, 1790639050,
1790639054, and 1790639058; all ended at 1790639181. Thus the common
overlap was at least 123 seconds. The four individual GNU-time maximum RSS
values were 98,172, 98,016, 97,696, and 97,720 KiB. Their sum, rather than
the maximum of one worker, is compared against the stricter 33,554,432-KiB
(32-GiB) whole-workload ceiling. This is a conservative sum of individual
peaks, not a sampled simultaneous process-tree peak.

An independent read-only Python check parsed each of the seven retained
`time.txt` and `report.jsonl` pairs. Every worker exited 1, the expected
malware-detection exit code; every report recorded `status=1`,
`DETECTION_TERMINATED`, `root_size=34359738368`, exact
`NDB.LargeFile-Edge.UNOFFICIAL` at offset 34,359,738,352 (EOF−16),
`skipped_operations=0`, and `temporary_bytes=0`. Each GNU-time record had
zero swaps; all seven case-private temporary directories were empty.
Afterward the host's `/proc/vmstat` `oom_kill` count remained 46, equal to
the pre-run baseline; `free -k` showed zero swap and 30,212,580 KiB
`MemAvailable`. `docker ps -a` found no leftover four-worker containers.

An earlier one-worker trial, `job_afa01644a55f45f7959b22c5d0ee3b07`,
returned the expected detection but did not retain GNU-time stderr and is
**not** used as RSS evidence. The measured `worker-1-run02` supersedes it;
the incomplete trial is not relabelled as a pass.

## Remaining boundary

This focused run uses a small custom native-signature database on an exact,
materialized, read-only edge fixture. It does not run the full runtime gate,
the required Rust nightly address sanitizer, the separate PCRE full-subject
phase checks, daemon queue/staging or fanotify prevention, production CVDs,
or the complete capability matrix. The qualification volume still had only
about 42 GiB free before these low-temp cases, below the separate 68-GiB
disk-backed service admission. No volume resize, GitHub workflow change,
commit, or push occurred.
