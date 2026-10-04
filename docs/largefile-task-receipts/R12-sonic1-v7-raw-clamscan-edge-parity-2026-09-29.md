# R12 Sonic1 v7 exact-32-GiB raw ClamScan file parity — 2026-09-29

## Scope and identity

This receipt covers the current frozen v7 candidate's **direct-file**
ClamScan ingress against one fully materialized exact-32-GiB raw fixture
in Release and C ASan/UBSan builds. It is a positive exact-tail custom
signature case, not a parser, stdin, service, production-CVD, or final
release qualification. The authorized runner was `sonic1` with profile
`sonic1-camera-key`, in pinned container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
and image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.

The v7 deterministic source package was transferred as
`transfer_f25284af5f9c4d72ad0db0d7612173e4`, hash
`4c61f7b0fad326770c936863992ad6f3f70f4fb5e5c56eec58b9cb3035c4dbdf`.
Its embedded source-content manifest was independently regenerated on
Sonic1 and compared byte-for-byte. The case-local manifest SHA-256 is
`72bb5de991f23098030c27f666578740b1ca74eaf0e7b3e1b9938735a70b2ebb`.
The copied Release scanner/cache hashes are
`0a8ea8421d6d0be1fd23f1d2458287fa24c4e927a9203baf0245494dd16ea2a0` /
`c312a602270217130f04e1a11e12bb4c5883dd58b5b5ee1b78037c3768a90992`;
C ASan/UBSan hashes are
`812a8b396786f5051d6523136e3e6b53d7cb8e520ce0739bf0ff9dc7e13d3949` /
`127534b6724c2b70285e823b9613dc4a4f8318966d9d0f10f17a54ed9b810f1f`.
Both builds had passed their 32/32 non-edge CTests and the exact-size
three-library-API case before these CLI runs. C sanitizer used
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`; this is linked C
sanitizer evidence, not Rust-source sanitizer instrumentation.

## Fixture, signature and runs

The container's read-only `/ram/edge-stable.bin` is actually backed by
root ext4, **not tmpfs**. Before and after the runs it was
34,359,738,368 bytes with 67,108,880 allocated 512-byte blocks,
inode 8149459 and mtime 1790047133. A bounded independent read found
the 16-byte `EDGE-LATE-MARKER` at byte 34,359,738,352 (EOF minus 16).
The source signature `large-edge.ndb`, copied separately into each
case's isolated database path, hashes to
`24f6061b35491ee66a054b4a67145d138356188aeb2e16cd3bdcf98925fd1300`.
Prior independent full-file hashes and both current scanner input-hash
logs returned
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
Independent post-run hash job
`job_8015b341d0074fd191a0a3c01fb39c21` exited zero and returned
that same SHA-256 after both scans, closing fresh full-file hash parity.

Both scans used exact 32-GiB file/contiguous/PCRE ceilings, 64-GiB
logical/temporary ceilings, a four-hour scan time, `--alert-exceeds-max`,
JSON reporting, hash logging, an isolated NDB, empty certificate
directory, and a separate LV-backed case-private temporary directory.
Neither used `--force-to-disk`; this raw test does not exercise the
full-size OneNote disk-spooling path that remains blocked for lack of
headroom. Managed Release job `job_53f52e2e0f0a4ddda8885a6971534fa9`
and C sanitizer job `job_368eb5fd5c6c4b7c849f84ee80dc3f33` each
exited 1 for the expected detection, not an infrastructure error. The
resource wrappers completed their rows successfully.

| Observation | Release | C ASan/UBSan |
| --- | ---: | ---: |
| Report status/verdict/completion | 1 / 2 / `DETECTION_TERMINATED` | same |
| Type and exact root/logical bytes | `CL_TYPE_BINARY_DATA`; 34,359,738,368 | same |
| Matcher/temporary bytes | 34,368,129,024 / 0 | same |
| Files / skipped operations | 1 / 0 | same |
| Exact alert/offset | `NDB.LargeFile-Edge.UNOFFICIAL` / 34,359,738,352 | same |
| Report elapsed | 189,946 ms | 337,369 ms |
| Ordered process-tree samples | 1,808 | 2,677 |
| Peak RSS/PSS | 100,572 / 97,616 KiB | 139,832 / 136,927 KiB |
| Sampled temp/swap/OOM/OOM-kill | 0 / 0 / 0 / 0 | same |

Both text logs reported the exact signature `FOUND`, debug matcher
offset 34,359,738,352, and the same full input hash. An independent
read-only verifier parsed each report/resource row/trace, rehashed each
copied source manifest, scanner and CMake cache against the row, checked
consecutive sample numbers and increasing timestamps, row sample count
and RSS maximum, exact alert/offset/size/completion, zero sampled
swap/OOM/temp, absence of sanitizer diagnostics, and empty case-private
temporary directories. It exited zero for both cases. Container
`memory.events` remained `oom=0`, `oom_kill=0` and `/proc/swaps` showed
no active swap. Post-run qualification LV free space was
28,028,596,224 bytes; root had about 100 MiB free.

| Retained artifact | Release SHA-256 | C ASan/UBSan SHA-256 |
| --- | --- | --- |
| `scan-report.jsonl` | `5d20cad79f8cdb0cb9468ef6721d9e6040d86b2341a9d8583099f49e615bd4d5` | `05d67219eb8e81ad682c71b54efc8c1c26ebcd97902e2eac012f7a9096ad68fb` |
| `provenance/scan.log` | `a8ef96cf670035f2dbc3ecbec664af43ab45309182d0b70170e2679e8718a2fb` | `a9850739a59fdcefcc304dafa9a0e24d74906e010c15b3f64dd1af1bfc760c2d` |
| `provenance/acceptance-case-resources.tsv` | `9901d106c36f532734161d5adec237f10e39b53154db2bd22297b01bc3381ffc` | `bce559e0a279851599dd9ef1f8c31f64d6d16d4482823859ead70a189a869abc` |
| `provenance/samples.tsv` | `653115ad99ead1da48036731c94bce176f2a71499ffe501274c6f9d47ec01eb9` | `24c4bee90a544a3f1a00204a571c15affdb607251049f8ee99b9d22b3e516a7e` |

Evidence roots:
`/qualification/r12-v7-raw-clamscan-edge-20260929-release` and
`/qualification/r12-v7-raw-clamscan-edge-20260929-asan`.
No capability was promoted. This proof does not cover CLI stdin,
clamd/clamdscan, milter, on-access, PCRE phases, OneNote, clean-control
completion, production databases or final release readiness. No
software, usage reset, GitHub push or GitHub workflow was used.
