# R12 Sonic1 v5 fully materialized 32-GiB OneNote clean completion — 2026-09-29

## Candidate and control

This is a **single Release custom-signature CLI parser case**, not full
OneNote, R12, sanitizer, production-CVD, daemon, or release qualification.
Sonic1 used profile `sonic1-camera-key`, pinned container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The container's private `/dev/shm` held the input; its dedicated
`/qualification` LV held case-private disk spooling and evidence.

The fresh deterministic v5 source archive was 17,907,029 bytes, SHA-256
`f046a4cd88b6bfb265ba6dd531c3415c90d6f6ac81c0608f29b3df6727894b0d`.
MCP-SSH transfer `transfer_c7062f4597a74f9b9d3d5910c5b16367` atomically
committed it; independent Sonic1 `sha256sum` matched. The extracted source
regenerated the embedded Git-less manifest byte-for-byte, SHA-256
`19c087939965455bce3d8bb011532e0fab1604c1620953e50301236dcb130bcf`.
The v5 Release configuration and build jobs were
`job_dd422d2a90c94ca0a362cf03d10cec4c` and
`job_0b859bdf30ae4258a7e0f524149fa976`, both successful. The build used
the already-installed stable Rust toolchain and existing `/build/cargo`
cache with `CARGO_NET_OFFLINE=true`; no dependencies were downloaded or
software installed. Earlier build attempts failed before testing because
the inherited Rustup/Cargo homes were root-owned or read-only; they were
not source compile failures. The copied Release `clamscan` SHA-256 is
`dfca320f4485066f6873c1d8f3f8d97a9ebd28be43896f4ccc00c796fca02e1e`,
matching the original built binary; copied `CMakeCache.txt` SHA-256 is
`c4f0c803259e430ef516f11514964cb14434b97b9b1881f828a9c0e9e70787ac`.

The clean-control NDB was independently rehashed to
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.
The previous bounded oracle read every byte of the exact 34,359,738,368-byte
fixture and proved its signature literal absent; its result SHA-256 is
`f36d13d05f436c6b1ee2b1e31daea156c7fb93c8deb5bce9bd4335c30c4e801e`.
The v5 scan log independently hashes the same fixture to
`1c593530684ac8c98d818437db669e556966051e4b1c4b4e9a65c049623feacf`.
The fixture's fully allocated 67,108,864 blocks, inode 1619 and mtime
1790541183 were unchanged before and after v5. It had no hole before EOF
in the prior oracle check.

## Regression and exact-size result

The v5 `cl_scan_api` Check run, with its CTest certificate-directory
environment, passed **837/837** assertions (`job_bc3c601bd10b411b936388dd20377d0c`).
It includes the new PE regression: section-header bytes are not considered
overlay, while an actually appended overlay remains visible. A first direct
test attempt omitted `CVD_CERTS_DIR` and failed all case setups before any
assertion; it is not counted as a product failure or a pass.

The v5 `clamscan` returned `COMPLETE`, `OK` and zero skipped operations for
both the 544-byte embedded `clam.exe` and the original 52,297-byte
`clam.exe.webapp-export.one`. Their retained structured reports have SHA-256
`952334dd754bb0ad03393ad94ea339ce9fcdfa8a0b795b47a0817520ff3fcdee`
and `3a2bfd0fe02c681af42a0b3708f589632327b74211b76be5a798956f2cf48ad9`.
The small OneNote report records two files, two parser operations and two
detector operations. Both inputs had reproduced the false InstallShield
incomplete result with v4; see the v4 clean-failure receipt.

Managed full scan/resource job `job_8fbac9534147454583ca9c0bc51dfbc0`
exited **0** after about 199 seconds. It used `--force-to-disk=yes`,
32-GiB file/contiguous/PCRE limits, 64-GiB scan and temporary limits,
14,400,000-ms scan-time limit, an empty cert directory, the isolated clean
NDB, and case-private spool under
`/qualification/r12-v5-onenote32g-clean-20260929-release`.
Its structured report (`scan-report.jsonl`, SHA-256
`560ed6699a7c3c06311c3df60a80f4673eac3d4d1ff07c366f4cb0ea53bfdbe8`)
records `status=0`, `completion=COMPLETE`, `CL_TYPE_ONENOTE`, root size
34,359,738,368, logical bytes 34,359,738,912, matcher bytes
34,368,129,568, temporary bytes 34,359,720,552, two files scanned,
two parser and detector operations, zero skipped operations, and 198,344 ms
elapsed. The input-hash and `OK` log hashes to
`ff4656eb02b436b19bd852baaa7bf72a2cb07cb12216c00aa59f4950d4c12b66`.

The resource record (`provenance/acceptance-case-resources.tsv`, SHA-256
`0e337e83b8dba373ddd2f2ee0ac8840dc7f2a97ddbcae53e764cc1fe30991192`)
binds the exact source, binary and configuration hashes above. Its 199
ordered procfs process-tree samples peaked at 100,144 KiB RSS, 97,209 KiB
PSS, zero swap, zero OOM and zero OOM kills; sample trace SHA-256 is
`46c8a94942e4514012a05a6b66b3d5346eacdaa2a9ed749230d025f7688c00da`.
The apparent temporary-tree peak was 68,479,090,688 bytes, below the
64-GiB (68,719,476,736-byte) limit; apparent size is not physical LV use.
Container `memory.events` ended with `oom=0` and `oom_kill=0`; host swap
was disabled. The case-private spool directory was empty after the run,
and the dedicated LV returned to 34,793,192 KiB available.

## Remaining boundary

The v5 C ASan/UBSan counterpart, full parser/ingress matrix, production
CVD/service canary and release gate remain open. The prior v4 positive
OneNote Release/C-sanitizer detection-terminated parity is separate
evidence, not v5 clean sanitizer parity. The prior 4,018,532-KiB sanitizer
build would lower this LV below one 32-GiB disk spool if repeated there;
`/build` currently has only 119,440 KiB free and `/dev/shm` is noexec.
Sonic1 has about 31.8 million KiB free on the separate
`/tmp/clamav-disk-ext4-v2` mount, but that mount is not in the pinned
container; using it for a sanitizer build requires an isolated, explicitly
verified container/build handoff, not an assumption that `/build` has space.
Do not silently promote this one successful Release case to a fully
qualified parser row. No usage reset, GitHub push, workflow dispatch, or
software installation occurred.
