# R12 Sonic1 v6 exact-32-GiB OneNote late-child parity — 2026-09-29

## Scope and identity

This receipt covers **one custom-signature CLI late-child detection case**
against the same fully materialized 32-GiB OneNote fixture used by the v6
clean-control parity receipt. It closes the current-candidate positive
recheck after the v5 PE-overlay fix; it does not qualify the entire OneNote
family, every ingress, production CVDs, or release readiness.

The authorized runner was `sonic1` with login profile `sonic1-camera-key`.
The pinned container was
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
and image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The `/qualification` mount is the dedicated disk-backed LV; the input was
fully allocated in this container's private `/dev/shm`. Each scan ran as
UID/GID 1000 with a separate disk-backed case-private temporary directory.

The frozen v6 deterministic source archive SHA-256 was
`6a886cf5269cda75c2e8f300cb0dd3772592b2a19ffd29c7cf5a31d272652987`,
transferred and committed as
`transfer_26b9fdda6e42413aa3261159939562fa`. Both copied source-content
manifests hash to
`c19b0777b9580611ec879bdbfb2740621aaf8bdbcc9f0a1f1189415be9c8fe5b`.
The copied Release scanner/config hashes are
`353e424176464b972d07cbe2bb7e2cf7cdb3f015140a285144c93772819d5555` /
`c9e1473effc653f8e63ca8631e5b8954256281fd9fc84ee4599f383e7a2c5f00`;
the C ASan/UBSan scanner/config hashes are
`c95d2b99f01427b4bc2e76910bf775dc3abc9d1bda5f6490021685eabb0466e7` /
`036acc0b132d131dd8095372b82209d539815c2e44c0c454157aae1e218fba66`.
The case-local `late-mz.ndb` hash is
`18e92066983cbc35d84ccd8a1c83b09ddf73c965b4032b5930a4b6724965176b`;
the v6 Release scanner detected its literal on the three-byte preflight.
The broader v6 Release and C sanitizer CTest suites passed 32/32 before
these runs, as recorded in the clean-control parity receipt.

## Fixture oracle and observed scans

The unchanged exact-34,359,738,368-byte fixture is
`/dev/shm/r12-v17-onenote32g-clamscan-diskspool-20260927-run01-input.one`.
Before and after these runs it had inode 1619, mtime 1790541183, and
67,108,864 allocated 512-byte blocks. Both v6 scanner logs computed its
SHA-256 as
`1c593530684ac8c98d818437db669e556966051e4b1c4b4e9a65c049623feacf`,
matching the independent earlier full-file oracle. A fresh bounded read
verified `MZP` (`4d5a50`) at expected fixture offset 34,359,719,413
(EOF minus 18,955). The report does not expose a scanner-reported member
offset: the offset is independently established fixture/oracle evidence,
not a claimed scanner offset observation.

Both scans used `--force-to-disk=yes`, the isolated NDB, an empty cert
directory, explicit 32-GiB file/contiguous/PCRE ceilings, 64-GiB scan and
temporary ceilings, four-hour scan time, `--alert-exceeds-max=yes`, JSON
reporting, input hash logging, and the case-private spool. C sanitizer used
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. The managed Release job
was `job_21e6653722e34afca7b5fe3bb3f3f537`; the C sanitizer job was
`job_526a1d7a1c7c40e6bc9a2caca9a554af`. Both exited 1 for the expected
detection, not an infrastructure failure.

| Observation | Release | C ASan/UBSan |
| --- | ---: | ---: |
| Report status / completion | 1 / `DETECTION_TERMINATED` | same |
| File type / root size | `CL_TYPE_ONENOTE` / 34,359,738,368 | same |
| Logical / matcher / temporary bytes | 34,359,738,912 / 544 / 34,359,720,552 | same |
| Files / parser operations / skipped | 2 / 2 / 0 | same |
| Exact alert | `OneNote.Reader.LateMZ.UNOFFICIAL` | same |
| Report elapsed | 139,463 ms | 144,594 ms |
| Ordered process-tree samples | 140 | 145 |
| Peak RSS / PSS | 100,228 / 97,426 KiB | 139,972 / 137,164 KiB |
| Peak apparent temporary tree | 68,710,277,120 bytes | 68,630,208,512 bytes |
| Peak swap / OOM / OOM kills | 0 / 0 / 0 | 0 / 0 / 0 |

An independent read-only verifier found the structured reports identical
after excluding only `elapsed_ms`. It rehashed each retained source,
scanner and config copy against its resource row; checked consecutive
sample numbers, sample count, RSS maxima, zero sampled swap/OOM, exact
alert/input hash, and the 64-GiB apparent temporary ceiling. The Release
apparent temporary peak was only 9,199,616 bytes below that ceiling, so it
is a narrow historical path-sum margin, not spare staging capacity.
Subsequent source review found that the v6 sampler counted the OneNote
spool and its hard-link owner pathname twice; see
`R13-hardlink-temporary-sampler-correction-2026-09-29.md`. The original
artifact hashes and conservative under-64-GiB observation remain unchanged.
Apparent tree size is not physical LV allocation. Both case-private spools
were empty afterward; the dedicated LV returned to 34,626,296 KiB free.
Container `memory.events` ended with `oom=0`, `oom_kill=0`, and `/proc/swaps` showed no
active swap. The managed C sanitizer job captured zero stderr bytes.

| Retained artifact | Release SHA-256 | C ASan/UBSan SHA-256 |
| --- | --- | --- |
| `scan-report.jsonl` | `c9a9b3c997e4d5bc924948c6a8c81b0c4f5fa0deb357de37fadbbbe249d7ee22` | `331bdbe72c2f5c5d669ab0851aeef8807177ed3f19ec1a4b7e408ebd393117d8` |
| `provenance/scan.log` | `1af263dc4e0fe5fae77d51e6c278f8f0c526e9cc48c40bbbe0223e814df212a2` | same |
| `provenance/acceptance-case-resources.tsv` | `5ea913cf4d440ffe02c42b2438666c15d651dedc04053badac8cdc10f453126e` | `6241daa85feec64e5f368379cc3b4078d66b65213c61271752aee04e9093be47` |
| `provenance/samples.tsv` | `d664b77c9413f3558fd1f41624d18da57835a7722d3e42fefc14b7988fe7300e` | `657f3648456cfa00c414856ad6866ce42b8da8c4c8b5c42e0e609a1edc7aebcc` |

The evidence roots are
`/qualification/r12-v6-onenote32g-positive-20260929-release` and
`/qualification/r12-v6-onenote32g-positive-20260929-asan`. This result
does not change the manifest's pending `CL_TYPE_ONENOTE` status: malformed
and fault paths, all ingress forms, production CVD/service canary, Rust
source instrumentation, all parser branches, and final readiness remain
open. No software, usage reset, GitHub push, or GitHub workflow was used.
