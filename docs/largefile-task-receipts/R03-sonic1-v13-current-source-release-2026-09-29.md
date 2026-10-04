# R03 Sonic1 v13 current-source Release build — 2026-09-29

This receipt is a coherent Linux x86-64 Release build and bounded regression
result for a newly frozen source snapshot, **not** 32-GiB release
qualification. The required materialized full-size, sanitizer, ingress,
parser, PCRE, fanotify and production-CVD cases remain open.

The canonical dirty checkout was frozen with
`tools/largefile_deterministic_source_package.py` into
`/private/tmp/clamav-current-v13-20260929.tar.gz` (17,927,112 bytes).
Package SHA-256:
`5399fbfd12d70fa407c5fc3832cda2768110d4d0fabb8c15c9ec7347a17ece19`.
Source-content manifest SHA-256:
`02800474c1ceea761cd95524e4b79b5b18faea21b1b5ed4ce03e32824e5eee8b`.
MCP-SSH durable upload `transfer_bddef9f521434a8781d0136d50ee54e8`
reached `ready_to_commit` with the expected bytes/checksum and committed by
atomic rename. It was extracted into
`/qualification/source-current-v13-20260929` in the pinned Sonic1 container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
(image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`).
The Git-less manifest regenerated from the extracted tree compared
byte-identically with the packaged manifest (`job_2b0e4adeb53e492eb744e84fcf2fd80a`,
exit 0, followed by `cmp` exit 0). Remote source guards
`job_6f678f82da6e441b8cae2481c0b71a36` exited 0, including the 604-entry
capability map and materialized-limit-fixture small-size tests.

The configuration replicated v11's full Release switches with the offline
Rust/Cargo environment: app, clamonacc, milter, UnRAR, JSON/shared/static
libraries, tests, large-file defaults and exact-edge test, WERROR and
interpreter bytecode. `CMAKE_HOME_DIRECTORY` and `ClamAV_SOURCE_DIR` both
point to the extracted v13 tree. Configure
`job_44608d0b435a48c682082b0f0b136056` exited 0; two-job offline build
`job_f4cc7251fe28493cbc6027f67308ae60` exited 0. The build is
`/qualification/build-current-v13-20260929-release`.

| Built artifact | SHA-256 |
| --- | --- |
| `clamscan/clamscan` | `684473c1a6a38f2a778b8a620a8ef144521cc9001c87258a052431e751879368` |
| `clamd/clamd` | `77d0f2bafb07b2a8a7ce06249701d619ea9feeed7086b442adc09392c8cd3a71` |
| `clamdscan/clamdscan` | `4a0f9d6775722dd556bbb1d0e4d643292c306a3500e8a0a1fd361173add97559` |
| `CMakeCache.txt` | `6c7a23ab9fdec2b124d0e416f7445918287e51d7932e2e25846677d286ae2d67` |
| `Testing/Temporary/LastTest.log` | `718900301beca57896f97472b6edbda23db8534b3809c84d5f262a9b698e2d96` |

The non-edge Release CTest job `job_419fa627528c44b08d46bca42d285274`
used `-E ^largefile_library_exact_32g$` and exited 0: **32/32 passed** in
119.75 seconds, including `libclamav`, `libclamav_rust`, `clamscan`, `clamd`,
`freshclam`, `sigtool`, source guards and acceptance-control tests. The
exact-32-GiB library test was excluded intentionally; it was not run on v13.

After this build and suite, the dedicated qualification ext4 LV had
3,639,304,192 bytes available; host `MemAvailable` was 24,206,561,280 bytes
and swap was zero. That is below the contract's 68-GiB disk-backed and
48-GiB effective-memory admission thresholds. The 32-GiB-plus-one
materialized fixture was not created, and no v13 full-size case, sanitizer
parity or release gate was claimed. The older v11 full-size cases remain
separate, source-mismatched development evidence. Pending user decisions on
the dedicated LV expansion and OneNote tmpfs migration remain unchanged.

State: `v13-source-bound-release-build-and-32-non-edge-tests-pass; full-size-admission-and-release-gates-open`
