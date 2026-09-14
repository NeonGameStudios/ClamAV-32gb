# R03/R06 current-source Release and sanitizer matrix after fragment spooling — 2026-09-13

## Scope

Revalidate the current source after the R06 FSSHTTPB `DataElementFragment`
payload changed from direct `Vec<u8>` materialization to the bounded
`ReaderBlob` memory/spool boundary. This receipt records build and application
matrix evidence only; it does not promote a capability or replace the roadmap
qualification requirements.

## Provenance

- Source root: `/src`, mounted from the canonical worktree
  `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- Source inventory: 1,697 entries; SHA-256
  `96cd668c2435e5d6bda12d313d611011afdc100eb05d361751a9a9b8af7dbdae`
- Release build: `/tmp/clamav-release-current-20260913`
- ASan/UBSan build: `/tmp/clamav-asan-current-20260912`
- Existing ARM64 Docker container: `clamav-current-rust-build-20260911`
  from `rust:1.97-bookworm`; no host software was installed

## Results

- Both Release and ASan/UBSan `check_clamav` targets rebuilt successfully
  with `cmake --build ... --target check_clamav -j1`.
- Complete current-source Release CTest: **28/28 passed** in **192.61 s**.
  This included the aggregate `libclamav`, source/readiness controls, Rust,
  clamscan, clamd, freshclam, and sigtool targets.
- Bounded current-source ASan/UBSan CTest: **27/27 passed** in **500.85 s**;
  the documented long aggregate `libclamav` test was excluded. No ASan,
  UBSan, leak, undefined-behavior, or runtime-error diagnostic was emitted.
- Parser unit suite: **80/80 passed** with
  `cargo test --locked --offline --lib`.
- `git diff --check`, inventory freshness, snapshot freshness, and the full
  source-guard wrapper passed.

## Boundary

The readiness command remains correctly blocked: 601 total capabilities, 0
qualified, 147 bounded, 440 pending, 14 allowlisted unsupported, and 587
release blockers. Certified Linux x86-64, exact/materialized 32-GiB cases,
production-CVD/service evidence, resource/fanotify evidence, independent
format-8 bytecode evidence, and final canary/release evidence remain open.
No capability was promoted and no usage-reset or banked-reset credit was used.
