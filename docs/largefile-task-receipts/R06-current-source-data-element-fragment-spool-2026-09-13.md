# R06 current-source DataElementFragment spooling — 2026-09-13

## Scope

The modern OneNote FSSHTTPB `DataElementFragment` parser no longer
materializes its declared fragment payload with `read_vec_u64`. It now stores
the payload in the existing `ReaderBlob` abstraction. Memory-backed readers
retain the bounded in-memory behavior; stream-backed readers spool in
refill-sized chunks under the originating temporary-storage budget. The
fragment's declared range remains checked before reading, and its payload is
still held until the parsed fragment is dropped.

The change is intentionally limited to the parser boundary. It does not
promote any capability row or claim that the full modern OneNote format is
qualified.

## Evidence

- The vendored parser unit suite passed **80/80** with
  `cargo test --locked --offline --lib` in the existing ARM64 Docker build
  container.
- The current-source Release and ASan/UBSan `check_clamav` targets rebuilt
  successfully with `cmake --build ... --target check_clamav -j1`.
- The focused runtime and service evidence controls passed **2/2** in both
  Release and ASan/UBSan builds.
- The corrected source-guard control passed **1/1** in both Release and
  ASan/UBSan builds. The guard now pins the `read_blob(length)?` boundary.
- `git diff --check` passed and the committed source inventory matched the
  generator exactly.

The build used the existing `rust:1.97-bookworm` ARM64 container
`clamav-current-rust-build-20260911`; no host software was installed, no
usage-reset or banked-reset credit was used, and no remote qualification was
claimed.

Audited hashes:

- generated source-inventory SHA-256:
  `96cd668c2435e5d6bda12d313d611011afdc100eb05d361751a9a9b8af7dbdae`
- `libclamav_rust/onenote_parser/src/reader.rs`:
  `8d23390a87eaf9a37150a78326eddaaa41e1a1aed98f248641999dc99fbfc6aa`
- `libclamav_rust/onenote_parser/src/fsshttpb/data_element/data_element_fragment.rs`:
  `2e16c3f90e63a7d344cde955a7a16a7d538c248e193eb46c14c494ded8736579`

## Limitations

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB late-child evidence, production service evidence,
resource/fanotify evidence, independent bytecode format-8 evidence, and final
release readiness remain open. The current snapshot remains release-blocked;
no capability status changed.
