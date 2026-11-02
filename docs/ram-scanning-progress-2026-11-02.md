# Sonic1 RAM scanning progress — 2026-11-02

Status: **in progress; not qualified**. This is a scoped status snapshot. Candidate source, comprehensive diagnostics and hash-verified evidence remain in the local ClamAV workspace and on Sonic1; this document does not publish those artifacts.

## Objective

Scan exact 32-GiB raw inputs and supported unencrypted Stored ZIP members from a fully resident input. Stored members must use checked views into one resident archive, without materializing an entire extracted copy. Preserve the strictly-under-32-GiB whole-workload process RSS gate, 40-GiB PCRE ceiling, strictly-under-12-GiB post-PCRE gate, zero swap and 55-GiB physical/test ceiling. The input itself is 32 GiB of physical memory, so this is not a claim that the whole machine workload fits in 32 GiB of total RAM.

## Evidence obtained

- Release tests on Sonic1 have completed exact-32-GiB raw clean and late-positive scans and single-member Stored ZIP clean and late-positive scans. Separate exact-size multiple-member and nested Stored cases also passed scoped functional reviews. Views reported zero full-member materialization, and initial and terminal residency checks observed all 8,388,608 pages. These runs are configuration-specific and do not establish full qualification.
- A normalized-only exact-32-GiB Stored ZIP test on an earlier Release candidate timed out after 6,000 seconds. Its failure remains preserved. A separate compact-ledger Release candidate subsequently completed scoped exact-32-GiB single-Stored clean and normalized late-positive scans; both reported zero materialization, temporary bytes, skips or required cleanup failures. Sampled host nonfree peaks were 48,240,021,504 and 48,210,157,568 bytes, respectively. Sampling is not a continuous peak bound.
- A new exact-source build combines C/C++ ASan/UBSan with Rust ASan. Rust's build used `-Zsanitizer=address` and its archive exposed 42 distinct ASan symbols. Scanner SHA-256: `2619f1e8d8e7a74a5e8290883a866cd81a3c68c2ee67c7cec6f7242ca89ee201`; Rust archive: `8df5439828f25c759802a955be57d391198f7578d2fef3c3752c82fc6e4c4e9e`.
- A 64-MiB consumed-RAM Stored ZIP positive control with that combined sanitizer build detected its expected signature and reported zero temporary bytes, skips or cleanup failures. Its preserved evidence archive SHA-256 is `bb764efebbebd9f93d3b41b3d25ca8cd12d8ea1c4ce04a002084dd6ed2e25d57`. This is one small control, not full-size sanitizer qualification.

## Active test

As checked on 2026-11-02, a separately pinned exact-32-GiB normalized late-positive Stored ZIP scan using the combined Rust/C/C++ sanitizer build is running on Sonic1, along with its three monitoring services. Suite: `/tmp/clamav-qualification-disk-lv-v1/service-native-rust-asan-stored32-positive-20261102-v1`; source-pin manifest SHA-256: `0eb87d00e6e0732d27c6b9b47d446965b3e37c351a309a75d8009af788227662`. It has no terminal result yet. Preserve its diagnostics and review them before drawing any conclusion; do not launch a duplicate merely because it takes a long time.

## Remaining qualification

Prove or explicitly resolve continuous backing residency over all reader lifetimes; complete whole-workload process-generation RSS and combined host physical accounting, including phase-specific PCRE limits; broaden detector and cancellation/failure coverage; and finish the full-size sanitizer and remaining exact-source qualification matrix. Periodic memory samples and endpoint residency observations alone do not prove exact peaks or uninterrupted residency. Unsupported paths must remain incomplete or refused rather than report a clean result.

Detailed local records: `CLAMAV-RAM-SCANNING-GOAL.md`, `CLAMAV-RAM-SCANNING-HANDOFF-2026-10-29.md`, `CLAMAV-STORED-ZIP-32G-DESIGN.md`, and `ram-stored-view-candidate-20261031-v1/virtual-replay-ledger-layout-20261102-v1/SANITIZER-BUILD.md`. Preserve all existing evidence and verified backups.
