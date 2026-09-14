# R08 current-source Rust parser revalidation — 2026-09-14

The dirty canonical working tree at HEAD `8e837b88c89874b180a1a25f22d287f7d6be29db` was exercised from the retained ARM64 `rust:1.97-bookworm` Docker build artifacts. No clean qualification candidate was claimed. The current source manifest contains 1,697 entries and has SHA-256 `72d38dfa47fe40af62750cd89f2ebddd4ebae594fc29cb1e513b385f0a0c3803`; the regenerated inventory has SHA-256 `8c52256f9f23ee9a4b98708260b9e6dcc5f8fa8b9845e15eba940c8ef8b8a4c7`.

## Focused verification

With `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify` and `T=1200`, both current-source configurations passed all registered Rust-family selectors with zero failures and errors:

- Release: `rust_lha` 10/10, `rust_alz` 3/3, `rust_onenote` 5/5, and `rust_map` 2/2; combined log SHA-256 `10906203a1248ef435490689503840d4f9d8dbd39d631e059afa2c2ef87afa24` (`/private/tmp/clamav-rust-slices-release-20260914-clean.log`). Rebuilt `check_clamav` SHA-256: `c15c7e09ff6b2ce9b9566a80234263bc347241ec41c347cf0b3df5aa0b1d8e12`.
- ASAN/UBSAN: `rust_lha` 10/10, `rust_alz` 3/3, `rust_onenote` 5/5, and `rust_map` 2/2; combined log SHA-256 `10906203a1248ef435490689503840d4f9d8dbd39d631e059afa2c2ef87afa24` (`/private/tmp/clamav-rust-slices-asan-20260914-clean.log`). Rebuilt `check_clamav` SHA-256: `45596d3d3b8db55e6cbc6ed700d11259b9250cfa1cc26ba3d2dd662cfc2e7824`. The sanitizer log contains no AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer, or runtime-error diagnostic.

The OneNote selector includes the exact 32-GiB logical reader-boundary case. Its attachment regression now uses a logical extent just above the former 256-MiB whole-input parser ceiling: the fixture follows the legacy-compatible path, so a synthetic 32-GiB zero tail would otherwise force an unbounded compatibility scan. This keeps the attachment handoff assertion bounded while retaining the exact 32-GiB reader coverage in the neighboring test.

## Repository controls

The source guard passed with log SHA-256 `74bf6b34579163ed69b090a6458ce2e2fc999d10e13d1d70022e0b4aa82c318d` (`/private/tmp/clamav-rust-source-guards-20260914-final.log`). Snapshot freshness, regenerated inventory, acceptance case map, acceptance record schema, and `git diff --check` passed.

This is current-source parser-family development evidence, not final release qualification. No capability was promoted; certified Linux x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1, independent format-8, complete parser-family corpus breadth, and final release evidence remain open. No software was installed, no usage reset was used, and no commit, push, or GitHub workflow action was performed.
