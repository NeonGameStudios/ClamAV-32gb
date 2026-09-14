# R03 current-source Release and ASAN/UBSAN matrix refresh — 2026-09-14

The dirty canonical working tree at HEAD `8e837b88c89874b180a1a25f22d287f7d6be29db` was rebuilt in the retained ARM64 `rust:1.97-bookworm` container `clamav-current-rust-build-20260911`. This refresh follows the bounded OneNote attachment regression correction recorded in the R08 Rust receipt. No clean qualification candidate was claimed.

## Source and build identity

The current source manifest contains 1,697 entries and has SHA-256 `72d38dfa47fe40af62750cd89f2ebddd4ebae594fc29cb1e513b385f0a0c3803`. Both build trees were reconfigured from `/src`; their CMake source-manifest values and retained `source-manifest.txt` files match that hash.

Release build directory: `/tmp/clamav-release-current-20260913`.

- `CMakeCache.txt`: `d2c88954e4b292f9e7825c83965b2ba701c0bff9f5144d79bfe0447c9f504b0c`
- `clamscan`: `8a094a14aac2eb30bb01e4d74240551d1585f267d392a9c0f82cf376d6a08b71`
- `clamd`: `e9d826d58150393f371c497e3120efe67b9f376d251fe68e8eb6a127d2327e14`
- `check_clamav`: `811dbd4e5995e3f2f06a5943aa9f8aefab3d8e2d82bf3af1710b8202bde0a78b`

ASAN/UBSAN build directory: `/tmp/clamav-asan-current-20260912`.

- `CMakeCache.txt`: `4cfbd43bec86acff15d33e3339ebc0ad43f61b56cbd0bf9df20ff2cee5d7f0f2`
- `clamscan`: `e4a192f3151cc061234718da6df0f0f63de945519f6094e56598358210bcb1d6`
- `clamd`: `ebdd5a9634fbfb0bc6dc8db4ec3dca2baa5586cf8db6d2600c8a96d3f3453e17`
- `check_clamav`: `55ff4cbcf8837dd50dc48d7872a4dd3390ea8326a7c70b1bdf4412fa754b6f1a`

## Verification

The 28-test CTest inventory was run with only the established aggregate ARM64 `libclamav` test excluded (`-E '^libclamav$'`). The remaining 27 tests passed in each configuration:

- Release: 27/27 in 128.81 seconds; log SHA-256 `1b00012718b23d355206271627fb4e779cb256ad17caf26cee92c487fb78d44a` (`/private/tmp/clamav-release-bounded-matrix-rust-final-20260914.log`).
- ASAN/UBSAN: 27/27 in 502.89 seconds; log SHA-256 `4c9f13e79a7e3d5af1dbe9c40637f550db1862af938ca30ef3f4c8974f95266d` (`/private/tmp/clamav-asan-bounded-matrix-rust-final-20260914.log`). No AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer, or runtime-error diagnostic was present.

The passing matrix includes thread-pool, source guards, runtime/service evidence checks, acceptance schema/producers, application admission, daemon protocol, late-member, process-resource samplers, milter, Rust integration, `clamscan`, `clamd`, freshclam, and sigtool controls. The source guard also confirms the 604-row capability manifest, acceptance map, and empty schema-valid authoritative records file.

The aggregate ARM64 `libclamav` test remains excluded because its established duration exceeds the available bounded-run budget. This is an evidence limitation, not a pass.

## Qualification boundary

State: current-source development-verified; release qualification remains open. Readiness is still 604 total, 0 qualified, 147 bounded, 443 pending, 14 allowlisted unsupported, and 590 blocking. Certified Linux x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, independent format-8, Sonic1, complete capability-specific acceptance records, and final release review remain required. No capability was promoted, no software was installed, no usage reset was used, and no commit, push, or GitHub workflow action was performed.
