# R03 current-source bounded Release and ASAN/UBSAN matrix — 2026-09-14

## Scope and identity

The dirty canonical working tree at HEAD `8e837b88c89874b180a1a25f22d287f7d6be29db` was rebuilt in the retained `rust:1.97-bookworm` ARM64 container `clamav-current-rust-build-20260911`. No clean qualification candidate was claimed. The current source manifest contains 1,697 entries and has SHA-256 `2dad186cd18993d6dd5ebaa793a8dcdb63197c2c30ba1152adaa5f84498022b8`.

Capability manifest: `7b04f2ebe9f9ec44dce95cb291edccecb951bd69af451ab0cb3b62544d79670c`.
Case map: `ae97ade4a9a518178a13844b2f28390cc4d054c5a3afc0eadfec58d20847db08`.
Inventory: `e2a7974fc1d42efbd529cc5228b10914901eb052aed78776d1241f2280349703`.

## Build artifacts

Release build directory: `/tmp/clamav-release-current-20260913`.

- `CMakeCache.txt`: `af2fe69b889f05d0ab5b6b87d1bb742873825371d8226e6a414275a74c08d959`
- `clamscan`: `8a094a14aac2eb30bb01e4d74240551d1585f267d392a9c0f82cf376d6a08b71`
- `clamd`: `e9d826d58150393f371c497e3120efe67b9f376d251fe68e8eb6a127d2327e14`
- `check_clamav`: `b9ad354f91baa3c11740dfba6fb33c3d4d8d454fb123875015f9f58bb703a4c6`

ASAN/UBSAN build directory: `/tmp/clamav-asan-current-20260912`.

- `CMakeCache.txt`: `342f477d96232ca059ff9cee3bfe052fcfa584e216ee4b229fb83fc15dd43e25`
- `clamscan`: `e4a192f3151cc061234718da6df0f0f63de945519f6094e56598358210bcb1d6`
- `clamd`: `ebdd5a9634fbfb0bc6dc8db4ec3dca2baa5586cf8db6d2600c8a96d3f3453e17`
- `check_clamav`: `0ad257ed42bf8a739e5083d7df375a4ed8a0d1f35ba6d9f41e2dd0d2394e1213`

## Verification

With `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`, the checked-in test root certificate, the complete bounded CTest matrix excluding only the documented aggregate ARM64 `libclamav` target passed:

- Release: 27/27 in 127.90 seconds; log SHA-256 `e113326d13f7cf06e6c9d3b9e7f6d70a7da3f9fcb04774b8e5e9e8136bcabce9` (`/private/tmp/clamav-release-bounded-matrix-final-20260914.log`).
- ASAN/UBSAN: 27/27 in 146.73 seconds; log SHA-256 `38cd83b6dac4dd4bc84c5c095bf92b5470b068676ccbd047f6efce2197b7ba26` (`/private/tmp/clamav-asan-bounded-matrix-final-20260914.log`). No AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer, or runtime-error diagnostic was present.

The matrix includes application, daemon, milter, Rust, freshclam, sigtool, ingress, protocol, resource, source-guard, acceptance-schema, case-map, and late-member controls. The aggregate ARM64 `libclamav` CTest remains excluded because its established run exceeds the configured duration budget; this is an explicit evidence limitation, not a pass.

## Qualification boundary

State: current-source development-verified; release qualification open. Readiness remains 604 total, 0 qualified, 147 bounded, 443 pending, 14 allowlisted unsupported, and 590 blocking. Certified Linux x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, independent format-8, Sonic1, complete parser-family evidence, and final release candidate review remain required. No capability was promoted, no software was installed, no usage reset was used, and no commit, push, or GitHub workflow action was performed.
