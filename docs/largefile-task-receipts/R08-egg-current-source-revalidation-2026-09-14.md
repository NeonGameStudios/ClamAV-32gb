# R08 current-source EGG parser revalidation — 2026-09-14

The dirty canonical working tree at HEAD `8e837b88c89874b180a1a25f22d287f7d6be29db` was exercised from the retained ARM64 `rust:1.97-bookworm` Docker build artifacts. The current source manifest contains 1,697 entries and has SHA-256 `2dad186cd18993d6dd5ebaa793a8dcdb63197c2c30ba1152adaa5f84498022b8`.

With `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify` and `T=1200`, both current-source configurations passed the registered EGG selectors with zero failures and errors:

- Release: `egg_map` 16/16, `egg_metadata` 1/1, and `egg_sfx` 3/3; log SHA-256 `6738056ddb259e12bf12ef0959d1cffb02a51dbf2ea9075363923c0417279388` (`/private/tmp/clamav-egg-slices-release-20260914.log`).
- ASAN/UBSAN: `egg_map` 16/16, `egg_metadata` 1/1, and `egg_sfx` 3/3; log SHA-256 `6738056ddb259e12bf12ef0959d1cffb02a51dbf2ea9075363923c0417279388` (`/private/tmp/clamav-egg-slices-asan-20260914.log`). The log contains no AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer, or runtime-error diagnostic.

The `egg` selector was also invoked but contains zero registered tests; it is not counted as a pass. This is current-source parser-family development evidence, not final qualification. Complete EGG/SFX corpus breadth, certified Linux x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1, independent format-8, and final release evidence remain open. No capability was promoted, no software was installed, no usage reset was used, and no commit, push, or GitHub workflow action was performed.
