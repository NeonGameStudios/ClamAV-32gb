# Task receipt: 7-Zip linked revalidation

Task ID / parent milestone: `R08` / roadmap parser-family sweep

Scope: compile the current source and run the focused 7-Zip parser, map,
cleanup, SFX, and SFX-corpus Check cases against the production-linked static
library. This is development evidence only; it does not promote any
capability to release-qualified.

Evidence identity:

- Source manifest SHA-256: `0efece36509e28c0d0268e553acd3b48d8a37035a5896edc14c32e41433901e6`
- Test binary: `/tmp/clamav-current-build/unit_tests/check_clamav`
- Test binary SHA-256: `a5c873802f6eb3b495f369035cceac33bb41b3c8254810355281d66cd93734a0`
- Build-cache `CMakeCache.txt` SHA-256: `e627362d7bc7b267f369ad16857622932666e0d5d7100051bab2b5c09183a947`
- Platform: disposable AArch64 Linux Docker toolchain
- Rust toolchain: `cargo 1.97.1`

The current source configured and linked successfully with CMake, GCC, the
locked Rust dependency set, the vendored 7-Zip SDK, and the static
`check_clamav` target. The build used the existing toolchain container; no
host software was installed.

Focused results, all with zero failures and zero errors:

- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=7z`: **28/28 checks**
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=7z_map`: **4/4 checks**
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=7z_cleanup`: **1/1 checks**
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=7z_sfx`: **3/3 checks**
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=7z_sfx_corpus`: **1/1 checks**

The `7z` result includes `test_7z_sticky_incomplete_result_is_fail_visible`,
which confirms that a valid empty archive cannot erase a pre-existing sticky
incomplete result. The related cases exercise the map boundary, cleanup-status
merge, SFX admission, and the materialized embedded-child corpus path.

State: `development-verified`; `7z-sticky-completion` and related rows remain
pending until the roadmap's certified Linux x86-64, sanitizer, production-CVD/
service, resource, full-size, Sonic1, and final release gates are satisfied.

No GitHub workflow action, commit, push, or usage reset was used.
