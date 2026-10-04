# R03 Sonic1 v9 source-bound build and non-edge CTest matrix — 2026-09-29

## Candidate identity

The deterministic v9 source package was transferred with MCP-SSH durable
transfer `transfer_7ab91a6aa7c947c7813d5720fdd3a012`, then verified on
Sonic1 and extracted to `/qualification/source-v9-temp-race-20260929`.
Independent regeneration of its Git-less manifest matched byte-for-byte;
SHA-256
`884ba2f7a7e180a063c48bb62a8417e20277dee9c849c2f8e307bfdc50fb06b0`.
Package and bounded runtime details are in
`R13-sonic1-v9-bounded-capture-race-2026-09-29.md`. The pinned container is
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`;
host/profile are `sonic1` / `sonic1-camera-key`. All builds used the extracted
v9 source, not the stale `/src` mount, an existing offline Cargo cache copied
to `/qualification`, and a disk-backed `/qualification` TMPDIR. No software
was installed or fetched.

## Build and test result

| Build | Managed configure / build / non-edge CTest jobs | Cache SHA-256 | CTest outcome |
| --- | --- | --- | --- |
| Release | `job_101d4b07288641ba810438d0f8b38873` / `job_c443b8744c4f4358a7e689f23b5e30b8` / `job_2dfef30441994a15999a242525df6343` | `6e80757e0e72b8fba04529ea43d9324670bb4e0848dd368c1edc175fe25addf5` | 32/32 passed, 117.76 s |
| C ASan/UBSan | `job_92c4bcb41d534b9ea1a21b4b06f2e487` / `job_d8aed0205da74ef89df297561a891a61` / `job_8174a8e5d66243d2a1818f15311c2e5e` | `1d2be36a7087eed76c5a4c88ceb93997edda5a5c64c5f23330b0efe57c50e5b6` | 32/32 passed, 233.71 s |

Both builds enabled the application, clamonacc, milter, JSON shared, shared
and static libraries, UnRAR, tests, large-file defaults and the exact-size
qualification test. The sanitizer build used GCC 12.2 with
`-fsanitize=address,undefined -fno-omit-frame-pointer`, executable/shared
linker sanitizer flags, RelWithDebInfo and `ENABLE_WERROR=OFF`, following the
prior successful C-sanitizer feature profile. Its CTest used
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Both CTest suites
explicitly excluded `largefile_library_exact_32g`; that case is separate.

The v9 Release `clamscan` SHA-256 is
`83dee8840b488f79d95b636e6f914bb831b16d55c233bba6d2f943a4c9ffded9`.
The C sanitizer `check_clamav`, `clamscan` and `clamd` SHA-256 values are,
respectively,
`f21297a2651c236de621f998c821f88eff5658d22b335e85ccd62c18a22facf7`,
`7b56f0f166512073f39e23c8b1daf26b50733385b054a67cdb979c4505c270ef`,
and `81387a027f9d30b7aabecad86d5768897cc9672eb26c1776012b5295be3b964b`.
Both Release and C sanitizer exact-three-API cases passed independently,
with source-bound resource traces and checks, under
`R05-sonic1-v9-library-exact32g-api-2026-09-29.md`. The C sanitizer job was
`job_cfb37f778001445eaaa28f201b8be321`.

This sanitizer build does **not** instrument the Rust component: Sonic1's
container has only the stable Rust toolchain, no nightly/LLVM sanitizer
toolchain, and no `clang` executable. Its bytecode runtime configuration
reports interpreter only, not JIT. Those remain distinct R03/R07 release
blockers. Current disk/memory admission also prevents full PCRE and service
qualification without a separately approved host resource change. No
capability was promoted and final readiness was not claimed.

State: `v9-release-and-c-sanitizer-builds-passed; 32/32-non-edge-each; exact-three-api-parity-passed; rust-sanitizer-and-jit-open; release-gates-open`
