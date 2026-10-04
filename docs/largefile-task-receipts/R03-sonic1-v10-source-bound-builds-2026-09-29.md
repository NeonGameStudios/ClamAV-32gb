# R03 Sonic1 v10 source-bound Release/C-sanitizer builds — 2026-09-29

## Candidate and runner

The current dirty canonical checkout was frozen as the deterministic v10
source package, transferred to Sonic1 with MCP-SSH durable transfer
`transfer_77f0ca552870446faf4b19351359dc2a`, and extracted to
`/qualification/source-v10-r04-20260929`. Independent Git-less source-manifest
regeneration matched the packaged file byte-for-byte; SHA-256
`a8bcd93903525147ababd91633e6764e570136ff4239332cb73c60d3e62a3d6a`.
The local manifest was regenerated after receipt edits and still had the same
hash. Package SHA-256, transfer and v10 Python guard results are in
`R04-service-input-rehash-2026-09-29.md`.

Host/profile: `sonic1` / `sonic1-camera-key`. Pinned container:
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`;
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
Both builds used the extracted v10 source, not the stale `/src` mount, and
the existing offline Cargo cache and disk-backed `/qualification` TMPDIR.

## Coherent build and baseline tests

| Profile | Configure / build / non-edge CTest jobs | CMakeCache SHA-256 | Outcome |
| --- | --- | --- | --- |
| Release | `job_f80b382506734cb1a4cab7cab6bd7795` / `job_e4fa6fb2b43a41e08dc17fb0319b8e06` / `job_1d152bd7837a461da3dd9790b95344f1` | `0fc3d24b3f10929cbff0cb299d155decbf815f4e4ff5b8b7efedf21ac2e4beb1` | 32/32 non-edge CTests passed; 139.83 s |
| C ASan/UBSan | `job_b0ea637df0d946638b5eb324d8160d92` / `job_2ca7f491441f49549d7fa6c37f80a89b` / `job_a19c90162c0c4d52827fec79326eeb98` | `0697e08a37ed49d5003b701ebefc1e5521b81980a8d6b73f7ebb74b1ab303d64` | 32/32 non-edge CTests passed; 236.52 s |

Both caches name `/qualification/source-v10-r04-20260929` as their CMake
home directory and enable app, clamonacc, milter, JSON shared, shared/static
libraries, UnRAR, tests, large-file defaults and the exact-size test.
Release has `ENABLE_WERROR=ON`; the C sanitizer profile uses RelWithDebInfo,
GCC `-fsanitize=address,undefined -fno-omit-frame-pointer`, sanitizer linker
flags and `ENABLE_WERROR=OFF`. Its CTest used
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Both CTest commands
excluded `largefile_library_exact_32g`, which is a separate full-size case.

| Binary | Release SHA-256 | C ASan/UBSan SHA-256 |
| --- | --- | --- |
| `clamscan` | `a3ae4989218dc5a917fc768b7ef983cc20b63d9bc907b1d7a9652377370b07ca` | `87c34994e207cdf3c20f03012f796d0717db505a2def4f08b7a3ddf647a7a13d` |
| `clamd` | `1daf216feaf3b7b097087887ccda8acafa944b95af06036c694288b641f29a91` | `5714b5141160306e0789fb53ac3de2cf62df3a0ba00a66cc53a9a313b51573ea` |
| `clamdscan` | `99a325973d7074d63f30feedbceb00c8744bdc0bdf93e438008100ba9dab0d70` | `bbe513a779b78973c7101c2cc2ff5bc78a6220953ee200136c0af1a0b5a3d27f` |
| `check_clamav` | `29119715ded894878338b71c95f152a49066be4541df0e760df50dac2e487c13` | `077589d09357a35505a5f3240b43fac32af6225d3065ee1f40abdcd3afc70edb` |

At the post-build preflight the qualification LV had 9,003,225,088 free
bytes; memory available was 23,065,288 KiB and swap was zero. This permits
bounded raw/library edge work but not the required 48-GiB-available-memory
and 68-GiB-free disk-backed certified daemon/PCRE service profile.

This is build and non-edge test readiness only. The C sanitizer build still
contains stable, uninstrumented Rust; LLVM JIT is not available in this
cached toolchain. Full-size v10 library/CLI, Rust-sanitizer, PCRE, service,
fanotify, production-CVD and complete R04 matrix evidence remain separate
requirements. No capability was promoted, no software was installed, and no
usage reset, commit, push or GitHub workflow action occurred.

State: `v10-release-and-c-sanitizer-builds-passed; non-edge-ctest-32-of-32-each; full-size-and-release-gates-open`.
