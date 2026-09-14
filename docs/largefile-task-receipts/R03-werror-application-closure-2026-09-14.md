# R03 current-source Werror application closure — 2026-09-14

Task ID / parent milestone: `R03` / `R10`.

The current-source `ENABLE_WERROR=ON` build now completes across the configured
ClamAV library and application targets. This closes the warning sites exposed
after the earlier flag-propagation and focused-cleanup receipts, including the
NSIS resumable bzip2 state machine, legacy signedness/width checks, pointer
typing, allocation bounds, daemon portability, and deprecated clamsubmit MIME
form handling. No suppression was added to application logic; the generated
Flex/Bison scaffolding and imported BSD qsort implementation use narrowly
scoped diagnostic handling for generator/legacy implementation noise.

The dirty canonical working tree remained at HEAD
`8e837b88c89874b180a1a25f22d287f7d6be29db`. The final current-source
manifest contains 1,697 entries and has SHA-256
`5b64f7a13b71b0320aa5104d9c8f9bbc1e941a30c99bb62a612686e0fc8f0fe4`.

## Verification

Using the retained ARM64 `rust:1.97-bookworm` Docker container
(`clamav-current-rust-build-20260911`):

* The Werror configuration `/tmp/clamav-werror-fixed-20260914` completed with
  `-DENABLE_WERROR=ON`, `-DENABLE_TESTS=OFF`, and the application, on-access,
  milter, and unrar options enabled. Its CMakeCache SHA-256 is
  `a24e5688e61c4ef981a3e91d36aabd6b5a14e150f27e4eeb409612250fc85af2`.
* The complete `cmake --build /tmp/clamav-werror-fixed-20260914 -j1` build
  passed with exit 0, including `clamav`, `clamscan`, `clamconf`, `clamd`,
  `clamdscan`, `clamonacc`, `clamav-milter`, `clamsubmit`, `freshclam`, and
  `clamdtop`.
* The rebuilt current-source Release tree
  `/tmp/clamav-release-current-20260913` completed with exit 0. Its
  CMakeCache SHA-256 is
  `1645995e25859b5563715da91a714a90691f688c7b4645dc55aaec7fae32f615`.
* The rebuilt current-source ASAN/UBSAN tree
  `/tmp/clamav-asan-current-20260912` completed with exit 0. Its CMakeCache
  SHA-256 is
  `ade9a74d0690bb89fe2f2e4a060af9be20339e9632c1d58da5c840ae46cdb460`.
* Release `check_clamav` (`f3654b4006e248f6e95f6a0dd0a78fd16d8b764db7a4faf430b377895d1c288c`)
  passed `cl_api` 529/529 with zero failures or errors.
* ASAN/UBSAN `check_clamav` (`e3f1224541b1961c8a8ed7e0a0065d858a33ca1f78d1d5b3bcb2c7d652d71736`)
  was rebuilt successfully. The prior aggregate ASAN/UBSAN `cl_api` rerun did
  not return in the bounded wait and is not counted as a pass; the aggregate
  was not repeated after this rebuild. Focused ASAN/UBSAN 7-Zip, YARA, and
  regex cases all passed with no sanitizer diagnostic.
* Focused current-source Release and ASAN/UBSAN parser/matcher runs passed in
  both builds: 7-Zip `cl_suite/7z` 29/29, YARA `matchers/yara` 21/21, and
  bundled regex `regex/cli_regcomp/execute` 4/4. The sanitizer runs used the
  same leak-detection and halt-on-diagnostic settings and emitted no sanitizer
  diagnostic.

This is ARM64 development evidence. The aggregate ARM64 `libclamav` CTest
timeout, certified Linux x86-64, exact/materialized 32-GiB, production
CVD/service, resource/fanotify, Sonic1, independent format-8, complete
capability-specific acceptance records, and final release review remain open.
The solid EGG AZO boundary remains intentionally fail-visible because this
source tree has no AZO decoder/state API.

A separate maximal-warning exploration now passes the generated YARA
parser/lexer, arena, hash-table, JSON, blob, shared utility layers, and the
current `str.c`, `strlcat.c`, `table.c`, `www.c`, `disasm.c`, and `filtering.c`
translation units before reaching the larger legacy warning set in
`libclamav/matcher-ac.c`. It remains non-qualifying and is not used to
downgrade the supported Werror application-build result above.

State: `development-verified; global-release-qualification-pending`.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
