# R03 current-source Werror warning cleanup — 2026-09-14

Task ID / parent milestone: `R03` / `R10`.

The CMake warning-flag accumulator fix made `ENABLE_WERROR=ON` effective. This
follow-up cleaned the first warning sites exposed by that real configuration:
bundled regex, XZ/7-Zip, generated YARA lexer, fileblob control flow, AC/BM
matcher offsets and return typing, TFLite field-offset initialization, and
InstallShield map bounds. No warning suppression was added for these source
families.

The dirty canonical working tree remained at HEAD
`8e837b88c89874b180a1a25f22d287f7d6be29db`. The current-source manifest
contains 1,697 entries and has SHA-256
`19330bf9d99e14ef53661bf531e3cb402200abe0e395dbb44b49af86356a7667`.

## Verification

Using the retained ARM64 `rust:1.97-bookworm` Docker container
(`clamav-current-rust-build-20260911`):

* Isolated Werror configuration `/tmp/clamav-werror-fixed-20260914` completed
  with `-DENABLE_WERROR=ON` and reported
  `WARNCFLAGS: -Werror -Wall -Wextra -Wformat-security`. Its CMakeCache SHA-256
  is `097292a43b9376cb1d6a0d59f08447e1606f09c5021617f3d593267b820f5214`.
* `cmake --build ... --target regex -j1` — exit 0.
* `cmake --build ... --target lzma_sdk -j1` — exit 0.
* `cmake --build ... --target yara -j1` — exit 0.
* Advancing `cmake --build ... --target clamav -j1` reached the legacy
  `libclamav/nsis/bzlib.c` state machine and failed on its macro-driven
  `-Werror=implicit-fallthrough` diagnostics. No global Werror qualification
  is claimed; this identifies the next separate cleanup/suppression decision.
* The retained current-source Release and ASan/UBSan application API suites
  were rebuilt against this complete slice and each passed 529 checks with
  zero failures/errors. Release `check_clamav` SHA-256 is
  `73300dbf222904af9cb924324ef83a76d017a4f4a105824804b899eb533ed2cb`;
  sanitizer `check_clamav` SHA-256 is
  `86437d38b423a6b3b51ef75066aefc9299c88a6e7f052bc157a508bb39314fe0`.
  The sanitizer log SHA-256 is
  `09dc07dc38bb729f141b00c39854f2c1aeb8007aceb17d2c0b1ecd579f829d0f` and
  contains no AddressSanitizer, UBSan, LeakSanitizer, or runtime diagnostics.
* Source guards, snapshot/inventory freshness, and `git diff --check` remain
  required after this receipt/documentation update; no capability was promoted.

State: `development-verified; global-warning-clean-qualification-pending`.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
