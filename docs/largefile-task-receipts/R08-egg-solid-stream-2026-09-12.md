# Task receipt: bounded solid EGG stream extraction

Task ID / parent milestone: `R08` / EGG parser-family sweep

Scope: implement the bounded streaming extraction behavior that the
production EGG scanner already consumes for solid archives. The implementation
replays the shared uncompressed stream, forwards only the requested member's
byte range, verifies every decoded block's declared size and CRC, and keeps
the unsupported solid AZO codec explicitly fail-visible.

Evidence identity:

- Source manifest SHA-256: `d40278d4f36ecca521499f421e97428b55a01cfe38bc61a63fff82fe81322783`
- Test binary: `/tmp/clamav-current-build/unit_tests/check_clamav`
- Test binary SHA-256: `1688fa049ff4f3eaa5d83bae900d01f429e0180b5b20fb3a07a0dfa977e073fd`
- Build-cache `CMakeCache.txt` SHA-256: `2cb58702a077ee0efda8a33dd81f078fa7b41a35e101aed2674fb15a3b0a446b`
- Platform: disposable AArch64 Linux Docker toolchain
- Rust toolchain: `cargo 1.97.1`

The current source configured and linked successfully with the existing
toolchain container. No host software was installed. The focused current-
source EGG map suite passed with zero failures and zero errors:

- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=egg_map`: **15/15 checks**
- `test_egg_solid_stored_members_are_streamed`: extracts both members from a
  shared stored stream, including the late member's exact byte range.
- `test_egg_solid_bzip2_members_are_streamed`: extracts the late member from a
  shared BZIP2-framed stream and verifies the callback output.
- `test_egg_solid_deflate_members_are_streamed`: extracts both members from a
  two-block raw-DEFLATE stream while preserving decoder state across the block
  boundary and verifies the late member's exact byte range.
- `test_egg_solid_lzma_members_are_streamed`: extracts both members from a
  two-block LZMA stream while preserving decoder state across the block
  boundary and verifies the late member's exact byte range.

The repository source guards also passed, including the regenerated
large-file inventory, capability manifest (597 entries), release-readiness
tests, acceptance case map (597 capabilities), and zero-record schema check.
`git diff --check` and the saved status snapshot check passed.

The build graph was then checked from a targeted-build starting point. After
removing only the two generated RAR outputs from the disposable build
directory, `cmake --build /tmp/clamav-current-build --target check_clamav -j2`
regenerated both `clam-v2.rar` and `clam-v3.rar` through the new fixture
dependency and ended with 53/53 materialized scan files. The complete
configured CTest matrix subsequently passed 15/15 in 156.15 seconds, including
the `libclamav` target (all 2,915 checks), the large-file control tests, Rust,
clamscan, clamd, freshclam, and sigtool. This closes the targeted-build
fixture omission without changing the production scanner contract.

State: `development-verified`; EGG capability rows remain pending until the
roadmap's certified Linux x86-64, sanitizer, production-CVD/service, resource,
full-size, Sonic1, and final release gates are satisfied. Solid AZO streams
remain explicit failures pending an independently evidenced decoder-state
path. The legacy contiguous extraction API remains unchanged and does not
claim solid support.

No GitHub workflow action, commit, push, or usage reset was used.
