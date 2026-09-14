# Task receipt: R08 no-mempool bytecode allocation ownership

Task ID / parent milestone: `R08`

Exact capability kind:id: `feature:DISABLE_MPOOL`. The matching focused test
family is `bytecode:map_read`. This receipt records ARM64 development
verification only and does not promote the capability to qualified.

## Source and build identity

- Canonical checkout: `<repository-root>`.
- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `8e837b88c89874b180a1a25f22d287f7d6be29db`.
- The post-change dirty-source manifest contains 1,697 entries and has
  SHA-256 `3d146e1b5ab18ac7e158cac6e96b88c39952a1eca8ff4ceb1d4e0bd405a7b13e`.
- The existing dirty working tree was preserved; no reset, clean, commit, or
  push was performed.
- The generated large-file inventory was refreshed to 44,885 lines and has
  SHA-256 `053e2a023252b2d8ee3c0d85c71d6054fb68fac89cecd580f1ad715ed9691156`.

## Observed gap and change

With `DISABLE_MPOOL` enabled, `cli_bcapi_malloc()` previously called
`cli_max_malloc()` without recording ownership, skipped the normal zero-size
and allocation-ceiling checks, and left a reset TODO in
`bytecode_context_reset()`. Bytecode API allocations could therefore leak
across a context reset and did not have the same admission behavior as the
memory-pool path.

- `struct cli_bc_ctx` now stores a bounded list of no-mempool allocations.
- `cli_bcapi_malloc()` rejects zero and over-ceiling requests, allocates with
  `cli_max_malloc()`, grows the ownership list with checked
  `cli_max_realloc()`, and frees the new allocation if list growth fails.
- `bytecode_context_reset()` frees every tracked allocation and clears the
  ownership list.
- `test_bytecode_malloc_is_bounded_and_reset` covers rejected sizes, a
  successful allocation, and the no-mempool ownership count.

Owned files:

- `libclamav/bytecode_api.c`
- `libclamav/bytecode.c`
- `libclamav/bytecode_priv.h`
- `unit_tests/check_bytecode.c`
- `docs/largefile-capabilities.tsv`

## Development verification

The build used the existing Docker development container and the pinned
toolchain; no software was installed. The no-mempool configuration was:

```text
CMAKE_BUILD_TYPE=Release
DISABLE_MPOOL=ON
ENABLE_STATIC_LIB=ON
ENABLE_SHARED_LIB=OFF
ENABLE_TESTS=ON
ENABLE_APP=ON
ENABLE_CLAMONACC=ON
ENABLE_MILTER=ON
ENABLE_UNRAR=ON
ENABLE_LARGE_FILE_QUALIFICATION_TEST=OFF
```

- Full static build, including applications and roadmap-specific test
  executables: exit 0.
- `CK_RUN_SUITE=bytecode CK_RUN_CASE=map_read .../check_clamav`: 25 checks,
  zero failures, zero errors; exit 0.
- Complete configured CTest matrix after building all targets and refreshing
  the generated inventory: 28/28 passed in 229.29 seconds.
- The full `libclamav` C suite in that matrix passed 2,919 checks with zero
  failures and zero errors.
- Source guard, runtime evidence, service evidence, application admission,
  clamd, milter, freshclam, sigtool, and Rust integration entries all passed
  in the final 28/28 matrix.
- `git diff --check`: exit 0.

The first CTest attempt was intentionally superseded: it ran before the
application and fixture targets were built, so it reported missing binaries,
missing generated AutoIt fixtures, and stale inventory. After the full build
and inventory refresh, the authoritative rerun passed 28/28.

Built artifact SHA-256 values:

- `unit_tests/check_clamav`:
  `48c6eebfa25b311a29c32913288c9ede9b4bb00983ac8040e4ea37a4e1d664e2`
- `clamscan/clamscan`:
  `6d63180c63646a775d2d353261b89e6d39619307a247af953082c80a36606d7e`
- `clamd/clamd`:
  `6c2c3db43e5a305beb2726b86bb004cb141e623190d8d9e1c74e436b6611a4d9`
- `sigtool/sigtool`:
  `f875e6cc654ae2a9aac221a6c4fd5390e9545d39877f9a023cd26a1da06314b1`

## Limits and next action

This is development verification on ARM64, not release qualification. The
certified Linux x86-64 build, exact 32-GiB materialized cases, sanitizer
matrix, production-CVD/service evidence, Sonic1 evidence, and final
allocator-variant qualification remain open. Keep the capability `pending`
until those roadmap gates are satisfied.

State: `development-verified`; release qualification remains pending.
