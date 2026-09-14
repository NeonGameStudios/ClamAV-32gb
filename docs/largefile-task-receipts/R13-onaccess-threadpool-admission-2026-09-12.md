# Task receipt: R13 on-access thread-pool admission — 2026-09-12

Task ID / parent milestone: `R13` / R10.

Exact capability kind:id list: `on-access:permission` and the shared
on-access worker-queue scheduling contract. This receipt does not promote any
capability to release qualification.

Starting commit and working-tree/source manifest identity: starting commit
`8e837b88`; the worktree already contained the roadmap implementation and
uncommitted task files. The post-change source manifest generated from the
current worktree is SHA-256
`6cd062f6259247475caac8fadca689e4ed806ae56db26b07a2edac725acd939c`.

Prerequisites verified: the existing `rust:1.97-bookworm` ARM64 development
container was reused with the current checkout mounted at `/src`. The
out-of-tree Release build was configured at
`/tmp/clamav-release-current-20260912`; CMake reported clamonacc, milter,
UnRAR, and pthread support enabled. No software was installed.

Owned files and excluded shared files: `clamonacc/clamonacc.c`,
`clamonacc/c-thread-pool/thpool.c`, `unit_tests/CMakeLists.txt`,
`unit_tests/check_onas_threadpool.c`,
`tools/largefile_onaccess_config_admission_test.sh`,
`tools/largefile_source_guards.sh`, and the generated
`docs/largefile-inventory.tsv`. Existing unrelated worktree changes were
preserved.

Observed failing case and expected behavior: `thpool_init(0)` previously
returned a pool with no workers, allowing the on-access queue to accept an
event that could never be processed. A configured `OnAccessMaxThreads` value
also narrowed from `long long` into the context's `int32_t` field without an
upper-bound check. Zero, negative, and greater-than-`INT32_MAX` values must be
rejected before daemon or fanotify startup; a positive one-worker pool must
execute queued work.

Changes made:

- Reject non-positive thread-pool sizes and native-size allocation overflow
  before creating the pool.
- Validate `OnAccessMaxThreads` in `clamonacc` before startup and before the
  narrowing assignment.
- Add a direct bundled-pool regression and an application-level config
  admission regression for `0` and `2147483648`.
- Add source-guard coverage and refresh the generated inventory.

Commands, exits, logs and fixture/database hashes:

- Reconfigure current source with CMake — exit 0.
- Build `check_onas_threadpool` and `clamonacc` — exit 0.
- Focused CTest for both new tests — `2/2` passed.
- Full configured CTest after inventory refresh — `26/26` passed in `172.23`
  seconds.
- Final `sh tools/largefile_source_guards.sh` — exit 0.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — exit 0.
- `git diff --check` — exit 0.
- Rebuilt `clamonacc` SHA-256:
  `b1620ed4c2890846c61f936866f33b4239fb18bb139ab0a2c65baff7c0c90692`.
- Rebuilt pool regression SHA-256:
  `4ec61ad9573cdd1066062e06792c680e90e8d7afa4b9bef6dfb43b206b8b9a8f`.

Development tests passed: direct pool rejection/execution and actual
`clamonacc` invalid-config admission passed; the complete current-source
ARM64 Release CTest matrix passed `26/26`.

Full-size/certified evidence produced, or explicitly not run: not produced;
the available container is Linux ARM64 and cannot satisfy the roadmap's
certified Linux x86-64, exact 32-GiB, sanitizer, production-CVD, Sonic1,
resource-sidecar, or privileged fanotify permission requirements.

Remaining failures / next slice: continue R12/R13 implementation and case
coverage, then run the per-case matrix on an authorized certified x86-64 host.
R07's independent format-8 artifact and R14 production canary remain open.

State: `development-verified; qualification-blocked-by-runner-and-fixtures`

