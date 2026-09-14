# Task receipt: R09 GGUF empty-array element type — 2026-09-11

Task ID / parent milestone: `R09` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, starting commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the existing intentionally
dirty working tree preserved. No dependency installation, remote execution,
Docker execution, SSH, usage reset, commit, push, or GitHub workflow action was
used.

Prerequisites verified: the existing GGUF structural walker and its required-
unsupported development regressions were inspected. The walker recursively
validated an array element type only while visiting array elements, leaving a
zero-count array's invalid element type unchecked.

Observed failing case and expected behavior: a recognized GGUF model with one
metadata entry whose value is an array with an undefined element type and a
zero element count must remain malformed, incomplete, and non-cacheable. It
must not become a clean result solely because the array is empty.

Changes made:

- `libclamav/scanners.c` now validates the GGUF array's declared element type
  before reading or iterating its count, so the zero-count path cannot bypass
  the type check.
- `unit_tests/check_clamav.c` adds and registers
  `test_ai_model_gguf_empty_metadata_array_type_is_fail_visible`, requiring
  `CL_EPARSE`, no alert, and `dont_cache_flag` for an otherwise aligned
  model.
- `tools/largefile_source_guards.sh` binds the new source behavior and
  regression to the source-level guard set.

Verification performed or pending:

- Targeted source assertions and
  `sh -n tools/largefile_source_guards.sh` passed.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` passed 147
  tests with 2 expected skips; the service workload checker passed 28 tests
  with 2 expected Linux-only skips.
- The acceptance map reported 597 capabilities, the acceptance-record check
  passed with 0 records, the refreshed snapshot passed its freshness check,
  inventory generation completed, and `git diff --check` passed.
- A direct current-source `cc -fsyntax-only` attempt exited 1 before
  compiling `scanners.c` because the host has no `openssl/ssl.h`; no
  software was installed.
- The full current-source C test binary is not available on this host; the
  existing Docker API is unavailable and the cached build must not be used as
  current-source runtime evidence. The host also lacks the dependency headers
  needed for a direct `scanners.c` syntax-only compile.
- Host tooling, service workload, inventory, snapshot, acceptance-map/schema,
  and diff checks remain development evidence only and do not qualify the row.

Full-size/certified evidence: not produced. Certified Linux x86-64, Release
and sanitizer builds, production-CVD/service, full-size model corpus, R04 case
records, and final release qualification remain open.

Remaining failures / next slice: run the focused current-source C regression
when a coherent build is available, then continue broader GGUF/ONNX/TFLite
model-corpus and certified qualification work. No capability was promoted.

State: `implemented`; linked current-source verification is pending.
