# R09 AI-model skipped-read hardening — 2026-09-17

Task ID / parent milestone: R09 required unsupported rows; AI-model parser
fail-closed behavior.

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`.

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`, local HEAD
`6312634ec24539dc6087a76df401a81b8e9aca7c`, intentionally dirty working tree.

Prerequisites verified: current source tree and generated inventory were
available locally; no package installation was needed.

Owned files and excluded shared files: `libclamav/scanners.c`,
`unit_tests/check_clamav.c`, `tools/largefile_source_guards.sh`, and the
regenerated `docs/largefile-inventory.tsv`. Existing unrelated changes were
preserved.

Observed failing case and expected behavior: the GGUF and ONNX structural
walkers validated skipped length-delimited payload bounds by advancing the
fmap offset without reading the skipped bytes. An in-range backing-read
failure inside producer metadata could therefore be accepted as a clean
structural parse. The expected result is `CL_EREAD`, an incomplete/non-cacheable
scan, and no clean verdict.

Changes made: `cli_ai_model_skip()` now reads skipped ranges through bounded
4-KiB buffers, checks the scan deadline per chunk, and maps a backing read
failure to `CL_EREAD` with an explicit incomplete reason. Current-source C
regressions build valid ONNX and GGUF structures with 300,000-byte skipped
payloads and fail the fmap after the first 256 KiB; both are registered in the
ordinary and required-unsupported test cases.

Commands, exits, logs and fixture hashes:

* `sh -n tools/largefile_source_guards.sh` — exit 0.
* `sh tools/largefile_inventory.sh` followed by exact comparison against
  `docs/largefile-inventory.tsv` — exit 0.
* `git diff --check` — exit 0.
* `sh tools/largefile_source_guards.sh` — exit 0; 604 capability bindings and
  all included AI-model, acceptance, evidence, snapshot, and readiness checks
  passed.

Development tests passed: source-level and Python/tooling verification passed.
The newly added C regression was not linked or executed because the local
application build lacks JSON-C/Check/curl development metadata and the
current-source Sonic1 delivery boundary remains blocked.

Full-size/certified evidence produced, or explicitly not run: none. No
certified Linux x86-64, sanitizer, production-database, full-size, or release
qualification evidence is claimed.

Remaining failures / next slice: build and run the current source on an
authorized x86-64 runner with the required dependencies, then execute the
fresh AI-model parser regression and R04 capability cases. Release readiness
remains blocked.

State: development-verified; runtime-qualification-open
