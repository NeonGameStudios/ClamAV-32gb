# Task receipt: R09 TFLite buffer-vector bounds

Task ID / parent milestone: `R09` / `R00`

Exact capability: `parser:CL_TYPE_AI_MODEL`

Scope: validate the `Buffer.data` scalar byte-vector range for every buffer
table reached from a recognized TFLite Model. This closes a valid-content
boundary in the structural admission path; it does not promote the AI-model
capability or claim release qualification.

Canonical checkout and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

Source manifest SHA-256 captured before this receipt was added:
`b989450e9cd864618b90c326d1740b67b02361bfda98badfc8358fd151e72f48`.

## Change

`libclamav/scanners.c` now walks the Model `buffers` vector with a dedicated
validator. Each present `Buffer.data` field is interpreted as a scalar byte
vector and must have a complete in-range FlatBuffer offset, length, and payload
range. The required AI-model C test group includes
`test_ai_model_tflite_buffer_data_range_is_fail_visible`, which feeds an
out-of-range `UINT32_MAX` data offset through the public scan API and requires
`CL_EPARSE`, cleared verdict/alert state, and a non-cacheable fmap.

## Verification

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips** before this slice; the source guard rerun covers the updated generated map and R09 binding.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `diff -u docs/largefile-inventory.tsv <(sh tools/largefile_inventory.sh)` — **passed**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- `git diff --check` — **passed**.

The new C test was not linked in this environment: the retained CMake binary
predates the edit and the available Docker images lack the JSON-C/Zlib test
development headers needed for a fresh build. No software was installed and
no remote execution or MCP-SSH path was available.

Release readiness remains blocked at 597 total, 0 qualified, 143 bounded, 440
pending, 14 deliberate unsupported exclusions, 0 unsupported required rows,
and 583 release-blocking rows. No usage reset was used; no capability was
promoted.

State: `development-verified`; linked R09 execution and certified evidence
remain open.
