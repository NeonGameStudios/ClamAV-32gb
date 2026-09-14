# Task receipt: R09 TFLite vtable regression

Task ID / parent milestone: `R09` / `R00`

Exact capability: `parser:CL_TYPE_AI_MODEL`

Scope: bind the TFLite vtable-distance hardening to the checked-in required
AI-model test group. This adds fail-visible regression coverage; it does not
promote the AI-model capability or claim release qualification.

Canonical checkout and branch:

- `<repository-root>`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

Source manifest SHA-256 captured before this receipt was added:
`8f570c95d58bdc2a19372f336ddc7628e8ed6b91101f3c3b488635d6b7b1c15a`.

## Change

`unit_tests/check_clamav.c` now tests zero and `UINT32_MAX` TFLite vtable
distances through the public `CL_TYPE_AI_MODEL` scan path. Each case requires
`CL_EPARSE`, a cleared verdict/alert, and a non-cacheable fmap. The regression
is registered in `tc_required_unsupported`, pinned by the source guard, and
listed in the AI-model capability evidence description.

## Verification

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `diff -u docs/largefile-inventory.tsv <(sh tools/largefile_inventory.sh)` — **passed**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- `git diff --check` — **passed**.

The new C test was not linked in this environment: the retained CMake binary
predates the edit and the available Docker images lack the JSON-C/Zlib test
development headers needed for a fresh build. No software was installed and
no remote execution or remote SSH path was available.

Release readiness remains blocked at 597 total, 0 qualified, 143 bounded, 440
pending, 14 deliberate unsupported exclusions, 0 unsupported required rows,
and 583 release-blocking rows. No usage reset was used; no capability was
promoted.

State: `development-verified`; linked R09 execution and certified evidence
remain open.
