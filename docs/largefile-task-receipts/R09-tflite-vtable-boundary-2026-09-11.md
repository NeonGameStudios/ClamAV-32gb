# Task receipt: R09 TFLite vtable boundary

Task ID / parent milestone: `R09` / `R00`

Scope: harden the recognized `CL_TYPE_AI_MODEL` TFLite structural validator
against a FlatBuffer table whose vtable points forward or overlaps the table.
This is a bounded implementation slice; it does not qualify the AI-model row
or change release status.

Canonical checkout and starting identity:

- `<repository-root>`
- branch `largefile-roadmap-qualification`
- starting `HEAD`: `b4cde643fce085fa016338339830b2b28ff9a42a`
- working tree intentionally remained dirty; existing changes were preserved
- source manifest SHA-256 captured before adding this receipt:
  `3489c7110396017f7dd8ea0f0dc6320c0f1389fa1b011c69330c8e545e470532`

Change made:

- `libclamav/scanners.c` now requires the raw TFLite vtable distance to be a
  nonzero positive backwards offset and requires the complete vtable to end
  before the table begins. This removes signed-delta reinterpretation and
  overlap acceptance while retaining the existing table/field range checks.

Verification:

- `python3 -B -m unittest discover -s tools -p '*_test.py'`: 147 passed,
  2 expected skips.
- `sh tools/largefile_source_guards.sh`: passed; 597 capability entries.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`:
  passed.
- `git diff --check`: passed.
- `sh tools/largefile_release_readiness.sh --status`: exit 1 as expected;
  `capability_qualified=0`, `capability_pending=440`,
  `capability_blocked=583`, `release_readiness=blocked`.

Build limitation: the retained ARM64 Docker image was available, but its
CMake graph has no `ninja`; its direct `scanners.c` compile also stopped before
translation because the image contains `/usr/include/zlib.h` without the
required `zconf.h`. The image's absolute Cargo toolchain was usable, yet an
offline current-source check stopped before compilation because the mounted
existing cache lacked `base64` after the cached git dependency was patched. No
software was installed and no network dependency fetch was attempted. No
linked current-source binary or capability qualification is claimed for this
slice.

Remaining work: add this regression to a coherent C build when the existing
dependency/toolchain cache or authorized Linux runner is available, then bind
the full AI-model cases through R04. Certified x86-64, sanitizer, full-size,
materialized-edge, production-CVD/service, and final-canary evidence remain
open.

State: `development-verified`; release qualification remains pending.
