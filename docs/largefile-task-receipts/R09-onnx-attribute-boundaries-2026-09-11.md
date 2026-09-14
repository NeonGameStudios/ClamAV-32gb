# Task receipt: R09 ONNX AttributeProto boundaries — 2026-09-11

Task ID / parent milestone: `R09` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, starting commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the existing intentionally
dirty working tree preserved. The final development source-manifest SHA-256
was `b77269f6cd5ed67ab0582298b98dc0ad1e0913312716ba2456b432078b28efbd`.
No host dependency installation, remote execution, usage reset, commit, push,
or GitHub workflow action was used. The missing build dependencies were
installed only inside the disposable `clamav-current-rust-build-20260911`
container, which was based on the existing `rust:1.97-bookworm` image.

Prerequisites verified: the current ONNX schema defines `AttributeProto.name`
as a required semantic field for an attribute and defines a finite
`AttributeType` discriminator. The structural walker must not treat a nested
attribute with valid protobuf wire types as complete when those semantic
boundaries are violated.

Observed failing case and expected behavior: a recognized ONNX model carrying
an unnamed `AttributeProto`, or an attribute type outside the defined enum,
must remain malformed, incomplete, and non-cacheable. A named attribute with
a valid type must remain structurally supported.

Changes made:

- `libclamav/scanners.c` now requires a nested `AttributeProto` name and
  bounds its type discriminator to the current ONNX range 0 through 14 while
  walking varints.
- `unit_tests/check_clamav.c` adds valid named/typed, unnamed, and invalid
  type fixtures, and registers them in both ordinary and
  required-unsupported development groups.
- `tools/largefile_source_guards.sh` binds the new attribute policy and test
  registrations.

Verification performed:

- `python3 -B -m unittest discover -s tools -p '*_test.py'`: 147 passed,
  2 expected skips.
- `sh tools/largefile_source_guards.sh`: exit 0, including the 597-entry
  manifest, release-readiness, snapshot, evidence-schema, acceptance-map,
  and source checks.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md`, `sh -n tools/largefile_source_guards.sh`, and
  `git diff --check`: exit 0. The generated inventory was refreshed and
  matched its generator output.
- A current-source disposable ARM64 Docker build configured and completed at
  100% with CMake `RelWithDebInfo`, tests enabled, static libraries enabled,
  shared libraries disabled, and both large-file qualification switches off.
  The resulting `check_clamav`, `clamscan`, and `clamd` binaries were linked
  from the current checkout. The container architecture was `aarch64` and the
  `check_clamav` binary SHA-256 was
  `e7de427e54e2a73c272bea510dacf79726ca843f976d93c029b67ba38ca3c569`.
- The linked `cl_suite/required_unsupported` run passed 56 checks with 0
  failures and 0 errors. The linked `cl_suite/cl_api` run passed 519 checks
  with 0 failures and 0 errors; its only diagnostic was the expected fixture
  message `traverse_to: Failed open payload`.
- The generated CTest integration run passed `libclamav`, `clamscan`, and
  `sigtool` (3/3; `libclamav` took 74.61 seconds). `clamscan --version`,
  `clamscan --help`, and the built application version banner also completed
  successfully.
- The configured large-file CTest controls passed 8/8, including source
  guards, runtime-evidence validation, development acceptance capture,
  clamscan admission, daemon report protocol, ZIP late-member coverage, and
  the milter quota check.
- A direct `check_clamd` invocation was intentionally not counted as a test
  result because it omitted the harness's separately-started
  `clamd-test.socket`; it produced connection failures, not daemon-source
  assertions.

Full-size/certified evidence: not produced. Certified Linux x86-64, Release
and sanitizer builds, production-CVD/service, full-size model corpus, R04
case records, and final release qualification remain open.

Current release gate remains blocked: 597 total, 0 qualified, 143 bounded,
440 pending, 14 allowlisted unsupported, and 583 blockers. The ARM64 build
does not satisfy the roadmap's certified Linux x86-64 profile and was
configured with large-file defaults disabled, so this evidence demonstrates
current-source development functionality only; it does not promote any
capability or establish 32 GiB qualification.

State: `implemented`; linked current-source development verification passed;
certified 32 GiB verification remains pending.
