# Task receipt: R09 ONNX TensorProto enum boundaries — 2026-09-11

Task ID / parent milestone: `R09` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, starting commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the existing intentionally
dirty working tree preserved. No dependency installation, remote execution,
usage reset, commit, push, or GitHub workflow action was used.

Prerequisites verified: the current ONNX structural walker was compared with
the current upstream ONNX schema. `TensorProto.data_type` is an int32 enum and
`TensorProto.data_location` is an enum with only `DEFAULT` and `EXTERNAL`.

Observed failing case and expected behavior: a recognized ONNX model carrying
an out-of-range TensorProto data type or data-location enum must remain
malformed, incomplete, and non-cacheable. It must not become a clean result
merely because the protobuf wire types are valid.

Changes made:

- `libclamav/scanners.c` now bounds `TensorProto.data_type` to the current
  ONNX enum range 0 through 28 and bounds `TensorProto.data_location` to 0 or
  1 while walking varints.
- `unit_tests/check_clamav.c` adds and registers a valid upper-bound case plus
  invalid data-type and data-location cases in both ordinary and
  required-unsupported development groups.
- `tools/largefile_source_guards.sh` binds the enum policy and registrations.

Verification performed or pending:

- `sh tools/largefile_source_guards.sh` exited 0, including the 597-entry
  manifest, readiness, snapshot, evidence-schema, acceptance-map, and source
  checks.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md`, `sh -n tools/largefile_source_guards.sh`, and
  `git diff --check` exited 0. The generated inventory was refreshed.
- A direct host `cc -fsyntax-only` attempt exited 1 before reaching
  `scanners.c` because `openssl/ssl.h` is absent. The local Docker API is also
  unavailable, so no linked current-source C execution was claimed and no
  software was installed.
- `sh tools/largefile_release_readiness.sh --status` remains correctly
  blocked: 597 total, 0 qualified, 143 bounded, 440 pending, 14 allowlisted
  unsupported, and 583 blockers.

Full-size/certified evidence: not produced. Certified Linux x86-64, Release
and sanitizer builds, production-CVD/service, full-size model corpus, R04 case
records, and final release qualification remain open.

Remaining failures / next slice: run the three focused regressions against a
coherently rebuilt current-source C target, then continue the ONNX nested
message semantic coverage and remaining R08 parser families.

State: `implemented`; linked current-source verification is pending.
