# Task receipt: R09 ONNX TensorProto required data type — 2026-09-11

Task ID / parent milestone: `R09` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, starting commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the existing intentionally
dirty working tree preserved. The post-change development source-manifest
SHA-256 was
`908ab7e9c96b2695efd4182fc5856ece4129908be8b05ecbdc6f4d3f3136717b`.
No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used. The linked verification reused the disposable
`clamav-current-rust-build-20260911` container and its already-installed
build dependencies.

Observed gap and expected behavior: ONNX `TensorProto.data_type` is a
required field. An otherwise well-formed empty tensor message must therefore
remain malformed, incomplete, and non-cacheable rather than being admitted as
a structurally supported model.

Changes made:

- `libclamav/scanners.c` now tracks `TensorProto.data_type` presence while
  recursively walking an ONNX tensor and rejects the tensor when the required
  field is absent.
- `unit_tests/check_clamav.c` adds
  `test_ai_model_onnx_rejects_missing_tensor_data_type` and registers it in
  both the ordinary and required-unsupported development groups.
- `tools/largefile_source_guards.sh` pins the new parser error and test
  registrations.
- `docs/largefile-inventory.tsv` was regenerated after the source line-number
  changes.

Verification performed:

- Current-source incremental CMake build completed at 100% in the disposable
  ARM64 container with `RelWithDebInfo`, tests enabled, static libraries
  enabled, shared libraries disabled, and large-file defaults and the
  qualification test disabled.
- Linked `cl_suite/required_unsupported`: 57 checks, 0 failures, 0 errors.
- Linked `cl_suite/cl_api`: 520 checks, 0 failures, 0 errors.
- Updated CTest integration/control selection: 11/11 passed, including
  `libclamav`, `clamscan`, `sigtool`, source guards, runtime evidence,
  acceptance capture, clamscan admission, daemon report protocol, ZIP late
  member, and milter quota checks.
- A built `clamscan` smoke scan loaded the repository's deterministic unit
  signature database and correctly reported the matching test string as
  infected (one file scanned, one infected, exit code 1).
- `python3 -B -m unittest discover -s tools -p '*_test.py'`: 147 passed,
  2 expected skips.
- `sh tools/largefile_source_guards.sh`, snapshot consistency, shell syntax,
  inventory consistency, and `git diff --check`: exit 0.

Qualification boundary: the build ran on `aarch64` with
`ENABLE_LARGE_FILE_DEFAULTS=OFF`, not the roadmap's certified Linux x86-64
profile. This is current-source development verification only. No capability
was promoted. Certified Release/sanitizer, full-size, production-service,
R04-record, and final-canary evidence remain open.

Current release gate remains blocked: 597 total, 0 qualified, 143 bounded,
440 pending, 14 allowlisted unsupported, and 583 blockers.

State: `implemented`; linked current-source development verification passed;
certified 32 GiB verification remains pending.
