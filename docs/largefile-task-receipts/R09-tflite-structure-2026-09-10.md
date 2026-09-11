# Task receipt: R09 TFLite structural admission

Task ID / parent milestone: `R09` / `R00`

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`; existing dirty working tree preserved; the
generated inventory and snapshot were refreshed after this slice.

Prerequisites verified: the existing AI-model dispatch and GGUF structural
parser were inspected; no dependency installation, remote runner, Docker
execution, usage reset, commit, push, or GitHub workflow action was used.

Owned files and excluded shared files: owned the AI-model parser section in
`libclamav/scanners.c`, required-unsupported Check cases in
`unit_tests/check_clamav.c`, and the corresponding source-guard/ledger
metadata. Shared release labels and qualification records were not promoted.

Observed failing case and expected behavior: TFLite inputs are recognized by
the `TFL3` file identifier but previously fell through to the generic AI-model
unsupported result. A structurally valid Model root should complete without a
whole-input allocation; invalid root, vtable, vector, and string ranges must
remain incomplete and non-cacheable.

Changes made:

- Added a bounded, non-materializing FlatBuffer validator for the TFLite Model
  root. It checks the file identifier, root offset, signed vtable relation,
  vtable/table ranges, field offsets, direct Model vectors, referenced table
  topology, string termination, table-count admission, and the required
  nonempty subgraph vector.
- Routed `TFL3` inputs through that validator while retaining the mandatory
  outer raw matcher and the explicit ONNX unsupported boundary.
- Added one valid minimal Model fixture and root/vector corruption regressions
  to the required-unsupported development group.

Commands, exits, logs and fixture/database hashes:

- `git diff --check` passed before final gate execution.
- `sh tools/largefile_source_guards.sh` passed after the generated
  inventory/snapshot refresh, including the 597-row acceptance map and schema
  checks; no current-source C link is available on this host.

Development tests passed: not yet run against a linked C test binary; the
source-level tests and registrations are covered by the final source guard.

Full-size/certified evidence produced, or explicitly not run: not run. No
current-source CMake build, Linux x86-64 Release/sanitizer build, production
database, materialized large-file edge, or R04 qualification record exists
for this slice.

Remaining failures / next slice: TFLite nested model semantics and full model
corpus qualification remain open. All 597 capability rows remain
pending/blocked for release purposes.

Refinement (2026-09-10 UTC): present Model-table fields now require the
complete four-byte FlatBuffer uoffset to fit inside the table's declared object
size. `test_ai_model_tflite_field_width_is_fail_visible` covers a table whose
field starts in-range but whose value crosses the declared object boundary;
the malformed model remains `CL_EPARSE` and non-cacheable. The source guard
passed after this refinement. The ONNX bounded structural parser is now
implemented separately; TFLite nested tensor/operator semantics, current-source
C execution, sanitizer, certified Linux x86-64, production model corpus, and
release qualification remain open.

State: development-verified
