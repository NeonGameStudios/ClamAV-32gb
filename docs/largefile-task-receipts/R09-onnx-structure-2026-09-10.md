# Task receipt: R09 ONNX structural admission

Task ID / parent milestone: `R09` / `R00`

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`; existing dirty working tree preserved; the
generated inventory and snapshot were refreshed after this slice.

Prerequisites verified: the existing AI-model dispatch, GGUF parser, and TFLite
FlatBuffer validator were inspected; the ONNX protobuf field layout was checked
against the [authoritative ONNX ModelProto definition](https://raw.githubusercontent.com/onnx/onnx/main/onnx/onnx.proto); no dependency installation,
remote runner, Docker execution, usage reset, commit, push, or GitHub workflow
action was used.

Observed failing case and expected behavior: non-GGUF/non-TFLite AI-model input
previously fell through to a generic unsupported result. A structurally valid
ONNX ModelProto should complete without a whole-input allocation; malformed
varints, wire types, fixed-width fields, nested ranges, or missing required
ModelProto fields must remain incomplete and non-cacheable.

Changes made:

- Added a bounded protobuf wire-format walker for ONNX ModelProto inputs. It
  validates field numbers, required operator-set versions, varints, fixed-width
  values, length-delimited ranges, parser depth, and total field count.
- Correctly recognizes ModelProto `graph` field 7 and `opset_import` field 8,
  then recursively validates known graph/node/attribute/tensor/sparse-tensor
  paths without materializing model strings or weight payloads. Skipped
  length-delimited payloads also pass through the shared scan-deadline check.
- Routed non-GGUF, non-TFLite AI-model inputs through the ONNX structural parser.
- Added valid ModelProto, missing-graph, nested-message-truncation, and missing
  operator-set-version regressions to the required-unsupported development
  group.

Commands, exits, logs and fixture/database hashes:

- `git diff --check` passed before final gate execution.
- `sh tools/largefile_source_guards.sh` exited 0. The gate passed the refreshed
  597-row acceptance map/schema checks, development service tests, legacy clamd
  protocol tests, boundary corpus tests, snapshot tests, and source guards.
- `cc -fsyntax-only -std=gnu11 -I/private/tmp/clamav-scanner-syntax -I.
  -Ilibclamav -Ilibclamav_rust libclamav/scanners.c` exited 1 before parsing
  this source because the host lacks `openssl/ssl.h`; no software was
  installed.

Development tests passed: repository source-level tests and registrations
passed through the final source gate; no linked current-source C test binary is
available on this host.

Full-size/certified evidence produced, or explicitly not run: not run. No
current-source CMake build, Linux x86-64 Release/sanitizer build, production
database, materialized large-file edge, or R04 qualification record exists for
this slice.

Remaining failures / next slice: ONNX tensor/type/operator semantic validation,
full production model corpus coverage, current-source consumer execution, and
certified parser/release qualification remain open. All 597 capability rows
remain pending/blocked for release purposes.

State: development-verified
