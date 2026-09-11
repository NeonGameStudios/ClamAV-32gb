# Task receipt: ONNX nested-message kind correction

Task ID / parent milestone: `R09` / `CL_TYPE_AI_MODEL`

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`

Canonical source and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- current generated inventory SHA-256:
  `1df723edb9310f51654d2b03644436ec7e2ac07e5ade009688159cf9b4115914`

Prerequisites verified: no current-source CMake build is available on this
host (`cmake` is absent), so the linked Check binary remains unavailable.
The change was limited to the current source and focused test registration;
no software, remote runner, Docker runtime, usage reset, commit, push, or
GitHub workflow action was used.

Observed valid-content gap: the ONNX structural walker classified several
known length-delimited message fields as another message type. In particular,
`NodeProto.metadata_props` and device configuration payloads were parsed as
`AttributeProto`, whose field-2 wire contract rejects the valid
`StringStringEntryProto`/integer forms. The same aliasing affected nested
message families such as `SparseTensorProto` tensor values and model-level
newer message fields.

Implemented slice: added an explicit opaque ONNX message kind for recognized
length-delimited messages whose full schema is not walked. Actual known paths
remain typed (`GraphProto`, `NodeProto`, `AttributeProto`, `TensorProto`,
`SparseTensorProto`, and `OperatorSetIdProto`); opaque paths still receive
field-number/wire/range/field-count validation without inheriting an unrelated
schema. Corrected the Node and SparseTensor child mappings.

Focused regression: `test_ai_model_onnx_accepts_node_metadata_properties`
builds a valid `ModelProto -> GraphProto -> NodeProto -> metadata_props`
fixture and requires a clean, cacheable result. The test is registered in
both the normal and required-unsupported groups, and source guards require
both registrations.

Verification:

- `git diff --check` — passed.
- `sh tools/largefile_inventory.sh` followed by generated inventory copy —
  completed.
- `python3 -B tools/largefile_status_snapshot.py --output
  32gb-current-snapshot.md` and `--check` — passed.
- `sh tools/largefile_source_guards.sh` — passed; 597 capability entries and
  all local evidence controls passed.
- Linked current-source C execution — unavailable because the host lacks the
  required build environment; no runtime claim is made.

The field mapping was checked against the authoritative ONNX protobuf schema:
<https://github.com/onnx/onnx/blob/main/onnx/onnx.proto>.

State: `development-verified` source/control slice; parser semantics,
production model corpus, sanitizer, certified Linux x86-64, full-size
qualification, and release qualification remain open.
