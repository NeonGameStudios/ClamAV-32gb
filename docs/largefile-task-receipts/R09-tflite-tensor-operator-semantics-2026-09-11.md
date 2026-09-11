# Task receipt: TFLite tensor and operator semantic bindings

Task ID / parent milestone: `R09` / required AI-model parser slice

Canonical checkout and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- existing dirty worktree preserved; no reset, clean, commit, or push
- current Git-mode source-manifest SHA-256:
  `bddb576c899480c8b07299abc0b303c16d81008c760bc7d6741c35ca14c00fe2`

## Implementation

`libclamav/scanners.c` now walks recognized TFLite `OperatorCode`, `SubGraph`,
`Tensor`, and `Operator` tables without materializing model weights. The
bounded walk validates signed tensor-shape dimensions (including the TFLite
unknown-dimension sentinel), limits tensor rank, checks TensorType enum bytes,
binds tensor buffer indices to the Model buffers vector, validates tensor name
strings, and binds operator opcode/input/output references to the declared
operator-code and tensor vectors. Null table entries and out-of-range
references fail closed as incomplete, non-cacheable scans.

`unit_tests/check_clamav.c` adds a valid one-tensor/one-operator FlatBuffer
fixture and public API regressions for invalid TensorType, tensor-buffer,
opcode, input, and output references. Each malformed case requires
`CL_EPARSE`, a cleared verdict/alert, and non-cacheability; the valid control
requires a clean, cacheable result.

## Verification

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed;
  2 expected skips**.
- `sh tools/largefile_source_guards.sh` — **passed**, including the 597-row
  capability manifest and acceptance controls.
- isolated host C parser harness built from the current TFLite validator block
  and ran the valid control plus five malformed reference/type cases — **6/6
  passed**.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — **passed**.
- regenerated inventory matches `tools/largefile_inventory.sh` exactly.
- `git diff --check` — **passed**.
- `sh tools/largefile_release_readiness.sh --status` remains expected to fail:
  `597` total, `0` qualified, `143` bounded, `440` pending, `14` allowlisted
  unsupported, and `583` blockers.

## Build boundary

A read-only current-source C syntax probe reached the disposable ARM64 image
but stopped at its missing `json.h` development header. The image also lacks
the coherent JSON-C/Zlib/check development set required for a linked rebuild;
therefore no linked C result is claimed for this slice. No software was
installed on the host or in a container, no remote/MCP-SSH execution was
used, no usage reset or banked reset was used, and no GitHub workflow action
was triggered.

Full TFLite shape/type/operator semantics, sanitizer, certified Linux x86-64,
full-size, production-service, and final release qualification remain open.

State: `development-verified`; release readiness remains blocked.
