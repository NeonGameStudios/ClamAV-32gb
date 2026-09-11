# Task receipt: GGUF zero-element tensor compatibility correction

Task ID / parent milestone: `R09` / `CL_TYPE_AI_MODEL`

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`

Canonical source and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- current generated inventory SHA-256:
  `318655ffc4e1b388747b3d6917abbbba82141340a1e1b79fd6595eb431580026`

Observed valid-content gap: the bounded GGUF validator rejected every tensor
shape containing a zero dimension. The authoritative GGML reader accepts
non-negative dimensions and explicitly treats a zero-element tensor as
representable, so the old check was a valid-content false negative.

Implemented slice: read the complete dimension vector, preserve a zero total
element count once any dimension is zero, and continue to apply the existing
rank, tensor-type, block-shape, alignment, offset, and file-range checks. A
zero-element tensor does not cause payload materialization.

Focused regression: `test_ai_model_gguf_accepts_zero_element_tensor` constructs
a rank-one F32 tensor with a zero dimension and an aligned empty data section;
it requires a clean, cacheable result and is registered in the
`tc_required_unsupported` group.

Verification:

- `git diff --check` — passed.
- Full Python tools suite — 145 tests passed, 2 expected Linux skips.
- Inventory refresh — passed; generated inventory hash recorded above.
- Snapshot generation and freshness check — passed.
- `sh tools/largefile_source_guards.sh` — passed; 597 capability entries and
  all source/evidence subchecks passed.
- Linked current-source C execution — unavailable because this host lacks the
  required CMake/build environment; no runtime claim is made.

The format behavior was checked against the authoritative GGML reader:
<https://github.com/ggml-org/ggml/blob/master/src/gguf.cpp>.

State: `development-verified` source/control slice; complete GGUF semantics,
production model corpus, sanitizer, certified Linux x86-64, full-size
qualification, and release qualification remain open.
