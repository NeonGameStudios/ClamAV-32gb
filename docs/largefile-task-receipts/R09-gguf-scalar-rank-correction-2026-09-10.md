# Task receipt: GGUF scalar-rank compatibility correction

Task ID / parent milestone: `R09` / `CL_TYPE_AI_MODEL`

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`

Canonical source and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- current generated inventory SHA-256:
  `91a0a52548767e73ed4978f93611550ee95d83181931cf57d86c1f7823e00441`

Prerequisites verified: no current-source CMake build is available on this
host (`cmake` is absent), so the linked Check binary remains unavailable.
No software, remote runner, Docker runtime, usage reset, commit, push, or
GitHub workflow action was used.

Observed valid-content gap: the GGUF validator rejected `n_dimensions == 0`
before calculating tensor geometry. The authoritative ggml reader initializes
the remaining dimensions to one and accepts rank-zero scalar tensors, so this
was a valid-content false negative rather than a malformed-input boundary.

Implemented slice: retain the existing maximum rank-four and dimension-range
checks, but allow rank zero. A scalar still receives normal tensor-type
geometry and aligned data-range validation; the parser does not materialize
the payload.

Focused regression: `test_ai_model_gguf_accepts_scalar_tensor` constructs a
rank-zero F32 tensor with an aligned four-byte payload and requires a clean,
cacheable result. It is registered in the required-unsupported group and
source-guarded.

Verification:

- `git diff --check` — passed.
- Inventory refresh and status snapshot generation/check — passed.
- `sh tools/largefile_source_guards.sh` — pending after this receipt is
  recorded; the prior source guard passed before the receipt-only update.
- Linked current-source C execution — unavailable because the host lacks the
  required build environment; no runtime claim is made.

The format behavior was checked against the authoritative ggml reader and
format sources:
<https://github.com/ggml-org/ggml/blob/master/src/gguf.cpp>
<https://github.com/ggml-org/ggml/blob/master/docs/gguf.md>.

State: `development-verified` source/control slice; complete GGUF semantics,
production model corpus, sanitizer, certified Linux x86-64, full-size
qualification, and release qualification remain open.
