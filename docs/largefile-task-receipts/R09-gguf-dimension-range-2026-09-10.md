# Task receipt: GGUF dimension-range hardening

Task ID / parent milestone: `R09` / `CL_TYPE_AI_MODEL`

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`

Canonical source and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- current generated inventory SHA-256:
  `318655ffc4e1b388747b3d6917abbbba82141340a1e1b79fd6595eb431580026`

Observed boundary gap: the GGUF validator read tensor dimensions as unsigned
values and could therefore admit a value above `INT64_MAX`. The reference
GGML reader stores dimensions in signed `int64_t` fields and rejects negative
results, so the high-bit range must be fail-visible even when another
dimension makes the total tensor size zero.

Implemented slice: reject dimensions above the signed GGML range before
zero-element product handling. The existing checked product, rank, tensor
type, block-shape, alignment, offset, and input-range rules remain active.

Focused regression: `test_ai_model_gguf_dimension_exceeds_ggml_range_is_fail_visible`
uses a high-bit dimension and requires `CL_EPARSE`, a cleared verdict, and a
non-cacheable fmap. It is registered in `tc_required_unsupported` and covered
by the source guard.

Verification:

- Full Python tools suite — 145 tests passed, 2 expected Linux skips.
- Inventory refresh — passed; generated inventory hash recorded above.
- Snapshot generation and freshness check — passed.
- `sh tools/largefile_source_guards.sh` — passed; 597 capability entries and
  all source/evidence subchecks passed.
- Linked current-source C execution — unavailable because this host lacks the
  required CMake/build environment; no runtime claim is made.

The signed dimension behavior was checked against the authoritative GGML
reader: <https://github.com/ggml-org/ggml/blob/master/src/gguf.cpp>.

State: `development-verified` source/control slice; complete GGUF semantics,
production model corpus, sanitizer, certified Linux x86-64, full-size
qualification, and release qualification remain open.
