# Task receipt: R09 required-unsupported behavior

Task ID / parent milestone: `R09` / `R00`

Scope: make the required unsupported parser and matcher paths explicit, fail
closed, and observable without allowing an ignored classifier result to hide a
generic raw signature. This is a development-verification slice; it does not
promote release readiness or replace certified Linux x86-64 evidence.

Changes made:

- `scanraw()` routes `CL_TYPE_IGNORED` through the generic matcher target so an
  ignored classifier result cannot suppress the outer raw virus pass.
- AC ignored-type returns are limited to recognition-only scans; mixed virus
  and file-type scans continue to evaluate generic malware signatures.
- The generic UnRAR backend error maps to `CL_EPARSE`, preserving a
  fail-visible result for malformed or incomplete RAR/RARSFX inspection.
- The RAR timeout regression hook expires the same monotonic deadline used by
  production scans.
- Added a focused Check test case for the required unsupported group and
  corrected the ignored-type raw-matching fixture.
- The R04 record verifier now exposes `R09_REQUIRED_CAPABILITIES` and a
  `--require-r09` gate, requiring both reviewed case rows for all seven
  focused capabilities in one invocation. The schema regression exercises a
  complete 14-record binding and proves removal of one case fails closed.

Focused commands and results:

- Disposable ARM64 development build of `check_clamav`, followed by
  `CK_FORK=no CK_RUN_SUITE=cl_suite CK_RUN_CASE=required_unsupported` —
  `100%: Checks: 5, Failures: 0, Errors: 0`.
- Documented static ARM64 test shape (`ENABLE_STATIC_LIB=ON`,
  `ENABLE_SHARED_LIB=OFF`, `ENABLE_UNRAR=ON`) built `check_clamav`,
  `clamscan`, `libclamunrar_static`, and `libclamunrar_iface_static`.
- The backend-enabled static test binary followed by
  `CK_FORK=no CK_RUN_SUITE=cl_suite CK_RUN_CASE=rar` —
  `100%: Checks: 11, Failures: 0, Errors: 0`.
- The backend-enabled static `clamscan` reported its version successfully and
  reached the materialized repository `clam-v3.rar` fixture. That fixture
  returned an explicit `Can't parse data ERROR` / exit code 2 after an
  incomplete nested payload, so no clean verdict was fabricated.
- `sh tools/largefile_source_guards.sh` — passed; 597 capability entries and
  all static roadmap guards passed.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` — passed for
  597 capabilities.
- `python3 -B tools/largefile_acceptance_cases.py --check-records` — schema
  passed with 0 records, so no runtime qualification claim was made.
- `python3 -B tools/largefile_acceptance_cases_test.py` — exit 0, including
  the 14-record R09 binding gate and missing-case rejection.
- `git diff --check` — passed.

Behavior covered by the focused group:

- RAR without a backend is explicit `CL_EPARSE`/incomplete.
- Ignored parser input is explicit `CL_EPARSE`/incomplete.
- Ignored classification still permits a matching generic raw signature to
  return `CL_VIRUS`.
- Python-compiled and AI-model parser inputs are explicit `CL_EPARSE`/
  incomplete.

Follow-on real recognized-type policy probe:

- The current-source ARM64 `clamscan` was run in disposable Docker against
  three real temporary inputs and a valid clean NDB database: a Python
  bytecode header, a GGUF AI-model header, and an ID3 MP3 classified as an
  ignored type. All three returned CLI exit 2 and the exact structured
  `UNSUPPORTED`/`CL_EPARSE` result with zero verdict and zero temporary bytes.
- The structured reports bind `CL_TYPE_PYTHON_COMPILED` to
  `Python compiled bytecode parser is unsupported`, `CL_TYPE_AI_MODEL` to
  `AI model parser is unsupported`, and `CL_TYPE_IGNORED` to
  `recognized ignored file type parser is unsupported`. Each report has
  `skipped_operations=1`, proving the parserless result was not presented as
  clean coverage.
- Evidence directory:
  `/var/folders/y0/gkrfmky90fldtnxzr_s84kfw0000gr/T/clamav-r09-recognized-runtime.o09jx062`.
  Source-manifest SHA-256 is
  `d9f7d88e21581ab56b9ce9be648a2ece13781c6545ae7ffbdf05601381aacf06`,
  scanner SHA-256 is
  `7d91e17a36d7a28de57f0c3c196c62f71515dbb4090ee865c2e680534b6e7681`, and
  CMakeCache SHA-256 is
  `e2a9a9c78ab10e1058614aec90269f6c4e4a0c890f30b07edc4834ad5d918fd7`.
  The input hashes are Python `edc0ec6aef78fdabf48ff3a93527f14ea6b429bca9a7f49b193a98567fc2758c`,
  GGUF `3adfbc3a3fd82830d23e4ea2bd10527d57f6ebc11f22af2dec937caa45c87444`,
  ignored MP3 `88dd8c025aaebeb8eff0ac05b17417292e8e180b09bb1a0d8e348b0c7d843e41`,
  and clean database `c19dcf071b3e51ca13f62b3e3514f049da4c6d0ff61b4442b384347604fc30a3`.
- Report hashes are Python
  `64f0ae3884bed2a1012377999d6a76d4e3888a21528ad061c5d880da532b3b35`,
  GGUF `2d2c44e68a458f2a87216eb6e9f365851def4229dc1b80023634dafda546f7d6`,
  and ignored MP3
  `79a088aeb7da91d55d15221a0f80b2cbd9c4560a9c43e1b4e88edc9547ff6330`.
- This strengthens the development policy evidence for the three recognized
  rows. It does not implement a model or Python parser, and the rows remain
  pending until the roadmap's required implementation/scope decision and
  certified evidence are complete.

Follow-on real RAR backend probe:

- The current-source ARM64 `clamscan` at
  `/private/tmp/clamav-largefile-static-build/clamscan/clamscan` was run in
  the existing disposable `rust:1.97-bookworm` container with the repository
  CVD verification fixture and the build-tree `clamav.hdb` database.
- Both existing XOR-decoded repository fixtures were scanned through the
  production CLI and backend: `clam-v2.rar` returned the exact
  `ClamAV-Test-File.UNOFFICIAL FOUND` result with exit 1, and `clam-v3.rar`
  returned the same result with exit 1. The container wrapper exited 0 after
  recording both per-file results.
- The probe binds scanner SHA-256
  `7d91e17a36d7a28de57f0c3c196c62f71515dbb4090ee865c2e680534b6e7681`, source
  manifest SHA-256
  `0b186975cd257a4f29d7939c839eb099bdad12e7aee3ae00b7f583f9297d6239`,
  CMakeCache SHA-256
  `e2a9a9c78ab10e1058614aec90269f6c4e4a0c890f30b07edc4834ad5d918fd7`,
  database SHA-256
  `e9649d9d3416df7802567063f88d8ff181795ed4e2bab827134c1707375df38c`,
  `clam-v2.rar` SHA-256
  `db8de765a932a60fa5acf2321e07f4ed2c336e6a78474cf8228e730577bc3a75`,
  and `clam-v3.rar` SHA-256
  `9ce61f3a6a692618f4969af44fc70867eafca86b27a9cd10ea801262635d3e87`.
- This is stronger than the injected UnRAR callback tests: it proves the
  backend-enabled production binary loads the database, classifies real RAR
  input, extracts/scans nested content, and preserves the detection result.
  It does not close RARSFX-specific coverage, current-source sanitizer or
  certified x86-64 evidence, or the full-size acceptance requirements.
- `CK_FORK=no CK_RUN_SUITE=cl_suite CK_RUN_CASE=required_unsupported`
  against the current-source ARM64 `check_clamav` in the same disposable
  environment passed `100%: Checks: 5, Failures: 0, Errors: 0`. The run used
  only the pre-existing temporary JSON-C and Check runtime libraries; no
  dependency was installed.
- A temporary neutral-prefix wrapper around `clam-v3.rar` was also scanned to
  exercise the RARSFX path. The diagnostic trace classified the embedded RAR
  signature as `RAR-SFX` at offset 128, opened it through the backend, extracted
  `clam.exe`, and the reliable non-debug run returned
  `ClamAV-Test-File.UNOFFICIAL FOUND` with `scanner_exit=1`. The temporary
  wrapper SHA-256 was
  `4a729cbc63fa073d30362319c38f85ff7d4ccd7c64864d0b3e9e261c87eb2f70`.
  This is development evidence for RARSFX dispatch only; it does not replace
  the required certified and full-size records.
- The same RARSFX run wrote `/private/tmp/clamav-rarsfx-report.iP7KlB/rarsfx.jsonl`:
  `DETECTION_TERMINATED`, `root_size=492`, `files_scanned=3`,
  `max_recursion_depth=2`, `last_alert=ClamAV-Test-File.UNOFFICIAL`, and
  `temporary_bytes=908`. The structured report SHA-256 is
  `e11e250527b1b633da80899f1e13f7797f60e2eb445511d379ebfa85a898100c`.

The fuzzy-image rows now have an explicit Rust FFI admission boundary and
focused Rust tests for null pointers, output-size/slice-size limits, valid
hashing, malformed images, and exact hashmap lookup. The C path retains
contiguous-residency admission, fail-visible oversize/read errors, and the
resource-limit regression. The seven formerly required-unsupported rows are
now `pending` in the capability manifest, not excluded; release qualification
remains blocked. Standalone Rust unit execution was attempted but the
disposable ARM64 image lacks OpenSSL development headers for the full crate
test profile; the production CMake Rust target still compiles successfully.
Certified Linux x86-64 Release/sanitizer, full-size, daemon, library, and
ingress evidence remain unavailable.

The image-fuzzy matcher now honors the declared nonzero hamming-distance field
using the differing-bit count across the eight-byte hashes. Distances above
the representable 64-bit hash width and signatures with extra `#` fields are
rejected before insertion. Focused source regressions cover one-bit acceptance,
two-bit rejection at distance one, over-width distance rejection, and extra
field rejection. A direct offline Rust test invocation remains blocked by the
missing cached `clam-sigutil` Git dependency, even though the production Rust
target itself rebuilt successfully. No host software was installed; the
current disposable rebuild populated its separate Cargo cache with the
locked Rust dependencies needed to rebuild the archive.

The existing production CLI regression was updated to exercise that contract
instead of asserting the former unsupported behavior. Against a freshly
relinked current-source ARM64 `clamscan` (Rust archive rebuilt from this
checkout), `python3 -m unittest -v clamscan.fuzzy_img_hash_test` passed all
4/4 cases: malformed algorithm and hash inputs remain rejected, the existing
exact-match/feature-disable cases pass, a one-bit-near signature is detected,
and a two-bit-near signature with declared distance one is not reported. The
scanner SHA-256 is
`bf640f23c01f6c85fdd426abae7749e96dc05bd7101d68bf1c6a2ac4293dd047`; the
pre-receipt-update dirty source-manifest SHA-256 for this focused run was
`a6daaad26a5337d77b6f1288c748c4d85794c2856a21d54eaccf48f55569042b`.
This receipt update is intentionally not treated as a new executable build
identity.

The full CMake target rebuild remains environment-limited: the cached ARM64
container lacks the architecture-specific OpenSSL development header and
JSON-C/cURL linker symlinks. The focused binary was therefore rebuilt by
relinking the existing C objects/static libraries with the freshly compiled
Rust archive and existing runtime libraries; this is development evidence,
not a coherent release build or qualification record.

Follow-on current-source production CLI revalidation:

- The CLI was relinked against the current `libclamav_static.a`; the version
  smoke returned exit 0 and `ClamAV 1.5.3-largefile-devel`.
- With the required empty `/usr/local/etc/certs` directory created inside the
  disposable ARM64 container, `VERSION=1.5.3-largefile-devel SOURCE=/src
  BUILD=/tmp/clamav-largefile-static-build TMP=/tmp CLAMSCAN=... python3 -m
  unittest -v clamscan.fuzzy_img_hash_test` passed **4/4**. The real
  `/src/logo.png` fixture produced the expected exact-match alerts, disabled
  fuzzy-image and disabled image scans returned clean, malformed signatures
  returned exit 2, and the one-bit hamming-distance case detected while the
  two-bit case did not.
- Current retained hashes for this relink are: `clamscan`
  `e00719e21aad70e1e67c79dab7729a6da5bd125ef06a6519de31bfa43b44d8fd`,
  `libclamav_static.a`
  `e3f9034af8a8c571f5bcd18e128abd1f3bbccd91a47986746e704654adcdfaca`, and
  `CMakeCache.txt`
  `5ff75d1e193f0cc883ee9595833f608fdc43e21e8e1d7cfeb56d015f63b2897c`.
- This strengthens development evidence for the fuzzy-image required rows;
  the rows remain pending because the roadmap still requires certified
  Linux x86-64, sanitizer, full-size, and capability-bound evidence.

State: `development-verified`; release readiness remains blocked.

GGUF structural-admission refinement (2026-09-10 UTC):

- The recognized GGUF AI-model path now has a bounded structural parser for
  versions 1--3. It checks metadata scalar/array types, caps nested metadata
  arrays by parser depth and remaining input, honors the optional
  `general.alignment` value, validates tensor descriptor boundaries, and
  checks aligned tensor-data offsets without copying model payloads.
- The existing non-GGUF model case remains explicit unsupported, and a valid
  minimal GGUF header is now covered by a required-unsupported development
  group regression. Malformed/truncated GGUF remains incomplete and
  non-cacheable; the mandatory outer raw matcher is unchanged.
- This does not claim complete tensor shape/type validation, ONNX or
  TensorFlow Lite parser coverage, full model corpus evidence, sanitizer or
  certified x86-64 execution, or release qualification. No software, remote
  execution, Docker, usage reset, commit, push, or GitHub workflow action was
  used.

GGUF alignment refinement (2026-09-10 UTC):

- `general.alignment` now requires a power-of-two value at least 8 bytes and
  no larger than the bounded parser ceiling; the required-group regression
  rejects an otherwise well-formed metadata entry with alignment 4.
- This follows the GGUF format requirement that tensor-data alignment be an
  8-byte multiple and does not expand the release claim. Full tensor encoding
  coverage and certified evidence remain open.

The required group also covers a raw-detection control appended after a valid
GGUF header. It confirms structural admission does not suppress the outer raw
matcher or its exact alert result.

GGUF duplicate-alignment refinement (2026-09-10 UTC):

- The bounded GGUF path now rejects a repeated `general.alignment` metadata
  key instead of allowing a later value to silently replace the earlier
  alignment choice. This matches the upstream GGUF reader's duplicate-key
  rejection behavior and keeps the special alignment field unambiguous.
- The required-unsupported development group covers two conflicting valid
  alignment entries and confirms the result is `CL_EPARSE`, non-cacheable, and
  clean of a stale alert. Certified parser, full model corpus, sanitizer, and
  x86-64 evidence remain unavailable. No software, remote execution, Docker,
  usage reset, commit, push, or GitHub workflow action was used.

GGUF tensor-layout refinement (2026-09-10 UTC):

- GGUF tensor offsets are relative to the tensor-data blob. The bounded path
  now requires each recognized tensor to start at the preceding tensor's
  alignment-padded end, rejecting overlap and unexplained holes instead of
  validating only the furthest end position.
- A required-unsupported development regression with two F32 descriptors at
  the same relative offset now returns `CL_EPARSE`, marks the input
  non-cacheable, and clears stale alerts. This follows the reference GGUF
  reader's contiguous-offset check; certified parser, full model corpus,
  sanitizer, and x86-64 evidence remain unavailable.

GGUF tensor-rank refinement (2026-09-10 UTC):

- Tensor descriptors now reject rank values above the four-dimensional
  `GGML_MAX_DIMS` boundary before reading the dimension vector. A complete
  five-dimension F32 descriptor is covered by a required-unsupported
  development regression and returns `CL_EPARSE` with non-cacheable state.
- This follows the reference GGML tensor-rank check; tensor-type/corpus
  coverage, certified parser, sanitizer, and x86-64 evidence remain open.

GGUF metadata-key refinement (2026-09-10 UTC):

- GGUF metadata entries now reject a zero-length key before consuming its
  value. This matches the reference reader's empty-key boundary and prevents
  an unnamed value from being admitted as structurally valid.
- A required-unsupported development regression covers a complete empty-key
  entry and returns `CL_EPARSE` with non-cacheable state. Tensor-type/corpus
  coverage, certified parser, sanitizer, and x86-64 evidence remain open.

GGUF quantized-tensor geometry refinement (2026-09-10 UTC):

- The bounded parser now validates encoded block geometry for established
  GGML tensor types, including Q4_0/Q4_1, Q5/Q8, K-quant, IQ, integer, and
  BF16 types. Quantized element counts must be exact multiples of their
  format block size, and byte-size multiplication remains checked before the
  relative contiguous-layout validation.
- A complete one-block Q4_0 descriptor is admitted without reading or copying
  model payload semantics; a 31-element Q4_0 descriptor is fail-visible. This
  is structural development evidence only; full corpus, decoder semantics,
  sanitizer, certified parser, and x86-64 qualification remain open.

GGUF current-quantized-type refinement (2026-09-10 UTC):

- The same bounded geometry table now covers the current GGML tensor IDs
  `TQ1_0`, `TQ2_0`, `MXFP4`, `NVFP4`, `Q1_0`, and `Q2_0`, using the
  published block element and byte sizes. A table-driven required-group
  regression admits one aligned block for each type and verifies clean,
  cacheable structural completion.
- This expands format admission only; model payload decoding, ONNX/TFLite
  coverage, current-source linked execution, sanitizer, certified x86-64, and
  release qualification remain open. No dependency was installed and no
  remote, Docker, usage-reset, commit, push, or GitHub workflow action was
  used.

Bounded Python-bytecode parser refinement (2026-09-10 UTC):

- Recognized Python compiled inputs now use a non-executing marshal structural
  walker. It bounds recursion, object count, signed lengths, reference indices,
  and every fmap offset, and accepts the legacy and modern code-object field
  layouts without materializing marshal payloads.
- The scan dispatcher merges the parser result with the existing raw matcher:
  a valid bounded code object can complete cleanly, a raw malware match keeps
  precedence, and truncated or unsupported marshal data returns `CL_EPARSE`
  with a non-cacheable map.
- Required-group regressions cover truncated input and minimal legacy and
  modern code objects, plus raw-detection precedence through a malformed
  recognized input. The local 145-test tools suite (2 expected skips),
  snapshot check, `git diff --check`, and full source guards passed. This is
  development-level structural evidence only; independent format-8 fixtures,
  linked current-source execution, sanitizer, certified x86-64, full-size
  materialization, and capability qualification remain open. No dependency,
  remote execution, Docker, usage reset, commit, push, or GitHub workflow
  action was used.

GGUF quantized row-shape refinement (2026-09-11 UTC):

- The bounded GGUF geometry checker now validates the innermost row dimension
  against the quantization block size, not only the product of all tensor
  dimensions. This rejects a shape such as `16x2` for Q4_0, whose total of 32
  elements could otherwise pass while each row remains incomplete.
- Added `test_ai_model_gguf_quantized_row_shape_misalignment_is_fail_visible`
  to the required-unsupported development group. The source guard and
  repository control sweep pass; a fresh linked C execution is not claimed
  because the available ARM64 Docker image lacks the test/development
  libraries and no package installation was authorized. Full tensor semantics,
  sanitizer, certified x86-64, production-CVD/service, and release
  qualification remain open.

GGUF tensor-name boundary refinement (2026-09-11 UTC):

- The bounded GGUF parser now rejects tensor names whose encoded byte length
  reaches the reference `GGML_MAX_NAME` limit of 64, before skipping the name
  payload. This prevents an oversized name from being admitted as part of an
  otherwise valid descriptor.
- Added `test_ai_model_gguf_tensor_name_limit_is_fail_visible` with a complete
  descriptor and payload after the boundary. The source/control sweep passes;
  linked C execution remains unclaimed because the available ARM64 Docker
  image lacks the test/development libraries and no package installation was
  authorized. Full model semantics, sanitizer, certified x86-64,
  production-CVD/service, and release qualification remain open.

TFLite metadata-buffer vector coverage hardening (2026-09-11 UTC):

- The bounded FlatBuffer walk now explicitly documents and tests that
  `Model.metadata_buffer` is its schema-defined vector of scalar `int32`
  buffer indices. Those values are not FlatBuffer table offsets and remain out
  of the table walker.
- Added `test_ai_model_tflite_metadata_buffer_is_structurally_supported` with
  two structurally valid buffer tables and a metadata-buffer index of one.
  Source/evidence guards remain the available verification; linked C execution,
  certified Linux x86-64, full-size evidence, and release qualification remain
  open.

TFLite metadata-buffer index-binding hardening (2026-09-11 UTC):

- The bounded FlatBuffer walk now validates every signed `metadata_buffer`
  entry against the declared `buffers` vector count. Negative values and
  out-of-range indices are rejected as incomplete before they can be treated
  as valid model metadata references.
- Added `test_ai_model_tflite_metadata_buffer_index_is_fail_visible`, which
  changes the valid fixture's index from one to two while its two buffer
  tables remain present, requiring `CL_EPARSE`, a cleared verdict, and cache
  taint. The source/control sweep remains green; linked current-source C
  execution, certified Linux x86-64, full-size evidence, and release
  qualification remain open.

TFLite signed metadata-buffer index hardening (2026-09-11 UTC):

- The bounded FlatBuffer walk now decodes `Model.metadata_buffer` entries as
  schema-defined signed `int32` values before comparing them with the root
  `buffers` count. Negative indices are rejected explicitly rather than
  relying on an unsigned comparison to classify them as out of range.
- Added `test_ai_model_tflite_metadata_buffer_negative_index_is_fail_visible`,
  which uses an otherwise valid two-buffer model with an `int32` value of -1
  and requires `CL_EPARSE`, a cleared verdict, and cache taint. Source/evidence
  guards remain green, and the linked ARM64 current-source required-unsupported
  group passed 38/38. Certified Linux x86-64, full-size evidence, and release
  qualification remain open.

Current-source C compile correction (2026-09-11 UTC):

- The disposable current-source build found that the TFLite field helper's
  local vtable offset reused the `field_offset` output-parameter name. The
  local was renamed to `vtable_field_offset`; this is a compile-only naming
  correction and does not change the validator's behavior or admission policy.
- The ARM64 build completed incrementally from the persistent temporary build
  directory, and the required-unsupported group passed 38/38. No certified or
  full-size capability promotion is made without the required external
  evidence.

Current-source AI-model test corrections (2026-09-11 UTC):

- AI-model unit fixtures now set `options.parse = ~0U`; without an explicit
  parser option, the public scan path correctly performs raw-only matching and
  cannot exercise parser admission assertions.
- GGUF validation now requires the actual final tensor payload to fit in the
  input while retaining alignment padding only between tensors. This accepts a
  valid scalar tensor whose final four-byte payload ends at EOF.
- Python and GGUF raw-matching fixtures now place their signature offsets at
  the marker bytes (8 and 32 respectively). Their assertions use the public
  `cl_scanmap_ex()` contract: parser status and `verdict_out` are checked
  independently. The linked ARM64 required-unsupported group passed 38/38;
certified x86-64, full-size evidence, and release qualification remain open.

Python marshal backing-read status hardening (2026-09-11 UTC):

- The bounded Python reader now distinguishes an in-range fmap backing-read
  failure (`CL_EREAD`, sticky incomplete, non-cacheable) from a short or
  malformed marshal range (`CL_EPARSE`).
- Added and registered `test_python_compiled_parser_preserves_fmap_read_failure`
  in the ordinary and required-unsupported groups. Host tooling and source
  guards pass; no linked current-source C execution is claimed because the
  available Docker images lack JSON-C and Check development headers. Full
  Python semantics, certified x86-64, full-size, sanitizer, and release
  qualification remain open.
