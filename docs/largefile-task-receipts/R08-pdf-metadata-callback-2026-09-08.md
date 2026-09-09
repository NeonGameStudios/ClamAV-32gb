# Task receipt: PDF metadata callback context admission

Task ID / parent milestone: `R08` / `R00` five-issue follow-up

Exact capability kind:id list: `library:pdf-metadata-callback-context`

Starting commit and working-tree/source manifest identity: `41cde8160286813f0f98e109c1450e40ff4117fb`; the checkout was already dirty and its existing changes were preserved.

Prerequisites verified: the roadmap, current snapshot, capability manifest, and source guards were reviewed. The highest-risk PDF metadata callbacks were inspected from the canonical checkout.

Observed failing case and expected behavior: `Pages_cb` dereferenced `pdf->ctx` while checking `this_layer_metadata_json` before validating that the scan context existed. The eight string-metadata callbacks likewise evaluated `SCAN_COLLECT_METADATA` after copying a possibly-null context, and could dereference it. A compatibility caller that reaches any metadata callback through ordinary PDF dictionary parsing without a scan context must return safely with metadata collection disabled.

Changes made:

- `Author_cb`, `Creator_cb`, `ModificationDate_cb`, `CreationDate_cb`, `Producer_cb`, `Title_cb`, `Keywords_cb`, and `Subject_cb` now validate the owning context, options, metadata JSON, and object before using the shared collection policy.
- `Pages_cb` now validates the same state and computes `objstart` only after those checks.
- Added `test_pdf_metadata_callbacks_accept_null_context`, which reaches the callback family through `pdf_parseobj()` with metadata dictionary keys and no scan context.
- Added source guards for the null-safe callback conditions and regression registration.
- Refreshed the generated inventory entries for the callback guard changes and the regression's tracked arithmetic sites.

Follow-on encryption admission correction:

- `pdf_handle_enc()` now passes the validated crypt-filter dictionary length
  (`cf_len`) to each `parse_enc_method_ctx()` call. The previous path passed
  `n` before that variable was initialized on the crypt-filter branch.
- `pdf_getdict()` now restores the opening `<<` after `pdf_nextobject()` has
  skipped the delimiters and intervening whitespace. This keeps ordinary
  `/CF << /StdCF ... >>` formatting on the dictionary path instead of
  treating `/StdCF` as the value pointer.
- Added `test_pdf_encryption_uses_crypt_filter_length`, which exercises a
  version-4 AES crypt-filter dictionary and asserts that stream, string, and
  embedded-file methods all resolve to `ENC_AESV2`.
- Added source guards for the validated length, whitespace-aware dictionary
  admission, and regression registration.

Development verification:

- `sh tools/largefile_source_guards.sh` — exit 0; 597 capability rows and all source/evidence controls passed.
- `git diff --check` — exit 0.
- After rebuilding the affected static library and unit-test binary from the
  current checkout inside the disposable ARM64 Docker image, the focused PDF
  test case passed **24 checks, 0 failures, 0 errors; exit 0**. This is
  development evidence only; it is not certified Linux x86-64 evidence.
- The initial callback-only run was not rebuilt against the changed library;
  that historical result is superseded by the current-source 24/24 run.
- A broader current-source `check_clamav` run was attempted in the same
  disposable environment with `CK_FORK=no CK_DEFAULT_TIMEOUT=300`; the
  container terminated it with exit **137** after reaching the test harness.
  The container reports approximately 2.4 GiB of memory, far below the
  roadmap admission requirement, and no assertion or sanitizer diagnostic
  was emitted. This is retained as a resource-limited non-result, not as a
  source regression.

Full-size/certified evidence: not run; this is a small callback-safety regression, not certified Linux x86-64 or release evidence.

Remaining failures / next slice: the certified runner and capability-specific release evidence remain unavailable. The other four R00 issues retain their existing dispositions; no capability status was promoted.

State: `development-verified`
