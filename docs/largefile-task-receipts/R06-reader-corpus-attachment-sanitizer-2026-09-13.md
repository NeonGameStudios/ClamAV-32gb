# Task receipt: R06 OneNote corpus attachment sanitizer follow-up — 2026-09-13

Task ID / parent milestone: `R06` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`.
No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used.

Purpose: close the remaining evidence gap for the focused OneNote reader
case that detects an embedded attachment after the former 256 MiB whole-input
boundary. The test exercises the production `scan_onenote()` entrypoint with
the real decrypted `clam.exe.2010.one` attachment-bearing corpus, a bounded
fmap callback, a logical length of `256 * 1024U * 1024U + 1U`, and an isolated
`OneNote.Reader.MZ` child signature.

Environment and build:

- Existing Docker container `clamav-current-rust-build-20260911` was reused;
  no software was installed.
- The existing ARM64 `RelWithDebInfo` ASan/UBSan configuration was
  reconfigured against the current checkout with the source-manifest hash
  above, then rebuilt with `cmake --build /tmp/clamav-asan-current-20260912
  --parallel 2`.
- The rebuild completed at 100% with exit 0. The focused test executable is
  an ARM64 ELF PIE with debug information; SHA-256:
  `693452f4b76d8337803046131fd99b1e79f1d346ae0415d5b977a1b1ddbf1828`.

Verification:

- Command: `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_onenote T=1200
  ./check_clamav` from the sanitizer `unit_tests` directory.
- Result: 4/4 checks passed with zero failures and zero errors, covering
  `initial_read_failure_is_fail_visible`, `truncated_prefix_is_parse_error`,
  `reader_crosses_former_whole_input_cap`, and
  `reader_streams_corpus_attachment_above_former_cap`.
- A fallback `grep` scan of `test-stderr.log` found no
  `AddressSanitizer`, `LeakSanitizer`, `runtime error`, or
  `UndefinedBehaviorSanitizer` diagnostics.

Qualification boundary: this is current-source ARM64 Docker development
evidence only. It does not prove exact 32-GiB/materialized resources,
certified Linux x86-64 execution, production CVD or service behavior,
Sonic1 execution, all late-offset OneNote variants, or final release
qualification. No capability was promoted.

State: `development-verified`; focused current-source OneNote reader
attachment test passed under ASan/UBSan with coherent source provenance.
