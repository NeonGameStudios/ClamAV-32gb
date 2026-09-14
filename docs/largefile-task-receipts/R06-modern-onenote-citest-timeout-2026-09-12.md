# Task receipt: R06 modern OneNote CTest timeout correction

Task ID / parent milestone: `R06` / `R00`

Scope: preserve the OneNote reader-boundary evidence while correcting the
CTest allowance for the deterministic service-evidence regression. This does
not promote OneNote or the release candidate to qualified status.

Evidence:

- The current Release-linked Rust OneNote suite was run in the existing
  architecture-matched Docker runner with
  `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_onenote`; it passed `4/4`, including
  `test_rust_onenote_reader_streams_corpus_attachment_above_former_cap`.
- A fresh complete Release CTest run initially exposed one harness defect:
  `largefile_service_evidence_check` was terminated by its generic 60-second
  CTest allowance at `63.99` seconds after its internal verifier checks had
  completed. No service assertion failed.
- `unit_tests/CMakeLists.txt` now gives that deterministic verifier the same
  documented long-running `300`-second allowance as the other multi-minute
  large-file controls. This changes only test orchestration; production scan
  limits and evidence assertions are unchanged.
- The focused corrected test passed `1/1` in `219.53` seconds.
- The complete reconfigured Release CTest matrix passed `28/28` in
  `282.83` seconds. This included `libclamav`, all large-file controls,
  clamscan, clamd, freshclam, sigtool, Rust, and milter targets.
- The build recorded source-manifest SHA-256
  `0eb96c128b88b2f3bfa379dbdacbac84923e9dde49d6acd8912f8bc0af4bc721` with
  `1,697` entries.

This is development verification only. Certified Linux x86-64, exact 32-GiB,
sanitizer, production-CVD/Sonic1, privileged fanotify, materialized edge, and
final release qualification remain open. No software was installed, no usage
reset was used, and no commit, push, or GitHub workflow action was performed.
