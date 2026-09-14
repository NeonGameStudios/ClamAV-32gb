# Task receipt: R06 OneNote parser current-source offline verification

- Task ID / parent milestone: R06 reader-backed modern OneNote, parser test slice
- Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`
- Starting source identity: checksum-verified Sonic1 source archive
  `0e05b85322a35be6b107e6a70b4dcbd38701220acd63b5ab0ba8ce6846a5c321`; the
  remote disposable test source includes the repaired `tc_largefile` harness
  initialization (`unit_tests/check_clamav.c` SHA-256
  `4a81f43c0caf099034398171ec731e969801c4a69e387820dcdc1a48f855fb36`)
- Prerequisites verified: Sonic1 x86-64 Docker image
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`;
  Rust `1.97.1 (8bab26f4f 2026-07-14)`; existing offline Cargo cache
- Owned files: none; this is a verification-only slice
- Observed gap / expected behavior: exercise the reader-backed parser and
  ensure logical input above the former whole-input cap, short reads, and
  normal path parsing complete without materializing a whole input buffer
- Command and exit: named container
  `clamav-onenote-tests-current-20260912` ran
  `cargo test --offline --all-targets` from
  `/src/libclamav_rust/onenote_parser` with `CARGO_HOME=/cargo-home` and
  `CARGO_TARGET_DIR=/tmp/onenote-target`; Docker exit `0`
- Development tests passed: 72 unit tests and 5 integration tests, including
  `test_parse_section_reader_accepts_logical_input_above_former_cap` and
  `test_parse_section_reader_matches_buffer_with_short_reads`; no failures,
  ignored tests, or sanitizer diagnostics were reported
- Full-size/certified evidence: not produced; this is development parser
  evidence only and does not qualify the capability
- Remaining failures / next slice: production-linked current-source,
  Rust-address-instrumented, certified Linux x86-64, materialized-large-file,
  production-CVD/service, R04 case records, and final release evidence remain
  required
- State: development-verified

