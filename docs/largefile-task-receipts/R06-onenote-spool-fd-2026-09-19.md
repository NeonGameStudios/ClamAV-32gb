# R06 OneNote spool descriptor release — 2026-09-19

Task ID / parent milestone: `R06` / `R03`.

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`.

Starting source: branch `largefile-roadmap-qualification`, commit `7f3458c4`,
with the intentionally dirty working tree preserved. The remote validation
container was `clamav-current-7f3458c4` (`b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`).

Observed gap: the valid modern OneNote over-cap regression exhausted the
process file-descriptor limit because each materialized parser spool retained
its write descriptor until the parser object graph was dropped.

Changes:

- `ReaderSpool` now retains the path, length, budget and owner identity after
  materialization, but closes its writer descriptor immediately.
- Path replacement and anti-symlink ownership checks remain enforced after the
  writer is closed.
- Added a Rust unit regression proving a stream-backed blob closes its writer
  while remaining readable.
- The C regression sets the file-size and logical-scan limits explicitly and
  exercises the intended `CLI_MAX_LARGE_FILESIZE` (32 GiB) logical input.

Remote build and verification:

- CMake rebuild: exit `0`; `check_clamav` linked successfully.
- Focused command: `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_onenote T=120
  /tmp/clamav-7f3458c4-build/unit_tests/check_clamav`; exit `0`, 5 checks,
  0 failures, 0 errors.
- `ctest --test-dir /tmp/clamav-7f3458c4-build -R '^libclamav_rust$'
  --output-on-failure`; exit `0`, 1/1 passed.
- Final `check_clamav` SHA-256:
  `c63153016d97a9ca9fcd97e9b92a9768762514f1aecc451e3323fcee22fa2ae1`.
- Source hashes matched between the local candidate and remote mount for
  `reader.rs` and `fmap.c`.

Remaining failures / boundary: the linked `libclamav` CTest still reports 17
failures in the broader scan-API matrix (archive fixture and streaming-mail
cases). The focused R06 group passes; those broader failures are retained as
separate follow-up work and are not relabeled or weakened here. This receipt
does not claim certified x86-64 full-size qualification, materialized
32-GiB-edge evidence, sanitizer parity, service ingress coverage, or release
readiness.

State: `development-verified` for the scoped R06 reader/spool regression.
