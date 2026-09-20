# Task receipt: R06 materialized oversized OneNote container — 2026-09-19

Task ID / parent milestone: `R06` / `R00`

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`

## Scope

Exercise the vendored OneNote parser against a real attachment-bearing corpus
that is physically materialized as a file larger than the former 256 MiB
whole-input boundary. This is a development boundary check; it is not the
roadmap's late-child, full 32-GiB, certified Linux x86-64, or ClamAV
production-linked qualification case.

## Fixture and provenance

- Source corpus: the existing repository fixture
  `unit_tests/input/clamav_hdb_scanfiles/clam.exe.webapp-export.one.xor`.
- The repository's existing `unit_tests/input/xor_testfile.py` decrypted the
  corpus into a fresh `/private/tmp` directory; no repository fixture was
  changed and no software or dependency was installed.
- A second fresh file was written with the decrypted corpus followed by zero
  bytes to exactly `268,435,457` bytes (`256 MiB + 1`). The tail was fully
  allocated rather than sparse: `stat` reported `524,296` blocks.
- The current checkout was branch `largefile-roadmap-qualification` at commit
  `de6fb02653f9c30954614e4a4ef0ea7f91617cea`, with no pre-existing dirty
  changes before this receipt was added.

## Verification

- `cargo run --offline --bin onenote-parse` parsed the original 52,297-byte
  file successfully.
- The same parser parsed the fully allocated 256 MiB + 1-byte file
  successfully. Its debug model contained exactly one `EmbeddedFile` with
  filename `clam.exe`; after normalizing only the section filename, the
  original and oversized parser outputs were byte-for-byte identical.
- The current parser suite, run with a temporary Cargo target directory and
  `--offline`, passed 85 unit tests, 6 integration tests, and 1 ignored
  doctest. This includes the logical above-former-cap and short-read reader
  cases.

## Qualification boundary

This proves that a physically oversized, file-backed modern OneNote container
with an embedded child can be parsed without the old whole-input rejection.
The embedded child remains in the original small corpus prefix; this does not
prove a child whose own serialized offset is beyond 256 MiB, nor does it
replace the existing production-linked reader callback test, sanitizer run,
full-size qualification, Sonic1 execution, service/CVD, fanotify, or final
release evidence. No capability status was promoted and the release gate
remains blocked.

State: `development-verified`; physical oversized-container parse passed;
late-child and certified R06 completion remain pending.
