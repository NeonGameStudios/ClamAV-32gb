# Task receipt: R09 real UnRAR backend probe (superseded)

Correction recorded 2026-09-13: the original `_minimal_rar` test builder used
an explicit `binascii.crc32()` seed that did not match UnRAR's raw-initialized
header CRC convention. Its historical artifact hashes and “valid archive”
description below are therefore not admissible as complete-archive evidence.
The builder is corrected and the valid rerun is recorded in
`R09-real-unrar-backend-release-2026-09-13.md`.

Task ID / parent milestone: `R09` / `R00`

Scope: exercise the actual production-linked UnRAR module through the current
source ARM64 Release `clamscan`, using a small valid RAR4 archive and a
neutral-prefix RAR-SFX wrapper. This is development evidence only; it does
not promote either capability to certified release status.

## Build identity

- Container: `clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.
- Build directory: `/tmp/clamav-release-current-20260912`.
- Build shape: Release, shared and static libraries, applications, tests,
  milter, on-access, and `ENABLE_UNRAR=ON`.
- Source manifest SHA-256:
  `638480cc7d781d77029c9022aecd882c62b7cfd5d9737eb43c3d37dacaf7b0db`.
- Scanner SHA-256:
  `b085b063e507da218d1ea5ed3436a91a7572bcf11462c4ec9ff3daa17eaa99c6`.
- CMakeCache SHA-256:
  `cf3622e210201cf7f5ce1ca92167de34585eb58353441f03d4ecbcf50cb5b3b7`.
- The runtime loaded the build-tree
  `libclamunrar_iface.so.14.0.0` through `LD_LIBRARY_PATH`; no software was
  installed.

## Inputs and database

- The historical RAR4 input was intended to be a stored archive containing `child.bin` with the
  ten-byte payload `RarPayload`. It is 78 bytes and has SHA-256
  `b2ba8d8371ca9e445442e8372a5f49c743b510e85840231f87206e536c58cd14`.
- The RAR-SFX input prepends a 23-byte neutral stub to the same archive. It is
  101 bytes and has SHA-256
  `a69494322e9691a49cebeb4fab9f8463a8954aeb3e7bbb0195fb3f8522ad6ac3`.
- The disposable SHA-256 HDB signature database is 77 bytes with SHA-256
  `786ec076426a0887453272110caeeeb44af7a913dbd797cdb47314cf45948188`.
  Its child payload hash is
  `d7696ea690748f06312f557aeab17288e1992594cf7fae6856fcb985952e9b26`.
- The repository signing fixture directory was supplied through
  `CVD_CERTS_DIR` so database initialization was independently verifiable.

## Results

- RAR4 scan: `RarChild.UNOFFICIAL FOUND`, `scanner exit 1`, but the malformed
  historical header CRC caused an archive-incomplete warning.
- RAR-SFX scan: `RarChild.UNOFFICIAL FOUND`, `scanner exit 1`, with the same
  historical fixture defect.
- Debug evidence for the RAR4 path included recognition as RAR, successful
  `unrar_open`, extraction of `child.bin`, `Extraction complete`, and nested
  scanning of the extracted text member before the detection.
- Debug evidence for the RAR-SFX path classified the embedded signature as
  `RAR-SFX` at offset 23, created a `CL_TYPE_RARSFX` nested object, opened it
  through UnRAR, extracted `child.bin`, and detected the nested member.
- The repeatable `unit_tests/clamscan/rar_backend_test.py` regression now
  generates the same archive and signature shape itself. After correcting
  CMake's fallback from a vacuous `unittest clamscan` invocation to explicit
  unittest discovery, the current-source CTest target exercised 125 cases and
  passed with one platform skip.

These historical results are retained for traceability only and do not close
the complete-archive evidence gap. The corrected valid rerun closes the
specific development-evidence gap for loading the optional backend and
reaching real RAR/RARSFX extraction through the CLI. The
`parser:CL_TYPE_RAR` and `parser:CL_TYPE_RARSFX` manifest rows remain
`pending`: the input is intentionally tiny and synthetic, and the roadmap
still requires complete corpus, full-size, sanitizer, certified Linux
x86-64, production-CVD/service, Sonic1, and final release evidence.
