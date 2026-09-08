# Task receipt: R03 disposable runtime revalidation

Task ID / parent milestone: `R03` / `R10`

Scope: revalidate the existing ARM64 development binaries with the
already-present temporary runtime libraries, using the current source tree
for fixtures and test code. This is development evidence only; it is not the
certified Linux x86-64 Release/sanitizer candidate required by the roadmap.

Starting source: branch `largefile-roadmap-qualification`, working tree dirty
with the existing large-file changes. The latest fanotify source edits were
syntax-checked separately and were not relinked into this pre-existing build.

Prerequisites and runtime identities:

- Existing build: `/private/tmp/clamav-largefile-static-build`.
- Existing disposable image: `clamav-largefile-local-toolchain2:latest`.
- Existing JSON-C runtime SHA-256:
  `ea62d713f572e016d493478bc3c80cb4d87bdde775c862d2972c72446b4c4f0f`.
- Existing Subunit runtime SHA-256:
  `d65621fe7f51a577024f1bf9df8ce5b67b41f1ffcc4b517940e93acf9fbc1ff8`.
- Existing `clamscan` SHA-256:
  `7d91e17a36d7a28de57f0c3c196c62f71515dbb4090ee865c2e680534b6e7681`.
- Existing `clamd` SHA-256:
  `408785d6d2e3112149749ca666e12b7832664c162ca006d01c2df0a60355708a`.
- Existing `clamdscan` SHA-256:
  `a1980dc80f0710fd825a3c01cdc24485d024d43f3140a55af218ac281d322c0e`.

Observed environment issue: the CTest-generated daemon tests place their
relative Unix socket under the host-mounted build directory, where this
Docker backend rejects socket binding with `Operation not supported`. The
same tests were run directly with `TMP=/tmp` inside the disposable container,
leaving binaries and source paths unchanged while moving only the test temp
directory to a native container filesystem.

Verification:

- `clamscan` CTest target — passed.
- Direct `clamd_test.py` with `TMP=/tmp` — 15 tests passed in 27.051 seconds,
  including PING/PONG, reload, scan, report, quarantine, limits, and OneNote
  configuration controls.
- `libclamav` CTest target with current source mounted — 2,666 checks passed
  in 81.63 seconds.
- Large-file clamscan admission and FILDESREPORT protocol controls — passed.
- `freshclam` and `sigtool` CTest targets — passed.
- CTest wrapper for `clamd` — not promoted because its host-mounted socket
  path is unsupported by this container backend; the direct daemon run is the
  usable development result.

No software was installed, no MCP/SSH runner was used, and no usage reset was
requested or consumed. No full-size or certified x86-64 evidence was
produced. R03 remains open for the authorized runner, coherent current-source
Release/sanitizer builds, and retained provenance artifacts.

On-access configuration blocker: an isolated CMake configure with
`ENABLE_CLAMONACC=ON`, tests disabled, the existing temporary JSON-C library,
and the existing disposable toolchain reached feature detection but stopped
at `find_package(CURL)`: the image has neither `CURL_INCLUDE_DIR` nor
`CURL_LIBRARY` for development. The prior attempt with tests enabled stopped
earlier at missing Libcheck development files. The next action is an
authorized Linux build environment with the required installed development
dependencies; no header or dependency was stubbed into the application build.

State: `development-verified`
