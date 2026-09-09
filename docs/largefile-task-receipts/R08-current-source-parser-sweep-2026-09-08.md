# Task receipt: R08 current-source parser-family sweep

Task ID / parent milestone: `R08` / `R00`

Scope: run the remaining high-risk parser, unpacker, container, document,
compression, and executable Check groups one at a time against the current
source build. Per-group processes keep a single constrained development
container from accumulating the memory used by unrelated test families.

Evidence identity:

- Canonical source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- Test binary: `/private/tmp/clamav-largefile-tests-static/unit_tests/check_clamav`
- Current test-binary SHA-256:
  `bc1857bffc084e2a067c2b2a054cfcfb96aea0655cbe48d3db81df89563fc980`
- Build-cache `CMakeCache.txt` SHA-256:
  `df719a311170acd54eb3dfeac16a6d75210885ee40dc3d1a4b28c44fca1bb0ab`
- Platform: disposable ARM64 Linux development container

Commands used three bounded batches of the form:

```text
CK_FORK=no CK_DEFAULT_TIMEOUT=300 CK_RUN_SUITE=cl_suite
CK_RUN_CASE=<named-case> /tmp/clamav-largefile-tests-static/unit_tests/check_clamav
```

The source tree and retained fixtures were mounted read-only for the test
inputs. The container had its missing JSON-C and Check runtime libraries
installed only for the disposable run; no host software was installed.

Results:

- Rust/archive/filesystem batch: 17 named groups, 107 checks, 0 failures,
  0 errors. This included `rust_lha`, `rust_alz`, archive members, ISO/UDF,
  partition/GPT/MBR, and HWP OLE2 corpus groups.
- Executable/image/document batch: 31 named groups, 217 checks, 0 failures,
  0 errors. This included graphics, DMG, JPEG, ELF, PE, HWP3, XAR, RIFF,
  RTF, and structured-map groups.
- Mail/compression/OLE/executable batch: 44 named groups, 230 checks,
  0 failures, 0 errors. This included mail/MHTML, BinHex, bzip2, ARJ/SFX,
  AutoIt, InstallShield, EGG, MSExpand, XZ, OLE/VBA, SWF, and Mach-O.

Total: 92 bounded group runs and 554 passing checks. The HWP OLE2 map/corpus
groups were intentionally repeated as overlap between the first two batches.

This sweep found no current-source assertion or parser failure requiring a
code change. It is development evidence only: the fixtures are not the
materialized 32-GiB edges, and no certified Linux x86-64 Release/sanitizer,
production-database, resource, fanotify, or final-canary qualification was
produced.

State: `development-verified`; R08 implementation coverage is strengthened,
but capability rows remain pending until R03/R04/R12 qualification evidence
exists.
