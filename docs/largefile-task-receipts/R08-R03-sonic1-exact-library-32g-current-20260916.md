# R08/R03 Sonic1 current-source exact library 32-GiB edge — 2026-09-16

## Scope

Run the current-source Linux x86-64 exact 32-GiB library qualification case
after the OneNote stream-spool descriptor-retention fix. The test exercises
the public path, descriptor, and fmap scan entry points against the exact
tail marker. This is a bounded library-ingress slice; it is not the complete
R11 vertical proof and does not promote a capability.

## Provenance

- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`
- Image: `clamav-32gb:dev-current`, image ID
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Source mount: `/tmp/clamav-32gb-current-20260915` mounted at `/src`
- Source revision: Git-less content manifest
  `1fce4719f42ed92d5f0a4b8eeebb6db6268cb5981b7251894d950413cce6135f`
- Build source-manifest comparison: fresh source-manifest generation matched
  `/tmp/clamav-current-build-20260915/source-manifest.txt` with `cmp` exit 0
- CMake cache SHA-256:
  `6df8b77fe9a15394b9909f85281012678c01d6b1dd72899e83710985fdfc5e05`
- `unit_tests/check_clamav` SHA-256:
  `b33f75bfaac218a49e500eae52ce39a8dabc30a12413825dc6dd32f77f85b732`
- Build configuration: Linux x86-64, Release, large-file defaults OFF,
  `ENABLE_LARGE_FILE_QUALIFICATION_TEST=ON`, Rust toolchain `stable`, Cargo
  offline mode

## Command and result

The tracked MCP-SSH asynchronous job ran:

```text
docker exec 53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9 \
  env RUSTUP_TOOLCHAIN=stable CARGO_HOME=/tmp/clamav-cargo-home-20260915 \
  CARGO_NET_OFFLINE=true ctest --test-dir /tmp/clamav-current-build-20260915 \
  --output-on-failure -R ^largefile_library_exact_32g$ --timeout 14400
```

Job `job_16d9d7b02b64424eacc2ca582bea2772` reached terminal state
`succeeded` with exit code `0`.

```text
1/1 Test #6: largefile_library_exact_32g ......   Passed  341.08 sec
100% tests passed, 0 tests failed out of 1
Total Test time (real) = 341.09 sec
```

The test's exact marker/signature assertions cover:

- 32 GiB logical file size and marker offset `34359738304`
- `LargeFile.Library.32G.UNOFFICIAL`
- `CL_VERDICT_STRONG_INDICATOR`
- `DETECTION_TERMINATED`
- path (`cl_scanfile_ex2`), descriptor (`cl_scandesc_ex2`), and fmap
  (`cl_scanmap_ex2`) APIs
- matcher/logical/temporary limit bindings and an exact tail reached beyond
  the former 32-bit boundary

## Post-run controls

- Temporary signature and generated edge fixture names were absent after the
  test completed.
- Container filesystem availability after the run was `91560562688` bytes
  for both `/tmp` and `/src`.
- Container memory after the run reported `63858008064` bytes available;
  baseline swap remained `893124608` bytes used. No new swap/OOM/sanitizer
  signal was observed in this test.
- No host software was installed or downloaded. No usage-reset or banked-reset
  tool was called. No GitHub workflow was changed or triggered.

## Disposition

This closes a current-source x86-64 exact library API slice and confirms the
descriptor-retention fix does not break the full 32-GiB tail path. It remains
development qualification evidence only: the generated file is not a fully
materialized release-family fixture, and R11 still requires a complete
vertical slice with production databases, CLI/daemon/client modes, sanitizer
parity, independent case records, and measured resource evidence. No
capability was promoted.
