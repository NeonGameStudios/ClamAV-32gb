# R03/R04 current-source unsanitized integration recheck — 2026-09-19

Task ID / parent milestone: `R03` / current-source application verification.

## Scope and source identity

This receipt records a no-sanitizer ARM64 development build used to separate
the Rust integration from the retained sanitizer-runtime boundary. It is
supporting development evidence, not certified release qualification.

- Repository: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- Branch: `largefile-roadmap-qualification`
- Source commit: `bc7b0eb0331a5ca056f923b226de7b6c09832c6f`
- Disposable container: `clamav-current-build-20260911`
- Local image: `clamav-largefile-local-toolchain2:latest`

## Build environment and command

- Linux `aarch64` container with Clang 16.0.6, Rust/Cargo 1.97.1, and CMake
  3.25.1.
- Build tree: `/tmp/clamav-current-release-make2`.
- CMake configuration: `RelWithDebInfo`, static libclamav, tests, app,
  clamonacc, milter, UnRAR, and Rust consumer enabled; large-file defaults and
  the qualification test disabled for this development recheck.
- The build used the container's normal compiler/linker flags (`-O2 -g`), with
  no ASan or UBSan instrumentation.
- The `check_clamav` target completed at 100%, including the Rust target and
  native static library.

## Runtime results

The CTest Rust integration command was:

```text
PATH=/usr/local/cargo/bin:$PATH \
  ctest --test-dir /tmp/clamav-current-release-make2 \
  --output-on-failure -R '^libclamav_rust$'
```

Result:

```text
1/1 Test #27: libclamav_rust ... Passed 40.88 sec
100% tests passed, 0 tests failed out of 1
```

The focused native API command was:

```text
CVD_CERTS_DIR=/src/unit_tests/input/signing/verify T=120 \
  CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api \
  /tmp/clamav-current-release-make2/unit_tests/check_clamav
```

Result:

```text
100%: Checks: 533, Failures: 0, Errors: 0
```

The emitted `traverse_to: Failed open payload` line is from the expected
negative-path action test; it did not produce a Check failure.

## Qualification boundary

This recheck does not prove the exact materialized 32-GiB edge, certified
Linux x86-64 admission, full parser/matcher coverage, service/on-access/milter
parity, resource ceilings, or release qualification. It adds no capability
promotion. The earlier ASan/UBSan CTest Rust run remains an instrumentation
environment failure (`Your application is linked against incompatible ASan
runtimes`); the no-sanitizer CTest result above demonstrates that the Rust
consumer and native ClamAV integration pass when that boundary is removed.

The readiness snapshot remains:

```text
capability_total=604
capability_qualified=0
capability_bounded=147
capability_pending=443
capability_unsupported=14
capability_unsupported_required=0
capability_blocked=590
release_readiness=blocked
```

No host software was installed, no MCP-SSH mutation or GitHub workflow action
was used, and no usage-reset credit was used.
