# R04 current-source ARM64 development capture — 2026-09-19

Task ID / parent milestone: `R04` / current-source application verification.

## Scope and source identity

This receipt records a coherent current-source ARM64 development build and a
six-case `clamscan` acceptance capture. It is supporting development evidence,
not certified release qualification.

- Repository: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- Branch: `largefile-roadmap-qualification`
- Source commit: `1641bfa1589eddad2923cc2a7c411046736590e8`
- Capture source-manifest SHA-256:
  `5d085875a9023ba2bda525e71f0b103fa50fd24d41986475ddba353986a2511a`
- Capture evidence root: `/private/tmp/clamav-r04-development-current-2`

## Build environment

- Disposable ARM64 Linux container:
  `clamav-current-build-20260911`
- Local image: `clamav-largefile-local-toolchain2:latest`
- Rust `1.97.1` (`aarch64-unknown-linux-gnu`) and CMake `3.25.1`.
- CMake tree: `/tmp/clamav-current-build`.
- Configuration: `RelWithDebInfo`, static libclamav, tests, clamonacc,
  milter, UnRAR, and Rust consumer enabled. The retained tree carries
  development ASan/UBSan flags; this is not certified sanitizer evidence.
- The following development packages were installed only inside the
  disposable container to complete its missing build inputs:
  `libcurl4-openssl-dev`, `libmilter-dev`, `libmilter1.0.1`, `libtinfo-dev`,
  `libssl-dev`, and `zlib1g-dev`. No host or repository software was
  installed.

## Build result

The complete build reached 100% and compiled/linked the C and Rust components,
including libclamav, clamd, clamdscan, clamonacc, clamav-milter, clamscan,
clambc, sigtool, freshclam, clamsubmit, clamdtop, and the test binaries.

The focused CTest command was:

```text
ctest --test-dir /tmp/clamav-current-build --output-on-failure \\
  -R '^(libclamav|libclamav_rust)$' -j2
```

It completed after `1200.90` seconds with `0% tests passed, 2 tests failed`:

- `libclamav_rust`: the CMake-injected `LD_PRELOAD` mixed GCC's ASan runtime
  with the Rust test's ASan runtime and reported
  `Your application is linked against incompatible ASan runtimes`. Rust
  compilation and linking succeeded; this is an instrumentation-environment
  boundary, not a Rust compile failure.
- `libclamav`: the aggregate Check run exceeded its 1200-second wrapper
  timeout and returned exit `111`. Its output included
  `traverse_to: Failed open payload`. The narrower `cl_api` group was rerun
  with the CTest certificate environment and completed with `533` checks,
  `0` failures, and `0` errors; it emitted the same diagnostic from the
  expected negative-path action test. The aggregate timeout therefore
  remains unresolved development evidence rather than a source assertion
  failure.

## R04 six-case acceptance capture

The current-source scanner was run with
`tools/largefile_development_acceptance_capture.py` inside the same
container. The producer wrote six records, and the host-side independent
validators accepted both the 604-capability case map and the six-record
schema:

```text
large-file acceptance case map passed (604 capabilities)
large-file acceptance record schema passed (6 records)
```

The retained records are:

| Case | Exit | Verdict | Completion | Result |
| --- | ---: | --- | --- | --- |
| `clamscan:file:clean-edge` | 0 | `CLEAN` | `COMPLETE` | passed |
| `clamscan:file:detection-edge` | 1 | `DETECTED` | `DETECTION_TERMINATED` | exact `LargeFile.R04.Runtime.Detection.UNOFFICIAL`, offset 25 |
| `clamscan:file:limit-edge` | 2 | `INCOMPLETE` | `LIMIT_INCOMPLETE` | `Heuristics.Limits.Exceeded.MaxFileSize` |
| `clamscan:stdin:clean-edge` | 0 | `CLEAN` | `COMPLETE` | passed |
| `clamscan:stdin:detection-edge` | 1 | `DETECTED` | `DETECTION_TERMINATED` | exact signature, offset 25 |
| `clamscan:stdin:limit-edge` | 2 | `INCOMPLETE` | `LIMIT_INCOMPLETE` | `Heuristics.Limits.Exceeded.MaxFileSize` |

All six records identify `Linux-aarch64`, the development sanitizer profile,
the runtime-edge fixture, successful health/cleanup, and the configured
development resource bounds. Evidence hashes include:

- `provenance/acceptance-cases.tsv`:
  `6fd0940e723c7df645851326d5fe9e1220f7a214f1e110c0a5ebd037e9185505`
- `provenance/source-manifest.txt`:
  `5d085875a9023ba2bda525e71f0b103fa50fd24d41986475ddba353986a2511a`
- `provenance/CMakeCache.txt`:
  `4a2eeee53af89fba3e9a579a52432b770686a3cc94be0bacde410a027f313335`

## Qualification boundary

This capture does not prove the exact materialized 32-GiB edge, certified
Linux x86-64 admission, production database behavior, full parser/matcher
coverage, service/on-access/milter parity, resource ceilings, or release
qualification. No capability rows were promoted. The readiness snapshot
remains:

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

No MCP-SSH mutation, GitHub workflow action, or usage-reset credit was used.
