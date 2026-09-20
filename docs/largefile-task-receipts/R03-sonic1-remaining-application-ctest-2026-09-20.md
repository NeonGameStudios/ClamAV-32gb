# Task receipt: R03 Sonic1 remaining application CTest

Task ID / parent milestone: `R03` / `R10`

Scope: run the remaining bounded application controls for the current-source
Rust integration, updater, and signature-tool targets. This run is
development evidence; it does not claim full-size materialized ingress,
independent format-8 compiler/artifact coverage, sanitizer parity,
production-CVD behavior, or release readiness.

Environment and identity:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Source bind: `/tmp/clamav-32gb-current-20260915` mounted at `/src`.
- Build directory: `/src/build-roadmap-20260920`.

Command and result:

```text
ctest --test-dir /src/build-roadmap-20260920 --output-on-failure -R '^(libclamav_rust|freshclam|sigtool)$'
exit=0

1/3 Test #24: libclamav_rust ................... Passed 13.01 sec
2/3 Test #27: freshclam ........................ Passed 17.69 sec
3/3 Test #28: sigtool .......................... Passed  1.55 sec
100% tests passed, 0 tests failed out of 3
Total Test time (real) = 32.26 sec
```

Retained output:

- `/tmp/clamav-r10-sonic1-app-ctest-20260920.log`
- SHA-256:
  `ae9d8e1083ddb34590b18aaa96d41300a47399e077b4177d1a50e95f9717624b`

Remaining work: full-size exact/materialized cases, independent format-8
compiler/artifact proof, milter and on-access runtime evidence,
sanitizer/production-CVD parity, resource and fanotify proof, and final
release readiness remain open.

State: `development-verified; full-size-and-release-evidence-open`
