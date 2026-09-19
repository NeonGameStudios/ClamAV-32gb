# Sonic1 current-source registered CTest pass — 2026-09-19

## Scope

This receipt records the registered CTest suite after the current local source
was synchronized into the Sonic1 build container and `check_clamav` was rebuilt.
It is development integration evidence, not certified release qualification:
the build is not claimed as the frozen Release/sanitizer candidate, no
materialized 32-GiB fixture was used, and no capability status was promoted.

## Identity

- Host: `sonic1`
- Login profile: `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Build tree: `/tmp/clamav-7f3458c4-build`
- Local branch: `largefile-roadmap-qualification`
- Local HEAD used for synchronization: `aa6c0077130c9f7aefd8d366aa9a689ffc6c87fe`
- Async job: `job_40911f0e518f429b819ea8ca4fdcd7d1`

The test binary was rebuilt from the synchronized current sources before this
run. The synchronized source set included the changed `mbox.c`, OneNote reader,
and `check_clamav.c` files. The container's disposable synthetic Git metadata
exists only to let the snapshot checker read the local revision; it is not
independent Git provenance.

## Result

Command:

```text
docker exec -u 0 -w /tmp/clamav-7f3458c4-build \
  clamav-current-7f3458c4 ctest --output-on-failure --timeout 1200
```

```text
100% tests passed, 0 tests failed out of 31
Total Test time (real) = 255.72 sec
```

All 31 registered tests passed, including:

- aggregate `libclamav` and `libclamav_rust` suites;
- clamscan, clamd, freshclam, sigtool, and milter tests;
- source guards, runtime/service evidence checks, acceptance schemas and
  producers;
- logical ZIP late-member, on-access stream deadline, resource metrics/OOM,
  clamd threadpool/write-fault, and milter controls.

## Interpretation

The synchronized current source now has a clean registered integration suite
on Sonic1's existing development build tree. Certified Linux x86-64 Release
and sanitizer identity, production database/service evidence, full-size
materialized cases, independent format-8 execution, resource/fanotify proof,
and final R11–R15 review remain open under the roadmap.
