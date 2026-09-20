# Sonic1 exact current-source Release build and CTest pass — 2026-09-20

## Scope

This receipt records a clean current-source Release build and registered CTest
run on Sonic1. It is Release integration evidence for R03, not final roadmap
qualification: the large-file qualification toggle remained off, no materialized
32-GiB fixture was used, and no capability status was promoted.

## Identity

- Host: `sonic1`
- Login profile: `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Source bind: `/tmp/clamav-32gb-7f3458c4` mounted at `/src`
- Build tree: `/tmp/clamav-7f3458c4-release-build`
- Local branch: `largefile-roadmap-qualification`
- Local source baseline: `aa6c0077130c9f7aefd8d366aa9a689ffc6c87fe`
- Local documentation tip at run time: `1de599f9ba133a127d41549672eaf964e0f683b7`
- Exact source manifest: `f7be88d8961ee5e5546e5fbcf44374a70c083deccbb34ba867547a9cd6aacf8f`
- Release configure job: `job_1ed80bb0b35d47cb9aaed3e870ed7db5`
- Release full-build job: `job_b4c793211813464b9c377d34c50156bb`
- Release CTest job: `job_c948fbeaf36d49ef84f6d06f0f6fc66a`

## Reconfiguration and build

The first Release configure used the default `ENABLE_STATIC_LIB=OFF`, which
cannot link the internal-symbol test executable. The build tree was corrected
and reconfigured with the required static test topology:

```text
CMAKE_BUILD_TYPE:STRING=Release
ENABLE_LARGE_FILE_QUALIFICATION_TEST:BOOL=OFF
ENABLE_STATIC_LIB:BOOL=ON
CLAMAV_SOURCE_COMMIT:INTERNAL=aa6c0077130c9f7aefd8d366aa9a689ffc6c87fe
CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL=f7be88d8961ee5e5546e5fbcf44374a70c083deccbb34ba867547a9cd6aacf8f
```

The complete default Release target then built successfully with `-j1`.

## Result

Command:

```text
docker exec -u 0 -w /tmp/clamav-7f3458c4-release-build \
  clamav-current-7f3458c4 ctest --output-on-failure --timeout 1200
```

```text
100% tests passed, 0 tests failed out of 31
Total Test time (real) = 220.08 sec
```

All 31 registered tests passed, including all 24 `largefile` and
`release-controls` tests, the aggregate `libclamav` and `libclamav_rust`
suites, clamscan, clamd, freshclam, sigtool, both milter checks, source
guards, acceptance producers, resource controls, and on-access stream
controls.

## Interpretation

The exact current-source tree now has a passing Sonic1 Release integration
build and registered test suite. Certified sanitizer identity, production
database/service evidence, full-size materialized cases, independent format-8
execution, resource/fanotify proof, and final R11–R15 review remain open under
the roadmap.
