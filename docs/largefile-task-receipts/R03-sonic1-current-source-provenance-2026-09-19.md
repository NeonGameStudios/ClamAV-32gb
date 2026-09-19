# Sonic1 exact current-source provenance rebuild and CTest pass — 2026-09-19

## Scope

This receipt records a clean development rebuild and registered CTest run after
the Sonic1 staging tree was corrected to match the local current-source
manifest byte-for-byte. It is development integration evidence, not certified
release qualification: the build is `RelWithDebInfo`, the large-file
qualification toggle is off, no materialized 32-GiB fixture was used, and no
capability status was promoted.

## Identity

- Host: `sonic1`
- Login profile: `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Source bind: `/tmp/clamav-32gb-7f3458c4` mounted at `/src`
- Build tree: `/tmp/clamav-7f3458c4-build`
- Local branch: `largefile-roadmap-qualification`
- Local source baseline: `aa6c0077130c9f7aefd8d366aa9a689ffc6c87fe`
- Local documentation tip at run time: `ca82b71cbe2ea5dedb91284a53025c0796eadca2`
- Exact source manifest: `f7be88d8961ee5e5546e5fbcf44374a70c083deccbb34ba867547a9cd6aacf8f`
- CTest job: `job_23e53b58ba464e4aa244a40eee0e69ae`

The local documentation tip differs from the source baseline only by ledger
and receipt metadata excluded by `tools/largefile_source_manifest.sh`. The
container's disposable synthetic Git metadata reports the source baseline so
the snapshot checker can read a revision; it is not independent Git
provenance.

## Reconfiguration and build

CMake was reconfigured from `/src` and recorded:

```text
CMAKE_BUILD_TYPE:STRING=RelWithDebInfo
ENABLE_LARGE_FILE_QUALIFICATION_TEST:BOOL=OFF
ENABLE_MILTER:BOOL=ON
ENABLE_UNRAR:BOOL=ON
CLAMAV_SOURCE_COMMIT:INTERNAL=aa6c0077130c9f7aefd8d366aa9a689ffc6c87fe
CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL=f7be88d8961ee5e5546e5fbcf44374a70c083deccbb34ba867547a9cd6aacf8f
```

The focused `check_clamav` rebuild completed successfully before CTest.

## Result

Command:

```text
docker exec -u 0 -w /tmp/clamav-7f3458c4-build \
  clamav-current-7f3458c4 ctest --output-on-failure --timeout 1200
```

```text
100% tests passed, 0 tests failed out of 31
Total Test time (real) = 225.03 sec
```

All 31 registered tests passed, including the aggregate `libclamav` and
`libclamav_rust` suites; clamscan, clamd, freshclam, sigtool, and milter;
source guards; acceptance schemas and producers; resource controls; and
on-access stream controls.

## Interpretation

The exact current-source tree now has a clean registered integration suite on
Sonic1's existing development build. Certified Linux x86-64 Release and
sanitizer identity, production database/service evidence, full-size
materialized cases, independent format-8 execution, resource/fanotify proof,
and final R11–R15 review remain open under the roadmap.
