# Full `libclamav` integration — current-source Release (2026-09-13)

## Scope

Reconfigure and incrementally rebuild the existing ARM64 Release tree against
the current source manifest, then run the complete `libclamav` integration
target. The prior Release cache was rejected because it still carried the
pre-RAR-fixture source identity.

## Provenance

- source tree: `/src` mounted from the working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`;
- build directory: `/tmp/clamav-release-current-20260913`;
- `check_clamav` SHA-256:
  `a77b37a977bb7544b906d071a23aa910b7d6f18146074d4780798f32e89ef753`;
- `CMakeCache.txt` SHA-256:
  `2010829dbb1fb883a2c22acb4462931e47cedd280db994e6f497ce9040d5bff7`;
- configuration: Release, applications/tests/milter/UnRAR enabled, static
  libraries enabled, large-file defaults and exact-qualification test switch
  left disabled as required for the development profile.

## Commands and result

```text
cmake -S /src -B /tmp/clamav-release-current-20260913 \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_APP=ON -DENABLE_CLAMONACC=ON \
  -DENABLE_MILTER=ON -DENABLE_JSON_SHARED=ON \
  -DENABLE_LARGE_FILE_DEFAULTS=OFF \
  -DENABLE_LARGE_FILE_QUALIFICATION_TEST=OFF \
  -DENABLE_MAN_PAGES=ON -DENABLE_SHARED_LIB=OFF \
  -DENABLE_STATIC_LIB=ON -DENABLE_TESTS=ON -DENABLE_UNRAR=ON \
  -DENABLE_SYSTEMD=ON
cmake --build /tmp/clamav-release-current-20260913 --parallel 2
ctest --test-dir /tmp/clamav-release-current-20260913 -V -R '^libclamav$'
```

Reconfiguration and rebuild both exited 0; all targets reached 100%. The
CTest target passed `1/1` in 89.73 seconds. Its underlying integration
harness ran `2,919` checks with zero failures and zero errors:
`100%: Checks: 2919, Failures: 0, Errors: 0`.

The run covers the complete current parser/library C test suite, including
large-file reader, quota, archive, document, image, matcher, CVD, and
fail-visible error paths. The retained `traverse_to: Failed open payload`
line is the existing expected diagnostic from the replaced-symlink test.

This is current-source ARM64 Release development evidence. It does not
establish certified x86-64, exact 32-GiB/materialized-resource, production
CVD/service, privileged fanotify, independent format-8, resource, or final
release qualification.
