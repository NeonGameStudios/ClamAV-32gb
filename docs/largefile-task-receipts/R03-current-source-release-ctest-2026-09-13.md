# Complete current-source Release CTest matrix (2026-09-13)

## Scope

Revalidate the complete registered application and large-file control matrix
after reconfiguring and rebuilding the Release tree against the current
source manifest.

## Provenance

- source tree: `/src` mounted from the working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`;
- build directory: `/tmp/clamav-release-current-20260913`;
- `clamscan` SHA-256:
  `3a59979b9987600aaf9590cece8ac51bd9e508d99808a652a73c61d0c89c754b`;
- `clamd` SHA-256:
  `59ba066ee121c15a1792008be6f5b2973db311e7cb2e448a98c69a891e164c6d`;
- `clamav-milter` SHA-256:
  `d2244c5805b384dad3e84188c80452ae0c08358a5d86cc7feea3bfe20e28cc0d`;
- `CMakeCache.txt` SHA-256:
  `2010829dbb1fb883a2c22acb4462931e47cedd280db994e6f497ce9040d5bff7`;
- configuration: Release, applications/tests/milter/UnRAR enabled, static
  libraries enabled, large-file defaults and exact-qualification test switch
  disabled for the development profile.

## Result

```text
ctest --test-dir /tmp/clamav-release-current-20260913 --output-on-failure
```

All 28 registered targets passed in 182.03 seconds (`100% tests passed, 0
tests failed out of 28`). The matrix covered:

- all large-file admission, fail-closed, protocol, acceptance-schema,
  resource-contract, process-metrics, and late-member controls;
- the complete `libclamav` suite (2,919 checks, zero failures/errors);
- `libclamav_rust`, `clamscan`, `clamd`, `freshclam`, `sigtool`, and both
  milter targets.

This is current-source ARM64 Release development evidence. It does not
establish certified x86-64, exact 32-GiB/materialized-resource, production
CVD/service, privileged fanotify, independent format-8, resource, or final
release qualification.
