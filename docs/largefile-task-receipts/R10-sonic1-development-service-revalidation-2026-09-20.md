# Task receipt: R10 Sonic1 development service revalidation

Task ID / parent milestone: `R10` / `R04`

Scope: revalidate the current-source development service producer after the
structured-report validator was tightened to require the contract's 64-GiB
logical scan budget.

Observed issue:

- The producer wrote `MaxScanSize 64M` and labeled records `max-scan=64M`.
- The current report validator correctly rejected those records because every
  service report must expose the 64-GiB logical budget, even for small
  development fixtures.

Correction:

- Added one producer constant for the 64-GiB development logical budget.
- Bound the generated ClamD configuration, resource-phase record, and build
  identity to that value. The other development limits remain bounded and the
  capture remains explicitly non-release evidence.

Verification:

```text
PYTHONPATH=tools python3 -B -m unittest -v tools.largefile_development_service_capture_test
Ran 8 tests in 0.014s
OK

python3 -u /src/tools/largefile_development_service_capture.py \
  /tmp/clamav-7f3458c4-release-build/clamd/clamd \
  /tmp/clamav-7f3458c4-dev-service-capture-current \
  --clamdscan /tmp/clamav-7f3458c4-release-build/clamdscan/clamdscan \
  --source-root /src --build-dir /tmp/clamav-7f3458c4-release-build \
  --cvd-certs-dir /src/unit_tests/input/signing/verify
exit=0
development service capture wrote 36 R04 records
```

Source-bound identities:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`.
- Producer SHA-256: `22c4739fd71d3f054a2fe244a97333834f78c8bf94a574b83e8a6e656a03f8c3`.
- Source manifest SHA-256: `1467bb29c64d76457408cecdefbc1ff9cb84aed64513a58eb76f00a919f16976`.
- Build identity SHA-256: `e91dec533598c3006ba6e79abe051ab9060bf56e17ef394513ade4d92990bffb`.
- Acceptance records SHA-256: `9894540371613f42df2bfd9eae9d7a0bd1b8482b417b816eb24cedeb0a780e67`.

Interpretation: the bounded clamd/clamdscan development matrix is now
development-verified for its 12 ingress identities and three outcomes. It
does not promote any capability or close the materialized 32-GiB, parser,
sanitizer, PCRE-resource, fanotify, production-CVD, or final-readiness gates.

State: `development-verified; certified-capacity-and-release-evidence-open`
