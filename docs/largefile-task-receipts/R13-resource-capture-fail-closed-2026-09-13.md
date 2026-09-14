# R13 resource-capture fail-closed correction (2026-09-13)

## Implementation

`tools/largefile_acceptance_resource_capture.py` previously continued after a
sampler error whenever an earlier sample existed. That could publish a
resource sidecar with an incomplete peak. It now terminates the wrapped
command and fails the capture when a required process-tree or phase-protocol
sample fails while the command is still alive. A sampler failure racing normal
process exit remains handled by the existing no-sample check. Phase protocol
reads also reject a symlink replacement after capture starts.

Regression coverage in
`tools/largefile_acceptance_resource_capture_test.py` now verifies both
behaviors:

- a live sampler failure terminates the command and raises a fail-closed error;
- a replaced phase file that is symlinked is rejected.

The focused host unit file ran 5/5 tests successfully.

## Current-source verification

The existing ARM64 Docker trees were reconfigured and rebuilt from the current
working tree:

- source manifest: 1,697 entries;
- source manifest SHA-256:
  `0cd222db4377ba8d53519d743cf75f2b5f0cdcf504f0223d7551de5ab9213439`;
- Release `CMakeCache.txt` SHA-256:
  `5d881cb99c86bc4705246d32ba215710b155f8a2327c187b114e3400937ff991`;
- ASan/UBSan `CMakeCache.txt` SHA-256:
  `6c9dc9865a1c020d4b5ef2b9f710b94d2ab4f9fa44d943a711f1d735d364e7ca`;
- Release `unit_tests/check_clamav` SHA-256:
  `395d236f58f664a2cd8bbe8718e3e1e14fc4c563d2764024ae32f75c0581f067`;
- ASan/UBSan `unit_tests/check_clamav` SHA-256:
  `3e5346b491693581b7a76ceaa6a4df8d0a32fde860802a80c9eea00074f46d3`.

The complete Release CTest matrix passed 28/28 in 180.64 seconds. The
focused ASan/UBSan `largefile_acceptance_resource_capture` target passed 1/1
in 0.09 seconds. Retained sanitizer logs contained no sanitizer diagnostics.

This improves fail-closed evidence collection but does not establish
certified x86-64, full-size/materialized resource measurements, privileged
fanotify, production canary, independent format-8 bytecode, or final release
qualification.
