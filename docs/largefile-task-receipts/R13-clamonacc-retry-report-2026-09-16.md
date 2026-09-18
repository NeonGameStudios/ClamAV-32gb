# Task receipt: R13 clamonacc retry report publication — 2026-09-16

## Scope

This receipt records a local implementation correction for the R13
on-access evidence sink. It is not Linux runtime or release qualification
evidence.

## Correction

`clamonacc` now buffers each scan attempt's structured clamd report in a
temporary stream. When retries are enabled, a failed attempt is discarded
before the next attempt starts. After the final attempt, exactly one retained
daemon report is copied to the configured JSONL stream; if no terminating
report was retained, exactly one fail-closed fallback is emitted. This removes
the prior duplicate-report path where an incomplete first attempt could be
published before a retry or fallback.

The temporary report stream is also treated as required evidence: if it cannot
be created, the scan is made fail-visible and the final fallback path is
used. The shared output stream remains serialized by the existing scan mutex.

The fanotify evidence sink also rejects any response value other than the
two kernel-defined permission responses instead of serializing an unknown
value as `FAN_ALLOW`.

## Verification

- `sh tools/largefile_source_guards.sh` — passed, including the 604-entry
  capability manifest and all repository regression groups;
- `python3 -m unittest discover tools -p '*_test.py' -v` — passed, 199 tests
  with 2 Linux-only filesystem tests skipped on this macOS host;
- `cargo test -p onenote_parser --quiet` — passed, 80 unit tests and 5
  integration tests, with existing compiler warnings only;
- `git diff --check` — passed;
- no remote source was promoted and no qualification result was asserted;
- a compiler/runtime check of the modified C target remains pending until a
  Linux x86-64 build environment with generated CMake metadata and its
  dependencies is available.

State: `implementation-corrected; locally-guarded; runtime-qualification-pending`.
