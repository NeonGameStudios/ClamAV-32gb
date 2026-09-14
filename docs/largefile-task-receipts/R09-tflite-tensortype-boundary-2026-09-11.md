# Task receipt: R09 TFLite TensorType boundary — 2026-09-11

Task ID / parent milestone: `R09` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_AI_MODEL`.

Starting identity: branch `largefile-roadmap-qualification`; the existing
intentionally dirty working tree was preserved. No dependency installation,
remote execution, remote SSH, usage reset, commit, push, or GitHub workflow action
was used.

Observed gap and expected behavior: the bounded TFLite structural validator
claimed to reject unknown `TensorType` enum values but accepted every value
through `31`. The current TensorFlow Lite schema defines values `0` through
`22`, so the first undefined value must remain incomplete and non-cacheable;
the outer raw matcher must still retain precedence for an actual detection.

Changes made:

- Added `CLI_AI_MODEL_TFLITE_MAX_TENSOR_TYPE 22U` and use it for the bounded
  TensorType admission check in `libclamav/scanners.c`.
- Added and registered `test_ai_model_tflite_tensor_type_is_fail_visible`,
  which mutates a valid tensor/operator model to enum value `23` and requires
  `CL_EPARSE`, no alert, and `dont_cache_flag`.
- Added source guards binding the numeric limit and required-unsupported test
  registration.

Verification:

- Disposable ARM64 Docker syntax check with `-Wall -Wextra
  -Wformat-security -Werror -std=gnu90` passed for the current
  `libclamav/scanners.c`. JSON-C was represented only by the existing
  temporary declaration stub; no linked-runtime result is claimed.
- `python3 -B -m unittest discover -s tools -p '*_test.py'`: 147 passed,
  2 expected skips.
- `python3 -B tools/largefile_service_workload_check_test.py`: 28 passed,
  2 expected Linux-only skips.
- `sh tools/largefile_source_guards.sh`: passed, including 597 capability
  rows, acceptance schemas, inventory freshness, and the new TFLite guard.
- `git diff --check`: passed.
- Stable source-manifest SHA-256 after this slice:
  `155263cd8958e3c4bdbc36a862e5d14c05d5992c97770f39d918f8ca953b6fdf`.

Full-size/certified evidence: not run. The current-source C test binary,
certified Linux x86-64 runner, sanitizer build, production CVD/service,
full-size model corpus, R04 records, and final release qualification remain
unavailable/open.

Disposition: `development-verified`. No capability was promoted. The next
R09 slice is current-source linked execution and broader TFLite model corpus
qualification; no unsupported-row status changed.
