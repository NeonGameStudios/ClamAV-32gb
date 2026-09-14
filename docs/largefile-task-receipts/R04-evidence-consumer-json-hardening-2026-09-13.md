# R04 evidence-consumer JSON hardening — 2026-09-13

## Scope

Close the remaining last-key-wins parsing paths in evidence consumers. Every
JSON object used to bind a service input, oversize result, clamscan admission
result, or acceptance proof must reject duplicate keys before schema and
outcome validation.

## Changes

- `largefile_acceptance_cases.py` now applies the strict loader when validating
  retained service-input identity evidence.
- `largefile_acceptance_case_producer.py` uses the strict loader for service
  input binding.
- `largefile_service_oversize.py` uses strict object loading when combining
  alerts-off and alerts-on evidence.
- `largefile_clamscan_admission_test.py` uses strict object loading for its
  structured CLI report.
- Added regression coverage for the acceptance validator, service producer,
  and oversize evidence combiner.

## Verification

```text
PYTHONPATH=tools python3 -B -m unittest discover -s tools -p 'largefile_*_test.py' -v
Ran 174 tests in 8.390s
OK (skipped=2)
```

The skipped tests require Linux filesystem allocation controls and were not
treated as passes. No capability was promoted; this is R04 verifier hardening,
not qualification evidence.
