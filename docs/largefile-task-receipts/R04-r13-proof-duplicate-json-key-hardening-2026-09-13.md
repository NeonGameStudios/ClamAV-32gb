# R04/R13 proof JSON duplicate-key hardening — 2026-09-13

## Scope

Harden the retained R13 fanotify and PCRE phase proof readers against
duplicate JSON keys. Python's default JSON decoder keeps the last occurrence
of a key, which could otherwise allow a later field to replace an independently
emitted status, identity, resource claim, or runtime outcome before validation.

## Changes

- `tools/largefile_fanotify_evidence.py` now uses the shared strict JSON
  loader from `largefile_acceptance_cases.py`.
- `tools/largefile_pcre_phase_evidence.py` now uses the same loader.
- Added regression coverage for duplicate top-level keys in both proof
  verifiers.

## Verification

```text
PYTHONPATH=tools python3 -B -m unittest -v \
  tools.largefile_acceptance_cases_test \
  tools.largefile_fanotify_evidence_test \
  tools.largefile_pcre_phase_evidence_test
Ran 34 tests
OK
```

The shared acceptance loader regression also passed. This receipt records
local verifier hardening only; no R13 capability was promoted and no Linux
fanotify or PCRE qualification result was inferred from these unit tests.
