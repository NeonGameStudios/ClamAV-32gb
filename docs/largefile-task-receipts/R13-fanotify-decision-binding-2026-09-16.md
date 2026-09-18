# Task receipt: R13 fanotify permission-decision binding — 2026-09-16

## Scope

Harden the R13 evidence verifier so a recorder's own permission response is
not mistaken for ClamAV's production prevention decision, and require
monitoring-only scan reports to be structured and case-bound.

## Changes

- prevention kernel-event records retain both the observer's explicit
  `FAN_ALLOW` response and a separate `permission_response` produced by the
  ClamAV/clamonacc supervisor;
- the verifier requires `permission_response` to match the case contract's
  `FAN_ALLOW` or `FAN_DENY` value;
- monitoring-only cases now require a fixture SHA-256 and a structured
  `on-access-scan` report with matching case, completion, exit code, counters,
  and clean/detection/failure semantics;
- negative tests cover a missing ClamAV permission response and a monitoring
  report bound to the wrong case.

## Checks

- `python3 -B tools/largefile_fanotify_evidence_test.py` — 17/17 passed;
- `python3 -B tools/largefile_acceptance_cases_test.py` — 15/15 passed;
- `git diff --check` — passed.

## Boundary

This is verifier/schema hardening only. It does not create ClamAV scan
reports, provide the six real R13 prevention cases, or promote the
on-access capability. The existing capture primitive still records only its
observer response; a real R13 run must retain the ClamAV response separately.

State: `development-verified; qualification-still-open`
