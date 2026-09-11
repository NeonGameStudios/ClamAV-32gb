# Task receipt: R04 resource-phase grammar

Task ID / parent milestone: `R04` / `R00`

Scope: make the acceptance-record resource-phase field fail closed when it
contains unreviewed or malformed tokens. This tightens evidence validation;
it does not create qualification evidence or promote a capability.

Canonical checkout and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

Source manifest SHA-256 captured before this receipt was added:
`952ee0e289bbc991ff53505db0213f9f3e9201e7ccb09f8a4e9a5768a7ed7091`.

## Correction

`tools/largefile_acceptance_cases.py` now parses the complete semicolon-
delimited resource-phase grammar. Measured RSS/PCRE/temporary tokens,
development max-file/max-scan/max-temp tokens, and the reviewed development
and lifecycle markers are accepted; unknown tokens, empty tokens, and
duplicate measured/development phases fail closed. Previously, the validator
could extract the required tokens while silently ignoring additional text.

`tools/largefile_acceptance_cases_test.py` adds a regression for an
unreviewed resource token, and `tools/largefile_source_guards.sh` pins the
parser and grammar entry point.

## Verification

- `PYTHONPATH=tools python3 -B -m unittest largefile_acceptance_cases_test largefile_acceptance_case_producer_test largefile_development_service_capture_test` — **26 passed**.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `diff -u docs/largefile-inventory.tsv <(sh tools/largefile_inventory.sh)` — **passed**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- `git diff --check` — **passed**.

The full-size certified Linux x86-64 runner remains unavailable, so no
authoritative acceptance record was added. No software was installed, and no
remote execution, MCP-SSH, usage reset, GitHub workflow action, commit, or
push was used.

Release readiness remains blocked at 597 total, 0 qualified, 143 bounded, 440
pending, 14 deliberate unsupported exclusions, 0 unsupported required rows,
and 583 release-blocking rows.

State: `development-verified`; R04 case evidence remains open.
