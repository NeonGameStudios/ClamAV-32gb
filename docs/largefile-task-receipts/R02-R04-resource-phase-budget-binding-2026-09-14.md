# R02/R04 resource-phase budget binding — 2026-09-14

Task ID / parent milestone: R02 Gap A and R04 case-record verifier

Exact capability kind:id list: shared acceptance-record resource-phase contract; no capability promoted

Starting commit and working-tree/source manifest identity: HEAD `8e837b88c89874b180a1a25f22d287f7d6be29db`; current source manifest SHA-256 `acd0805ba989e02c3ff36a09857bae86e7268ecd8b35df5cd95076733f1b8ade`

Prerequisites verified: existing R02 runtime producer/verifier and R13 resource sidecar use the PLAN budgets; the generic R04 parser accepted measured budget labels without checking their numeric limits.

Owned files and excluded shared files: `tools/largefile_acceptance_cases.py`, its tests, and the two runtime acceptance producers' resource-phase serialization. Shared capability manifest, acceptance map, and release gate were not changed.

Observed gap and expected behavior: a copied acceptance record could claim a measured `rss`, `pcre`, `post-pcre`, or `temporary` phase with an out-of-contract numeric budget and still pass the generic record parser. The verifier must enforce the 32-GiB overall subcase, 40-GiB PCRE ceiling, strictly-below-12-GiB post-PCRE phase, and 64-GiB temporary budget; development-envelope tokens remain separate.

Changes made: added canonical measured-phase budget validation to `parse_resource_phases()`, rejected units on measured tokens, required the strict post-PCRE operator, updated both runtime producers and fixtures to serialize `post-pcre<12582912`, and added boundary regressions for over-budget and malformed measured tokens.

Commands, exits, logs and fixture/database hashes:

* `python3 -B tools/largefile_acceptance_cases_test.py` — exit 0, 14/14.
* `python3 -B tools/largefile_acceptance_resources_test.py` — exit 0, 7/7.
* `python3 -B tools/largefile_runtime_acceptance_case_producer_test.py` — exit 0, 8/8.
* `python3 -B tools/largefile_acceptance_cases.py --check-map` — exit 0, 604 capabilities.
* `python3 -B tools/largefile_acceptance_cases.py --check-records` — exit 0, 0 records (schema-valid incomplete state).
* `sh tools/largefile_source_guards.sh` — exit 0; capability manifest, readiness regressions, snapshot/inventory/evidence schemas, and source guards passed.
* `git diff --check` — exit 0.

Development tests passed: all tests above, including the new four budget-overflow controls and strict post-PCRE boundary.

Full-size/certified evidence produced, or explicitly not run: not run. This tooling change does not provide certified Linux x86-64, materialized 32-GiB, production CVD/service, resource sampler, fanotify, or final release evidence.

Remaining failures / next slice: readiness remains blocked until capability-specific records and independent resource measurements are available; certified x86-64 and the external format-8 compiler/artifact remain open prerequisites.

State: development-verified
