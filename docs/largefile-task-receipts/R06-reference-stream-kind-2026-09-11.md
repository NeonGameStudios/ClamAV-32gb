# Task receipt: R06 OneStore reference-stream kind validation

Task ID / parent milestone: `R06` / `R00`

Scope: make OneStore object-reference mapping fail closed when the declared
context and object-space reference streams have individually mismatched
lengths. This is a bounded parser-hardening slice; it does not promote
OneNote or release readiness.

## Correction

`Object::parse` previously compared only the combined number of context and
object-space property IDs with the combined number of referenced cells, and
accepted surplus object IDs because it checked only for a short object stream.
A malformed object could therefore swap stream counts or silently discard
surplus IDs while constructing the mapping table. The parser now validates all
three streams exactly before constructing the mapping table. In addition,
rich-text parsing now rejects embedded text-run data without a corresponding
style entry while preserving the valid text-only asymmetry. Unit regressions
cover matching streams, swapped counts, short streams, surplus IDs, and the
rich-text pairing boundary.

## Verification

- `cargo test --offline --manifest-path /private/tmp/onenote-parser-check/Cargo.toml --lib` — **69 passed**.
- Disposable production-source parser binary parsed the bundled `New Section 1.one` sample — **passed**.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `python3 -B tools/largefile_service_workload_check_test.py` — **28 passed; 2 expected Linux-only skips**.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` — **597 capabilities passed**.
- `python3 -B tools/largefile_acceptance_cases.py --check-records` — **0-record schema passed**.
- `sh tools/largefile_release_readiness_test.sh` — **passed**.
- Generated inventory freshness check — **passed** after refresh.
- Targeted source assertions and `sh -n tools/largefile_source_guards.sh` — **passed**.
- `git diff --check` — **passed**.

The monolithic `tools/largefile_source_guards.sh` wrapper was not counted as
passed: it produced no result within the bounded local run and was stopped.
No capability was promoted. Certified Linux x86-64, sanitizer, materialized
late-content, production-service, R03 runner, R04 records, and final release
qualification remain open. No remote execution, usage reset, GitHub workflow
action, commit, or push was used.

State: implementation slice development-verified; release qualification
remains blocked.
