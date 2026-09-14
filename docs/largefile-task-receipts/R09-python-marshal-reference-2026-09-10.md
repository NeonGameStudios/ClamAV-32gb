# Task receipt: R09 Python marshal reference-table hardening

Task ID / parent milestone: `R09` / `R00`

Scope: close malformed and valid reference-table accounting edges in the
bounded Python compiled-bytecode structural walker without executing bytecode
or changing the unsupported/certification policy.

Changes made:

- Rejected marshal `TYPE_REF` tokens carrying `FLAG_REF`; a lookup cannot also
  register itself as a new reference-table entry.
- Centralized bounded object/reference accounting for normal objects and
  dictionary keys.
- Counted dictionary keys in the object budget and registered flagged keys so
  later valid `TYPE_REF` lookups resolve correctly.
- Added focused legacy fixtures for out-of-range references, flagged
  references, and a valid reference to a flagged dictionary key.

Commands and results:

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — exit 0,
  145 tests passed, 2 expected skips.
- `sh tools/largefile_inventory.sh` — exit 0; refreshed 597-capability
  inventory.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — exit 0.
- `git diff --check` — exit 0.
- `sh tools/largefile_source_guards.sh` — exit 0; all source, schema,
  producer, service, protocol, boundary, and acceptance-map guards passed.

Limitations:

- The host still lacks the generated build configuration and required C
  dependency headers, so the edited C translation unit was not linked here.
- No independent format-8 compiler/artifact, certified Linux x86-64 run,
  full-size materialized evidence, Docker/remote SSH execution, or R04
  qualification record is claimed.

State: `development-verified`; release readiness remains blocked.
