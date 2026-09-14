# Task receipt: R09 Python modern marshal-layout correction and revalidation

Task ID / parent milestone: `R09` / `R00`

Exact capability kind:id list: parser:`CL_TYPE_PYTHON_COMPILED`

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`; existing dirty working tree preserved; the
generated inventory and snapshot were refreshed after this slice.

Prerequisites verified: the bounded marshal walker and its synthetic modern
code-object regression were compared with a locally generated CPython 3.11
marshal stream. No dependency installation, remote runner, Docker execution,
usage reset, commit, push, or GitHub workflow action was used.

Observed failing case and expected behavior: Python 3.11+ marshal code
objects carry six leading 32-bit fields, eight object fields, then first-line,
line-table, and exception-table objects. The prior five-leading interpretation
was incorrect: it could accept only a synthetic shape and would reject the
real current CPython layout. Valid modern input must reach the end of the file
without executing bytecode; malformed input remains fail-visible.

Changes made:

- Added an explicit object-field count to each supported code-object layout.
- Corrected the Python 3.11+ layout to six leading integers and eight
  objects, including `co_nlocals`, matching the locally generated CPython
  3.11 marshal output.
- Updated the modern regression fixture to include `co_nlocals` before the
  stack-size and flags fields while retaining the locals-plus name/kind and
  qualname object fields.
- Added source guards for the layout contract.

Authoritative reference: `https://github.com/python/cpython/blob/3.11/Python/marshal.c`.

Commands, exits, logs and fixture/database hashes:

- `python3 -B -c '...marshal.dumps(compile(...))...'` — exit 0; the local
  CPython stream reports six leading uint32 fields.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — 147 tests
  passed, 2 expected skips.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` — 597
  capabilities passed.
- `python3 -B tools/largefile_acceptance_cases.py --check-records` — 14
  records passed schema validation.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`,
  `sh -n tools/largefile_source_guards.sh`, and `git diff --check` — passed.
- The linked current-source C test binary was unavailable on this host because
  the required OpenSSL development headers are absent; no software was
  installed.

Development tests passed: the source-level registration/guard contract and
the host-side qualification controls passed; direct C execution remains
unavailable on this host.

Full-size/certified evidence produced, or explicitly not run: not run. No
independent format-8 artifact, certified Linux x86-64 Release/sanitizer build,
production database, materialized large-file edge, or R04 qualification record
exists for this slice.

Remaining failures / next slice: independent format-8 bytecode evidence and
certified execution remain blocked by the missing external compiler/runner;
Python parser production-corpus and release qualification remain open.

State: development-verified
