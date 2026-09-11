# Task receipt: R09 Python modern marshal-layout correction

Task ID / parent milestone: `R09` / `R00`

Exact capability kind:id list: parser:`CL_TYPE_PYTHON_COMPILED`

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`; existing dirty working tree preserved; the
generated inventory and snapshot were refreshed after this slice.

Prerequisites verified: the bounded marshal walker and its synthetic modern
code-object regression were compared with the CPython 3.11+ marshal writer
layout in the official `Python/marshal.c` source. No dependency installation,
remote runner, Docker execution, usage reset, commit, push, or GitHub workflow
action was used.

Observed failing case and expected behavior: Python 3.11+ marshal code
objects carry five leading 32-bit fields, eight object fields, then first-line,
line-table, and exception-table objects. The walker had been changed to an
incorrect six-leading/nine-object interpretation, which would reject valid
modern compiled files or parse them at the wrong boundaries. Valid modern
input must reach the end of the file without executing bytecode; malformed
input remains fail-visible.

Changes made:

- Added an explicit object-field count to each supported code-object layout.
- Corrected the Python 3.11+ layout to five leading integers and eight
  objects, matching CPython's removal of `co_nlocals` from the marshalled
  code-object sequence.
- Updated the modern regression fixture to retain the locals-plus name/kind
  and qualname object fields without the obsolete `co_nlocals` field.
- Added source guards for the layout contract.

Authoritative reference: `https://github.com/python/cpython/blob/3.11/Python/marshal.c`.

Commands, exits, logs and fixture/database hashes:

- `git diff --check` — run before the final controls.
- Inventory and snapshot freshness checks passed after the source/test change.
- Full source/evidence guard sweep passed, including the acceptance map and
  schema controls.
- The linked current-source C test binary was unavailable on this host because
  the required OpenSSL development headers are absent; no software was
  installed.

Development tests passed: source-level registration and guard coverage passed;
direct C execution remains unavailable on this host.

Full-size/certified evidence produced, or explicitly not run: not run. No
independent format-8 artifact, certified Linux x86-64 Release/sanitizer build,
production database, materialized large-file edge, or R04 qualification record
exists for this slice.

Remaining failures / next slice: independent format-8 bytecode evidence and
certified execution remain blocked by the missing external compiler/runner;
Python parser production-corpus and release qualification remain open.

State: development-verified
