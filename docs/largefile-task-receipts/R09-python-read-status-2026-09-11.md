# R09 Python marshal backing-read status — 2026-09-11

Task ID / parent milestone: `R09` / `CL_TYPE_PYTHON_COMPILED`

Exact capability kind:id list: `parser:CL_TYPE_PYTHON_COMPILED`

Observed gap: the bounded Python marshal reader treated every short return from
`fmap_readn()` as `CL_EPARSE`, even when the requested range was inside the fmap
and the backing callback failed operationally. That erased the distinction
between malformed/truncated input and an unreadable input source.

Implemented slice:

- `libclamav/scanners.c` now recognizes `fmap_readn()`'s `(size_t)-1` result in
  `cli_python_read()`, marks the scan incomplete, and returns `CL_EREAD`.
- Short or truncated ranges retain `CL_EPARSE` and the existing outer
  incomplete/non-cacheable behavior.
- Added and registered
  `test_python_compiled_parser_preserves_fmap_read_failure` in both the
  ordinary and required-unsupported test cases. The public scan contract
  requires `CL_EREAD`, a cleared verdict/alert, and cache taint.
- Added the corresponding source guard and capability evidence wording.

Evidence:

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — 147 passed,
  2 expected skips.
- `sh tools/largefile_source_guards.sh` — passed; capability manifest and
  acceptance map each cover 597 bindings, and snapshot/inventory freshness
  checks passed.
- `git diff --check` passed for the changed source, test, guard, and capability
  files before receipt generation.
- Final audited source-manifest SHA-256:
  `a7cf950670932058e077cf81706fe4fef93a16730d124312527f8650870f4b97`.

No linked current-source C execution is claimed: the retained build predates
this edit and the available Docker images do not provide JSON-C and Check
development headers. No package installation was performed. Capability status
remains `pending`; certified Linux x86-64, sanitizer, production-CVD/service,
full-size, and final release qualification remain open.
