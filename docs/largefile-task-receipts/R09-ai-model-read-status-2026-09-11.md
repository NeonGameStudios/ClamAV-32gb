# Task receipt: R09 AI-model backing-read status

Task ID / parent milestone: `R09` / `R00`

Exact capability kind:id list: parser:`CL_TYPE_AI_MODEL`

Canonical checkout and branch:

- `<repository-root>`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

## Scope and correction

The bounded AI-model reader now distinguishes an in-range fmap backing-read
failure from ordinary truncated input. `fmap_readn()` returning its failure
sentinel is preserved as `CL_EREAD`, with sticky incomplete and non-cacheable
state; a short read remains the parser's `CL_EPARSE` malformed/truncated
boundary.

`test_ai_model_parser_preserves_fmap_read_failure` injects a failing fmap
callback, checks the public `CL_TYPE_AI_MODEL` dispatch result and clean
verdict state, and is registered in both the ordinary and required-unsupported
test cases. The capability narrative and source guards bind the regression.

## Verification

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- regenerated inventory matches `sh tools/largefile_inventory.sh`.
- `git diff --check` — **passed**.
- current source-manifest SHA-256: `493b07b798b0ad97cc7425819fb6face2e2ceb46eba8833751fecdece1af13b2`.

The linked current-source C runtime was not claimed: the retained build
predates these edits and the available Docker images lack the JSON-C and
Check development headers needed for a current relink. No software was
installed.

No capability was promoted. Full AI-model parser semantics, certified Linux
x86-64, full-size, sanitizer, privileged, production-service, R04 acceptance,
and final release qualification remain open. No remote execution, remote SSH,
usage reset, GitHub workflow action, commit, or push was used.

State: source and host-control verified; linked runtime and certification
evidence remain open.
