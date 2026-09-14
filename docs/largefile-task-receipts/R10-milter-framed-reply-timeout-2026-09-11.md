# Task receipt: R10 milter framed-reply and indefinite-timeout semantics

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: ingress:`milter`

Canonical checkout and branch:

- `<repository-root>`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

## Scope and correction

The milter structured-report ingress now enforces the one-report framing
contract: after one JSON report, a second report frame is rejected rather than
merged into the first result. This prevents contradictory or duplicated
outcomes from being treated as authoritative.

`ReadTimeout=0` now uses an explicit zero sentinel and leaves the socket read
blocking indefinitely, as documented. Deadline checks are performed only for
nonzero timeout values; the previous implementation compared the current time
against a deadline equal to the current time and failed immediately.

## Verification

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- regenerated inventory matches `sh tools/largefile_inventory.sh`.
- `git diff --check` — **passed**.
- current source-manifest SHA-256: `bff47fe203f641e0a094c4bbfb66ef835723d64d1904e3cc223b317c31da29f6`.

The linked current-source C runtime was not claimed: the retained build
predates these edits and the available Docker images lack the JSON-C and
Check development headers needed for a current relink. No software was
installed.

No capability was promoted. Certified Linux x86-64, full-size, sanitizer,
privileged, production-service, R04 acceptance, and final release
qualification remain open; release readiness remains blocked. No remote
execution, remote SSH, usage reset, GitHub workflow action, commit, or push was
used.

State: source and host-control verified; linked runtime and certification
evidence remain open.
