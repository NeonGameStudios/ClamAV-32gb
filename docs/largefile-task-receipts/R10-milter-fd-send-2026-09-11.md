# Task receipt: R10 nonblocking milter descriptor send

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: ingress:`milter`

Canonical checkout and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

## Scope and correction

The milter socket is created nonblocking, so `nc_sendmsg()` can encounter
`EAGAIN` while passing a temporary-file descriptor with `SCM_RIGHTS`. The
descriptor-send path now retries interrupted sends, waits for writability
within the existing 30-second connection budget, rejects short successful
sends, and fails closed on timeout or wait errors. The prior nonblocking FIXME
is removed.

## Verification

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- regenerated inventory matches `sh tools/largefile_inventory.sh`.
- `git diff --check` — **passed**.
- current source-manifest SHA-256: `4ec4f450396d56a5ba56183daf0e2a4c666e9c0889c4ee08f753f4cf4d46837f`.

The linked current-source C runtime was not claimed: the retained build
predates these edits and the available Docker images lack the JSON-C and
Check development headers needed for a current relink. No software was
installed.

No capability was promoted. Certified Linux x86-64, full-size, sanitizer,
privileged, production-service, R04 acceptance, and final release
qualification remain open. No remote execution, MCP-SSH, usage reset,
GitHub workflow action, commit, or push was used.

State: source and host-control verified; linked runtime and certification
evidence remain open.
