# Task receipt: R10 on-access descriptor reply timeout

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: ingress:`on-access`

Canonical checkout and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

## Scope and correction

The descriptor-backed on-access reply reader now honors its configured timeout
before each blocking `recv()` by using the same socket readiness helper as the
curl-backed reader. Timeout and select failures retain distinct internal
status, allowing the caller to report `CL_ETIMEOUT` versus `CL_EREAD`.

The reader also now captures the signed `recv()` result before assigning the
successful byte count to its unsigned buffered-length field. This makes EINTR,
negative reads, EOF, and partial-line handling defined instead of allowing a
negative result to wrap to a large `size_t` value.

## Verification

- Existing Docker toolchain syntax check with `-Wall -Wextra -Wformat-security` — **passed with no warnings** for `clamonacc/client/communication.c`.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- regenerated inventory matches `sh tools/largefile_inventory.sh`.
- `git diff --check` — **passed**.
- current source-manifest SHA-256: `133ccef558ef5cb9df05ab884e4516c49a8f9867d25f260088230eba7a9ac3aa`.

A wider changed-ingress syntax sweep could not proceed past the missing
JSON-C development header in the existing Docker image; no dependency was
installed. No current-source linked on-access runtime was claimed.

No capability was promoted. Certified Linux x86-64, sanitizer, privileged
on-access execution, full-size service parity, R04 acceptance, and final
release qualification remain open. No remote execution, MCP-SSH, usage reset,
GitHub workflow action, commit, or push was used.

State: source and host-control verified; linked runtime and certification
evidence remain open.
