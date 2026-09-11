# Task receipt: R10 on-access report-command length hardening

Task ID / parent milestone: `R10` / `R00`

Scope: make private on-access report-command construction fail closed for
length arithmetic and formatting failures without changing the wire protocol.

Changes made:

- Added checked `size_t` arithmetic for the command prefix, path, and NUL
  terminator.
- Replaced the unbounded `sprintf` call with `snprintf` and rejected negative
  or truncated formatting results before transport.
- Added source guards that require the checked construction and forbid the old
  `sprintf` path.

Commands and results:

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — exit 0,
  145 tests passed, 2 expected skips.
- `/usr/bin/cc -fsyntax-only -std=c11 -DHAVE_CONFIG_H=0 -I. -Icommon
  -Ilibclamav -Iclamonacc -Iclamonacc/client clamonacc/client/protocol.c` —
  blocked before translation-unit parsing because the host lacks
  `openssl/ssl.h`.
- `sh tools/largefile_inventory.sh` — exit 0; refreshed 597-capability
  inventory.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — exit 0.
- `git diff --check` — exit 0.
- `sh tools/largefile_source_guards.sh` — exit 0; all source, schema,
  producer, service, protocol, boundary, and acceptance-map guards passed.

Limitations:

- No coherent current-source C build, certified runner, full-size materialized
  evidence, Docker/MCP-SSH execution, or R04 qualification record is claimed.

State: `development-verified`; release readiness remains blocked.
