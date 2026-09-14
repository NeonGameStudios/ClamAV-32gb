# R01 provenance revalidation — 2026-09-13

Task ID / parent milestone: `R01` / `R00`.

## Current checks

- `python3 -B tools/largefile_status_snapshot_test.py` — **13/13 passed**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **exit 0**.
- `sh tools/largefile_source_manifest.sh <repository-root> /tmp/clamav-source-manifest-check-20260913.txt` — **exit 0**.
- The current Git-mode source manifest contains **1,697 files** and has SHA-256
  `8bc6ca7cb824cfd13e3e6980a79d053503d9df9a475e6d90f23c0392f82aeb34`,
  matching the current Release and ASan/UBSan build identities.

## Interpretation

The tracked dashboard remains deterministic across Git `HEAD` changes because
it excludes `HEAD` from generated text. The source revision and input hashes
remain external run provenance, and generated dashboards, task receipts, and
the task ledger remain narrowly excluded from executable source identity.
Untracked candidate source/helpers remain included, so they cannot silently
escape the build manifest. This revalidates R01's provenance contract; it does
not qualify any capability or change the blocked release gate.

No usage reset, installation, commit, push, workflow action, or remote
mutation was performed.
