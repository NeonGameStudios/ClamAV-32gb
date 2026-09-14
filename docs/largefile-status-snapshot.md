# 32 GiB roadmap snapshot

The authoritative, current snapshot is [../32gb-current-snapshot.md](../32gb-current-snapshot.md).

This compatibility file is intentionally not a second generated dashboard;
keeping a duplicate here allowed its counts and hashes to become stale. Use
the canonical snapshot and its freshness check:

```sh
python3 tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md
```
