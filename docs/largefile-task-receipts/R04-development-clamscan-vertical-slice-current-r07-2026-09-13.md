# Task receipt: R04 current-source Release `clamscan` vertical slice after rebind

Task ID / parent milestones: `R04` / `R03`, `R10`, `R11`.

The source-aligned ARM64 Release `clamscan` at
`/tmp/clamav-release-current-20260913/clamscan/clamscan` generated six fresh
small-fixture R04 records using the repository signing-certificate directory.
The records bind source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`, build
identity SHA-256
`bf0a1dd63535bd868bfae91fc389eee741472f9164dd8e5d709bbfee7e095036`, and
CMake cache SHA-256
`1f125879914959b31775438b6dbd865a1bf45e219c587c92ecd424df1d5b45e9`.

The six records cover file and stdin ingress for:

- clean completion (`COMPLETE`), 2 records;
- exact custom-signature detection (`DETECTION_TERMINATED`), 2 records; and
- exact MaxFileSize rejection (`LIMIT_INCOMPLETE`), 2 records.

The producer exited 0, wrote six records, and independently validated them
against the current capability map and retained artifacts. The acceptance TSV
SHA-256 is
`5b844e5803e3322f7b86c38d6c7236f193bd3ca700286837be4872216c30a342`.

This is small-fixture ARM64 development evidence only. It does not prove
exact 32-GiB/materialized ingress, certified Linux x86-64 resource limits,
production CVD, privileged fanotify, Sonic1, or final release qualification.
No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
