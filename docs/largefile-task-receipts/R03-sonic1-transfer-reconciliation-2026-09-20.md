# R03 Sonic1 transfer reconciliation — 2026-09-20

Task ID / parent milestone: `R03` / `R01`

## Scope

Reconcile the MCP-SSH durable-transfer ledger after the previously recorded
current-source `file_write_limit_exceeded` boundary. This is read-only state
inspection; no transfer was resumed, canceled, committed, or retried.

## Access and ledger state

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Host inventory and connection description succeeded.
- The ledger contains 173 transfers for this host/profile:
  `committed=72`, `complete=36`, `ready_to_verify=11`, `interrupted=39`,
  `error=9`, `failed=3`, `integrity_failed=2`, and `aborted=1`.
- A recent 520-byte legacy fixture upload completed successfully, showing that
  small legacy operations can finish; this is not current-source evidence.

## Candidate-relevant findings

- `transfer_86fa31547d5644a49e38bbc78519cde0` is a 2,131,060-byte legacy
  patch in `ready_to_verify`, with no expected SHA-256. It targets an older
  `aa6-to-7633c81d` patch and is not the current candidate; it was not applied.
- Its companion `transfer_f1eb3fff28b74b99b64c1191f9b3a5fd` failed before write
  with `No such file`.
- `transfer_6a4eecbb392a434297c90ae6f7cbfdea` is an interrupted 91,904-byte
  `matcher.c` upload against the stale `clamav-32gb-current-20260915` tree;
  it was not resumed.
- The previously committed 1-MiB segments for the September 15 stale source
  remain historical artifacts and do not identify the current checkout.
- No complete transfer of the current local candidate, with a current source
  manifest and checksum, is present in the ledger.

## Result

The transfer service has not cleared the current-source staging prerequisite.
Small legacy success does not change the release gate: current-source Sonic1
qualification remains externally blocked until a complete, checksum-bound
candidate can be staged and verified. No software was installed, no source
was mutated remotely, and no usage reset was used.

State: `blocked-external-prerequisite`
