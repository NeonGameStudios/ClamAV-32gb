# R03 Sonic1 durable-transfer state audit — 2026-09-20

Task ID / parent milestone: R03 / current-source staging provenance.

Exact capability kind:id list: none; no capability was promoted.

Starting commit and working-tree/source manifest identity: local candidate
`e8db9f03` (`Record reconciled Sonic1 CTest pass`), clean before this receipt.

The roadmap continuation procedure requires an interrupted durable transfer to
be inspected with both the transfer list and its per-transfer status before any
resume, abort, completion, commit, or retry decision. The inspected transfer
was:

```text
transfer_id: transfer_6a4eecbb392a434297c90ae6f7cbfdea
host: sonic1
login_profile: sonic1-camera-key
destination: /tmp/clamav-32gb-current-20260915/libclamav/matcher.c
expected_bytes: 91904
expected_sha256: 2630ca391c45aa7c4aeb5d2a361266dfc78a388179a6157e96281b8545dbee5c
state: interrupted
cancel_requested: true
next_offset: 0
last_error: SFTP error: No such file: No such file
remote_may_still_be_running: true
```

The status call returned successfully, but it did not establish a recoverable
remote partial or a completed destination. Because the service still reports
that remote work may be running, no mutating transfer action was attempted.
The transfer remains an interrupted, non-authoritative artifact and must not be
used as current-source provenance.

This audit does not change the separate authoritative MCP-SSH
`file_write_limit_exceeded` boundary on the complete current-source staging
transfer. The local candidate remains the only current-source tree; the stale
Sonic1 `/src` tree remains usable only for explicitly labelled development
rechecks. No full-size, sanitizer, fanotify, or release qualification evidence
was produced.

State: development-verified / staging-blocked
