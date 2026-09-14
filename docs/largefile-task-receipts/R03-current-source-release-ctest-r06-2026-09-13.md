# R03 current-source Release matrix revalidation after R06 — 2026-09-13

Task ID / parent milestones: `R03` / `R06`.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`c75877cc35ffc2d86a4a7c086cc2a51a80e026ec96a5e047ec223e98942246d9`.

Purpose: revalidate the full current-source Release application matrix after
the R06 OneNote test gained its post-scan temporary-ledger release assertion.

Environment and build:

- Existing Docker container `clamav-current-rust-build-20260911` was reused;
  no software was installed.
- Existing ARM64 Release tree `/tmp/clamav-release-current-20260913` was
  reconfigured against the current checkout and rebuilt.
- CMake cache SHA-256:
  `896566415d30f389249b746b177d369132e48f12fdd2b201114cbfdbef69b175`.
- `check_clamav` SHA-256:
  `395d236f58f664a2cd8bbe8718e3e1e14fc4c563d2764024ae32f75c0581f067`.
- Application hashes were retained from the rebuilt tree: `clamscan`
  `3a59979b9987600aaf9590cece8ac51bd9e508d99808a652a73c61d0c89c754b`,
  `clamd` `59ba066ee121c15a1792008be6f5b2973db311e7cb2e448a98c69a891e164c6d`,
  `clamdscan` `c977d808601e6f8c22fc93f3dee399d1be0d2a7e44783369993e639ef6c080b9`,
  `clamav-milter` `d2244c5805b384dad3e84188c80452ae0c08358a5d86cc7feea3bfe20e28cc0d`,
  `freshclam` `8daad5f527c8fafc71bbf102923c652513d4f4604ada85942bd9706dac55bd9a`,
  and `sigtool` `e1c02b25cf807bcedbbdee52d8ebaecf789c61937e755575630909d2c1c2601a`.

Verification:

- Command: `ctest --output-on-failure` from the Release tree.
- Result: 28/28 tests passed in 187.23 seconds.
- The matrix included the complete `libclamav` suite (2,919 checks, zero
  failures/errors), all large-file controls and verifiers, Rust, `clamscan`,
  `clamd`, `clamdscan`, both milter targets, `freshclam`, and `sigtool`.

Qualification boundary: this is current-source ARM64 Docker development
evidence only. It does not prove certified Linux x86-64 execution, exact
32-GiB/materialized resources, production CVD/service behavior, privileged
fanotify permission events, Sonic1 execution, independent bytecode format-8
execution, or final release qualification. No capability was promoted.

State: `development-verified`.
