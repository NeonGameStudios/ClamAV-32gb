# Task receipt: R09 fuzzy-image Release integration — 2026-09-13

Task ID / parent milestone: `R09` / `R00`.

Exact capability kind:id list: `matcher:fuzzy-image`.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`.
No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used.

Environment: the fresh current-source ARM64 Release build in Docker at
`/tmp/clamav-release-current-20260913` was used with its linked `clamscan`
executable and static/shared runtime dependencies. The test was run from the
repository's `unit_tests` directory with the existing Python integration
harness and no Valgrind substitution.

Verification command:

```text
python3 -m unittest clamscan.fuzzy_img_hash_test --verbose
```

Result: 4/4 tests passed with zero failures and zero errors:

- valid fuzzy-image signatures matched through the `clamscan` application,
  including an exact match and a second-subsignature all-match case;
- the `--scan-image-fuzzy-hash=no` and `--scan-image=no` controls suppressed
  the fuzzy-image result;
- malformed hash input was rejected with the expected database error;
- a one-bit-near hash matched at distance one while a two-bit-near hash did
  not.

Qualification boundary: this is current-source ARM64 Docker Release
development evidence. It does not prove certified Linux x86-64 execution,
production CVD/service behavior, a materialized 32-GiB image, sanitizer or
resource qualification for this application test, Sonic1 execution, or final
release qualification. No capability was promoted.

State: `development-verified`; scanner-facing fuzzy-image application
integration passed on the fresh current-source Release build.
