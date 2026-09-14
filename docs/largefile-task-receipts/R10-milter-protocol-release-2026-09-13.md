# Task receipt: R10 milter protocol Release integration — 2026-09-13

Task ID / parent milestone: `R10` / `R00`.

Exact capability kind:id list: `ingress:milter`.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`.
No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used.

Environment: the fresh current-source ARM64 Release build in Docker at
`/tmp/clamav-release-current-20260913` was exercised through the registered
`clamav_milter_protocol` CTest. The CTest environment bound the production
`clamd`, `clamav-milter`, and current linked libraries, with
`MILTER_DEVELOPMENT_LEGACY_LIMITS=1` as configured by the repository test
profile. That profile uses the bounded 100 MiB development message limit;
the test does not claim the literal 32-GiB certified milter run.

Verification command:

```text
ctest --test-dir /tmp/clamav-release-current-20260913 -V -R '^clamav_milter_protocol$'
```

Result: CTest passed 1/1 in 5.38 seconds. The verbose harness reported the
four expected protocol outcomes:

```text
{'clean': 'a', 'infected': 'r', 'exact_limit': 'a', 'limit_plus_one': 't'}
```

This verifies current-source libmilter framing, clamd communication, clean
acceptance, malware rejection, exact configured-limit acceptance, and
limit-plus-one fail-visible handling through the application pair.

Qualification boundary: this is current-source ARM64 Docker Release
development evidence with the 100 MiB development profile. It does not prove
the literal 32-GiB milter wire case, exact materialized resources, certified
Linux x86-64 execution, production CVD/service behavior, sanitizer/resource
qualification for this protocol run, Sonic1 execution, or final release
qualification. No capability was promoted.

State: `development-verified`; current-source Release milter protocol
integration passed with all four expected outcomes.
