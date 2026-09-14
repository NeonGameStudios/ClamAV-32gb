# Task receipt: development capture trust-root default

Task ID / parent milestone: `R04` follow-up

Exact capability kind:id list: the six development `clamscan` cases for
`clamscan:file` and `clamscan:stdin` (clean, detection, and limit).

Starting commit and working-tree/source manifest identity:

- canonical source: `<repository-root>`
- branch: `largefile-roadmap-qualification`
- working tree was intentionally dirty and preserved
- the capture generated source-manifest SHA-256
  `d90bb48391837b351aad61cb5b6be61dff8cd483b2fadb98f26124ef153eb9bc`

Prerequisites verified:

- current-source ARM64 `clamscan` and shared libraries were available in
  `/private/tmp/clamav-32gb-docker-build`
- the existing repository trust root at
  `unit_tests/input/signing/verify` was present
- runtime packages were installed only inside the disposable Docker
  container; no host software or remote server was used

Owned files and excluded shared files:

- owned: `tools/largefile_development_acceptance_capture.py`, its focused
  test, and source-guard assertions
- excluded: scanner trust behavior, authoritative acceptance records,
  release readiness, and certified runner evidence

Observed failing case and expected behavior:

- omitting `--cvd-certs-dir` from the current-source capture caused the
  scanner to reject its missing default `/usr/local/etc/certs` directory
  before producing a report
- the repository development producer should select its existing test CA by
  default, while a supplied CA path must remain explicit and valid

Changes made:

- added `resolve_cvd_certs_dir()` to default to
  `unit_tests/input/signing/verify`
- invalid or symlinked trust roots now fail before any scan case starts
- updated the CLI help and added default/explicit/missing-directory tests

Commands, exits, logs and fixture hashes:

- `python3 -B tools/largefile_development_acceptance_capture_test.py`: exit
  0, 2/2 passed
- `python3 -B tools/largefile_development_service_capture_test.py`: exit 0,
  6/6 passed
- real current-source disposable ARM64 capture without
  `--cvd-certs-dir`: exit 0, wrote 6 records
- independent acceptance verifier: exit 0, all 6 records accepted
- build identity SHA-256:
  `bbb93131d6db7a67bab6b6cdf222fbbc4e2253cbd0b84ea86f687ca7dc849c23`
- acceptance record SHA-256:
  `5c83642a2dbd373eaf7d06e82eb817a150e4fbca0485ed3c055306d7ce0c6f1e`

Development tests passed:

- file and stdin clean cases returned `COMPLETE` / exit 0
- file and stdin detection cases found the exact unofficial signature at
  offset 25 / exit 1
- file and stdin limit cases returned the exact MaxFileSize reason / exit 2
- all records retained the repository default trust root indirectly through
  the successful signed-database load and bound current source/build/report
  identities
- the full tools suite, source guards, snapshot check, and diff check remain
  required after this producer-only change

Full-size/certified evidence produced, or explicitly not run:

- no 32-GiB materialized edge, Linux x86-64, sanitizer, production CVD,
  privileged fanotify, or release qualification evidence was produced
- this is ARM64 disposable development evidence only

Remaining failures / next slice:

- obtain the authorized Linux x86-64 runner and feed the same explicit trust
  root into the certified producer; authoritative readiness remains blocked

State: `development-verified`
