# R02 structured-report parser follow-up

Task ID / parent milestone: `R02` structured report and client boundary

Exact capability kind:id list: report/client boundary controls in the
existing clamd structured-report path; no capability row is promoted by this
slice.

Starting commit and working-tree/source manifest identity:

- canonical checkout: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- branch: `largefile-roadmap-qualification`
- starting HEAD for this slice: `41cde8160286813f0f98e109c1450e40ff4117fb`
- working tree intentionally remained dirty; pre-existing changes were
  preserved
- refreshed derived inventory SHA-256:
  `481a33d06be4121fb1dcda5f0919a8333dc274816c45086520d5b35d811fba2f`

Prerequisites verified:

- current source was read from the canonical checkout
- the existing ARM64 development build tree and disposable toolchain image
  were available
- no certified Linux x86-64 runner or privileged fanotify environment was
  available

Owned files and excluded shared files:

- owned: `common/clamdcom.c`, `unit_tests/check_clamd.c`, and this receipt
- excluded: capability status promotion, release evidence, GitHub workflows,
  commits, pushes, and remote execution

Observed failing case and expected behavior:

`scan_report_json_status()` accepted a numeric or string infected/incomplete
verdict when its `completion` field contained an unknown label. A structured
report must reject an unknown completion, and an infected verdict must use
`DETECTION_TERMINATED`; an explicitly incomplete string verdict must use a
non-detection incomplete class.

Changes made:

- added strict recognition for the seven completion names emitted by the
  current report schema
- required `DETECTION_TERMINATED` for numeric and string infected verdicts
- restricted explicit string incomplete completions to
  `LIMIT_INCOMPLETE`, `UNSUPPORTED`, `MALFORMED_CONFIRMED`,
  `RESOURCE_FAILURE`, or `APPLICATION_ABORT`
- added four regressions covering unknown and contradictory completion values

Commands, exits, logs and fixture/database hashes:

- disposable ARM64 rebuild of `check_clamav`: exit 0, target built
- disposable ARM64 rebuild of `check_clamd`: exit 0, target built
- `CK_FORK=no CK_RUN_SUITE=clamd CK_RUN_CASE="option parser" ./check_clamd`:
  exit 0, 27 checks, 0 failures, 0 errors
- `git diff --check`: exit 0
- `sh -n tools/largefile_source_guards.sh`: exit 0
- regenerated `docs/largefile-inventory.tsv`; inventory comparison passed

Development tests passed:

- current-source `check_clamav` TCases: `onenote` 2/2,
  `pdf_corpus` 1/1, `zip` 19/19, `mail` 16/16, `rust_onenote` 2/2
- `sh tools/largefile_source_guards.sh`: exit 0; 597-row manifest and all
  local evidence controls passed

Full-size/certified evidence produced, or explicitly not run:

No full-size or certified evidence was produced. No Linux x86-64 Release or
sanitizer build, production database run, 32-GiB materialized fixture,
privileged fanotify run, or final canary was run.

Remaining failures / next slice:

The local report boundary is development-verified. R02 still requires
authentic certified client/daemon output and phase/resource evidence. R03 is
blocked on the authorized x86-64 runner; R06 remains blocked on a reviewed
reader-backed modern OneNote API boundary; release readiness remains blocked.

State: `development-verified`

Development service capture (2026-09-08): the purpose-built current-source
capture wrote and validated 24 R04-bound structured-report records. It covered
the six direct daemon commands (`SCAN`, `CONTSCAN`, `MULTISCAN`, `ALLMATCHSCAN`,
`INSTREAM`, and `FILDES`) across clean, detection, and limit outcomes, plus
fdpass and stream client paths across the same three outcomes. The retained
development artifact is outside the repository at
`/private/tmp/clamav-r02-service-capture`; its provenance hashes are:

- `acceptance-cases.tsv`: `39d2896df6f919785011b5c0831b5fdbf389ff1080d1c6420a515568b69ebae4`
- `source-manifest.txt`: `934fb12fcc12144d5008de440a5124deeaf09ab4faa94de1436fd1da9a9fb79a`
- `build-identity.txt`: `fec47b69cfefa7bcacb0ba348f083ef26b2ab4b98d47f743612d5c861c141c47`

The capture's validator accepted all 24 records. This is stronger local
daemon/report evidence, but it is not a full-size, certified, or release
qualification record.
