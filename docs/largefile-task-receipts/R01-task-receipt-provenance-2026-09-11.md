# Task receipt: R01 task-receipt provenance exclusion

Task ID / parent milestone: `R01` / source and evidence provenance

Exact capability kind:id list: release-control provenance; no capability
status changes.

Canonical checkout and branch:

- `<repository-root>`
- `largefile-roadmap-qualification`
- working tree intentionally remains dirty; no existing changes were reset,
  cleaned, committed, or pushed
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`

## Prerequisites verified

The source-manifest helper already excluded the generated dashboard and task
ledger. A receipt-only edit was not permitted to participate in the source
identity because receipts are external run metadata, not executable source,
build settings, fixtures, verifiers, or capability policy.

## Observed gap and expected behavior

`docs/largefile-task-receipts/*` was included in Git-mode source manifests.
Adding or correcting a receipt therefore changed the source identity and could
invalidate otherwise identical build evidence. Receipt changes must leave the
source identity unchanged; source and untracked candidate-file changes must
continue to change it.

## Changes made

`tools/largefile_source_manifest.sh` now excludes the bounded task-receipt
directory alongside the existing dashboard and ledger metadata exclusions.
`tools/largefile_status_snapshot_test.py` now creates and edits a receipt in
its isolated Git repository regression, proving that dashboard, ledger, and
receipt edits do not alter the manifest while executable and untracked source
edits do. `tools/largefile_source_guards.sh` pins the reviewed exclusion.

The post-change working-tree source-manifest SHA-256 is
`c7c8baa7616f7e990ffc41763c92d6ebbd287ced505f8da1735a12a91f323e12` across
1,678 manifest entries. The generated dashboard remains independent of this
run metadata identity.

## Verification

- `python3 -B tools/largefile_status_snapshot_test.py` — **13 passed**.
- `sh tools/largefile_source_guards.sh` — **passed**; 597 capability entries,
  release-readiness tests, acceptance schema/map tests, and all source guards
  passed.
- `sh tools/largefile_source_manifest.sh <repository-root> /private/tmp/clamav-r01-receipt-exclusion-source-manifest.txt` — **exit 0**; SHA-256 matched the identity above.
- `git diff --check` — **passed**.

No compiler, runtime, remote host, remote SSH, installation, usage reset,
GitHub workflow action, commit, or push was used. No capability was promoted.

## Remaining failures / next action

R03 still lacks the authorized certified Linux x86-64 runner and coherent
current-source build. R04/R10 full-size service evidence, R06 materialized
late-content qualification, R07's independent format-8 compiler/artifact,
R09 certified parser/matcher evidence, and R11–R15 release work remain open.

State: `development-verified`; release qualification remains blocked.
