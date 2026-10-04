# R01 Git-less source-package guard parity — 2026-09-26

Task ID / parent milestone: R01 — snapshot and evidence provenance

Exact capability kind:id list: coordinator provenance control; no capability promotion

Starting commit and working-tree/source manifest identity: commit `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; dirty qualification tree; superseded v7 manifest SHA-256 `acd1fcc3deb563f21e315bf0d0c868e83b4a00d4ca932727ca22163fa5c65be7`

Prerequisites verified: the tracked checkout passed `largefile_source_guards.sh`; the source-manifest helper intentionally excludes `32gb-current-snapshot.md` as generated bookkeeping; a pristine v8 package extraction reproduced the source manifest but failed the guard suite solely because the excluded dashboard was absent.

Owned files and excluded shared files: `tools/largefile_source_guards.sh`; no release evidence or capability status was edited.

Observed failing case and expected behavior: a Git-less immutable source package must validate from its content-bound manifest without requiring an out-of-band copy of excluded dashboard metadata. A Git checkout must still fail if its tracked dashboard is missing or stale.

Changes made: the source guard now checks the saved dashboard when present, rejects a missing dashboard in a Git checkout, and in a Git-less package regenerates the dashboard to stdout to validate all bound inputs without adding it to source identity.

Commands, exits, logs and fixture/database hashes:

- `sh -n tools/largefile_source_guards.sh` — exit 0.
- `python3 -B tools/largefile_status_snapshot_test.py` — 15/15 passed.
- `sh tools/largefile_source_guards.sh` in the tracked checkout — exit 0.
- Deterministic v9 source manifest — 1,711 entries, 176,613 bytes, SHA-256 `e67d00f1376f5cddd764ed4c98bc18073a75464178b4d0dddc0195aa02f6fdda`.
- Deterministic v9 package and independent repeat — 18,378,886 bytes, identical SHA-256 `68e914ba28a884573ed1c755a2869a75bb2c23d7f0b8ff717d2fe00ca6b5b3b2`.
- Clean v9 extraction regenerated the byte-identical source manifest and passed the complete source-guard suite without `32gb-current-snapshot.md`.
- MCP-SSH durable staging transfer `transfer_c30a04d17f1c4f5f95188a95d04f1688` reached `source_ready` with the expected package size and SHA-256. Remote resume was intentionally withheld.

Development tests passed: tracked and pristine Git-less source guards; deterministic package repeat; extracted-manifest equality; `git diff --check`.

Full-size/certified evidence produced, or explicitly not run: no new full-size or certified runtime evidence. Sonic1 still timed out during SSH Connect while the prior RAM-writer job remained unreconciled.

Remaining failures / next slice: reconcile job `job_27525a5bf28d4fa9aa673d45f7a05bea`; only then resume and commit the v9 transfer. Transfer `transfer_70485937d756408387bd2d055d753956` is superseded v7 source and must never be resumed or committed.

State: development-verified
