# R37 production-database source review — 2026-11-08

## Source review

The separately versioned R37 V2 candidate's complete 2,034-entry source manifest verifies. Manifest-file SHA-256: `c4f10700877778b0784c1bd2b23140d9e1c2f3ea7f00a84a0d1aba405b4b922c`.

The Linux-only opt-in attestation wiring installs a non-filtering sigload callback only for consumed-RAM scans. The V2 record reports parsed callback events and `cl_load`'s loaded-signature total separately; it does not claim those totals reconcile. The production verifier expects this V2 schema and separately checks the pinned complete database inventory.

Critical source SHA-256 values:

- `clamscan/manager.c`: `e31a712db6815271b86164bb554be7f86ec929b90e0e94e0dbc76beac5366318`
- `clamscan/CMakeLists.txt`: `f41e85aaa76f9584ca9fb7013f93946e94b1accb5b1cbb1ea486e01ed5735a9e`
- `clamscan/ram_db_load_attestation.c`: `2425cbbefb6325537b8543589345243a909a5d23cf67e929604a6edce78685ad`
- `clamscan/ram_db_load_attestation.h`: `c17b921f86497dedaa84e95fa7c140b7017728de3828c3284305ff8c213db56c`

A separate dirty checkout still emits V1 attestation output and does not match the V2 verifier. Its existing changes were preserved.

## Qualification status

No build, ClamAV test, production database load, or scan ran for this review. The production-database runtime launch package remains unfinished. The strongest integrated Stored-ZIP result remains the 960-MiB synthetic control; exact-32-GiB raw/Stored scans and the 48/40-GiB profiles remain unqualified.

A 07:51 UTC Sonic1 preflight deferred the single FreshClam attempt: host nonfree was 48.1738 GiB, while the 2-GiB worker plus 128-MiB supervisor projected 50.2988 GiB before the required reserve. No updater request was made; the attempt remains unused pending a fresh passing preflight.

The full static source review is preserved in the qualification workspace with SHA-256 `584baee3c6cdda0813d2d5c64c8f47bba3a39bc5e6bc79d9c00600f6cb9502db`. The active qualification goal remains open.
