# Task receipt: R10 current-source daemon rebuild and integration

Task ID / parent milestone: `R10` / `R03`

Scope: rebuild the application-facing `clamscan`, `clamd`, `clamdscan`, and
`check_clamd` targets from the canonical checkout and exercise the daemon
integration path in the disposable ARM64 development environment. This is
development evidence only; it does not qualify a capability or replace the
authorized Linux x86-64 runner.

Canonical source and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- `HEAD`: `41cde8160286813f0f98e109c1450e40ff4117fb`
- working tree intentionally remained dirty; no reset, commit, or push

Prerequisites and environment:

- Existing disposable image: `clamav-largefile-local-toolchain2:latest`
- Container architecture: Linux ARM64
- Build directory: `/private/tmp/clamav-largefile-build`
- Missing C/C++ development headers were installed only inside the disposable
  container: OpenSSL, zlib, json-c, PCRE2, curl, milter, Check, and Subunit.
- The build used the canonical checkout mounted at `/src`; no remote runner or
  production service was contacted.

Changes made:

- No repository source changes were made in this slice.
- The disposable build was repaired and rebuilt from the current source so the
  application binaries were available for runtime verification.

Artifact identities:

- `clamscan`: `81e20a8f7d23a0f0ecbbbdbf8fa321599204133c768c6fe7c5ffb01b9c1165f7`
- `clamd`: `26544a9402d58be3aab134e9d16e8c0d51c4acfcb2620d168802c463f1aa83b8`
- `clamdscan`: `ff445b50e04876a5ba9f5cbfdf25c69568662cce21ae9b26dd33f5c2b3a38b21`
- `check_clamd`: `22bd715ea5a1a7ef1671aa9bc7021e8f82c68f538228a656239923a8c7025e45`
- `CMakeCache.txt`: `9aa2f74db82662e6378a9f7644b2b4369eb699c28c0e94d23b8a368abc85298f`

Commands and actual results:

- `cmake --build . --target clamscan check_clamav -j2` — `clamscan` built;
  the aggregate `check_clamav` target was not built because this existing
  shared-library configuration exposes wrapper-only test declarations that
  are enabled only for the static Linux test shape.
- `clamscan --version` — exit 0, `ClamAV 1.5.3-largefile-devel`.
- `clamscan` with `unit_tests/input/clamav.hdb` against the repository test
  executable — exit 1 with exact `ClamAV-Test-File.UNOFFICIAL FOUND`.
- `clamscan` with the same database against `README.md` — exit 0 with `OK`.
- `cmake --build . --target clamd clamdscan check_clamd -j2` — exit 0.
- Focused `clamd_test.TC.test_clamd_05_check_clamd` — exit 0; Check client
  suite reported 111 checks with zero failures or errors.
- Full `clamd_test.TC` — exit 0; 15 tests passed in 29.529 seconds.

The full daemon integration covered ping/version, reload, file/stream/fdpass/
multiscan clients, structured and limit paths, OneNote policy, and shutdown
cleanup. The daemon emitted the current capability-manifest line with
`large_file_ceiling=34359738368`, `logical_scan_ceiling=68719476736`,
`matcher_work_ceiling=274877906944`, and `temporary_ceiling=68719476736`.

Limitations / next action:

- This is ARM64 development verification with test signatures and default
  development-sized runtime inputs. It is not certified x86-64 Release or
  sanitizer evidence, not a 32-GiB materialized run, and not fanotify proof.
- The next release-critical action remains obtaining the authorized Linux
  x86-64 runner, then rebuilding Release and sanitizer candidates and binding
  their real records to the existing R04 matrix.

State: `development-verified`
