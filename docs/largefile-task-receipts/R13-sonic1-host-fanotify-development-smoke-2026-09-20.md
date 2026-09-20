# Task receipt: R13 Sonic1 host fanotify development smoke — 2026-09-20

Task ID / parent milestone: `R13` / `R04`.

## Implementation change

The fanotify observer now binds a target event to both the fixture path and
the unprivileged actor PID. This prevents clamonacc's own same-path scan opens
from being mistaken for the actor's kernel permission event.

The runtime runner now arms that observer first, waits for an explicit
readiness file, starts clamd/clamonacc, and releases the actor through a
second handshake file. This makes clean `FAN_ALLOW` and detection `FAN_DENY`
cases independently bindable on kernels where an early denial would otherwise
prevent the late observer group from receiving an event. The focused tests and
source guards cover the PID binding and readiness failure path. The runner's
`AlertExceedsMax` setting now resolves once, defaulting to `yes` while allowing
the roadmap-required alerts-off limit contract without duplicate config keys.

## Sonic1 development evidence

Execution used host `sonic1` with login profile `sonic1-camera-key` on Linux
x86-64 (`5.15.0-190-generic`). The disposable current-source container was
`53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`, image
`clamav-32gb:dev-current`, image ID
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The host used a private 64-MiB tmpfs mount at
`/tmp/clamav-fanotify-mount-20260920`; the actor UID was `65534`.

The rebuilt current-source binaries were the staged `clamd` and `clamonacc`
under `build-roadmap-20260920`, with the synchronized runner scripts. The
runner's bounded development envelope was `MaxFileSize=64M`,
`MaxScanSize=128M`, `MaxTemporarySize=64M`, and `MaxScanTime=60000`; these
values are intentionally not a 32-GiB qualification claim.

Observed prevention cases:

- Clean fixture: observer target event `1`, clamonacc event `1`, structured
  completion `COMPLETE`, actor opened, `FAN_ALLOW`, scan exit `0`.
- Detection fixture: observer target event `1`, clamonacc event `1`, exact
  temporary NDB alert `R13-Fanotify-Detection.UNOFFICIAL` at offset `0`,
  structured completion `DETECTION_TERMINATED`, actor denied, `FAN_DENY`,
  scan exit `1`.
- Limit fixture: a sparse 67,108,865-byte file under a 64-MiB maximum with
  `AlertExceedsMax=no` produced `LIMIT_INCOMPLETE`, actor denied, `FAN_DENY`,
  and scan exit `2`; the report retained the exact MaxFileSize reason and no
  partial scan bytes.
- Monitoring-only clean fixture: actor opened and the structured scan report
  completed without claiming a permission event.

Both prevention runs retained `clamd` startup and pre-cleanup PONG health,
observer readiness, clean daemon/client exits, absent socket and PID files,
and `cleanup.complete=true`. The earlier full-profile attempt remains an
honest admission failure: host temporary free space was
`33614528512` bytes while the required temporary envelope was
`73014444032` bytes.

Selected retained-artifact SHA-256 values:

| Case | Result | Bound kernel | Bound actor | Bound report |
| --- | --- | --- | --- | --- |
| clean | `931991a16890461dd32f1862fdef4efd9cd49df73a3f9fcdb6e04bd0ddc7ecc2` | `4c6a2a12ce4924d440d896b1aa39f1f2e7b7d8f0f8f8e6973e2b1375b72af845` | `995d28ba039e0ad5fd2e786fb05925aa61c26434734f705ded855e55b2e00e5a` | `63daa9720ff3dc947aff3887ceabba4bcb91aaf5a7e58b5f0783bc0b0f2aaaa3` |
| detection | `e0794d9aa989193c1af6c90eb6dfc2acbc2cf7e4d6adb8400680b600ffbb9b78` | `ac56452f761af729e0f912283683ed8b1422a86561aebf912bddea52285e797c` | `2d789e421ea72cc7ecd28f1e0c94339279bf4a843339eda04bdb8ba61e027076` | `0159f40d29815fef38b1c0e67d90c4998c7f5ecbfb914a013bdf787853c63aff` |
| limit | `33540e9e129116c077d84eae32ffcd33663da56b9ee016ee570e76ee2182cf9a` | `e6c89d3a27784d1a41faa992b2bbac0acbdf74d0e170f7ee241f2855151065b5` | `3a4a6278dba66eed9d6e9de2ded11492fd27851c1cccd6d463ed16e3db36e7a3` | `5f46932f0bf22ae4702b7398054727dcd46a71c1b590940f90c3ab1be8ca00a3` |

## Verification and limits

- `largefile_fanotify_capture_test.py` — 8/8;
- `largefile_fanotify_case_binder_test.py` — 5/5;
- `largefile_fanotify_evidence_test.py` — 20/20;
- `largefile_fanotify_runtime_runner_test.py` — 6/6;
- `sh tools/largefile_source_guards.sh` — passed, including the 604-entry
  capability and release-readiness controls;
- `git diff --check` — passed.

This is development verification of two real host prevention outcomes and one
monitoring-only outcome. It does not promote `on-access:permission`: the six
case prevention matrix, timeout/resource/parser cases, full-size resource and
PCRE phases, sanitizer toolchain, certified Linux x86-64, production-CVD
parity, and final release gate remain open. No software was installed or
downloaded, no production deployment was changed, and the routine GitHub push
was intentionally not performed while the new local commit is younger than
the repository's 30-minute batching threshold.
