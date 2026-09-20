# Task receipt: R13 Sonic1 host fanotify development smoke — 2026-09-20

Task ID / parent milestone: `R13` / `R04`.

## Implementation change

The fanotify observer now binds a target event to both the fixture path and
the unprivileged actor PID. This prevents clamonacc's own same-path scan opens
from being mistaken for the actor's kernel permission event. The passive
observer runs in fanotify's `PRE_CONTENT` class so it retains fast denial
events before clamonacc's authoritative `CONTENT` group completes; it always
replies `FAN_ALLOW` and does not replace clamonacc's decision.

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
- Resource fixture: the clean fixture under a development-only
  `MaxTemporarySize=2` limit produced `RESOURCE_FAILURE`, actor denied,
  `FAN_DENY`, and scan exit `2`; the report retained status `35` and the
  exact temporary-storage-limit reason. A one-byte variant reproduced the
  same resource result but exposed a timing-only observer miss, so it was not
  used as the bound case.
- Timeout fixture: the clean fixture under a development-only
  `MaxScanTime=1` limit produced `LIMIT_INCOMPLETE`, actor denied, `FAN_DENY`,
  and scan exit `2`; the report retained status `21` and the exact
  `Heuristics.Limits.Exceeded.MaxScanTime` reason. The fanotify contract now
  follows the established public `CL_ETIMEOUT` mapping instead of treating a
  configured deadline as an uncategorized application abort.
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
| clean | `931991a16890461dd32f1862fdef4efd9cd49df73a3f9fcdb6e04bd0ddc7ecc2` | `16d8a023c16aa49e2f2a4f82e83313ee164c53777820175c6273593be2f3b0e0` | `995d28ba039e0ad5fd2e786fb05925aa61c26434734f705ded855e55b2e00e5a` | `75548758375824439d2545977752595cd4d12a47288878e3d7f0dfc51a1358fa` |
| detection | `e0794d9aa989193c1af6c90eb6dfc2acbc2cf7e4d6adb8400680b600ffbb9b78` | `700fd41121beb5c43cfdf49a52ef6f5573dd1e5467637eab3fc94cf7fdc2d7a4` | `2d789e421ea72cc7ecd28f1e0c94339279bf4a843339eda04bdb8ba61e027076` | `0159f40d29815fef38b1c0e67d90c4998c7f5ecbfb914a013bdf787853c63aff` |
| limit | `33540e9e129116c077d84eae32ffcd33663da56b9ee016ee570e76ee2182cf9a` | `269db112d76c71a7cfb8edd166b0794447a1d7cf7956996f5a71390d7e2f64b6` | `76f3c94ad9b804dee4e4a9f3c25306b6f1d1c3d0f8daa6645b4dc49d3ce18e0b` | `04a565650fa7d70488cca6d2f16efaea58f9d02a4b58e7ea168888f38aab0296` |
| resource | `91dde7be109b11deb992bc4dea388c5843465b52b229591bcec7c85670769320` | `6f41d5d92e3ae7b989ed9fc78c61b7eda2343d2f44a7a7c071a5f70acf907bac` | `0a8d243535d91b0b05c66e69b4ed1b3ae0621b9bbd700431e7130e1d65ccd306` | `a466ccfbbec62a3845cbbe511cc421ed11d793ead473b28dad106090ce301c03` |
| timeout | `2006cb9f2dde9845f73eed412ed2a174aad45640a80b01e3cdbb301967195d73` | `d2e0b73de4e74968d6cca0ec16e304773a03dadfbc1b57b26b44af439e1b242b` | `af3ff6b454818eb34b0abf29df626bd12a7f4f3c53787e415d28f28397786f50` | `c3bca243f3a97ef21f3f19b66ef55128e4fb0183b0fb1a3a1cf8a0c384f10333` |
| parser | `a0d35c58b0032ac1b6d58e3c0e8b59e872a0558c4bbbcf71f9f303fef46a3d67` | `e53fb303b2ed5ad3f5d1f3e5e4b7316714039883ab985e0837a731bf1450d7c4` | `016e2b6309f147e6efb990a1ee8a743a4faed1fc5195a80c0001ad11164aa975` | `281e675018273c5c567c3f6815e5857377e3731c717e6b60b59fac14fdfd2e27` |

## Verification and limits

- `largefile_fanotify_capture_test.py` — 8/8;
- `largefile_fanotify_case_binder_test.py` — 5/5;
- `largefile_fanotify_evidence_test.py` — 21/21;
- `largefile_fanotify_runtime_runner_test.py` — 6/6;
- `sh tools/largefile_source_guards.sh` — passed, including the 604-entry
  capability and release-readiness controls;
- `git diff --check` — passed.

This is development verification of all six real host prevention outcomes and
one monitoring-only outcome. It does not promote `on-access:permission`: the
full-size resource and
PCRE phases, sanitizer toolchain, certified Linux x86-64, production-CVD
parity, and final release gate remain open. No software was installed or
downloaded, no production deployment was changed, and the routine GitHub push
was intentionally not performed while the new local commit is younger than
the repository's 30-minute batching threshold.
