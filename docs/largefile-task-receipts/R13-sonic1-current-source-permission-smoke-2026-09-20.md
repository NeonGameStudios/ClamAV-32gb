# Task receipt: R13 Sonic1 current-source permission smoke — 2026-09-20

Task ID / parent milestone: `R13` / `R00`.

Scope: exercise the exact current-source Linux x86-64 `clamd`/`clamonacc`
pair against real unprivileged opens in one disposable privileged Docker
runtime. This smoke covers one clean prevention allow and one detection
prevention deny. It is development evidence only and does not claim the full
R13 matrix or release qualification.

## Runtime identity and admission boundary

- host: Sonic1, Linux `x86_64`, accessed with the `sonic1-camera-key` login
  profile;
- source HEAD: `aa6c0077130c9f7aefd8d366aa9a689ffc6c87fe`;
- source manifest SHA256: `f7be88d8961ee5e5546e5fbcf44374a70c083deccbb34ba867547a9cd6aacf8f`;
- image: `clamav-32gb:dev-current`, image ID
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`;
- source container: `clamav-current-7f3458c4`, container ID
  `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`;
- build: the exact existing Release build from that container, staged
  temporarily at `/tmp/clamav-7f3458c4-release-build` and removed after the
  run;
- runtime: `docker run --rm --privileged`, a private `/watch` tmpfs, and
  `OnAccessIncludePath /watch`; fixture creation and service startup used the
  excluded setup actor, while file opens used `nobody`.

The host preflight had already passed for this run: 12 CPUs, 62,282,008 KiB
effective available memory against the 50,331,648 KiB minimum, no finite
cgroup memory limit, and 37,088,712 KiB free filesystem space. The separate
Sonic1 sanitizer toolchain preflight remains blocked because `clang`/`clang++`
and a Rust nightly toolchain are unavailable.

## Prevention observations

The final tracked Docker job was `job_f9e2d5978fe479abc679050f397301a`.
`clamd_alive=true` and `clamonacc_alive=true` were observed before the wrapper
performed its cleanup.

- Clean fixture `/watch/clean.bin`: the unprivileged actor exited `0`, printed
  `allowed`, and the retained fanotify evidence recorded
  `event_kind=FAN_OPEN_PERM`, `permission_response=FAN_ALLOW`,
  `response_written=true`, `scan_status=0`, and `scan_infected=0`. The typed
  report recorded a `COMPLETE` clean event.
- Detection fixture `/watch/detection.bin`: the unprivileged actor exited `1`,
  printed `denied`, and the retained clamonacc log recorded
  `LargeFile.R13.Current.Detection.UNOFFICIAL` at offset `7`. The typed report
  recorded `status=1`, `verdict=2`, `completion=DETECTION_TERMINATED`,
  `last_alert_offset=7`, and `clamonacc_event_id=3`. The bound fanotify event
  recorded `event_kind=FAN_OPEN_PERM`, `permission_response=FAN_DENY`,
  `response_written=true`, `scan_status=1`, `scan_infected=1`, and
  `scan_errors=0`.

The final clamonacc log included:

```text
ClamInotif: watching '/watch'
/watch/detection.bin FOUND
ClamWorker: permission scan detected malware in '/watch/detection.bin'
```

The NDB fixture used the current test CVD certificate directory, so the
detection was verified by the running service rather than by a mock result.

## Cleanup and qualification boundary

The wrapper terminated clamonacc and clamd, removed its temporary database,
configuration, logs, reports, fanotify evidence, and runtime directory. The
temporary host-staged Release build was then removed and verified as the exact
path created for this run. No source-tree or production deployment state was
changed.

This receipt does not provide the six-case R13 matrix, monitoring-only parity,
timeout/resource cases, full-size fixtures, sanitizer evidence, parser
coverage, R04 certified case records, or release qualification. No capability
status changed; R13 remains open.

State: `development-smoke-verified; privileged-clean-allow-detection-deny`
