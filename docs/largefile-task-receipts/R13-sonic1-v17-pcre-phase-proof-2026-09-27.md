# R13 Sonic1 v17 PCRE phase proof — 2026-09-27

## Scope and provenance

This is a fresh, source-bound R13 proof for a positive PCRE tail detection and
a separate clean continuation on the same fully allocated exact 32-GiB
fixture. It closes the PCRE phase-evidence case for this v17 candidate only;
it is not a capability promotion or final release qualification. Host/profile:
`sonic1` / `sonic1-camera-key`.

The deterministic source package SHA-256 is
`236ddf76834d1ae697b8b52af8ceaabd5f3698a3531be52774f0db67648af105`; the
extracted source manifest SHA-256 is
`0e011be4f9c399c62b752efc574cbbe1c893735184088d05e497d1e2ce0699dc`. The
Release CMake cache/build identity SHA-256 is
`fe939bfa15cd2615c090d601d2ba8deca9f2d6f7c9c2b739b959bba7e6d1d95a`, and
`clamscan` SHA-256 is
`f33c19d2b8ee5f978de84c54450c09297669cc306e1a06f52420ffae0ea4f0d2`.
The container is
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`, image
ID `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The retained evidence root is
`/qualification/r13-pcre-v17-20260927`; proof format v2 SHA-256 is
`2278afa54a8de65f9be2de926fe480d023464bc66bdf0fd4cbfcff0a17c90e1c`.
The source-bound `largefile_pcre_phase_evidence.py` verifier passed on Sonic1.

The read-only `/ram/edge-stable.bin` fixture is exactly 34,359,738,368 bytes,
fully allocated, and hashes to
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`. The
positive custom PCRE database SHA-256 is
`3b7056c08f3bb0e2e0f86a71efe90bb0035cb7503844b6cbf5fd390c65087e8f`; the
clean database SHA-256 is
`b62c970a93761d1f4cf78834a0ddbface57028d4a6f6fbecfb5bdf4888ccf86c`.

## Results

| Run | Tracked MCP-SSH job | Exit / report completion | Samples | Process-tree RSS peak | PCRE RSS peak | Post-PCRE RSS peak |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Exact-tail detection | `job_c532a10491fc4edf8c91657f46bc318b` | 1 / `DETECTION_TERMINATED` | 1,468 | 33,641,948 KiB | 33,641,948 KiB | 87,516 KiB |
| Clean continuation | `job_02015226855247598b1c92baf5fa5957` | 0 / `COMPLETE` | 1,552 | 33,640,432 KiB | 33,640,432 KiB | 86,000 KiB |

Both reports prove `root_size=contiguous_bytes=34359738368` and zero skipped
operations. Detection reports `PcreTail32G.UNOFFICIAL`; the process log
records the exact regex offset `34359738352` (EOF−16) and subject release.
The separate clean run reports `status=0`, clean verdict, `COMPLETE`, and no
alert. The raw 100-ms process-tree traces retain root PID and sampled-PID
identity; they order PCRE, the synchronous post-PCRE release sample, and
deep-parse, with distinct process roots and non-overlapping run timestamps.

Both PCRE peaks are below the 40-GiB phase budget, both post-PCRE peaks are
below 12 GiB, and both runs report zero swap, temporary peak, and new OOM
events/kills. Host swap remained disabled; post-run `MemAvailable` was
63,804,996 KiB. The qualification temporary directory was empty and all
MCP-SSH jobs were terminal.

## Acceptance boundary

These PCRE runs numerically exceed the separate 33,554,432-KiB (32-GiB)
whole-workload ceiling by 87,516 KiB (85.5 MiB) and 86,000 KiB (84.0 MiB).
That observation does not invalidate the distinct R13 40-GiB PCRE-phase /
below-12-GiB post-phase proof, and it must not be relabelled as a pass or
failure of the stricter, separate subcase.

Contract clarification after inspecting the current
`tools/largefile_runtime_gate.sh`: that stricter 32-GiB RSS check is actually
enforced on its separate 1/2/4-worker non-PCRE concurrency scans, while the
full-subject PCRE proof is assessed against the 40-GiB phase and below-12-GiB
post-phase limits. Thus the PCRE observations above do not themselves fail
the separate concurrency gate; they also do not prove it. The concurrency
workload still needs its own retained, source-bound execution and summed RSS
evidence. Do not change either threshold or infer a concurrency result from
this PCRE run.

After the run, `/qualification` had 50,349,884 KiB free, below the roadmap's
68-GiB disk-staging admission; the host root had 276,236 KiB available. No
volume was resized. Production-CVD canary, sanitizers, fanotify, remaining
capability-specific cases, whole-workload RSS cap, and final readiness remain
open. No software was installed, no GitHub workflow was changed or triggered,
and no commit or push was made.

## Supplemental direct-RAM diagnostic (not accepted as scan evidence)

Two follow-up attempts scanned a byte-identical, read-only tmpfs copy of the
same fully allocated 32-GiB fixture. The RAM copy independently matched the
fixture SHA-256. Both attempts reached the full-map PCRE matcher log but did
not produce a completed scan report or accepted resource row:

- `job_5a21a3877f554b45b5f8745c33eaa732`, PID-namespace container
  `e12a0f5a18cea5293e47dab29050d8e52d01b5f7e75b8707fb918edd0c7a75ae`,
  failed closed when procfs metrics for PID 19 disappeared.
- `job_97cbc6a3c50e4c2b9ccaaf89193a1142`, host-PID container
  `87c3bd7755b373669438592c9f62ab7b26641b108ed74a6a38e6cdb813117c04`,
  recorded 1,236 regular samples, then failed closed when PID 814059 lacked
  procfs metrics. Its last successful RSS sample was 30,102,368 KiB; the log
  ended during the EOF PCRE matching phase.

The second container's cgroup reported `memory.max=60129542144` bytes,
`memory.events.local` values `max=0`, `oom=0`, `oom_kill=1`. Thus the recorded
kill was not a cgroup memory-limit event; together with the host's zero-swap
state and 32-GiB tmpfs residency, this is consistent with host-level memory
exhaustion. At inspection, `/proc/meminfo` reported `MemTotal=65234456 KiB`,
`Shmem=33557700 KiB`, and `MemAvailable=30333516 KiB`. After cleanup,
`free -k` showed `MemAvailable=63900648 KiB`, with zero swap. The tmpfs copy
and disposable container were removed; the disk-backed fixture and both
failed-run artifacts remain on the qualification bind mount at
`/qualification/r13-pcre-v17-ram-20260927/`.

These experiments do not prove a successful in-RAM 32-GiB PCRE scan, and they
must not replace or weaken the accepted disk-backed PCRE phase proof above.
For this host and workload, a 32-GiB tmpfs subject plus the PCRE working set
is incompatible with the no-OOM acceptance requirement. No memory limit was
raised and no third in-RAM retry was started.

## Same-day follow-up checks

On the pinned v17 Release container, targeted CTest for
`largefile_acceptance_resource_capture` and `largefile_procfs_tree_metrics`
passed 2/2. The standalone `largefile_pcre_phase_evidence_test.py` passed
13/13. These validate the evidence tooling; they do not change the failed
direct-RAM scan disposition.

A fresh R03 sanitizer preflight found only stable Rust 1.97.1, no `clang` or
`clang++`, and rejected `rustc -Zsanitizer=address` because the compiler is
not nightly. No sanitizer build was started and no tools were installed.
The current source's required C ASan/UBSan plus Rust address-instrumentation
evidence therefore remains externally blocked on this runner.
