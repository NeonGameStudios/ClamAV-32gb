# R13 two-run exact-size PCRE evidence contract — 2026-09-27

## Result

The PCRE phase verifier now has a feasible, fail-closed two-run contract.
This is verifier development evidence, **not** a completed Sonic1 PCRE
qualification or a matcher promotion.

The earlier single-run proof required both a positive exact-tail detection and
subsequent deep parsing in the same process. A positive scan can terminate
before parser dispatch; conversely, `--allmatch` can log the dispatch boundary
for a binary file without proving that a parser family actually ran. Neither
observation can stand in for an independent clean continuation. The prior v5
positive report also omits `last_alert_offset`, although its real debug log
records `cli_pcre_scanbuf: located regex match @ 34359738352`. The runtime
marker lines in that log have a `LibClamAV debug: ` prefix. A verifier that
required a JSON alert offset or only accepted unprefixed synthetic markers
could not validate that real evidence.

Proof format v2 therefore requires two distinct process trees and separately
retained configurations, databases, process logs, scan reports, and RSS traces:

- Detection: exact 32-GiB fully allocated, non-sparse fixture; expected PCRE
  alert; exact-tail offset from the scanner's runtime debug log; matching
  report identity; ordered before-PCRE, PCRE, and post-PCRE release markers.
- Continuation: the same fixture hash, a distinct database and process,
  complete clean report with no skipped operation, and a deep-parse dispatch
  marker **after** PCRE subject release.
- Both runs: hash-bound artifacts and source/build identity, per-run
  process-tree samples, 40-GiB PCRE-phase ceiling and strictly below 12-GiB
  post-PCRE ceiling. A detection-side deep marker never substitutes for the
  continuation process.

The verifier now reads the capture tool's actual tab-separated raw trace,
including root PID and every sampled process-tree PID, rather than accepting
a hand-assembled JSON sample summary. It checks row order, phase order, PID
membership/count, independent processes, exact per-phase and overall maxima,
and sample count against each hash-bound resource sidecar. It also binds both
configurations to the source manifest, build identity, database, scanner
binary, exact fixture, command arguments, JSON report target and status, and
ordered phase-rendezvous artifacts. A positive `--allmatch` run may include
an optional deep-parse sample; terminal `complete` samples remain separate
from deep parsing. The capture tool was updated to retain PID sets and
terminal samples for the next source package. The older v15 trace lacks PID
sets and cannot be promoted through this stronger contract.

The fixture check compares file size, allocated blocks and first data/hole
extents to the exact 32-GiB target. The source guard pins the new verifier
branches. Local regression run:

`python3 -B tools/largefile_pcre_phase_evidence_test.py` — 31/31 passed.

`python3 -B tools/largefile_acceptance_resource_capture_test.py` — 16/16
passed.

`git diff --check` and `sh tools/largefile_source_guards.sh` — passed after
the final monotone-sample-phase change.

## Acceptance boundary

The retained v15 Sonic1 scanner build predates this verifier-only source
change. A fresh source package and actual two-run, exact-size PCRE capture
remain necessary before any R13 proof can be accepted. At the time of this
verifier work Sonic1 retained a 32-GiB RAM fixture and reported only about
29 GiB MemAvailable; starting another full-subject PCRE allocation in that
state risked OOM. The dedicated qualification volume also had roughly
53 GiB free, below the
68-GiB disk-backed staging requirement. Neither resource gate was waived.

Later on the same date, the two actual scanner runs were captured as a
diagnostic in `R13-sonic1-v15-two-run-pcre-diagnostic-2026-09-27.md` after
freeing a hash-verified duplicate RAM fixture. That live evidence does not
retroactively place this v2 verifier in the frozen v15 source package or
waive the disk-staging gate.

No software was installed or downloaded, no GitHub workflow was changed or
triggered, and no capability was promoted.
