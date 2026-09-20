# R13 PCRE resource-phase bridge — 2026-09-20

Task ID / parent milestone: R13 / R02-R04 resource evidence.

Exact capability kind:id list: `matcher:pcre`; no capability was promoted.

Starting commit and working-tree/source manifest identity: local candidate
`497c4549` (`Record Sonic1 transfer state audit`), clean before this slice.

Observed gap and expected behavior: the resource-capture wrapper created and
sampled a phase protocol file named by
`CLAMAV_LARGEFILE_RESOURCE_PHASE_FILE`, but the application source had no
consumer for that variable. A real PCRE resource run therefore could never
publish `pcre` or `post-pcre` phase peaks from application events. The wrapper
must receive real application phase transitions and must append a terminal
`complete` event only after the wrapped process exits normally from the
capture loop.

Changes made:

- `libclamav/matcher.c` now writes opt-in `pcre-start` and `post-pcre` events
  at the existing full-subject PCRE boundaries. The file is opened append-only
  without creation, symlink-following is rejected where supported, short or
  interrupted writes are handled, and only the first full-subject transition
  in a process is recorded so nested layers cannot corrupt the one-case
  protocol. Normal scanning is unchanged when the environment variable is
  absent.
- `tools/largefile_acceptance_resource_capture.py` appends `complete` after
  the wrapped command finishes and uses a regular-file, no-follow descriptor
  for the terminal write. Sampler failures still terminate without publishing
  completion.
- Added terminal-write and symlink-replacement regressions and source guards;
  regenerated `docs/largefile-inventory.tsv`.

Development verification:

- `PYTHONPATH=tools python3 -B -m unittest largefile_acceptance_resource_capture_test largefile_acceptance_resources_test largefile_acceptance_cases_test largefile_pcre_phase_evidence_test` — 42/42 passed.
- `sh tools/largefile_source_guards.sh` — passed, including the 604-entry
  capability manifest and release-readiness controls.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — passed.
- `git diff --check` — passed.

Full-size/certified evidence produced, or explicitly not run: not run. No
coherent current-source CMake build is available in this worktree, the local
Docker API is unavailable, and the current-source Sonic1 staging transfer is
blocked by the recorded MCP-SSH durable-write policy boundary. No linked C
compile, 32-GiB resource run, sanitizer run, or release qualification is
claimed from this slice.

A non-installing GCC/Clang syntax probe using the existing generated build
flags was attempted against the current `libclamav/matcher.c`; it stopped
before translation because the host does not provide `openssl/ssl.h` (exit 1).
No dependency was installed or downloaded.

Remaining failures / next slice: build and exercise this bridge in a coherent
current-source Linux x86-64 candidate, then retain real process-tree samples
at the application events and bind them through the existing PCRE phase
evidence verifier. The 40-GiB PCRE, strictly-below-12-GiB post-PCRE,
full-size, sanitizer, fanotify, production-CVD, and final release gates remain
open.

State: development-verified; runtime-qualification-open
