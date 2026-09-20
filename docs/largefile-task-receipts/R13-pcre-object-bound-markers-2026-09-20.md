# Task receipt: R13 object-bound PCRE phase markers

Task ID / parent milestone: `R13` / `R04`

Scope: make the PCRE runtime evidence contract bind all phase markers to the
same scan-layer object and recursion level. This prevents an unrelated nested
scan's `deep-parse` marker from satisfying the target PCRE sequence. The
change hardens evidence binding only; it does not promote any capability.

Changes:

- `libclamav/matcher.c` now emits `object_id` with the `before-pcre`, `pcre`,
  and `post-pcre-before-deep-parse` events.
- `libclamav/scanners.c` emits the same `object_id` with `deep-parse`.
- `tools/largefile_pcre_phase_evidence.py` parses object-bound markers and
  accepts a proof only when one object has ordered, same-sized
  `before-pcre` -> `pcre` -> `post-pcre-before-deep-parse` -> `deep-parse`
  events with the required release flags.
- Added regressions for missing identity, unrelated-object markers, and
  object-bound ordering. The generated large-file inventory was regenerated
  from `tools/largefile_inventory.sh`.

Verification:

- `python3 -B tools/largefile_pcre_phase_evidence_test.py` — 13 tests passed.
- `sh tools/largefile_source_guards.sh` — passed, including the 604-entry
  capability manifest and release-readiness controls.
- `git diff --check` — passed.
- Existing generated build flags were used to compile the changed
  `matcher.c` and `scanners.c` objects with the pre-existing
  `rust:1.97-bookworm` image, generated headers, UnRAR interface header, and a
  declaration-only JSON header stub. The compile exited 0 with no dependency
  installation or download.

Runtime boundary:

- The existing remote Sonic1 binary predates this marker-format change, so no
  remote runtime claim is made for the new `object_id` field yet.
- Full-size PCRE RSS evidence remains open and still requires the authorized
  Linux x86-64 admission envelope and a coherent rebuild containing this
  change.

State: `development-verified`
