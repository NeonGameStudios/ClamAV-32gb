# Task receipt: R13 object-bound PCRE phase markers

Task ID / parent milestone: `R13` / `R04`

Scope: make the PCRE runtime evidence contract bind all phase markers to the
same scan-layer object and recursion level. This prevents an unrelated nested
scan's `deep-parse` marker from satisfying the target PCRE sequence. The
change hardens evidence binding only; it does not promote any capability.

Follow-up Sonic1 smoke:

- The modified `matcher.c` and `scanners.c` were transferred to the
  disposable `/tmp/clamav-32gb-current-20260915` source mount using guarded
  SFTP chunks. Their remote SHA-256 values matched the local source hashes
  `2630ca391c45aa7c4aeb5d2a361266dfc78a388179a6157e96281b8545dbee5c` and
  `14a4e40baeccdf6540efc96477312221fc9dea2a129c86a5698374d4c50973d4`.
- Container `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a`
  rebuilt `clamscan`; the resulting disposable binary SHA-256 was
  `89d60f864d1439e81c7b2ed6029f4404c06c0e954ab3092f8502c99df05ae9bb`.
- A 4105-byte bounded tail fixture was scanned with the retained custom
  `PcreTail` database and repository test CVD certificates. The scan exited 1
  with the expected `PcreTail.UNOFFICIAL` detection.
- The runtime log contained the object-bound sequence
  `before-pcre(object_id=0,recursion_level=0,subject_bytes=105,release=0)` ->
  `pcre(object_id=0,recursion_level=0,subject_bytes=105,release=0)` ->
  `post-pcre-before-deep-parse(object_id=0,recursion_level=0,subject_bytes=105,release=1)`.
- This is marker-format evidence only. Because the positive PCRE detection
  terminates the bounded scan, it has no subsequent deep-parse event; the
  fail-closed verifier correctly rejects this run as qualification evidence.
  The 8-GiB rerun reached Sonic1's 20-second async ceiling before completion,
  so the full-size object-bound qualification proof remains open.

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
