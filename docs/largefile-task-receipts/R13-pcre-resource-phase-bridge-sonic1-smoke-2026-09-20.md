# R13 PCRE resource-phase bridge — Sonic1 smoke — 2026-09-20

Task ID / parent milestone: `R13 / R02-R04 resource evidence`.

Scope: exercise the reconciled application phase bridge in the existing Sonic1
development container using the bounded custom PCRE positive-control fixture.
This is stale-tree development evidence only; it does not promote
`matcher:pcre` or establish full-size resource qualification.

Provenance and source boundary:

- Remote staging root: `/tmp/clamav-32gb-current-20260915`.
- Container ID:
  `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID:
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Container `/src` is a read-write bind of the remote staging root.
- Only the current local `libclamav/matcher.c` was reconciled into this
  stale tree for this smoke; the rest of the remote source remains stale.
  The reconciled file SHA-256 is
  `d3cef1e0836507208b664053033a6342b7d392db1a9c716088666e7926ea23ac`.

Build and runtime result:

- `cmake --build /src/build-roadmap-20260920 --target clamav -j2` exited 0;
  `matcher.c` compiled and `libclamav.so` linked.
- `cmake --build /src/build-roadmap-20260920 --target clamscan -j2` exited 0.
- The existing custom database loaded one generic PCRE signature,
  `PcreTail;Engine:81-255,Target:0;1;5441494c4d41524b;0/TAILMARK/`.
- `clamscan` scanned the existing 105-byte `fixture-small-tail.bin` with
  `CLAMAV_LARGEFILE_RESOURCE_PHASE_FILE` pointing at an empty append-only
  phase file. It returned exit 1, as expected for the positive-control
  detection, and debug output recorded the full-map PCRE match and the
  `post-pcre-before-deep-parse` transition with `subject_released=1`.
- The retained phase file content was exactly:

  ```text
  pcre-start
  post-pcre
  ```

This confirms the application-to-capture-file bridge is active at runtime in
the reconciled stale-tree smoke. It does not prove current-source provenance,
process-tree RSS/PSS/VAS bounds, 32-GiB behavior, sanitizer parity, fanotify,
production CVD/service behavior, or release readiness. No capability was
promoted.

No software was installed or downloaded, and no GitHub workflow was triggered.

State: `development-verified; runtime-qualification-open`.
