# Task receipt: R05 streaming ZIP late-member fixture

Task ID / parent milestone: `R05` / `R00`

This slice prepares the deterministic ZIP late-member fixture for the
roadmap's large outer-coordinate runs. It does not claim a live scanner run
or release qualification.

`tools/largefile_zip_late_member.py` now writes the prefix and target member
through bounded 1-MiB chunks instead of constructing either payload in a
single in-memory byte string. The generator accepts explicit prefix and
target-prefix sizes for the eventual multi-gigabyte fixture families and
uses ZIP64-capable output when required. The independent oracle now parses
the EOCD/ZIP64 records, central directory, and local header with bounded
random-access reads, then streams the target member while computing its CRC
and locating the marker. It does not load the archive or member into memory.

Verified commands:

- `python3 -B tools/largefile_zip_late_member_test.py` — 7 tests passed,
  including a 2-MiB prefix / 1-MiB target-prefix parameterized round trip and
  a synthetic ZIP64 central-directory/EOCD round trip.
- `sh tools/largefile_source_guards.sh` — passed; the complete 601-entry
  capability manifest, readiness tests, evidence schemas, acceptance map,
  and source guards all remain green.

The current host was not used to create the roadmap-scale materialized ZIP:
its capacity and architecture remain below the certified runner contract,
as recorded in `R03-materialized-edge-capacity-check-2026-09-13.md`.
Therefore no capability was promoted and the R05 full-family, certified
Linux x86-64, and retained runtime evidence requirements remain open.

No usage reset, software installation, commit, push, remote command, or
workflow action was performed.
