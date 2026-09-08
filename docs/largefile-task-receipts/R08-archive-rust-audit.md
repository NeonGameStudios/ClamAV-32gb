# Task receipt: R08 archive and Rust bounded-path audit

Task ID / parent milestone: `R08` / `R00`

Scope: inspect the active ZIP/SFX, LHA/LZH, and ALZ call paths for a concrete
large-input implementation gap. This is a source-level qualification slice;
it does not promote a capability or replace current-source runtime evidence.

Prerequisites verified:

- The canonical checkout and `largefile-roadmap-qualification` branch were
  preserved with the existing dirty worktree.
- The roadmap requires bounded input, authoritative member lengths, exact
  terminal completion, late-member detection, quota/deadline enforcement, and
  fail-visible cleanup/error propagation.
- A certified Linux x86-64 build and the complete dependency set remain
  unavailable on this macOS/ARM64 host.

Call-path findings:

- ZIP/SFX ordinary and encrypted members reach `unz_from_fmap()` and dispatch
  supported methods to `unz_stream()` (`libclamav/unzip.c:1568-1588`). The
  active reader uses fixed 64-KiB refills (`libclamav/unzip.h:84-128`), so the
  legacy decoder's `unsigned int` input narrowing is not reachable from the
  archive scan path. Unsupported methods mark the scan incomplete and return
  `CL_EUNPACK`; the retained contiguous `unz_legacy()` implementation is
  explicitly not dispatched.
- ZIP's bounded deflate path rejects a stream that ends before all declared
  compressed input is consumed, rejects output-size disagreement, checks
  decoder finalization, and only then invokes the child callback
  (`libclamav/unzip.c:670-697` and the adjacent BZIP2/implode branches).
- LHA/LZH uses `LhaPositionReader` over `FMapReader`, checks each declared
  compressed range against the fmap, enforces header allocation and configured
  limits, spools output in bounded chunks, rejects decoder output beyond or
  below the declared size, checks CRC, and verifies the archive terminator
  position before completing (`libclamav_rust/src/scanners.rs:1117-1428`).
- ALZ uses `FMapReader` and the reader-backed streaming API, performs metadata
  admission before extraction, propagates metadata/limit failures, maps
  unrepresentable sizes to `CL_ERESOURCE`, handles parser/read/panic failures,
  and retains post-parse unsupported-feature and limit results
  (`libclamav_rust/src/scanners.rs:1537-1713`).
- Rust archive metadata refuses member-index narrowing beyond the 32-bit C
  callback contract and marks the scan incomplete before returning
  `CL_ERESOURCE` (`libclamav_rust/src/util.rs:127-207`).

Observed failing case and expected behavior: no new failing source case was
found in these three active paths. The previously suspected ZIP compressed-size
cast belongs to the dormant legacy implementation and must not be “fixed” by
loosening the bounded-reader design. Any full qualification still requires
materialized exact-edge fixtures, late detections, sanitizer runs, and a
coherent certified build.

Changes made: no parser or matcher source changes. Added this receipt to retain
the call-path classification and prevent the dormant ZIP path from being used
as evidence or reactivated accidentally.

Commands and exits:

- `sh tools/largefile_source_guards.sh` — exit 0; manifest, readiness, source,
  boundary, acceptance-map, producer, and regression guards passed.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` — exit 0;
  597 capabilities mapped.
- `python3 -B tools/largefile_acceptance_cases.py --check-records` — exit 0;
  schema valid with 0 records, so no qualification claim was made.
- `git diff --check` — exit 0 after the receipt update.
- `sh tools/largefile_release_readiness.sh --status` — exit 1 with
  `release_readiness=blocked`, as required while evidence is absent.

Development tests passed: static source guards and acceptance schema checks.
No current-source C/Rust linked execution was available for this slice.

Full-size/certified evidence produced, or explicitly not run: not run. The
required Linux x86-64 runner, complete build dependencies, production
databases, and materialized fixtures are unavailable.

Remaining failures / next slice: R03 must establish the certified build;
R04/R10 must populate capability-specific live records; R09 still requires
implementation or an explicit user-approved contract decision for the seven
required unsupported rows; R11-R14 remain open for full-size, service,
resource, on-access, and canary proof.

State: `development-verified`; release readiness remains blocked.
