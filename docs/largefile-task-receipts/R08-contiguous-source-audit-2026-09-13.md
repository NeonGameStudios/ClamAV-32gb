# Task receipt: R08 contiguous-read source audit — 2026-09-13

Task ID / parent milestone: `R08` / `R00`.

## Scope

Audit the active `libclamav` call paths for whole-map fmap reads or allocations
derived from the complete input length. The roadmap permits a full-subject
contiguous read only for the explicitly exceptional PCRE path; parser and
decoder paths must use bounded windows, readers, or disk-backed spools.

## Findings

- The roadmap-approved complete-map fmap read is
  `fmap_need_off_once(map, 0, map->len)` in `libclamav/matcher.c`.
- That call is inside the full-subject PCRE branch and is preceded by the
  effective PCRE size check, `cli_scan_reserve_contiguous(ctx, map->len)`, and
  a deadline check. A failed map read releases the reservation and marks the
  scan incomplete; a successful PCRE pass releases the reservation and unlocks
  the fmap before deep parsing continues.
- Two legacy PE unpacker branches also contain explicit full-map reads:
  `fmap_readn(map, spinned, 0, fsize)` for `PESpin` and `yC`. These are not
  unbounded parser exceptions: each call is preceded by
  `cli_pe_unpack_size_check(ctx, ..., fsize)`, which rejects a contiguous
  buffer above `CLI_MAX_ALLOCATION` and marks the recognized unpacker
  incomplete. They therefore fail closed at the 1-GiB individual-allocation
  guard rather than attempting a 32-GiB allocation.
- Hashing, script normalization, compressed-input readers, MIME line reads,
  PDF filter input, XAR output, ZIP/7-Zip input, and the inspected parser
  families use bounded fmap windows or quota-accounted temporary spools.
- The deprecated whole-file inspection callback still rejects layers above the
  individual-allocation ceiling and preserves the sticky incomplete result;
  it is not an accidental full-map exception.

No unsafe unguarded full-range parser or decoder path was identified. No source
change was made in this slice because weakening or duplicating the existing
guards would not improve the application.

## Verification

- The narrow source audit searched `fmap_need_*`, `fmap_readn*`, `mmap`, and
  `cli_max_malloc/calloc` uses involving complete map lengths. It found the
  guarded PCRE read plus the two guarded PE unpacker reads described above;
  no unguarded parser or decoder full-range path was found.
- `sh tools/largefile_source_guards.sh` — exit 0; 601 capability entries,
  readiness regressions, acceptance-map/record checks, PCRE/fanotify evidence
  checks, and source guards passed.
- `sh tools/largefile_release_readiness.sh --status` — exit 1 with
  `release_readiness=blocked`; this is expected because certified x86-64,
  materialized large-file, production-CVD, and capability-specific evidence
  are still absent.

## Qualification boundary

This is current-source ARM64 development/source evidence. It does not promote
PCRE or any parser capability to certified release status and does not replace
the required full-size R11–R14 runs.

State: `development-verified; implementation-gap-not-found; qualification-open`.
