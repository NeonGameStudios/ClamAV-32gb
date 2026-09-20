# R08 solid EGG AZO boundary regression — 2026-09-20

## Scope

Make the remaining solid-EGG AZO limitation explicit at the production-path
streaming boundary without presenting AZO as implemented.

## Change

- Added `test_egg_solid_azo_members_are_fail_visible` to the `egg_map` Check
  case. It opens a valid solid EGG-shaped archive using algorithm 3 through
  `cli_egg_open_ex`, then extracts through
  `cli_egg_extract_file_stream`.
- The regression requires `CL_EUNPACK`, zero output, the exact sticky reason
  `solid EGG codec requires persistent decoder state`, and
  `map->dont_cache_flag`.
- Existing successful solid STORE/BZIP2/persistent-DEFLATE/persistent-LZMA
  tests remain registered unchanged.
- The capability manifest now records this fail-visible production-linked
  boundary; no capability was promoted.

## Limitation

`libclamav/egg.c` contains no AZO decoder or persistent AZO state machine. The
regression therefore closes the evidence gap around conservative handling, not
the implementation gap. Solid AZO support, complete EGG corpus evidence, and
current-source external qualification remain open roadmap requirements.

## Local bookkeeping

The generated inventory, status snapshot, and source-guard expectations were
updated in the same working-tree change. Remote Sonic1 qualification was not
attempted or mutated for this slice.
