# Sonic1 real-file scan report

Date: 2026-08-18

## Scope

Sonic1 accessed the USB flash drive after `/dev/sda1` was mounted read-only at
`/mnt/clamav-test-files`. The requested directory was:

```text
/mnt/clamav-test-files/clamAV-test-files
```

The five large files were scanned with the current Release build,
`ClamAV 1.5.3-largefile-devel`, using Sonic1's existing production CVD mirror:

```text
/home/camera/clamav-32gb-work-f08c7b0/evidence/production-cvd-mirror-20260816/db
```

That mirror contained `main.cvd`, `daily.cvd`, and `bytecode.cvd` (about
108 MiB total, dated 2026-08-16). ClamAV's legacy RSA verification succeeded
for all three CVDs. Detached `.sign` files were absent. A fresh `freshclam`
attempt reached `database.clamav.net`, but the CDN returned HTTP 403 and put
the host on cooldown, so no newer database was downloaded.

The two 4 KiB `._*` AppleDouble metadata files in the directory were excluded.

## Latest official-CVD verification — 2026-08-18

The current Sonic1 source mount was rebuilt successfully in the existing
`clamav-32gb:test-tools-742a8a4` container (`gmake -C /work/build-current-release
-j2`, exit 0). The resulting binary reports `ClamAV 1.5.3-largefile-devel`.
The preprocessor output for the rebuilt `libclamav` translation unit confirms
`SIZE_MAX`, `ANONYMOUS_MAP`, and the 32 GiB
`CLI_MAX_PCRE_CONTIGUOUS_FILESIZE` branch are active.

The USB files were then scanned serially with the official `main.cvd`,
`daily.cvd`, and `bytecode.cvd` database files. Sonic1 reported 62 GiB total
memory and 58 GiB available before the run. The evidence is preserved at:

```text
/home/camera/clamav-32gb-work/usb-scan-20260818-current/
```

With top-level limits of 32 GiB but the normal `PCREMaxFileSize` default
(100 MiB), the four files below 32 GiB all returned exit 2 with:
`PCRE signatures require an oversized contiguous subject`. The 50 GiB file
returned exit 2 with `Heuristics.Limits.Exceeded.MaxFileSize` and
`Exceeded max scan size`. No file was reported clean after an incomplete scan.

| File | Bytes | Result | Wall time | Peak RSS |
|---|---:|---|---:|---:|
| `1.53gb.m4v` | 1,529,898,209 | incomplete, PCRE subject limit | 1:59.80 | 1,071,752 KB |
| `2.31gb.exe` | 2,313,609,237 | incomplete, PCRE subject limit | 13:35.45 | 1,370,368 KB |
| `3.27gb.mp4` | 3,272,094,941 | incomplete, PCRE subject limit | 3:10.92 | 1,072,056 KB |
| `4.7gb.iso` | 4,699,979,776 | incomplete, PCRE subject limit | 4:44.83 | 1,073,572 KB |
| `50.gb.iso` | 49,999,802,368 | rejected, top-level 32 GiB limit | 0:11.35 | 1,057,800 KB |

As a focused override check, `1.53gb.m4v` was rescanned with
`--pcre-max-filesize=32G`. It no longer reported the PCRE contiguous-subject
warning; instead it reached a separate parser limitation:
`ZIP masked local-header values are unsupported` (exit 2, 1:44.90 wall time,
2,551,708 KB peak RSS). This is evidence that the large-file/PCRE path is
active, not evidence of full embedded ZIP/format-parser support.

The 50 GiB file was also checked with the explicit 32 GiB PCRE setting and
remained fail-visible: exit 2 after 11.60 seconds with
`Heuristics.Limits.Exceeded.MaxFileSize` and `Exceeded max scan size`.

The official database fingerprints for this run were:

```text
bytecode.cvd  6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb
daily.cvd     09571f432efc1cc88bfff594768f880ed5abf4b9913e97e5f9c0a98a7a4bed70
main.cvd      0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365
```

This pass complements the earlier raw-only POC profile: synthetic boundary
tests and raw scans demonstrate the large-file fmap/offset path, while the
official-CVD pass shows the expected distinction between top-level limits,
PCRE configuration, and independent deep-parser limits.

The Sonic1 binary was rebuilt from the current local working tree after the
PCRE whole-file path was upgraded. On qualifying 64-bit anonymous-map builds,
the effective `PCREMaxFileSize` ceiling now follows the 32 GiB large-file
ceiling; builds without that capability retain the historical 1 GiB bounded
allocation ceiling. This changes only the PCRE contiguous-subject policy; it
does not remove parser-specific or resource limits.

Local source guards and the fail-closed POC regression passed. The rebuilt
Sonic1 `matchers` suite passed 14/14 checks.

## Results with current runtime defaults

The scan used `--alert-exceeds-max=yes` so a skipped input could not appear as
an unqualified clean result. Every large file exceeded the current default
limits and returned exit status 1 with an incomplete scan:

| File | Bytes | `file` classification | ClamAV result |
|---|---:|---|---|
| `4.7gb.iso` | 4,699,979,776 | Nintendo Wii disc image | `Heuristics.Limits.Exceeded.MaxFileSize FOUND` |
| `50.gb.iso` | 49,999,802,368 | UDF filesystem data | `Heuristics.Limits.Exceeded.MaxFileSize FOUND` |
| `1.53gb.m4v` | 1,529,898,209 | ISO Media / MP4 v2 | `Heuristics.Limits.Exceeded.MaxFileSize FOUND` |
| `3.27gb.mp4` | 3,272,094,941 | ISO Media / MP4 Base Media | `Heuristics.Limits.Exceeded.MaxFileSize FOUND` |
| `2.31gb.exe` | 2,313,609,237 | PE32 Windows executable | `Heuristics.Limits.Exceeded.MaxFileSize FOUND` |

`FOUND` in this table is the configured limit heuristic, not a malware
detection. The corresponding stderr was:

```text
LibClamAV Warning: Scan incomplete: Heuristics.Limits.Exceeded.MaxFileSize
```

The source defaults in `libclamav/default.h` remain:

```text
CLI_DEFAULT_MAXFILESIZE = 100 MiB
CLI_DEFAULT_MAXSCANSIZE = 400 MiB
CLI_MAX_LARGE_FILESIZE  = 32 GiB
```

Therefore the fork currently has a 32 GiB accepted ceiling for explicit
configuration, but it does not default to 32 GiB operation.

## Deliberate 32 GiB deployment profile

For a dedicated, memory-budgeted service, the minimum clamd-side profile for
this large-file path is:

```text
MaxFileSize 32G
MaxScanSize 32G
StreamMaxLength 32G
AlertExceedsMax yes
```

The first three values must be kept aligned across direct `clamscan`, `clamd`,
and stream clients. `AlertExceedsMax yes` makes limit crossings visible as
non-clean results instead of allowing a skipped object to look clean. This is
not a recommendation to make the profile the global default: `MaxThreads`,
RSS headroom, temporary storage, parser-specific allocations, and concurrent
requests still need a measured budget.

This profile does not remove every bounded parser path. In particular,
`OnAccessMaxFileSize` is a separate on-access policy, and several legacy
parsers still use format-specific or contiguous-buffer ceilings. The Rust
whole-input and other parser caps documented in the main specification remain
independent of the top-level 32 GiB setting. On qualifying 64-bit builds,
PCRE's contiguous-subject policy is now allowed through 32 GiB, subject to
available memory and the configured scan-time/resource budget.

On Sonic1, this profile was applied directly to `50.gb.iso`. It returned exit
status 1 in 11.5s with `Heuristics.Limits.Exceeded.MaxFileSize FOUND`,
`Data scanned: 0 B`, and the matching incomplete-scan warning. The summary
reported 46.57 GiB read while determining/rejecting the input, so the limit is
fail-visible but should not be described as a zero-I/O rejection.

## Completed explicit 32 GiB raw-scan profile

The below-32-GiB files were rerun with:

```text
--max-filesize=32G --max-scansize=32G --max-scantime=900000
--pcre-max-filesize=32G --alert-exceeds-max=yes --scan-archive=no
```

`2.31gb.exe` additionally required `--scan-pe=no` because the raw top-level
profile otherwise entered the InstallShield parser after recognizing an
embedded signature. This is a raw-scan qualification profile, not a claim of
deep PE/archive-parser coverage.

| File | Raw profile result | Time | Data scanned | Data read | Notes |
|---|---|---:|---:|---:|---|
| `1.53gb.m4v` | `OK`, exit 0 | 3m14s | 3.03 GiB | 1.42 GiB | no diagnostics |
| `3.27gb.mp4` | `OK`, exit 0 | 6m21s | 6.49 GiB | 3.05 GiB | no diagnostics |
| `4.7gb.iso` | `OK`, exit 0 | 9m16s | 9.32 GiB | 4.38 GiB | no diagnostics |
| `2.31gb.exe` | `OK`, exit 0 | 11m33s | 2.29 GiB | 2.15 GiB | `--scan-pe=no`; no diagnostics |

These are successful raw top-level scans of all four files below 32 GiB. The
scan summaries report the expected clean status against the production CVD
mirror; they are not a guarantee that the files contain no undetected threat.

## Deep-parser observations

Two files were also run with archive/PE scanning enabled. Neither hit the old
PCRE oversized-subject warning after the source upgrade, but both exposed
malformed or unsupported embedded-parser data:

| File | Result | Diagnostic |
|---|---|---|
| `1.53gb.m4v` | exit 2, 99.5s | `ZIP masked local-header values are unsupported` |
| `2.31gb.exe` | exit 2, 825.3s | `7-Zip archive header could not be parsed completely` |

The raw-only profile deliberately avoids treating those parser failures as a
false-clean result: it scans the original top-level bytes while explicitly
omitting the corresponding deep processing. Full parser qualification remains
a separate workstream.

## Parser conclusion

The raw-scan objective is now demonstrated for all four files below 32 GiB on
Sonic1, including the post-upgrade PCRE path. This does not establish full
ISO/UDF/MP4/PE/archive parser support. The deep-parser probes above show why:
recognized embedded formats can still be malformed or use parser paths with
independent limits. Those paths must be qualified separately with parser-
appropriate fixtures, enough execution time, and explicit non-clean handling
for incomplete inspection.

## Follow-up

1. Repeat the successful raw profile on macOS with equivalent `ANONYMOUS_MAP`
   and 64-bit build checks; Sonic1 is Linux evidence, not macOS proof.
2. Add RSS, virtual memory, page-fault, temporary-storage, and concurrency
   measurements to the materialized-file qualification.
3. Qualify the deep ZIP/7-Zip/InstallShield/PE paths independently; do not
   fold parser-disabled raw results into deep-parser coverage.
4. Treat the 50 GB file as an expected rejection under the current 32 GiB
   ceiling; it requires a separately designed larger policy.
5. Obtain a fresh production database through `freshclam` after the current
   CDN cooldown/block is resolved.
