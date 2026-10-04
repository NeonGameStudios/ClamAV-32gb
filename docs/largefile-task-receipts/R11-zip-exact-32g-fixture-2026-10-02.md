# R05/R11 exact-size ZIP fixture preparation

Date: 2026-10-02

## Candidate and scope

- Repository/branch: `ClamAV-32gb`, `largefile-roadmap-qualification`.
- Candidate HEAD: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; working tree remains dirty.
- Scope: make the existing deterministic stored-ZIP late-marker fixture generator able to calculate an exact outer ZIP64 file size, for the first full-size parser vertical slice.
- Owned files: `tools/largefile_zip_late_member.py` and `tools/largefile_zip_late_member_test.py`.

## Change and development verification

Added `prefix_size_for_outer_size()` and a mutually exclusive `--outer-size`
CLI option. The size calculation includes the prefix's ZIP64 local and central
size records, the late target's ZIP64 local-header offset, and ZIP64 end
records; generation fails if the requested size cannot use that layout. After
writing, the independent raw ZIP oracle must confirm the exact requested outer
size, central-directory structure, prefix CRC, target CRC, and unique late
marker location. It also computes the target member's MD5 during the
independent streaming pass, binding the exact child to a dedicated HDB
signature instead of relying on a marker match in the stored outer ZIP bytes.
This additional oracle field is versioned as schema 2, preventing older
version-1 receipts from being treated as child-signature-bound evidence.

The helper suite passed 10/10 before and after the schema-2 change. On
2026-10-02, `python3 -B -m unittest discover -s tools -p
'largefile_zip_late_member_test.py' -v` passed **10/10** with the version-2
assertions enabled. This is development evidence only. The 32-GiB calculation resolves the default target
fixture to a stored prefix of
34,359,705,207 bytes for an exact outer size of 34,359,738,368 bytes. The
size model places the marker at outer-file offset 34,359,738,091 (277 bytes
before EOF). The deterministic 32,809-byte target has MD5
`385c70115dabd2c132681b7ad7c2e145`, yielding the planned HDB entry
`385c70115dabd2c132681b7ad7c2e145:32809:LargeFileZipLateMember`. These values
must match the post-generation oracle before the database is used.

## Current-source Sonic1 fixture and signature preflight — 2026-10-02

Using the manifest-bound current-source package recorded in
`R03-R05-sonic1-current-source-release-exact-32g-2026-10-02.md`, the exact
fixture was generated in the verified 40-GiB tmpfs:
`/ram/r11-zip-exact-32g.bin`. The runner is `sonic1` /
`sonic1-camera-key`, container
`450e8d8f297ffb0d8ace2900b2802bfb2a6f47b63ea40d1e48d0168fd7a41a6c`, using
the candidate Release build. Managed generation job
`job_798428caa4e24a7abcbc19e151c5d6f3` passed and wrote
`logs/r11-zip-generate.log` and `evidence/r11-zip-exact-32g-oracle.json`.

The generated fixture is exactly 34,359,738,368 bytes with SHA-256
`450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`.
The generator's independent ZIP parser confirms the prefix CRC, ZIP64
central-directory/local-header layout, target member size 32,809, target
member MD5 `385c70115dabd2c132681b7ad7c2e145`, marker offset within member
32,779, and outer marker offset 34,359,738,091. A second independent raw-file
oracle (managed job `job_53262797598a4462a06ba74f5a3d6a25`) read all
34,359,738,368 bytes and passed `--require-materialized`: allocated bytes
equal exact file size, first hole is EOF, stable metadata is true, and the
marker occurs exactly once at the independently expected offset.

The target member was separately extracted and its MD5/size/marker offset
matched the ZIP oracle. Candidate ClamScan then loaded the derived child HDB
and a child-relative NDB signature; the preflight reported the exact
`LargeFile.Zip.32G.LateMember.UNOFFICIAL` marker hit at offset 32,779 and
`LargeFileZipLateMember.UNOFFICIAL` HDB match. An initial label-control run
showed the engine appends `.UNOFFICIAL`, so the database names were corrected
before any full-size scan. This proves signature syntax/target coordinates
only; it does not yet prove the ZIP parser on the 32-GiB outer file.

## Sonic1 exact-size parent scans and source-integrity anomaly — 2026-10-02

The exact fixture initially passed both the generator oracle and the separate
materialized-file oracle. The retained jobs are
`job_798428caa4e24a7abcbc19e151c5d6f3` and
`job_53262797598a4462a06ba74f5a3d6a25`; both recorded SHA-256
`450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`, exact
allocation, a first hole at EOF, and the unique late marker at outer offset
34,359,738,091.

The Release clean scan (`job_2554ee0c969442c4a2558231aba9675a`) exited 0 and
reported `COMPLETE`, clean/trusted status, `CL_TYPE_ZIP`, root size 34,359,738,368,
3 files scanned, 3 parser and 3 detector operations, 0 skipped operations,
68,719,476,384 logical bytes, and 34,359,705,207 temporary bytes. It took
272,338 ms and removed its disk-backed spool; swap remained zero. However, its
ClamAV `FileHash` was already `187c79ad521c4d8c0dde6544d96dedc0d6a10248a9784b0e9580ae9b808af1a6`,
not the pre-scan oracle hash. Because the input changed, this clean result is
not a valid accepted paired control.

The Release custom-detection scan (`job_893d47cf7852494fbf69f95bb4ac6971`)
exited 2. Its report was status 27 (`Can't parse data`), completion
`UNSUPPORTED`, only the ZIP root scanned, two operations skipped, and reason
`ZIP member did not reach a complete extraction state`. The ZIP extractor
computed prefix CRC32 `b2786ee0` against declared `41db104f`; no late-member
alert was reached. Its spool was removed and swap remained zero.

Afterward, independent `sha256sum` also returned the ClamAV hash
`187c79ad...`. A complete streaming prefix check reproduced CRC32 `b2786ee0`
and found exactly one differing byte from the generated all-`P` payload:
outer offset 7,523,329,127 changed from `P` (0x50) to `Q` (0x51). ZIP headers,
the target member, and the late marker remained readable. The file inode (7),
mtime and ctime remained at generation time. No other running container had
the `/ram` bind mount; Sonic1 exposed no EDAC memory-controller counters and
the Oct 2 kernel-journal search returned no EDAC/MCE/ECC records. These facts
do not establish whether the byte changed in the runner, in the source path, or
through another host-level cause; do not attribute it to hardware or ClamAV
without further evidence.

### Next action at the v1 incident review (superseded below)

Regenerate the deterministic fixture and immediately repeat both independent
oracle checks. Then repeat the clean/detect pair serially while binding
pre-scan and post-scan full-file hashes; use a read-only `/ram` mount for the
scanner if available. If the byte changes again, capture the exact phase and
stop promoting the ZIP slice until the source-integrity cause is understood.
After a stable pair, run applicable sanitizer and service/client ingress
parity. Production CVD acquisition remains blocked by the FreshClam CDN 403
and cooldown documented in the R03/R05 receipt. Bind genuine records through
the capability-specific verifier; do not promote `CL_TYPE_ZIP` based on this
incomplete evidence.

State: **initial materialized fixture passed its oracles; first Release clean
scan completed but source integrity changed, and the detection scan was
incomplete. ZIP qualification remains pending**.

## Regenerated v2 disk-backed read-only pair — 2026-10-02

The v1 tmpfs anomaly remains unexplained and is retained above as historical
evidence. A fresh deterministic v2 fixture was regenerated and copied to the
disk-backed qualification volume. The scanner containers mounted the fixture
directory read-only; the spool remained on the qualification disk. This
isolates ClamAV from mutating the source and avoids treating the earlier
mutable-tmpfs result as proof.

### Candidate and input identity

- Candidate commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; working tree
  remains dirty.
- Source content manifest SHA-256:
  `b7e4fefa1a661aa8bd9dc76ac499073ce45c5b2d03451d70c51692672338c144`.
- Deterministic package SHA-256:
  `71ee62d2c1c2a5bb206c668f0f5e25f5f0818c5db2a75f04679be0266ead7645`.
- Release image:
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Fixture: `/qualification/qual32g-mur2oy8d-5798545b-run/evidence/r11-zip-exact-32g-v2.bin`;
  34,359,738,368 bytes, fully materialized, SHA-256
  `450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`.
- Fresh RAM oracle: `job_25e83ba85e264442a5832047a37604f7`; disk-copy independent
  materialization oracle: `job_46f1962f868c4cf89116781c203621ba`. Both passed
  size/hash/unique-marker checks; the disk copy allocated 34,359,742,464 bytes
  (filesystem block rounding) and its first hole was EOF.
- Oracle v2 records `prefix.bin` size 34,359,705,207; target member
  `late-marker.bin` size 32,809, data offset 34,359,705,312, MD5
  `385c70115dabd2c132681b7ad7c2e145`; marker member offset 32,779 and outer
  offset 34,359,738,091 (277 bytes before EOF).
- Exact generator-oracle JSON (SHA-256
  `433d80b2c962eb5058df9302ef9cd5b5a4c86ea4b2780314aa8a030924e6fbb8`):

```json
{
  "fixture_sha256": "450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a",
  "fixture_size": 34359738368,
  "marker": "CLAMAV-ZIP-LATE-MEMBER-MARKER",
  "marker_file_offset": 34359738091,
  "marker_member_offset": 32779,
  "marker_sha256": "e7921ad836cf51e6d06d5b414dd49cec3ed5a5ddc5405b4a9a69b1eb4db58f44",
  "target_member": "late-marker.bin",
  "target_member_data_offset": 34359705312,
  "target_member_md5": "385c70115dabd2c132681b7ad7c2e145",
  "target_member_size": 32809,
  "version": 2
}
```

- The redundant RAM copy was deleted only after the disk copy passed its
  independent oracle, restoring the runner's RAM headroom.

### Release clean control

Managed scan: `job_7cc97b2cc2c94634ab3bd6543ecbc101`; 279,353 ms. The exact-size
ZIP completed as `COMPLETE`, clean/trusted, with 3 files scanned, 3 parser
operations, 3 detector operations, and 0 skipped operations. Logical bytes
were 68,719,476,384; matcher work was 68,736,257,664; peak temporary bytes
were 34,359,705,207. ClamAV's root FileHash matched the independent SHA-256.
Its structured report is retained on the runner at
`evidence/r11-zip-clean-disk-ro-report.json` (SHA-256
`9d5aeba274a0450d97b50856ec9d1dcfa5206e838f76fe4ebabfd321f54412e0`); the
full log is `logs/r11-zip-clean-disk-ro.log` (SHA-256
`dbc4cd0fdc3d0d293c5ad71b75cd4e18e87accc3834951ce47bc75fe7c3d8832`).

```json
{"version":1,"status":0,"status_name":"No viruses detected","verdict":0,"completion":"COMPLETE","target":"\/var\/tmp\/r11-zip-exact-32g-v2.bin","file_type":"CL_TYPE_ZIP","root_size":34359738368,"logical_bytes":68719476384,"matcher_bytes":68736257664,"contiguous_bytes":0,"temporary_bytes":34359705207,"files_scanned":3,"max_recursion_depth":1,"elapsed_ms":279353,"parser_operations":3,"detector_operations":3,"skipped_operations":0,"max_file_size":34359738368,"max_scan_size":68719476736,"max_pcre_file_size":34359738368,"max_matcher_work":274877906944,"max_temporary_size":68719476736,"max_contiguous_size":34359738368,"max_scan_time":14400000,"max_files":10000,"max_recursion":17}
```

### Release custom-signature detection

Managed scan: `job_028eb84a2ecb4108bf28e2ce78caccea`; 273,475 ms. The wrapper
accepted only ClamScan's expected detection exit code 1. The child-relative
NDB marker matched at offset 32,779 and the target-child HDB signature matched
the independently computed member MD5. The outer file's FileHash again
matched `450fa681…99d85a`; the parent signatures also reached the root scan.
The structured result reports 3 files, 3 parser and 3 detector operations,
0 skipped operations, 68,719,476,384 logical bytes, 34,359,705,207 temporary
bytes, and `last_alert=LargeFileZipLateMember.UNOFFICIAL`. It is
`DETECTION_TERMINATED`, not a clean pass. The legacy numeric `status=0` and
`status_name` field do not override `verdict=2`, completion, the alert, or the
ClamScan exit code; `unit_tests/check_clamd.c` explicitly tests the
status-0/verdict-2 detection form.

```json
{"version":1,"status":0,"status_name":"No viruses detected","verdict":2,"completion":"DETECTION_TERMINATED","target":"\/var\/tmp\/r11-zip-exact-32g-v2.bin","file_type":"CL_TYPE_ZIP","root_size":34359738368,"logical_bytes":68719476384,"matcher_bytes":68736257664,"contiguous_bytes":0,"temporary_bytes":34359705207,"files_scanned":3,"max_recursion_depth":1,"elapsed_ms":273475,"parser_operations":3,"detector_operations":3,"skipped_operations":0,"max_file_size":34359738368,"max_scan_size":68719476736,"max_pcre_file_size":34359738368,"max_matcher_work":274877906944,"max_temporary_size":68719476736,"max_contiguous_size":34359738368,"max_scan_time":14400000,"max_files":10000,"max_recursion":17,"last_alert":"LargeFileZipLateMember.UNOFFICIAL"}
```

Detection report SHA-256:
`7951e0240ebac0657a1b19da43b9cd2a5402badacd0197b7f393574353e46681`;
full log SHA-256:
`8b057478302789bd75967b1338230d1f21ffe0e475b32614c8e1c970d292125c`.
The fixture oracle JSON SHA-256 is
`433d80b2c962eb5058df9302ef9cd5b5a4c86ea4b2780314aa8a030924e6fbb8`.

### Integrity, resources, and scope

- Independent post-clean hash job `job_d55a3347ed644419b8ad132b6b2da510`
  and post-detection hash job `job_5d62bd38a400453e9a17e78960db3b2e` both
  returned the exact fixture SHA-256. The detector's own root FileHash agreed.
- The scan input bind mount was read-only; the qualification volume had about
  70 GiB free before and after scans. The 56-GiB container memory/swap limit
  was equal (no container swap); host swap was 0, and host memory remained
  available. Peak sampled scanner RSS was under 120 MiB.
- The disk-backed extraction spool was empty after each run. The transient
  scanner container ran with networking disabled, all capabilities dropped,
  `no-new-privileges`, and a read-only root filesystem.
- The raw fixture oracle and both structured reports are embedded above for
  local review. Full logs and the original 32-GiB fixture remain on Sonic1 in
  the stated qualification directory; do not delete that retained evidence
  until it is intentionally archived elsewhere.
- This resolves the v2 direct Release ZIP parent-scan pair and the observed
  v1 input-integrity discrepancy for the read-only disk-backed path. It does
  **not** explain the earlier mutable-tmpfs byte change and does **not** finish
  R11: production-CVD clean/detection, library/daemon/client ingress parity,
  Release/sanitizer parity for this family, measured R04 capability records,
  adversarial verifier failure, and other roadmap tasks remain outstanding.

State: **v2 Release `clamscan` clean control and custom late-marker detection
both passed their direct-file outcomes with stable input hashes and zero
skips; full ZIP-family/R11 qualification remains pending**.

## Release daemon/client fdpass pair on v2 fixture — 2026-10-02

After the direct `clamscan` pair, the same pinned Release image scanned the
same materialized fixture through a real foreground `clamd` and
`clamdscan --fdpass`, with one worker and a two-request queue. This was a
tracked MCP-SSH job (`job_2c4cdfa2aefb4c0f8361aac2a5489d56`), exited 0, and
printed `clamdscan_clean_exit=0`, `clamdscan_detect_exit=1`, and
`r11_zip_clamd_fdpass_pair=complete`. Each phase used a fresh daemon and its
matching clean/custom-signature DB. The fixture was mounted read-only at
`/var/tmp`; scanner networking was disabled, privileges/capabilities dropped,
rootfs read-only, and memory/swap limits both set to 56 GiB.

### Structured results

Clean report SHA-256:
`48671063faba164b28bc8fd6872fc8cc7bfceb5e1a6e3e27e0a81b1b9c427a9b`.
Detection report SHA-256:
`4f69ad7df49b5b6c26dac4dc6e79d6ee202b89f34c972d6c2228bca5fcb719dc`.
The reports bind the same 34,359,738,368-byte `CL_TYPE_ZIP` root and report
68,719,476,384 logical bytes, 3 scanned files, 3 parser operations, and zero
skips. Clean completion was `COMPLETE`/verdict 0/status 0 in 590,826 ms, with
5 detector operations. Detection was `DETECTION_TERMINATED`/verdict 2/status
1 in 519,578 ms, with 2 detector operations and
`LargeFile.Zip.32G.LateMember.UNOFFICIAL`. Its marker matched at member offset
32,779, as recorded in the daemon's retained debug log and independently
predicted by the oracle (outer offset 34,359,738,091, 277 bytes before EOF).

The JSON reports' exact content is retained on Sonic1 at
`evidence/r11-zip-clamd-clean-report.json` and
`evidence/r11-zip-clamd-detect-report.json`. Full client and daemon logs are
retained under `logs/r11-zip-clamd-{clean,detect}[-daemon].log`. Client-log
hashes (clean, detect) are `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
and `357bdca71b52164253521d44a06a314af57e0c5b2949a18dd77f4d96f2c779ba`;
daemon-log hashes (clean, detect) are
`c9c0bbab5b3a1744262d9ef79c0cc87f0afeb906d9204ee80edd04066de299f5` and
`e32cd580766178987c99eb4d813fdeb28c9b80e819cc7893213a1bc418e5c73f`.

```json
{"id":0,"version":1,"status":0,"status_name":"No viruses detected","verdict":0,"completion":"COMPLETE","target":"\/var\/tmp\/r11-zip-exact-32g-v2.bin","file_type":"CL_TYPE_ZIP","root_size":34359738368,"logical_bytes":68719476384,"matcher_bytes":103104386304,"contiguous_bytes":0,"temporary_bytes":68719410414,"files_scanned":3,"max_recursion_depth":1,"elapsed_ms":590826,"parser_operations":3,"detector_operations":5,"skipped_operations":0,"max_file_size":34359738368,"max_scan_size":68719476736,"max_pcre_file_size":34359738368,"max_matcher_work":274877906944,"max_temporary_size":68719476736,"max_contiguous_size":34359738368,"max_scan_time":14400000,"max_files":10000,"max_recursion":17}
{"id":0,"version":1,"status":1,"status_name":"Virus(es) detected","verdict":2,"completion":"DETECTION_TERMINATED","target":"\/var\/tmp\/r11-zip-exact-32g-v2.bin","file_type":"CL_TYPE_ZIP","root_size":34359738368,"logical_bytes":68719476384,"matcher_bytes":68736224471,"contiguous_bytes":0,"temporary_bytes":68719410414,"files_scanned":3,"max_recursion_depth":1,"elapsed_ms":519578,"parser_operations":3,"detector_operations":2,"skipped_operations":0,"max_file_size":34359738368,"max_scan_size":68719476736,"max_pcre_file_size":34359738368,"max_matcher_work":274877906944,"max_temporary_size":68719476736,"max_contiguous_size":34359738368,"max_scan_time":14400000,"max_files":10000,"max_recursion":17,"last_alert":"LargeFile.Zip.32G.LateMember.UNOFFICIAL"}
```

Independent post-pair hash job `job_a639be7b39574dbca7736ddbf9961d4a`
returned fixture SHA-256
`450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`, matching
the pre-scan oracle and ClamAV's root FileHash. The detection JSON includes
the exact signature but omits `last_alert_offset`; the debug log does provide
the child-relative offset. Until the report/record producer carries that
offset through to a capability record, this pair is evidence for the R11
slice, not a passing R04 detection record.

### Resource and lifecycle observations

- Structured peak temporary usage was 68,719,410,414 bytes, 66,322 bytes
  below the configured 64-GiB limit. Live sampling saw the scratch tree reach
  that bound; free space reached 5.3 GiB on the dedicated qualification LV,
  then returned to 70 GiB after daemon shutdown and spool cleanup. Both
  clamd temp directories were empty afterward.
- The daemon stayed CPU-active during the long scans. Sampled daemon RSS was
  86–236 MiB; these were point samples, not a peak-RSS capture. Host swap was
  0 and the container had no swap allowance. Do not treat point samples as a
  formal whole-process resource record.
- Both daemons answered the pre-scan `PONG` readiness check, exited after the
  client completed, and their logs show socket/PID-file removal. The wrapper
  did not perform a separate post-stop PING, so the full required lifecycle
  proof remains open.
- The detection report's `matcher_bytes` was 68,736,224,471; clean was
  103,104,386,304. Both reported `temporary_bytes=68,719,410,414`,
  `max_recursion_depth=1`, and no skipped operations.

### Scope

This extends the v2 Release ZIP result from direct CLI scanning to the
`clamdscan --fdpass` clean and late-detection path. It is not a full R11 or
R12 qualification: production CVDs, remaining daemon/client modes, the
fdpass limit-edge case, sanitizer parity, formal peak resource capture,
post-stop health assertions, R04 case-record integration/adversarial checks,
and remaining parser/matcher families are still outstanding. The report's
missing alert offset is a concrete R04 integration gap to address before
claiming capability qualification.

State: **Release `clamd` + `clamdscan --fdpass` clean and late-marker outcomes
both passed on the stable v2 fixture; full R11 and release readiness remain
pending.**

## C ASan/UBSan direct CLI parity on v2 fixture — 2026-10-02

The same source package and Release image's prebuilt `build-asan` binaries
were used for a serial `clamscan` clean/detection pair in tracked job
`job_e57d13193b734bd880fedc98cf17a1b6`. Its C and C++ flags in
`build-asan/CMakeCache.txt` are
`-fsanitize=address,undefined -fno-omit-frame-pointer`. Both commands set
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. The scanner used the
same read-only v2 fixture, same clean and custom-signature databases, and the
same 32-GiB file / 64-GiB logical / 64-GiB temporary / 256-GiB matcher
limits. Container network was disabled; capabilities were dropped; rootfs was
read-only; memory and memory-swap limits were equal at 56 GiB.

The job exited 0 only after its wrapper observed clean ClamScan exit 0 and
detection exit 1, with both nonempty reports. The clean report SHA-256 is
`5ea27b4da406d53c9ceb8fc63da4f1d70e2705a918fc123cd09751a8fe8236bd`; the
detection report SHA-256 is
`e63721690ec3f92913f0ef8b1053d9095621f73018d6c3363978c3c81e2d0506`.
The complete logs are `logs/r11-zip-asan-clean.log` and
`logs/r11-zip-asan-detect.log`, with SHA-256 values
`17d2cfa738fdd47dfcf9ef92be7afc8afc7c124a5764d708b668d1c644457376` and
`2cb358cbe195b20501d50c9fd1d01bda9cf12186388d7d800379b28db1397362`.

```json
{"version":1,"status":0,"status_name":"No viruses detected","verdict":0,"completion":"COMPLETE","target":"\/var\/tmp\/r11-zip-exact-32g-v2.bin","file_type":"CL_TYPE_ZIP","root_size":34359738368,"logical_bytes":68719476384,"matcher_bytes":68736257664,"contiguous_bytes":0,"temporary_bytes":34359705207,"files_scanned":3,"max_recursion_depth":1,"elapsed_ms":479658,"parser_operations":3,"detector_operations":3,"skipped_operations":0,"max_file_size":34359738368,"max_scan_size":68719476736,"max_pcre_file_size":34359738368,"max_matcher_work":274877906944,"max_temporary_size":68719476736,"max_contiguous_size":34359738368,"max_scan_time":14400000,"max_files":10000,"max_recursion":17}
{"version":1,"status":0,"status_name":"No viruses detected","verdict":2,"completion":"DETECTION_TERMINATED","target":"\/var\/tmp\/r11-zip-exact-32g-v2.bin","file_type":"CL_TYPE_ZIP","root_size":34359738368,"logical_bytes":68719476384,"matcher_bytes":68736257664,"contiguous_bytes":0,"temporary_bytes":34359705207,"files_scanned":3,"max_recursion_depth":1,"elapsed_ms":477868,"parser_operations":3,"detector_operations":3,"skipped_operations":0,"max_file_size":34359738368,"max_scan_size":68719476736,"max_pcre_file_size":34359738368,"max_matcher_work":274877906944,"max_temporary_size":68719476736,"max_contiguous_size":34359738368,"max_scan_time":14400000,"max_files":10000,"max_recursion":17,"last_alert":"LargeFileZipLateMember.UNOFFICIAL"}
```

The debug log confirms
`LargeFile.Zip.32G.LateMember.UNOFFICIAL` at member-relative offset 32,779;
the HDB child signature also matched. ClamAV's full root FileHash in both logs
is `450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`,
matching the independent oracle. A search of both complete logs found no
AddressSanitizer, UndefinedBehaviorSanitizer, runtime-error, or leak
diagnostics. The report retains the legacy status 0 with verdict 2 and
`DETECTION_TERMINATED`; the wrapper's observed exit 1 is the scan's actual
detection exit, not the MCP job exit.

Both runs reported 3 files, 3 parser operations, 3 detector operations, and
zero skipped operations. Temporary usage was 34,359,705,207 bytes, below the
64-GiB limit; both temp directories were empty afterward and free disk space
returned to 70 GiB. Sampled ClamScan RSS was roughly 93–210 MiB, but these
point samples are not a continuous peak-process-tree capture.

This establishes C-ASan/UBSan direct CLI parity for the v2 ZIP clean and
late-member cases, not sanitizer daemon/client parity or full R11. Production
CVDs, other ingress modes, materialized over-limit behavior, full resource
sidecars, R04 case integration/adversarial checks, and the remaining roadmap
families are still open. As in the Release daemon case, the structured
detection JSON retains the signature but not a child-relative offset; the
offset is independently established by the oracle and raw debug log.

State: **Release direct + daemon/fdpass and C-ASan/UBSan direct clean/detection
checks now pass on the stable v2 ZIP fixture; sanitizer service parity and
capability-specific R04 qualification remain pending.**

## C ASan/UBSan daemon/client fdpass parity on v2 fixture — 2026-10-02

The prebuilt sanitizer daemon and client were run serially against the same
read-only, materialized v2 fixture and clean/custom-signature databases in
tracked MCP-SSH job `job_d12388701f194b8fad300bcef5cdbcd6`. The pinned image was
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The one-shot container used no network, UID 1000, dropped capabilities,
no-new-privileges, a read-only root filesystem, a 56-GiB memory limit with no
swap allowance, a read-only fixture mount, and the dedicated qualification LV
for evidence and scratch. Each fresh foreground daemon passed its `PONG`
readiness check. Both phases used `clamdscan --fdpass`; ASan ran with leak
detection and halt/abort-on-error, and UBSan with halt-on-error and stack
traces.

The wrapper job exited 0 after observing the clean client exit 0 and detection
client exit 1. Clean completed as `COMPLETE`/verdict 0/status 0 in 1,100,905
ms. Detection completed as `DETECTION_TERMINATED`/verdict 2/status 1 in
927,310 ms with `LargeFile.Zip.32G.LateMember.UNOFFICIAL`. Both reports bind
the 34,359,738,368-byte ZIP root, 68,719,476,384 logical bytes, three files,
three parser operations, and zero skipped operations. The clean run recorded
five detector operations and 103,104,386,304 matcher bytes; detection recorded
two detector operations and 68,736,224,471 matcher bytes. Both structured
reports recorded `temporary_bytes=68,719,410,414` and a 68,719,476,736-byte
configured maximum.

Report SHA-256 values (clean, detection) are
`d1b7783bc35fe6ef463c926b1b4616b582f1a1f26763c57318a5cf0c36c37dce` and
`7f933f1fbf6c2630b5448f88c2f57d02fd7c3f637b3a247d322db6d83aad76d0`.
Client-log hashes are the empty-file hash
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (clean)
and `357bdca71b52164253521d44a06a314af57e0c5b2949a18dd77f4d96f2c779ba`
(detection). Daemon-log hashes (clean, detection) are
`9c6330d64fa7e9b539342a51397e1ec01976b61fd45da9ee916401e5c27339b7` and
`cab34ee721befb1a039bde289bb1886526dca74b833ac0bace60808d055af895`.
All four logs were searched for ASan, UBSan, runtime-error, and leak
diagnostics; there were no matches. The marker log independently shows the
custom signature at member-local offset 32,779, consistent with the ZIP oracle
and the earlier Release runs. The JSON detection report still omits
`last_alert_offset`; do not misstate the member-local offset as a root offset.

The temporary directory reached 68,719,414,510 bytes (about 66 KiB below the
configured 64-GiB ceiling); the qualification LV's minimum observed free
space was 5.3 GiB. After the wrapper completed, both ASan daemon temp
directories measured only 4,096 bytes, and free space returned to 70 GiB.
Clamd RSS samples ranged roughly 190–290 MiB; these are point samples, not a
continuous process-tree peak. The host had no swap in use, and the container
had no swap allowance. The temporary container was automatically removed;
reports and logs remain on the qualification LV under
`qual32g-mur2oy8d-5798545b-run/evidence/` and `.../logs/`.

This closes the C-ASan/UBSan `clamd` + `clamdscan --fdpass` clean/detection
parity slice for this fixture. It does not complete R11: production-CVD
coverage, limit-edge and other ingress modes, continuous resource sidecars,
post-stop health assertions, R04 record integration/adversarial checks, and
the other parser/matcher families remain open. In particular, this real
detection is not yet a passing R04 record because its structured report does
not carry the nested member's offset.

State: **Release and C-ASan/UBSan `clamd` + `clamdscan --fdpass` clean and
late-marker outcomes pass on the stable v2 ZIP fixture; full R11, R04, and
release readiness remain pending.**

## Release direct ClamScan from a read-only RAM-backed fixture — 2026-10-02

To exercise the requested in-memory input path, the already verified v2 ZIP
fixture was copied from the qualification LV into Sonic1's dedicated 40-GiB
tmpfs. The copy is 34,359,738,368 bytes and its allocated bytes equal its
size; its SHA-256 is
`450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`, matching
the disk source and independent oracle. The tmpfs had 8 GiB free after staging;
host available memory was 28 GiB, and host swap was zero. The original disk
fixture remains unchanged.

### Excluded launch failure

The first tracked attempt, `job_95a41ab5fc75464fbdcec3f83f029ec2`, passed its
input checksum but exited 80 before scanning: direct ClamScan defaulted to
`/usr/local/etc/certs`, absent from the pinned image, and signature database
verification failed (`Invalid certs directory` / `Broken or not a CVD file`).
This is a launcher configuration failure, not a scan result. Its diagnostic
is retained as `logs/r11-zip-ram-release-clean.log` with SHA-256
`e70e88aada816b3da629c23883cdde46be7c1277f0b0a00ab4705b7af2fc1b4a`. The
retry below explicitly supplied the candidate's existing CVD certificate
directory using ClamScan's supported `--cvdcertsdir` option and used distinct
artifact names; the failed attempt remains intact.

### Corrected clean/detection pair

Tracked job `job_d0e5e5ea6b554a0483f5c8ae3437534e` exited 0 after observing
the expected ClamScan exits (clean 0, detection 1), nonempty reports, and
matching SHA-256 checks before the clean scan, between scans, and after
detection. It used image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
network disabled, UID 1000, dropped capabilities, no-new-privileges,
read-only root filesystem, memory limit/swap limit both 56 GiB, and a
read-only `/ram` bind mount. All scratch and result files were directed to
the qualification LV. The full 32-GiB RAM copy was independently hashed
before the run and remained hash-identical after both phases.

Clean completed `COMPLETE`/status 0/verdict 0 in 591,514 ms. It scanned three
files with three parser operations, five detector operations, and zero
skips. Detection completed `DETECTION_TERMINATED`/status 1/verdict 2 in
532,046 ms with `LargeFile.Zip.32G.LateMember.UNOFFICIAL`; it scanned three
files with three parser operations, two detector operations, and zero skips.
Both reports bind the 34,359,738,368-byte root and 68,719,476,384 logical
bytes. Clean matcher work was 103,104,386,304 bytes; detection matcher work
was 68,736,224,471 bytes. Both report `temporary_bytes=68,719,410,414` under
the configured 68,719,476,736-byte maximum.

Report SHA-256 values (clean, detection):
`e4d69ae0094833f8a65deae03c97930b6d10ae4fb02236d51eeeccf67707c40d` and
`bbabea4bda493ea1ec7696c926233ed2a17892a66fcdf71522fd31f44bd71463`.
Log hashes (clean, detection):
`f00784002d268bd526916717bd4ca57019a896be9d32382a1098c72074007211` and
`876000b03ed0a675ee026c50c64c47a15de7b1dc7f2e988a7e394c57d48bb90f`.
The detection log confirms the marker signature matched at member-local
offset 32,779, consistent with the independent ZIP oracle; the root marker is
at outer offset 34,359,738,091. As in the disk-backed path, the structured
report contains the signature but omits `last_alert_offset`, so this is not
yet a passing R04 record.

Resource observations: the scratch tree reached 68,719,414,510 bytes, about
66 KiB below the configured maximum; minimum observed qualification-LV free
space was 5.3 GiB and returned to 70 GiB after the scan. Both temporary
directories were empty afterward. Host available RAM stayed about 28 GiB
with swap disabled; sampled ClamScan RSS was roughly 55–188 MiB, not a
continuous process-tree peak. The tested file remains in `/ram` for the next
in-memory qualification slice; the validated disk source remains preserved
on the qualification LV.

This adds a genuine RAM-backed input clean/detection path for the ZIP family,
in addition to the disk-backed Release and sanitizer checks. It does not
finish R11: production-CVD coverage, limit-edge and other ingress cases,
formal continuous resource sidecars, post-stop health assertions, R04 record
integration/adversarial checks, and the remaining parser/matcher families
remain open.

State: **The exact v2 fixture passed Release ClamScan clean and late-marker
detection from a hash-verified, read-only tmpfs input; full R11/R04 and
release readiness remain pending.**
