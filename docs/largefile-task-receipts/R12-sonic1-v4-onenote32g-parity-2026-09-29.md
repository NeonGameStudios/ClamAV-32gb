# R12 Sonic1 v4 exact-32-GiB OneNote late-child parity — 2026-09-29

## Scope and provenance

This is one current-source, custom-signature, CLI parser case; it is **not**
complete OneNote, R04, R12 or release qualification. Host/profile:
`sonic1` / `sonic1-camera-key`. The existing pinned qualification container
is `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
Its `/qualification` bind is the dedicated disk-backed LV. The fixture lives
in that container's private `/dev/shm`, not the Sonic1 host's `/dev/shm`.
Both successful scans ran as UID/GID 1000 in the pinned container, with a
separate case-private disk spool and process-tree resource capture.

The deterministic v4 source-package SHA-256 is
`2efc584180e27b93bfcce704e9a29336353a951c2a36e04c13def7360c93eafe`
and committed MCP-SSH transfer is
`transfer_1fa2dcffa4e94708b78b7b7e06d06a64` (see the R03 v4
build receipt). Both resource records recomputed the extracted source-content
manifest SHA-256
`1ab7e63f3b74eb987e2eef9b79a672e4fedab83bda83ed13c9895ad9bf8e1ff0`.
The separately copied Release `clamscan` and CMake cache hashes are
`064be4e7f5b9b3d8f65c2ea09d12d28babb288fb98f7b435a350fc1a575a8479`
and `b29ca3126d65244e58d8afc9e7920daeb51a011ab4e44c9f24e5f38f73ef1f79`;
the C ASan/UBSan counterparts are
`37e6cf687ff2984aafc3f2abbf113d04fa6d6f48d72498bf6fce42620f1e48c2`
and `732733843a582eccbb5debdedb971e0f6dcdc4d386d9383085902d2cd19a9c8e`.
An independent checker rehashed these copied case-local identity artifacts
and checked them against the corresponding resource rows.

The exact 34,359,738,368-byte fixture is
`/dev/shm/r12-v17-onenote32g-clamscan-diskspool-20260927-run01-input.one`.
It had 67,108,864 allocated 512-byte blocks, inode 1619 and mtime
1790541183 before the scans; these metadata and the bounded late-marker
read were unchanged after both scans. The earlier independent hash and a
separate full-file hash after the Release scan (`job_bce43bb62edf43d1b48ca486ea40d020`)
and another after the C-sanitizer scan (`job_1099b0c7375d41828d5bcb4e75915a9a`)
all gave SHA-256
`1c593530684ac8c98d818437db669e556966051e4b1c4b4e9a65c049623feacf`,
which also equals both scanner input-hash logs. Independent bounded reads
confirmed `MZP` at offset 34,359,719,413 (EOF−18,955), calculated from the
52,297-byte source and its offset-33,342 marker. The scanner's OneNote alert
does **not** itself include an offset field, so this is fixture/oracle
coordinate evidence rather than scanner-reported offset parity.
The isolated `late-mz.ndb` contains
`OneNote.Reader.LateMZ:0:0:4d5a50` and hashes to
`18e92066983cbc35d84ccd8a1c83b09ddf73c965b4032b5930a4b6724965176b`.

## Successful cases

Each scan used `--force-to-disk=yes`, the custom NDB and explicit empty
cert-directory, 32-GiB MaxFileSize/MaxContiguousSize/PcreMaxFileSize,
64-GiB MaxScanSize/MaxTemporarySize, `MaxScanTime=14400000`, and
`--alert-exceeds-max=yes`. The C sanitizer process set
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. The source-controlled
resource capture independently sampled the process tree at one-second
intervals and retained the report, scanner log, source/build/config copies,
resource TSV, and sample trace under each case directory.

| Build | Managed job | Report elapsed | Samples | Peak process-tree RSS | Peak apparent temporary-tree bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| Release | `job_e2852faf283b474894cdf22073da9e50` | 140,820 ms | 141 | 100,420 KiB | 68,121,001,984 |
| C ASan/UBSan | `job_1fa3757fb5cd48548e27bb0790f32992` | 143,795 ms | 144 | 139,180 KiB | 68,248,010,752 |

The Release evidence root is
`/qualification/r12-v4-onenote32g-20260929-release-positive-retry1`;
the sanitizer root is
`/qualification/r12-v4-onenote32g-20260929-asan-positive`.
Both scanner processes exited 1 for the expected detection. Each report
records `status=1`, `completion=DETECTION_TERMINATED`,
`file_type=CL_TYPE_ONENOTE`, `root_size=34359738368`,
`logical_bytes=34359738912`, `matcher_bytes=544`,
`temporary_bytes=34359720552`, `files_scanned=2`,
`max_recursion_depth=1`, `parser_operations=2`,
`skipped_operations=0`, and exact alert
`OneNote.Reader.LateMZ.UNOFFICIAL`. An independent read-only checker found
the two structured reports identical after excluding only `elapsed_ms`.
It also checked exactly one resource row per case, the complete ordered
sample counts, sampled RSS maxima, identity hashes, detection/input-hash
logs, zero swap/OOM events, the 64-GiB apparent temporary-tree ceiling,
and empty private spool directories. The sampler's temporary-tree peak is
the sum of apparent file sizes in the temporary tree, not observed physical
LV allocation; it is under 64 GiB (68,719,476,736 bytes) in both cases.
The container's post-run `memory.events` was `oom=0, oom_kill=0`; host swap
remained disabled. The dedicated LV returned to 36,276,872 KiB available
after the sanitizer case. These case-local no-OOM observations do not erase
the separate earlier `grep` OOM diagnostic.

Retained artifact SHA-256 values:

| Artifact | Release | C ASan/UBSan |
| --- | --- | --- |
| `scan-report.jsonl` | `50e609c43ad16d9577d219a1e846bdb1852d44d1711f5989ecc7e329a7a95975` | `199d7f4dc1f8940f8b643737551afef8d88037b3984a0a569e02b7b8fe42e5ae` |
| `provenance/acceptance-case-resources.tsv` | `c8d2eab66f422d65eb9bc46969eeec42ce7386923955e6e1147bee044ec78573` | `6676227ee3dc6c98ca09eb4a9b5c20381bdb6795b93009f389ed97ddbc8c4542` |
| `provenance/samples.tsv` | `39505e5f2280c067fe385d594fd1994666ba363af561cdc334cb44c699e33660` | `983a9b2851306ddf4beb294c0c44b9e964d67a4ef00cc259b7dd3c7b975175ef` |
| `provenance/scan.log` | `1af263dc4e0fe5fae77d51e6c278f8f0c526e9cc48c40bbbe0223e814df212a2` | same |

## Diagnostic attempts retained, not promoted

The first disposable `docker run` exited 125 before scanning: it tried to
bind the fixture from the **host** `/dev/shm`, where `stat` confirmed that
path is absent. A read-only `--ipc=container:<pinned ID>` probe also exited
125 because the donor container's IPC namespace is non-shareable. The first
resource-wrapper attempt inside the correct pinned container exited 1
before fixture inspection because it omitted `--cvdcertsdir`; its scanner
log says the default `/usr/local/etc/certs` directory does not exist.
Those three attempts are not scan results. The first case directory and
managed job records were retained, not promoted or used for the successful
case. A bounded 3-byte preflight with the
correct cert directory loaded the signature before each full run.

## Remaining boundary

This proves one exact-materialized OneNote late-child detection with v4
Release/C-sanitizer parity and measured cleanup. It does not prove a clean
OneNote completion, modern-reader path identity, exact scanner-reported
member offset, all malformed/fault/limit cases, Rust address instrumentation,
all ingress/service paths, production CVDs, 68-GiB service staging admission,
or final readiness. The current dedicated LV still lacks that 68-GiB free
service prerequisite. No software was installed; no usage reset, GitHub
workflow, commit or push occurred.
