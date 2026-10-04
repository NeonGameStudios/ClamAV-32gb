# R11 Sonic1 current-source exact 32-GiB ZIP scan — 2026-10-03

## Scope and identity

Targeted current-source Release evidence for a fully materialized exact-size
ZIP fixture: clean deep traversal, nested-member detection, and the root raw
tail-offset control. This is not a capability promotion or release
qualification. Host/profile: `sonic1` / `sonic1-camera-key`.

- Candidate commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`, branch
  `largefile-roadmap-qualification`; working tree fingerprint
  `13f8cfe5bab2e54cc718546a07976757eb525781f4173e76ba6f72d884b5862f`,
  163 porcelain rows at packaging time.
- Deterministic source package SHA-256:
  `74412a4e327ddb3fb4fd579ec7f82757b7716f0133ee1cd2223078282b0f03f1`;
  extracted source manifest SHA-256:
  `9d84ffae72cb5d8351c81d40da78936fcb6d1c8a067b67b5778abeff67a5e20d`.
- Fresh Release `clamscan` SHA-256:
  `a4a11840b6badda07c0424fb2548c9e14face97639153d26823f7d2a05f73e31`.
  Focused current-source CTest (`cl_api`) passed 1/1 in 20.85 s. The ZIP
  parser selectors also passed: `zip` 20/20, `zip_sfx` 5/5, and `zip_map`
  3/3, all with zero failures or errors. They ran with
  `CK_RUN_SUITE=cl_suite`, the selected `CK_RUN_CASE`, and
  `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`; each CTest invocation
  exited 0. The retained final `zip_map` `test.log` SHA-256 is
  `6c1ae1808de2233e67df257caca4b6cec0ef6d86dd0f8d0d0773407942838d06`, and
  its `LastTest.log` SHA-256 is
  `f255315ac4769fbd5ee92932ae5ab425ef862dec3103899e5d7a1e5e1c2381e7`.
- Pinned container:
  `2a0ab4cddff8df902eb201c4662fe67e7d83e57761f250659b3a5aa9d26fafee`,
  image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Fixture:
  `/tmp/clamav-eb75db20-stream-fixture/zip-direct-sequence-8/exact-32g.zip`,
  exactly 34,359,738,368 bytes, SHA-256
  `450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`.
  Its stable identity was inode 11949415, mtime 1791041680, and 67,108,880
  allocated blocks before and after the clean scan. The independent post-scan
  hash matched the oracle.
- ZIP oracle marker: `CLAMAV-ZIP-LATE-MEMBER-MARKER`; root offset
  34,359,738,091; member-relative offset 32,779; late child size 32,809 and
  MD5 `385c70115dabd2c132681b7ad7c2e145`.

## Exact-size clean nested traversal

Tracked MCP-SSH job `job_034e9439efee446fba722bb30a3ad0ad` completed with exit
0 in 623,378 ms. It used a private one-entry never-match HDB, explicit test
certificates, `--scan-archive=yes`, `--force-to-disk=yes`, and the 32-GiB
file/contiguous/PCRE limits, 64-GiB logical/temp limits, 256-GiB matcher-work
limit, four-hour scan deadline, 10,000-file limit, and recursion 17.

The structured report is clean/trusted and `COMPLETE`, with root size
34,359,738,368; logical bytes 68,719,476,384; matcher bytes 103,104,386,304;
temporary bytes 68,719,410,414; 3 files; depth 1; 3 parser operations; 5
detector operations; and 0 skipped operations. The legacy status is 0, as
expected for a clean report. ClamAV's root FileHash matched the independent
fixture SHA-256.

- Report SHA-256:
  `02f57c6f2e37aa88e3bfc95b2615c72a83796d992b6e8412ec1268fe21d0b3ce`.
- Log SHA-256:
  `860ae19252cbe5aefaaa267ee28fa0256091663ec52f3b3b7169cb91e98dd665`.
- Exit/output summary: `OK`; 96.02 GiB cumulative data scanned; 32.00 GiB
  read from the root input; 10 m 23 s.
- The spool directory was empty after exit; `/tmp` free space returned to
  99,005,144 KiB. Host swap was zero, and cgroup `memory.events` remained
  `low=0, high=0, max=0, oom=0, oom_kill=0`. During the run the disk-backed
  spool peaked at 61,230,780,023 bytes. Cgroup `memory.max` was unlimited;
  the large `memory.current` sample was predominantly reclaimable file cache,
  with host `MemAvailable` remaining about 60.5 GiB.

## Paired current-source detection and offset controls

The same exact-size fixture was also tested against the current Release
binary with private root NDB and child HDB signatures. The full archive
all-match job `job_f3efdc50d733404d937146517b7ab43c` completed in 520,075 ms:
3 files, 3 parser operations, 5 detector operations, 0 skipped operations,
`DETECTION_TERMINATED`, and both root/child signatures in the log. Its
`last_alert` is the child HDB signature, so it correctly has no root
`last_alert_offset`; transformed/materialized child offsets are not root
coordinates. The report uses the legacy status 0 with verdict 2 and
`DETECTION_TERMINATED`; `unit_tests/check_clamd.c` explicitly accepts this
library report form as infected, so it is not a status inconsistency.

- All-match report SHA-256:
  `282ec4456e73f1a533b772d721486682acfbc13ef374c5060cd3ba783c2c2850`.
- All-match log SHA-256:
  `b452e6a30228d7d3f2e967f6b125b07e954e4f098e352ef13ddc40affe9f4bb2`.
- A separate raw-only scan (`--scan-archive=no`), job
  `job_cd61229716a042c993ea4c6153f5f436`, completed in 108,770 ms and
  detected `LargeFile.Zip.32G.LateMember.UNOFFICIAL` at exact root offset
  34,359,738,091. It scanned one file with no temporary spool; the root hash
  matched the oracle. Report SHA-256:
  `43223d2b1ac493f7c7f0492eed7baf4ff91c2efcda3646cb49b459f3d76dd402`.

The earlier default archive detection run was supervised with the short
Docker-call timeout and continued inside the container after that wrapper
expired. Subsequent exact-size scans used the tracked async host-command path
with a 1,200-second limit and were reconciled to terminal exit status; no
duplicate scan was launched.

## Boundary

This is evidence for the current candidate's exact-size ZIP clean deep
traversal, nested detection, and raw root-offset behavior only. It does not
cover production CVDs, the full parser corpus, all ingress paths, sanitizer
parity, PCRE phase RSS on this source package, queue/resource qualification,
privileged fanotify, the production canary, or final readiness. No capability
was promoted. No software was installed, no GitHub workflow was triggered,
and no commit or push was made.

State: `current-source exact-size ZIP clean and detection controls observed;
R11/R13 and release qualification remain open`.
