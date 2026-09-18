# R11 Sonic1 materialized 32-GiB ZIP late-member slice — 2026-09-16

## Scope

Run the current-source Linux x86-64 materialized ZIP vertical slice against a
32-GiB outer file whose late stored member contains a deterministic marker.
The slice covers the production `clamscan` ZIP parser path for clean and
detection outcomes and the direct `clamdscan` path, FD-passing, and INSTREAM
client ingress controls, with an independent raw-byte oracle and explicit
large limits. It does not constitute final release qualification.

## Provenance

- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`
- Image: `clamav-32gb:dev-current`, image ID
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Source mount: `/tmp/clamav-32gb-current-20260915` mounted at `/src` as a
  read-write bind mount
- Build source manifest: `1fce4719f42ed92d5f0a4b8eeebb6db6268cb5981b7251894d950413cce6135f`
- CMake cache SHA-256:
  `6df8b77fe9a15394b9909f85281012678c01d6b1dd72899e83710985fdfc5e05`
- `clamscan` SHA-256:
  `070cb60d14e564d26d4f466625a101968ce56503cb2075cc0c4b4441930912a9`
- Build: Linux x86-64 Release, large-file defaults OFF,
  `ENABLE_LARGE_FILE_QUALIFICATION_TEST=ON`, Rust `stable`, Cargo offline

The fixture was generated at
`/src/r11-materialized-20260916/32g-zip-edge.bin` by the repository helper
`tools/largefile_zip_late_member.py`. The generator now fsyncs the completed
file before its oracle binds the digest. The fixture oracle is:

```text
fixture_size=34359738368
fixture_sha256=450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a
target_member_data_offset=34359705312
target_member_size=32809
marker_member_offset=32779
marker_file_offset=34359738091
marker_sha256=e7921ad836cf51e6d06d5b414dd49cec3ed5a5ddc5405b4a9a69b1eb4db58f44
```

The detection database was the isolated custom signature
`LargeFile.Zip.32G.LateMember.UNOFFICIAL`, SHA-256
`bf46b473a957dcbca10874953ada625c791742e0d421aa1e55ec747b9d2b7e10`.
`--normalize=no` was explicit because this build keeps the roadmap large-file
defaults disabled. An earlier default-normalization control stopped at the
20-MiB `MaxScriptNormalize` policy; that expected configuration result is not
counted as this ZIP result. Later exploratory normalized controls explicitly
raised `MaxHTMLNormalize`, `MaxHTMLNoTags`, `MaxScriptNormalize`, and
`MaxZipTypeRcg` to 32 GiB on both daemon and direct CLI paths.

## Clean result

Tracked async job `job_3189d2f9c1e84a19a2dac7c31bfc4d07` exited `0` after
`330262 ms`:

```text
/src/r11-materialized-20260916/32g-zip-edge.bin: OK
status=0 verdict=0 completion=COMPLETE file_type=CL_TYPE_ZIP
root_size=34359738368 logical_bytes=68719476384 matcher_bytes=68736257664
temporary_bytes=34359705207 files_scanned=3 parser_operations=3
detector_operations=3 skipped_operations=0 max_recursion_depth=1
```

The report SHA-256 is
`63200cdd5c6fa85679a7df2aa2e3d4bf6acc60e29ab1897716ad684ad48547f9`.

## Detection result

Tracked async job `job_70377ab71ef7442498783d4f3d85b275` exited `1` after
`264276 ms`, the expected `clamscan` detection exit:

```text
/src/r11-materialized-20260916/32g-zip-edge.bin: LargeFile.Zip.32G.LateMember.UNOFFICIAL FOUND
status=1 verdict=2 completion=DETECTION_TERMINATED file_type=CL_TYPE_ZIP
root_size=34359738368 logical_bytes=68719476384 matcher_bytes=34368128640
temporary_bytes=34359705207 files_scanned=3 parser_operations=3
detector_operations=1 skipped_operations=0 max_recursion_depth=1
last_alert=LargeFile.Zip.32G.LateMember.UNOFFICIAL
```

The report SHA-256 is
`5921928b1b4012a17f5506aba2062ae9d86e30cf4aba3676bf48b4b69ac31dbb`.

## Daemon/client ingress controls

The strict service harness could not be used as a qualification producer in
this run: the remote source checkout was dirty and the existing build was
bound to source manifest
`1fce4719f42ed92d5f0a4b8eeebb6db6268cb5981b7251894d950413cce6135f`.
Instead, an isolated daemon was launched from the same build with the edge
database and an explicit `CVD_CERTS_DIR=/src/certs`. Its `MaxTemporarySize`
was set to 40 GiB because Sonic1 had only about 54 GiB free; this is below the
release service profile's 64-GiB temporary budget and is therefore not release
evidence.

The direct path and FD-passing clients both detected the marker:

```text
path:    job_b3748d040c814538818e665ba07bf612, client elapsed 388 s,
         report elapsed_ms=203873, report sha256=
         7a0df665cabebbdc8dce4f21f99919ead815f6cea572c43d464cae16209daf34
fdpass:  job_39e0dd0e0814410b9a9b5145caa402ac, client elapsed 196 s,
         report elapsed_ms=195389, report sha256=
         cbac3df6c803c440532b69c52f47f826c13dcf5397842bc7f5638208582710f5
```

Both reports were `status=1`, `verdict=2`, `DETECTION_TERMINATED`,
`CL_TYPE_ZIP`, `root_size=34359738368`, and carried
`last_alert_offset=34359738091`. Both reported one parser operation, one
scanned file, and two skipped operations with the reason `ZIP member did not
reach a complete extraction state`; this confirms the client ingress and
offset but does not establish complete service-side ZIP extraction.

The INSTREAM client was deliberately run as a separate final control. Tracked
job `job_7ab5b4bf749147039436c672d4b011f3` exited `2` after 268 s. Its report
was `status=35`, `verdict=0`, `completion=RESOURCE_FAILURE`,
`target=instream(local)`, `root_size=34359738368`,
`temporary_bytes=34359738368`, `skipped_operations=3`, and reason
`temporary storage exceeded the configured resource limit`. The report SHA-256
was
`356c947fd87f6863c9bef6d01772de54a9d6fdbc257af7c130604949162c23e4`.
This is consistent with the stream backing plus ZIP extraction requiring more
than the exploratory 40-GiB budget on a host with roughly 54 GiB free; it is a
resource-bound limitation, not a demonstrated parser regression.

The daemon and all client processes were stopped by exact observed PID, and
the isolated temporary directory was empty afterward. The daemon/client
controls remain exploratory because they used a dirty source/build identity,
a non-release temporary budget, a custom edge database, and did not provide
production-CVD, sanitizer, or complete service qualification evidence.

## Normalization parity follow-up

The extended daemon configuration was retried with all four explicit engine
caps at 32 GiB. Tracked job `job_2ce45498eb0a4d5fa1b3fe2f523ff868` returned
`status=27`, `verdict=0`, `completion=UNSUPPORTED`, `CL_TYPE_ZIP`, one scanned
file, one parser operation, and reason `ZIP member did not reach a complete
extraction state`; report SHA-256:
`93d3b4fde60861da3d02dd02ee5c214b2d523465cd432b00e44361887ed8e9d1`.

The direct `clamscan --normalize=yes` control used the same four engine caps
and returned the same structured result. Tracked job
`job_55e52e7f73964e5ba73c44e900159491` reported `elapsed_ms=195637` and
report SHA-256
`230ce9c0777eac1d5d83794902dc8f757befbe81b9f19d5036f7ddfa2aba3ff6`.
These attempts do not isolate a normalization implementation failure: the
fixture had already exhibited an unexplained cache-resident byte change in
the large prefix, and the later independent prefix check found another
`0x51` at offset `8827839591`. After targeted `POSIX_FADV_DONTNEED` eviction,
that byte read back as the expected `0x50`. The normalized results therefore
remain exploratory integrity-contaminated observations, not a basis for
changing parser or temporary-space accounting. The subsequent corrected full
oracle revalidation, tracked as job
`job_560045d795b74a838d87a3f13f5e5af3`, passed with fixture SHA-256
`450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`, exact
size `34359738368`, and marker offset `34359738091`.

## Integrity and cleanup controls

The independent oracle passed before scanning and after both original scans,
with the same expected fixture SHA-256. A post-clean ordinary buffered prefix
read did observe one cache-resident non-`P` byte at offset `19155960935`
(`0x51`), while direct I/O at that offset returned the expected `0x50`.
Dropping only that file page with `POSIX_FADV_DONTNEED` restored the buffered
read. A later full prefix check found a second `0x51` at offset
`8827839591`; targeted eviction restored that byte as well. The corrected
full-oracle revalidation then passed as tracked async job
`job_560045d795b74a838d87a3f13f5e5af3`, preserving the expected fixture
SHA-256, exact size, and marker coordinates. File size, mtime, ctime, ext4
metadata, and kernel diagnostics showed no corresponding disk write or I/O
error. The origin of this cache-only instability is unresolved, so it is
retained as an environment/integrity caveat rather than attributed to ClamAV
or silently ignored. The isolated temporary spool directory was empty after
the prior runs.

## MCP-SSH asynchronous extension

The MCP-SSH documentation's tracked asynchronous command path was used to
carry a current-source `clamscan` run beyond the short synchronous Docker
execution window. After `ssh.hosts.list`, `ssh.connection.describe`, and
`ssh.docker.provenance`, the command was previewed and started with
`ssh.command.start` as a typed `docker exec` invocation, with the effective
Sonic1 timeout explicitly set to 600 seconds. The container's sanitized
environment also required the explicit typed setting
`CVD_CERTS_DIR=/src/certs`; without it, `clamscan` exited before scanning with
a CVD certificate-store error.

Tracked job `job_df1a384e8d864874b67d96d78d7d4755` ran for approximately 326
seconds and exited `0`. Its structured report SHA-256 is
`94a9afcaf6710a778aac19d121500757933d500710d435293f5af22b30464cb7` and it
reported:

```text
status=0 verdict=0 completion=COMPLETE file_type=CL_TYPE_ZIP
root_size=34359738368 logical_bytes=68719476384 matcher_bytes=68736257664
temporary_bytes=34359705207 files_scanned=3 parser_operations=3
detector_operations=3 skipped_operations=0 max_recursion_depth=1
elapsed_ms=325239
```

The required post-run oracle then observed one cache-resident `Q` byte at
offset `8827839591`, changing the full buffered SHA-256 to
`b2b3c61bf5fbfa21808b5cab1c23a62c1eb34c8b7fe8bb9f36857d9cdf0f7c2c`.
Evicting only that page with `POSIX_FADV_DONTNEED` restored byte `0x50`, and a
new full oracle returned the expected SHA-256
`450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`.
This confirms the async extension works, but the repeated Sonic1 cache
instability still disqualifies the run from unconditional qualification.

## Disposition

This closes a useful current-source materialized ZIP parser slice: the clean
path completed at exactly 32 GiB, the late marker was detected at its exact
outer-file coordinate, and the path and FD-passing daemon clients reached
that coordinate. INSTREAM fails visibly with a structured shared-resource
result under the constrained host budget. The normalized controls were
repeated with configuration parity but remain uninterpretable while the
fixture exhibits cache-resident instability. No capability is promoted. R11
remains pending unconditional qualification until the fixture is supplied by
an independent immutable/read-only path and the normalized/service controls
are repeated on the certified runner; production CVD, complete daemon/client
service, sanitizer, resource, on-access, and final release evidence also
remain open.

No software was installed or downloaded. No usage-reset or banked-reset tool
was called.
