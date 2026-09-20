# Task receipt: R10 Sonic1 resource and milter protocol controls

Task ID / parent milestone: `R10` / `R13`

Exact capability/control list: `largefile_procfs_tree_rss`,
`largefile_procfs_tree_metrics`, `largefile_procfs_tree_oom`, and
`clamav_milter_protocol`.

Scope: run the remaining bounded process-tree resource controls and repair the
milter protocol test's explicitly supported lower-limit development mode. This
receipt does not claim a full-size milter message, exact-edge materialization,
production-CVD behavior, sanitizer parity, or release readiness.

Environment and identity:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Source bind: `/tmp/clamav-32gb-current-20260915` mounted at `/src`.
- Build directory: `/src/build-roadmap-20260920`.

Observed initial result:

```text
ctest --test-dir /src/build-roadmap-20260920 --output-on-failure \
  -R '^(clamav_milter_protocol|largefile_procfs_tree_(rss|metrics|oom))$'
exit=8

largefile_procfs_tree_rss       Passed
largefile_procfs_tree_metrics   Passed
largefile_procfs_tree_oom       Passed
clamav_milter_protocol          Failed before socket creation
```

The milter test was already configured for `MILTER_DEVELOPMENT_LEGACY_LIMITS=1`,
but its generated clamd configuration left `OnAccessMaxFileSize` at the
certified 32-GiB default. The daemon therefore correctly entered large-file
admission and rejected Sonic1's `temporary_free=33558360064` bytes against
`required=73014444032` bytes. This is an environment blocker for the
full-size path, not evidence that the milter protocol itself passed.

Change made:

- `unit_tests/milter_protocol_test.py` now adds `OnAccessMaxFileSize 100M`
  alongside the other 100/400-MiB development limits. The corrected local and
  mounted test source hashes are both
  `4679c4e760f902fbed682703a686cf46527ee4a4a933f28310f2d624e34af1c4`.

Corrected development result:

```text
ctest --test-dir /src/build-roadmap-20260920 --output-on-failure \
  -R '^clamav_milter_protocol$'
environment: MILTER_DEVELOPMENT_LEGACY_LIMITS=1
exit=0

1/1 Test #23: clamav_milter_protocol ........... Passed 5.41 sec
100% tests passed, 0 tests failed out of 1
Total Test time (real) = 5.41 sec
```

Retained output:

- Initial resource/milter run: `/tmp/clamav-r10-sonic1-resource-milter-initial-20260920.log`
  - SHA-256: `8776d3b758e2fe13df80d6a23eae727e33fb86b82c0dfdca3040b1dcb5d60f98`
- Corrected development milter run: `/tmp/clamav-r10-sonic1-milter-development-20260920.log`
  - SHA-256: `21510ab07fe6cd5ac56845298651e0739754d73e341367682cc52d870cb72e03`

Remaining work: certified full-size milter ingress, exact-edge materialized
evidence, resource/queue parity, sanitizer and production-CVD evidence,
fanotify proof, and final release readiness remain open. The Sonic1 temporary
storage admission blocker remains concrete and unchanged.

State: `development-verified; full-size-and-release-evidence-open`
