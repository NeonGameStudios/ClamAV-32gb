# Task receipt: R10 Sonic1 daemon and front-end smoke

Task ID / parent milestone: `R10` / `R04`

Scope: build the current daemon, client, on-access and milter front ends and
exercise their startup paths in the disposable Sonic1 container. This is
development verification only; it is not full ingress parity, fanotify
qualification, PCRE qualification, or release evidence.

Environment and identity:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Source bind: `/tmp/clamav-32gb-current-20260915` mounted read-write at `/src`.

Build and executable results:

```text
make -C /src/build-roadmap-20260920 -j2 clamd clamdscan clamonacc clamav-milter
exit=0

clamav-milter --version
exit=0
clamav-milter 1.5.3-largefile-devel

clamd --help
clamdscan --help
clamonacc --help
exit=0 for each
```

The initial default-config startup exposed the expected disposable-container
setup issue: no generated `/usr/local/etc/clamd.conf` existed. A disposable
config using the repository signing certificate directory then loaded the
one-signature PCRE database successfully.

Full-size admission result:

- The 32-GiB profile created its socket and loaded the database, then refused
  daemon admission with `temporary_free=33587748864` bytes below the required
  `73014444032` bytes. This confirms the known Sonic1 temporary-space blocker;
  it was not bypassed.

Bounded control-plane result:

- A second disposable config explicitly bounded `MaxMatcherWork` to `2G`,
  `MaxTemporarySize` to `2G`, `MaxContiguousSize` to `512M`, `MaxScanSize` to
  `1G`, and the related file/parser limits below the available capacity.
- The tracked foreground daemon stayed up for the bounded 15-second smoke;
  `clamdscan --config-file=/src/clamd-roadmap-smoke.conf --ping=1:1` returned
  `PONG` with exit 0.
- The tracked command reached its intentional `timeout` terminal state with
  exit 124, and the daemon log showed normal startup, the large-file
  capability manifest, enabled scanner families, and socket cleanup.

Interpretation:

- `clamd`, `clamdscan`, `clamonacc`, and `clamav-milter` build and start at
  their help/version entry points.
- `clamd` and `clamdscan` communicate over the Unix socket when the configured
  resource envelope fits the host.
- Certified 32-GiB daemon admission remains blocked until at least 68 GiB of
  disk-backed temporary capacity is available. The bounded smoke does not
  claim 32-GiB scanning capability.

State: `development-verified; certified-capacity-blocked`
