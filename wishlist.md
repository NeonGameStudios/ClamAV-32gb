# Wishlist

## Large-file validation and expansion progression

1. **Validate the current 32 GiB raw path on the local macOS host**
   - **In progress:** native macOS host-preflight capture added; local build
     tool availability and memory telemetry are being qualified.
   - Use the bare-metal 64 GB machine with one worker first.
   - Exercise sparse boundary fixtures and materialized inputs where practical.
   - Verify exact tail-marker detection, 32 GiB + 1 rejection, and the absence of
     false `OK` results.
   - Record RSS, virtual memory, I/O, page faults, scan time, temporary storage,
     build identity, and macOS-specific behavior.

2. **Compare local macOS results with Sonic1 Linux results**
   - Run equivalent raw workloads and configurations.
   - Preserve the platform differences in the evidence rather than treating the
     Linux runtime gate as proof of macOS behavior.

3. **Define a higher-memory deployment profile**
   - Establish a fixed resource budget that leaves headroom for the OS,
     signatures, parser scratch space, page cache, temporary storage, and
     concurrency.
   - Only then consider widening `MaxFileSize`, `MaxScanSize`,
     `StreamMaxLength`, and milter quotas toward a 50–100 GiB policy.
   - Add one-worker and measured-concurrency tests for the new boundary.

4. **Review parser-specific limits independently**
   - Decide which bounded paths should remain capped and which need
     windowed/streaming or higher-memory implementations.
   - Preserve fail-visible, non-clean behavior whenever a parser cannot inspect
     all required content.

5. **Complete legitimate service qualification**
   - Use the official ClamAV databases obtained through `freshclam`.
   - Test authorized real clean/infected files, materialized workloads,
     parser-expansion inputs, cold-cache behavior, daemon paths, and resource
     budgets.
