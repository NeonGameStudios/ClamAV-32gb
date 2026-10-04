# R13 offline continuation status — 2026-09-27

## Candidate and scope

- Canonical repository: `/Volumes/512gbNVME/github-external/ClamAV-32gb`.
- Branch: `largefile-roadmap-qualification`.
- HEAD: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; the working tree already
  contains extensive user/task changes. No source files were changed in this
  continuation.
- Work was limited to read-only inspection and status reconciliation. No build,
  test, reset, install, job start, cancellation, or remote mutation was done.

## Existing remote job reconciliation

The tracked job `job_548d7adf8fa94755b62c826a72f00508` was polled twice for
status. Both requests timed out after 30 seconds during SSH `Connect`:

- `req_a9cc044ac23d4299b8068c96cc780608`
- `req_846848cb9f1945bd9e7486782e2a7966`
- `req_d74cc5a2d75f4f21af5478d7f609160c`

All three are observation failures, not terminal job results. The job outcome
remains unknown; it was neither restarted nor canceled. Reconcile this exact
job before deciding any further action. The next qualification test round,
when authorized by connectivity and resource prerequisites, must include the
previously used relevant suites as well as the new cases.

The read-only `ssh_command_list` MCP ledger returned this same job as
`state=running`, `remote_may_still_be_running=true`, remote PID `945329`,
started at `2026-09-27T20:35:13.287721209Z`. The command's input path is under
`/dev/shm`; that fact does not establish a completed result or waive the
disk-backed staging and no-OOM acceptance requirements. A bounded stdout read
at offset 0 then timed out after 30 seconds during SFTP (`req_4c7e8876090b4f38ba73a332b685973a`). The MCP ledger is not treated as proof that the remote process is still alive.

## PCRE evidence boundary

The existing v17 receipt
`R13-sonic1-v17-pcre-phase-proof-2026-09-27.md` reports a successful exact-tail
PCRE run and separate clean continuation, each within the 40-GiB PCRE-phase
ceiling and below the 12-GiB post-PCRE ceiling. It also reports that the
separate 32-GiB whole-workload runtime subcase exceeded its cap by about
85 MiB. Per the roadmap, these are distinct contracts; the stricter runtime
cap is not to be relaxed or represented as met. This receipt does not qualify
the overall candidate or release.

## Local access boundary

The canonical checkout was confirmed not writable in this task. The writable
`ClamAV` sibling is stale and was left untouched. Only this task receipt was
written using a one-command approval; source edits remain unavailable under
the default workspace permissions.

## Current source and build-only route

The current source-manifest helper produced SHA-256
`0e011be4f9c399c62b752efc574cbbe1c893735184088d05e497d1e2ce0699dc`, matching
the v17 manifest recorded by the existing service and PCRE evidence. Therefore
the current source content represented by that manifest already has a v17
Release build; no redundant rebuild was started.

Local Docker access was approved for read-only inventory and ephemeral image
inspection. The cached ClamAV toolchain images are AArch64 and lack `rustc`;
their `pkg-config` cannot load `libpkgconf.so.3`. The cached Rust image is also
AArch64 and lacks both `rustc` and CMake. No image was pulled, no package was
installed, and no source was mounted into those containers. They cannot supply
the certified Linux x86-64 build path.

State: active; remote job outcome and remaining roadmap acceptance items are
unresolved.

## Follow-up offline implementation audit

No Sonic1 test or remote-job operation was performed in this continuation.
The source-level audit identified a concrete remaining R08 implementation
gap, distinct from the already-implemented safety checks above:

- `libclamav/pe.c`'s PESpin path allocates `fsize` bytes and reads the complete
  fmap into that buffer before calling `unspin()`.
- The yC path does the same before `yc_decrypt()`. That routine mutates the
  unpacked PE sections through pointers into the whole-file buffer and writes
  the resulting prefix only after all sections are processed.
- Both routes pass through `cli_pe_unpack_size_check()`, so inputs requiring a
  contiguous buffer above `CLI_MAX_ALLOCATION` fail closed as incomplete.
  This is safe behavior, but it does not meet PLAN.md's remaining PE-unpacker
  conversion to bounded/spooled processing or the R08 `pe-unpacker-over-1g`
  capability.

This is not a safe one-line limit adjustment: PESpin computes a checksum over
the input and rewrites section ranges, while yC runs a byte-oriented emulator
over mutable section windows and later emits a reconstructed image. The next
implementation slice must replace those whole-map interfaces with checked
reader/writer or disk-backed section windows, preserve fail-visible status and
cleanup behavior, and avoid a giant resident buffer or mmap being described as
streaming.

Testing remains intentionally deferred. Before considering this slice done,
the next authorized Sonic1 test round must rerun the prior relevant PE/parser
and source-guard suites together with new cases for valid PESpin/yC completion,
late embedded detection, malformed/bounds failures, >1-GiB input admission,
temporary cleanup, and resource accounting; then run the applicable current
Release and sanitizer suites. The existing Sonic1 job remains ambiguous and
must be reconciled before any retry or cleanup decision.

At this checkpoint the implementation target was identified; no source change
or test claim had yet been made.

## Sonic1 reconciliation on continuation

- `ssh.hosts.list` returned the exact host ID `sonic1`; the supplied profile
  `sonic1-camera-key` was accepted by `ssh.connection.describe` (request
  `req_c1e1092918d044998d2ea1990906baf0`). The host reports Linux/POSIX,
  sudo enabled, and host-key verification disabled.
- `ssh.command.status` for the existing OneNote scan job timed out during SSH
  Connect after 30 seconds (`req_fe58ceb514f24a8ca15cbe86843434ad`). This is
  not a remote terminal result.
- A fresh `ssh.command.list` ledger read (`req_dca98d92659743eebb2731c84ef39f71`)
  still reports job `job_548d7adf8fa94755b62c826a72f00508` as `running`, with
  `remote_may_still_be_running=true` and PID `945329`. The job was not
  canceled, restarted, or treated as complete. No new test was launched.

State: exact-job outcome remains unknown; continue without remote testing until
the job can be safely reconciled and the connectivity/test round is available.

## Offline implementation increment

One bounded part of the PE resource-accounting gap was fixed after the audit:

- `cli_scanpe()` now computes the exact yC output-prefix length after checking
  that removing the final section cannot underflow the source length.
- The shared PE temporary-file macro now accepts a 64-bit reservation size;
  the yC branch reserves the exact output bytes before creating/writing its
  reconstructed temporary. Other callers retain their prior `dsize` behavior.
- Static source guards were added for the size-aware reservation and yC
  binding. The generated integer/offset inventory was regenerated after the
  source line changes.

This does **not** remove the yC whole-input `fsize` allocation, the analogous
PESpin allocation, or their >1-GiB fail-closed boundary. No build or test was
run; the new working-tree source manifest is SHA-256
`c4944c54d52f52d00f23b2c3a74f26a63a19fdf5dd26ec3507ce25e569098ed5`
(1,712 entries; 176,727 bytes). The older v17 build identity does not prove
this modified source. When testing is available, rerun the prior relevant PE,
parser, source-guard, Release and sanitizer suites together with a yC temporary
budget boundary case before treating even this small increment as verified.

State: implementation increment recorded; qualification remains open.

## Follow-on yC streaming increment and build boundary

After the two consecutive Sonic1 status attempts timed out during SSH Connect,
offline work replaced yC's full-input heap buffer with a disk-backed path:

- `cli_scanpe()` now applies configured scan limits rather than the individual
  contiguous-allocation ceiling for yC, reserves the full staged input size,
  and passes the fmap plus reservation counter to the unpacker.
- `yc_decrypt()` stages the input through 64-KiB fmap reads, decrypts code in
  64-KiB blocks while carrying CL, jump-budget, and deadline state across block
  boundaries, patches checked PE fields, truncates the removed final-section
  tail, and releases that reclaimed amount from temporary accounting.
- Static source guards bind the staged path and variant-adjusted decryptor
  coordinate. A read-only review found and corrected omission of the signed
  variant offset from the second-layer decryptor coordinate.

This code is **not compiled or tested**. `clang -fsyntax-only` stopped at the
missing `openssl/ssl.h`; no CMake executable, configured build tree, OpenSSL
development headers, or pkg-config executable is available in this local
environment. Docker is installed, but access to its local socket is denied.
No software was installed and no tests were run. `git diff --check` over the
changed C/source-guard files was clean; that is only whitespace hygiene, not
build or behavior evidence.

Two fresh polls of the same existing Sonic1 job timed out during Connect:
`req_610c38451d4d48dab5b8f5cb4a5600b6` and
`req_463409de318f4761ac2b6d5eb21f6c48`. The job was not restarted or canceled;
its terminal result remains unknown. The next usable test round must reconcile
that exact job first, then rerun prior relevant PE/parser/source-guard suites
alongside yC valid-output parity, malformed/bounds, >1-GiB admission, temp
cleanup/accounting, Release, and sanitizer cases. PESpin still has its separate
whole-input allocation gap.

A fresh read-only agent-owned job-ledger query (`req_0aaf7c2d040748f098e65103bdbdc345`)
still lists job `job_548d7adf8fa94755b62c826a72f00508` as `running` with
`remote_may_still_be_running=true`, PID `945329`, and the same 2026-09-27
start time. This is not a terminal result or proof of current process health;
the job remains untouched pending a successful status reconciliation.

State: yC source implementation advanced; local build prerequisites and
Sonic1 connectivity are external blockers; qualification remains open.

The deterministic source manifest for this unbuilt working tree is
`/private/tmp/clamav-yc-stream-20260927.manifest`, SHA-256
`2874bdfe0c004912982b136df36b447547e168a15d8be52e7447b27a7910fab8`
(1,712 entries; 176,727 bytes). It binds source content only; it is not build,
transfer, or qualification provenance.

## Cached local build-environment probe

To avoid installing anything, the two cached local ClamAV toolchain images
were inspected and used only for network-disabled, read-only-source probes:

- `clamav-largefile-local-toolchain:latest` is Linux/ARM64. CMake found
  OpenSSL and Zlib, then configuration stopped because BZip2 development
  headers/library were absent.
- `clamav-largefile-local-toolchain2:latest` is also Linux/ARM64 and includes
  BZip2. CMake additionally found LibXml2, PCRE2, and Iconv, but stopped at
  missing JSON-C headers/library. Its `pkg-config` executable cannot load
  `libpkgconf.so.3`.
- A one-file Clang syntax probe with temporary version metadata stopped at
  missing `openssl/opensslconf.h`; the cached image does not contain that
  OpenSSL development header. The host itself has no CMake, pkg-config, or
  OpenSSL development headers. Both images are AArch64 and cannot substitute
  for Sonic1's certified Linux x86-64 build/qualification regardless.

All source mounts were read-only; no tests, package installs, network access,
or source-tree writes were performed by these probes. The local configure and
probe logs/build scratch are under `/private/tmp/clamav-yc-arm64-build*`.
State remains: no usable full local build, and Sonic1 status reconciliation
still fails during SSH Connect.
