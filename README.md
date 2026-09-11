# ClamAV-32gb

This repository is a ClamAV fork focused on making scanning of inputs up to
exactly 32 GiB (34,359,738,368 bytes) predictable and bounded. The work is
being applied across `libclamav`, `clamscan`, `clamd`, `clamdscan`, the milter,
and on-access scanning.

> **Status:** active development on `largefile-roadmap-qualification`. This is
> not an official Cisco Talos release and it is not release-qualified yet.
> The [current snapshot](32gb-current-snapshot.md) is the source of truth for
> qualification status.

## What this fork is building

The current branch combines ClamAV 1.5.3 with an ongoing large-file safety and
qualification effort. The implemented development slices include:

- fail-closed input admission and shared accounting for logical content,
  matcher work, temporary storage, memory, files, recursion, and time;
- reader-backed and streaming paths for selected archive, OneNote, and other
  large-format parsers, with bounded spooling and cleanup;
- bounded structural validation for GGUF, ONNX, and TFLite model inputs, while
  retaining raw matching;
- a non-executing, bounded structural walker for Python bytecode;
- deadline, partial-write, EINTR, report-framing, descriptor-passing, and
  cleanup hardening across service and front-end paths; and
- capability inventories, acceptance-map checks, workload checks, source
  guards, and readiness reporting so incomplete coverage stays visible.

The goal is not simply to accept a 32 GiB file. A scan must account for every
logical child and derived representation, preserve raw matching, and never
report or cache `OK` when a required parser, matcher, decoder, or signature ABI
was skipped. Unsupported or incomplete results must remain explicit.

## Current qualification status

The repository currently tracks 597 capability rows:

| Measure | Current value |
| --- | ---: |
| Qualified | 0 |
| Bounded development slices | 143 |
| Pending | 440 |
| Explicitly unsupported | 14 |
| Blocked by open evidence or qualification gates | 583 |
| Parser rows still blocked | 80 / 80 |
| Release readiness | **Blocked** |

These numbers are intentionally conservative. Full parser coverage, complete
materialized ingress testing, production-database runs, sanitizer evidence, a
certified Linux x86-64 runner, and final release gates are still open.

## GitHub notes — since the previous push

- Hardened the shared 32 GiB ingress/resource contract and fail-visible result
  handling across daemon, client, milter, and on-access paths.
- Extended bounded OneNote reader/parser coverage, including modern-first
  fallback behavior, checked offsets, cleanup, and short-input rejection.
- Strengthened bounded AI-model validation for GGUF, ONNX, and TFLite, plus
  non-executing Python marshal/bytecode handling and fuzzy-image admission.
- Added or refreshed R00–R10 evidence receipts, capability/inventory data,
  service workload checks, source guards, and readiness snapshots.
- Revalidated the local Python tooling and Rust parser suites; no capability was
  promoted to release-qualified status.

Release readiness remains **Blocked** pending full-size fixtures, complete
parser and materialized-ingress coverage, sanitizer and production-service
evidence, and a certified Linux x86-64 run.

## Roadmap and evidence

- [PLAN.md](PLAN.md) — authoritative release contract and acceptance plan
- [32gb-luna-execution-roadmap.md](docs/32gb-luna-execution-roadmap.md) —
  step-by-step execution directive
- [32gb-current-snapshot.md](32gb-current-snapshot.md) — current readiness
  snapshot and remaining blockers
- [largefile-capabilities.tsv](docs/largefile-capabilities.tsv) — capability
  manifest covering ingress, parsers, matchers, and build features
- [largefile-task-ledger.md](docs/largefile-task-ledger.md) — implementation
  receipts and evidence ledger
- [largefile-service-input-policy.md](docs/largefile-service-input-policy.md) —
  service-input boundary and result policy
- [largefile-qualification-followups.md](docs/largefile-qualification-followups.md) —
  remaining qualification follow-ups

## Development checks

From the repository root:

```sh
python3 -B -m unittest discover -s tools -p '*_test.py'
python3 -B tools/largefile_service_workload_check_test.py
python3 -B tools/largefile_acceptance_cases.py --check-map
python3 -B tools/largefile_acceptance_cases.py --check-records
python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md
sh tools/largefile_release_readiness.sh --status
```

The readiness command is expected to exit non-zero while the repository is
still blocked. The commands above validate development tooling and evidence
structure; they do not substitute for the outstanding full-size, sanitizer,
service, and certified-runner qualification suites.

## Building and using ClamAV

This fork retains the standard ClamAV source-build flow. See
[INSTALL.md](INSTALL.md) for build options and the
[upstream installation documentation](https://docs.clamav.net/manual/Installing/Installing-from-source-Unix.html)
for the platform-specific prerequisites. The roadmap documents the additional
resource and qualification requirements for the 32 GiB target.

For signature development, start with the
[ClamAV signature-writing manual](https://docs.clamav.net/manual/Signatures.html).
For upstream user documentation, see [docs.clamav.net](https://docs.clamav.net/).

## Contributing

Please keep changes tied to a capability row, test case, or evidence receipt
where possible. Do not turn a bounded development slice into a release claim
without the required current-source, sanitizer, service, and certified-runner
evidence. Issues and pull requests can be opened in this repository.

This fork is based on [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav)
and retains its upstream attribution and licensing. Upstream bug reports and
documentation improvements should continue to use the appropriate upstream
projects.

## Licensing

ClamAV is licensed for public/open source use under the GNU General Public
License, Version 2 (GPLv2).

See [COPYING.txt](COPYING.txt) for a copy of the license.

### 3rd Party Code

ClamAV contains a number of components that include code copied in part or in
whole from 3rd party projects and whose code is not owned by Cisco and which
are licensed differently than ClamAV. These include:

- Yara: Apache 2.0 license
  - Yara has since switched to the BSD 3-Clause License;
    our source is out-of-date and needs to be updated.
- 7z / lzma: public domain
- libclamav's NSIS/NulSoft parser includes:
  - zlib: permissive free software license
  - bzip2 / libbzip2: BSD-like license
- OpenBSD's libc/regex: BSD license
- file: BSD license
- str.c: contains BSD-licensed modified implementations of `strtol()` and
  `stroul()`, Copyright (c) 1990 The Regents of the University of California
- pngcheck (png.c): MIT/X11-style license
- getopt.c: MIT license
- Curl: license inspired by MIT/X, but not identical
- libmspack: LGPL license
- UnRAR (libclamunrar): a non-free/restricted open source license
  - The UnRAR license is incompatible with GPLv2 because it contains a clause
    that prohibits reverse engineering a RAR compression algorithm from the
    UnRAR decompression code.
  - For this reason, libclamunrar/libclamunrar_iface is not linked with
    libclamav. It is loaded at run time; if it fails to load, ClamAV continues
    without RAR support.

See the [COPYING directory](COPYING) for the third-party project licenses.

## Acknowledgements

This fork builds on the work of the
[ClamAV Team](https://www.clamav.net/about.html#credits), Cisco Talos, and the
many upstream contributors whose code and documentation remain part of the
project.
