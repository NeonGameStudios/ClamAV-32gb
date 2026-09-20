# R13 resource capture process-log retention — 2026-09-20

Task ID / parent milestone: `R13 / R02-R04 resource evidence`.

Scope: make the resource-capture producer retain an optional merged scanner
process log, then exercise the current phase bridge and process-tree sampler in
one coherent bounded Sonic1 smoke. This is stale-tree development evidence;
it is not a qualification or capability-promotion record.

Implementation:

- `tools/largefile_acceptance_resource_capture.py` now accepts
  `--process-log` and captures the wrapped command's stdout and stderr into a
  bounded evidence-root artifact.
- Existing non-empty or symlinked process-log paths are rejected; the capture
  closes the log on startup, sampler, interruption, and normal completion
  paths. The source guard and symlink regression cover the new contract.

Local verification:

- Focused resource/phase tests passed 28/28.
- The full 604-entry source guard, release-readiness controls, snapshot check,
  and diff check passed.

Sonic1 smoke identity and boundary:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container:
  `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image:
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- `/src` was the read-write bind of
  `/tmp/clamav-32gb-current-20260915`.
- Only the current local `matcher.c` and the current capture wrapper were
  reconciled into the otherwise stale remote tree. The placeholder provenance
  manifest in this smoke is therefore not a current-source identity.

Coherent run result:

- The existing 8-GiB-minus-8-byte sparse fixture was scanned with the custom
  `PcreTail` signature. The exact fixture size was `8589934584` bytes, the
  fixture SHA-256 was
  `1d887622f47df15eb5d8bcb461f6412406abe8542ed9aa6a9c6cd62af80a12d8`, and
  the exact tail match was at offset `8589934576`.
- The tracked async wrapper reported 358 process-tree samples and published a
  resource row before returning exit 1 for the expected positive-control
  detection.
- Resource row: RSS peak `8426876 KiB`, PSS peak `8424042 KiB`, VAS peak
  `8476920 KiB`, swap `0 KiB`, temporary peak `0` bytes, PCRE phase peak
  `8426876 KiB`, post-PCRE phase peak `8271844 KiB`, and one stable OOM cgroup
  with zero OOM events and zero OOM kills.
- The phase file was exactly `pcre-start`, `post-pcre`, `complete` in order.
- The retained merged process log contains the object-bound runtime markers
  `deep-parse`, `before-pcre`, `pcre`, and
  `post-pcre-before-deep-parse`, with `subject_released=1` at the post-PCRE
  marker, plus the exact tail match and `PcreTail.UNOFFICIAL` detection.

Retained remote artifact hashes:

- Phase file:
  `a1917770ee2192298a3ac5d2f07c2f5f20d52f8189e8c5af65a2a20d60763c35`.
- Resource sidecar:
  `9ea0d6fb46e4a8ae0e5c5322532e35f09947f7c101b0826707dd5f059d346ced`.
- Merged process log:
  `c5eab8d9c335f9cbd96185ef9e0b7c36cfce255d471ee278c413a9baa64dfa40`.

Limits: the run does not prove current-source provenance, the 32-GiB case,
the strict release proof JSON with timestamped phase samples, sanitizer
parity, fanotify, production-CVD/service behavior, or release readiness. No
capability was promoted. No software was installed or downloaded, and no
GitHub workflow was triggered.

State: `development-verified; runtime-qualification-open`.
